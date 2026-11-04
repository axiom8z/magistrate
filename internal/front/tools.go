package front

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/axiom8z/sayswho/internal/approve"
	"github.com/axiom8z/sayswho/internal/audit"
	"github.com/axiom8z/sayswho/internal/gate"
	"github.com/axiom8z/sayswho/internal/policy"
	"github.com/axiom8z/sayswho/internal/prov"
	"github.com/axiom8z/sayswho/internal/rpc"
	"github.com/axiom8z/sayswho/internal/secrets"
	"github.com/axiom8z/sayswho/internal/upstream"
)

// maxCalls bounds the calls running at once. Past it a call is refused rather than queued: the read
// loop must stay free to see cancellations, and a queue would hold a megabyte per line for nothing.
const maxCalls = 32

// Rule IDs, one per reason a call or result can be blocked. They are stable names that appear in the
// log and in what the model reads.
const (
	ruleUnknownTool     = "unknown-tool"
	ruleUpstreamDead    = "upstream-dead"
	ruleUpstreamTimeout = "upstream-timeout"
	ruleUpstreamError   = "upstream-error"
	ruleResultBlockType = "result-block-type"
	ruleResultMalformed = "result-malformed"
	ruleAuditFailed     = "audit-failed"
	ruleTooManyCalls    = "too-many-calls"
	ruleMalformedCall   = "malformed-call"
	ruleNotInitialized  = "not-initialized"
	ruleNotInPolicy     = "tool-not-in-policy"
	rulePinMismatch     = "pin-mismatch"
	ruleUnknownArgument = "unknown-argument"
	ruleLatchFailed     = "latch-failed"
)

// ruleText is what the model reads about a block. It is all our own wording, and no text from a
// server or from the call goes into it, so a block can't be made to say anything else.
var ruleText = map[string]string{
	ruleUnknownTool:        "no tool has that name.",
	ruleUpstreamDead:       "the server behind this tool has stopped and will not restart in this session.",
	ruleUpstreamTimeout:    "the server did not answer in time.",
	ruleUpstreamError:      "the server answered with an error. Its text is not shown, because server text is untrusted.",
	ruleResultBlockType:    "the result held a block that is not text, such as an image or a resource, and only text is let through.",
	ruleResultMalformed:    "the server's result was malformed.",
	ruleAuditFailed:        "the audit log cannot be written, so no call can go through.",
	ruleTooManyCalls:       "too many calls are running at once. Try again when one finishes.",
	ruleNotInPolicy:        "the policy does not name this tool, so it can't be used.",
	rulePinMismatch:        "this tool's definition is not the one the policy pinned, so it can't be used until an operator has reviewed it.",
	ruleUnknownArgument:    "the call has an argument the policy does not list for this tool.",
	ruleLatchFailed:        "the gateway can't record its state, so no call can go through.",
	gate.RuleBudget:        "a value in this call did not come from the user, and this session has no approvals left to ask for.",
	gate.RuleRefused:       "a person already refused this same call in this session.",
	approve.RuleDeclined:   "a value in this call did not come from the user, and a person declined it.",
	approve.RuleCancelled:  "a value in this call did not come from the user, and the question to a person was dismissed.",
	approve.RuleTimeout:    "a value in this call did not come from the user, and nobody answered in time.",
	approve.RuleMalformed:  "a value in this call did not come from the user, and the answer from the client could not be read.",
	approve.RuleNoDialog:   "a value in this call did not come from the user, and this client can't ask a person.",
	secrets.RuleOverBudget: "this call holds more encoded text than can be checked for credentials, and no approval can let it through.",
}

// secretText is what the model reads for every secret rule, which have no entry above. A block for a
// credential is the one that no person can approve.
const secretText = "this call holds what looks like a credential, and no approval can let it through."

type textBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// toolResult holds the only fields of a result that go back to the client. Anything else a server
// adds, such as _meta or a block's annotations, is left out by decoding into this.
type toolResult struct {
	Content           []textBlock    `json:"content"`
	StructuredContent jsontext.Value `json:"structuredContent,omitzero"`
	IsError           bool           `json:"isError,omitzero"`
}

// blocked is the result a model reads when something is refused. A block is a normal isError result
// and not a protocol error, because clients show those to the model, which can then adapt.
func blocked(rule string) jsontext.Value {
	text, known := ruleText[rule]
	if !known {
		text = secretText
	}
	raw, _ := json.Marshal(toolResult{ // cannot fail: these are our own constant strings
		Content: []textBlock{{"text", "Blocked by SaysWho, rule " + rule + ": " + text}},
		IsError: true,
	})
	return raw
}

// startServers starts the servers and builds the tool list, which then stays fixed for the session.
func (g *Gateway) startServers(ctx context.Context, start func(context.Context) []*upstream.Server) {
	defer close(g.ready)
	var tools []upstream.Tool
	for _, s := range start(ctx) {
		g.servers[s.Name()] = s
		if why := s.Failure(); why != "" {
			g.notes.Printf("server %q is out of service: %s", s.Name(), why)
		}
		tools = append(tools, g.admit(s)...)
	}
	// A fixed order, whatever order the servers listed them in or finished starting.
	slices.SortFunc(tools, func(a, b upstream.Tool) int { return strings.Compare(a.Name, b.Name) })
	raw, err := json.Marshal(map[string][]upstream.Tool{"tools": tools})
	if err != nil {
		g.notes.Printf("building the tool list: %v", err)
		raw = []byte(`{"tools":[]}`)
	}
	g.listing = raw
}

// admit renames a server's tools to <server>__<tool> and hides any that could not be used safely.
// Only name, description and inputSchema go on: upstream.Tool holds no more than those and the
// annotations, and they are cleared here. A tool the policy refuses is hidden rather than only blocked,
// because a changed description is what a poisoned tool looks like, and the model must not read it.
func (g *Gateway) admit(s *upstream.Server) []upstream.Tool {
	var kept []upstream.Tool
	for _, t := range s.Tools() {
		name := s.Name() + "__" + t.Name
		refused := g.vet(name, t)
		switch {
		case !policy.ValidName(t.Name) || !policy.ValidName(name):
			g.notes.Printf("hiding tool %.128q of server %q: its name breaks the MCP rules or is too long", t.Name, s.Name())
		case !validSchema(t.InputSchema):
			g.notes.Printf("hiding tool %.128q of server %q: its inputSchema is not an object schema", t.Name, s.Name())
		case g.listed[name]:
			g.notes.Printf("hiding a second tool named %.128q on server %q", t.Name, s.Name())
		case refused != "":
			g.notes.Printf("hiding tool %.128q of server %q: %s", t.Name, s.Name(), refused)
			g.hidden[name] = refused
		default:
			g.listed[name] = true
			t.Name, t.Annotations = name, nil
			kept = append(kept, t)
		}
	}
	return kept
}

// vet checks a tool against the policy and returns the rule refusing it, if any. A pin that is missing
// or malformed simply fails to match. The pass mode has no labels, so it has nothing to check.
func (g *Gateway) vet(name string, t upstream.Tool) string {
	if g.policy.Mode == policy.ModePass {
		return ""
	}
	entry, known := g.policy.Tools[name]
	if !known {
		return ruleNotInPolicy
	}
	if pin, err := policy.Pin(t); err != nil || pin != entry.Pin {
		return rulePinMismatch
	}
	return ""
}

// validSchema checks the shape clients insist on. All servers share one list here, and a client that
// rejects one bad entry would lose the tools of every server. Claude Code 2.1.302 rejects a list over
// a null properties, a null required or a null inside required, which a plain decode would read as
// "nothing there", so those two members stay raw until they have been looked at.
func validSchema(raw jsontext.Value) bool {
	var schema struct {
		Type       string         `json:"type"`
		Properties jsontext.Value `json:"properties"`
		Required   jsontext.Value `json:"required"`
	}
	if raw.Kind() != jsontext.KindBeginObject || json.Unmarshal(raw, &schema) != nil || schema.Type != "object" {
		return false
	}
	if schema.Properties != nil && schema.Properties.Kind() != jsontext.KindBeginObject {
		return false
	}
	if schema.Required == nil {
		return true
	}
	var names []*string
	return schema.Required.Kind() == jsontext.KindBeginArray && json.Unmarshal(schema.Required, &names) == nil && !slices.Contains(names, nil)
}

func (g *Gateway) toolsCall(ctx context.Context, m *rpc.Message) {
	refuseRequest := func(rule string, code int, message string) {
		g.logRefusal(audit.Record{}, rule)
		g.replyError(m.ID, code, message)
	}
	if !g.initialized {
		refuseRequest(ruleNotInitialized, rpc.CodeInvalidRequest, "Call initialize first")
		return
	}
	name, args, ok := parseCall(m.Params)
	if !ok {
		refuseRequest(ruleMalformedCall, rpc.CodeInvalidParams, "Invalid params")
		return
	}
	g.mu.Lock()
	_, duplicate := g.inflight[string(m.ID)]
	running := len(g.inflight)
	g.mu.Unlock()
	if duplicate {
		refuseRequest(ruleMalformedCall, rpc.CodeInvalidRequest, "Request ID already in use")
		return
	}
	<-g.ready
	rec := g.record(name, args)
	server, tool, rule := g.route(name)
	if rule == "" && running >= maxCalls {
		rule = ruleTooManyCalls
	}
	if rule != "" {
		g.logRefusal(rec, rule)
		g.reply(m.ID, blocked(rule))
		return
	}
	c := &call{id: m.ID, name: name, server: server, tool: tool, args: args, rec: rec, label: g.policy.Tools[name]}
	json.Unmarshal(args, &c.fields) // cannot fail: parseCall checked it is an object
	decision := g.decide(c)
	if decision.Action == gate.Block {
		g.logRefusal(rec, decision.Rule)
		g.reply(m.ID, blocked(decision.Rule))
		return
	}
	if decision.ArgsAreSources {
		g.prov.AddArguments(c.fields)
	}
	if decision.Action == gate.Ask && g.clientElicits {
		g.budget.Begin(rec.ArgsHMAC)
	}
	callCtx, cancel := context.WithCancel(ctx)
	g.mu.Lock()
	g.inflight[string(m.ID)] = cancel
	g.mu.Unlock()
	g.calls.Go(func() { g.run(callCtx, c, decision) })
}

// call is one call on its way through the gateway. Fields holds the same values as args, by name.
type call struct {
	id         jsontext.Value
	name, tool string
	server     *upstream.Server
	args       jsontext.Value
	fields     map[string]jsontext.Value
	rec        audit.Record
	label      policy.Tool
	report     prov.Report
}

// decide gathers what gate.Decide may look at. It runs on the read loop, so calls are judged in the
// order they arrived, and the budget can't be spent twice by calls judged at once.
func (g *Gateway) decide(c *call) gate.Decision {
	in := gate.Input{Mode: g.policy.Mode, Read: c.label.Effect == policy.EffectRead,
		HasPrompt: g.hasPrompt, Exposed: g.latch.Exposed()}
	in.AsksLeft, in.Refused = g.budget.State(c.rec.ArgsHMAC)
	if g.policy.Mode == policy.ModePass {
		return gate.Decide(in)
	}
	for name := range c.fields {
		if _, takes := c.label.ArgFor(name); !takes {
			in.Bad = ruleUnknownArgument
		}
	}
	leaves := prov.Strings(c.args)
	in.Secret = secrets.ScanCall(leaves)
	c.report = g.prov.Check(c.label, c.fields)
	if !in.Read && g.sensitive.Contains(leaves) {
		c.report.Findings = append(c.report.Findings, prov.Finding{Rule: prov.RuleSensitive})
	}
	if len(c.report.Findings) > 0 {
		in.Finding = c.report.Findings[0].Rule
	}
	c.rec.Sources = c.report.Sources
	return gate.Decide(in)
}

// run takes an allowed or held call to its end, on its own goroutine, so that the read loop stays free
// to read the answer to a question and any cancellation.
func (g *Gateway) run(ctx context.Context, c *call, decision gate.Decision) {
	if decision.Action == gate.Ask {
		rule := g.hold(ctx, c, decision.Rule)
		switch {
		case ctx.Err() != nil:
			c.rec.Rule = ""
			c.rec.Decision = audit.Cancelled
			if err := g.audit.Append(c.rec, true); err != nil {
				g.notes.Printf("audit log failed: %v", err)
			}
			g.finish(c.id)
			return
		case rule != "":
			g.logRefusal(c.rec, rule)
			g.finish(c.id)
			g.reply(c.id, blocked(rule))
			return
		}
		g.budget.Approved(c.rec.ArgsHMAC)
		c.rec.Rule = approve.RuleApproved
	}
	g.forward(ctx, c)
}

// hold logs that a person is being asked, then asks. It returns the rule refusing the call, or "" for
// an approval. Waiting here costs the call nothing: its timeout starts when it reaches the server.
func (g *Gateway) hold(ctx context.Context, c *call, why string) string {
	rec := c.rec
	rec.Decision, rec.Rule = audit.Ask, why
	if err := g.audit.Append(rec, true); err != nil {
		g.notes.Printf("audit log failed: %v", err)
		return ruleAuditFailed
	}
	if !g.clientElicits {
		return approve.RuleNoDialog
	}
	return g.ask(ctx, approve.Prompt(c.name, c.report.Findings, c.fields))
}

// ask sends one question to the client and waits for the answer. A question that ends any other way
// is cancelled as well, so nobody is left answering a dialog for a call that is already over.
func (g *Gateway) ask(ctx context.Context, message string) string {
	answer := make(chan *rpc.Message, 1)
	g.mu.Lock()
	g.asked++
	id := jsontext.Value(fmt.Sprintf(`"sayswho-ask-%d"`, g.asked))
	g.questions[string(id)] = answer
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		delete(g.questions, string(id))
		g.mu.Unlock()
	}()
	if err := g.out.Write(rpc.Message{ID: id, Method: "elicitation/create", Params: approve.Params(message)}); err != nil {
		g.notes.Printf("asking the client: %v", err)
		return approve.RuleNoDialog
	}
	timer := time.NewTimer(approve.Timeout)
	defer timer.Stop()
	select {
	case m := <-answer:
		return approve.Outcome(m)
	case <-timer.C:
	case <-ctx.Done():
	}
	params := fmt.Appendf(nil, `{"requestId":%s,"reason":"the gateway stopped waiting"}`, id)
	if err := g.out.Write(rpc.Message{Method: "notifications/cancelled", Params: params}); err != nil {
		g.notes.Printf("asking the client: %v", err)
	}
	return approve.RuleTimeout
}

// answered gives the client's answer to the question waiting for it. An answer to nothing is dropped.
func (g *Gateway) answered(m *rpc.Message) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if answer, waiting := g.questions[string(m.ID)]; waiting {
		delete(g.questions, string(m.ID))
		answer <- m
	}
}

// parseCall takes what it needs from the params and nothing else, so _meta and unknown fields stay
// behind. Formatting the arguments rewrites them from our own parse, with escapes and whitespace
// normalized and numbers left alone. What a server gets is then the same bytes the gateway checks,
// which leaves no room for the two to read one call differently.
func parseCall(params jsontext.Value) (string, jsontext.Value, bool) {
	var p struct {
		Name      string         `json:"name"`
		Arguments jsontext.Value `json:"arguments"`
	}
	if params.Kind() != jsontext.KindBeginObject || json.Unmarshal(params, &p) != nil || p.Name == "" {
		return "", nil, false
	}
	if p.Arguments == nil {
		p.Arguments = jsontext.Value("{}")
	}
	if p.Arguments.Kind() != jsontext.KindBeginObject || p.Arguments.Format() != nil {
		return "", nil, false
	}
	return p.Name, p.Arguments, true
}

// record starts the audit record for a call. Only a tool we listed is named, and arguments appear
// only as lengths, sorted so that no names are needed: a hijacked model picks both the tool name and
// the argument names, and could otherwise carry a secret into the log in one of them.
func (g *Gateway) record(name string, args jsontext.Value) audit.Record {
	var fields map[string]jsontext.Value
	json.Unmarshal(args, &fields) // cannot fail: parseCall checked it is an object
	lengths := []int{}
	for _, field := range slices.Sorted(maps.Keys(fields)) {
		lengths = append(lengths, len(fields[field]))
	}
	rec := audit.Record{ArgLens: lengths, ArgsHMAC: g.audit.Digest(name, args)}
	if g.listed[name] {
		rec.Tool = name
	}
	return rec
}

// route finds the server for a name, splitting at the first "__". Policy load guarantees no server
// name can make that split land in the wrong place.
func (g *Gateway) route(name string) (*upstream.Server, string, string) {
	serverName, tool, _ := strings.Cut(name, "__")
	server := g.servers[serverName]
	if server != nil && server.Failure() != "" {
		return nil, "", ruleUpstreamDead
	}
	if rule := g.hidden[name]; rule != "" && !g.listed[name] {
		return nil, "", rule
	}
	if server == nil || !g.listed[name] {
		return nil, "", ruleUnknownTool
	}
	return server, tool, ""
}

// logRefusal records a refusal and makes it durable. The call is refused either way, so a failing
// log changes nothing here except that it is noted.
func (g *Gateway) logRefusal(rec audit.Record, rule string) {
	rec.Decision, rec.Rule = audit.Block, rule
	if err := g.audit.Append(rec, true); err != nil {
		g.notes.Printf("audit log failed: %v", err)
	}
}

// forward sends one allowed call to its server. The latch goes on disk first, so a crash can't lose
// the fact that untrusted output may have been read. So does the decision on any act: the client may
// kill us at any moment, and what a server did must never be missing from the log. A read that goes
// missing has done nothing, so it doesn't pay for an fsync.
func (g *Gateway) forward(ctx context.Context, c *call) {
	rec := c.rec
	if c.label.Output != policy.OutputTrusted {
		if err := g.latch.Set(); err != nil {
			g.notes.Printf("setting the latch: %v", err)
			g.logRefusal(rec, ruleLatchFailed)
			g.finish(c.id)
			g.reply(c.id, blocked(ruleLatchFailed))
			return
		}
	}
	rec.Decision = audit.Allow
	if err := g.audit.Append(rec, c.label.Effect != policy.EffectRead); err != nil {
		g.notes.Printf("audit log failed: %v", err)
		g.finish(c.id)
		g.reply(c.id, blocked(ruleAuditFailed))
		return
	}
	raw, callErr := c.server.Call(ctx, c.tool, c.args)
	result, rule := g.outcome(c.server, raw, callErr)
	var redacted string
	if rule == "" && callErr == nil && g.policy.Mode != policy.ModePass {
		result, redacted, rule = redact(result)
	}
	cancelled := ctx.Err() != nil
	switch {
	case cancelled:
		rec.Decision = audit.Cancelled
	case rule != "":
		rec.Decision, rec.Rule = audit.Block, rule
		result = blocked(rule)
	default:
		rec.Decision, rec.Rule = audit.Result, redacted
		g.observe(c, result)
	}
	err := g.audit.Append(rec, rec.Decision == audit.Block)
	g.finish(c.id)
	switch {
	case cancelled:
		// The specification says a cancelled request gets no response.
	case err != nil:
		g.notes.Printf("audit log failed: %v", err)
		g.reply(c.id, blocked(ruleAuditFailed))
	default:
		g.reply(c.id, result)
	}
}

// observe tells provenance what a result said, before the client can act on it. Pass mode has no use
// for it, and must behave as if there were no gateway at all.
func (g *Gateway) observe(c *call, result jsontext.Value) {
	if g.policy.Mode == policy.ModePass {
		return
	}
	var res toolResult
	json.Unmarshal(result, &res) // cannot fail: rebuild wrote it from this type
	seen := prov.Result{Structured: res.StructuredContent, IsError: res.IsError}
	for _, block := range res.Content {
		seen.Texts = append(seen.Texts, block.Text)
	}
	g.prov.Observe(c.name, c.label, c.fields, seen)
	if c.label.Sensitive {
		for _, text := range append(seen.Texts, prov.Strings(seen.Structured)...) {
			g.sensitive.Register(text)
		}
	}
}

// redact cleans a rebuilt result of known-format secrets before anyone reads it (DESIGN section 5),
// since a model can't re-encode what it never saw. It returns the result to send, the first secret
// rule that fired, and the rule blocking the result if it can't be rewritten.
func redact(result jsontext.Value) (cleaned jsontext.Value, fired, block string) {
	var res toolResult
	json.Unmarshal(result, &res) // cannot fail: rebuild wrote it from this type
	var ids []string
	for i, b := range res.Content {
		text, found := secrets.Redact(b.Text)
		res.Content[i].Text = text
		ids = append(ids, found...)
	}
	structured, found, err := redactJSON(res.StructuredContent)
	if err != nil {
		return nil, "", ruleResultMalformed
	}
	if ids = append(ids, found...); len(ids) == 0 {
		return result, "", ""
	}
	res.StructuredContent = structured
	cleaned, err = json.Marshal(res)
	if err != nil {
		return nil, "", ruleResultMalformed
	}
	return cleaned, ids[0], ""
}

// redactJSON rewrites only the strings in a JSON value, token by token, so its numbers stay as written.
// It reads decoded strings, because an escape like g would hide a secret from a look at the raw
// bytes and not from the client. Two member names that redact alike make the rewrite fail, which is
// why it can return an error.
func redactJSON(raw jsontext.Value) (jsontext.Value, []string, error) {
	if raw == nil {
		return nil, nil, nil
	}
	var out bytes.Buffer
	var ids []string
	dec, enc := jsontext.NewDecoder(bytes.NewReader(raw)), jsontext.NewEncoder(&out)
	for {
		tok, err := dec.ReadToken()
		if errors.Is(err, io.EOF) {
			return bytes.TrimSpace(out.Bytes()), ids, nil
		}
		if err != nil {
			return nil, nil, err
		}
		if tok.Kind() == jsontext.KindString {
			if text, found := secrets.Redact(tok.String()); len(found) > 0 {
				tok, ids = jsontext.String(text), append(ids, found...)
			}
		}
		if err := enc.WriteToken(tok); err != nil {
			return nil, nil, err
		}
	}
}

// finish drops the call from the in-flight table. It runs before the reply goes out, so a client that
// reuses an ID right after seeing the reply is not refused as a duplicate.
func (g *Gateway) finish(id jsontext.Value) {
	g.mu.Lock()
	defer g.mu.Unlock()
	cancel := g.inflight[string(id)]
	delete(g.inflight, string(id))
	cancel() // the call is over, and this releases its context
}

// outcome turns what a call came back with into the result for the client, or the rule blocking it.
func (g *Gateway) outcome(server *upstream.Server, raw jsontext.Value, err error) (jsontext.Value, string) {
	var serverErr *rpc.Error
	switch {
	case err == nil:
		return rebuild(raw)
	case errors.Is(err, upstream.ErrCancelled):
		return nil, ""
	case errors.Is(err, upstream.ErrDead):
		g.notes.Printf("server %q is out of service: %s", server.Name(), server.Failure())
		return nil, ruleUpstreamDead
	case errors.Is(err, upstream.ErrTimeout):
		g.notes.Printf("server %q did not answer in time", server.Name())
		return nil, ruleUpstreamTimeout
	case errors.As(err, &serverErr):
		// %.200q cuts the text to 200 characters and escapes it: only the operator sees it, as data.
		g.notes.Printf("server %q answered error %d: %.200q", server.Name(), serverErr.Code, serverErr.Message)
	}
	return nil, ruleUpstreamError
}

// rebuild copies a server's result field by field, so nothing unknown can reach the client. One block
// that is not text blocks the whole result (DESIGN section 2): the checks that come later read text
// and structuredContent, and an image or a resource could carry anything past them.
func rebuild(raw jsontext.Value) (jsontext.Value, string) {
	var res toolResult
	if raw.Kind() != jsontext.KindBeginObject || json.Unmarshal(raw, &res) != nil {
		return nil, ruleResultMalformed
	}
	for _, b := range res.Content {
		if b.Type != "text" {
			return nil, ruleResultBlockType
		}
	}
	if res.StructuredContent != nil && res.StructuredContent.Kind() != jsontext.KindBeginObject {
		return nil, ruleResultMalformed
	}
	out, err := json.Marshal(res)
	if err != nil {
		return nil, ruleResultMalformed
	}
	return out, ""
}
