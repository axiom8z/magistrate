package front

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"maps"
	"slices"
	"strings"

	"github.com/axiom8z/sayswho/internal/audit"
	"github.com/axiom8z/sayswho/internal/policy"
	"github.com/axiom8z/sayswho/internal/rpc"
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
)

// ruleText is what the model reads about a block. It is all our own wording, and no text from a
// server or from the call goes into it, so a block can't be made to say anything else.
var ruleText = map[string]string{
	ruleUnknownTool:     "no tool has that name.",
	ruleUpstreamDead:    "the server behind this tool has stopped and will not restart in this session.",
	ruleUpstreamTimeout: "the server did not answer in time.",
	ruleUpstreamError:   "the server answered with an error. Its text is not shown, because server text is untrusted.",
	ruleResultBlockType: "the result held a block that is not text, such as an image or a resource, and only text is let through.",
	ruleResultMalformed: "the server's result was malformed.",
	ruleAuditFailed:     "the audit log cannot be written, so no call can go through.",
	ruleTooManyCalls:    "too many calls are running at once. Try again when one finishes.",
}

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
	raw, _ := json.Marshal(toolResult{ // cannot fail: these are our own constant strings
		Content: []textBlock{{"text", "Blocked by SaysWho, rule " + rule + ": " + ruleText[rule]}},
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
// upstream.Tool carries only name, description and inputSchema, so nothing else gets through.
func (g *Gateway) admit(s *upstream.Server) []upstream.Tool {
	var kept []upstream.Tool
	for _, t := range s.Tools() {
		name := s.Name() + "__" + t.Name
		switch {
		case !policy.ValidName(t.Name) || !policy.ValidName(name):
			g.notes.Printf("hiding tool %.128q of server %q: its name breaks the MCP rules or is too long", t.Name, s.Name())
		case !validSchema(t.InputSchema):
			g.notes.Printf("hiding tool %.128q of server %q: its inputSchema is not an object schema", t.Name, s.Name())
		case g.listed[name]:
			g.notes.Printf("hiding a second tool named %.128q on server %q", t.Name, s.Name())
		default:
			g.listed[name] = true
			t.Name = name
			kept = append(kept, t)
		}
	}
	return kept
}

// validSchema checks the shape clients insist on. All servers share one list here, and a client that
// rejects one bad entry would lose the tools of every server.
func validSchema(raw jsontext.Value) bool {
	var schema struct {
		Type       string                    `json:"type"`
		Properties map[string]jsontext.Value `json:"properties"`
		Required   []string                  `json:"required"`
	}
	return raw.Kind() == jsontext.KindBeginObject && json.Unmarshal(raw, &schema) == nil && schema.Type == "object"
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
	callCtx, cancel := context.WithCancel(ctx)
	g.mu.Lock()
	g.inflight[string(m.ID)] = cancel
	g.mu.Unlock()
	g.calls.Go(func() { g.forward(callCtx, m.ID, server, tool, args, rec) })
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

// forward runs one call in its own goroutine. Nothing classifies calls yet, so all of them count as
// risky: each decision is on disk before the server can act on it. The client may kill us at any
// moment, and what a server did must never be missing from the log.
func (g *Gateway) forward(ctx context.Context, id jsontext.Value, server *upstream.Server, tool string,
	args jsontext.Value, rec audit.Record) {
	rec.Decision = audit.Allow
	if err := g.audit.Append(rec, true); err != nil {
		g.notes.Printf("audit log failed: %v", err)
		g.finish(id)
		g.reply(id, blocked(ruleAuditFailed))
		return
	}
	raw, callErr := server.Call(ctx, tool, args)
	result, rule := g.outcome(server, raw, callErr)
	cancelled := ctx.Err() != nil
	switch {
	case cancelled:
		rec.Decision = audit.Cancelled
	case rule != "":
		rec.Decision, rec.Rule = audit.Block, rule
		result = blocked(rule)
	default:
		rec.Decision = audit.Result
	}
	err := g.audit.Append(rec, rec.Decision == audit.Block)
	g.finish(id)
	switch {
	case cancelled:
		// The specification says a cancelled request gets no response.
	case err != nil:
		g.notes.Printf("audit log failed: %v", err)
		g.reply(id, blocked(ruleAuditFailed))
	default:
		g.reply(id, result)
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
