// Package prov answers the question the gateway is named for: who said that? It holds what a session
// has learned about where values came from, and checks a call's arguments against it, by the rules of
// DESIGN section 3. This is value matching, a heuristic, and section 9 lists what it can't see.
package prov

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/axiom8z/sayswho/internal/policy"
)

// Sources, as the audit log names them. Each is a kind of thing and never a value.
const (
	SourcePrompt    = "prompt"
	SourceOperator  = "trusted_values"
	SourceArguments = "arguments" // sent before the latch, with no prompt file
	sourceTool      = "tool:"
	sourceBound     = "bound:"
)

// Rules a failed value can name.
const (
	RuleControl    = "unsourced-control"
	RuleCredential = "credential-not-in-prompt"
	RuleQuantity   = "quantity-invalid"
	RuleLink       = "unsourced-link"
	RuleSensitive  = "registered-sensitive-value"
)

const (
	// maxBoundRecords is the most records a lookup can return and still bind: past this it is a
	// listing the model picks from, not a lookup of what the user named.
	maxBoundRecords = 3
	// maxSeen bounds the memory kept for "first seen in". Forgetting only costs a dialog that detail.
	maxSeen = 16 << 20
)

// dateShape is what a data argument of type date may hold. It can carry a date and nothing else.
var dateShape = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?(?:Z|[+-]\d{2}:\d{2})?)?$`)

// State is what one session knows. It lives in memory, so a restart asks more and never less.
type State struct {
	mu       sync.Mutex
	prompt   string
	boundIDs bool
	sources  map[string]string // value in canon form -> what first vouched for it
	bound    map[string]bool   // kind + NUL + value in canon form
	seen     []seenResult
	seenSize int
}

type seenResult struct{ tool, text string }

// Finding is one value that failed a check. It holds the value for the person's dialog, so nothing
// here may go to the log except Rule.
type Finding struct {
	Arg, Value, Rule string
	SeenIn           string // the tool whose output first held the value, or ""
}

// Report is the outcome of checking one call.
type Report struct {
	Findings []Finding
	Sources  []string // what vouched for the values that passed, sorted and without repeats
	controls int      // control leaves looked at, passed or not
}

// Result is what a tool sent back.
type Result struct {
	Texts      []string
	Structured jsontext.Value
	IsError    bool
}

// New returns the state for a session. An empty prompt matches nothing, which is the no-prompt case.
func New(prompt string, trustedValues []string, boundIDs bool) *State {
	s := &State{prompt: canonPrompt(prompt), boundIDs: boundIDs, sources: map[string]string{}, bound: map[string]bool{}}
	for _, v := range trustedValues {
		s.add(v, SourceOperator)
	}
	return s
}

// add records a whole value as sourced. The first source to vouch for a value is the one kept.
func (s *State) add(value, source string) {
	c := canon(value)
	if _, known := s.sources[c]; c != "" && !known {
		s.sources[c] = source
	}
}

// inPrompt is rule 1. The length limits are why "June 13" can't authorise deleting file 13, and why
// "or" can't search out a file. They count the value without punctuation at its ends, or "13." and
// "or." would walk past them. There is no decoding, and no match for a non-ASCII value at all: with
// only ASCII folding there is no telling what such a value might be standing in for.
func (s *State) inPrompt(value string) bool {
	c := canon(value)
	core := strings.TrimFunc(c, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
	return isASCII(value) && len(core) >= 3 && (len(core) >= 5 || !allDigits(core)) && tokenIn(c, s.prompt)
}

// source names what vouches for a value, or returns "". Only an argument declaring a bind kind can be
// answered by a bound ID of that kind.
func (s *State) source(value, bindKind string) string {
	if !isASCII(value) {
		return ""
	}
	if s.inPrompt(value) {
		return SourcePrompt
	}
	if from, ok := s.sources[canon(value)]; ok {
		return from
	}
	if s.bound[bindKind+"\x00"+canon(value)] {
		return sourceBound + bindKind
	}
	return ""
}

// Check judges every leaf of a call's arguments. An argument the tool does not take is judged as
// control, though the caller blocks the call before this result can matter.
func (s *State) Check(tool policy.Tool, args map[string]jsontext.Value) Report {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.check(tool, args)
}

func (s *State) check(tool policy.Tool, args map[string]jsontext.Value) Report {
	var r Report
	for _, name := range slices.Sorted(maps.Keys(args)) {
		arg, _ := tool.ArgFor(name)
		for _, l := range leaves(args[name]) {
			s.checkLeaf(&r, name, arg, l)
		}
	}
	slices.Sort(r.Sources)
	r.Sources = slices.Compact(r.Sources)
	return r
}

func (s *State) checkLeaf(r *Report, name string, arg policy.Arg, l leaf) {
	switch arg.Role {
	case policy.RoleContent:
		for _, link := range links(l.text) {
			s.need(r, name, link, s.source(link, ""), RuleLink)
		}
		return
	case policy.RoleQuantity:
		if !s.quantityOK(l, arg.Max) {
			s.fail(r, name, l.text, RuleQuantity)
		}
		return
	case policy.RoleCredential:
		// A credential comes from the person and nowhere else, whatever else may vouch for a value.
		if l.kind != jsontext.KindNull && !s.inPrompt(l.text) {
			s.fail(r, name, l.text, RuleCredential)
		}
		return
	case policy.RoleData:
		if typed(l, arg) {
			return
		}
	}
	// JSON null names nothing, and models send it for optional arguments they are leaving out. An empty
	// string stays a value: to a server it can mean "all of them".
	if l.kind != jsontext.KindNull {
		r.controls++
		s.need(r, name, l.text, s.source(l.text, arg.Bind), RuleControl)
	}
}

func (s *State) need(r *Report, name, value, source, rule string) {
	if source == "" {
		s.fail(r, name, value, rule)
		return
	}
	r.Sources = append(r.Sources, source)
}

func (s *State) fail(r *Report, name, value, rule string) {
	r.Findings = append(r.Findings, Finding{name, value, rule, s.firstSeen(value)})
}

func (s *State) firstSeen(value string) string {
	needle := fold(value)
	for _, result := range s.seen {
		if needle != "" && strings.Contains(result.text, needle) {
			return result.tool
		}
	}
	return ""
}

// quantityOK takes a JSON number from 0 to limit, or a number named in the prompt whatever its length.
// A string is never within the ceiling: a lax server could coerce "5000". A string can only be named.
func (s *State) quantityOK(l leaf, limit *float64) bool {
	forms := []string{l.text}
	switch l.kind {
	case jsontext.KindNumber:
		f, err := strconv.ParseFloat(l.text, 64)
		if err != nil {
			return false
		}
		if limit != nil && f >= 0 && f <= *limit {
			return true
		}
		// The prompt may say 5000 or 5000.00 where the call says 5000.0.
		forms = append(forms, strconv.FormatFloat(f, 'f', -1, 64), strconv.FormatFloat(f, 'f', 2, 64))
	case jsontext.KindString:
	default:
		return false
	}
	return isASCII(l.text) && slices.ContainsFunc(forms, func(form string) bool { return tokenIn(canon(form), s.prompt) })
}

func typed(l leaf, arg policy.Arg) bool {
	switch arg.Type {
	case policy.TypeNumber:
		return l.kind == jsontext.KindNumber
	case policy.TypeBoolean:
		return l.kind == jsontext.KindTrue || l.kind == jsontext.KindFalse
	case policy.TypeDate:
		return l.kind == jsontext.KindString && dateShape.MatchString(l.text)
	case policy.TypeEnum:
		return l.kind == jsontext.KindString && slices.Contains(arg.Values, l.text)
	}
	return false
}

// AddArguments is the no-prompt rule: before the latch the agent has read nothing untrusted, so what
// it sends must have come from the user.
func (s *State) AddArguments(args map[string]jsontext.Value) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, value := range args {
		for _, l := range leaves(value) {
			if l.kind != kindName && l.kind != jsontext.KindNull {
				s.add(l.text, SourceArguments)
			}
		}
	}
}

// Observe learns from a result. Text and structuredContent can disagree, and a client may show the
// model either, so both are read. An error result never vouches or binds: errors often echo the call,
// and that would launder a value the model chose.
func (s *State) Observe(name string, tool policy.Tool, args map[string]jsontext.Value, res Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.remember(name, res)
	if res.IsError {
		return
	}
	if tool.Output == policy.OutputTrusted {
		s.vouch(name, res)
	}
	if s.boundIDs && tool.Binds != nil {
		s.bind(tool, args, res)
	}
}

func (s *State) remember(name string, res Result) {
	var b strings.Builder
	for _, text := range res.Texts {
		b.WriteString(text + "\n")
	}
	for _, l := range leaves(res.Structured) {
		b.WriteString(l.text + "\n")
	}
	s.seen = append(s.seen, seenResult{name, fold(b.String())})
	s.seenSize += b.Len()
	for s.seenSize > maxSeen && len(s.seen) > 1 {
		s.seenSize -= len(s.seen[0].text)
		s.seen = slices.Delete(s.seen, 0, 1)
	}
}

// vouch is rule 3: whole-leaf equality on structuredContent or JSON text. Go parses no YAML, and a
// value inside free text is not a leaf, so plain text vouches for nothing.
func (s *State) vouch(name string, res Result) {
	values := leaves(res.Structured)
	for _, text := range res.Texts {
		if raw := jsontext.Value(text); raw.IsValid() {
			values = append(values, leaves(raw)...)
		}
	}
	for _, l := range values {
		if l.kind != kindName && l.kind != jsontext.KindNull {
			s.add(l.text, sourceTool+name)
		}
	}
}

// bind is rule 4. Each condition closes a route: the path means JSON text can't forge an ID, the text
// check means a server can't bind what the model was not shown, the record limit means a listing binds
// nothing, and the control leaf means a data-only lookup like get_day_calendar_events(day) can't be
// steered into binding whatever it finds.
func (s *State) bind(tool policy.Tool, args map[string]jsontext.Value, res Result) {
	r := s.check(tool, args)
	if r.controls == 0 || slices.ContainsFunc(r.Findings, func(f Finding) bool { return f.Rule == RuleControl }) {
		return
	}
	records := 0
	path := strings.Split(strings.ReplaceAll(tool.Binds.Path, "[*]", ".[*]"), ".")
	values := walk(res.Structured, path, &records)
	if records > maxBoundRecords {
		return
	}
	text := fold(strings.Join(res.Texts, "\n"))
	for _, v := range values {
		if id := leaves(v); len(id) == 1 && (v.Kind() == jsontext.KindString || v.Kind() == jsontext.KindNumber) {
			if isASCII(id[0].text) && tokenIn(fold(id[0].text), text) {
				s.bound[tool.Binds.Kind+"\x00"+canon(id[0].text)] = true
			}
		}
	}
}

// walk follows a split binds path. Every element a [*] steps over counts as a record, whether or not
// it holds the field, so padding a result with records lacking an ID doesn't get it under the limit.
func walk(raw jsontext.Value, path []string, records *int) []jsontext.Value {
	if len(path) == 0 {
		return []jsontext.Value{raw}
	}
	var found []jsontext.Value
	if path[0] == "[*]" {
		var items []jsontext.Value
		json.Unmarshal(raw, &items) // anything but a list leaves this empty
		*records += len(items)
		for _, item := range items {
			found = append(found, walk(item, path[1:], records)...)
		}
		return found
	}
	var fields map[string]jsontext.Value
	json.Unmarshal(raw, &fields) // anything but an object leaves this empty
	if next, ok := fields[path[0]]; ok {
		found = walk(next, path[1:], records)
	}
	return found
}
