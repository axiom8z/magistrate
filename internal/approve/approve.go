// Package approve is what the person sees and what is remembered about their answers: the text of a
// question, the budget of questions per session, and the calls already refused. There is no "always
// allow". Holding the call and carrying the question over the wire is the front's job.
package approve

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/axiom8z/sayswho/internal/prov"
	"github.com/axiom8z/sayswho/internal/rpc"
)

// Timeout is how long a question stays open. It is not a measured value: long enough to come back to
// a terminal, and short enough that a held call does not outlast anyone's interest in it.
const Timeout = 10 * time.Minute

// How a question can end without an approval.
const (
	RuleDeclined  = "ask-declined"
	RuleCancelled = "ask-cancelled"
	RuleTimeout   = "ask-timeout"
	RuleMalformed = "ask-malformed"
	RuleNoDialog  = "ask-no-dialog"
)

// RuleApproved is logged on the forwarded call when a person said yes.
const RuleApproved = "ask-approved"

const (
	maxShownRunes  = 200 // of any one value, so a long one can't push the rest out of sight
	maxShownValues = 10
)

// ansiSequence is a terminal escape sequence, which goes whole so its parameters don't show as junk.
var ansiSequence = regexp.MustCompile("\x1b\\[[0-?]*[ -/]*[@-~]|\x1b\\][^\x07\x1b]*(?:\x07|\x1b\\\\)?")

// Budget counts a session's questions and remembers refused calls by digest. A digest stays marked
// from the moment its question goes out until a person approves, so anything else that ends the
// question is a refusal, and a burst of the same call can't open a stack of dialogs.
type Budget struct {
	mu      sync.Mutex
	left    int
	refused map[string]bool
}

// NewBudget returns a budget of asks questions.
func NewBudget(asks int) *Budget { return &Budget{left: asks, refused: map[string]bool{}} }

// State reports the questions left and whether this call has been refused.
func (b *Budget) State(digest string) (left int, refused bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.left, b.refused[digest]
}

// Begin spends one question on this call.
func (b *Budget) Begin(digest string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.left--
	b.refused[digest] = true
}

// Approved clears the mark. The next identical call is asked about again, since no answer is standing.
func (b *Budget) Approved(digest string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.refused, digest)
}

// Clean removes what could make a value look like something else on a terminal or in a dialog:
// control characters, ANSI sequences, and invisible format characters, which include every bidi
// control. Line and paragraph separators go too, so that a value can't fake a line of the question.
func Clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			return -1
		}
		return r
	}, ansiSequence.ReplaceAllString(strings.ToValidUTF8(s, ""), ""))
}

// shown prepares one value for the question. A value that is not plain ASCII gets a warning, because
// what is removed or looks alike may be the whole attack: "аlice" here can look just like the "alice"
// the person asked for.
func shown(value string) string {
	text := Clean(value)
	suspect := text != value || strings.ContainsFunc(value, func(r rune) bool { return r >= utf8.RuneSelf })
	if n := utf8.RuneCountInString(text); n > maxShownRunes {
		text = string([]rune(text)[:maxShownRunes]) + fmt.Sprintf("... (%d more characters)", n-maxShownRunes)
	}
	if suspect {
		text += " (WARNING: holds hidden or non-ASCII characters, so it may not be what it looks like)"
	}
	return text
}

// Prompt writes the question. All of its wording is ours, and values appear only through shown. In
// session mode there are no findings: the call is held because of when it came, not what it holds.
func Prompt(tool string, findings []prov.Finding, args map[string]jsontext.Value) string {
	var b strings.Builder
	fmt.Fprintf(&b, "SaysWho: %s wants to run.", Clean(tool))
	if len(findings) == 0 {
		b.WriteString(" Untrusted tool output has been read in this session, so any action needs your approval.")
	}
	for i, f := range findings {
		if i == maxShownValues {
			fmt.Fprintf(&b, "\n... and %d more values like these.", len(findings)-i)
			break
		}
		if f.Rule == prov.RuleSensitive { // the registry says only yes or no, so no value is named here
			b.WriteString("\nThis call holds a value from a tool labelled sensitive.")
			continue
		}
		fmt.Fprintf(&b, "\n%s: %s is not in your request; %s.", Clean(f.Arg), shown(f.Value), firstSeen(f))
	}
	b.WriteString("\n\nThe whole call:")
	for _, name := range slices.Sorted(maps.Keys(args)) {
		fmt.Fprintf(&b, "\n  %s = %s", Clean(name), shown(string(args[name])))
	}
	b.WriteString("\n\nApprove it only if you meant this. Tool output can look like instructions.")
	return b.String()
}

func firstSeen(f prov.Finding) string {
	if f.SeenIn == "" {
		return "not seen in any tool output"
	}
	return "first seen in " + Clean(f.SeenIn)
}

// Params is the elicitation/create request for a question. One required boolean, with no default, so
// that the person has to say yes.
func Params(message string) jsontext.Value {
	raw, _ := json.Marshal(map[string]any{ // cannot fail: these are plain strings and maps
		"mode":    "form",
		"message": message,
		"requestedSchema": map[string]any{
			"type":       "object",
			"properties": map[string]any{"approve": map[string]string{"type": "boolean", "title": "Approve this call"}},
			"required":   []string{"approve"},
		},
	})
	return raw
}

// Outcome reads the client's answer and returns the rule that refuses the call, or "" for the one
// answer that lets it through: an explicit accept holding approve as the JSON value true.
func Outcome(m *rpc.Message) string {
	var answer struct {
		Action  string `json:"action"`
		Content struct {
			Approve *bool `json:"approve"`
		} `json:"content"`
	}
	if m.Error != nil || json.Unmarshal(m.Result, &answer) != nil {
		return RuleMalformed
	}
	switch answer.Action {
	case "accept":
		switch {
		case answer.Content.Approve == nil:
			return RuleMalformed
		case *answer.Content.Approve:
			return ""
		}
		return RuleDeclined
	case "decline":
		return RuleDeclined
	case "cancel":
		return RuleCancelled
	}
	return RuleMalformed
}
