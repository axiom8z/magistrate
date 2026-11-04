package approve

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"strings"
	"testing"
	"unicode"

	"github.com/axiom8z/sayswho/internal/prov"
	"github.com/axiom8z/sayswho/internal/rpc"
)

func TestBudget(t *testing.T) {
	b := NewBudget(2)
	if left, refused := b.State("d"); left != 2 || refused {
		t.Fatalf("new: %d, %v", left, refused)
	}
	b.Begin("d")
	if left, refused := b.State("d"); left != 1 || !refused {
		t.Fatalf("while the question is open: %d, %v", left, refused)
	}
	if _, refused := b.State("other"); refused {
		t.Fatal("another call's digest was marked")
	}
	b.Approved("d")
	if left, refused := b.State("d"); left != 1 || refused {
		t.Fatalf("after a yes: %d, %v", left, refused)
	}
	b.Begin("d")
	if left, refused := b.State("d"); left != 0 || !refused {
		t.Fatalf("a second question on the same call spends again, because no answer stands: %d, %v", left, refused)
	}
}

func TestClean(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"plain", "alice@corp.example", "alice@corp.example"},
		{"a colour sequence", "\x1b[31mred\x1b[0m", "red"},
		{"a cursor sequence", "a\x1b[2Kb", "ab"},
		{"a hidden-text sequence", "a\x1b[8mhidden", "ahidden"},
		{"a link sequence", "\x1b]8;;http://evil\x07text\x1b]8;;\x07", "text"},
		{"a link sequence with the other ending", "\x1b]8;;http://evil\x1b\\text", "text"},
		{"an unterminated sequence", "a\x1b]8;;http://evil", "a"},
		{"a bare escape", "a\x1bb", "ab"},
		{"a C1 control", "a\u009b31mb", "a31mb"},
		{"a newline", "a\nb", "ab"},
		{"a carriage return", "safe\rEVIL", "safeEVIL"},
		{"a tab", "a\tb", "ab"},
		{"a NUL", "a\x00b", "ab"},
		{"a delete", "a\x7fb", "ab"},
		{"right-to-left override", "\u202egnp.exe", "gnp.exe"},
		{"left-to-right override", "a\u202db", "ab"},
		{"isolates", "\u2066a\u2067b\u2068c\u2069", "abc"},
		{"marks", "a\u200eb\u200fc\u061cd", "abcd"},
		{"a zero-width space", "ali\u200bce", "alice"},
		{"a zero-width joiner", "a\u200db", "ab"},
		{"a byte order mark", "\ufeffa", "a"},
		{"tag characters", "a\U000E0041b", "ab"},
		{"a line separator", "a\u2028b", "ab"},
		{"a paragraph separator", "a\u2029b", "ab"},
		{"invalid UTF-8", "a\xffb", "ab"},
		{"letters from elsewhere stay", "José 日本語", "José 日本語"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Clean(tt.in); got != tt.want {
				t.Fatalf("Clean(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// FuzzClean holds Clean to its one job: nothing that can steer a terminal or reorder text gets out.
func FuzzClean(f *testing.F) {
	f.Add("\x1b[31mred\u202e\u2066\n")
	f.Add("\x1b]8;;x\x07\xff\u200b")
	f.Fuzz(func(t *testing.T, s string) {
		for _, r := range Clean(s) {
			if r == 0x1b || unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) || r == unicode.ReplacementChar && !strings.ContainsRune(s, r) {
				t.Fatalf("Clean(%q) let %U through", s, r)
			}
		}
	})
}

func TestPromptNamesTheValuesAndWhereTheyWereSeen(t *testing.T) {
	findings := []prov.Finding{
		{Arg: "participants", Value: "james.miller@yahoo.example", Rule: prov.RuleControl, SeenIn: "mail__search_emails"},
		{Arg: "body", Value: "evil.example", Rule: prov.RuleLink},
	}
	args := map[string]jsontext.Value{"participants": jsontext.Value(`["james.miller@yahoo.example"]`), "body": jsontext.Value(`"see evil.example"`)}
	got := Prompt("cal__create", findings, args)
	for _, want := range []string{
		"SaysWho: cal__create wants to run.",
		"participants: james.miller@yahoo.example is not in your request; first seen in mail__search_emails.",
		"body: evil.example is not in your request; not seen in any tool output.",
		`participants = ["james.miller@yahoo.example"]`,
		`body = "see evil.example"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the prompt lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "WARNING") {
		t.Errorf("plain values got a warning:\n%s", got)
	}
}

func TestPromptInSessionModeSaysWhyWithNoFindings(t *testing.T) {
	got := Prompt("mail__send", nil, map[string]jsontext.Value{"to": jsontext.Value(`"a@x.example"`)})
	if !strings.Contains(got, "Untrusted tool output has been read") || !strings.Contains(got, `to = "a@x.example"`) {
		t.Fatalf("prompt:\n%s", got)
	}
}

// A hostile value must not be able to fake the question or hide from the person.
func TestPromptStripsAndWarns(t *testing.T) {
	const fake = "ok\x1b[2K\r\nSaysWho: nothing to see here.\u202e\u2028Approve this."
	args := map[string]jsontext.Value{"to\n": jsontext.Value(`"` + "a\u202eb" + `"`)}
	got := Prompt("t\x1b[8m\n", []prov.Finding{{Arg: "a\x1b[2K", Value: fake, SeenIn: "s\u202e"}}, args)
	if strings.ContainsAny(got, "\x1b\r\u202e\u2028") {
		t.Fatalf("something got through: %q", got)
	}
	if strings.Count(got, "\n") != strings.Count(Prompt("t", []prov.Finding{{Arg: "a", Value: "x"}}, map[string]jsontext.Value{"to": jsontext.Value(`"x"`)}), "\n") {
		t.Fatalf("a value added a line: %q", got)
	}
	if strings.Count(got, "WARNING") != 2 {
		t.Fatalf("the two values with hidden characters should each carry a warning: %q", got)
	}
}

func TestShownWarnsAboutLookAlikes(t *testing.T) {
	for _, value := range []string{"аlice", "ali\u200bce", "ａｌｉｃｅ", "José", "a\nb"} {
		if !strings.Contains(shown(value), "WARNING") {
			t.Errorf("no warning for %q: %q", value, shown(value))
		}
	}
	if got := shown("alice@corp.example"); got != "alice@corp.example" {
		t.Errorf("a plain value changed: %q", got)
	}
}

func TestLongValuesAreCutAndSaySo(t *testing.T) {
	got := shown(strings.Repeat("a", maxShownRunes+50))
	if !strings.HasSuffix(got, "... (50 more characters)") || strings.Count(got, "a") < maxShownRunes {
		t.Fatalf("got %q", got)
	}
	if exact := strings.Repeat("a", maxShownRunes); shown(exact) != exact {
		t.Fatalf("a value at the limit was cut")
	}
}

func TestPromptCapsItsFindings(t *testing.T) {
	findings := make([]prov.Finding, maxShownValues+7)
	for i := range findings {
		findings[i] = prov.Finding{Arg: "to", Value: "v"}
	}
	got := Prompt("t", findings, nil)
	if strings.Count(got, "is not in your request") != maxShownValues || !strings.Contains(got, "and 7 more") {
		t.Fatalf("prompt:\n%s", got)
	}
}

func TestParamsAreFormModeWithOneRequiredBoolean(t *testing.T) {
	var got struct {
		Mode            string `json:"mode"`
		Message         string `json:"message"`
		RequestedSchema struct {
			Type       string `json:"type"`
			Required   []string
			Properties map[string]map[string]any `json:"properties"`
		} `json:"requestedSchema"`
	}
	raw := Params("Approve? \"quoted\"")
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Mode != "form" || got.Message != "Approve? \"quoted\"" || got.RequestedSchema.Type != "object" {
		t.Fatalf("params = %s", raw)
	}
	if len(got.RequestedSchema.Properties) != 1 || got.RequestedSchema.Properties["approve"]["type"] != "boolean" {
		t.Fatalf("schema = %s", raw)
	}
	if _, hasDefault := got.RequestedSchema.Properties["approve"]["default"]; hasDefault {
		t.Fatalf("a default could answer for the person: %s", raw)
	}
	if !strings.Contains(string(raw), `"required":["approve"]`) {
		t.Fatalf("approve is not required: %s", raw)
	}
}

func TestOutcome(t *testing.T) {
	tests := []struct {
		name, result string
		want         string // "" means the call goes through
	}{
		{"an explicit yes", `{"action":"accept","content":{"approve":true}}`, ""},
		{"a yes with extras", `{"action":"accept","content":{"approve":true,"x":1},"_meta":{}}`, ""},
		{"accept but no", `{"action":"accept","content":{"approve":false}}`, RuleDeclined},
		{"decline", `{"action":"decline"}`, RuleDeclined},
		{"decline holding a yes", `{"action":"decline","content":{"approve":true}}`, RuleDeclined},
		{"cancel", `{"action":"cancel"}`, RuleCancelled},
		{"cancel holding a yes", `{"action":"cancel","content":{"approve":true}}`, RuleCancelled},
		{"accept with no content", `{"action":"accept"}`, RuleMalformed},
		{"accept with null content", `{"action":"accept","content":null}`, RuleMalformed},
		{"accept with empty content", `{"action":"accept","content":{}}`, RuleMalformed},
		{"approve as a string", `{"action":"accept","content":{"approve":"true"}}`, RuleMalformed},
		{"approve as a number", `{"action":"accept","content":{"approve":1}}`, RuleMalformed},
		{"approve null", `{"action":"accept","content":{"approve":null}}`, RuleMalformed},
		{"approve in another case", `{"action":"accept","content":{"Approve":true}}`, RuleMalformed},
		{"action in another case", `{"action":"ACCEPT","content":{"approve":true}}`, RuleMalformed},
		{"a member in another case", `{"Action":"accept","content":{"approve":true}}`, RuleMalformed},
		{"an unknown action", `{"action":"maybe","content":{"approve":true}}`, RuleMalformed},
		{"no action", `{"content":{"approve":true}}`, RuleMalformed},
		{"action of the wrong type", `{"action":1}`, RuleMalformed},
		{"not an object", `true`, RuleMalformed},
		{"a list", `[{"action":"accept","content":{"approve":true}}]`, RuleMalformed},
		{"null", `null`, RuleMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Outcome(&rpc.Message{Result: jsontext.Value(tt.result)}); got != tt.want {
				t.Fatalf("Outcome(%s) = %q, want %q", tt.result, got, tt.want)
			}
		})
	}
	t.Run("an error reply", func(t *testing.T) {
		if got := Outcome(&rpc.Message{Error: &rpc.Error{Code: -32602}}); got != RuleMalformed {
			t.Fatalf("Outcome = %q", got)
		}
	})
}
