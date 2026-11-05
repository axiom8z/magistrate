package prov

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"math/rand/v2"
	"net/url"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/axiom8z/magistrate/internal/policy"
)

func argsOf(t *testing.T, raw string) map[string]jsontext.Value {
	t.Helper()
	var args map[string]jsontext.Value
	if err := json.Unmarshal([]byte(raw), &args); err != nil {
		t.Fatalf("bad test arguments %s: %v", raw, err)
	}
	return args
}

// rules lists a report's findings as "arg:rule", which is what most tests compare.
func rules(r Report) []string {
	got := []string{}
	for _, f := range r.Findings {
		got = append(got, f.Arg+":"+f.Rule)
	}
	return got
}

func TestPromptMatching(t *testing.T) {
	tests := []struct {
		name, prompt, value string
		want                bool
	}{
		// Whole token.
		{"a plain word", "email alice now", "alice", true},
		{"at the very start", "alice is here", "alice", true},
		{"at the very end", "email alice", "alice", true},
		{"the whole prompt", "alice", "alice", true},
		{"case folds one way", "email ALICE", "alice", true},
		{"case folds the other way", "email alice", "ALICE", true},
		{"a letter before", "email malice", "alice", false},
		{"a letter after", "email alices", "alice", false},
		{"a digit before", "email 2alice", "alice", false},
		{"a digit after", "email alice2", "alice", false},
		{"an underscore before", "email _alice", "alice", false},
		{"an underscore after", "email alice_", "alice", false},
		{"an at sign before", "email x@alice", "alice", false},
		{"an at sign after", "email alice@x.com", "alice", false},
		{"a hyphen before", "email x-alice", "alice", false},
		{"a hyphen after", "email alice-x", "alice", false},
		{"a dot before", "email evil.alice", "alice", false},
		{"a dot after, ending a sentence", "email alice.", "alice", true},
		{"a comma after", "email alice, please", "alice", true},
		{"quotes round it", `email "alice"`, "alice", true},
		{"brackets round it", "email (alice)", "alice", true},
		{"curly quotes round it", "email “alice”", "alice", true},
		{"a non-ASCII letter beside it", "email éalice", "alice", false},
		{"a combining mark after it", "email alicé", "alice", false},
		{"a later occurrence counts when the first is glued", "malice and alice", "alice", true},
		{"a host in a longer host", "see evil.x.com", "x.com", false},
		{"a longer host from a shorter one", "see x.com", "evil.x.com", false},
		{"an address whose domain is named", "mail bob@x.com", "x.com", false},
		{"the whole address", "mail bob@x.com.", "bob@x.com", true},
		// Phrases.
		{"multi-word as one phrase", "meet Mark Black today", "mark black", true},
		{"multi-word in the wrong order", "meet Black Mark today", "mark black", false},
		{"multi-word with a word between", "meet Mark J Black today", "mark black", false},
		{"multi-word split across a line", "meet Mark\nBlack today", "mark black", false},
		// Length limits.
		{"June 13 cannot authorise 13", "the meeting on June 13", "13", false},
		{"four digits are too few", "room 1234 please", "1234", false},
		{"five digits are enough", "account 12345 please", "12345", true},
		{"digits inside a longer number", "account 123456 please", "12345", false},
		{"punctuation does not make 13 long enough", "the meeting on June 13.", "13.", false},
		{"nor a bracket", "the meeting (June 13)", "(13)", false},
		{"nor a scheme", "the meeting on June 13", "https://13", false},
		{"the or route", "at 10:00 or at 16:00", "or", false},
		{"two letters are too few", "at home", "at", false},
		{"punctuation does not make or long enough", "this or.", "or.", false},
		{"three letters are enough", "the fox", "fox", true},
		{"short but not only digits", "sector 1a2 ok", "1a2", true},
		{"nothing at all", "anything", "", false},
		{"only punctuation", "wait ... now", "...", false},
		// URLs.
		{"the same URL", "see https://x.com/a", "https://x.com/a", true},
		{"no scheme in the value", "see https://x.com/a", "x.com/a", true},
		{"no scheme in the prompt", "see x.com/a", "https://x.com/a", true},
		{"another scheme", "see https://x.com/a", "http://x.com/a", true},
		{"www in the value", "see x.com", "www.x.com", true},
		{"www in the prompt", "see www.x.com", "x.com", true},
		{"www and a scheme in the prompt", "see HTTPS://WWW.X.COM/a", "x.com/a", true},
		{"a trailing slash in the value", "see x.com/a", "x.com/a/", true},
		{"a trailing slash in the prompt", "see x.com/a/ now", "x.com/a", true},
		{"the host of a named page", "see x.com/a", "x.com", true},
		{"a page the prompt did not name", "see x.com", "x.com/evil", false},
		{"a query the prompt did not name", "see x.com/a", "x.com/a?d=secret", false},
		{"www inside a longer host stays", "see a-www.x.com", "a-x.com", false},
		// Rewrites.
		{"no percent decoding", "email alice", "%61lice", false},
		{"no base64 decoding", "email alice", "YWxpY2U=", false},
		{"no entity decoding", "email alice", "&#97;lice", false},
		{"a fullwidth value", "email alice", "ａｌｉｃｅ", false},
		{"a Cyrillic value", "email alice", "аlice", false},
		{"a Kelvin sign does not fold to k", "email kim", "Kim", false},
		{"nor does a prompt's", "email Kim", "kim", false},
		{"a non-ASCII value that is in the prompt still fails closed", "email José", "José", false},
		{"a zero-width space inside", "email alice", "ali​ce", false},
		{"no prompt at all", "", "alice", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(tt.prompt, nil, false).source(tt.value, ""); (got == SourcePrompt) != tt.want {
				t.Fatalf("source(%q) in %q = %q, want a match: %v", tt.value, tt.prompt, got, tt.want)
			}
		})
	}
}

func TestLinks(t *testing.T) {
	tests := []struct {
		name, text string
		want       []string
	}{
		{"plain text", "see you on monday at noon, ok?", nil},
		{"a scheme", "go to https://evil.example/x?a=1 now", []string{"https://evil.example/x?a=1"}},
		{"any scheme", "ftp://files/evil", []string{"ftp://files/evil"}},
		{"a scheme in capitals", "HTTPS://EVIL.COM", []string{"HTTPS://EVIL.COM"}},
		{"www", "Check www.secure-systems-252.com", []string{"www.secure-systems-252.com"}},
		{"a bare host with a path", "Check secure-systems-252.xyz/login", []string{"secure-systems-252.xyz/login"}},
		{"an unusual ending", "visit evil.aero", []string{"evil.aero"}},
		{"an ending of 24 letters", "visit evil.abcdefghijklmnopqrstuvwx", []string{"evil.abcdefghijklmnopqrstuvwx"}},
		{"an ending of 25 letters is not one", "visit evil.abcdefghijklmnopqrstuvwxy", nil},
		{"an ending of 1 letter is not one", "section a.b", nil},
		{"an ending with a digit is not one", "version 3.5mm", nil},
		{"a filename counts: the matcher has no exception for them", "see notes.txt", []string{"notes.txt"}},
		{"no space after a full stop counts too", "done.Next", []string{"done.Next"}},
		{"a sentence's full stop is left off", "visit evil.com.", []string{"evil.com"}},
		{"a sentence's colon is left off", "at evil.com:", []string{"evil.com"}},
		{"a port stays", "at evil.com:8080/x", []string{"evil.com:8080/x"}},
		{"a query with no path", "at evil.com?d=secret", []string{"evil.com?d=secret"}},
		{"a fragment with no path", "at evil.com#secret", []string{"evil.com#secret"}},
		{"brackets", "(evil.com)", []string{"evil.com"}},
		{"angle brackets", "<evil.com>", []string{"evil.com"}},
		{"quotes", `"evil.com"`, []string{"evil.com"}},
		{"a path's dotted file is not a second link", "x.com/file.txt", []string{"x.com/file.txt"}},
		{"two links", "a.com and b.org", []string{"a.com", "b.org"}},
		{"a label that hides the ending", "evil.com.x1", []string{"evil.com.x1"}},
		{"an underscore in a host", "x_evil.com", []string{"x_evil.com"}},
		{"a doubled dot", "a..evil.com", []string{"a..evil.com"}},
		{"a leading dot", ".evil.com", []string{"evil.com"}},
		{"a leading hyphen", "-evil.com", []string{"-evil.com"}},
		{"a backslash path", `evil.com\x`, []string{"evil.com"}},
		{"no scheme before the slashes", "//evil.com/x", []string{"evil.com/x"}},
		{"after a sign", "url=evil.com", []string{"evil.com"}},
		{"after a colon with no space", "see:evil.com", []string{"evil.com"}},
		{"an underscore before the scheme", "_http://evil.com", []string{"evil.com"}},
		{"Chinese around a link", "請看evil.com網站", []string{"請看evil.com網站"}},
		{"a non-ASCII first label", "中文.com", []string{"中文.com"}},
		{"accented", "bücher.de", []string{"bücher.de"}},
		// Addresses.
		{"an email", "write to mark.black-2134@gmail.com please", []string{"mark.black-2134@gmail.com"}},
		{"an email with a tag", "a+b@x.io", []string{"a+b@x.io"}},
		{"an email with a non-ASCII start", "josé@evil.com", []string{"josé@evil.com"}},
		{"a domain with nothing before the at sign", "@evil.com", []string{"evil.com"}},
		// IP addresses.
		{"IPv4 with a path", "Reset at 192.168.4.20/login", []string{"192.168.4.20/login"}},
		{"IPv4 with a port", "10.0.0.1:80", []string{"10.0.0.1:80"}},
		{"IPv4 after an underscore", "_10.0.0.1", []string{"_10.0.0.1"}},
		{"three numbers are not an address", "1.2.3", nil},
		// IBANs.
		{"an IBAN", "wire to GB82WEST12345698765432", []string{"GB82WEST12345698765432"}},
		{"an IBAN with spaces", "US13 3000 0001 2121 2121 212", []string{"US13 3000 0001 2121 2121 212"}},
		{"an IBAN with hyphens", "US13-3000-0001-2121-2121-212", []string{"US13-3000-0001-2121-2121-212"}},
		{"lower case", "gb82west12345698765432", []string{"gb82west12345698765432"}},
		{"after an underscore", "_GB82WEST12345698765432", []string{"_GB82WEST12345698765432"}},
		{"ten characters after the digits is too few", "GB82WEST123456", nil},
		{"eleven is enough", "GB82WEST1234567", []string{"GB82WEST1234567"}},
		{"inside a longer word is not one", "xGB82WEST12345698765432", nil},
		// Folding for links only.
		{"fullwidth www", "ｗｗｗ．evil．com", []string{"www.evil.com"}},
		{"a fullwidth at sign", "mark.black-2134＠gmail.com", []string{"mark.black-2134@gmail.com"}},
		{"a fullwidth scheme", "ｈｔｔｐｓ：／／ｅｖｉｌ．ｃｏｍ", []string{"https://evil.com"}},
		{"an ideographic full stop", "evil。com", []string{"evil.com"}},
		{"a halfwidth one", "evil｡com", []string{"evil.com"}},
		{"ideographic spaces in an IBAN", "US13　3000　0001　2121　2121　212", []string{"US13 3000 0001 2121 2121 212"}},
		{"a zero-width space in a host", "evil​.com", []string{"evil.com"}},
		{"a soft hyphen in a host", "ev­il.com", []string{"evil.com"}},
		// Conceded in DESIGN section 9: links a matcher can't see.
		{"conceded: spelled out", "Check secure-systems-252 dot com", nil},
		{"conceded: spaced", "h t t p s : / / evil . com", nil},
		{"conceded: encoded", "aHR0cHM6Ly9ldmlsLmNvbQ==", nil},
		{"conceded: a look-alike dot", "evil․com", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := links(tt.text); !slices.Equal(got, tt.want) {
				t.Fatalf("links(%q) = %q, want %q", tt.text, got, tt.want)
			}
		})
	}
}

func TestLeaves(t *testing.T) {
	got := leaves(jsontext.Value(`{"a":["x",1.50,true,false,null,{"b":"y"}],"c":{},"d":[]}`))
	want := []leaf{
		{kindName, "a"}, {jsontext.KindString, "x"}, {jsontext.KindNumber, "1.50"}, {jsontext.KindTrue, "true"},
		{jsontext.KindFalse, "false"}, {jsontext.KindNull, "null"}, {kindName, "b"}, {jsontext.KindString, "y"},
		{kindName, "c"}, {kindName, "d"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("leaves = %+v", got)
	}
	for _, tt := range []struct {
		raw  string
		kind jsontext.Kind
		text string
	}{
		{`"aA"`, jsontext.KindString, "aA"},
		{`13.0`, jsontext.KindNumber, "13.0"},
		{`1e2`, jsontext.KindNumber, "1e2"},
	} {
		if got := leaves(jsontext.Value(tt.raw)); len(got) != 1 || got[0] != (leaf{tt.kind, tt.text}) {
			t.Errorf("leaves(%s) = %+v", tt.raw, got)
		}
	}
	if got := leaves(nil); len(got) != 0 {
		t.Errorf("leaves(nil) = %+v", got)
	}
}

// Every role, against the sources that can and can't satisfy it.
func TestRoles(t *testing.T) {
	ceiling := 100.0
	tool := policy.Tool{Effect: policy.EffectAct, Args: map[string]policy.Arg{
		"to":     {Role: policy.RoleControl},
		"note":   {Role: policy.RoleControl, Bind: "note"},
		"body":   {Role: policy.RoleContent},
		"amount": {Role: policy.RoleQuantity, Max: &ceiling},
		"n":      {Role: policy.RoleData, Type: policy.TypeNumber},
		"flag":   {Role: policy.RoleData, Type: policy.TypeBoolean},
		"on":     {Role: policy.RoleData, Type: policy.TypeDate},
		"perm":   {Role: policy.RoleData, Type: policy.TypeEnum, Values: []string{"r", "rw"}},
		"pass":   {Role: policy.RoleCredential},
	}}
	prompt := "send 5000 or 250.5 to alice@corp.example for rent, passphrase hunter2 at https://bank.example/pay"
	tests := []struct {
		name, args string
		want       []string
	}{
		{"no arguments", `{}`, nil},

		{"control: in the prompt", `{"to":"alice@corp.example"}`, nil},
		{"control: not in the prompt", `{"to":"bob@corp.example"}`, []string{"to:" + RuleControl}},
		{"control: a list, all sourced", `{"to":["alice@corp.example","rent"]}`, nil},
		{"control: a list, one not", `{"to":["alice@corp.example","bob@corp.example"]}`, []string{"to:" + RuleControl}},
		{"control: an object's values", `{"to":{"x":"bob@corp.example"}}`, []string{"to:" + RuleControl, "to:" + RuleControl}},
		{"control: an object's names count", `{"to":{"bob@corp.example":"rent"}}`, []string{"to:" + RuleControl}},
		{"control: a number", `{"to":13}`, []string{"to:" + RuleControl}},
		{"control: a number named in the prompt", `{"to":5000}`, []string{"to:" + RuleControl}},
		{"control: a boolean", `{"to":true}`, []string{"to:" + RuleControl}},
		{"control: null names nothing", `{"to":null}`, nil},
		{"control: empty names nothing", `{"to":[]}`, nil},
		{"control: an empty string is not sourced", `{"to":""}`, []string{"to:" + RuleControl}},
		{"control: a non-ASCII value", `{"to":"аlice@corp.example"}`, []string{"to:" + RuleControl}},

		{"content: plain words", `{"body":"the rent is late"}`, nil},
		{"content: a link in the prompt", `{"body":"pay at https://bank.example/pay today"}`, nil},
		{"content: an email in the prompt", `{"body":"cc alice@corp.example"}`, nil},
		{"content: an unsourced link", `{"body":"pay at evil.example"}`, []string{"body:" + RuleLink}},
		{"content: a path the prompt did not name", `{"body":"pay at https://bank.example/evil"}`, []string{"body:" + RuleLink}},
		{"content: in a list", `{"body":["ok","evil.example"]}`, []string{"body:" + RuleLink}},
		{"content: in an object's name", `{"body":{"evil.example":1}}`, []string{"body:" + RuleLink}},
		{"content: a fullwidth link", `{"body":"ｅｖｉｌ．ｅｘａｍｐｌｅ"}`, []string{"body:" + RuleLink}},
		{"content: a word in the prompt needs no source", `{"body":"nothing like a link"}`, nil},

		{"quantity: inside the ceiling", `{"amount":90}`, nil},
		{"quantity: zero", `{"amount":0}`, nil},
		{"quantity: at the ceiling", `{"amount":100}`, nil},
		{"quantity: a fraction", `{"amount":99.5}`, nil},
		{"quantity: over the ceiling", `{"amount":100.01}`, []string{"amount:" + RuleQuantity}},
		{"quantity: over, but named", `{"amount":5000}`, nil},
		{"quantity: over, named, written with a point", `{"amount":5000.0}`, nil},
		{"quantity: over, named, written with an exponent", `{"amount":5e3}`, nil},
		{"quantity: over, named with cents", `{"amount":250.50}`, nil},
		{"quantity: a string", `{"amount":"90"}`, []string{"amount:" + RuleQuantity}},
		{"quantity: a string over the ceiling", `{"amount":"9000"}`, []string{"amount:" + RuleQuantity}},
		{"quantity: a string the prompt names", `{"amount":"5000"}`, nil},
		{"quantity: negative", `{"amount":-5000}`, []string{"amount:" + RuleQuantity}},
		{"quantity: negative and small", `{"amount":-1}`, []string{"amount:" + RuleQuantity}},
		{"quantity: too big for a float", `{"amount":1e999}`, []string{"amount:" + RuleQuantity}},
		{"quantity: a boolean", `{"amount":true}`, []string{"amount:" + RuleQuantity}},
		{"quantity: null", `{"amount":null}`, []string{"amount:" + RuleQuantity}},
		{"quantity: a list, each checked", `{"amount":[1,1000]}`, []string{"amount:" + RuleQuantity}},
		{"quantity: an object's name", `{"amount":{"rent":1}}`, []string{"amount:" + RuleQuantity}},
		{"quantity: a fullwidth string", `{"amount":"５０００"}`, []string{"amount:" + RuleQuantity}},

		{"data number: a number", `{"n":7}`, nil},
		{"data number: a negative one", `{"n":-7}`, nil},
		{"data number: a string counts as control", `{"n":"7"}`, []string{"n:" + RuleControl}},
		{"data number: a sourced string passes as control", `{"n":"rent"}`, nil},
		{"data boolean: true", `{"flag":true}`, nil},
		{"data boolean: false", `{"flag":false}`, nil},
		{"data boolean: a string counts as control", `{"flag":"true"}`, []string{"flag:" + RuleControl}},
		{"data date: a day", `{"on":"2024-01-01"}`, nil},
		{"data date: a time", `{"on":"2024-01-01 10:30"}`, nil},
		{"data date: seconds", `{"on":"2024-01-01T10:30:59"}`, nil},
		{"data date: a zone", `{"on":"2024-01-01T10:30:59Z"}`, nil},
		{"data date: an offset", `{"on":"2024-01-01T10:30:59+02:00"}`, nil},
		{"data date: a smuggled value", `{"on":"see evil.com/x?d=secret"}`, []string{"on:" + RuleControl}},
		{"data date: a date with more after it", `{"on":"2024-01-01 evil.com"}`, []string{"on:" + RuleControl}},
		{"data date: a line after it", "{\"on\":\"2024-01-01\\n\"}", []string{"on:" + RuleControl}},
		{"data date: a number", `{"on":20240101}`, []string{"on:" + RuleControl}},
		{"data enum: listed", `{"perm":"rw"}`, nil},
		{"data enum: in another case", `{"perm":"RW"}`, []string{"perm:" + RuleControl}},
		{"data enum: not listed", `{"perm":"admin"}`, []string{"perm:" + RuleControl}},
		{"data: an object's name counts as control", `{"n":{"evil":1}}`, []string{"n:" + RuleControl}},
		{"data: null names nothing", `{"n":null}`, nil},

		{"credential: in the prompt", `{"pass":"hunter2"}`, nil},
		{"credential: not in the prompt", `{"pass":"letmein"}`, []string{"pass:" + RuleCredential}},
		{"credential: an empty one is refused, not skipped", `{"pass":""}`, []string{"pass:" + RuleCredential}},
		{"credential: null names nothing", `{"pass":null}`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rules(New(prompt, nil, true).Check(tool, argsOf(t, tt.args)))
			if !slices.Equal(got, append([]string{}, tt.want...)) {
				t.Fatalf("findings = %q, want %q", got, tt.want)
			}
		})
	}
}

// A credential comes from the prompt alone, whatever else vouches for the same value.
func TestCredentialIgnoresEverySourceButThePrompt(t *testing.T) {
	tool := policy.Tool{Effect: policy.EffectAct, Args: map[string]policy.Arg{"pass": {Role: policy.RoleCredential}}}
	s := New("no secrets here", []string{"hunter2"}, false)
	s.Observe("t", policy.Tool{Output: policy.OutputTrusted}, nil, Result{Structured: jsontext.Value(`{"a":"hunter2"}`)})
	s.AddArguments(argsOf(t, `{"x":"hunter2"}`))
	if got := rules(s.Check(tool, argsOf(t, `{"pass":"hunter2"}`))); len(got) != 1 {
		t.Fatalf("findings = %q", got)
	}
}

func TestReportNamesItsSourcesAndNoValues(t *testing.T) {
	tool := policy.Tool{Effect: policy.EffectAct, Args: map[string]policy.Arg{
		"a": {Role: policy.RoleControl}, "b": {Role: policy.RoleControl}, "c": {Role: policy.RoleControl},
		"d": {Role: policy.RoleContent}, "e": {Role: policy.RoleControl, Bind: "note"}}}
	s := New("email alice-canary", []string{"op-canary"}, true)
	s.Observe("dir__who", policy.Tool{Output: policy.OutputTrusted}, nil, Result{Structured: jsontext.Value(`{"a":"tool-canary"}`)})
	s.bound["note\x00bound-canary"] = true
	r := s.Check(tool, argsOf(t, `{"a":"alice-canary","b":"op-canary","c":"tool-canary","d":"see alice-canary.example.com","e":"bound-canary"}`))
	want := []string{"bound:note", "prompt", "tool:dir__who", "trusted_values"}
	if len(r.Findings) != 1 || !slices.Equal(r.Sources, want) {
		t.Fatalf("report = %+v", r)
	}
	if strings.Contains(strings.Join(r.Sources, " "), "canary") {
		t.Fatalf("a value got into the sources: %q", r.Sources)
	}
}

func TestTrustedValues(t *testing.T) {
	s := New("", []string{"Ops@Corp.Example", "https://www.status.example/", "42"}, false)
	for _, tt := range []struct {
		value string
		want  bool
	}{
		{"ops@corp.example", true},
		{"OPS@CORP.EXAMPLE", true},
		{"status.example", true},
		{"http://status.example", true},
		{"42", true}, // the limits are for words found in free text; the operator listed this one whole
		{"ops", false},
		{"corp.example", false},
		{"4", false},
	} {
		if got := s.source(tt.value, ""); (got == SourceOperator) != tt.want {
			t.Errorf("source(%q) = %q", tt.value, got)
		}
	}
}

func observeTrusted(s *State, res Result) {
	s.Observe("dir__who", policy.Tool{Effect: policy.EffectRead, Output: policy.OutputTrusted}, nil, res)
}

func TestTrustedToolIsWholeLeafEquality(t *testing.T) {
	tests := []struct {
		name  string
		res   Result
		value string
		want  bool
	}{
		{"a structured leaf", Result{Structured: jsontext.Value(`{"email":"a@x.example"}`)}, "a@x.example", true},
		{"nested", Result{Structured: jsontext.Value(`{"r":[{"e":["a@x.example"]}]}`)}, "a@x.example", true},
		{"case folded", Result{Structured: jsontext.Value(`{"e":"A@X.example"}`)}, "a@x.example", true},
		{"a number, as written", Result{Structured: jsontext.Value(`{"n":13}`)}, "13", true},
		{"a JSON text leaf", Result{Texts: []string{`{"email":"a@x.example"}`}}, "a@x.example", true},
		{"a JSON string as text", Result{Texts: []string{`"a@x.example"`}}, "a@x.example", true},
		{"either text block", Result{Texts: []string{"not json", `["a@x.example"]`}}, "a@x.example", true},
		{"both, disagreeing: structured", Result{Texts: []string{`{"e":"t@x.example"}`}, Structured: jsontext.Value(`{"e":"s@x.example"}`)}, "s@x.example", true},
		{"both, disagreeing: text", Result{Texts: []string{`{"e":"t@x.example"}`}, Structured: jsontext.Value(`{"e":"s@x.example"}`)}, "t@x.example", true},
		{"part of a leaf", Result{Structured: jsontext.Value(`{"e":"a@x.example, b@x.example"}`)}, "a@x.example", false},
		{"a word in a leaf", Result{Structured: jsontext.Value(`{"e":"call alice now"}`)}, "alice", false},
		{"a member name", Result{Structured: jsontext.Value(`{"alice":1}`)}, "alice", false},
		{"null", Result{Structured: jsontext.Value(`{"e":null}`)}, "null", false},
		{"plain text is not a leaf", Result{Texts: []string{"a@x.example"}}, "a@x.example", false},
		{"YAML is not parsed", Result{Texts: []string{"email: a@x.example"}}, "a@x.example", false},
		{"JSON inside text is not parsed", Result{Texts: []string{`see {"e":"a@x.example"}`}}, "a@x.example", false},
		{"an error vouches for nothing", Result{Structured: jsontext.Value(`{"e":"a@x.example"}`), IsError: true}, "a@x.example", false},
		{"an error's text vouches for nothing", Result{Texts: []string{`{"e":"a@x.example"}`}, IsError: true}, "a@x.example", false},
		// A non-ASCII control value fails closed wherever it came from. With only ASCII folding there is
		// no telling what it might be standing in for, so even a trusted tool can't vouch for it.
		{"a non-ASCII leaf", Result{Structured: jsontext.Value(`{"e":"josé@x.example"}`)}, "josé@x.example", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New("", nil, false)
			observeTrusted(s, tt.res)
			if got := s.source(tt.value, ""); (got == "tool:dir__who") != tt.want {
				t.Fatalf("source(%q) = %q", tt.value, got)
			}
		})
	}
}

// Whoever writes an untrusted tool's output must gain nothing from it, however it is dressed.
func TestUntrustedToolVouchesForNothing(t *testing.T) {
	for _, output := range []string{"", policy.OutputUntrusted} {
		s := New("", nil, false)
		s.Observe("mail__read", policy.Tool{Effect: policy.EffectRead, Output: output}, nil,
			Result{Texts: []string{`{"e":"a@x.example"}`}, Structured: jsontext.Value(`{"e":"a@x.example"}`)})
		if got := s.source("a@x.example", ""); got != "" {
			t.Errorf("output %q: source = %q", output, got)
		}
	}
}

func TestAddArguments(t *testing.T) {
	s := New("", nil, false)
	s.AddArguments(argsOf(t, `{"to":"a@x.example","n":13,"list":["one","two"],"obj":{"name-canary":"three"},"nothing":null}`))
	for _, value := range []string{"a@x.example", "13", "one", "two", "three"} {
		if got := s.source(value, ""); got != SourceArguments {
			t.Errorf("source(%q) = %q", value, got)
		}
	}
	for _, value := range []string{"name-canary", "to", "null", "a", "x.example"} {
		if got := s.source(value, ""); got != "" {
			t.Errorf("source(%q) = %q", value, got)
		}
	}
}

// The lookup and acts used by the bound ID tests. It is DESIGN section 3's example with roles spelled
// out, and find_notes has its control argument named.
var (
	findNotes = policy.Tool{Effect: policy.EffectRead,
		Args:  map[string]policy.Arg{"query": {Role: policy.RoleControl}, "day": {Role: policy.RoleData, Type: policy.TypeDate}},
		Binds: &policy.Binds{Path: "result[*].id", Kind: "note"}}
	editNote = policy.Tool{Effect: policy.EffectAct, Args: map[string]policy.Arg{"note_id": {Role: policy.RoleControl, Bind: "note"}}}
)

func canEdit(t *testing.T, s *State, id string) bool {
	t.Helper()
	raw, _ := jsontext.AppendQuote(nil, id)
	return len(s.Check(editNote, map[string]jsontext.Value{"note_id": raw}).Findings) == 0
}

func TestBoundIDs(t *testing.T) {
	const prompt = "find my vacation plans"
	result := func(ids ...string) Result {
		return Result{Texts: []string{"notes " + strings.Join(ids, " ")}, Structured: jsontext.Value(`{"result":[{"id":"` + strings.Join(ids, `"},{"id":"`) + `"}]}`)}
	}
	tests := []struct {
		name     string
		boundIDs bool
		tool     policy.Tool
		args     string
		res      Result
		id       string
		want     bool
	}{
		{"a path value in the text, from a sourced lookup", true, findNotes, `{"query":"vacation plans"}`, result("n-7"), "n-7", true},
		{"three records", true, findNotes, `{"query":"vacation plans"}`, result("n-1", "n-2", "n-3"), "n-3", true},
		{"four records bind nothing", true, findNotes, `{"query":"vacation plans"}`, result("n-1", "n-2", "n-3", "n-4"), "n-1", false},
		{"records with no ID still count", true, findNotes, `{"query":"vacation plans"}`,
			Result{Texts: []string{"n-1"}, Structured: jsontext.Value(`{"result":[{"id":"n-1"},{},{},{}]}`)}, "n-1", false},
		{"a numeric ID", true, findNotes, `{"query":"vacation plans"}`,
			Result{Texts: []string{"note 13."}, Structured: jsontext.Value(`{"result":[{"id":13}]}`)}, "13", true},
		{"bound IDs turned off", false, findNotes, `{"query":"vacation plans"}`, result("n-7"), "n-7", false},
		{"not in the text", true, findNotes, `{"query":"vacation plans"}`,
			Result{Texts: []string{"no notes"}, Structured: jsontext.Value(`{"result":[{"id":"n-7"}]}`)}, "n-7", false},
		{"only part of a longer token in the text", true, findNotes, `{"query":"vacation plans"}`,
			Result{Texts: []string{"xn-7y"}, Structured: jsontext.Value(`{"result":[{"id":"n-7"}]}`)}, "n-7", false},
		{"JSON text can't forge one", true, findNotes, `{"query":"vacation plans"}`,
			Result{Texts: []string{`{"result":[{"id":"n-7"}]}`}}, "n-7", false},
		{"in the text but at another path", true, findNotes, `{"query":"vacation plans"}`,
			Result{Texts: []string{"n-7"}, Structured: jsontext.Value(`{"result":[{"owner":"n-7"}]}`)}, "n-7", false},
		{"an object at the path", true, findNotes, `{"query":"vacation plans"}`,
			Result{Texts: []string{"n-7"}, Structured: jsontext.Value(`{"result":[{"id":{"n-7":"n-7"}}]}`)}, "n-7", false},
		{"a list at the path", true, findNotes, `{"query":"vacation plans"}`,
			Result{Texts: []string{"n-7"}, Structured: jsontext.Value(`{"result":[{"id":["n-7"]}]}`)}, "n-7", false},
		{"a boolean at the path", true, findNotes, `{"query":"vacation plans"}`,
			Result{Texts: []string{"true"}, Structured: jsontext.Value(`{"result":[{"id":true}]}`)}, "true", false},
		{"a non-ASCII ID", true, findNotes, `{"query":"vacation plans"}`,
			Result{Texts: []string{"nöte"}, Structured: jsontext.Value(`{"result":[{"id":"nöte"}]}`)}, "nöte", false},
		{"an error result", true, findNotes, `{"query":"vacation plans"}`,
			Result{Texts: []string{"n-7"}, Structured: jsontext.Value(`{"result":[{"id":"n-7"}]}`), IsError: true}, "n-7", false},
		{"no structured content", true, findNotes, `{"query":"vacation plans"}`, Result{Texts: []string{"n-7"}}, "n-7", false},
		{"a lookup with an unsourced control leaf", true, findNotes, `{"query":"secrets"}`, result("n-7"), "n-7", false},
		{"one sourced leaf and one not", true, findNotes, `{"query":["vacation plans","secrets"]}`, result("n-7"), "n-7", false},
		{"a data-only lookup binds nothing", true, findNotes, `{"day":"2024-05-20"}`, result("n-7"), "n-7", false},
		{"no arguments binds nothing", true, findNotes, `{}`, result("n-7"), "n-7", false},
		{"null is not a control leaf", true, findNotes, `{"query":null}`, result("n-7"), "n-7", false},
		{"data out of type counts as control, and fails", true, findNotes, `{"query":"vacation plans","day":"soon"}`, result("n-7"), "n-7", false},
		{"data in type does no harm", true, findNotes, `{"query":"vacation plans","day":"2024-05-20"}`, result("n-7"), "n-7", true},
		{"the two-letter route", true, findNotes, `{"query":"my"}`, result("n-7"), "n-7", false},
		{"a read with no args block: every leaf counts as control", true,
			policy.Tool{Effect: policy.EffectRead, Binds: findNotes.Binds}, `{"x":"vacation plans"}`, result("n-7"), "n-7", true},
		{"a read with no args block and an unsourced leaf", true,
			policy.Tool{Effect: policy.EffectRead, Binds: findNotes.Binds}, `{"x":"secrets"}`, result("n-7"), "n-7", false},
		{"a path with no wildcard", true,
			policy.Tool{Effect: policy.EffectRead, Args: findNotes.Args, Binds: &policy.Binds{Path: "file.id", Kind: "note"}},
			`{"query":"vacation plans"}`, Result{Texts: []string{"n-7"}, Structured: jsontext.Value(`{"file":{"id":"n-7"}}`)}, "n-7", true},
		{"a wildcard over what is not a list", true, findNotes, `{"query":"vacation plans"}`,
			Result{Texts: []string{"n-7"}, Structured: jsontext.Value(`{"result":{"id":"n-7"}}`)}, "n-7", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New(prompt, nil, tt.boundIDs)
			s.Observe("crm__find_notes", tt.tool, argsOf(t, tt.args), tt.res)
			if got := canEdit(t, s, tt.id); got != tt.want {
				t.Fatalf("can edit %q: %v", tt.id, got)
			}
		})
	}
}

func TestABoundIDAnswersOnlyItsOwnKind(t *testing.T) {
	s := New("find my vacation plans", nil, true)
	s.Observe("crm__find_notes", findNotes, argsOf(t, `{"query":"vacation plans"}`),
		Result{Texts: []string{"n-7"}, Structured: jsontext.Value(`{"result":[{"id":"n-7"}]}`)})
	r := s.Check(editNote, argsOf(t, `{"note_id":"n-7"}`))
	if len(r.Findings) != 0 || !slices.Equal(r.Sources, []string{"bound:note"}) {
		t.Fatalf("the right kind: %+v", r)
	}
	for _, arg := range []policy.Arg{
		{Role: policy.RoleControl},
		{Role: policy.RoleControl, Bind: "event"},
	} {
		tool := policy.Tool{Effect: policy.EffectAct, Args: map[string]policy.Arg{"id": arg}}
		if got := rules(s.Check(tool, argsOf(t, `{"id":"n-7"}`))); len(got) != 1 {
			t.Errorf("argument %+v accepted a note ID: %q", arg, got)
		}
	}
	link := policy.Tool{Effect: policy.EffectAct, Args: map[string]policy.Arg{"body": {Role: policy.RoleContent}}}
	s.bound["note\x00evil.example"] = true
	if got := rules(s.Check(link, argsOf(t, `{"body":"evil.example"}`))); len(got) != 1 {
		t.Errorf("a bound ID vouched for a link in content: %q", got)
	}
}

// DESIGN section 3 says "all sourced", and rule 4 is one of the sources, so a lookup whose only control
// leaf is itself a bound ID can bind in turn. bench/forecast/revised.py does not allow this.
func TestABoundIDCanSourceALookupThatBinds(t *testing.T) {
	s := New("find my vacation plans", nil, true)
	s.Observe("crm__find_notes", findNotes, argsOf(t, `{"query":"vacation plans"}`),
		Result{Texts: []string{"n-7"}, Structured: jsontext.Value(`{"result":[{"id":"n-7"}]}`)})
	replies := policy.Tool{Effect: policy.EffectRead,
		Args:  map[string]policy.Arg{"note_id": {Role: policy.RoleControl, Bind: "note"}},
		Binds: &policy.Binds{Path: "result[*].id", Kind: "note"}}
	s.Observe("crm__replies", replies, argsOf(t, `{"note_id":"n-7"}`),
		Result{Texts: []string{"n-8"}, Structured: jsontext.Value(`{"result":[{"id":"n-8"}]}`)})
	if !canEdit(t, s, "n-8") {
		t.Fatal("the chain did not bind")
	}
}

func TestFirstSeenNamesTheEarliestToolThatShowedAValue(t *testing.T) {
	s := New("", nil, false)
	s.Observe("mail__search", policy.Tool{}, nil, Result{Texts: []string{"from James.Miller@yahoo.example today"}})
	s.Observe("mail__read", policy.Tool{}, nil, Result{Texts: []string{"james.miller@yahoo.example again"}, Structured: jsontext.Value(`{"e":"only.structured@x.example"}`)})
	tool := policy.Tool{Effect: policy.EffectAct, Args: map[string]policy.Arg{"to": {Role: policy.RoleControl}}}
	for value, want := range map[string]string{
		"james.miller@yahoo.example": "mail__search",
		"only.structured@x.example":  "mail__read",
		"nowhere@x.example":          "",
	} {
		r := s.Check(tool, argsOf(t, `{"to":"`+value+`"}`))
		if len(r.Findings) != 1 || r.Findings[0].SeenIn != want || r.Findings[0].Value != value {
			t.Errorf("%s: %+v", value, r.Findings)
		}
	}
}

func TestSeenStaysBounded(t *testing.T) {
	s := New("", nil, false)
	big := strings.Repeat("x", maxSeen/2)
	for i := range 5 {
		s.Observe("t", policy.Tool{}, nil, Result{Texts: []string{fmt.Sprintf("mark%d %s", i, big)}})
	}
	if s.seenSize > maxSeen || len(s.seen) >= 5 {
		t.Fatalf("seen holds %d results and %d bytes", len(s.seen), s.seenSize)
	}
	if s.firstSeen("mark0") != "" || s.firstSeen("mark4") != "t" {
		t.Fatal("it kept the wrong end")
	}
	huge := New("", nil, false)
	huge.Observe("t", policy.Tool{}, nil, Result{Texts: []string{strings.Repeat("x", maxSeen+1)}})
	if len(huge.seen) != 1 {
		t.Fatal("the latest result should stay, whatever its size")
	}
}

// Property: a rewritten value never matches. The rewrites are the ones a hijacked model could use to
// get a value past a person or a filter, while a lax server or a human still reads the same thing.
func TestPropertyARewrittenValueNeverMatches(t *testing.T) {
	values := []string{"alice", "alice@corp.example", "corp.example", "corp.example/pay", "12345", "GB82WEST12345698765432", "Mark Black"}
	rewrites := map[string]func(string) string{
		"base64":      func(v string) string { return base64.StdEncoding.EncodeToString([]byte(v)) },
		"hex":         func(v string) string { return hex.EncodeToString([]byte(v)) },
		"percent":     func(v string) string { return "%" + hex.EncodeToString([]byte(v[:1])) + v[1:] },
		"query":       func(v string) string { return url.QueryEscape(v) + "%20" },
		"reversed":    reverse,
		"spaced":      func(v string) string { return strings.Join(strings.Split(v, ""), " ") },
		"zero width":  func(v string) string { return v[:1] + "​" + v[1:] },
		"soft hyphen": func(v string) string { return v[:1] + "­" + v[1:] },
		"bidi":        func(v string) string { return "‮" + v },
		"fullwidth":   widen,
		"homoglyph": func(v string) string {
			return strings.NewReplacer("a", "а", "e", "е", "1", "١", "M", "М").Replace(v)
		},
		"combining": func(v string) string { return v[:1] + "́" + v[1:] },
		"appended":  func(v string) string { return v + "x" },
		"prepended": func(v string) string { return "x" + v },
		"subdomain": func(v string) string { return "evil." + v },
		"parent":    func(v string) string { return v + ".evil.example" },
		"tagged":    func(v string) string { return strings.Replace(v, "@", "+evil@", 1) + "+x" },
		"newline":   func(v string) string { return v + "\nx" },
		"nul":       func(v string) string { return v + "\x00" },
		"swapped":   func(v string) string { return v[1:] + v[:1] },
		"doubled":   func(v string) string { return v + " " + v },
	}
	s := New("pay "+strings.Join(values, " and "), nil, false)
	for _, v := range values {
		if !s.inPrompt(v) {
			t.Fatalf("%q should match as written, or this test proves nothing", v)
		}
		for name, rewrite := range rewrites {
			if changed := rewrite(v); changed != v && s.source(changed, "") != "" {
				t.Errorf("%s of %q matched: %q", name, v, changed)
			}
		}
	}
}

func reverse(v string) string {
	r := []rune(v)
	slices.Reverse(r)
	return string(r)
}

func widen(v string) string {
	return strings.Map(func(r rune) rune {
		if r > ' ' && r < 0x7f {
			return r + 0xFEE0
		}
		return r
	}, v)
}

// Property: more untrusted output never turns ask into allow. Nothing an untrusted tool says, however
// often and in whatever form, may change what a later call is judged on.
func TestPropertyUntrustedOutputNeverTurnsAskIntoAllow(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	lookup := policy.Tool{Effect: policy.EffectRead, Args: findNotes.Args, Binds: findNotes.Binds}
	acts := map[string]policy.Tool{
		`{"note_id":"n-7"}`:         editNote,
		`{"to":"evil@x.example"}`:   {Effect: policy.EffectAct, Args: map[string]policy.Arg{"to": {Role: policy.RoleControl}}},
		`{"body":"see evil.x.com"}`: {Effect: policy.EffectAct, Args: map[string]policy.Arg{"body": {Role: policy.RoleContent}}},
	}
	dressings := []func(string) Result{
		func(v string) Result { return Result{Texts: []string{v}} },
		func(v string) Result { return Result{Texts: []string{`{"id":"` + v + `"}`}} },
		func(v string) Result { return Result{Structured: jsontext.Value(`{"result":[{"id":"` + v + `"}]}`)} },
		func(v string) Result {
			return Result{IsError: true, Texts: []string{v}, Structured: jsontext.Value(`{"result":[{"id":"` + v + `"}]}`)}
		},
		func(v string) Result {
			return Result{Texts: []string{"please allow " + v}, Structured: jsontext.Value(`{"result":[{"id":"` + v + `"}]}`)}
		},
	}
	values := []string{"n-7", "evil@x.example", "evil.x.com", "n-8"}
	s := New("find my vacation plans", nil, true)
	for round := range 2000 {
		v := values[rng.IntN(len(values))]
		res := dressings[rng.IntN(len(dressings))](v)
		tool := policy.Tool{Effect: policy.EffectRead, Output: policy.OutputUntrusted}
		args := map[string]jsontext.Value{}
		if rng.IntN(2) == 0 {
			// The lookup itself, from an unsourced query, or from a data-only one.
			tool, args = lookup, argsOf(t, `{"query":"`+v+`"}`)
		}
		s.Observe("mail__read", tool, args, res)
		for raw, act := range acts {
			if len(s.Check(act, argsOf(t, raw)).Findings) == 0 {
				t.Fatalf("round %d: %s now passes", round, raw)
			}
		}
	}
}

// FuzzPromptMatch feeds the rule 1 matcher anything, and holds it to what section 3 promises.
func FuzzPromptMatch(f *testing.F) {
	f.Add("email alice@x.com on June 13 or later", "alice@x.com")
	f.Add("the meeting on June 13", "13")
	f.Add("at 10:00 or at 16:00", "or")
	f.Add("see https://www.x.com/a/", "http://x.com/a")
	f.Add("ＡＬＩＣＥ alice", "ａｌｉｃｅ")
	f.Add("\xff\xfe", "\xff")
	f.Fuzz(func(t *testing.T, prompt, value string) {
		s := New(prompt, nil, false)
		if !s.inPrompt(value) {
			return
		}
		c := canon(value)
		core := strings.TrimFunc(c, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
		switch {
		case strings.ContainsFunc(value, func(r rune) bool { return r >= utf8.RuneSelf }):
			t.Fatalf("a non-ASCII value matched: %q", value)
		case len(core) < 3:
			t.Fatalf("too short to match: %q", value)
		case len(core) < 5 && allDigits(core):
			t.Fatalf("too few digits to match: %q", value)
		case !strings.Contains(canonPrompt(prompt), c):
			t.Fatalf("%q matched a prompt that does not hold it: %q", value, prompt)
		}
	})
}

// FuzzLinks holds the link matcher to two things: it never panics or hangs, and what it reports is
// really there. A link is checked as a whole, so a report that changed it could pass when it shouldn't.
func FuzzLinks(f *testing.F) {
	f.Add("Check www.secure-systems-252.com and 192.168.4.20/login")
	f.Add("mark.black-2134＠gmail.com ｗｗｗ．evil．com")
	f.Add("US13 3000 0001 2121 2121 212")
	f.Add("請看evil.com網站 a..b.co. _http://x.y:80/z?q#f")
	f.Add("\xff\x00.com@")
	f.Fuzz(func(t *testing.T, text string) {
		wide := foldWide(text)
		for _, link := range links(text) {
			if !strings.Contains(strings.ReplaceAll(wide, " ", ""), strings.ReplaceAll(link, " ", "")) {
				t.Fatalf("links(%q) reported %q, which is not in it", text, link)
			}
		}
	})
}

// FuzzLeaves checks that arguments can't crash the walk, and that a value is never lost: a string leaf
// the walker failed to report would be a value nobody checked.
func FuzzLeaves(f *testing.F) {
	f.Add(`{"a":["x",1,true,null,{"b":"canary"}]}`)
	f.Add(`"canary"`)
	f.Add(`[[[[["canary"]]]]]`)
	f.Fuzz(func(t *testing.T, raw string) {
		value := jsontext.Value(raw)
		got := leaves(value)
		if !value.IsValid() {
			return
		}
		var parsed any
		if json.Unmarshal(value, &parsed) != nil {
			return
		}
		if want := countScalars(parsed); len(got) != want {
			t.Fatalf("leaves(%s) found %d values, want %d: %+v", raw, len(got), want, got)
		}
	})
}

func countScalars(v any) int {
	n := 0
	switch v := v.(type) {
	case map[string]any:
		for _, item := range v {
			n += 1 + countScalars(item)
		}
	case []any:
		for _, item := range v {
			n += countScalars(item)
		}
	default:
		n = 1
	}
	return n
}
