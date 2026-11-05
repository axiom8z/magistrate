package secrets

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	alnum  = upper + lower + digits
	word   = alnum + "_"
	hexLow = "0123456789abcdef"
	base32 = upper + "234567"
)

// gen makes fake credentials at run time. Every prefix below is split so that no complete
// token-shaped string ever sits in a file, because scanners flag a fake exactly as they flag a real one.
type gen struct{ r *rand.Rand }

func newGen(seed uint64) *gen { return &gen{rand.New(rand.NewPCG(seed, 7))} }

func (g *gen) chars(alphabet string, n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = alphabet[g.r.IntN(len(alphabet))]
	}
	return string(out)
}

// format is one rule's fake and the look-alikes it must leave alone.
type format struct {
	id     string
	fake   func(g *gen) string
	misses func(g *gen) map[string]string
}

var formats = []format{
	{"anthropic-api-key",
		func(g *gen) string { return "sk-" + "ant-" + "api03-" + g.chars(word+"-", 93) + "AA" },
		func(g *gen) map[string]string {
			return map[string]string{
				"too short":   "sk-" + "ant-" + "api03-" + g.chars(word, 40),
				"placeholder": "sk-" + "ant-" + "api03-" + strings.Repeat("x", 90),
				"no version":  "sk-" + "ant-" + "key-" + g.chars(word, 90),
			}
		}},
	{"openai-api-key",
		func(g *gen) string { return "sk-" + "proj-" + g.chars(word, 58) + "T3Blbk" + "FJ" + g.chars(word, 58) },
		func(g *gen) map[string]string {
			return map[string]string{
				"no marker":  "sk-" + g.chars(alnum, 48),
				"short head": "sk-" + g.chars(alnum, 5) + "T3Blbk" + "FJ" + g.chars(alnum, 30),
				"short tail": "sk-" + g.chars(alnum, 30) + "T3Blbk" + "FJ" + g.chars(alnum, 5),
			}
		}},
	{"huggingface-token",
		func(g *gen) string { return []string{"hf", "api" + "_org"}[g.r.IntN(2)] + "_" + g.chars(alnum, 34) },
		func(g *gen) map[string]string {
			return map[string]string{
				"too short":     "hf" + "_" + g.chars(alnum, 33),
				"placeholder":   "hf" + "_" + strings.Repeat("x", 34),
				"snake case":    "hf" + "_hub_" + "download_" + "files_" + "from_" + "the_" + "cache_folder",
				"counting":      "hf" + "_" + strings.Repeat("1234567890", 4),
				"org too short": "api" + "_org_" + g.chars(alnum, 33),
			}
		}},
	{"perplexity-api-key",
		func(g *gen) string { return "pp" + "lx-" + g.chars(alnum, 48) },
		func(g *gen) map[string]string {
			return map[string]string{
				"too short":   "pp" + "lx-" + g.chars(alnum, 47),
				"placeholder": "pp" + "lx-" + strings.Repeat("0", 48),
			}
		}},
	{"aws-access-key",
		func(g *gen) string {
			return []string{"AK" + "IA", "AS" + "IA", "AB" + "IA", "AC" + "CA"}[g.r.IntN(4)] + g.chars(base32, 16)
		},
		func(g *gen) map[string]string {
			return map[string]string{
				"too short":      "AK" + "IA" + g.chars(base32, 15),
				"placeholder":    "AK" + "IA" + strings.Repeat("X", 16),
				"wrong alphabet": "AK" + "IA" + g.chars(lower, 16),
				"plain word":     "ASIA is the largest continent",
			}
		}},
	{"gcp-api-key",
		func(g *gen) string { return "AI" + "za" + g.chars(word+"-", 35) },
		func(g *gen) map[string]string {
			return map[string]string{
				"too short":   "AI" + "za" + g.chars(alnum, 34),
				"placeholder": "AI" + "za" + strings.Repeat("x", 35),
			}
		}},
	{"azure-client-secret",
		func(g *gen) string { return g.chars(alnum, 3) + "8" + "Q~" + g.chars(alnum+"~._-", 34) },
		func(g *gen) map[string]string {
			return map[string]string{
				"too short":   g.chars(alnum, 3) + "8" + "Q~" + g.chars(alnum, 30),
				"no digit":    "abcd" + "Q~" + g.chars(alnum, 34),
				"placeholder": "abc8" + "Q~" + strings.Repeat("a", 34),
			}
		}},
	{"digitalocean-token",
		func(g *gen) string { return []string{"dop", "doo", "dor"}[g.r.IntN(3)] + "_v1_" + g.chars(hexLow, 64) },
		func(g *gen) map[string]string {
			return map[string]string{
				"too short":      "dop" + "_v1_" + g.chars(hexLow, 63),
				"wrong alphabet": "dop" + "_v1_" + g.chars(upper, 64),
				"placeholder":    "dop" + "_v1_" + strings.Repeat("0", 64),
			}
		}},
	{"vault-token",
		func(g *gen) string {
			return "hv" + string("sbr"[g.r.IntN(3)]) + "." + g.chars(word+"-", 24+g.r.IntN(80))
		},
		func(g *gen) map[string]string {
			return map[string]string{
				"too short":   "hv" + "s." + g.chars(word, 23),
				"placeholder": "hv" + "s." + strings.Repeat("z", 95),
				"counting":    "hv" + "s." + strings.Repeat("abc123", 8),
				"old, a word": "s." + "getCustomerAccountBalance",
				"old, joined": "o" + "s." + g.chars(lower, 8) + g.chars(upper, 8) + g.chars(digits, 8),
				"old, long":   "s." + g.chars(lower, 10) + g.chars(upper, 10) + g.chars(digits, 10),
				"old, short":  "s." + g.chars(lower, 8) + g.chars(upper, 8) + g.chars(digits, 7),
			}
		}},
	{"github-token",
		func(g *gen) string {
			if g.r.IntN(3) == 0 {
				return "gh" + "s_" + g.chars(word+"-", 100) + "." + g.chars(word+"-", 100)
			}
			return "gh" + string("pousr"[g.r.IntN(5)]) + "_" + g.chars(alnum, 36)
		},
		func(g *gen) map[string]string {
			return map[string]string{
				"too short":   "gh" + "p_" + g.chars(alnum, 35),
				"bad letter":  "gh" + "x_" + g.chars(alnum, 36),
				"placeholder": "gh" + "p_" + strings.Repeat("x", 36),
				"counting":    "gh" + "o_" + strings.Repeat("1234567890", 4),
			}
		}},
	{"github-fine-grained-pat",
		func(g *gen) string { return "github" + "_pat_" + g.chars(word, 82) },
		func(g *gen) map[string]string {
			return map[string]string{
				"too short":   "github" + "_pat_" + g.chars(word, 81),
				"placeholder": "github" + "_pat_" + strings.Repeat("x", 82),
			}
		}},
	{"gitlab-token",
		func(g *gen) string {
			if g.r.IntN(14) == 0 {
				return "GR" + "1348941" + g.chars(word+"-", 20)
			}
			kinds := []string{"pat", "oas", "dt", "rt", "rtr", "cbt", "ptt", "ft", "imt", "agent", "wt", "soat", "ffct"}
			return "gl" + kinds[g.r.IntN(len(kinds))] + "-" + g.chars(word+"-", 20)
		},
		func(g *gen) map[string]string {
			return map[string]string{
				"too short":   "gl" + "pat-" + g.chars(alnum, 19),
				"placeholder": "gl" + "pat-" + strings.Repeat("x", 20),
				"counting":    "gl" + "ptt-" + strings.Repeat("abcdef", 5),
				"other word":  "gl" + "obal-" + g.chars(alnum, 30),
			}
		}},
	{"slack-token",
		func(g *gen) string {
			if g.r.IntN(2) == 0 {
				return "xa" + "pp-1-" + g.chars(upper+digits, 11) + "-" + g.chars(digits, 13) + "-" + g.chars(lower+digits, 32)
			}
			return "xo" + "x" + string("abeoprs"[g.r.IntN(7)]) + "-" + g.chars(digits, 12) + "-" + g.chars(digits, 12) + "-" + g.chars(alnum, 24)
		},
		func(g *gen) map[string]string {
			return map[string]string{
				"too short":   "xo" + "xb-12345",
				"words":       "xo" + "xb-your-" + "token-here",
				"placeholder": "xo" + "xb-" + strings.Repeat("0", 10) + "-" + strings.Repeat("0", 10),
			}
		}},
	{"slack-webhook",
		func(g *gen) string {
			return "https://hooks" + ".slack.com/services/T" + g.chars(upper+digits, 8) + "/B" + g.chars(upper+digits, 8) + "/" + g.chars(alnum, 24)
		},
		func(g *gen) map[string]string {
			return map[string]string{
				"too short":   "https://hooks" + ".slack.com/services/T000/B000/xxx",
				"other paths": "https://hooks" + ".slack.com/health/" + g.chars(alnum, 50),
			}
		}},
	{"stripe-key",
		func(g *gen) string {
			return []string{"sk", "rk"}[g.r.IntN(2)] + "_" + []string{"test", "live", "prod", "org"}[g.r.IntN(4)] + "_" + g.chars(alnum, 24)
		},
		func(g *gen) map[string]string {
			return map[string]string{
				"too short":   "sk" + "_live_" + g.chars(alnum, 19),
				"placeholder": "sk" + "_live_" + strings.Repeat("x", 24),
				"public key":  "pk" + "_live_" + g.chars(alnum, 24),
				"identifier":  "disk" + "_test_" + "connection",
				"counting":    "sk" + "_live_" + strings.Repeat("1234567890", 3),
				"pairs":       "rk" + "_live_" + strings.Repeat("abc123", 4),
			}
		}},
	{"npm-token",
		func(g *gen) string { return "np" + "m_" + g.chars(alnum, 36) },
		func(g *gen) map[string]string {
			return map[string]string{
				"too short":   "np" + "m_" + g.chars(alnum, 35),
				"placeholder": "np" + "m_" + strings.Repeat("x", 36),
			}
		}},
	{"pypi-token",
		func(g *gen) string {
			if g.r.IntN(2) == 0 {
				return "py" + "pi-AgEN" + "dGVzdC5weXBpLm9yZw" + g.chars(word+"-", 60)
			}
			return "py" + "pi-AgEI" + "cHlwaS5vcmc" + g.chars(word+"-", 60)
		},
		func(g *gen) map[string]string {
			return map[string]string{
				"too short":   "py" + "pi-AgEI" + "cHlwaS5vcmc" + g.chars(alnum, 49),
				"plain name":  "py" + "pi-" + g.chars(lower, 60),
				"placeholder": "py" + "pi-AgEI" + "cHlwaS5vcmc" + strings.Repeat("x", 60),
			}
		}},
	{"sendgrid-key",
		func(g *gen) string { return "S" + "G." + g.chars(word+"-", 22) + "." + g.chars(word+"-", 43) },
		func(g *gen) map[string]string {
			return map[string]string{
				"too short":   "S" + "G." + g.chars(alnum, 40),
				"placeholder": "S" + "G." + strings.Repeat("x", 66),
			}
		}},
	{"telegram-bot-token",
		func(g *gen) string { return g.chars(digits, 10) + ":A" + "A" + g.chars(word+"-", 33) },
		func(g *gen) map[string]string {
			return map[string]string{
				"too short":   g.chars(digits, 10) + ":A" + "A" + g.chars(alnum, 32),
				"few digits":  g.chars(digits, 7) + ":A" + "A" + g.chars(alnum, 33),
				"placeholder": "1111111111" + ":A" + "A" + strings.Repeat("1", 33),
			}
		}},
	{"shopify-token",
		func(g *gen) string {
			return "sh" + []string{"pat", "pca", "ppa", "pss"}[g.r.IntN(4)] + "_" + g.chars(hexLow, 32)
		},
		func(g *gen) map[string]string {
			return map[string]string{
				"too short":      "sh" + "pat_" + g.chars(hexLow, 31),
				"wrong alphabet": "sh" + "pat_" + g.chars(lower[6:], 32),
				"placeholder":    "sh" + "pat_" + strings.Repeat("0", 32),
			}
		}},
	{"databricks-token",
		func(g *gen) string { return "da" + "pi" + g.chars(hexLow, 32) },
		func(g *gen) map[string]string {
			return map[string]string{
				"too short":   "da" + "pi" + g.chars(hexLow, 31),
				"placeholder": "da" + "pi" + strings.Repeat("0", 32),
			}
		}},
	{"private-key",
		func(g *gen) string {
			kind := []string{"", "RSA ", "EC ", "OPENSSH ", "ENCRYPTED "}[g.r.IntN(5)]
			return "-----BEGIN " + kind + "PRIVATE" + " KEY-----\n" + g.chars(alnum+"+/", 64) + "\n" + g.chars(alnum+"+/", 40) + "=\n-----END " + kind + "PRIVATE" + " KEY-----"
		},
		func(g *gen) map[string]string {
			return map[string]string{
				"public key":  "-----BEGIN PUBLIC" + " KEY-----\n" + g.chars(alnum, 64),
				"prose":       "never paste a private" + " key into a chat",
				"no dashes":   "BEGIN RSA PRIVATE" + " KEY",
				"header only": "the file must start with -----BEGIN RSA PRIVATE" + " KEY-----",
				"in code":     `strings.HasPrefix(s, "-----BEGIN OPENSSH PRIVATE` + ` KEY-----")`,
				"dots":        "-----BEGIN PRIVATE" + " KEY-----\n...\n-----END PRIVATE" + " KEY-----",
				"your key":    "-----BEGIN EC PRIVATE" + " KEY-----\n<your key here>\n-----END EC PRIVATE" + " KEY-----",
				"empty":       "-----BEGIN ENCRYPTED PRIVATE" + " KEY-----\n-----END ENCRYPTED PRIVATE" + " KEY-----",
				"a few words": "-----BEGIN PRIVATE" + " KEY-----\n" + strings.Repeat("abc ", 20),
			}
		}},
	{"jwt",
		func(g *gen) string {
			return "ey" + "J" + g.chars(word+"-", 30) + ".ey" + "J" + g.chars(word+"-", 60) + "." + g.chars(word+"-", 43)
		},
		func(g *gen) map[string]string {
			return map[string]string{
				"two parts":   "ey" + "J" + g.chars(alnum, 30) + ".ey" + "J" + g.chars(alnum, 30),
				"short head":  "ey" + "J" + g.chars(alnum, 5) + ".ey" + "J" + g.chars(alnum, 30) + "." + g.chars(alnum, 20),
				"placeholder": "ey" + "J" + strings.Repeat("x", 30) + ".ey" + "J" + strings.Repeat("x", 30) + ".xxxx",
			}
		}},
	{"url-credentials",
		func(g *gen) string {
			return []string{"https", "postgres", "redis"}[g.r.IntN(3)] + "://" + g.chars(lower, 6) + ":" + g.chars(alnum, 16) + "@db.example.com/main"
		},
		func(g *gen) map[string]string {
			return map[string]string{
				"no password": "ssh://" + "git@example.com/repo.git",
				"port":        "https://example.com:8080/path",
				"port, email": "https://example.com:8080?to=someone@example.com",
				"path email":  "https://example.com/users:list/someone@example.com",
				"template":    "postgres://user:${" + "DB_PASSWORD}@db.example.com",
				"short":       "https://user:ab" + "@example.com",
				"variables":   "mysql://$DB_USER:$" + "DB_PASS@localhost:5432/channel",
				"lower var":   "redis://user:$" + "password@localhost",
				"windows var": "postgres://user:%" + "PG_PASS%@localhost",
				"the word":    "postgres://user:" + "password@localhost/db",
				"the word up": "postgres://admin:" + "PASSWORD@localhost/db",
				"changeme":    "https://user:" + "changeme@example.com",
				"one char":    "https://user:" + "xxxxxxxx@example.com",
			}
		}},
}

// The oldest Vault form, which has its own edges and so doesn't belong in formats, whose fakes get text
// stuck to them.
func TestOldVaultTokenIsCaughtBetweenEdges(t *testing.T) {
	g := newGen(31)
	for range 200 {
		token := "s." + g.chars(lower, 8) + g.chars(upper, 8) + g.chars(digits, 8)
		for _, wrap := range []string{"%s", "token=%s", `{"token":"%s"}`, "line one\n%s\nline three"} {
			if id := ScanCall([]string{fmt.Sprintf(wrap, token)}); id != "vault-token" {
				t.Fatalf("wrapped as %q got %q", wrap, id)
			}
		}
	}
}

// A real password can start with a dollar and still be caught, if it isn't only a name.
func TestURLPasswordThatLooksLikeAVariableButIsNot(t *testing.T) {
	for _, password := range []string{"$ecret!23", "$a-b-c", "%41bc%", "%a", "pass" + "word1", "$", "%%"} {
		text := "https://user:" + password + "@example.com"
		if len(password) >= 3 && ScanCall([]string{text}) != "url-credentials" {
			t.Errorf("%q was treated as a template", password)
		}
	}
}

// Secrets encoded in part, with some of their own spaces and line breaks left as they were.
func TestPrivateKeyEncodedInPart(t *testing.T) {
	g := newGen(32)
	body := g.chars(alnum+"+/", 64) + "\n" + g.chars(alnum+"+/", 40)
	key := "-----BEGIN RSA PRIVATE" + " KEY-----\n" + body + "\n-----END RSA PRIVATE" + " KEY-----"
	cases := map[string]string{
		"only the first byte": "%2D" + key[1:],
		"some of the bytes":   strings.Replace(strings.Replace(key, "-", "%2D", 3), "B", "%42", 1),
		"spaces as plus":      strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(key, " ", "+"), "\n", "%0A"), "/", "%2F"),
		"plus, nothing else":  strings.ReplaceAll(key, " ", "+"),
	}
	for name, text := range cases {
		if id := ScanCall([]string{text}); id != "private-key" {
			t.Errorf("%s got %q", name, id)
		}
		out, ids := Redact(text)
		if !slices.Contains(ids, "private-key") || strings.Contains(out, body[:30]) {
			t.Errorf("%s: Redact gave IDs %v and kept the body", name, ids)
		}
	}
}

// A percent-encoded token inside a sentence is still redacted alone, so the whole-text read must not
// widen what it replaces when a narrower run already holds the secret.
func TestRedactionOfAnEncodedTokenKeepsTheSentence(t *testing.T) {
	g := newGen(33)
	token := "gh" + "p_" + g.chars(alnum, 36)
	out, ids := Redact("before " + percentAll(token) + " after")
	if out != "before [REDACTED:github-token] after" || !slices.Equal(ids, []string{"github-token"}) {
		t.Errorf("got %q, IDs %v", out, ids)
	}
}

// Placeholders that repeat a short unit pass, and a real token followed by the same thing doesn't.
func TestRepeatsUnit(t *testing.T) {
	g := newGen(34)
	token := "gh" + "p_" + g.chars(alnum, 36)
	for _, pad := range []string{"abcabc", "1234567890", "xy", "-"} {
		if id := ScanCall([]string{token + strings.Repeat(pad, 500)}); id != "github-token" {
			t.Errorf("a token padded with %q got %q", pad, id)
		}
	}
	for _, text := range []string{strings.Repeat("abc123", 10), "prefix-" + strings.Repeat("abcdefghijkl", 3), strings.Repeat("a", 40)} {
		if !repeatsUnit(text) {
			t.Errorf("%q should count as a repeat", text)
		}
	}
	for _, text := range []string{g.chars(alnum, 40), strings.Repeat("abcdefghijklm", 3), "short", strings.Repeat("ab", 5)} {
		if repeatsUnit(text) {
			t.Errorf("%q should not count as a repeat", text)
		}
	}
}

// This limit is conceded: a token followed by repeats of its own last bytes reads as a placeholder, when
// what's left before the repeat is no longer than a prefix. Someone rewriting a secret on purpose has
// easier ways too, which DESIGN section 9 concedes.
func TestMissTokenPaddedWithItsOwnTail(t *testing.T) {
	g := newGen(35)
	key := "AK" + "IA" + g.chars(base32, 16)
	tail := key[maxPrefix:]
	if id := ScanCall([]string{key[:maxPrefix] + strings.Repeat(tail, 5)}); id != "" {
		t.Errorf("this limit has changed, and the design should say so: got %q", id)
	}
}

func TestEveryRuleHasATestAndThereAre24(t *testing.T) {
	if len(rules) != 24 {
		t.Errorf("%d rules, and the design says 24", len(rules))
	}
	seen := map[string]bool{}
	for _, f := range formats {
		seen[f.id] = true
	}
	for _, r := range rules {
		if !seen[r.id] {
			t.Errorf("rule %s has no fake in this file", r.id)
		}
		if strings.ContainsAny(r.id, " \t\r\n[]") {
			t.Errorf("rule ID %q would break the marker", r.id)
		}
	}
}

// Fake credentials hit their own rule, every time, across many random draws. This is also what shows
// the entropy filter does not eat real tokens, because these have the same alphabets and lengths.
// A random fake can also match some other rule: a JWT has room for "SG." and enough characters after
// it. Either one blocks the call, so what this checks is that the fake's own rule fires.
func TestEveryRuleFiresOnItsFakes(t *testing.T) {
	ownRule := func(id, token string) bool {
		for i := range rules {
			if rules[i].id == id {
				return len(rules[i].find(token)) > 0
			}
		}
		return false
	}
	for _, f := range formats {
		g := newGen(1)
		for range 2000 {
			token := f.fake(g)
			if id := ScanCall([]string{token}); id == "" || !ownRule(f.id, token) {
				t.Fatalf("%s: a fake of length %d got %q", f.id, len(token), id)
			}
		}
	}
}

func TestNearMissesDoNotFire(t *testing.T) {
	for _, f := range formats {
		g := newGen(2)
		for name, text := range f.misses(g) {
			if id := ScanCall([]string{text}); id != "" {
				t.Errorf("%s, %s: got %q", f.id, name, id)
			}
			if out, ids := Redact(text); out != text || ids != nil {
				t.Errorf("%s, %s: Redact changed it, IDs %v", f.id, name, ids)
			}
		}
	}
}

// Ordinary text must pass, and at no point should it spend a noticeable part of the budget.
func TestOrdinaryTextIsClean(t *testing.T) {
	texts := []string{
		"The quarterly numbers are attached, and the team will review them on Monday.",
		"https://example.com/docs/getting-started/installation?lang=en#linux",
		"C:/Program Files/Some Application/resources/app/extensions/typescript-language-features/dist",
		"3f2b1c9e-7a44-4e1b-9d3a-1c2f5b7e8a90 da39a3ee5e6b4b0d3255bfef95601890afd80709",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"100% of tasks finished, 50%20off, a%2Fb and a stray % at the end %",
		`{"key":"value","task-id":"task-1234567890","Authorization":"Bearer <token>"}`,
		"mask_test_values and desk-booking and risk-assessment-report-2026-final",
		"",
	}
	for _, text := range texts {
		if id := ScanCall([]string{text}); id != "" {
			t.Errorf("%q: got %q", text, id)
		}
	}
}

// A secret must be caught wherever it sits, including with a word character stuck to either side.
func TestPositionInTheTextDoesNotMatter(t *testing.T) {
	for _, f := range formats {
		token := f.fake(newGen(3))
		for _, wrap := range []string{"%s", "x%s", "%sx", "key=%s;", `{"a":"%s"}`, "line one\n%s\nline three", "é%sé"} {
			if id := ScanCall([]string{fmt.Sprintf(wrap, token)}); id == "" {
				t.Errorf("%s wrapped as %q was missed", f.id, wrap)
			}
		}
	}
}

// The filter must not be possible to pass by padding, which is why it is not Shannon entropy.
func TestPaddingCannotHideAToken(t *testing.T) {
	for _, f := range formats {
		token := f.fake(newGen(4))
		for _, c := range []string{"a", "0", "-", "_", "x"} {
			padded := token + strings.Repeat(c, 200_000)
			if id := ScanCall([]string{padded}); id == "" {
				t.Errorf("%s padded with %q was missed", f.id, c)
			}
		}
	}
}

// encoders are every way of hiding a text that the scanner claims to read.
var encoders = map[string]func(string) string{
	"percent":    percentAll,
	"percent-up": func(s string) string { return strings.ToUpper(percentAll(s)) },
	"base64":     func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) },
	"base64raw":  func(s string) string { return base64.RawStdEncoding.EncodeToString([]byte(s)) },
	"base64url":  func(s string) string { return base64.URLEncoding.EncodeToString([]byte(s)) },
	"base64rawu": func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) },
	"hex":        func(s string) string { return hex.EncodeToString([]byte(s)) },
	"hex-upper":  func(s string) string { return strings.ToUpper(hex.EncodeToString([]byte(s))) },
}

// percentAll encodes every byte, because url.QueryEscape leaves letters and digits as they are and a
// token made only of those would come out unchanged.
func percentAll(s string) string {
	var out strings.Builder
	for i := range len(s) {
		fmt.Fprintf(&out, "%%%02x", s[i])
	}
	return out.String()
}

func encoderNames() []string {
	names := make([]string, 0, len(encoders))
	for name := range encoders {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// checkCaught asserts both paths catch an encoded secret, and that Redact leaves none of it behind.
func checkCaught(t *testing.T, label, id, encoded string) {
	t.Helper()
	if got := ScanCall([]string{"before " + encoded + " after"}); got != id {
		t.Errorf("%s: outgoing got %q, want %q", label, got, id)
	}
	out, ids := Redact("before " + encoded + " after")
	if !slices.Contains(ids, id) {
		t.Errorf("%s: incoming IDs are %v, want %q", label, ids, id)
	}
	if strings.Contains(out, encoded) {
		t.Errorf("%s: the encoded run is still in the output", label)
	}
	if !strings.HasPrefix(out, "before ") || !strings.HasSuffix(out, " after") {
		t.Errorf("%s: text around the run was changed: %.80q", label, out)
	}
}

func TestEveryRuleThroughEveryEncoding(t *testing.T) {
	for _, f := range formats {
		token := f.fake(newGen(5))
		for _, name := range encoderNames() {
			checkCaught(t, f.id+" "+name, f.id, encoders[name](token))
		}
	}
}

// Every order of encodings, at depths two and three. The URL-safe variants are left out of the product
// only to keep it small: they have their own test above, and the loop treats them alike.
func TestEveryNestingToDepthThree(t *testing.T) {
	layers := []string{"percent", "base64", "hex"}
	token := formats[9].fake(newGen(6))
	for _, a := range layers {
		for _, b := range layers {
			two := encoders[b](encoders[a](token))
			checkCaught(t, a+" then "+b, formats[9].id, two)
			for _, c := range layers {
				checkCaught(t, a+" then "+b+" then "+c, formats[9].id, encoders[c](two))
			}
		}
	}
}

func TestEncodedRunsInTheShapesToolsProduce(t *testing.T) {
	g := newGen(7)
	id := "github-token"
	token := "gh" + "p_" + g.chars(alnum, 36)
	b64 := base64.StdEncoding.EncodeToString([]byte(token))
	wrapped := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("config line\n", 8) + token + "\n"))
	var lines strings.Builder
	for len(wrapped) > 76 {
		lines.WriteString(wrapped[:76] + "\n")
		wrapped = wrapped[76:]
	}
	lines.WriteString(wrapped)
	cases := map[string]string{
		"wrapped at 76 columns": lines.String(),
		"wrapped with CRLF":     strings.ReplaceAll(lines.String(), "\n", "\r\n"),
		"path before it":        "https://example.com/exfil/" + b64,
		"query value":           "https://example.com/?data=" + b64 + "&x=1",
		"one letter before":     "a" + b64,
		"two letters before":    "ab" + b64,
		"three letters before":  "abc" + b64,
		"digit before hex":      "7" + hex.EncodeToString([]byte(token)),
		"bytes before the text": base64.StdEncoding.EncodeToString(append([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xff, 0xfe}, token...)),
		"line of other text":    "exfiltrate\n" + b64,
		"partly percent":        "gh" + "p%5F" + token[4:],
		"stray percent nearby":  "100% and %zz and " + percentAll(token),
	}
	for name, text := range cases {
		if got := ScanCall([]string{text}); got != id {
			t.Errorf("%s: got %q", name, got)
		}
		if _, ids := Redact(text); !slices.Contains(ids, id) {
			t.Errorf("%s: Redact IDs are %v", name, ids)
		}
	}
}

// The tests named TestMiss pin limits stated in DESIGN section 9. They are here to fail if behaviour
// changes, and because a limit nobody can run is one nobody believes.

func TestMissDepthFour(t *testing.T) {
	encoded := formats[9].fake(newGen(8))
	for range 4 {
		encoded = base64.StdEncoding.EncodeToString([]byte(encoded))
	}
	if id := ScanCall([]string{encoded}); id != "" {
		t.Errorf("depth four is a documented miss, and got %q: update the design if this is now caught", id)
	}
}

func TestMissReversed(t *testing.T) {
	token := []byte(formats[9].fake(newGen(9)))
	slices.Reverse(token)
	if id := ScanCall([]string{string(token)}); id != "" {
		t.Errorf("reversed text is a documented miss, and got %q", id)
	}
}

func TestMissSplitAcrossCalls(t *testing.T) {
	token := formats[9].fake(newGen(10))
	for _, part := range []string{token[:20], token[20:]} {
		if id := ScanCall([]string{part}); id != "" {
			t.Errorf("each call holds only part of the token, and got %q", id)
		}
	}
}

func TestMissFormatless(t *testing.T) {
	if id := ScanCall([]string{newGen(11).chars(alnum, 40)}); id != "" {
		t.Errorf("a formatless secret is a documented miss, and got %q", id)
	}
}

func TestMissSiblingsEachEncodedAlone(t *testing.T) {
	token := formats[9].fake(newGen(12))
	leaves := []string{
		base64.StdEncoding.EncodeToString([]byte(token[:20])),
		base64.StdEncoding.EncodeToString([]byte(token[20:])),
	}
	if id := ScanCall(leaves); id != "" {
		t.Errorf("each half encoded alone is not put back together, and got %q", id)
	}
}

func TestMissSiblingsInTheWrongOrder(t *testing.T) {
	token := formats[9].fake(newGen(13))
	if id := ScanCall([]string{token[20:], token[:20]}); id != "" {
		t.Errorf("the join follows leaf order, and got %q", id)
	}
}

func TestSplitAcrossSiblingLeavesIsCaughtByTheJoin(t *testing.T) {
	for _, f := range formats {
		token := f.fake(newGen(14))
		cases := map[string][]string{
			"two halves":         {token[:len(token)/2], token[len(token)/2:]},
			"one byte each":      strings.Split(token, ""),
			"word before":        {"hello", token[:10], token[10:]},
			"word after":         {token[:10], token[10:], "hello"},
			"both":               {"hello", token[:10], token[10:], "hello"},
			"empty leaves":       {"", token[:10], "", token[10:], ""},
			"encoded, then join": {encoders["base64"](token)[:12], encoders["base64"](token)[12:]},
			"percent, then join": {percentAll(token)[:10], percentAll(token)[10:]},
			"hex, then join":     {encoders["hex"](token)[:9], encoders["hex"](token)[9:]},
		}
		for name, leaves := range cases {
			if id := ScanCall(leaves); id != f.id {
				t.Errorf("%s, %s: got %q", f.id, name, id)
			}
		}
	}
}

func TestScanCallReturnsOnlyAnID(t *testing.T) {
	token := formats[9].fake(newGen(15))
	got := ScanCall([]string{"x " + token})
	if got != "github-token" || strings.Contains(got, token[4:12]) {
		t.Errorf("got %q", got)
	}
}

func TestRedactionLeavesNoFragmentOfTheMatch(t *testing.T) {
	for _, f := range formats {
		g := newGen(16)
		for range 50 {
			token := f.fake(g)
			text := "start " + token + " end"
			out, ids := Redact(text)
			if !slices.Contains(ids, f.id) {
				t.Fatalf("%s: IDs are %v", f.id, ids)
			}
			if !strings.Contains(out, "[REDACTED:") || !strings.HasPrefix(out, "start ") {
				t.Fatalf("%s: output %.100q", f.id, out)
			}
			// No window of the token may survive. Prefixes are shorter than the window except where the
			// token has a fixed part, so the window is set past the longest of those.
			const window = 20
			end := len(token)
			if f.id == "url-credentials" {
				end = strings.Index(token, "@") // the host after the credentials stays, by design
			}
			for i := 0; i+window <= end; i++ {
				if strings.Contains(out, token[i:i+window]) {
					t.Fatalf("%s: a fragment survived at offset %d of %d", f.id, i, end)
				}
			}
		}
	}
}

func TestRedactionPadsAndGluedTailsAreGone(t *testing.T) {
	g := newGen(17)
	token := "gh" + "p_" + g.chars(alnum, 36)
	second := g.chars(alnum, 36)
	// The first match stops at the underscore, so without tail handling this body would stay.
	out, _ := Redact(token + "gh" + "p_" + second + " end")
	if strings.Contains(out, second) {
		t.Errorf("the glued second token survived: %q", out)
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(token + "x"))
	if !strings.HasSuffix(encoded, "=") {
		t.Fatal("this test needs padding")
	}
	out, _ = Redact("a " + encoded + " b")
	if out != "a [REDACTED:github-token] b" {
		t.Errorf("padding left behind: %q", out)
	}
}

func TestRedactionOutputIsStable(t *testing.T) {
	for _, f := range formats {
		g := newGen(18)
		text := "a " + f.fake(g) + " b " + encoders["base64"](f.fake(g)) + " c " + percentAll(f.fake(g))
		once, ids := Redact(text)
		if len(ids) == 0 {
			t.Errorf("%s: nothing fired", f.id)
		}
		twice, again := Redact(once)
		if twice != once || again != nil {
			t.Errorf("%s: a second pass changed it, IDs %v", f.id, again)
		}
		if id := ScanCall([]string{once}); id != "" {
			t.Errorf("%s: redacted text still fires %q", f.id, id)
		}
	}
}

func TestRedactionKeepsTheRestOfTheText(t *testing.T) {
	g := newGen(19)
	first, second := "AK"+"IA"+g.chars(base32, 16), "gh"+"p_"+g.chars(alnum, 36)
	out, ids := Redact("one " + first + " two " + second + " three")
	if out != "one [REDACTED:aws-access-key] two [REDACTED:github-token] three" {
		t.Errorf("got %q", out)
	}
	if !slices.Equal(ids, []string{"aws-access-key", "github-token"}) {
		t.Errorf("IDs are %v", ids)
	}
	plain := "Nothing to see here, 100% clean."
	if out, ids := Redact(plain); out != plain || ids != nil {
		t.Errorf("a clean text came back as %q, IDs %v", out, ids)
	}
}

func TestRedactionOverlappingMatchesMerge(t *testing.T) {
	g := newGen(20)
	token := "gh" + "p_" + g.chars(alnum, 36)
	out, ids := Redact("postgres://user:" + token + "@db.example.com")
	if strings.Contains(out, token) || strings.Contains(out, token[10:20]) {
		t.Errorf("got %q", out)
	}
	if !slices.Equal(ids, []string{"github-token", "url-credentials"}) {
		t.Errorf("IDs are %v", ids)
	}
	if !strings.HasSuffix(out, "@db.example.com") && !strings.Contains(out, "db.example.com") {
		t.Errorf("the host went too: %q", out)
	}
}

// overBudget builds text with more candidates than the budget allows: base64-shaped words with
// spaces between, each of which is decoded at every offset.
func overBudget() string {
	return strings.Repeat("abcdefghijklmnopqrstuvwx ", maxCandidates)
}

func TestOverBudgetBlocks(t *testing.T) {
	if id := ScanCall([]string{overBudget()}); id != RuleOverBudget {
		t.Errorf("too many candidates got %q", id)
	}
	// Decoded bytes are limited separately: few candidates, each huge.
	big := strings.Repeat("abcdefgh", (maxDecoded/4)/8)
	if id := ScanCall([]string{big, big, big, big}); id != RuleOverBudget {
		t.Errorf("too many decoded bytes got %q", id)
	}
}

// One call stays under the budget, while ten of them would pass it if they shared one. Decoded bytes
// can hold further encoded runs, so the first part measures the cost and doesn't assume it.
func TestBudgetIsPerCall(t *testing.T) {
	text := strings.Repeat("abcdefghijklmnopqrstuvwx ", maxCandidates/10)
	s := scan{match: firstRule}
	if id := s.leaves([]string{text}); id != "" || s.candidates*10 <= maxCandidates {
		t.Fatalf("this test needs a call under budget whose tenfold is over it: got %q after %d candidates", id, s.candidates)
	}
	for range 10 {
		if id := ScanCall([]string{text}); id != "" {
			t.Fatalf("one call under budget got %q, so the budget leaked between calls", id)
		}
	}
}

func TestOverBudgetResultHidesWhatItCouldNotCheck(t *testing.T) {
	g := newGen(21)
	hidden := base64.StdEncoding.EncodeToString([]byte("gh" + "p_" + g.chars(alnum, 36)))
	plain := "AK" + "IA" + g.chars(base32, 16)
	out, ids := Redact(overBudget() + hidden + " " + plain + " kept")
	if !slices.Contains(ids, RuleOverBudget) || !slices.Contains(ids, "aws-access-key") {
		t.Errorf("IDs are %v", ids)
	}
	if strings.Contains(out, hidden) || strings.Contains(out, plain) {
		t.Error("something it could not check got through")
	}
	if !strings.HasSuffix(out, " kept") {
		t.Errorf("text with no encoded shape should stay: %.60q", out[max(0, len(out)-60):])
	}
}

func TestHashCoversEveryFieldOfEveryRule(t *testing.T) {
	base := hashRules(table)
	if RulesHash() != base || len(base) != 64 {
		t.Fatalf("hash is %q", base)
	}
	changes := map[string]func(r *rule){
		"id":      func(r *rule) { r.id += "x" },
		"keyword": func(r *rule) { r.keywords += ",x" },
		"filter":  func(r *rule) { r.minSymbols++ },
		"skip":    func(r *rule) { r.skip += "x" },
		"pattern": func(r *rule) { r.pattern += "x" },
	}
	for i := range table {
		for name, change := range changes {
			edited := slices.Clone(table)
			change(&edited[i])
			if hashRules(edited) == base {
				t.Errorf("changing the %s of rule %d left the hash the same", name, i)
			}
		}
	}
	moved := slices.Clone(table)
	moved[0], moved[1] = moved[1], moved[0]
	if hashRules(moved) == base {
		t.Error("reordering rules left the hash the same")
	}
}

// frozenHash is the rule table's hash. Editing a rule means editing this line as well, so the change is
// visible in review and the numbers measured under the old table can't be mistaken for the new one's.
const frozenHash = "26c7217fa824123d7b36d1018e3561782a21eb492fd4fec74ad915a8f4740511"

// FuzzPlantedToken holds the scanner to its promise on text it has never seen: a token sitting among
// anything at all fires, and redaction leaves no piece of it behind.
func FuzzPlantedToken(f *testing.F) {
	token := "gh" + "p_" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hI6"
	f.Add("", "")
	f.Add("%%%", "abc")
	f.Add("-----BEGIN ", "://user:"+"pass"+"@")
	f.Add("\xff\x00", "====")
	f.Fuzz(func(t *testing.T, before, after string) {
		text := before + token + after
		if ScanCall([]string{text}) == "" {
			t.Fatalf("missed the token in %q", text)
		}
		out, ids := Redact(text)
		if len(ids) == 0 || strings.Contains(out, token) || strings.Contains(out, token[4:24]) {
			t.Fatalf("Redact(%q) = %q, %v", text, out, ids)
		}
	})
}

// FuzzDecodeLoop feeds the decoders anything at all. Nothing may panic, a clean answer from Redact must
// leave the text alone, and whatever Redact returns must not fire a plain rule again.
func FuzzDecodeLoop(f *testing.F) {
	f.Add("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4 %41%42%43 6162636465666768696a6b6c6d6e6f70")
	f.Add(strings.Repeat("%25", 40))
	f.Add("abcd\r\nefgh\r\nijkl\r\nmnop")
	f.Add("\xff\xfe\x00%")
	f.Fuzz(func(t *testing.T, text string) {
		id := ScanCall([]string{text})
		out, ids := Redact(text)
		if len(ids) == 0 && out != text {
			t.Fatalf("no rule fired, yet the text changed: %q to %q", text, out)
		}
		if id != "" && len(ids) == 0 {
			t.Fatalf("ScanCall said %q and Redact found nothing in %q", id, text)
		}
		if again := firstRule(out); again != "" {
			t.Fatalf("rule %s still fires after redaction: %q", again, out)
		}
	})
}

func TestHashIsFrozen(t *testing.T) {
	if got := RulesHash(); got != frozenHash {
		t.Errorf("the rule table changed: hash is %s", got)
	}
}

func TestConcurrentUse(t *testing.T) {
	registry := NewRegistry()
	var wg sync.WaitGroup
	for worker := range 16 {
		wg.Go(func() {
			g := newGen(uint64(100 + worker))
			for i := range 200 {
				f := formats[i%len(formats)]
				token := f.fake(g)
				if id := ScanCall([]string{token[:5], token[5:], encoders["hex"](token)}); id == "" {
					t.Errorf("%s was missed", f.id)
				}
				if out, ids := Redact("x " + token); len(ids) == 0 || strings.Contains(out, token) {
					t.Errorf("%s was not redacted", f.id)
				}
				value := fmt.Sprintf("value%d-%d", worker, i)
				registry.Register("the id is " + value)
				if !registry.Contains([]string{"send " + value}) {
					t.Errorf("value %d was not found", i)
				}
				RulesHash()
			}
		})
	}
	wg.Wait()
}

// worstCases are inputs built to do the most work per byte, each 1 MiB, the most a line can be.
func worstCases() map[string][]string {
	const size = 1 << 20
	fill := func(unit string) string { return strings.Repeat(unit, size/len(unit)+1)[:size] }
	var every strings.Builder
	for _, r := range rules {
		for _, word := range r.words {
			every.WriteString(word + " ")
		}
	}
	short := fill("abcdefghijklmnop ")
	nested := base64.StdEncoding.EncodeToString([]byte(short[:size*3/4]))
	leaves := make([]string, size/4)
	for i := range leaves {
		leaves[i] = "a"
	}
	urls := fill("://a:bcd")
	return map[string][]string{
		"every keyword, repeated":      {fill(every.String())},
		"keywords in one huge word":    {fill(strings.ReplaceAll(every.String(), " ", ""))},
		"short base64 words":           {short},
		"base64 of short base64 words": {nested},
		"one huge base64 run":          {fill("abcdefgh")},
		"one huge hex run":             {fill("0123abcd")},
		"percent everywhere":           {fill("%41")},
		"percent of percent":           {fill("%2541")},
		"many one-byte leaves":         leaves,
		"long token with low variety":  {"gh" + "p_" + fill("a")},
		"almost a url, repeated":       {urls},
		"almost a jwt, repeated":       {fill("ey" + "J" + strings.Repeat("a", 20) + ".")},
		"digits and colons":            {fill("1234567890:A" + "A")},
		"line breaks only":             {fill("\n")},
	}
}

// A scan of the worst input we can build must finish in bounded time. The limit is far above what it
// takes, because machines running tests vary; the numbers worth reading are in the log.
func TestWorstCase1MiBStaysBounded(t *testing.T) {
	const limit = 30 * time.Second
	registry := NewRegistry()
	registry.Register("value123 another456 third789")
	for name, leaves := range worstCases() {
		start := time.Now()
		id := ScanCall(leaves)
		outgoing := time.Since(start)
		start = time.Now()
		Redact(strings.Join(leaves, ""))
		incoming := time.Since(start)
		start = time.Now()
		registry.Contains(leaves)
		values := time.Since(start)
		t.Logf("%-30s outgoing %8.1f ms (%q), incoming %8.1f ms, values %8.1f ms", name,
			float64(outgoing.Microseconds())/1000, id, float64(incoming.Microseconds())/1000, float64(values.Microseconds())/1000)
		if outgoing > limit || incoming > limit || values > limit {
			t.Errorf("%s took too long", name)
		}
	}
}

// Rule 4 of the project: no complete token-shaped string in a file, fake or not. Scanning our own
// source with our own rules is the check for it.
func TestNoSecretShapedStringInThisPackageOrMagbench(t *testing.T) {
	for _, dir := range []string{".", "../../cmd/magbench"} {
		paths, err := filepath.Glob(filepath.Join(dir, "*"))
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range paths {
			if info, err := os.Stat(path); err != nil || info.IsDir() {
				continue
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if id := firstRule(string(data)); id != "" {
				t.Errorf("%s holds something matching %s", path, id)
			}
		}
	}
}

func TestRegisterTakesOnlyDigitBearingTokensOfSixOrMore(t *testing.T) {
	r := NewRegistry()
	r.Register(`name: Jane Doe, ref "AB1234", pin 12345, code=A1B2C3 word sevenseven card/987654`)
	has := map[string]bool{
		"ab1234":            true, // a digit and six characters
		"please AB1234 now": true, // found inside other text, ignoring case
		"a1b2c3":            true,
		"987654":            true,
		"12345":             false, // too short
		"Jane Doe":          false, // no digit
		"sevenseven":        false, // no digit
		"nothing":           false,
		"":                  false,
	}
	for text, want := range has {
		if got := r.Contains([]string{text}); got != want {
			t.Errorf("Contains(%q) = %v, want %v", text, got, want)
		}
	}
}

func TestRegisteredSpellingsCompareEqual(t *testing.T) {
	// The values here are made of parts, like the credentials above, and none is a real number.
	card := "4242" + " 4242 " + "4242" + " 0000"
	r := NewRegistry()
	r.Register("card " + card + ", ssn " + "078" + "-05-" + "1120")
	for _, text := range []string{
		"4242424242420000", "4242-4242-4242-0000", "pay " + card + " today",
		"0780" + "51120", "078" + " 05 " + "1120",
	} {
		if !r.Contains([]string{text}) {
			t.Errorf("%q was not found", text)
		}
	}
	if r.Contains([]string{"4242 4242 other"}) {
		t.Error("part of a value should not count")
	}
}

func TestContainsSeesTheJoinAndEncodings(t *testing.T) {
	r := NewRegistry()
	r.Register("the reference is XK-48213-QT")
	for name, leaves := range map[string][]string{
		"plain":   {"xk-48213-qt"},
		"among":   {"hello", "ref XK-48213-QT."},
		"join":    {"XK-48", "213-QT"},
		"base64":  {base64.StdEncoding.EncodeToString([]byte("XK-48213-QT and more"))},
		"percent": {percentAll("XK-48213-QT")},
		"hex":     {hex.EncodeToString([]byte("XK-48213-QT"))},
	} {
		if !r.Contains(leaves) {
			t.Errorf("%s: not found", name)
		}
	}
	if r.Contains([]string{"XK-48213"}) {
		t.Error("a part of the value should not count")
	}
}

func TestEmptyRegistryFindsNothingAndCostsNothing(t *testing.T) {
	r := NewRegistry()
	if r.Contains([]string{"123456", overBudget()}) {
		t.Error("an empty registry found something")
	}
	r.Register("no tokens here, 123 45 and words")
	if r.count != 0 || r.Contains([]string{"123 45"}) {
		t.Errorf("%d values registered", r.count)
	}
}

func TestRegistryFullAnswersYes(t *testing.T) {
	r := NewRegistry()
	var text strings.Builder
	for i := range maxValues + 1 {
		fmt.Fprintf(&text, "v%07d ", i)
	}
	r.Register(text.String())
	if !r.Contains([]string{"completely unrelated"}) {
		t.Error("past the limit, a check must not say no: it no longer knows")
	}
	same := NewRegistry()
	for i := range maxPerHead + 1 {
		same.Register(fmt.Sprintf("sameprefix%d", i))
	}
	if !same.Contains([]string{"completely unrelated"}) {
		t.Error("past the limit for one head, a check must not say no")
	}
}

func TestRegistryOverBudgetAnswersYes(t *testing.T) {
	r := NewRegistry()
	r.Register("value123")
	if !r.Contains([]string{overBudget()}) {
		t.Error("a check that could not finish said no")
	}
}

func TestVeryLongTokenIsCutAndStillFound(t *testing.T) {
	r := NewRegistry()
	long := "a1" + strings.Repeat("b", 5000)
	r.Register(long)
	if !r.Contains([]string{long}) {
		t.Error("the whole token was not found")
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, values := range r.byHead {
		for _, value := range values {
			if len(value) > maxValueLen {
				t.Errorf("stored %d bytes", len(value))
			}
		}
	}
}

func TestFold(t *testing.T) {
	for in, want := range map[string]string{
		"AbC":    "abc",
		"12 34":  "1234",
		"12-34":  "1234",
		"12  34": "12  34",
		"a 1":    "a 1",
		"1 a":    "1 a",
		"-1 2-":  "-12-",
		"É":      "É",
	} {
		if got := fold(in); got != want {
			t.Errorf("fold(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDecoders(t *testing.T) {
	if got := decodeBase64("aGVsbG8"); got != "hello" {
		t.Errorf("base64 got %q", got)
	}
	if got := decodeBase64("aGVsbG8gd29ybGQ_"); !strings.HasPrefix(got, "hello world") {
		t.Errorf("URL-safe base64 got %q", got)
	}
	if got := decodeBase64("aGVsbG8gd29ybA" + "x" + "x" + "x"); !strings.HasPrefix(got, "hello worl") {
		t.Errorf("a stray last character got %q", got)
	}
	if got := decodeHex("68656c6c6f"); got != "hello" {
		t.Errorf("hex got %q", got)
	}
	if got := decodeHex("68656c6c6f7"); got != "hello" {
		t.Errorf("odd hex got %q", got)
	}
	for in, want := range map[string]string{
		"a%20b": "a b", "%zz": "%zz", "100%": "100%", "%4": "%4", "%%41": "%A", "%41%": "A%", "%4a%4A": "JJ", "a+b": "a+b",
	} {
		if got := decodePercent(in); got != want {
			t.Errorf("percent %q got %q, want %q", in, got, want)
		}
	}
}

func BenchmarkScanCall(b *testing.B) {
	sentence := "The quarterly numbers are attached, and the team will review them on Monday. "
	for _, size := range []int{1 << 10, 16 << 10, 256 << 10} {
		leaves := []string{"someone@example.com", "report", strings.Repeat(sentence, size/len(sentence)+1)[:size]}
		b.Run(fmt.Sprintf("%dKB", size>>10), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				ScanCall(leaves)
			}
		})
	}
}

func BenchmarkRedact(b *testing.B) {
	sentence := "The quarterly numbers are attached, and the team will review them on Monday. "
	for _, size := range []int{1 << 10, 16 << 10, 256 << 10} {
		text := strings.Repeat(sentence, size/len(sentence)+1)[:size]
		b.Run(fmt.Sprintf("%dKB", size>>10), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				Redact(text)
			}
		})
	}
}
