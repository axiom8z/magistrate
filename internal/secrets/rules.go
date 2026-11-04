package secrets

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// rule is one known credential format, adapted from gitleaks (see NOTICE).
type rule struct {
	id string
	// keywords holds comma-separated literals, and one must appear before the regexp runs. The
	// regexps are the slow part of a scan, and most text holds none of these.
	keywords string
	// minSymbols is the entropy filter: how many different characters a match must use, which is
	// Hartley entropy written as a count. Shannon entropy would fall if a token were padded with one
	// repeated character, letting it slip under a threshold. Padding can't lower this count. It only
	// ever filters an anchored hit, here to drop placeholders like a prefix followed by xxxxxx.
	minSymbols int
	pattern    string
	words      []string
	re         *regexp.Regexp
}

// table differs from gitleaks in two ways, on purpose. No pattern has a word boundary, which would fail
// where a token touches other text: in the join of two leaves, after decoded garbage, or with a
// character added. And every length is open-ended, so a match takes the whole run and redaction
// leaves no tail. The cost is that a longer look-alike also matches.
var table = []rule{
	// AI providers
	{id: "anthropic-api-key", keywords: "sk-ant-", minSymbols: 14, pattern: `sk-ant-(?:api|admin)\d\d-[\w-]{80,}`},
	{id: "openai-api-key", keywords: "T3BlbkFJ", minSymbols: 14, pattern: `sk-[\w-]{20,}T3BlbkFJ[\w-]{20,}`},
	{id: "huggingface-token", keywords: "hf_", minSymbols: 8, pattern: `hf_[A-Za-z0-9]{34,}`},
	{id: "perplexity-api-key", keywords: "pplx-", minSymbols: 8, pattern: `pplx-[A-Za-z0-9]{48,}`},
	// Cloud
	{id: "aws-access-key", keywords: "A3T,AKIA,ASIA,ABIA,ACCA", minSymbols: 8, pattern: `(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16,}`},
	{id: "gcp-api-key", keywords: "AIza", minSymbols: 8, pattern: `AIza[\w-]{35,}`},
	{id: "azure-client-secret", keywords: "Q~", minSymbols: 8, pattern: `[\w~.]{3}\dQ~[\w~.-]{31,}`},
	{id: "digitalocean-token", keywords: "dop_v1_,doo_v1_,dor_v1_", minSymbols: 10, pattern: `do[opr]_v1_[a-f0-9]{64,}`},
	{id: "vault-token", keywords: "hvs.,hvb.", minSymbols: 8, pattern: `hv[sb]\.[\w-]{90,}`},
	// Git hosts
	{id: "github-token", keywords: "ghp_,gho_,ghu_,ghs_,ghr_", minSymbols: 8, pattern: `gh[pousr]_[A-Za-z0-9]{36,}`},
	{id: "github-fine-grained-pat", keywords: "github_pat_", minSymbols: 13, pattern: `github_pat_\w{82,}`},
	{id: "gitlab-token", keywords: "glpat-,gldt-,glrt-", minSymbols: 10, pattern: `gl(?:pat|dt|rt)-[\w.-]{20,}`},
	// Slack
	{id: "slack-token", keywords: "xox,xapp-", minSymbols: 8, pattern: `xox[abeoprs]-\d[A-Za-z0-9-]{9,}|xapp-\d-[A-Za-z0-9-]{10,}`},
	{id: "slack-webhook", keywords: "hooks.slack.com/", pattern: `hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,}`},
	// Payments and package registries
	{id: "stripe-key", keywords: "k_test_,k_live_,k_prod_", minSymbols: 11, pattern: `[rs]k_(?:test|live|prod)_[A-Za-z0-9]{20,}`},
	{id: "npm-token", keywords: "npm_", minSymbols: 8, pattern: `npm_[A-Za-z0-9]{36,}`},
	{id: "pypi-token", keywords: "pypi-AgEIcHlwaS5vcmc", minSymbols: 21, pattern: `pypi-AgEIcHlwaS5vcmc[\w-]{50,}`},
	// Other services
	{id: "sendgrid-key", keywords: "SG.", minSymbols: 8, pattern: `SG\.[\w=.-]{66,}`},
	{id: "telegram-bot-token", keywords: ":AA", minSymbols: 8, pattern: `\d{8,10}:AA[\w-]{33,}`},
	{id: "shopify-token", keywords: "shpat_,shpca_,shppa_,shpss_", minSymbols: 10, pattern: `shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32,}`},
	{id: "databricks-token", keywords: "dapi", minSymbols: 8, pattern: `dapi[a-f0-9]{32,}(?:-\d)?`},
	// Formats any service can use. The private key pattern runs on through the key's body, which is
	// the secret, while only the header is what identifies it. The URL pattern is not from gitleaks.
	{id: "private-key", keywords: "PRIVATE KEY", pattern: `-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\w+/=\s:,\\-]*`},
	{id: "jwt", keywords: "eyJ", minSymbols: 8, pattern: `eyJ[\w-]{17,}\.ey[\w/\\-]{17,}\.[\w/\\+=-]*`},
	{id: "url-credentials", keywords: "://", pattern: `://[^\s/?#:@'"{}<>\[\]]{0,64}:[^\s/?#@'"{}<>\[\]]{3,64}@`},
}

// rules is the compiled table. It never changes after startup, so scans can share it without a lock.
var rules = compile(table)

func compile(table []rule) []rule {
	compiled := make([]rule, len(table))
	for i, r := range table {
		r.words = strings.Split(r.keywords, ",")
		r.re = regexp.MustCompile(r.pattern)
		compiled[i] = r
	}
	return compiled
}

// RulesHash returns the SHA-256 of the rule table, in hex: every rule's ID, keywords, entropy filter
// and pattern. Evaluation results are tied to this value, so a changed rule shows up as a changed hash.
func RulesHash() string { return hashRules(table) }

func hashRules(table []rule) string {
	h := sha256.New()
	for _, r := range table {
		// %q keeps one field's text from running into the next, so moving a character across a field
		// boundary changes the hash.
		fmt.Fprintf(h, "%q %q %d %q\n", r.id, r.keywords, r.minSymbols, r.pattern)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// find returns where r matches text, after the keyword test and without the matches its filter drops.
func (r *rule) find(text string) [][]int {
	present := false
	for _, word := range r.words {
		if strings.Contains(text, word) {
			present = true
			break
		}
	}
	if !present {
		return nil
	}
	var kept [][]int
	for _, m := range r.re.FindAllStringIndex(text, -1) {
		if symbols(text[m[0]:m[1]]) >= r.minSymbols {
			kept = append(kept, m)
		}
	}
	return kept
}

// firstRule returns the ID of the first rule matching text, or "".
func firstRule(text string) string {
	for i := range rules {
		if len(rules[i].find(text)) > 0 {
			return rules[i].id
		}
	}
	return ""
}

// symbols counts the different bytes in s.
func symbols(s string) int {
	var seen [256]bool
	count := 0
	for i := range len(s) {
		if !seen[s[i]] {
			seen[s[i]] = true
			count++
		}
	}
	return count
}
