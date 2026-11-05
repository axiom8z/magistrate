// Package secrets finds known-format credentials in what crosses the gateway (DESIGN section 5). It has
// two paths: ScanCall checks an outgoing call, and Redact cleans a result before the model reads it,
// because a model can't re-encode what it never saw. Both see through percent, base64 and hex
// encoding, down to three layers.
//
// Only rule IDs and redacted text leave this package, never a matched value, and it logs nothing. It
// is safe for concurrent use: the rule table never changes, each scan owns its budget, and Registry
// has a lock. What it can't see is stated in DESIGN section 9, and tests named TestMiss pin those limits.
package secrets

import (
	"encoding/base64"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"
)

// RuleOverBudget is the rule ID for a scan that had to stop before it finished.
const RuleOverBudget = "scan-over-budget"

const (
	maxDepth = 3
	// minRun is the shortest stretch worth decoding. 16 base64 characters give 12 bytes, and no
	// real token of any rule is shorter than that.
	minRun = 16
	// The budget for one call. Decoding can multiply the text at every layer, so it is the budget that
	// bounds a scan, and a scan it stops counts as a hit: no one can tell what the rest held.
	maxCandidates = 1 << 16
	maxDecoded    = 16 << 20
)

// encoding says how to spot and read one kind of encoded run.
type encoding struct {
	chars  *[256]bool
	minLen int
	must   string // a run has to hold this
	// offsets is how many starting points to try, since text stuck to the front of a run, like the
	// path before base64 in a URL, shifts every byte after it. Each try is a separate candidate.
	offsets int
	decode  func(string) string
}

// percentStops ends a percent run, so that a token encoded inside a sentence is redacted without the rest.
const percentStops = " \t\r\n\"'`<>"

// Line breaks count as part of a base64 or hex run because the usual tools wrap their output, and
// with every offset tried, a line of other text before the wrapped lines does no harm.
var encodings = []*encoding{
	{chars: charSet("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_\r\n"), minLen: minRun, offsets: 4, decode: decodeBase64},
	{chars: charSet("0123456789abcdefABCDEF\r\n"), minLen: minRun, offsets: 2, decode: decodeHex},
	{chars: allBut(percentStops), minLen: 3, must: "%", offsets: 1, decode: decodePercent},
}

// wholePercent reads a whole text as one percent run. A secret encoded only in part can have its own
// spaces and line breaks left as they are, as a private key does, and then each run holds only a piece.
var wholePercent = &encoding{offsets: 1, decode: decodePercent}

func encodedInPart(text string) bool {
	return strings.Contains(text, "%") && strings.ContainsAny(text, percentStops)
}

var (
	hexChars   = charSet("0123456789abcdefABCDEF")
	tailChars  = charSet("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_=")
	lineBreaks = strings.NewReplacer("\r", "", "\n", "")
	urlSafe    = strings.NewReplacer("-", "+", "_", "/")
)

func charSet(chars string) *[256]bool {
	var set [256]bool
	for i := range len(chars) {
		set[chars[i]] = true
	}
	return &set
}

func allBut(chars string) *[256]bool {
	set := charSet(chars)
	for i := range set {
		set[i] = !set[i]
	}
	return set
}

// decodeBase64 reads either alphabet, with or without padding.
func decodeBase64(run string) string {
	clean := urlSafe.Replace(run)
	if len(clean)%4 == 1 {
		clean = clean[:len(clean)-1] // no base64 has this length, so the last character is not part of it
	}
	decoded, _ := base64.RawStdEncoding.DecodeString(clean) // only alphabet characters reach here
	return string(decoded)
}

func decodeHex(run string) string {
	decoded, _ := hex.DecodeString(run[:len(run)&^1]) // only hex digits reach here
	return string(decoded)
}

// decodePercent leaves a stray % alone. url.QueryUnescape fails on the whole string instead, so a
// single "100%" would hide everything around it.
func decodePercent(run string) string {
	var out strings.Builder
	for i := 0; i < len(run); i++ {
		if run[i] == '%' && i+2 < len(run) && hexChars[run[i+1]] && hexChars[run[i+2]] {
			value, _ := strconv.ParseUint(run[i+1:i+3], 16, 8) // both digits were just checked
			out.WriteByte(byte(value))
			i += 2
		} else {
			out.WriteByte(run[i])
		}
	}
	return out.String()
}

// run is a stretch of text that may be encoded.
type run struct {
	start, end int
	kind       *encoding
}

// findRuns returns every stretch of text that one of the encodings could have produced.
func findRuns(text string) []run {
	var runs []run
	for _, e := range encodings {
		if !strings.Contains(text, e.must) {
			continue
		}
		for i := 0; i < len(text); {
			if !e.chars[text[i]] || text[i] == '\r' || text[i] == '\n' {
				i++
				continue
			}
			end := i
			for end < len(text) && e.chars[text[end]] {
				end++
			}
			if body := strings.TrimRight(text[i:end], "\r\n"); len(body) >= e.minLen && strings.Contains(body, e.must) {
				runs = append(runs, run{i, i + len(body), e})
			}
			i = end
		}
	}
	return runs
}

// scan is the work for one call. Having one per call is why two calls can never share a budget.
type scan struct {
	match               func(string) string // what counts as a hit in plain text
	candidates, decoded int
}

// check returns the first rule that fires on text or on what it decodes to, or RuleOverBudget if the
// budget ran out first.
func (s *scan) check(text string, depth int) string {
	if id := s.match(text); id != "" {
		return id
	}
	if depth == maxDepth {
		return ""
	}
	for _, r := range findRuns(text) {
		if id := s.checkRun(text[r.start:r.end], r.kind, depth); id != "" {
			return id
		}
	}
	if encodedInPart(text) {
		return s.checkRun(text, wholePercent, depth)
	}
	return ""
}

func (s *scan) checkRun(raw string, e *encoding, depth int) string {
	clean := lineBreaks.Replace(raw)
	for offset := range min(e.offsets, len(clean)) {
		s.candidates++
		s.decoded += len(clean) - offset // no encoding here decodes to more than it started as
		if s.candidates > maxCandidates || s.decoded > maxDecoded {
			return RuleOverBudget
		}
		if id := s.check(e.decode(clean[offset:]), depth+1); id != "" {
			return id
		}
	}
	return ""
}

// leaves checks each leaf and then their join, which catches a secret split across siblings. The join
// follows the order given, so the caller should pass the leaves in document order.
func (s *scan) leaves(leaves []string) string {
	for _, leaf := range leaves {
		if id := s.check(leaf, 0); id != "" {
			return id
		}
	}
	if len(leaves) < 2 {
		return ""
	}
	return s.check(strings.Join(leaves, ""), 0)
}

// ScanCall checks the string leaves of one outgoing call. It returns the ID of the first rule that
// fires, RuleOverBudget if the scan could not finish, or "" if the call is clean. Both IDs mean block.
func ScanCall(leaves []string) string {
	s := scan{match: firstRule}
	return s.leaves(leaves)
}

// span is a stretch of text to replace, and the rule that asks for it.
type span struct {
	start, end int
	rule       string
}

// Redact returns text with every match replaced by a marker naming its rule, including any encoded
// run whose decoded form matched, plus the sorted IDs of what fired. Past the budget every run it
// could not decode is replaced too, with RuleOverBudget among the IDs, so the text is safe to pass on
// either way and the caller can still choose to block it.
func Redact(text string) (string, []string) {
	var spans []span
	for i := range rules {
		for _, m := range rules[i].find(text) {
			spans = append(spans, span{m[0], m[1], rules[i].id})
		}
	}
	s := scan{match: firstRule}
	for _, r := range findRuns(text) {
		if id := s.checkRun(text[r.start:r.end], r.kind, 0); id != "" {
			spans = append(spans, span{r.start, r.end, id})
		}
	}
	out, ids := replaceSpans(text, spans)
	// What's left can still hide a secret encoded only in part. Nothing narrower than the whole text is
	// known to hold it, so all of it goes.
	if encodedInPart(out) {
		if id := s.checkRun(out, wholePercent, 0); id != "" {
			ids = append(ids, id)
			slices.Sort(ids)
			return "[REDACTED:" + id + "]", slices.Compact(ids)
		}
	}
	return out, ids
}

func replaceSpans(text string, spans []span) (string, []string) {
	if len(spans) == 0 {
		return text, nil
	}
	slices.SortFunc(spans, func(a, b span) int { return a.start - b.start })
	var out strings.Builder
	var ids []string
	covered := 0
	for _, sp := range spans {
		ids = append(ids, sp.rule)
		// Padding and anything stuck to the end of a match go too, so no fragment of it can stay behind.
		// A match ending in something else, like the @ of URL credentials, is whole: what follows is
		// the host, and it stays.
		end := sp.end
		for tailChars[text[end-1]] && end < len(text) && tailChars[text[end]] {
			end++
		}
		if sp.start >= covered {
			out.WriteString(text[covered:sp.start])
			out.WriteString("[REDACTED:" + sp.rule + "]")
		}
		covered = max(covered, end)
	}
	out.WriteString(text[covered:])
	slices.Sort(ids)
	return out.String(), slices.Compact(ids)
}
