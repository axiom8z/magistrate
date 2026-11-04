package prov

import (
	"bytes"
	"encoding/json/jsontext"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Link patterns, after folding fullwidth forms. Go's regexp has no lookaround, so each takes the most
// it can and the code decides the rest.
var (
	schemeLink = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s'"<>)\]]+`)
	emailLink  = regexp.MustCompile(`[\w.+\-\p{L}\p{M}\p{N}]+@[\w\-\p{L}\p{M}\p{N}]+(?:\.[\w\-\p{L}\p{M}\p{N}]+)+`)
	ipv4Link   = regexp.MustCompile(`(?:\b|_)\d{1,3}(?:\.\d{1,3}){3}(?:[:/?#][^\s'"<>)\]]*)?`)
	ibanLink   = regexp.MustCompile(`(?i)(?:\b|_)[a-z]{2}\d{2}(?:[ -]?[a-z0-9]){11,30}`)
	dottedRun  = regexp.MustCompile(`[\w.\-\p{L}\p{M}\p{N}]+`)
	linkTail   = regexp.MustCompile(`^[:/?#][^\s'"<>)\]]*`)
	// hostEnd is a last label of 2-24 letters. Non-ASCII may follow, since text with no spaces between
	// words runs straight on from a link.
	hostEnd = regexp.MustCompile(`^[A-Za-z]{2,24}(?:$|[^\x00-\x7f])`)

	urlScheme    = regexp.MustCompile(`^[a-z][a-z0-9+.-]*://`)
	promptScheme = regexp.MustCompile(`[a-z][a-z0-9+.-]*://`)
	promptWWW    = regexp.MustCompile(`(^|[^\w.-])www\.`)
)

// fold is ASCII case folding. strings.ToLower won't do, because it maps the Kelvin sign to "k", and
// then a value spelled in other characters could match.
func fold(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// canon is the form a value compares in: folded, and a URL without its scheme, www. or trailing slash.
func canon(value string) string {
	value = urlScheme.ReplaceAllString(fold(value), "")
	return strings.TrimRight(strings.TrimPrefix(value, "www."), "/")
}

// canonPrompt puts text in the form canon's output is looked for in. A trailing slash can stay, since
// a slash is allowed beside a token.
func canonPrompt(text string) string {
	return promptWWW.ReplaceAllString(promptScheme.ReplaceAllString(fold(text), ""), "$1")
}

func isASCII(s string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool { return r >= utf8.RuneSelf })
}

func allDigits(s string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool { return r < '0' || r > '9' })
}

// glued reports whether a rune beside a token would make it part of a longer one. A name inside an
// address, or a host inside a longer host, is not what the user named.
func glued(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsMark(r) || r == '_' || r == '@' || r == '-'
}

// tokenIn reports whether value appears in text as a whole token: nothing glued to either end, and no
// "." before it, so "x.com" is not found in "evil.x.com". A "." after is fine, for the end of a
// sentence. A multi-word value is just a longer token, so it matches only as one phrase.
func tokenIn(value, text string) bool {
	for from := 0; value != ""; {
		at := strings.Index(text[from:], value)
		if at < 0 {
			return false
		}
		start, end := from+at, from+at+len(value)
		before, _ := utf8.DecodeLastRuneInString(text[:start])
		after, _ := utf8.DecodeRuneInString(text[end:])
		if (start == 0 || (!glued(before) && before != '.')) && (end == len(text) || !glued(after)) {
			return true
		}
		from = start + 1
	}
	return false
}

// A leaf is one value inside a JSON argument or result.
type leaf struct {
	kind jsontext.Kind // the JSON kind; a name in an object is kindName
	text string        // a string as decoded; anything else as written
}

// kindName marks an object's member name. Those are chosen by whoever wrote the JSON and reach the
// tool like any value, so a control argument can't hide a recipient in one.
const kindName jsontext.Kind = 'k'

// leaves flattens JSON with a token stream rather than recursion, so depth costs nothing. Numbers stay
// as written, which means 13.0 is not 13: a rewrite that fails closed.
func leaves(raw jsontext.Value) []leaf {
	var out []leaf
	dec := jsontext.NewDecoder(bytes.NewReader(raw))
	for {
		tok, err := dec.ReadToken()
		if err != nil {
			return out
		}
		kind := tok.Kind()
		if kind == jsontext.KindBeginObject || kind == jsontext.KindEndObject ||
			kind == jsontext.KindBeginArray || kind == jsontext.KindEndArray {
			continue
		}
		// After a name is read, the object holding it has an odd count of names and values.
		if inside, n := dec.StackIndex(dec.StackDepth()); inside == jsontext.KindBeginObject && n%2 == 1 {
			kind = kindName
		}
		out = append(out, leaf{kind, tok.String()})
	}
}

// Strings returns what the secret scanner reads from JSON: strings and numbers in document order, then
// member names. Values come first and together, so that the scanner's join of them can catch a secret
// split across sibling values with no name in the middle of it.
func Strings(raw jsontext.Value) []string {
	var values, names []string
	for _, l := range leaves(raw) {
		switch l.kind {
		case kindName:
			names = append(names, l.text)
		case jsontext.KindString, jsontext.KindNumber:
			values = append(values, l.text)
		}
	}
	return append(values, names...)
}

// foldWide maps fullwidth forms to ASCII and drops invisible format characters, for the link matcher
// only. Without it a link in content would fail open, by not looking like a link at all.
func foldWide(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 0xFF01 && r <= 0xFF5E:
			return r - 0xFEE0
		case r == 0x3002 || r == 0xFF61:
			return '.'
		case r == 0x3000:
			return ' '
		case unicode.Is(unicode.Cf, r):
			return -1
		}
		return r
	}, s)
}

// links finds what DESIGN section 3 calls links in free text. Each pattern blanks what it finds, so a
// link is reported once, and whole: a URL is not also reported as the host inside it.
func links(content string) []string {
	text := foldWide(content)
	var found []string
	take := func(pattern *regexp.Regexp) {
		text = pattern.ReplaceAllStringFunc(text, func(m string) string {
			found = append(found, m)
			return " "
		})
	}
	take(schemeLink)
	take(emailLink)
	take(ipv4Link)
	found = append(found, hosts(text)...)
	take(ibanLink) // last, because this one can run across words and would swallow a host
	for i, link := range found {
		found[i] = strings.TrimRight(link, ".,;:!?")
	}
	return found
}

// hosts walks the text one dotted run at a time, because a path after a host has to be skipped: the
// file.txt in x.com/file.txt is not a second link.
func hosts(text string) []string {
	var found []string
	for {
		at := dottedRun.FindStringIndex(text)
		if at == nil {
			return found
		}
		end := at[1]
		if run := strings.TrimLeft(text[at[0]:end], "."); isHost(run) {
			end += len(linkTail.FindString(text[end:]))
			found = append(found, strings.TrimLeft(text[at[0]:end], "."))
		}
		text = text[end:]
	}
}

// isHost looks at every label and not just the last, so evil.com.x1 still counts.
func isHost(run string) bool {
	labels := strings.Split(run, ".")
	for i := 1; i < len(labels); i++ {
		if labels[i-1] != "" && hostEnd.MatchString(labels[i]) {
			return true
		}
	}
	return false
}
