package secrets

import (
	"slices"
	"strings"
	"sync"
)

const (
	minValueLen = 6
	// maxValueLen cuts very long tokens. A leaf holding the whole token still contains the first part.
	maxValueLen = 256
	// The limits keep one tool's output from filling memory or slowing every later check. Once a limit
	// is hit, Contains answers yes to everything: a person is asked more, and no value slips through.
	maxValues  = 1 << 16
	maxPerHead = 16
	// valueDelimiters end a token. "/" and "=" are among them even though base64 uses them, because
	// the pieces are still found: any text holding the whole value holds each piece.
	valueDelimiters = " \t\r\n\"'`,;:=/\\|&()[]{}<>"
	valueEdges      = ".!?*-_+~#"
)

// Registry holds the sensitive values seen in one session: the tokens in the output of a tool labelled
// sensitive (DESIGN section 3, question 5). An act whose arguments hold one can't be allowed without
// asking (section 4). Values are looked up by their first characters, so the cost of a check depends on
// the length of the text and not on how many values there are.
type Registry struct {
	mu     sync.RWMutex
	byHead map[string][]string
	count  int
	full   bool
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry { return &Registry{byHead: map[string][]string{}} }

// Register adds every digit-bearing token of six or more characters found in text.
func (r *Registry) Register(text string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	isDelimiter := func(c rune) bool { return strings.ContainsRune(valueDelimiters, c) }
	for _, token := range strings.FieldsFunc(fold(text), isDelimiter) {
		token = strings.Trim(token, valueEdges)
		if len(token) >= minValueLen && strings.ContainsAny(token, "0123456789") {
			r.add(token[:min(len(token), maxValueLen)])
		}
	}
}

func (r *Registry) add(token string) {
	head := token[:minValueLen]
	if slices.Contains(r.byHead[head], token) {
		return
	}
	if r.count == maxValues || len(r.byHead[head]) == maxPerHead {
		r.full = true
		return
	}
	r.byHead[head] = append(r.byHead[head], token)
	r.count++
}

// Contains reports whether any leaf, their join, or anything they decode to holds a registered value.
// A check over budget answers yes, since it can't say no. It says only yes or no, never which value.
func (r *Registry) Contains(leaves []string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.full {
		return true
	}
	if r.count == 0 {
		return false
	}
	s := scan{match: r.firstValue}
	return s.leaves(leaves) != ""
}

// firstValue is the plain-text match for a scan. Any non-empty answer is a hit, so it names no value.
func (r *Registry) firstValue(text string) string {
	folded := fold(text)
	for i := 0; i+minValueLen <= len(folded); i++ {
		for _, value := range r.byHead[folded[i:i+minValueLen]] {
			if strings.HasPrefix(folded[i:], value) {
				return "registered-value"
			}
		}
	}
	return ""
}

// fold makes spellings of one value compare equal: ASCII case goes, and so does a space or hyphen
// between two digits, so that "4111 1111" and "4111-1111" both become "41111111".
func fold(s string) string {
	out := make([]byte, 0, len(s))
	for i := range len(s) {
		c := s[i]
		if (c == ' ' || c == '-') && i > 0 && i+1 < len(s) && isDigit(s[i-1]) && isDigit(s[i+1]) {
			continue
		}
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		out = append(out, c)
	}
	return string(out)
}

func isDigit(c byte) bool { return '0' <= c && c <= '9' }
