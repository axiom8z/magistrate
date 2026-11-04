// Package policy loads the operator's policy file. Anything malformed stops startup, because a
// gateway running on a policy it half understood would enforce something nobody wrote.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/axiom8z/sayswho/internal/upstream"
)

// maxNameLen is the longest tool name the MCP specification recommends.
const maxNameLen = 128

// Modes, from DESIGN section 8.
const (
	ModePass    = "pass"    // forward everything and decide nothing
	ModeSession = "session" // any act after the latch asks
	ModeValue   = "value"   // every control value must trace to a source
)

// What a tool does, and whose word its output is.
const (
	EffectRead      = "read"
	EffectAct       = "act"
	OutputTrusted   = "trusted"
	OutputUntrusted = "untrusted"
)

// Roles an argument can have, from DESIGN section 3.
const (
	RoleControl    = "control"    // chooses who, what or where, so it must trace to a source
	RoleContent    = "content"    // free text, but any link in it must trace to a source
	RoleQuantity   = "quantity"   // a number from 0 to Max, or one named in the prompt
	RoleData       = "data"       // must match Type, and counts as control if it does not
	RoleCredential = "credential" // must be in the prompt
)

// Types a data argument can declare.
const (
	TypeNumber  = "number"
	TypeBoolean = "boolean"
	TypeDate    = "date"
	TypeEnum    = "enum"
)

// bindPath is the small path language of binds: names joined by dots, each maybe followed by [*].
var bindPath = regexp.MustCompile(`^[A-Za-z0-9_-]+(\[\*\])?(\.[A-Za-z0-9_-]+(\[\*\])?)*$`)

// Policy is the whole policy file.
type Policy struct {
	Mode           string            `json:"mode"`
	BoundIDs       bool              `json:"bound_ids,omitzero"`
	AsksPerSession int               `json:"asks_per_session,omitzero"`
	TrustedValues  []string          `json:"trusted_values,omitzero"`
	Servers        map[string]Server `json:"servers"`
	Tools          map[string]Tool   `json:"tools,omitzero"`
}

// Server says how to start one MCP server. Env lists variable names to pass through from the
// gateway's own environment, never values, so a policy file holds no secrets.
type Server struct {
	Command string   `json:"command"`
	Args    []string `json:"args,omitzero"`
	Env     []string `json:"env,omitzero"`
}

// Tool is the operator's label for one tool, under the name clients see, <server>__<tool>.
type Tool struct {
	Effect       string         `json:"effect"`
	Output       string         `json:"output,omitzero"`
	Store        string         `json:"store,omitzero"`
	Irreversible bool           `json:"irreversible,omitzero"`
	Pin          string         `json:"pin"`
	Args         map[string]Arg `json:"args,omitzero"`
	Binds        *Binds         `json:"binds,omitzero"`
}

// Binds names where a lookup's result holds IDs that arguments of kind Kind may accept.
type Binds struct {
	Path string `json:"path"`
	Kind string `json:"kind"`
}

// Arg is one argument's label. In the file it is a bare role name or an object.
type Arg struct {
	Role   string   `json:"role"`
	Bind   string   `json:"bind,omitzero"`
	Max    *float64 `json:"max,omitzero"`
	Type   string   `json:"type,omitzero"`
	Values []string `json:"values,omitzero"`
}

// UnmarshalJSON accepts both spellings. The local type has no methods, or the second call would land
// back here for ever.
func (a *Arg) UnmarshalJSON(data []byte) error {
	if jsontext.Value(data).Kind() == jsontext.KindString {
		return json.Unmarshal(data, &a.Role)
	}
	type plain Arg
	return json.Unmarshal(data, (*plain)(a), json.RejectUnknownMembers(true))
}

// ArgFor returns the label for one argument of a call, and false if the tool does not take it. DESIGN
// section 3's own find_notes has binds and no args, and binding needs a control leaf, so a read with
// no args block takes anything and every leaf counts as control. "args":{} means no arguments at all.
func (t Tool) ArgFor(name string) (Arg, bool) {
	if a, ok := t.Args[name]; ok {
		return a, true
	}
	if t.Args == nil && t.Effect == EffectRead {
		return Arg{Role: RoleControl}, true
	}
	return Arg{}, false
}

// Load reads and checks the policy file at path.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse checks a policy held in memory. Unknown keys are errors: a misspelt rule that was silently
// ignored would look like a rule that was enforced.
func Parse(data []byte) (*Policy, error) {
	var p Policy
	if err := json.Unmarshal(data, &p, json.RejectUnknownMembers(true)); err != nil {
		return nil, err
	}
	if err := p.check(); err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *Policy) check() error {
	if p.Mode != ModePass && p.Mode != ModeSession && p.Mode != ModeValue {
		return fmt.Errorf(`mode %q is not available: use "pass", "session" or "value"`, p.Mode)
	}
	if p.AsksPerSession < 0 {
		return errors.New("asks_per_session is negative")
	}
	for _, v := range p.TrustedValues {
		// Values compare after ASCII folding only, so this one could never match anything.
		if strings.ContainsFunc(v, func(r rune) bool { return r >= utf8.RuneSelf }) {
			return fmt.Errorf("trusted value %q is not ASCII", v)
		}
	}
	if len(p.Servers) == 0 {
		return errors.New("no servers")
	}
	for name, s := range p.Servers {
		if err := checkServer(name, s); err != nil {
			return fmt.Errorf("server %q: %w", name, err)
		}
	}
	for name, t := range p.Tools {
		if err := p.checkTool(t); err != nil {
			return fmt.Errorf("tool %q: %w", name, err)
		}
	}
	return nil
}

func checkServer(name string, s Server) error {
	// Clients see <server>__<tool> and calls are split at the first "__". A server name holding
	// "__", or ending in "_" so that one forms at the join, would send a call to the wrong server.
	if !ValidName(name) || strings.Contains(name, "__") || strings.HasSuffix(name, "_") {
		return errors.New(`bad name: use letters, digits, "_", "-" and ".", with no "__" and no trailing "_"`)
	}
	if s.Command == "" {
		return errors.New("no command")
	}
	for _, v := range s.Env {
		if v == "" || strings.ContainsAny(v, "=\x00") {
			return fmt.Errorf("bad variable name %q", v)
		}
	}
	return nil
}

func (p *Policy) checkTool(t Tool) error {
	if t.Effect != EffectRead && t.Effect != EffectAct {
		return fmt.Errorf(`effect %q: use "read" or "act"`, t.Effect)
	}
	if t.Output != "" && t.Output != OutputTrusted && t.Output != OutputUntrusted {
		return fmt.Errorf(`output %q: use "trusted" or "untrusted"`, t.Output)
	}
	if t.Output == OutputTrusted && p.actWrites(t.Store) {
		return fmt.Errorf("output is trusted, but an act writes store %q, so whoever steers that act writes this output", t.Store)
	}
	if t.Binds != nil {
		if t.Effect != EffectRead {
			return errors.New("binds on an act: only a lookup can bind IDs")
		}
		if t.Binds.Kind == "" || !bindPath.MatchString(t.Binds.Path) {
			return fmt.Errorf("binds: bad path %q or empty kind", t.Binds.Path)
		}
	}
	for name, a := range t.Args {
		if err := p.checkArg(t, a); err != nil {
			return fmt.Errorf("argument %q: %w", name, err)
		}
	}
	return nil
}

func (p *Policy) checkArg(t Tool, a Arg) error {
	switch a.Role {
	case RoleControl, RoleContent, RoleCredential:
	case RoleQuantity:
		if a.Max == nil || *a.Max < 0 {
			return errors.New("a quantity needs a max of 0 or more")
		}
	case RoleData:
		if a.Type != TypeNumber && a.Type != TypeBoolean && a.Type != TypeDate && (a.Type != TypeEnum || len(a.Values) == 0) {
			return errors.New("data needs a type of number, boolean, date, or enum with values")
		}
	default:
		return fmt.Errorf("unknown role %q", a.Role)
	}
	// A key on the wrong role would do nothing, and look as though it did something.
	if (a.Bind != "" && a.Role != RoleControl) || (a.Max != nil && a.Role != RoleQuantity) ||
		(a.Type != "" && a.Role != RoleData) || (a.Values != nil && a.Type != TypeEnum) {
		return fmt.Errorf("a key here does not apply to role %q", a.Role)
	}
	if a.Bind == "" {
		return nil
	}
	if t.Irreversible {
		return errors.New("bind on an irreversible act: a bound ID is too narrow a promise for that")
	}
	if !p.anyBinds(a.Bind) {
		return fmt.Errorf("bind %q: no lookup binds that kind", a.Bind)
	}
	return nil
}

func (p *Policy) actWrites(store string) bool {
	for _, t := range p.Tools {
		if store != "" && t.Effect == EffectAct && t.Store == store {
			return true
		}
	}
	return false
}

func (p *Policy) anyBinds(kind string) bool {
	for _, t := range p.Tools {
		if t.Binds != nil && t.Binds.Kind == kind {
			return true
		}
	}
	return false
}

// ValidName reports whether s fits the MCP rule for tool names: 1 to 128 characters from ASCII
// letters, digits, "_", "-" and ".".
func ValidName(s string) bool {
	if s == "" || len(s) > maxNameLen {
		return false
	}
	for _, c := range []byte(s) {
		letter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		digit := c >= '0' && c <= '9'
		if !letter && !digit && c != '_' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

// Pin is the hash a policy records for a tool: SHA-256 of the RFC 8785 form of its definition, as the
// server names it. It covers what the gateway reads of a tool and no more, so a change to _meta costs
// no pin, while a change the model or init could see does.
func Pin(t upstream.Tool) (string, error) {
	raw, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	definition := jsontext.Value(raw)
	if err := definition.Canonicalize(); err != nil {
		return "", err
	}
	sum := sha256.Sum256(definition)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
