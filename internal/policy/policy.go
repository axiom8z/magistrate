// Package policy loads the operator's policy file. Anything malformed stops startup, because a
// gateway running on a policy it half understood would enforce something nobody wrote.
//
// This milestone only acts on mode and servers. bound_ids, asks_per_session, trusted_values and
// tools are parsed and kept for the decision logic still to come.
package policy

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"strings"
)

// maxNameLen is the longest tool name the MCP specification recommends.
const maxNameLen = 128

// Policy is the whole policy file.
type Policy struct {
	Mode           string                    `json:"mode"`
	BoundIDs       bool                      `json:"bound_ids"`
	AsksPerSession int                       `json:"asks_per_session"`
	TrustedValues  []string                  `json:"trusted_values"`
	Servers        map[string]Server         `json:"servers"`
	Tools          map[string]jsontext.Value `json:"tools"`
}

// Server says how to start one MCP server. Env lists variable names to pass through from the
// gateway's own environment, never values, so a policy file holds no secrets.
type Server struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
	Env     []string `json:"env"`
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
	// Other modes promise checks that do not exist yet. Accepting them would forward everything
	// while the operator believes the rules are on.
	if p.Mode != "pass" {
		return fmt.Errorf(`mode %q is not available: this build only has "pass"`, p.Mode)
	}
	if p.AsksPerSession < 0 {
		return errors.New("asks_per_session is negative")
	}
	if len(p.Servers) == 0 {
		return errors.New("no servers")
	}
	for name, s := range p.Servers {
		if err := checkServer(name, s); err != nil {
			return fmt.Errorf("server %q: %w", name, err)
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
