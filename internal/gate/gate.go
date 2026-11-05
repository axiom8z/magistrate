// Package gate makes the one decision the gateway exists for. Decide is pure, so every row of its
// table can be tested without a file, a server or a clock, and internal/archtest makes sure the
// front is the only caller.
package gate

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/axiom8z/magistrate/internal/policy"
)

// Action is what happens to a call.
type Action string

// The three outcomes.
const (
	Allow Action = "allow"
	Ask   Action = "ask"
	Block Action = "block"
)

// Rules Decide names by itself. The others arrive in Input.
const (
	RuleSession = "session-exposed"
	RuleBudget  = "ask-budget-spent"
	RuleRefused = "ask-already-refused"
)

// Input is all Decide may look at. The front gathers it, so that nothing here touches the disk.
type Input struct {
	Mode      string
	Bad       string // the rule, if the call fails before its values matter: unknown argument and so on
	Secret    string // the secret rule that fired, or "": no person can approve this one
	Read      bool
	HasPrompt bool
	Exposed   bool   // the latch, which is looked at only with no prompt file and in session mode
	Finding   string // the rule of the first value that failed, or "" if all of them passed
	AsksLeft  int
	Refused   bool // a person has already refused this same call
}

// Decision is what Decide returns. Rule says why for Ask and Block.
type Decision struct {
	Action Action
	Rule   string
	// ArgsAreSources means the call came before the latch with no prompt file, so its arguments can
	// only have come from the user and may source later values.
	ArgsAreSources bool
}

// Decide is the first-match table of DESIGN section 4. A mode it does not know is treated as value,
// the strict one, though policy lint should make that impossible.
func Decide(in Input) Decision {
	if in.Mode == policy.ModePass {
		return Decision{Action: Allow}
	}
	if in.Bad != "" {
		return Decision{Action: Block, Rule: in.Bad}
	}
	if in.Secret != "" {
		return Decision{Action: Block, Rule: in.Secret}
	}
	session := in.Mode == policy.ModeSession
	// With a prompt file in value mode the latch is not read at all: each value answers for itself,
	// from the first call on, so nothing is gained by knowing when the session was exposed.
	beforeLatch := (session || !in.HasPrompt) && !in.Exposed
	switch {
	case beforeLatch:
		return Decision{Action: Allow, ArgsAreSources: !session}
	case in.Read:
		return Decision{Action: Allow}
	case !session && in.Finding == "":
		return Decision{Action: Allow}
	case in.Refused:
		return Decision{Action: Block, Rule: RuleRefused}
	case in.AsksLeft <= 0:
		return Decision{Action: Block, Rule: RuleBudget}
	case session:
		return Decision{Action: Ask, Rule: RuleSession}
	}
	return Decision{Action: Ask, Rule: in.Finding}
}

// Latch is a file that says untrusted output may have reached the agent. Only a new state directory
// clears it, because the agent's memory of what it read outlives this process.
type Latch struct {
	path string
	mu   sync.Mutex
	set  bool
}

// NewLatch returns the latch kept in the state directory dir.
func NewLatch(dir string) *Latch { return &Latch{path: filepath.Join(dir, "latch")} }

// Set makes the latch durable and returns once it is. The caller forwards the first untrusted call
// only after that, or a crash could lose the fact that its output was ever read.
func (l *Latch) Set() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.set {
		return nil
	}
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	if err := errors.Join(f.Sync(), f.Close()); err != nil {
		return err
	}
	// A new file's name survives a power cut only once its folder is synced. Windows can't sync a
	// folder, so this is best effort.
	if d, err := os.Open(filepath.Dir(l.path)); err == nil {
		d.Sync()
		d.Close()
	}
	l.set = true
	return nil
}

// Exposed reports whether the latch is set. Anything but a clear "no such file" counts as set, so a
// latch that can't be read fails closed.
func (l *Latch) Exposed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.set {
		return true
	}
	_, err := os.Stat(l.path)
	l.set = err == nil
	return !errors.Is(err, fs.ErrNotExist)
}
