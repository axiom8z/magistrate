package gate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/axiom8z/sayswho/internal/policy"
)

const rule = "some-rule"

// Every row of the table in DESIGN section 4, in order, and in every mode that reaches it.
func TestDecideRows(t *testing.T) {
	tests := []struct {
		name string
		in   Input
		want Decision
	}{
		// pass decides nothing, so that it can equal no gateway at all.
		{"pass allows a bad call", Input{Mode: policy.ModePass, Bad: rule}, Decision{Action: Allow}},
		{"pass allows a failed value", Input{Mode: policy.ModePass, Finding: rule}, Decision{Action: Allow}},
		{"pass allows after the latch", Input{Mode: policy.ModePass, Exposed: true}, Decision{Action: Allow}},

		// Row 1: malformed, unknown tool or argument, pin mismatch. Nothing beats it, not even a read.
		{"value: bad", Input{Mode: policy.ModeValue, Bad: rule, HasPrompt: true}, Decision{Action: Block, Rule: rule}},
		{"value: a bad read", Input{Mode: policy.ModeValue, Bad: rule, HasPrompt: true, Read: true}, Decision{Action: Block, Rule: rule}},
		{"value: bad, before the latch with no prompt", Input{Mode: policy.ModeValue, Bad: rule}, Decision{Action: Block, Rule: rule}},
		{"value: bad, with asks left", Input{Mode: policy.ModeValue, Bad: rule, HasPrompt: true, AsksLeft: 5}, Decision{Action: Block, Rule: rule}},
		{"session: bad", Input{Mode: policy.ModeSession, Bad: rule}, Decision{Action: Block, Rule: rule}},
		{"session: a bad read", Input{Mode: policy.ModeSession, Bad: rule, Read: true}, Decision{Action: Block, Rule: rule}},

		// Row 2: a secret, or a scan over budget. There is no approval path, so asks left change nothing.
		{"value: a secret", Input{Mode: policy.ModeValue, Secret: rule, HasPrompt: true, AsksLeft: 5}, Decision{Action: Block, Rule: rule}},
		{"value: a secret in a read", Input{Mode: policy.ModeValue, Secret: rule, HasPrompt: true, Read: true, AsksLeft: 5}, Decision{Action: Block, Rule: rule}},
		{"value: a secret, before the latch with no prompt", Input{Mode: policy.ModeValue, Secret: rule, AsksLeft: 5}, Decision{Action: Block, Rule: rule}},
		{"session: a secret, before the latch", Input{Mode: policy.ModeSession, Secret: rule, AsksLeft: 5}, Decision{Action: Block, Rule: rule}},
		{"row 1 comes first", Input{Mode: policy.ModeValue, Bad: "first", Secret: rule}, Decision{Action: Block, Rule: "first"}},
		{"pass allows a secret, as no gateway would", Input{Mode: policy.ModePass, Secret: rule}, Decision{Action: Allow}},

		// Row 3: a read, or no prompt file and a clear latch, when arguments become sources.
		{"value: a read", Input{Mode: policy.ModeValue, HasPrompt: true, Read: true, Finding: rule}, Decision{Action: Allow}},
		{"value: a read with no asks left", Input{Mode: policy.ModeValue, HasPrompt: true, Read: true, Refused: true}, Decision{Action: Allow}},
		{"value: a read after the latch with no prompt", Input{Mode: policy.ModeValue, Read: true, Exposed: true, Finding: rule}, Decision{Action: Allow}},
		{"value: no prompt, latch clear, an act", Input{Mode: policy.ModeValue, Finding: rule}, Decision{Action: Allow, ArgsAreSources: true}},
		{"value: no prompt, latch clear, a read: its arguments are sources too", Input{Mode: policy.ModeValue, Read: true, Finding: rule}, Decision{Action: Allow, ArgsAreSources: true}},
		{"session: a read after the latch", Input{Mode: policy.ModeSession, Read: true, Exposed: true}, Decision{Action: Allow}},
		{"session: an act before the latch", Input{Mode: policy.ModeSession, Finding: rule}, Decision{Action: Allow}},
		{"session: a read before the latch", Input{Mode: policy.ModeSession, Read: true}, Decision{Action: Allow}},

		// Row 4: every value passed.
		{"value: all sourced", Input{Mode: policy.ModeValue, HasPrompt: true}, Decision{Action: Allow}},
		{"value: all sourced, after the latch, with no prompt", Input{Mode: policy.ModeValue, Exposed: true}, Decision{Action: Allow}},
		{"value: all sourced, with a refused digest: nothing asks, so nothing is refused", Input{Mode: policy.ModeValue, HasPrompt: true, Refused: true}, Decision{Action: Allow}},
		{"session has no such row: all sourced still asks", Input{Mode: policy.ModeSession, Exposed: true, AsksLeft: 1, HasPrompt: true}, Decision{Action: Ask, Rule: RuleSession}},

		// Row 5: budget left, and this digest not already refused.
		{"value: a failed value", Input{Mode: policy.ModeValue, HasPrompt: true, Finding: rule, AsksLeft: 1}, Decision{Action: Ask, Rule: rule}},
		{"value: a failed value after the latch, with no prompt", Input{Mode: policy.ModeValue, Exposed: true, Finding: rule, AsksLeft: 1}, Decision{Action: Ask, Rule: rule}},
		{"session: an act after the latch", Input{Mode: policy.ModeSession, Exposed: true, AsksLeft: 1}, Decision{Action: Ask, Rule: RuleSession}},
		{"session: the finding is not the reason", Input{Mode: policy.ModeSession, Exposed: true, AsksLeft: 1, Finding: rule}, Decision{Action: Ask, Rule: RuleSession}},

		// Row 6: otherwise.
		{"value: no budget", Input{Mode: policy.ModeValue, HasPrompt: true, Finding: rule}, Decision{Action: Block, Rule: RuleBudget}},
		{"value: a negative budget", Input{Mode: policy.ModeValue, HasPrompt: true, Finding: rule, AsksLeft: -1}, Decision{Action: Block, Rule: RuleBudget}},
		{"value: already refused", Input{Mode: policy.ModeValue, HasPrompt: true, Finding: rule, AsksLeft: 1, Refused: true}, Decision{Action: Block, Rule: RuleRefused}},
		{"session: no budget", Input{Mode: policy.ModeSession, Exposed: true}, Decision{Action: Block, Rule: RuleBudget}},
		{"session: already refused", Input{Mode: policy.ModeSession, Exposed: true, AsksLeft: 1, Refused: true}, Decision{Action: Block, Rule: RuleRefused}},

		// Fail closed.
		{"an unknown mode is strict", Input{Mode: "nonsense", HasPrompt: true, Finding: rule, AsksLeft: 1}, Decision{Action: Ask, Rule: rule}},
		{"no mode is strict", Input{HasPrompt: true, Finding: rule}, Decision{Action: Block, Rule: RuleBudget}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Decide(tt.in); got != tt.want {
				t.Fatalf("Decide(%+v) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}

// The latch is read only without a prompt file and in session mode. With a prompt file in value mode
// it must make no difference to anything, in any row. DESIGN: the rerun found it changes nothing.
func TestAPromptInValueModeNeverReadsTheLatch(t *testing.T) {
	for _, bad := range []string{"", rule} {
		for _, read := range []bool{false, true} {
			for _, finding := range []string{"", rule} {
				for _, asks := range []int{0, 1} {
					for _, refused := range []bool{false, true} {
						in := Input{Mode: policy.ModeValue, HasPrompt: true, Bad: bad, Read: read, Finding: finding, AsksLeft: asks, Refused: refused}
						clear := Decide(in)
						in.Exposed = true
						if set := Decide(in); set != clear {
							t.Errorf("the latch changed %+v: %+v against %+v", in, set, clear)
						}
						if clear.ArgsAreSources {
							t.Errorf("with a prompt file, arguments became sources: %+v", in)
						}
					}
				}
			}
		}
	}
}

func TestArgumentsBecomeSourcesOnlyBeforeTheLatchWithNoPrompt(t *testing.T) {
	for _, tt := range []struct {
		in   Input
		want bool
	}{
		{Input{Mode: policy.ModeValue}, true},
		{Input{Mode: policy.ModeValue, Read: true}, true},
		{Input{Mode: policy.ModeValue, Exposed: true, Read: true}, false},
		{Input{Mode: policy.ModeValue, Exposed: true}, false},
		{Input{Mode: policy.ModeValue, HasPrompt: true}, false},
		{Input{Mode: policy.ModeValue, Bad: rule}, false},
		{Input{Mode: policy.ModeSession}, false},
		{Input{Mode: policy.ModePass}, false},
	} {
		if got := Decide(tt.in).ArgsAreSources; got != tt.want {
			t.Errorf("Decide(%+v).ArgsAreSources = %v", tt.in, got)
		}
	}
}

func TestLatchIsClearUntilSet(t *testing.T) {
	dir := t.TempDir()
	l := NewLatch(dir)
	if l.Exposed() {
		t.Fatal("a new state directory reads as exposed")
	}
	if err := l.Set(); err != nil {
		t.Fatal(err)
	}
	if !l.Exposed() {
		t.Fatal("a set latch reads as clear")
	}
	if _, err := os.Stat(filepath.Join(dir, "latch")); err != nil {
		t.Fatalf("no file on disk: %v", err)
	}
	if err := l.Set(); err != nil {
		t.Errorf("setting it twice: %v", err)
	}
}

func TestLatchSurvivesARestartAndAnythingAtItsPathCounts(t *testing.T) {
	dir := t.TempDir()
	if err := NewLatch(dir).Set(); err != nil {
		t.Fatal(err)
	}
	if !NewLatch(dir).Exposed() {
		t.Error("a new process on the same state directory reads as clear")
	}
	if NewLatch(t.TempDir()).Exposed() {
		t.Error("a new state directory should be clear")
	}
	full := t.TempDir()
	if err := os.WriteFile(filepath.Join(full, "latch"), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !NewLatch(full).Exposed() {
		t.Error("a file with garbage in it reads as clear")
	}
	folder := t.TempDir()
	if err := os.Mkdir(filepath.Join(folder, "latch"), 0o700); err != nil {
		t.Fatal(err)
	}
	if !NewLatch(folder).Exposed() {
		t.Error("a folder at the latch's path reads as clear")
	}
}

// Once set, the latch stays set in this process even if the file goes away, since only a new state
// directory may clear it.
func TestLatchStaysSetWhenItsFileIsDeleted(t *testing.T) {
	dir := t.TempDir()
	l := NewLatch(dir)
	if err := l.Set(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "latch")); err != nil {
		t.Fatal(err)
	}
	if !l.Exposed() {
		t.Fatal("deleting the file cleared the latch in a running process")
	}
}

// A path no system call will accept stands in for a latch that can't be read, since a real permission
// failure is hard to arrange the same way on all three operating systems.
func TestAnUnreadableLatchCountsAsExposed(t *testing.T) {
	l := NewLatch("bad\x00dir")
	if !l.Exposed() {
		t.Fatal("an unreadable latch read as clear")
	}
	if err := l.Set(); err == nil {
		t.Fatal("setting a latch that can't be written returned no error")
	}
	if !l.Exposed() {
		t.Fatal("a failed Set cleared it")
	}
}

func TestSetFailsWhenTheFolderIsGone(t *testing.T) {
	l := NewLatch(filepath.Join(t.TempDir(), "gone"))
	if err := l.Set(); err == nil {
		t.Fatal("no error")
	}
	if l.Exposed() {
		t.Error("nothing was written and the folder does not exist, so this should read as clear")
	}
}
