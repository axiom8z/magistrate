package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

const zeroHead = "0000000000000000000000000000000000000000000000000000000000000000"

// writeLog creates a log of n records in a fresh state directory and returns its path.
func writeLog(t *testing.T, n int) string {
	t.Helper()
	dir := t.TempDir()
	l, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		rec := Record{Tool: "srv__tool", Decision: Allow, ArgLens: []int{i, 3}, ArgsHMAC: l.Digest("srv__tool", []byte("{}"))}
		if err := l.Append(rec, i%2 == 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "audit.log")
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// verifyBytes runs the real Verify on data, the same path the CLI uses.
func verifyBytes(t *testing.T, data []byte, head string) (Summary, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return Verify(path, head)
}

func lines(data []byte) [][]byte { return bytes.SplitAfter(data[:len(data):len(data)], []byte("\n")) }

func TestLogFormat(t *testing.T) {
	data := readFile(t, writeLog(t, 2))
	all := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(all) != 2 {
		t.Fatalf("%d lines, want 2", len(all))
	}
	for i, line := range all {
		var parsed struct {
			Rec  Record `json:"rec"`
			Hash string `json:"hash"`
		}
		if err := json.Unmarshal([]byte(line), &parsed, json.RejectUnknownMembers(true)); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		if parsed.Rec.Seq != uint64(i+1) || parsed.Rec.Tool != "srv__tool" || parsed.Rec.Decision != Allow || parsed.Rec.Time == "" {
			t.Errorf("line %d: record = %+v", i, parsed.Rec)
		}
		if !ValidHead(parsed.Hash) {
			t.Errorf("line %d: hash = %q", i, parsed.Hash)
		}
		if !strings.HasPrefix(line, `{"rec":{"seq":`) {
			t.Errorf("line %d does not start with the record: %s", i, line)
		}
	}
}

// The format is a promise to anyone writing their own verifier, so this computes it the way the
// package comment states it, with sha256 directly and without using chain.
func TestHashFollowsTheDocumentedFormula(t *testing.T) {
	data := readFile(t, writeLog(t, 3))
	prev := make([]byte, 32) // all zeros before the first record
	const before, after = `{"rec":`, `,"hash":"`
	for line := range strings.Lines(string(data)) {
		split := strings.LastIndex(line, after)
		rec := line[len(before):split]
		sum := sha256.Sum256(append(bytes.Clone(prev), rec...))
		want := hex.EncodeToString(sum[:])
		if got := line[split+len(after) : len(line)-len("\"}\n")]; got != want {
			t.Fatalf("hash = %s, want %s\nline: %s", got, want, line)
		}
		prev = sum[:]
	}
}

// rewriteChain edits the first record and recomputes every hash, as a writer with full access could.
func rewriteChain(t *testing.T, data []byte) []byte {
	t.Helper()
	var rewritten []byte
	var prev [32]byte
	for i, line := range lines(data) {
		if len(line) == 0 {
			continue
		}
		rec := line[len(`{"rec":`):bytes.LastIndex(line, []byte(`,"hash":"`))]
		if i == 0 {
			rec = bytes.Replace(rec, []byte(Allow), []byte(Block), 1)
		}
		next, hash := chain(prev, rec)
		rewritten, prev = append(rewritten, next...), hash
	}
	return rewritten
}

// This records the other half of the limit in DESIGN section 6, and why saved heads exist. Each hash
// has to cover the one before it, or a head saved at some point would say nothing about the records
// before that point.
func TestRewrittenChainPassesAloneAndFailsAgainstASavedHead(t *testing.T) {
	data := readFile(t, writeLog(t, 4))
	early, err := verifyBytes(t, bytes.Join(lines(data)[:2], nil), "")
	if err != nil {
		t.Fatal(err)
	}
	rewritten := rewriteChain(t, data)
	if bytes.Equal(rewritten, data) {
		t.Fatal("the rewrite changed nothing")
	}
	if _, err := verifyBytes(t, rewritten, ""); err != nil {
		t.Fatalf("documented limit changed: a recomputed chain failed with no saved head: %v", err)
	}
	if _, err := verifyBytes(t, rewritten, early.Head); err == nil {
		t.Fatal("a rewrite of the records before a saved head passed")
	}
}

func TestVerifyGoodLog(t *testing.T) {
	path := writeLog(t, 5)
	sum, err := Verify(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if sum.Count != 5 || !ValidHead(sum.Head) || sum.Head == zeroHead {
		t.Fatalf("summary = %+v", sum)
	}
	if sum.Size != int64(len(readFile(t, path))) {
		t.Fatalf("size = %d", sum.Size)
	}
}

func TestVerifyEmptyLog(t *testing.T) {
	sum, err := verifyBytes(t, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if sum.Count != 0 || sum.Head != zeroHead {
		t.Fatalf("summary = %+v", sum)
	}
}

func TestVerifyMissingFile(t *testing.T) {
	if _, err := Verify(filepath.Join(t.TempDir(), "none"), ""); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v", err)
	}
}

// Property: changing any single byte of a log, to any value, fails verification. Every position is
// tried with every bit flipped on its own and with all bits flipped. The last byte is covered too:
// without its newline the line counts as torn.
func TestAnyFlippedByteFailsVerify(t *testing.T) {
	data := readFile(t, writeLog(t, 4))
	for pos := range data {
		for _, mask := range []byte{1, 2, 4, 8, 16, 32, 64, 128, 255} {
			mutated := bytes.Clone(data)
			mutated[pos] ^= mask
			if _, err := verify(bytes.NewReader(mutated), ""); err == nil {
				t.Fatalf("byte %d (%q) xor %#x passed verification", pos, data[pos], mask)
			}
		}
	}
}

// Property: no edit that keeps the JSON equivalent gets past verification either, because a line
// must equal what the writer would produce byte for byte. Each of these would pass a checker that
// only parsed the line and recomputed the hash from the parsed record.
func TestEquivalentRewritesFailVerify(t *testing.T) {
	data := readFile(t, writeLog(t, 2))
	first := lines(data)[0]
	var head string
	if err := json.Unmarshal(first, &struct {
		Hash *string `json:"hash"`
	}{&head}); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		edit func(string) string
	}{
		{"CRLF line ending", func(s string) string { return strings.Replace(s, "\n", "\r\n", 1) }},
		{"space after the colon", func(s string) string { return strings.Replace(s, `"rec":`, `"rec": `, 1) }},
		{"space before the hash", func(s string) string { return strings.Replace(s, `,"hash"`, `, "hash"`, 1) }},
		{"space before the newline", func(s string) string { return strings.Replace(s, "\"}\n", "\"} \n", 1) }},
		{"uppercase hash", func(s string) string { return strings.Replace(s, head, strings.ToUpper(head), 1) }},
		{"escaped hash", func(s string) string {
			return strings.Replace(s, `"hash":"`+head[:1], `"hash":"\u00`+fmt.Sprintf("%x", head[0])[:2], 1)
		}},
		{"blank line between records", func(s string) string { return strings.Replace(s, "\n", "\n\n", 1) }},
		{"blank line at the end", func(s string) string { return s + "\n" }},
		{"hash member first", func(s string) string {
			line := lines([]byte(s))[0]
			rest := s[len(line):]
			rec := line[len(`{"rec":`):bytes.Index(line, []byte(`,"hash":`))]
			return `{"hash":"` + head + `","rec":` + string(rec) + "}\n" + rest
		}},
		{"extra member", func(s string) string { return strings.Replace(s, `,"hash"`, `,"x":1,"hash"`, 1) }},
		{"duplicate hash member", func(s string) string { return strings.Replace(s, "\"}\n", `","hash":"`+head+"\"}\n", 1) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			edited := tt.edit(string(data))
			if edited == string(data) {
				t.Fatal("the edit changed nothing")
			}
			if _, err := verifyBytes(t, []byte(edited), ""); err == nil {
				t.Fatal("passed verification")
			}
		})
	}
}

func TestVerifyDetectsStructuralEdits(t *testing.T) {
	data := readFile(t, writeLog(t, 4))
	l := lines(data)
	join := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	tests := []struct {
		name string
		log  []byte
	}{
		{"delete the first line", join(l[1], l[2], l[3])},
		{"delete a middle line", join(l[0], l[2], l[3])},
		{"reorder two lines", join(l[1], l[0], l[2], l[3])},
		{"reorder the last two lines", join(l[0], l[1], l[3], l[2])},
		{"repeat a line", join(l[0], l[1], l[1], l[2], l[3])},
		{"repeat the last line", join(l[0], l[1], l[2], l[3], l[3])},
		{"insert a made-up line", join(l[0], []byte(`{"rec":{"seq":2},"hash":"`+zeroHead+`"}`+"\n"), l[1], l[2], l[3])},
		{"insert junk", join(l[0], []byte("junk\n"), l[1], l[2], l[3])},
		{"torn last line", data[:len(data)-1]},
		{"torn in the middle of the last line", data[:len(data)-20]},
		{"junk after the last line", join(data, []byte("junk"))},
		{"a list instead of a record", []byte("[1,2]\n")},
		{"a record that is not an object", []byte(`{"rec":5,"hash":"` + zeroHead + `"}` + "\n")},
		{"no record", []byte(`{"hash":"` + zeroHead + `"}` + "\n")},
		{"no hash", []byte(`{"rec":{"seq":1}}` + "\n")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := verifyBytes(t, tt.log, ""); err == nil {
				t.Fatal("passed verification")
			}
		})
	}
}

// A chain whose hashes are all correct but whose sequence numbers are not. Only a writer that holds
// the whole chain could produce this, and the hash can't tell, so the sequence check has to.
func TestVerifyDetectsBadSequence(t *testing.T) {
	var prev [32]byte
	line, _ := chain(prev, []byte(`{"seq":9}`))
	if _, err := verifyBytes(t, line, ""); err == nil || !strings.Contains(err.Error(), "sequence") {
		t.Fatalf("err = %v, want a sequence failure", err)
	}
}

func TestVerifySavedHead(t *testing.T) {
	path := writeLog(t, 4)
	data := readFile(t, path)
	full, err := Verify(path, "")
	if err != nil {
		t.Fatal(err)
	}
	two, err := verifyBytes(t, bytes.Join(lines(data)[:2], nil), "")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		head   string
		wantOK bool
	}{
		{"the current head", full.Head, true},
		{"an older head", two.Head, true},
		{"the head of the empty log", zeroHead, true},
		{"a head that was never in this log", strings.Repeat("ab", 32), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Verify(path, tt.head)
			if (err == nil) != tt.wantOK {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

// This test records a documented limit, DESIGN section 6: with no saved head, cutting lines off the
// end leaves a shorter valid chain, and verify cannot tell. It passes because that is how the log
// behaves, not because this is good. A saved head is the only thing that catches it.
func TestTailTruncationWithoutSavedHeadPassesDocumentedLimit(t *testing.T) {
	path := writeLog(t, 4)
	data := readFile(t, path)
	cut := bytes.Join(lines(data)[:2], nil)
	sum, err := verifyBytes(t, cut, "")
	if err != nil {
		t.Fatalf("documented limit changed: truncated log failed: %v", err)
	}
	if sum.Count != 2 {
		t.Fatalf("count = %d, want 2", sum.Count)
	}
}

func TestTailTruncationWithSavedHeadFails(t *testing.T) {
	path := writeLog(t, 4)
	full, err := Verify(path, "")
	if err != nil {
		t.Fatal(err)
	}
	cut := bytes.Join(lines(readFile(t, path))[:2], nil)
	if _, err := verifyBytes(t, cut, full.Head); err == nil {
		t.Fatal("a log cut before the saved head passed")
	}
	if _, err := verifyBytes(t, nil, full.Head); err == nil {
		t.Fatal("an emptied log passed against a saved head")
	}
}

func TestReopenContinuesTheChain(t *testing.T) {
	path := writeLog(t, 3)
	dir := filepath.Dir(path)
	before := readFile(t, path)
	l, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Append(Record{Tool: "t", Decision: Block, Rule: "r"}, true); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	after := readFile(t, path)
	if !bytes.HasPrefix(after, before) {
		t.Fatal("reopening changed earlier records")
	}
	sum, err := Verify(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if sum.Count != 4 {
		t.Fatalf("count = %d, want 4", sum.Count)
	}
	if !strings.Contains(string(lines(after)[3]), `"seq":4`) {
		t.Fatalf("fourth line: %s", lines(after)[3])
	}
}

func TestOpenRefusesABadLogAndLeavesItAlone(t *testing.T) {
	good := readFile(t, writeLog(t, 3))
	flipped := bytes.Clone(good)
	flipped[10] ^= 1
	tests := []struct {
		name string
		log  []byte
	}{
		{"flipped byte", flipped},
		{"torn last line", good[:len(good)-5]},
		{"no final newline", good[:len(good)-1]},
		{"junk", []byte("not a log\n")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "audit.log")
			if err := os.WriteFile(path, tt.log, 0o600); err != nil {
				t.Fatal(err)
			}
			l, err := Open(dir)
			if err == nil {
				l.Close()
				t.Fatal("opened a log that fails verification")
			}
			if !strings.Contains(err.Error(), "failed verification") {
				t.Errorf("message is not clear: %v", err)
			}
			if !bytes.Equal(readFile(t, path), tt.log) {
				t.Fatal("the bad log was changed")
			}
			if _, err := os.Stat(filepath.Join(dir, "audit.key")); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("a refused start left a key behind: %v", err)
			}
		})
	}
}

func TestConcurrentAppendsKeepAValidChain(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	const writers, each = 8, 25
	var wg sync.WaitGroup
	for range writers {
		wg.Go(func() {
			for i := range each {
				if err := l.Append(Record{Tool: "t", Decision: Allow}, i%5 == 0); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	sum, err := Verify(filepath.Join(dir, "audit.log"), "")
	if err != nil {
		t.Fatal(err)
	}
	if sum.Count != writers*each {
		t.Fatalf("count = %d, want %d", sum.Count, writers*each)
	}
}

// Swaps the fsync for a counter or a failure. Open has started the writer by then, so the swap goes
// through a record first: l.in is unbuffered, so a finished Append means the writer is back in its
// select and not looking at l.sync.
func withSync(t *testing.T, sync func() error) (*Log, string) {
	t.Helper()
	dir := t.TempDir()
	l, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Append(Record{Tool: "first"}, false); err != nil {
		t.Fatal(err)
	}
	l.sync = sync
	return l, filepath.Join(dir, "audit.log")
}

func TestAppendSyncsOnlyWhenAsked(t *testing.T) {
	syncs := 0
	l, _ := withSync(t, func() error { syncs++; return nil })
	check := func(durable bool, want int, wantSynced uint64) {
		t.Helper()
		if err := l.Append(Record{Tool: "t"}, durable); err != nil {
			t.Fatal(err)
		}
		if syncs != want {
			t.Fatalf("durable=%v: %d syncs, want %d", durable, syncs, want)
		}
		if l.Synced() != wantSynced {
			t.Fatalf("durable=%v: Synced() = %d, want %d", durable, l.Synced(), wantSynced)
		}
	}
	// withSync already wrote record 1, without asking for a sync.
	check(false, 0, 0)
	check(true, 1, 3)
	check(false, 1, 3)
	check(true, 2, 5)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if syncs != 3 {
		t.Fatalf("Close did not flush: %d syncs, want 3", syncs)
	}
}

// Fail closed: after one failure, nothing else may be accepted, even if the disk has recovered,
// since the chain may now have a gap.
func TestFailedSyncIsSticky(t *testing.T) {
	boom := errors.New("disk on fire")
	failing := true
	l, path := withSync(t, func() error {
		if failing {
			return boom
		}
		return nil
	})
	if err := l.Append(Record{Tool: "t"}, true); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the sync failure", err)
	}
	if l.Synced() != 0 {
		t.Fatalf("a failed sync counted as durable: Synced() = %d", l.Synced())
	}
	failing = false // the disk recovers, but the log must stay failed
	before := readFile(t, path)
	for _, durable := range []bool{false, true} {
		if err := l.Append(Record{Tool: "t"}, durable); !errors.Is(err, boom) {
			t.Fatalf("durable=%v: err = %v, want the first failure", durable, err)
		}
	}
	if !bytes.Equal(readFile(t, path), before) {
		t.Fatal("a failed log kept writing")
	}
	if err := l.Close(); !errors.Is(err, boom) {
		t.Fatalf("Close = %v, want the first failure", err)
	}
}

func TestFailedWriteIsSticky(t *testing.T) {
	l, _ := withSync(t, func() error { return nil })
	l.file.Close() // the next Stat and Write can only fail
	first := l.Append(Record{Tool: "t"}, false)
	if first == nil {
		t.Fatal("write to a closed file reported success")
	}
	if err := l.Append(Record{Tool: "t"}, false); err == nil || err.Error() != first.Error() {
		t.Fatalf("err = %v, want the first failure %v", err, first)
	}
	l.Close()
}

// Two gateways on one state directory would fork the chain. The second to write must stop, leaving
// the log valid, rather than write a line that makes the whole log fail.
func TestSecondWriterIsRefused(t *testing.T) {
	dir := t.TempDir()
	first, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Append(Record{Tool: "t"}, true); err != nil {
		t.Fatal(err)
	}
	if err := second.Append(Record{Tool: "t"}, true); err == nil {
		t.Fatal("second writer wrote over a log that had moved")
	}
	if err := first.Append(Record{Tool: "t"}, true); err != nil {
		t.Fatal(err)
	}
	first.Close()
	second.Close()
	sum, err := Verify(filepath.Join(dir, "audit.log"), "")
	if err != nil {
		t.Fatal(err)
	}
	if sum.Count != 2 {
		t.Fatalf("count = %d, want 2", sum.Count)
	}
}

func TestAppendAfterCloseFails(t *testing.T) {
	l, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.Append(Record{Tool: "t"}, true); !errors.Is(err, ErrClosed) {
		t.Fatalf("err = %v, want ErrClosed", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("second Close = %v", err)
	}
}

func TestKeyIsCreatedOnceAndKept(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.key")
	l, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	digest := l.Digest("t", []byte("{}"))
	l.Close()
	key := readFile(t, path)
	if len(key) != 32 {
		t.Fatalf("key is %d bytes", len(key))
	}
	if bytes.Equal(key, make([]byte, 32)) {
		t.Fatal("key is all zeros")
	}
	again, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if !bytes.Equal(readFile(t, path), key) {
		t.Fatal("reopening changed the key")
	}
	if again.Digest("t", []byte("{}")) != digest {
		t.Fatal("reopening changed the digest")
	}
}

func TestKeyPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no owner-only mode bits")
	}
	dir := t.TempDir()
	l, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for _, name := range []string{"audit.key", "audit.log"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("%s has mode %o", name, perm)
		}
	}
}

func TestOpenRefusesAWrongSizedKey(t *testing.T) {
	for _, size := range []int{0, 31, 33} {
		dir := t.TempDir()
		path := filepath.Join(dir, "audit.key")
		if err := os.WriteFile(path, make([]byte, size), 0o600); err != nil {
			t.Fatal(err)
		}
		l, err := Open(dir)
		if err == nil {
			l.Close()
			t.Fatalf("opened with a %d-byte key", size)
		}
		if got := readFile(t, path); len(got) != size {
			t.Fatalf("the bad key was changed: %d bytes", len(got))
		}
	}
}

func TestDigestDependsOnKeyNameAndArguments(t *testing.T) {
	a, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	base := a.Digest("n", []byte("v"))
	if base != a.Digest("n", []byte("v")) {
		t.Error("not stable")
	}
	if base == b.Digest("n", []byte("v")) {
		t.Error("the key does not matter")
	}
	if base == a.Digest("m", []byte("v")) {
		t.Error("the name does not matter")
	}
	if base == a.Digest("n", []byte("w")) {
		t.Error("the arguments do not matter")
	}
	if a.Digest("ab", []byte("c")) == a.Digest("a", []byte("bc")) {
		t.Error("name and arguments can shift into each other")
	}
	if len(base) != 64 {
		t.Errorf("digest has %d characters", len(base))
	}
}

func TestValidHead(t *testing.T) {
	tests := []struct {
		head string
		want bool
	}{
		{zeroHead, true},
		{strings.Repeat("ab", 32), true},
		{strings.Repeat("AB", 32), false},
		{strings.Repeat("ab", 31), false},
		{strings.Repeat("ab", 33), false},
		{strings.Repeat("zz", 32), false},
		{"", false},
	}
	for _, tt := range tests {
		if got := ValidHead(tt.head); got != tt.want {
			t.Errorf("ValidHead(%q) = %v", tt.head, got)
		}
	}
}

// FuzzVerify has two jobs. Arbitrary bytes must never panic the verifier, and if they pass, they
// must really be a chain: re-deriving each line gives the same bytes, and the count and head agree.
// The offset and mask then flip one byte of a real log, which must always fail.
func FuzzVerify(f *testing.F) {
	dir := f.TempDir()
	l, err := Open(dir)
	if err != nil {
		f.Fatal(err)
	}
	for i := range 3 {
		if err := l.Append(Record{Tool: "t", Decision: Allow, ArgLens: []int{i}}, false); err != nil {
			f.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		f.Fatal(err)
	}
	good, err := os.ReadFile(filepath.Join(dir, "audit.log"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good, uint(0), byte(1))
	f.Add(good[:len(good)-1], uint(7), byte(255))
	f.Add([]byte("{}\n"), uint(100), byte(32))
	f.Add([]byte(""), uint(0), byte(0))
	f.Add([]byte(`{"rec":{"seq":1},"hash":"00"}`+"\n"), uint(3), byte(4))
	f.Fuzz(func(t *testing.T, data []byte, offset uint, mask byte) {
		if sum, err := verify(bytes.NewReader(data), ""); err == nil {
			checkChain(t, data, sum)
		}
		if mask == 0 {
			return
		}
		mutated := bytes.Clone(good)
		mutated[offset%uint(len(mutated))] ^= mask
		if _, err := verify(bytes.NewReader(mutated), ""); err == nil {
			t.Fatalf("byte %d xor %#x passed verification", offset%uint(len(mutated)), mask)
		}
	})
}

// checkChain re-derives a log that passed, using only chain, so a bug in the verifier's control
// flow can't hide behind itself.
func checkChain(t *testing.T, data []byte, sum Summary) {
	t.Helper()
	if sum.Size != int64(len(data)) {
		t.Fatalf("verified %d of %d bytes", sum.Size, len(data))
	}
	var prev [32]byte
	rest := data
	var count uint64
	for len(rest) > 0 {
		end := bytes.IndexByte(rest, '\n')
		if end < 0 {
			t.Fatal("passed with a torn last line")
		}
		line := rest[:end+1]
		rec := line[len(`{"rec":`) : len(line)-len(`,"hash":"`)-64-len("\"}\n")]
		want, hash := chain(prev, rec)
		if !bytes.Equal(line, want) {
			t.Fatalf("line %d is not what the writer would write", count+1)
		}
		prev, rest = hash, rest[end+1:]
		count++
	}
	if count != sum.Count {
		t.Fatalf("count = %d, re-derived %d", sum.Count, count)
	}
	if got := fmt.Sprintf("%x", prev); got != sum.Head {
		t.Fatalf("head = %s, re-derived %s", sum.Head, got)
	}
}
