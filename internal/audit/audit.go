// Package audit keeps the gateway's tamper-evident record of every decision.
//
// The log is one JSON line per record:
//
//	{"rec":{...},"hash":"<hex>"}
//
// where hash = SHA-256(prev || the exact bytes of rec), prev is the previous line's hash as raw
// bytes, and the first line's prev is 32 zero bytes. Each hash covers everything before it, so
// changing, adding, removing or reordering a line breaks every hash after it.
//
// The limits are real and stated in DESIGN section 6. A writer can recompute the whole chain, and
// cutting lines off the end leaves a valid shorter chain. Only a head saved somewhere else catches
// those, and only for the part of the log before that head.
package audit

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Decisions a record can hold.
const (
	Allow     = "allow"     // the call was forwarded
	Block     = "block"     // the call or its result was refused; Rule says why
	Result    = "result"    // a forwarded call's result went to the client
	Cancelled = "cancelled" // the call was cancelled, so no result was sent
)

// Record is one decision. It holds lengths and a keyed hash of the arguments, never their values,
// so the log can be shared without sharing what the agent sent. Seq and Time are set when written.
type Record struct {
	Seq      uint64 `json:"seq"`
	Time     string `json:"time"`
	Tool     string `json:"tool"`
	Decision string `json:"decision"`
	Rule     string `json:"rule,omitzero"`
	ArgLens  []int  `json:"arg_lens,omitzero"`
	ArgsHMAC string `json:"args_hmac,omitzero"`
}

// Summary is what Verify found.
type Summary struct {
	Count uint64 // records in the chain
	Head  string // hash of the last record, in hex; all zeros for an empty log
	Size  int64  // bytes verified
	prev  [sha256.Size]byte
}

// ErrClosed is returned by Append after Close.
var ErrClosed = errors.New("audit log is closed")

// Log appends to the chain. One goroutine does all the writing, so records can never interleave and
// each one chains onto the record truly before it.
type Log struct {
	key  []byte
	in   chan entry
	stop chan struct{}
	done chan struct{}
	once sync.Once
	// synced is the sequence number of the last record known to be on disk.
	synced atomic.Uint64

	// Owned by the writer goroutine once Open returns.
	file *os.File
	sync func() error // file.Sync; tests replace it to make it fail
	sum  Summary      // the chain so far
	err  error        // the first failure; it is sticky, because a chain with a gap proves nothing
}

type entry struct {
	rec     Record
	durable bool
	reply   chan error
}

// Open starts the log in dir, creating the key and log files if needed. An existing log must verify
// in full first. One that does not, including one with a torn last line, stops startup; it is never
// repaired or truncated, because repairing evidence would destroy it.
func Open(dir string) (*Log, error) {
	path := filepath.Join(dir, "audit.log")
	sum, err := Verify(path, "")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("existing log %s failed verification and was left unchanged; move it aside to start a new one: %w", path, err)
	}
	key, err := loadKey(filepath.Join(dir, "audit.key"))
	if err != nil {
		return nil, fmt.Errorf("audit key: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	// A new file's name survives a power cut only once its folder is synced. Windows can't sync a
	// folder, so this is best effort.
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	l := &Log{key: key, in: make(chan entry), stop: make(chan struct{}), done: make(chan struct{}),
		file: file, sync: file.Sync, sum: sum}
	go l.run()
	return l, nil
}

// Append writes rec and returns once it is written, and fsynced if durable is set. Any failure is
// returned here and by every later call, so the caller can refuse to act.
func (l *Log) Append(rec Record, durable bool) error {
	e := entry{rec, durable, make(chan error, 1)}
	select {
	case l.in <- e:
		return <-e.reply
	case <-l.stop:
		return ErrClosed
	}
}

// Close flushes and closes the file, returning the sticky failure if there was one.
func (l *Log) Close() error {
	l.once.Do(func() { close(l.stop) })
	<-l.done
	return l.err
}

// Synced returns the sequence number of the last record known to be on disk. It is how a test can see
// that a decision was made durable before anything acted on it.
func (l *Log) Synced() uint64 { return l.synced.Load() }

// Digest is the args_hmac for a call. It covers the requested name as well as the arguments, so
// someone holding the key can match a record to a call, while the log alone reveals neither, even
// for a guessable value.
func (l *Log) Digest(name string, args []byte) string {
	mac := hmac.New(sha256.New, l.key)
	mac.Write([]byte(name))
	mac.Write([]byte{0}) // so that a name and arguments can't shift into each other
	mac.Write(args)
	return hex.EncodeToString(mac.Sum(nil))
}

func (l *Log) run() {
	defer close(l.done)
	for {
		select {
		case e := <-l.in:
			if l.err == nil {
				l.err = l.write(e)
			}
			e.reply <- l.err
		case <-l.stop:
			l.err = errors.Join(l.err, l.sync(), l.file.Close())
			return
		}
	}
}

func (l *Log) write(e entry) error {
	e.rec.Seq = l.sum.Count + 1
	e.rec.Time = time.Now().UTC().Format(time.RFC3339Nano)
	rec, err := json.Marshal(e.rec)
	if err != nil {
		return err
	}
	line, hash := chain(l.sum.prev, rec)
	// With two gateways on one state directory, each would chain onto a head the other has passed.
	// Refusing to write when the file has moved keeps the log valid and blocks this gateway instead.
	info, err := l.file.Stat()
	if err != nil {
		return err
	}
	if info.Size() != l.sum.Size {
		return fmt.Errorf("log is %d bytes, expected %d: something else changed it", info.Size(), l.sum.Size)
	}
	if _, err := l.file.Write(line); err != nil {
		return err
	}
	l.sum.Count, l.sum.prev, l.sum.Size = e.rec.Seq, hash, l.sum.Size+int64(len(line))
	if !e.durable {
		return nil
	}
	if err := l.sync(); err != nil {
		return err
	}
	l.synced.Store(e.rec.Seq)
	return nil
}

// chain returns the full line for a record and its hash. The line is built by hand because any
// re-encoding could change bytes the hash covers.
func chain(prev [sha256.Size]byte, rec []byte) ([]byte, [sha256.Size]byte) {
	h := sha256.New()
	h.Write(prev[:])
	h.Write(rec)
	var hash [sha256.Size]byte
	h.Sum(hash[:0])
	line := append([]byte(`{"rec":`), rec...)
	line = append(line, `,"hash":"`...)
	line = hex.AppendEncode(line, hash[:])
	return append(line, "\"}\n"...), hash
}

// Verify checks the whole log at path. It fails on any edit, insert, delete, reorder or malformed
// line, and on a savedHead (if not "") that is not the head of some prefix of the chain. With no
// saved head, cutting lines off the end still passes: that limit is in the package comment.
func Verify(path, savedHead string) (Summary, error) {
	f, err := os.Open(path)
	if err != nil {
		return Summary{}, err
	}
	defer f.Close()
	return verify(f, savedHead)
}

func verify(r io.Reader, savedHead string) (Summary, error) {
	var sum Summary
	sum.Head = hex.EncodeToString(sum.prev[:])
	found := savedHead == "" || savedHead == sum.Head
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadBytes('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return sum, err
		}
		if len(line) == 0 {
			break
		}
		if err != nil {
			return sum, fmt.Errorf("line %d: torn last line, with no newline", sum.Count+1)
		}
		hash, err := checkLine(line, sum.prev, sum.Count+1)
		if err != nil {
			return sum, fmt.Errorf("line %d: %w", sum.Count+1, err)
		}
		sum.Count, sum.prev, sum.Size = sum.Count+1, hash, sum.Size+int64(len(line))
		sum.Head = hex.EncodeToString(hash[:])
		found = found || sum.Head == savedHead
	}
	if !found {
		return sum, errors.New("saved head is not in the log: it was cut or rewritten at or before that point")
	}
	return sum, nil
}

// checkLine verifies one line and returns its hash. Parsing alone is not enough, since it would let
// a space or an uppercase hex digit slip past the hash, so the line must equal, byte for byte, the
// one that chain would write. The messages name no log content, because a tampered log is hostile
// input that ends up on someone's terminal.
func checkLine(line []byte, prev [sha256.Size]byte, seq uint64) (hash [sha256.Size]byte, err error) {
	var parsed struct {
		Rec jsontext.Value `json:"rec"`
	}
	if json.Unmarshal(line, &parsed) != nil {
		return hash, errors.New("malformed record line")
	}
	want, hash := chain(prev, parsed.Rec)
	if !bytes.Equal(line, want) {
		return hash, errors.New("hash mismatch: this line or an earlier one was changed, added, removed or moved")
	}
	var rec struct {
		Seq uint64 `json:"seq"`
	}
	if json.Unmarshal(parsed.Rec, &rec) != nil || rec.Seq != seq {
		return hash, errors.New("wrong sequence number")
	}
	return hash, nil
}

// ValidHead reports whether s has the form of a saved head: 64 lowercase hex digits.
func ValidHead(s string) bool {
	raw, err := hex.DecodeString(s)
	return err == nil && len(raw) == sha256.Size && hex.EncodeToString(raw) == s
}

// loadKey reads the HMAC key, creating it on first use. O_EXCL means a key is never overwritten:
// that would orphan the hashes already logged. Mode 0o600 is owner-only where the OS has such modes;
// on Windows the file inherits the folder's permissions.
func loadKey(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		key, err := os.ReadFile(path)
		if err == nil && len(key) != 32 {
			return nil, fmt.Errorf("%s does not hold a 32-byte key", path)
		}
		return key, err
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	key := make([]byte, 32)
	rand.Read(key) // never fails: crypto/rand crashes the program instead of returning weak bytes
	if _, err := f.Write(key); err != nil {
		return nil, err
	}
	return key, f.Sync()
}
