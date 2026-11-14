package front

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"testing/synctest"
	"time"

	"github.com/axiom8z/magistrate/internal/audit"
	"github.com/axiom8z/magistrate/internal/policy"
	"github.com/axiom8z/magistrate/internal/rpc"
	"github.com/axiom8z/magistrate/internal/upstream"
	"github.com/axiom8z/magistrate/test/fakemcp"
)

// backend is one fake server behind a gateway under test. A hold, if set, keeps the gateway's start
// waiting after this server's handshake until the hold closes, whatever the context says.
type backend struct {
	cfg  upstream.Config
	pipe *fakemcp.Pipe
	hold <-chan struct{}
}

func server(name string, h fakemcp.Handler) backend {
	return backend{cfg: upstream.Config{Name: name}, pipe: fakemcp.NewPipe(h)}
}

// session is a gateway under test, with the test playing the client over in-memory pipes.
type session struct {
	t      *testing.T
	gw     *Gateway
	in     io.WriteCloser
	lines  chan string
	done   chan error
	dir    string
	notes  *lockedBuffer
	closed sync.Once
	err    error
	// reading holds a token whenever the client is reading its stdout. A test that takes it stops the
	// client reading, and the gateway's next write waits until the test gives it back.
	reading chan struct{}
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// clientOut is the client's end of stdout. As each line is written, it checks that no result goes out
// while its call is still in the in-flight table, since a client that reuses an ID the moment it reads
// the result must not be refused as a duplicate. From the client's side that gap is too narrow to hit
// reliably, so the table is read while the line is being written. Error replies are left out, because
// refusing a duplicate is one, and it goes out while the first call is still running. The check counts
// on tests never giving another request the ID of a call that is still running. Each write also waits
// for the session's reading token.
type clientOut struct {
	t       *testing.T
	gw      *Gateway
	w       io.Writer
	reading chan struct{}
}

func (c clientOut) Write(line []byte) (int, error) {
	<-c.reading
	defer func() { c.reading <- struct{}{} }()
	if m, err := rpc.Parse(line); err == nil && m.IsResponse() && m.Error == nil {
		c.gw.mu.Lock()
		_, running := c.gw.inflight[string(m.ID)]
		c.gw.mu.Unlock()
		if running {
			c.t.Errorf("the result for %s went out while its call was still in flight", m.ID)
		}
	}
	return c.w.Write(line)
}

// passConfig is the mode the tests of the proxy itself run in, with nothing being decided.
func passConfig() Config { return Config{Policy: &policy.Policy{Mode: policy.ModePass}} }

func newSession(t *testing.T, backends ...backend) *session {
	t.Helper()
	return newSessionIn(t, t.TempDir(), passConfig(), backends...)
}

// newSessionIn runs a gateway on an existing state directory, as a restart would.
func newSessionIn(t *testing.T, dir string, cfg Config, backends ...backend) *session {
	t.Helper()
	auditLog, err := audit.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	s := &session{t: t, in: inW, lines: make(chan string, 256), done: make(chan error, 1), dir: dir, notes: &lockedBuffer{},
		reading: make(chan struct{}, 1)}
	s.reading <- struct{}{}
	if cfg.StateDir == "" { // a test of a broken latch names its own folder, apart from the log's
		cfg.StateDir = dir
	}
	s.gw = New(auditLog, log.New(s.notes, "", 0), cfg)
	start := func(ctx context.Context) []*upstream.Server {
		var servers []*upstream.Server
		for _, b := range backends {
			servers = append(servers, upstream.Attach(ctx, b.cfg, b.pipe.Stdin, b.pipe.Stdout, b.pipe.Kill))
			if b.hold != nil {
				<-b.hold
			}
		}
		return servers
	}
	go func() {
		err := s.gw.Serve(inR, clientOut{t: t, gw: s.gw, w: outW, reading: s.reading}, start)
		outW.Close()
		s.done <- err
	}()
	go func() {
		defer close(s.lines)
		r := rpc.NewReader(outR)
		for {
			line, err := r.ReadLine()
			if err != nil {
				return
			}
			s.lines <- string(line)
		}
	}()
	t.Cleanup(s.close)
	return s
}

// close ends the session the way a client does, by closing stdin, and waits for Serve to return.
func (s *session) close() {
	s.closed.Do(func() {
		s.in.Close()
		s.err = <-s.done
	})
}

func (s *session) send(line string) {
	s.t.Helper()
	if _, err := io.WriteString(s.in, line+"\n"); err != nil {
		s.t.Fatalf("sending to the gateway: %v", err)
	}
}

// recvLine returns the next line the client sees. In a synctest bubble the wait is on the fake clock.
// It is longer than any timeout under test, and shorter than go test's own limit for the others.
func (s *session) recvLine() string {
	s.t.Helper()
	select {
	case line, ok := <-s.lines:
		if !ok {
			s.t.Fatal("the gateway closed its output")
		}
		return line
	case <-time.After(5 * time.Minute):
		s.t.Fatal("no reply from the gateway")
		return ""
	}
}

func (s *session) recv() *rpc.Message {
	s.t.Helper()
	line := s.recvLine()
	m, err := rpc.Parse([]byte(line))
	if err != nil {
		s.t.Fatalf("the gateway sent something that is not JSON-RPC: %q: %v", line, err)
	}
	return m
}

func (s *session) initialize() {
	s.t.Helper()
	s.send(`{"jsonrpc":"2.0","id":"init","method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{}}}`)
	if m := s.recv(); string(m.ID) != `"init"` || m.Error != nil {
		s.t.Fatalf("initialize failed: %+v", m)
	}
}

func (s *session) call(id int, name, args string) {
	s.t.Helper()
	s.send(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, id, name, args))
}

// wantResult checks m is the reply to request id and returns the raw result.
func wantResult(t *testing.T, m *rpc.Message, id int) string {
	t.Helper()
	if m.Error != nil || string(m.ID) != fmt.Sprint(id) {
		t.Fatalf("wanted the result of %d, got id %s error %v", id, m.ID, m.Error)
	}
	return string(m.Result)
}

// wantBlocked checks result is an isError result the model can read, naming the rule.
func wantBlocked(t *testing.T, result, rule string) {
	t.Helper()
	var r toolResult
	if err := json.Unmarshal([]byte(result), &r, json.RejectUnknownMembers(true)); err != nil {
		t.Fatalf("not a tool result: %s: %v", result, err)
	}
	if !r.IsError || len(r.Content) != 1 || r.Content[0].Type != "text" || r.StructuredContent != nil {
		t.Fatalf("not a readable block: %s", result)
	}
	if !strings.Contains(r.Content[0].Text, "rule "+rule+":") {
		t.Fatalf("block does not name rule %s: %s", rule, result)
	}
}

// records closes the session and returns the audit log, after checking it verifies.
func (s *session) records() []audit.Record {
	s.t.Helper()
	s.close()
	path := filepath.Join(s.dir, "audit.log")
	if _, err := audit.Verify(path, ""); err != nil {
		s.t.Fatalf("the log fails verification: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		s.t.Fatal(err)
	}
	var recs []audit.Record
	for line := range strings.Lines(string(data)) {
		var parsed struct {
			Rec  audit.Record `json:"rec"`
			Hash string       `json:"hash"`
		}
		if err := json.Unmarshal([]byte(line), &parsed); err != nil {
			s.t.Fatal(err)
		}
		recs = append(recs, parsed.Rec)
	}
	return recs
}

func TestInitializeAnswersOurVersionWhateverTheClientAsks(t *testing.T) {
	tests := []struct{ name, params string }{
		{"the same version", `{"protocolVersion":"2025-11-25","capabilities":{}}`},
		{"a newer version", `{"protocolVersion":"2026-07-28","capabilities":{}}`},
		{"an older version", `{"protocolVersion":"2024-11-05","capabilities":{}}`},
		{"a version of the wrong type", `{"protocolVersion":5,"capabilities":{}}`},
		{"no version", `{"capabilities":{}}`},
		{"empty params", `{}`},
	}
	want := `{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"magistrate","version":"` + upstream.Version + `"}}`
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newSession(t)
			s.send(`{"jsonrpc":"2.0","id":0,"method":"initialize","params":` + tt.params + `}`)
			m := s.recv()
			if got, wantSorted := canonical(t, m.Result), canonical(t, jsontext.Value(want)); got != wantSorted {
				t.Fatalf("result:\n got %s\nwant %s", got, wantSorted)
			}
		})
	}
}

func canonical(t *testing.T, v jsontext.Value) string {
	t.Helper()
	c := bytes.Clone(v)
	if err := (*jsontext.Value)(&c).Canonicalize(); err != nil {
		t.Fatal(err)
	}
	return string(c)
}

func TestInitializeRecordsElicitation(t *testing.T) {
	tests := []struct {
		name, params string
		want         bool
	}{
		{"as Claude Code declares it", `{"capabilities":{"roots":{"listChanged":true},"elicitation":{"form":{},"url":{}}}}`, true},
		{"empty object", `{"capabilities":{"elicitation":{}}}`, true},
		{"form only", `{"capabilities":{"elicitation":{"form":{}}}}`, true},
		{"url only, which can't carry a form", `{"capabilities":{"elicitation":{"url":{}}}}`, false},
		{"not an object", `{"capabilities":{"elicitation":true}}`, false},
		{"not declared", `{"capabilities":{"roots":{}}}`, false},
		{"null", `{"capabilities":{"elicitation":null}}`, false},
		{"no capabilities", `{}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newSession(t)
			s.send(`{"jsonrpc":"2.0","id":0,"method":"initialize","params":` + tt.params + `}`)
			s.recv()
			s.close()
			if s.gw.clientElicits != tt.want {
				t.Fatalf("clientElicits = %v, want %v", s.gw.clientElicits, tt.want)
			}
		})
	}
}

func TestProtocolMethods(t *testing.T) {
	const notFound, invalid, badParams = -32601, -32600, -32602
	init := `{"jsonrpc":"2.0","id":"i","method":"initialize","params":{}}`
	tests := []struct {
		name    string
		before  []string // sent first, each getting one reply that is not looked at
		send    string
		wantID  string
		wantErr int    // 0 means a result is expected
		wantRes string // checked when not empty
	}{
		{"server/discover with a string id", nil, `{"jsonrpc":"2.0","id":"server-discover-probe-1","method":"server/discover","params":{"_meta":{}}}`, `"server-discover-probe-1"`, notFound, ""},
		{"server/discover after initialize", []string{init}, `{"jsonrpc":"2.0","id":5,"method":"server/discover"}`, "5", notFound, ""},
		{"an unknown method", []string{init}, `{"jsonrpc":"2.0","id":7,"method":"resources/list"}`, "7", notFound, ""},
		{"prompts are not offered", []string{init}, `{"jsonrpc":"2.0","id":8,"method":"prompts/list"}`, "8", notFound, ""},
		{"ping before initialize", nil, `{"jsonrpc":"2.0","id":1,"method":"ping"}`, "1", 0, `{}`},
		{"ping after initialize", []string{init}, `{"jsonrpc":"2.0","id":2,"method":"ping"}`, "2", 0, `{}`},
		{"tools/list before initialize", nil, `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`, "3", invalid, ""},
		{"tools/call before initialize", nil, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo__echo"}}`, "4", invalid, ""},
		{"initialize twice", []string{init}, `{"jsonrpc":"2.0","id":6,"method":"initialize","params":{}}`, "6", invalid, ""},
		{"initialize with params of the wrong shape", nil, `{"jsonrpc":"2.0","id":9,"method":"initialize","params":{"capabilities":5}}`, "9", badParams, ""},
		{"an id spelled with an escape comes back as sent", nil, "{\"jsonrpc\":\"2.0\",\"id\":\"\\u0061\",\"method\":\"ping\"}", "\"\\u0061\"", 0, `{}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := server("echo", fakemcp.Default)
			s := newSession(t, be)
			for _, line := range tt.before {
				s.send(line)
				s.recv()
			}
			s.send(tt.send)
			m := s.recv()
			if string(m.ID) != tt.wantID {
				t.Errorf("id = %s, want %s", m.ID, tt.wantID)
			}
			switch {
			case tt.wantErr != 0 && (m.Error == nil || m.Error.Code != tt.wantErr):
				t.Errorf("error = %+v, want code %d", m.Error, tt.wantErr)
			case tt.wantErr == 0 && m.Error != nil:
				t.Errorf("error = %+v", m.Error)
			case tt.wantRes != "" && string(m.Result) != tt.wantRes:
				t.Errorf("result = %s, want %s", m.Result, tt.wantRes)
			}
			s.close()
			if got := be.pipe.Conn.Calls("tools/call"); len(got) != 0 {
				t.Error("a refused call reached the server")
			}
		})
	}
}

func TestNotificationsGetNoReply(t *testing.T) {
	s := newSession(t, server("echo", fakemcp.Default))
	s.initialize()
	for _, line := range []string{
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","method":"notifications/made-up","params":{"a":1}}`,
		`{"jsonrpc":"2.0","method":"tools/list"}`, // a method with no id is a notification, whatever its name
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":99}}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled"}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":"not an object"}`,
		`{"jsonrpc":"2.0","id":"unasked","result":{}}`, // a response to nothing
	} {
		s.send(line)
	}
	s.send(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	if m := s.recv(); string(m.ID) != "1" {
		t.Fatalf("the next reply was not to the ping: %+v", m)
	}
}

// One bad line gets one error with a null id, and the session carries on.
func TestBadLinesGetANullIDErrorAndReadingContinues(t *testing.T) {
	const parse, invalid = -32700, -32600
	tests := []struct {
		name string
		line string
		code int
	}{
		{"not JSON", `hello`, parse},
		{"blank line", ``, parse},
		{"truncated", `{"jsonrpc":"2.0","id":1,`, parse},
		{"duplicate key", `{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}`, parse},
		{"duplicate key in params", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","name":"b"}}`, parse},
		{"over the cap", `{"jsonrpc":"2.0","id":1,"method":"` + strings.Repeat("x", rpc.MaxLine) + `"}`, invalid},
		{"far over the cap", strings.Repeat("y", 3*rpc.MaxLine), invalid},
		{"a batch", `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`, invalid},
		{"a null id", `{"jsonrpc":"2.0","id":null,"method":"ping"}`, invalid},
		{"a float id", `{"jsonrpc":"2.0","id":1.5,"method":"ping"}`, invalid},
		{"a boolean id", `{"jsonrpc":"2.0","id":true,"method":"ping"}`, invalid},
		{"no version", `{"id":1,"method":"ping"}`, invalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newSession(t)
			s.send(tt.line)
			m := s.recv()
			if string(m.ID) != "null" || m.Error == nil || m.Error.Code != tt.code {
				t.Fatalf("reply = id %s error %+v, want a null id and code %d", m.ID, m.Error, tt.code)
			}
			s.send(`{"jsonrpc":"2.0","id":42,"method":"ping"}`)
			if m := s.recv(); string(m.ID) != "42" || m.Error != nil {
				t.Fatalf("reading did not continue: %+v", m)
			}
		})
	}
}

func TestErrorMessagesDoNotEchoInput(t *testing.T) {
	s := newSession(t)
	s.send(`{"jsonrpc":"2.0","id":1,"id":"ECHOED-TEXT","method":"ECHOED-TEXT"}`)
	if line := s.recvLine(); strings.Contains(line, "ECHOED-TEXT") {
		t.Fatalf("the reply repeats the input: %s", line)
	}
}

// The client gets its first answers at once, however slow a server is, because the tools are the only
// thing that has to wait for one.
func TestSlowServerDoesNotDelayInitialize(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		slow := server("slow", fakemcp.On("initialize", func(c *fakemcp.Conn, m *rpc.Message) {
			<-release
			fakemcp.Default(c, m)
		}))
		s := newSession(t, slow)
		start := time.Now()
		s.send(`{"jsonrpc":"2.0","id":"probe","method":"server/discover"}`)
		s.recv()
		s.initialize()
		if got := time.Since(start); got != 0 {
			t.Errorf("initialize waited %v for a slow server", got)
		}
		time.AfterFunc(3*time.Second, func() { close(release) })
		s.send(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
		if got := wantResult(t, s.recv(), 1); !strings.Contains(got, "slow__echo") {
			t.Fatalf("listing = %s", got)
		}
		if got := time.Since(start); got != 3*time.Second {
			t.Errorf("tools/list answered after %v, want 3s", got)
		}
	})
}

// A client that stops reading stdout must not crash or hang the gateway. It keeps going until stdin
// ends, and shuts down as usual.
func TestClosedStdoutIsNotedAndTheSessionEndsCleanly(t *testing.T) {
	dir := t.TempDir()
	auditLog, err := audit.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	var notes lockedBuffer
	input := `{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n" + `{"jsonrpc":"2.0","id":2,"method":"made/up"}` + "\n"
	gw := New(auditLog, log.New(&notes, "", 0), passConfig())
	err = gw.Serve(strings.NewReader(input), brokenWriter{}, func(context.Context) []*upstream.Server { return nil })
	if err != nil {
		t.Fatalf("Serve = %v, want nil: the client leaving is not a failure", err)
	}
	if got := strings.Count(notes.String(), "replying to the client"); got != 2 {
		t.Errorf("%d notes, want 2: %q", got, notes.String())
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestEOFStopsTheServersAndClosesTheLog(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		polite := server("polite", fakemcp.Default)
		stubborn := backend{cfg: upstream.Config{Name: "stubborn"}, pipe: fakemcp.NewStubbornPipe(fakemcp.Default)}
		s := newSession(t, polite, stubborn)
		s.initialize()
		s.call(1, "polite__echo", `{}`)
		wantResult(t, s.recv(), 1)
		s.send(`{"jsonrpc":"2.0","id":"p","method":"ping"}`)
		s.recv()
		synctest.Wait()

		start := time.Now()
		s.close()
		if s.err != nil {
			t.Errorf("Serve = %v, want nil", s.err)
		}
		// 300 ms is when Claude Code on Windows kills the tree.
		if got := time.Since(start); got >= 300*time.Millisecond {
			t.Errorf("shutdown took %v", got)
		}
		if !stubborn.pipe.Killed() {
			t.Error("the stubborn server was not killed")
		}
		if err := s.gw.audit.Append(audit.Record{}, false); err == nil {
			t.Error("the log is still open")
		}
		if recs := s.records(); len(recs) != 2 {
			t.Errorf("records = %+v", recs)
		}
	})
}

// A client can leave while a server is still in its handshake. That server must not outlive the session,
// and Serve must not read the server table while the handshake can still write to it, which is what the
// race detector looks at here.
func TestAClientLeavingDuringAHandshakeStopsThatServer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		held := server("held", fakemcp.On("initialize", func(*fakemcp.Conn, *rpc.Message) {}))
		s := newSession(t, held)
		synctest.Wait()
		s.close()
		if s.err != nil {
			t.Errorf("Serve = %v", s.err)
		}
		if !held.pipe.Killed() {
			t.Error("the session ended with its server still running")
		}
	})
}

// A start can outlast the client: StartAll returns only when every server has finished, and a server
// whose handshake the client's leaving cut short has to die first. Here a hold stands in for such a slow
// start, after one server is up. Serve must wait for the start, then stop the server it returned.
// synctest.Wait returns only once every other goroutine is durably blocked, so a Serve that did not wait
// would have returned before the check. Unlike the test above, this one needs no race detector to fail.
func TestServeWaitsForAStartThatOutlivesTheClient(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		late := server("late", fakemcp.Default)
		late.hold = release
		s := newSession(t, late)
		synctest.Wait()
		s.in.Close()
		synctest.Wait()
		if len(s.done) != 0 {
			t.Error("Serve returned while the start was still running")
		}
		close(release)
		s.close()
		if s.err != nil {
			t.Errorf("Serve = %v", s.err)
		}
		if !late.pipe.Killed() {
			t.Error("a server the start returned after the client left is still running")
			late.pipe.Kill() // so the bubble can end and the package's other tests still run
		}
	})
}

// A call can still be running after the client has left. A held call that the leaving cancels still has
// to tell the client its question is over. Serve must wait for every call, so that each record reaches
// the log before the log closes. Here the client has stopped reading, which holds that call at that
// write, and as above a Serve that did not wait would have returned before the test looks at s.done.
func TestServeWaitsForACallStillRunningWhenTheClientLeaves(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, _ := guard{prompt: "tell alice", tools: mailTools}.start(t)
		s.call(1, "s__send_mail", `{"to":"evil@x.example"}`)
		if m := s.recv(); m.Method != "elicitation/create" {
			t.Fatalf("wanted a question, got %+v", m)
		}
		<-s.reading
		s.in.Close()
		synctest.Wait()
		if len(s.done) != 0 {
			t.Error("Serve returned while a call was still running")
		}
		s.reading <- struct{}{}
		if recs := s.records(); len(recs) != 2 || recs[0].Decision != audit.Ask || recs[1].Decision != audit.Cancelled {
			t.Errorf("records = %+v, want the ask and then the cancellation", recs)
		}
	})
}

func TestEOFWithACallInFlightEndsItWithNoReply(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		be := server("s", fakemcp.On("tools/call", func(*fakemcp.Conn, *rpc.Message) {}))
		s := newSession(t, be)
		s.initialize()
		s.call(1, "s__echo", `{}`)
		synctest.Wait()
		s.close()
		if s.err != nil {
			t.Errorf("Serve = %v", s.err)
		}
		if len(s.lines) != 0 {
			t.Errorf("a reply went to a client that left: %q", <-s.lines)
		}
		recs := s.records()
		if len(recs) != 2 || recs[1].Decision != audit.Cancelled {
			t.Errorf("records = %+v", recs)
		}
	})
}

func TestEOFDuringTheHandshakeDoesNotWaitForIt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newSession(t, server("silent", fakemcp.On("initialize", func(*fakemcp.Conn, *rpc.Message) {})))
		synctest.Wait()
		start := time.Now()
		s.close()
		if got := time.Since(start); got >= 300*time.Millisecond {
			t.Errorf("shutdown took %v", got)
		}
	})
}

func TestReadErrorIsReported(t *testing.T) {
	dir := t.TempDir()
	auditLog, err := audit.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	gw := New(auditLog, log.New(io.Discard, "", 0), passConfig())
	err = gw.Serve(iotest.ErrReader(errors.New("stdin broke")), &out, func(context.Context) []*upstream.Server { return nil })
	if err == nil || !strings.Contains(err.Error(), "stdin broke") {
		t.Fatalf("Serve = %v", err)
	}
}
