// Package upstream runs the MCP servers behind the gateway: it starts each one, does the handshake,
// and turns a call into a request on that server's pipes. A server that misbehaves is killed and
// stays dead, because nothing it says afterwards can be trusted and a restart would hide that.
package upstream

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/axiom8z/sayswho/internal/rpc"
)

const (
	// ProtocolVersion is the only MCP version the gateway speaks, on either side.
	ProtocolVersion = "2025-11-25"
	// Version is the gateway's own version, reported to clients and servers.
	Version = "0.1.0"

	// A client waits only so long for its tool list, so a hung server has to cost its own tools and
	// not the whole gateway. CallTimeout is long enough for slow tools. Neither is a measured value.
	HandshakeTimeout = 20 * time.Second
	CallTimeout      = 2 * time.Minute

	maxPages     = 32   // tools/list pages from one server, which also ends a cursor loop
	maxTools     = 1024 // tools from one server
	stderrKept   = 4 << 10
	outboxSize   = 64
	shutdownWait = 200 * time.Millisecond // Claude Code on Windows kills the tree at 300 ms
)

// What a request can end with, other than a *rpc.Error from the server.
var (
	ErrDead      = errors.New("server is dead")
	ErrTimeout   = errors.New("request timed out")
	ErrCancelled = errors.New("request cancelled")
)

// Config says how to reach one server.
type Config struct {
	Name, Command string
	Args          []string
	Env           []string // names of variables to pass through
}

// Tool is one tool as the server listed it. Only these fields are read, so _meta and anything else a
// server adds never get further than this struct. Annotations are read for init and covered by the
// pin; the gateway clears them before listing a tool, since they are hints from an untrusted server.
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitzero"`
	InputSchema jsontext.Value `json:"inputSchema"`
	Annotations jsontext.Value `json:"annotations,omitzero"`
}

// Server is one running MCP server.
type Server struct {
	cfg    Config
	stdin  io.WriteCloser
	kill   func()
	wait   func() // reaps the process, once its output has been read
	stderr *stderrTail
	tools  []Tool

	outbox  chan []byte   // lines waiting for writeLoop
	dead    chan struct{} // closed when the server is dead
	gone    chan struct{} // closed when the read loop has ended and the process is reaped
	dieOnce sync.Once
	why     string // why it died; written before dead closes

	mu      sync.Mutex
	nextID  int64
	pending map[int64]chan *rpc.Message // our request IDs still waiting for a reply
}

// StartAll starts every server at once, so one slow server costs one handshake timeout and not the
// sum of them. Servers come back in the order of cfgs.
func StartAll(ctx context.Context, cfgs []Config) []*Server {
	servers := make([]*Server, len(cfgs))
	var wg sync.WaitGroup
	for i, cfg := range cfgs {
		wg.Go(func() { servers[i] = Start(ctx, cfg) })
	}
	wg.Wait()
	return servers
}

// Start spawns a server and does the handshake. It always returns a Server: one that failed comes
// back already dead, so its calls end in a rule ID like those of any other dead server.
func Start(ctx context.Context, cfg Config) *Server {
	cmd := exec.Command(cfg.Command, cfg.Args...)
	cmd.Env = environment(cfg.Env)
	// With a Writer as Stderr, exec copies the pipe in its own goroutine, so a chatty server can't
	// block on a full pipe. WaitDelay bounds that copy, since a server's child may hold the pipe.
	tail := &stderrTail{}
	cmd.Stderr = tail
	cmd.WaitDelay = 100 * time.Millisecond
	stdin, inErr := cmd.StdinPipe()
	stdout, outErr := cmd.StdoutPipe()
	err := errors.Join(inErr, outErr)
	if err == nil {
		err = cmd.Start()
	}
	if err != nil {
		s := newServer(cfg, func() {}, func() {})
		close(s.gone)
		s.die("could not start: " + err.Error())
		return s
	}
	// Kill reaches only the direct child. A wrapper's children see their pipes close and are left
	// to exit on their own; closing our ends means they cannot keep the gateway waiting.
	s := newServer(cfg, func() {
		cmd.Process.Kill()
		stdin.Close()
		stdout.Close()
	}, func() { cmd.Wait() })
	s.stderr = tail
	s.run(stdin, stdout)
	s.handshake(ctx)
	return s
}

// Attach does the handshake over pipes someone else opened, the way Start does for a child process.
// Tests use it to run a server in-process.
func Attach(ctx context.Context, cfg Config, stdin io.WriteCloser, stdout io.Reader, kill func()) *Server {
	s := newServer(cfg, kill, func() {})
	s.run(stdin, stdout)
	s.handshake(ctx)
	return s
}

func newServer(cfg Config, kill, wait func()) *Server {
	return &Server{cfg: cfg, kill: kill, wait: wait, outbox: make(chan []byte, outboxSize),
		dead: make(chan struct{}), gone: make(chan struct{}), pending: map[int64]chan *rpc.Message{}}
}

func (s *Server) run(stdin io.WriteCloser, stdout io.Reader) {
	s.stdin = stdin
	go s.writeLoop()
	go s.readLoop(stdout)
}

// environment builds a child's whole environment from a short list plus what the policy names. The
// gateway's own environment may hold API keys, and a server gets none of it by default.
func environment(policyNames []string) []string {
	names := []string{"PATH", "HOME", "TMPDIR", "LANG"}
	if runtime.GOOS == "windows" {
		names = []string{"PATH", "PATHEXT", "SystemRoot", "SystemDrive", "windir", "ComSpec", "TEMP", "TMP", "USERPROFILE"}
	}
	env := []string{} // not nil: a nil Env would mean inherit everything
	for _, name := range append(names, policyNames...) {
		if value, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+value)
		}
	}
	return env
}

// handshake runs initialize and tools/list under one deadline. Any failure closes the server.
func (s *Server) handshake(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, HandshakeTimeout)
	defer cancel()
	if err := s.negotiate(ctx); err != nil {
		s.die("handshake failed: " + err.Error())
		<-s.gone // exec has finished copying stderr by then, so Failure can show all of it
	}
}

func (s *Server) negotiate(ctx context.Context) error {
	// Empty capabilities: a server told we support nothing has no business asking us for anything.
	raw, err := s.request(ctx, "initialize", map[string]any{
		"protocolVersion": ProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]string{"name": "sayswho", "version": Version},
	})
	if err != nil {
		return err
	}
	var init struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if err := json.Unmarshal(raw, &init); err != nil {
		return errors.New("malformed initialize result")
	}
	if init.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("server answered protocol version %q, and only %s is supported", init.ProtocolVersion, ProtocolVersion)
	}
	if err := s.send(ctx, rpc.Message{Method: "notifications/initialized"}); err != nil {
		return err
	}
	s.tools, err = s.listTools(ctx)
	return err
}

func (s *Server) listTools(ctx context.Context) ([]Tool, error) {
	var tools []Tool
	params := map[string]string{}
	for range maxPages {
		raw, err := s.request(ctx, "tools/list", params)
		if err != nil {
			return nil, err
		}
		var page struct {
			Tools      []Tool `json:"tools"`
			NextCursor string `json:"nextCursor"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return nil, errors.New("malformed tools/list result")
		}
		if tools = append(tools, page.Tools...); len(tools) > maxTools {
			return nil, fmt.Errorf("more than %d tools", maxTools)
		}
		if page.NextCursor == "" {
			return tools, nil
		}
		params = map[string]string{"cursor": page.NextCursor}
	}
	return nil, fmt.Errorf("more than %d pages of tools", maxPages)
}

// Call runs one tool and returns the raw result for the caller to rebuild. A cancelled ctx ends the
// call with ErrCancelled, and the call timeout ends it with ErrTimeout.
func (s *Server) Call(ctx context.Context, tool string, args jsontext.Value) (jsontext.Value, error) {
	ctx, cancel := context.WithTimeout(ctx, CallTimeout)
	defer cancel()
	// Only name and arguments go upstream, which leaves progress tokens and all other _meta behind.
	return s.request(ctx, "tools/call", struct {
		Name      string         `json:"name"`
		Arguments jsontext.Value `json:"arguments"`
	}{tool, args})
}

// request sends one request under an ID of our own and waits for the matching reply. Because the ID
// is ours, client IDs never reach a server, and a reply matching nothing in pending is dropped.
func (s *Server) request(ctx context.Context, method string, params any) (jsontext.Value, error) {
	raw, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	reply := make(chan *rpc.Message, 1) // buffered, so readLoop never waits on a caller who left
	s.mu.Lock()
	if s.pending == nil {
		s.mu.Unlock()
		return nil, ErrDead
	}
	s.nextID++
	id := s.nextID
	s.pending[id] = reply
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
	}()
	if err := s.send(ctx, rpc.Message{ID: strconv.AppendInt(nil, id, 10), Method: method, Params: raw}); err != nil {
		return nil, err
	}
	select {
	case m, open := <-reply:
		// die closes the channel. A reply that came first is still read first, so a server that
		// answers and exits at once has its answer counted.
		if !open {
			return nil, ErrDead
		}
		if m.Error != nil {
			return nil, m.Error
		}
		return m.Result, nil
	case <-ctx.Done():
		cancelled := fmt.Appendf(nil, `{"requestId":%d,"reason":"the gateway stopped waiting"}`, id)
		s.sendNow(rpc.Message{Method: "notifications/cancelled", Params: cancelled})
		return nil, contextError(ctx)
	}
}

func contextError(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return ErrTimeout
	}
	return ErrCancelled
}

// send queues a line for writeLoop, giving up if the server is dead or ctx ends first. A server that
// stopped reading fills the queue, and a caller must still be able to time out.
func (s *Server) send(ctx context.Context, m rpc.Message) error {
	line, err := rpc.Encode(m)
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return contextError(ctx) // select picks at random, and a cancelled call must not go out
	}
	select {
	case s.outbox <- line:
		return nil
	case <-ctx.Done():
		return contextError(ctx)
	case <-s.dead:
		return ErrDead
	}
}

// sendNow queues a line only if there is room. It is for the read loop and for cancellations: a
// peer that isn't reading can't be helped by them, and waiting on it could deadlock both sides.
func (s *Server) sendNow(m rpc.Message) {
	if line, err := rpc.Encode(m); err == nil {
		select {
		case s.outbox <- line:
		default:
		}
	}
}

func (s *Server) writeLoop() {
	for {
		select {
		case line := <-s.outbox:
			if _, err := s.stdin.Write(line); err != nil {
				s.die("its input closed")
				return
			}
		case <-s.dead:
			return
		}
	}
}

func (s *Server) readLoop(stdout io.Reader) {
	defer close(s.gone)
	defer s.wait() // exec's Wait closes the pipes, so it has to wait until reading is over
	r := rpc.NewReader(stdout)
	for {
		line, err := r.ReadLine()
		if errors.Is(err, rpc.ErrLineTooLong) {
			s.die("it sent a line over the 1 MiB cap")
			return
		}
		if err != nil {
			s.die("it exited")
			return
		}
		m, err := rpc.Parse(line)
		switch {
		case err != nil:
			s.die("it sent invalid JSON-RPC")
			return
		case m.IsResponse():
			s.deliver(m)
		case m.IsRequest():
			// We declared no capabilities, so no request is valid. Refusing them all is what stops a
			// server opening a dialog that looks like the gateway's (DESIGN section 2).
			s.sendNow(rpc.Message{ID: m.ID, Error: &rpc.Error{Code: rpc.CodeMethodNotFound, Message: "Method not found"}})
		}
		// What remains is a notification, and a server has nothing to tell us.
	}
}

func (s *Server) deliver(m *rpc.Message) {
	id, err := strconv.ParseInt(string(m.ID), 10, 64)
	if err != nil {
		return // a string or null id: not one of ours
	}
	s.mu.Lock()
	reply, ok := s.pending[id]
	delete(s.pending, id) // out of the map under the lock, so die can't close it while we send
	s.mu.Unlock()
	if ok {
		reply <- m
	}
}

// die marks the server dead, wakes every waiting call by closing its channel, and kills the server.
// A nil pending map is what stops later requests from waiting for a reply that can never come.
func (s *Server) die(why string) {
	s.dieOnce.Do(func() {
		s.why = why
		close(s.dead)
		s.mu.Lock()
		for _, reply := range s.pending {
			close(reply)
		}
		s.pending = nil
		s.mu.Unlock()
		s.kill()
	})
}

// Close closes the server's input, gives it a moment to leave, and then kills it. When it returns
// the process is gone. Nothing relies on it finishing, since the client may kill the whole process
// tree first.
func (s *Server) Close() {
	if s.stdin != nil {
		s.stdin.Close()
	}
	select {
	case <-s.dead:
	case <-time.After(shutdownWait):
	}
	s.die("the gateway stopped it")
	<-s.gone
}

// Name is the server's name from the policy.
func (s *Server) Name() string { return s.cfg.Name }

// Tools is what the server listed during the handshake.
func (s *Server) Tools() []Tool { return s.tools }

// Failure says why the server is dead, with the end of its stderr escaped, or "" while it is alive.
// It is for the operator's stderr only. Server text never goes to the client.
func (s *Server) Failure() string {
	select {
	case <-s.dead:
	default:
		return ""
	}
	if s.stderr != nil && s.stderr.String() != "" {
		return fmt.Sprintf("%s; last stderr: %q", s.why, s.stderr.String())
	}
	return s.why
}

// stderrTail keeps the last stderrKept bytes written to it.
type stderrTail struct {
	mu  sync.Mutex
	buf []byte
}

func (t *stderrTail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if extra := len(t.buf) - stderrKept; extra > 0 {
		t.buf = append(t.buf[:0], t.buf[extra:]...) // moves the tail to the front of the same array
	}
	return len(p), nil
}

func (t *stderrTail) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf)
}
