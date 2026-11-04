// Package front is the gateway's client-facing side. It speaks MCP to the agent on stdin and stdout,
// and every tool call passes through it on the way to a server.
package front

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"log"
	"sync"

	"github.com/axiom8z/sayswho/internal/approve"
	"github.com/axiom8z/sayswho/internal/audit"
	"github.com/axiom8z/sayswho/internal/gate"
	"github.com/axiom8z/sayswho/internal/policy"
	"github.com/axiom8z/sayswho/internal/prov"
	"github.com/axiom8z/sayswho/internal/rpc"
	"github.com/axiom8z/sayswho/internal/upstream"
)

// Config is what a Gateway enforces. HasPrompt is separate from Prompt because an empty prompt file is
// still a prompt file: it sources nothing, and must not turn on the no-prompt rule.
type Config struct {
	Policy    *policy.Policy
	Prompt    string
	HasPrompt bool
	StateDir  string
}

// Gateway serves one client session.
type Gateway struct {
	audit  *audit.Log
	notes  *log.Logger // stderr, for the operator; never the client
	out    *rpc.Writer
	policy *policy.Policy
	prov   *prov.State
	latch  *gate.Latch
	budget *approve.Budget
	// hasPrompt says whether a prompt file was given.
	hasPrompt bool

	// Written once by the read loop, before it starts any call that reads them.
	initialized   bool
	clientElicits bool // the client declared form elicitation, so a person can be asked

	// Written by startServers before it closes ready, and only read after that.
	ready   chan struct{}
	servers map[string]*upstream.Server
	listed  map[string]bool
	hidden  map[string]string // tools the policy refuses, with the rule that says why
	listing jsontext.Value

	calls     sync.WaitGroup
	mu        sync.Mutex
	inflight  map[string]context.CancelFunc // running calls, by the client's raw request ID
	questions map[string]chan *rpc.Message  // open questions, by our raw request ID
	asked     int                           // questions sent, which makes each one's ID
}

// New returns a Gateway that records to auditLog and writes operator notes to notes.
func New(auditLog *audit.Log, notes *log.Logger, cfg Config) *Gateway {
	p := cfg.Policy
	return &Gateway{audit: auditLog, notes: notes, policy: p, hasPrompt: cfg.HasPrompt,
		prov: prov.New(cfg.Prompt, p.TrustedValues, p.BoundIDs), latch: gate.NewLatch(cfg.StateDir),
		budget: approve.NewBudget(p.AsksPerSession), ready: make(chan struct{}),
		servers: map[string]*upstream.Server{}, listed: map[string]bool{}, hidden: map[string]string{},
		inflight: map[string]context.CancelFunc{}, questions: map[string]chan *rpc.Message{}}
}

// Serve runs the session until in ends, then stops the servers and closes the log. Only protocol
// messages are ever written to out.
//
// The servers start in the background, so that server/discover and initialize get their answers at
// once however slow a server is. The two methods that need the tools wait for them.
func (g *Gateway) Serve(in io.Reader, out io.Writer, start func(context.Context) []*upstream.Server) error {
	g.out = rpc.NewWriter(out)
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	go g.startServers(ctx, start)
	readErr := g.readLoop(ctx, in)

	// The client is gone, so nobody can take an answer. Cancelling ends every call and any handshake
	// still running. None of this is relied on: the client may kill us at any point in it, and that
	// is why decisions are made durable when they happen rather than here.
	stop()
	<-g.ready
	g.calls.Wait()
	var stopping sync.WaitGroup
	for _, s := range g.servers {
		stopping.Go(s.Close)
	}
	stopping.Wait()
	return errors.Join(readErr, g.audit.Close())
}

func (g *Gateway) readLoop(ctx context.Context, in io.Reader) error {
	r := rpc.NewReader(in)
	for {
		line, err := r.ReadLine()
		switch {
		case errors.Is(err, io.EOF):
			return nil
		case errors.Is(err, rpc.ErrLineTooLong):
			g.replyError(rpc.NullID, rpc.CodeInvalidRequest, "Line over the 1 MiB cap")
			continue
		case err != nil:
			return err
		}
		m, err := rpc.Parse(line)
		switch {
		case errors.Is(err, rpc.ErrInvalidMessage):
			g.replyError(rpc.NullID, rpc.CodeInvalidRequest, "Invalid Request")
		case err != nil:
			g.replyError(rpc.NullID, rpc.CodeParseError, "Parse error")
		default:
			g.handle(ctx, m)
		}
	}
}

func (g *Gateway) handle(ctx context.Context, m *rpc.Message) {
	switch {
	case m.IsResponse():
		g.answered(m)
	case m.IsNotification():
		// notifications/initialized needs no action, and unknown notifications are to be ignored.
		if m.Method == "notifications/cancelled" {
			g.cancelCall(m.Params)
		}
	case m.Method == "initialize":
		g.initialize(m)
	case m.Method == "ping":
		g.reply(m.ID, jsontext.Value("{}"))
	case m.Method == "tools/list":
		g.toolsList(m)
	case m.Method == "tools/call":
		g.toolsCall(ctx, m)
	default:
		// This covers server/discover. Claude Code probes with it, then falls back to initialize on
		// -32601, which is how it comes to speak the one protocol era we support.
		g.replyError(m.ID, rpc.CodeMethodNotFound, "Method not found")
	}
}

// initialize answers with our one version whatever the client asked for. There is no instructions
// field and no listChanged, so the only tool list a client ever sees is the one sent once.
func (g *Gateway) initialize(m *rpc.Message) {
	var params struct {
		Capabilities struct {
			Elicitation jsontext.Value `json:"elicitation"`
		} `json:"capabilities"`
	}
	if g.initialized {
		g.replyError(m.ID, rpc.CodeInvalidRequest, "Already initialized")
		return
	}
	if m.Params != nil && json.Unmarshal(m.Params, &params) != nil {
		g.replyError(m.ID, rpc.CodeInvalidParams, "Invalid params")
		return
	}
	g.initialized = true
	g.clientElicits = declaresForm(params.Capabilities.Elicitation)
	g.reply(m.ID, map[string]any{
		"protocolVersion": upstream.ProtocolVersion,
		"capabilities":    map[string]any{"tools": map[string]any{}},
		"serverInfo":      map[string]string{"name": "sayswho", "version": upstream.Version},
	})
}

// declaresForm reads the elicitation capability. The specification says an empty object means form
// mode, and that a server must not send a mode the client did not declare, so a client declaring only
// url can't be asked.
func declaresForm(raw jsontext.Value) bool {
	var modes map[string]jsontext.Value
	if raw.Kind() != jsontext.KindBeginObject || json.Unmarshal(raw, &modes) != nil {
		return false
	}
	_, form := modes["form"]
	_, url := modes["url"]
	return form || !url
}

func (g *Gateway) toolsList(m *rpc.Message) {
	if !g.initialized {
		g.replyError(m.ID, rpc.CodeInvalidRequest, "Call initialize first")
		return
	}
	<-g.ready
	g.reply(m.ID, g.listing)
}

func (g *Gateway) cancelCall(params jsontext.Value) {
	var p struct {
		RequestID jsontext.Value `json:"requestId"`
	}
	if json.Unmarshal(params, &p) != nil {
		return // the specification says to ignore a malformed cancellation
	}
	g.mu.Lock()
	cancel := g.inflight[string(p.RequestID)]
	g.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (g *Gateway) reply(id jsontext.Value, result any) {
	raw, err := json.Marshal(result)
	if err == nil {
		err = g.out.Write(rpc.Message{ID: id, Result: raw})
	}
	if err != nil {
		g.notes.Printf("replying to the client: %v", err)
	}
}

func (g *Gateway) replyError(id jsontext.Value, code int, message string) {
	if err := g.out.Write(rpc.Message{ID: id, Error: &rpc.Error{Code: code, Message: message}}); err != nil {
		g.notes.Printf("replying to the client: %v", err)
	}
}
