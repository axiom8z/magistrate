// Package fakemcp is a small scriptable MCP server for tests. A test gives it a Handler that decides
// what each message gets back, usually falling through to Default for everything it does not care
// about. It runs in-process on pipes or, through Serve, as a child process.
package fakemcp

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io"
	"sync"
	"sync/atomic"

	"github.com/axiom8z/magistrate/internal/rpc"
)

// EchoTool is the tool Default lists.
const EchoTool = `{"name":"echo","description":"Echo the text back.","inputSchema":{"type":"object","properties":{"text":{"type":"string"}}}}`

// InitializeResult is the answer Default gives to initialize.
const InitializeResult = `{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"fake","version":"0"}}`

// Handler answers one message. It runs on the server's read loop, so a handler that returns without
// answering is how a test plays a server that hangs.
type Handler func(c *Conn, m *rpc.Message)

// Conn is the server's end of the connection.
type Conn struct {
	mu   sync.Mutex
	out  io.Writer
	seen []string
	exit func()
}

// Send writes raw bytes followed by a newline, valid JSON or not.
func (c *Conn) Send(line string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	io.WriteString(c.out, line+"\n")
}

// Reply answers m with a raw JSON result.
func (c *Conn) Reply(m *rpc.Message, result string) {
	c.Send(`{"jsonrpc":"2.0","id":` + string(m.ID) + `,"result":` + result + `}`)
}

// Fail answers m with a JSON-RPC error.
func (c *Conn) Fail(m *rpc.Message, code, message string) {
	c.Send(`{"jsonrpc":"2.0","id":` + string(m.ID) + `,"error":{"code":` + code + `,"message":"` + message + `"}}`)
}

// Exit plays a server that dies: the stream ends with no goodbye.
func (c *Conn) Exit() { c.exit() }

// Seen returns every line received so far, exactly as it arrived.
func (c *Conn) Seen() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.seen...)
}

// Calls returns the messages received with this method, parsed.
func (c *Conn) Calls(method string) []*rpc.Message {
	var calls []*rpc.Message
	for _, line := range c.Seen() {
		if m, err := rpc.Parse([]byte(line)); err == nil && m.Method == method {
			calls = append(calls, m)
		}
	}
	return calls
}

func (c *Conn) readLoop(in io.Reader, h Handler) {
	r := rpc.NewReader(in)
	for {
		line, err := r.ReadLine()
		if err != nil {
			return
		}
		c.mu.Lock()
		c.seen = append(c.seen, string(line))
		c.mu.Unlock()
		if m, err := rpc.Parse(line); err == nil {
			h(c, m)
		}
	}
}

// Default is a well-behaved server with one echo tool.
func Default(c *Conn, m *rpc.Message) {
	switch m.Method {
	case "initialize":
		c.Reply(m, InitializeResult)
	case "tools/list":
		c.Reply(m, `{"tools":[`+EchoTool+`]}`)
	case "tools/call":
		c.Reply(m, EchoResult(m))
	default:
		if m.IsRequest() {
			c.Fail(m, "-32601", "Method not found")
		}
	}
}

// EchoResult is the result of the echo tool for the tools/call message m: its arguments as text.
func EchoResult(m *rpc.Message) string {
	var params struct {
		Arguments jsontext.Value `json:"arguments"`
	}
	json.Unmarshal(m.Params, &params)
	text, _ := jsontext.AppendQuote(nil, string(params.Arguments))
	return `{"content":[{"type":"text","text":` + string(text) + `}]}`
}

// On answers one method with h and leaves the rest to Default.
func On(method string, h Handler) Handler {
	return func(c *Conn, m *rpc.Message) {
		if m.Method == method {
			h(c, m)
			return
		}
		Default(c, m)
	}
}

// ListTools is a server whose tools/list returns these raw tool objects.
func ListTools(tools string) Handler {
	return On("tools/list", func(c *Conn, m *rpc.Message) { c.Reply(m, `{"tools":[`+tools+`]}`) })
}

// CallResult is a server whose every tools/call gets this raw result.
func CallResult(result string) Handler {
	return On("tools/call", func(c *Conn, m *rpc.Message) { c.Reply(m, result) })
}

// Serve runs h on real streams until in ends. A test binary calls it to play a server in a child
// process; exit is what Conn.Exit does there.
func Serve(in io.Reader, out io.Writer, exit func(), h Handler) {
	c := &Conn{out: out, exit: exit}
	c.readLoop(in, h)
}

// Pipe is a server running in-process on pipes. Stdin and Stdout are the ends a gateway would hold.
type Pipe struct {
	Conn   *Conn
	Stdin  io.WriteCloser
	Stdout io.Reader
	close  func()
	killed atomic.Bool
}

// NewPipe starts h on in-memory pipes. Like a real server, it ends when its input closes.
func NewPipe(h Handler) *Pipe { return newPipe(h, false) }

// NewStubbornPipe starts a server that ignores its input closing, so only Kill can end it.
func NewStubbornPipe(h Handler) *Pipe { return newPipe(h, true) }

func newPipe(h Handler, stubborn bool) *Pipe {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	var once sync.Once
	end := func() {
		once.Do(func() {
			inR.Close()
			outW.Close()
		})
	}
	p := &Pipe{Conn: &Conn{out: outW, exit: end}, Stdin: inW, Stdout: outR, close: end}
	go func() {
		p.Conn.readLoop(inR, h)
		if !stubborn {
			end()
		}
	}()
	return p
}

// Kill is what the gateway calls to kill this server.
func (p *Pipe) Kill() {
	p.killed.Store(true)
	p.close()
}

// Killed reports whether Kill was called.
func (p *Pipe) Killed() bool { return p.killed.Load() }
