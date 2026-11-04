// Command stubmodel stands in for the model endpoint on 127.0.0.1, so the real Claude Code client can
// be driven through one tool call with no model and no paid API. It answers the first request with a
// canned tool_use, and once a tool result comes back it answers with canned text.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	logPath := flag.String("log", "", "file that records what the client sent")
	portFile := flag.String("portfile", "", "file to write the listening port to")
	tool := flag.String("tool", "", "tool to call, as the client names it")
	text := flag.String("text", "hi", "value of the tool's text argument")
	lifetime := flag.Duration("lifetime", 5*time.Minute, "exit after this long, in case the script that started it dies")
	flag.Parse()

	logFile, err := os.OpenFile(*logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		log.Fatal(err)
	}
	// Loopback only: this must never be reachable from another machine.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := os.WriteFile(*portFile, []byte(strconv.Itoa(port)), 0o600); err != nil {
		log.Fatal(err)
	}
	time.AfterFunc(*lifetime, func() { os.Exit(1) })

	stub := &model{log: logFile, tool: *tool, input: fmt.Sprintf(`{"text":%q}`, *text)}
	log.Fatal(http.Serve(listener, stub))
}

type model struct {
	log         io.Writer
	tool, input string
}

func (m *model) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	data, _ := io.ReadAll(r.Body)
	body := string(data)
	listed := strings.Contains(body, `"`+m.tool+`"`)
	answered := strings.Contains(body, `"tool_result"`)
	builtin := strings.Contains(body, `"name":"Bash"`) // one built-in tool stands for them all
	fmt.Fprintf(m.log, "REQ %s %s bytes=%d toolListed=%v toolResult=%v builtinTools=%v\n", r.Method, r.URL.Path, len(body), listed, answered, builtin)
	switch {
	case strings.Contains(r.URL.Path, "count_tokens"):
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"input_tokens":1}`)
	case !strings.Contains(r.URL.Path, "/messages"):
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, `{"type":"error","error":{"type":"not_found_error","message":"stub"}}`)
	default:
		if answered {
			m.logResult(body)
		}
		useTool := listed && !answered
		if strings.Contains(body, `"stream":true`) {
			m.stream(w, useTool)
		} else {
			m.single(w, useTool)
		}
	}
}

// logResult records how the tool result reads to the model, which is what the script checks.
func (m *model) logResult(body string) {
	start := strings.Index(body, `"tool_result"`)
	end := min(start+700, len(body))
	fmt.Fprintf(m.log, "TOOLRESULT %s\n", body[start:end])
}

func (m *model) single(w http.ResponseWriter, useTool bool) {
	w.Header().Set("Content-Type", "application/json")
	content, stop := `{"type":"text","text":"done"}`, "end_turn"
	if useTool {
		content = fmt.Sprintf(`{"type":"tool_use","id":"toolu_stub1","name":%q,"input":%s}`, m.tool, m.input)
		stop = "tool_use"
	}
	fmt.Fprintf(w, `{"id":"msg_stub","type":"message","role":"assistant","model":"stub","content":[%s],"stop_reason":%q,"stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}`, content, stop)
}

func (m *model) stream(w http.ResponseWriter, useTool bool) {
	w.Header().Set("Content-Type", "text/event-stream")
	flusher := w.(http.Flusher)
	event := func(name, data string) {
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", name, data)
		flusher.Flush()
	}
	event("message_start", `{"type":"message_start","message":{"id":"msg_stub","type":"message","role":"assistant","model":"stub","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}}`)
	stop := "end_turn"
	if useTool {
		stop = "tool_use"
		event("content_block_start", fmt.Sprintf(`{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_stub1","name":%q,"input":{}}}`, m.tool))
		event("content_block_delta", fmt.Sprintf(`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":%q}}`, m.input))
	} else {
		event("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`)
		event("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"done"}}`)
	}
	event("content_block_stop", `{"type":"content_block_stop","index":0}`)
	event("message_delta", fmt.Sprintf(`{"type":"message_delta","delta":{"stop_reason":%q,"stop_sequence":null},"usage":{"output_tokens":1}}`, stop))
	event("message_stop", `{"type":"message_stop"}`)
}
