// Command stubmodel stands in for the model endpoint on 127.0.0.1, so the real Claude Code client can
// be driven through tool calls with no model and no paid API. It answers with one canned tool_use per
// step, moving on as tool results come back, and then with canned text.
package main

import (
	"encoding/json"
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

// step is one tool call the model makes.
type step struct {
	Tool  string          `json:"tool"`
	Input json.RawMessage `json:"input"`
}

func main() {
	logPath := flag.String("log", "", "file that records what the client sent")
	portFile := flag.String("portfile", "", "file to write the listening port to")
	tool := flag.String("tool", "", "tool to call, as the client names it")
	text := flag.String("text", "hi", "value of the tool's text argument")
	stepsPath := flag.String("steps", "", "JSON file listing the tool calls to make in turn, in place of -tool and -text")
	lifetime := flag.Duration("lifetime", 5*time.Minute, "exit after this long, in case the script that started it dies")
	flag.Parse()

	steps := []step{{*tool, json.RawMessage(fmt.Sprintf(`{"text":%q}`, *text))}}
	if *stepsPath != "" {
		data, err := os.ReadFile(*stepsPath)
		if err == nil {
			err = json.Unmarshal(data, &steps)
		}
		if err != nil {
			log.Fatal(err)
		}
	}
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

	log.Fatal(http.Serve(listener, &model{log: logFile, steps: steps}))
}

type model struct {
	log   io.Writer
	steps []step
}

func (m *model) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	data, _ := io.ReadAll(r.Body)
	body := string(data)
	// The client resends the whole conversation each time, so the results in it say how far we are.
	done := strings.Count(body, `"tool_result"`)
	current := m.steps[min(done, len(m.steps)-1)]
	listed := strings.Contains(body, `"`+current.Tool+`"`)
	builtin := strings.Contains(body, `"name":"Bash"`) // one built-in tool stands for them all
	fmt.Fprintf(m.log, "REQ %s %s bytes=%d toolListed=%v toolResult=%v builtinTools=%v\n", r.Method, r.URL.Path, len(body), listed, done > 0, builtin)
	switch {
	case strings.Contains(r.URL.Path, "count_tokens"):
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"input_tokens":1}`)
	case !strings.Contains(r.URL.Path, "/messages"):
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, `{"type":"error","error":{"type":"not_found_error","message":"stub"}}`)
	default:
		if done > 0 {
			m.logResult(body)
		}
		var call *step
		if listed && done < len(m.steps) {
			call = &current
		}
		if strings.Contains(body, `"stream":true`) {
			m.stream(w, call, done+1)
		} else {
			m.single(w, call, done+1)
		}
	}
}

// logResult records how the newest tool result reads to the model, which is what the script checks.
func (m *model) logResult(body string) {
	start := strings.LastIndex(body, `"tool_result"`)
	end := min(start+700, len(body))
	fmt.Fprintf(m.log, "TOOLRESULT %s\n", body[start:end])
}

func (m *model) single(w http.ResponseWriter, call *step, n int) {
	w.Header().Set("Content-Type", "application/json")
	content, stop := `{"type":"text","text":"done"}`, "end_turn"
	if call != nil {
		content = fmt.Sprintf(`{"type":"tool_use","id":"toolu_stub%d","name":%q,"input":%s}`, n, call.Tool, call.Input)
		stop = "tool_use"
	}
	fmt.Fprintf(w, `{"id":"msg_stub","type":"message","role":"assistant","model":"stub","content":[%s],"stop_reason":%q,"stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}`, content, stop)
}

func (m *model) stream(w http.ResponseWriter, call *step, n int) {
	w.Header().Set("Content-Type", "text/event-stream")
	flusher := w.(http.Flusher)
	event := func(name, data string) {
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", name, data)
		flusher.Flush()
	}
	event("message_start", `{"type":"message_start","message":{"id":"msg_stub","type":"message","role":"assistant","model":"stub","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}}`)
	stop := "end_turn"
	if call != nil {
		stop = "tool_use"
		event("content_block_start", fmt.Sprintf(`{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_stub%d","name":%q,"input":{}}}`, n, call.Tool))
		event("content_block_delta", fmt.Sprintf(`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":%q}}`, call.Input))
	} else {
		event("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`)
		event("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"done"}}`)
	}
	event("content_block_stop", `{"type":"content_block_stop","index":0}`)
	event("message_delta", fmt.Sprintf(`{"type":"message_delta","delta":{"stop_reason":%q,"stop_sequence":null},"usage":{"output_tokens":1}}`, stop))
	event("message_stop", `{"type":"message_stop"}`)
}
