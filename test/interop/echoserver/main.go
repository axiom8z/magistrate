// Command echoserver is a tiny MCP server with one tool that sends its text back. It uses the older
// encoding/json and none of the gateway's packages on purpose: the gateway's wire format then gets
// checked by code that shares nothing with it.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

const (
	initializeResult = `{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"echo","version":"0"}}`
	toolsResult      = `{"tools":[{"name":"echo","description":"Send the text back.","inputSchema":{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}}]}`
)

type request struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params struct {
		Arguments struct {
			Text string `json:"text"`
		} `json:"arguments"`
	} `json:"params"`
}

func main() {
	fmt.Fprintln(os.Stderr, "echoserver: started") // the gateway must drain this and not pass it on
	input := bufio.NewReader(os.Stdin)
	for {
		line, err := input.ReadBytes('\n')
		if err != nil {
			return
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			fmt.Fprintln(os.Stderr, "echoserver: bad message:", err)
			continue
		}
		switch {
		case req.ID == nil:
			// A notification: nothing to answer.
		case req.Method == "initialize":
			reply(req.ID, initializeResult)
		case req.Method == "tools/list":
			reply(req.ID, toolsResult)
		case req.Method == "tools/call":
			text, _ := json.Marshal("echo: " + req.Params.Arguments.Text)
			reply(req.ID, fmt.Sprintf(`{"content":[{"type":"text","text":%s}]}`, text))
		default:
			fmt.Printf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"Method not found"}}`+"\n", req.ID)
		}
	}
}

func reply(id json.RawMessage, result string) {
	fmt.Printf(`{"jsonrpc":"2.0","id":%s,"result":%s}`+"\n", id, result)
}
