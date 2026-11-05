"""The MCP server behind the gateway during log replay. It lists a suite's tools and answers each call
with what the log says that call returned, so the gateway sees what it would have seen on the day.

It reads two files named by environment variables, which the policy lets through to it:
MAGISTRATE_TOOLS holds the tool list, and MAGISTRATE_CASE holds the logged calls. With no case it can only
list tools, which is all `magistrate init` needs. Standard library only.
"""
import collections
import json
import os
import sys

PROTOCOL = "2025-11-25"


def key(name, args):
    # Sorted, because a call is matched by what it says and not by how it was spelled.
    return name, json.dumps(args, sort_keys=True)


def load_outputs():
    path = os.environ.get("MAGISTRATE_CASE")
    outputs = collections.defaultdict(collections.deque)
    if path:
        with open(path, encoding="utf-8") as f:
            for call in json.load(f)["calls"]:
                outputs[key(call["tool"], call["args"])].append(call["result"])
    return outputs


def main():
    with open(os.environ["MAGISTRATE_TOOLS"], encoding="utf-8") as f:
        tools = json.load(f)
    outputs = load_outputs()
    stdout = sys.stdout.buffer
    for line in sys.stdin.buffer:
        message = json.loads(line)
        method = message.get("method")
        if "id" not in message or method is None:
            continue  # a notification, or an answer to something this server never asked
        if method == "initialize":
            result = {"protocolVersion": PROTOCOL, "capabilities": {"tools": {}}, "serverInfo": {"name": "relay", "version": "0"}}
        elif method == "tools/list":
            result = {"tools": tools}
        elif method == "tools/call":
            params = message["params"]
            queue = outputs[key(params["name"], params.get("arguments") or {})]
            # A call the log does not hold means the harness is wrong, and it checks for this text.
            result = queue.popleft() if queue else {"content": [{"type": "text", "text": "RELAY: this call is not in the log"}], "isError": True}
        else:
            reply = {"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32601, "message": "Method not found"}}
            stdout.write(json.dumps(reply).encode() + b"\n")
            stdout.flush()
            continue
        reply = {"jsonrpc": "2.0", "id": message["id"], "result": result}
        stdout.write(json.dumps(reply).encode() + b"\n")
        stdout.flush()


if __name__ == "__main__":
    main()
