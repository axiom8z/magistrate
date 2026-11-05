"""The MCP server behind the gateway during a benchmark run. It lists a suite's tools, and passes each call over a
loopback socket to the tool host in the harness, which runs the real tool against the task's environment.

    harness (client) -> sayswho -> this file -> socket -> harness (tool host) -> run_function(env, ...)

It reads two environment variables, which the policy lets through: SAYSWHO_TOOLS names a file holding the tool list,
and SAYSWHO_HOST_PORT is the tool host's port. With no port it can only list tools, which is all `sayswho init` needs.
Standard library only, so the gateway can start it with any Python.
"""
import json
import os
import socket
import sys

PROTOCOL = "2025-11-25"
LOOPBACK = "127.0.0.1"


def main():
    with open(os.environ["SAYSWHO_TOOLS"], encoding="utf-8") as f:
        tools = json.load(f)
    port = os.environ.get("SAYSWHO_HOST_PORT")
    host = None
    stdout = sys.stdout.buffer

    def answer(message_id, body):
        stdout.write(json.dumps({"jsonrpc": "2.0", "id": message_id, **body}).encode() + b"\n")
        stdout.flush()

    for line in sys.stdin.buffer:
        message = json.loads(line)
        method = message.get("method")
        if "id" not in message or method is None:
            continue  # a notification, or an answer to something this server never asked
        if method == "initialize":
            answer(message["id"], {"result": {"protocolVersion": PROTOCOL, "capabilities": {"tools": {}}, "serverInfo": {"name": "host_relay", "version": "0"}}})
        elif method == "tools/list":
            answer(message["id"], {"result": {"tools": tools}})
        elif method == "tools/call" and port:
            if host is None:
                host = socket.create_connection((LOOPBACK, int(port))).makefile("rwb")
            params = message["params"]
            host.write(json.dumps({"name": params["name"], "arguments": params.get("arguments") or {}}).encode() + b"\n")
            host.flush()
            answer(message["id"], {"result": json.loads(host.readline())})
        else:
            answer(message["id"], {"error": {"code": -32601, "message": "Method not found"}})


if __name__ == "__main__":
    main()
