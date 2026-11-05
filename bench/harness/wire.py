"""How the benchmark talks to the real gateway binary: as a client on one side, and as the tool host on the other.
Standard library only, so test_wire.py can check all of it without AgentDojo installed.
"""
import json
import os
import pathlib
import re
import socket
import subprocess
import sys
import threading

HERE = pathlib.Path(__file__).resolve().parent
PROTOCOL = "2025-11-25"
BLOCK = re.compile(r"^Blocked by Magistrate, rule ([^:]+):")
# A wedged run must not hang the whole benchmark. The harness counts it as invalid.
CASE_TIMEOUT = 120

ACCEPT = {"action": "accept", "content": {"approve": True}}
DECLINE = {"action": "decline"}


def always_decline(_params):
    """The `deny` approver: nobody is there, so every question gets a no. This is the headline."""
    return DECLINE


def always_accept(_params):
    """The `approve` approver, which shows what only blocks can stop."""
    return ACCEPT


def server_entry():
    """How the policy starts the relay. -I keeps the relay's folder off the import path."""
    return {"command": sys.executable, "args": ["-I", "-X", "utf8", str(HERE / "host_relay.py")], "env": ["MAGISTRATE_TOOLS", "MAGISTRATE_HOST_PORT"]}


def text_result(text, structured=None, is_error=False):
    result = {"content": [{"type": "text", "text": text}]}
    if structured is not None:
        result["structuredContent"] = structured
    if is_error:
        result["isError"] = True
    return result


class ToolHost:
    """Listens on loopback, and answers each call the relay passes on by asking `handler(name, arguments)`."""

    def __init__(self, handler):
        self.handler = handler
        self.problems = []
        self.calls = []
        self.server = socket.create_server(("127.0.0.1", 0))
        self.port = self.server.getsockname()[1]
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        try:
            connection, _ = self.server.accept()
        except OSError:
            return  # closed before any tool was called
        with connection, connection.makefile("rwb") as stream:
            for line in stream:
                request = json.loads(line)
                self.calls.append(request["name"])
                try:
                    reply = self.handler(request["name"], request["arguments"])
                except Exception as problem:  # a broken tool host must be seen, not taken for a tool error
                    self.problems.append(f'{request["name"]}: {type(problem).__name__}: {problem}')
                    reply = text_result("HOST ERROR", is_error=True)
                stream.write(json.dumps(reply).encode() + b"\n")
                stream.flush()

    def close(self):
        self.server.close()


class Reply:
    def __init__(self, text, rule, asks, is_error):
        self.text = text
        self.rule = rule  # the gateway's rule if it refused the call, else None
        self.asks = asks
        self.is_error = is_error


class GatewaySession:
    """One gateway process with its own state directory, spoken to the way a client would."""

    def __init__(self, binary, policy, state, tools_file, host_port, prompt_file=None, approver=always_decline):
        self.approver = approver
        self.next_id = 0
        command = [str(binary), "serve", "--policy", str(policy), "--state", str(state)]
        if prompt_file:
            command += ["--prompt-file", str(prompt_file)]
        env = dict(os.environ, MAGISTRATE_TOOLS=str(tools_file), MAGISTRATE_HOST_PORT=str(host_port))
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
        self.timer = threading.Timer(CASE_TIMEOUT, self.process.kill)
        self.timer.start()
        self.request("initialize", {"protocolVersion": PROTOCOL, "capabilities": {"elicitation": {"form": {}}}, "clientInfo": {"name": "harness", "version": "0"}})
        self.send({"method": "notifications/initialized"})

    def send(self, message):
        self.process.stdin.write(json.dumps({"jsonrpc": "2.0", **message}).encode() + b"\n")
        self.process.stdin.flush()

    def request(self, method, params):
        self.next_id += 1
        wanted = self.next_id
        self.send({"id": wanted, "method": method, "params": params})
        asks = 0
        while True:
            line = self.process.stdout.readline()
            if not line:
                raise RuntimeError("the gateway closed its output")
            message = json.loads(line)
            if message.get("method") == "elicitation/create":
                asks += 1
                self.send({"id": message["id"], "result": self.approver(message.get("params") or {})})
            elif message.get("id") == wanted:
                return message, asks

    def tools(self):
        message, _ = self.request("tools/list", {})
        return message["result"]["tools"]

    def call(self, tool, arguments):
        message, asks = self.request("tools/call", {"name": "s__" + tool, "arguments": arguments})
        if "error" in message:
            raise RuntimeError(f'the gateway answered {tool} with an error: {message["error"]}')
        result = message["result"]
        text = result["content"][0]["text"] if result.get("content") else ""
        match = BLOCK.match(text)
        return Reply(text, match.group(1) if match else None, asks, bool(result.get("isError")))

    def close(self):
        self.process.stdin.close()
        self.process.wait()
        self.timer.cancel()
        self.process.stdout.close()


def write_tools(path, listing):
    pathlib.Path(path).write_text(json.dumps(listing), encoding="utf-8")


def draft_policy(binary, base_file, tools_file):
    """`magistrate init` against the relay, which is also where the tool pins come from."""
    env = dict(os.environ, MAGISTRATE_TOOLS=str(tools_file))
    env.pop("MAGISTRATE_HOST_PORT", None)
    done = subprocess.run([str(binary), "init", "--policy", str(base_file)], capture_output=True, env=env, timeout=120)
    if done.returncode != 0:
        raise RuntimeError("init failed: " + done.stderr.decode(errors="replace"))
    return json.loads(done.stdout)


def base_policy():
    return {"mode": "value", "servers": {"s": server_entry()}}
