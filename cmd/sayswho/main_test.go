package main

import (
	"bytes"
	"encoding/json/v2"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/axiom8z/sayswho/internal/audit"
	"github.com/axiom8z/sayswho/internal/rpc"
	"github.com/axiom8z/sayswho/test/fakemcp"
)

// serverVar makes the test binary play an MCP server. It reaches the child only because the policy
// these tests write names it, which also exercises the environment allowlist end to end.
const serverVar = "SAYSWHO_CMD_TEST_SERVER"

func TestMain(m *testing.M) {
	if os.Getenv(serverVar) != "" {
		// Stray output on the server's stderr, which must never reach the client.
		fmt.Fprintln(os.Stderr, "server chatter on stderr")
		fakemcp.Serve(os.Stdin, os.Stdout, func() { os.Exit(3) }, fakemcp.Default)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// writePolicy writes a policy running this test binary as a server called echo.
func writePolicy(t *testing.T, dir string) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(serverVar, "1")
	data, err := json.Marshal(map[string]any{
		"mode":    "pass",
		"servers": map[string]any{"echo": map[string]any{"command": exe, "env": []string{serverVar}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// session mirrors what Claude Code sends, in the order the evidence log shows it.
var session = strings.Join([]string{
	`{"jsonrpc":"2.0","id":"server-discover-probe-1","method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`,
	`{"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{"roots":{"listChanged":true},"elicitation":{"form":{},"url":{}}},"clientInfo":{"name":"claude-code","version":"2.1.302"}},"jsonrpc":"2.0","id":0}`,
	`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
	`{"method":"tools/list","jsonrpc":"2.0","id":1}`,
	`{"method":"tools/call","params":{"name":"echo__echo","arguments":{"text":"hi"},"_meta":{"claudecode/toolUseId":"toolu_stub1","progressToken":2}},"jsonrpc":"2.0","id":2}`,
}, "\n") + "\n"

// serveSession runs a whole session through the real serve command and a real child process. Stdin
// stays open until the last reply is seen, because a client leaving is what ends in-flight calls.
func serveSession(t *testing.T, args []string, input string, replies int) (code int, stdout, stderr string) {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	var errBuf bytes.Buffer
	done := make(chan int)
	go func() {
		code := run(append([]string{"serve"}, args...), inR, outW, &errBuf)
		outW.Close()
		done <- code
	}()
	go func() {
		io.WriteString(inW, input)
	}()
	var out strings.Builder
	r := rpc.NewReader(outR)
	for range replies {
		line, err := r.ReadLine()
		if err != nil {
			t.Fatalf("output ended early, after %q: %v; stderr: %s", out.String(), err, errBuf.String())
		}
		out.Write(line)
		out.WriteByte('\n')
	}
	inW.Close()
	// Drain whatever else comes, which should be nothing.
	rest, _ := io.ReadAll(outR)
	out.Write(rest)
	code = <-done
	return code, out.String(), errBuf.String()
}

func TestServeEndToEnd(t *testing.T) {
	dir := t.TempDir()
	policyPath := writePolicy(t, dir)
	state := filepath.Join(dir, "state")
	code, stdout, stderr := serveSession(t, []string{"--policy", policyPath, "--state", state}, session, 4)
	if code != exitOK {
		t.Fatalf("exit code = %d; stderr: %s", code, stderr)
	}

	// Nothing but protocol messages on stdout, and exactly the expected ones.
	var byID = map[string]*rpc.Message{}
	for line := range strings.Lines(stdout) {
		m, err := rpc.Parse([]byte(strings.TrimSuffix(line, "\n")))
		if err != nil {
			t.Fatalf("stdout holds something that is not JSON-RPC: %q: %v", line, err)
		}
		byID[string(m.ID)] = m
	}
	if len(byID) != 4 {
		t.Fatalf("%d replies on stdout: %s", len(byID), stdout)
	}
	if strings.Contains(stdout, "chatter") || strings.Contains(stderr, "chatter") {
		t.Fatalf("a healthy server's stderr was passed on: stdout %q, stderr %q", stdout, stderr)
	}
	if m := byID[`"server-discover-probe-1"`]; m == nil || m.Error == nil || m.Error.Code != rpc.CodeMethodNotFound {
		t.Errorf("server/discover = %+v", m)
	}
	if m := byID["0"]; m == nil || !strings.Contains(string(m.Result), `"protocolVersion":"2025-11-25"`) {
		t.Errorf("initialize = %+v", m)
	}
	if m := byID["1"]; m == nil || !strings.Contains(string(m.Result), `"name":"echo__echo"`) {
		t.Errorf("tools/list = %+v", m)
	}
	if m := byID["2"]; m == nil || !strings.Contains(string(m.Result), "hi") || strings.Contains(string(m.Result), "isError") {
		t.Errorf("tools/call = %+v", m)
	}

	// The log verifies, through the command a person would run.
	logPath := filepath.Join(state, "audit.log")
	var out, errOut bytes.Buffer
	if code := run([]string{"verify", logPath}, nil, &out, &errOut); code != exitOK {
		t.Fatalf("verify = %d: %s", code, errOut.String())
	}
	if !strings.HasPrefix(out.String(), "ok: 2 records, head ") {
		t.Errorf("verify printed %q", out.String())
	}
	if data, err := os.ReadFile(logPath); err != nil || bytes.Contains(data, []byte(`"hi"`)) {
		t.Errorf("the log holds an argument value, or could not be read (%v): %s", err, data)
	}

	// A second run on the same state continues the same chain.
	code, _, stderr = serveSession(t, []string{"--policy", policyPath, "--state", state}, session, 4)
	if code != exitOK {
		t.Fatalf("second run: exit code = %d; stderr: %s", code, stderr)
	}
	sum, err := audit.Verify(logPath, "")
	if err != nil || sum.Count != 4 {
		t.Fatalf("after a second run: %+v, %v", sum, err)
	}
}

func TestServeReportsABrokenServerAndKeepsGoing(t *testing.T) {
	dir := t.TempDir()
	data := `{"mode":"pass","servers":{"gone":{"command":"sayswho-no-such-command"}}}`
	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	input := `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}` + "\n" +
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"gone__x"}}` + "\n"
	code, stdout, stderr := serveSession(t, []string{"--policy", policyPath, "--state", filepath.Join(dir, "state")}, input, 2)
	if code != exitOK {
		t.Fatalf("exit code = %d; stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "upstream-dead") {
		t.Errorf("stdout = %s", stdout)
	}
	if !strings.Contains(stderr, "gone") || !strings.Contains(stderr, "could not start") {
		t.Errorf("stderr = %s", stderr)
	}
}

func TestServeRefusesToStart(t *testing.T) {
	dir := t.TempDir()
	good := writePolicy(t, dir)
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"mode":"pass","servers":{"a":{"command":"x"}},"typo":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	notPass := filepath.Join(dir, "value.json")
	if err := os.WriteFile(notPass, []byte(`{"mode":"value","servers":{"a":{"command":"x"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	torn := t.TempDir()
	if err := os.WriteFile(filepath.Join(torn, "audit.log"), []byte(`{"rec":{"seq":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	blocked := filepath.Join(dir, "a-file")
	if err := os.WriteFile(blocked, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		args    []string
		want    int
		wantErr string
	}{
		{"no flags", []string{"serve"}, exitUsage, "usage"},
		{"no state", []string{"serve", "--policy", good}, exitUsage, "usage"},
		{"no policy", []string{"serve", "--state", dir}, exitUsage, "usage"},
		{"stray argument", []string{"serve", "--policy", good, "--state", dir, "extra"}, exitUsage, "usage"},
		{"unknown flag", []string{"serve", "--nope"}, exitUsage, "usage"},
		{"missing policy file", []string{"serve", "--policy", filepath.Join(dir, "none"), "--state", dir}, exitUsage, "policy"},
		{"bad policy", []string{"serve", "--policy", bad, "--state", dir}, exitUsage, "typo"},
		{"a mode not built yet", []string{"serve", "--policy", notPass, "--state", dir}, exitUsage, "not available"},
		{"torn log", []string{"serve", "--policy", good, "--state", torn}, exitFailed, "failed verification"},
		{"state path is a file", []string{"serve", "--policy", good, "--state", blocked}, exitFailed, "state directory"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := run(tt.args, strings.NewReader(""), &out, &errOut); code != tt.want {
				t.Fatalf("exit code = %d, want %d; stderr: %s", code, tt.want, errOut.String())
			}
			if !strings.Contains(errOut.String(), tt.wantErr) {
				t.Errorf("stderr %q does not mention %q", errOut.String(), tt.wantErr)
			}
			if out.Len() != 0 {
				t.Errorf("stdout should stay empty, got %q", out.String())
			}
		})
	}
}

func TestUsage(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"no command", nil},
		{"unknown command", []string{"nope"}},
		{"run is not built yet", []string{"run"}},
		{"init is not built yet", []string{"init"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := run(tt.args, nil, &out, &errOut); code != exitUsage {
				t.Fatalf("exit code = %d", code)
			}
			if !strings.Contains(errOut.String(), "usage") {
				t.Errorf("stderr = %q", errOut.String())
			}
		})
	}
}

// makeLog writes a real log through the audit package and returns its path.
func makeLog(t *testing.T, records int) string {
	t.Helper()
	dir := t.TempDir()
	l, err := audit.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for range records {
		if err := l.Append(audit.Record{Tool: "s__t", Decision: audit.Allow}, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "audit.log")
}

func TestVerifyCommand(t *testing.T) {
	good := makeLog(t, 3)
	sum, err := audit.Verify(good, "")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}

	// The end of milestone 2: flip one byte and verify fails.
	flipped := filepath.Join(t.TempDir(), "flipped.log")
	changed := bytes.Clone(data)
	changed[len(changed)/2] ^= 1
	if err := os.WriteFile(flipped, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	truncated := filepath.Join(t.TempDir(), "truncated.log")
	firstLine := data[:bytes.IndexByte(data, '\n')+1]
	if err := os.WriteFile(truncated, firstLine, 0o600); err != nil {
		t.Fatal(err)
	}
	other := strings.Repeat("ab", 32)
	tests := []struct {
		name    string
		args    []string
		want    int
		wantOut string
	}{
		{"a good log", []string{good}, exitOK, "ok: 3 records, head " + sum.Head},
		{"a good log and its head, flag last", []string{good, "--head", sum.Head}, exitOK, "ok: 3 records"},
		{"a good log and its head, flag first", []string{"--head", sum.Head, good}, exitOK, "ok: 3 records"},
		{"a flipped byte", []string{flipped}, exitFailed, ""},
		{"a head from elsewhere", []string{good, "--head", other}, exitFailed, ""},
		{"a truncated log with no head passes, the documented limit", []string{truncated}, exitOK, "ok: 1 records"},
		{"a truncated log and the head it lost", []string{truncated, "--head", sum.Head}, exitFailed, ""},
		{"a missing file", []string{filepath.Join(t.TempDir(), "none")}, exitFailed, ""},
		{"no log", nil, exitUsage, ""},
		{"only a head", []string{"--head", sum.Head}, exitUsage, ""},
		{"two logs", []string{good, good}, exitUsage, ""},
		{"a head with no value", []string{good, "--head"}, exitUsage, ""},
		{"an empty head", []string{good, "--head", ""}, exitUsage, ""},
		{"a short head", []string{good, "--head", "abc"}, exitUsage, ""},
		{"an uppercase head", []string{good, "--head", strings.ToUpper(sum.Head)}, exitUsage, ""},
		{"an unknown flag", []string{good, "--nope"}, exitUsage, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := run(append([]string{"verify"}, tt.args...), nil, &out, &errOut)
			if code != tt.want {
				t.Fatalf("exit code = %d, want %d; stdout %q stderr %q", code, tt.want, out.String(), errOut.String())
			}
			if !strings.Contains(out.String(), tt.wantOut) {
				t.Errorf("stdout %q does not hold %q", out.String(), tt.wantOut)
			}
			if code != exitOK && errOut.Len() == 0 {
				t.Error("a failure printed nothing")
			}
		})
	}
}
