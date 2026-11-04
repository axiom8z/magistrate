// Command sayswho is a security gateway for AI agents. It proxies MCP over stdio between an agent and
// its tools, and keeps a hash-chained log of every decision. This package only reads the command
// line; the work is in the internal packages.
package main

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"maps"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"syscall"
	"unicode/utf8"

	"github.com/axiom8z/sayswho/internal/audit"
	"github.com/axiom8z/sayswho/internal/front"
	"github.com/axiom8z/sayswho/internal/policy"
	"github.com/axiom8z/sayswho/internal/upstream"
)

// Exit codes, part of the documented interface.
const (
	exitOK     = 0
	exitFailed = 1 // something went wrong, or verify found a bad log
	exitUsage  = 2 // the command line or the policy file is wrong
)

const usageText = `usage:
  sayswho serve --policy <file> --state <dir> [--prompt-file <file>]
  sayswho run --policy <file> --state <dir> --prompt-file <file> [--client <path>] [-- client flags]
  sayswho init --policy <file>
  sayswho verify <log> [--head <hex>]
`

// draftAsks is the question budget a draft starts with. DESIGN section 4: interrupted tasks in the
// rerun asked at most four times.
const draftAsks = 5

func main() {
	// Without this, Go kills the process when a write to a closed stdout fails. With it, the write
	// just returns an error, so the gateway still reaches its shutdown when the client goes away.
	signal.Notify(make(chan os.Signal, 1), syscall.SIGPIPE)
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run is main without the process-wide effects, so tests can drive the real thing.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return usage(stderr, nil)
	}
	switch args[0] {
	case "serve":
		return serve(args[1:], stdin, stdout, stderr)
	case "run":
		return runClient(args[1:], stdin, stdout, stderr)
	case "init":
		return draftPolicy(args[1:], stdout, stderr)
	case "verify":
		return verify(args[1:], stdout, stderr)
	}
	return usage(stderr, fmt.Errorf("unknown command %q", args[0]))
}

// usage reports a command line that can't run, saying why if there is more to say than the syntax.
func usage(stderr io.Writer, err error) int {
	if err != nil {
		fmt.Fprintf(stderr, "sayswho: %v\n", err)
	}
	fmt.Fprint(stderr, usageText)
	return exitUsage
}

func serve(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	policyPath := flags.String("policy", "", "")
	stateDir := flags.String("state", "", "")
	prompt, hasPrompt := "", false
	// A Func flag runs only when the flag is given, so --prompt-file "" from an empty shell variable
	// is refused. Taken as "no prompt file", it would turn on the rule that trusts early arguments.
	flags.Func("prompt-file", "", func(path string) (err error) {
		prompt, err = readPrompt(path)
		hasPrompt = err == nil
		return err
	})
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *policyPath == "" || *stateDir == "" {
		return usage(stderr, err)
	}
	p, err := policy.Load(*policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "sayswho: policy %s: %v\n", *policyPath, err)
		return exitUsage
	}
	if err := os.MkdirAll(*stateDir, 0o700); err != nil {
		fmt.Fprintf(stderr, "sayswho: state directory: %v\n", err)
		return exitFailed
	}
	auditLog, err := audit.Open(*stateDir)
	if err != nil {
		fmt.Fprintf(stderr, "sayswho: %v\n", err)
		return exitFailed
	}
	start := func(ctx context.Context) []*upstream.Server {
		return upstream.StartAll(ctx, serverConfigs(p))
	}
	notes := log.New(stderr, "sayswho: ", 0)
	cfg := front.Config{Policy: p, Prompt: prompt, HasPrompt: hasPrompt, StateDir: *stateDir}
	if err := front.New(auditLog, notes, cfg).Serve(stdin, stdout, start); err != nil {
		fmt.Fprintf(stderr, "sayswho: %v\n", err)
		return exitFailed
	}
	return exitOK
}

// runClient is the run command of DESIGN section 7. It makes the gateway the client's only MCP server
// and turns off the client's own tools, which a gateway can't see. The -- ends the options, because
// --mcp-config takes any number of values and would otherwise swallow the prompt, and a prompt starting
// with "-" would read as a flag.
func runClient(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	policyPath := flags.String("policy", "", "")
	stateDir := flags.String("state", "", "")
	promptPath := flags.String("prompt-file", "", "")
	client := flags.String("client", "claude", "")
	if err := flags.Parse(args); err != nil || *policyPath == "" || *stateDir == "" || *promptPath == "" {
		return usage(stderr, err)
	}
	// Both are checked here as well as in serve, because a client can bury a server that fails to start.
	prompt, err := readPrompt(*promptPath)
	if err != nil {
		fmt.Fprintf(stderr, "sayswho: prompt file: %v\n", err)
		return exitUsage
	}
	if _, err := policy.Load(*policyPath); err != nil {
		fmt.Fprintf(stderr, "sayswho: policy %s: %v\n", *policyPath, err)
		return exitUsage
	}
	config, err := writeClientConfig(*policyPath, *stateDir, *promptPath)
	if err != nil {
		fmt.Fprintf(stderr, "sayswho: client config: %v\n", err)
		return exitFailed
	}
	argv := append([]string{"--tools", "", "--strict-mcp-config", "--mcp-config", config}, flags.Args()...)
	cmd := exec.Command(*client, append(argv, "--", prompt)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	err = cmd.Run()
	var ended *exec.ExitError
	if errors.As(err, &ended) {
		return ended.ExitCode()
	}
	if err != nil {
		fmt.Fprintf(stderr, "sayswho: starting the client: %v\n", err)
		return exitFailed
	}
	return exitOK
}

// writeClientConfig writes the MCP config that starts this same binary, and returns its path. The
// client may run from any folder, so every path in it is absolute.
func writeClientConfig(policyPath, stateDir, promptPath string) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	paths := []string{policyPath, stateDir, promptPath}
	for i, path := range paths {
		if paths[i], err = filepath.Abs(path); err != nil {
			return "", err
		}
	}
	raw, err := json.Marshal(map[string]any{"mcpServers": map[string]any{"sayswho": map[string]any{
		"type": "stdio", "command": exe,
		"args": []string{"serve", "--policy", paths[0], "--state", paths[1], "--prompt-file", paths[2]},
	}}})
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(paths[1], 0o700); err != nil {
		return "", err
	}
	config := filepath.Join(paths[1], "mcp-config.json")
	return config, os.WriteFile(config, raw, 0o600)
}

// draftPolicy is the init command. It asks each server for its tools and prints the policy with a
// strict guess at every label, for a person to correct. A server that fails stops it, because a draft
// quietly missing a server's tools would look finished.
func draftPolicy(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	policyPath := flags.String("policy", "", "")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *policyPath == "" {
		return usage(stderr, err)
	}
	p, err := policy.Load(*policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "sayswho: policy %s: %v\n", *policyPath, err)
		return exitUsage
	}
	servers := upstream.StartAll(context.Background(), serverConfigs(p))
	defer func() {
		for _, s := range servers {
			s.Close()
		}
	}()
	if err := fillDraft(p, servers); err != nil {
		fmt.Fprintf(stderr, "sayswho: %v\n", err)
		return exitFailed
	}
	raw, err := json.Marshal(p, jsontext.WithIndent("  "), json.Deterministic(true))
	if err == nil {
		_, err = policy.Parse(raw) // what comes out has to load, or it is no use to anyone
	}
	if err != nil {
		fmt.Fprintf(stderr, "sayswho: the draft does not load: %v\n", err)
		return exitFailed
	}
	fmt.Fprintf(stdout, "%s\n", raw)
	return exitOK
}

// fillDraft replaces the policy's tools with drafted labels. Pass mode reads no labels, so a draft of
// one moves to value, the mode they are for.
func fillDraft(p *policy.Policy, servers []*upstream.Server) error {
	if p.Mode == policy.ModePass {
		p.Mode = policy.ModeValue
	}
	if p.AsksPerSession == 0 {
		p.AsksPerSession = draftAsks
	}
	p.Tools = map[string]policy.Tool{}
	for _, s := range servers {
		if why := s.Failure(); why != "" {
			return fmt.Errorf("server %q: %s", s.Name(), why)
		}
		for _, t := range s.Tools() {
			label, err := policy.Draft(s.Name(), t)
			if err != nil {
				return fmt.Errorf("server %q: %w", s.Name(), err)
			}
			p.Tools[s.Name()+"__"+t.Name] = label
		}
	}
	return nil
}

// readPrompt reads the user's request, the one trusted input besides the policy file.
func readPrompt(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(data) {
		return "", errors.New("the prompt file is not valid UTF-8")
	}
	return string(data), nil
}

func serverConfigs(p *policy.Policy) []upstream.Config {
	var cfgs []upstream.Config
	for _, name := range slices.Sorted(maps.Keys(p.Servers)) {
		s := p.Servers[name]
		cfgs = append(cfgs, upstream.Config{Name: name, Command: s.Command, Args: s.Args, Env: s.Env})
	}
	return cfgs
}

func verify(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	head := ""
	// A Func flag runs only when the flag is given, so --head "" from an empty shell variable is
	// refused. Treating it as "no saved head" would pass a log the caller meant to check.
	flags.Func("head", "", func(value string) error {
		if !audit.ValidHead(value) {
			return errors.New("not 64 lowercase hex digits")
		}
		head = value
		return nil
	})
	// flag stops at the first plain argument, so parse again after the log path to allow --head on
	// either side of it.
	if err := flags.Parse(args); err != nil || flags.NArg() == 0 {
		return usage(stderr, err)
	}
	path := flags.Arg(0)
	if err := flags.Parse(flags.Args()[1:]); err != nil || flags.NArg() != 0 {
		return usage(stderr, err)
	}
	sum, err := audit.Verify(path, head)
	if err != nil {
		fmt.Fprintf(stderr, "sayswho: verify failed for %s: %v\n", path, err)
		return exitFailed
	}
	fmt.Fprintf(stdout, "ok: %d records, head %s\n", sum.Count, sum.Head)
	return exitOK
}
