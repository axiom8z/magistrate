// Command sayswho is a security gateway for AI agents. It proxies MCP over stdio between an agent and
// its tools, and keeps a hash-chained log of every decision. This package only reads the command
// line; the work is in the internal packages.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"maps"
	"os"
	"os/signal"
	"slices"
	"syscall"

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
  sayswho serve --policy <file> --state <dir>
  sayswho verify <log> [--head <hex>]
`

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
	if err := front.New(auditLog, notes).Serve(stdin, stdout, start); err != nil {
		fmt.Fprintf(stderr, "sayswho: %v\n", err)
		return exitFailed
	}
	return exitOK
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
