// Command magbench measures the delay a gateway adds to MCP calls (DESIGN section 8).
//
//	magbench stub
//	magbench run [flags] [-- gateway command line]
//
// stub is an instant MCP server. run measures it directly and, given a command line, through a gateway
// whose policy starts the stub, in interleaved rounds. An argument equal to {state} becomes a new
// empty folder for each start, because a gateway reads its whole log at startup and a growing log
// would slow later rounds.
//
// The load is open loop, like wrk2: request i is due at t0 + i/rate whatever became of earlier ones,
// and latency runs from the due time, so a stall is charged to every request it held up.
package main

import (
	"bufio"
	"bytes"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/axiom8z/magistrate/internal/rpc"
)

const (
	toolName  = "payload"
	protocol  = "2025-11-25"
	stateSlot = "{state}"
	spinNS    = 3e6 // the last stretch before a due time is spun, because a sleep overshoots by more
	lateNS    = 1e6 // a send later than this counts as late
	never     = math.MaxInt64

	grace    = 10 * time.Second      // how long to wait for late replies after the last send
	kneeTime = 3 * time.Second       // the length of one knee probe
	kneeP99  = 10 * time.Millisecond // a knee probe passes with p99 under this and nothing failed
)

// The sizes in KB and the rates per second that DESIGN section 8 names.
var (
	sizes = []int{1, 16, 256}
	rates = []int{100, 500}
)

func main() {
	switch {
	case len(os.Args) > 1 && os.Args[1] == "stub":
		stub(os.Stdin, os.Stdout)
	case len(os.Args) > 1 && os.Args[1] == "run":
		os.Exit(run(os.Args[2:], os.Stdout))
	default:
		fmt.Fprintln(os.Stderr, "usage: magbench stub | magbench run [flags] [-- gateway command line]")
		os.Exit(2)
	}
}

// stub answers one request at a time. Each call names its payload size, so one policy file serves
// every size, and each reply body is built once, so that the stub's work stays out of the measurement.
func stub(in io.Reader, out io.Writer) {
	reader, bodies := rpc.NewReader(in), map[int]string{}
	var reply []byte
	for {
		line, err := reader.ReadLine()
		if err != nil {
			return
		}
		if m, err := rpc.Parse(line); err == nil && m.IsRequest() {
			reply = append(append(append(reply[:0], `{"jsonrpc":"2.0","id":`...), m.ID...), stubBody(m, bodies)...)
			out.Write(reply)
		}
	}
}

func stubBody(m *rpc.Message, bodies map[int]string) string {
	switch m.Method {
	case "initialize":
		return `,"result":{"protocolVersion":"` + protocol + `","capabilities":{"tools":{}},"serverInfo":{"name":"magbench","version":"0"}}}` + "\n"
	case "tools/list":
		return `,"result":{"tools":[{"name":"` + toolName + `","inputSchema":{"type":"object","properties":{"size":{"type":"integer"}}}}]}}` + "\n"
	case "tools/call":
		var params struct {
			Arguments struct {
				Size int `json:"size"`
			} `json:"arguments"`
		}
		json.Unmarshal(m.Params, &params)
		size := min(max(params.Arguments.Size, 0), rpc.MaxLine-256)
		if bodies[size] == "" {
			bodies[size] = `,"result":{"content":[{"type":"text","text":"` + payload(size) + `"}]}}` + "\n"
		}
		return bodies[size]
	}
	return `,"error":{"code":-32601,"message":"Method not found"}}` + "\n"
}

// payload is prose rather than one repeated letter, which the secret scanner would read as one huge
// encoded run: that would measure its worst case and not the normal one.
func payload(size int) string {
	const sentence = "The quarterly numbers are attached, and the team will review them on Monday. "
	return strings.Repeat(sentence, size/len(sentence)+1)[:size]
}

// target is a running server or gateway that has finished its handshake.
type target struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	tool   string
	cold   int64 // from starting the process to the first tools/list reply
	state  string
}

func startTarget(argv []string) (*target, error) {
	t := &target{}
	argv = slices.Clone(argv)
	if i := slices.Index(argv, stateSlot); i >= 0 {
		dir, err := os.MkdirTemp("", "magbench-state-")
		if err != nil {
			return nil, err
		}
		argv[i], t.state = dir, dir
	}
	began := nowNS()
	t.cmd = exec.Command(argv[0], argv[1:]...)
	t.cmd.Stderr = os.Stderr
	stdin, inErr := t.cmd.StdinPipe()
	stdout, outErr := t.cmd.StdoutPipe()
	err := errors.Join(inErr, outErr)
	if err == nil {
		err = t.cmd.Start()
	}
	if err != nil {
		return nil, err
	}
	t.stdin, t.stdout = stdin, bufio.NewReaderSize(stdout, rpc.MaxLine+64)
	// A handshake that never finishes ends here, by the kill closing the pipe it is reading.
	timer := time.AfterFunc(time.Minute, func() { t.cmd.Process.Kill() })
	defer timer.Stop()
	if err := t.handshake(began); err != nil {
		t.stop()
		return nil, err
	}
	return t, nil
}

func (t *target) handshake(began int64) error {
	init := `{"protocolVersion":"` + protocol + `","capabilities":{},"clientInfo":{"name":"magbench","version":"0"}}`
	if _, err := t.request(`"init"`, "initialize", init); err != nil {
		return err
	}
	io.WriteString(t.stdin, `{"jsonrpc":"2.0","method":"notifications/initialized"}`+"\n")
	listing, err := t.request(`"list"`, "tools/list", "{}")
	t.cold = nowNS() - began
	if err != nil {
		return err
	}
	var result struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	json.Unmarshal(listing, &result)
	for _, tool := range result.Tools {
		if strings.HasSuffix(tool.Name, toolName) { // a gateway lists it as <server>__payload
			t.tool = tool.Name
			return nil
		}
	}
	return errors.New("its tools/list has no " + toolName + " tool")
}

func (t *target) request(id, method, params string) ([]byte, error) {
	line := `{"jsonrpc":"2.0","id":` + id + `,"method":"` + method + `","params":` + params + "}\n"
	if _, err := io.WriteString(t.stdin, line); err != nil {
		return nil, err
	}
	reply, err := t.stdout.ReadSlice('\n')
	if err != nil {
		return nil, fmt.Errorf("%s: %w", method, err)
	}
	m, err := rpc.Parse(bytes.TrimSpace(reply))
	if err != nil || m.Error != nil {
		return nil, errors.New(method + " failed")
	}
	return m.Result, nil
}

func (t *target) stop() {
	t.stdin.Close()
	timer := time.AfterFunc(5*time.Second, func() { t.cmd.Process.Kill() })
	defer timer.Stop()
	t.cmd.Wait()
	if t.state != "" {
		os.RemoveAll(t.state)
	}
}

// load is one measurement.
type load struct {
	tool          string
	size, rate, n int
	grace         time.Duration
}

// stats is one measurement's outcome. A request that got no payload, being a refusal or no reply at
// all, counts as never answered: a refusal is quick, and leaving it in would make overload look fast.
type stats struct {
	values          [5]int64 // p50, p90, p99, p99.9, max, in ns
	n, failed, late int
	cold            int64
}

// openLoop runs a load over a target's pipes. The sender and the reader are separate goroutines and
// neither waits for the other, so a slow reply can't delay a send. If the target stops reading, the
// sender does wait, and the requests behind it are late and charged for it. abort must end both.
func openLoop(in io.Writer, out *bufio.Reader, l load, abort func()) stats {
	received := make([]int64, l.n)
	done := make(chan struct{})
	go func() {
		defer close(done)
		readReplies(out, l.size, received)
	}()
	deadline := time.AfterFunc(time.Duration(l.n)*time.Second/time.Duration(l.rate)+l.grace, abort)
	defer deadline.Stop()
	start := nowNS() + 1e8 // first due time, far enough ahead that it can't be late already
	late := sendAll(in, l, start)
	<-done
	return summarize(received, start, l.rate, late)
}

func dueTime(start int64, i, rate int) int64 { return start + int64(i)*1e9/int64(rate) }

func sendAll(in io.Writer, l load, start int64) (late int) {
	tail := fmt.Sprintf(`,"method":"tools/call","params":{"name":%q,"arguments":{"size":%d}}}`+"\n", l.tool, l.size)
	line := make([]byte, 0, 256)
	for i := range l.n {
		due := dueTime(start, i, l.rate)
		if wait := due - nowNS(); wait > spinNS {
			time.Sleep(time.Duration(wait - spinNS))
		}
		for nowNS() < due {
		}
		line = append(strconv.AppendInt(append(line[:0], `{"jsonrpc":"2.0","id":`...), int64(i), 10), tail...)
		if _, err := in.Write(line); err != nil {
			return late
		}
		if nowNS()-due > lateNS {
			late++
		}
	}
	return late
}

// readReplies does no JSON parsing: at 256 KB that would slow this loop and back up the very pipe
// being measured. A reply shorter than the payload can't hold it, so it isn't counted as answered.
func readReplies(out *bufio.Reader, size int, received []int64) {
	for range received {
		line, err := out.ReadSlice('\n')
		now := nowNS()
		if err != nil {
			return
		}
		if id, ok := replyID(line); ok && id < len(received) && len(line) >= size {
			received[id] = now
		}
	}
}

func replyID(line []byte) (int, bool) {
	_, rest, found := bytes.Cut(line[:min(len(line), 64)], []byte(`"id":`))
	end := bytes.IndexByte(rest, ',')
	if !found || end < 0 {
		return 0, false
	}
	id, err := strconv.Atoi(string(rest[:end]))
	return id, err == nil && id >= 0
}

// summarize drops the first tenth of the requests as warm-up, then takes percentiles by nearest rank.
func summarize(received []int64, start int64, rate, late int) stats {
	s := stats{late: late}
	var latencies []int64
	for i := len(received) / 10; i < len(received); i++ {
		if received[i] == 0 {
			latencies = append(latencies, never)
			s.failed++
		} else {
			latencies = append(latencies, received[i]-dueTime(start, i, rate))
		}
	}
	slices.Sort(latencies)
	s.n = len(latencies)
	for i, p := range []float64{50, 90, 99, 99.9, 100} {
		s.values[i] = latencies[max(int(math.Ceil(p/100*float64(s.n)))-1, 0)]
	}
	return s
}

// config is what the flags say.
type config struct {
	rounds   int
	duration time.Duration
	knee     bool
	modes    []mode
}

type mode struct {
	name string
	argv []string
}

func measure(m mode, size, rate int, duration time.Duration) (stats, error) {
	t, err := startTarget(m.argv)
	if err != nil {
		return stats{}, fmt.Errorf("%s: %w", m.name, err)
	}
	defer t.stop()
	l := load{t.tool, size << 10, rate, int(duration.Seconds() * float64(rate)), grace}
	s := openLoop(t.stdin, t.stdout, l, func() { t.cmd.Process.Kill() })
	s.cold = t.cold
	return s, nil
}

// searchKnee finds the highest rate that passes: it doubles until a rate fails, then bisects down to
// about a tenth. Each probe is a fresh process, so one failed probe can't spoil the next.
func searchKnee(start, limit int, passes func(rate int) bool) int {
	low, high := 0, start
	for high <= limit && passes(high) {
		low, high = high, high*2
	}
	if high > limit {
		return low
	}
	for high-low > max(low/10, 1) {
		if mid := (low + high) / 2; passes(mid) {
			low = mid
		} else {
			high = mid
		}
	}
	return low
}

func parseFlags(args []string, stubArgv []string) (*config, error) {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	c := &config{}
	flags.IntVar(&c.rounds, "rounds", 5, "interleaved rounds")
	flags.DurationVar(&c.duration, "duration", 20*time.Second, "length of one measurement")
	flags.BoolVar(&c.knee, "knee", true, "search for the knee after the rounds")
	if err := flags.Parse(args); err != nil {
		return nil, err
	}
	c.modes = []mode{{"direct", stubArgv}}
	if flags.NArg() > 0 {
		c.modes = append(c.modes, mode{"gateway", flags.Args()})
	}
	return c, nil
}

func run(args []string, out io.Writer) int {
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "magbench:", err)
		return 1
	}
	c, err := parseFlags(args, []string{exe, "stub"})
	if err != nil {
		fmt.Fprintln(os.Stderr, "magbench:", err)
		return 2
	}
	if err := rounds(c, out); err != nil {
		fmt.Fprintln(os.Stderr, "magbench:", err)
		return 1
	}
	return 0
}

type cell struct {
	size, rate int
	mode       string
}

func rounds(c *config, out io.Writer) error {
	results := map[cell][]stats{}
	for round := range c.rounds {
		for _, size := range sizes {
			for _, rate := range rates {
				// Each round swaps who goes first, so a machine warming up or cooling down favours neither.
				for i := range c.modes {
					m := c.modes[(i+round)%len(c.modes)]
					s, err := measure(m, size, rate, c.duration)
					if err != nil {
						return err
					}
					key := cell{size, rate, m.name}
					results[key] = append(results[key], s)
					fmt.Fprintf(out, "round %d %dKB %d/s %s n=%d failed=%d late=%d p50=%s p99=%s max=%s cold=%s\n", round+1, size, rate, m.name,
						s.n, s.failed, s.late, ms(s.values[0]), ms(s.values[2]), ms(s.values[4]), ms(s.cold))
				}
			}
		}
	}
	printTable(c, results, out)
	if !c.knee {
		return nil
	}
	for _, size := range sizes {
		for _, m := range c.modes {
			var failure error
			best := searchKnee(slices.Max(rates), 100_000, func(rate int) bool {
				s, err := measure(m, size, rate, kneeTime)
				failure = errors.Join(failure, err)
				return err == nil && s.failed == 0 && s.values[2] <= int64(kneeP99)
			})
			if failure != nil {
				return failure
			}
			fmt.Fprintf(out, "knee %dKB %s: %d/s (p99 at most %v, nothing failed, %v probes)\n", size, m.name, best, kneeP99, kneeTime)
		}
	}
	return nil
}

func printTable(c *config, results map[cell][]stats, out io.Writer) {
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "ms, lowest-highest of %d rounds\t\tn\tfailed\tlate\tp50\tp90\tp99\tp99.9\tmax\tcold start\n", c.rounds)
	for _, size := range sizes {
		for _, rate := range rates {
			var direct, gateway []stats
			for _, m := range c.modes {
				rows := results[cell{size, rate, m.name}]
				if m.name == "direct" {
					direct = rows
				} else {
					gateway = rows
				}
				fmt.Fprintf(w, "%dKB %d/s\t%s\t%d\t%d\t%d", size, rate, m.name, rows[0].n, total(rows, func(s stats) int { return s.failed }), total(rows, func(s stats) int { return s.late }))
				printRanges(w, func(i, col int) int64 { return rows[i].values[col] }, len(rows))
				fmt.Fprintf(w, "\t%s\n", rangeOf(len(rows), func(i int) int64 { return rows[i].cold }))
			}
			if gateway != nil {
				fmt.Fprintf(w, "%dKB %d/s\tadded\t\t\t", size, rate)
				printRanges(w, func(i, col int) int64 { return subtract(gateway[i].values[col], direct[i].values[col]) }, len(gateway))
				fmt.Fprintln(w)
			}
		}
	}
	w.Flush()
}

func printRanges(w io.Writer, value func(i, col int) int64, rows int) {
	for col := range 5 {
		fmt.Fprintf(w, "\t%s", rangeOf(rows, func(i int) int64 { return value(i, col) }))
	}
}

func total(rows []stats, field func(stats) int) int {
	sum := 0
	for _, s := range rows {
		sum += field(s)
	}
	return sum
}

func subtract(a, b int64) int64 {
	if a == never || b == never {
		return never
	}
	return a - b
}

func rangeOf(rows int, value func(i int) int64) string {
	low, high := int64(never), int64(-never)
	for i := range rows {
		low, high = min(low, value(i)), max(high, value(i))
	}
	return ms(low) + "-" + ms(high)
}

func ms(ns int64) string {
	if ns == never {
		return "never"
	}
	return strconv.FormatFloat(float64(ns)/1e6, 'f', 3, 64)
}
