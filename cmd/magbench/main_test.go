package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

// Percentiles by nearest rank on known inputs. With 100 values after warm-up, p50 is the 50th and p99
// the 99th, and the first tenth of the requests, here 11 of 111, never counts.
func TestSummarizeOnKnownInputs(t *testing.T) {
	const start, rate = int64(1000), 1000 // one request due every millisecond
	received := make([]int64, 111)
	for i := range received {
		latency := int64(i-11+1) * 1e6 // the i-th kept request takes (i+1) ms
		if i < 11 {
			latency = 500e9 // warm-up: this would dominate if it counted
		}
		received[i] = dueTime(start, i, rate) + latency
	}
	got := summarize(received, start, rate, 3)
	want := [5]int64{50e6, 90e6, 99e6, 100e6, 100e6}
	if got.values != want {
		t.Errorf("values = %v, want %v", got.values, want)
	}
	if got.n != 100 || got.failed != 0 || got.late != 3 {
		t.Errorf("n = %d, failed = %d, late = %d", got.n, got.failed, got.late)
	}
}

// A request with no answer is the slowest of all, so that overload can't look fast.
func TestAnUnansweredRequestCountsAsNever(t *testing.T) {
	received := make([]int64, 20)
	for i := range received {
		received[i] = dueTime(0, i, 1000) + 1e6
	}
	received[15] = 0
	got := summarize(received, 0, 1000, 0)
	if got.failed != 1 || got.values[4] != never || got.values[0] != 1e6 {
		t.Errorf("%+v", got)
	}
	if ms(got.values[4]) != "never" {
		t.Errorf("printed as %s", ms(got.values[4]))
	}
}

func TestReplyID(t *testing.T) {
	tests := []struct {
		line string
		id   int
		ok   bool
	}{
		{`{"jsonrpc":"2.0","id":7,"result":{}}`, 7, true},
		{`{"jsonrpc":"2.0","id":0,"result":{}}`, 0, true},
		{`{"jsonrpc":"2.0","id":-1,"result":{}}`, 0, false},
		{`{"jsonrpc":"2.0","id":null,"error":{}}`, 0, false},
		{`{"jsonrpc":"2.0","id":"list","result":{}}`, 0, false},
		{`not a reply`, 0, false},
	}
	for _, tt := range tests {
		if id, ok := replyID([]byte(tt.line)); ok != tt.ok || (ok && id != tt.id) {
			t.Errorf("replyID(%s) = %d, %v", tt.line, id, ok)
		}
	}
}

// The search must land on the highest passing rate to within a tenth, and must not run past its limit.
func TestSearchKnee(t *testing.T) {
	tests := []struct{ start, limit, knee, low, high int }{
		{100, 100000, 3000, 2727, 3000},
		{100, 100000, 100, 100, 100},
		{100, 100000, 50, 46, 50}, // below where it starts
		{100, 100000, 0, 0, 0},    // nothing passes
		{500, 4000, 1000000, 4000, 4000},
	}
	for _, tt := range tests {
		probes := 0
		got := searchKnee(tt.start, tt.limit, func(rate int) bool {
			probes++
			if rate > tt.limit {
				t.Errorf("probed %d, past the limit of %d", rate, tt.limit)
			}
			return rate <= tt.knee
		})
		if got < tt.low || got > tt.high {
			t.Errorf("knee %d from %d: got %d, want %d to %d", tt.knee, tt.start, got, tt.low, tt.high)
		}
		if probes > 40 {
			t.Errorf("%d probes", probes)
		}
	}
}

// slowTarget answers each request after a delay, one at a time, as a server stuck in a queue would.
func slowTarget(t *testing.T, delay time.Duration) (io.Writer, *bufio.Reader) {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	go func() {
		defer outW.Close()
		lines := bufio.NewScanner(inR)
		for id := 0; lines.Scan(); id++ {
			time.Sleep(delay)
			fmt.Fprintf(outW, `{"jsonrpc":"2.0","id":%d,"result":{}}`+"\n", id)
		}
	}()
	t.Cleanup(func() { inW.Close(); outR.Close() })
	return inW, bufio.NewReader(outR)
}

// This is the point of an open loop. A target that takes 20 ms per request at 200 requests per second
// falls further behind with every request, and the wait must be charged to the requests that sat
// through it. A closed-loop tool would report about 20 ms here, because it waits before sending the
// next one. So must a loop that stalls its own sender, which the send buffer below rules out.
func TestAStalledTargetIsChargedForEveryRequestItHeldUp(t *testing.T) {
	in, out := slowTarget(t, 20*time.Millisecond)
	buffered := &asyncWriter{w: in, lines: make(chan []byte, 1024)}
	go buffered.run()
	got := openLoop(buffered, out, load{tool: "t", size: 0, rate: 200, n: 60, grace: 5 * time.Second}, func() {})
	if got.failed != 0 {
		t.Fatalf("%+v", got)
	}
	// The last request is due at 295 ms and can't be done before about 1,200 ms.
	if got.values[4] < int64(500*time.Millisecond) {
		t.Errorf("the worst latency is %s ms, which is what a closed loop would report", ms(got.values[4]))
	}
	if got.values[0] < int64(100*time.Millisecond) {
		t.Errorf("the median latency is %s ms, though most requests waited behind others", ms(got.values[0]))
	}
}

// asyncWriter stands in for the operating system's pipe buffer, so that the sender never blocks here.
type asyncWriter struct {
	w     io.Writer
	lines chan []byte
}

func (a *asyncWriter) Write(p []byte) (int, error) {
	a.lines <- bytes.Clone(p)
	return len(p), nil
}

func (a *asyncWriter) run() {
	for line := range a.lines {
		a.w.Write(line)
	}
}

// A healthy target at a low rate should cost next to nothing, so a test of the tool's own overhead.
func TestAFastTargetReportsLowLatency(t *testing.T) {
	in, out := slowTarget(t, 0)
	got := openLoop(in, out, load{tool: "t", size: 0, rate: 200, n: 40, grace: 5 * time.Second}, func() {})
	if got.failed != 0 || got.values[2] > int64(50*time.Millisecond) {
		t.Errorf("%+v", got)
	}
}

// A reply too short to hold the payload is a refusal and not an answer, or overload would look fast.
func TestARefusalIsNotCountedAsAnAnswer(t *testing.T) {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	go func() {
		defer outW.Close()
		lines := bufio.NewScanner(inR)
		for id := 0; lines.Scan(); id++ {
			fmt.Fprintf(outW, `{"jsonrpc":"2.0","id":%d,"result":{"isError":true}}`+"\n", id)
		}
	}()
	defer inW.Close()
	got := openLoop(inW, bufio.NewReader(outR), load{tool: "t", size: 1024, rate: 200, n: 20, grace: time.Second}, func() {})
	if got.failed != got.n || got.n == 0 {
		t.Errorf("%+v", got)
	}
}

func TestStubAnswersEveryKindOfRequest(t *testing.T) {
	var out bytes.Buffer
	stub(strings.NewReader(strings.Join([]string{
		`{"jsonrpc":"2.0","id":"a","method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":"b","method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"payload","arguments":{"size":2048}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"nonsense"}`,
	}, "\n")+"\n"), &out)
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("%d replies: %q", len(lines), out.String())
	}
	if !strings.Contains(lines[0], `"protocolVersion":"`+protocol+`"`) || !strings.Contains(lines[1], `"name":"`+toolName+`"`) {
		t.Errorf("handshake: %s %s", lines[0], lines[1])
	}
	if !strings.HasPrefix(lines[2], `{"jsonrpc":"2.0","id":3,`) || len(lines[2]) < 2048 {
		t.Errorf("the payload reply is %d bytes", len(lines[2]))
	}
	if !strings.Contains(lines[3], "-32601") {
		t.Errorf("unknown method: %s", lines[3])
	}
	// Prose, because one repeated letter would read as a huge encoded run and measure the scanner's worst case.
	if strings.Contains(payload(4096), strings.Repeat("a", 32)) || len(payload(4096)) != 4096 {
		t.Error("the payload is not the prose of the right size it should be")
	}
}
