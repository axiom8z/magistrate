package rpc

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"runtime"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
)

func TestReadLine(t *testing.T) {
	atCap := strings.Repeat("x", MaxLine)
	tests := []struct {
		name  string
		input string
		want  []string // the lines, in order; "!" stands for ErrLineTooLong
	}{
		{"empty stream", "", nil},
		{"one line", "a\n", []string{"a"}},
		{"two lines", "a\nb\n", []string{"a", "b"}},
		{"CRLF is accepted", "a\r\nb\r\n", []string{"a", "b"}},
		{"a CR inside a line stays", "a\rb\n", []string{"a\rb"}},
		{"last line without a newline", "a\nb", []string{"a", "b"}},
		{"blank line is a line", "\n\na\n", []string{"", "", "a"}},
		{"exactly at the cap", atCap + "\nb\n", []string{atCap, "b"}},
		{"at the cap with CRLF", atCap + "\r\nb\n", []string{atCap, "b"}},
		{"at the cap without a newline", atCap, []string{atCap}},
		{"one over the cap, then reading goes on", atCap + "x\nb\n", []string{"!", "b"}},
		{"far over the cap, then reading goes on", atCap + atCap + atCap + "\nb\n", []string{"!", "b"}},
		{"over the cap with no newline", atCap + "x", []string{"!"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewReader(strings.NewReader(tt.input))
			for i, want := range tt.want {
				line, err := r.ReadLine()
				if want == "!" {
					if !errors.Is(err, ErrLineTooLong) {
						t.Fatalf("line %d: err = %v, want ErrLineTooLong", i, err)
					}
					continue
				}
				if err != nil {
					t.Fatalf("line %d: %v", i, err)
				}
				if string(line) != want {
					t.Fatalf("line %d: got %d bytes, want %d", i, len(line), len(want))
				}
			}
			if _, err := r.ReadLine(); !errors.Is(err, io.EOF) {
				t.Fatalf("after the last line: err = %v, want io.EOF", err)
			}
		})
	}
}

// The cap exists to bound memory against a peer that never sends a newline. A 64 MiB line must cost
// about what a 1 MiB line costs, and the bytes past the cap must not be kept.
func TestOverLongLineDoesNotGrowMemory(t *testing.T) {
	const size = 64 << 20
	r := NewReader(io.MultiReader(io.LimitReader(endlessX{}, size), strings.NewReader("\nnext\n")))
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := r.ReadLine()
	runtime.ReadMemStats(&after)
	if !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("err = %v, want ErrLineTooLong", err)
	}
	if got := after.TotalAlloc - before.TotalAlloc; got > 8<<20 {
		t.Errorf("reading a %d MiB line allocated %d MiB", size>>20, got>>20)
	}
	if line, err := r.ReadLine(); err != nil || string(line) != "next" {
		t.Errorf("the next line = %q, %v", line, err)
	}
}

type endlessX struct{}

func (endlessX) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

// A read error other than EOF must come through, or a broken pipe would look like a clean finish.
func TestReadLinePassesReadErrors(t *testing.T) {
	boom := errors.New("boom")
	r := NewReader(io.MultiReader(strings.NewReader("partial"), iotest.ErrReader(boom)))
	if _, err := r.ReadLine(); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}
}

func TestParseAccepts(t *testing.T) {
	tests := []struct {
		name                     string
		line                     string
		request, notice, respond bool
		id                       string
	}{
		{"request, integer id", `{"jsonrpc":"2.0","id":7,"method":"ping"}`, true, false, false, "7"},
		{"request, string id", `{"jsonrpc":"2.0","id":"a","method":"ping"}`, true, false, false, `"a"`},
		{"request, negative id", `{"jsonrpc":"2.0","id":-3,"method":"ping"}`, true, false, false, "-3"},
		{"request, huge integer id", `{"jsonrpc":"2.0","id":123456789012345678901234567890,"method":"ping"}`, true, false, false, "123456789012345678901234567890"},
		{"notification", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, false, true, false, ""},
		{"result", `{"jsonrpc":"2.0","id":1,"result":{}}`, false, false, true, "1"},
		{"null result", `{"jsonrpc":"2.0","id":1,"result":null}`, false, false, true, "1"},
		{"error", `{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"x"}}`, false, false, true, "1"},
		{"error with a null id", `{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"x"}}`, false, false, true, "null"},
		{"unknown members are ignored", `{"jsonrpc":"2.0","method":"x","extra":1}`, false, true, false, ""},
		{"whitespace around values", " {\"jsonrpc\" : \"2.0\" ,\t\"id\" : 1 , \"method\":\"x\"}\r", true, false, false, "1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := Parse([]byte(tt.line))
			if err != nil {
				t.Fatal(err)
			}
			if m.IsRequest() != tt.request || m.IsNotification() != tt.notice || m.IsResponse() != tt.respond {
				t.Errorf("kind: request=%v notification=%v response=%v", m.IsRequest(), m.IsNotification(), m.IsResponse())
			}
			if string(m.ID) != tt.id {
				t.Errorf("id = %q, want %q", []byte(m.ID), tt.id)
			}
		})
	}
}

// What comes out holds U+FFFD and nothing that a strict decoder would refuse, so no later reader can
// see the broken original.
func TestParseRepairsBrokenCharacters(t *testing.T) {
	tests := []struct{ name, line, want string }{
		{"half an emoji, as JSON.stringify writes it", `{"jsonrpc":"2.0","method":"x","params":{"a":"cut \ud83d"}}`, "cut �"},
		{"the other half", `{"jsonrpc":"2.0","method":"x","params":{"a":"\ude00 cut"}}`, "� cut"},
		{"an invalid byte", "{\"jsonrpc\":\"2.0\",\"method\":\"x\",\"params\":{\"a\":\"cut \xff\"}}", "cut �"},
		{"a whole emoji stays whole", `{"jsonrpc":"2.0","method":"x","params":{"a":"😀"}}`, "\U0001F600"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := Parse([]byte(tt.line))
			if err != nil {
				t.Fatal(err)
			}
			var params struct {
				A string `json:"a"`
			}
			if err := json.Unmarshal(m.Params, &params); err != nil {
				t.Fatalf("a strict decoder refuses what came out: %v", err)
			}
			if params.A != tt.want {
				t.Errorf("got %q, want %q", params.A, tt.want)
			}
		})
	}
}

func TestParseRejects(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		invalid bool // ErrInvalidMessage rather than a parse error
	}{
		{"not JSON", `hello`, false},
		{"empty line", ``, false},
		{"truncated", `{"jsonrpc":"2.0",`, false},
		{"duplicate key", `{"jsonrpc":"2.0","id":1,"id":2,"method":"x"}`, false},
		{"duplicate key inside params", `{"jsonrpc":"2.0","method":"x","params":{"a":1,"a":2}}`, false},
		{"duplicate key spelled with an escape", "{\"jsonrpc\":\"2.0\",\"method\":\"x\",\"params\":{\"a\":1,\"\\u0061\":2}}", false},
		{"a broken character does not excuse a duplicate key", "{\"jsonrpc\":\"2.0\",\"method\":\"x\",\"params\":{\"a\":\"\\ud83d\",\"a\":\"b\"}}", false},
		{"trailing data", `{"jsonrpc":"2.0","method":"x"} {"jsonrpc":"2.0","method":"y"}`, false},
		{"nesting beyond the decoder's limit", `{"jsonrpc":"2.0","method":"x","params":` + strings.Repeat("[", 10001) + strings.Repeat("]", 10001) + `}`, false},
		{"batch", `[{"jsonrpc":"2.0","id":1,"method":"x"}]`, true},
		{"empty batch", `[]`, true},
		{"a bare number", `5`, true},
		{"a bare string", `"x"`, true},
		{"top-level null", `null`, true},
		{"no version", `{"id":1,"method":"x"}`, true},
		{"wrong version", `{"jsonrpc":"1.0","id":1,"method":"x"}`, true},
		{"numeric version", `{"jsonrpc":2.0,"id":1,"method":"x"}`, true},
		{"method of the wrong type", `{"jsonrpc":"2.0","id":1,"method":7}`, true},
		{"null id on a request", `{"jsonrpc":"2.0","id":null,"method":"x"}`, true},
		{"float id on a request", `{"jsonrpc":"2.0","id":1.5,"method":"x"}`, true},
		{"exponent id on a request", `{"jsonrpc":"2.0","id":1e3,"method":"x"}`, true},
		{"boolean id on a request", `{"jsonrpc":"2.0","id":true,"method":"x"}`, true},
		{"object id on a request", `{"jsonrpc":"2.0","id":{},"method":"x"}`, true},
		{"array id on a request", `{"jsonrpc":"2.0","id":[1],"method":"x"}`, true},
		{"empty method", `{"jsonrpc":"2.0","id":1,"method":""}`, true},
		{"method and result", `{"jsonrpc":"2.0","id":1,"method":"x","result":{}}`, true},
		{"method and error", `{"jsonrpc":"2.0","id":1,"method":"x","error":{"code":1,"message":"m"}}`, true},
		{"neither method nor id", `{"jsonrpc":"2.0"}`, true},
		{"id with no result or error", `{"jsonrpc":"2.0","id":1}`, true},
		{"result and error", `{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"m"}}`, true},
		{"response without an id", `{"jsonrpc":"2.0","result":{}}`, true},
		{"result with a null id", `{"jsonrpc":"2.0","id":null,"result":{}}`, true},
		{"float id on a response", `{"jsonrpc":"2.0","id":1.5,"result":{}}`, true},
		{"error of the wrong type", `{"jsonrpc":"2.0","id":1,"error":5}`, true},
		{"error code that is a float", `{"jsonrpc":"2.0","id":1,"error":{"code":1.5,"message":"m"}}`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.line))
			if err == nil {
				t.Fatal("accepted")
			}
			if got := errors.Is(err, ErrInvalidMessage); got != tt.invalid {
				t.Fatalf("err = %v, want ErrInvalidMessage = %v", err, tt.invalid)
			}
		})
	}
}

// Whatever spelling the client chose for its ID is what it must get back, because some clients
// compare the raw text. These spellings would all change under a normal re-encode.
func TestEncodeEchoesIDBytes(t *testing.T) {
	ids := []string{
		`7`, `-0`, `123456789012345678901234567890`,
		`"plain"`, "\"\\u0061\"", `"\/"`, "\"\\ud83d\\ude00\"", `"é"`, `""`, `"a\nb"`,
	}
	for _, id := range ids {
		t.Run(id, func(t *testing.T) {
			parsed, err := Parse([]byte(`{"jsonrpc":"2.0","id":` + id + `,"method":"ping"}`))
			if err != nil {
				t.Fatal(err)
			}
			line, err := Encode(Message{ID: parsed.ID, Result: jsontext.Value(`{}`)})
			if err != nil {
				t.Fatal(err)
			}
			want := `{"jsonrpc":"2.0","id":` + id + `,"result":{}}` + "\n"
			if string(line) != want {
				t.Fatalf("got  %s\nwant %s", line, want)
			}
		})
	}
}

func TestEncodeErrorWithNullID(t *testing.T) {
	line, err := Encode(Message{ID: NullID, Error: &Error{CodeParseError, "Parse error"}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}` + "\n"
	if string(line) != want {
		t.Fatalf("got  %s\nwant %s", line, want)
	}
}

// A raw value holding whitespace must still come out as one line.
func TestEncodeIsOneLine(t *testing.T) {
	line, err := Encode(Message{Method: "x", Params: jsontext.Value("{\n\t\"a\" :\r\n [1,\n 2.50]\n}")})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"jsonrpc":"2.0","method":"x","params":{"a":[1,2.50]}}` + "\n"
	if string(line) != want {
		t.Fatalf("got  %s\nwant %s", line, want)
	}
}

func TestEncodeRefusesInvalidRawValue(t *testing.T) {
	if _, err := Encode(Message{Method: "x", Params: jsontext.Value(`{"a":`)}); err == nil {
		t.Fatal("encoded broken JSON")
	}
}

func TestWriterWritesOneCallPerMessage(t *testing.T) {
	const writers, each = 8, 50
	var sink countingWriter
	w := NewWriter(&sink)
	var wg sync.WaitGroup
	for range writers {
		wg.Go(func() {
			for range each {
				if err := w.Write(Message{Method: "x", Params: jsontext.Value(`{"pad":"` + strings.Repeat("p", 4000) + `"}`)}); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	if sink.writes != writers*each {
		t.Fatalf("%d Write calls for %d messages", sink.writes, writers*each)
	}
	r := NewReader(&sink.buf)
	for range writers * each {
		line, err := r.ReadLine()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(line); err != nil {
			t.Fatalf("interleaved output: %v", err)
		}
	}
}

// countingWriter is not safe for concurrent use on purpose, so that a missing lock shows up under
// the race detector.
type countingWriter struct {
	buf    bytes.Buffer
	writes int
}

func (c *countingWriter) Write(p []byte) (int, error) {
	c.writes++
	return c.buf.Write(p)
}

func TestWriterReportsFailure(t *testing.T) {
	boom := errors.New("boom")
	if err := NewWriter(failingWriter{boom}).Write(Message{Method: "x"}); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}
}

type failingWriter struct{ err error }

func (f failingWriter) Write([]byte) (int, error) { return 0, f.err }

// FuzzFrames feeds arbitrary bytes through the frame reader and the parser. Neither may panic, no
// line may pass the cap or hold a newline, and anything accepted must encode back to one valid line.
func FuzzFrames(f *testing.F) {
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n"))
	f.Add([]byte(`{"jsonrpc":"2.0","id":"a","result":{"x":1}}` + "\r\n" + `{"jsonrpc":"2.0","method":"n"}`))
	f.Add([]byte(`[{"jsonrpc":"2.0"}]` + "\n\n\x00\xff\n"))
	f.Add([]byte(`{"jsonrpc":"2.0","id":null,"error":{"code":1,"message":"m"}}`))
	f.Add([]byte(strings.Repeat("{", 100) + "\n" + strings.Repeat("a", 70000) + "\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		r := NewReader(bytes.NewReader(data))
		for {
			line, err := r.ReadLine()
			if errors.Is(err, io.EOF) {
				return
			}
			if errors.Is(err, ErrLineTooLong) {
				continue
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(line) > MaxLine || bytes.IndexByte(line, '\n') >= 0 {
				t.Fatalf("bad line of %d bytes", len(line))
			}
			m, err := Parse(line)
			if err != nil {
				continue
			}
			out, err := Encode(*m)
			if err != nil {
				t.Fatalf("accepted a message it cannot encode: %v", err)
			}
			if bytes.IndexByte(out[:len(out)-1], '\n') >= 0 {
				t.Fatalf("encoded message has an inner newline: %q", out)
			}
			again, err := Parse(out[:len(out)-1])
			if err != nil {
				t.Fatalf("encoded message does not parse: %v", err)
			}
			if !bytes.Equal(again.ID, m.ID) {
				t.Fatalf("id changed from %q to %q", []byte(m.ID), []byte(again.ID))
			}
		}
	})
}
