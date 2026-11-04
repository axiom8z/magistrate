// Package rpc reads and writes newline-delimited JSON-RPC 2.0, the framing MCP uses over stdio.
//
// Every byte that crosses a process boundary passes through here, so the strict rules live in one
// place: a 1 MiB cap per line, no duplicate keys, no batches, and IDs that are a string or an integer.
package rpc

import (
	"bufio"
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"sync"
)

// MaxLine caps one message, so a hostile peer cannot grow our memory without end.
const MaxLine = 1 << 20

// Error codes from the JSON-RPC 2.0 specification.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
)

var (
	// ErrLineTooLong means a line passed MaxLine. Its bytes have been skipped, so the next read
	// starts on the next line.
	ErrLineTooLong = errors.New("line over the 1 MiB cap")
	// ErrInvalidMessage means a line was JSON but not a JSON-RPC 2.0 message we accept.
	ErrInvalidMessage = errors.New("not a valid JSON-RPC 2.0 message")
)

// NullID is the id of an error reply when the request's own id could not be read.
var NullID = jsontext.Value("null")

// Message is one JSON-RPC message of any kind. A nil Value means the member was absent, which is
// different from a member holding null. ID stays as raw bytes, so a reply can echo what the peer
// sent exactly, however it spelled it.
type Message struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      jsontext.Value `json:"id,omitzero"`
	Method  string         `json:"method,omitzero"`
	Params  jsontext.Value `json:"params,omitzero"`
	Result  jsontext.Value `json:"result,omitzero"`
	Error   *Error         `json:"error,omitzero"`
}

// Error is the error member of a response. Message comes from the peer, so Error() leaves it out:
// peer text must not slip into a log line or a reply just because someone printed the error.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return fmt.Sprintf("JSON-RPC error %d", e.Code) }

// IsRequest reports whether the peer expects a reply to this message.
func (m *Message) IsRequest() bool { return m.Method != "" && len(m.ID) > 0 }

// IsNotification reports whether this is a method call that takes no reply.
func (m *Message) IsNotification() bool { return m.Method != "" && len(m.ID) == 0 }

// IsResponse reports whether this message answers an earlier request.
func (m *Message) IsResponse() bool { return m.Method == "" }

// Parse decodes one line strictly. The decoder itself rejects duplicate keys and trailing data; the
// checks after it are the JSON-RPC rules. A failure is ErrInvalidMessage when the line was JSON of the
// wrong shape, such as a batch, and some other error when it was not JSON.
//
// Broken characters are the one thing it repairs. A server cutting text at a fixed length can split an
// emoji, and clients show U+FFFD for the piece, so refusing the line would make the gateway kill a
// server over what works fine without it. The whole line is rewritten first, so nothing later can read
// the original.
func Parse(line []byte) (*Message, error) {
	var m Message
	err := json.Unmarshal(line, &m)
	if err != nil {
		clean := jsontext.Value(bytes.Clone(line))
		if clean.Format(jsontext.AllowInvalidUTF8(true)) == nil {
			m = Message{}
			err = json.Unmarshal(clean, &m)
		}
	}
	if err != nil {
		var wrongShape *json.SemanticError
		if errors.As(err, &wrongShape) {
			return nil, ErrInvalidMessage
		}
		return nil, err
	}
	if !m.valid() {
		return nil, ErrInvalidMessage
	}
	return &m, nil
}

func (m *Message) valid() bool {
	if m.JSONRPC != "2.0" {
		return false
	}
	if m.Method != "" {
		noAnswer := len(m.Result) == 0 && m.Error == nil
		return noAnswer && (len(m.ID) == 0 || validID(m.ID))
	}
	if len(m.ID) == 0 || (len(m.Result) > 0) == (m.Error != nil) {
		return false // a response has an id and exactly one of result and error
	}
	// JSON-RPC lets an error reply carry a null id, when the peer could not read the request's id.
	return validID(m.ID) || (m.ID.Kind() == jsontext.KindNull && m.Error != nil)
}

// validID accepts a string or an integer. Floats would not survive a round trip through most
// parsers, and null or a boolean cannot identify anything.
func validID(id jsontext.Value) bool {
	switch id.Kind() {
	case jsontext.KindString:
		return true
	case jsontext.KindNumber:
		return !bytes.ContainsAny(id, ".eE")
	}
	return false
}

// Encode renders a message as exactly one line. Encoding reformats every raw value, which removes
// any whitespace a peer left in it, so no newline can survive inside a message. PreserveRawStrings
// keeps string escapes as they came, which is what lets a reply echo an ID byte for byte.
func Encode(m Message) ([]byte, error) {
	m.JSONRPC = "2.0"
	line, err := json.Marshal(m, jsontext.PreserveRawStrings(true))
	if err != nil {
		return nil, err
	}
	return append(line, '\n'), nil
}

// Reader splits a stream into lines. It uses bufio.Reader rather than bufio.Scanner because a
// Scanner stops for good at its first oversize line, and we must be able to refuse one and go on.
type Reader struct{ br *bufio.Reader }

// NewReader returns a Reader for r.
func NewReader(r io.Reader) *Reader { return &Reader{bufio.NewReaderSize(r, 64<<10)} }

// ReadLine returns the next line without its line ending. A last line with no newline still counts,
// and io.EOF comes after it. CRLF is accepted because text-mode stdout on Windows writes it.
func (r *Reader) ReadLine() ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.br.ReadSlice('\n')
		// Past the cap, stop keeping bytes but keep reading, so the next call starts on a new line.
		if len(line) <= MaxLine+1 {
			line = append(line, chunk...)
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil && (!errors.Is(err, io.EOF) || len(line) == 0) {
			return nil, err
		}
		line = bytes.TrimSuffix(bytes.TrimSuffix(line, []byte("\n")), []byte("\r"))
		if len(line) > MaxLine {
			return nil, ErrLineTooLong
		}
		return line, nil
	}
}

// Writer emits one line per message. The lock and the single Write call keep concurrent replies
// from interleaving.
type Writer struct {
	mu sync.Mutex
	w  io.Writer
}

// NewWriter returns a Writer for w.
func NewWriter(w io.Writer) *Writer { return &Writer{w: w} }

// Write encodes m and sends it as one line.
func (w *Writer) Write(m Message) error {
	line, err := Encode(m)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	_, err = w.w.Write(line)
	return err
}
