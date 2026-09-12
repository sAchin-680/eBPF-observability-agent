// Package capture defines the record the kernel-side programs emit and decodes
// it from ring buffer bytes.
package capture

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

// MaxData is the payload size carried per event. It must match MAX_DATA in
// bpf/capture.h; a mismatch produces records that decode without error and are
// wrong.
const MaxData = 256

// Direction identifies which side of the exchange a payload came from.
type Direction uint8

const (
	// Egress is data the traced process wrote, which for a server is the
	// response and for a client is the request.
	Egress Direction = 0
	// Ingress is data the traced process read.
	Ingress Direction = 1
)

func (d Direction) String() string {
	if d == Egress {
		return "egress"
	}
	return "ingress"
}

// Source identifies which TLS implementation produced the event, so that a gap
// in capture can be attributed to the right attach strategy.
type Source uint8

const (
	OpenSSL Source = 0
	GoTLS   Source = 1
)

func (s Source) String() string {
	if s == GoTLS {
		return "gotls"
	}
	return "openssl"
}

// rawEvent mirrors struct event in bpf/capture.h exactly, including the
// padding the C compiler inserts. Decoding with encoding/binary against this
// layout keeps the two definitions in step: a field added on one side without
// the other changes the size and the decode fails immediately, rather than
// silently shifting every field after it.
type rawEvent struct {
	TimestampNS uint64
	PID         uint32
	TID         uint32
	Conn        uint64
	Len         uint64
	Captured    uint32
	Direction   uint8
	Source      uint8
	Comm        [16]byte
	Data        [MaxData]byte
	_           [2]byte // trailing padding to the struct's 8-byte alignment
}

// Event is one captured payload.
type Event struct {
	// Monotonic kernel timestamp. Useful for measuring intervals between
	// events; it is not wall-clock time.
	Timestamp time.Duration

	PID uint32
	TID uint32

	// Conn identifies the TLS connection this payload belongs to: OpenSSL's
	// SSL* or Go's *tls.Conn. It is an address inside the traced process,
	// used only as an opaque identity and never dereferenced.
	//
	// It pairs a request with its response. Addresses are reused once a
	// connection closes, so it is only unique within one process and only for
	// as long as that connection lives.
	Conn uint64

	Comm      string
	Direction Direction
	Source    Source

	// Len is the length the traced call reported. Data may be shorter.
	Len uint64

	// Data is the captured prefix of the payload.
	Data []byte
}

// Truncated reports whether the call carried more than was captured.
func (e Event) Truncated() bool {
	return e.Len > uint64(len(e.Data))
}

// Decode parses one ring buffer record.
func Decode(raw []byte) (Event, error) {
	var r rawEvent
	if len(raw) < binary.Size(&r) {
		return Event{}, fmt.Errorf("short record: %d bytes, want %d", len(raw), binary.Size(&r))
	}
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &r); err != nil {
		return Event{}, fmt.Errorf("decoding record: %w", err)
	}

	n := r.Captured
	if n > MaxData {
		n = MaxData
	}

	return Event{
		Timestamp: time.Duration(r.TimestampNS),
		PID:       r.PID,
		TID:       r.TID,
		Conn:      r.Conn,
		Comm:      string(bytes.TrimRight(r.Comm[:], "\x00")),
		Direction: Direction(r.Direction),
		Source:    Source(r.Source),
		Len:       r.Len,
		Data:      append([]byte(nil), r.Data[:n]...),
	}, nil
}
