package capture

import (
	"encoding/binary"
	"testing"
)

// wireSize is sizeof(struct event) as the kernel-side compiler lays it out:
// 8 timestamp + 4 pid + 4 tid + 8 conn + 8 len + 4 captured + 1 direction
// + 1 source + 16 comm + 256 data, padded to the struct's 8-byte alignment.
//
// This is the one number both sides must agree on. A field added or reordered
// on either side without the other produces records that decode without error
// and carry wrong values in every field after the change, which is far harder
// to diagnose than a failure here.
const wireSize = 312

func TestWireSizeMatchesKernelStruct(t *testing.T) {
	var r rawEvent
	if got := binary.Size(&r); got != wireSize {
		t.Fatalf("rawEvent is %d bytes, kernel struct event is %d; bpf/capture.h and this file have diverged",
			got, wireSize)
	}
}

func TestDecode(t *testing.T) {
	raw := make([]byte, wireSize)
	le := binary.LittleEndian
	le.PutUint64(raw[0:], 1_500_000_000) // timestamp
	le.PutUint32(raw[8:], 4242)          // pid
	le.PutUint32(raw[12:], 4243)         // tid
	le.PutUint64(raw[16:], 0xdeadbeef)   // connection identity
	le.PutUint64(raw[24:], 900)          // len reported by the call
	le.PutUint32(raw[32:], 16)           // bytes actually captured
	raw[36] = byte(Ingress)
	raw[37] = byte(GoTLS)
	copy(raw[38:], "gohold\x00")
	copy(raw[54:], "HTTP/1.1 200 OK\r\n")

	ev, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if ev.PID != 4242 || ev.TID != 4243 {
		t.Errorf("pid/tid = %d/%d, want 4242/4243", ev.PID, ev.TID)
	}
	if ev.Conn != 0xdeadbeef {
		t.Errorf("conn = %#x, want 0xdeadbeef", ev.Conn)
	}
	if ev.Comm != "gohold" {
		t.Errorf("comm = %q, want %q", ev.Comm, "gohold")
	}
	if ev.Direction != Ingress || ev.Source != GoTLS {
		t.Errorf("direction/source = %v/%v, want ingress/gotls", ev.Direction, ev.Source)
	}
	if len(ev.Data) != 16 {
		t.Fatalf("captured %d bytes, want 16", len(ev.Data))
	}
	if string(ev.Data) != "HTTP/1.1 200 OK\r" {
		t.Errorf("data = %q", ev.Data)
	}
}

func TestTruncatedReportsWhenCallCarriedMore(t *testing.T) {
	// The call reported 900 bytes; only 256 fit in the record. Keeping both
	// numbers is what makes the shortfall visible instead of silent.
	full := Event{Len: 900, Data: make([]byte, MaxData)}
	if !full.Truncated() {
		t.Error("a 900-byte payload captured at 256 should report truncated")
	}

	short := Event{Len: 74, Data: make([]byte, 74)}
	if short.Truncated() {
		t.Error("a fully captured payload should not report truncated")
	}
}

func TestDecodeRejectsShortRecord(t *testing.T) {
	if _, err := Decode(make([]byte, wireSize-1)); err == nil {
		t.Error("expected an error for a record shorter than the struct")
	}
}
