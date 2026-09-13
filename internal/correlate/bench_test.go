package correlate

import (
	"testing"
	"time"

	"github.com/sAchin-680/ebpf-observability-agent/internal/capture"
)

// The correlator runs on the goroutine that drains the ring buffer, so its cost
// per event is the cost of not draining. Phase 3 measured the rate at which
// drops begin (8,000 to 12,000 events/s); a change that makes this materially
// slower moves that threshold down without failing any test.
//
// Benchmarked rather than asserted: the number that matters is the trend across
// commits, which CI compares, not an absolute value on one machine.

func benchEvents() []capture.Event {
	req := []byte("GET /users/42 HTTP/1.1\r\nHost: api.internal\r\nAccept: */*\r\n\r\n")
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 21\r\n\r\n")

	// Request and response on the same connection, which is the pairing the
	// correlator exists to do. A benchmark of requests alone would measure the
	// map insert and never the match.
	return []capture.Event{
		{
			Timestamp: time.Millisecond,
			PID:       4242,
			TID:       4242,
			Conn:      0xdeadbeef,
			Comm:      "api",
			Direction: capture.Egress,
			Source:    capture.OpenSSL,
			Len:       uint64(len(req)),
			Data:      req,
		},
		{
			Timestamp: 3 * time.Millisecond,
			PID:       4242,
			TID:       4242,
			Conn:      0xdeadbeef,
			Comm:      "api",
			Direction: capture.Ingress,
			Source:    capture.OpenSSL,
			Len:       uint64(len(resp)),
			Data:      resp,
		},
	}
}

func BenchmarkHandlePair(b *testing.B) {
	events := benchEvents()

	var emitted int
	c := New(DefaultTTL, func(Record) { emitted++ })

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := range events {
			// A distinct connection per iteration: reusing one would leave the
			// pending map at size 1 and measure a lookup that never grows.
			ev := events[j]
			ev.Conn = uint64(i)
			c.Handle(ev)
		}
	}
	b.StopTimer()

	if emitted == 0 {
		b.Fatal("no records emitted — the benchmark is not exercising correlation")
	}
}

// Unmatched requests accumulate until they are swept, so the sweep runs against
// whatever the map has grown to. This is the path that a slow backend or a
// half-open connection leaves work on.
func BenchmarkExpire(b *testing.B) {
	events := benchEvents()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		c := New(time.Nanosecond, func(Record) {})
		for j := 0; j < 1000; j++ {
			ev := events[0]
			ev.Conn = uint64(j)
			c.Handle(ev)
		}
		time.Sleep(time.Millisecond)
		b.StartTimer()

		c.Expire()
	}
}
