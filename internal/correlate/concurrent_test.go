package correlate

import (
	"sync"
	"testing"
	"time"

	"github.com/sAchin-680/ebpf-observability-agent/internal/capture"
)

// TestConcurrentAccess reproduces a crash that reached a running agent.
//
//	fatal error: concurrent map iteration and map write
//	correlate.(*Correlator).Expire  correlate.go:221
//	created by main.main            cmd/agent/main.go:132
//
// The correlator was documented as single-goroutine and was, until expiry moved
// onto a ticker. Three goroutines then reached it: the ring buffer reader
// calling Handle, the timer calling Expire, and the metrics callback calling
// Pending and Stats. Nothing in the test suite ran two of them at once, so
// -race had nothing to find and every unit test passed.
//
// It surfaced during a canary rollout, on the node the canary was on, which is
// the argument for gating promotion on the node's health rather than on whether
// the pod started.
//
// Run with -race. Without it this test can pass while the bug is present.
func TestConcurrentAccess(t *testing.T) {
	c := New(50*time.Millisecond, func(Record) {})

	req := []byte("GET /concurrent HTTP/1.1\r\nHost: test\r\n\r\n")
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// The reader goroutine. Distinct connections so entries accumulate and
	// expiry has something to iterate over, which is where the fatal error was.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20000; i++ {
			ts := time.Duration(i) * time.Millisecond
			c.Handle(capture.Event{
				Timestamp: ts,
				PID:       uint32(i%8 + 1),
				Conn:      uint64(i),
				Comm:      "svc",
				Direction: capture.Egress,
				Source:    capture.OpenSSL,
				Len:       uint64(len(req)),
				Data:      req,
			})
			// Only some requests get a response, so the rest are left for
			// Expire to sweep while Handle keeps writing.
			if i%3 == 0 {
				c.Handle(capture.Event{
					Timestamp: ts + time.Millisecond,
					PID:       uint32(i%8 + 1),
					Conn:      uint64(i),
					Comm:      "svc",
					Direction: capture.Ingress,
					Source:    capture.OpenSSL,
					Len:       uint64(len(resp)),
					Data:      resp,
				})
			}
		}
		close(stop)
	}()

	// The expiry ticker.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				c.Expire()
			}
		}
	}()

	// The metrics callback. Pending calls len() on the same map, which races
	// with a write exactly as iteration does.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = c.Pending()
				_ = c.Stats()
			}
		}
	}()

	wg.Wait()

	// Not an assertion about the counts, which depend on how the goroutines
	// interleaved. It checks the correlator still did its job rather than
	// having been made safe by doing nothing.
	st := c.Stats()
	if st.Requests == 0 {
		t.Fatal("no requests recorded; the test is not exercising the correlator")
	}
	if st.Completed == 0 {
		t.Fatal("no requests completed; responses are not being matched")
	}
}
