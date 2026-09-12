package ebpf

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sync/atomic"
	"time"

	bpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/sAchin-680/ebpf-observability-agent/internal/capture"
)

// dropReportInterval controls how often the ring buffer drop counter is read
// and reported.
const dropReportInterval = 5 * time.Second

// ringSource pairs a ring buffer with the drop counter belonging to the same
// compiled program. Each program has its own instance of both.
type ringSource struct {
	name    string
	events  *bpf.Map
	dropped *bpf.Map
}

// sources returns every ring buffer the loaded programs publish to.
//
// The programs are compiled separately and so do not share maps; each is
// drained independently. A host running only Python has no Go programs loaded
// and therefore one source rather than two.
func (t *Tracer) sources() []ringSource {
	out := []ringSource{{"openssl", t.objs.Events, t.objs.Dropped}}
	if t.gotls != nil {
		out = append(out, ringSource{"gotls", t.gotls.objs.Events, t.gotls.objs.Dropped})
	}
	return out
}

// Run drains every ring buffer, passing each decoded event to handle, until ctx
// is cancelled.
//
// Draining promptly is the agent's main obligation to the kernel side. The ring
// buffer is fixed size; when it fills, reservations fail and events are dropped
// with no effect on and no signal to the traced application. Work done in
// handle is therefore work not spent draining.
func (t *Tracer) Run(ctx context.Context, handle func(capture.Event)) error {
	srcs := t.sources()
	if len(srcs) == 0 {
		return errors.New("no ring buffers to read")
	}

	errc := make(chan error, len(srcs))
	for _, src := range srcs {
		go func(src ringSource) {
			errc <- t.drain(ctx, src, handle)
		}(src)
	}

	go t.reportDrops(ctx, srcs)

	// The first reader to fail stops the agent: a ring buffer that cannot be
	// read is a silent loss of every event it holds.
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		return nil
	}
}

func (t *Tracer) drain(ctx context.Context, src ringSource, handle func(capture.Event)) error {
	rd, err := ringbuf.NewReader(src.events)
	if err != nil {
		return fmt.Errorf("opening %s ring buffer: %w", src.name, err)
	}
	defer rd.Close()

	// Read blocks, so cancellation works by closing the reader out from under
	// it, which makes the blocked Read return ErrClosed.
	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, os.ErrClosed) {
				return nil
			}
			return fmt.Errorf("reading %s ring buffer: %w", src.name, err)
		}

		atomic.AddUint64(&t.received, 1)

		ev, err := capture.Decode(rec.RawSample)
		if err != nil {
			// A record the agent cannot decode means the kernel-side layout
			// and this build have diverged. Reporting it is more useful than
			// discarding it quietly.
			log.Printf("%s: %v", src.name, err)
			continue
		}
		handle(ev)
	}
}

// reportDrops polls the kernel drop counters and reports increases.
//
// The counter is the only evidence that events were lost: a failed reservation
// leaves no other trace, and the traced application is unaffected either way.
// Without this the agent would under-report traffic while appearing healthy.
func (t *Tracer) reportDrops(ctx context.Context, srcs []ringSource) {
	ticker := time.NewTicker(dropReportInterval)
	defer ticker.Stop()

	last := make(map[string]uint64, len(srcs))

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, src := range srcs {
				n, err := readDrops(src.dropped)
				if err != nil {
					continue
				}
				if n > last[src.name] {
					log.Printf("WARNING: %s dropped %d events (%d total): ring buffer full",
						src.name, n-last[src.name], n)
				}
				last[src.name] = n
			}
		}
	}
}

// Received reports how many events have been read from the ring buffers.
//
// The pairing with the drop counter is what makes either meaningful. A drop
// count alone cannot be compared between workloads, because the number of
// events a request produces depends on how the traffic is shaped: a large
// response arrives in several reads, and TLS record headers are read
// separately from the records they describe. Expressing the agent's limit in
// events per second rather than requests per second makes it a property of the
// agent instead of a property of the test.
func (t *Tracer) Received() uint64 {
	return atomic.LoadUint64(&t.received)
}

// Attached reports how many distinct libraries and executables are probed.
//
// Reported as the agent's own health rather than as telemetry about a service:
// a count that stops growing while new processes start means discovery has
// stalled, which is indistinguishable from quiet traffic unless it is measured.
func (t *Tracer) Attached() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.attached)
}

// Drops returns the total number of events lost per source since start.
func (t *Tracer) Drops() map[string]uint64 {
	out := make(map[string]uint64)
	for _, src := range t.sources() {
		if n, err := readDrops(src.dropped); err == nil {
			out[src.name] = n
		}
	}
	return out
}

func readDrops(m *bpf.Map) (uint64, error) {
	var n uint64
	var key uint32
	if err := m.Lookup(&key, &n); err != nil {
		return 0, err
	}
	return n, nil
}
