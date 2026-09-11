package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	bpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// execSettleDelay is how long to wait after an exec before inspecting the
// process.
//
// At the moment exec completes, the new image is mapped but its shared
// libraries are not: the dynamic linker runs afterwards, as the process's own
// first instructions. Inspecting immediately therefore finds no libssl even for
// a process that is about to load it.
//
// Waiting is a compromise rather than a solution. It cannot be eliminated by
// waiting longer, because a library can be loaded at any point in a process's
// life, not only at startup.
const execSettleDelay = 60 * time.Millisecond

// execRetries bounds how many times a process is re-examined after the initial
// delay.
//
// A runtime that loads TLS lazily — only when the first HTTPS connection is
// made — will not have libssl mapped at any fixed point after exec. Retrying a
// few times covers slow starts without polling indefinitely.
const execRetries = 4

// execRetryInterval spaces the retries.
const execRetryInterval = 250 * time.Millisecond

// execEvent mirrors struct exec_event in bpf/discover.bpf.c.
type execEvent struct {
	PID  uint32
	Comm [16]byte
}

// discoverer notifies on process execution.
type discoverer struct {
	objs discoverObjects
	link link.Link
}

func newDiscoverer() (*discoverer, error) {
	var objs discoverObjects
	if err := loadDiscoverObjects(&objs, nil); err != nil {
		var ve *bpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("verifier rejected discovery program:\n%+v", ve)
		}
		return nil, fmt.Errorf("loading discovery program: %w", err)
	}

	tp, err := link.Tracepoint("sched", "sched_process_exec", objs.HandleExec, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attaching sched_process_exec: %w", err)
	}

	return &discoverer{objs: objs, link: tp}, nil
}

func (d *discoverer) Close() error {
	if d.link != nil {
		d.link.Close()
	}
	return d.objs.Close()
}

// WatchExecs attaches probes to processes as they start, until ctx is cancelled.
//
// It complements the scan performed at startup, which covers processes already
// running. Together they cover every process: those that existed when the agent
// started, and those that appear afterwards.
func (t *Tracer) WatchExecs(ctx context.Context) error {
	if t.discover == nil {
		d, err := newDiscoverer()
		if err != nil {
			return err
		}
		t.discover = d
	}

	rd, err := ringbuf.NewReader(t.discover.objs.ExecEvents)
	if err != nil {
		return fmt.Errorf("opening exec ring buffer: %w", err)
	}

	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	// Inspection is queued rather than done inline. A blocked inspection would
	// stop the reader draining, and a full exec ring buffer loses processes
	// entirely rather than merely delaying them.
	pending := make(chan execEvent, 256)
	go t.inspectLoop(ctx, pending)

	go func() {
		for {
			rec, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, os.ErrClosed) {
					return
				}
				log.Printf("exec ring buffer: %v", err)
				return
			}

			var e execEvent
			if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
				continue
			}

			select {
			case pending <- e:
			default:
				// The queue is full, which means inspection is not keeping up
				// with process churn. Reporting it is the only way this becomes
				// visible; the alternative is untraced processes and no signal.
				log.Printf("exec queue full, skipping pid %d (%s)",
					e.PID, bytes.TrimRight(e.Comm[:], "\x00"))
			}
		}
	}()

	return nil
}

func (t *Tracer) inspectLoop(ctx context.Context, pending <-chan execEvent) {
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-pending:
			go t.inspectAfterExec(ctx, e)
		}
	}
}

// inspectAfterExec attaches to whatever TLS implementation a newly executed
// process turns out to use.
//
// Both paths are attempted because the two are not alternatives: a Go binary
// can link OpenSSL for other purposes, and a process can load libssl long after
// its own image was mapped.
func (t *Tracer) inspectAfterExec(ctx context.Context, e execEvent) {
	comm := string(bytes.TrimRight(e.Comm[:], "\x00"))

	timer := time.NewTimer(execSettleDelay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}

	for attempt := 0; attempt < execRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(execRetryInterval):
			}
		}

		// A process that has already exited is not an error; short-lived
		// processes are the common case on any busy host.
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", e.PID)); err != nil {
			return
		}

		t.mu.Lock()
		n, err := t.attachPID(int(e.PID), comm)
		t.mu.Unlock()
		if err != nil {
			log.Printf("inspecting pid %d (%s): %v", e.PID, comm, err)
			return
		}
		if n > 0 {
			return // attached; nothing further to wait for
		}
	}
}
