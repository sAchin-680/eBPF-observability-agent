// Command agent traces HTTP and HTTPS traffic on the host without modifying
// the traced applications.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/sAchin-680/ebpf-observability-agent/internal/capture"
	"github.com/sAchin-680/ebpf-observability-agent/internal/ebpf"
	"github.com/sAchin-680/ebpf-observability-agent/internal/httpparse"
)

// rescanInterval controls how often the agent looks for TLS libraries and Go
// executables it has not yet attached to.
//
// Polling is an interim mechanism. A process that starts and exits between two
// scans is never seen, so a short-lived client can complete its request
// unobserved however short the interval. Closing that gap needs notification
// rather than sampling: a tracepoint on process execution, which replaces this
// loop.
const rescanInterval = 500 * time.Millisecond

func main() {
	log.SetFlags(log.Ltime)

	tracer, err := ebpf.NewTracer()
	if err != nil {
		log.Fatalf("loading kernel programs: %v", err)
	}
	defer tracer.Close()

	attach(tracer, true)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		cancel()
	}()

	go func() {
		ticker := time.NewTicker(rescanInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				attach(tracer, false)
			}
		}
	}()

	log.Printf("reading events")
	if err := tracer.Run(ctx, printEvent); err != nil {
		log.Printf("reading events: %v", err)
	}

	for name, n := range tracer.Drops() {
		if n > 0 {
			log.Printf("%s: %d events dropped over the run", name, n)
		}
	}
	log.Printf("detaching")
}

// attach discovers and attaches new targets. announce distinguishes the startup
// scan, which reports what it found, from the periodic rescan, which stays
// silent unless something new appears.
func attach(t *ebpf.Tracer, announce bool) {
	n, err := t.AttachAll()
	if err != nil && announce {
		log.Fatalf("attaching probes: %v", err)
	}
	g, err := t.AttachGoBinaries()
	if err != nil && announce {
		log.Printf("go discovery: %v", err)
	}
	if announce {
		log.Printf("tracing %d TLS %s and %d Go %s",
			n, plural(n, "library", "libraries"), g, plural(g, "binary", "binaries"))
	}
}

// printEvent renders one captured payload.
//
// Payloads that are not HTTP are discarded here rather than reported. Roughly
// half of all captured events are five-byte TLS record headers, and response
// bodies arrive through the same path as start lines; passing those on as
// telemetry would report traffic that does not exist.
//
// This is the placeholder consumer until correlation pairs requests with their
// responses into single records.
func printEvent(e capture.Event) {
	m, ok := httpparse.Parse(e.Data)
	if !ok {
		return
	}

	note := ""
	if e.Truncated() {
		note = " trunc/" + strconv.FormatUint(e.Len, 10)
	}

	switch m.Kind {
	case httpparse.Request:
		host := m.Host
		if host == "" {
			host = "-"
		}
		fmt.Printf("%-7s req  pid=%-7d comm=%-15s %-7s %-24s host=%s%s\n",
			e.Source, e.PID, e.Comm, m.Method, truncate(m.Path, 24), host, note)
	case httpparse.Response:
		fmt.Printf("%-7s resp pid=%-7d comm=%-15s %d %s%s\n",
			e.Source, e.PID, e.Comm, m.Status, m.Reason, note)
	}
}

// truncate shortens a field to keep the output aligned.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "\u2026"
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
