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

	"github.com/sAchin-680/ebpf-observability-agent/internal/correlate"
	"github.com/sAchin-680/ebpf-observability-agent/internal/ebpf"
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

// expireInterval controls how often unanswered requests are swept.
const expireInterval = 5 * time.Second

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

	// One correlator, driven from the reader, so no locking is needed.
	corr := correlate.New(correlate.DefaultTTL, printRecord)

	// Expiry runs on a timer because an unanswered request is only detectable
	// by the absence of a response, which produces no event to react to.
	go func() {
		ticker := time.NewTicker(expireInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				corr.Expire()
			}
		}
	}()

	log.Printf("reading events")
	if err := tracer.Run(ctx, corr.Handle); err != nil {
		log.Printf("reading events: %v", err)
	}

	st := corr.Stats()
	log.Printf("requests=%d completed=%d expired=%d unmatched-responses=%d non-http=%d pending=%d",
		st.Requests, st.Completed, st.Expired, st.ResponsesUnmatched, st.NotHTTP, corr.Pending())
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

// printRecord renders one correlated request record.
//
// This is the terminal consumer until the OpenTelemetry exporter replaces it.
func printRecord(r correlate.Record) {
	status := "-"
	if r.Outcome == correlate.Expired {
		status = "expired"
	} else if r.Status > 0 {
		status = strconv.Itoa(r.Status)
	}

	host := r.Host
	if host == "" {
		host = "-"
	}

	fmt.Printf("%-7s pid=%-7d comm=%-15s %-7s %-26s %-7s %8s  host=%s\n",
		r.Source, r.PID, r.Comm, r.Method, truncate(r.Path, 26), status,
		formatDuration(r.Duration), host)
}

// formatDuration renders the request duration. An expired record has no
// duration, and printing zero would read as an instantaneous request.
func formatDuration(d time.Duration) string {
	if d == 0 {
		return "-"
	}
	return d.Round(time.Microsecond).String()
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
