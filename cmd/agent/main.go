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

// printEvent renders one captured payload. This is the placeholder consumer
// until the HTTP parser takes over: it prints the payload's first line, which
// for HTTP/1.1 is the request line or the status line.
func printEvent(e capture.Event) {
	note := ""
	if e.Truncated() {
		note = " trunc/" + strconv.FormatUint(e.Len, 10)
	}
	fmt.Printf("%-7s %-7s pid=%-7d comm=%-15s len=%-5d%-12s %s\n",
		e.Source, e.Direction, e.PID, e.Comm, e.Len, note, firstLine(e.Data))
}

// firstLine returns the printable prefix of the payload up to the first line
// break, so that a binary protocol produces a short marker rather than pages of
// control characters.
func firstLine(b []byte) string {
	const limit = 96
	out := make([]rune, 0, limit)
	for _, c := range b {
		if c == '\r' || c == '\n' {
			break
		}
		if c < 0x20 || c > 0x7e {
			out = append(out, '.')
		} else {
			out = append(out, rune(c))
		}
		if len(out) == limit {
			break
		}
	}
	return string(out)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
