// Command agent traces HTTP and HTTPS traffic on the host without modifying
// the traced applications.
package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sAchin-680/ebpf-observability-agent/internal/ebpf"
)

// rescanInterval controls how often the agent looks for TLS libraries it has
// not yet attached to.
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

	n, err := tracer.AttachAll()
	if err != nil {
		log.Fatalf("attaching probes: %v", err)
	}
	g, err := tracer.AttachGoBinaries()
	if err != nil {
		log.Printf("go discovery: %v", err)
	}
	log.Printf("tracing %d TLS %s and %d Go %s",
		n, plural(n, "library", "libraries"), g, plural(g, "binary", "binaries"))
	log.Printf("capture output: sudo cat /sys/kernel/tracing/trace_pipe")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(rescanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if _, err := tracer.AttachAll(); err != nil {
				log.Printf("rescan: %v", err)
			}
			if _, err := tracer.AttachGoBinaries(); err != nil {
				log.Printf("rescan (go): %v", err)
			}
		case <-stop:
			log.Printf("detaching")
			return
		}
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
