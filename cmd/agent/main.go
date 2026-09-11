// Command agent traces HTTP and HTTPS traffic on the host without modifying
// the traced applications.
package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/sAchin-680/ebpf-observability-agent/internal/ebpf"
)

func main() {
	log.SetFlags(log.Ltime)

	tracer, err := ebpf.NewTracer()
	if err != nil {
		log.Fatalf("loading kernel programs: %v", err)
	}
	defer tracer.Close()

	libssl, err := ebpf.FindLibSSL()
	if err != nil {
		log.Fatalf("locating OpenSSL: %v", err)
	}

	if err := tracer.AttachOpenSSL(libssl); err != nil {
		log.Fatalf("attaching probes: %v", err)
	}

	log.Printf("attached to %s", libssl)
	log.Printf("capture output: sudo cat /sys/kernel/tracing/trace_pipe")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Printf("detaching")
}
