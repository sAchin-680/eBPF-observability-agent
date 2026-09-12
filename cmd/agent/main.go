// Command agent traces HTTP and HTTPS traffic on the host without modifying
// the traced applications.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/sAchin-680/ebpf-observability-agent/internal/correlate"
	"github.com/sAchin-680/ebpf-observability-agent/internal/ebpf"
	"github.com/sAchin-680/ebpf-observability-agent/internal/otel"
	"github.com/sAchin-680/ebpf-observability-agent/internal/proc"
)

// version identifies the agent build on the telemetry it produces.
const version = "0.2.0-phase2"

// expireInterval controls how often unanswered requests are swept.
const expireInterval = 5 * time.Second

func main() {
	log.SetFlags(log.Ltime)

	otlpEndpoint := flag.String("otlp-endpoint", "localhost:4317",
		"OTLP gRPC endpoint for traces; empty disables trace export")
	metricsAddr := flag.String("metrics-addr", ":9464",
		"address to serve Prometheus metrics on")
	printRecords := flag.Bool("print", false, "also print each record to stdout")
	flag.Parse()

	tracer, err := ebpf.NewTracer()
	if err != nil {
		log.Fatalf("loading kernel programs: %v", err)
	}
	defer tracer.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Two mechanisms, covering disjoint sets of processes. The scan finds what
	// is already running; the exec tracepoint reports what starts afterwards.
	// Neither alone is sufficient, and together they leave no window.
	if err := tracer.WatchExecs(ctx); err != nil {
		log.Fatalf("watching process execs: %v", err)
	}
	attach(tracer, true)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		cancel()
	}()

	// Started unconditionally: the endpoint controls trace export only, and the
	// agent's own metrics are worth serving regardless of whether a trace
	// backend exists.
	var exporter *otel.Exporter
	{
		exporter, err = otel.New(ctx, otel.Config{
			Endpoint:     *otlpEndpoint,
			Insecure:     true,
			MetricsAddr:  *metricsAddr,
			AgentVersion: version,
		})
		if err != nil {
			log.Fatalf("starting exporters: %v", err)
		}
		defer func() {
			// Bounded, and separate from the main context, which is already
			// cancelled by the time this runs.
			flushCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := exporter.Shutdown(flushCtx); err != nil {
				log.Printf("flushing telemetry: %v", err)
			}
		}()
		if exporter.TracesEnabled() {
			log.Printf("exporting traces to %s, metrics on %s", *otlpEndpoint, *metricsAddr)
		} else {
			log.Printf("trace export disabled, metrics on %s", *metricsAddr)
		}
	}

	names := newServiceNames()

	// One correlator, driven from the reader, so no locking is needed.
	corr := correlate.New(correlate.DefaultTTL, func(r correlate.Record) {
		if *printRecords || !exporter.TracesEnabled() {
			printRecord(r)
		}
		if exporter != nil {
			exporter.Record(ctx, r, names.of(int(r.PID), r.Comm))
		}
	})
	corr.SetEndpointResolver(func(pid uint32, conn uint64) (string, string, bool) {
		t, ok := tracer.LookupTuple(pid, conn)
		if !ok {
			return "", "", false
		}
		return t.Source.String(), t.Destination.String(), true
	})

	if exporter != nil {
		// Registered after the correlator exists, since its state is part of
		// what is reported.
		if err := exporter.RegisterSelfMetrics(func() otel.SelfState {
			return otel.SelfState{
				DroppedEvents:   tracer.Drops(),
				PendingRequests: corr.Pending(),
				AttachedTargets: tracer.Attached(),
			}
		}); err != nil {
			log.Printf("registering self metrics: %v", err)
		}
	}

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

	if exporter != nil {
		log.Printf("produced telemetry for %d services", exporter.Services())
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

// attach scans for targets among processes that are already running.
//
// Processes starting after this point are covered by the exec tracepoint
// instead, so this runs once rather than repeatedly.
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
		log.Printf("tracing %d TLS %s and %d Go %s at startup; watching for new processes",
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

	peer := r.Peer
	if peer == "" {
		peer = "-"
	}

	fmt.Printf("%-7s pid=%-7d comm=%-15s %-7s %-24s %-7s %9s  peer=%-21s host=%s\n",
		r.Source, r.PID, r.Comm, r.Method, truncate(r.Path, 24), status,
		formatDuration(r.Duration), peer, host)
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

// serviceNames caches inferred names per process.
//
// Inference reads several files under /proc, which is far more work than the
// rest of handling a record. The name cannot change for the lifetime of a
// process, so it is resolved once.
//
// The cache is keyed by pid and is therefore wrong if a pid is reused by an
// unrelated process. Over an agent's lifetime that is possible; the entry is
// replaced when the name is resolved for a process the cache has not seen,
// which a reused pid is not. Correcting it properly needs the process start
// time as part of the key, which is deferred until it matters.
type serviceNames struct {
	mu    sync.Mutex
	cache map[int]string
}

func newServiceNames() *serviceNames {
	return &serviceNames{cache: make(map[int]string)}
}

func (s *serviceNames) of(pid int, fallback string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	if name, ok := s.cache[pid]; ok {
		return name
	}

	name := proc.ServiceName(pid)
	if name == "" || name == "unknown" {
		// The process has already exited, which is normal for a short-lived
		// client. Its command name is the best remaining signal.
		if fallback != "" {
			name = fallback
		} else {
			name = "unknown"
		}
	}
	s.cache[pid] = name
	return name
}
