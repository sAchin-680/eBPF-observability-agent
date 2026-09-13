// Package otel converts request records into OpenTelemetry telemetry and
// exports it.
//
// The agent emits telemetry on behalf of other processes, which is not the
// shape the OpenTelemetry SDK assumes. A tracer provider carries one resource
// describing one service, because a normal application instruments itself. Here
// a single agent produces spans for every service on the node, each of which
// must appear under its own service name.
//
// A tracer provider is therefore created per traced service, all sharing one
// exporter and one connection. The alternative — a single provider with the
// service name as a span attribute — puts it in the wrong place in the data
// model, where backends that group by resource will not find it.
package otel

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// instrumentationName identifies the producer of these spans. It describes the
// agent, not the traced service, and is how a consumer can tell that a span was
// produced without the service's participation.
const instrumentationName = "github.com/sAchin-680/ebpf-observability-agent"

// Config configures the exporters.
type Config struct {
	// Endpoint is the OTLP gRPC address of the trace backend.
	Endpoint string

	// Insecure disables TLS to the backend. Appropriate for a collector on the
	// same host; a network hop should be encrypted.
	Insecure bool

	// MetricsAddr is the address the Prometheus endpoint listens on.
	MetricsAddr string

	// AgentVersion is reported on every resource, so telemetry can be
	// attributed to the agent build that produced it.
	AgentVersion string

	// NodeName is the host the agent runs on, reported on every resource. It is
	// what makes a span attributable to the node that captured it, which a
	// per-node agent needs and the traced service cannot supply. Empty outside a
	// cluster, and then omitted rather than reported as "".
	NodeName string
}

// Exporter turns request records into spans and metrics.
type Exporter struct {
	cfg      Config
	traceExp *otlptrace.Exporter
	metrics  *metrics

	// providers is one tracer provider per service name. Providers are created
	// on demand, because the set of services is discovered rather than
	// configured and is not known at startup.
	mu        sync.Mutex
	providers map[string]*sdktrace.TracerProvider
}

// New starts the metrics endpoint and, if an endpoint is configured, connects
// to the trace backend.
//
// The two are independent. Traces can be disabled while metrics continue, which
// is what benchmarking requires — exporting traces means opening TLS
// connections the agent would then trace, and its own export cost would be
// counted as capture cost. It is also what a node needs when a trace backend is
// unreachable: the agent's own health is still worth reporting, and an agent
// that reported nothing because it could not reach one place would be
// indistinguishable from an agent that had stopped.
//
// Trace connection is lazy. The OTLP exporter does not require the backend to
// be reachable at startup and retries in the background, so a backend that is
// down delays telemetry rather than preventing tracing.
func New(ctx context.Context, cfg Config) (*Exporter, error) {
	m, err := newMetrics(cfg.MetricsAddr)
	if err != nil {
		return nil, err
	}

	e := &Exporter{
		cfg:       cfg,
		metrics:   m,
		providers: make(map[string]*sdktrace.TracerProvider),
	}

	if cfg.Endpoint == "" {
		return e, nil
	}

	opts := []otlptracegrpc.Option{otlptracegrpc.WithEndpoint(cfg.Endpoint)}
	if cfg.Insecure {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}

	traceExp, err := otlptracegrpc.New(ctx, opts...)
	if err != nil {
		m.shutdown(ctx)
		return nil, fmt.Errorf("creating OTLP trace exporter: %w", err)
	}
	e.traceExp = traceExp
	return e, nil
}

// TracesEnabled reports whether spans are exported.
func (e *Exporter) TracesEnabled() bool { return e.traceExp != nil }

// tracerFor returns the tracer for a service, creating its provider on first
// use.
func (e *Exporter) tracerFor(service string) trace.Tracer {
	e.mu.Lock()
	defer e.mu.Unlock()

	tp, ok := e.providers[service]
	if !ok {
		attrs := []attribute.KeyValue{
			semconv.ServiceName(service),
			// Telemetry describes the producer, which here is the agent rather
			// than the service. Without this a consumer cannot distinguish a
			// service that instruments itself from one observed externally.
			semconv.TelemetrySDKName("ebpf-observability-agent"),
			semconv.TelemetrySDKLanguageGo,
			attribute.String("telemetry.agent.version", e.cfg.AgentVersion),
		}
		if e.cfg.NodeName != "" {
			attrs = append(attrs, semconv.K8SNodeName(e.cfg.NodeName))
		}
		res := resource.NewWithAttributes(semconv.SchemaURL, attrs...)

		tp = sdktrace.NewTracerProvider(
			sdktrace.WithResource(res),
			// Batched so that export never happens on the path that drains the
			// ring buffer. A slow backend must not become ring buffer pressure.
			sdktrace.WithBatcher(e.traceExp,
				sdktrace.WithBatchTimeout(5*time.Second),
				sdktrace.WithMaxExportBatchSize(512),
			),
		)
		e.providers[service] = tp
	}

	return tp.Tracer(instrumentationName)
}

// Shutdown flushes pending telemetry and closes the exporters.
func (e *Exporter) Shutdown(ctx context.Context) error {
	e.mu.Lock()
	providers := make([]*sdktrace.TracerProvider, 0, len(e.providers))
	for _, tp := range e.providers {
		providers = append(providers, tp)
	}
	e.mu.Unlock()

	var firstErr error
	for _, tp := range providers {
		if err := tp.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if e.traceExp != nil {
		if err := e.traceExp.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if err := e.metrics.shutdown(ctx); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// Services reports how many distinct services telemetry has been produced for.
func (e *Exporter) Services() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.providers)
}
