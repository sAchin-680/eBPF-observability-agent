package otel

import (
	"context"
	"crypto/rand"
	"net"
	"strconv"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/sAchin-680/ebpf-observability-agent/internal/correlate"
)

// Record converts one request record into a span and updates the metrics.
//
// The span is created with explicit start and end times taken from the kernel
// timestamps, rather than from when the agent happened to process the record.
// Anything else would measure the agent's own scheduling.
func (e *Exporter) Record(ctx context.Context, r correlate.Record, service string) {
	// Metrics are recorded whether or not traces are exported, so that the
	// agent's own measurements remain available when there is nowhere to send
	// spans.
	defer e.metrics.record(ctx, r, service)

	if !e.TracesEnabled() {
		return
	}

	tracer := e.tracerFor(service)

	kind := trace.SpanKindServer
	if r.Kind == correlate.Client {
		kind = trace.SpanKindClient
	}

	// Every request becomes the root of its own trace.
	//
	// An uninstrumented caller sends no trace context, so there is nothing to
	// continue. Two traced services calling each other produce two unrelated
	// traces rather than one, which is the cost of requiring no cooperation
	// from the applications. Propagating context would mean modifying the
	// requests those applications send, which is exactly what this agent does
	// not do.
	sctx := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    newTraceID(),
		SpanID:     newSpanID(),
		TraceFlags: trace.FlagsSampled,
	})
	ctx = trace.ContextWithSpanContext(ctx, sctx)

	start := r.StartWall
	end := start.Add(r.Duration)

	_, span := tracer.Start(ctx, spanName(r),
		trace.WithSpanKind(kind),
		trace.WithTimestamp(start),
		trace.WithAttributes(attributesFor(r)...),
	)

	// A record that expired carries no status, because no response was seen.
	// Marking it as an error would assert a failure that was never observed.
	switch {
	case r.Outcome == correlate.Expired:
		span.SetStatus(codes.Unset, "no response captured")
	case r.Status >= 500:
		span.SetStatus(codes.Error, r.Reason)
	default:
		span.SetStatus(codes.Ok, "")
	}

	span.End(trace.WithTimestamp(end))
}

// spanName follows the HTTP semantic conventions, which call for the method and
// a low-cardinality route rather than the raw target.
//
// The route is not available: it exists only inside the application's router,
// and this agent sees the request as it appeared on the wire. The method alone
// is used rather than the full path, because including an identifier makes
// every request its own span name and renders any grouping by name useless.
func spanName(r correlate.Record) string {
	if r.Method == "" {
		return "HTTP"
	}
	return r.Method
}

func attributesFor(r correlate.Record) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		semconv.HTTPRequestMethodKey.String(r.Method),
		semconv.URLPath(r.Path),
		attribute.String("process.command", r.Comm),
		attribute.Int("process.pid", int(r.PID)),
		// Which capture path produced this, so a gap in coverage can be
		// attributed to the right attach strategy.
		attribute.String("telemetry.capture.source", r.Source.String()),
	}

	if r.Status > 0 {
		attrs = append(attrs, semconv.HTTPResponseStatusCode(r.Status))
	}
	if r.Host != "" {
		attrs = append(attrs, semconv.ServerAddress(r.Host))
	}
	if r.Outcome == correlate.Expired {
		attrs = append(attrs, attribute.Bool("telemetry.response_captured", false))
	}

	if host, port, ok := splitHostPort(r.Peer); ok {
		attrs = append(attrs,
			semconv.NetworkPeerAddress(host),
			semconv.NetworkPeerPort(port),
		)
	}
	if host, port, ok := splitHostPort(r.Local); ok {
		attrs = append(attrs,
			semconv.NetworkLocalAddress(host),
			semconv.NetworkLocalPort(port),
		)
	}

	return attrs
}

func splitHostPort(s string) (string, int, bool) {
	if s == "" {
		return "", 0, false
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, false
	}
	return host, port, true
}

// newTraceID and newSpanID generate identifiers directly rather than relying on
// the SDK's generator, because the span context is constructed before any span
// exists to inherit from.
func newTraceID() trace.TraceID {
	var id trace.TraceID
	rand.Read(id[:])
	return id
}

func newSpanID() trace.SpanID {
	var id trace.SpanID
	rand.Read(id[:])
	return id
}
