package otel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/attribute"
	promexp "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/sAchin-680/ebpf-observability-agent/internal/correlate"
)

// Metrics are exposed for scraping rather than pushed.
//
// Traces are pushed because a trace is an event that has already happened and
// has nowhere to wait. Metrics are a current value, and scraping keeps their
// timing under the monitoring system's control, makes the agent's own liveness
// observable through scrape failure, and removes any need to configure a
// metrics destination on every node.
//
// Service name is an attribute here rather than a resource, which is the
// opposite of the choice made for traces. That is the Prometheus data model: a
// dimension is a label, and a label is what a query groups by.

// latencyBuckets are explicit rather than left to the default.
//
// The default boundaries are chosen for operations measured in whole seconds.
// The requests observed here are dominated by sub-millisecond local calls, and
// with default buckets every one of them lands in the first bucket, making any
// percentile below the first boundary pure interpolation — a p99 that is an
// artifact of the bucket edges rather than a measurement.
var latencyBuckets = []float64{
	0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01,
	0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
}

type metrics struct {
	provider *sdkmetric.MeterProvider
	server   *http.Server

	duration metric.Float64Histogram
	requests metric.Int64Counter
}

func newMetrics(addr string) (*metrics, error) {
	registry := prometheus.NewRegistry()

	exporter, err := promexp.New(promexp.WithRegisterer(registry))
	if err != nil {
		return nil, fmt.Errorf("creating Prometheus exporter: %w", err)
	}

	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(exporter),
		sdkmetric.WithView(sdkmetric.NewView(
			sdkmetric.Instrument{Name: "http.server.request.duration"},
			sdkmetric.Stream{Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
				Boundaries: latencyBuckets,
			}},
		)),
	)

	meter := provider.Meter(instrumentationName)

	duration, err := meter.Float64Histogram(
		"http.server.request.duration",
		metric.WithDescription("Duration of traced HTTP requests"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	requests, err := meter.Int64Counter(
		"http.server.requests",
		metric.WithDescription("Traced HTTP requests"),
	)
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	m := &metrics{provider: provider, server: srv, duration: duration, requests: requests}

	go func() {
		// A metrics endpoint that cannot bind is reported but is not fatal: the
		// agent's purpose is to trace, and it should keep doing so.
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Printf("metrics endpoint: %v\n", err)
		}
	}()

	return m, nil
}

func (m *metrics) record(ctx context.Context, r correlate.Record, service string) {
	attrs := []attribute.KeyValue{
		attribute.String("service_name", service),
		attribute.String("http_request_method", r.Method),
		attribute.String("span_kind", r.Kind.String()),
	}

	// Status is a dimension only when it was observed. Recording zero for an
	// expired record would create a status_code="0" series that looks like a
	// real class of response.
	if r.Status > 0 {
		attrs = append(attrs,
			attribute.Int("http_response_status_code", r.Status),
			attribute.String("status_class", statusClass(r.Status)),
		)
	} else {
		attrs = append(attrs, attribute.String("status_class", "unknown"))
	}

	set := metric.WithAttributes(attrs...)
	m.requests.Add(ctx, 1, set)

	// An expired record has no duration to report. Recording zero would pull
	// every percentile toward zero and understate real latency.
	if r.Outcome == correlate.Completed {
		m.duration.Record(ctx, r.Duration.Seconds(), set)
	}
}

// statusClass reduces a status code to its class, so that an error rate can be
// computed without summing over every code individually.
func statusClass(code int) string {
	switch {
	case code >= 500:
		return "5xx"
	case code >= 400:
		return "4xx"
	case code >= 300:
		return "3xx"
	case code >= 200:
		return "2xx"
	default:
		return "1xx"
	}
}

func (m *metrics) shutdown(ctx context.Context) error {
	var firstErr error
	if err := m.server.Shutdown(ctx); err != nil {
		firstErr = err
	}
	if err := m.provider.Shutdown(ctx); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}
