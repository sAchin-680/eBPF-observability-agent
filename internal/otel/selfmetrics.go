package otel

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// The agent's own health, kept separate from the telemetry it produces about
// other services.
//
// The two answer different questions. "Is this service healthy" is about the
// traced application; "is the agent seeing everything" is about the agent, and
// an agent that has stopped observing looks identical to a service that has
// stopped receiving traffic. Without these, a drop to zero is ambiguous.

// SelfMetrics reports the agent's own state.
type SelfMetrics struct {
	dropped  metric.Int64ObservableCounter
	pending  metric.Int64ObservableGauge
	services metric.Int64ObservableGauge
	attached metric.Int64ObservableGauge
}

// SelfState is what the agent reports about itself at scrape time.
type SelfState struct {
	// DroppedEvents is the count of events lost to a full ring buffer, per
	// capture source. This is the measurement that decides whether the agent's
	// output can be trusted at a given request rate.
	DroppedEvents map[string]uint64

	// PendingRequests is how many requests are awaiting a response. A value
	// that grows without bound means responses are being missed.
	PendingRequests int

	// AttachedTargets is the number of libraries and executables probed.
	AttachedTargets int
}

// RegisterSelfMetrics arranges for the agent's own state to be reported on each
// scrape.
//
// Observed rather than recorded: these are current values that exist whether or
// not anything happened, so they are read when asked for rather than pushed on
// every event. Counting drops on the event path would also mean doing work
// precisely when the agent is already failing to keep up.
func (e *Exporter) RegisterSelfMetrics(read func() SelfState) error {
	meter := e.metrics.provider.Meter(instrumentationName)

	dropped, err := meter.Int64ObservableCounter(
		"ebpf_agent.events.dropped",
		metric.WithDescription("Events lost because the ring buffer was full"),
	)
	if err != nil {
		return err
	}

	pending, err := meter.Int64ObservableGauge(
		"ebpf_agent.requests.pending",
		metric.WithDescription("Requests awaiting a response"),
	)
	if err != nil {
		return err
	}

	services, err := meter.Int64ObservableGauge(
		"ebpf_agent.services.observed",
		metric.WithDescription("Distinct services telemetry has been produced for"),
	)
	if err != nil {
		return err
	}

	attached, err := meter.Int64ObservableGauge(
		"ebpf_agent.targets.attached",
		metric.WithDescription("Libraries and executables currently probed"),
	)
	if err != nil {
		return err
	}

	_, err = meter.RegisterCallback(
		func(ctx context.Context, o metric.Observer) error {
			s := read()
			for source, n := range s.DroppedEvents {
				o.ObserveInt64(dropped, int64(n),
					metric.WithAttributes(attribute.String("source", source)))
			}
			o.ObserveInt64(pending, int64(s.PendingRequests))
			o.ObserveInt64(services, int64(e.Services()))
			o.ObserveInt64(attached, int64(s.AttachedTargets))
			return nil
		},
		dropped, pending, services, attached,
	)
	return err
}
