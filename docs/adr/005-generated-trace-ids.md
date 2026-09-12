# ADR-005: Generate a trace ID per request, and propagate no context

**Status:** Accepted
**Date:** 2026-09-13

## Context

A distributed trace is assembled from spans that share a trace ID. A service
receives that ID in a request header, includes it in its own spans, and passes
it on. The chain works because every service in it participates.

This agent traces services that do not participate. They send no trace context,
because nothing in them knows tracing exists — which is the property the whole
project rests on. A request arriving at a traced service carries no ID to
continue, and a request leaving one carries none for the next service to pick
up.

## Decision

Every observed request becomes the root of its own trace, with a freshly
generated ID. No context is read from incoming requests and none is added to
outgoing ones.

## Alternatives considered

**Inject trace context into outgoing requests.** The agent sees the plaintext
request before it is encrypted and could add a header. This is rejected on the
grounds the project exists for: the agent would be modifying the traffic it
observes. A tracing tool that alters requests can change application behaviour —
a signed request becomes invalid, a length-sensitive protocol breaks, a strict
server rejects an unexpected header — and it would no longer be true that the
traced application is unaffected. That claim is tested, and this would make it
false.

**Infer the chain from timing and endpoints.** Spans could be related by
observing that one service called another within a plausible window. This
produces traces that look complete and are sometimes wrong, and there is no way
for a reader to tell which. A missing relationship is a known gap; an invented
one is misinformation.

**Read context when it happens to be present.** An instrumented service calling
an uninstrumented one does send a header the agent could honour. This is
tempting and may be worth doing later, but it produces traces whose
completeness varies with which services happen to be instrumented — the opposite
of the uniform coverage this agent is for. It is deferred rather than rejected.

## Consequences

**Traces are single-service.** Two traced services calling each other produce
two unrelated traces. The call is visible from both sides — the caller's client
span and the callee's server span — but nothing links them.

**Every span is a root span.** Backends expecting a trace to contain a hierarchy
will find one span. Tempo reports these as complete traces, because they are.

**Latency is per hop, not end to end.** A slow request identifies the service
that was slow, but not what it was waiting for.

**The traced application is genuinely untouched.** No header is added, no byte
is changed, nothing is injected into a buffer. This is what makes the
agent-crash and process-restart guarantees meaningful: the agent only ever
reads.

**Correlation is by connection, not by ID.** Requests are paired with responses
using the TLS connection object, which is an implementation detail of the
process rather than anything on the wire — so the pairing works regardless of
what the application sends.
