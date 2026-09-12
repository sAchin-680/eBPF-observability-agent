# Overhead

What the agent costs, measured rather than estimated.

Raw output of every run is kept beside each result set. A summary cannot be
checked; raw data can, and a summary can always be regenerated from it.

Reproduce with `scripts/bench.sh`.

---

## Result

Measured on a 4-core aarch64 VM, kernel 6.8.0, against the Go sample service
over HTTPS, 50 connections, 15 seconds per run, median of 3 repetitions.

| req/s | Δ p50 | Δ p99 | agent CPU | events/s | dropped | loss |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1000 | +0.600 ms | +1.500 ms | 1.54 s | 4,003 | 0 | 0.00% |
| 2000 | +0.300 ms | +0.400 ms | 1.78 s | 7,987 | 0 | 0.00% |
| 3000 | +0.200 ms | +0.100 ms | 2.23 s | 11,979 | 292 | 0.05% |
| 4000 | +0.200 ms | +0.100 ms | 2.81 s | 15,763 | 5,154 | 1.08% |
| 6000 | +0.100 ms | +0.000 ms | 4.08 s | 23,176 | 18,437 | 2.57% |
| 8000 | +0.100 ms | +0.050 ms | 4.01 s | 19,311 | 376,364 | 39.38% |

Deltas are against the control arm, not against an idle machine. See below.

**Loss begins between 8,000 and 12,000 events per second**, which was 2,000 to
3,000 requests per second in this test. The first measurable loss is 0.05% at
11,979 events/s.

The agent's limit is stated per event rather than per request because the number
of events a request produces depends on the traffic: a large response arrives in
several reads, TLS record headers are read separately from the records they
describe, and the load generator's own TLS traffic is captured as well. Roughly
four events per request here — a different workload would reach the same event
rate at a different request rate.

---

## Reading the numbers

**Overhead falls as load rises.** +0.6 ms at 1,000 req/s, +0.1 ms at 6,000. The
per-request cost of the probes does not change; what changes is the baseline. A
lightly loaded machine is a slower machine, and the more of the measurement that
is spent working rather than waiting, the smaller a fixed cost appears beside it.

**8,000 req/s is past saturation, not a data point.** Events received falls from
23,176/s to 19,311/s while loss rises to 39%. Fewer events are seen because more
are discarded before they can be. The latency figures there describe a system
observing three fifths of its traffic.

**CPU is the agent's own, from /proc.** 1.54 s to 4.08 s over a 15-second run —
roughly 10% to 27% of one core, on a machine that also runs the load generator
and the service being measured.

---

## Why there is a control arm

The first version of this benchmark reported the agent making requests **faster**,
consistently, at every rate, in both orderings.

Two explanations were tried and both were wrong. Warm-up: the untraced arm ran
first and absorbed TLS setup and cold caches — adding a discarded warm-up run did
not remove the effect. Ordering: whichever arm ran second within a pair benefited
from the one before it — alternating the order did not remove it either.

The cause is that **an idle machine is slower than a busy one**. Cores drop into
low-power states, and a request arriving at an idle core waits for it to come
back. Any additional load reduces latency, whatever that load is doing.

The control arm is a busy loop that burns comparable CPU while observing nothing:
no probes, no kernel programs. It is six times faster than idle at 1,000 req/s —
0.25 ms against 1.55 ms — which is the entire effect, and none of it belongs to
the agent.

| | p50 at 1000 req/s |
| :--- | ---: |
| idle machine | 1.550 ms |
| control, CPU busy, observing nothing | 0.250 ms |
| agent attached | 0.900 ms |

Measured against idle, the agent appears to save 0.65 ms. Measured against the
control, it costs 0.65 ms. Same data, opposite sign.

This is worth stating plainly: a benchmark comparing against an idle baseline
does not merely understate the cost, it inverts it. The result was questioned
only because it was impossible — a probe cannot make a request faster. A
flattering result that was merely implausible would have gone unexamined.

---

## What these numbers are not

- **Not a production figure.** A 4-core VM shared with the load generator and
  the service under test is not a server.
- **Not independent of the workload.** Every request here is a small response on
  a warm keep-alive connection. Larger responses produce more events per request
  and reach the loss threshold at a lower request rate.
- **Not the limit of the approach.** The ring buffer is 256 KiB and each record
  carries 256 bytes of payload. Both are chosen, not forced, and either would
  move the threshold.
- **Not measured with trace export enabled.** Export opens TLS connections the
  agent would then trace, and its cost would be counted as capture cost. What is
  measured here is the capture path.
