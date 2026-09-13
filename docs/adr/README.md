# Architecture decision records

One file per decision, named `NNN-short-title.md`.

Each record states the context that forced the decision, the decision itself,
the alternatives considered and why they were rejected, and the consequences —
including what the choice gives up. The consequences section is the one that
matters most later; a record listing only benefits is advocacy rather than a
record.

Records are written when the decision is made, not assembled afterwards. A
record written retroactively tends to justify the path taken rather than
capture the constraints that produced it, and loses the alternatives that were
genuinely considered at the time.

Records are immutable once merged. A decision that is later reversed gets a
new record superseding the old one; the original stays in place, marked as
superseded, because the reasoning that was valid under earlier constraints is
part of the history.

## Format

```markdown
# ADR-NNN: Title

**Status:** Accepted | Superseded by ADR-NNN
**Date:** YYYY-MM-DD

## Context
The forces at play — technical constraints, requirements, and what makes this
a decision rather than an obvious default.

## Decision
What was chosen, stated plainly.

## Alternatives considered
Each option evaluated, and the specific reason it was not chosen.

## Consequences
What follows from this decision, including the costs accepted and the options
now foreclosed.
```

## Index

| ADR | Decision | Status |
| :--- | :--- | :--- |
| 001 | DaemonSet rather than sidecar | Not yet written |
| [002](002-uprobes-on-tls-entry-points.md) | Capture plaintext at TLS library entry points | Accepted |
| [003](003-tracepoints-over-kprobes.md) | Prefer tracepoints, record where a kprobe is unavoidable | Accepted |
| [004](004-core-over-bcc.md) | Compile once with CO-RE rather than per host with BCC | Accepted |
| [005](005-generated-trace-ids.md) | Generate a trace ID per request, propagate no context | Accepted |
| [006](006-capability-scoping.md) | Enumerated capabilities, including `CAP_SYS_ADMIN`, rather than privileged | Accepted |
| 007 | Canary rollout rather than fleet-wide apply | Not yet written |

The phase each record is written during is listed in
[../ROADMAP.md](../ROADMAP.md).
