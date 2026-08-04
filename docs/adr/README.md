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
| 002 | uprobes on TLS read/write rather than traffic mirroring | Not yet written |
| 003 | Tracepoints over kprobes where both exist | Not yet written |
| 004 | CO-RE rather than BCC | Not yet written |
| 005 | Per-request generated trace IDs, no context propagation | Not yet written |
| 006 | `CAP_BPF` and `CAP_PERFMON` rather than `--privileged` | Not yet written |
| 007 | Canary rollout rather than fleet-wide apply | Not yet written |

The phase each record is written during is listed in
[../ROADMAP.md](../ROADMAP.md).
