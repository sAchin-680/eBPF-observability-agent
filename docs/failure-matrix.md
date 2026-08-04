# Failure matrix

Behaviour the agent is required to exhibit when things go wrong, and the test
that demonstrates each.

This is a checklist, not a description. Every row needs a test that is run and
observed. A row whose **Status** is *pending* has expected behaviour specified
but not demonstrated, and no claim to the contrary is made elsewhere in this
repository.

All rows must pass before Phase 3 is considered shipped.

---

| # | Scenario | Expected behaviour | Verified by | Status |
| :--- | :--- | :--- | :--- | :--- |
| 1 | Traced process restarts | Agent detects the restart and re-attaches automatically | Integration test: kill and restart a sample application, assert traces resume | pending |
| 2 | Sustained high load | Overhead stays within documented bounds; dropped events are logged, never silent | Load test with drop-rate logging assertion | pending |
| 3 | Agent process crashes | Traced application is completely unaffected | Kill the agent mid-load-test, assert the sample application's latency and error rate are unchanged | pending |
| 4 | Kernel without BTF or CO-RE support | Agent fails to load with a clear error and does not destabilize the node | Run against a deliberately incompatible kernel image, assert clean failure and node health | pending |

---

## Why each row is here

**1 — Process restart.** A uprobe attached to a process dies with that
process. Attachment to a shared library file survives, but per-process state
does not, and a statically-linked binary is a per-process attachment by
definition. Without re-attachment the agent silently stops tracing a service
that has merely been redeployed — the failure looks identical to a service
that stopped receiving traffic.

**2 — Sustained load.** The ring buffer is fixed-size. When userspace cannot
drain it fast enough, the kernel drops events and reports success. Undetected,
this makes the agent under-report request volume while appearing healthy. The
requirement is not that drops never happen; it is that they are counted,
exported, and visible.

**3 — Agent crash.** This is the property that determines whether the agent is
deployable at all. The expectation is that probes are torn down when the
owning file descriptors close, leaving the traced application untouched. That
is a reason to expect the behaviour, not evidence of it. Kernel-attached code
failing to clean up is precisely the risk that makes operators refuse
node-level agents, so the claim is worth proving rather than asserting.

**4 — Unsupported kernel.** CO-RE requires the target kernel to expose BTF. On
a kernel without it, the correct behaviour is to refuse to load and say why.
The failure that matters is not the refusal — it is a partial load that leaves
probes attached, or a repeated load attempt that degrades the node. The test
asserts both a clean error and unchanged node health.

---

## Relationship to requirements

| Row | Requirement |
| :--- | :--- |
| 1 | FR7 |
| 2 | NFR1, NFR2 |
| 3 | NFR3 |
| 4 | FR8, NFR5 |

Full requirement definitions are in [requirements.md](requirements.md).
