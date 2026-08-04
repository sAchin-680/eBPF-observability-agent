# Requirements

Functional and non-functional requirements for the agent, with the artifact
that verifies each.

A requirement is marked verified only when a test, benchmark, or recorded
result demonstrates it. Where the **Verified by** column reads *pending*, the
requirement is specified but unproven, and no claim to the contrary is made
elsewhere in this repository.

---

## Success criteria

Each phase is complete when its criterion is demonstrably met. The criteria are
checkable rather than subjective, and each gates the phase that follows.

| Phase | Criterion |
| :--- | :--- |
| 1 | The agent produces correlated request records — method, path, status, latency — for Go, Python, and Node sample applications, with an empty source diff against those applications |
| 2 | A fourth, previously unseen application appears in the Grafana dashboard with no configuration change |
| 3 | Measured overhead exists as p50/p95/p99 latency delta, agent CPU, and ring buffer drop rate at a stated RPS threshold; the agent is verified not to affect the traced application when the agent itself crashes |
| 4 | The DaemonSet deploys via canary and then full fleet, with capability scoping documented and no use of `--privileged`; CI passes across two to three kernel versions |

Explicitly **not** success criteria: support for every language, readiness for
production workloads, or feature parity with existing commercial agents. This
is a scoped system, and claiming beyond what is built and measured undermines
the value of what is.

---

## Functional requirements

| ID | Requirement | Verified by |
| :--- | :--- | :--- |
| FR1 | Attach uprobes to `SSL_write` and `SSL_read` in OpenSSL, and to Go's `crypto/tls` write and read paths | pending |
| FR2 | Attach kprobes or tracepoints to correlate captured payloads with socket 4-tuples | pending |
| FR3 | Parse HTTP/1.1 method, path, status code, and timing from captured byte chunks | pending |
| FR4 | Reconstruct one logical request/response record per exchange | pending |
| FR5 | Convert request records into OpenTelemetry spans with an inferred service name | pending |
| FR6 | Export spans to Tempo, and rate/error/duration metrics to Prometheus or Mimir | pending |
| FR7 | Detect traced process restarts and re-attach automatically | pending |
| FR8 | Fail closed with a clear error on kernels lacking BTF or CO-RE support, without destabilizing the node | partial — `scripts/check-env.sh` and the `vmlinux` target fail closed with a diagnostic; agent-side handling pending |

## Non-functional requirements

| ID | Requirement | Verified by |
| :--- | :--- | :--- |
| NFR1 | Overhead is measured rather than assumed: p50/p95/p99 latency delta at increasing request rates | pending |
| NFR2 | Ring buffer drop rate is observable and logged; events are never dropped silently | pending |
| NFR3 | An agent crash does not affect the traced application, demonstrated by test rather than by argument | pending |
| NFR4 | No `--privileged`. Capabilities scoped to `CAP_BPF` and `CAP_PERFMON`, or `CAP_SYS_ADMIN` on older kernels, documented per operation | pending |
| NFR5 | One compiled binary runs unmodified across all tested kernel versions | partial — `test/toolchain` proves CO-RE relocation on kernel 6.8; multi-kernel matrix pending |
| NFR6 | Canary rollout is verifiable through node CPU, `dmesg` kernel warnings, and traced-application health before full fleet rollout | pending |

---

## Notes on specific requirements

**FR8 and NFR5 are the same property viewed from two directions.** CO-RE lets
one binary span kernel versions; the requirement to fail closed covers the
kernels where it cannot. Both depend on BTF being present and readable, which
is why environment verification precedes every build.

**NFR3 cannot be satisfied by reasoning about probe lifetimes.** The claim is
that a crashed agent leaves the traced application untouched. The mechanism —
probes being torn down when the owning file descriptors close — is a reason to
expect it, not evidence that it holds. The verification is a test that kills
the agent mid-load and asserts the traced application's latency and error rate
are unchanged.

**NFR2 exists because the failure mode is silence.** A ring buffer that
overflows drops events without error. If drop rate is not exported, the agent
reports fewer requests than occurred and looks healthy doing it.
