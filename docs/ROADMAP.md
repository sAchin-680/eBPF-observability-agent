# Roadmap

Four phases, built in order. The dependency chain is real: overhead cannot be
benchmarked in Phase 3 without the data path from Phase 1, and fleet rollout
cannot be demonstrated in Phase 4 without the export pipeline from Phase 2.

Each phase ships completely — working, tested, documented, demonstrated —
before the next begins, and is tagged at completion.

Success criteria for each phase are in [requirements.md](requirements.md).

---

## Phase 1 — Core tracing

Establish the kernel-to-userspace data path and prove zero-instrumentation
capture across three language runtimes.

**Deliverables**

- [ ] Agent traces three unmodified sample applications
- [ ] Data-path diagram committed
- [ ] Recording of an empty source diff alongside live traces

**Tasks**

| # | Task | State |
| :--- | :--- | :--- |
| 1 | `clang -target bpf` build pipeline and `vmlinux.h` generation | Complete |
| 2 | Minimal uprobe program for `SSL_write` / `SSL_read` | |
| 3 | Symbol resolution for dynamically-loaded `libssl.so` | |
| 4 | Symbol resolution for statically-linked Go binaries | |
| 5 | kprobe or tracepoint for socket 4-tuple correlation | |
| 6 | `BPF_MAP_TYPE_RINGBUF` map and `ringbuf.NewReader()` in the agent | |
| 7 | Minimal HTTP/1.1 parser — method, path, status, timing | |
| 8 | Correlation logic: payload event plus socket event into a request record | |
| 9 | Three sample applications (Go, Flask, Express) over HTTP and HTTPS | |
| 10 | Agent startup: `/proc` scan plus `sched_process_exec` for new processes | |
| 11 | Demo recording: empty diff and live traces | |
| 12 | Data-path diagram | |

**Build order.** Tasks are listed by dependency, not by execution order. One
language runs end to end first — kernel hook through ring buffer to parsed
record — before a second attach strategy is attempted. Debugging three uprobe
attach strategies concurrently is the most common way this work stalls, and
symbol resolution differing per runtime is the highest-rated entry in the risk
register.

```
1 → 2 → 3 → 6 → 7 → 8        OpenSSL path, end to end
              ↓
        4 → 5 → 9 → 10        Go path, socket correlation, remaining runtimes
              ↓
           11 → 12            demo and diagram
```

Task 9 has no dependencies and can be pulled forward as soon as a target to
trace is useful.

---

## Phase 2 — Observability pipeline

Convert request records into OpenTelemetry telemetry and prove that a
previously unseen application requires no configuration.

**Deliverables**

- [ ] Dashboards committed as JSON
- [ ] Demonstration of a fourth, unseen application appearing with no config change

**Tasks**

| # | Task |
| :--- | :--- |
| 1 | OpenTelemetry Go SDK on the agent side only |
| 2 | Request record to OTel span: service name inference, duration, status, generated trace ID |
| 3 | Docker Compose stack: Tempo, Prometheus or Mimir, Grafana |
| 4 | Export spans to Tempo and metrics to Prometheus or Mimir |
| 5 | Grafana dashboard JSON: request rate, error rate, latency histogram by inferred service |
| 6 | Diagnosis view: highest error rate and p99 latency by service |
| 7 | Fourth sample application, verified to appear with no configuration change |

---

## Phase 3 — Correctness, safety, performance

Establish what the agent costs and where it breaks, with numbers rather than
adjectives.

**Deliverables**

- [ ] Overhead benchmark report with graphs
- [ ] A documented verifier constraint and the restructuring around it
- [ ] Multi-kernel test matrix results
- [ ] Failure matrix with all rows passing

**Tasks**

| # | Task |
| :--- | :--- |
| 1 | Stress in-kernel HTTP header parsing until a verifier constraint is hit; document it as encountered |
| 2 | Restructure around the constraint |
| 3 | Load test harness (`k6` or `wrk`) against traced and untraced instances |
| 4 | Load sweep capturing p50/p95/p99 latency delta, agent CPU, ring buffer drop rate |
| 5 | Identify the request rate at which drops begin |
| 6 | Provision two to three kernel versions |
| 7 | Run the same compiled binary against each; record the pass/fail matrix |
| 8 | Verify every failure-matrix row explicitly |

The verifier constraint must be one actually encountered and reproduced, with
the rejection log recorded verbatim. The request rate at which drops begin is
a specific number, not a characterization.

---

## Phase 4 — Deployment

Deploy as real infrastructure, with blast-radius control appropriate to a
privileged node-level agent.

**Deliverables**

- [ ] Canary to full rollout demonstration
- [ ] Capability scoping documented
- [ ] CI matrix across kernel versions, passing
- [ ] Agent self-health dashboard

**Tasks**

| # | Task |
| :--- | :--- |
| 1 | Terraform modules for a multi-node test fleet |
| 2 | DaemonSet manifest: `hostPID`, hostPath mounts for `/sys/kernel/debug` and `/sys/fs/bpf` |
| 3 | Scope and document capabilities, with the older-kernel fallback |
| 4 | Helm chart |
| 5 | Canary node selector, deployed to one or two nodes |
| 6 | Canary verification: node CPU, `dmesg`, traced-application health |
| 7 | ArgoCD sync for full-fleet promotion by Git commit |
| 8 | GitHub Actions matrix build: compile and test suite per kernel version |
| 9 | Agent self-health dashboard: desired versus ready, drop rate, per-node CPU and memory |
| 10 | Canary to full rollout recording |

Agent self-health is a separate concern from the telemetry the agent produces
about traced applications, and belongs on its own dashboard.

---

## Architecture decision records

ADRs are written at the point the decision is made, not collected at the end.
An ADR written retroactively tends to justify rather than record.

| ADR | Decision | Written during |
| :--- | :--- | :--- |
| 001 | DaemonSet rather than sidecar | Phase 4 |
| 002 | uprobes on TLS read/write rather than traffic mirroring | Phase 1, task 2 |
| 003 | Tracepoints over kprobes where both exist | Phase 1, task 5 |
| 004 | CO-RE rather than BCC | Phase 1, task 1 |
| 005 | Per-request generated trace IDs, no context propagation | Phase 2, task 2 |
| 006 | `CAP_BPF` and `CAP_PERFMON` rather than `--privileged` | Phase 4 |
| 007 | Canary rollout rather than fleet-wide apply | Phase 4 |

---

## Releases

Tagged at the end of each phase, giving fixed points to reference later.

| Tag | Marks |
| :--- | :--- |
| `v0.1-phase1` | Core tracing complete |
| `v0.2-phase2` | Observability pipeline complete |
| `v0.3-phase3` | Benchmarks and failure matrix complete |
| `v1.0-phase4` | Deployment complete |
