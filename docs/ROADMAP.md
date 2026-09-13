# Roadmap

Four phases, built in order. The dependency chain is real: overhead cannot be
benchmarked in Phase 3 without the data path from Phase 1, and fleet rollout
cannot be demonstrated in Phase 4 without the export pipeline from Phase 2.

Each phase ships completely — working, tested, documented, demonstrated —
before the next begins, and is tagged at completion.

Success criteria for each phase are in [requirements.md](requirements.md).

---

## Phase 1 — Core tracing · complete

Establish the kernel-to-userspace data path and prove zero-instrumentation
capture across three language runtimes.

**Deliverables**

- [x] Agent traces three unmodified sample applications
- [x] Data-path diagram committed — [data-path.md](data-path.md)
- [ ] Recording of an empty source diff alongside live traces — `scripts/demo.sh` runs; the recording has not been captured

**Tasks**

| # | Task | State |
| :--- | :--- | :--- |
| 1 | `clang -target bpf` build pipeline and `vmlinux.h` generation | Complete |
| 2 | Minimal uprobe program for `SSL_write` / `SSL_read` | Complete — `bpf/ssl.bpf.c`, four OpenSSL entry points |
| 3 | Symbol resolution for dynamically-loaded `libssl.so` | Complete — `internal/proc/discover.go`, per-process `/proc` maps |
| 4 | Symbol resolution for statically-linked Go binaries | Complete — `internal/proc/gobin.go`, return-site probes |
| 5 | kprobe or tracepoint for socket 4-tuple correlation | Complete — `bpf/sock.bpf.c`, IPv4 and IPv6 |
| 6 | `BPF_MAP_TYPE_RINGBUF` map and `ringbuf.NewReader()` in the agent | Complete — `bpf/capture.h`, with drop accounting |
| 7 | Minimal HTTP/1.1 parser — method, path, status, timing | Complete — `internal/httpparse/` |
| 8 | Correlation logic: payload event plus socket event into a request record | Complete — `internal/correlate/` |
| 9 | Three sample applications (Go, Flask, Express) over HTTP and HTTPS | Complete — `samples/`, four services |
| 10 | Agent startup: `/proc` scan plus `sched_process_exec` for new processes | Complete — `bpf/discover.bpf.c` |
| 11 | Demo recording: empty diff and live traces | Script ready, not recorded |
| 12 | Data-path diagram | Complete — [data-path.md](data-path.md) |

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

## Phase 2 — Observability pipeline · complete

Convert request records into OpenTelemetry telemetry and prove that a
previously unseen application requires no configuration.

**Deliverables**

- [x] Dashboards committed as JSON — [deploy/compose/grafana/dashboards/](../deploy/compose/grafana/dashboards/)
- [x] Demonstration of a fourth, unseen application appearing with no config change — `scripts/gate-phase2.sh` passes

**Tasks**

| # | Task | State |
| :--- | :--- | :--- |
| 1 | OpenTelemetry Go SDK on the agent side only | Complete |
| 2 | Request record to OTel span: service name inference, duration, status, generated trace ID | Complete — one provider per service |
| 3 | Docker Compose stack: Tempo, Prometheus, Grafana | Complete — [deploy/compose/](../deploy/compose/) |
| 4 | Export spans to Tempo and metrics to Prometheus | Complete — traces pushed, metrics scraped |
| 5 | Grafana dashboard JSON | Complete — 13 panels |
| 6 | Diagnosis view: highest error rate and p99 latency by service | Complete — 4 ranked panels |
| 7 | Fourth sample application, verified to appear with no configuration change | Complete — `scripts/gate-phase2.sh` |

---

## Phase 3 — Correctness, safety, performance · complete

Establish what the agent costs and where it breaks, with numbers rather than
adjectives.

**Deliverables**

- [x] Overhead benchmark report — [docs/benchmarks/](benchmarks/)
- [x] A documented verifier constraint and the restructuring around it — [docs/verifier/](verifier/)
- [x] Multi-kernel test matrix results — [docs/kernel-matrix.md](kernel-matrix.md)
- [x] Failure matrix with all rows passing — [docs/failure-matrix.md](failure-matrix.md)

**Tasks**

| # | Task |
| :--- | :--- |
| 1 | Stress in-kernel HTTP header parsing until a verifier constraint is hit; document it as encountered — **done**, [docs/verifier/](verifier/) |
| 2 | Restructure around the constraint — **done**, parsing is in userspace |
| 3 | Load test harness against traced and untraced instances — **done**, `scripts/bench.sh` |
| 4 | Load sweep capturing p50/p95/p99 latency delta, agent CPU, ring buffer drop rate — **done**, [docs/benchmarks/](benchmarks/) |
| 5 | Identify the rate at which drops begin — **done**, 8,000 to 12,000 events/s |
| 6 | Provision two to three kernel versions — **done**, 5.15 and 6.8 |
| 7 | Run the same compiled binary against each; record the pass/fail matrix — **done**, [docs/kernel-matrix.md](kernel-matrix.md) |
| 8 | Verify every failure-matrix row explicitly — **done**, all four rows pass |

The verifier constraint must be one actually encountered and reproduced, with
the rejection log recorded verbatim. The request rate at which drops begin is
a specific number, not a characterization.

---

## Phase 4 — Deployment

Deploy as real infrastructure, with blast-radius control appropriate to a
privileged node-level agent.

**Deliverables**

- [ ] Canary to full rollout demonstration
- [x] Capability scoping documented — [capabilities.md](capabilities.md),
      [ADR-006](adr/006-capability-scoping.md), and the container-level
      measurements in [`deploy/k8s/README.md`](../deploy/k8s/README.md)
- [x] CI matrix across kernel versions, passing — [ci.md](ci.md)
- [ ] Agent self-health dashboard

**Tasks**

| # | Task | State |
| :--- | :--- | :--- |
| 1 | Terraform modules for a multi-node test fleet | Not started |
| 2 | DaemonSet manifest: `hostPID`, hostPath mounts for `/sys/kernel/debug` and `/sys/fs/bpf` | Complete — `deploy/k8s/`, with one read-only tracefs mount rather than two; `/sys/fs/bpf` is not needed and the reason debugfs is, is the exec tracepoint rather than uprobes |
| 3 | Scope and document capabilities, with the older-kernel fallback | Complete — [capabilities.md](capabilities.md), NFR4 corrected |
| 4 | Helm chart | Complete — `deploy/helm/ebpf-agent`, with a drift check against `deploy/k8s/` in `make verify` |
| 5 | Canary node selector, deployed to one or two nodes | Complete — two releases of one chart on a three-node cluster; promotion is a node label change |
| 6 | Canary verification: node CPU, `dmesg`, traced-application health | Complete — [canary.md](canary.md), `scripts/gate-canary.sh`, demonstrated failing |
| 7 | ArgoCD sync for full-fleet promotion by Git commit | Not started |
| 8 | GitHub Actions matrix build: compile and test suite per kernel version | Complete — [ci.md](ci.md); compiles once, runs on 5.15, 6.1 and 6.6 in QEMU |
| 9 | Agent self-health dashboard: desired versus ready, drop rate, per-node CPU and memory | Not started |
| 10 | Canary to full rollout recording | Not started |

Agent self-health is a separate concern from the telemetry the agent produces
about traced applications, and belongs on its own dashboard.

---

## Architecture decision records

ADRs are written at the point the decision is made, not collected at the end.
An ADR written retroactively tends to justify rather than record.

| ADR | Decision | Written during |
| :--- | :--- | :--- |
| 001 | DaemonSet rather than sidecar | Phase 4 |
| [002](adr/002-uprobes-on-tls-entry-points.md) | uprobes on TLS read/write rather than traffic mirroring | Written |
| [003](adr/003-tracepoints-over-kprobes.md) | Tracepoints over kprobes where both exist | Written |
| [004](adr/004-core-over-bcc.md) | CO-RE rather than BCC | Written |
| [005](adr/005-generated-trace-ids.md) | Generate a trace ID per request, propagate no context | Written |
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
