# Zero-Instrumentation eBPF Observability Agent

**Request-level tracing for HTTP and HTTPS services, with zero changes to the traced application.**

This agent attaches to the kernel and to TLS library entry points using eBPF,
reconstructs HTTP request/response pairs from raw syscalls and
decrypted-in-place buffers, and exports them as OpenTelemetry traces and
metrics.

No SDK. No sidecar proxy. No configuration injected into the traced process.
One binary, once per node.

---

## Architecture

```text
        ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
        │  Go service  │  │    Python    │  │   Node.js    │
        │ (crypto/tls) │  │  (OpenSSL)   │  │  (OpenSSL)   │
        └───────┬──────┘  └───────┬──────┘  └───────┬──────┘
                │                 │                 │
                └─────────────────┼─────────────────┘
                                  │  uprobes + tracepoints
                                  ▼
        ┌──────────────────────────────────────────────────┐
        │              eBPF programs (kernel)              │
        │  SSL_write/read · Go TLS write/read · socket tp  │
        └─────────────────────────┬────────────────────────┘
                                  │  BPF ring buffer
                                  ▼
        ┌──────────────────────────────────────────────────┐
        │               Userspace agent (Go)               │
        │       parse · correlate · build OTel spans       │
        └─────────────────────────┬────────────────────────┘
                                  │  OTLP
                                  ▼
               ┌──────────────────┴──────────────────┐
               ▼                                     ▼
        Tempo (traces)                     Prometheus (metrics)
               └──────────────────┬──────────────────┘
                                  ▼
                               Grafana
```

The traced applications are unmodified and unaware of the agent. Attachment
happens at the shared library and kernel boundary, so any process on the node
becomes observable the moment it starts — including processes started after
the agent is already running.

[`docs/data-path.md`](docs/data-path.md) traces a request end to end: how
probes are attached, why the read and write paths differ, how a TLS connection
is bound to its socket, and where coverage can silently degrade.

---

## Why this exists

Instrumenting a fleet for tracing today means adding an SDK per language,
redeploying every service, and maintaining that instrumentation indefinitely.
Coverage ends up defined by whichever team had time to add it rather than by
what actually needs observing. Legacy services, vendored binaries, and
anything nobody got around to remain permanently blind.

eBPF moves the attachment point below the application entirely. Hook the
kernel and TLS boundary once per host, and every process on that host becomes
traceable regardless of language, with no code change and no restart.

The trade-off is real: kernel version differences, per-runtime TLS internals,
verifier constraints on what kernel-side code is permitted to do, and the
operational risk that a faulty kernel program can affect a node. This project
treats that complexity as the primary subject rather than an implementation
detail.

---

## Status

Phases 1 to 3 are complete. The table reflects the actual state, not the target
state: a capability is marked complete only when a test, benchmark or recorded
result demonstrates it, and every entry below links to that evidence through
[`docs/requirements.md`](docs/requirements.md).

| Capability | Status |
| :--- | :--- |
| Reproducible Linux development environment, BTF-verified | Complete |
| BPF build pipeline (`vmlinux.h` generation, `bpf2go` codegen) | Complete |
| Uprobe capture of OpenSSL, all four read and write entry points | Complete |
| Go `crypto/tls` capture, via return-site probes | Complete |
| Ring buffer data path with drop accounting | Complete |
| HTTP/1.1 start-line parsing | Complete |
| Request and response correlation into single records | Complete |
| Socket endpoint capture, IPv4 and IPv6 | Complete |
| Process discovery via `sched_process_exec` | Complete |
| OpenTelemetry export to Tempo and Prometheus | Complete |
| Grafana dashboards, provisioned from version control | Complete |
| Documented verifier constraint on in-kernel parsing | Complete |
| Kubernetes DaemonSet deployment | Complete |
| Canary rollout, gated on node and application health | Complete |
| Measured overhead and ring buffer drop-rate benchmarks | Complete |
| Multi-kernel validation, one binary on 5.15 and 6.8 | Complete |
| CI: one build, verified on three kernels in QEMU | Complete |
| Failure matrix, all four rows | Complete |

The phase plan is in [`docs/ROADMAP.md`](docs/ROADMAP.md).

### Measured

| | |
| :--- | :--- |
| Added latency | +0.65 ms p50 at 1,000 req/s, against a CPU-matched control |
| Loss threshold | between 8,000 and 12,000 events/s |
| Kernels | one binary, by checksum, on 5.15 and 6.8 |
| Failure matrix | four rows of four, each with a test that can fail |

Method and caveats in [`docs/benchmarks/`](docs/benchmarks/). The comparison is
against a control that burns comparable CPU rather than against an idle machine,
because an idle machine is slower and comparing against it reverses the sign of
the result.

---

## Scope

### In scope

- HTTP/1.1 request and response tracing — method, path, status, timing — over
  both plaintext and TLS
- OpenSSL interception via uprobes, covering any runtime that dynamically links
  libssl, including Python, Ruby, PHP, C/C++, and distribution-packaged Node
- Go `crypto/tls` as a second, independent capture path, since Go does not
  link OpenSSL
- Connection correlation via kprobes and tracepoints
- CO-RE compilation, validated across multiple kernel versions
- OpenTelemetry export to Tempo and Prometheus/Mimir, visualized in Grafana
- Kubernetes DaemonSet deployment with scoped capabilities, and canary rollout
  via Helm and ArgoCD
- Terraform-provisioned multi-node test fleet

### Out of scope

- **HTTP/2 and gRPC.** Binary framing over TLS is a materially harder
  in-kernel parsing problem than HTTP/1.1 and is not attempted here.
- **Statically linked TLS.** A runtime that links OpenSSL into its own binary
  presents no shared library to attach to. Distribution-packaged Node links
  system OpenSSL and is traced; the official Node build links it statically and
  is not. The symbols remain exported in both cases, so this needs per-binary
  attachment rather than a new mechanism.
- **Database wire protocols** such as MySQL and PostgreSQL.
- **Cross-service trace context propagation.** The agent generates a trace ID
  per request, because an uninstrumented caller supplies no incoming context
  to propagate.
- **Multi-tenancy and RBAC** on the observability backend.
- **Non-Linux hosts.** eBPF is a Linux kernel subsystem by construction.

---

## Prerequisites

Functional and non-functional requirements are tracked in
[`docs/requirements.md`](docs/requirements.md). This section covers only what
is needed to build and run the agent.

| Component | Requirement |
| :--- | :--- |
| Kernel | Linux ≥ 5.8 with `CONFIG_DEBUG_INFO_BTF=y` |
| Toolchain | `clang` / `llvm` with BPF backend, `bpftool`, libbpf headers |
| Language | Go 1.25 or later, matching `go.mod` |
| Privileges | Five capabilities with `ALL` dropped; see [`docs/capabilities.md`](docs/capabilities.md) |

The agent never requires `--privileged`.

macOS and Windows cannot load eBPF programs.
[`scripts/lima-ebpf.yaml`](scripts/lima-ebpf.yaml) provisions a disposable
Ubuntu 24.04 VM with the complete toolchain for development on those hosts.

---

## Getting started

Provision the Linux development environment:

```bash
limactl start --name=ebpf scripts/lima-ebpf.yaml
limactl shell ebpf
```

Build and verify, inside the VM:

```bash
cd /workspace
make check      # verify kernel and toolchain prerequisites
make vmlinux    # generate bpf/vmlinux.h from the running kernel's BTF
make build      # compile BPF programs and the agent binary
```

`make check` validates BTF availability, JIT status, ring buffer support,
uprobe and tracepoint support, and OpenSSL symbol visibility, reporting
precisely what breaks if any check fails. The agent is designed to fail closed
with a clear error rather than load onto a node it cannot safely instrument.

Run `make help` for the full target list.

Every push is checked against three kernels: the artifacts are compiled once and
booted on 5.15, 6.1 and 6.6 in QEMU, because a matrix that rebuilds per kernel
would test the toolchain rather than the binary. [`docs/ci.md`](docs/ci.md)
describes each gate, what it protects against, and which ones were removed for
reporting noise.

---

## Repository layout

```text
bpf/                    kernel-side eBPF programs (C, clang -target bpf)
cmd/agent/              userspace agent entrypoint
internal/
  ebpf/                 program loading, map access, probe attachment
  proc/                 process discovery and symbol resolution
  http/                 HTTP/1.1 parsing from captured buffers
  correlate/            payload and socket events into request records
  otel/                 OpenTelemetry span and metric construction
  config/               agent configuration
samples/                unmodified sample applications for validation
deploy/
  compose/              local stack: Tempo, Prometheus, Grafana
  k8s/                  DaemonSet manifests, applied as-is
  helm/                 the same DaemonSet as a chart, with canary overlays
  terraform/            multi-node test fleet provisioning
docs/
  adr/                  architecture decision records
  benchmarks/           raw overhead and load-test results
  diagrams/             architecture and data-path diagrams
scripts/                environment provisioning and verification
  ci/                   checks the CI matrix runs inside each kernel VM
test/
  toolchain/            loads a program into the kernel: the build pipeline works
  verifier/             what the verifier accepts and rejects, recorded
```

Unit tests live beside the code they test, in `internal/`. Load and integration
testing is done by the scripts in `scripts/`, against the real sample
applications rather than against mocks.

---

## Design decisions

Non-obvious decisions are recorded as ADRs in [`docs/adr/`](docs/adr/), each
stating the alternatives considered and what the choice gives up. They are
written at the point the decision is made rather than collected afterwards;
the schedule is in [`docs/ROADMAP.md`](docs/ROADMAP.md).

| ADR | Decision |
| :--- | :--- |
| 001 | DaemonSet rather than sidecar |
| [002](docs/adr/002-uprobes-on-tls-entry-points.md) | Capture plaintext at TLS library entry points |
| [003](docs/adr/003-tracepoints-over-kprobes.md) | Prefer tracepoints, record where a kprobe is unavoidable |
| [004](docs/adr/004-core-over-bcc.md) | Compile once with CO-RE rather than per host with BCC |
| [005](docs/adr/005-generated-trace-ids.md) | Generate a trace ID per request, propagate no context |
| [006](docs/adr/006-capability-scoping.md) | Enumerated capabilities, including `CAP_SYS_ADMIN`, rather than privileged |
| 007 | Canary rollout rather than fleet-wide apply |

---

## Security posture

The agent runs with elevated kernel privileges by necessity: it reads process
memory via uprobes and requires `hostPID` in its Kubernetes deployment. It
does not run `--privileged`.

The agent needs `CAP_SYS_ADMIN` to attach uprobes — measured, not assumed, and
close to root. It also runs with AppArmor unconfined: under the container
runtime's default profile it starts, reports no error, and traces fewer than
half the processes on the node. It is still not `--privileged` — seccomp
filtering and device isolation remain — but the distance is smaller than a
capability list suggests. [`docs/capabilities.md`](docs/capabilities.md) records
what each capability enables and what breaks without it;
[`deploy/k8s/README.md`](deploy/k8s/README.md) records the container-level
measurements.

Only request metadata is captured — method, path, status, and timing. Request
and response bodies are never persisted or exported, despite passing through
the capture path in plaintext.

A compromised agent holding these capabilities could observe plaintext traffic
across the entire node. The exact capability set, the operation each one
enables, and the full threat model are documented alongside the deployment
manifests in Phase 4.

---

## License

Not yet licensed.
