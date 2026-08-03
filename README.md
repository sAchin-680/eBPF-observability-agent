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

Full high- and low-level design, including the detailed data-path diagram,
lives in [`docs/architecture.md`](docs/architecture.md).

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

This repository is under active development. The table reflects the actual
state, not the target state. Capabilities are marked complete only when backed
by a passing test or a recorded benchmark.

| Capability | Status |
| :--- | :--- |
| Reproducible Linux development environment, BTF-verified | Complete |
| BPF build pipeline (`vmlinux.h` generation, `bpf2go` codegen) | Complete |
| Uprobe capture of OpenSSL `SSL_write` / `SSL_read` | In progress |
| Go `crypto/tls` capture path | Not started |
| Socket-level connection correlation | Not started |
| HTTP/1.1 request and response reconstruction | Not started |
| OpenTelemetry export to Tempo and Prometheus | Not started |
| Kubernetes DaemonSet deployment | Not started |
| Measured overhead and ring buffer drop-rate benchmarks | Not started |

The phase plan is in [`docs/ROADMAP.md`](docs/ROADMAP.md).

---

## Scope

### In scope

- HTTP/1.1 request and response tracing — method, path, status, timing — over
  both plaintext and TLS
- OpenSSL interception via uprobes, covering any runtime that links libssl,
  including Python, Ruby, PHP, and C/C++
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
- **Node.js TLS internals.** Node bundles its own BoringSSL variant; this is a
  known gap rather than a solved case.
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
| Language | Go 1.23 or later |
| Privileges | `CAP_BPF` + `CAP_PERFMON`, or `CAP_SYS_ADMIN` on older kernels |

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
  helm/                 Kubernetes DaemonSet chart
  terraform/            multi-node test fleet provisioning
docs/
  adr/                  architecture decision records
  benchmarks/           raw overhead and load-test results
  diagrams/             architecture and data-path diagrams
scripts/                environment provisioning and verification
test/
  unit/                 parser and correlation logic
  integration/          full pipeline against sample applications
  load/                 overhead and drop-rate benchmarks
```

---

## Design decisions

Every non-obvious decision is recorded as an ADR in [`docs/adr/`](docs/adr/),
with the alternatives considered and what each choice gives up.

| ADR | Decision |
| :--- | :--- |
| [001](docs/adr/001-daemonset-not-sidecar.md) | DaemonSet rather than sidecar |
| [002](docs/adr/002-uprobes-on-tls.md) | uprobes on TLS read/write rather than traffic mirroring |
| [003](docs/adr/003-tracepoints-over-kprobes.md) | Tracepoints over kprobes where both exist |
| [004](docs/adr/004-core-over-bcc.md) | CO-RE rather than BCC |
| [005](docs/adr/005-generated-trace-ids.md) | Per-request generated trace IDs, no context propagation |
| [006](docs/adr/006-capability-scoping.md) | `CAP_BPF` + `CAP_PERFMON` rather than `--privileged` |
| [007](docs/adr/007-canary-rollout.md) | Canary rollout rather than fleet-wide apply |

---

## Security posture

The agent runs with elevated kernel privileges by necessity: it reads process
memory via uprobes and requires `hostPID` in its Kubernetes deployment. It
does not run `--privileged`.

[`docs/security.md`](docs/security.md) documents the exact capability set and
the operation each capability enables, the blast radius should the agent be
compromised, and the data-handling posture — what is captured (method, path,
status, timing) and what is never persisted or exported (request and response
bodies).

---

## License

Not yet licensed.
