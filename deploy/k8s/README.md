# Kubernetes deployment

Raw manifests for the agent, one pod per node.

```bash
make image                     # builds; needs bpf/vmlinux.h, which it generates
kubectl apply -f deploy/k8s/
```

Filenames are numerically prefixed because `kubectl apply -f <dir>` applies in
lexical order, and the DaemonSet cannot be created before its namespace.

The Helm chart in [`../helm/`](../helm/) renders to these. Both are kept: the
plain form can be read without running a templating engine, and `helm template`
can be diffed against it.

---

## What the pod needs, and why

Every item below was established by removing it and observing the failure, not
by copying a reference manifest. The capability set itself is covered
separately in [`docs/capabilities.md`](../../docs/capabilities.md) and ADR-006.

| Setting | Why | Without it |
| :--- | :--- | :--- |
| `hostPID: true` | discovery reads each process's mapped libraries through `/proc`, and reaches into container filesystems via `/proc/<pid>/root` | the agent sees only itself |
| `/sys/kernel/tracing` (read-only) | the `sched_process_exec` tracepoint's numeric id is readable only from tracefs | startup fails: *neither debugfs nor tracefs are mounted* |
| `appArmorProfile: Unconfined` | the runtime's default profile permits `ptrace` and `/proc` access only against peers under the same profile | **no error**; the agent traces other containers and is blind to the host — 3 targets instead of 7 |
| five capabilities, `ALL` dropped | load programs, attach uprobes, read other processes' `/proc` | varies by capability; see ADR-006 |
| `runAsUser: 0` | traversing `/proc/<pid>/root` into another container's filesystem | discovery finds nothing |

Three things a node agent is usually given that this one does not need:

- **`/sys/fs/bpf`** — for pinning programs so they outlive the process. The
  agent pins nothing: probes are torn down with it, so a crashed agent leaves
  no kernel state behind.
- **`/sys/kernel/debug` read-write** — only the legacy tracefs `uprobe_events`
  attach path writes there. Both supported kernels expose the uprobe PMU
  (`/sys/bus/event_source/devices/uprobe`: type 9 on 6.8, type 7 on 5.15), so
  uprobes go through `perf_event_open`. Read-only tracefs is enough.
- **`hostNetwork: true`** — the agent opens one port, for metrics. Putting it
  on the host network would risk a collision on 9464 for no gain; traces leave
  over an outbound OTLP connection.

`seccompProfile: RuntimeDefault` is kept. Tested with seccomp unconfined the
agent behaves identically, so the default profile costs nothing — `bpf()` and
`perf_event_open()` pass because the container holds `CAP_SYS_ADMIN`.

### The AppArmor finding

This is the one worth reading twice. Under the runtime's default profile the
agent starts cleanly, logs no error, reports itself healthy, and traces fewer
than half the processes on the node:

```
--- caps only ---                     tracing 0 TLS libraries and 3 Go binaries
--- caps + apparmor=unconfined ---    tracing 1 TLS library  and 6 Go binaries
--- caps + seccomp=unconfined ---     tracing 0 TLS libraries and 3 Go binaries
```

`docker-default` allows `ptrace (trace,read) peer=docker-default`, so the agent
can inspect processes in other containers and not processes on the host. The
three it found were containers; the four it missed were not.

Nothing about this is visible from the agent's own telemetry: attach count is
lower, and a lower attach count is indistinguishable from a node running less
software. It is the failure mode this project keeps returning to — coverage
that degrades without an error — and here it is produced by a security default
rather than by a bug.

It also narrows the distance to `privileged: true` more than the capability
list alone suggests. What remains: seccomp filtering, device isolation, and an
enumerated capability set rather than all of them.

---

## Verification

Two environments, testing different things.

### On a node — `--pid=host`, the faithful case

A container on a host, in the root PID namespace, which is what a DaemonSet pod
with `hostPID` gets on a real cluster:

```bash
docker run -d --name agent-test --pid=host \
  --cap-drop=ALL \
  --cap-add=BPF --cap-add=PERFMON --cap-add=SYS_ADMIN \
  --cap-add=SYS_PTRACE --cap-add=DAC_READ_SEARCH \
  --security-opt apparmor=unconfined \
  --read-only --tmpfs /tmp \
  -v /sys/kernel/tracing:/sys/kernel/tracing:ro \
  --network=host \
  ghcr.io/sachin-680/ebpf-observability-agent:latest \
  --otlp-endpoint= --metrics-addr=:9466
```

Result on kernel 6.8, against the four sample services: **7 targets attached,
90 events captured**, with a read-only root filesystem and `ALL` dropped.

### In kind — the API surface, not the PID namespace

```bash
kind create cluster --config scripts/kind-cluster.yaml
kind load docker-image ghcr.io/sachin-680/ebpf-observability-agent:0.2.0-phase2 --name ebpf
kubectl apply -f deploy/k8s/
```

Three nodes, three pods ready, including the tainted control-plane node. A
workload pod making continuous HTTPS calls was attached and produced **12,826
events**.

One caveat, and it is a property of kind rather than of the agent: a kind node
is a container with its own PID namespace, so `hostPID` there means the node
container's namespace, not the kernel's root namespace. BPF reports PIDs in the
root namespace, so the exec-tracepoint path hands userspace PID numbers that do
not resolve in the agent's `/proc`, and processes started *after* the agent are
missed. The startup scan is unaffected; `kubectl rollout restart ds/ebpf-agent`
re-runs it. On a real node the two namespaces are the same one.

---

## Known rough edge

Attaching to a very short-lived process can fail partway:

```
skipping SSL_read in /usr/lib/libssl.so.3:
  creating perf_uprobe PMU: token /proc/8236/root/usr/lib/libssl.so.3:0x26fe4:
  not found: no such file or directory
```

The library is resolved through `/proc/<pid>/root` once per symbol, and a
process that exits mid-attach invalidates the path between them — so some
entry points attach and others do not, leaving partial coverage of that
library. Holding one `O_PATH` descriptor for the file and attaching every
symbol through `/proc/self/fd/<n>` would close the window. Not yet done.
