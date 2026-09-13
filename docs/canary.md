# Canary verification

Whether a canary is safe to promote, decided by measurement rather than by
whether the pods came up.

Reproduce with `scripts/gate-canary.sh`, from inside the cluster VM.

---

## What is compared

The agent runs on every node with `CAP_SYS_ADMIN` and attaches probes into
other processes' memory. The question a canary has to answer is not whether it
produces telemetry — Phase 1 answered that — but whether the node is still
healthy with it there and the applications on it are unaffected.

Four axes, under identical load applied to both nodes at the same time:

| Axis | Threshold | Why this one |
| :--- | :--- | :--- |
| traced-application health | zero failures; median request within 1.25× of the control | what a user of the traced service would notice |
| node CPU | within 1.30× of the control | the agent's cost falls on the node, not on the service |
| kernel log | no BPF, uprobe, verifier, taint or segfault messages | a faulty BPF program appears here before anywhere else |
| agent self-health | zero restarts, zero ring buffer drops, non-zero attach count | the three failures that produce no error elsewhere |

The attach-count check is there because an agent that attaches to nothing looks
exactly like a healthy one: it runs, serves metrics, reports Ready, and
produces no telemetry. That is the failure this project keeps returning to.

---

## The control arm

The comparison is against another node running the **previous build of the
agent**, not against a node running nothing. A canary measured against an
unmonitored node measures the agent's existence rather than the change.

Choosing that node turned out to matter more than expected. The first version
took whichever stable node the API listed first, which was the control-plane
node:

```
ebpf-worker (canary)        2.6%
ebpf-control-plane (stable) 17.2%
within 1.30x of the stable node (ratio 0.15)
```

A ratio of 0.15 passes whatever the canary is doing, including burning CPU —
the control-plane node runs the API server and is busy for reasons that have
nothing to do with the agent. A threshold that cannot be exceeded is not a
threshold. The gate now requires the control to share the canary node's role,
and says so explicitly when no such node exists.

Same fix in the same spirit as the benchmark work in
[`benchmarks/`](benchmarks/README.md), where comparing against an idle machine
reversed the sign of the result.

---

## Result

Kernel 6.8, three-node kind cluster, both releases on the chart from
`deploy/helm/ebpf-agent`.

```
1. Both releases are deployed, on disjoint nodes
   canary  -> ebpf-worker
   stable  -> ebpf-control-plane ebpf-worker2
   disjoint: comparing ebpf-worker against ebpf-worker2
   identical images: this run exercises the rollout, not a new build

3. Node CPU during the load
   ebpf-worker (canary)   2.1%
   ebpf-worker2 (stable)  1.8%
   within 1.30x of the stable node (ratio 1.17)

4. Traced-application health
   canary node            RESULT ok=300 failed=0 mean_ms=4.13 p50_ms=3.80
   stable node            RESULT ok=300 failed=0 mean_ms=4.10 p50_ms=3.75
   median request within 1.25x of stable (ratio 1.01)

5. Kernel log
   no BPF, uprobe, verifier or taint messages since this run started

6. Agent self-health
   canary   ebpf-worker    restarts=0 drops=0 attached=1
   stable   ebpf-worker2   restarts=0 drops=0 attached=1

PASS — the canary node is as healthy as the stable node on every axis
```

Both releases ran the same image here, so what this run demonstrates is the
rollout mechanism and the gate, not a new build. The gate prints that caveat
itself rather than letting a green run imply more than it showed.

---

## The gate can fail

A gate that has never failed is a gate nobody has tested. Pinning a busy-loop
pod to the canary node and re-running it:

```
3. Node CPU during the load
   ebpf-worker (canary)   99.0%
   ebpf-worker2 (stable)  0.5%
   canary node CPU is 198.00x the stable node (limit 1.30x)

4. Traced-application health
   canary node            RESULT ok=300 failed=0 mean_ms=4.24 p50_ms=3.94
   stable node            RESULT ok=300 failed=0 mean_ms=4.02 p50_ms=3.75
   median request within 1.25x of stable (ratio 1.05)

FAIL — do not promote
```

Worth reading the second block as carefully as the first. With one core pegged,
**request latency barely moved** — 3.94 ms against 3.75 ms, well inside the
threshold. The node had capacity elsewhere, so the application noticed nothing
while the node was in trouble.

That is the argument for measuring all four axes rather than just the one the
user experiences. Latency alone would have promoted this canary.

---

## What kind cannot show

Two limitations, both properties of the test environment rather than the agent:

**The kernel log is host-wide.** kind nodes share one kernel, so `dmesg` cannot
be attributed to the canary node. A clean log is still evidence; a dirty one
would need investigation before being blamed on the canary.

**Node CPU is container CPU.** A kind node is a container, so the figures are
not comparable to a real node's in absolute terms. Both arms are measured the
same way at the same moment, which is what the ratio needs.

Neither weakens the gate on a real cluster, where nodes are machines. They are
recorded because a number that looks precise and means something narrower than
it appears is worse than no number.

---

## Promotion

The gate prints the command on success:

```bash
kubectl label node <node> observability/agent-channel-
```

Removing the label returns the node to the stable release, because stable is
expressed as *not the canary* rather than as a label of its own. There is a
brief window during which the canary pod is terminating and the stable pod has
not yet started, and that node is untraced for a few seconds — visible as a dip
in attached targets, not as an error.
