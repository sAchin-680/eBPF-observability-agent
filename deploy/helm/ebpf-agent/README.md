# ebpf-agent chart

The agent as a DaemonSet, packaged so that a canary is an installation rather
than an edit.

```bash
kubectl apply -f deploy/k8s/00-namespace.yaml
helm install stable deploy/helm/ebpf-agent -n ebpf-observability \
  -f deploy/helm/ebpf-agent/values-stable.yaml
```

The namespace is applied separately and deliberately — see below.

---

## Canary

A canary is this same chart, installed a second time, under its own release
name, restricted to nodes carrying a label:

```bash
helm install canary deploy/helm/ebpf-agent -n ebpf-observability \
  -f deploy/helm/ebpf-agent/values-canary.yaml \
  --set image.tag=<new build>

kubectl label node <node> observability/agent-channel=canary
```

Nothing differs between the two releases except the image tag and where each
runs. What is on trial is the build, not the configuration.

Promotion is a label change, not an edit to either release:

```bash
kubectl label node <node> observability/agent-channel-      # back to stable
```

Verified on a three-node cluster: canary on one node, stable on the other two,
and removing the label moved that node back to stable with no change to either
release.

### Why stable uses affinity and canary uses nodeSelector

Mirroring the canary — a `nodeSelector` for `agent-channel=stable` — is the
obvious approach and is wrong in a way that produces no error. A node carrying
neither label is then selected by neither release, runs no agent, and reports
nothing, which is indistinguishable from a node with no traffic. Observed
exactly that on the control-plane node before the affinity form replaced it.

`values-stable.yaml` expresses stable as *not the canary*:

```yaml
- key: observability/agent-channel
  operator: NotIn
  values: [canary]
```

so coverage is the default. A node has to be explicitly labelled to leave the
stable release, and a node that joins the cluster tomorrow is traced without
anyone remembering to label it.

Note the one gap this leaves: during promotion the canary pod is deleted before
the stable pod is scheduled, so that node is briefly untraced. Seconds, and
visible as a dip in attached targets rather than as an error.

---

## The namespace is not in this chart

Helm writes its release record as a Secret into the release namespace, so the
namespace must exist before any template is applied. A chart containing its own
release `Namespace` fails on a clean cluster:

```
Error: INSTALLATION FAILED: create: failed to create: namespaces "ebpf-observability" not found
```

`--create-namespace` is not the fix either. It creates an unlabelled namespace,
and this namespace carries the Pod Security Admission labels that permit the
agent's capability set. On a cluster enforcing PSA, an unlabelled namespace
rejects every pod the chart schedules. So the namespace is applied first, from
[`deploy/k8s/00-namespace.yaml`](../../k8s/00-namespace.yaml), where it lives in
version control next to its labels — and it is owned by neither release, so
uninstalling one does not take down the other.

---

## Values

| Key | Default | Notes |
| :--- | :--- | :--- |
| `image.repository` | `ghcr.io/sachin-680/ebpf-observability-agent` | |
| `image.tag` | `""` | falls back to the chart's `appVersion`; overriding it is how a canary runs a different build |
| `otlpEndpoint` | `tempo.observability.svc.cluster.local:4317` | empty disables trace export and leaves metrics running |
| `metrics.port` | `9464` | |
| `metrics.annotations` | `true` | Prometheus scrape annotations; no ServiceMonitor, which would need a CRD |
| `nodeSelector` | `{}` | the canary overlay sets this |
| `affinity` | `{}` | the stable overlay sets this |
| `tolerations` | `[{operator: Exists}]` | every node, tainted ones included |
| `updateStrategy.rollingUpdate.maxUnavailable` | `1` | blast-radius control, not throughput |
| `priorityClassName` | `system-node-critical` | eviction silently stops tracing that node |
| `resources` | 100m / 128Mi, memory limit 512Mi | no CPU limit; see below |
| `tracefsPath` | `/sys/kernel/tracing` | some nodes mount it under `/sys/kernel/debug/tracing` |
| `rbac.create` | `true` | ServiceAccount only — no Role, token not mounted |

**No CPU limit by default.** Throttling the agent during a traffic spike makes
it drop ring buffer events, which corrupts the telemetry rather than delaying
it. The memory limit stays: a leaking agent should be killed, not left to
pressure the node it exists to observe.

### What is not configurable

The capability set, `hostPID`, the AppArmor profile and the tracefs mount are
fixed in the template, not exposed as values. Each was established by removing
it and observing what broke — `docs/capabilities.md`, `deploy/k8s/README.md`,
ADR-006 — and most of those failures are silent. Dropping `CAP_SYS_PTRACE`
costs three of seven targets and logs nothing; enforcing the default AppArmor
profile does the same. A values file that invites an operator to trim the list
invites a silent loss of coverage.

Changing them means editing `templates/daemonset.yaml`, where the reasoning sits
next to the value.

---

## Drift

`deploy/k8s/` and this chart describe the same pod, and duplication like that
diverges quietly. [`scripts/helm-diff-manifests.sh`](../../../scripts/helm-diff-manifests.sh)
renders the chart and diffs the pod spec against the raw manifest, ignoring
release-scoped names. It runs as part of `make verify`, and it has already
caught one difference.
