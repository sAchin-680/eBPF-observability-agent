# Test fleet

Provisions the multi-node cluster the canary rollout runs on.

```bash
terraform init
terraform apply
```

Provisioning stops at the cluster. What runs *on* it is decided by git through
ArgoCD — see [`../argocd/`](../argocd/README.md). Terraform owning the
infrastructure and Argo owning the workloads is the boundary; both owning
deployments would mean two systems disagreeing about the same objects.

```
terraform ──▶ cluster, nodes, labels
                    │
argocd ─────▶ namespaces, releases, image tags
```

---

## What it builds

| | |
| :--- | :--- |
| 1 control plane | traced like any other node — a control plane excluded from tracing is a gap that looks like a quiet node |
| `worker_count` workers | default 2, minimum 2 |
| `canary_worker_count` labelled `observability/agent-channel=canary` | default 1 |

`worker_count` has a validation rule rather than a comment: with one worker the
canary is the entire fleet, and the gate has nothing to compare against.

### Only the canary nodes are labelled

Deliberately. The Helm chart selects the canary by requiring the label and
selects stable by requiring its *absence* (`NotIn [canary]`). That asymmetry is
what makes coverage the default: a node added tomorrow with no label at all is
traced by the stable release rather than by neither. Labelling the rest
"stable" would look tidier and would reintroduce exactly the silent gap the
asymmetry prevents — one observed on a real node, in
[`../helm/ebpf-agent/README.md`](../helm/ebpf-agent/README.md).

---

## Why kind, and why through the CLI

**Why kind rather than cloud instances.** The fleet exists to exercise rollout
mechanics — a canary node, a stable node, node labels, a DaemonSet rolling one
node at a time. None of that needs separate machines. What *would* need them is
kernel variation, and that is tested far more rigorously elsewhere: the CI
matrix boots real 5.15, 6.1 and 6.6 kernels in QEMU on every push
([`../../docs/ci.md`](../../docs/ci.md)). A cloud module here would add expense
and a second thing to keep working, in exchange for a kernel axis that is
already covered.

The honest limitation: **kind nodes share one kernel**, so this fleet cannot
show a problem that only appears on one kernel, and `hostPID` in a kind pod is
the node container's namespace rather than the host's. Both are recorded in
[`../../deploy/k8s/README.md`](../k8s/README.md).

**Why the kind CLI rather than the `tehcyx/kind` provider.** The provider was
tried first. It vendors its own copy of kind as a library, which lags the
released binary, and against the node image this project uses everywhere else
it fails during creation:

```
could not find a log line that matches "Reached target .*Multi-User System.*"
```

The available fix is to pin an older Kubernetes version for Terraform alone —
which would mean the fleet Terraform builds is not the fleet everything else was
tested against. Calling the same binary a person would call keeps those
identical.

What that costs: Terraform cannot see drift *inside* the cluster. It knows the
cluster exists and what configuration created it, and no more. Acceptable here,
because what runs on the cluster is Argo's business and drift there is reverted
by `selfHeal`.

---

## Host prerequisites

**inotify limits.** Running a second kind cluster on the same host fails at node
startup with the error quoted above — the same message, from a completely
different cause, which is what made it slow to diagnose:

```bash
sudo sysctl -w fs.inotify.max_user_instances=512
sudo sysctl -w fs.inotify.max_user_watches=524288
```

The default 128 instances is enough for one cluster and not two. Nothing in the
error mentions inotify.

**Docker access.** Where the docker socket needs root, Terraform is run under
`sudo`, and kind then writes *root's* kubeconfig. The module runs
`kind export kubeconfig` explicitly for that reason: without it the apply
succeeds and the cluster is invisible to the user who ran it, which reads as the
fleet not having been created.

---

## Verified

Applied and destroyed on kernel 6.8, alongside an existing cluster:

```
$ terraform apply -var cluster_name=ebpf-tf -var worker_count=2
canary_nodes = ["ebpf-tf-worker"]
stable_nodes = ["ebpf-tf-control-plane", "ebpf-tf-worker2"]

$ kubectl get nodes -L observability/agent-channel
NAME                    STATUS   ROLES           VERSION   AGENT-CHANNEL
ebpf-tf-control-plane   Ready    control-plane   v1.34.0
ebpf-tf-worker          Ready    <none>          v1.34.0   canary
ebpf-tf-worker2         Ready    <none>          v1.34.0

$ terraform destroy
Destroy complete! Resources: 2 destroyed.
```

The labels match the outputs, and destroy removes the cluster without touching
the other one on the same host.
