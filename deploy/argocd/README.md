# GitOps

The fleet's configuration is what is in this repository on `main`. Promotion is
a commit; there is no promote command and no kubectl.

```bash
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/v2.13.3/manifests/install.yaml
kubectl apply -f deploy/argocd/root.yaml      # once; everything else via git
```

---

## Shape

```
                    git push to main
                           │
                           ▼
                 ebpf-agent-root  (watches deploy/argocd/apps/)
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
     ebpf-agent-canary          ebpf-agent-stable
     (labelled node)            (every other node)
              │                         │
              └──── deploy/helm/ebpf-agent, different values ────┘
```

The root Application applies the others. Without it, the manifests that decide
what runs on the fleet would themselves be applied by hand — the one thing
outside the system that is supposed to govern what runs on the fleet.

Both children point at the same chart. The only differences are the values file
(which nodes) and the image tag (which build), which is what keeps a canary a
test of the build rather than of the configuration.

---

## Promoting a build

```
1. edit deploy/argocd/apps/canary.yaml     image.tag: <new>
2. commit, push                            → canary node only
3. scripts/gate-canary.sh                  → read the output
4. edit deploy/argocd/apps/stable.yaml     image.tag: <new>
5. commit, push                            → the rest of the fleet
```

Two commits, not one, and deliberately so. Step 3 is a person reading evidence.

### The gate is not a sync hook

Wiring `gate-canary.sh` in as a PreSync hook would make promotion automatic and
is the obvious next step. It is not done, because the decision to expose every
node in the fleet to a new kernel-side program should be taken by someone who
looked at the measurements — and a green check is not the same as having looked.
The gate that caught a crash in [`../../docs/rollout.md`](../../docs/rollout.md)
reported `restarts=1` next to four passing checks; automation would have needed
that one line to be fatal in advance, and the value of reading it was noticing
something that had not been anticipated.

`scripts/rollout.sh` is the same sequence driven imperatively, for a cluster
without Argo.

---

## What `selfHeal` changes

An edit made with kubectl is reverted to what git says, usually within seconds.

This matters most in the case it is least welcome: during an incident, when
someone edits the DaemonSet directly to stop the bleeding. That edit will be
undone. The correct response is a commit, and the cost of that discipline is
paid exactly when it is most annoying — which is the point, because the
alternative is a fleet whose real configuration exists only in one person's
shell history.

`prune: true` is the same principle: a file deleted from git is deleted from the
cluster, so the repository cannot quietly stop describing what is running.

---

## Namespaces

`CreateNamespace=false` on both children, deliberately. The agent's namespace
carries the Pod Security Admission labels that permit its capability set — a
namespace created implicitly by Argo would not have them, and on a cluster
enforcing PSA every pod would be rejected. It is applied once from
[`../k8s/00-namespace.yaml`](../k8s/00-namespace.yaml) and owned by neither
release, so removing one Application cannot take down the other.

---

## Reaching the UI

Argo's server has no ingress here; it is reached by port-forward.

```bash
kubectl -n argocd port-forward svc/argocd-server 8080:443
kubectl -n argocd get secret argocd-initial-admin-secret \
  -o jsonpath='{.data.password}' | base64 -d
```

The dashboard that matters day to day is not this one — it is the agent
self-health dashboard in [`../../docs/rollout.md`](../../docs/rollout.md). Argo
tells you what it applied; that tells you whether it was a good idea.
