# GitOps

The fleet's configuration is what is on `main`. Promotion is a commit.

Mechanics and the manifests are in
[`deploy/argocd/`](../deploy/argocd/README.md); this records what happened when
it was run.

---

## Demonstrated

ArgoCD v2.13.3 on the three-node kind cluster, pulling this repository from
GitHub. One root Application applies the two child Applications, which point at
the same Helm chart with different values files and image tags.

```
NAME                SYNC     HEALTH    REV
ebpf-agent-canary   Synced   Healthy   f4f2dfb
ebpf-agent-root     Synced   Healthy   f4f2dfb
ebpf-agent-stable   Synced   Healthy   f4f2dfb
```

### A commit changed what runs on a node

[PR #40](https://github.com/sAchin-680/eBPF-observability-agent/pull/40) changed
one line in `deploy/argocd/apps/canary.yaml`:

```yaml
        - name: image.tag
-         value: 0.3.1-phase4
+         value: 0.2.0-phase2
```

Nothing else was run — no `kubectl`, no `helm`. After the merge:

```
canary-ebpf-agent  ...:0.2.0-phase2      ← the commit
stable-ebpf-agent  ...:0.3.1-phase4      ← untouched
```

[PR #41](https://github.com/sAchin-680/eBPF-observability-agent/pull/41)
restored it, and the fleet converged again:

```
canary-ebpf-agent  ...:0.3.1-phase4
stable-ebpf-agent  ...:0.3.1-phase4
```

That both releases end on the same tag is the correct resting state: the canary
label stays on its node so the next rollout has somewhere to land, and no node
is left running something different from the rest of the fleet.

---

## Promotion is two commits, not one

```
1. edit apps/canary.yaml   → canary node only
2. scripts/gate-canary.sh  → read the output
3. edit apps/stable.yaml   → the rest of the fleet
```

**The gate is deliberately not a sync hook.** Wiring `gate-canary.sh` in as a
PreSync hook would make promotion automatic, which sounds like the goal. It is
not. The crash the gate caught in [rollout.md](rollout.md) appeared as one line
— `restarts=1` — beside four passing checks, and the value of it was a person
noticing something that had not been anticipated. Automating that away requires
knowing in advance what to fail on, which is exactly what was missing.

The decision to expose every node in the fleet to a new kernel-side program is
worth a human step.

---

## What `selfHeal` costs, and why it is on

An edit made with `kubectl` is reverted to what git says, usually within
seconds.

This is least welcome in the case that matters most: during an incident, when
someone patches the DaemonSet directly to stop the bleeding. That patch will be
undone, and the correct response is a commit. The discipline is paid for
precisely when it is most irritating — which is the argument for it, because
the alternative is a fleet whose real configuration exists only in one person's
shell history.

`prune: true` is the same idea from the other direction: a file deleted from git
is deleted from the cluster, so the repository cannot quietly stop describing
what is running.

---

## Argo polls; it does not receive

Argo checks the repository roughly every three minutes. Both demonstrations
above were refreshed by hand to avoid waiting:

```bash
kubectl -n argocd patch app ebpf-agent-root --type merge \
  -p '{"metadata":{"annotations":{"argocd.argoproj.io/refresh":"hard"}}}'
```

In a real deployment a webhook removes that delay. It is worth stating plainly
rather than implying that a merge takes effect instantly: between merge and
sync there is a window in which git and the cluster disagree, and that window is
minutes by default.
