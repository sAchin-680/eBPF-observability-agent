---
name: Bug report
about: Something behaves differently from what is documented
labels: bug
---

## What happened

## What was expected

## Environment

Most failures in this agent are environmental, and these answer most of them
before anyone reads the code.

```
kernel:        # uname -r
architecture:  # uname -m
BTF present:   # ls -l /sys/kernel/btf/vmlinux
agent version: # the image tag, or the build it was run from
```

Running under Kubernetes? Include the `securityContext` the pod actually got
(`kubectl get pod <name> -o yaml`), not the one in the manifest.

## Agent output

The startup lines matter most — how many targets it attached to, and whether
anything was skipped:

```
```

## Silent, or loud?

- [ ] The agent reported an error
- [ ] The agent looked healthy and produced less than expected

The second is the harder case and the more useful report. If coverage was lower
than expected, say what you expected to be traced and what was.
