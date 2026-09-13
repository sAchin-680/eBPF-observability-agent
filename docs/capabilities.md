# Capabilities

What privilege the agent needs, established by removing it until things break.

Reproduce with `scripts/capabilities.sh`. Capabilities are attached to the
binary with `setcap` and the agent runs as an ordinary user, which is how a
Kubernetes `securityContext` grants them. Running as root and dropping
capabilities would test something different: root bypasses several permission
checks outright, so a set that works for root can fail for a user holding the
same capabilities.

---

## Result

Kernel 6.8.0-138, aarch64, `perf_event_paranoid=4`.

| Capability set | Outcome |
| :--- | :--- |
| `cap_bpf` | does not start |
| `cap_bpf,cap_perfmon` | does not start |
| `cap_bpf,cap_perfmon,cap_dac_read_search` | loads, attaches nothing |
| `+cap_sys_ptrace` | loads, attaches nothing |
| `+cap_sys_resource` | loads, attaches nothing |
| `cap_sys_admin,cap_dac_read_search` | **works** — 4 targets |
| `cap_bpf,cap_perfmon,cap_sys_admin,cap_sys_ptrace,cap_dac_read_search` | **works** — 7 targets |
| root, for comparison | works — 8 targets |

**`CAP_BPF` and `CAP_PERFMON` are not sufficient.** NFR4 stated that pair as the
requirement. It is wrong, and the agent cannot run under it.

---

## What each capability is actually for

| Capability | Enables | Without it |
| :--- | :--- | :--- |
| `CAP_BPF` | loading programs and creating maps | `bpf()` is refused |
| `CAP_SYS_ADMIN` | attaching a uprobe through `perf_event_open` | every attach fails with `permission denied`; the agent runs and captures nothing |
| `CAP_DAC_READ_SEARCH` | reading `/proc/self/mem`, and other processes' files through `/proc/<pid>/root` | the agent cannot start |
| `CAP_SYS_PTRACE` | reading other processes' `/proc` entries during discovery | starts and works, but finds 4 targets instead of 7 |
| `CAP_PERFMON` | nothing observable here, given `CAP_SYS_ADMIN` | — |

`CAP_PERFMON` is retained despite having no measurable effect alongside
`CAP_SYS_ADMIN`, because it is the capability that *should* govern this on a
kernel where the uprobe path is relaxed, and dropping it would make the manifest
depend on today's kernel behaviour.

---

## Two findings worth stating plainly

### Granting capabilities creates the need for more of them

`cap_bpf` alone does not fail at `bpf()`. It fails here:

```
detecting kernel version: opening mem: open /proc/self/mem: permission denied
```

A binary that gains capabilities through `setcap` is no longer dumpable, so the
kernel reassigns its own `/proc` entries to root. The process then cannot read
its own memory map without `CAP_DAC_READ_SEARCH`. Granting privilege is what
created the need for further privilege, and the failure names a file that has
nothing obviously to do with BPF.

This is not specific to this agent. Anything that reads `/proc/self/*` and is
granted file capabilities meets it.

### The uprobe requirement is not `perf_event_paranoid`

`CAP_SYS_ADMIN` looked like it might be standing in for a relaxed sysctl, since
Ubuntu ships `perf_event_paranoid=4` where upstream defaults to 2. It is not.
With the sysctl lowered to `-1`, which disables the restriction entirely, the
same capability set still fails:

```
kernel.perf_event_paranoid = -1
cap_bpf,cap_perfmon,cap_dac_read_search
  attached: 1 target, 0 events, 9 permission denied
```

Attaching a uprobe through `perf_event_open` requires `CAP_SYS_ADMIN` on this
kernel irrespective of the sysctl. The sysctl was restored afterwards; it is not
a mitigation and should not be relaxed in its place.

---

## What this means for deployment

**`CAP_SYS_ADMIN` is required, and it is close to root.** It is worth being
direct about that rather than presenting the capability list as if it were a
meaningful reduction in the common case.

**It is still not `--privileged`, but the gap is narrower than capabilities
alone suggest.** Measured in a container afterwards: the agent must also run
with AppArmor unconfined, because the runtime's default profile permits
`ptrace` and `/proc` access only against peers under the same profile, and
under it the agent silently traces containers and not the host. So one of the
two confinements `--privileged` disables has to be given up anyway. What is
kept: seccomp filtering, device isolation, and an enumerated capability set
rather than all of them. A compromised agent under this set can trace and read
process memory; under `--privileged` it can additionally load kernel modules
and write to any device. See
[`deploy/k8s/README.md`](../deploy/k8s/README.md) for that experiment.

**The blast radius is unchanged by any of this.** An agent that can attach
uprobes can read plaintext for every process on the node. That is what the agent
is for, and no capability set makes it smaller. The mitigation is what the agent
does with what it reads — only method, path, status and timing leave the
process — not the privilege it holds.

---

## The manifest

```yaml
securityContext:
  privileged: false
  runAsNonRoot: false          # /proc/<pid>/root traversal needs uid 0
  appArmorProfile:
    type: Unconfined           # the default profile silently halves coverage
  seccompProfile:
    type: RuntimeDefault       # measured to cost nothing, so it stays
  capabilities:
    drop: ["ALL"]
    add:
      - CAP_BPF                # load programs, create maps
      - CAP_PERFMON            # perf subsystem; see the note above
      - CAP_SYS_ADMIN          # attach uprobes via perf_event_open
      - CAP_SYS_PTRACE         # read other processes' /proc entries
      - CAP_DAC_READ_SEARCH    # read /proc/self/mem and files via /proc/<pid>/root
```

`drop: ["ALL"]` first is what makes this a list rather than a suggestion:
without it the container keeps the runtime's defaults and the enumeration above
describes nothing.
