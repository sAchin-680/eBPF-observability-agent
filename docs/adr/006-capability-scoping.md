# ADR-006: Enumerated capabilities, including CAP_SYS_ADMIN, rather than privileged

**Status:** Accepted
**Date:** 2026-09-13

## Context

The agent loads BPF programs, attaches uprobes to other processes' libraries,
and reads those processes' `/proc` entries. All of that is privileged.

The project's non-functional requirement stated `CAP_BPF` and `CAP_PERFMON`,
never `--privileged`. That was written before anything was built, and it was a
reasonable expectation: those two capabilities exist precisely to let BPF tools
avoid `CAP_SYS_ADMIN`.

Measurement showed it is wrong. With `CAP_BPF` and `CAP_PERFMON` the agent does
not start, and the reason is not BPF — it cannot read `/proc/self/mem`, because
holding file capabilities makes a process non-dumpable and reassigns its own
`/proc` entries to root. With that fixed by `CAP_DAC_READ_SEARCH`, the agent
starts and attaches nothing: `perf_event_open` refuses every uprobe without
`CAP_SYS_ADMIN`, and lowering `perf_event_paranoid` to `-1` does not change it.

Full results in [capabilities.md](../capabilities.md).

## Decision

Run with `ALL` capabilities dropped and five added:
`CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`,
`CAP_DAC_READ_SEARCH`. Do not run `--privileged`. State plainly that
`CAP_SYS_ADMIN` is close to root rather than presenting the list as a large
reduction in privilege.

## Alternatives considered

**`CAP_BPF` and `CAP_PERFMON`, as originally required.** Does not work. Kept as
the target if a future kernel routes uprobe attachment through `CAP_PERFMON`,
which is what that capability was introduced for.

**Relax `perf_event_paranoid` instead.** Tested and does not help: at `-1`, which
disables the restriction entirely, uprobe attachment still fails. It would also
be worse if it had worked — a host-wide sysctl weakens every process on the node
to avoid one capability on one of them.

**Run `--privileged`.** Simpler, and would certainly work. It grants every
capability, disables seccomp and AppArmor confinement, and exposes all host
devices. The difference from the set above is not cosmetic: a compromised agent
under `--privileged` can load kernel modules and write to any device, which has
nothing to do with tracing.

**Drop `CAP_SYS_PTRACE`.** The agent runs without it, but discovery finds four
targets instead of seven, because it cannot read other processes' `/proc`
entries. That is a silent reduction in coverage rather than an error, which is
the failure mode this project most consistently tries to avoid.

**Narrow `CAP_DAC_READ_SEARCH` by making the agent dumpable.** Would remove the
`/proc/self/mem` problem at its source, but re-enabling dumpability on a process
holding `CAP_SYS_ADMIN` means any process with the same uid can read its memory.
That is a worse trade.

## Consequences

**A requirement was wrong and is now corrected rather than quietly restated.**
NFR4 said `CAP_BPF` and `CAP_PERFMON`. The document now says what is true and why,
and links to the experiment.

**The privilege reduction is real but modest.** `CAP_SYS_ADMIN` covers a large
surface. The honest claim is that confinement remains in place and device access
does not, not that the agent is unprivileged.

**The set is kernel-dependent.** It was established on 6.8. A kernel that routes
uprobe attachment differently would need it re-measured, which is why the script
is committed alongside the result.

**Blast radius is unchanged by the capability set.** An agent that can attach
uprobes can read plaintext for every process on the node. The mitigation is what
leaves the process — method, path, status and timing, never bodies — not the
capability list.
