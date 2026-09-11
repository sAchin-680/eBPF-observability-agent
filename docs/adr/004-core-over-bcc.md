# ADR-004: Compile once with CO-RE rather than per host with BCC

**Status:** Accepted
**Date:** 2026-09-12

## Context

Kernel-side programs read kernel structures whose field offsets differ between
kernel versions. A program compiled against one kernel's layout reads the wrong
bytes on another — silently, since the read succeeds and returns whatever
occupies that offset.

The agent is intended to be deployed as a DaemonSet across a fleet whose nodes
do not all run the same kernel. Whatever resolves those offsets has to work
across that fleet without per-node intervention.

## Decision

Compile once, with CO-RE. Field accesses emit relocations rather than fixed
offsets, and the loader resolves them against the running kernel's own type
information at load time.

## Alternatives considered

**BCC, compiling on each host at load time.** Correct by construction, since the
program is compiled against the kernel it will run on. It requires a compiler
toolchain and kernel headers present on every node, adds seconds of compilation
to every agent start, and makes the agent's behaviour depend on toolchain
versions that vary across a fleet. For a DaemonSet this is a large amount of
machinery shipped to every node to solve a problem that can be solved once.

**Compiling one binary per kernel version.** Avoids both the relocation
machinery and the per-host toolchain, but requires knowing every kernel version
in the fleet ahead of time, building for each, and selecting correctly at deploy
time. A node upgraded out of band gets a binary compiled for a kernel it is no
longer running, with no error.

**Avoiding kernel structures entirely.** Some data can be obtained through
helpers that return values rather than structure pointers, which sidesteps the
problem. It does not cover the socket endpoints, which are read out of
`struct sock` and have no helper equivalent.

## Consequences

**One artifact.** The same binary is expected to load on every supported kernel,
which is what makes a fleet rollout a deployment rather than a build matrix.

**The kernel must expose BTF.** CO-RE depends on the kernel carrying its own type
information. A kernel built without it cannot be supported at all, which makes
this a hard prerequisite rather than a degradation, and is why environment
verification checks for it before anything else runs.

**Relocation failures surface at load, not at runtime.** A field that does not
exist on the target kernel fails the load with a diagnostic, rather than reading
a plausible wrong value. This is the property that makes the approach safe
enough to deploy widely.

**Cross-architecture builds need more than a cross-compiler.** The generated
type header comes from the running kernel, so it describes the build host's
architecture. Building for a foreign architecture requires that architecture's
type information as well — a packaging concern, but one that follows directly
from this decision.

**Verification is single-kernel so far.** The toolchain test proves relocation
against one kernel. The claim that one binary runs across several is not yet
demonstrated, and is recorded as unverified until the kernel matrix exists.
