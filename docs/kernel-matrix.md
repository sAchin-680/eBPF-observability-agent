# Kernel compatibility

One compiled binary, more than one kernel. This is the claim CO-RE exists to
support, and the reason the agent is compiled once rather than on every host.

Reproduce with `scripts/kernel-check.sh` on each kernel, using the same binary
every time.

---

## Result

Binary `sha256 fb600b07…`, built once on 6.8 and run unmodified on both.

| Check | 5.15.0-190 | 6.8.0-138 |
| :--- | :--- | :--- |
| Kernel exposes BTF | pass — 5,997,320 bytes | pass — 6,972,891 bytes |
| Agent loads, relocations resolve | pass | pass |
| Verifier accepts every program | pass | pass |
| Probes attach | pass — 2 targets | pass — 6 targets |
| Socket endpoint capture | pass — kprobe attached | pass — kprobe attached |
| Captures TLS payloads | pass — 23 events | pass — 24 events |
| Reports its own health | pass | pass |
| Detaches cleanly | pass | pass |
| | **8 passed** | **8 passed** |

The differing target counts are not a discrepancy. The 5.15 host runs fewer Go
binaries, so there is less to attach to; both attached everything present.

---

## Why this is a test of the artifact

The 5.15 host has no compiler and no Go toolchain, and mounts the working tree
read only. It cannot rebuild the thing it is testing. The binary's checksum is
reported by the check itself, so two runs can be shown to have exercised the
same file rather than two builds that happened to agree.

Building on each kernel would test the toolchain. NFR5 is a claim about the
artifact, so the artifact is what travels.

---

## What spanning these two versions exercises

**Struct layouts differ.** The agent reads `sock_common` for socket endpoints and
`task_struct` for process identity. Field offsets are not stable across this
range, and the binary carries relocations rather than fixed offsets precisely
because of that. A failure would appear at load, not as wrong data — which is
the property that makes the approach safe to deploy widely.

**The socket probe had no guarantee.** It attaches to `tcp_sendmsg`, an internal
symbol, which ADR-003 records as a deliberate exception to preferring
tracepoints. It attached on both kernels here, so the risk that decision
accepted did not materialise across this range. That is worth stating as an
observation rather than as reassurance: the symbol is still unstable, the
degradation path is still implemented, and a wider range may well exercise it.

---

## What this does not establish

- **Two versions, not a range.** 5.15 and 6.8 bracket useful ground but do not
  demonstrate everything between or beyond them.
- **One architecture.** Both are aarch64. The Go register ABI differs on x86-64
  from the C macros the probes use, which is a known and unexercised gap.
- **One distribution.** Both are Ubuntu, so both carry BTF and are configured
  similarly. A kernel built without `CONFIG_DEBUG_INFO_BTF` is covered by the
  failure matrix rather than here.
