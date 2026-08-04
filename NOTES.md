# Engineering notes

A running record of kernel quirks, verifier rejections, and environment
failures encountered while building the agent, captured as they occur.

Error output is recorded verbatim. A paraphrased verifier log loses the
register state and instruction offset, which is the part that explains the
failure.

Format per entry: context, symptom, cause, resolution.

---

## 2026-08-04 — Development environment

### Toolchain install aborted on an unavailable package

**Context:** First provisioning run of the Ubuntu 24.04 arm64 development VM.

**Symptom:** `scripts/check-env.sh` reported `clang not installed`, despite
clang being listed in the provisioning script. Provisioning log showed:

```
E: Package 'gcc-multilib' has no installation candidate
```

**Cause:** `gcc-multilib` exists to build 32-bit x86 binaries and has no arm64
candidate. `apt-get install` is atomic, so one unavailable package aborted the
entire transaction, silently skipping clang, llvm, libbpf-dev and bpftrace.
The reported symptom pointed nowhere near the cause.

**Resolution:** Removed `gcc-multilib` from `scripts/lima-ebpf.yaml`. It was
never required for BPF compilation.

### tracefs checks reported false negatives when run unprivileged

**Context:** Environment verification reported no uprobe or tracepoint support
on a kernel that plainly has both.

**Symptom:** `[ -e /sys/kernel/tracing/uprobe_events ]` evaluated false as a
normal user; the same test under `sudo` succeeded.

**Cause:** `/sys/kernel/tracing` is mode 0700, root-only. Path traversal fails
with `EACCES`, which a `test -e` reports identically to a missing file.
"Permission denied" and "does not exist" are indistinguishable through that
interface.

**Resolution:** `scripts/check-env.sh` now runs the tracefs probes under sudo
when not already root.

**Worth carrying forward:** this conflation recurs throughout eBPF work —
failed probe attachment, unreadable `/proc/<pid>/maps`, BTF access. When
something reports missing, confirm it is not merely unreadable.

### OpenSSL exports versioned symbols

**Context:** Confirming `SSL_write` is resolvable before committing to the
uprobe approach (ADR-002).

**Symptom:** `nm -D libssl.so.3 | grep -E ' T SSL_write$'` returned nothing,
initially suggesting the symbol was unavailable.

**Cause:** The symbol is exported as `SSL_write@@OPENSSL_3.0.0`. Symbol
versioning allows one shared library to export several ABI-incompatible
versions of the same function; the base name never appears unadorned. The
match pattern anchored on end-of-line and missed it.

```
569: 00000000000364e4  192 FUNC GLOBAL DEFAULT 12 SSL_write@@OPENSSL_3.0.0
677: 0000000000035de0  192 FUNC GLOBAL DEFAULT 12 SSL_read@@OPENSSL_3.0.0
```

**Resolution:** Match the base name up to the `@` separator.

**Open question for symbol resolution (Phase 1):** attaching by the name
`SSL_write` requires deciding how that string matches a versioned symbol, and
what to do when a library exports more than one version of it. A uprobe
resolves to `(inode, file offset)` — here offset `0x364e4` — so the name is a
convenience that some layer must reduce to a single address.

### BPF globals do not produce generated Go bindings

**Context:** Building the toolchain verification test.

**Symptom:**

```
test/toolchain/toolchain_test.go:48:17: objs.LastExecTgid undefined
	(type smokeObjects has no field or method LastExecTgid)
```

**Cause:** A global variable in BPF C is placed in `.bss`, which the kernel
exposes as a map named `.bss`. `bpf2go` generates no binding for it, because
`.bss` is not a valid Go identifier.

**Resolution:** Declared an explicit `BPF_MAP_TYPE_ARRAY` with `SEC(".maps")`
instead. This also exercises map creation, which the ring buffer data path
depends on.
