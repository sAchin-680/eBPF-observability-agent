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

---

## 2026-09-12 — OpenSSL capture path

### Probe arguments cannot be compiled for a generic BPF target

**Context:** First build of the SSL uprobes with `bpf2go -target bpfel`.

**Symptom:**

```
error: The eBPF is using target specific macros, please provide -target that is
not bpf, bpfel or bpfeb
  note: expanded from macro 'BPF_UPROBE' ... 'PT_REGS_PARM1'
```

**Cause:** A uprobe receives the CPU register state at the call site, so
reading argument *n* means reading whichever register the platform ABI assigns
to it. `PT_REGS_PARMn` resolves that per architecture and refuses to compile
when the architecture is unknown. A generic little-endian BPF target therefore
cannot build any program that reads probe arguments.

**Resolution:** Named architectures instead. Naming a foreign architecture then
failed differently:

```
error: no member named 'di' in 'struct pt_regs'
```

`bpf/vmlinux.h` is generated from the running kernel's BTF, so `struct pt_regs`
carries the host layout — `di` is an x86 register name absent from the arm64
definition. Cross-architecture builds need a `vmlinux.h` per architecture, not
merely a per-architecture target. Settled on `-target native`; multi-architecture
release artifacts are deferred to deployment packaging.

### curl negotiates HTTP/2, so the first captured payload was not HTTP/1.1

**Context:** First successful capture, expecting an HTTP/1.1 request line.

**Symptom:**

```
WRITE len=64 data=PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
WRITE len=37 data=
READ  len=568 data=
```

**Cause:** curl negotiated HTTP/2 over ALPN. The first payload is the HTTP/2
connection preface; everything after is binary framing with HPACK-compressed
headers, so `%s` terminated immediately on a non-printable byte.

**Resolution:** `curl --http1.1` for capture testing.

**Worth carrying forward:** this is direct evidence for the HTTP/2 scope
exclusion. There is no request line to find in a single buffer — header state
lives in a compression context shared across frames and across requests on the
same connection. Protocol negotiation is also invisible from the probe, so an
agent cannot assume HTTP/1.1 simply because port 443 is in use.

### CPython calls SSL_write_ex and SSL_read_ex, not SSL_write and SSL_read

**Context:** curl traced correctly; Python produced no events at all.

**Symptom:** No events for `comm=python3`, despite the request succeeding and
Python loading the same library:

```
inode 3188  /lib/aarch64-linux-gnu/libssl.so.3
inode 3188  /usr/lib/aarch64-linux-gnu/libssl.so.3
```

**Cause:** The probes were attached correctly; CPython 3.12 simply calls
different functions.

```
python _ssl.so:  U SSL_read_ex@OPENSSL_3.0.0
                 U SSL_write_ex@OPENSSL_3.0.0
curl:            neither — uses SSL_write / SSL_read
```

OpenSSL 1.1.1 added the `_ex` variants and callers are split between the two
APIs. The unprobed symbols are still present in the library, so nothing reports
a missing symbol and nothing errors. The failure is silent.

**Resolution:** Probe all four entry points.

`SSL_read_ex` needed more than a second probe: it returns 1 or 0 for success or
failure and writes the byte count through an out-parameter, so the return probe
must carry the `readbytes` pointer across from entry and read it back out of the
traced process. The stash value became a struct rather than a bare address.

**Worth carrying forward:** "one hook per TLS library" is already wrong within a
single library. It is one hook per API variant, and the cost of missing one is
silence rather than an error.

### Go binaries contain no OpenSSL at all

**Context:** Confirming the expected negative result for Go.

**Symptom:** A working Go HTTPS client produced zero events.

**Cause:** Go implements TLS in pure Go and links no OpenSSL:

```
ldd: linux-vdso.so.1, libc.so.6, ld-linux-aarch64.so.1
SSL_ symbols: 0
crypto/tls.(*Conn).Write / .Read: 2
```

**Resolution:** None required; this is the expected result and the reason Go
needs an independent attach strategy against `crypto/tls` symbols in the
application binary itself.

### Hardcoded library paths miss processes loading their own copy

**Context:** Verifying that path-based library discovery was insufficient.

**Symptom:** With the agent attached, one of two identical requests was
captured. The second produced nothing and no error.

```
inode 3188    /usr/lib/aarch64-linux-gnu/libssl.so.3
inode 541016  /opt/customssl/libssl.so.3
```

**Cause:** Discovery searched a fixed list of distribution paths and attached to
the first match. A uprobe is placed in a file, identified by inode, so a process
loading a different copy of the same library is not covered by that attachment.
`LD_LIBRARY_PATH`, bundled runtimes, and container images all produce this.

**Resolution:** Read `/proc/<pid>/maps` and attach per distinct `(device,
inode)`. Paths are opened through `/proc/<pid>/root` so that a path meaningful
only inside another mount namespace still resolves.

**Worth carrying forward:** deduplication must key on the file, not the path.
`/lib` and `/usr/lib` are the same directory on Debian and Ubuntu, so the same
library appears under two names and would otherwise be probed twice, doubling
every captured event.

### A one-shot /proc scan cannot see processes that start later

**Context:** After switching to `/proc`-based discovery, a short-lived client
using the non-standard library was still missed.

**Symptom:** The library appeared in no scan, because the process started after
the agent's only scan and exited before any later one.

**Cause:** Sampling. Discovery ran once at startup.

**Resolution:** Interim periodic rescan. This narrows the window but cannot
close it: a process that starts and exits between two scans is never observed,
whatever the interval. Closing it requires notification rather than sampling,
via a tracepoint on process execution.

**Worth carrying forward:** verifying discovery needs a long-lived process
holding the library open before the agent starts, otherwise the test measures
scan timing rather than discovery correctness.

### The kernel trace pipe accepts only one reader

**Context:** A verification run captured nothing, with the agent attached and
traffic flowing.

**Symptom:**

```
cat: /sys/kernel/tracing/trace_pipe: Device or resource busy
```

**Cause:** A reader left running by an earlier run still held the pipe.
`trace_pipe` is a consuming, single-reader interface.

**Resolution:** Terminate stale readers before capture. This is one more reason
the trace pipe is unsuitable as a data path: it is a single global resource
shared with every other tracer on the host.
