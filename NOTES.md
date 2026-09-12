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

---

## 2026-09-12 — Go crypto/tls capture

### A uretprobe on a Go function aborts the traced process

**Context:** Establishing whether the read side of `crypto/tls.(*Conn).Read`
could use a return probe, as the OpenSSL path does.

**Symptom:** Three runs, three aborts, exit code 2. Without the probe the same
binary exits 0 every time.

```
runtime: g 35: unexpected return pc for crypto/tls.(*Conn).Read
         called from 0xfffffffff000
stack: frame={sp:0x4000145bf0, fp:0x4000145c60} stack=[0x4000145000,0x4000146000)
```

**Cause:** A uretprobe replaces the return address on the stack with a kernel
trampoline, here `0xfffffffff000`. Go's runtime walks its own stack using
pclntab metadata and treats an unrecognised return PC as corruption.

**Resolution:** Attach to the function's own RET instructions instead, leaving
the stack untouched. On AArch64 instructions are a fixed four bytes and aligned,
so scanning the function body for `0xd65f03c0` finds every return site exactly —
seven in `crypto/tls.(*Conn).Read`, eight in `.Write`. The same scan on x86-64
is not reliable: `0xc3` is one byte in a variable-length stream and occurs inside
other instructions and inside embedded data, so return sites there need
instruction-length decoding from the function start.

**Worth carrying forward:** this is an agent crashing the application it traces,
which is the outcome NFR3 exists to prevent. It is also not a failure the agent
could detect — the damage is entirely in the traced process.

### Goroutines migrate between OS threads mid-call

**Context:** Choosing the correlation key for Go read entry and return. The
OpenSSL path keys on the thread, which is correct there.

**Symptom:** With the capture working, the write and the matching read of a
single request appear on different threads of the same process:

```
gohold-19795  WRITE pid=19792
gohold-19796  READ  pid=19792
```

Four distinct OS threads carried traffic for one single-request-at-a-time
client.

**Cause:** A TLS read blocks on network I/O by definition. The Go scheduler
parks the goroutine, and it resumes on whichever thread is free.

**Resolution:** Key on the goroutine rather than the thread. Go's register ABI
keeps the current goroutine pointer in a dedicated register — `x28` on arm64,
`r14` on x86-64 — which is stable across the migration and needs no knowledge of
the runtime's internal struct layout, unlike reading a goroutine ID.

**Worth carrying forward:** a thread-keyed implementation would still have
appeared to work. The entry would simply not be found at return, so reads would
be silently dropped rather than misattributed, and the write path would keep
producing request lines. The symptom is missing responses, not an error.

### Register ABI agreement between Go and C is an arm64 coincidence

**Context:** Reading slice arguments from `crypto/tls.(*Conn).Write`.

**Symptom:** The C argument macros returned correct values:

```
arg0=receiver  arg1=b.ptr=0x40000da000  arg2=b.len=64  arg3=b.cap=4096
```

**Cause:** On arm64 both Go's register ABI and the platform C ABI pass the first
arguments in x0 onwards, so the macros happen to read the right registers.

**Worth carrying forward:** they diverge on x86-64. Go passes in RAX, RBX, RCX
while the C macros read RDI, RSI, RDX. The same code would read unrelated
registers there and report plausible-looking nonsense rather than failing.

### Go discovery finds unrelated system binaries

**Context:** First run of Go binary discovery on the development host.

**Symptom:**

```
attached /usr/local/bin/buildkitd   (go, 7 return sites)
attached /usr/local/bin/rootlesskit (go, 7 return sites)
attached /tmp/gohold/gohold         (go, 7 return sites)
```

**Cause:** Any Go binary importing `crypto/tls` is a valid target, and a typical
host runs several unrelated ones.

**Worth carrying forward:** correct behaviour, but it means attachment count
scales with the number of distinct Go executables rather than with the number of
services worth tracing. Unlike a shared library, each Go binary carries its own
copy of crypto/tls, so there is no shared file to attach to once.

---

## 2026-09-12 — Ring buffer data path

### Kernel and userspace struct layouts must be asserted, not assumed

**Context:** Replacing the trace pipe with `BPF_MAP_TYPE_RINGBUF`, which moves
raw bytes rather than formatted text.

**Cause for concern:** The record is written by a C struct and read by a Go
struct. A field added or reordered on one side alone produces records that
decode without error and carry wrong values in every field after the change.
There is no error to catch, only wrong numbers.

**Resolution:** Both sides measured and pinned at 304 bytes, with a unit test
asserting it:

```
C  sizeof(struct event) = 304
Go binary.Size(rawEvent) = 304
```

The Go struct carries an explicit trailing pad, because `encoding/binary` packs
without alignment while the C compiler rounds the struct up to its own
alignment. Omitting it leaves the Go side two bytes short and every record
fails to decode.

### Building records in ring buffer memory removes the stack limit

**Context:** Payload capture size was fixed at 256 bytes by the 512-byte BPF
stack.

**Cause:** `bpf_ringbuf_reserve` returns a pointer into the ring buffer, so the
record is never on the stack.

**Worth carrying forward:** the binding constraint is now throughput rather than
stack size. Every byte reserved is capacity unavailable to the next event, so
raising the capture size directly raises the drop rate at a given request rate.
That trade is the subject of the overhead benchmark.

### The ring buffer did not drop under the load available here

**Context:** Verifying that drop accounting works, rather than assuming it.

**Symptom:** 400 concurrent clients produced 1200 events and zero drops at
256 KiB. The path was implemented but unexercised, which is not the same as
verified.

**Resolution:** Rebuilt with the buffer at its 4 KiB minimum, roughly thirteen
records, and repeated the load:

```
WARNING: openssl dropped 2 events (2 total): ring buffer full
682 events delivered
```

**Worth carrying forward:** the load reachable from one host against a remote
endpoint is network-bound, not agent-bound, so it cannot establish the rate at
which drops begin. That figure needs a local target and a proper load harness.

### Most ingress events are five bytes of TLS record header

**Context:** Reviewing captured output.

**Symptom:** Roughly half of all ingress events carry `len=5` and no printable
payload.

**Cause:** Both OpenSSL and Go read the five-byte TLS record header in a
separate call before reading the record body.

**Worth carrying forward:** these are not HTTP and the parser must ignore them.
They also consume ring buffer capacity and inflate the event rate by about a
factor of two, so filtering them in kernel space would directly reduce drop
pressure.

---

## 2026-09-12 — HTTP/1.1 parsing

### A method name alone is not enough to identify a request line

**Context:** Captured payloads are arbitrary bytes read out of another process:
TLS record headers, HTTP/2 frames, response bodies, and binary data all arrive
through the same path as start lines.

**Cause for concern:** Matching a request line loosely accepts things that are
not requests. Response bodies contain prose beginning with method names —
"GET the latest release from our downloads page" parses as a request to the
path "the" unless a version string is also required.

**Resolution:** Require an explicit method from a fixed list, a non-empty path,
and a recognised version on the same line. Status codes are constrained to
100–599 so that three digits occurring in binary data do not become a response.

### The HTTP/2 preface parses cleanly as an HTTP/1.1 request

**Context:** Guarding the case observed earlier, where curl and Go both
negotiated HTTP/2 by default.

**Symptom:** `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` satisfies every structural rule
for a request line: a method-shaped token, a target, and a version.

**Resolution:** PRI is excluded from the accepted methods, with a regression
test. Without it every HTTP/2 connection would be reported as an HTTP/1.1
request to the path "*", which is worse than reporting nothing: the traffic
would appear in dashboards as real requests that never happened.

### Header scanning must stop at the end of the headers

**Context:** Extracting Host for service name inference.

**Cause for concern:** A request body can contain a line shaped like a header.
Scanning the whole captured prefix would read `Host:` out of a body supplied by
whoever sent the request.

**Resolution:** The scan stops at the blank line separating headers from body,
with a test covering a body that carries a Host line.

### Fuzzing found nothing, over ten million inputs

**Context:** The parser reads bytes influenced by whoever is talking to the
traced process, so a panic in it is a crash of the agent.

**Result:** 10,438,535 executions in 30 seconds, no panics and no invariant
violations. The invariants asserted were that a recognised request has a
non-empty method and path, and a recognised response has a status in range.

### Not every request produces a matching response event

**Context:** First end-to-end run with parsing enabled.

**Symptom:** 16 requests, 11 responses.

**Cause:** Unconfirmed. A response is delivered across several reads, and the
status line is only present in whichever read carries the start of the record
body; reads that land elsewhere parse as nothing. Ring buffer drops were not
reported during this run, so loss is not the explanation.

**Worth carrying forward:** correlation cannot assume a response exists for
every request. A request left unmatched needs an expiry path, or unmatched
requests will accumulate for the lifetime of the agent.

---

## 2026-09-12 — Request correlation

### The TLS connection object is the correlation key

**Context:** Pairing a request payload with its response. The socket four-tuple
is not available at a TLS library hook, and the obvious process- or thread-based
keys are both wrong.

**Why the alternatives fail:**

- *Thread*: correct for OpenSSL, wrong for Go, where a goroutine blocked on a
  read resumes on a different thread. Also wrong for any thread pool serving
  many connections.
- *Process*: a server handles many connections concurrently; a single pending
  slot per process would interleave unrelated exchanges.

**Resolution:** The receiver argument already identifies the connection —
OpenSSL's `SSL*` and Go's `*tls.Conn` — and was being discarded. It is unique
for the connection's lifetime, which is exactly the window correlation needs.

**Worth carrying forward:** the pointer is an address in the traced process and
is never dereferenced, only compared. Addresses are reused after a connection
closes and two processes can hold the same address simultaneously, so the key is
scoped by pid and bounded by a TTL rather than trusted as globally unique.

### The earlier request/response mismatch was not loss

**Context:** Parsing alone produced 16 requests and 11 responses, with no ring
buffer drops to explain the gap.

**Resolution:** With correlation and counters in place:

```
requests=14 completed=13 expired=1 unmatched-responses=0 non-http=13 pending=0
```

The apparent gap was two separate things. Most of it was payloads that are not
HTTP at all — thirteen in this run, largely TLS record headers — which the
parser discards and which were never responses to begin with. The remainder was
one genuinely unanswered request, now reported as expired rather than vanishing.

**Worth carrying forward:** counting what is discarded is what turned an
unexplained discrepancy into two understood numbers. Without the non-HTTP and
unmatched counters the gap would still look like loss.

### An expired record must not carry a status

**Context:** Deciding what to report when no response arrives.

**Reasoning:** The absence of a captured response does not mean the request
failed. It may have been answered on a connection the agent attached to
mid-exchange, or split across reads leaving no start line in any captured
prefix. Reporting a synthetic error status would fabricate failures that did not
occur, which is worse than reporting an incomplete record.

**Resolution:** Expired records carry status zero and an explicit outcome, and
the printer renders the duration as unknown rather than as zero.

### Measured durations match the network round trip

**Context:** Sanity-checking that timestamps mean anything.

**Result:** Every completed record against the same remote endpoint fell between
27ms and 34ms, consistent with the round-trip time to that host. A correlation
bug pairing unrelated events would produce durations unrelated to each other.

---

## 2026-09-12 — Sample applications

### All three runtimes traced, with correlation complete

**Context:** First run against three unmodified sample services rather than
against remote endpoints.

**Result:**

```
requests=84 completed=84 expired=0 unmatched-responses=0 non-http=28 pending=0

gotls   comm=go-api  GET /slow       200  150.445ms
openssl comm=python  GET /slow       200  155.812ms
openssl comm=node    GET /slow       200  152.642ms
gotls   comm=go-api  GET /users/999  404       75µs
gotls   comm=go-api  GET /error      500      224µs
```

Every request matched a response, with nothing expired or unmatched.

**Worth carrying forward:** the `/slow` endpoint sleeps for 150ms, and all three
services were measured between 150.4ms and 155.8ms. That is an independent check
on the timing path: a correlator pairing unrelated events would not reproduce a
known duration across three separate runtimes.

### Node traceability depends on how Node was built

**Context:** Node was scoped out as a known gap, on the assumption that it
bundles its own TLS. It was traced without any work.

**Cause:** The distribution package splits Node into a thin executable and
`libnode.so`, and that library links system OpenSSL:

```
/lib/aarch64-linux-gnu/libnode.so.109 imports SSL_write
```

The executable itself imports no SSL symbols at all, which is why inspecting
`node` alone is misleading. Library-level attachment covers it for free.

**But the official build does not behave that way:**

```
official node v22.11.0
  ldd  : no libssl, no libcrypto — OpenSSL is statically linked
  .dynsym: 6 SSL_write / SSL_read symbols defined inside the binary
  .symtab: 2
```

**Worth carrying forward:** two things follow. First, a capability
demonstration is only as good as the build it was demonstrated against;
"traces Node" would have been an overclaim from this evidence alone. Second,
the static case is not out of reach — the symbols are exported, so it needs
per-binary attachment of the kind the Go path already does, not a new
mechanism. The stated gap is narrower than assumed.

### Inspecting the executable is not enough to find TLS

**Context:** `nm -D` on the node executable reports zero SSL imports, while the
process plainly uses OpenSSL.

**Cause:** The calls come from a library the executable loads, not from the
executable. Any check that looks only at `/proc/<pid>/exe` misses this entirely.

**Worth carrying forward:** discovery has to read the process's mapped
libraries, which is what it does. The lesson is that the executable's own
symbol table answers a narrower question than it appears to.

---

## 2026-09-12 — Process discovery

### Polling replaced with a tracepoint on process execution

**Context:** Discovery ran on a 500ms timer. A process that starts and exits
between two scans is never observed, and no interval closes that window — a
short-lived client completes a request in less time than any practical scan
period.

**Resolution:** A tracepoint on `sched_process_exec` reports every exec. The
startup scan is kept for processes already running; the two cover disjoint sets
and together leave no gap.

**Verified with the sample services absent at startup and started afterwards:**

```
03:10:45 tracing 1 TLS library and 2 Go binaries at startup; watching for new processes
03:10:52 attached .../samples/go-api/go-api (pid 32066, go, 7 return sites)

requests=48 completed=48 expired=0 unmatched-responses=0 non-http=16 pending=0
```

The startup line shows only unrelated system binaries. The attachment seven
seconds later is the tracepoint firing for a process that did not exist when the
agent started.

**Hook choice:** the tracepoint rather than a kprobe on the kernel's exec
implementation. Tracepoints are an interface the kernel commits to keeping;
the internal functions behind exec are not, and have been renamed across
releases. A kprobe would load on the kernel it was written against and silently
fail to attach elsewhere, defeating the portability CO-RE provides. This is
ADR-003 applied.

### A process has no shared libraries at the moment it execs

**Context:** Inspecting a process immediately on notification found no libssl,
even for processes that plainly load it.

**Cause:** At exec the new image is mapped but its libraries are not. The
dynamic linker runs afterwards, as the process's own first instructions.

**Resolution:** Inspection is delayed briefly and retried a few times.

**Worth carrying forward:** the delay is a compromise, not a fix, and waiting
longer does not solve it. A library can be loaded at any point in a process's
life — a runtime that opens its first HTTPS connection minutes after starting
maps libssl then, not at exec. Covering that properly needs a hook on library
loading rather than on process creation.

### Stopping a process by command-line pattern matched nothing

**Context:** A test intended to start with no sample services running began with
one still alive, which invalidated the result until noticed.

**Symptom:** `pkill -f 'go-api/go-api'` matched nothing. The service is started
from its own directory, so its command line is `./go-api` and no
directory-qualified pattern matches it.

**Resolution:** Match on process name with `pkill -x`.

**Worth carrying forward:** the test reported success while measuring the wrong
thing. Verifying the precondition — that nothing was running — is what caught it,
and the second run asserts that precondition explicitly before proceeding.

---

## 2026-09-12 — Socket endpoints

### Joining a TLS connection to its socket

**Context:** A probe on a TLS library sees the connection object and the
plaintext but nothing about the network. The four-tuple lives in `struct sock`,
which only appears in the kernel's TCP path, where the plaintext no longer
exists. Neither hook alone can produce a record carrying both.

**Resolution:** The thread joins them. A TLS write encrypts and then calls
write(), reaching `tcp_sendmsg` on the same thread. The TLS probe records which
connection the thread is inside; the TCP probe reads that and binds the socket
it was handed to that connection.

The programs are compiled separately, so each would normally get its own copy of
those maps. Passing one program's map instances as replacements at load time
makes all of them operate on the same kernel maps, which keeps the Go programs
loadable only on hosts that run Go binaries.

**A kprobe, deliberately, against the general preference for tracepoints.** No
tracepoint provides what is needed: the socket tracepoints fire on state
transitions, which report a connection being established rather than a
particular send, and establishment happens on a different thread in the accept
path and in softirq context with no useful process identity. The cost is that
`tcp_sendmsg` has no stability guarantee, so attachment is attempted and a
failure is reported and tolerated — records are still produced, without
endpoints.

### Every address was reported with its octets reversed

**Symptom:** `peer=1.0.0.127:8444`.

**Cause:** The kernel stores the address as four bytes in network order. Decoding
the record with little-endian integers reverses them, and writing the value back
out big-endian reverses them a second time.

**Worth carrying forward:** the result is a syntactically valid address, so
nothing downstream would have rejected it. The fix was to stop converting
entirely and carry the address as raw bytes end to end, which removes the
opportunity for the error rather than correcting it.

### Half the connections were invisible because they were IPv6

**Symptom:** Resolution succeeded for some services and never for others:

```
openssl: 15/36 resolved     gotls: 0/7 resolved

curl -> :8444 (Flask)   resolved
curl -> :8443 (Go)      not resolved
curl -> :8445 (Node)    not resolved
curl -> example.com     resolved
```

The same curl binary behaved differently per destination, which ruled out the
client, the language, and the server/client distinction.

**Cause:** The Go and Node services bind the default dual-stack address, so a
connection to `localhost` arrives over IPv6. Flask binds `0.0.0.0`, so the same
client falls back to IPv4. The program returned early on any family other than
`AF_INET`, discarding every IPv6 connection silently.

**Resolution:** Handle both families, storing addresses as sixteen raw bytes and
unmapping IPv4-mapped IPv6 addresses in userspace.

```
openssl: 36/36 resolved     gotls: 7/7 resolved
peer=[::1]:50244    peer=104.20.23.154:443
```

**Worth carrying forward:** IPv6 is not an edge case to defer. A Go or Node
service on its default address is reached over IPv6 for every local connection,
so an IPv4-only implementation misses the common case while appearing to work
against whichever service happens to bind IPv4.

### The active connection marker is never cleared

**Known limitation, not yet addressed.** The marker recording which connection a
thread is inside persists after the TLS call returns. An unrelated TCP send on
that thread before the next TLS call would be attributed to the stale
connection.

Clearing it would need a probe on the TLS call's return, which is exactly what
cannot be done safely on Go. The exposure is bounded — a thread handling a
keep-alive connection sends only for that connection, and the next TLS call
overwrites the marker — but it is wrong data rather than missing data, which
makes it worth recording.

---

## 2026-09-13 — OpenTelemetry export

### The agent traced itself, and did not survive it

**Context:** First run with the OTLP exporter enabled.

**Symptom:** The agent exited five seconds after start, having produced no
telemetry. Its own startup log showed why:

```
attached /home/.../bin/agent  (pid 46059, go, 7 return sites)
attached /bin/prometheus      (go, 7 return sites)
attached /tempo               (go, 7 return sites)
attached .../grafana          (go, 7 return sites)
```

**Cause:** The agent is a Go program that uses crypto/tls, because that is how
it ships telemetry. It therefore matches its own discovery criteria exactly.
Every export is a TLS write, which fires the agent's own probes, which produces
events, which the agent exports. The loop amplifies itself.

It also attached to the three backends it exports to, which would have done the
same thing one step removed.

**Resolution:** Exclude processes running the agent's own executable, matched by
device and inode rather than by pid — the agent may have more than one process,
and a pid says nothing about what is running under it.

**Worth carrying forward:** this was invisible in every earlier phase. The agent
only became a candidate for its own probes once it started using TLS, so the
defect was introduced by the feature that exposed it. Anything that observes a
class of processes has to consider whether it is a member of that class.

Tracing the observability backends is a separate question left open: it is
correct behaviour in general, and only a problem when the agent exports to them.

### Service name inference, and why the obvious signals fail

**Context:** OpenTelemetry requires a service name, and nothing tells the agent
what a service is called.

**Why the direct signals are insufficient:** the executable name is the runtime
for anything interpreted — three Python services all report `python3`. The
entry-point filename is usually a convention: `app.py`, `server.js`, `main.go`.
Neither distinguishes one service from another.

**Resolution:** take the most specific non-generic signal available, falling
back rather than guessing. Where the entry point is itself a conventional name,
the directory containing it is used, which is what a service is usually named
after.

```
service_name="go-api"        from the executable
service_name="python-flask"  app.py is generic, so the directory
service_name="node-express"  server.js is generic, so the directory
```

**Worth carrying forward:** this is a heuristic and will be wrong somewhere. In
a container or a pod the authoritative answer is a label, and that supersedes
all of this — which makes this the right amount of effort for now rather than a
problem to solve completely.

### Both ends of a local call are observed, and counting both is wrong

**Context:** The agent sees curl writing a request and the server reading the
same request, producing a record for each.

**Resolution:** The direction of the request payload already says which side a
process was on — a process that read the request is serving it. That maps
directly onto the span kinds the data model already has, so no new concept was
needed and a query can separate them.

Without it, every local request appears twice in the request rate.

### A tracer provider describes one service, and the agent is not that service

**Context:** The SDK attaches a resource, including the service name, to a
provider rather than to a span, because a normal application instruments itself.

**Resolution:** One provider per traced service, all sharing a single exporter
and connection. Putting the service name on the span instead would be simpler
but places it where a backend grouping by resource will not find it.

**Result:**

```
Tempo service.name values: ["curl","go-api","node-express","python-flask"]
```
