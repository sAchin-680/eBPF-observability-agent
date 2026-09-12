# The verifier constraint

Why the agent parses HTTP in userspace.

Every program below was compiled, loaded, and either accepted or rejected by the
verifier on kernel 6.8.0. The rejections are the point, and the verifier's own
output is kept beside this file rather than described.

Reproduce with `sudo go test ./test/verifier/ -v`.

---

## Result

| Program | Bytes scanned | Outcome | Verifier time |
| :--- | ---: | :--- | ---: |
| scan until the data says to stop | — | rejected, `invalid read from stack` | 95 ms |
| scan bounded by a length from userspace | — | rejected, `invalid read from stack` | 22 ms |
| count line breaks, bounded by the buffer | 256 | **accepted**, 22 instructions | 51 ms |
| per-header parse | 32 | **accepted**, 76 instructions | 45 ms |
| per-header parse | 64 | rejected, `argument list too long` | 280 ms |
| per-header parse | 96 | rejected, `argument list too long` | 294 ms |
| per-header parse | 128 | rejected, `argument list too long` | 306 ms |
| per-header parse | 256 | rejected, `argument list too long` | 302 ms |

**A per-header parse verifies over 32 bytes and does not over 64.**

HTTP headers are hundreds of bytes. A `Host` header alone is routinely longer
than the largest buffer this structure can be verified over, so the limit is not
a tuning problem — it rules out the approach.

---

## The three ways it fails

### 1. No bound at all

Scanning until the data says to stop is the natural way to find the end of a
header block, and the bound is then a property of the data rather than of the
program.

```
18: (71) r2 = *(u8 *)(r3 +0)
invalid read from stack R3 off=0 size=1
processed 2833 insns (limit 1000000)
```

The rejection is not about the loop. The verifier unrolled it, followed the
index to 256, and refused the read that leaves the buffer. It proves memory
safety by exploring paths, so it discovers the overrun rather than reasoning
about termination.

### 2. A bound the verifier cannot see

Bounding the scan by the length the caller passed looks like a fix. It is not,
because the bound arrives in a register from userspace:

```
R6_r=Pscalar(smin=umin=250, smax=umax=0x7fffffff, ...)
invalid read from stack R2 off=0 size=1
```

`umax=0x7fffffff`. The verifier knows nothing about the value and must assume
two billion, so the scan overruns for the same reason as the first.

### 3. A bound it can see, over a buffer that is too large

With a compile-time bound and an index that provably stays inside the buffer,
the program is verifiable — but only while the work inside the loop stays small.
Counting line breaks over 256 bytes compiles to 22 instructions and verifies in
51 ms. Adding the per-header work — tracking where each line begins, comparing
its first bytes against a name — verifies over 32 bytes and fails over 64:

```
load program: argument list too long
```

`E2BIG` is what the verifier returns when it exhausts its budget of a million
instructions. The compiler unrolls the loop and the verifier walks every
resulting path, so the cost grows with the product of the bound and the branching
inside it, not with the bound alone. Doubling 32 to 64 is enough.

---

## What this changes

Parsing happens in userspace. The kernel-side program copies a bounded prefix of
the payload and submits it; everything that requires looking at the bytes
happens after that.

The cost is that the captured prefix is fixed at 256 bytes, so a request whose
headers extend past it is truncated, and truncation is reported rather than
hidden. The alternative is not a larger in-kernel parser — that is what does not
verify — but a second capture path, which is more machinery than the headers
are currently worth.

---

## An aside worth recording

Asking for the verifier's log changed both the reported error and the time taken.

| | with log | without log |
| :--- | :--- | :--- |
| reported error | `invalid argument` (EINVAL) | `argument list too long` (E2BIG) |
| verification time | 5.7 s | 0.30 s |

At 64 bytes, retrieving the log was worse than slow. The loader retries with a
progressively larger buffer while the log is truncated, and no buffer was ever
large enough: the process reached 5.3 GB resident on a 5.9 GB machine and was
killed.

```
Out of memory: Killed process 99292 (verifier.test)
total-vm: 7,041,392 kB   anon-rss: 5,344,556 kB
```

Verification itself takes 280 ms. Only the log is unbounded — and while trying to
retrieve it, the real errno was replaced by a less specific one. The size sweep
therefore runs with logging disabled, and logs are kept only for the small
programs where they are readable and correct.
