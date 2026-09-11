# ADR-003: Prefer tracepoints, and record where a kprobe is unavoidable

**Status:** Accepted
**Date:** 2026-09-12

## Context

Two kernel-side hooks are needed beyond the TLS entry points: notification when
a process starts, so it can be inspected and attached to, and access to a
socket's endpoints, so records carry network addresses.

Both are reachable either through a tracepoint — a static instrumentation point
the kernel maintains as an interface — or through a kprobe on an internal
function. The choice matters more here than it usually would, because the agent
is required to run as one compiled binary across several kernel versions. A hook
that attaches on one kernel and not another defeats that, and does so at load
time on a node already in production.

## Decision

Use a tracepoint wherever one exposes what is needed. Use a kprobe only where no
tracepoint does, record why in the program itself, and treat its failure as a
degradation rather than a fatal error.

| Need | Hook | Kind |
| :--- | :--- | :--- |
| Process started | `sched:sched_process_exec` | tracepoint |
| Socket endpoints for a send | `tcp_sendmsg` | kprobe |

## Alternatives considered

**A kprobe for process execution.** The kernel's exec implementation has been
renamed and restructured across releases, and a kprobe on it would silently fail
to attach elsewhere. The tracepoint provides process identity, which is all that
is required, so there is no reason to take that risk.

**A socket tracepoint instead of `tcp_sendmsg`.** The available socket
tracepoints fire on state transitions and report a connection being established
rather than a particular send. Two problems follow. Establishment happens on a
different thread from the TLS call in the accept path, and it happens in softirq
context with no useful process identity — so the thread-based association that
binds a connection to its socket is unavailable there.

**Reading the socket from the TLS library's own structures.** Avoids the kernel
hook entirely, but requires knowing the internal layout of `SSL` or
`crypto/tls.Conn`, which differ per version of each library. That trades a
documented kernel-version risk for an undocumented library-version risk, across
more libraries.

**Not capturing endpoints at all.** Viable — method, path, status and latency are
useful without them — but endpoints are what distinguish two services with the
same route, and they are needed for span attributes later.

## Consequences

**The exec path is portable.** The tracepoint is an interface the kernel commits
to keeping, so process discovery is expected to work unchanged across the kernel
versions under test.

**The socket path is not guaranteed.** `tcp_sendmsg` is an internal symbol. On a
kernel where it has been renamed or inlined, attachment fails. The agent reports
that and continues, producing records without endpoints. This is the first
capability that can be absent at runtime on an otherwise supported kernel, and
the multi-kernel matrix has to check for it specifically rather than only
checking that the agent starts.

**Every kprobe is an explicit exception.** One exists today and its reasoning is
in the program. A second should require the same argument, so that the
preference does not erode by accumulation.
