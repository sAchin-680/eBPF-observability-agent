# ADR-002: Capture plaintext at TLS library entry points

**Status:** Accepted
**Date:** 2026-09-12

## Context

The agent must observe HTTP request and response content for services it does
not control. Most of that traffic is TLS, so it is ciphertext everywhere it can
conventionally be observed: on the wire, at the socket layer, and in every
kernel networking hook.

The content is in cleartext at exactly one boundary — inside the traced process,
between the application handing a buffer to its TLS library and that library
encrypting it. Any approach that does not read at that boundary must either
obtain the session keys or terminate the connection.

## Decision

Attach uprobes to the read and write entry points of the TLS implementation the
process actually uses, and copy the caller's buffer there.

Four OpenSSL entry points are probed rather than two, because callers are split
between the original and the `_ex` API with nothing to distinguish them from
outside: curl uses `SSL_write`/`SSL_read`, CPython uses the `_ex` variants
exclusively. Go is probed separately at `crypto/tls`, which shares no code with
OpenSSL.

## Alternatives considered

**Application instrumentation (SDK or agent per language).** Reliable and
detailed, and the approach this project exists to avoid. It requires a code
change and a redeploy for every service, a separate implementation per language,
and ongoing maintenance. Coverage becomes whatever teams had time to add.

**Sidecar or mesh proxy.** No application code change, but the topology changes:
an extra network hop per request, certificates to manage, and the proxy must
terminate TLS to see content. It also only covers traffic routed through it,
which excludes anything a service does directly.

**Packet capture or XDP.** No application change and very low overhead, but it
observes ciphertext. Making it useful requires session keys, which means
cooperation from the traced process — the constraint being avoided.

**Syscall-level probes on `read` and `write`.** Simple, stable, and language
independent, but by the time a buffer reaches a syscall it is already encrypted.
This works for plaintext HTTP only.

**Reading session keys and decrypting in the agent.** Removes the need for
per-library probes, but requires extracting key material from process memory and
implementing record-layer decryption. Strictly more invasive, substantially more
complex, and a far worse thing to have in a privileged agent.

## Consequences

**The attach point is per implementation, not per language.** This is the real
cost, and it is larger than expected. Go needs an entirely separate strategy
because it links no OpenSSL. Node is traced only when its OpenSSL is dynamically
linked — the distribution package is, the official build is not.

**Coverage gaps are silent.** An unprobed entry point produces no error and no
missing symbol; the traffic simply never appears. CPython was invisible until
the `_ex` variants were probed, with nothing to indicate why.

**Probes read another process's memory.** The agent requires privilege to do so,
and a compromised agent could read plaintext for every traced process on the
node. That is recorded in the security posture rather than treated as
incidental.

**Nothing about the traced process changes.** No restart, no configuration, no
added latency path, and no certificate handling. Attachment is to a file, so
processes started afterwards are covered without the agent knowing they exist.

**Payloads are truncated.** A fixed-size prefix is copied per call, which is
enough for a start line and the first headers but not for full message
reconstruction.
