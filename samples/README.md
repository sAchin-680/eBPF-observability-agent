# Sample applications

Three HTTP services in three languages, used to verify that the agent traces
unmodified applications.

**These applications contain no instrumentation, and that is the point.** No
tracing SDK, no OpenTelemetry dependency, no agent configuration, no environment
variables read, no wrapper around the HTTP handler. They are ordinary services
written the way their ecosystems would write them, and they are unaware the
agent exists.

Any change here that makes tracing work would invalidate the result being
demonstrated. `git diff` against these files must stay empty when the agent runs.

## Services

| Service | Runtime | TLS implementation | Port |
| :--- | :--- | :--- | :--- |
| `go-api` | Go 1.23 | `crypto/tls`, statically linked | 8443 |
| `python-flask` | CPython 3.12 + Flask | OpenSSL via `libssl.so.3` | 8444 |
| `node-express` | Node.js 22 + Express | OpenSSL, statically linked into `node` | 8445 |

The three differ in exactly the way that matters: each reaches TLS through a
different mechanism, so each requires a different attach strategy. That is what
makes them a test of the agent rather than three copies of the same test.

## Endpoints

Every service exposes the same routes, so behaviour can be compared across
runtimes:

| Route | Response |
| :--- | :--- |
| `GET /health` | 200, minimal body |
| `GET /users` | 200, JSON list |
| `GET /users/:id` | 200, or 404 for id `999` |
| `GET /slow` | 200 after roughly 150ms |
| `GET /error` | 500 |
| `POST /users` | 201 |

`/slow` and `/error` exist so that latency distribution and error rate are
exercised rather than assumed, which the Phase 2 dashboards need.

## Running

```bash
make -C samples certs     # self-signed certificates, once
make -C samples run       # start all three in the background
make -C samples traffic   # generate a mixed request load
make -C samples stop
```

Certificates are self-signed and generated locally. They are not committed:
a repository containing a private key teaches the wrong habit even when the key
is worthless.

Clients must pass `--http1.1`. Every modern client negotiates HTTP/2 over ALPN
by default, and HTTP/2 is out of scope: its binary framing carries header state
in a compression context shared across frames, so there is no request line to
find in a single captured payload.
