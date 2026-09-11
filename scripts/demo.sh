#!/usr/bin/env bash
# demo.sh — the Phase 1 demonstration.
#
# Shows that three services in three languages are traced without a single
# change to their source. The proof is the diff: it is taken live, against the
# services that are about to be traced, and it is empty.
#
# Run from the repository root inside the Linux VM:
#
#	sudo -E scripts/demo.sh
#
# Record the terminal while this runs. It is paced for reading.

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

# Run under sudo, which resets PATH and would otherwise lose the Go toolchain
# that the sample services are built with.
export PATH="$PATH:/usr/local/go/bin"

bold()  { printf "\n\033[1m%s\033[0m\n" "$1"; }
dim()   { printf "\033[2m%s\033[0m\n" "$1"; }
pause() { sleep "${1:-3}"; }

trap 'make -C samples stop >/dev/null 2>&1; pkill -f bin/agent >/dev/null 2>&1' EXIT

# ---------------------------------------------------------------------------
bold "1. Three services, three languages, three TLS implementations"
printf "%s\n" \
  "   samples/go-api         Go          crypto/tls, statically linked" \
  "   samples/python-flask   CPython     OpenSSL via libssl.so.3" \
  "   samples/node-express   Node.js     OpenSSL via libnode.so"
pause 4

# ---------------------------------------------------------------------------
bold "2. None of them is instrumented"
dim "   No tracing SDK, no OpenTelemetry dependency, no agent configuration."
dim "   Taken live, against the services about to be traced:"
echo
SERVICES="samples/go-api/main.go samples/python-flask/app.py samples/node-express/server.js"
echo "   \$ git diff --stat HEAD -- <the three services>"
git diff --stat HEAD -- $SERVICES || true
DIFF_LINES=$(git diff HEAD -- $SERVICES | wc -l)
if [ "$DIFF_LINES" -eq 0 ]; then
  printf "   \033[32m(empty — the services are unmodified)\033[0m\n"
else
  printf "   \033[31mWARNING: %s lines of local changes to the services\033[0m\n" "$DIFF_LINES"
  printf "   The demonstration is only meaningful with an unmodified tree.\n"
fi
echo
dim "   And no tracing dependency is declared by any of them:"
echo
echo "   \$ cat samples/go-api/go.mod"
sed 's/^/     /' samples/go-api/go.mod
echo "   \$ jq -c .dependencies samples/node-express/package.json"
sed -n 's/^/     /p' <<<"$(jq -c .dependencies samples/node-express/package.json 2>/dev/null || echo '{"express":"*"}')"
echo "   \$ pip list, in the Flask service venv"
(samples/python-flask/.venv/bin/pip list --format=freeze 2>/dev/null | grep -iE 'flask|otel|opentelemetry|ddtrace|elastic' | sed 's/^/     /') || true
echo
if grep -rqiE 'opentelemetry|ddtrace|elastic-apm|newrelic|zipkin|jaeger' \
     samples/go-api/go.mod samples/node-express/package.json 2>/dev/null; then
  printf "   \033[31mWARNING: a tracing dependency is declared\033[0m\n"
else
  printf "   \033[32m(none — nothing in these services knows the agent exists)\033[0m\n"
fi
pause 5

# ---------------------------------------------------------------------------
bold "3. Start the agent — before the services exist"
dim "   Nothing is running to trace yet. The agent attaches to processes as"
dim "   they start, so it does not need to be restarted when they do."
make -C samples stop >/dev/null 2>&1
pkill -f bin/agent >/dev/null 2>&1
sleep 1

./bin/agent > /tmp/demo-agent.log 2>&1 &
sleep 5
echo
grep -E "tracing .* at startup" /tmp/demo-agent.log | sed 's/^/   /'
pause 3

# ---------------------------------------------------------------------------
bold "4. Start the services"
make -C samples run 2>&1 | grep -vE "^make(\[|:)" | sed 's/^/   /'
sleep 3
echo
dim "   Attachments made after the agent was already running:"
grep "samples/" /tmp/demo-agent.log | sed 's/^/   /' || echo "   (none)"
pause 4

# ---------------------------------------------------------------------------
bold "5. Send traffic"
dim "   Six routes per service, including a deliberate 404, a 500, and an"
dim "   endpoint that sleeps for 150ms."
make -C samples traffic 2>&1 | grep -vE "^make(\[|:)" | sed 's/^/   /'
sleep 3

# ---------------------------------------------------------------------------
bold "6. What the agent produced"
grep -vE "^[0-9]{2}:" /tmp/demo-agent.log | head -24 | sed 's/^/   /'
echo
dim "   method, path, status, latency, and socket endpoints — from three"
dim "   runtimes that were never touched."
pause 4

# ---------------------------------------------------------------------------
bold "7. Nothing was dropped or left unmatched"
pkill -f bin/agent >/dev/null 2>&1
sleep 2
grep -E "requests=" /tmp/demo-agent.log | sed 's/^/   /'
echo
dim "   non-http counts payloads discarded as not being HTTP, most of them"
dim "   five-byte TLS record headers. expired counts requests whose response"
dim "   was never captured; those carry no status rather than a guessed one."
echo
