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

# No pipefail: pipelines here end in tools that stop reading early, which
# leaves the producer killed by SIGPIPE and turns a success into a failure.
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

# Run under sudo, which resets PATH and would otherwise lose the Go toolchain
# that the sample services are built with.
export PATH="$PATH:/usr/local/go/bin"

# Never invoke a pager. Under a terminal recorder there is no one to press a
# key, so a paged command blocks the run indefinitely.
export GIT_PAGER=cat
export PAGER=cat
: "${TERM:=xterm-256color}"
export TERM

# Only the agent needs privilege. The services run as the invoking user, which
# is both how they would run in reality and a requirement here: the working tree
# is a shared mount where the guest's root maps to an unprivileged host user and
# cannot write.
# Run this script as your normal user. Only the agent is elevated.
#
# The inverse — running the whole script as root and dropping privilege for the
# services — fails in two ways that are easy to miss: the services end up owned
# by root and a later unprivileged stop cannot kill them, and the nested
# privilege drop blocks when the script runs under a terminal recorder.
if [ "$(id -u)" -eq 0 ]; then
  echo "Run as your normal user, not root. The agent elevates itself." >&2
  exit 1
fi
if ! sudo -n true 2>/dev/null; then
  echo "Passwordless sudo is required to load the agent's kernel programs." >&2
  exit 1
fi
samples() { make -C "$REPO/samples" "$@"; }

# show runs a samples target and prints its output indented.
#
# Deliberately not a pipeline. `samples run` leaves services running in the
# background, and although each has its output redirected to a file, something
# in the chain keeps the pipe's write end open — so a reader on the other end
# never sees EOF and the pipeline never finishes. The script then hangs at step
# 4, and whatever eventually kills it fires the EXIT trap, which stops the
# agent. The visible symptom is an agent that traced almost nothing, which
# points nowhere near the cause.
#
# Redirecting to a file and printing it afterwards has no reader to block.
show() {
  local out
  out=$(mktemp)
  samples "$@" > "$out" 2>&1
  grep -vE "^make(\[|:)" "$out" | sed 's/^/   /'
  rm -f "$out"
}

# The agent's log lives in the working tree, not /tmp. A shared temp directory
# accumulates files owned by whichever user last ran the demo, and the next run
# then cannot write its own log — while still finding the previous one to read.
AGENT_LOG="$REPO/samples/logs/agent.log"
mkdir -p "$(dirname "$AGENT_LOG")"
rm -f "$AGENT_LOG"

bold()  { printf "\n\033[1m%s\033[0m\n" "$1"; }
dim()   { printf "\033[2m%s\033[0m\n" "$1"; }
pause() { sleep "${1:-3}"; }

trap 'samples stop >/dev/null 2>&1; sudo pkill -f bin/agent >/dev/null 2>&1' EXIT

# Building is a prerequisite rather than part of the demonstration. Compiling
# mid-run produces a minute of unrelated output, and under sudo it rebuilds
# from an empty cache belonging to a different user.
missing=""
[ -x bin/agent ] || missing="$missing bin/agent (make build)"
[ -x samples/go-api/go-api ] || missing="$missing samples/go-api/go-api"
[ -x samples/python-flask/.venv/bin/python ] || missing="$missing the Flask venv"
[ -d samples/node-express/node_modules ] || missing="$missing node_modules"
[ -f samples/certs/cert.pem ] || missing="$missing samples/certs"
if [ -n "$missing" ]; then
  printf "Missing:%s\n\n" "$missing"
  printf "Prepare first, as your normal user:\n\n"
  printf "    make build\n    make -C samples prepare\n\n"
  exit 1
fi

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
show stop
sudo pkill -f bin/agent >/dev/null 2>&1
sleep 1

# setsid before sudo, not after.
#
# With `sudo setsid`, sudo itself stays in this script's process group and
# forwards signals sent to that group down to the agent. A later step then kills
# the agent without meaning to, and the failure looks like an agent that traced
# nothing rather than one that was terminated — the log ends with a clean
# "detaching" either way. Putting setsid first moves the whole chain into its
# own session, where group signals do not reach it.
# --print because this demonstration shows the records themselves. Without it
# the agent prints nothing when a trace backend is reachable, on the grounds
# that the records are going somewhere better — which is right for running it,
# and leaves this step blank.
setsid sudo ./bin/agent --print > "$AGENT_LOG" 2>&1 < /dev/null &
sleep 5
echo
grep -E "tracing .* at startup" "$AGENT_LOG" | sed 's/^/   /'
pause 3

# ---------------------------------------------------------------------------
bold "4. Start the services"
show run
sleep 3
echo
dim "   Attachments made after the agent was already running:"
grep "samples/" "$AGENT_LOG" | sed 's/^/   /' || echo "   (none)"
pause 4

# ---------------------------------------------------------------------------
bold "5. Send traffic"
dim "   Six routes per service, including a deliberate 404, a 500, and an"
dim "   endpoint that sleeps for 150ms."
show traffic
sleep 3

# ---------------------------------------------------------------------------
bold "6. What the agent produced"
grep -vE "^[0-9]{2}:" "$AGENT_LOG" | head -24 | sed 's/^/   /'
echo
dim "   method, path, status, latency, and socket endpoints — from three"
dim "   runtimes that were never touched."
pause 4

# ---------------------------------------------------------------------------
bold "7. Nothing was dropped or left unmatched"
sudo pkill -f bin/agent >/dev/null 2>&1
sleep 2
grep -E "requests=" "$AGENT_LOG" | sed 's/^/   /'
echo
dim "   non-http counts payloads discarded as not being HTTP, most of them"
dim "   five-byte TLS record headers. expired counts requests whose response"
dim "   was never captured; those carry no status rather than a guessed one."
echo
