#!/usr/bin/env bash
# gate-phase2.sh — the Phase 2 acceptance test.
#
# A previously unseen application must appear in the telemetry with no
# configuration change and no agent restart.
#
# The test is written to be able to fail. It asserts that the new service is
# absent before it is started, checks that nothing outside samples/ names it,
# and counts agent restarts, so that a pass cannot be produced by a service that
# was already running or by an agent that was restarted to pick it up.
#
# Run from the repository root as your normal user.

# No pipefail: a pipeline ending in grep -q reports failure when the producer is
# killed by SIGPIPE after the match, which inverts the check.
set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export PATH="$PATH:/usr/local/go/bin"

NEW_SERVICE="ruby-api"
NEW_PORT=8446
PROM=localhost:9090
TEMPO=localhost:3200
AGENT_LOG=samples/logs/agent.log

# Every trace query is scoped to this run. Tempo retains traces for an hour, so
# a previous run of this test leaves its own evidence behind — and an unscoped
# query would find it and conclude the service was already known. Rather than
# wiping the backend, which would also discard unrelated data, the window
# starts when this run does.
RUN_START=$(date +%s)

# Every trace query is scoped to this run. Tempo retains traces for an hour, so
# a previous run of this test leaves its own evidence behind — and an unscoped
# query would find it and conclude the service was already known. Rather than
# wiping the backend, which would also discard unrelated data, the window
# starts when this run does.
RUN_START=$(date +%s)

# Every trace query is scoped to this run. Tempo retains traces for an hour, so
# a previous run of this test leaves its own evidence behind — and an unscoped
# query would find it and conclude the service was already known. Rather than
# wiping the backend, which would also discard unrelated data, the window
# starts when this run does.
RUN_START=$(date +%s)

bold() { printf "\n\033[1m%s\033[0m\n" "$1"; }
ok()   { printf "   \033[32m%s\033[0m\n" "$1"; }
bad()  { printf "   \033[31m%s\033[0m\n" "$1"; }

services_in_prometheus() {
  curl -s --get "$PROM/api/v1/query" \
    --data-urlencode 'query=group by (service_name) (http_server_requests_total{span_kind="server"})' |
    python3 -c 'import json,sys; print(",".join(sorted(s["metric"]["service_name"] for s in json.load(sys.stdin)["data"]["result"])))'
}

# Traces are counted by searching for the service, not by reading the tag
# index. The tag index is built from flushed blocks, so a service that started
# producing traces seconds ago is absent from it while its traces are plainly
# queryable — and a service that stopped producing them long ago is still
# present. Neither answers the question this test asks.
traces_for_service() {
  curl -s --get "$TEMPO/api/search" \
    --data-urlencode "q={resource.service.name=\"$1\"}" \
    --data-urlencode "start=$RUN_START" \
    --data-urlencode "end=$(date +%s)" \
    --data-urlencode "limit=20" |
    python3 -c 'import json,sys; print(len(json.load(sys.stdin).get("traces") or []))'
}

# ---------------------------------------------------------------------------
bold "1. Nothing outside samples/ names the new service"
# Generated files are excluded: bpf/vmlinux.h is 180,000 lines rendered from the
# kernel's own type information, and a bare port number occurs in it by
# coincidence. Only authored source can express knowledge of a service.
if grep -rli "$NEW_SERVICE\|$NEW_PORT" --include='*.go' --include='*.c' --include='*.h' \
     --include='*.yaml' --include='*.json' \
     --exclude='vmlinux.h' --exclude='*_bpfel*.go' --exclude='*_bpfeb*.go' \
     cmd internal bpf deploy scripts 2>/dev/null; then
  bad "found above — the agent or its configuration names this service"
  exit 1
fi
ok "neither '$NEW_SERVICE' nor port $NEW_PORT appears in cmd/ internal/ bpf/ deploy/ scripts/"

# Stated rather than hidden: the agent does contain the string "ruby", in the
# list of interpreter names used for service naming. That is knowledge that Ruby
# is an interpreted language, which applies to every Ruby program ever written.
# It is not knowledge that this service exists, and removing it would not
# prevent the service being traced — it would only make the inferred name worse.
if [ "$(grep -rl '"ruby"' --include='*.go' internal 2>/dev/null | wc -l)" -gt 0 ]; then
  printf "   \033[2m%s\033[0m\n" \
    "note: 'ruby' appears in the generic-interpreter list in internal/proc/service.go." \
    "      That is language-level knowledge, not service-level, and affects only" \
    "      the inferred name. Capture does not depend on it."
fi

# ---------------------------------------------------------------------------
bold "2. Start from a known state, without the new service"
make -C samples stop >/dev/null 2>&1
pkill -f "ruby.*server.rb" 2>/dev/null
sudo pkill -9 -f 'bin/agent$' 2>/dev/null
sleep 2
make -C samples run >/dev/null 2>&1
sleep 3

rm -f "$AGENT_LOG"
sudo setsid ./bin/agent > "$AGENT_LOG" 2>&1 < /dev/null &
sleep 7
sed -n 's/^/   /p' <<<"$(grep -E 'tracing .* at startup' "$AGENT_LOG")"

# ---------------------------------------------------------------------------
bold "3. The new service is absent before it is started"
for _ in 1 2 3; do make -C samples traffic >/dev/null 2>&1; done
sleep 8

before_prom=$(services_in_prometheus)
before_traces=$(traces_for_service "$NEW_SERVICE")
echo "   prometheus services: $before_prom"
echo "   traces for $NEW_SERVICE: $before_traces"
if [[ "$before_prom" == *"$NEW_SERVICE"* ]] || [ "$before_traces" -gt 0 ]; then
  bad "$NEW_SERVICE is already present — the test would prove nothing"
  exit 1
fi
ok "$NEW_SERVICE is absent, as required"

# ---------------------------------------------------------------------------
bold "4. Start the new service. The agent is not touched."
( cd samples/ruby-api && setsid ruby server.rb > ../logs/ruby-api.log 2>&1 < /dev/null & )
sleep 4
if curl -sk --http1.1 --max-time 5 "https://localhost:$NEW_PORT/health" >/dev/null 2>&1; then
  ok "$NEW_SERVICE is responding on :$NEW_PORT"
else
  bad "$NEW_SERVICE did not start — see samples/logs/ruby-api.log"
  exit 1
fi

# ---------------------------------------------------------------------------
bold "5. Send traffic to the new service only"
for _ in 1 2 3 4 5 6; do
  for path in /health /users /users/1 /users/999 /slow /error; do
    curl -sk --http1.1 --max-time 5 "https://localhost:$NEW_PORT$path" >/dev/null 2>&1
  done
  curl -sk --http1.1 --max-time 5 -X POST -d '{}' "https://localhost:$NEW_PORT/users" >/dev/null 2>&1
done
sleep 12

# ---------------------------------------------------------------------------
bold "6. Result"
after_prom=$(services_in_prometheus)
after_traces=$(traces_for_service "$NEW_SERVICE")
echo "   prometheus services: $after_prom"
echo "   traces for $NEW_SERVICE: $after_traces"

restarts=$(grep -c 'tracing .* at startup' "$AGENT_LOG")
echo "   agent starts during this run: $restarts"

fail=0
[[ "$after_prom"  == *"$NEW_SERVICE"* ]] || { bad "$NEW_SERVICE produced no metrics"; fail=1; }
[ "$after_traces" -gt 0 ] || { bad "$NEW_SERVICE produced no traces"; fail=1; }
[[ "$restarts" -eq 1 ]] || { bad "the agent started $restarts times; it must start once"; fail=1; }

if [ "$fail" -eq 0 ]; then
  ok "PASS — an unseen service appeared in traces and metrics, with no"
  ok "       configuration change and no agent restart"
else
  bad "FAIL"
fi
exit "$fail"
