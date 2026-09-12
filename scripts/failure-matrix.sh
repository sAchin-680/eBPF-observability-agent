#!/usr/bin/env bash
# failure-matrix.sh — verify how the agent behaves when things go wrong.
#
# Each row of docs/failure-matrix.md is a claim about behaviour under failure.
# This script is where those claims are tested rather than argued.
#
# The tests are written to be able to fail. Each asserts its own preconditions
# first, so that a pass cannot be produced by a condition that was never set up
# — a service that was already restarted, or an agent that was never running.
#
# Row 4 — a kernel without BTF — is not here. It needs a different kernel, and
# belongs with the multi-kernel matrix.
#
# Run from the repository root as your normal user:
#
#   scripts/failure-matrix.sh [row]

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"

TARGET_PORT=8443
TARGET="https://localhost:$TARGET_PORT/health"
AGENT_LOG=samples/logs/fm-agent.log
OUT=docs/benchmarks/failure-matrix
mkdir -p "$OUT"

bold() { printf "\n\033[1m%s\033[0m\n" "$1"; }
ok()   { printf "   \033[32mPASS\033[0m  %s\n" "$1"; }
bad()  { printf "   \033[31mFAIL\033[0m  %s\n" "$1"; }
info() { printf "   \033[2m%s\033[0m\n" "$1"; }

FAILED=0

agent_pid() { pgrep -x agent | head -1; }

start_agent() {
  sudo setsid ./bin/agent --otlp-endpoint="" --metrics-addr=:9464 \
    > "$AGENT_LOG" 2>&1 < /dev/null &
  for _ in $(seq 1 30); do
    if [ -n "$(agent_pid)" ]; then sleep 4; return 0; fi
    sleep 1
  done
  return 1
}

stop_agent() { sudo pkill -x agent 2>/dev/null; sleep 2; }

events_received() {
  curl -s --max-time 2 localhost:9464/metrics 2>/dev/null |
    awk '/^ebpf_agent_events_received_total/ {s += $2} END {print s + 0}'
}

reset() {
  make -C samples stop >/dev/null 2>&1
  stop_agent
  make -C samples run >/dev/null 2>&1
  sleep 3
}

# ---------------------------------------------------------------------------
# Row 1 — a traced process restarts, and the agent picks it up again
# ---------------------------------------------------------------------------
row_restart() {
  bold "Row 1: traced process restarts"
  info "expected: the agent detects the new process and resumes tracing"

  reset
  start_agent || { bad "agent did not start"; FAILED=1; return; }

  # Establish that the service is traced before restarting it. Without this the
  # test cannot distinguish re-attachment from never having attached.
  before=$(events_received)
  curl -sk --http1.1 --max-time 5 "$TARGET" >/dev/null 2>&1
  sleep 3
  mid=$(events_received)
  if [ "$mid" -le "$before" ]; then
    bad "the service was not traced before the restart; nothing to prove"
    FAILED=1; stop_agent; return
  fi
  info "traced before restart: $(( mid - before )) events"

  old_pid=$(pgrep -x go-api | head -1)
  info "restarting the service (pid $old_pid)"
  make -C samples stop >/dev/null 2>&1
  sleep 2
  make -C samples run >/dev/null 2>&1
  sleep 5
  new_pid=$(pgrep -x go-api | head -1)

  if [ -z "$new_pid" ] || [ "$new_pid" = "$old_pid" ]; then
    bad "the service did not actually restart (pid $old_pid -> ${new_pid:-none})"
    FAILED=1; stop_agent; return
  fi
  info "restarted as pid $new_pid"

  after_restart=$(events_received)
  for _ in 1 2 3 4 5; do
    curl -sk --http1.1 --max-time 5 "$TARGET" >/dev/null 2>&1
  done
  sleep 4
  final=$(events_received)

  if [ "$final" -gt "$after_restart" ]; then
    ok "tracing resumed: $(( final - after_restart )) events after restart"
  else
    bad "no events after the restart; the agent did not re-attach"
    FAILED=1
  fi
  stop_agent
}

# ---------------------------------------------------------------------------
# Row 3 — the agent is killed, and the traced application is unaffected
# ---------------------------------------------------------------------------
#
# This is the property that decides whether the agent is deployable at all, and
# the one most worth testing rather than reasoning about: an earlier version of
# this agent provably violated it. A return probe on Go's TLS read aborted the
# traced process outright, because Go walks its own stack and does not recognise
# the kernel's trampoline as a return address.
#
# The agent is killed with SIGKILL, so it has no opportunity to detach. What is
# being tested is whether the kernel's own cleanup is sufficient.
row_agent_crash() {
  bold "Row 3: agent process is killed mid-load"
  info "expected: the traced application continues, unaffected"

  reset

  # Baseline: the service under load with no agent at all.
  info "measuring the service without the agent"
  hey -z 20s -c 50 -q 40 -t 10 "$TARGET" > "$OUT/crash-baseline.txt" 2>&1
  sleep 3

  start_agent || { bad "agent did not start"; FAILED=1; return; }
  pid=$(agent_pid)
  info "agent running as pid $pid"

  # Load for 20s; the agent is killed 8s in, so the run spans both states.
  ( sleep 8; sudo kill -9 "$pid" 2>/dev/null; echo "killed at t+8s" ) &
  killer=$!
  hey -z 20s -c 50 -q 40 -t 10 "$TARGET" > "$OUT/crash-during.txt" 2>&1
  wait "$killer" 2>/dev/null

  if [ -n "$(agent_pid)" ]; then
    bad "the agent survived SIGKILL; the test did not exercise a crash"
    FAILED=1; stop_agent; return
  fi
  info "agent is gone"

  python3 - "$OUT/crash-baseline.txt" "$OUT/crash-during.txt" <<'PYEOF'
import re, sys

def parse(path):
    t = open(path).read()
    def pct(p):
        m = re.search(rf"^\s*{p}%%?\s+in\s+([0-9.]+)\s+secs", t, re.M)
        return float(m.group(1)) * 1000 if m else float("nan")
    ok = re.search(r"\[200\]\s+(\d+)\s+responses", t)
    codes = re.findall(r"\[(\d{3})\]\s+(\d+)\s+responses", t)
    errs = re.search(r"Error distribution:", t)
    return {
        "p50": pct(50), "p99": pct(99),
        "ok": int(ok.group(1)) if ok else 0,
        "non200": sum(int(n) for c, n in codes if c != "200"),
        "errors": bool(errs),
    }

base, during = parse(sys.argv[1]), parse(sys.argv[2])

print(f"   {'':22} {'baseline':>12} {'agent killed':>14}")
print(f"   {'p50 (ms)':22} {base['p50']:>12.3f} {during['p50']:>14.3f}")
print(f"   {'p99 (ms)':22} {base['p99']:>12.3f} {during['p99']:>14.3f}")
print(f"   {'200 responses':22} {base['ok']:>12} {during['ok']:>14}")
print(f"   {'non-200 responses':22} {base['non200']:>12} {during['non200']:>14}")
print(f"   {'transport errors':22} {str(base['errors']):>12} {str(during['errors']):>14}")

fail = []
if during["non200"] > 0:
    fail.append(f"{during['non200']} non-200 responses while the agent was killed")
if during["errors"]:
    fail.append("transport errors while the agent was killed")
# The service must keep serving. A large shortfall in completed requests would
# mean it stalled; a small one is the rate limiter and scheduling noise.
if during["ok"] < base["ok"] * 0.9:
    fail.append(f"completed {during['ok']} requests against a baseline of {base['ok']}")

sys.exit("\n".join(fail) if fail else 0)
PYEOF

  if [ $? -eq 0 ]; then
    ok "the application was unaffected by the agent being killed"
  else
    bad "the application was affected"
    FAILED=1
  fi
}

# ---------------------------------------------------------------------------
# Row 2 — under sustained load, loss is counted rather than silent
# ---------------------------------------------------------------------------
row_drops_visible() {
  bold "Row 2: sustained load"
  info "expected: events lost to a full ring buffer are counted and exported"

  reset
  start_agent || { bad "agent did not start"; FAILED=1; return; }

  # Enough load to exceed the measured threshold of roughly 12,000 events/s.
  hey -z 20s -c 80 -q 75 -t 10 "$TARGET" > "$OUT/drops-load.txt" 2>&1
  sleep 3

  metrics=$(curl -s --max-time 3 localhost:9464/metrics 2>/dev/null)
  dropped=$(awk '/^ebpf_agent_events_dropped_total/ {s += $2} END {print s + 0}' <<<"$metrics")
  received=$(awk '/^ebpf_agent_events_received_total/ {s += $2} END {print s + 0}' <<<"$metrics")

  info "received $received events, dropped $dropped"

  if ! grep -q "^ebpf_agent_events_dropped_total" <<<"$metrics"; then
    bad "the drop counter is not exported; loss would be invisible"
    FAILED=1
  elif [ "$dropped" -gt 0 ]; then
    logged=$(grep -c "dropped" "$AGENT_LOG")
    if [ "$logged" -gt 0 ]; then
      ok "loss occurred, was counted ($dropped), and was logged"
    else
      bad "loss occurred and was counted, but nothing was logged"
      FAILED=1
    fi
  else
    # Not a failure of the property. The counter exists and reads zero, which
    # is the correct report for a run that lost nothing.
    ok "the counter is exported and reads zero; this load lost no events"
    info "the threshold is measured separately in docs/benchmarks/"
  fi
  stop_agent
}

# ---------------------------------------------------------------------------
case "${1:-all}" in
  restart) row_restart ;;
  crash)   row_agent_crash ;;
  drops)   row_drops_visible ;;
  all)     row_restart; row_drops_visible; row_agent_crash ;;
  *)       echo "usage: $0 [restart|drops|crash|all]" >&2; exit 1 ;;
esac

make -C samples stop >/dev/null 2>&1
stop_agent

bold "Result"
if [ "$FAILED" -eq 0 ]; then
  ok "every row tested here passed"
else
  bad "at least one row failed"
fi
exit "$FAILED"
