#!/usr/bin/env bash
# bench.sh — measure what the agent costs.
#
# Runs the same load against the same service with the agent attached and
# without, and records the difference. Also records the agent's own CPU and the
# events it lost, so a latency figure can be read together with whether the
# agent was keeping up when it was measured.
#
# Results are written as CSV to docs/benchmarks/, alongside the raw output of
# every run. The raw files are kept because a summary cannot be checked, and a
# summary can always be regenerated from them.
#
# Run from the repository root as your normal user:
#
#   scripts/bench.sh [-d duration] [-r "rates"] [-n repeats] [-o name]

# No pipefail: pipelines here end in tools that stop reading early, which
# leaves the producer killed by SIGPIPE and turns a success into a failure.
set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"

DURATION=20
RATES="200 500 1000 2000 4000 8000"
REPEATS=3
NAME="$(date +%Y%m%d-%H%M%S)"
TARGET="https://localhost:8443/health"
CONNECTIONS=50

while getopts "d:r:n:o:t:c:" opt; do
  case "$opt" in
    d) DURATION="$OPTARG" ;;
    r) RATES="$OPTARG" ;;
    n) REPEATS="$OPTARG" ;;
    o) NAME="$OPTARG" ;;
    t) TARGET="$OPTARG" ;;
    c) CONNECTIONS="$OPTARG" ;;
    *) exit 1 ;;
  esac
done

OUT="docs/benchmarks/$NAME"
RAW="$OUT/raw"
CSV="$OUT/results.csv"
mkdir -p "$RAW"

bold() { printf "\n\033[1m%s\033[0m\n" "$1"; }
info() { printf "   \033[2m%s\033[0m\n" "$1"; }

command -v hey >/dev/null || {
  echo "hey is required: go install github.com/rakyll/hey@latest" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# Agent lifecycle
# ---------------------------------------------------------------------------

# Matched on process name. The command line carries flags, so a pattern anchored
# on the binary path finds nothing, and an unanchored one also matches the sudo
# that launched it.
agent_pid() { pgrep -x agent | head -1; }

start_agent() {
  # Trace export is disabled while measuring. Exporting opens TLS connections
  # the agent would then trace, and the cost of doing so would be counted as
  # capture cost. Metrics stay enabled, because the drop counter is part of the
  # measurement.
  setsid sudo ./bin/agent --otlp-endpoint="" --metrics-addr=:9464 \
    > samples/logs/bench-agent.log 2>&1 < /dev/null &
  for _ in $(seq 1 30); do
    if [ -n "$(agent_pid)" ]; then sleep 3; return 0; fi
    sleep 1
  done
  echo "agent did not start; see samples/logs/bench-agent.log" >&2
  return 1
}

stop_agent() {
  sudo pkill -x agent 2>/dev/null
  sleep 2
}

# A control that consumes CPU without observing anything.
#
# The first runs of this benchmark reported the traced arm as faster, in every
# repetition and in both orderings. A probe cannot make a request faster, so
# something other than the probe was responsible. The leading explanation is
# that an otherwise idle machine lets cores drop into low-power states, and a
# request arriving at an idle core waits for it to come back — so any additional
# load reduces latency, whatever that load is doing.
#
# This arm tests that explanation. It burns roughly the CPU the agent does,
# attaches nothing, and loads no kernel programs. If it shows the same
# "speed-up", the effect belongs to the machine and not to the agent, and the
# agent's real cost is the traced arm measured against this rather than against
# an idle one.
CONTROL_PIDS=()

start_control() {
  local workers="${1:-1}"
  for _ in $(seq 1 "$workers"); do
    bash -c 'while :; do :; done' &
    CONTROL_PIDS+=($!)
  done
  sleep 3
}

stop_control() {
  for pid in "${CONTROL_PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null
  done
  CONTROL_PIDS=()
  sleep 2
}

# cpu_ticks reads a process's accumulated CPU from /proc, in clock ticks.
# Sampling either side of a run gives what that run cost, without a sampling
# tool that would consume some itself.
cpu_ticks() {
  local pid="${1:-}"
  [ -z "$pid" ] && { echo 0; return; }
  awk '{print $14 + $15}' "/proc/$pid/stat" 2>/dev/null || echo 0
}

# dropped_events reads the agent's count of events lost to a full ring buffer.
# A latency measurement taken while the agent was dropping describes a different
# system from one taken while it was keeping up.
dropped_events() {
  curl -s --max-time 2 localhost:9464/metrics 2>/dev/null |
    awk '/^ebpf_agent_events_dropped_total/ {sum += $2} END {print sum + 0}'
}

# received_events reads the agent's count of events read from the ring buffers.
#
# Reported alongside drops so the agent's limit can be stated per event rather
# than per request. How many events a request produces depends on the traffic:
# a large response arrives in several reads, TLS record headers are read
# separately, and the load generator's own TLS traffic is captured too. A
# threshold in requests per second describes this test; one in events per second
# describes the agent.
received_events() {
  curl -s --max-time 2 localhost:9464/metrics 2>/dev/null |
    awk '/^ebpf_agent_events_received_total/ {sum += $2} END {print sum + 0}'
}

# ---------------------------------------------------------------------------
# One measurement
# ---------------------------------------------------------------------------

run_load() {
  local arm="$1" rate="$2" rep="$3"
  local raw="$RAW/${arm}-${rate}-rep${rep}.txt"

  # -q is per worker, so the requested rate is divided across connections.
  local per_worker=$(( rate / CONNECTIONS ))
  [ "$per_worker" -lt 1 ] && per_worker=1

  hey -z "${DURATION}s" -c "$CONNECTIONS" -q "$per_worker" -t 10 \
      "$TARGET" > "$raw" 2>&1

  python3 - "$raw" <<'PYEOF'
import re, sys
text = open(sys.argv[1]).read()

def pct(label):
    # hey prints a literal double percent, e.g. "  50%% in 0.0018 secs".
    m = re.search(rf"^\s*{label}%%?\s+in\s+([0-9.]+)\s+secs", text, re.M)
    return float(m.group(1)) if m else float("nan")

rps = re.search(r"Requests/sec:\s+([0-9.]+)", text)
ok = re.search(r"\[200\]\s+(\d+)\s+responses", text)

print(",".join([
    f"{float(rps.group(1)):.1f}" if rps else "nan",
    f"{pct(50)*1000:.3f}", f"{pct(95)*1000:.3f}", f"{pct(99)*1000:.3f}",
    ok.group(1) if ok else "0",
]))
PYEOF
}

# ---------------------------------------------------------------------------
bold "Benchmark: $NAME"
info "target      $TARGET"
info "duration    ${DURATION}s per run"
info "connections $CONNECTIONS"
info "rates       $RATES"
info "repeats     $REPEATS"

make -C samples stop >/dev/null 2>&1
stop_agent
make -C samples run >/dev/null 2>&1
sleep 3
curl -sk --max-time 5 "$TARGET" >/dev/null || {
  echo "target not responding: $TARGET" >&2
  exit 1
}

# Warm up, and discard it.
#
# The first measured run would otherwise pay for everything that happens once:
# TLS session setup, lazy initialisation in the server's runtime, cold caches.
# Whichever arm ran first would absorb that and look slower — the first attempt
# at this benchmark reported the agent making requests faster, which was exactly
# that cost landing on the untraced arm.
bold "Warm-up"
info "discarded; removes one-time costs from the first measurement"
hey -z 10s -c "$CONNECTIONS" -q 20 "$TARGET" > "$RAW/warmup.txt" 2>&1
sleep 3

{
  echo "# ebpf-observability-agent benchmark"
  echo "# date:        $(date -Is)"
  echo "# kernel:      $(uname -r)"
  echo "# arch:        $(uname -m)"
  echo "# cpus:        $(nproc)"
  echo "# target:      $TARGET"
  echo "# duration:    ${DURATION}s"
  echo "# connections: $CONNECTIONS"
  echo "# repeats:     $REPEATS"
  echo "arm,requested_rps,achieved_rps,p50_ms,p95_ms,p99_ms,ok_responses,agent_cpu_s,dropped_events,received_events,events_per_s"
} > "$CSV"

bold "Measuring"

# Each point is measured several times, with the order of the two arms
# alternating between repetitions.
#
# A single pair is not enough. Warm-up removes most one-time cost, but whichever
# arm runs second within a pair still benefits from the pair before it.
# Alternating the order and reporting medians removes that advantage rather than
# assuming it is small.
for rate in $RATES; do
  for rep in $(seq 1 "$REPEATS"); do
    if [ $(( rep % 2 )) -eq 1 ]; then
      order="untraced control traced"
    else
      order="traced control untraced"
    fi

    for arm in $order; do
      case "$arm" in
        traced)  start_agent || exit 1 ;;
        control) start_control 1 ;;
      esac

      pid="$(agent_pid)"
      cpu_before=$(cpu_ticks "$pid")
      drops_before=$(dropped_events)
      recv_before=$(received_events)

      result=$(run_load "$arm" "$rate" "$rep")

      cpu_after=$(cpu_ticks "$pid")
      drops_after=$(dropped_events)
      recv_after=$(received_events)

      ticks=$(( cpu_after - cpu_before ))
      cpu_s=$(python3 -c "print(f'{$ticks / $(getconf CLK_TCK):.2f}')")
      drops=$(( drops_after - drops_before ))
      recv=$(( recv_after - recv_before ))
      events_per_s=$(python3 -c "print(f'{$recv / $DURATION:.0f}')")

      echo "$arm,$rate,$result,$cpu_s,$drops,$recv,$events_per_s" >> "$CSV"
      printf "   rep%-2s %-9s %6s req/s  achieved %-8s p50 %-8s p95 %-8s p99 %-8s cpu %-6s drops %s\n" \
        "$rep" "$arm" "$rate" $(echo "$result" | cut -d, -f1-4 | tr ',' ' ') "$cpu_s" "$drops"
      [ "$arm" = traced ] && printf "        events %s (%s/s)\n" "$recv" "$events_per_s"

      case "$arm" in
        traced)  stop_agent ;;
        control) stop_control ;;
      esac

      # Settle, so one run's queue does not become the next run's latency.
      sleep 4
    done
  done
done

make -C samples stop >/dev/null 2>&1

# ---------------------------------------------------------------------------
bold "Summary (median of $REPEATS repetitions)"
python3 - "$CSV" <<'PYEOF'
import csv, statistics, sys

rows = [r for r in csv.DictReader(l for l in open(sys.argv[1]) if not l.startswith("#"))]

def med(arm, rate, field):
    vals = [float(r[field]) for r in rows
            if r["arm"] == arm and r["requested_rps"] == rate
            and r[field] not in ("", "nan")]
    return statistics.median(vals) if vals else float("nan")

rates = sorted({r["requested_rps"] for r in rows}, key=int)

print(f"   {'rps':>6} {'p50 idle':>9} {'p50 ctl':>9} {'p50 agt':>9} {'agt-ctl':>9} "
      f"{'p99 ctl':>9} {'p99 agt':>9} {'agt-ctl':>9} {'cpu s':>7} {'events/s':>9} "
      f"{'drops':>7} {'loss':>7}")
for rate in rates:
    p50i = med("untraced", rate, "p50_ms")
    p50c, p50t = med("control", rate, "p50_ms"), med("traced", rate, "p50_ms")
    p99c, p99t = med("control", rate, "p99_ms"), med("traced", rate, "p99_ms")
    cpu = med("traced", rate, "agent_cpu_s")
    drops = sum(int(r["dropped_events"]) for r in rows
                if r["arm"] == "traced" and r["requested_rps"] == rate)
    eps = med("traced", rate, "events_per_s")
    recv = sum(int(r["received_events"]) for r in rows
               if r["arm"] == "traced" and r["requested_rps"] == rate)
    loss = 100.0 * drops / (drops + recv) if (drops + recv) else 0.0
    print(f"   {rate:>6} {p50i:>9.3f} {p50c:>9.3f} {p50t:>9.3f} {p50t - p50c:>+9.3f} "
          f"{p99c:>9.3f} {p99t:>9.3f} {p99t - p99c:>+9.3f} {cpu:>7.2f} "
          f"{eps:>9.0f} {drops:>7} {loss:>6.2f}%")

print()
print("   Latency in milliseconds.")
print()
print("   The agent's cost is the difference against the control, not against")
print("   the idle machine. The control burns comparable CPU while observing")
print("   nothing, so whatever an idle machine's latency owes to power states")
print("   and cold caches is present in both. Comparing against idle instead")
print("   attributes that to the agent, with the wrong sign.")
PYEOF

bold "Results"
echo "   $CSV"
echo "   $RAW/ (raw output of every run)"
