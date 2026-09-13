#!/usr/bin/env bash
# leak-check.sh — start and stop the agent repeatedly and check that the kernel
# is left as it was found.
#
# This is the failure that matters most for a node-level agent and is invisible
# to every other test: BPF programs, maps and links are kernel objects, not
# process memory. A program whose link is never closed survives the process that
# created it. Restart such an agent a few hundred times — which a DaemonSet on a
# crash loop does in an afternoon — and the node accumulates orphaned programs
# until map memory or the program limit runs out, with nothing in the agent's
# own telemetry to show for it.
#
# Nothing here needs a workload. Attaching and detaching is what is being
# measured, not capture.
#
#   scripts/ci/leak-check.sh <agent-binary> [cycles]

set -u

AGENT="${1:-dist/agent}"
CYCLES="${2:-5}"
LOG=/tmp/leak-agent.log

pass=0; fail=0
ok()  { printf "  \033[32mPASS\033[0m  %-34s %s\n" "$1" "${2:-}"; pass=$((pass+1)); }
bad() { printf "  \033[31mFAIL\033[0m  %-34s %s\n" "$1" "${2:-}"; fail=$((fail+1)); }

[ -x "$AGENT" ] || { echo "not executable: $AGENT" >&2; exit 1; }
command -v bpftool >/dev/null || BPFTOOL=$(ls -1 /usr/lib/linux-tools/*/bpftool 2>/dev/null | tail -1)
BPFTOOL=${BPFTOOL:-bpftool}
command -v "$BPFTOOL" >/dev/null 2>&1 || { echo "bpftool required" >&2; exit 1; }

count_progs() { "$BPFTOOL" prog show 2>/dev/null | grep -cE '^[0-9]+:'; }
count_maps()  { "$BPFTOOL" map  show 2>/dev/null | grep -cE '^[0-9]+:'; }

echo
printf "\033[1mResource cleanup across %d start/stop cycles\033[0m\n" "$CYCLES"
printf "  kernel %s\n\n" "$(uname -r)"

base_progs=$(count_progs); base_maps=$(count_maps)
printf "  baseline: %s programs, %s maps\n" "$base_progs" "$base_maps"

for i in $(seq 1 "$CYCLES"); do
  setsid "$AGENT" --otlp-endpoint= --metrics-addr=:9464 > "$LOG" 2>&1 < /dev/null &
  pid=$!
  sleep 6

  if ! kill -0 "$pid" 2>/dev/null; then
    bad "cycle $i: agent exited early"
    head -3 "$LOG" | sed 's/^/          /'
    break
  fi

  # SIGTERM, which is what a pod eviction sends. SIGKILL is tested separately in
  # the failure matrix, because the kernel — not the agent — is what cleans up
  # there, and the two paths fail differently.
  kill -TERM "$pid" 2>/dev/null
  for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done

  if kill -0 "$pid" 2>/dev/null; then
    bad "cycle $i: agent ignored SIGTERM"
    kill -KILL "$pid" 2>/dev/null
    break
  fi

  sleep 1
  printf "  cycle %d: %s programs, %s maps\n" "$i" "$(count_progs)" "$(count_maps)"
done

sleep 2
end_progs=$(count_progs); end_maps=$(count_maps)

# Exact equality rather than a tolerance. A leak of one object per restart is
# still a leak, and a threshold would hide precisely the slow accumulation this
# exists to catch.
if [ "$end_progs" -eq "$base_progs" ]; then
  ok "BPF programs released" "$end_progs, same as baseline"
else
  bad "BPF programs leaked" "$base_progs at start, $end_progs after $CYCLES cycles"
  "$BPFTOOL" prog show 2>/dev/null | tail -10 | sed 's/^/          /'
fi

if [ "$end_maps" -eq "$base_maps" ]; then
  ok "BPF maps released" "$end_maps, same as baseline"
else
  bad "BPF maps leaked" "$base_maps at start, $end_maps after $CYCLES cycles"
fi

# Matched on the full invocation, not on the binary path. This script's own
# command line contains that path — it was passed as an argument — so a pattern
# of just "$AGENT" matches the checker and reports a leak on every run.
if pgrep -f -- "$AGENT --otlp-endpoint" >/dev/null 2>&1; then
  bad "agent process still running after SIGTERM"
else
  ok "no agent processes remain"
fi

echo
printf "  %d passed, %d failed\n" "$pass" "$fail"
[ "$fail" -eq 0 ]
