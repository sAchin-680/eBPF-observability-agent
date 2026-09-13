#!/usr/bin/env bash
# capabilities.sh — find the smallest capability set the agent actually needs.
#
# NFR4 says CAP_BPF and CAP_PERFMON, and never --privileged. That is a claim,
# and this establishes whether it is true by running the agent with each
# candidate set and recording what breaks.
#
# Capabilities are attached to the binary with setcap and the agent runs as an
# ordinary user, which is how a Kubernetes securityContext grants them. Running
# as root and dropping capabilities would test something subtly different: root
# bypasses several permission checks outright, so a set that works for root can
# fail for a user holding the same capabilities.
#
# The binary is copied to a local filesystem first. The working tree is a shared
# mount, and file capabilities are extended attributes that a mount may not
# support — and when it does not, setcap fails quietly enough to look like a
# capability problem.
#
# Run from the repository root as your normal user.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.."

AGENT=bin/agent
WORK=/tmp/cap-test
TARGET=https://localhost:8443/health
RESULTS="$WORK/results.txt"

bold() { printf "\n\033[1m%s\033[0m\n" "$1"; }
info() { printf "   \033[2m%s\033[0m\n" "$1"; }

[ -x "$AGENT" ] || { echo "build first: make build" >&2; exit 1; }
command -v setcap >/dev/null || { echo "setcap required: apt install libcap2-bin" >&2; exit 1; }

mkdir -p "$WORK"
: > "$RESULTS"

# The capability sets to try, least privileged first.
#
# Each is a guess at what the agent needs; the point is to find which guesses
# are wrong. CAP_SYS_PTRACE is included because discovery reads other processes'
# address-space layout through /proc, which is what that capability gates —
# something the original claim did not account for.
SETS=(
  "cap_bpf"
  "cap_bpf,cap_perfmon"
  "cap_bpf,cap_perfmon,cap_dac_read_search"
  "cap_bpf,cap_perfmon,cap_sys_ptrace,cap_dac_read_search"
  "cap_bpf,cap_perfmon,cap_sys_ptrace,cap_dac_read_search,cap_sys_resource"
  "cap_sys_admin,cap_dac_read_search"
  "cap_bpf,cap_perfmon,cap_sys_admin,cap_sys_ptrace,cap_dac_read_search"
)

# run_with executes the agent holding one capability set and reports what
# worked. Every failure mode is distinguished, because "it did not work" is not
# a useful result: the interesting output is which operation failed first.
run_with() {
  local caps="$1"
  local bin="$WORK/agent"
  local log="$WORK/${caps//,/-}.log"

  cp -f "$AGENT" "$bin"
  if ! sudo setcap "${caps}=ep" "$bin" 2>"$WORK/setcap.err"; then
    printf "   %-52s \033[31mcannot set\033[0m  %s\n" "$caps" "$(head -1 "$WORK/setcap.err")"
    return
  fi

  # No sudo. The whole point is that the capabilities carry the privilege.
  setsid "$bin" --otlp-endpoint= --metrics-addr=:9466 > "$log" 2>&1 < /dev/null &
  sleep 6

  local outcome detail
  if ! pgrep -f "$bin" >/dev/null 2>&1; then
    outcome="did not start"
    detail="$(grep -oE '(loading kernel programs|attaching probes)[^"]*' "$log" | head -1 | cut -c1-60)"
    [ -z "$detail" ] && detail="$(head -1 "$log" | cut -c1-60)"
  else
    local attached events
    attached=$(grep -c "attached " "$log")
    curl -sk --http1.1 --max-time 6 "$TARGET" >/dev/null 2>&1
    curl -sk --http1.1 --max-time 6 https://example.com >/dev/null 2>&1
    sleep 4
    events=$(curl -s --max-time 2 localhost:9466/metrics 2>/dev/null |
             awk '/^ebpf_agent_events_received_total/ {s+=$2} END {print s+0}')

    if [ "$attached" -eq 0 ]; then
      outcome="loads, attaches nothing"
      detail="discovery found no targets"
    elif [ "${events:-0}" -eq 0 ]; then
      outcome="attaches, captures nothing"
      detail="$attached targets, 0 events"
    else
      outcome="works"
      detail="$attached targets, $events events"
    fi
    pkill -f "$bin" 2>/dev/null
    sleep 1
  fi

  local colour=31
  [ "$outcome" = "works" ] && colour=32
  printf "   %-52s \033[${colour}m%-26s\033[0m %s\n" "$caps" "$outcome" "$detail"
  echo "$caps|$outcome|$detail" >> "$RESULTS"
}

bold "Capability scoping"
info "agent runs as $(id -un), privilege comes only from file capabilities"
info "kernel $(uname -r)"
echo

make -C samples stop >/dev/null 2>&1
sudo pkill -x agent 2>/dev/null
make -C samples run >/dev/null 2>&1
sleep 3

printf "   %-52s %-26s %s\n" "CAPABILITY SET" "OUTCOME" "DETAIL"
printf "   %-52s %-26s %s\n" "$(printf '%.0s-' {1..52})" "$(printf '%.0s-' {1..26})" "------"

for caps in "${SETS[@]}"; do
  run_with "$caps"
done

# Root, for comparison. Not a candidate — it is the thing being avoided — but
# without it there is nothing to say a failure above was caused by the
# capability set rather than by the environment.
bold "Reference"
sudo pkill -x agent 2>/dev/null
setsid sudo "$AGENT" --otlp-endpoint= --metrics-addr=:9466 > "$WORK/root.log" 2>&1 < /dev/null &
sleep 6
curl -sk --http1.1 --max-time 6 "$TARGET" >/dev/null 2>&1
sleep 4
root_events=$(curl -s --max-time 2 localhost:9466/metrics 2>/dev/null |
              awk '/^ebpf_agent_events_received_total/ {s+=$2} END {print s+0}')
printf "   %-52s \033[32m%-26s\033[0m %s\n" "root (for comparison, not a target)" "works" \
  "$(grep -c 'attached ' "$WORK/root.log") targets, ${root_events:-0} events"
sudo pkill -x agent 2>/dev/null

make -C samples stop >/dev/null 2>&1
bold "Results"
info "$RESULTS"
info "per-set agent logs in $WORK/"
