#!/usr/bin/env bash
# kernel-check.sh — verify that this binary works on this kernel.
#
# Run on each kernel in the matrix, with the same binary every time. Building
# here would test the toolchain; NFR5 is a claim about the artifact, so the
# artifact is what travels. The binary's checksum is reported so that two runs
# can be shown to have exercised the same file.
#
# Reports a result per capability rather than a single pass or fail. The socket
# probe attaches to a kernel-internal symbol with no stability guarantee, and
# its absence is a documented degradation rather than a failure: records are
# still produced, without network endpoints.
#
#   scripts/kernel-check.sh [path-to-agent]

set -uo pipefail

AGENT="${1:-/workspace/bin/agent}"
LOG=/tmp/kernel-check-agent.log
METRICS=localhost:9464

pass=0; fail=0; degraded=0
ok()   { printf "  \033[32mPASS\033[0m      %-34s %s\n" "$1" "${2:-}"; pass=$((pass+1)); }
bad()  { printf "  \033[31mFAIL\033[0m      %-34s %s\n" "$1" "${2:-}"; fail=$((fail+1)); }
warn() { printf "  \033[33mDEGRADED\033[0m  %-34s %s\n" "$1" "${2:-}"; degraded=$((degraded+1)); }
info() { printf "            \033[2m%s\033[0m\n" "$1"; }

echo
echo "Kernel check — $(uname -srm)"
echo "======================================================================"
info "agent:  $AGENT"
info "sha256: $(sha256sum "$AGENT" 2>/dev/null | cut -c1-32)..."
info "built:  $(stat -c %y "$AGENT" 2>/dev/null | cut -d. -f1)"
echo

# --- prerequisites --------------------------------------------------------
if [ -r /sys/kernel/btf/vmlinux ]; then
  ok "kernel BTF" "$(stat -c %s /sys/kernel/btf/vmlinux) bytes"
else
  bad "kernel BTF" "absent; CO-RE cannot resolve relocations"
fi

[ -x "$AGENT" ] || { bad "agent binary" "not executable at $AGENT"; exit 1; }

# --- load -----------------------------------------------------------------
# This is the CO-RE claim. The binary carries relocations rather than fixed
# offsets, and loading resolves them against this kernel's own type information.
# A struct whose layout differs is handled here or not at all.
sudo pkill -x agent 2>/dev/null; sleep 1
sudo setsid "$AGENT" --otlp-endpoint="" --metrics-addr=:9464 > "$LOG" 2>&1 < /dev/null &
sleep 8

if ! pgrep -x agent >/dev/null; then
  bad "agent loads" "see below"
  sed 's/^/            /' "$LOG" | head -12
  exit 1
fi
ok "agent loads" "CO-RE relocations resolved"

if grep -qi "verifier rejected" "$LOG"; then
  bad "verifier accepts programs" "rejected on this kernel"
  grep -i -A3 "verifier rejected" "$LOG" | sed 's/^/            /' | head -8
else
  ok "verifier accepts programs"
fi

attached=$(grep -c "^.*attached " "$LOG")
if [ "$attached" -gt 0 ]; then
  ok "probes attach" "$attached targets"
else
  bad "probes attach" "nothing attached"
fi

# The socket probe is the one expected to be fragile: it attaches to
# tcp_sendmsg, an internal symbol, which is the exception recorded in ADR-003.
if grep -qi "socket endpoints unavailable" "$LOG"; then
  warn "socket endpoint capture" "kprobe did not attach on this kernel"
  info "records are still produced, without network endpoints"
else
  ok "socket endpoint capture" "kprobe attached"
fi

# --- capture --------------------------------------------------------------
before=$(curl -s --max-time 2 "$METRICS/metrics" | awk '/^ebpf_agent_events_received_total/ {s+=$2} END {print s+0}')

for _ in 1 2 3 4 5; do
  curl -sk --http1.1 --max-time 8 https://example.com >/dev/null 2>&1
done
python3 -c "
import urllib.request
for _ in range(3):
    try: urllib.request.urlopen('https://example.com').read()
    except Exception: pass
" 2>/dev/null
sleep 5

after=$(curl -s --max-time 2 "$METRICS/metrics" | awk '/^ebpf_agent_events_received_total/ {s+=$2} END {print s+0}')

if [ "$after" -gt "$before" ]; then
  ok "captures TLS payloads" "$(( after - before )) events"
else
  bad "captures TLS payloads" "no events observed"
fi

if curl -s --max-time 2 "$METRICS/metrics" | grep -q "^ebpf_agent_events_dropped_total"; then
  ok "reports its own health" "metrics endpoint serving"
else
  bad "reports its own health" "metrics absent"
fi

sudo pkill -x agent 2>/dev/null
sleep 2
if pgrep -x agent >/dev/null; then
  bad "detaches cleanly" "still running after SIGTERM"
else
  ok "detaches cleanly"
fi

echo "======================================================================"
printf "  %d passed, %d degraded, %d failed   (%s)\n\n" \
  "$pass" "$degraded" "$fail" "$(uname -r)"
[ "$fail" -eq 0 ]
