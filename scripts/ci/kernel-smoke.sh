#!/usr/bin/env bash
# kernel-smoke.sh — run the prebuilt artifacts against whatever kernel is
# currently booted.
#
# This is the script the CI matrix runs inside each VM. It receives binaries it
# did not build and must not build anything: the claim under test (NFR5) is that
# ONE compiled artifact loads on several kernels, and a script that recompiles
# per kernel would test the toolchain instead and pass either way.
#
# It reports the kernel and the checksum of every artifact it ran, so two runs
# can be shown to have exercised the same bytes.
#
#   scripts/ci/kernel-smoke.sh <dist-dir>

set -u

DIST="${1:-dist}"
AGENT="$DIST/agent"
LOG=/tmp/agent-smoke.log

pass=0; fail=0
ok()   { printf "  \033[32mPASS\033[0m  %-32s %s\n" "$1" "${2:-}"; pass=$((pass+1)); }
bad()  { printf "  \033[31mFAIL\033[0m  %-32s %s\n" "$1" "${2:-}"; fail=$((fail+1)); }
info() { printf "        \033[2m%s\033[0m\n" "$1"; }

echo
printf "\033[1mkernel %s  (%s)\033[0m\n" "$(uname -r)" "$(uname -m)"
for f in "$DIST"/*; do
  [ -f "$f" ] || continue
  info "$(basename "$f")  $(sha256sum "$f" | cut -c1-16)"
done
echo

# BTF has to exist for CO-RE to relocate anything. Checked first because every
# failure below is explained by its absence, and the error the loader produces
# does not say so.
if [ -r /sys/kernel/btf/vmlinux ]; then
  ok "BTF present" "$(stat -c%s /sys/kernel/btf/vmlinux) bytes"
else
  bad "BTF missing" "CONFIG_DEBUG_INFO_BTF=n — CO-RE is impossible here"
  echo; echo "  $pass passed, $fail failed"; exit 1
fi

# The compiled Go test binaries. These load real programs and, in the verifier
# case, deliberately load programs the verifier must reject — so a kernel that
# accepts what older kernels refused shows up as a failure here rather than as a
# silent change in behaviour.
for t in "$DIST"/*.test; do
  [ -x "$t" ] || continue
  name=$(basename "$t" .test)
  if out=$("$t" -test.v 2>&1); then
    ok "$name" "$(grep -c -- '--- PASS' <<<"$out") subtests"
  else
    bad "$name"
    grep -E -- '--- FAIL|FAIL|panic' <<<"$out" | head -5 | sed 's/^/          /'
  fi
done

# The agent itself: does the object load and relocate against THIS kernel's
# types. Attaching to nothing is an acceptable outcome here — a CI VM runs no
# TLS workload — so the assertion is that it reached its read loop, not that it
# captured anything.
if [ -x "$AGENT" ]; then
  setsid "$AGENT" --otlp-endpoint= --metrics-addr=:9464 > "$LOG" 2>&1 < /dev/null &
  sleep 8
  if grep -q "reading events" "$LOG"; then
    ok "agent loads and attaches" "$(grep -c 'attached ' "$LOG") targets on this VM"
  else
    bad "agent did not reach its read loop"
    head -5 "$LOG" | sed 's/^/          /'
  fi
  pkill -f "$AGENT" 2>/dev/null
else
  bad "agent binary missing" "$AGENT"
fi

echo
printf "  %d passed, %d failed\n" "$pass" "$fail"
[ "$fail" -eq 0 ]
