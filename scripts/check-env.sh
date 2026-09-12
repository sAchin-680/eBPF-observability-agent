#!/usr/bin/env bash
# check-env.sh — run this INSIDE the Linux VM.
#
# Verifies every kernel capability this project depends on, and explains what
# each one is for. If a check fails, the explanation tells you what breaks.
#
# Ground Rule 4 applies to your own environment too: don't assume BTF is there,
# check that the file exists.

# No pipefail.
#
# Nearly every check here is a pipeline ending in grep -q, which exits on its
# first match and closes the pipe. The producer then dies of SIGPIPE with status
# 141, and under pipefail that becomes the pipeline's status — so a check
# inverts: the symbol is found, and the check reports it missing. This script
# reported exactly that for SSL_write on a library that plainly exports it.
set -u
pass=0; fail=0
ok()   { printf "  \033[32mPASS\033[0m  %-34s %s\n" "$1" "${2:-}"; pass=$((pass+1)); }
bad()  { printf "  \033[31mFAIL\033[0m  %-34s %s\n" "$1" "${2:-}"; fail=$((fail+1)); }
note() { printf "        \033[2m%s\033[0m\n" "$1"; }

echo
echo "eBPF environment check — $(uname -srm)"
echo "======================================================================"

# 1. Are we even on Linux?
[ "$(uname -s)" = "Linux" ] && ok "linux kernel" "$(uname -r)" \
  || { bad "linux kernel" "eBPF is Linux-only. Run this inside the VM."; exit 1; }

# 2. BTF — BPF Type Format.
#    A blob of kernel struct layouts compiled into the running kernel. CO-RE
#    uses it at LOAD time to rewrite our struct field offsets to match THIS
#    kernel. Without it, one binary cannot span kernel versions (NFR5).
if [ -r /sys/kernel/btf/vmlinux ]; then
  ok "kernel BTF" "$(stat -c %s /sys/kernel/btf/vmlinux) bytes"
  note "this file is what makes CO-RE possible — it is our whole ADR-004"
else
  bad "kernel BTF" "/sys/kernel/btf/vmlinux missing"
  note "kernel lacks CONFIG_DEBUG_INFO_BTF=y — CO-RE cannot work here"
fi

# 3. bpftool — generates vmlinux.h (C header of every kernel struct) from BTF.
command -v bpftool >/dev/null && ok "bpftool" "$(bpftool version | head -1)" \
  || bad "bpftool" "needed to generate bpf/vmlinux.h"

# 4. clang with a BPF backend. gcc cannot do this (until very recently); clang
#    is the practical requirement. -target bpf emits BPF bytecode ELF.
if command -v clang >/dev/null; then
  if clang -print-targets 2>/dev/null | grep -q bpf || llc --version 2>/dev/null | grep -q bpf; then
    ok "clang w/ bpf target" "$(clang --version | head -1)"
  else
    bad "clang w/ bpf target" "clang present but no BPF backend"
  fi
else
  bad "clang" "not installed"
fi

# 5. bpf() syscall reachable + perf_event_open. Root or CAP_BPF+CAP_PERFMON.
if [ "$(id -u)" -eq 0 ] || capsh --print 2>/dev/null | grep -q cap_bpf; then
  ok "privileges" "root or CAP_BPF present"
else
  note "not root — you will need sudo to load programs (Phase 4 scopes this down)"
fi

# 6. Unprivileged BPF is normally disabled; that's expected and fine.
if [ -r /proc/sys/kernel/unprivileged_bpf_disabled ]; then
  ok "unprivileged_bpf_disabled" "$(cat /proc/sys/kernel/unprivileged_bpf_disabled)"
  note "1 or 2 = only privileged loads allowed. Expected on a modern distro."
fi

# 7. JIT — BPF bytecode is JIT-compiled to native. Off means interpreted, slow,
#    and your Phase 3 overhead numbers would be meaningless.
if [ -r /proc/sys/net/core/bpf_jit_enable ]; then
  v=$(cat /proc/sys/net/core/bpf_jit_enable)
  [ "$v" != "0" ] && ok "bpf JIT" "enabled ($v)" || bad "bpf JIT" "disabled — benchmarks would be invalid"
fi

# 8. Ring buffer map type. BPF_MAP_TYPE_RINGBUF landed in 5.8. It's how the
#    kernel side hands events to our Go agent (FR: ring buffer data path).
kv=$(uname -r | cut -d. -f1,2)
awk -v k="$kv" 'BEGIN{ split(k,a,"."); if (a[1]>5 || (a[1]==5 && a[2]>=8)) exit 0; exit 1 }' \
  && ok "BPF_MAP_TYPE_RINGBUF" "kernel $kv >= 5.8" \
  || bad "BPF_MAP_TYPE_RINGBUF" "kernel $kv < 5.8 — would need perf buffer instead"

# tracefs (/sys/kernel/tracing) is mode 0700 root-only, so these probes must run
# under sudo. Testing them as an unprivileged user reports a false negative.
SUDO=""; [ "$(id -u)" -eq 0 ] || SUDO="sudo"

# 9. uprobes. We attach to SSL_write/SSL_read in userspace libraries. This is
#    the mechanism that lets us see plaintext before it is encrypted (ADR-002).
if $SUDO test -e /sys/kernel/tracing/uprobe_events || $SUDO test -e /sys/kernel/debug/tracing/uprobe_events; then
  ok "uprobe support" "tracefs uprobe_events present"
else
  bad "uprobe support" "no uprobe_events — cannot attach to userspace symbols"
fi

# 10. tracepoints — stable-ABI kernel hooks. ADR-003 prefers these over kprobes.
if $SUDO test -d /sys/kernel/tracing/events/syscalls || $SUDO test -d /sys/kernel/debug/tracing/events/syscalls; then
  ok "tracepoints" "syscall tracepoints available"
else
  bad "tracepoints" "tracefs not mounted?"
fi

# 11. Go toolchain for the userspace agent.
if command -v go >/dev/null || [ -x /usr/local/go/bin/go ]; then
  ok "go" "$( (command -v go >/dev/null && go version) || /usr/local/go/bin/go version )"
else
  bad "go" "userspace agent needs Go"
fi

# 12. Is there a libssl to hook? Our first uprobe target.
so=$(ldconfig -p 2>/dev/null | grep -m1 'libssl\.so\.3' | awk '{print $NF}')
if [ -n "${so:-}" ]; then
  ok "libssl.so.3" "$so"
  # Symbols carry a version suffix (SSL_write@@OPENSSL_3.0.0), so match the
  # base name up to the '@'. Anything matching on an exact end-of-line will
  # report a false negative on any versioned shared library.
  # grep -c rather than -q: it reads all of its input, so the producer is never
  # signalled, and the result is a count rather than an exit status.
  if [ "$(nm -D "$so" 2>/dev/null | grep -cE ' T SSL_write(@|$)')" -gt 0 ]; then
    note "SSL_write is an exported, versioned dynamic symbol — uprobe attach is viable"
  else
    bad "SSL_write symbol" "not exported by $so — uprobe attach by name will fail"
  fi
else
  bad "libssl.so.3" "no OpenSSL 3 found — install libssl-dev"
fi

echo "======================================================================"
printf "  %d passed, %d failed\n\n" "$pass" "$fail"
[ "$fail" -eq 0 ] || { echo "  Resolve the failures above before building."; exit 1; }
