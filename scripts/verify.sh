#!/usr/bin/env bash
# verify.sh — the fast check.
#
# Everything that is pure logic: the build, formatting, vet, and every test that
# does not need load applied to a running service. Around a minute.
#
# Deliberately excludes the slow tier — the demo, the failure matrix, the kernel
# matrix, the benchmark sweep — which take twenty minutes between them because
# each one starts services, applies load, and waits for a ring buffer to drain.
# Those only need re-running when the capture path or the scripts change, and
# they have their own entry points:
#
#   scripts/demo.sh              the Phase 1 demonstration
#   scripts/gate-phase2.sh       the Phase 2 acceptance gate
#   scripts/failure-matrix.sh    behaviour under failure
#   scripts/kernel-check.sh      one binary on one kernel
#   scripts/bench.sh             overhead and the loss threshold
#
# Run from the repository root inside the Linux VM.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export PATH="$PATH:/usr/local/go/bin"

fail=0
step() { printf "\n\033[1m%s\033[0m\n" "$1"; }
ok()   { printf "  \033[32mok\033[0m    %s\n" "$1"; }
bad()  { printf "  \033[31mFAIL\033[0m  %s\n" "$1"; fail=1; }

start=$(date +%s)

step "build"
if make vmlinux >/dev/null 2>&1 && go generate ./... >/dev/null 2>&1 \
   && CGO_ENABLED=0 go build -o bin/agent ./cmd/agent 2>/dev/null; then
  ok "agent builds  $(sha256sum bin/agent | cut -c1-16)"
else
  bad "build"
  make vmlinux 2>&1 | tail -3
  go build -o bin/agent ./cmd/agent 2>&1 | head -10
fi

step "static"
unformatted=$(gofmt -l . 2>/dev/null | grep -v _bpfel | head -5)
if [ -z "$unformatted" ]; then ok "gofmt"; else bad "gofmt"; echo "$unformatted" | sed 's/^/        /'; fi

vetout=$(go vet ./... 2>&1)
if [ -z "$vetout" ]; then ok "go vet"; else bad "go vet"; head -10 <<<"$vetout" | sed 's/^/        /'; fi

for f in scripts/*.sh samples/*.sh; do
  [ -f "$f" ] || continue
  bash -n "$f" 2>/dev/null || bad "shell syntax: $f"
done
ok "shell scripts parse"

step "tests"
if out=$(go test ./internal/... 2>&1); then ok "unit"; else bad "unit"; grep -E "FAIL|---" <<<"$out" | head -10 | sed 's/^/        /'; fi

# These load programs into the kernel, so they need privilege, but they apply no
# load and finish in seconds.
if out=$(sudo env PATH="$PATH" go test ./test/... 2>&1); then
  ok "kernel: toolchain and verifier"
else
  bad "kernel: toolchain and verifier"
  grep -E "FAIL|---" <<<"$out" | head -10 | sed 's/^/        /'
fi

step "environment"
if out=$(bash scripts/check-env.sh 2>&1); then
  ok "$(grep -oE '[0-9]+ passed, [0-9]+ failed' <<<"$out")"
else
  bad "environment"
  grep FAIL <<<"$out" | sed 's/^/        /'
fi

step "documentation"
broken=$(python3 - <<'PY'
import re, os, glob
bad = []
for f in glob.glob('**/*.md', recursive=True):
    if 'node_modules' in f:
        continue
    for l in re.findall(r'\]\((?!http|#)([^)]+)\)', open(f).read()):
        p = os.path.normpath(os.path.join(os.path.dirname(f), l.split('#')[0]))
        if not os.path.exists(p):
            bad.append(f"{f} -> {l}")
print("\n".join(bad))
PY
)
if [ -z "$broken" ]; then ok "internal links resolve"; else bad "broken links"; sed 's/^/        /' <<<"$broken"; fi

printf "\n"
if [ "$fail" -eq 0 ]; then
  printf "  \033[32mall fast checks passed\033[0m in %ds\n\n" "$(( $(date +%s) - start ))"
else
  printf "  \033[31mfast checks failed\033[0m in %ds\n\n" "$(( $(date +%s) - start ))"
fi
exit "$fail"
