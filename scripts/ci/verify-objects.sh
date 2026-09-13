#!/usr/bin/env bash
# verify-objects.sh — check that the compiled BPF objects contain what CO-RE
# needs, before anything tries to load them.
#
# `clang` succeeding says almost nothing. The failure this guards against is
# specific and silent: drop -g from the compile flags and every object still
# builds, still loads on the machine that built it, and no longer carries the
# relocations that let it load anywhere else. The agent would then work in
# development and break on the first node running a different kernel — which is
# the entire premise of the project.
#
#   scripts/ci/verify-objects.sh

set -u

pass=0; fail=0
ok()  { printf "  \033[32mPASS\033[0m  %-34s %s\n" "$1" "${2:-}"; pass=$((pass+1)); }
bad() { printf "  \033[31mFAIL\033[0m  %-34s %s\n" "$1" "${2:-}"; fail=$((fail+1)); }

objects=$(find internal test -name '*_bpfel*.o' -o -name '*_bpfeb*.o' 2>/dev/null | sort)
[ -n "$objects" ] || { echo "no compiled objects found — run 'go generate ./...' first"; exit 1; }

echo
printf "\033[1mBPF object validation\033[0m\n"

for obj in $objects; do
  name=$(basename "$obj")
  # readelf prints "[ 1] .text" and "[10] .text": the section name is the
  # second whitespace field in one case and the third in the other, so column
  # indexing silently reports the wrong thing for every object with ten or more
  # sections. Match the bracketed index instead.
  sections=$(readelf -SW "$obj" 2>/dev/null |
             sed -n 's/^[[:space:]]*\[[[:space:]]*[0-9]\+\][[:space:]]\+\([^[:space:]]\+\).*/\1/p')

  # .BTF carries the type information CO-RE resolves against.
  if grep -qx '.BTF' <<<"$sections"; then
    ok "$name: BTF present"
  else
    bad "$name: no .BTF section" "compiled without -g; CO-RE cannot work"
  fi

  # .BTF.ext carries the CO-RE relocation records themselves. An object with
  # .BTF but no .BTF.ext loads on the build kernel and nowhere else.
  if grep -qx '.BTF.ext' <<<"$sections"; then
    ok "$name: CO-RE relocations present"
  else
    bad "$name: no .BTF.ext section" "field offsets are baked in, not relocatable"
  fi

  # At least one program section. An object with maps and no programs is what a
  # misspelled SEC() annotation produces.
  progs=$(readelf -S "$obj" 2>/dev/null |
          grep -cE '(uprobe|uretprobe|kprobe|tracepoint|tp)/')
  if [ "$progs" -gt 0 ]; then
    ok "$name: $progs program section(s)"
  else
    bad "$name: no program sections" "check the SEC() annotations"
  fi
done

# The ring buffer is the data path. Its absence would not fail a compile; it
# would produce an agent that attaches successfully and reports nothing.
if grep -rq 'BPF_MAP_TYPE_RINGBUF' bpf/; then
  ok "ring buffer declared"
else
  bad "no ring buffer map declared"
fi

echo
printf "  %d passed, %d failed\n" "$pass" "$fail"
[ "$fail" -eq 0 ]
