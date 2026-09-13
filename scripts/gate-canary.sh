#!/usr/bin/env bash
# gate-canary.sh — decide whether a canary is safe to promote.
#
# The agent runs on every node with CAP_SYS_ADMIN and attaches probes to other
# processes' memory. The question a canary has to answer is not "does it produce
# telemetry" — Phase 1 answered that — but "is the node still healthy with it
# there, and are the applications on it unaffected".
#
# So this compares the canary node against a stable node on four axes, under
# identical load applied to both:
#
#   1. traced-application health   failures and duration of real requests
#   2. node CPU                    while that load runs
#   3. kernel log                  BPF warnings, verifier complaints, taint
#   4. agent self-health           restarts, ring buffer drops, attach count
#
# It is written to be able to fail. Thresholds are stated, the control arm is a
# node running the previous build rather than a node running nothing, and every
# number it prints comes from a measurement taken during this run.
#
# Run inside the cluster VM, from the repository root.

# No pipefail: a pipeline ending in grep -q reports failure when the producer is
# killed by SIGPIPE after a match, which inverts the check.
set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.."

NS=${NS:-ebpf-observability}
CANARY=${CANARY:-canary}
STABLE=${STABLE:-stable}
REQUESTS=${REQUESTS:-300}

# Thresholds. Stated here rather than buried in the comparisons, because a gate
# whose pass condition is not legible is not a gate.
MAX_CPU_RATIO=1.30      # canary node CPU, relative to the stable node
MAX_TIME_RATIO=1.25     # request duration on the canary node, relative to stable
MAX_DROPS=0             # ring buffer events dropped, either release

K="sudo kubectl"
D="sudo docker"

bold() { printf "\n\033[1m%s\033[0m\n" "$1"; }
ok()   { printf "   \033[32m%s\033[0m\n" "$1"; }
bad()  { printf "   \033[31m%s\033[0m\n" "$1"; fail=1; }
note() { printf "   \033[2m%s\033[0m\n" "$1"; }

fail=0
RUN_START=$(date +%s)

# ---------------------------------------------------------------------------
bold "1. Both releases are deployed, on disjoint nodes"

node_of() {
  $K -n "$NS" get pods -l "app.kubernetes.io/instance=$1" \
    -o jsonpath='{range .items[*]}{.spec.nodeName}{"\n"}{end}' 2>/dev/null | sort
}

canary_nodes=$(node_of "$CANARY")
stable_nodes=$(node_of "$STABLE")

[ -n "$canary_nodes" ] || { bad "no pods for release '$CANARY'"; exit 1; }
[ -n "$stable_nodes" ] || { bad "no pods for release '$STABLE'"; exit 1; }

CANARY_NODE=$(head -1 <<<"$canary_nodes")

# The control arm has to be comparable, not merely available. Taking the first
# stable node picked the control-plane node, which runs the API server and sat
# at 17% CPU against the canary worker's 3% — a ratio of 0.15 that passes
# whatever the canary is doing, including burning CPU. A threshold that cannot
# be exceeded is not a threshold.
#
# So the control is a stable node with the same role as the canary node.
is_control_plane() {
  $K get node "$1" -o jsonpath='{.metadata.labels}' 2>/dev/null |
    grep -q 'node-role.kubernetes.io/control-plane' && echo yes || echo no
}
canary_role=$(is_control_plane "$CANARY_NODE")

STABLE_NODE=""
while read -r n; do
  [ -n "$n" ] || continue
  if [ "$(is_control_plane "$n")" = "$canary_role" ]; then STABLE_NODE=$n; break; fi
done <<<"$stable_nodes"

if [ -z "$STABLE_NODE" ]; then
  STABLE_NODE=$(head -1 <<<"$stable_nodes")
  note "no stable node shares the canary's role; CPU comparison is not like-for-like"
fi

echo "   canary  -> $(tr '\n' ' ' <<<"$canary_nodes")"
echo "   stable  -> $(tr '\n' ' ' <<<"$stable_nodes")"

overlap=$(comm -12 <(echo "$canary_nodes") <(echo "$stable_nodes"))
if [ -n "$overlap" ]; then
  bad "both releases run on: $(tr '\n' ' ' <<<"$overlap")"
  bad "two agents on one node double the probe overhead and make this comparison meaningless"
  exit 1
fi
ok "disjoint: comparing $CANARY_NODE against $STABLE_NODE"

# A canary running the same build as stable tests the rollout mechanism and
# nothing else. Worth saying out loud rather than letting a green run imply more
# than it showed.
canary_img=$($K -n "$NS" get ds -l "app.kubernetes.io/instance=$CANARY" \
  -o jsonpath='{.items[0].spec.template.spec.containers[0].image}' 2>/dev/null)
stable_img=$($K -n "$NS" get ds -l "app.kubernetes.io/instance=$STABLE" \
  -o jsonpath='{.items[0].spec.template.spec.containers[0].image}' 2>/dev/null)
echo "   canary image: $canary_img"
echo "   stable image: $stable_img"
[ "$canary_img" = "$stable_img" ] && \
  note "identical images: this run exercises the rollout, not a new build"

# ---------------------------------------------------------------------------
bold "2. Apply identical load to both nodes"

# A Job per node, pinned by nodeName, making real HTTPS requests through
# OpenSSL — the path the agent actually instruments. Each reports failures and
# wall-clock duration, which is what a traced application notices.
load_job() {
  local name=$1 node=$2
  $K delete job "$name" -n default --ignore-not-found >/dev/null 2>&1
  cat <<YAML | $K apply -f - >/dev/null
apiVersion: batch/v1
kind: Job
metadata:
  name: $name
  namespace: default
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      nodeName: $node
      containers:
        - name: curl
          image: curlimages/curl:8.11.1
          command: ["sh","-c"]
          args:
            - |
              # Per-request time from curl itself, not wall clock over the
              # whole loop: busybox date has no sub-second resolution, and at
              # 300 fast requests the loop total rounds to the same integer
              # number of seconds on both arms whatever the difference is.
              ok=0; failed=0
              : > /tmp/times
              i=0
              while [ \$i -lt $REQUESTS ]; do
                if t=\$(curl -sk --http1.1 --max-time 5 -o /dev/null \
                          -w '%{time_total}' \
                          https://kubernetes.default.svc/healthz 2>/dev/null); then
                  ok=\$((ok+1)); echo "\$t" >> /tmp/times
                else
                  failed=\$((failed+1))
                fi
                i=\$((i+1))
              done
              awk -v ok=\$ok -v failed=\$failed '
                { t[n++] = \$1 * 1000; s += \$1 * 1000 }
                END {
                  # Sorted, so the median is reported alongside the mean: a few
                  # slow requests move the mean and say nothing about what a
                  # typical request experienced.
                  for (i = 0; i < n; i++)
                    for (j = i+1; j < n; j++)
                      if (t[j] < t[i]) { x = t[i]; t[i] = t[j]; t[j] = x }
                  printf "RESULT ok=%d failed=%d mean_ms=%.2f p50_ms=%.2f\n",
                         ok, failed, (n ? s/n : 0), (n ? t[int(n/2)] : 0)
                }' /tmp/times
YAML
}

load_job canary-load "$CANARY_NODE"
load_job stable-load "$STABLE_NODE"
echo "   $REQUESTS HTTPS requests on each node, started together"

# ---------------------------------------------------------------------------
# Node CPU, sampled while the load runs.
#
# kind nodes are containers, so their CPU is the container's. This is not the
# same as a real node's CPU and is not comparable in absolute terms — but both
# arms are measured the same way at the same time, and the comparison between
# them is what the threshold is applied to.
sleep 8
bold "3. Node CPU during the load"

cpu_of() {
  local node=$1 total=0 n=0
  for _ in 1 2 3; do
    local v
    v=$($D stats --no-stream --format '{{.CPUPerc}}' "$node" 2>/dev/null | tr -d '%')
    case "$v" in ''|*[!0-9.]*) ;; *) total=$(awk "BEGIN{print $total + $v}"); n=$((n+1));; esac
    sleep 2
  done
  [ "$n" -eq 0 ] && { echo "0"; return; }
  awk "BEGIN{printf \"%.1f\", $total / $n}"
}

canary_cpu=$(cpu_of "$CANARY_NODE")
stable_cpu=$(cpu_of "$STABLE_NODE")
printf "   %-22s %s%%\n" "$CANARY_NODE (canary)" "$canary_cpu"
printf "   %-22s %s%%\n" "$STABLE_NODE (stable)" "$stable_cpu"

cpu_verdict=$(awk -v c="$canary_cpu" -v s="$stable_cpu" -v m="$MAX_CPU_RATIO" '
  BEGIN { if (s <= 0) { print "no-baseline"; exit }
          r = c / s; printf "%s %.2f", (r <= m ? "ok" : "over"), r }')
case "$cpu_verdict" in
  ok*)          ok "within ${MAX_CPU_RATIO}x of the stable node (ratio ${cpu_verdict#ok })" ;;
  over*)        bad "canary node CPU is ${cpu_verdict#over }x the stable node (limit ${MAX_CPU_RATIO}x)" ;;
  no-baseline)  note "stable node reported 0% CPU; ratio not meaningful" ;;
esac

# ---------------------------------------------------------------------------
bold "4. Traced-application health"

$K wait --for=condition=complete job/canary-load job/stable-load \
  -n default --timeout=300s >/dev/null 2>&1

read_result() {
  $K logs -n default "job/$1" 2>/dev/null | grep '^RESULT' | tail -1
}
canary_res=$(read_result canary-load)
stable_res=$(read_result stable-load)

field() { sed -n "s/.*$2=\([0-9.]*\).*/\1/p" <<<"$1"; }

c_failed=$(field "$canary_res" failed); c_secs=$(field "$canary_res" p50_ms)
s_failed=$(field "$stable_res" failed); s_secs=$(field "$stable_res" p50_ms)

if [ -z "${c_secs:-}" ] || [ -z "${s_secs:-}" ]; then
  bad "a load job produced no result"
  $K get pods -n default -l batch.kubernetes.io/job-name 2>/dev/null | sed 's/^/        /'
else
  printf "   %-22s %s\n" "canary node" "$canary_res"
  printf "   %-22s %s\n" "stable node" "$stable_res"

  [ "${c_failed:-1}" -eq 0 ] || bad "$c_failed requests failed on the canary node"
  [ "${s_failed:-1}" -eq 0 ] || bad "$s_failed requests failed on the stable node — the control arm is unhealthy"

  time_verdict=$(awk -v c="$c_secs" -v s="$s_secs" -v m="$MAX_TIME_RATIO" '
    BEGIN { if (s <= 0) { print "no-baseline"; exit }
            r = c / s; printf "%s %.2f", (r <= m ? "ok" : "over"), r }')
  case "$time_verdict" in
    ok*)         ok "median request within ${MAX_TIME_RATIO}x of stable (ratio ${time_verdict#ok })" ;;
    over*)       bad "median request took ${time_verdict#over }x longer on the canary node (limit ${MAX_TIME_RATIO}x)" ;;
    no-baseline) note "stable arm reported no timings; ratio not meaningful" ;;
  esac
fi

# ---------------------------------------------------------------------------
bold "5. Kernel log"

# A faulty BPF program shows up here before it shows up anywhere else. On kind
# the kernel is shared by every node and by the host, so this cannot be
# attributed to the canary node specifically — it is still the right place to
# look, and a clean log is still evidence.
note "kind shares one kernel across all nodes; this is host-wide, not per-node"
kern=$(sudo dmesg --since "$(date -d "@$RUN_START" '+%Y-%m-%d %H:%M:%S')" 2>/dev/null |
       grep -iE 'bpf|uprobe|verifier|oops|taint|segfault' |
       grep -viE 'bpf_jit_enable|bpf: Loaded' | head -10)
if [ -z "$kern" ]; then
  ok "no BPF, uprobe, verifier or taint messages since this run started"
else
  bad "kernel log messages during this run:"
  sed 's/^/        /' <<<"$kern"
fi

# ---------------------------------------------------------------------------
bold "6. Agent self-health"

# What the agent reports about itself. Restarts and drops are the two failures
# that do not show up as an error anywhere else: a crash-looping agent still
# reports Ready between crashes, and a dropping agent produces telemetry that is
# simply incomplete.
agent_health() {
  local release=$1 port=$2 node=$3 pod restarts drops targets
  # Pinned to the node being compared. Taking the release's first pod reported
  # on whichever node the API happened to list first, which for the stable
  # release was not the node in the comparison.
  pod=$($K -n "$NS" get pods -l "app.kubernetes.io/instance=$release" \
        --field-selector "spec.nodeName=$node" \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
  restarts=$($K -n "$NS" get pod "$pod" \
        -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null)

  $K -n "$NS" port-forward "$pod" "$port:9464" >/dev/null 2>&1 &
  local pf=$!
  sleep 4
  drops=$(curl -s --max-time 3 "localhost:$port/metrics" 2>/dev/null |
          awk '/^ebpf_agent_events_dropped_total/ {s+=$2} END {print s+0}')
  targets=$($K -n "$NS" logs "$pod" 2>/dev/null | grep -c 'attached ')
  kill "$pf" 2>/dev/null; wait "$pf" 2>/dev/null

  printf "   %-8s %-28s %-20s restarts=%-3s drops=%-5s attached=%s\n" \
    "$release" "$pod" "$node" "${restarts:-?}" "${drops:-?}" "${targets:-?}"

  [ "${restarts:-1}" -eq 0 ] || bad "$release has restarted ${restarts} times"
  [ "${drops:-1}" -le "$MAX_DROPS" ] || bad "$release dropped ${drops} events (limit $MAX_DROPS)"
  [ "${targets:-0}" -gt 0 ] || bad "$release attached to nothing — coverage is silently zero"
}

agent_health "$CANARY" 19470 "$CANARY_NODE"
agent_health "$STABLE" 19471 "$STABLE_NODE"

# ---------------------------------------------------------------------------
$K delete job canary-load stable-load -n default --ignore-not-found >/dev/null 2>&1

bold "Verdict"
if [ "$fail" -eq 0 ]; then
  ok "PASS — the canary node is as healthy as the stable node on every axis"
  ok "       promote with: kubectl label node $CANARY_NODE observability/agent-channel-"
else
  bad "FAIL — do not promote"
fi
exit "$fail"
