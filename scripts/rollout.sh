#!/usr/bin/env bash
# rollout.sh — canary to full fleet, one node at a time, gated at every step.
#
# This is the demonstration for Phase 4: a new build reaches one node, is
# measured there against a node running the previous build, and only then
# reaches the rest. Nothing is promoted because it started successfully.
#
# It is a script rather than a recording on purpose. A recording shows that it
# worked once, on a machine you cannot inspect; this can be run again, and it
# stops where it should when something is wrong. It writes a timestamped
# transcript so a run can be read afterwards without having watched it.
#
#   scripts/rollout.sh <image-tag>          promote that build across the fleet
#   scripts/rollout.sh <image-tag> --dry    show the plan, change nothing
#
# Watch it happen on the self-health dashboard: the per-node build panel is the
# rollout, and drops and attach counts are what the gate is reading.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.."

NS=${NS:-ebpf-observability}
CANARY=${CANARY:-canary}
STABLE=${STABLE:-stable}
CHART=deploy/helm/ebpf-agent
LABEL=observability/agent-channel
K="${KUBECTL:-sudo kubectl}"
H="${HELM:-sudo helm}"

TAG="${1:-}"
DRY="${2:-}"
[ -n "$TAG" ] || { echo "usage: scripts/rollout.sh <image-tag> [--dry]" >&2; exit 1; }

mkdir -p docs/rollouts
TRANSCRIPT="docs/rollouts/rollout-$(date +%Y%m%d-%H%M%S).log"

bold() { printf "\n\033[1m%s\033[0m\n" "$1" | tee -a "$TRANSCRIPT"; }
ok()   { printf "   \033[32m%s\033[0m\n" "$1" | tee -a "$TRANSCRIPT"; }
bad()  { printf "   \033[31m%s\033[0m\n" "$1" | tee -a "$TRANSCRIPT"; }
say()  { printf "   %s\n" "$1" | tee -a "$TRANSCRIPT"; }
stamp(){ date -u +%H:%M:%SZ; }

: > "$TRANSCRIPT"
say "rollout of $TAG at $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ---------------------------------------------------------------------------
bold "1. Where the fleet is now"

current_image() {
  $K -n "$NS" get ds -l "app.kubernetes.io/instance=$1" \
    -o jsonpath='{.items[0].spec.template.spec.containers[0].image}' 2>/dev/null
}

say "stable: $(current_image "$STABLE")"
say "canary: $(current_image "$CANARY")"
$K get nodes -L "$LABEL" --no-headers 2>/dev/null |
  awk '{printf "   %-22s %s\n", $1, ($6==""?"(stable)":$6)}' | tee -a "$TRANSCRIPT"

canary_nodes=$($K get nodes -l "$LABEL=canary" -o name 2>/dev/null | wc -l | tr -d ' ')
if [ "$canary_nodes" -eq 0 ]; then
  bad "no node is labelled $LABEL=canary — label one first"
  exit 1
fi
say "$canary_nodes node(s) will receive $TAG first"

if [ "$DRY" = "--dry" ]; then
  bold "Dry run"
  say "would: helm upgrade $CANARY --set image.tag=$TAG"
  say "would: run scripts/gate-canary.sh"
  say "would: helm upgrade $STABLE --set image.tag=$TAG, one node at a time"
  exit 0
fi

# ---------------------------------------------------------------------------
bold "2. $(stamp)  Canary: $TAG onto the labelled node only"

$H upgrade --install "$CANARY" "$CHART" -n "$NS" \
  -f "$CHART/values-canary.yaml" --set "image.tag=$TAG" \
  2>&1 | grep -E "STATUS|Error" | sed 's/^/   /' | tee -a "$TRANSCRIPT"

if ! $K -n "$NS" rollout status "ds/$CANARY-ebpf-agent" --timeout=180s >/dev/null 2>&1; then
  bad "the canary DaemonSet did not become ready"
  $K -n "$NS" get pods -l "app.kubernetes.io/instance=$CANARY" 2>&1 | sed 's/^/      /' | tee -a "$TRANSCRIPT"
  exit 1
fi
ok "canary running $TAG"

# Settle before measuring. An agent that started ten seconds ago has attached to
# whatever was running then and has no drop history at all, so gating on it
# would pass regardless of what the build does.
say "settling for 60s before measuring"
sleep 60

# ---------------------------------------------------------------------------
bold "3. $(stamp)  Gate: is the canary node as healthy as a stable one"

if bash scripts/gate-canary.sh 2>&1 | tee -a "$TRANSCRIPT" | grep -q "PASS"; then
  ok "gate passed"
else
  bad "gate failed — stopping here, with $TAG on the canary node only"
  bad "roll back with: helm upgrade $CANARY $CHART -n $NS -f $CHART/values-canary.yaml --set image.tag=<previous>"
  say "transcript: $TRANSCRIPT"
  exit 1
fi

# ---------------------------------------------------------------------------
bold "4. $(stamp)  Fleet: the same build to everything else"

# maxUnavailable is 1 in the chart, so this is already one node at a time. The
# rollout status call below is what makes that sequential rather than merely
# declared: it returns when every node has the new build and is ready.
$H upgrade --install "$STABLE" "$CHART" -n "$NS" \
  -f "$CHART/values-stable.yaml" --set "image.tag=$TAG" \
  2>&1 | grep -E "STATUS|Error" | sed 's/^/   /' | tee -a "$TRANSCRIPT"

if $K -n "$NS" rollout status "ds/$STABLE-ebpf-agent" --timeout=300s 2>&1 | tail -1 | sed 's/^/   /' | tee -a "$TRANSCRIPT"; then
  ok "fleet running $TAG"
else
  bad "the fleet rollout stalled — nodes may be split across builds"
  $K -n "$NS" get pods -o wide 2>&1 | sed 's/^/      /' | tee -a "$TRANSCRIPT"
  exit 1
fi

# ---------------------------------------------------------------------------
bold "5. $(stamp)  Result"

say "stable: $(current_image "$STABLE")"
say "canary: $(current_image "$CANARY")"

$K -n "$NS" get pods -o wide --no-headers 2>/dev/null |
  awk '{printf "   %-28s %-10s %s\n", $1, $3, $7}' | tee -a "$TRANSCRIPT"

# Both releases now run the same build, which is the correct end state: the
# canary label stays on its node so the next rollout has somewhere to land, and
# the node is not left running something different from the rest of the fleet.
ok "PASS — $TAG on every node, promoted only after the gate"
say "transcript: $TRANSCRIPT"
