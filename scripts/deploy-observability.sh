#!/usr/bin/env bash
# deploy-observability.sh — bring up the stack that watches the agents.
#
# Separate from the agent's own deployment, and applied separately: this is what
# tells you the agent is unhealthy, so it should not share a rollout with it.
#
# The dashboard JSON is not embedded in a manifest. It lives in
# deploy/grafana/dashboards/ as a file Grafana can also load directly, and is
# turned into a ConfigMap here — so there is one copy, and the version in the
# cluster is the version in the repository.
#
#   scripts/deploy-observability.sh [--port-forward]

set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.."

NS=observability
DASHBOARDS=deploy/grafana/dashboards
K="${KUBECTL:-sudo kubectl}"

bold() { printf "\n\033[1m%s\033[0m\n" "$1"; }
ok()   { printf "   \033[32m%s\033[0m\n" "$1"; }
info() { printf "   \033[2m%s\033[0m\n" "$1"; }

bold "Applying manifests"
$K apply -f deploy/k8s/observability/ 2>&1 | sed 's/^/   /'

bold "Loading dashboards from $DASHBOARDS"
# Recreated rather than patched: --from-file with an unchanged name leaves
# deleted panels behind, and a dashboard that still shows a panel the file no
# longer defines is worse than one that is missing.
$K -n "$NS" create configmap grafana-dashboards \
  --from-file="$DASHBOARDS" \
  --dry-run=client -o yaml | $K apply -f - >/dev/null
for f in "$DASHBOARDS"/*.json; do
  info "$(basename "$f")  $(python3 -c "import json,sys; d=json.load(open('$f')); print(len([p for p in d['panels'] if p['type']!='row']), 'panels')" 2>/dev/null)"
done

# The deployment's checksum annotation is what makes a dashboard change take
# effect; without it the ConfigMap updates and the running Grafana keeps serving
# what it started with.
sum=$(cat "$DASHBOARDS"/*.json | shasum -a 256 2>/dev/null | cut -c1-16 \
      || cat "$DASHBOARDS"/*.json | sha256sum | cut -c1-16)
$K -n "$NS" patch deployment grafana --type=strategic \
  -p "{\"spec\":{\"template\":{\"metadata\":{\"annotations\":{\"checksum/dashboards\":\"$sum\"}}}}}" >/dev/null 2>&1

bold "Waiting for rollout"
for d in kube-state-metrics prometheus grafana; do
  if $K -n "$NS" rollout status "deployment/$d" --timeout=180s >/dev/null 2>&1; then
    ok "$d ready"
  else
    printf "   \033[31m%s\033[0m\n" "$d did not become ready"
    $K -n "$NS" get pods -l "app.kubernetes.io/name=$d" 2>&1 | sed 's/^/      /'
  fi
done

# Prometheus discovering zero agents is the failure worth catching here: every
# panel then renders empty, which looks identical to a fleet with nothing to
# report.
bold "Checking that Prometheus found the agents"
$K -n "$NS" port-forward svc/prometheus 19090:9090 >/dev/null 2>&1 &
pf=$!
sleep 5
targets=$(curl -s --max-time 5 'localhost:19090/api/v1/query?query=count(ebpf_agent_targets_attached)' 2>/dev/null |
          python3 -c 'import json,sys; r=json.load(sys.stdin)["data"]["result"]; print(r[0]["value"][1] if r else 0)' 2>/dev/null)
kill "$pf" 2>/dev/null

if [ "${targets:-0}" -gt 0 ]; then
  ok "$targets agent(s) being scraped"
else
  printf "   \033[31m%s\033[0m\n" "no agents scraped — the dashboard will be empty"
  info "check that the agent pods carry prometheus.io/scrape=true"
fi

bold "Dashboard"
info "kubectl -n $NS port-forward svc/grafana 3001:3000"
info "then open http://127.0.0.1:3001"

if [ "${1:-}" = "--port-forward" ]; then
  $K -n "$NS" port-forward --address 0.0.0.0 svc/grafana 3001:3000 >/dev/null 2>&1 &
  sleep 3
  ok "forwarding on :3001 (pid $!)"
fi
