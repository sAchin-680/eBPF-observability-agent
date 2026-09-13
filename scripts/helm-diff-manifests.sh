#!/usr/bin/env bash
# helm-diff-manifests.sh — prove the chart and the raw manifests agree.
#
# deploy/k8s/ and deploy/helm/ both describe the same DaemonSet. Keeping both is
# useful — the raw form can be read without a templating engine — and is exactly
# the kind of duplication that silently diverges. A security setting fixed in
# one and not the other is the failure this guards against.
#
# What is compared is the pod spec, which is where privilege, mounts and probes
# live. Names and labels are release-scoped by design and are not compared.
#
# Run from the repository root.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.."

CHART=deploy/helm/ebpf-agent
RAW=deploy/k8s/10-daemonset.yaml
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

command -v helm >/dev/null || { echo "helm required" >&2; exit 1; }

# The release name is what the chart uses to scope object names, and the raw
# manifest's DaemonSet is called ebpf-agent — so rendering under that name makes
# the two comparable without rewriting either.
helm template ebpf "$CHART" -n ebpf-observability > "$WORK/rendered.yaml" || exit 1

extract() {
  python3 - "$1" <<'PY'
import sys, yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
ds = [d for d in docs if d.get("kind") == "DaemonSet"]
if len(ds) != 1:
    sys.exit(f"expected exactly one DaemonSet, found {len(ds)}")
spec = ds[0]["spec"]["template"]["spec"]

# Container names and the image tag are release-scoped, not security-relevant,
# and would report a difference on every version bump.
for c in spec.get("containers", []):
    c.pop("image", None)
spec.pop("serviceAccountName", None)

print(yaml.safe_dump(spec, sort_keys=True, default_flow_style=False))
PY
}

extract "$RAW"            > "$WORK/raw.spec"     || exit 1
extract "$WORK/rendered.yaml" > "$WORK/helm.spec" || exit 1

if diff -u "$WORK/raw.spec" "$WORK/helm.spec" > "$WORK/diff"; then
  printf "   \033[32mok\033[0m    chart and raw manifests describe the same pod\n"
  exit 0
fi

printf "   \033[31mdiffer\033[0m  deploy/k8s/ and deploy/helm/ have drifted\n\n"
sed -n 's/^/   /p' "$WORK/diff"
exit 1
