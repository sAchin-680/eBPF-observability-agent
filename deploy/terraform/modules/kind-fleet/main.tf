# A kind cluster shaped for canary rollouts.
#
# Driven through the kind CLI rather than the tehcyx/kind provider, and that is
# a considered choice rather than a shortcut. The provider vendors its own copy
# of kind as a library, which lags the released binary: against the node image
# this project uses everywhere else it fails during cluster creation with
#
#   could not find a log line that matches "Reached target .*Multi-User System.*"
#
# because the vendored kind does not recognise a newer image's startup. The fix
# on offer is to pin an older Kubernetes version for Terraform alone — which
# would mean the fleet Terraform builds is not the fleet everything else in this
# repository was tested against. Calling the same binary a person would call
# keeps those identical, at the cost of the provider's resource graph.
#
# What is given up is real: Terraform cannot see drift inside the cluster. It
# knows the cluster exists and what configuration it was created from, and
# nothing more. That is an acceptable trade here because what runs *on* the
# cluster is not Terraform's business at all — it is ArgoCD's, and drift there
# is reverted by selfHeal.

terraform {
  required_providers {
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
  }
}

locals {
  # Workers are canary first, then the remainder. Which specific nodes carry the
  # label does not matter; that the count is explicit does, because a fleet
  # where every node is a canary is not a canary rollout.
  canary_workers = min(var.canary_worker_count, var.worker_count - 1)
  stable_workers = var.worker_count - local.canary_workers

  # The node labels are the interesting part of this module.
  # deploy/helm/ebpf-agent selects by observability/agent-channel: the canary
  # release requires the label, and the stable release requires its absence,
  # expressed as NotIn rather than as a label of its own. That asymmetry makes
  # coverage the default — a node added tomorrow with no label is traced by the
  # stable release rather than by neither.
  #
  # So only canary nodes are labelled here. Labelling the others "stable" would
  # look tidier and would reintroduce the failure the asymmetry prevents.
  config = yamlencode({
    kind       = "Cluster"
    apiVersion = "kind.x-k8s.io/v1alpha4"
    name       = var.cluster_name
    nodes = concat(
      [{ role = "control-plane" }],
      [for i in range(local.canary_workers) : {
        role   = "worker"
        labels = { "observability/agent-channel" = "canary" }
      }],
      [for i in range(local.stable_workers) : { role = "worker" }],
    )
  })
}

# The rendered cluster configuration, written out rather than piped in, so that
# a failed apply leaves behind the exact file kind was given.
resource "local_file" "kind_config" {
  content         = local.config
  filename        = "${path.root}/.terraform/${var.cluster_name}-kind.yaml"
  file_permission = "0644"
}

resource "null_resource" "cluster" {
  # Recreate the cluster when its shape changes. Without this, editing
  # worker_count would update the file and leave the running cluster untouched,
  # and Terraform would report success having changed nothing.
  triggers = {
    config       = local.config
    cluster_name = var.cluster_name
    node_image   = var.node_image
    # Captured so destroy still works when the variables are gone.
    kubeconfig = pathexpand("~/.kube/config")
  }

  provisioner "local-exec" {
    command = <<-EOT
      set -eu
      if kind get clusters 2>/dev/null | grep -qx '${var.cluster_name}'; then
        echo "cluster ${var.cluster_name} already exists; leaving it alone"
        exit 0
      fi
      kind create cluster \
        --name '${var.cluster_name}' \
        --image '${var.node_image}' \
        --config '${local_file.kind_config.filename}' \
        --wait 180s
      # Explicit, because kind writes the kubeconfig of whoever ran it. Applied
      # under sudo — which it must be where the docker socket needs root — that
      # is root's kubeconfig, and the cluster is then invisible to the user who
      # ran terraform. The apply succeeds and the fleet appears not to exist.
      kind export kubeconfig --name '${var.cluster_name}'
    EOT
  }

  provisioner "local-exec" {
    when = destroy
    # || true: destroying a cluster that is already gone is the expected state
    # after a manual `kind delete`, and failing there would leave Terraform
    # unable to remove the resource from state without a manual edit.
    command = "kind delete cluster --name '${self.triggers.cluster_name}' || true"
  }
}
