output "cluster_name" {
  # Depends on the resource rather than on the variable, so that consumers of
  # this output cannot run before the cluster exists.
  value = null_resource.cluster.triggers.cluster_name
}

output "kubeconfig_path" {
  value = null_resource.cluster.triggers.kubeconfig
}

output "canary_nodes" {
  # kind names the first worker <cluster>-worker and the rest -worker2, -worker3.
  value = [for i in range(local.canary_workers) :
  i == 0 ? "${var.cluster_name}-worker" : "${var.cluster_name}-worker${i + 1}"]
}

output "stable_nodes" {
  value = concat(
    ["${var.cluster_name}-control-plane"],
    [for i in range(local.canary_workers, var.worker_count) :
    i == 0 ? "${var.cluster_name}-worker" : "${var.cluster_name}-worker${i + 1}"]
  )
}
