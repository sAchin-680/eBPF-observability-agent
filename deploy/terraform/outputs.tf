output "cluster_name" {
  description = "Name of the provisioned fleet."
  value       = module.fleet.cluster_name
}

output "kubeconfig_path" {
  description = "Where the kubeconfig was written."
  value       = module.fleet.kubeconfig_path
}

output "canary_nodes" {
  description = "Nodes labelled as the canary channel. The rollout in scripts/rollout.sh targets these."
  value       = module.fleet.canary_nodes
}

output "stable_nodes" {
  description = "Everything else, including the control plane, which is traced like any other node."
  value       = module.fleet.stable_nodes
}

output "next_steps" {
  description = "What to run once the fleet exists. Provisioning stops at the cluster: what runs on it is decided by git, not by Terraform."
  value       = <<-EOT
    kubectl apply -f deploy/k8s/00-namespace.yaml
    scripts/deploy-observability.sh
    kubectl apply -f deploy/argocd/root.yaml
  EOT
}
