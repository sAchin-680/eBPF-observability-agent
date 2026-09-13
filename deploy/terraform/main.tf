# The local test fleet.
#
# What this provisions is a kind cluster: nodes are containers sharing the host
# kernel. That is a deliberate choice and a real limitation, both recorded in
# README.md — the short version is that one kernel is the right variable to hold
# fixed here, because kernel variation is tested separately and far more
# rigorously by the CI matrix, which boots real kernels in QEMU.
#
#   terraform init && terraform apply
module "fleet" {
  source = "./modules/kind-fleet"

  cluster_name        = var.cluster_name
  node_image          = var.node_image
  worker_count        = var.worker_count
  canary_worker_count = var.canary_worker_count
}
