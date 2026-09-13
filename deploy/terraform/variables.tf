variable "cluster_name" {
  description = "Name of the test fleet. Becomes the kind cluster name and the prefix of every node."
  type        = string
  default     = "ebpf"
}

variable "node_image" {
  description = <<-EOT
    The kind node image, which fixes the Kubernetes version.

    Pinned rather than defaulted to latest: a test fleet that silently changes
    Kubernetes version between applies makes every result on it unattributable.
  EOT
  type        = string
  default     = "kindest/node:v1.34.0"
}

variable "worker_count" {
  description = "Worker nodes, excluding the control plane. Three or more is what makes a canary meaningful — with one worker, the canary is the entire fleet."
  type        = number
  default     = 2

  validation {
    condition     = var.worker_count >= 2
    error_message = "worker_count must be at least 2: a canary rollout needs a node to canary on and a node to compare against."
  }
}

variable "canary_worker_count" {
  description = "How many workers carry observability/agent-channel=canary. The rest are covered by the stable release, which selects everything that is not the canary."
  type        = number
  default     = 1

  validation {
    condition     = var.canary_worker_count >= 1
    error_message = "canary_worker_count must be at least 1."
  }
}
