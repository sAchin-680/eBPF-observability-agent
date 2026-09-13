# Provider versions are pinned, not floated.
#
# Terraform's value is that the same configuration produces the same
# infrastructure. A provider free to move to a new major version between two
# applies gives that up quietly: `terraform apply` on an unchanged repository
# would then be able to change the fleet.
terraform {
  required_version = ">= 1.5"

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
