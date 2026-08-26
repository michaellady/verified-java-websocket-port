# Exact versions are part of the benchmark tool identity. Upgrades require a
# deliberate preregistration change and regenerated lock files.

terraform {
  required_version = "= 1.9.8"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.0.0"
    }
  }
}
