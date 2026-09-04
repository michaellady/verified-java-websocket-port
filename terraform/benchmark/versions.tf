# Version pins match the DIALED contract (the dialed-setup composite action
# installs Terraform 1.9.8 in CI; the AWS provider floor matches the DIALED
# stack/bootstrap templates).

terraform {
  required_version = ">= 1.9"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0.0"
    }
  }
}
