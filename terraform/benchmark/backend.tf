# Partial backend config, DIALED-style. Populated at `terraform init` time by
# .github/workflows/benchmark.yml via -backend-config flags.
#
# Expected -backend-config (naming contract from DIALED bootstrap-state):
#   bucket=dialed-{project_name}-{account_id}-tfstate   e.g. dialed-vjwp-bench-539402214167-tfstate
#   key=benchmark/terraform.tfstate
#   region=<aws_region>
#   dynamodb_table=dialed-{project_name}-{account_id}-tflocks
#   encrypt=true
#
# Workspace naming contract: bench-pr-<N> (one workspace per benchmark job,
# created and deleted in the SAME workflow job). State objects therefore live
# at env:/bench-pr-<N>/benchmark/terraform.tfstate — the bench-janitor
# workflow's orphan sweep matches exactly that key shape.
#
# NOTE: the state bucket and lock table DO NOT EXIST yet. Creating them is
# part of the owner-gated DIALED bootstrap step (see
# docs/us008-benchmark-pipeline.md). Until then, init fails closed.

terraform {
  backend "s3" {}
}
