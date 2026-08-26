# Variables for the job-scoped benchmark-confirmation root.
#
# project_name / aws_region / account_ids arrive via the DIALED auto-tfvars
# file (dialed.auto.tfvars.json, generated from .dialed.yml by the
# dialed-setup composite action). pr_number / instance_type / ami_id are
# passed explicitly by the workflow.

variable "project_name" {
  type        = string
  description = "From .dialed.yml. Resource-name prefix; must match the DIALED bootstrap boundary/role naming (vjwp-bench)."
}

variable "aws_region" {
  type        = string
  description = "From .dialed.yml. Region for the benchmark host. Default us-east-1; the region is BOUND to us-east-1 (owner decision 2026-08-26) in benchmarks/environments/confirmation.json."
  default     = "us-east-1"
}

variable "pr_number" {
  type        = string
  description = "PR number driving this benchmark job (workspace = bench-pr-<N>)."

  validation {
    condition     = can(regex("^[0-9]+$", var.pr_number))
    error_message = "pr_number must be a decimal PR number."
  }
}

variable "instance_type" {
  type        = string
  description = <<-EOT
    Instance type for the confirmation host. Confirmation rigor is TIERED
    per the owner-authorized amendment of 2026-08-26
    (workspace protected root: us008-contract-amendment-tiered-benchmark-rigor.json):

      TIER 2 (METAL_MEASURED): a *.metal type — flagship-grade rigor,
        single-protocol, opt-in. Bare metal removes virtualization overhead
        (the same reason Docker sbx is excluded from hosting measured
        samples; dedicated tenancy is still a VM).
      TIER 1 (VM_MEASURED_JITTER_AVERAGED): an ordinary VM type — default
        for the scale campaign, N-round jitter-averaged per the
        preregistered stats plan.

    The tier is DERIVED from the type (see local.rigor_tier), stamped on the
    instance tags, and exported as an output so the environment binding
    records it; a Tier-1 number must never be represented as metal-grade.

    TIER-1 BOUND (owner decision 2026-08-26): c7i.xlarge, recorded in
    benchmarks/environments/confirmation.json. A measured Tier-1 run must
    pass the bound type. TIER 2 remains DEFERRED_BY_OWNER: c5n.metal is
    still only the DEFAULT-CANDIDATE from the feasibility study, not a
    bound decision, and no Tier-2 sample may be collected until the owner
    binds a metal type in the same preregistration document.
  EOT
  default     = "c7i.xlarge"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]*\\.[a-z0-9-]+$", var.instance_type))
    error_message = "instance_type must be a well-formed EC2 instance type (family.size, e.g. c5n.metal, m7i.metal-24xl, or c7i.large)."
  }
}

variable "ami_id" {
  type        = string
  description = <<-EOT
    Pinned x86_64 AMI id for the confirmation host.

    BOUND (owner decision 2026-08-26) in
    benchmarks/environments/confirmation.json: ami-02b3d83d84b07786d
    (al2023-ami-2023.12.20260817.0-kernel-6.1-x86_64, deprecation
    2026-11-10 — re-probe and re-pin past that date). The exact default is
    intentional: non-plumbing execution cannot silently
    resolve or substitute another image.

    PROBE STEP (required before pinning — see the probe-before-wire rule):
    run one real query against the target dev account and read the response:
      aws ec2 describe-images --owners amazon \
        --filters 'Name=name,Values=al2023-ami-2023.*-x86_64' \
                  'Name=state,Values=available' \
        --query 'sort_by(Images,&CreationDate)[-1].[ImageId,Name,CreationDate]' \
        --region us-east-1 --profile dev-admin
    Then pin the returned ImageId here (or via -var) AND record it plus the
    resulting kernel identity in the confirmation environment file.
  EOT
  default     = "ami-02b3d83d84b07786d"
}

variable "allow_unpinned_ami" {
  type        = bool
  description = <<-EOT
    Legacy-named escape hatch for PIPELINE PLUMBING TESTS ONLY. When true,
    the exact Tier-1 class/AMI/region precondition is relaxed; if ami_id is
    explicitly empty, the newest AL2023 x86_64 AMI is resolved dynamically.
    Any such host is NOT a valid confirmation host and the runner emits only
    NOT_MEASURED sentinels. Measured runs require false plus exact frozen pins.
  EOT
  default     = false
}

variable "max_run_minutes" {
  type        = number
  description = "Belt-and-braces bound mirrored in the workflow's timeout-minutes; recorded as a tag so the janitor and humans can see the intended lifetime."
  default     = 120
}
