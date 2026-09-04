# terraform/benchmark — SELF-CONTAINED job-scoped root for the US-008
# benchmark-confirmation host (design "shape A" from the completed
# feasibility study).
#
# Lifecycle contract: .github/workflows/benchmark.yml applies this root,
# waits for SSM, runs the benchmark runner natively via SSM send-command,
# syncs results out of S3, and DESTROYS this root in the SAME job under
# `if: always()` — never PR-open→PR-close billing. bench-janitor.yml sweeps
# any bench-pr-* workspace whose state is older than 3 hours.
#
# Provenance: confirmation rigor is TIERED (owner-authorized amendment
# 2026-08-26, us008-contract-amendment-tiered-benchmark-rigor.json):
# a *.metal instance_type is Tier 2 (METAL_MEASURED, flagship opt-in);
# any other type is Tier 1 (VM_MEASURED_JITTER_AVERAGED, the scale-campaign
# default). The tier is derived from the type, tagged on the host, and
# exported — a Tier-1 number must never be represented as metal-grade.
# Virtualization overhead remains the reason Docker sbx is excluded from
# hosting measured samples.
#
# Isolation: this root deliberately does NOT consume the EVC shared tier
# (no terraform_remote_state). It provisions its own tiny ephemeral VPC so
# the confirmation host is provenance-distinct from app stacks and nothing
# long-lived is shared. The SG is egress-only (zero ingress rules): all
# control flows outbound through SSM.

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      ManagedBy = "dialed"
      Project   = var.project_name
      Env       = "dev"
      Workspace = terraform.workspace
      PR        = var.pr_number
      Tier      = "bench"
      Lifetime  = "${var.max_run_minutes}m-job-scoped"
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  name       = "${var.project_name}-pr-${var.pr_number}"

  # DIALED boundary contract: every ${project_name}-* role this pipeline
  # mints MUST carry the dialed-${project_name}-boundary permissions
  # boundary. The deploy role's ManageProjectRolesWithBoundary statement
  # (DIALED bootstrap main.tf) rejects role creation without it.
  boundary_arn = "arn:aws:iam::${local.account_id}:policy/dialed-${var.project_name}-boundary"

  ami_id = var.ami_id != "" ? var.ami_id : data.aws_ami.al2023_x86_64.id

  # Tiered-rigor label (owner amendment 2026-08-26). Derived, never asserted:
  # a .metal or .metal-<size> type (e.g. c5n.metal, m7i.metal-24xl) => Tier 2;
  # anything else => Tier 1. The workflow/runner must carry this label into
  # the environment binding for every published number.
  rigor_tier = can(regex("\\.metal(-[a-z0-9]+)?$", var.instance_type)) ? "METAL_MEASURED" : "VM_MEASURED_JITTER_AVERAGED"
}

# ─── AMI ────────────────────────────────────────────────────────────────────
# Measured runs require a PINNED var.ami_id, probed against the real dev
# account first (see variables.tf for the documented probe command). The
# pinned id is BOUND (owner decision 2026-08-26) in
# benchmarks/environments/confirmation.json: ami-02b3d83d84b07786d. This
# data source exists only for allow_unpinned_ami plumbing tests; the
# precondition on the instance enforces the gate.

data "aws_ami" "al2023_x86_64" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

# ─── Ephemeral network (job-scoped, egress-only) ────────────────────────────

resource "aws_vpc" "bench" {
  cidr_block           = "10.208.0.0/24" # avoids lore 10.1.0.0/16 and roxas 10.0.0.0/16 in the same dev account
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${local.name}-vpc" }
}

resource "aws_internet_gateway" "bench" {
  vpc_id = aws_vpc.bench.id

  tags = { Name = "${local.name}-igw" }
}

resource "aws_subnet" "bench" {
  vpc_id                  = aws_vpc.bench.id
  cidr_block              = "10.208.0.0/26"
  map_public_ip_on_launch = true

  tags = { Name = "${local.name}-subnet" }
}

resource "aws_route_table" "bench" {
  vpc_id = aws_vpc.bench.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.bench.id
  }

  tags = { Name = "${local.name}-rt" }
}

resource "aws_route_table_association" "bench" {
  subnet_id      = aws_subnet.bench.id
  route_table_id = aws_route_table.bench.id
}

# Egress-only security group: ZERO ingress rules. SSM Agent dials out to the
# SSM/EC2Messages endpoints over 443; results go out to S3. Nothing dials in.
resource "aws_security_group" "bench" {
  name        = "${local.name}-egress-only"
  description = "US-008 benchmark host - no ingress, egress only (SSM + S3)"
  vpc_id      = aws_vpc.bench.id

  egress {
    description = "All egress (SSM control channel, S3 results, package mirrors)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.name}-sg" }
}

# ─── Host IAM (boundary-carrying, SSM-managed) ──────────────────────────────

resource "aws_iam_role" "host" {
  name                 = "${var.project_name}-host-pr-${var.pr_number}"
  permissions_boundary = local.boundary_arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.host.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Results-bucket access only: the host may read the staged runner and write
# results/ objects in its OWN per-job bucket. No other S3 reach.
resource "aws_iam_role_policy" "results_bucket" {
  name = "results-bucket-rw"
  role = aws_iam_role.host.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ListOwnBucket"
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = aws_s3_bucket.results.arn
      },
      {
        Sid      = "ReadRunnerWriteResults"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = "${aws_s3_bucket.results.arn}/*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "host" {
  name = "${var.project_name}-host-pr-${var.pr_number}"
  role = aws_iam_role.host.name
}

# ─── Results bucket (job-scoped, force_destroy) ─────────────────────────────
# force_destroy is deliberate: the bucket and its contents are torn down in
# the same job after the workflow syncs results into the run's artifact. The
# durable copy of any real (future) benchmark results is the workflow
# artifact + the evidence flow, never this bucket.

resource "aws_s3_bucket" "results" {
  bucket        = "${var.project_name}-results-${local.account_id}-pr-${var.pr_number}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "results" {
  bucket = aws_s3_bucket.results.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "results" {
  bucket = aws_s3_bucket.results.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# ─── The confirmation host ──────────────────────────────────────────────────

resource "aws_instance" "bench" {
  ami                         = local.ami_id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.bench.id
  vpc_security_group_ids      = [aws_security_group.bench.id]
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.host.name

  # IMDSv2 only.
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = 50
    encrypted   = true
  }

  tags = {
    Name      = "${local.name}-host"
    RigorTier = local.rigor_tier
  }

  lifecycle {
    precondition {
      condition     = var.ami_id != "" || var.allow_unpinned_ami
      error_message = "AMI is not pinned. Measured benchmark runs require a preregistration-bound ami_id (probe the real account first; see variables.tf). Set allow_unpinned_ami=true ONLY for pipeline plumbing tests whose output is never a measurement."
    }
  }
}
