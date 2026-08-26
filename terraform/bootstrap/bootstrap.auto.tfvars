project_name                = "vjwp-bench"
aws_region                  = "us-east-1"
github_repo                 = "michaellady/verified-java-websocket-port"
current_account_id          = "539402214167"
envs_in_this_account        = ["dev"]
assume_oidc_provider_exists = true

# GitHub emits IMMUTABLE subject claims for this repo (numeric ids embedded) —
# verified 2026-08-26 via `gh api /repos/michaellady/verified-java-websocket-port/actions/oidc/customization/sub`
# (.sub_claim_prefix = "repo:michaellady@936234/verified-java-websocket-port@1344905073").
# The classic owner/name pattern never matches an immutable sub, so the first
# plumbing run failed at AssumeRoleWithWebIdentity. Only the immutable form is
# admitted by the trust policy.
oidc_extra_sub_repos = ["michaellady@936234/verified-java-websocket-port@1344905073"]
oidc_trusted_workflow_refs = [
  "michaellady/verified-java-websocket-port/.github/workflows/benchmark.yml@refs/heads/main",
  "michaellady/verified-java-websocket-port/.github/workflows/bench-janitor.yml@refs/heads/main",
]
