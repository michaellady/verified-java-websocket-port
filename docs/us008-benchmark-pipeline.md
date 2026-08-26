# US-008 benchmark-confirmation pipeline (enabling work)

Status: PREREGISTRATION FROZEN TO THE OWNERLESS MAXIMUM; HOST BINDING
OWNER-GATED. The pipeline scaffold below is unchanged (SCAFFOLD: no AWS
resource created, no bootstrap applied, runner still a `NOT_MEASURED`-only
stub), and the preregistration substance on top of it is now complete to
the maximum extent possible without owner decisions. **Nothing here claims
US-008 passes**, and US-008 cannot pass in this state by design:

- `benchmarks/plan/workloads.json` is a frozen, schema-enforced
  preregistration (`schemas/benchmark-plan-1.0.0.schema.json`): six exact
  workloads with fixed rates/concurrency/operations/durations and
  deterministic input/output generators, the executable SHA-256
  seed-derivation rule with per-workload derived pair orders (5 warmup +
  30 measured), the frozen statistics plan, per-metric CI thresholds, and
  the schema-pinned forbidden-practices list. PRD-stated values are
  marked `PRD_VERBATIM`; every choice the PRD left open is marked
  `PREREGISTERED_BY_DRIVER` with its rationale.
- `internal/benchplan` is the preregistered reference statistics engine:
  paired natural-log ratio analysis (mean, sample SD, two-sided 95%
  Student-t with 29 df, exponentiated bounds), the frozen power model
  (alpha 0.025, power >= 0.8, max log-SD 0.10, named `ln(0.8)` memory and
  `ln(1.1)` non-regression alternatives), and the fail-closed decision
  rule. It is validated against published t-tables (t_{0.975,29} =
  2.045230), an independent Simpson-rule integration, an
  independently-derived (Python hashlib) pair-order golden vector, and
  closed-form synthetic fixtures labeled
  `SYNTHETIC_FIXTURE_NOT_A_MEASUREMENT`. No measured datum exists
  anywhere; the engine refuses unbound `MEASURED` sample sets.
- `benchmarks/environments/primary-macos.json` now carries honestly
  OBSERVED host facts (recorded commands + timestamps) matching the
  PRD-pinned class (macOS 26.4.1, Apple M4 Pro); run-time snapshot fields
  stay `PENDING_FREEZE_AT_MEASUREMENT` and every tool identity stays
  `OWNER_DECISION_PENDING`.
- `benchmarks/environments/confirmation.json` keeps every host field
  `OWNER_DECISION_PENDING`/`NOT_MEASURED` and adds the schema-enforced
  `required_binding_fields` completion meter.
- `cmd/benchplanctl verify --root .` validates all benchmark documents,
  re-derives the pair orders, checks the power model, and prints exactly
  which fields remain unbound. Current, verified output: documents
  consistent; **single remaining blocker class `HOST_BINDING_PENDING`**
  (27 unbound host/tool fields; exit code 3). Exit code 0 is unreachable
  until the owner binds the confirmation host and tool identities.

The pipeline fails closed at every missing prerequisite by design.

Owner authorization context: the project moved into Enterprise Vibe Code
specifically so this pipeline can use EVC's DIALED-managed AWS accounts, and
the implementation-ordering amendment
(`workspace/orchestrator/verified-java-websocket-port-claude/protected/us008-contract-amendment-implementation-ordering.json`
in HQ) lets implementation stories proceed while every measurement gate
stays frozen until the confirmation host binds.

## Design (feasibility-study "shape A" — honored exactly)

One standalone workflow job owns the entire host lifecycle:

```
label 'benchmark' on PR (or workflow_dispatch)
  └─ job: benchmark-host            (environment: dev, timeout 120 min)
       1. dialed-setup composite    → OIDC role, region, account, tfvars
       2. terraform init            → S3 state dialed-vjwp-bench-<acct>-tfstate,
                                      DDB locks, workspace bench-pr-<N>
       3. terraform apply           → ephemeral VPC + egress-only SG +
                                      boundary-carrying IAM role/profile +
                                      per-job S3 results bucket +
                                      BARE-METAL instance (c5n.metal candidate)
       4. wait for SSM Online       → metal boot can take 10-20 min
       5. stage runner in S3, ssm send-command → run natively, no ingress
       6. poll invocation           → fail loudly on Failed/TimedOut
       7. s3 sync results           → upload-artifact (30-day retention)
       8. ALWAYS (if: always())     → terraform destroy (3 attempts) +
                                      workspace delete +
                                      verify no instance still live
```

Plus `bench-janitor.yml`: an every-3-hours sweeper that destroys any
`bench-pr-*` workspace whose state object is 3+ hours old — job-scoped
stacks should never outlive the job's 2-hour hard timeout, so age alone
identifies an orphan (no PR-state check needed, unlike DIALED's pr-janitor).

### Why job-scoped, not PR-open→PR-close (~140x cost rationale)

The billed resource is a bare-metal instance at an on-demand rate on the
order of ~$4/hour (c5n.metal, us-east-1 — verify current AWS pricing before
enabling). A DIALED-standard PR-lifetime stack would bill from PR open to PR
close: a typical week-long review cycle is ~168 instance-hours. The
job-scoped lifecycle bills roughly 1–2 hours per labeled run. That is the
~140x billing-window difference (168h vs ~1.2h) that drove shape A. The
`if: always()` teardown, the 120-minute hard job timeout, the post-destroy
"no live instance" verification, and the 3-hour janitor are four independent
layers bounding worst-case spend.

### Why bare metal

Virtualization overhead is the reason Docker sbx is excluded from hosting
measured benchmark samples; a dedicated-tenancy instance is still a VM, so
it would reintroduce exactly the overhead class the exclusion exists to
remove. `terraform/benchmark/variables.tf` therefore validates
`instance_type` against `*.metal`. `c5n.metal` is the default-candidate
only — the final type is **OWNER-DECISION-PENDING** in
`benchmarks/environments/confirmation.json`.

### Borrowed DIALED plumbing

- `.github/actions/dialed-setup` — composite action adapted from the DIALED
  skill template: loads `.dialed.yml`, derives
  `arn:aws:iam::<acct>:role/dialed/dialed-vjwp-bench-deploy-dev`, assumes it
  via GitHub OIDC, installs Terraform, exports auto-tfvars.
- State naming — `dialed-vjwp-bench-<account>-tfstate` bucket +
  `dialed-vjwp-bench-<account>-tflocks` DDB table; workspace `bench-pr-<N>`;
  state key `benchmark/terraform.tfstate`.
- Permissions boundary — the host role is created as
  `vjwp-bench-host-pr-<N>` carrying `dialed-vjwp-bench-boundary`, matching
  the bootstrap's `ManageProjectRolesWithBoundary` condition (roles minted
  by the deploy role MUST carry the boundary or creation is denied).
- The benchmark root is self-contained (own ephemeral VPC, `10.208.0.0/24`)
  and does NOT read the EVC shared tier: the confirmation host must be
  provenance-distinct, and nothing long-lived should be shared with app
  stacks.

### Fail-closed preregistration gates baked into the pipeline

- Provisioning **fails** unless `ami_id` is pinned (owner probe documented
  in `terraform/benchmark/variables.tf`) or `allow_unpinned_ami=true` is
  passed explicitly for a plumbing test whose output can never be a
  measurement.
- The runner stub refuses every mode except `pipeline-smoke` and emits the
  result-schema skeleton with `NOT_MEASURED` in every metric field, then
  self-checks that no metric field holds a number.
- The workflow summary states on every run that the output is not a
  benchmark, not a performance claim, and not evidence that US-008 passes.

## Gated NEXT STEPS — owner / parent-session actions required

None of these are performed by this scaffold, and the pipeline cannot run
until they are. Each is an explicit AWS or GitHub mutation requiring owner
authorization:

1. **DIALED bootstrap apply (AWS mutation).** Create the `vjwp-bench` state
   bucket + lock table, OIDC provider reference, per-env deploy role, and
   permissions boundary in the EVC dev account (539402214167), following the
   DIALED bootstrap templates. Until then, `terraform init` and OIDC role
   assumption fail closed.
2. **GitHub `dev` environment (GitHub settings mutation).** Both workflows
   declare `environment: dev`; the narrowed OIDC trust admits only
   `pull_request` and `environment:dev` subjects, so the janitor
   (schedule/dispatch) cannot assume the role without it.
3. **Branch protection — RECOMMEND NOT adopting DIALED's default
   main-branch-protection checks on this repo.** This is a SHARED repo where
   a second authority plane (Codex) also pushes. DIALED's standard setup
   marks its deploy/system-test jobs as required checks on `main`; here that
   would make an expensive, label-gated metal-host workflow a merge gate for
   both planes and let a benchmark-infra outage block unrelated Codex
   landings (and vice versa). The benchmark workflow should stay label-gated
   and advisory. If any protection is added, scope it to checks both planes
   already share, never to `benchmark-host`.
4. **vCPU quota request (AWS support mutation).** c5n.metal is 72 vCPUs; a
   fresh account's "Running On-Demand Standard instances" quota is typically
   below that. The owner must request/verify ≥72 standard vCPUs in the
   chosen region before the first plumbing run, or apply fails at instance
   launch.
5. **Budget alarm (AWS mutation).** Before enabling the label trigger,
   create an AWS Budgets alarm (suggested: monthly cost budget with alerts
   at ~$50/$100, plus an EC2-usage-hours alarm) in the dev account so a
   janitor-missed orphan is surfaced by billing, not by the invoice.
6. **Owner decisions to bind in `benchmarks/environments/confirmation.json`:**
   final instance type (candidate c5n.metal), final region (candidate
   us-east-1), pinned AMI (after the documented probe), kernel identity,
   CPU-frequency policy, and every tool identity + digest (JDK, Rust
   toolchain, load driver, measurement tools, independently rebuilt
   analyzer).
7. **Plan freeze + independent attestation** of the preregistration itself
   (`benchmarks/plan/workloads.json` OWNER_DECISION_PENDING fields resolved,
   then frozen) — the PRD forbids any raw or tuning sample predating the
   independently attested plan commit. Current assurance posture:
   `OWNER_ATTESTED_NOT_INDEPENDENT`, `independent_review_claimed: false`.

## What this scaffold explicitly does NOT do

- No `terraform plan/apply` was run against AWS; no AWS CLI mutation was
  made; no GitHub setting, environment, or branch protection was touched;
  no DIALED setup script was executed.
- No benchmark sample exists; no performance number appears anywhere in
  this file set; every unmeasured value is a `NOT_MEASURED` sentinel and
  every unmade decision an `OWNER_DECISION_PENDING` sentinel.
- US-008 remains `passes: false` and this scaffold is not evidence toward
  passing it.
