# US-008 benchmark-confirmation pipeline (enabling work)

Status: PREREGISTRATION FROZEN; TIER-1 HOST IDENTITIES BOUND; FULL HOST
BINDING STILL OWNER-GATED. Confirmation rigor is TIERED per the
owner-authorized amendment of 2026-08-26 (workspace protected root
`us008-contract-amendment-tiered-benchmark-rigor.json`): Tier-1
`VM_MEASURED_JITTER_AVERAGED` is the campaign default, Tier-2
`METAL_MEASURED` is the opt-in flagship and is currently
`DEFERRED_BY_OWNER`. The owner's Tier-1 pinning decision of 2026-08-26
bound the confirmation-host identities `instance_type: c7i.xlarge`,
`region: us-east-1`, `ami_id: ami-02b3d83d84b07786d`
(`al2023-ami-2023.12.20260817.0-kernel-6.1-x86_64`) plus the pipeline
tool identities (Terraform 1.9.8, the go.mod-directed Go toolchain
record, the exact runner build literal, yq 4.44.3 — enforced by the
dialed-setup action). The DIALED bootstrap tier is applied in the EVC dev
account, and the pipeline's end-to-end plumbing was proven by the green,
sentinel-only run 33000379021 (`benchmark-plumbing` label, c7i.large,
latest-AL2023 boot; `NOT_MEASURED` sentinels only — not a measurement).
The owner's round-2 decision of 2026-08-27 (workspace protected root
`us009-us008-owner-decisions-2026-08-27.json`) additionally bound the
CPU-frequency policy (`DOCUMENT_DEFAULTS_RECORD_OBSERVED`) and decided
the allocation-accounting method (`BUILTIN_ACCOUNTING_PER_RUN`, recorded
as the `measurement_tools` candidate — the host-tenancy
`allocation_evidence` field remains an open owner decision; see
`docs/us008-attestation-package.md` for the name-collision record).
The runner remains a `NOT_MEASURED`-only stub, 25 host/tool binding
fields remain unbound, and `benchplanctl verify` fails closed with the
single blocker class `HOST_BINDING_PENDING` (exit 3). **Nothing here
claims US-008 passes**, and US-008 cannot pass in this state by design:

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
- `benchmarks/environments/confirmation.json` records the owner's Tier-1
  binding of 2026-08-26: `instance_type` / `region` / `ami_id` /
  `ami_name` are `BOUND` (each with its probe-before-wire rationale), the
  pipeline tool identities `terraform` / `go_toolchain` /
  `runner_build_flags` / `yq` are `BOUND` and regression-pinned by exact
  string equality (plus cross-checks against the workflow and action
  files) in `internal/benchplan/validate_test.go`, the round-2 owner
  decision of 2026-08-27 bound `cpu_frequency_policy` (same
  exact-equality pin), the round-3 owner decision of 2026-08-27 bound
  `allocation_evidence` to the `STANDARD_CLOUD_CHECKS` tenancy
  observation procedure (same exact-equality pin; per-run observations
  stay pending), Tier-2
  (`METAL_MEASURED`) is explicitly `DEFERRED_BY_OWNER`, and the remaining
  17 of its 23 required binding fields stay honestly
  `OWNER_DECISION_PENDING`/`NOT_MEASURED` behind the schema-enforced
  `required_binding_fields` completion meter (`binding_status: UNBOUND`).
- `cmd/benchplanctl verify --root .` validates all benchmark documents,
  re-derives the pair orders, checks the power model, and prints exactly
  which fields remain unbound. Current, verified output: documents
  consistent; **single remaining blocker class `HOST_BINDING_PENDING`**
  (24 unbound host/tool fields — 17 on the confirmation environment plus
  7 primary tool identities — and 5 primary runtime-snapshot fields
  deferred to measurement time; exit code 3). The plan's
  `attestation_state` is `OWNER_ATTESTED` (owner-only, digest-bound;
  2026-08-27). Exit code 0 additionally
  requires both environments' `binding_status: BOUND` and the plan's
  `attestation_state: INDEPENDENTLY_ATTESTED` — an owner-only
  attestation never satisfies that gate, and syntactically complete
  field values with UNBOUND/unattested status never verify as bound.

Review fixes B1-B4/I5/I6 (adversarial review, session 01a03f01) landed on
top of the frozen preregistration:

- **Masking rule frozen (B1).** Every masked client frame's 32-bit
  masking key derives from `vjwp-us008-mask|v1` (first 4 bytes of
  SHA-256 over workload id, pair index, frame index —
  `shared_definitions.masking_rule`, implemented and golden-vector
  tested as `internal/benchplan.MaskingKey`), so every declared frame's
  full wire bytes are deterministic.
- **Identity-verifying decision rule (B2).**
  `internal/benchplan.DecideEndpoint` now takes the bound identity
  closure and requires EQUALITY of all ten canonical digests, failing
  closed with typed `BINDING_MISMATCH` per field; presence/format alone
  verifies nothing.
- **Exact host representable (B3).** `confirmation.json` adds
  `instance_id`, `observed_architecture` (schema-pinned to `x86_64` when
  observed/bound), and `allocation_evidence` (dedicated/exclusive
  tenancy observation) to the binding meter; raw sample records must
  declare `environment_role` (primary/confirmation) and the engine
  rejects records that do not.
- **Run validity operationalized (B4).** The 5% reference-drift
  envelope is now an exact frozen procedure
  (`statistics.reference_drift_procedure`: wl-02 reference runs, 1
  baseline + 7 scheduled, product-form comparison) and canonical raw
  records carry `run_validity_observations` (background CPU, thermal,
  power, identity, invalid samples, drift) enforced fail-closed by the
  engine (`RUN_VALIDITY_MISSING` / `RUN_VALIDITY_VIOLATION`).
- **Go-over-shell (I6, completed in round 2).** The runner stub is the
  Go binary `cmd/benchrunner` (same refusal/sentinel semantics,
  self-check never skipped). Every workflow step containing a
  conditional, loop, or state machine is a one-line invocation of a
  unit-tested Go helper: `cmd/benchjanitor` (orphan selection + batch
  destroy) and `cmd/benchops` (apply/destroy var construction, destroy
  retries, workspace delete, SSM online wait, SSM send+poll, leftover-
  host verification), sharing the `internal/benchexec` transport seam.
  The only remaining multi-line shell steps are strictly linear
  transport command sequences with no conditionals or loops (workspace
  name derivation, terraform init backend flags, output capture, build
  + upload, s3 sync, job summary). Both workflows are actionlint-clean.
- **Canonical binding meter (round 2 BLOCKING fix).** The
  required-binding-field lists are code+schema truth, not document
  truth: `internal/benchplan.CanonicalBindingFields` freezes the
  per-role lists (primary 20, confirmation 23), the environment schema
  consts them per role, the filename-to-role contract is enforced, and
  `benchplanctl verify` meters the CANONICAL list and fails with
  `METER_TAMPERED` on any divergence — a document shrinking its own
  list can never reach a bound verdict.

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
                                      tiered confirmation host (Tier-1
                                      bound c7i.xlarge; opt-in Tier-2
                                      *.metal, deferred)
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

The rationale was sized against the flagship tier: a bare-metal instance
at an on-demand rate on the order of ~$4/hour (c5n.metal, us-east-1 —
verify current AWS pricing before enabling; the bound Tier-1 c7i.xlarge
probed at USD 0.1785/hour, so job-scoping matters even more at metal
rates). A DIALED-standard PR-lifetime stack would bill from PR open to PR
close: a typical week-long review cycle is ~168 instance-hours. The
job-scoped lifecycle bills roughly 1–2 hours per labeled run. That is the
~140x billing-window difference (168h vs ~1.2h) that drove shape A. The
`if: always()` teardown, the 120-minute hard job timeout, the post-destroy
"no live instance" verification, and the 3-hour janitor are four independent
layers bounding worst-case spend.

### Tiered rigor: why the flagship tier is bare metal (and Tier-1 is a VM)

Virtualization overhead is the reason Docker sbx is excluded from hosting
measured benchmark samples, and a dedicated-tenancy instance is still a
VM. The original contract therefore required bare metal outright; the
owner-authorized amendment of 2026-08-26 (workspace protected root
`us008-contract-amendment-tiered-benchmark-rigor.json`) split that rigor
into two tiers:

- **Tier 2 — `METAL_MEASURED`** (opt-in flagship): a `*.metal` type with
  no virtualization overhead. Currently **`DEFERRED_BY_OWNER`**: no
  flagship run is scheduled and no metal type is bound; `c5n.metal` in
  `terraform/benchmark/variables.tf` remains the default-candidate only.
- **Tier 1 — `VM_MEASURED_JITTER_AVERAGED`** (campaign default): an
  ordinary VM type whose residual virtualization jitter is absorbed by
  the preregistered N-round protocol. **BOUND** by the owner on
  2026-08-26 to `c7i.xlarge` (the 4-vCPU variant so the load driver and
  the endpoint under test do not share a physical core; same CPU family
  and image as green plumbing run 33000379021).

`terraform/benchmark/variables.tf` no longer restricts `instance_type`
to `*.metal`: the rigor tier is DERIVED from the type
(`local.rigor_tier` — `*.metal`/`*.metal-<size>` ⇒ Tier 2, anything else
⇒ Tier 1), stamped on the instance tags, and exported as a Terraform
output so the environment binding of every published number records it.
A Tier-1 number must never be represented as metal-grade.

### Borrowed DIALED plumbing

- `.github/actions/dialed-setup` — composite action adapted from the DIALED
  skill template: loads `.dialed.yml`, derives
  `arn:aws:iam::<acct>:role/dialed/dialed-vjwp-bench-deploy-dev`, assumes it
  via GitHub OIDC, enforces the recorded yq pin (4.44.3 — installs the
  exact pin whenever the resolving yq differs and fails if the pin does
  not resolve), installs Terraform 1.9.8, exports auto-tfvars.
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

## Owner / parent-session actions: done vs still gated

Completed with explicit owner authorization:

1. **DIALED bootstrap apply — DONE.** The `vjwp-bench` state bucket + lock
   table, OIDC trust, deploy role, and permissions boundary exist in the
   EVC dev account (539402214167); the applied bootstrap tier is committed
   under `terraform/bootstrap/`.
2. **End-to-end plumbing — PROVEN, sentinel-only.** The owner-ordered
   plumbing test (green run 33000379021, `benchmark-plumbing` label)
   exercised OIDC role assumption, provision, SSM-native runner
   invocation, result sync, and teardown on a c7i.large with a
   latest-AL2023 boot. Its output is `NOT_MEASURED` sentinels by
   construction and can never be a measurement.
3. **Tier-1 host pinning — DONE (2026-08-26).** `instance_type
   c7i.xlarge`, `region us-east-1`, and the AMI pin recorded in
   `benchmarks/environments/confirmation.json`; Tier-2 explicitly
   `DEFERRED_BY_OWNER`.

Deliberate non-adoption (not a gate — a standing recommendation):

- **Branch protection: RECOMMEND NOT adopting DIALED's default
  main-branch-protection checks on this repo.** This is a SHARED repo where
  a second authority plane (Codex) also pushes. DIALED's standard setup
  marks its deploy/system-test jobs as required checks on `main`; here that
  would make an expensive, label-gated metal-host workflow a merge gate for
  both planes and let a benchmark-infra outage block unrelated Codex
  landings (and vice versa). The benchmark workflow stays label-gated and
  advisory by design; nothing fails closed on its absence. If any
  protection is ever added, scope it to checks both planes already share,
  never to `benchmark-host`.

Still gated — mechanically fail-closed until each is done (Terraform
preconditions, `benchplanctl` exit 3, or AWS itself reject the run):

1. **Tier-2 vCPU quota request (AWS support mutation; Tier-2 runs only).**
   Metal types are large (c5n.metal is 72 vCPUs) and the account's
   probed "Running On-Demand Standard instances" quota (L-1216C47A) is
   64 vCPUs — m5zn.metal (48 vCPUs) is the only probed metal candidate
   that fits it today; AWS rejects any larger metal launch until the
   quota is raised. The bound Tier-1 c7i.xlarge (4 vCPUs) fits the
   standing quota; no request is needed for the campaign default.
2. **Remaining owner decisions to bind in
   `benchmarks/environments/confirmation.json`** (the 18 pending
   confirmation fields the completion meter reports): the host-tenancy
   allocation-evidence observation procedure (still open — the round-2
   `BUILTIN_ACCOUNTING_PER_RUN` decision of 2026-08-27 resolved
   allocation-ACCOUNTING evidence, a measurement-tool method, not host
   tenancy), every
   measurement/analyzer tool identity + digest (JDK distribution, Rust
   toolchain, load driver, measurement tools, independently rebuilt
   analyzer, digested runner), the booted-host facts recorded at
   provision of the bound host (instance id, availability zone, observed
   architecture, OS/kernel identity, CPU model, memory, NUMA topology,
   clocksource) — plus a Tier-2 metal type if the deferred flagship run
   is ever scheduled, and the 7 primary-environment tool identities.
   The CPU-frequency policy is now BOUND (round-2 decision 2026-08-27).
   `benchplanctl` fails closed (exit 3, HOST_BINDING_PENDING) until bound.
3. **Plan freeze + independent attestation** of the preregistration itself
   (`benchmarks/plan/workloads.json` OWNER_DECISION_PENDING fields resolved,
   then frozen) — the PRD forbids any raw or tuning sample predating the
   independently attested plan commit; the preflight stays BLOCKED until
   then. Current assurance posture: `OWNER_ATTESTED_NOT_INDEPENDENT`,
   `independent_review_claimed: false`.

Recommended before enabling measured runs (owner step, NOT mechanically
enforced by the pipeline):

- **Budget alarm (AWS mutation).** Create an AWS Budgets alarm (suggested:
  monthly cost budget with alerts at ~$50/$100, plus an EC2-usage-hours
  alarm) in the dev account so a janitor-missed orphan is surfaced by
  billing alerts, not by the invoice.

## What this file set still explicitly does NOT contain

- No benchmark sample exists; no performance number appears anywhere in
  this file set; every unmeasured value is a `NOT_MEASURED` sentinel and
  every unmade decision an `OWNER_DECISION_PENDING` sentinel.
- The only AWS mutations to date are the owner-authorized DIALED
  bootstrap apply and the job-scoped, self-destroying plumbing-run stack
  (run 33000379021); every host/AMI pinning probe was a read-only call.
  The plumbing run's output is sentinel-only by construction and can
  never be a measurement.
- US-008 remains `passes: false`; neither this pipeline state nor the
  Tier-1 binding is evidence toward passing it.
