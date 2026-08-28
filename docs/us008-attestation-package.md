# US-008 attestation package (prepared 2026-08-27; two owner acts discharged 2026-08-27)

This document PREPARED the owner's plan-freeze + attestation step, and
now also records its partial discharge. The round-3 owner decision
record `us008-owner-attestation-2026-08-27.json` (workspace protected
root, decided_at 2026-08-27T03:52:36Z captured from `date -u`)
discharged two owner acts:

- **Plan freeze + attestation (owner-only): DONE.** The plan is FROZEN
  as of its content at mainline 51257ac and `attestation_state` is now
  `OWNER_ATTESTED`, digest-bound in the plan's `attestation_record`
  (SHA-256 `5fb3fea8b5f1213b7ae5039ce7574c23bf720f543b0bd8c568abe596
  eef86993` of the exact frozen bytes). The attestation is OWNER-ONLY:
  assurance stays `OWNER_ATTESTED_NOT_INDEPENDENT` with
  `independent_review_claimed: false` (the owner was shown this
  labeling in the question and attested under it); no independent
  attestor exists and none is claimed, so the state is NOT
  `INDEPENDENTLY_ATTESTED` and the exit-0 gate stays unsatisfied.
- **Host-tenancy allocation-evidence procedure: DONE.**
  `confirmation.json host_identity.allocation_evidence` is `BOUND` to
  `STANDARD_CLOUD_CHECKS` (per-run DescribeInstances tenancy-attribute
  query + exact instance-type confirmation + job-scoped
  exclusive-reservation record covering the run's duration). The
  binding covers the PROCEDURE; the per-run observations stay honestly
  pending until measured runs exist.

Both environments remain `binding_status: UNBOUND`, `benchplanctl
verify` still fails closed (exit 3, `HOST_BINDING_PENDING`), and no
sample of any kind exists. Everything below is the exact,
machine-cross-checked list of what remains between this state and a
fully bound, attested preregistration.

Verification source of truth: `benchplanctl verify --root .` (the
completion meter is code+schema truth — `internal/benchplan.
CanonicalBindingFields` — never document truth). Current meter: **24
unbound fields (17 confirmation + 7 primary) + 5 primary
runtime-snapshot fields deferred to measurement time; attestation
`OWNER_ATTESTED`.**

## Bound so far (no action needed)

- Tier-1 host identities (owner decision 2026-08-26, record
  `us008-owner-pinning-tier1.json` + timestamp-correction sidecar):
  `instance_type c7i.xlarge`, `region us-east-1`,
  `ami_id ami-02b3d83d84b07786d`,
  `ami_name al2023-ami-2023.12.20260817.0-kernel-6.1-x86_64`.
- Pipeline tool identities (same decision): terraform 1.9.8, the
  go.mod-directed Go toolchain record, the exact runner build literal,
  yq 4.44.3 (enforced by the dialed-setup action).
- CPU-frequency policy (round-2 owner decision 2026-08-27, record
  `us009-us008-owner-decisions-2026-08-27.json`):
  `DOCUMENT_DEFAULTS_RECORD_OBSERVED` — no tuning and no tuning claims,
  host default scaling behavior documented (facts recorded at provision),
  observed clock recorded per run.
- Allocation-accounting method (same round-2 record,
  `us008_allocation_evidence = BUILTIN_ACCOUNTING_PER_RUN`): Java
  allocation evidence from the JVM's own accounting (GC/NMT statistics),
  Rust from a counting allocator, recorded per run. Recorded as the
  `measurement_tools` candidate in BOTH environments; the field itself
  stays `OWNER_DECISION_PENDING` because exact sampler identities and
  digests are undecided.
- Host-tenancy observation procedure (round-3 owner decision
  2026-08-27, record `us008-owner-attestation-2026-08-27.json`):
  `allocation_evidence = STANDARD_CLOUD_CHECKS` — per-run
  DescribeInstances tenancy query, exact instance-type confirmation,
  job-scoped exclusive-reservation record; procedure bound, per-run
  observations pending until runs exist.
- Plan attestation (same round-3 record,
  `us008_plan_attestation = ATTESTED_BY_OWNER`): plan FROZEN at its
  51257ac content, digest-bound `attestation_record`,
  `attestation_state: OWNER_ATTESTED` (owner-only; independent
  attestation still open — see item 1 below).

## Name-collision record (RESOLVED 2026-08-27)

`host_identity.allocation_evidence` in `confirmation.json` is the
dedicated/exclusive **tenancy** observation procedure (review fix B3:
DescribeInstances tenancy attribute, instance-type confirmation,
job-scoped exclusive-reservation record — proof the host is dedicated or
exclusively reserved for the run). The round-2 decision id
`us008_allocation_evidence` shares the name but its recorded meaning
(GC/NMT statistics; counting allocator; per-run recording) is
allocation-**accounting** evidence — a measurement-tool method. The two
were NOT conflated: the accounting decision is recorded under
`tool_identities.measurement_tools`, and the tenancy field stayed
honestly pending. Binding the tenancy field with the accounting decision
would have been a false binding. **RESOLUTION:** the round-3 record
`us008-owner-attestation-2026-08-27.json`
(`us008_tenancy_allocation_evidence_procedure = STANDARD_CLOUD_CHECKS`)
designates the tenancy field's own observation procedure; the field is
now `BOUND` to it (regression-pinned by full string equality in
`internal/benchplan/validate_test.go`, which also guards that the bound
value is never the accounting method).

## Remaining owner acts, grouped

1. **Plan freeze + attestation — DONE 2026-08-27 (owner-only).** Record
   `us008-owner-attestation-2026-08-27.json`
   (`us008_plan_attestation = ATTESTED_BY_OWNER`); digest-bound
   `attestation_record` in `benchmarks/plan/workloads.json`; plan
   `attestation_state: OWNER_ATTESTED`. HONEST RESIDUE: the PRD phrase
   "independently attested plan commit" is not fully discharged — the
   attestation is owner-only (`OWNER_ATTESTED_NOT_INDEPENDENT`,
   `independent_review_claimed: false`), no independent attestor exists
   or is claimed, and `benchplanctl`'s exit-0 gate still requires
   `INDEPENDENTLY_ATTESTED` (never loosened).
2. **Host-tenancy allocation-evidence procedure — DONE 2026-08-27**
   (the name-collision item above, now resolved): record
   `us008-owner-attestation-2026-08-27.json`
   (`us008_tenancy_allocation_evidence_procedure =
   STANDARD_CLOUD_CHECKS`); `confirmation
   host_identity.allocation_evidence` is `BOUND` to the procedure;
   per-run observations pending until runs exist.
3. **Tool identities + digests, pending acquisition** — decided only
   when the exact artifacts are acquired and digested:
   - confirmation `tool_identities`: `java_runtime` (candidate OpenJDK
     17.0.19 Linux x86_64), `rust_toolchain` (candidate 1.95.0
     x86_64-unknown-linux-gnu), `load_driver`, `measurement_tools`
     (method decided; identities/digests pending), `analyzer`
     (independently rebuilt, per PRD), `runner` (replaces the
     `NOT_MEASURED`-only stub `cmd/benchrunner`).
   - primary `tool_identities`: `java_runtime`, `rust_toolchain`,
     `load_driver`, `measurement_tools`, `analyzer`.
4. **Executable digests — exist only when the artifacts exist**
   (`NOT_MEASURED`, never fabricated): `java_executable_digest`,
   `rust_executable_digest` in both environments (no Rust executable
   exists before US-009+; no Java benchmark executable is promoted).
5. **Booted-host facts recorded at provision of the bound host**
   (`NOT_MEASURED` until the first bound boot): `instance_id`,
   `observed_architecture` (schema-pinned to `x86_64`),
   `availability_zone`, `os_identity`, `kernel_identity`, `cpu_model`,
   `memory_total_bytes`, `numa_topology`, `clocksource` — plus the
   default-scaling FACTS the bound CPU-frequency policy defers to
   provision (cpufreq driver/governor presence or absence, turbo
   visibility, SMT state).
6. **Primary runtime-snapshot fields** (`PENDING_FREEZE_AT_MEASUREMENT`,
   frozen per-run by their recorded procedures, not before):
   `power_source_state`, `low_power_mode_state`,
   `thermal_pressure_state`, `background_process_census`,
   `clock_sync_state`.
7. **Tier-2 (`METAL_MEASURED`) — only if a flagship run is ever
   scheduled** (`DEFERRED_BY_OWNER`): metal instance type binding plus
   the vCPU quota-increase request sized to it.

## Driver follow-ups flagged before any measured run (not owner acts)

- ~~**Per-run observed-clock record slot.**~~ **DONE 2026-08-28**
  (US-008 restart). The bound CPU-frequency policy requires the observed
  clock recorded per measured run; `run_validity_observations` had no
  such slot, and its `additionalProperties: false` meant one could not
  be added at measurement time without a preregistration change. The
  slot now exists: `run_validity_observations.observed_cpu_clock`
  (`source` + `samples_mhz`) in
  `schemas/benchmark-raw-sample-1.0.0.schema.json`, required on
  `MEASURED` records only (the `then` branch, so every SYNTHETIC fixture
  is unaffected), with `internal/benchplan.DecideEndpoint` BLOCKING any
  MEASURED sample that omits it and `EnforceRunValidity` erroring on
  malformed readings. Malformed evidence is BLOCKED even when the same
  set carries a second defect: `DecideEndpoint` validates run-validity
  observations BEFORE pair analysis, so an unanalyzable set cannot mask
  absent clock evidence behind an `INCONCLUSIVE` analysis failure
  (`TestDecideMalformedClockOutranksUnanalyzablePairs`). The canonical
  schema and the Go contract agree on what counts as an attributed
  `source` across the whole `unicode.IsSpace` set
  (`TestSchemaAndGoAgreeOnClockSourceAttribution`), and each nested
  shape rule has a negative test
  (`TestSchemaObservedClockShapeRulesAreEnforced`).

  It is **RECORD-ONLY**, exactly as the owner bound the policy: no
  threshold is applied to clock values.
  `TestObservedClockAppliesNoThreshold` is a tripwire on the
  `EnforceRunValidity` seam over four vectors (`1`, `3200`, `99999`, and
  the `800/4800/1200` spread). It catches a low minimum, a low maximum,
  or a narrow ratio rule. It does NOT catch a threshold that admits all
  four vectors, nor one added at a different seam (`DecideEndpoint`, or
  the schema). **Correction:** an earlier revision of this bullet said
  that test "guards that none is added" — that was an overstatement. A
  mutation probe confirmed it: an unattested threshold rejecting only
  the unvisited 2000–2500 MHz band leaves the test passing. The
  record-only property rests on the frozen preregistration and review,
  with this test as a partial tripwire, not as a proof.

  Landed NOW, ahead of the runner binding, deliberately: doing it before
  any MEASURED benchmark sample exists, and before the measurement
  runner is built, keeps the recording contract frozen ahead of the
  data it will govern instead of changing it afterwards.
  **Correction:** an earlier revision of this bullet said this landed
  "before any Rust source or sample exists." The "Rust source" half was
  simply false. At `85366c4` this worktree already tracked 63 `.rs`
  files totalling roughly 22,350 lines of Rust production code, and
  `rust/ws-core/src/lib.rs` landed at `9fe68ff` (2026-08-26), an
  ancestor of this commit. What is genuinely true, and all that was ever
  needed, is that no MEASURED sample of any kind exists yet and the
  measurement runner is still an unbound stub. The runner that POPULATES
  the slot still binds with the measurement runner identity.
- **Exact AWS provider pin + lockfile** for `terraform/benchmark`
  (currently floating `>= 6.0.0`), already flagged in
  `confirmation.json` terraform notes.
- **Exact CI Go toolchain pin** (CI currently resolves 1.25.x floating
  via `go-version-file`), already flagged in `confirmation.json`
  go_toolchain notes.
- **AMI deprecation 2026-11-10**: re-probe and re-pin (a recorded
  preregistration change) if measured runs continue past that date.

## One-sitting owner checklist

1. ~~Designate the tenancy allocation-evidence procedure (item 2).~~
   DONE 2026-08-27 (`us008-owner-attestation-2026-08-27.json`).
2. Decide/acquire the tool identities + digests as artifacts land
   (item 3; executables arrive with US-009+).
3. Provision the bound host once; record the booted-host facts (item 5).
4. Verify `benchplanctl verify --root .` reports zero unbound fields.
5. Set both environments `binding_status: BOUND` and attest
   independently (`attestation_state: INDEPENDENTLY_ATTESTED`) — at
   which point `benchplanctl verify` exits 0 and the no-sample gate
   lifts (subject to the PRD's other US-008 dependency gates). The plan
   freeze itself is DONE (owner-attested 2026-08-27, digest-bound); the
   independent attestation is the part that remains, and it is neither
   performed nor claimed by any driver round.
