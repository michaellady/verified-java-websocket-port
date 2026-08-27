# US-008 attestation package (prepared 2026-08-27)

This document PREPARES the owner's plan-freeze + attestation step. It is
not the attestation: the plan remains `attestation_state: UNATTESTED`,
both environments remain `binding_status: UNBOUND`, `benchplanctl
verify` fails closed (exit 3, `HOST_BINDING_PENDING`), and no sample of
any kind exists. Everything below is the exact, machine-cross-checked
list of what remains between this state and a fully bound, attested
preregistration, so the owner can act on it in one sitting.

Verification source of truth: `benchplanctl verify --root .` (the
completion meter is code+schema truth — `internal/benchplan.
CanonicalBindingFields` — never document truth). Current meter: **25
unbound fields (18 confirmation + 7 primary) + 5 primary
runtime-snapshot fields deferred to measurement time.**

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

## Name-collision record (one owner touch required)

`host_identity.allocation_evidence` in `confirmation.json` is the
dedicated/exclusive **tenancy** observation procedure (review fix B3:
DescribeInstances tenancy attribute, instance-type confirmation,
job-scoped exclusive-reservation record — proof the host is dedicated or
exclusively reserved for the run). The round-2 decision id
`us008_allocation_evidence` shares the name but its recorded meaning
(GC/NMT statistics; counting allocator; per-run recording) is
allocation-**accounting** evidence — a measurement-tool method. The two
were NOT conflated: the accounting decision is recorded under
`tool_identities.measurement_tools`, and the tenancy field remains
honestly pending. Binding the tenancy field with the accounting decision
would have been a false binding. **Remaining owner act: designate the
tenancy/allocation observation procedure** (or explicitly re-scope the
field — either way, one recorded decision).

## Remaining owner acts, grouped

1. **Plan freeze + independent attestation** (the PRD forbids any raw or
   tuning sample predating the independently attested plan commit).
   Separate owner act — deliberately NOT performed by any driver round.
   Current posture: `OWNER_ATTESTED_NOT_INDEPENDENT`,
   `independent_review_claimed: false`, plan `UNATTESTED`.
2. **Host-tenancy allocation-evidence procedure** (the name-collision
   item above): `confirmation host_identity.allocation_evidence`.
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

- **Per-run observed-clock record slot.** The bound CPU-frequency policy
  requires the observed clock recorded per measured run; the canonical
  raw-sample schema's `run_validity_observations` has no such slot yet.
  It must be added (schema or runner-record extension) when the
  measurement runner and tools bind — before any measured sample exists.
- **Exact AWS provider pin + lockfile** for `terraform/benchmark`
  (currently floating `>= 6.0.0`), already flagged in
  `confirmation.json` terraform notes.
- **Exact CI Go toolchain pin** (CI currently resolves 1.25.x floating
  via `go-version-file`), already flagged in `confirmation.json`
  go_toolchain notes.
- **AMI deprecation 2026-11-10**: re-probe and re-pin (a recorded
  preregistration change) if measured runs continue past that date.

## One-sitting owner checklist

1. Designate the tenancy allocation-evidence procedure (item 2).
2. Decide/acquire the tool identities + digests as artifacts land
   (item 3; executables arrive with US-009+).
3. Provision the bound host once; record the booted-host facts (item 5).
4. Verify `benchplanctl verify --root .` reports zero unbound fields.
5. Set both environments `binding_status: BOUND`, freeze the plan, and
   independently attest (`attestation_state: INDEPENDENTLY_ATTESTED`) —
   at which point `benchplanctl verify` exits 0 and the no-sample gate
   lifts (subject to the PRD's other US-008 dependency gates).
