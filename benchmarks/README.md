# benchmarks/ — US-008 preregistration (frozen; Tier-1 host bound, full binding owner-gated)

This directory holds the **preregistration** for the US-008 controlled
Java/Rust resource benchmarks and the pipeline runner stub. The plan and
environment documents are frozen and machine-validated by
`benchplanctl verify --root .` against `schemas/benchmark-*.schema.json`.
Confirmation rigor is TIERED per the owner-authorized amendment of
2026-08-26: Tier-1 `VM_MEASURED_JITTER_AVERAGED` is the campaign default
and its host identities are BOUND (c7i.xlarge, us-east-1, pinned AL2023
kernel-6.1 AMI `ami-02b3d83d84b07786d`); Tier-2 `METAL_MEASURED` is the
opt-in flagship and is `DEFERRED_BY_OWNER`. **US-008 has not run, has no
samples, and does not pass**: 26 host/tool binding fields remain unbound
and the single remaining blocker class is `HOST_BINDING_PENDING`
(owner-gated completion of the confirmation-host and
measurement/analyzer tool-identity binding; `benchplanctl verify` fails
closed with exit 3). The pipeline's end-to-end plumbing was proven by
the green, sentinel-only run 33000379021 — `NOT_MEASURED` sentinels
only, not a measurement.

## The no-fabrication rule (read this first)

Nothing in this directory, in the benchmark pipeline, or in any artifact the
pipeline produces may contain an invented measurement. Concretely:

- Every value that has not been measured is the literal sentinel string
  `NOT_MEASURED`. A `NOT_MEASURED` sentinel is the only honest placeholder;
  a plausible-looking number in its place is fabrication and is a blocking
  integrity violation.
- Every decision the owner has not yet made is the literal sentinel string
  `OWNER_DECISION_PENDING`. Defaults named next to a sentinel (e.g.
  "candidate: c5n.metal") are candidates, not decisions.
- Where the PRD states an exact value it is frozen verbatim and marked
  `PRD_VERBATIM`. Where the PRD left a choice open, the driver chose and
  froze it, marked `PREREGISTERED_BY_DRIVER` with a rationale — that is an
  allowed preregistration act. Only host and tool identities stay
  `OWNER_DECISION_PENDING`.
- Fields that can only be captured at measurement time (power/thermal
  state, background census, clock sync) carry the sentinel
  `PENDING_FREEZE_AT_MEASUREMENT` plus a frozen capture procedure; they
  are run-record fields, not preflight-binding fields.
- Honestly observed present-day facts (the primary host's `sw_vers` /
  `sysctl` identity) are marked `OBSERVED` with the exact command and
  UTC timestamp recorded. Observation is not attestation: the document
  stays `binding_status: UNBOUND` until the owner freezes and attests.
- The runner under `runner/` is a **stub**: it validates its arguments and
  emits the result-schema skeleton with `NOT_MEASURED` in every metric
  field. It will refuse to run in any mode that implies measurement.
- No benchmark sample may be collected before the owner-attested,
  explicitly non-independent plan freeze, before the confirmation host and
  every measurement/analyzer tool identity are bound in
  `environments/confirmation.json`, and while the US-008 dependency gates in
  the PRD remain blocked.
- Docker sbx may isolate build/test preparation but must never host a
  measured sample (microVM overhead changes the declared boundary).
  Confirmation-host rigor is tiered per the owner amendment of
  2026-08-26: Tier-2 `METAL_MEASURED` (bare metal, no virtualization
  overhead — dedicated tenancy is still a VM) is the opt-in flagship,
  currently `DEFERRED_BY_OWNER`; Tier-1 `VM_MEASURED_JITTER_AVERAGED`
  (the bound c7i.xlarge campaign default) absorbs residual
  virtualization jitter through the preregistered N-round protocol. The
  rigor tier is derived from the instance type and recorded with every
  binding; a Tier-1 number must never be represented as metal-grade.

## Layout

- `plan/workloads.json` — the frozen machine-validated preregistration
  (`schemas/benchmark-plan-1.0.0.schema.json`): six exact workloads with
  fixed rates, concurrency, operations, durations, and deterministic
  input/output generators; the executable SHA-256 seed rule with each
  workload's derived pair order (5 warmup + 30 measured); the frozen
  masking-key rule (`vjwp-us008-mask|v1`) making every client frame's
  wire bytes deterministic; the frozen statistics plan, power model, and
  reference-drift procedure; the per-metric CI thresholds; and the
  schema-pinned forbidden-practices list. The plan's machine-readable
  `freeze_state` is `OWNER_ATTESTED_NOT_INDEPENDENT`; this is a valid
  story-level freeze and is separate from sample readiness. No results field exists and the schema
  (`additionalProperties: false`) forbids ever adding one.
- `environments/primary-macos.json` — the primary macOS Apple M4 Pro
  environment with honestly OBSERVED host identity (commands + timestamps
  recorded), preregistered run policy, and OWNER_DECISION_PENDING tool
  identities (`binding_status: UNBOUND`).
- `environments/confirmation.json` — the provenance-distinct exclusively
  reserved Linux x86_64 confirmation host, with tiered rigor. The
  owner's Tier-1 decision of 2026-08-26 BOUND `instance_type`
  (c7i.xlarge), `region` (us-east-1), `ami_id` / `ami_name` (pinned
  AL2023 kernel-6.1), and the pipeline tool identities (terraform,
  go_toolchain, runner_build_flags, yq) — each regression-pinned by
  exact string equality in `internal/benchplan/validate_test.go`.
  Tier-2 is `DEFERRED_BY_OWNER`. The remaining 19 of its 23 required
  binding fields stay OWNER_DECISION_PENDING or NOT_MEASURED behind the
  schema-enforced `required_binding_fields` completion meter
  (`binding_status: UNBOUND` until the owner pins every field).
- The SSM-invoked runner stub is the Go binary `cmd/benchrunner` (schema
  emission only; cross-compiled for the confirmation host by
  `.github/workflows/benchmark.yml`). It refuses every mode except
  `pipeline-smoke` and self-checks that no metric field holds anything
  but the `NOT_MEASURED` sentinel.

Verification and reference implementation:

- `benchplanctl verify --root .` — validates the three documents against
  their schemas, re-derives every pair order from the seed rule, checks
  the frozen power model, and prints the binding completion meter. Exit
  code 3 = documents consistent, `HOST_BINDING_PENDING` remains (the
  current, expected state); exit 0 (fully bound) is owner-gated.
- `benchplanctl order` — prints the SHA-256-derived Java/Rust pair order
  (the executable form of the seed spec).
- `internal/benchplan` — the preregistered reference statistics engine
  (paired log-ratio analysis, Student-t via incomplete beta, power model,
  fail-closed decision rule), validated only on synthetic fixtures
  labeled `SYNTHETIC_FIXTURE_NOT_A_MEASUREMENT` and published t-tables.
  It is NOT the bound analyzer: the PRD requires an independently rebuilt
  analyzer whose identity and digest bind with the tool identities.
- `schemas/benchmark-raw-sample-1.0.0.schema.json` — the canonical
  raw-pair record shape; a `MEASURED` record must carry all ten binding
  digests, so no measured record can validly exist before host binding.

The PRD's canonical US-008 file set (`benchmarks/plan.json`,
`benchmarks/workloads/`, `benchmarks/analysis-contract.json`,
`benchmarks/analyzer/`) is produced when US-008 itself is executed; the
frozen preregistration above pre-shapes that content. The owner-attested,
non-independent freeze is complete; host/tool binding still blocks samples.
