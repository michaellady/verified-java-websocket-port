# benchmarks/ — US-008 preregistration (frozen to the ownerless maximum)

This directory holds the **preregistration** for the US-008 controlled
Java/Rust resource benchmarks and the pipeline runner stub. The plan and
environment documents are frozen to the maximum extent possible without
owner decisions and are machine-validated by
`benchplanctl verify --root .` against `schemas/benchmark-*.schema.json`.
**US-008 has not run, has no samples, and does not pass**: the single
remaining blocker class is `HOST_BINDING_PENDING` (owner-gated
confirmation-host and measurement/analyzer tool-identity binding).

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
- No benchmark sample may be collected before the plan is frozen and
  independently attested (see the PRD: "No raw or tuning sample may predate
  the independently attested plan commit"), before the confirmation host and
  every measurement/analyzer tool identity are bound in
  `environments/confirmation.json`, and while the US-008 dependency gates in
  the PRD remain blocked.
- Docker sbx may isolate build/test preparation but must never host a
  measured sample (microVM overhead changes the declared boundary). The
  confirmation host must be bare metal — dedicated tenancy is still a VM.

## Layout

- `plan/workloads.json` — the frozen machine-validated preregistration
  (`schemas/benchmark-plan-1.0.0.schema.json`): six exact workloads with
  fixed rates, concurrency, operations, durations, and deterministic
  input/output generators; the executable SHA-256 seed rule with each
  workload's derived pair order (5 warmup + 30 measured); the frozen
  statistics plan and power model; the per-metric CI thresholds; and the
  schema-pinned forbidden-practices list. No results field exists and the
  schema (`additionalProperties: false`) forbids ever adding one.
- `environments/primary-macos.json` — the primary macOS Apple M4 Pro
  environment with honestly OBSERVED host identity (commands + timestamps
  recorded), preregistered run policy, and OWNER_DECISION_PENDING tool
  identities (`binding_status: UNBOUND`).
- `environments/confirmation.json` — the provenance-distinct dedicated
  Linux x86_64 confirmation host: every host field OWNER_DECISION_PENDING
  or NOT_MEASURED, plus the schema-enforced `required_binding_fields`
  completion meter (`binding_status: UNBOUND` until the owner pins every
  field).
- `runner/run-benchmark.sh` — the SSM-invoked runner stub (schema emission
  only).

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
frozen preregistration above pre-shapes that content. Final plan freeze
still requires the owner's independent attestation of the plan commit.
