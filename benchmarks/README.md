# benchmarks/ — US-008 preregistration skeletons (enabling work)

This directory holds the **preregistration skeletons** for the US-008
controlled Java/Rust resource benchmarks and the pipeline runner stub. It is
enabling work: **US-008 has not run, has no samples, and does not pass.**

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

- `plan/workloads.json` — machine-readable preregistration of the six PRD
  workloads, the pairing/seeding rules, the frozen statistics plan, and the
  CI thresholds. No results fields exist here, by design.
- `environments/confirmation.json` — binding-field skeleton for the
  provenance-distinct dedicated Linux x86_64 confirmation host
  (`binding_status: UNBOUND` until the owner pins every field).
- `environments/primary-macos.json` — binding-field skeleton for the primary
  macOS Apple M4 Pro environment.
- `runner/run-benchmark.sh` — the SSM-invoked runner stub (schema emission
  only).

The PRD's canonical US-008 file set (`benchmarks/plan.json`,
`benchmarks/workloads/`, `benchmarks/analysis-contract.json`,
`benchmarks/analyzer/`) is produced when US-008 itself is executed; these
skeletons pre-shape that content without claiming any of it is frozen.
