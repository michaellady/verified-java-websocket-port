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
5. **Booted-host facts that HAVE a field, holding a `NOT_MEASURED`
   sentinel until the first bound boot**: `instance_id`,
   `observed_architecture` (schema-pinned to `x86_64`),
   `availability_zone`, `os_identity`, `kernel_identity`, `cpu_model`,
   `memory_total_bytes`, `numa_topology`, `clocksource`. These nine are
   exactly the `NOT_MEASURED` entries of `host_identity` in
   `confirmation.json`, and all nine sit on the completion meter, so
   `benchplanctl verify` counts them as unbound today.
6. **Default-scaling facts that have NO field at all** — the facts the
   bound CPU-frequency policy defers to provision: cpufreq
   driver/governor presence or absence, turbo/boost visibility, SMT
   state. These are a DIFFERENT category from item 5 and are listed
   separately for that reason. An earlier revision of this list grouped
   them under item 5's "`NOT_MEASURED` until the first bound boot"
   heading, which wrongly implied a field exists and is merely empty.
   It does not: no field exists for any of them in `confirmation.json`,
   so they are UNRECORDED and UNREPRESENTED, not unmeasured. Only
   `cpu_model`'s notes gesture at them ("base/turbo policy"), and
   `cpu_frequency_policy` is `BOUND` — it binds the POLICY and asserts
   no fact about the booted host, so it is not a sentinel either.
   OUTSTANDING EXTENSION. Whether it needs a schema change is
   CONDITIONAL on what is being added, and both halves of the condition
   were probed against the canonical schema:
   - **Adding an OPTIONAL field record needs NO schema change.**
     `host_identity` declares no named properties and its
     `additionalProperties` is `{"$ref": "#/$defs/fieldRecord"}`, so a
     well-formed record is already admitted under any name. PROBE:
     adding `scaling_driver`, `smt_state` and `turbo_visibility` to
     `host_identity` and validating against
     `benchmark-environment-1.0.0.schema.json` returned 0 failures
     (control, unmodified document: also 0).
   - **Making one MANDATORY — enrolling it on the completion meter —
     DOES need a schema change.** `required_binding_fields` is pinned
     by an EXACT 23-item `const` in the confirmation branch of
     `benchmark-environment-1.0.0.schema.json` (line 81 at this
     commit), so a document may not list a 24th. PROBE: the same document with those three
     paths appended to `required_binding_fields` failed validation with
     `at '/required_binding_fields': 'const' failed`. Extending that
     `const` to 26 entries made the same document validate with 0
     failures, so the `const` is exactly the schema blocker.
   Mandatory enrolment therefore moves three artifacts in lockstep: the
   `required_binding_fields` `const` in the schema,
   `CanonicalBindingFields["confirmation"]` in
   `internal/benchplan/validate.go` (23 entries today), and the
   `required_binding_fields` list in `confirmation.json`. The meter is
   code+schema truth and fails when they disagree — PROBE: the
   26-entry document metered as "declares 26 required binding fields;
   the canonical confirmation list has 23". A fourth edit is needed only
   if the RECORD'S PRESENCE is to be schema-enforced rather than only
   meter-enforced: with the `const` extended but the three records
   absent, the schema returned 0 failures and only the meter objected;
   adding the names to the confirmation branch's `host_identity.required`
   list produced `missing properties 'scaling_driver', 'smt_state',
   'turbo_visibility'`. None of this is done: nothing records, requires,
   or checks these facts today, and the extension is still outstanding.
   **Correction of record, round 3.** Both earlier framings of this
   sentence were wrong in opposite directions and are superseded by the
   conditional above. The round-1 note in `confirmation.json` said
   representing these facts "requires adding fields to
   `benchmark-environment-1.0.0.schema.json`" — false for optional
   records. The round-2 revision said the extension "is the METER rather
   than the schema" and that "the schema needs no change" — false for
   mandatory metering, which is the case actually contemplated here,
   because of the 23-item `const`.
7. **Primary runtime-snapshot fields** (`PENDING_FREEZE_AT_MEASUREMENT`,
   frozen per-run by their recorded procedures, not before):
   `power_source_state`, `low_power_mode_state`,
   `thermal_pressure_state`, `background_process_census`,
   `clock_sync_state`.
8. **Tier-2 (`METAL_MEASURED`) — only if a flagship run is ever
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
  **Correction:** the round-1 revision of that differential test did not
  support the "whole `unicode.IsSpace` set" claim made for it. It drove
  itself from 17 literal strings covering only 15 of the set's 25 code
  points, silently omitting ten members of U+2000–U+200A. That was not a
  theoretical gap: narrowing the schema pattern to exactly the 15
  exercised code points — a pattern that genuinely disagrees with Go on
  the other ten — left the test PASSING (exit 0). The test now derives
  its vectors by ENUMERATING `unicode.IsSpace` over `0..unicode.MaxRune`
  from Go's own tables instead of from a hand-written list, so no member
  can be omitted and the set cannot drift as the standard library is
  updated. It runs 60 subtests over the 25 enumerated code points in
  both directions (each alone must be rejected by both seams; each
  wrapped around a non-whitespace character must be accepted by both),
  plus whitespace-only composites and realistic attributed sources, and
  it checks its own derivation so a collapsed enumeration cannot render
  it vacuous. Re-running the same narrowing mutation against the fixed
  test now FAILS on exactly the ten previously-omitted code points
  (U+2000–U+2002, U+2004–U+200A) plus the all-code-points composite,
  reporting `schema rejected=false go rejected=true`.
  **Third correction (round 3):** "the claim and the coverage now match"
  was still an overstatement, in the half the round-2 fix did not touch.
  Enumeration made the REJECTED side exhaustive; the ACCEPTED side stayed
  a sample, and every accepted vector in it is printable ASCII. PROBE:
  narrowing the schema pattern to `[!-~]` — which rejects the Go-valid
  source `"Ω"` (U+03A9) — left that test AND the whole suite at exit 0
  (28 ok, 0 FAIL). The gap is now closed by comparing the two ACCEPTED
  SETS exhaustively rather than by adding vectors:
  `TestSchemaClockSourcePatternEqualsGoOnEveryRune` extracts the pattern
  from the canonical schema by JSON path, compiles it with the validator's
  own regexp engine, and requires schema-accepts to equal Go-accepts for
  all 1,112,064 valid runes (every code point except the 2,048
  surrogates, which cannot survive JSON decoding). Two proxies make that
  sweep affordable — the extracted pattern for the schema, and
  `strings.TrimSpace` for the Go seam — so the test first pins each proxy
  against its REAL seam (`ValidateSampleSetDocument` and
  `EnforceRunValidity`) on 40 witness runes and refuses to run the sweep
  if either proxy disagrees. Per-rune exhaustion is equivalent to
  every-input agreement here because both rules are "some rune qualifies"
  over a per-rune predicate: the pattern is a single unanchored character
  class, and `TrimSpace` empties a string only if every rune is a space.
  MUTATION: with `[!-~]` applied, the new test FAILS, reporting
  disagreement on 1,111,945 of 1,112,064 runes with the non-ASCII
  witnesses `U+03A9 'Ω'`, `U+20AC '€'`, `U+65E5 '日'`, `U+1F600 '😀'`
  named in the failure; the older differential test still passes, which is
  exactly why the two are separate. The claim in that older test's comment
  is now scoped to what it actually covers.

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
  simply false. **Second correction:** the round-1 wording that replaced
  it was itself inaccurate. It said this worktree "tracked 63 `.rs`
  files totalling roughly 22,350 lines of Rust production code," which
  mixed two different scopes and counted test code as production. The
  whole tree tracks 64 `.rs` files, not 63; 63 is the count under
  `rust/`. And 22,350 is `rust/`'s TOTAL line count, of which a
  majority is not production. The verified figures, identical at
  `85366c4` and at this commit because no `.rs` file changed between
  them:
  - tracked `.rs`, whole tree: **64 files, 22,359 lines**.
  - tracked `.rs` under `rust/`: **63 files, 22,350 lines**. The 64th is
    outside `rust/` —
    `assurance/replay/fixtures/us006-standin/production-connection-state-machine.rs`,
    9 lines, a replay fixture rather than a crate.
  - within `rust/`: Cargo integration tests (`*/tests/*`) are 25 files /
    9,638 lines; gate canaries (`rust/gates/canaries/`) are 2 files / 48
    lines; inline `#[cfg(test)]` modules inside `src/` files are a
    further 2,269 lines across 12 files.
  - so **11,955 lines are test or canary code and 10,395 lines are
    production Rust** — not 22,350.

  Counting rule, stated so the figures are auditable rather than
  asserted: lines are `wc -l` lines over `git ls-files '*.rs'`; a file
  is test code if it has a `/tests/` path segment or sits under
  `rust/gates/canaries/`; inside every other file, lines within
  `#[cfg(test)]` items are test code. The inline figure was measured by
  brace-matching with a Rust-aware lexer and independently cross-checked
  against a naive first-`#[cfg(test)]`-to-EOF count; both give 2,269.

  None of the argument rests on those counts, and the part that does is
  unchanged: Rust source predates this commit. The earliest tracked
  `.rs` landed at `d9211f8` (2026-08-26T15:37:07Z), and
  `rust/ws-core/src/lib.rs` reached that path at `9fe68ff`
  (2026-08-27T03:29:19Z) via the crate rename; both are ancestors of
  this commit, confirmed with `git merge-base --is-ancestor`. (The
  round-1 correction dated `9fe68ff` "2026-08-26"; that was the
  committer's local date — in UTC it is 2026-08-27.) What is genuinely
  true, and all that was ever needed, is that no MEASURED sample of any
  kind exists yet and the measurement runner is still an unbound stub.
  The runner that POPULATES the slot still binds with the measurement
  runner identity.
- **Wire the raw-sample schema into the ingestion path before any
  measured run is accepted.** The canonical raw-sample schema is not
  runtime defense today: every `ValidateSampleSetDocument` caller lives
  in `internal/benchplan/validate_test.go`, and `DecideEndpoint` and
  `EnforceRunValidity` likewise have no non-test production callers, so
  `additionalProperties: false` and the clock-source pattern currently
  constrain fixtures and tests rather than incoming data. The round-3
  independent reviewer was asked to rule on whether this blocks and ruled
  that it does NOT block a preregistration-only change, because no
  production measurement path exists yet — but that it MUST block any
  future runner or ingestion acceptance. Recorded here so that gate is
  not lost when the runner is built.
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
   This covers item 5 ONLY. The item-6 default-scaling facts are not on
   the meter and have no field, so provisioning does not record them and
   step 4 will not report them as missing.
4. Verify `benchplanctl verify --root .` reports zero unbound fields.
5. Set both environments `binding_status: BOUND` and attest
   independently (`attestation_state: INDEPENDENTLY_ATTESTED`) — at
   which point `benchplanctl verify` exits 0 and the no-sample gate
   lifts (subject to the PRD's other US-008 dependency gates). The plan
   freeze itself is DONE (owner-attested 2026-08-27, digest-bound); the
   independent attestation is the part that remains, and it is neither
   performed nor claimed by any driver round.
