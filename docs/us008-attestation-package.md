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
   - **Adding an OPTIONAL field record needs NO schema change**, for a
     name the schema does not already constrain. The base `host_identity`
     subschema declares no named properties and its
     `additionalProperties` is `{"$ref": "#/$defs/fieldRecord"}`, so an
     unconstrained name admits any WELL-FORMED field record — the record
     SHAPE is still enforced: a `host_identity` entry carrying
     `not_a_field_record` failed with 7 failures including `additional
     properties 'not_a_field_record' not allowed`. PROBE: adding
     `scaling_driver`, `smt_state` and `turbo_visibility` to
     `host_identity` and validating against
     `benchmark-environment-1.0.0.schema.json` returned 0 failures
     (control, unmodified document: also 0), and one of the three
     carrying an arbitrary `BOUND` value also returned 0.
     **Correction of record, round 4.** The round-3 wording of this
     sentence — "a well-formed record is already admitted under any
     name" — was too broad and is false as written. The confirmation
     branch DOES declare one named `host_identity` property,
     `observed_architecture`, which adds a status-gated value constraint
     on top of the field-record shape: when `status` is `OBSERVED` or
     `BOUND` it requires `value` and pins it to `x86_64`. Probed all four
     ways against the canonical schema: `BOUND`/`arm64` fails with `at
     '/host_identity/observed_architecture/value': value must be
     'x86_64'`; `BOUND`/`x86_64` returns 0; `BOUND` with no `value` fails
     with `missing property 'value'`; `NOT_MEASURED` returns 0, so the
     constraint really is status-gated. What is demonstrated here is
     therefore limited to previously UNDECLARED names, such as the three
     probed.
   - **Making one MANDATORY — enrolling it on the completion meter —
     DOES need a schema change.** `required_binding_fields` is pinned
     by an EXACT 23-item `const` in the confirmation branch of
     `benchmark-environment-1.0.0.schema.json` (line 81 at this
     commit), so a document may not list a 24th. PROBE: the same document with those three
     paths appended to `required_binding_fields` failed validation with
     `at '/required_binding_fields': 'const' failed`. Extending that
     `const` to 26 entries made the same document validate with 0
     failures, so the `const` is exactly the schema blocker.
   Mandatory enrolment moves SEVEN edit sites across FIVE files in
   lockstep.
   **Correction of record, round 4.** The round-3 revision of this
   sentence listed only the first three below and called them "three
   artifacts in lockstep". That inventory was incomplete: it named three
   of the seven sites, omitting four hard-coded counts that the build
   itself enforces. The list below was produced by EXECUTING the
   enrolment — extending the `const`,
   `CanonicalBindingFields["confirmation"]` and `confirmation.json`
   together and then reading which tests fail — rather than by
   enumerating the sites from memory:
   1. the `required_binding_fields` `const` in the schema's confirmation
      branch (23 entries today);
   2. `CanonicalBindingFields["confirmation"]` in
      `internal/benchplan/validate.go` (23 entries today), at the SAME
      INDEX as the document's list — the meter compares the two
      positionally, so inserting into one and appending to the other
      reported `METER_TAMPERED` even with both at 26 entries;
   3. the `required_binding_fields` list in `confirmation.json`, PLUS the
      three `host_identity` field records themselves, since the meter
      fails a canonical field that has no record;
   4. `internal/benchplan/validate_test.go`, the hard-coded
      `len(CanonicalBindingFields["confirmation"]) != 23`
      (`TestCanonicalBindingFieldListsAreTheFrozenShapes`);
   5. `internal/benchplan/validate_test.go`, the hard-coded
      `confirmationUnbound != 17`
      (`TestVerifyShrunkenMeterIsMeterTampered`);
   6. `internal/benchplan/validate_test.go`, the hard-coded
      `len(report.UnboundFields) != 24`
      (`TestVerifyRealTreeReportsOnlyHostBindingPending`);
   7. `cmd/benchplanctl/main_test.go`, the literal expected line `binding
      completion meter: 24 field(s) unbound`
      (`TestVerifyOnRealTreeExitsHostBindingPending`).
   Items 4–7 are CONDITIONAL on the enrolled records' status, and both
   halves were probed rather than reasoned: enrolling three PENDING
   records moves 23 → 26, 17 → 20 and 24 → 27 and failed all four of
   those tests; enrolling three already-`BOUND` records failed item 4
   only, because the unbound counts do not move. The meter is code+schema
   truth and fails when code and document disagree — PROBE: the 26-entry
   document metered as "declares 26 required binding fields; the
   canonical confirmation list has 23".
   An EIGHTH edit is needed only if the RECORD'S PRESENCE is to be
   schema-enforced rather than only meter-enforced: with the `const`
   extended but the three records absent, the schema returned 0 failures
   and only the meter objected; adding the names to the confirmation
   branch's `host_identity.required` list produced `missing properties
   'scaling_driver', 'smt_state', 'turbo_visibility'`.
   Beyond those, several PROSE counts would go stale without failing any
   test — the meter line at the top of this file,
   `docs/us008-benchmark-pipeline.md`, `benchmarks/README.md`, the
   `cpu_frequency_policy` notes in `confirmation.json`, and the count
   comments in `validate_test.go`. That they are unenforced is itself an
   observation from the probe: the full suite reported exactly the four
   test failures above and nothing else. They are listed for completeness
   and must be updated by hand.
   None of this is done: nothing records, requires, or checks these facts
   today, and the extension is still outstanding.
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
  a sample. Every accepted vector in that sample contains at least one
  non-space rune, and every non-space rune in every one of them is
  printable ASCII (U+0021–U+007E). PROBE: narrowing the schema pattern to
  `[!-~]` — which rejects the Go-valid source `"Ω"` (U+03A9) but matches
  every one of those qualifying runes — left that test AND the whole
  suite at exit 0 (28 ok, 0 FAIL).
  **Correction of record, round 4 (a):** the round-3 wording of the
  preceding sentence said "every accepted vector in it is printable
  ASCII". That is false. Most of those vectors are a NON-ASCII Unicode
  space wrapped around `"x"` — one per `unicode.IsSpace` code point — so
  the vectors themselves are not ASCII at all; it is the QUALIFYING
  non-space rune that is. The distinction is the whole point, since it is
  precisely why the `[!-~]` narrowing survived that test. The corrected
  property is now CHECKED rather than asserted: `assertBothAccept`
  verifies, on every vector it is given, that the vector has at least one
  non-space rune and that every non-space rune in it is printable ASCII.

  The gap is closed by comparing the two ACCEPTED SETS over the whole
  rune domain rather than by adding vectors:
  `TestSchemaAndGoAgreeOnClockSourceForEveryRune` requires
  schema-accepts to equal Go-accepts for all 1,112,064 valid runes
  (every code point except the 2,048 surrogates, which cannot survive
  JSON decoding).
  **Correction of record, round 4 (b):** the round-3 revision of this
  test SAMPLED ITS OWN JOIN. It swept two proxies — the extracted
  pattern and `strings.TrimSpace` — having pinned them against the real
  seams on only 40 witness runes, so a schema constraint rejecting an
  unwitnessed rune left the sweep green while the real schema and the Go
  seam disagreed. That was reproduced before the fix: adding
  `{"not": {"const": "ሴ"}}` (U+1234) to the source subschema left the
  round-3 test AND the whole suite at exit 0, 28 ok, 0 FAIL.
  The proxies are now GONE. Both sides of the sweep are the real seams:
  the schema side compiles the canonical schema with the production
  `compileCanonicalSchema` and reads its verdict through the production
  `validateDecodedValue` — the same two functions
  `ValidateSampleSetDocument` itself calls — applying the whole schema to
  a whole document, and the Go side calls `EnforceRunValidity` directly.
  What is elided is only the per-rune re-read and re-compile of the
  schema FILE, and only because a temporary timing probe measured the
  full `ValidateSampleSetDocument` path at 0.94–1.20 ms per document —
  17–22 minutes over the domain. The sweep as written runs the domain in
  roughly 32 s of wall time on a 14-core host, across
  `runtime.NumCPU()` workers that each hold their own compiled schema and
  decoded document, so nothing mutable is shared; the Go side is not
  stood in for at all, at a measured 39–48 ns per rune. The one remaining
  shortcut — reassigning the source leaf of a decoded document instead of
  re-encoding it per rune — is verified per rune rather than assumed: the
  sweep round-trips each source string through `jsonschema`'s own decoder
  and fails if any rune does not come back identical.
  MUTATIONS, all executed and read: with the U+1234 `not` applied the
  fixed test FAILS, naming `U+1234 'ሴ'` as the single disagreement of
  1,112,064; with the same constraint moved OUT of the source subschema
  into an `allOf`/`not` on `observed_cpu_clock` it also FAILS on
  U+1234, so the sweep catches a constraint anywhere in the schema and
  not merely one in the subschema it used to read; and with `[!-~]`
  applied it FAILS on 1,111,945 of 1,112,064 runes, naming `U+03A9 'Ω'`,
  `U+1234 'ሴ'`, `U+20AC '€'`, `U+65E5 '日'` and `U+1F600 '😀'`. Under
  that last mutation the older differential test still passes, which is
  exactly why the two are kept separate.
  **Correction of record, round 5.** The round-4 revision of this bullet
  claimed the every-rune sweep lifted to every input because a guard
  ruled out "any applicator keyword anywhere on the containment chain
  from the document root down to the source". That claim was false. The
  guard enumerated ROUTES, and review round 5 found a route it did not
  walk: attaching `allOf` to the schema root's existing `then` branch and
  re-descending from there to `source` with a large `maxLength`. Read at
  the seam, that mutation makes the schema reject a 65-character Go-valid
  source — `at '/run_validity_observations/observed_cpu_clock/source':
  maxLength: got 65, want 64` — and REPRODUCED at `fcca87c`, before any
  fix, it left `go test -count=1 ./...` at exit 0 with 28 ok, 3 no-test,
  0 FAIL. That route enumeration was itself the round-4 fix, one round
  old when it fell. Enumerating routes was the wrong shape: there are
  unboundedly many of them, and `maxLength` is invisible to any
  single-rune probe by construction, since every one-rune source has
  length 1.

  **The approach changed rather than the guard deepening.** The property
  that matters — for a source string `s`, schema-accepts(`s`) equals
  Go-accepts(`s`) — is now tested DIRECTLY on strings by
  `TestSchemaAndGoAgreeOnClockSourceForGeneratedStrings`, driving the
  same two real seams (`compileCanonicalSchema` +
  `validateDecodedValue`; `EnforceRunValidity`) over a deterministically
  generated corpus. Length-sensitive constraints, and constraints
  attached under any applicator whatsoever, fall out of it by
  OBSERVATION instead of by anticipation. The corpus is a pure function
  of a PCG seed pair fixed in the source (`0x5553303038524553` /
  `0x5452544553524f54`) and is **201,843** sources: the empty string; a
  dense ladder of seven shapes at every rune length 1–256
  (whitespace-only; all-single-byte-non-space, so byte length equals rune
  length; all-non-space-outside-U+0021–U+007E, so no printable ASCII
  appears anywhere; a single qualifying rune at the start, at the end and
  in the middle of a whitespace run; and a random mix); four shapes at
  each of the long lengths 512,
  1 024, 2 048, 4 096, 8 192, 16 384, 32 768 and 65 536; a 200 000-string
  random battery, one of whose five strata draws from the WHOLE rune
  domain rather than from a curated list; and 18 realistic sources and
  regression witnesses. Those five figures sum to the total exactly:
  1 + 1 792 + 32 + 200 000 + 18 = 201 843. Its **coverage is asserted from the corpus, not assumed**:
  at every rune length 1–256 the test requires at least one Go-ACCEPTED
  source of that rune length, at least one Go-ACCEPTED source of that
  BYTE length, at least one Go-ACCEPTED source of that length carrying no
  printable-ASCII rune at all, and at least one Go-REJECTED source of
  that length — and it fails fast, before the sweep, if any is missing.
  Those four are exactly what make a `maxLength`, a `minLength`, a
  byte-counting length rule and a `[!-~]`-style narrowing impossible to
  hide from it in that range. The JSON round trip is verified per source
  through `jsonschema`'s own decoder, as in the rune sweep. Measured
  across the runs of this round on a 14-core host, it takes **3.75–4.02 s**
  of wall time. Observed on `go1.25.5`: 153,659
  Go-accepted / 48,184 Go-rejected, longest 65,536 runes / 159,936 bytes,
  corpus `sha256 9a6fc6d6…2816e870` — logged on every run, and
  deliberately NOT asserted, because `math/rand/v2` pins the PCG bit
  stream but not the mapping from it to `IntN` across Go releases.

  **The structural checks are kept, and are described as partial.** The
  test still asserts that the clock-source subschema declares exactly
  `description`/`type`/`minLength`/`pattern`, and that the pattern parses
  (with `regexp/syntax` under the same Perl flags `regexp.Compile` uses)
  to a single `OpCharClass` — which is *why* single-rune exhaustion is
  evidence about longer strings, not a proof that it is. The route
  enumeration is GONE, replaced by a whole-document **constraint
  census**: every occurrence, at any pointer in
  `benchmark-raw-sample-1.0.0.schema.json`, of a keyword that can assert
  on a string (`const`, `enum`, `format`, `maxLength`, `minLength`,
  `pattern`, `contentEncoding`, `contentMediaType`, `contentSchema`) or
  compose another subschema onto one (`$ref`, `$dynamicRef`, `allOf`,
  `anyOf`, `oneOf`, `not`, `if`, `then`, `else`, `dependentSchemas`,
  `propertyNames`, `patternProperties`, `unevaluatedProperties`,
  `unevaluatedItems`), frozen as **24 entries** with `$ref` targets
  attached. The census does not care how a constraint is reached, only
  that it exists, so it has no routes to miss. It is complete over
  keyword occurrences ADDED to or REMOVED from this document; it is
  **blind to a change in the VALUE of a keyword already present**, and to
  `$id`/`$anchor`, and to the content of an external resource a `$ref`
  were repointed at (the repoint itself is caught). It is not called
  complete anywhere.

  **Mutations, all executed and read**, against the two legs
  (`gen` = generated-strings leg, `rune` = every-rune leg including the
  structural checks; exit 1 = caught):

  | mutation | `gen` | `rune` | what caught it |
  | --- | --- | --- | --- |
  | round-5 finding: `then.allOf` → `source.maxLength: 64` | 1 | 1 | 31,092 disagreements, first at 65 runes; census `+2` |
  | `anyOf` at root → `source.maxLength: 64` | 1 | 1 | same 31,092; census `+2` |
  | `dependentSchemas` at root → `source.maxLength: 64` | 1 | 1 | same 31,092; census `+2` |
  | round-4 witness: `source.not.const = "ሴ"` (U+1234) | 1 | 1 | 31 disagreements; rune sweep names U+1234 |
  | `source.pattern = "[!-~]"` | 1 | 1 | 49,847 disagreements; rune sweep 1,111,945 of 1,112,064 |
  | `source.pattern` anchored with `^` | 1 | 1 | 51,401 disagreements. The rune SWEEP reports none — single-rune verdicts are identical under an anchor — so the generated leg carries the semantics here and the `OpCharClass` check (`parses to Concat`) is what fails on the rune leg |
  | `source.minLength: 2` | 1 | 1 | 5,535 disagreements at length 1 |
  | `source.maxLength: 65535` | 1 | 1 | 3 disagreements, all at 65,536 runes |
  | `source.maxLength: 65536` | **0** | 1 | **the bound**: the string battery does NOT see it; only the subschema key assertion does |
  | delete the `source` subschema | 1 | 1 | 153,659 disagreements; the rune sweep fails first, on 1,112,039 of 1,112,064, so the census `−2` is never reached |

  The last row is the honest edge of the battery and is stated as a
  residual below rather than smoothed over.

  **THE CLAIM, stated as what is actually proven.** For the clock-source
  string, the canonical raw-sample schema — compiled and read through the
  production `compileCanonicalSchema` and `validateDecodedValue`, the
  same two functions `ValidateSampleSetDocument` calls, applied to a
  whole document — and `internal/benchplan.EnforceRunValidity` return the
  SAME accept/reject verdict on:

  1. every one of the **1,112,064** valid single-rune sources
     (exhaustive over the rune domain; the 2,048 surrogates are excluded
     because they are not valid runes and cannot survive JSON decoding),
     and
  2. all **201,843** sources of the generated corpus described above,
     spanning rune lengths 0–256 densely and 512–65,536 sparsely, with
     the four per-length coverage properties asserted rather than
     assumed, and
  3. the enumerated `unicode.IsSpace` differential vectors of
     `TestSchemaAndGoAgreeOnClockSourceAttribution`, including the empty
     string.

  That is what is established. It is **not** "agreement on every possible
  input", and the earlier wording that said so is withdrawn. Agreement on
  inputs outside those three sets rests on the structural assumptions
  recorded under RESIDUALS below, which are checked but not proved
  exhaustive.

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
  in `internal/benchplan/validate_test.go`, and `DecideEndpoint` has no
  non-test callers at all, so `additionalProperties: false` and the
  clock-source pattern currently constrain fixtures and tests rather than
  incoming data.
  **Correction of record, round 4.** The round-3 wording said
  `EnforceRunValidity` "likewise" has no non-test callers. That is false:
  it has exactly one, `DecideEndpoint` at
  `internal/benchplan/decide.go:308`. The accurate statement is that
  `DecideEndpoint` is `EnforceRunValidity`'s only non-test caller and
  `DecideEndpoint` itself has none, so the cluster is still unreachable
  from any production entry point — which is the conclusion that
  actually matters here, and it survives the correction. Verified by a
  repo-wide search for each of the three symbols across every `.go` file,
  not by reading the package alone. The round-3
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

## RESIDUALS — known limitations carried, not closed

This branch's adversarial review is bounded and stops after round 5. What
follows is every limitation the driver knows of and is deliberately NOT
closing, with the reason. It is written to be read WITHOUT the review
conversation: each item states the limitation, how it was established,
and what would close it. Nothing here is a discovered defect awaiting a
fix; each is a scope edge that a future reader should treat as an open
assumption rather than a proven property.

### R1 — The clock-source agreement claim is bounded, not universal

The two differential legs prove agreement on 1,112,064 single-rune
sources and on 201,843 generated sources up to 65,536 runes. They do not
prove it for every string. Concretely, and MEASURED rather than
estimated: adding `maxLength: 65536` to the source subschema — a
constraint that rejects Go-valid sources of 65,537 runes and longer —
leaves the generated-strings leg at exit 0. It is caught today only
because the subschema's own keyword set is pinned by name, and it would
also be caught by the constraint census (R2). **Closing it** would mean
either an unbounded-length argument the schema does not currently
support, or a symbolic/decision-procedure comparison of the regexp
against `strings.TrimSpace` rather than a battery. Neither is proposed.

### R2 — The constraint census is blind to value changes

`frozenRawSampleConstraintCensus` freezes 24 keyword OCCURRENCES by JSON
pointer (with `$ref` targets attached). It catches any constraint added
anywhere or removed anywhere, which is what defeated the round-4 and
round-5 constructions. It does NOT catch a change to the VALUE of a
keyword already present, nor `$id`/`$anchor` changes, nor the content of
an external resource a `$ref` were repointed at (the repoint itself is
caught, since the target string is part of the entry; today the twelve
`$ref` occurrences carry just two distinct targets, `#/$defs/digest` and
`#/$defs/pair`, both same-document).

The value-change routes that can reach the clock source are exactly the
three keywords on its own subschema. `type` and `minLength` are pinned by
value in the same test. `pattern` is not pinned by value on purpose — it
is what the two sweeps exercise — so a `pattern` edit that keeps a single
`OpCharClass`, agrees with `unicode.IsSpace` on all 1,112,064 runes, and
still disagrees on some longer string is invisible to everything here.
No such pattern is known to exist; the point is that nothing in this
suite rules one out.

### R3 — The lift argument is an argument, not a proof

The chain "both rules are *some rune qualifies*, therefore per-rune
agreement gives per-string agreement" is reasoning, and reasoning of
exactly this shape has now been falsified four times on this branch
(rounds 2, 3, 4 and 5 each found a stated property was not the property
that held). Its premises are checked — subschema key set, `OpCharClass`
parse, whole-document census — but the checks are not a proof that the
premise list is complete. Treat the executed facts (the two sweeps, the
census, the mutation table) as the evidence, and the lift as commentary.

### R4 — The generated corpus is toolchain-deterministic, not universally so

The corpus is a pure function of the two PCG seed constants: no clock, no
address, no environment. It reproduced byte-identically across
consecutive runs (identical corpus line, `sha256 9a6fc6d6…2816e870`).
However `math/rand/v2` guarantees the PCG bit stream, not the mapping
from that stream to `IntN` results across Go releases, so a future
toolchain may produce a different corpus. The digest is therefore LOGGED
and not asserted. Nothing the test proves depends on that stability: the
four per-length coverage properties are recomputed from whatever corpus
is generated, on every run, and the test fails if they do not hold.

### R5 — `pattern` semantics rest on the validator's regexp engine

The `OpCharClass` parse characterises what the validator ran only because
`santhosh-tekuri/jsonschema/v6` defaults its engine to `goRegexpCompile`
= `regexp.Compile` (`roots.go:25`, `compiler.go:330` at v6.0.3) and
`UseRegexpEngine` is never called in this repository — verified by
repo-wide search over every `.go` file, whose single hit is the
explanatory comment in `validate_test.go` that says so, with no call
site. A dependency bump that changed the default engine, or
a future call to `UseRegexpEngine`, would silently invalidate that
characterisation. Neither is pinned by a test.

### R6 — `DecideEndpoint` has no non-test caller

Carried forward unchanged from round 3, where the independent reviewer
ruled it does not block a preregistration-only change but MUST block any
future runner or ingestion acceptance. The observed-clock rule is
IMPLEMENTED in `DecideEndpoint`; nothing in production calls
`DecideEndpoint` yet, so no measured sample is actually gated by it
today. See the driver follow-up above; repeated here so the residuals
list is self-contained.

### R7 — The record-only tripwire is partial by disclosure

`TestObservedClockAppliesNoThreshold` covers four vectors and cannot
catch a threshold that admits all four, nor one added at a different
seam. Already disclosed in the body above with the mutation that proves
it (an unattested threshold rejecting only the unvisited 2,000–2,500 MHz
band leaves it passing). The record-only property rests on the frozen
preregistration and on review, not on that test.

### R8 — The census makes legitimate schema evolution loud

By design: any future edit to `benchmark-raw-sample-1.0.0.schema.json`
that adds or removes a censused keyword fails
`TestSchemaAndGoAgreeOnClockSourceForEveryRune` until
`frozenRawSampleConstraintCensus` is updated. That is the intended
behaviour of a preregistration freeze, and the failure message names the
exact added and removed pointers, but a future editor should expect it
rather than read it as a defect.

### R9 — Test cost

The two differential legs cost roughly 24 s and 4 s of wall time on a
14-core host, and scale with `runtime.NumCPU()`. On a low-core CI runner
the package's test time will be substantially higher. No timeout tuning
has been done.

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
