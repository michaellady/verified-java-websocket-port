# US-026 disposable cutover-rehearsal contract

## Claim boundary

US-026 may complete only the deterministic rehearsal mechanics authorized by
the owner. The maximum result is:

```text
mechanics_status: PASS_OWNER_RELAXED_REHEARSAL_MECHANICS
cutover_acceptance: CUTOVER_BLOCKED
assurance: OWNER_ATTESTED_NOT_INDEPENDENT
independent_review_claimed: false
production_shaped_environment: NOT_BOUND
live_traffic_executed: false
live_side_effects_executed: false
CUTOVER_READY: UNREACHABLE
```

This result proves that fixed fixtures exercise the declared state machine,
shadow/canary decisions, mismatch abort, Java selection, reconciliation,
rollback accounting, and finite soak ticks. It does not prove a live or
production-shaped rehearsal, measured capacity/resources, wall-clock soak or
rollback, real side-effect isolation, deployment readiness, or permission to
remove Java.

## Shipped result

US-026 completed its owner-relaxed rehearsal mechanics at evaluator/tooling
head `69bc2f40456083a30ca2cc2faa87acf1d2585338` and tree
`c351fdc92d3c851fd3a001552eeb0d52d06b61e4`. The immutable rehearsed port
subject remains commit `84935acb5665ed50bd5eb718e918ed19adfcc646` and tree
`838fd4f551312447af3be1958916a1c5c2b5c885`. The result is exactly
`PASS_OWNER_RELAXED_REHEARSAL_MECHANICS/CUTOVER_BLOCKED` under
`OWNER_ATTESTED_NOT_INDEPENDENT` with `independent_review_claimed:false`.

The deterministic fixture records 32 shadow comparisons, two Rust canary
selections, one retained mismatch, three simulated rollback actions, 32
synthetic soak ticks, 15 reconciled fixture effects, and one duplicate effect
suppressed. It executes no live traffic, process, socket, clock, sleep, real
side effect, deployment, publication, signing, or Java removal.

The six write-once result artifacts are:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `cutover/contract.json` | 10,782 | `sha256:ea342692911c716769bd3436523fd6aa08334137bdf21c66c364eb00831164fa` |
| `cutover/shadow.json` | 23,552 | `sha256:c673f2630335381a7a7b8a3ccebbb2837826434b3066d94b98c1c6d747ca4257` |
| `cutover/canary.json` | 30,215 | `sha256:52a48575396d531ede45d7407ed790c07840fcff1fcf3a7eaab548c8d1864d37` |
| `cutover/rollback.json` | 10,303 | `sha256:d6c64c90c6e52af2b2556ce55d45b90974abf7207012005f2ad0247674c780f2` |
| `cutover/soak.json` | 15,002 | `sha256:5bdabb03e4be225b1171e9e9357fcf5a0f28660dfc180a1ca536455f2ca7fb87` |
| `evidence/cutover.json` | 2,688 | `sha256:89a6eed774d4f7fd6146d6e5d04390e282e9f792f3bf0bff192e8eec31f79af1` |

Acceptance and security testing found and closed five blocking defects before
the sole full review:

```text
B001 mismatch artifacts contradicted the retained changed Rust digest
B002 symlinked repository-root ancestors were accepted
B003 Java fallback identity pointed at the candidate manifest instead of Java intake/source identity
B004 capture repaired a partial six-artifact bundle instead of rejecting it
B005 rename publication could replace a concurrently created artifact
```

The one full comments-only review then found zero blockers, retained two
important findings, and retained one wording nit. The important findings are
that semantic validation maps many frozen invariants to generic
`ARTIFACT_DRIFT`, and hostile-test coverage is representative rather than
exhaustive. The nit observed that this contract described bundle-atomic rename
while the shipped writer uses no-replace hard-link publication under an
exclusive lock.

This post-ship documentation pass corrects only that publication wording. The
correction is doc-only: no code, test, schema, evidence, artifact digest, claim,
review result, or assurance state changes, and the historical one-nit review
record remains retained.

Focused QA, race, vet, and build checks passed. Broad failures were unrelated
historical binding drift and sandbox-denied loopback tests. Reality validation
used a clean clone at the exact shipped head/tree, ran 17 focused tests,
captured the six artifacts twice with byte-identical output, ran the real
verifier, and removed its disposable checkout.

The 12 blockers and seven nonclaims in the final retained section remain
authoritative. `CUTOVER_READY` remains unreachable.

## Incumbent contracts and immutable subject

The implementation extends the incumbent cutover vocabulary; it must not
create a second release model.

- `evidence/intake/cutover-contract.json` is the canonical US-003 boundary and
  readiness ladder. Its RFC 6455 boundary, exclusions, obligations, and
  owner-only assurance remain unchanged.
- `schemas/cutover-contract-1.0.0.schema.json` remains the schema for that
  intake contract. US-026 references its exact digest; it does not reinterpret
  or overwrite it.
- `assurance/candidate-manifest.json`, the US-023 snapshot evidence, the US-024
  refinement receipt, and the US-025 sample-free performance receipt are
  identity inputs. Their blocked/nonclaim states remain inputs too.
- `assurance/developer-tools/cutover-contract.json` is a synthetic developer
  fixture, not authoritative evidence. Its invented passing performance values
  must never feed US-026.

The rehearsed port subject is Git commit
`84935acb5665ed50bd5eb718e918ed19adfcc646`, tree
`838fd4f551312447af3be1958916a1c5c2b5c885`. It is the last code/evidence head
before post-ship documentation. US-026 tooling is the evaluator, not part of
the subject it evaluates.

All input paths are fixed repository-relative names. The verifier resolves
them from a canonical Git tree or through a held repository root, rejects
symlink/nonregular substitutions, hashes the bytes it actually validates, and
requires the committed result artifacts to bind those qualified digests.

## Selected architecture

Add a dependency-free Go package `internal/cutover` and a thin
`cmd/cutoverctl`. The package is a pure deterministic fixture evaluator. It
opens no socket, starts no process, sleeps for no duration, reads no clock,
touches no external service, and performs no real side effect.

`cutoverctl capture --root DIR` evaluates two embedded canonical fixture runs
and publishes the six PRD artifacts as one write-once bundle. `cutoverctl
verify --root DIR` rederives them from the immutable inputs, byte-compares every
artifact, checks all cross-digests, and exits nonzero on drift. Capture uses an
adjacent exclusive lock, secure temporary files, file sync, no-replace hard
links, and parent-directory sync. A concurrent destination appearance fails,
and any existing partial bundle is rejected rather than repaired or completed.

### Two fixture runs

The canonical input contains 16 ordered requests. Request IDs and idempotency
keys are unique except for one declared duplicate retry. The fixed canary rule
routes exactly two first-attempt keys to Rust by a frozen SHA-256 projection;
all other requests route to Java. No optional stopping, rerouting, or fixture
extension is permitted.

The nominal run proves mechanics only:

1. shadow evaluates Java and Rust semantic-result fixture digests for all 16
   requests;
2. both effect projections are isolated and therefore commit zero effects;
3. the fixed canary routes exactly two requests to Rust;
4. the duplicate idempotency key produces one authoritative fixture effect;
5. 32 deterministic soak ticks preserve the declared queue/error/backpressure
   fixture bounds; and
6. the run terminates at `REHEARSAL_MECHANICS_COMPLETE/CUTOVER_BLOCKED`.

The seeded-mismatch run changes exactly one Rust semantic result on the first
Rust-routed request. It must:

1. record the failed Rust attempt before changing route state;
2. abort canary immediately with typed reason `SEMANTIC_MISMATCH`;
3. route that request and all subsequent requests to the Java fallback;
4. commit no isolated Rust effect;
5. deduplicate the retry by idempotency key;
6. reconcile the authoritative Java fixture-effect multiset exactly, with zero
   missing, extra, or duplicate effects; and
7. finish at `FALLBACK_RECONCILED/CUTOVER_BLOCKED` without entering soak.

Resource fixture fields are comparison inputs labeled
`SYNTHETIC_FIXTURE_NOT_A_MEASUREMENT`. They may trigger a simulated abort but
cannot satisfy or contradict US-025 thresholds.

## Non-skippable state machines

The nominal trace must be exactly:

```text
SOURCE_QUALIFIED
SNAPSHOT_BOUND
FIXTURE_READY
SHADOW_VERIFIED_FIXTURE
CANARY_VERIFIED_FIXTURE
SOAK_VERIFIED_FIXTURE
REHEARSAL_MECHANICS_COMPLETE
CUTOVER_BLOCKED
```

The mismatch trace must be exactly:

```text
SOURCE_QUALIFIED
SNAPSHOT_BOUND
FIXTURE_READY
SHADOW_VERIFIED_FIXTURE
CANARY_ABORTED_FIXTURE
JAVA_FALLBACK_SELECTED_FIXTURE
FALLBACK_RECONCILED_FIXTURE
CUTOVER_BLOCKED
```

Transitions are a closed adjacency table. Missing, duplicated, reordered,
unknown, repeated-terminal, or skipped states block. The evaluator has no
transition to canonical `CUTOVER_READY`; that state is reserved for a future
separately authorized production-shaped and independently attested decision.

Rollback is recorded as exactly three simulated deterministic actions
(`abort`, `select-java`, `reconcile`). It is not elapsed time. Soak is exactly
32 fixture ticks and contains no timestamps or duration claim.

## Artifact model

The six requested files have distinct, closed schemas:

```text
cutover/contract.json   vjwp-cutover-rehearsal-contract/1.0.0
cutover/shadow.json     vjwp-cutover-phase-receipt/1.0.0
cutover/canary.json     vjwp-cutover-phase-receipt/1.0.0
cutover/rollback.json   vjwp-cutover-phase-receipt/1.0.0
cutover/soak.json       vjwp-cutover-phase-receipt/1.0.0
evidence/cutover.json   vjwp-cutover-evidence/1.0.0
```

`contract.json` binds the immutable subject commit/tree; canonical intake
contract, candidate, refinement, and performance receipt digests; fixture
digest; Java fallback identity fact; Rust subject identity; fixed route rule;
effect policy; exact state tables; exact counts; and all claim ceilings.

The Java fallback fact is honest: it binds retained Java source/build-input
identity and the fixture route target, while recording
`java_fallback_executable_drilled:false`. A source/build-input identity cannot
be promoted to a rebuilt or executed fallback binary.

Each phase receipt binds the contract digest, fixture digest, subject, run ID,
ordered states, selected request IDs, semantic/effect/resource comparison
facts, typed outcome, and zero real-side-effect/traffic flags. `rollback.json`
contains the preserved failed attempt and exact reconciliation multiset.
`soak.json` contains the 32 tick records for the nominal run and an explicit
`NOT_ENTERED_ABORTED_CANARY` result for the mismatch run.

`evidence/cutover.json` binds all five cutover artifact byte digests and may
claim only `PASS_OWNER_RELAXED_REHEARSAL_MECHANICS/CUTOVER_BLOCKED`. Review,
QA, and reality provenance remains `NOT_EXECUTED` in the repository receipt;
executed phase provenance belongs in HQ orchestration state and is not
self-asserted by the producer.

## Typed failure codes

At minimum the evaluator fails closed with:

```text
INPUT_ABSENT
INPUT_SYMLINK_OR_NONREGULAR
INPUT_DIGEST_MISMATCH
SUBJECT_MISMATCH
CONTRACT_MISMATCH
FIXTURE_MISMATCH
STATE_SKIP_OR_REORDER
ROUTE_COUNT_MISMATCH
SHADOW_SEMANTIC_MISMATCH
UNEXPECTED_REAL_EFFECT
CANARY_NOT_ABORTED
FAILED_ATTEMPT_NOT_RETAINED
JAVA_FALLBACK_NOT_SELECTED
IDEMPOTENCY_DUPLICATE_EFFECT
RECONCILIATION_MISSING_EFFECT
RECONCILIATION_EXTRA_EFFECT
ROLLBACK_STEP_MISMATCH
SOAK_TICK_MISMATCH
RESOURCE_FIXTURE_PROMOTED
CUTOVER_READY_FORBIDDEN
ARTIFACT_DRIFT
```

Aggregate success cannot hide one request, effect, state, or tick failure.

## Hostile acceptance tests

Tests construct data in temporary directories and never touch external state.
Required cases include:

1. exact nominal and mismatch traces;
2. every skipped/reordered/duplicated/unknown state and forged
   `CUTOVER_READY`;
3. wrong subject/tree/intake/candidate/refinement/performance/fixture/fallback
   identity, including zero/malformed digests;
4. missing, extra, duplicated, or reordered requests, canary selections,
   attempts, effects, rollback actions, and soak ticks;
5. mismatches before and after the declared abort point;
6. canary continuation after abort and failure to preserve the failed attempt;
7. Java fallback not selected or selected before abort;
8. duplicated retry effect, missing authoritative effect, extra isolated Rust
   effect, and reordered reconciliation;
9. 0/1/31/32/33 soak ticks and mismatch run incorrectly entering soak;
10. resource fixture relabeled as measured evidence;
11. stale/altered result artifact, wrong cross-digest, trailing/unknown JSON,
    duplicate keys, and nonfinite values; and
12. symlinked root/ancestor/final artifact, concurrent capture ownership,
    partial write, and stranded lock.

## Primitive Test and file plan

The state machine, digest/cross-file validation, deterministic routing,
idempotency/effect reconciliation, and exclusive artifact transaction pass
Atomicity, Bitter Lesson, and ZFC; they belong in Go. Authorization of live
traffic, production effects, capacity, soak duration, deployment, and Java
removal fails the test and stays in the owner/prompt layer.

Implementation may add only:

```text
internal/cutover/rehearsal.go
internal/cutover/rehearsal_test.go
internal/cutover/artifacts.go
internal/cutover/artifacts_test.go
cmd/cutoverctl/main.go
cmd/cutoverctl/main_test.go
schemas/cutover-rehearsal-contract-1.0.0.schema.json
schemas/cutover-phase-receipt-1.0.0.schema.json
schemas/cutover-evidence-1.0.0.schema.json
cutover/contract.json
cutover/shadow.json
cutover/canary.json
cutover/rollback.json
cutover/soak.json
evidence/cutover.json
```

Any blocking need for another path requires explicit scope expansion before
editing. The incumbent intake contract/schema and candidate/refinement/
performance evidence are read-only inputs.

## Review, QA, and reality

Run one complete comments-only review of the fixed implementation diff. Fix
only blocking correctness/security findings, allow the same reviewer one
targeted closure, and stop. Retain important findings and nits without another
full review.

QA runs focused tests/race/vet/build, then broad Go gates once and classifies
retained unrelated failures. Reality uses a disposable clean checkout at the
exact head/tree, rederives byte-identical artifacts twice, runs real
`cutoverctl verify`, proves no socket/process/clock/sleep/external-effect path
exists, and deletes only its exact temporary directory.

## Owner-relaxed done criteria and retained nonclaims

Mechanics complete only when the exact immutable inputs and fixture are bound;
both traces match their closed state tables; shadow effects remain isolated;
the fixed two-request canary works; mismatch abort/fallback/reconciliation and
idempotency are exact; rollback has three simulated actions; nominal soak has
32 deterministic ticks; forged `CUTOVER_READY` is unreachable; artifacts
rederive byte-identically; one bounded review has no open blocker; and QA plus
fresh reality pass.

The following remain blocking:

```text
PRODUCTION_SHAPED_ENVIRONMENT_NOT_BOUND
LIVE_SHADOW_NOT_EXECUTED
LIVE_CANARY_NOT_EXECUTED
REAL_SIDE_EFFECT_ISOLATION_NOT_EXECUTED
US025_MEASURED_CAPACITY_NOT_ACCEPTED
REAL_RESOURCE_MONITORING_NOT_EXECUTED
WALL_CLOCK_SOAK_NOT_EXECUTED
REAL_JAVA_FALLBACK_BINARY_NOT_REBUILT_OR_DRILLED
REAL_ROLLBACK_BOUND_NOT_MEASURED
INDEPENDENT_ATTESTATION_NOT_EXECUTED
PRODUCTION_DEPLOYMENT_NOT_AUTHORIZED
JAVA_REMOVAL_NOT_AUTHORIZED
```

The exact retained nonclaims are:

```text
no production-shaped rehearsal
no live traffic or effects
no measured capacity or resources
no elapsed soak or rollback bound
no executable Java fallback drill
no CUTOVER_READY or deployment readiness
no production mutation, publication, signing, or Java removal
```

## Provenance and attribution

Architecture was completed directly by the Codex root after two delegated
architecture attempts were interrupted for deepening unavailable prerequisites
without producing the bounded one-file deliverable. Provider/model are OpenAI
`gpt-5.6-sol`, xhigh reasoning, branch `codex/race-catchup`, start head
`f2c63cc56b5b3d3ce922bb84b6f947771e9c04ae`. No new Claude US-026 design or
code was inspected or borrowed.
