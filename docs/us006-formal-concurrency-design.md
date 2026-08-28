# US-006 implementation-linked formal and concurrency design

Status: implementation-ready design only. No proof backend, TLA+ model checker,
Loom run, Kani run, Docker sbx command, Autobahn run, production action,
publication action, or protected-evidence read was performed for this design.

Assurance is `OWNER_ATTESTED_NOT_INDEPENDENT` and
`independent_review_claimed` is `false`. The worktree base
`c6dd294aa3f82bd5be8151f2c41e87e1f8a580c3` and every inherited file are
`BORROWED_FROM_CLAUDE_MAINLINE`; this document does not claim independent
authorship or review of those files.

## Decision and completion boundary

US-006 will add one read-only formal-preflight module behind the existing
`assurectl` interface. It snapshots the four canonical inputs once, strictly
decodes the JSON inputs, checks the TLA+ module shape, validates all digests and
cross-links, applies the fixed claim ceiling, and emits a deterministic
verdict. It never invokes a proof tool or Docker. Proof-tool execution remains
behind the protected US-007 operator and reaches the candidate repository only
as a classifier-approved, digest-bound receipt.

The design freezes two future production identities and does not pretend they
exist today:

| Target | Required future fully-qualified Rust symbol | Planned file | Current state |
| --- | --- | --- | --- |
| mask | `websocket_core::frame::mask::apply_mask_in_place` | `crates/websocket-core/src/frame/mask.rs` | `UNRESOLVED_FUTURE_PRODUCTION_SYMBOL` |
| frame header | `websocket_core::frame::decode::FrameHeaderDecoder::decode_header` | `crates/websocket-core/src/frame/decode.rs` | `UNRESOLVED_FUTURE_PRODUCTION_SYMBOL` |

The current inherited scaffold is at `rust/connection-core/src/framing.rs` and
exports nothing. Its digest at the design base is
`sha256:c3d3201a1c15d5cf632ba940630e887b766411335a534d2d8165c0635b1423b8`.
It is evidence that no target is implemented, not a production linkage. US-009
may relocate the crate as already disclosed by `docs/rust-workspace.md`; if it
does, US-009/US-012 must either preserve the two fully-qualified identities or
make an explicit reviewed update to `proof-targets.json` before any backend
result can attach. A validator never guesses a renamed item.

US-006 is complete when the four artifacts, their three new JSON schemas, the
read-only validator, CLI wiring, and fixture matrix pass. It fixes the plan and
claim ceiling. It does not establish a Rust property before US-012/US-017 ship
and execute the linked symbols.

## Borrowed foundations and exact scope

The plan consumes the following attributed inherited inputs:

| Input | Design-base digest | Permitted use |
| --- | --- | --- |
| `evidence/intake/port-seam-dossier.json` | `sha256:34e260b2e6a47d6f24ee0ba0c2d17eb98098370e7e43680adb040e736d474f2e` | US-012 and US-017 seam and evidence-obligation inventory |
| `evidence/intake/compatibility-surface.json` | `sha256:b9c7107e810a80dd6a3ca0f91fb5bab2c4fd8256fd5d849bc5932f5cf4d80cb0` | `surface.framing.masking` and `surface.concurrency.command-order` |
| `evidence/intake/cutover-contract.json` | `sha256:ea6d6148dd67b705e74db48056dd5f17f22626fda48d148aef01f37de2d46f76` | US-010 client-handshake cutover remains declared without promoted evidence; US-012/US-017 formal targets remain declared and unsatisfied |
| `evidence/corpus-calibration.json` | `sha256:810a2b22fd3211d34d535d4babc9bcd2090eeea492ad64161f9e1a8c4880731d` | borrowed corpus contract and its explicit pending-live ceiling |
| `corpora/public/manifest.json` | `sha256:3798bb112f3c9807d70aff22539fe10e3f7e0b25db6f1dae68b370799e14c642` | public scenario count and artifact binding only |
| `corpora/public/scenarios.jsonl` | `sha256:fe1735bc42c11f66afe2965a7449fc6cad31cca3e2048305388241c781501e5f` | future conformance/differential input; not executed here |
| `assurance/evidence-model.json` | `sha256:8202a03d9a0eddcd2d57df366f501fc99dc79177cfe7c1eaf9549e0d6e6e368f` | inherited evidence vocabulary and lifecycle integration |

The accepted development-sandbox foundation is Claude's retained US-007
attempt, and must be represented as borrowed operational isolation rather than
new US-006 proof:

- classifier-approved summary: `evidence/security-validation.json`, digest
  `sha256:147f6fc2c29762dbf4e5035daefbe3edeecc224dfcb90d9fbf4f1734f857c36b`;
- public live evidence: `evidence/sbx-validation.json`, digest
  `sha256:ba746b0411cfe4759ee90460106ccc33f47992a5c72c13500f9022e5ce823be2`;
- attempt `us007-sbx-output-live-0123`, target commit
  `870aac28139604e217ae44469e679557994f7a0d`, source tree
  `4937f8fab01300b542ca4dd23f90f6202ed3f268`;
- projection canonical digest
  `sha256:f89d23b18b1f7784d315e411ec90b38055f88026d08ffb188bd4fc8d1c961685`;
- Docker sbx CLI and daemon `v0.39.0`, commit
  `def8cb0523a77e757bdd6ef52b459fe374f3783e`, CLI binary digest
  `sha256:f2a9e83f41a1cc20292d1f0e40974c495065f59a933aaec98f0619c286ddbeaf`;
- shell template
  `docker.io/docker/sandbox-templates:shell@sha256:1e642f7fadebcbff3d8de67114e9b42a5971ba9b4287ebffa1d05662f5a0f5ec`;
- sandbox policy digest
  `sha256:64ef802a579cc5bd04f1cd430f1b0a1ec0829e3ee3f73a5e9f5c0c508c171854`.

That receipt establishes the accepted development workload profile, including
its recorded memory-scoping amendment. It does not qualify Kani, Loom, TLC, or
the finite mask prototype, and it does not authorize the candidate CLI to
launch them. Each selected backend needs a new owner-authorized execution or
capability probe through that profile, with its own exact tool/input/output
digests. Missing authorization or tool availability is
`UNAVAILABLE_BACKEND_BLOCKED`, never a skip.

## Deep module and Primitive Test

The module is `internal/formal`. Its only caller-facing interface is:

```go
type Request struct {
    RootPath string
    Mode     string // PREFLIGHT or REPLAY
}

func Validate(context.Context, Request) (Verdict, error)
```

`Verdict` contains a fixed state, bundle digest, normalized findings,
assurance, and `independent_review_claimed`. Schema compilation, single-read
snapshots, raw-file hashing, identifier indexes, linkage reconciliation,
receipt validation, and replay comparison stay behind that interface. Tests
use the same interface; no test-only alternate validator exists. There is no
generic backend adapter in candidate code: the protected operator and the
read-only receipt validator are the two real sides of the existing US-007
execution seam.

Primitive Test outcomes are fixed as follows:

| Capability | Atomicity | Bitter Lesson | ZFC | Placement |
| --- | --- | --- | --- | --- |
| snapshot regular single-link files once and detect read-time drift | concurrent substitution must not change one verdict | stronger models still need immutable input | filesystem transport | Go |
| strict JSON decode, Draft 2020-12 validation, identifier uniqueness, and closed-enum checks | read-only over one snapshot | deterministic validation remains necessary | no judgment | Go |
| hash raw TLA+/artifact bytes and canonical typed JSON | deterministic and idempotent | transport remains necessary | no judgment | Go using inherited digest helpers |
| reconcile obligations, symbols, backends, canaries, and receipts as a closed graph | read-only over one snapshot | exact graph reconciliation remains necessary | declarative policy enforcement | Go |
| choose which properties matter and how far an outcome may claim | no state race | a stronger model improves this judgment | assurance judgment | declarative JSON and this design |
| decide whether an abstract model refines production Rust | requires review, not atomic transport | stronger reviewers improve it | explicit judgment | future reviewed refinement artifact |
| launch proof tools or Docker | protected authority and cleanup must be atomic | transport remains necessary | process transport | existing protected US-007 operator, never candidate code |

This produces depth and locality: one small validation interface owns all
mechanical claim-ceiling enforcement, while policy authors can change a target
or backend inventory only by changing a digest-bound declarative artifact.

## Closed outcome vocabulary

Every target, backend, and result uses one of these exact `claim_scope` values:

| Value | Meaning | Explicitly does not mean |
| --- | --- | --- |
| `BOUNDED_TEST_EVIDENCE` | finite enumeration, bounded model checking, property tests, or a bounded prototype passed for the recorded domain | proof outside the bounds or production refinement |
| `SYSTEMATIC_CONCURRENCY_TESTING` | a scheduler systematically explored the recorded finite tasks/schedules/preemptions | mathematical proof, native-thread race freedom, or unbounded liveness |
| `PROVED_MODEL` | the exact abstract model satisfied the recorded invariants/temporal properties under recorded assumptions | the production Rust implementation satisfies them |
| `UNAVAILABLE_BACKEND_BLOCKED` | the backend, authorization, platform capability, tool, or required output was unavailable | skip, success, not-applicable, inferred pass, or satisfied obligation |
| `FUTURE_PRODUCTION_REFINEMENT` | a future reviewed composition/refinement link is required between evidence and the exact shipped symbol | a current outcome or permission to claim production proof |

Backend execution has a separate exact `execution_state` enum:
`EXECUTED_PASS`, `EXECUTED_COUNTEREXAMPLE`, or
`UNAVAILABLE_BACKEND_BLOCKED`. There is no `SKIP`, `PASS` without a scope, or
generic `PROOF` value. `EXECUTED_PASS` is illegal when the obligation count is
zero, a known-bad canary survives, any required artifact is absent, an input or
output digest is missing, or a target linkage is disconnected.

The inherited lattice strings remain unchanged. Projection into the US-004
lifecycle is conservative:

- `BOUNDED_TEST_EVIDENCE` -> `BoundedCheckPassed` only;
- `SYSTEMATIC_CONCURRENCY_TESTING` -> `trace_observation` only;
- `PROVED_MODEL` -> `ProofEstablished` only for the model subject, never a
  production-code subject;
- `UNAVAILABLE_BACKEND_BLOCKED` -> no satisfied lattice outcome; retain the
  explicit backend state plus a blocking finding (the inherited `unsupported`
  outcome is reserved for an actually observed unsupported construct);
- `FUTURE_PRODUCTION_REFINEMENT` -> `disconnected` until reviewed linkage
  exists.

The validator must not change the inherited schemas or the frozen
`assurance/failures.json` registry. Formal reason values are normalized to the
existing universal envelopes: semantic/claim/linkage/canary problems use
`SEMANTIC_INCONSISTENCY/BLOCK`, digest substitution uses
`DIGEST_MISMATCH/QUARANTINE`, and changed bound inputs use
`STALE_INPUT/INVALIDATE`. The formal verdict also carries a closed subordinate
`reason` such as `ZERO_OBLIGATIONS` or `INFLATED_CLAIM` for exact fixture
matching.

## Artifact and schema layout

Backend-dev adds these schema files without editing an inherited schema:

```text
schemas/formal-proof-targets-1.0.0.schema.json
schemas/formal-backend-qualification-1.0.0.schema.json
schemas/concurrency-plan-1.0.0.schema.json
```

All three use JSON Schema Draft 2020-12; every object has
`additionalProperties:false`; all listed fields are required; identifiers use
`^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$`; artifact paths are canonical relative
repository paths; digests are `^sha256:[0-9a-f]{64}$`; arrays declared as sets
must be nonempty, sorted lexicographically, and unique. JSON Schema handles
shape and local conditionals. `internal/formal` handles cross-file uniqueness,
sorting, counts, digests, reachability, and conditional graph rules.

### `assurance/formal/proof-targets.json`

Top-level entity `FormalProofTargets` has exactly:

| Field | Type and constraint |
| --- | --- |
| `$schema` | const `../../schemas/formal-proof-targets-1.0.0.schema.json` |
| `schema_version` | const `1.0.0` |
| `entity_type` | const `FormalProofTargets` |
| `plan_id` | const `formal-proof-targets.us006.v1` |
| `source_basis` | nonempty sorted array of closed `ArtifactRef` objects (`path`, `sha256`, `attribution`) |
| `targets` | exactly two closed `Target` objects, unique by `target_id` |
| `required_consumers` | const `['CONFORMANCE','DIFFERENTIAL','PRODUCTION']` |
| `assurance` | const `OWNER_ATTESTED_NOT_INDEPENDENT` |
| `independent_review_claimed` | const `false` |
| `production` | const `false` |
| `publication` | const `false` |

`ArtifactRef.attribution` is one of `BORROWED_CLAUDE_US003`,
`BORROWED_CLAUDE_US004`, `BORROWED_CLAUDE_US005`,
`BORROWED_CLAUDE_US007`, or `US006_OWNED`. Every source-basis digest is checked
against the raw snapshotted bytes.

Each closed `Target` has exactly:

| Field | Type and constraint |
| --- | --- |
| `target_id` | `target.frame-mask` or `target.frame-header-decoder` |
| `story_id` | const `US-012` |
| `planned_file` | exact canonical path from the target table above |
| `rust_symbol` | exact fully-qualified symbol from the target table above |
| `item_kind` | `FUNCTION` or `ASSOCIATED_FUNCTION` |
| `linkage_state` | `UNRESOLVED_FUTURE_PRODUCTION_SYMBOL`, `RESOLVED_PRODUCTION_SYMBOL`, or `DISCONNECTED` |
| `source_sha256` | null unless resolved; digest when resolved |
| `semantic_identity` | null unless resolved; compiler/rust-analyzer identity when resolved |
| `required_call_paths` | exactly `CONFORMANCE`, `DIFFERENTIAL`, and `PRODUCTION` records |
| `obligations` | nonempty sorted closed `Obligation` array |
| `prohibited_duplicates` | const `['PROOF_ONLY_REIMPLEMENTATION','ADAPTER_LOCAL_CODEC','TEST_ONLY_COPY']` |
| `maximum_current_scope` | `FUTURE_PRODUCTION_REFINEMENT` while unresolved, otherwise no higher than the selected backend allows |

Each `required_call_paths` record has `consumer`, `entry_symbol`,
`linkage_artifact` (nullable `ArtifactRef`), and `state`. `state` is
`FUTURE_REQUIRED`, `LINKED`, or `DISCONNECTED`. When linked, the artifact must
be a compiler/call-graph or instrumented-trace receipt showing the consumer
reaches the exact `rust_symbol`; source-name text search alone is insufficient.
Conformance and differential may enter through `ConnectionCore`, but their
production trace must reach these exact symbols. They may not invoke a copied
codec.

Each closed `Obligation` has `obligation_id`, `property_id`, `statement`,
`required_backend_ids`, `expected_canary_ids`, `subject_target_id`,
`minimum_obligation_count` (integer, minimum 1), `allowed_claim_scopes`, and
`production_refinement_required` (const true). The inventory is fixed:

| Target | Obligation IDs |
| --- | --- |
| `target.frame-mask` | `obligation.mask-equation` (for every tested `i`, `out[i] = in[i] XOR key[(offset+i) mod 4]`); `obligation.mask-involution` (two applications with identical key and offset restore the input) |
| `target.frame-header-decoder` | `obligation.length-canonical-7`; `obligation.length-canonical-16`; `obligation.length-canonical-64-high-bit-zero`; `obligation.checked-header-arithmetic`; `obligation.preallocation-cap`; `obligation.control-fin-and-length`; `obligation.role-masking` |

Canonical lengths mean 0..125 use the seven-bit form, 126..65,535 use the
16-bit form and reject values below 126, and 65,536..2^63-1 use the 64-bit form
and reject values below 65,536 or with the high bit set. Checked arithmetic
covers base header + extended length + optional four-byte mask + payload,
checked conversion to `usize`, and all configured frame/buffer caps before any
payload allocation. Control constraints require FIN, control opcodes only, and
payload length <=125. Role masking requires masked inbound frames for a server
and unmasked inbound frames for a client; Java's documented receive leniency is
not a compatibility target.

Conditional rules are fail closed: unresolved targets require null source and
linkage artifacts and permit only `FUTURE_PRODUCTION_REFINEMENT`; resolved
targets require all three linked consumers and matching source/semantic
identity; `DISCONNECTED` always blocks. No obligation may name a different
production-code identity than its target.

### `assurance/formal/backend-qualification.json`

Top-level entity `FormalBackendQualification` has exactly:

| Field | Type and constraint |
| --- | --- |
| `$schema` | const `../../schemas/formal-backend-qualification-1.0.0.schema.json` |
| `schema_version` | const `1.0.0` |
| `entity_type` | const `FormalBackendQualification` |
| `qualification_id` | const `formal-backend-qualification.us006.v1` |
| `proof_targets` | `ArtifactRef` to `proof-targets.json` |
| `connection_model` | `ArtifactRef` to `connection-model.tla` |
| `concurrency_plan` | `ArtifactRef` to `concurrency/plan.json` |
| `borrowed_sandbox_foundation` | closed `SandboxFoundation` below |
| `backends` | nonempty sorted closed `Backend` array, unique by ID |
| `aggregate_state` | `BLOCKED`, `BOUNDED_ONLY`, `SYSTEMATIC_ONLY`, `MODEL_ONLY`, or `MIXED_NON_PRODUCTION`; never `PROVED_PRODUCTION` in US-006 |
| `assurance` | const `OWNER_ATTESTED_NOT_INDEPENDENT` |
| `independent_review_claimed` | const `false` |
| `production` / `signing` / `publication` | const false |

`SandboxFoundation` contains exactly `attribution` (const
`BORROWED_CLAUDE_US007`), `attempt_id`, `security_validation`,
`live_evidence`, `sbx_template`, `sandbox_policy`,
`projection_canonical_digest`, `target_commit`, `source_tree`, `cli_path`,
`cli_version`, `cli_commit`, `cli_binary_digest`, `daemon_version`,
`daemon_commit`, `template_reference`, `sandbox_policy_digest`,
`enforcement_model`, `memory_scope`, `authorized_use`, and `limitations`.
The expected values are the borrowed foundation values above.
`sbx_template` binds `security/sbx-template.json` at
`sha256:a5325fcb926253c267fe9e4baffb0dd397340a9e9edea521cab7f20bbfe3f312`;
`sandbox_policy` binds `security/sandbox-policy.json` at the policy digest
already named above.
`authorized_use` is const `OPERATIONAL_ISOLATION_FOUNDATION_ONLY`;
`memory_scope` must preserve the exact owner-accepted outer-sandbox/per-memory-
canary limitation; and `limitations` must state that a new execution still
needs owner authorization, promotion, cleanup, classification, and a public
projection.

Each closed `Backend` contains exactly:

```text
backend_id, selected, method, tool, availability_probe, sbx_execution,
expected_property_ids, obligation_ids, obligation_count, known_good_canaries,
known_bad_canaries, bounds, assumptions, provenance, unsupported_constructs,
trusted_base, required_artifacts, execution_state, claim_scope, outcomes,
replay, limitations
```

The nested objects are closed:

- `tool`: `name`, `version`, `commit` (nullable), `binary_sha256` (nullable
  only when unavailable), `installation_provenance`, `executable_promotion`
  (nullable only when unavailable);
- `availability_probe`: `executed` boolean, `receipt` nullable `ArtifactRef`,
  `exit_code` nullable integer, and `observation`; a selected unavailable
  backend requires an executed, digest-bound failed capability probe unless
  authorization itself is the recorded blocker;
- `sbx_execution`: exact CLI/daemon/template/policy values, `request_digest`,
  `receipt_digest`, `input_root_digest`, `output_root_digest`, `cleanup_state`,
  and `classification_state`, all nullable only for
  `UNAVAILABLE_BACKEND_BLOCKED`;
- both canary arrays: nonempty closed records with `canary_id`, `input`,
  `expected_outcome`, `observed_outcome`, `output`, and nullable
  `counterexample`; an executed known-bad canary requires a non-null minimized
  counterexample;
- `bounds`: method-specific closed object selected by JSON Schema `oneOf`;
- `outcomes`: one record per obligation with `obligation_id`, `raw_outcome`,
  `claim_scope`, `artifact_refs`, and nullable `counterexample`;
- `replay`: `replay_id`, exact `argv` array, sorted `environment` array,
  `working_directory`, `seed`, `expected_exit_code`, `semantic_output_digest`,
  `repeat_count` (minimum 2 for executed pass), and
  `reconciled_identically`; and
- `required_artifacts`: nonempty unique enum values from `SBX_REQUEST`,
  `SBX_RECEIPT`, `TOOL_IDENTITY`, `INPUT_MANIFEST`, `OUTPUT_MANIFEST`,
  `OBLIGATION_INVENTORY`, `GOOD_CANARY_RESULT`, `BAD_CANARY_COUNTEREXAMPLE`,
  `RAW_TOOL_RESULT`, `NORMALIZED_RESULT`, `REPLAY_RECEIPT`,
  `CLEANUP_RECEIPT`, and `CLASSIFIER_PROJECTION`.

`selected` is `true` for each of the four planned backends below. Every
outcome has at least one artifact reference (an unavailable outcome references
its authorization/capability blocker). `raw_outcome` is exactly one of
`BOUNDED_CHECK_PASSED`, `SYSTEMATIC_EXPLORATION_PASSED`,
`MODEL_CHECK_PASSED`, `COUNTEREXAMPLE`, `BACKEND_UNAVAILABLE`,
`UNSUPPORTED_CONSTRUCT`, or `DISCONNECTED`. Only `COUNTEREXAMPLE` permits a
non-null counterexample. `BACKEND_UNAVAILABLE`, `UNSUPPORTED_CONSTRUCT`, and
`DISCONNECTED` cannot satisfy an obligation.

The planned backend inventory is:

| Backend ID | Method | Maximum scope | Required treatment |
| --- | --- | --- | --- |
| `backend.finite-mask-prototype` | `FINITE_EXHAUSTIVE_PROTOTYPE` | `BOUNDED_TEST_EVIDENCE` | The accepted prototype may be imported only with exact public provenance, tool/input/output digests, nonzero mask obligations, and good/bad canaries. No retained prototype artifact exists at the design base, so absence is blocked rather than inferred. |
| `backend.kani-production` | `KANI_BOUNDED_MODEL_CHECKING` | `BOUNDED_TEST_EVIDENCE` | Must target the exact shipped Rust symbols. An unavailable tool/probe blocks Kani claims. Unwind/bounds and unsupported Rust constructs are mandatory. |
| `backend.loom-concurrency` | `LOOM_SYSTEMATIC_SCHEDULE_EXPLORATION` | `SYSTEMATIC_CONCURRENCY_TESTING` | Must consume `assurance/concurrency/plan.json`; never maps to proof. An unavailable tool/probe blocks Loom claims. |
| `backend.tlc-connection-model` | `TLC_EXPLICIT_STATE_MODEL_CHECKING` | `PROVED_MODEL` | May establish only the exact `ConnectionModel` subject and recorded bounds/fairness. Unavailable TLC blocks the model claim. |

Method-specific bounds are exact shapes:

- finite prototype: `payload_lengths`, `offsets`, `keys`, `byte_values`,
  `cases_evaluated` (all nonempty/nonzero);
- Kani: `max_payload_bytes`, `max_unwind`, `solver`, `pointer_width`,
  `harness_ids`, `cases_evaluated`;
- Loom: `max_tasks`, `max_schedules`, `max_preemptions`, `max_branches`,
  `queue_capacities`, `schedule_count`;
- TLC: `state_bound`, `command_capacity`, `write_capacity`, `event_capacity`,
  `distinct_states`, `transitions`, `fairness`.

Cross-field rules reject: selected but unprobed; zero or mismatched obligations;
empty expected-property inventory; empty good/bad canaries; surviving seeded
bad canaries; missing required artifacts; unsupported constructs claimed as
covered; digests that do not reopen; replay count below two or unequal semantic
digests; finite/Kani scope above bounded; Loom scope other than systematic;
TLC scope above model; unavailable represented by null/skip/success; and any
production claim while a target or required consumer is unresolved.

### `assurance/formal/connection-model.tla`

This is raw UTF-8 TLA+ text, not JSON. It is hashed byte-for-byte and its module
name must be exactly `ConnectionModel`. The validator implements a deliberately
small structural checker, not a TLA+ parser: exactly one module header and
footer; no tabs, CRLF, absolute paths, `EXTENDS TLC`, `Java`, `Rust`, mask,
payload-byte, or frame-header algorithm; and exactly these declared identifiers:

```text
EXTENDS Naturals, Sequences, FiniteSets
States == {"Connecting", "Open", "Closing", "Closed"}
MaxCommands == 2
MaxWrites == 2
MaxEvents == 2
MaxAccepted == 3
MaxBackpressure == 2
VARIABLES state, commandQ, writeQ, eventQ, shutdownRequested,
          terminalQueued, terminalDelivered, backpressureCount
vars == <<...all variables in the order above...>>
Init
CompleteHandshake
EnqueueCommand
ReceiveFrame
ReceiveClose
FlushOutbound
BeginShutdown
DeliverCallback
ApplyBackpressure
FinishClose
Next
TypeOK
QueueBounds
LifecycleMonotonic
ClosedIsTerminal
TerminalDeliveredAtMostOnce
BackpressurePreservesAcceptedWork
Spec
TerminationUnderFairness
```

`Next` is exactly the disjunction of the nine actions. `Spec` is `Init`, the
stuttering closure of `Next`, weak fairness for owner progress, outbound flush,
and callback delivery when their enabling conditions remain true. Producer
admission has no fairness assumption: a full queue may return explicit
backpressure. `MaxAccepted` and `MaxBackpressure` bound otherwise cyclic
counters so TLC explores a genuinely finite graph rather than an ever-growing
counter dimension. `TerminationUnderFairness` is conditional on a requested
shutdown and the declared progress fairness. The model represents only the
abstract `Connecting -> Open -> Closing -> Closed` lifecycle, bounded queues,
and terminal delivery. It contains no codec, mask, length, allocation, or
production Rust algorithm, so it cannot become a proof-only duplicate.
`LifecycleMonotonic`, `ClosedIsTerminal`, and
`BackpressurePreservesAcceptedWork` are temporal transition properties in the
TLC configuration, rather than merely named formulas. Shutdown liveness is
wrapped in `[]`, so it is checked from every reachable state where shutdown has
been requested instead of passing vacuously from the initial state.
The TLC configuration disables generic deadlock reporting because `Closed` is
the intended terminal state with no enabled `Next` action; terminal reachability
and absorption remain explicit checked properties rather than being mislabeled
as a deadlock failure.

The supplemental current-head TLC execution is retained under
`evidence/formal/tlc-4dc9582/`: two semantically identical Linux/arm64 replays
of the clean model plus one killed mutant for every configured check. Its claim
scope is `PROVED_MODEL_ONLY`. It intentionally does not promote the original
US-006 backend-qualification envelope, whose broader typed sbx artifact
protocol was not reconstructed for this supplemental run. A structurally valid
module or a TLC pass does not change production linkage.
Only a future reviewed refinement artifact may replace
`FUTURE_PRODUCTION_REFINEMENT`; it must bind the exact model digest, exact Rust
symbol/source digests, composition mapping, preserved invariants, uncovered
behavior, reviewer identity/role, and post-review source tree. That artifact is
outside US-006.

### `assurance/concurrency/plan.json`

Top-level entity `ConcurrencyPlan` has exactly:

| Field | Type and constraint |
| --- | --- |
| `$schema` | const `../../schemas/concurrency-plan-1.0.0.schema.json` |
| `schema_version` | const `1.0.0` |
| `entity_type` | const `ConcurrencyPlan` |
| `plan_id` | const `concurrency-plan.us006.v1` |
| `story_id` | const `US-017` |
| `implementation_state` | const `FUTURE_PRODUCTION_REFINEMENT` |
| `owner_symbol` | const `websocket_driver::owner::ConnectionOwner::step` and state `UNRESOLVED_FUTURE_PRODUCTION_SYMBOL` |
| `actions` | exactly the nine action records below |
| `bounds` | closed fixed bounds below |
| `fairness` | closed fixed assumptions below |
| `properties` | nonempty exact inventory below |
| `seeded_defects` | exact six US-017 defects below |
| `required_artifacts` | exact systematic/native artifact inventory |
| `claim_scope` | const `SYSTEMATIC_CONCURRENCY_TESTING` |
| `native_thread_evidence` | closed future separate-evidence record |
| `assurance` | const `OWNER_ATTESTED_NOT_INDEPENDENT` |
| `independent_review_claimed` | const false |
| `production` / `publication` | const false |

The nine closed actions are `command-enqueue`, `inbound-frame`,
`inbound-close`, `outbound-flush`, `shutdown`, `callback-delivery`,
`backpressure`, `owner-step`, and `finish-close`. Each action record has
`action_id`, `actor`, `preconditions`, `effects`, `observable_outcomes`, and
`maximum_occurrences_per_schedule`. `command-enqueue` includes `SendText`,
`SendBinary`, `Ping`, and `Close`. Inbound close is distinct from an ordinary
frame. Outbound flush includes zero, partial, and complete writes. Callback
delivery means draining typed events after owner processing; the protocol core
does not invoke callbacks. Backpressure covers command-queue full, write-queue
full, event-queue full, and receiver drop. Shutdown covers adapter shutdown and
EOF. The plan forbids direct shared mutable protocol state outside the owner.

Fixed version-1 bounds are:

```json
{
  "producer_tasks": 2,
  "owner_tasks": 1,
  "inbound_tasks": 1,
  "flush_tasks": 1,
  "callback_tasks": 1,
  "shutdown_tasks": 1,
  "max_tasks": 7,
  "command_queue_capacity": 2,
  "write_queue_capacity": 2,
  "event_queue_capacity": 2,
  "commands_per_producer": 2,
  "inbound_actions": 2,
  "flush_actions": 3,
  "callback_actions": 3,
  "shutdown_actions": 1,
  "max_schedules": 100000,
  "max_preemptions": 3,
  "max_branches": 1000000
}
```

All bounds are positive and exact. Reaching `max_schedules` or
`max_branches` without exhausting the planned space records bounded systematic
evidence and an explicit limitation; it never silently means exhaustive.

Fairness contains exactly:

- `WEAK_OWNER_PROGRESS_WHEN_WORK_PENDING`;
- `WEAK_FLUSH_PROGRESS_WHEN_WRITABLE`;
- `WEAK_CALLBACK_PROGRESS_WHEN_EVENT_PENDING`;
- `NO_PRODUCER_ADMISSION_FAIRNESS_QUEUE_FULL_RETURNS_BACKPRESSURE`.

The property inventory is: accepted commands are applied at most once; FIFO is
preserved within each producer and committed owner order is reflected in
writes/events; no write bypasses pending-write backpressure; command/write/
event depths never exceed capacity; close and shutdown converge under declared
fairness; terminal delivery occurs exactly once when a terminal event is
accepted; no post-terminal callback/write is introduced; every explored run
terminates or yields a bounded minimized schedule; and receiver drop has one
typed outcome. The six required seeded defects are `lock-sharing`,
`lost-command`, `queue-bypass`, `write-reorder`, `close-race`, and
`duplicate-delivery`; every one must be killed before an executed systematic
record can pass.

Required systematic artifacts are the plan/tool/input/output digests, explored
schedule count, branch/preemption maxima, per-property result, good-canary
result, all six killed-defect results, and a deterministic minimized schedule
for each failure. Native-thread stress/race evidence is a separate future
record with platform, tool digest, source tree, repeat count, flake
reconciliation, and output digest. Loom cannot satisfy it, and native stress
cannot satisfy the systematic plan.

## Validator and CLI behavior

Backend-dev adds `internal/formal/` with `model.go`, `snapshot.go`,
`schema.go`, `tla.go`, `validate.go`, and tests, then extends the incumbent
`cmd/assurectl` rather than creating another CLI.

```text
assurectl formal-preflight --root DIR
assurectl formal-replay --root DIR
```

There are no backend/tool/receipt path flags and no arbitrary argv. Both modes
use the four fixed repository-relative paths. `formal-preflight` validates the
current immutable snapshot. `formal-replay` validates again and requires the
recorded replay identities and semantic output digests to reconcile; it does
not launch a backend. The protected operator remains the only executor.

The operation order is fixed:

1. open `DIR` as a root-confined directory and read each required regular,
   single-link file once with before/open/after identity checks and size limits;
2. strict-decode JSON, rejecting null, duplicate/unknown fields, trailing
   values, invalid UTF-8, excessive depth/size, and noncanonical paths;
3. compile the three new schemas from the same snapshot and validate all JSON;
4. hash raw artifact bytes, validate every declared digest, and build unique ID
   indexes;
5. validate the exact TLA+ structure and digest;
6. reconcile target -> obligation -> backend -> canary/result -> artifact and
   consumer linkage reachability;
7. apply method-specific claim ceilings and the unavailable/refinement rules;
8. validate deterministic replay bindings and normalized semantic output;
9. normalize findings by envelope code, subordinate reason, path, and message;
10. emit one JSON verdict and exit 0 only when it is mechanically valid. A
    mechanically valid blocked qualification still has `state:"BLOCKED"` but
    no structural findings; CLI exit semantics must distinguish `valid:true`
    from an assurance claim. Any structural finding exits 1; usage exits 2.

The verdict has exactly `valid`, `state`, `bundle_digest`, `claim_scopes`,
`findings`, `assurance`, and `independent_review_claimed`. `state` is never
`PROVED_PRODUCTION` in US-006. Two unchanged invocations must produce identical
bytes; timestamps, host paths, map iteration order, and wall durations are not
part of the semantic verdict.

## Deterministic replay and digest binding

JSON artifact digests bind raw retained bytes. Semantic replay uses inherited
typed `encoding/json` canonicalization after strict decoding; arrays whose
order is semantically irrelevant are required sorted before hashing. TLA+ and
tool outputs are raw-byte SHA-256. No digest is computed over an object that
contains its own digest.

For each backend, `replay_id` is the SHA-256 of the canonical closed tuple:

```text
backend_id, method, tool identity digest, executable promotion digest,
borrowed sbx profile digest, new sbx request digest, input root digest,
proof-targets digest, connection-model digest, concurrency-plan digest,
ordered property IDs, ordered obligation IDs, method bounds, assumptions,
unsupported constructs, exact argv, exact environment, working directory, seed
```

The execution result separately binds `replay_id`, exit code, raw output
manifest, normalized semantic output digest, obligation count, canary results,
counterexamples, cleanup receipt, and classifier projection. Repeating an
executed passing backend at least twice must yield the same normalized semantic
output digest and obligation inventory. Environment metadata and nondeterministic
tool timing may remain in raw receipts but is excluded from the semantic digest
by an explicit schema, never by ad hoc filtering.

A counterexample has a stable ID derived from backend, obligation, canonical
input, bounds, and schedule/seed. Minimization may remove inputs or schedule
steps only while replay still reproduces the same subordinate reason and target
symbol. The retained minimized artifact and its replay receipt are mandatory.

## Fixture matrix

Fixtures are inert JSON/TLA+ mutations under
`assurance/formal/fixtures/`; they never contain a proof executable or launch
command. Every fixture is marked `SYNTHETIC_NON_CLAIM` and is forbidden from
the canonical qualification's artifact graph. `cases.json` is closed and binds
each fixture tree digest, expected universal envelope, subordinate reason, CLI
exit, and claim scope.

Known-good controls:

| Fixture ID | Expected result |
| --- | --- |
| `good-unresolved-production-plan` | structurally valid `BLOCKED`; both future symbols and consumers remain explicit, no proof claim |
| `good-finite-mask-bounded` | nonzero equation/involution inventory, good canary passes, seeded bad canary has reproducible counterexample, scope exactly `BOUNDED_TEST_EVIDENCE` |
| `good-systematic-concurrency` | fixed actions/bounds/fairness, all six seeded defects killed, scope exactly `SYSTEMATIC_CONCURRENCY_TESTING` |
| `good-proved-model-only` | model obligations and artifacts are complete, subject is model digest only, scope exactly `PROVED_MODEL`, production refinement remains future |
| `good-unavailable-backend-blocked` | exact capability/authorization blocker retained, no success outcome or satisfied obligation, scope exactly `UNAVAILABLE_BACKEND_BLOCKED` |

Known-bad semantic canaries, each requiring a minimized reproducible
counterexample when executed, are `bad-mask-key-index`,
`bad-mask-non-involution`, `bad-length-noncanonical-16`,
`bad-length-noncanonical-64`, `bad-length-high-bit-64`,
`bad-header-overflow`, `bad-allocation-before-cap`, `bad-control-fragmented`,
`bad-control-oversized`, and `bad-role-masking`.

Hostile structural fixtures are exact:

| Fixture ID | Mutation | Required subordinate reason |
| --- | --- | --- |
| `zero-obligations` | obligation array/count is zero | `ZERO_OBLIGATIONS` |
| `missing-target` | backend obligation names no target | `MISSING_TARGET` |
| `missing-required-artifact` | remove tool/input/output/canary/replay artifact | `MISSING_REQUIRED_ARTIFACT` |
| `missing-digest` | null/remove a required digest | `MISSING_DIGEST` |
| `disconnected-symbol` | claim a result while source or one consumer is unresolved | `DISCONNECTED_TARGET` |
| `disconnected-proof-copy` | point a backend to a proof-only duplicate symbol | `PROOF_ONLY_DUPLICATE` |
| `unsupported-claimed-covered` | property intersects unsupported constructs but outcome says pass | `UNSUPPORTED_CONSTRUCT_CLAIMED` |
| `known-bad-survives` | seeded bad canary reports pass/no counterexample | `KNOWN_BAD_CANARY_SURVIVED` |
| `inflated-finite-proof` | finite/Kani outcome claims model or production proof | `INFLATED_CLAIM` |
| `inflated-loom-proof` | Loom outcome claims proof | `INFLATED_CLAIM` |
| `inflated-model-production` | TLC/model result names a Rust production subject without refinement | `REFINEMENT_MISSING` |
| `unavailable-as-skip` | unavailable backend uses skip/not-applicable | `UNAVAILABLE_REPRESENTED_AS_SKIP` |
| `unavailable-as-success` | unavailable backend satisfies an obligation | `UNAVAILABLE_REPRESENTED_AS_SUCCESS` |
| `replay-digest-mismatch` | mutate normalized output or replay tuple | `REPLAY_MISMATCH` |
| `inflated-schedule-count` | report schedules/obligations inconsistent with retained artifacts | `INFLATED_COUNT` |

Each hostile fixture must fail through both package and CLI. Counts are derived
from retained arrays/artifacts and compared to declared counts; a large claimed
number is never accepted as evidence by itself.

## Backend-dev implementation and test plan

Backend-dev should implement in this order, without executing any proof tool or
Docker command unless a later phase separately grants protected authority:

1. Add the three strict schemas and schema tests for unknown, duplicate, null,
   trailing, missing, enum, conditional, zero-count, and assurance-ceiling
   cases.
2. Add `proof-targets.json` with the two future exact identities, nine
   obligations, inherited source-basis digests, all consumer links future, and
   no resolved-production claim.
3. Add the abstract `ConnectionModel` module with only the declared lifecycle,
   queue, fairness, and terminal-delivery vocabulary. Add byte-for-byte shape
   tests; do not claim TLC execution.
4. Add `concurrency/plan.json` with the fixed action inventory, version-1
   bounds, fairness assumptions, properties, six defects, and systematic-only
   classification.
5. Add `backend-qualification.json`. Bind the borrowed Claude US-007 values
   exactly. For any backend lacking a retained qualified result, use
   `UNAVAILABLE_BACKEND_BLOCKED`; do not invent a tool version, digest,
   execution, canary, or obligation outcome. If the accepted finite mask
   prototype is supplied as a classifier-approved public artifact, bind it and
   cap it at `BOUNDED_TEST_EVIDENCE`; otherwise keep it blocked.
6. Implement the single-read `internal/formal.Validate` path using the
   incumbent strict-decoding, schema, canonical-digest, root-confinement, and
   normalized-finding patterns. Do not create a second evidence lifecycle or a
   candidate-side backend launcher.
7. Wire `formal-preflight` and `formal-replay` into `assurectl` with fixed paths
   and deterministic JSON. Add package/CLI byte-equality and no-mutation tests.
8. Add all good, seeded-bad, and hostile fixtures. Require exact envelope,
   subordinate reason, path, exit, and claim scope; prove that zero, missing,
   disconnected, unsupported, unavailable-as-skip/success, and inflated counts
   all block.
9. Add integration tests showing unresolved Rust symbols block only their own
   production claims, a proof-only duplicate is rejected, all three consumers
   must reach the same future symbol, Loom never projects above
   `trace_observation`, and a model never reaches a production subject without
   refinement.
10. Verify only the new package and CLI tests, the targeted Go race/vet/build
    gates, deterministic replay output, fixture completeness, and `git diff`.
    Do not run unrelated repository tests, Maven, Cargo, Rust, Kani, Loom, TLC,
    Docker/sbx, network probes, Autobahn, production, signing, or publication.

Implementation-phase targeted commands are expected to be:

```text
go test ./internal/formal ./cmd/assurectl -count=1
go test -race ./internal/formal ./cmd/assurectl -count=1
go vet ./internal/formal ./cmd/assurectl
go build ./cmd/assurectl
go test ./internal/formal -run '^TestUS006' -count=1
go test ./cmd/assurectl -run '^TestFormal' -count=1
```

Before running them, backend-dev must inspect the selected tests and prove they
contain no backend, Docker/sbx, Java, Rust, Python, container, network,
Autobahn, protected-evidence, signing, production, or publication launch path.
An exit code alone is not completion: the actual CLI output must show the exact
good blocked ceiling and every hostile fixture must produce its expected typed
failure.
