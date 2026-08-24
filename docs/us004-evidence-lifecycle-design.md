# US-004: inherited evidence lifecycle design

Status: execution-ready architecture contract. This document designs the US-004
adapter; it does not implement or claim acceptance of the lifecycle.

Assurance: `OWNER_ATTESTED_NOT_INDEPENDENT`.
`independent_review_claimed` is `false`. Production access and publication are
not authorized.

## Decision

Instantiate the accepted Laboratory Zero contracts as data, and place one
WebSocket-specific adapter in `internal/assurance`. The adapter's interface is
the only target-repository seam. Its implementation delegates canonical JSON,
digests, evidence/evolution validation, the two existing protocol validators,
checkpoint resumption, and immutable attempt handling to the accepted parent
packages. It adds only child scope, the frozen single-owner assurance ceiling,
and artifact-path selection.

The adapter must not import or copy `labzero.Evaluate`. That implementation is
specialized to `laboratory-zero`, exact Lab Zero source paths and toolchains,
and its complete demonstration artifact inventory
(`laboratories/lab-zero/lifecycle.go:302-442`). The reusable parent seam is the
generic `foundation`, `protocol`, and `validators` packages. Laboratory Zero's
manifest and fixtures remain the accepted example and adversarial oracle.

This is a deep module: callers supply a root and a declarative lifecycle
document, then receive one normalized verdict. Deleting it would force every
CLI, replay, and acceptance test to repeat scope binding, schema selection,
validator agreement, attempt/failure reconciliation, DAG closure, and public
reachability checks. That gives the interface leverage and keeps assurance
knowledge local.

No Go `interface` type is introduced. The parent already has a real verifier
seam with two concrete adapters, `validators.VerifyReference` and
`validators.VerifyIndependent`. A second target adapter would be speculative
and would violate the two-adapter rule.

## Accepted parent baseline

The acceptance source is the current, clean
`companies/open-source-projects/projects/verified-java-to-rust-port` tree. The
Laboratory Zero report records the accepted snapshot root
`sha256:3362b2e93e78dd10a739af3f474286a60a4ae487e93d1b24c91a029e5faeb14b`
and public evidence root
`sha256:7868eb6731d3703ff1cf5048b7e9c353444dd1ee5a41faff439862e274c4f487`
(`docs/laboratory-zero-report.md`). The child template is pinned as:

- `templates/child-prd/laboratory-template.json`
- SHA-256 `eb8afd7c9089456c08515b3b43182a57545ef50f40b1953944f85acdae308599`
- template ID `verified-java-to-rust-child-laboratory-v1`
- frozen by `lab-zero-snapshot-v1`

The implementation phase must create
`assurance/upstream-manifest.json`, listing the accepted source path, SHA-256,
and target path for every inherited byte. Verification must reject an omitted,
extra, or digest-mismatched inherited file. A mutable branch name, local path,
or repository HEAD is not an acceptable pin.

The accepted Go module currently lives inside the local-only HQ tree and has
no standalone Git remote or release tag. Therefore implementation must vendor
the minimal accepted module snapshot under
`third_party/verified-java-to-rust-foundation/`, with the upstream manifest as
its file-by-file content pin. `go.mod` may use a local `replace` to that module.
This is a vendored dependency, not a fork: no behavior may be edited in the
vendored tree. Any desired behavior change is a parent change followed by a
new reviewed pin. A locally resolved parent path is forbidden because it would
make clean replay non-reproducible.

Key inherited pins include:

| Parent artifact | SHA-256 | Use |
|---|---|---|
| `protocol/canonical.go` | `9deead477c7e58b3af00045cdb6e1e3aec98ca09226a49fe54f2c855b3616d49` | strict decode, canonical bytes, digests, normalized findings |
| `protocol/types.go` | `af5d4d3306ffe966d4bc5986070abc7018c55712067aed9ab48f20aeca3767bc` | bundle, DAG, stage, attempt, failure, authorization, checkpoint types |
| `protocol/policy.go` | `908a0c721ad72fbc8f4995520648735635b45caa7686d5c36281a56a213b50e4` | dispositions and retry allowlist |
| `validators/reference.go` | `bb6697319cd9eea23ad474680d25ff5ef0e182188d353eee4ab05afd8e4d9b43` | reference verifier adapter |
| `validators/independent.go` | `4f4cc4c95773ff8b6657c3bf553ec40ce45853b15bf9ea318bb8f6ae0b06c405` | structurally different verifier adapter |
| `validators/foundation_adapter.go` | `5ceeb0d6e556efe2bfba927d677943eaf9f89a8fba0c04e4823465e3a5d76a56` | accepted evidence/evolution adapter |
| `schemas/evidence-model-1.1.0.schema.json` | `6eb952861989ec129c364f1fd2d320fcc6b8db4823f3d9a73e85b69db92fd134` | canonical entity/claim/evidence case |
| `schemas/evolution-1.1.0.schema.json` | `70896b77c1c3c20f6b697998db848927a27df196852c04ec590ee8a07d96159c` | lifecycle and staleness evolution |
| `schemas/developer-tool-run.schema.json` | `a77b5d1bd2101c837fcef044178441d29932065fe9b794dff8f62fd4b3cd26ac` | non-assurance tool records |
| `protocol/schemas/protocol-bundle-1.0.0.schema.json` | `fd5b1be0266d7b4f922d39e74878a410b9bd69de9449d4cd083eb4af2751f40a` | DAG, stages, attempts, failures, authorization, publication |
| `protocol/schemas/checkpoint-1.0.0.schema.json` | `458c47c0e42ca440400a3638aa6f81b5056724b13add2cdbeb1248fbbb994d2b` | resumable checkpoint |

All other copied schemas are also pinned in `assurance/upstream-manifest.json`;
the table is not a substitute for that complete manifest.

## Target layout

Implementation should create only this assurance slice:

```text
assurance/
  upstream-manifest.json
  schema/                         # exact accepted schema bytes
  failures.json                   # frozen code/disposition registry
  evidence-model.json             # WebSocket evidence-model-1.1.0 case
  evidence-dag.json               # exact projection of lifecycle bundle DAG
  lifecycle.json                  # child-scoped protocol bundle and state input
  evolution.json                  # accepted evolution-1.1.0 document
  public-contract.json            # PUBLIC/PUBLIC_DERIVED projection allowlist
  replay/
    README.md                     # offline, copy-paste replay contract
    fixtures/                     # synthetic good and adversarial inputs
cmd/assurectl/main.go             # thin verify/replay transport
internal/assurance/
  adapter.go
  adapter_test.go
  testdata/
third_party/verified-java-to-rust-foundation/
```

`assurance/evidence-dag.json` must be byte-equivalent, after canonical decode,
to the node/edge projection inside `assurance/lifecycle.json`. It is retained
separately so substitution is detectable; it is not a second graph.

There is no accepted standalone JSON Schema for the Lab Zero
`lifecycle.json`, `evidence-dag.json`, fault registry, or public contract. The
child must not invent weaker schemas with those names. Instead:

- `lifecycle.json` is validated as the accepted protocol bundle schema and by
  both accepted protocol validators.
- `evidence-dag.json` is the exact canonical node/edge projection of that
  validated bundle.
- `failures.json` is checked against the closed inherited registry and every
  emitted `FailureEnvelope` is validated by the evidence-model and protocol
  bundle contracts.
- `public-contract.json` is checked by graph reachability plus a closed field
  allowlist; it never substitutes for protocol publication validation.

## Adapter interface

The target package exposes concrete functions, not an abstraction hierarchy:

```go
type Request struct {
    RootPath      string
    LifecyclePath string
    Mode          string // VERIFY or REPLAY
}

type Verdict struct {
    State              string
    SnapshotRoot       string
    PublicEvidenceRoot string
    Findings           []protocol.Finding
    Assurance          string
    IndependentReviewClaimed bool
}

func Verify(ctx context.Context, request Request) (Verdict, error)
func Replay(ctx context.Context, request Request) (Verdict, error)
```

The interface invariants are:

1. `RootPath` is opened inside the module using `os.OpenRoot`; callers cannot
   supply an unconstrained `fs.FS`. Links, non-regular files, multi-link files,
   size changes, and pre/post-read identity changes fail closed.
2. `LifecyclePath` is a slash-relative canonical path under that root.
3. both modes read immutable byte snapshots, use strict duplicate/unknown-field
   rejection, and return normalized findings in deterministic order;
4. `Replay` recomputes every digest and graph result from retained bytes. It
   cannot trust a prior verdict or rewrite a receipt;
5. a validator disagreement emits
   `PARENT_VALIDATOR_DISAGREEMENT/BLOCK`; it never chooses the more permissive
   result;
6. every verdict emitted by this story sets assurance to
   `OWNER_ATTESTED_NOT_INDEPENDENT` and
   `IndependentReviewClaimed` to `false`. Deterministically distinct verifier
   implementations are not human-independent attestations;
7. neither function publishes, reads production, uses a network, or executes
   Autobahn.

`cmd/assurectl` only parses `verify|replay`, calls the package, emits canonical
JSON, and exits nonzero for every finding. All policy and validation remain
behind the package interface.

## Canonical artifact mapping

| Child concept | Accepted parent source | Target representation |
|---|---|---|
| sources/intake | `java-intake.schema.json`; `SourcePin` in evidence-model | schema copy + `SourcePin` entities |
| surfaces and semantic IDs | `evidence-model-1.1.0.schema.json` | `SurfaceItem`/`SemanticId` entities |
| migration maps | evidence-model migration rows | `MigrationMap` entities and rows |
| dossiers | `port-seam-dossier.schema.json` | exact child dossier artifact and entity |
| deltas | `behavior-delta-ledger.schema.json` | append-only delta artifact and entity |
| compatibility | `compatibility-surface.schema.json` | exact compatibility artifact and entity |
| cutover | `cutover-contract.schema.json` | exact cutover artifact and entity |
| oracles/corpora/traces | evidence model plus `navigation-corpus.schema.json` | typed entities with content-addressed artifacts |
| claims and replay | evidence-model claims/replay bundles | claim-scoped records; no inferred assurance |
| formal obligations | evidence model plus parent formal validators | nonzero obligations, retained tool/canary evidence |
| evidence and mutations | evidence-model evidence/mutation records | signed denominator and evidence entities |
| benchmarks | `BenchmarkRun` entity; explicit benchmark artifacts | content-addressed plan/raw/analysis refs |
| developer tools | `developer-tool-run.schema.json` | three required `DeveloperToolRun` artifacts |
| attempts/failures | protocol bundle and evidence model | immutable ordered attempts and universal envelopes |
| snapshots/authorization | protocol bundle/checkpoint schemas | content-addressed snapshot and action authorization |
| classifications | evidence model and protocol node classification | closed five-value classification |
| staleness | `evolution-1.1.0.schema.json` | exact `StalenessEdge` graph and minimal stale cut |

## Acceptance-criterion contract

| AC | Inherited sources | Target module/files | Required invariants | Tests and stable failures |
|---|---|---|---|---|
| 1. Canonical schemas | evidence-model 1.1.0 and 1.0.0, evolution 1.1.0, all concrete schemas, frozen child template | `assurance/schema/`, `upstream-manifest.json`, `evidence-model.json`, `evolution.json` | exact bytes/digests; closed entity enum; strict JSON; no removed required fields or lowered cardinalities | good parent fixtures pass; schema drift, missing entity, unknown field, or pin mismatch yield inherited `INVALID_*_JSON`, `INVALID_*_SCHEMA_VERSION`, `MISSING_EVIDENCE_FIELD`, `MISSING_LABORATORY_ARTIFACT`, or `ARTIFACT_DIGEST_MISMATCH` |
| 2. Failure/attempt lifecycle | `protocol/types.go`, `policy.go`, runner attempt logic, `docs/error-registry.md` | `failures.json`, lifecycle attempts/failures, adapter | one of six dispositions; exact snapshot/stage/actor/role/run binding; ordinal contiguous; retained failed attempt; only named transient retries; retry creates a new ID and immutable prior record | envelope round trip; hidden/orphan failure; ordinal gap; retry exhaustion; unknown error. Codes: `INVALID_FAILURE_BINDING`, `HIDDEN_FAILED_ATTEMPT`, `ORPHAN_FAILURE`, `NONCONTIGUOUS_ATTEMPTS`, `RETRY_BOUND_EXCEEDED`, `INVALID_ATTEMPT_OUTCOME` |
| 3. Content-addressed DAG | protocol bundle schema, reference/independent validators, checkpoint runner, Lab Zero graph fixture | `evidence-dag.json`, `lifecycle.json`, `evolution.json`, adapter | exact graph projection; unique typed IDs/edges; root reaches every node; digest binds bytes; current child scope; fresh dependency closure; immutable checkpoint resumption; public closure contains only public classifications and no protected tokens/raw diagnostics | mutate cycle, dangling edge, disconnect, digest, scope, staleness, checkpoint, and public reachability. Codes: `CYCLIC_GRAPH`, `DANGLING_EDGE`, `DISCONNECTED_EVIDENCE`, `DIGEST_MISMATCH`, `CROSS_COMPANY_REFERENCE`, `STALE_INPUT`, `ROOT_BINDING_MISMATCH`, `PROTECTED_DISCLOSURE`, `PROTECTED_PUBLICATION_DISCLOSURE` |
| 4. Developer tools | developer-tool schema, Lab Zero lifecycle tool validator, `profiles/lsp/qualification.json` | three tool-run artifacts referenced from `evidence-model.json` | exact JDT LS 1.60.0, rust-analyzer 2026-08-17.4, Rust Glancer v0.1.1; Glancer bounded and mutually exclusive; assurance claims and gate effects empty; failures/fallback never satisfy or veto gates | exact good profile plus wrong version, missing run, nonempty claim/effect, overlapping profiles, failed RA plus fallback. Codes: `INVALID_DEVELOPER_TOOL_RUN`, `MISSING_DEVELOPER_TOOL_RUN`, `LSP_ASSURANCE_BOUNDARY`, `LSP_PROFILE_OVERLAP`; navigation failure is `LSP_NAVIGATION_FAILURE/DEGRADE_NON_ASSURANCE` |
| 5. Good/bad fixtures | canonical adversarial corpus, passing/evolution fixtures, Lab Zero lifecycle, acceptance tests | `assurance/replay/fixtures/`, adapter tests, story acceptance test | synthetic good fixture may reach only its declared allowed state and carries no real-world assurance claim; every bad fixture produces the exact stable code/disposition and a nonzero CLI exit | bad receipt `EXTERNAL_RECEIPT_INVALID`; zero obligations `ZERO_PROOF_OBLIGATIONS` and `FORMAL_EVIDENCE_INVALID`; missing evidence `MISSING_EVIDENCE`; post-review mutation `REVIEW_SUBJECT_ROOT_MISMATCH` or `ROOT_BINDING_MISMATCH`; stale pin `STALE_INPUT`; role conflict `ROLE_CONFLICT`; leakage canary `PROTECTED_DISCLOSURE`/`REVOKE` |

## Frozen failure and retry rules

`assurance/failures.json` is a closed registry. It retains all parent codes and
may add child-specific codes only with an explicit disposition and test. An
unknown code is `BLOCK`. It must preserve both accepted names where parent
surfaces differ:

- `ORACLE_MISMATCH/BLOCK` and `ORACLE_DISAGREEMENT/BLOCK` are distinct aliases;
- protocol `PROTECTED_DISCLOSURE/QUARANTINE` remains valid for pre-publication
  quarantine, while a public-root reachability or leakage finding is the
  stricter `PROTECTED_DISCLOSURE/REVOKE` or
  `PROTECTED_PUBLICATION_DISCLOSURE/REVOKE`;
- no adapter silently rewrites one code into the other.

The automatic retry allowlist is exactly:

- `NETWORK_DENIED`
- `WORKER_INTERRUPTED`
- `STORAGE_UNAVAILABLE`
- `LEASE_EXPIRED`
- `QUARANTINE_UNAVAILABLE` only at the bounded ingest-storage operation

Every other failure is non-retryable unless an accepted parent rule explicitly
states otherwise. A retry appends a new `Attempt` and new command/nonce; it
does not alter or replace the failed attempt or its envelope.

## Single-owner assurance ceiling

The adapter starts with `protocol.JavaToRustPolicy()`, changes only the company
and project scope to `open-source-projects/verified-java-websocket-port`, and
binds the accepted `java-websocket-single-owner-1.0.0` amendment as additional
policy input. It must not remove graph, failure, retry, classification,
publication, or freshness checks.

Owner actions may satisfy the amendment's action-role authorization rules, but
they never create an `Attestation{Independent:true}` and never satisfy a gate
that explicitly requires independent evidence. Synthetic fixtures testing the
mechanics are labeled `SYNTHETIC_NON_CLAIM`. The actual US-004 result and public
contract remain `OWNER_ATTESTED_NOT_INDEPENDENT` with
`independent_review_claimed:false`.

## Primitive Test

| Capability | Atomicity | Bitter Lesson | ZFC | Placement |
|---|---|---|---|---|
| strict decode, canonicalization, digest and schema validation | naturally read-only and deterministic | unchanged for a stronger model | pure parsing/formatting | Go, inherited |
| root-confined immutable reads and all-or-none snapshot/checkpoint writes | concurrent substitution or partial state can corrupt evidence; atomicity required | unchanged | filesystem transport | Go adapter using parent primitives |
| DAG cycle/reachability, digest, role, staleness and classification checks | deterministic over one byte snapshot | unchanged | graph/data validation | Go, inherited validators |
| append attempts/failures and bounded resume | concurrent callers require serialized immutable ordinals/state | unchanged | state transport | Go runner/checkpoint implementation |
| choose oracle, claim scope, reviewer conclusion, readiness target, or whether a discrepancy is acceptable | not an atomic transport problem | a stronger model can reason better | contains judgment | declarative reviewed JSON or prompt/reviewer layer |
| select failure disposition or retry eligibility | registry is immutable input; validator only checks exact membership | policy judgment can improve, enforcement does not | judgment in registry, transport in code | declarative `failures.json`; Go enforces it |
| interpret developer-tool observations | no transport race | stronger review can improve | assurance judgment | declarative; Go only enforces empty assurance/gate effects |

No shell implementation is needed. New nontrivial transport belongs in Go.

## Test plan and back pressure

The implementation worker must add table-driven tests through the adapter
interface, not tests of copied helper internals:

1. exact inherited-schema and vendored-source digest reconciliation;
2. strict/canonical JSON, complete entity inventory, and lossless evolution;
3. reference/independent validator full-finding equality;
4. cycle, dangling edge, unreachable node, cross-company scope, stale edge,
   mutable substitution, role mismatch, and protected-public closure canaries;
5. immutable retry and checkpoint/resume tests, including prior-attempt byte
   preservation;
6. exact developer-tool versions, mutual exclusion, failed/fallback behavior,
   and empty assurance/gate effects;
7. bad receipt, zero obligation, missing evidence, post-review mutation, stale
   pin, role conflict, and leakage fixtures with exact codes/dispositions;
8. CLI verify/replay equality and nonzero exit on every finding.

Required commands from the target repository:

```text
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
go build ./...
go run ./cmd/assurectl verify --root . --lifecycle assurance/lifecycle.json
go run ./cmd/assurectl replay --root . --lifecycle assurance/lifecycle.json
```

The two CLI commands may report an honestly blocked owner-only lifecycle while
US-004 is being instantiated; success means deterministic agreement with the
declared expected state, not promotion to independent acceptance.

## Implementation handoff

The next worker should first vendor and reconcile the accepted parent byte set,
then write failing adapter tests before implementation. It must not change the
vendored dependency, create a parallel schema, perform a live Autobahn run,
publish, access production, push the branch, edit orchestration state, or mark
the PRD story passed. Any missing accepted source byte, digest drift, validator
disagreement, or ambiguity between a public and protected closure is a real
blocker and must be reported rather than repaired locally.
