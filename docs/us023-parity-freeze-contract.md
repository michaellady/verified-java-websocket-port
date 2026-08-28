# US-023 immutable parity-freeze contract

Status: owner-relaxed snapshot mechanics shipped at `9f5bdde`. The committed
candidate root is `sha256:dd96c5fb0346f736e6ddadf7848d34ceb5e4c2beefe77c1730bec6649516190e`
and the post-reality evaluation root is
`sha256:4f608c8f658dd287efef362bdfe027cf66116f95e1192810bce2fb3e1d83ce21`.
Real verification and replay return byte-identical `FROZEN/BLOCKED` verdicts;
this is not parity completion or READY.

US-023 freezes an honest, immutable description of the candidate. The snapshot
may be structurally valid while its parity verdict remains `BLOCKED`. That is
the only owner-relaxed completion: it closes the story mechanics without
turning unavailable authority, execution, review, or protected evidence into a
pass.

The original PRD remains authoritative and visible. In particular, both
blocking platforms, fresh human and declared-final Codex review, current Rust
Autobahn/protected execution, complete formal linkage, and zero unresolved
finding or divergence remain required for `READY`. They are not rewritten as
optional gates. Assurance never exceeds `OWNER_ATTESTED_NOT_INDEPENDENT`, and
`independent_review_claimed` is always `false` in US-023.

## Incumbent facts and claim boundary

- `assurance/evidence-dag.json` is the exact US-004 lifecycle projection used
  by the incumbent `assurectl` verifier. US-023 must not modify, extend, or
  reinterpret it. The new candidate graph binds that file as one immutable
  historical input.
- US-009 through US-022 evidence is useful only at its recorded subject,
  commit, tree, platform, bounds, and assurance. Retained evidence does not
  become a current-candidate run merely because its bytes are in the graph.
- The consumed/no-rerun Autobahn authority is immutable. US-023 launches no
  Autobahn, Docker, or `wstest` process and does not relabel synthetic US-019
  fixtures as conformance.
- The public verifier may open exactly the public projection files
  `corpora/hidden/manifest.json` and `corpora/sealed/manifest.json`. It never
  follows their artifact paths, enumerates protected storage, or tests whether
  a protected object exists.
- The freeze is internal, unsigned, non-published, and non-production. It makes
  no performance, cutover, `CUTOVER_READY`, publication, signing, or production
  claim.
- Human review is not available. `assurance/reviews/human.json` must therefore
  be an honest `NOT_EXECUTED` receipt with blocker
  `HUMAN_REVIEW_NOT_EXECUTED`; an AI receipt cannot occupy that slot.
- Reviewer, QA, and reality receipts created by later phases must name the
  actual provider `openai`, model `gpt-5.6-sol`, reasoning effort `xhigh`, and
  their real invocation IDs. A sole owner, another model, missing provenance,
  or a self-authored independence claim fails closed.

## Deep module seam

Extend `internal/assurance`; do not add another assurance framework. That
package already owns the strict lifecycle snapshot, root-confined `os.Root`
reads, stable-file checks, canonical paths, normalized findings, and
`assurectl` transport. Candidate verification should reuse those utilities and
the incumbent Git-object patterns from `internal/mutation`.

The complete new interface is:

```go
type CandidateMode string // VERIFY or REPLAY

type CandidateRequest struct {
    RootPath string
    Mode     CandidateMode
}

type CandidateVerdict struct {
    SnapshotState             string // FROZEN or INVALID
    ParityState               string // READY or BLOCKED
    CandidateRoot             string
    EvaluationRoot            string
    TargetCommit              string
    TargetTree                string
    Assurance                 string
    IndependentReviewClaimed  bool
    GateCounts                GateCounts
    Blockers                  []Blocker
    Findings                  []Finding
}

func EvaluateCandidate(context.Context, CandidateRequest) (CandidateVerdict, error)
```

The interface is the test seam. `VERIFY` checks the committed graph and exact
derived reports. `REPLAY` performs the same checks from the named immutable Git
objects and emits the same canonical verdict bytes; it starts no external
workload. All schema loading, Git resolution, graph construction, family
reconciliation, formal coverage derivation, review-chain validation, and report
rendering stay inside this module.

`assurectl` adds only:

```text
assurectl candidate-verify --root ABS
assurectl candidate-replay --root ABS
```

The artifact locations below are constants, not caller-selected paths. The CLI
rejects missing, repeated, unknown, relative, aliased, or trailing arguments.
Exit 0 means the snapshot is valid and exactly reproduced; it does **not** mean
`ParityState == READY`. Invalid structure, drift, or a dishonest status exits
1. A valid blocked snapshot exits 0 and reports every blocker.

### Designs considered

A single self-hashing manifest was rejected: including its own digest is
impossible, and adding review receipts to the candidate root creates a cycle
when a review targets that root. A generic plugin registry was also rejected;
there is one closed US-023 denominator and no second adapter.

The selected design uses one immutable candidate DAG/root and one external,
domain-separated evaluation root. The candidate root freezes implementation,
attempts, claims, and evidence and never changes when a receipt arrives. The
evaluation root, derived in `evidence/parity-replay.json`, attaches external
review/QA/reality receipts to that already frozen root. Neither root envelope
hashes itself. Deleting this module would scatter Git, graph, claim, review,
and coverage rules across the CLI and every story verifier, so the module has
depth, leverage, and locality.

## Exact artifact set

Implementation adds these closed Draft 2020-12 schemas:

```text
schemas/us023-candidate-manifest-1.0.0.schema.json
schemas/us023-claims-1.0.0.schema.json
schemas/us023-attempts-1.0.0.schema.json
schemas/us023-formal-obligations-1.0.0.schema.json
schemas/us023-review-receipt-1.0.0.schema.json
schemas/us023-parity-replay-1.0.0.schema.json
```

and these artifacts:

```text
assurance/candidate-manifest.json
assurance/candidate-claims.json
assurance/formal/obligation-catalog.json
assurance/reviews/codex.json
assurance/reviews/codex-targeted-closure.json
assurance/reviews/human.json
assurance/reviews/qa.json
assurance/reviews/reality.json
evidence/us023/attempts.json
evidence/parity-replay.json
docs/us023-parity-coverage.md
```

`assurance/evidence-dag.json` remains byte-for-byte incumbent US-004 evidence.
It is a required `HISTORICAL_DAG` node in the new manifest, not an output.

Every JSON object has `additionalProperties:false`; every field listed below
is required, including false booleans, zero counters, empty arrays, and nulls.
All arrays have fixed semantic order or are lexicographically sorted and unique.
All integers are checked nonnegative integers. Digests are lowercase
`sha256:` values. Parsing rejects duplicate keys at every depth, unknown fields,
trailing values, invalid UTF-8, noncanonical paths, and nonlocal schema
references.

### `assurance/candidate-manifest.json`

The manifest has exactly:

```text
$schema, schema_version, story_id, candidate_id,
snapshot_state, parity_state, assurance, independent_review_claimed,
publication, production, signing, performance_claimed, cutover_claimed,
target, graph, root_node_id, candidate_root, replay
```

`target` is `{commit,tree,object_format}` and identifies the freeze target which
contains the shipped Rust and the predecessor evidence it consumed. Later
content and evaluation nodes may use later committed Git anchors, but every
node's `subject_commit` and `subject_tree` must still equal the shipped target;
an evidence commit cannot silently change the subject. The root envelope itself
is excluded from its own hash.
The verifier resolves `commit^{commit}` and `commit^{tree}`, requires both
objects to be present in the verified checkout, and never fetches a missing
object.

The freeze uses three monotonic commits: (A) the shipped target, against which
all fresh attempts execute; (B) an evidence-only commit adding the resulting
attempts, claims, and catalog without changing the target source,
tests, lockfile, or configuration closures; and (C) the root-envelope commit
adding `candidate-manifest.json`, which binds A and every content object from
B. The verifier derives and restricts the A..B membership delta to the exact
US-023 evidence/schema paths. Review receipts are later commits and never
rewrite C. This protocol removes both Git self-reference and subject drift.

`graph` has sorted `nodes` and `edges`. A node is exactly:

```text
id, kind, classification, path, bytes, sha256, git,
subject_commit, subject_tree, family, execution_state, claim_strength
```

`git` is `{commit,tree,blob}`. File nodes bind raw bytes from
`git show COMMIT:PATH`; aggregate nodes bind the canonical NUL-delimited listing
of their complete member nodes. `kind` is one of `SOURCE`, `TEST`, `LOCKFILE`,
`TOOL`, `CORPUS_PUBLIC_PROJECTION`, `CONFIG`, `MIGRATION_MAP`, `DOSSIER`,
`COMPATIBILITY_SURFACE`, `DELTA_LEDGER`, `CLAIMS`, `ATTEMPTS`, `EVIDENCE`,
`FORMAL_CATALOG`, `SCHEMA`, `HISTORICAL_DAG`, or `ROOT_INPUT`.

An edge is exactly `{from,to,relation}`. Relations are `CONTAINS`, `BINDS`,
`DERIVED_FROM`, `EXECUTED_BY`, `VALIDATES`, `RECONCILES`, `MAPS_TO`,
`REFINES`, `SUPPORTS`, `DISCHARGES`, or `BLOCKS`. Node IDs are unique, edge
endpoints must exist, duplicate edges fail, the graph must be acyclic, and
every node must be reachable from its root input. A pass-shaped disconnected
node is invalid, not merely blocked.

The graph reachable from `root_node_id` includes source, tests, `Cargo.lock`,
tool receipts, public
corpus projections, configuration, semantic-ID migration map, Port Seam
Dossier, compatibility surface, behavior delta ledger, claims, attempts,
formal catalog, all US-009 through US-022 evidence families, schemas, and the
historical US-004 DAG. Membership comes from the target Git tree and fixed
prefix/explicit-file selectors, never solely from manifest rows. Omission and
addition therefore both fail. `candidate_root` is SHA-256 over a domain string,
target identity, and the complete canonical graph:

```text
US023-CANDIDATE-V1\0 || target_commit || target_tree || graph
```

Review receipts, `evidence/parity-replay.json`, and
`docs/us023-parity-coverage.md` are fixed-path attachments outside this graph.
They may point to `candidate_root`; candidate content has no edge back to them.
The verifier still requires their committed working bytes, Git identities, and
derivation to be exact.

### `assurance/candidate-claims.json`

This is the closed original requirement registry, not a relaxed replacement:

```text
$schema, schema_version, story_id, candidate_id, prd_identity,
gates, evidence_families, nonclaims, blocker_catalog,
assurance, independent_review_claimed, publication, production, signing
```

`prd_identity` records the exact US-023 acceptance-criteria and E2E text
digests. `gates` has one row for every requirement atom under the five original
criteria. A row is exactly:

```text
gate_id, criterion_id, required, requirement_sha256, subject,
required_state, observed_state, evidence_node_ids, blocker_ids
```

`required` is always true for original acceptance gates. `required_state` is
`SATISFIED`; `observed_state` is `SATISFIED` or `BLOCKED`. There is no
`SKIPPED`, `WAIVED`, `NOT_APPLICABLE`, percentage, weighted score, or default.
Every blocked row has at least one typed blocker and no pass claim. Every
satisfied row has evidence and no blocker.

`evidence_families` is the exact ordered denominator `RFC`, `AUTOBAHN`,
`HANDSHAKE`, `DIFFERENTIAL`, `PROPERTY`, `FUZZ`, `RUNTIME`, `FORMAL`,
`CONCURRENCY`, `MUTATION`, `HIDDEN`, `SEALED`. Each row separately records
required and observed state, current shipped-Rust connection state, evidence
node IDs, unresolved finding count, divergence count, and blocker IDs. No
family aggregate may hide a blocked family.

The closed blocker catalog includes at least:

```text
GATE_NOT_EXECUTED
BLOCKING_PLATFORM_NOT_EXECUTED
TOOL_UNAVAILABLE
JAVA_SOURCE_OBJECT_UNAVAILABLE
AUTOBAHN_AUTHORITY_CONSUMED_NO_RERUN
CURRENT_RUST_AUTOBAHN_NOT_EXECUTED
CURRENT_RUST_PROTECTED_NOT_EXECUTED
PROTECTED_CONTROL_NOT_EXECUTED
INDEPENDENT_HOST_UNAVAILABLE
HUMAN_REVIEW_NOT_EXECUTED
SOLE_OWNER_NOT_INDEPENDENT
FORMAL_BACKEND_UNAVAILABLE
FORMAL_REFINEMENT_DISCONNECTED
FORMAL_BOUND_OR_ASSUMPTION_INCOMPATIBLE
FORMAL_STRENGTH_OVERSTATED
UNRESOLVED_FINDING
UNRESOLVED_DIVERGENCE
MUTATION_SURVIVOR
```

Each blocker is `{blocker_id,code,gate_ids,subject,evidence_node_ids,detail_code}`.
`detail_code` is a closed enum, not free-form prose. Findings about malformed
or dishonest artifacts are distinct from blockers: a finding makes the
snapshot `INVALID`; a blocker makes a truthful snapshot `FROZEN/BLOCKED`.

Nonclaims must include no live Autobahn rerun, no protected case access, no
current Rust/control hidden or sealed execution without a receipt, no
independent review, no unavailable-tool pass, no performance result, no
cutover, no `CUTOVER_READY`, no signing, no publication, and no production.

### `evidence/us023/attempts.json`

Attempts are an append-only, sorted closed ledger:

```text
$schema, schema_version, story_id, candidate_id, target,
challenge_sha256, platform_attempts, verifier_attempts,
test_reconciliation, source_reconciliation, counts
```

Every attempt is exactly:

```text
attempt_id, gate_id, platform, architecture, execution_state, blocker_code,
argv, working_directory, environment_sha256, tool,
input_root, output_sha256, stdout_sha256, stderr_sha256,
exit_code, timed_out, duration_ms, observed_counts
```

`execution_state` is `EXECUTED_PASS`, `EXECUTED_FAIL`, `NOT_EXECUTED`, or
`UNAVAILABLE`. A non-executed row has null process fields and a typed blocker;
an executed pass has exact tool, input, output, and process evidence. Declared
commands alone never pass.

The two blocking platforms are exactly `darwin/arm64` and `linux/arm64`.
Both must bind Rust 1.95.0, Cargo `--locked`, and pinned JDK 17. Required rows
cover Java build and the canonical 62-class test selector; Rust debug/release
workspace build and tests; Rust formatting and Clippy with warnings denied; Go
tests and `go vet`; unsafe, dependency, license, vulnerability, and lockfile
verification; no-stub controls; source/test membership; zero skipped,
filtered, ignored, quarantined, timed-out, or silently undiscovered tests; and
exact Java/Rust test-manifest reconciliation. A platform receipt for another
target commit or tree cannot satisfy a row.

`test_reconciliation` derives its denominator independently of result counts.
It binds the accepted Java test inventory and the complete Rust test executable
and test-ID listings on each platform, then reconciles discovered, executed,
passed, failed, skipped, filtered, ignored, quarantined, and timed-out IDs.
Every predecessor test ID must remain, every current ID must be classified, and
set equality is checked before count equality. `source_reconciliation` compares
the complete target-tree source/test membership to the anchored US-022
before/after closure; additions are explicit, while any missing predecessor
path or ID blocks as a deleted test.

### `assurance/formal/obligation-catalog.json`

This catalog is language-neutral first and language-specific second:

```text
$schema, schema_version, catalog_id, denominator_basis,
obligations, java_bindings, rust_bindings, evidence,
coverage, assurance, independent_review_claimed
```

The denominator is derived from the exact compatibility surface, migration
map, Port Seam Dossier, RFC inventory, and incumbent formal target inventory;
it is not selected from passing evidence. Every obligation has exactly:

```text
obligation_id, surface_ids, statement, normative_refs,
required_strength, allowed_methods, required_evidence_kinds,
required_mutation_ids
```

Java and Rust bindings are separate arrays keyed by every `obligation_id`.
Each binding records language, fully qualified production symbol (including the
Java descriptor or exact Rust item identity), item kind, source path, source
SHA-256, Git/archive identity, declaration identity, reachability from the
shipped entry seam, and `CONNECTED` or `DISCONNECTED`. Adapter, test-only, and
proof-only duplicate symbols are forbidden subjects. Missing self-contained
Java bytes remain `DISCONNECTED` with
`JAVA_SOURCE_OBJECT_UNAVAILABLE`; a digest assertion is not source access.

Each evidence row records:

```text
evidence_id, obligation_id, subject_language, method, execution_state,
observed_strength, bounds, assumptions, trusted_base,
tool:{name,version,binary_sha256}, input_sha256s, output_sha256s,
refinement:{state,from_subject,to_symbol,artifact_sha256},
counterexample, mutation_sensitivity
```

Bounds and assumptions are canonical typed maps, not prose. Evidence may
discharge an obligation only when its observed strength is no stronger than
its method, its bounds/assumptions are compatible with the obligation, its
trusted base and all tool/input/output digests are present, both language
bindings are connected as required, refinement reaches the exact shipped Rust
symbol, no counterexample is open, and every required mutation is killed.
Model proof without checked refinement remains proof of the model only.
`counterexample` is a nullable digest-bound minimized witness;
`mutation_sensitivity` is a nonempty set of exact immutable-anchor mutant IDs
and dispositions for pass evidence. At least one is substantive for every
evidence row; an empty placeholder satisfies neither requirement.

`coverage` has exactly one row per denominator obligation and reports Java,
Rust, refinement, mutation, and aggregate status separately. The aggregate is
`SATISFIED` only when every required cell is satisfied; otherwise it is
`BLOCKED` with blocker IDs. Reports contain raw counts by exact status but no
weighted aggregate, percentage, or score.

### Review, QA, and reality receipts

The shared review schema contains:

```text
$schema, schema_version, receipt_id, role, review_kind, status,
provider, model, reasoning_effort, invocation_id, reviewer_identity,
candidate_root, target, scope, comments_only, findings,
remediation_target, parent_gate_node_ids, assurance,
independent_review_claimed
```

`role` is `CODEX_REVIEWER`, `HUMAN_REVIEWER`, `QA`, or `REALITY`.
`review_kind` is `FULL`, `TARGETED_CLOSURE`, or `NOT_EXECUTED`. Only one
Codex `FULL` review is permitted for a candidate lineage. It must target the
complete candidate root and be comments-only. Findings are closed records with
stable IDs and severity `BLOCKING`, `IMPORTANT`, or `NIT`.

If the full review has blocking correctness/security findings, only those
findings may be remediated. The fix produces a successor candidate root. The
immutable full receipt remains in `assurance/reviews/codex.json`; a separate
`assurance/reviews/codex-targeted-closure.json` receipt names exactly the
predecessor root, successor root, and original blocking IDs. It may not add new
review scope and counts as a closure only when its status is `EXECUTED`.
Targeted regression and parent gates bind the successor. There is no second
full review. Important findings and nits remain visible and unimplemented
unless separately authorized.

Review receipts are outside candidate content and point inward; this prevents
the candidate/review hash cycle. `evidence/parity-replay.json` binds their
exact bytes in its external evaluation root.
`human.json` is `NOT_EXECUTED` with null provider/model/invocation, an empty
finding array, and `HUMAN_REVIEW_NOT_EXECUTED`. It cannot say accepted.

### Machine and human reports

`evidence/parity-replay.json` is the canonical machine report. It contains the
target, candidate root, exact sorted receipt descriptors, external evaluation
root, snapshot/parity states, exact gate and evidence-family rows, every formal
coverage row, all blockers, all nonclaims, review-chain summary, and
zero/explicit finding and divergence counts. The evaluation root is:

```text
US023-EVALUATION-V1\0 || candidate_root || canonical(sorted receipt descriptors)
```

When blocking review findings caused a successor candidate, the descriptor
set retains the predecessor candidate root, full-review receipt, exact
remediation mapping, successor candidate root, and targeted closure. No review
receipt enters either candidate DAG. The report is entirely derived;
hand-edited status, receipt membership, or counts fail verification.

`docs/us023-parity-coverage.md` is rendered from that machine report with a
fixed heading/table order and no timestamp. It shows every original criterion,
evidence family, formal obligation, blocker, and nonclaim. The verifier renders
the expected bytes in memory and requires byte equality. The human report may
not replace blocked rows with prose such as “substantially complete.”

## Verification and replay algorithm

1. Open the caller's absolute repository with the incumbent root-confined
   reader. Snapshot only the hard-coded artifact set and schema set once with
   size limits and stable single-link regular-file checks.
2. Strict-decode and schema-validate every JSON document before using a path or
   digest from it. Scan decoded keys **and string values** for protected or
   secret-bearing material.
3. Resolve the target commit/tree using a sanitized Git process. Derive closed
   source, test, schema, corpus-projection, and evidence membership with
   `git ls-tree`; read bytes from Git objects and compare any admitted
   working-tree artifact. Missing objects block verification; no fetch occurs.
4. Permit the two public hidden/sealed manifest paths as exact exceptions.
   Reject every other hidden/sealed path before filesystem or Git access, and
   never follow any path found inside those manifests.
5. Recompute all file, aggregate, candidate, and external evaluation digests; graph
   reachability and acyclicity; claim/gate state; attempt counts; evidence
   family state; formal coverage; review lineage; and the machine/human report
   bytes.
6. Invoke incumbent verifiers through their existing interfaces for the
   historical lifecycle, formal preflight/replay, differential evidence,
   US-021 campaigns, US-022 mutation/protected projection, and Rust policy.
   Record their deterministic result as graph reconciliation; never substitute
   a new permissive parser or execute a workload.
7. In `REPLAY`, start from the same Git objects even if the current branch has
   advanced. Require the canonical verdict and reports to match `VERIFY`
   byte-for-byte. Current working-tree drift in any committed US-023 envelope
   is still an error.

`ParityState` is derived, never trusted. It is `READY` only if every original
gate and every formal coverage row is satisfied, both blocking-platform
attempt sets pass, all evidence families are connected to shipped Rust, all
finding/divergence/survivor counts are zero, and full human plus Codex review
requirements are satisfied. Otherwise it is `BLOCKED`. `SnapshotState` is
`FROZEN` only when the artifact is honest, immutable, complete as a status
snapshot, and exactly replayable.

## Hostile fixture and E2E contract

Fixtures clone a minimal target Git repository and recompute legitimate roots
where necessary, so tests exercise semantic checks rather than only stale
digests. The real `assurectl candidate-verify --root ABS` and
`candidate-replay` binaries are the final test surface.

Required hostile cases include:

| Variant | Required result |
| --- | --- |
| empty/stub Rust accepted or real Rust node disconnected | invalid with `STUB_ACCEPTED` or `SHIPPED_RUST_DISCONNECTED` |
| predecessor test path/ID deleted, renamed, filtered, ignored, or silently absent | invalid or blocked with exact test-reconciliation finding; never pass |
| first-party `unsafe`, build hook, dependency, lockfile, license, or vulnerability drift | invalid/blocked at its unaggregated gate |
| RFC/handshake/differential/property/fuzz/runtime case omitted or duplicated | invalid denominator/membership finding |
| unresolved divergence or finding relabeled zero | invalid derived-count finding |
| proof/model node disconnected from shipped Rust | blocked `FORMAL_REFINEMENT_DISCONNECTED` |
| incompatible bound or assumption accepted | invalid `FORMAL_BOUND_OR_ASSUMPTION_INCOMPATIBLE` |
| bounded/model evidence overstated as production proof | invalid `FORMAL_STRENGTH_OVERSTATED` |
| required mutation survives or is omitted from the anchor-derived denominator | blocked/invalid `MUTATION_SURVIVOR` |
| candidate, edge, node, artifact, Git blob, root, report, or review digest changed | invalid immutable-binding finding |
| second full review or targeted closure with a new finding/scope | invalid review-lineage finding |
| AI receipt placed in `human.json` or sole owner claims independence | invalid review/assurance overclaim |
| retained Java/Autobahn/protected result relabeled current Rust | invalid subject-lineage finding |
| protected artifact edge, path traversal, symlink, FIFO, hard link, or secret-bearing decoded value | reject before access with protected/path finding |
| performance, cutover, `CUTOVER_READY`, signing, publication, production, or stronger assurance claim | invalid overclaim |

The shipped protected-edge fixture places a FIFO decoy behind a forbidden path.
Closed graph-order/denominator validation rejects that shape before any decoy
access, while separate symlink, FIFO, hard-link, traversal, and decoded-secret
fixtures exercise the root-confined reader. The narrower
`PROTECTED_EDGE_FORBIDDEN` branch and an instrumented opener are not directly
reached by the fixed public graph shape; that limitation remains an important
review observation rather than a stronger coverage claim.

The positive E2E freezes and replays the exact valid report twice. In the
owner-relaxed repository that report is expected to be
`FROZEN/BLOCKED`, with unavailable original gates visible and zero verifier
findings. A fabricated `READY` positive fixture is forbidden.

## Implementation and test plan

1. Add schemas and fixture builders first. Pin the exact required gate,
   evidence-family, blocker, node-kind, edge, review, and formal vocabularies.
2. Extend `internal/assurance` with candidate snapshot loading, incumbent Git
   helpers, graph/root derivation, claim derivation, formal coverage, review
   lineage, and deterministic renderers. Reuse existing strict JSON and path
   logic; do not copy it into a story-local package.
3. Add `assurectl` transport and CLI usage tests. It must expose no filesystem
   paths other than `--root` and must not launch external gate workloads.
4. Add unit tests for strict schemas, anchor-derived membership, content roots,
   graph cycles/reachability, typed blockers, status derivation, report byte
   equality, and every formal compatibility rule.
5. Add the hostile matrix and a protected no-access spy. Exercise actual Git
   objects and the real CLI.
6. Materialize the candidate target before review. Run every locally available
   gate with pinned JDK 17, Rust 1.95, and Cargo `--locked`; record unavailable
   remote/protected/human gates as typed blockers, never skipped passes.
7. Invoke exactly one fresh comments-only complete Codex review using actual
   OpenAI `gpt-5.6-sol` at `xhigh`. Remediate only blocking
   correctness/security findings, if any, then run only targeted closure,
   targeted regression, parent gates, QA, and reality with exact provenance.
8. Commit external receipts, regenerate the evaluation root and reports, then
   verify and replay from a
   clean self-contained checkout. No performance, cutover, publication, or
   production step is part of US-023.

## Architecture completion criteria

Implementation is mechanically complete only when the positive
`FROZEN/BLOCKED` snapshot reproduces exactly, every hostile variant fails at
the real CLI with the intended typed result, the historical US-004 DAG still
passes its incumbent tests unchanged, and no protected path was followed.
Parity itself remains blocked until the original gates say otherwise. The
freeze must make that gap easier to audit, never easier to overlook.
