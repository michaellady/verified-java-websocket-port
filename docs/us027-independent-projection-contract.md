# US-027 independent acceptance and public projection contract

Status: **owner-relaxed mechanics contract; strong independent acceptance is blocked**

```yaml
story: US-027
mechanics_ceiling: PASS_OWNER_RELAXED_PUBLIC_PROJECTION_MECHANICS
acceptance_ceiling: INDEPENDENT_ACCEPTANCE_BLOCKED
assurance: OWNER_ATTESTED_NOT_INDEPENDENT
independent_review_claimed: false
production: false
publication: false
signing: false
```

## Decision and immutable subject

US-027 ships a deterministic, local-only evaluator and minimized projection. It
does not create the provenance-distinct verifier demanded by the original
story. The user authorized sole-owner protection and a relaxed completion
ceiling, so the evaluator must expose the missing independence rather than
manufacture it.

The evaluated port subject is the exact pre-evaluator Git object:

```text
commit 98ddff676fe336e22ca9ae4ee7b6f8c6c9025ddc
tree   36ee700401268621aae58639185dcdc11e4c00c6
```

US-027's Go evaluator, schemas, receipts, and projections are tooling around
that subject and are never folded back into it. A later documentation commit
may describe the result but cannot change the subject or upgrade its claim.

## Primitive Test and trust boundary

The evaluator belongs in code because the critical work is deterministic
transport: bounded exact-byte reads, digest binding, set-complete publication,
schema closure, projection minimization, and atomic ownership. Whether the
remaining evidence merits independent acceptance stays in the declared policy
and claim ceiling.

The package opens no socket, starts no subprocess, reads no clock, sleeps for no
duration, reads no credential, accesses no protected evaluator, signs nothing,
publishes nothing externally, and mutates no production state. All inputs and
outputs are ordinary files under one caller-supplied repository root.

## Incumbent inputs

`internal/projection` consumes only an exact allowlist of committed public or
owner-visible repository inputs. Capture binds each path, byte count, SHA-256,
and Git subject. At minimum the closure includes:

- `contracts/laboratory-template.json` for the required laboratory sections and
  publication rule;
- `assurance/candidate-manifest.json` and `assurance/candidate-claims.json` for
  the immutable US-023 candidate, 44 original gates, and claim ceilings;
- `assurance/formal/obligation-catalog.json` for the exact 24-obligation
  denominator;
- `assurance/reviews/human.json`, `assurance/reviews/codex.json`, and
  `assurance/reviews/reality.json` as historical owner-only review inputs;
- `evidence/cutover.json` for the US-026 mechanics and 12 retained cutover
  blockers;
- `security/release-firewall.json` for the incumbent local projection
  vocabulary, not for a new live security claim.

The canonical project PRD is not committed in this repository. Therefore the
26-child `passes:true` ledger is an explicit owner-provided mechanics registry,
not an independently recomputed acceptance fact. Its exact ordered IDs are
`US-001` through `US-026`; duplicates, gaps, reordering, unknown IDs, or any
non-mechanics result fail verification. This limitation remains a blocker.

Every input is opened from a root-pinned, no-follow filesystem boundary,
bounded before allocation, and read exactly once into held bytes. Symlinked or
non-directory ancestors, nonregular leaves, path escape, duplicate normalized
paths, mutation between metadata and read, unexpected sizes, or digest drift
fail closed before JSON parsing or projection.

## Receipt slots

The three required receipts share one closed schema and bind the same subject,
candidate root, projection contract, input-root digest, and acceptance ceiling:

| Path | Role | Truthful committed state |
| --- | --- | --- |
| `assurance/receipts/human.json` | `HUMAN_REVIEWER` | `NOT_EXECUTED` |
| `assurance/receipts/codex.json` | `CODEX_OWNER_REVIEW` | `OWNER_ATTESTATION_ONLY` |
| `assurance/receipts/reality.json` | `OWNER_REALITY_REPLAY` | `OWNER_ATTESTATION_ONLY` |

The Codex and reality slots may bind separately recorded owner phases, but
their provider is still OpenAI under the same owner-controlled project. None of
the three may set `independent:true`, `accepted:true`, or `protected_access:true`.
The human slot has no invented identity, signature, model, invocation, or
finding. Receipt replay, mixed subjects, mutated digests, upgraded roles, or an
independence claim fails verification.

## Independent-replay mechanics

`assurance/independent-replay.json` is deliberately named after the PRD output,
but its fields must make the absence of independence impossible to miss:

```text
mechanics_status       PASS_OWNER_RELAXED_PUBLIC_PROJECTION_MECHANICS
acceptance_state       INDEPENDENT_ACCEPTANCE_BLOCKED
child_story_count      26
child_mechanics_passed 26
strong_child_accepted  0
formal_obligations     24
formal_strong_accepted 0
formal_blocked         24
protected_replay       NOT_EXECUTED
human_review           NOT_EXECUTED
independent_custodian  NOT_BOUND
```

The evaluator reads all 24 obligation IDs from the held obligation-catalog
bytes, rejects duplicate or disconnected IDs and catalog count drift, and emits
them in lexical order. An obligation can be projected only as `BLOCKED`; no
formal backend, protected result, production linkage, or independent review is
replayed by this story. The machine report binds the canonical Markdown
projection digest, public snapshot digest, and receipt digests.

The exact strong blockers are:

```text
CANONICAL_PRD_NOT_REPOSITORY_BOUND
INDEPENDENT_CUSTODIAN_NOT_BOUND
HUMAN_REVIEW_NOT_EXECUTED
PROTECTED_EVALUATOR_ACCESS_NOT_EXECUTED
PROVENANCE_DISTINCT_REPLAY_NOT_EXECUTED
ORIGINAL_PARITY_GATES_REMAIN_BLOCKED
STRONG_CHILD_GATE_CLOSURE_NOT_ESTABLISHED
MEASURED_RESOURCE_ENVELOPE_NOT_ACCEPTED
LIVE_CUTOVER_NOT_ACCEPTED
SIGNED_ATTESTATION_NOT_AUTHORIZED
EXTERNAL_PUBLICATION_NOT_AUTHORIZED
PRODUCTION_DEPLOYMENT_NOT_AUTHORIZED
JAVA_REMOVAL_NOT_AUTHORIZED
```

The exact nonclaims are:

```text
no provenance-distinct custodian, identity, or independent review
no human review or protected evaluator replay
no strong acceptance of all child gates or formal obligations
no measured performance or live cutover acceptance
no ACCEPTED, PUBLISHED, signed, or externally published result
no production deployment or Java removal
```

## Safe local public projection

The release firewall emits only these local files:

- `public/snapshot.json` — subject commit/tree, derived projection root, scoped
  mechanics badge, aggregate counts, blocker codes, freshness/fallback state,
  supersession/revocation unknown states, and deterministic replay command;
- `public/formal-coverage.md` — the 24 public obligation IDs, each `BLOCKED`,
  aggregate 0/24 strong coverage, and the independent-acceptance ceiling;
- `public/README.md` — a short human-readable statement of what the local
  projection proves and why strong acceptance remains blocked.

The public projection contains no hidden/sealed/protected path, case ID,
expected output, raw diagnostic, stderr/stdout body, credential, environment,
machine identity, invocation transcript, private receipt detail, signature, or
external URL. Digests and public blocker codes are allowed. A recursive
allowlist plus byte scanner rejects prohibited path components, field names,
content markers, control bytes, symlinks, devices, nested unexpected files, and
unclassified descendants.

The public snapshot uses only these conservative states:

```text
badge          OWNER_RELAXED_MECHANICS_COMPLETE_INDEPENDENCE_BLOCKED
freshness      SUBJECT_PINNED_NO_EXTERNAL_FRESHNESS_AUTHORITY
java_fallback  RETAINED_SOURCE_NOT_EXECUTABLE_DRILLED
supersession   UNKNOWN_NOT_AUTHORITY_BOUND
revocation     UNKNOWN_NOT_AUTHORITY_BOUND
publication    LOCAL_FILES_ONLY_NOT_PUBLISHED
```

`ACCEPTED`, `PUBLISHED`, `CUTOVER_READY`, an independent badge, or a production
claim is unreachable in types, schemas, fixtures, CLI summaries, and Markdown.

## Complete-set publication

`projectionctl capture --root DIR` derives all seven PRD artifacts. While an
exclusive adjacent lock is held, it preflights every destination and accepts
only:

1. zero existing artifacts, for a first capture; or
2. all seven existing byte-exact artifacts, for idempotent verification.

Any 1–6-file set fails before creating or repairing anything. First publication
uses same-directory owner-only temporary files, file sync, atomic no-replace
links, owned-temp cleanup, and parent-directory sync. A destination that appears
after preflight is preserved and capture fails. The evaluator never overwrites,
truncates, follows, or repairs evidence it does not exclusively own.

`projectionctl verify --root DIR` rederives all seven outputs from held input
bytes, validates all three JSON schemas and cross-digests, byte-compares every
artifact, scans the public subtree, and exits nonzero on any drift. Running
capture twice must leave all seven byte-identical.

CLI exits are fixed:

```text
0  complete owner-relaxed mechanics; strong acceptance remains blocked
1  input, artifact, schema, projection, lock, or provenance failure
2  invalid command or arguments
```

## Closed schemas

The three Draft 2020-12 schemas are closed (`additionalProperties:false` at
every object) and make all safety ceilings constants:

- `schemas/us027-receipt-1.0.0.schema.json`
- `schemas/us027-independent-replay-1.0.0.schema.json`
- `schemas/us027-public-snapshot-1.0.0.schema.json`

Markdown outputs are derived from typed values and exact-compared; they are not
parsed back as authority.

## Test contract

The implementation starts RED at public `Capture`/`Verify` and CLI seams. Green
requires:

- exact subject, input, receipt, 26-child, and 24-obligation binding;
- exactly 26 mechanics-passed children, 0 strongly accepted children, 24
  blocked obligations, and 0 strongly accepted obligations;
- three truthful same-subject receipt slots with independence false;
- deterministic seven-artifact capture, verify, and byte-identical recapture;
- closed-schema validation and cross-digest recomputation;
- public-tree allowlisting and a zero-protected-marker scan;
- mutation rejection for subject, tree, candidate root, input digest, receipt
  role/status/independence, child gaps/duplicates/order, obligation
  gaps/duplicates/order, counts, blocker/nonclaim sets, projection roots,
  Markdown, badge, freshness, fallback, supersession, and revocation;
- rejection of traversal, symlinked ancestors/leaves, nonregular files,
  oversized inputs, partial bundles, stale locks, concurrent destination
  appearance, schema extras, truncation, and post-capture drift;
- source scan proving no network, subprocess, clock, sleep, signing, external
  publication, or production mutation path.

Review iteration is bounded to one full comments-only pass. Only blocking
correctness or security findings may be remediated; the same reviewer may run
one targeted closure, never a second full review. QA and reality then run the
real CLI from disposable storage and a clean checkout at the exact evaluator
head. Those owner-controlled phases can validate the mechanics but cannot raise
the committed assurance ceiling.

## File plan

Implementation is limited to the 17 locked US-027 paths:

```text
assurance/receipts/{human,codex,reality}.json
assurance/independent-replay.json
public/snapshot.json
public/formal-coverage.md
public/README.md
docs/us027-independent-projection-contract.md
internal/projection/{projection,artifacts}.go
internal/projection/{projection,artifacts}_test.go
cmd/projectionctl/main.go
cmd/projectionctl/main_test.go
schemas/us027-receipt-1.0.0.schema.json
schemas/us027-independent-replay-1.0.0.schema.json
schemas/us027-public-snapshot-1.0.0.schema.json
```

No Autobahn rerun, protected access, signing operation, repository creation,
external publication, live deployment, or Java removal is authorized.
