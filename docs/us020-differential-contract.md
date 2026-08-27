# US-020 Differential Contract

Status: architecture only; no US-020 implementation or differential result is claimed here.

Repository anchor: `40fb3db800250f6a33ea3c0e1e0eaabac60df53f` on
`codex/race-catchup`. This design is valid only for that tree and its committed
public inputs. An implementer must re-audit any anchor drift before using it.

## Claim boundary

US-020 will establish a fresh, out-of-process comparison of the 74 committed
public neutral scenarios against the pinned Java oracle and the current Rust
connection implementation. The comparison is field-addressed: state, ordered
events/frames, close outcome and origin, error class, bytes consumed, wire bytes
buffered, and message bytes buffered remain independently adjudicable.

The existing public manifest says that 74 scenarios were selected, executed,
and passed by the reference-model pipeline. That is not a live Java-versus-Rust
result. The existing Java behavior-delta ledger is empty and pending a
baseline. US010 through US019 provide useful predecessor evidence, but none of
them constitutes the US-020 run described here.

The answer to “are all 74 public scenarios currently expressible through the
shipped Rust APIs?” is **no**:

* 72 scenarios have an action vocabulary which the current driver can submit;
  two (`us005.pub.0012` and `us005.pub.0063`) require an outbound fragmented
  send which `LocalCommand` cannot express;
* the public driver result does not expose the exact partial-consumed and
  internal wire/message-buffered counters required by the corpus, so none of
  the 74 can yet produce the complete comparison observation through only the
  shipped public interface; and
* driveability is not conformance. In particular, the current closed-state EOF
  and zero-byte transport behavior is expected to produce real deltas which
  US-020 must discover and adjudicate rather than hide in the adapter.

Open, Closing, and Closed initial states do **not** require a mutable test-only
constructor. They are reachable through the real public state machine as
specified below.

## Design twice

### Design A: general raw-trace differential framework — rejected

One option is a generic runner which gives both implementations arbitrary raw
WebSocket byte streams, reparses every output frame in Go, invents a common
state model, and lets plugins normalize future implementations. It appears
flexible, but it creates a second protocol parser and a second state machine.
That parser would duplicate masking, fragmentation, UTF-8, close, and partial
consumption rules already owned by the Java adapter and Rust core. A difference
between the framework and either implementation would then be indistinguishable
from a product difference. Its plugin surface also makes freshness, bounds, and
normalization erasure much harder to audit.

### Design B: one corpus-specific differential module — selected

Add one deep Go module, `internal/differential`, whose narrow facade owns the
entire operation:

```go
func RunPublicDifferential(ctx context.Context, cfg Config) (Receipt, error)
func VerifyPublicDifferential(repositoryRoot string, receiptBytes []byte) error
```

It loads only the incumbent committed public corpus, verifies its generated
projection, launches the incumbent pinned Java adapter and a narrow Rust
testee route, normalizes typed observations, applies the oracle hierarchy,
minimizes mismatches, appends adjudications to the canonical ledger, reconciles
the migration/compatibility inventories, runs the seven controls, and writes
one evidence bundle. None of those policies leak into callers.

The Java side continues to receive the existing JSONL oracle request. The Rust
side receives the same typed scenario over a bounded, versioned transport
envelope and drives the existing owner/core. The Go module canonicalizes both
typed responses; it never reparses WebSocket bytes or predicts protocol
behavior. This is the smallest seam which preserves the exact scenario step
order, uses the incumbent Java oracle/corpus, and makes process freshness
auditable.

The existing `internal/lab.OracleRequest` is intentionally not reused. It
groups input chunks before actions, omits fragment/EOF/zero-chunk distinctions,
and treats an expected Java error response as process failure. Reusing it would
change the public scenario rather than compare it. The existing
`internal/corpora` model and Java projection are reused.

## Public API and command line

`Config` is an explicit value, with no environment fallback:

```go
type Config struct {
    RepositoryRoot       string
    PublicCorpus         string
    JavaExecutable       string
    JavaAdapterJar       string
    JavaRuntimeJar       string
    JavaSupportJars      []string
    RustTestee           string
    MigrationInventory  string
    CompatibilitySurface string
    LedgerPath           string
    EvidencePath         string
    OracleHierarchyPath  string
    ScenarioTimeout      time.Duration
    SuiteTimeout         time.Duration
    MinimizationBudget   Budget
}
```

All paths must be absolute, clean after canonicalization, regular files (or the
repository root), and below the explicitly allowed root where applicable.
Symlinks, duplicate aliases, non-regular inputs, output/input aliasing, and
identity drift fail closed. Runtime identity is supplied by path plus SHA-256;
the runner does not search `PATH`, Maven caches, Cargo targets, or the network.

The sole CLI is a transport wrapper over the facade:

```text
differentialctl run \
  --repository-root ABS --public-corpus ABS \
  --java-executable ABS --java-adapter ABS --java-runtime ABS \
  --java-support ABS[,ABS...] --rust-testee ABS \
  --migration-inventory ABS --compatibility-surface ABS \
  --ledger ABS --oracle-hierarchy ABS --evidence ABS

differentialctl verify \
  --repository-root ABS --evidence ABS --ledger ABS \
  --oracle-hierarchy ABS
```

Unknown, repeated singleton, empty, relative, or trailing positional arguments
are usage errors. `run` exits zero only when all primary and replay observations
are stable, every field is adjudicated, all coverage rows reconcile, all seven
controls are detected, and the ledger/evidence commit succeeds atomically.
`verify` is read-only and independently validates schema, hashes, source/input
identities, process receipts, normalization loss audits, decision cells,
coverage, controls, and the ledger chain. It never silently upgrades evidence.

## Exact Rust process seam

The testee gains one non-network route:

```text
websocket-testee neutral-oracle --protocol NDRV1
```

Each child accepts exactly one length-prefixed `NDRV1` record on standard
input, rejects trailing bytes, emits exactly one length-prefixed `NOBS1` record
on standard output, and exits. A record contains the corpus ID, role, requested
initial state, ordered steps, exact byte chunks (including zero length), typed
actions, and exact limits. The response contains raw, ordered core/driver
observations and accounting snapshots. This small dependency-free codec is
only process transport; it contains no WebSocket opcode, frame, masking,
fragmentation, UTF-8, close, or error-class logic. Go parses the committed
scenario once and projects it to both incumbent Java JSONL and `NDRV1`.

The Rust route is an adapter over `ConnectionOwner`/`ConnectionCore`. It may not
special-case a corpus ID, consult expected output, rewrite an error, reorder an
event, infer consumed bytes from the submitted chunk, or parse emitted
WebSocket frames. The following are the only core-facing changes allowed:

1. `LocalCommand::SendFragment { kind, final_fragment, payload }`, together
   with the private outbound-fragment state and existing frame encoder path.
   This is the **only genuine protocol-behavior extension** in US-020.
2. A read-only per-step accounting/trace observation, populated at the existing
   decoder, fragment buffer, state transition, and outbound encoder seams. It
   reports what the core did; it cannot mutate state or select behavior. This
   is instrumentation, not another protocol implementation.

The trace must expose exact input bytes consumed even on a partial header
failure, wire bytes retained after the step, message bytes retained after the
step, pre/post public state, ordered semantic events, ordered outbound frame
descriptions, close outcome/origin, and typed error. Existing public production
behavior remains the authority; the neutral route cannot derive these values
after the fact.

### Initial-state bootstrapping

Every Rust child starts from `ConnectionCore::new`; there is no `with_state`,
friend mutation, feature-gated setter, or fixture-only constructor.

* **Open:** perform the real deterministic client or server handshake through
  the owner. The client uses the fixed US-020 nonce/request plus its canonical
  valid response; the server receives the canonical valid request. A bootstrap
  receipt records all bytes and events, which are validated and then excluded
  from the scenario observation.
* **Closing:** bootstrap Open, submit a deterministic local normal close, drain
  the generated write through the normal driver and acknowledge `WriteFlushed`.
  The peer close has not arrived. Validate state `Closing`, discard bootstrap
  observations, then begin step zero.
* **Closed:** bootstrap Closing, feed the deterministic matching peer close and
  complete the normal clean-close transition. Validate state `Closed`, discard
  bootstrap observations, then begin step zero.

Bootstrap failure is infrastructure failure, not a scenario mismatch. The
initial close was initiated before the measured scenario, so the normalized
scenario-level origin is `unknown_before_scenario` until a measured step
creates a local or remote origin. The evidence retains the bootstrap transcript
and digest separately, preventing discarded setup activity from being mistaken
for absent activity.

Java continues to use the incumbent adapter's explicit initial-state facility;
the runner records this asymmetry. The semantic comparison begins only after
both sides prove the requested public state.

## Normalized observation contract

For each scenario, runtime, and attempt, the runner preserves an immutable raw
response digest and produces the following canonical structure:

```text
scenario_id, role, requested_initial_state, limits
bootstrap: {method, pre_state, post_state, transcript_sha256}
steps[]:
  index, input:{kind, action?, bytes_sha256?, bytes_length?}
  pre_state, post_state
  bytes_consumed
  wire_buffered_bytes, message_buffered_bytes
  observations[] (original order):
    event:{kind, payload_base64?, text?, close_code?, close_reason?}
    frame:{direction, fin, opcode, masked, payload_base64, wire_length}
    state_transition:{from,to}
    close:{code?,reason?,clean,origin}
    error:{class,terminal,message_category?}
final_state, terminal_close, raw_sha256, normalized_sha256
normalization_loss[]:{json_pointer,rule,before_sha256,after_value}
```

Integers are unsigned decimal values with checked range; byte values are
canonical base64; absent, empty, zero, and null are distinct. Array order is
semantic. Error **class** is semantic; implementation-specific prose may be
mapped to a stable `message_category`, but it is never used to erase a class
difference. Close origin is one of `local`, `remote`,
`unknown_before_scenario`, or `none` and is separate from clean/code/reason.

The only permitted nondeterminism erasure is a client masking-key value or the
corresponding masked wire octets when the semantic observation already retains
opcode, FIN, mask-present, unmasked payload, and exact wire length. Masking
presence and payload are never erased. No state, event, ordering, close, error,
consumption, length, or buffering field may be dropped. Every erased pointer is
recorded in `normalization_loss`; an unlisted erasure fails verification.

The runner also constructs a lossless pre-normalization fingerprint. If two
different lossless observations produce the same normalized digest outside the
explicit masking equivalence above, that is `NORMALIZATION_COLLISION` and the
suite fails. A difference inside the allowlist must still be reported by the
loss audit; it is not silently ignored.

## Fresh execution and reproducibility

For each of the 74 scenarios the runner starts a fresh Java process and a fresh
Rust process for a primary attempt, then repeats both in fresh processes for a
stability attempt. Thus a clean suite has exactly 296 child-process receipts:
`74 scenarios × 2 runtimes × 2 attempts`. No child handles a second scenario.
The runner supplies a minimal fixed locale/time-zone environment, closes all
unneeded descriptors, uses empty temporary homes below a private suite
directory, and disables network access by construction of the selected
adapters. It captures exit status, start/end monotonic time, executable digest,
stdin/stdout digest and byte count, and bounded stderr digest. The raw response
is retained in evidence only when it is public and bounded.

Primary and stability normalized results must be byte-identical within each
runtime. A changed mismatch signature or an agreement which fails to replay is
`FLAKE`, blocks the suite, and is not adjudicated away. Process creation and
input/output digests prove a fresh invocation, not a cryptographic attestation
of an uncontaminated host; that limitation is an explicit nonclaim.

Source/input provenance includes the repository anchor and clean relevant-path
status, committed public corpus and manifest digests, corpus generator/source
digests, Java executable/adapter/runtime/support digests and declared
Java-WebSocket `1.6.0` identity, Rust executable plus relevant Rust source,
`Cargo.lock`, rustc/Cargo identities, Go runner source and toolchain, migration
and compatibility inventory digests, schema digests, and ledger pre/post head.
Any relevant dirty path, missing input, executable/source mismatch, or changed
input between primary and stability attempts fails closed.

The loader uses an exact allowlist rooted at the named public files. It must not
enumerate, open, digest, report the existence of, or derive identifiers from
hidden/sealed corpus locations. A configuration path containing or resolving
through a hidden/sealed component is rejected before access.

## Oracle hierarchy and adjudication

`evidence/oracle-hierarchy.json` is a committed, schema-validated set of
field-addressed decision cells. A cell names a scenario and JSON pointer,
records the available evidence, and selects the first applicable authority:

1. a cited RFC clause which decides that exact field;
2. a retained result from a selected, pinned, directly applicable Autobahn
   case;
3. the independent committed neutral expectation;
4. pinned Java behavior;
5. current Rust behavior.

Rank is not assigned to an entire scenario. For example, an RFC may govern the
close code while neither the RFC nor Autobahn governs the project-local error
class or retained-byte counter. “Applicable” therefore requires an exact field
mapping and evidence digest. A generic RFC citation or unrelated Autobahn case
does not outrank the neutral result. No Autobahn run is authorized or required
by this design; rank 2 is usable only where a selected retained result already
exists and applies.

The committed neutral expectations are reference-model-derived pending oracle
confirmation; the evidence must not relabel every field as RFC-derived. Java
and Rust agreement at ranks 4 and 5 never overrides ranks 1 through 3. A field
with no higher evidence may be described as observed compatibility, not RFC
correctness.

Each Java/Rust difference receives exactly one current classification:

* `java_quirk`: Rust agrees with the selected higher authority and Java does
  not. Rust must not emulate the quirk.
* `rust_defect`: Java agrees with the selected higher authority and Rust does
  not. The finding is retained, the Rust behavior is remediated, and a new
  primary/stability pair must close it.
* `underspecified`: no available higher authority decides the field, or the
  available authorities conflict. This blocks completion until an explicit
  owner/architecture decision selects behavior; the decision is appended, not
  backfilled.

An oracle conflict, absent decision cell, stale citation/result digest, or
unresolved current mismatch blocks. Agreement is also recorded with the
selected cell so that a future change is reproducible.

## Deterministic mismatch reduction

Before minimization, a mismatch must reproduce in the normal stability attempt
with the same differing JSON pointers, authority selection, and classification.
The minimizer then launches fresh paired children and applies a fixed greedy
order:

1. remove whole steps while preserving requested initial state;
2. remove contiguous ranges from transport chunks or action payloads;
3. shrink payloads to empty, one byte, and boundary prefixes/suffixes;
4. shrink numeric limits toward zero, one, exact observed boundary, and
   boundary minus/plus one; and
5. simplify close code/reason or fragment kind/finality without changing the
   mismatch signature.

A candidate is accepted only if both runtimes complete, both attempts are
stable, and the same normalized pointer/classification remains. The original
scenario is never changed. The reducer is capped at 128 candidates and 10
minutes per mismatch, with a suite-wide cap of 512 candidates and 30 minutes.
Budget exhaustion retains the smallest known public reproducer and blocks with
`MINIMIZATION_INCOMPLETE`; it never drops the finding.

The evidence embeds the minimal ordered scenario, its canonical bytes/digest,
the exact one-scenario reproduction command with absolute paths replaced by
named provenance references, and raw/normalized observation digests. The
reproducer contains public material only.

## Canonical append-only ledger

US-020 extends the existing canonical
`evidence/java/behavior-delta-ledger.json`; it must not create a parallel
`evidence/behavior-delta-ledger.json`. Because schema 1.0.0 cannot express the
three US-020 classifications and requires Autobahn evidence for every entry,
implementation adds `schemas/behavior-delta-ledger-1.1.0.schema.json` and
migrates the currently empty ledger in place before its first append.

Append semantics are:

* records have a contiguous sequence, stable `delta_id`, canonical record
  digest, `previous_digest`, finding observation/reproducer digests,
  field-addressed oracle decision, classification, adjudication evidence,
  and optional remediation plus closing-run receipts;
* existing canonical records must be an exact immutable prefix. An exclusive
  lock plus expected-head compare-and-swap guards each append. Same ID and same
  canonical record is an idempotent no-op; same ID with different content is a
  conflict;
* the file and evidence bundle are staged, fsynced, validated, and atomically
  renamed only after all suite gates pass. Failure leaves the pre-run ledger
  byte-for-byte intact; and
* a Rust defect remains historically visible after remediation. A Java quirk
  remains visible without a Rust emulation. An underspecified record gains a
  later decision/closure record; history is never edited.

The final suite may contain historical closed quirks/defects but has zero
unexplained or unresolved **current** mismatches, zero flakes, zero missing
observations, and zero normalization collisions.

## Migration and compatibility reconciliation

The implementation reads, but does not rewrite, the committed 47-row semantic
migration map (90 slice references, 10 distinct slices) and 14-item
compatibility surface. The evidence emits one reconciliation row per original
row/item with its source JSON pointer and digest. There is no inferred coverage
by substring or feature name.

Each in-scope post-handshake row/item names at least one exact US-020 public
scenario and the field pointers which exercise it. A single scenario may cover
multiple rows only through explicit mappings. Capability-excluded rows and the
eight explicitly excluded surfaces retain their original status/reason and are
outside the in-scope numerator; they are never marked covered.

The public neutral corpus is post-handshake. Client/server handshake rows and
items are therefore bound to their exact US010/US011 predecessor vectors and
evidence digests with `fresh_us020=false`; US017 supplies concurrency ownership
evidence and US018 supplies byte-stream adapter evidence where the neutral
scenario does not execute those topology properties. These bindings satisfy
inventory reconciliation, not fresh Java/Rust differential execution. Missing,
stale, ambiguous, capability-excluded-without-reason, or zero-vector in-scope
rows fail the suite.

The resulting coverage summary reports separate totals for:

* fresh US-020 scenario coverage;
* predecessor-evidence bindings;
* capability-excluded rows/items; and
* unresolved/missing/ambiguous rows (required to be zero).

This avoids both false “74 scenarios cover handshakes” claims and false gaps
caused by demanding a post-handshake scenario prove an excluded topology.

## Seven mandatory seeded controls

Controls run against synthetic copies of already captured **public** typed
observations. They never mutate the product binaries, oracle files, ledger, or
committed corpus. Each seed has a fixed ID/digest, exactly one intended
mutation, an expected detector code, and a negative assertion that no other
classification is accepted:

| Control | Seeded difference | Required result |
|---|---|---|
| Java quirk | Change one Java field while Rust and a rank 1–3 cell agree | `java_quirk` |
| Rust semantic defect | Change one Rust field while Java and a rank 1–3 cell agree | `rust_defect` |
| Event order | Swap two otherwise identical observations | `EVENT_ORDER_MISMATCH` |
| Error class | Substitute only the stable error class | `ERROR_CLASS_MISMATCH` |
| Close initiator | Substitute only close origin | `CLOSE_ORIGIN_MISMATCH` |
| Consumed byte | Add one to a valid partial-consumed count | `CONSUMED_BYTES_MISMATCH` |
| Normalization collision | Give two lossless raw observations the same normalized digest through an unapproved erasure | `NORMALIZATION_COLLISION` |

The control receipt records that all seven failed before the expected detector,
that the unmodified baseline passed, and that no control artifact entered the
real ledger. A detector that merely notices “some JSON changed” is insufficient:
the exact semantic path and code must match.

## Evidence and schema products

Implementation creates or updates exactly these US-020 products:

* `evidence/differential/manifest.json` — complete suite receipt, all 296
  process receipts, normalized observations/digests, stability results,
  reconciliation, controls, runtime bounds, source/input identities, and
  ledger pre/post heads;
* `schemas/differential-evidence-1.0.0.schema.json` — closed schema for that
  bundle, including bounded arrays/counts and exact enum domains;
* `evidence/oracle-hierarchy.json` and
  `schemas/oracle-hierarchy-1.0.0.schema.json` — reviewed, field-addressed
  authority cells and evidence digests;
* `evidence/java/behavior-delta-ledger.json` and
  `schemas/behavior-delta-ledger-1.1.0.schema.json` — canonical append-only
  history and its upgraded closed schema.

Minimal reproducers, coverage rows, controls, and raw public response receipts
are embedded in the manifest so there is one transactional evidence root, not
several files which can drift independently. Oversized child stderr is stored
only as its digest and an explicit truncation failure; no secret-bearing
environment value is captured.

The manifest status is `PASS` only with: 74 exact scenario IDs, 296 valid fresh
process receipts, zero primary/replay instability, zero current unresolved
differences, a valid ledger chain, all in-scope inventory rows/items mapped,
zero missing/ambiguous/collision/flake counts, seven detected controls, and all
runtime/provenance bounds satisfied.

## Resource bounds and hostile tests

Normal execution is serial to keep ordering and resource contention auditable.
Each child receives 5 seconds, 4 MiB stdout, 4 KiB stderr, 4 MiB input, 64 open
descriptors, and no inherited stdin after its single record. The primary plus
stability suite receives 15 minutes. Minimization has the separate finite
budgets above. A killed, timed-out, signaled, over-output, extra-output,
trailing-input, or nonzero child is infrastructure failure and is never turned
into a semantic result.

Required hostile tests include:

* relative/symlink/FIFO/device paths, input-output aliases, path swaps after
  validation, executable digest drift, dirty relevant source, and corpus
  digest drift;
* truncated/oversized/trailing `NDRV1` and `NOBS1`, unknown tags, duplicate
  fields, integer overflow, impossible state transition, invalid base64 from
  Java, extra JSONL responses, stderr overflow, timeout, signal, and exit-zero
  with malformed output;
* step reordering, interleaved action loss, zero chunk versus absent chunk,
  empty versus absent payload, partial consumption, retained fragment bytes,
  outbound fragments, and all three bootstrapped initial states;
* prohibited normalization erasure, unknown error mapping, ordered-array sort,
  close-origin collapse, raw digest substitution, and all seven controls;
* stale/ambiguous/missing oracle cells, lower-rank agreement attempting to
  override a higher rank, generic RFC citations, inapplicable retained
  Autobahn results, and rank gaps;
* ledger prefix rewrite, broken chain/head, stale compare-and-swap, duplicate
  ID conflict, interrupted atomic write, validation failure after staging, and
  two concurrent appenders; and
* missing/duplicate migration rows, fake handshake-to-neutral mappings, stale
  predecessor digests, excluded rows counted in-scope, and a zero-vector
  in-scope compatibility item.

Tests use bounded fixtures and fake child executables supplied as test helpers;
they do not invoke Docker, Autobahn, `wstest`, Linux, the network, or hidden
content.

## RED → GREEN → REFACTOR plan

Implementation must preserve these independently visible RED stages:

1. **Facade/process RED:** tests require exact public IDs, ordered projection,
   two fresh children per runtime/scenario, bounds, pinning, and hostile process
   rejection. They fail because `internal/differential` and the Rust route do
   not exist.
2. **Rust expression RED:** process tests feed the two outbound-fragment
   scenarios and the Open/Closing/Closed bootstrap fixtures. They fail because
   `SendFragment`, trace accounting, and `neutral-oracle` do not exist. GREEN
   adds only the fragment behavior extension plus read-only observation
   plumbing and real transition bootstraps.
3. **Normalization/control RED:** golden typed observations fail exact ordering,
   error/close/counter comparison and each of the seven seeds. GREEN implements
   the closed normalizer and loss/collision audit without parsing WebSocket
   bytes.
4. **Hierarchy/minimizer RED:** conflicting field cells and a multi-step seeded
   mismatch fail ranking and bounded reduction. GREEN implements exact-pointer
   authority selection and deterministic fresh-child minimization.
5. **Ledger RED:** an empty 1.0.0 ledger cannot represent classifications; chain,
   conflict, crash, and concurrent-append tests fail. GREEN adds schema 1.1.0,
   empty-ledger migration, compare-and-swap append, and atomic commit.
6. **Coverage/evidence RED:** all 47 migration rows and 14 compatibility items
   must reconcile without pretending handshake evidence is fresh. GREEN emits
   the complete closed manifest and independent verifier.
7. **Reality RED:** build the pinned Java oracle and Rust testee, then run the
   actual 74-scenario primary/stability suite. Any stable delta produces a
   retained reducer/ledger finding. Fix only blocking Rust correctness/security
   defects, rerun fresh affected pairs and the final suite, and stop when the
   stated zero-current-mismatch gates pass.

Refactor only after each stage is green. Do not loosen a detector or edit a
corpus expectation to make a product result pass. A stable underspecified case
requires the explicit decision described above.

## QA and reality commands

These are the expected local commands after implementation. All explicit paths
must refer to the pinned materialization used by the evidence; placeholders are
resolved before execution and recorded by digest.

```sh
go test ./internal/differential ./cmd/differentialctl -count=1
make -C rust gates
make -C java-oracle test
go test ./... -count=1

go run ./cmd/differentialctl run \
  --repository-root /ABS/REPO \
  --public-corpus /ABS/REPO/corpora/public/scenarios.jsonl \
  --java-executable /ABS/JAVA \
  --java-adapter /ABS/JAVA-ORACLE.jar \
  --java-runtime /ABS/Java-WebSocket-1.6.0.jar \
  --java-support /ABS/SUPPORT.jar \
  --rust-testee /ABS/websocket-testee \
  --migration-inventory /ABS/REPO/evidence/intake/semantic-id-migration-map.json \
  --compatibility-surface /ABS/REPO/evidence/intake/compatibility-surface.json \
  --ledger /ABS/REPO/evidence/java/behavior-delta-ledger.json \
  --oracle-hierarchy /ABS/REPO/evidence/oracle-hierarchy.json \
  --evidence /ABS/REPO/evidence/differential/manifest.json

go run ./cmd/differentialctl verify \
  --repository-root /ABS/REPO \
  --evidence /ABS/REPO/evidence/differential/manifest.json \
  --ledger /ABS/REPO/evidence/java/behavior-delta-ledger.json \
  --oracle-hierarchy /ABS/REPO/evidence/oracle-hierarchy.json
```

The final reality check is the `run` command itself followed by the independent
`verify`, reading the true exit status and manifest counts. Unit tests, a wrapper
echo, or an existing predecessor receipt cannot substitute for that path. The
full pinned Go test command should use the repository's declared Java 17
materialization when the ambient `JAVA_HOME` differs.

## Required implementation locks

Before implementation, acquire locks for these exact paths (new paths included):

```text
internal/differential/differential.go
internal/differential/differential_test.go
cmd/differentialctl/main.go
cmd/differentialctl/main_test.go
rust/connection-core/src/lib.rs
rust/connection-core/src/connection.rs
rust/connection-core/src/fragment.rs
rust/connection-core/tests/outbound_commands.rs
rust/connection-core/tests/connection_contract.rs
rust/websocket-driver/src/lib.rs
rust/websocket-driver/tests/driver_contract.rs
rust/websocket-testee/src/lib.rs
rust/websocket-testee/src/main.rs
rust/websocket-testee/src/neutral.rs
rust/websocket-testee/tests/process.rs
cmd/rustgate/main.go
cmd/rustgate/main_test.go
docs/rust-workspace.md
evidence/oracle-hierarchy.json
schemas/oracle-hierarchy-1.0.0.schema.json
evidence/differential/manifest.json
schemas/differential-evidence-1.0.0.schema.json
evidence/java/behavior-delta-ledger.json
schemas/behavior-delta-ledger-1.1.0.schema.json
evidence/us010-client-handshake.json
evidence/us011-server-handshake.json
evidence/us012-frame-codec.json
evidence/us013-messages.json
evidence/us014-fragmentation.json
evidence/us015-control.json
evidence/us016-close.json
evidence/us017-driver.json
evidence/us018-blocking-adapters.json
evidence/us019-autobahn-rust-readiness.json
```

The predecessor evidence paths are locked because source/binary bindings may
become stale when the core, driver, or testee changes. Refresh only identity and
re-verification fields actually invalidated by the implementation; do not
rewrite historical claims or imply new Java/Autobahn execution. Lock
`rust/Cargo.toml`, member `Cargo.toml` files, `rust/Cargo.lock`, `go.mod`, or
`go.sum` only if implementation proves a dependency/target edit unavoidable;
this design expects none. The migration and compatibility inventories are
inputs and should remain unlocked/read-only unless a separately approved story
changes their semantics.

## Explicit nonclaims and open verification risks

US-020 does not claim wire interoperability over TCP, browser behavior,
performance, allocation parity, concurrency-topology parity, TLS/NIO support,
all possible WebSocket behavior, hidden/sealed corpus performance, Linux
behavior, Autobahn execution, or external security isolation. It does not prove
that Java is correct merely because Java and Rust agree. It does not prove that
a fresh child process is an uncontaminated machine or that an RFC governs
project-local counters/error taxonomies.

The current unknowns are implementation findings, not reasons to enlarge the
seam:

* the exact set of stable Java/Rust deltas is unknown until the first fresh
  run; closed-state EOF/zero-chunk behavior is a likely delta, not a prewritten
  verdict;
* exact counter instrumentation must be placed where the Rust decoder and
  fragment state already know the values. If that cannot be exposed read-only
  without changing semantics, implementation stops for architecture review
  rather than reconstructing counts in Go;
* any field for which RFC, retained selected Autobahn evidence, and the neutral
  model cannot decide remains underspecified and requires an explicit decision;
  and
* handshake, concurrency ownership, and adapter coverage are predecessor
  bindings by design. A requirement for fresh Java-versus-Rust handshake or
  topology execution would be a separate scope change, not an invisible
  extension of this 74-scenario runner.

No hidden/sealed content, Docker, Autobahn, `wstest`, Linux runner, or network
probe is needed to implement or validate this contract.
