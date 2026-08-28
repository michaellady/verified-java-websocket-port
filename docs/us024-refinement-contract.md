# US-024 idiomatic Rust refinement contract

## Decision and claim boundary

US-024 performs one bounded internal Rust refactor after the US-023 freeze. It
extracts the WebSocket driver's pending-output and partial-write lifecycle into
one private owner type. The public API and every externally observable behavior
remain frozen. This is a maintainability and ownership refinement; it is not a
performance result, a parity-ready claim, or permission to redesign the
protocol.

The owner has relaxed the original acceptance criteria so that this story may
complete when the refinement mechanics, deterministic public before/after
replay, local gates, and owner review are truthful and green. Evidence that is
unavailable in this environment remains an explicit blocker/nonclaim. In
particular, US-024 does not run or claim hidden/sealed custodian confirmation,
Autobahn, Docker/wstest conformance, a formal backend, an independent host,
independent human review, performance, signing, publication, production, or
cutover.

Every US-024 artifact must carry:

```text
assurance: OWNER_ATTESTED_NOT_INDEPENDENT
independent_review_claimed: false
production: false
publication: false
signing: false
performance_claimed: false
cutover_claimed: false
```

The maximum positive result is `PASS_OWNER_RELAXED_MECHANICS`. It means only
that the declared internal refactor preserved the locally replayable behavior
and evidence invariants. It must coexist with the explicit blockers described
below.

## Shipped result

US-024 completed its owner-relaxed mechanics at repository head
`603ef0fdd5bb3f114d95b09e7282ee2a74c8e60a`. The implementation subject is
`579aa003760e6eac6a98d1d394fd07b81f447451`: `ConnectionOwner` delegates the
declared lifecycle to the private `OutputLedger`, while public declarations and
the `ConnectionCore` contract remain unchanged. The final repository receipt
is `evidence/refinement-replay.json` with digest
`sha256:3482e63dd0b5e31a244bdc82d5cd491ebeb3c22e5b345b434d709d1d27463853`.
It rederives 74/74 equal normalized public scenarios and 34 local replay
descriptors with 986 before and 1010 after observations.

The repository receipt deliberately retains
`IMPLEMENTATION_REPLAY_PASS_PENDING_REVIEW_QA_REALITY` and `NOT_EXECUTED`
phase provenance. Executed owner review, QA, and reality receipts live in the
HQ orchestration record rather than being self-asserted by repository evidence.
One full review and one targeted closure closed the four blocking review
findings. Two important nonblocking notes remain: the receipt does not bind the
exact tool versions/digests, feature/target set, or complete effective
environment, and the evidence rename is not followed by parent-directory
`fsync`. Full Rust debug and release QA passed 185/185, and fresh-checkout
reality validation rederived the exact receipt. These phases do not create
independent review.

The eight retained blockers are exactly:

```text
AUTOBAHN_AUTHORITY_CONSUMED
HIDDEN_SEALED_NOT_EXECUTED
FORMAL_BACKEND_NOT_EXECUTED
FORMAL_REFINEMENT_DISCONNECTED
CONCURRENCY_DIFFERENT_SUBJECT
INDEPENDENT_HOST_NOT_EXECUTED
INDEPENDENT_HUMAN_REVIEW_NOT_EXECUTED
PRODUCTION_CUTOVER_NOT_AUTHORIZED
```

The seven retained nonclaims are exactly:

```text
no fresh Java differential comparison
no Autobahn or Docker/wstest rerun
no hidden or sealed confirmation
no formal proof or equivalence
no independent host or human review
no performance result
no production, publication, signing, or cutover
```

Owner-relaxed completion also retains ten planned acceptance surfaces as
explicit coverage reductions rather than claiming they ran:

```text
successive partial plus exact-final write trace
multiple writes from one core step plus single final flush
event/failure adjacency around writes
shutdown with offered and queued writes plus surviving non-write outputs
exact byte-budget boundary plus one
twice-normalized replay of every hostile trace
valid swapped-binary identity canary
dirty Git worktree canary distinct from non-Git
limit/exclusion/mutant denominator canaries
filesystem symlink escape canary
```

## Correct repository layout

The PRD's `crates/...` paths are stale. The real workspace is rooted at
`rust/`, with these crates:

```text
rust/connection-core/
rust/websocket-driver/
rust/websocket-testee/
```

The canonical append-only delta ledger is
`evidence/java/behavior-delta-ledger.json`, not
`evidence/behavior-delta-ledger.json`. US-024 must not create the stale path or
a second ledger.

## Immutable before-state

There are two distinct before-state identities. They must not be collapsed.

The complete post-US-023 repository state on which implementation begins is:

```text
commit: 7ea615dfee70ae71af59e83559110c6c4671c405
tree:   9353bf8cd67ad401eec2036c661441a6c9bf95b0
```

The immutable US-023 snapshot embedded in that state remains:

```text
target commit: 1ff89fa30cb0ab6ff339afd3ce486a36e9f7f325
target tree:   dfb1950301e9680b1c47f0bd9debc0fc026d0e4f
candidate root: sha256:dd96c5fb0346f736e6ddadf7848d34ceb5e4c2beefe77c1730bec6649516190e
evaluation root: sha256:4f608c8f658dd287efef362bdfe027cf66116f95e1192810bce2fb3e1d83ce21
snapshot state: FROZEN
parity state: BLOCKED
original gates: 44 required, 0 satisfied, 44 blocked
```

The verifier must require those literal values and the pre-refinement SHA-256
identities of these three files:

```text
assurance/candidate-manifest.json
  sha256:ab24fb6cbc3b811ef1d08c46c3c1b4925b03595836f5ccd65f0858fea66c9925
evidence/parity-replay.json
  sha256:f2ca5d490429609977fc4782da3890e29629a9353fd5bfdc9bc6390a89c5f182
evidence/java/behavior-delta-ledger.json
  sha256:e4800359d8a667524216b74947e43c169153406338398473221286bfbba9724a
```

US-024 must preserve the first two files byte-for-byte. It must also preserve
the canonical ledger byte-for-byte because this story intends no semantic
delta. A resource/ownership-only refactor is described in the US-024 receipt,
not appended as a behavior delta. Any actual semantic difference makes the
story `BLOCKED_SEMANTIC_DRIFT`; it is not repaired by silently adding a ledger
entry. A separately approved semantic change would append through the existing
hash-chained CAS mechanism and reopen every affected gate.

## Selected refinement seam

### Current friction

`websocket_driver::ConnectionOwner` is the correct single mutable owner, but
one invariant is spread across two concepts and four primitive fields:

```rust
ledger: VecDeque<PendingOutput>,
offered_write: Option<TransportWrite>,
write_cursor: usize,
batch_writes_remaining: usize,
flush_due: bool,
```

`poll`, `commit`, `next_output`, `write_remaining`, and
`abort_undrainable_writes` must jointly maintain the following rules:

- an offered write owns the exact front write and its cursor;
- only a valid acknowledged prefix advances the cursor;
- later writes never bypass the offered write;
- a batch flush becomes due only after every write from that core step drains;
- non-write outputs retain their exact position around writes;
- shutdown removes undrainable writes without producing a phantom flush; and
- the owner never exposes a slice beyond the owned `TransportWrite`.

Those are one lifecycle, so storing them as unrelated `ConnectionOwner` fields
makes illegal internal combinations representable. The chosen refactor makes
that lifecycle one private deep module without changing the public seam.

### New private module

Add `rust/websocket-driver/src/output.rs`, declared as private `mod output` by
`rust/websocket-driver/src/lib.rs`. It owns the private `PendingOutput` enum and
a private `OutputLedger` with conceptually this state:

```rust
pub(crate) struct OutputLedger {
    pending: VecDeque<PendingOutput>,
    offered: Option<TransportWrite>,
    cursor: usize,
    batch_writes_remaining: usize,
    flush_due: bool,
}
```

The exact visibility may be narrower, but none of these types or fields becomes
public. `OutputLedger` owns the only implementations of:

- appending ordered `PendingOutput` values from one core step;
- checked addition of that step's write count;
- reporting whether any ordered output is pending;
- reporting the exact current write suffix length;
- applying zero, partial, exact, and excessive write progress;
- promoting the front pending write without copying it;
- yielding the next `DriverOutput` in exact order;
- consuming exactly one due flush fact; and
- discarding all undrainable writes on transport shutdown while preserving
  non-write outputs.

`ConnectionOwner` retains protocol mutation, input arbitration, command
dispositions, EOF/shutdown latches, and terminal convergence. It delegates only
the output/write lifecycle. The driver continues to use `VecDeque`,
`TransportWrite`, and the existing checked arithmetic; there is no dependency,
runtime, allocator, lock, thread, socket, callback, clock, unsafe block, or
parallel state machine.

### Frozen public symbols

The signatures and meanings of these existing public symbols are invariant:

```text
websocket_driver::connection_driver
websocket_driver::CommandHandle::try_enqueue
websocket_driver::ConnectionOwner::state
websocket_driver::ConnectionOwner::last_core_observation
websocket_driver::ConnectionOwner::last_core_step
websocket_driver::ConnectionOwner::observe_closed
websocket_driver::ConnectionOwner::poll
websocket_driver::DriverInput
websocket_driver::DriverOutput
websocket_driver::PollResult
websocket_driver::InputDisposition
websocket_driver::DeferredReason
websocket_driver::DriverInputError
websocket_driver::CommandDisposition
websocket_driver::EnqueueError
websocket_driver::TerminalOutcome
```

No public variant, field, lifetime, trait derivation, or error payload changes.
`ConnectionCore::step`, all `LocalCommand`/`CoreOutput` values, the TCP adapter,
and the neutral testee route remain untouched.

### Exact behavior identity

For every public input schedule, before and after must return the same sequence
of:

- `InputDisposition`, including the exact deferred/rejected reason and byte
  count;
- `CommandDisposition`, including the owned command and typed failure;
- `DriverOutput`, including exact write bytes and suffix boundaries;
- `ConnectionState`;
- `CoreStepObservation` and monotonic owner step sequence;
- semantic events and typed protocol/error/close classifications; and
- the single normalized terminal delivery.

The refactor must preserve these less obvious facts:

1. `WriteProgress { bytes: 0 }` is accepted only when a write is offered and
   leaves the exact suffix pending.
2. Progress when no suffix exists, or beyond the suffix, is rejected without
   any state mutation and reports the exact attempted/remaining counts.
3. Completing one write in a multi-write core batch does not emit
   `TransportWriteFlushed`; the fact is fed to `ConnectionCore` once, after the
   last write and all preceding ordered outputs drain.
4. Inbound bytes offered while output/flush is pending are deferred with the
   existing reason and consumed-byte behavior.
5. Shutdown may abort an offered and queued write, but it does not discard
   already queued events/failures, report a successful flush, or emit a second
   terminal result.
6. `DriverOutput::Write` remains borrowed from owner-held storage, so another
   mutable poll cannot occur while the slice is live.
7. No allocation, copy, bound, queue capacity, overflow behavior, or
   sequentially consistent producer-admission ordering changes.

## Exact implementation surface

The intended production diff is limited to:

```text
rust/websocket-driver/src/lib.rs
rust/websocket-driver/src/output.rs                 # new, private
```

The implementation must not change production code under:

```text
rust/connection-core/src/
rust/websocket-testee/src/
```

Add focused hostile acceptance coverage in:

```text
rust/websocket-driver/tests/refinement_contract.rs  # new
rust/websocket-testee/tests/process.rs               # test-only race correction
```

The evidence implementation may add or modify only these supporting surfaces:

```text
internal/differential/differential.go
internal/differential/differential_test.go
internal/refinement/refinement.go                   # new
internal/refinement/refinement_test.go              # new
cmd/refinementctl/main.go                           # new
cmd/refinementctl/main_test.go                      # new
schemas/us024-refinement-replay-1.0.0.schema.json   # new
evidence/refinement-replay.json                     # new
docs/us024-refinement-contract.md
```

`internal/differential` may expose one narrow Rust-only public-corpus replay
function that reuses its incumbent corpus loader, neutral-request encoder,
bounded child-process runner, strict response parser, and normalizer. It must
not introduce a second neutral protocol or alter Java/Rust normalization,
oracle precedence, scenario selection, timeouts, or differential evidence.

If a blocking defect requires another file, the implementation phase must
report it and expand the declared membership before editing. It must not hide
the expansion in generated evidence.

The accepted `rust/websocket-testee/tests/process.rs` scope expansion is
test-only. It replaces a released-ephemeral-port race with TCP port zero so the
existing connect-failed exit class is exercised deterministically; it does not
change production behavior or the neutral protocol.

## Before/after replay protocol

### Git subjects

The replay uses two immutable, clean Git subjects:

- before: exact commit/tree `7ea615d...` / `9353bf8...`;
- after: one declared implementation commit/tree containing the Rust refactor,
  hostile tests, replay code, and schema but preceding the generated receipt.

The after subject is not `HEAD` by convention. Its exact 40-hex commit and tree
are fields in the receipt. Capture rejects a dirty index/worktree for every
declared source, test, corpus, manifest, schema, and tool path. Verification
reads objects through Git, requires full 40-hex identities, rejects missing or
ambiguous objects, and proves each path's blob membership in its declared tree.

Both Rust testee binaries are built from clean materializations of those exact
trees using the same pinned Rust 1.95.0 toolchain, `Cargo.lock`, feature set,
profile, target, and environment. The receipt records the executable SHA-256,
byte count, canonicalization label, and source commit/tree; local replay rows
record command vectors and exit/timeout/test counts. It does not bind the exact
tool versions/digests, feature/target set, or complete effective environment,
which remains an important nonblocking evidence limitation. A binary copied
from another tree or rebuilt after source drift is blocking.

### Deterministic Mach-O identity

The shipped V2 evidence build uses the closed Cargo environment and
`--remap-path-prefix`, one codegen unit, and stripped debug information so a
random materialization path cannot survive in linker OSO records. Before
signing, the verifier requires one little-endian 64-bit Mach-O executable with
exactly one bounded `LC_UUID` and one bounded `LC_CODE_SIGNATURE`. It zeros the
existing UUID and signature blob in the hash preimage, hashes the
domain-separated preimage, writes the RFC 4122-compatible derived UUID, then
ad-hoc signs with `/usr/bin/codesign` and verifies the result with
`codesign --verify --strict`.

The receipt labels this algorithm
`MACHO_LC_UUID_SHA256_V2_CODESIG_ZERO_STRIPPED_ADHOC`. Any absent, duplicate,
truncated, or out-of-bounds command/signature structure fails closed. Three
isolated after-subject builds produced identical final bytes at
`sha256:f9d0ad21b2c06d2df215b8fb378c26f0adc9c0f37f01ea842fcdecfe68cab5e7`
and 1,371,456 bytes before the single final capture and verifier pass.

### Public behavior matrix

Replay selects exactly the 74 unique scenarios bound by
`corpora/public/manifest.json` and `corpora/public/scenarios.jsonl`. It invokes
the before and after `websocket-testee --neutral-oracle` routes through the
existing differential process/normalization code. For each scenario, the
receipt binds:

```text
scenario_id
canonical input SHA-256
before normalized observation SHA-256
after normalized observation SHA-256
before process exit/timeout class
after process exit/timeout class
```

The expected, selected, executed, compared, and equal counts must all be 74;
failed, duplicate, missing, filtered, skipped, and timed-out counts must be
zero. Scenario order is the canonical corpus order. Every paired normalized
observation must be byte-identical after canonical encoding, and a domain-
separated transcript root must rederive from the ordered rows. Running the
comparison with before and after swapped must produce the same equality result
and the corresponding swapped subject root.

This is a Rust-before/Rust-after replay. It preserves the Java differential
normalizer by exact source/test/artifact identity and may independently run the
existing `differentialctl verify` against retained US-020 evidence, but it must
not describe that retained receipt as a fresh Java comparison for the refined
subject.

### Property, fuzz, runtime, and driver surfaces

The replay tool reads the exact command arrays and target identities already
committed in:

```text
evidence/property/manifest.json
evidence/fuzz/manifest.json
evidence/runtime/manifest.json
```

It executes every locally runnable declared Rust replay command against both
clean subjects with the same pinned toolchain and records the exact target set,
test denominator, exit/timeout status, and repeat count. It must not silently
skip an unavailable command. An unavailable external tool is recorded as
`BLOCKED_UNAVAILABLE`, never converted to pass.

Full debug and release workspace tests cover the incumbent conformance,
property/fuzz seed, runtime, driver concurrency, and testee process surfaces.
The new hostile driver traces are additional after-tests; every before test
name remains a member of the after denominator. New tests cannot replace or
rename an old requirement-bearing test.

The receipt distinguishes:

- `FRESH_BEFORE_AFTER_PUBLIC_REPLAY`: exact paired neutral observations;
- `FRESH_LOCAL_TEST_REPLAY`: exact commands executed on both subjects;
- `RETAINED_IDENTITY_ONLY`: unchanged evidence for a different source subject;
  and
- `BLOCKED_UNAVAILABLE`: a required gate that did not execute.

No aggregate `PASS` may erase the distinction.

### Evidence document

`evidence/refinement-replay.json` is canonical JSON conforming to
`schemas/us024-refinement-replay-1.0.0.schema.json`. Its closed shape includes:

```text
schema/story/status/assurance/nonclaims
before and after Git/tree/Rust-tree/Cargo.lock/binary identities
immutable US-023 candidate/evaluation roots and artifact identities
declared production/test/tool path membership
public scenario rows and domain-separated roots
manifest-derived local replay receipts
source/test/corpus/limit/exclusion/mutant/ledger drift checks
formal and concurrency connection status
gate counts and blockers
review/QA/reality provenance
production/publication/signing/performance/cutover booleans
```

The verifier must compile the schema, decode with unknown/duplicate-field
rejection, cap the document and all arrays/strings, reject noncanonical paths,
reject symlinks and nonregular files, rederive every digest/count/root, compare
Git object membership, and fail closed on any unrecognized status. Validation
does not trust a captured summary or a wrapper's exit-code echo.

## Behavior-delta ledger rule

The verifier treats `evidence/java/behavior-delta-ledger.json` as a protected
append-only input. For this no-semantic-change story it requires all of:

- exact pre-refinement blob and SHA-256 identity;
- exact post-refinement byte equality;
- the same 103-record sequence and hash chain;
- the same accepted root, head, decisions, resolutions, and zero unledgered
  disagreements; and
- successful incumbent `differentialctl verify` when that retained verifier is
  invoked.

Truncation, reordering, record replacement, head rollback, an unreviewed append,
creation of the stale parallel ledger path, or relabeling an old record blocks
US-024. If normalized before/after Rust output differs, the correct result is a
semantic-drift blocker; the implementation may not mutate the ledger during
automatic remediation.

## Source, test, and assurance drift canaries

The US-024 verifier derives exact Git path/blob sets rather than trusting file
counts. It fails on any of the following:

1. deletion, rename, ignore, weakening, filtering, or silent nonexecution of a
   pre-existing Rust test;
2. a change to `Cargo.lock`, workspace membership, features, dependency policy,
   unsafe policy, licenses, limits, thresholds, exclusions, corpora, fuzz seeds,
   mutation denominator, mutant dispositions, oracle hierarchy, Java
   normalizer, or Java compatibility mapping;
3. a production Rust change outside the two declared driver source paths;
4. an undeclared generated file or an untracked file used as evidence;
5. a before/after test denominator where the before names are not an exact
   subset of the after names;
6. a public scenario count other than 74 or a scenario whose canonical input
   identity changes;
7. any normalized event, write, command, limit, error, close, ordering, or
   consumption difference;
8. a modified US-023 candidate/evaluation artifact or root;
9. a changed canonical behavior ledger;
10. promotion of retained-different-subject evidence to current-subject pass;
11. a stub, TODO, unimplemented path, ignored result, weakened assertion,
    relaxed timeout, or lowered case/repeat/mutant count introduced by US-024;
12. unsafe code, a new dependency, a lockfile change, or compiler/linter
    warnings; or
13. a receipt claiming independent, formal, protected, performance,
    production, publication, signing, or cutover assurance that was not run.

Unit tests for `internal/refinement` and `refinementctl` must plant at least
these drift canaries: changed after observation, missing/duplicate/reordered
scenario, swapped binary identity, dirty or non-Git source, deleted/renamed
test, changed limit or exclusion, changed mutant denominator, shortened ledger,
rewritten ledger record, changed US-023 root, symlink/path escape, oversized
receipt, duplicate/unknown JSON field, zero executed count, and a pass label on
an unavailable gate. Every bad fixture must fail through the same verifier used
for the committed artifact.

## Formal and concurrency truthfulness

US-024 does not connect a formal proof to production Rust.
`assurance/formal/proof-targets.json` binds frame decoder/mask symbols from the
US-023 target and says their production consumers are pending. The US-023
formal obligation catalog already reports Rust refinement as blocked. Those
artifacts remain byte-identical and US-024 records:

```text
formal_connection: DISCONNECTED_BLOCKED
formal_backend: NOT_EXECUTED
production_refinement: ABSENT
```

The refactor does not touch the actual formal target symbols
`FrameHeaderDecoder::decode_header` or `apply_mask_in_place`; this fact is an
identity check, not a proof equivalence argument.

The historical concurrency plan names the nonexistent future symbol
`websocket_driver::owner::ConnectionOwner::step` and marks it unresolved. The
shipped seam is `websocket_driver::ConnectionOwner::poll`, but US-024 must not
rewrite history or invent an equivalence proof. The current deterministic
concurrency tests and native-thread stress can run as local regression tests,
while the retained evidence remains a different subject. The receipt records:

```text
concurrency_connection: RETAINED_DIFFERENT_SUBJECT_BLOCKED
systematic_tests: FRESH_LOCAL_TEST_REPLAY or BLOCKED
formal_equivalence: NOT_CLAIMED
```

Changing either status to connected/pass without exact current-symbol proof,
drift tests, and the required independent review is blocking.

## Hostile acceptance cases

`rust/websocket-driver/tests/refinement_contract.rs` exercises only public
driver APIs and must include:

1. zero, one-byte, several partial, exact-final, and plus-one progress against
   the same offered write, proving exact suffix retention and no mutation on
   rejection;
2. a core step that produces multiple ordered outputs/writes, proving a later
   write never bypasses the front and only the last completed write schedules
   one flush;
3. an event/failure adjacent to writes, proving occurrence order is unchanged;
4. inbound bytes offered during an output, partial write, and due flush,
   proving the exact existing `DeferredReason` and zero-consumption behavior;
5. shutdown with an offered write and later queued write, proving both writes
   are aborted, non-write outputs survive, no phantom flush appears, admission
   closes, and exactly one terminal result is delivered;
6. terminal convergence with accepted queued commands, proving every command
   receives exactly one existing disposition before the single terminal;
7. producer drop/receiver drop and byte/entry backpressure at exact boundaries;
   and
8. deterministic replay of each trace twice with identical normalized output.

These tests add coverage; they do not replace the existing
`driver_contract.rs` or `concurrency.rs` tests.

## Review rule

After implementation and acceptance tests, run exactly one complete
comments-only review over the full US-024 diff. It covers correctness,
security, semantic preservation, evidence integrity, and Rust idiom. The review
agent edits no files and classifies findings as blocking, important, or nit.

Only blocking correctness/security findings are remediated. The same reviewer
then performs one targeted closure of those exact findings against the
remediation diff. There is no second full review. Important observations and
nits remain listed without implementation unless the owner separately expands
scope.

Review provenance records provider, model, reasoning effort, invocation, exact
before/after commits, diff identity, findings, and closure identity. A Codex
review is not a human review and must not be written into a human receipt.

## Exact local QA gates

Use the pinned JDK and Rust toolchains. All Cargo operations run from `rust/`
with `--locked`; dependency-bearing operations use the already materialized
closure and do not fetch. The canonical local commands are:

```sh
JAVA_HOME=/Users/mikelady/.jenv/versions/17 \
PATH=/Users/mikelady/.jenv/versions/17/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin \
go test ./... -count=1

JAVA_HOME=/Users/mikelady/.jenv/versions/17 \
PATH=/Users/mikelady/.jenv/versions/17/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin \
go vet ./...

JAVA_HOME=/Users/mikelady/.jenv/versions/17 \
PATH=/Users/mikelady/.jenv/versions/17/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin \
go build ./...

/Users/mikelady/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo \
  fmt --all -- --check
/Users/mikelady/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo \
  clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
/Users/mikelady/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo \
  test --workspace --all-targets --all-features --locked --offline
/Users/mikelady/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo \
  test --workspace --all-targets --all-features --release --locked --offline
/Users/mikelady/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo \
  build --workspace --all-targets --all-features --locked --offline
/Users/mikelady/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/cargo \
  build --workspace --all-targets --all-features --release --locked --offline

go run ./cmd/refinementctl verify \
  --repository-root /ABS/REPO \
  --evidence /ABS/REPO/evidence/refinement-replay.json

go run ./cmd/differentialctl verify \
  --repository-root /ABS/REPO \
  --evidence /ABS/REPO/evidence/differential/manifest.json \
  --ledger /ABS/REPO/evidence/java/behavior-delta-ledger.json \
  --oracle-hierarchy /ABS/REPO/evidence/oracle-hierarchy.json
```

The Go environment includes JDK 17 because Go tests exercise the accepted Java
toolchain bindings. If the accepted Java runtime jar/support closure is
materialized, also run `make -C java-oracle test` with
`JAVA_WEBSOCKET_JAR` and `RUNTIME_SUPPORT_CP` resolved to those exact verified
objects. If it is unavailable, record the Java rerun as blocked; do not fetch,
substitute, or relabel retained Java evidence.

The actual command's exit status and output are evidence. A wrapper echo is not
evidence. Any loopback test that is blocked only by the process sandbox may be
rerun once with the exact same command outside that sandbox and the original
failure retained.

## Acceptance result

US-024 may be marked owner-relaxed complete only when:

- the production diff is exactly the declared driver refactor;
- all old public symbols and test names remain;
- all hostile acceptance tests pass;
- the 74-scenario before/after normalized public replay is exactly equal;
- every locally runnable property/fuzz/runtime command and full Rust/Go gate
  passes with exact denominator reconciliation;
- US-023 artifacts/roots and the canonical delta ledger remain byte-identical;
- source/test/evidence drift canaries fail as designed;
- one bounded full review has no open blocking finding after at most one
  same-reviewer targeted closure;
- QA and fresh reality verification run the real CLI and binaries; and
- every unavailable original criterion remains an explicit blocker/nonclaim.

The final result must still say `FROZEN/BLOCKED`, retain the original 44/0/44
parity gate truth, and state `OWNER_ATTESTED_NOT_INDEPENDENT` with
`independent_review_claimed:false`. US-024 cannot make US-023 `READY` and cannot
authorize performance work, publication, production, or cutover.
