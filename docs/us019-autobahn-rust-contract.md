# US-019 inert Rust Autobahn preparation contract

## Claim boundary

US-019 prepares the exact US-018 Rust testee for the already pinned Autobahn
harness without running either Autobahn mode. It freezes the selected and
nonselected case inventory, binds the existing Rust `client` and `server`
process routes into an inert harness plan, challenges a new non-networked
process-contract route, exercises strict synthetic report reconciliation, and
proves that empty/stub, planted report, planted reference-protocol, stale-run,
and retained-history substitution controls are discriminated.

The owner has relaxed the original story. Completion status is exactly
`READY_NO_LIVE_CONFORMANCE`; neither `PASS`, `PASS_CONFORMANCE`, nor an
unqualified `READY` is valid US-019 status nomenclature. No fresh fuzzing-server
or fuzzing-client process may start, no Docker image or `wstest` entry point may
run, and no Linux x86_64 result may be inferred. The pinned Java evidence and
all retained Autobahn attempt history remain immutable inputs, not results for
the Rust testee. Synthetic fixtures never become historical, upstream, live,
strict-pass, differential, or conformance evidence.

Assurance is `OWNER_ATTESTED_NOT_INDEPENDENT` and
`independent_review_claimed` is `false`. Production, publication, signing,
strict-pass, both-mode execution, and independent-review claims remain false.

## Reconciled baseline

The architecture starts at
`f1d023dda39df244b3b9b27b71e11aefe4de66ef`. US-018 supplies the exact
`rust/websocket-testee` crate, its safe-Rust standard-library TCP adapters, and
the public `client` and `server` process routes. Those routes each own one
loopback connection and delegate protocol behavior through
`websocket_driver::connection_driver` and
`websocket_driver::ConnectionOwner::poll`. They do not yet implement an
Autobahn application echo loop or multi-case lifecycle. US-018 explicitly
records application echo, conformance-runner routing, Autobahn execution, and
Linux as nonclaims. US-019 must not erase those facts.

The incumbent Go laboratory already provides the deep protocol-independent
parts of the harness:

- static parsing of the digest-pinned source archive and every generated case
  identity;
- the frozen selected families `1.*` through `7.*` plus `10.*`, and the
  visibly nonselected families `9.*`, `12.*`, and `13.*`;
- exact result binding by role, case, terminal status, summary digest, and
  observation digest;
- strict raw-report normalization and exact selected-inventory
  reconciliation; and
- a retained no-rerun/history verifier for the committed Java baseline.

US-019 reuses those modules. It does not create a second registry parser,
report format, result classifier, container controller, relay, runner, or
dependency. The live `RunAutobahnQualification` path remains unchanged and is
not called by this story.

## Primitive Test

| Capability | Atomicity | Bitter Lesson | ZFC | Verdict |
| --- | --- | --- | --- | --- |
| Derive and canonically serialize the exact case manifest from the pinned source archive | Pure bounded derivation has no shared mutation; exclusive output creation is already atomic | A stronger model still needs byte-exact parsing and serialization | Digest checks, parsing, sorting, and formatting contain no acceptance judgment | Code |
| Hash and challenge the exact Rust process contract | One child, one random challenge, bounded pipes, and one wait need deterministic ownership | A stronger model still needs subprocess and byte transport | Exact executable identity, arguments, environment, output, timeout, and exit checks are transport | Code |
| Reconcile fixture reports and fixed controls | One invocation owns its private fixture tree; no shared update occurs | A stronger model still needs exact set/count/digest comparison | Applying a frozen mutation catalog and checking typed outcomes is deterministic | Code |
| Bind a committed receipt to current source, manifest, plans, and retained evidence | Verification is read-only; receipt creation uses an exclusive file | A stronger model still needs provenance and schema validation | Reading, hashing, canonicalization, and equality checks are transport | Code |
| Choose which protocol mutations represent useful controls | No concurrency requirement determines the choice | Better protocol reasoning can improve the catalog | Selecting representative defects is judgment | Prompt/design, then freeze the chosen catalog as data |
| Authorize a live Autobahn attempt or treat preparation as conformance | This is owner and assurance policy, not a transport race | Better reasoning can change the risk decision | It contains acceptance and authorization judgment | Prompt/owner only |

The code layer therefore performs only fixed transport and validation. It has
no retry, authorization, pass-waiver, or “close enough” policy.

## Design it twice

### Rejected design A: general endpoint-provider interface

One design replaced the Java endpoint fields in the live qualification
controller with a generic endpoint provider, report provider, process runner,
and role callback. That would support Java, Rust, stubs, and future adapters,
but its interface would expose container timing, relay sessions, process
readiness, report extraction, application routing, and rerun policy. Only one
live controller exists, so most adapters would be hypothetical. The module
would be shallow and a static preparation bug could accidentally reach the
live suite.

### Rejected design B: a `dry_run` branch in the live controller

A second design added Rust fields and a `dry_run` boolean to
`RunAutobahnQualification`. It reused more lines, but every caller would need
to understand which build, image, network, relay, runner, and report steps are
suppressed. A missed branch could start Docker or `wstest`; a stale live report
could also flow through the same receipt type. The deletion test fails because
static-readiness policy would be smeared across the live controller.

### Chosen design: one inert preparation module

The chosen design adds a separate deep module whose interface says exactly
what it can do. It reuses the incumbent parsers and reconciler internally, but
has no interface to the Docker controller, runner, relay, Java endpoint, or
live mode functions. Deleting this module would force callers to reimplement
manifest identity, Rust process identity, fixture provenance, control
discrimination, and receipt verification. It would not disturb the existing
live controller.

This seam maximizes locality: every rule that distinguishes static preparation
from live conformance is enforced in one place. It also gives leverage: the
same preparation interface is exercised by the CLI, tests, evidence verifier,
stub controls, and future live-work authorization review.

## Public interface and ownership

The external seam lives in `internal/lab/autobahn_rust.go`:

```go
type RustAutobahnPreparationConfig struct {
    RepositoryRoot       string
    SourceArchivePath    string
    CaseManifestPath     string
    ClientPlanPath       string
    ServerPlanPath       string
    TesteePath           string
    US018EvidencePath    string
    RetainedBaselinePath string
}

type RustAutobahnPreparationReceipt struct {
    // Closed, schema-backed fields described below; no raw peer bytes.
}

func PrepareRustAutobahn(
    ctx context.Context,
    config RustAutobahnPreparationConfig,
) (RustAutobahnPreparationReceipt, error)

func VerifyRustAutobahnPreparation(
    repositoryRoot string,
    receiptBytes []byte,
) error
```

`PrepareRustAutobahn` is the sole mutating/process interface. It owns one
private temporary directory, one `crypto/rand` challenge, one child process,
bounded stdout/stderr buffers, one deadline, and the returned in-memory
receipt. It does not write the evidence file; the CLI exclusively creates the
output only after preparation succeeds. It accepts no Docker path, image,
network, relay, runner, Java, report-history override, shell command, arbitrary
argument vector, environment map, retry count, or status override.

`VerifyRustAutobahnPreparation` is read-only. It strict-decodes the receipt,
recomputes every current file/tree digest named by the receipt, validates the
manifest and plans, checks the retained baseline digest and no-rerun
disposition, and replays the deterministic reconciliation/control summaries.
It never reruns the process challenge and never accepts an alternate status.

The configuration paths must be clean absolute paths resolving beneath the
one real repository root, except the source archive and built testee, which
may be in a private real work directory. Every input must be a bounded,
singly-linked regular file; directory/tree digests use sorted repository-
relative names and file bytes. Symlinks, hard-link substitution, path escape,
mutation while hashing, unbounded reads, and duplicate normalized names fail
closed. The built testee must be the current-host binary produced by the exact
locked/offline workspace build used for this receipt. This is an
owner-attested build binding, not a reproducible-build or signing claim.

## Immutable case manifest and inert mode plans

`autobahn/case-manifest.json` is generated from
`ParsePinnedAutobahnRegistryArchive` plus `SelectAutobahnRegistry`, not copied
from any historical report. It is canonical JSON with:

- schema, pinned source-archive, registry, report-source, image-manifest, and
  image-config digests;
- the eight selected and three nonselected family names in frozen order;
- every fully numeric selected case ID and every fully numeric nonselected
  case ID in lexical order;
- `selected_count = 247`, `nonselected_count = 271`, and separate canonical
  list digests; and
- `selection_policy = "STATIC_SELECTED_AND_NONSELECTED_NEVER_SKIPS"`.

There is no `excluded`, `skip`, wildcard case identity, unresolved generator,
or execution result in the manifest. The incumbent selection's historical
`Excluded*` field names are translated only at this serialization seam to
`nonselected`; semantic comparison still requires exact equality to the
incumbent derived set. Preparation reads the exact pinned source archive,
derives the selection again, and requires the committed manifest to equal the
canonical derived document byte for byte. A manifest produced from a receipt,
an index report, hand-written IDs, a different archive, or a stale generated
family is rejected.

`autobahn/fuzzingclient.json` and `autobahn/fuzzingserver.json` are inert plan
documents, deliberately not directly executable `wstest` specifications.
Each has:

- `status = "READY_NO_LIVE_CONFORMANCE"`;
- `execution_authorized = false` and `suite_process_allowed = false`;
- the exact case-manifest digest and pinned image/config/report-source
  digests;
- the exact suite mode to Rust role mapping: fuzzing-server exercises the
  Rust `client` route, while fuzzing-client exercises the Rust `server` route;
- a typed argument template made of tokens, never a shell string;
- fixed loopback-only transport, resource bounds, clean-workspace policy, and
  expected future session counts; and
- the explicit blockers `APPLICATION_ECHO_UNAVAILABLE`,
  `MULTI_CASE_LIFECYCLE_UNAVAILABLE`, `SERVER_READINESS_UNAVAILABLE`,
  `LIVE_RUN_NOT_AUTHORIZED`, and `LINUX_X86_64_NOT_EXECUTED` where
  applicable.

The plans contain no live URL, container name, report directory, executable
authorization token, or runnable suite command. A future story must transform
them into live specifications only after new owner authorization; US-019 has
no such transformation function.

The frozen route inventory is nevertheless exact. It binds the Rust fixture
agent `verified-rust-websocket-port-us019` and expands all selected cases as:

- fuzzing-server to Rust client: 247 one-case configurations and 494 planned
  one-shot `client` sessions, ordered as one
  `/runCase?case=1&agent=verified-rust-websocket-port-us019` session followed
  by one `/updateReports?agent=verified-rust-websocket-port-us019` session for
  each selected case;
- fuzzing-client to Rust server: 247 one-case configurations and 247 planned
  one-shot `server` processes, one per selected case; and
- every client route token, request target, fixed Host authority, explicit
  nonce, bound, role, selected case ID, manifest digest, and plan digest is
  represented as a canonical typed field rather than a shell-expanded string.

Static client nonces are the first 16 bytes of SHA-256 over the domain
`us019-static-client-nonce-v1`, manifest digest, selected case ID, and session
kind. They exist only to make the inert route inventory byte-stable and are not
authority for a future live run. The server plan records that the current
process emits no pre-accept readiness signal, while both plans record that the
current adapter observes application messages but cannot submit the required
echo commands during the connected pump. Thus the exact routing is useful for
integration review while its blockers remain machine-readable.

## Rust process contract and router evolution

The existing `client` and `server` routes remain unchanged and are the only
network-capable routes named by the inert plans. US-019 adds exactly one
non-networked route to `rust/websocket-testee/src/main.rs`:

```text
websocket-testee harness-contract <64-lowercase-hex-challenge>
```

It accepts exactly one nonempty challenge, reads no environment or stdin,
opens no socket, and emits one deterministic line containing the exact
challenge plus these closed facts:

```text
schema=1 status=READY_NO_LIVE_CONFORMANCE roles=client,server network_routes=client,server application_echo=false multi_case=false conformance=false challenge=<hex>
```

The route exits `0` only for that exact contract, `2` for all argument errors,
and has no other exit class. `PrepareRustAutobahn` generates the challenge,
executes only the verified absolute testee path with the literal first
argument `harness-contract`, supplies a fixed empty-secret environment, and
requires exact stdout, empty stderr, exit zero, and completion within ten
seconds. The receipt records the public challenge, testee SHA-256, transcript
SHA-256, executable byte count, source-tree digest, Cargo lock digest, US-018
evidence digest, host, Rust toolchain, and exact argument contract. Because
the fresh challenge is process-produced, cached stdout and an empty executable
cannot satisfy the probe. Because the output states both missing capabilities,
the probe cannot be mistaken for conformance readiness.

Rust process tests continue to execute both existing network routes only
against deterministic current-host loopback fixtures. No test or preparation
path supplies an Autobahn address, image, report path, Docker network, or
`wstest` process.

## Synthetic report reconciliation and control discrimination

The fixture module uses the existing `ReadAutobahnReports`,
`AutobahnResultBindingDigest`, and `ReconcileAutobahn` functions. It creates
private, bounded report fixtures from the exact manifest for tests only and
wraps every normalized set in this closed lineage:

```text
origin=SYNTHETIC_RECONCILIATION_FIXTURE
live_execution=false
suite_invoked=false
preparation_digest=<current inert plan digest>
challenge_digest=<current process challenge digest>
manifest_digest=<current committed manifest digest>
mode=client|server
control_id=<frozen catalog id>
```

No other origin is accepted by the fixture interface. The current challenge,
plan, manifest, role, case ID, status, result digest, observation digest, and
binding digest all enter the fixture-envelope digest. Raw fixtures never enter
`evidence/autobahn/`, never replace `evidence/java/autobahn-baseline.json`, and
are removed with the private temporary tree.

The existing report reader's Java-only agent check is narrowed into a closed
two-value agent binding: the unchanged live controller may use only its exact
Java agent, and the inert fixture module may use only
`verified-rust-websocket-port-us019` with synthetic lineage. Accepting the
Rust fixture agent never authorizes the live controller, and arbitrary agent
strings remain rejected.

For each role, the good synthetic fixture has exactly 247 selected results and
zero unknown, duplicate, nonselected, nonterminal, filtered, timed-out, or
missing entries. Its summary distinguishes `fixture_observed = 247` from
`suite_executed = 0`. Status counts cover `OK`, `FAILED`, `NON-STRICT`,
`INFORMATIONAL`, and `UNIMPLEMENTED`, but the resulting disposition is only
`SYNTHETIC_RECONCILED`, never strict-pass.

The evidence keeps live and fixture arithmetic in different objects. For each
live mode it records `expected = selected = missing = 247` and
`executed = passed = failed = non_strict = informational = skipped = filtered
= timed_out = 0`, satisfying:

```text
selected = executed + skipped + filtered + timed_out + missing
executed = passed + failed + non_strict + informational
```

For each good synthetic fixture it records `expected = selected =
fixture_observed = fixture_ok = 247` and every other fixture status/absence
bucket as zero. Controls must reconcile the same fixture partition after their
declared mutation or yield their declared typed rejection. A
strict-pass-shaped fixture therefore proves only that the gate recognizes the
shape; it never changes the live zero/missing counts.

The frozen control catalog is executed twice and must produce byte-identical
typed outcomes:

- an empty/stub process that exits zero without answering the fresh
  `harness-contract` challenge is rejected as `RUST_TESTEE_NOT_EXERCISED`;
- omitted, duplicated, nonselected-injected, nonterminal, altered-result,
  altered-observation, wrong-role-binding, and missing-case fixture mutants
  are rejected by the incumbent result reconciler;
- stale-challenge, stale-plan, stale-manifest, and wrong-origin envelopes are
  rejected as `AUTOBAHN_FIXTURE_LINEAGE_MISMATCH`;
- bytes or digests from the retained original, remediation, recovery, or any
  later historical receipt are rejected as
  `AUTOBAHN_HISTORY_SUBSTITUTION`; and
- the incumbent deterministic reference protocol mutation catalog is run
  without network access and every planted handshake/frame/state mutant must
  retain a nonzero killing inventory. These are explicitly
  `REFERENCE_MODEL_MUTANT` results, not Rust binary mutants or Autobahn case
  outcomes.

An identity mutant that changes nothing must survive and is used to prove the
control runner does not manufacture kills. US-019 does not claim an empty Rust
binary or a planted Rust binary was exercised by Autobahn; those remain live
mutation/conformance work.

## History and freshness firewall

Preparation strict-decodes the committed Java baseline and requires its exact
current digest, assurance, original/remediation sequence, attempt counts,
receipt digests, zero executed/result counts, and closed rerun disposition.
It records those values under `retained_history` without editing them. If the
current branch later adopts a separately reviewed authoritative recovery
receipt, that is a new explicit provenance migration; US-019 cannot discover
or substitute it from another branch, protected directory, report folder, or
controller log.

Freshness is identity-based, not timestamp-based. A fixture is current only if
it binds the newly generated process challenge and the exact current
preparation, manifest, testee, and role digests. A historical upstream report
lacks the synthetic origin and challenge. A prior synthetic fixture has the
wrong challenge. A retained Java receipt has both the wrong origin and wrong
testee. None can satisfy either preparation or fixture reconciliation.

The evidence schema contains no union that admits a live result. It forbids a
`results` field under retained history, requires `suite_executed = 0` for both
modes, requires `strict_pass_claimed = false`, and requires every live report,
raw report, normalized report, extraction, and replay-command digest field to
be null. This is intentional fail-closed separation, not missing evidence
hidden behind a nullable success field.

## Architecture gates

The Go architecture gate adds typed hostile-fixture findings:

- `AUTOBAHN_STATIC_LIVE_LINKAGE` if the inert module or `prepare-rust` CLI
  references `RunAutobahnQualification`, `newDockerController`, either live
  mode runner, Docker image/network/relay/runner construction, `wstest`, or a
  shell;
- `AUTOBAHN_TESTEE_LINKAGE_MISSING` if the current Rust source tree, US-018
  evidence, `harness-contract`, and existing `client`/`server` routes are not
  all bound;
- `AUTOBAHN_MANIFEST_DRIFT` if any family, fully expanded ID, count, source
  pin, order, or canonical digest differs;
- `AUTOBAHN_FIXTURE_LINEAGE_MISMATCH` for an origin, challenge, plan,
  manifest, role, or result-binding mismatch;
- `AUTOBAHN_HISTORY_SUBSTITUTION` for any retained/live/history artifact in a
  synthetic fixture position; and
- `AUTOBAHN_CONFORMANCE_OVERCLAIM` for `PASS`, `PASS_CONFORMANCE`, live
  execution, strict-pass, Linux, production, publication, signing, or
  independent-review claims in US-019 plans or evidence.

`rustgate` continues to enforce the US-018 transport and protocol-surface
rules. Its process-router check permits the exact inert `harness-contract`
literal and requires `application_echo=false`, `multi_case=false`, and
`conformance=false`. Hostile Rust fixtures that add Docker/`wstest`, a network
operation to that route, an environment/secret read, a conformance-true line,
or a second Autobahn-specific protocol loop are rejected. No crate or external
dependency is added.

Architecture canaries are syntactic and linkage evidence, not proof that
arbitrary obfuscated code cannot evade scanning. Their claim is bounded to the
exact reviewed source tree.

## CLI and evidence

`cmd/autobahnctl` keeps its existing live `run` route unchanged. It adds:

```text
autobahnctl prepare-rust \
  --repository-root ABS \
  --archive ABS \
  --manifest ABS \
  --client-plan ABS \
  --server-plan ABS \
  --testee ABS \
  --us018-evidence ABS \
  --retained-baseline ABS \
  --output ABS

autobahnctl verify-rust --repository-root ABS --evidence ABS
```

`prepare-rust` has a 30-second total bound, creates the output with
`O_EXCL`, mode `0400`, file and parent synchronization, and prints only
`READY_NO_LIVE_CONFORMANCE receipt=<path>` after verification. A blocked
preparation prints a typed `BLOCKED_STATIC_READINESS` finding and exits `1`;
usage exits `2`. `verify-rust` is read-only and uses the same typed verifier.
Neither route accepts the live plan digest, Docker, JDK, Java endpoint, relay,
runner, network, report-copy, retry, authorization, or waiver flags.

`evidence/us019-autobahn-rust-readiness.json` is validated by
`schemas/us019-autobahn-rust-readiness-1.0.0.schema.json` and the Go verifier.
It binds:

- architecture, implementation, and evidence commits;
- exact manifest, selected/nonselected lists, counts, and pins;
- both inert plans and role mappings;
- Rust source tree, Cargo lock, current-host binary, toolchain, challenge, and
  exact capability transcript;
- current US-018 evidence and its explicit application-echo/conformance/Linux
  nonclaims;
- good synthetic reconciliation summaries and all repeated control outcomes;
- retained baseline digest, attempt identities, and no-rerun disposition;
- architecture-canary counts and full debug/release/Go gate results; and
- the complete explicit nonclaim set below.

Alongside the top-level `READY_NO_LIVE_CONFORMANCE`, the receipt requires
`live_conformance_status = "BLOCKED_NOT_EXECUTED"`; neither field is
caller-controlled.

The schema is closed (`additionalProperties: false`) at every object. Its
top-level status is a const, not an enum containing a pass state. Cross-file
digests, canonical ordering, exact counts, control outcomes, and history
lineage are enforced by Go because JSON Schema alone cannot prove them.

## RED -> GREEN -> REFACTOR plan

All REDs are genuine focused failures recorded before implementation:

1. **Manifest RED.** A test imports the absent preparation interface and tries
   to load the committed fully expanded manifest. It fails because the module
   and manifest do not exist. Hostile variants omit a selected ID, inject a
   nonselected ID, retain a wildcard, change a source pin, reorder IDs, and
   claim a skip.
2. **Process-contract RED.** A process test invokes
   `websocket-testee harness-contract <challenge>` and fails with usage because
   the route does not exist. Empty/stub, cached-transcript, wrong-challenge,
   extra-output, stderr, timeout, and nonzero-exit helpers must all be rejected.
3. **Inert-plan RED.** Good client/server plans fail because no parser or Rust
   role binding exists. Mutants set execution authorization true, swap roles,
   name a shell/live runner, alter a digest, add a runnable URL, or omit the
   missing-capability blockers.
4. **Reconciliation RED.** Exact synthetic client and server fixtures exercise
   the existing report parser but fail the absent lineage/count summarizer.
   The good fixture must report 247 observed, zero live executed, and exact
   status/absence counts. Missing, duplicate, nonselected, nonterminal,
   digest, observation, and role-binding mutants must yield their typed
   failures.
5. **Freshness/history RED.** Replaying a prior challenge, using a mismatched
   plan/manifest, changing origin, inserting the retained baseline bytes, and
   inserting a historical upstream report must all fail. The RED exists until
   the exact lineage firewall is implemented.
6. **Control RED.** Execute the empty/stub process control twice, every fixed
   report mutant twice, the full incumbent reference protocol mutation catalog
   twice, and the identity survivor twice. The test fails until expected
   rejection/kill/survival outcomes reconcile byte-identically.
7. **Architecture RED.** Go hostile-source fixtures plant calls to every live
   controller entry, Docker/`wstest`, shell execution, a conformance-true Rust
   route, and history substitution. They must fail until the new typed gates
   exist.
8. **CLI/evidence RED.** Focused CLI tests require exact routes, flags, output
   creation, statuses, exits, bounds, and secret suppression. Schema and Go
   verification tests reject every mutable evidence field and any pass/live
   overclaim.

GREEN requires the focused tests, two deterministic control repetitions, the
locked/offline Rust debug and release suites, rustfmt, Clippy, Cargo metadata,
rustgate, full pinned-JDK Go tests with cache disabled, Go vet/build, port-plan
verification, and all predecessor formal/frame replays. No Autobahn, Docker,
Linux, or network other than existing current-host loopback process fixtures
runs during GREEN.

REFACTOR may consolidate private manifest/report binding helpers and reuse
incumbent bounded-file utilities. It must not add an endpoint trait, report
provider, dry-run switch on the live controller, suite executor, dependency,
second result classifier, or status waiver.

## Explicit nonclaims

US-019 does not claim:

- any fresh Autobahn fuzzing-server or fuzzing-client execution;
- any Rust selected case executed, passed, failed, timed out, skipped, or
  strict-passed by Autobahn;
- either live mode passed or conformance is ready;
- historical Java or sibling-branch results apply to the Rust testee;
- application echo, multi-case lifecycle, compression, or extension support;
- an empty Rust binary or planted Rust binary was executed by Autobahn;
- reference-model mutant kills are Rust binary mutation evidence;
- Linux x86_64, a second host, or both blocking platforms;
- production, publication, signing, release, or reproducible builds;
- independent review, formal proof, or exhaustive security; or
- authorization for any later suite run.

The useful result is narrower: the current Rust testee, exact pinned manifest,
inert role plans, strict report machinery, process identity, and negative
controls are connected and fail closed. The remaining live work is explicit
instead of being hidden behind a synthetic pass.

## Implementation file and lock plan

The implementation worker needs locks for:

- `autobahn/case-manifest.json`
- `autobahn/fuzzingclient.json`
- `autobahn/fuzzingserver.json`
- `internal/lab/autobahn_rust.go`
- `internal/lab/autobahn_rust_test.go`
- `internal/lab/autobahn.go`
- `internal/lab/autobahn_controller.go`
- `internal/lab/autobahn_controller_test.go`
- `cmd/autobahnctl/main.go`
- `cmd/autobahnctl/main_test.go`
- `rust/websocket-testee/src/main.rs`
- `rust/websocket-testee/tests/process.rs`
- `internal/rustgate/verify.go`
- `cmd/rustgate/main_test.go`
- `evidence/us019-autobahn-rust-readiness.json`
- `schemas/us019-autobahn-rust-readiness-1.0.0.schema.json`

The incumbent reference-protocol mutation code and committed corpus evidence
are read-only dependencies unless a focused RED proves a binding helper is
unavoidable. `evidence/java/autobahn-baseline.json` and every retained receipt
are read-only. Predecessor evidence refresh may require an additional lock for
`evidence/us018-blocking-adapters.json` after the implementation commit is
fixed; refresh may update only current source/provenance identity, never its
historical runtime claims or nonclaims. US-006 concurrency/formal locks and
unrelated US-007 security work remain untouched.
