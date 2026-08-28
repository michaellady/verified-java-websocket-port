# US-022 normalized mutation and protected-evaluation contract

Status: architecture only. This document does not claim a PIT,
`cargo-mutants`, hidden/sealed candidate, signature, publication, or
independent-review result.

US-022 uses an owner-relaxed gate. It still requires executable mutation
controls, a complete denominator, unchanged production and test surfaces, and
fail-closed verification of the public protected-evaluation projection. It
does not convert unavailable infrastructure into a passing result.

## Claim boundary

The incumbent public hidden and sealed manifests establish that the pinned
Java 1.6.0 oracle passed 92 hidden and 92 sealed behavior scenarios twice.
They do not bind those executions to the current Rust candidate, an empty Rust
binary, or planted Java/Rust binaries. `evidence/corpus-calibration.json`
records those three live gates as pending. US-022 must preserve that fact.

The owner-relaxed result may therefore claim only all of the following:

1. a deterministic in-tree runner compiled and executed planted source mutants
   against selected shipped Java and Rust production seams;
2. every declared planted mutant compiled, ran twice, and was killed twice by
   its fixed public test command;
3. the full pre/post Java and Rust test commands passed and their complete
   source/test inventories did not change;
4. an empty/stub Rust process failed the fixed public candidate probe;
5. the committed public hidden/sealed manifests and a digest-only public
   projection reconcile, contain no protected payload, and retain the pending
   Rust/control gates as explicit nonclaims.

PIT and `cargo-mutants` are distinct engines. When they are not present in the
accepted tool graph, the plan records `UNAVAILABLE_NOT_RUN`, the verifier
requires zero results attributed to them, and no planted result may use either
name. The unsigned, owner-attested evidence status is
`PASS_OWNER_RELAXED`; assurance is always
`OWNER_ATTESTED_NOT_INDEPENDENT`, with
`independent_review_claimed:false`, `signing:false`, `production:false`, and
`publication:false`.

## Deep module boundary

Add one package, `internal/mutation`, with this public surface:

```go
type Config struct {
    RepositoryRoot string
    ScratchRoot    string
    JavaExecutable string
    MavenExecutable string
    MavenRepository string
    CargoExecutable string
    RustcExecutable string
}

func RunPlanted(ctx context.Context, cfg Config) error
func Verify(repositoryRoot string) error
```

`RunPlanted` loads only the committed plan, validates all named inputs and tool
identities, copies the Java or Rust closure into a fresh private scratch
directory for each attempt, applies one exact planted edit, and launches fixed
build/test commands with deadlines and bounded output. It writes only
`evidence/mutation/java.json` and `evidence/mutation/rust.json`, using atomic
create-and-rename. It never opens a hidden or sealed case, follows a protected
artifact path, invokes a custodian API, or runs PIT/`cargo-mutants`.

`Verify` is read-only. It validates the plan, denominator, both mutation
manifests, and the public protected receipt; rederives every count and digest;
and binds every repository input to immutable Git objects. It does not execute
commands or infer an execution from a declared command.

The sole CLI is a transport wrapper:

```text
mutationctl run-planted --repository-root ABS --scratch-root ABS \
  --java ABS --maven ABS --maven-repository ABS --cargo ABS --rustc ABS
mutationctl verify --repository-root ABS
```

Arguments are exact and positional order is fixed. Unknown flags, repeated
flags, relative or unclean paths, trailing arguments, symlinks, aliases, and
input/output path overlap are usage errors. There are no environment or `PATH`
fallbacks. `run-planted` refuses a scratch root inside the repository and
removes only scratch children it created and identity-checked.

## Closed input inventory

The implementation adds strict schemas for the five story artifacts. The
verifier admits exactly these evidence inputs and their schema files:

- `mutation/plan.json`;
- `mutation/denominator.json`;
- `evidence/mutation/java.json`;
- `evidence/mutation/rust.json`;
- `evidence/protected/receipt.json`;
- `evidence/intake/surface-inventory.json`;
- `evidence/java/test-manifest.json` and its exact inventory;
- `evidence/us020-current-head-qualification.json`;
- `evidence/property/manifest.json` and `evidence/fuzz/manifest.json`;
- `evidence/corpus-calibration.json`; and
- the exact public projection files `corpora/hidden/manifest.json` and
  `corpora/sealed/manifest.json`.

The hidden and sealed manifest paths above are special, hard-coded public
projection inputs. The verifier may open those two files but must not enumerate
their directories, join or open an `artifacts[].path`, test whether a protected
artifact exists, or derive any identifier from protected storage. Every other
path containing a `hidden` or `sealed` component is rejected before filesystem
access.

Each repository input records `path`, byte count, SHA-256, and a Git source
anchor `{commit, tree, blob}`. `Verify` resolves the commit with `git cat-file`,
reads committed bytes with `git show`, checks the tree and blob, and compares
the relevant working-tree file to that immutable object. The Java source
materialization is not committed; it is instead bound to the accepted 1.6.0
archive digest, commit, surface-inventory digest, and the exact selected-file
digests. Any selected Java file which does not match that inventory blocks the
run.

## Planted mutation plan

`mutation/plan.json` is a closed, sorted inventory. Each row contains:

```text
runtime, mutant_id, engine=IN_TREE_PLANTED, production_path,
production_file_sha256, unique_match_sha256, replacement_sha256,
build_argv, test_argv, timeout_ms, expected_killing_test_ids
```

The production path must be in the accepted Java study surface or under
`rust/connection-core/src`. A mutation is a fixed, equal-context byte
replacement with exactly one match in the anchored source. It may not edit a
test, manifest, build file, feature definition, generated file, test-only
module, or evidence verifier. The replacement itself is public and is retained
in the plan by digest plus bounded canonical base64. The verifier replays the
replacement in memory and proves that it changes the anchored production file.

The initial inventory is deliberately small and behavior-shaped: at least four
Java and four Rust rows spanning frame admission, strict text/UTF-8, control or
fragment sequencing, and close/terminal behavior. Both runtimes must have a
nonzero denominator. Two mutants which edit the same byte range or have the
same resulting file digest are duplicates and fail verification.

Every mutant gets two fresh attempts. An attempt first runs the fixed build
command; only a successful build proceeds to the fixed test command. The test
command selects real committed tests and must fail for a planted defect. A
compile failure is not a kill. The unmodified baseline runs twice before any
mutant, and the unmodified candidate runs twice again after all mutants.

Maven is invoked offline against the explicit read-only accepted dependency
cache and the canonical 62-class selector from
`evidence/java/test-inventory.json`. Cargo is invoked with `--offline --locked`
against the complete `websocket-core` test surface. Locale, time zone, home,
target directory, and cache paths are fixed below the attempt scratch root.
The runner passes no inherited credential variables. These flags establish an
offline command intent, not a host-level network-isolation claim.

Process evidence retains argv, working-directory class, tool digest/version,
start/finish monotonic durations, deadline, exit status, termination reason,
and bounded stdout/stderr digests and byte counts. It retains no arbitrary
output text. A child which exceeds either output bound is terminated and is
not `KILLED`.

## Exact disposition and denominator math

The only normalized dispositions are:

```text
KILLED
SURVIVED
NOT_EXECUTED
UNCOVERED
TIMEOUT
TOOL_FAILURE
FLAKY
EQUIVALENT
TECHNICALLY_UNVIABLE
```

They have these meanings:

- `KILLED`: both fresh mutant builds pass and both fixed test executions fail
  with the same nonempty selected-test failure set;
- `SURVIVED`: both builds and both test executions pass;
- `NOT_EXECUTED`: a declared attempt has no launched-process receipt;
- `UNCOVERED`: an accepted external engine explicitly reports no covering
  test; the planted runner never guesses this disposition;
- `TIMEOUT`: any build or test exceeds its fixed deadline;
- `TOOL_FAILURE`: launch, protocol, report, cache, or tool-identity failure;
- `FLAKY`: the two attempts disagree in build/test outcome or failure set;
- `EQUIVALENT`: a semantic exclusion supported by technical evidence and an
  independent reviewer; it is never inferred from a surviving mutant; and
- `TECHNICALLY_UNVIABLE`: the mutation cannot form an executable candidate,
  supported by technical evidence and an independent reviewer.

The denominator has exactly one row for every plan row and no other rows. All
nine disposition counts are present, including zeros, and the verifier
recomputes:

```text
full = sum(all nine dispositions)
excluded = EQUIVALENT + TECHNICALLY_UNVIABLE
eligible = full - excluded
missed = SURVIVED + NOT_EXECUTED + UNCOVERED + TIMEOUT + TOOL_FAILURE + FLAKY
score_basis_points = 10000 * KILLED / eligible
```

The owner-relaxed gate requires `eligible > 0`, both runtime denominators
nonzero, `KILLED == eligible`, `missed == 0`, and
`score_basis_points == 10000`. Because independent review is unavailable and
must not be fabricated, this campaign additionally requires
`EQUIVALENT == 0` and `TECHNICALLY_UNVIABLE == 0`. If either occurs, the
artifact remains visible but the status is blocking rather than pass.

`MISSED` is a computed aggregate, not a tenth disposition. The denominator is
content-addressed by canonical JSON SHA-256 and Git, but it is not signed. The
verifier rejects a signature, `signing:true`, or wording which calls the
denominator signed or independently reviewed.

## Before/after reconciliation and anti-stub controls

Before the baseline and after the final candidate run, the runner creates a
snapshot containing:

- the complete selected Java production-file closure from the surface
  inventory;
- the complete Java test-source closure and committed Java test inventory;
- every tracked Rust production and test file under the three workspace
  crates, plus `Cargo.toml`, `Cargo.lock`, and the pinned toolchain file;
- the Java test-manifest and inventory digests and all count fields;
- exact source/test path counts and aggregate closure digests; and
- the exit/test counts for the canonical full Java selector and complete Rust
  workspace test command.

Before and after closure paths and digests must be byte-identical; tests may
not be removed, modified, filtered, ignored, or renamed. Both full commands
must pass with identical discovered/executed/passed counts, zero failed,
skipped, filtered, timed-out, or quarantined tests, and no command selector may
change. The runner operates only on scratch copies, so repository drift during
the campaign is a hard failure.

The Rust empty/stub negative control is a separate fixed executable which
implements the public process envelope but returns no semantic result. The
same bounded public candidate probe used for the real testee must reject it
twice. A planted control is valid only if its production edit compiled and the
real selected tests killed it twice. An offline Go reference-model mutant or a
declared command cannot substitute for either control.

Before and after snapshots also run the incumbent read-only verification
facades for current-head qualification, US-020 differential evidence, and
US-021 property/fuzz evidence. Their input digests and PASS results must be
identical. This is the no-stub reconciliation: the current candidate remains
bound to its existing public behavior evidence while the empty process is
observably rejected.

## Public protected receipt

`evidence/protected/receipt.json` is a deliberately narrow public projection.
It contains no free-form diagnostic or arbitrary byte field. Its fixed fields
are:

```text
schema/story/status/assurance/nonclaim booleans
policy and evaluator digests
tier rows for hidden and sealed
subject rows for pinned_java, rust_candidate, empty_rust, planted_java,
  and planted_rust
isolation-control enums
budget counters
leak-scan counts
source/projection digests
```

Each tier row binds the exact committed manifest digest, corpus ID, expected,
selected, executed, passed, failed, skipped, filtered, timed-out counts,
commitment root, transcript digest, report digest, and custodian policy digest.
The verifier rederives these fields from the public manifest without following
its protected artifact path. Hidden and sealed must each have one row, in that
order, with no extras.

The pinned-Java subject may be `PASS_RETAINED_RECONCILED` only because the
existing calibration and tier manifests bind its two reconciled runs. Until a
new custodian-produced public receipt binds the exact current Rust executable
and controls, the other four subjects must be
`NOT_EXECUTED_NO_PUBLIC_RECEIPT`. They contribute no hidden/sealed candidate or
control claim. A digest which names only a source tree, public run, or declared
command cannot upgrade that disposition.

Isolation controls use enums only. The retained receipt may record the
custodian's distinct identity/workspace/filesystem/cache handling and network
or protected-store denial only when those claims already appear in the bound
public projection. Signing-key separation is
`UNAVAILABLE_NOT_USED`, because no signature is produced. Missing, unknown,
or stronger values block verification; they are never filled with defaults.

The public receipt exposes only counts, booleans, fixed enums, IDs from the two
public manifests, and `sha256:` digests. It has no case IDs, case bodies,
expected outputs, actual outputs, raw diagnostics, salts, keys, tokens,
credentials, paths supplied by the protected store, timestamps, or prose.
Leak counters for all those categories must be zero. The verifier also scans
the five bounded US-022 artifacts for forbidden keys and rejects unknown keys;
it never scans protected storage.

## Strict parsing and fail-closed controls

All five JSON artifacts and their schemas are size-bounded. A token pass
rejects duplicate object keys at any depth before typed decoding. Typed
decoding uses `DisallowUnknownFields`, requires EOF, exact required fields,
exact schema/version/kind values, non-null arrays, checked nonnegative integer
ranges, sorted unique IDs, canonical repository-relative paths, and lowercase
`sha256:` digests. Unknown enum values and omitted booleans fail closed rather
than taking Go zero values.

Hostile tests must prove rejection of at least:

1. a missing or duplicated required field;
2. an extra or reordered denominator row;
3. a recomputed denominator with one undeclared or omitted mutant;
4. a survived, flaky, timeout, compile-failed, or single-attempt mutant relabeled
   `KILLED`;
5. changed before/after source, test, selector, or count evidence;
6. a result attributed to unavailable PIT or `cargo-mutants`;
7. an equivalent or technically-unviable row without independent review;
8. an immutable Git blob, Java source digest, tool identity, or output digest
   mismatch;
9. an empty-stub control relabeled as accepted;
10. a hidden/sealed artifact path followed from a manifest;
11. any protected case, output, diagnostic, secret, credential, signature, or
    arbitrary prose added to the public receipt;
12. a retained Java protected result relabeled as a current Rust result; and
13. an assurance, signing, publication, production, or independence overclaim.

The real `mutationctl verify --repository-root ABS` binary must pass on the
committed artifacts. Tests which call only an injected verifier function do
not establish the CLI path.

## Explicit nonclaims

- no PIT or `cargo-mutants` execution or coverage claim when those accepted
  engines are unavailable;
- no mutation-completeness proof beyond the finite declared planted inventory;
- no signed denominator and no equivalent-mutant review;
- no independent reviewer, signer, custodian independence, or role separation;
- no current Rust, empty/stub Rust, or planted-binary execution against hidden
  or sealed cases without a new digest-bound public custodian receipt;
- no access to protected cases, outputs, diagnostics, salts, keys, credentials,
  or stores;
- no host-enforced network-isolation claim for the public mutation campaign;
- no Autobahn, Docker/wstest, live conformance, production, publication, or
  signing action; and
- no assurance above `OWNER_ATTESTED_NOT_INDEPENDENT`.
