# catalog plane correspondence — round 1

branch: `claude/catalog-plane-correspondence` (from mainline `58f3aa4`)
date: 2026-09-03
assurance: OWNER_ATTESTED_NOT_INDEPENDENT, independent_review_claimed false

Started from `F006 — a vendored catalog judged against the wrong plane`. Five
things were asked for: establish the plane correspondence as checked evidence,
fix the diagnosis `formalcoverctl` emits, repair the two failing packages, keep
the Java-column finding intact, and state the owner question.

---

## 0. The handed-down diagnosis of the two failing packages was wrong

The task said `cmd/formalcoverctl` and `internal/formalcoverage` fail "because
they cite `corpora/frame/codec.json`, absent here for plane reasons." **They do
not.** I regenerated the artifacts and read the diff before touching anything:

```
-      "sha256": "sha256:5370eb0856a1f0f3d5c6c10999710d6189c06c0dfedd81c64bb0c1cf42563833",
-      "git_blob": "7b2313953a5e62aa129be29382a67f9b41ce52ad"
+      "sha256": "sha256:83419ff9615fb73ccd9c2b33ed488b040c1acf9796365d978340724d2b10e742",
+      "git_blob": "4eb417b8b4e87f6871df4d3d00a96cbd3a6a109c"
```

One input, `evidence/linkage/rust-identity-verification.json`. The retained
report was written at `bce5a07` against blob `7b23139`; mainline had already
moved that file to `4eb417b` at `518c81a` (the DIV-06 handshake change shifted
`rust/ws-core/src/connection.rs`, and the linkage overlay was refrozen). The
merge `92556bd` took mainline's newer file and did not regenerate the report.

`corpora/frame/codec.json` is not involved. Its absence IS baked into the
retained reconciliation as a basis pin — and the reconciliation test **passed**
throughout. An absent basis pin was already reconciled; it caused no failure.

So the repair is: the two packages failed for **stale derived evidence after a
merge**, on this plane, with nothing to do with planes at all. That is the third
mis-diagnosis in this chain, and it is the same shape as the first two: a
plausible cause accepted without reading the process. I read the diff.

The failures are now fixed by regenerating the retained artifacts, which the
same commit had to do anyway for the reason-code rename. Both packages pass.

Filed as `findings/F008-a-failing-test-explained-by-the-nearest-story.md`. The
refutation was inside the same test run: the reconciliation test — the only one
that reads that pin — passed while the report test failed. A story that names an
artifact is refuted when the test reading that artifact is not among the
failures, and nobody looked.

---

## 1. The correspondence, crate by crate

Read from both trees, never from names.

### The fork point

`git merge-base HEAD origin/codex/race-catchup` = `66f33d4` (2026-08-26).
`66f33d4:rust/` holds **exactly one crate**: `connection-core`, `[package] name
= "connection-core"`, no `[lib] name`, `src/` = close.rs, connection.rs,
control.rs, framing.rs, handshake.rs, lib.rs.

### The crate table, read from manifests

| Codex dir | Codex `[package]` | Codex `[lib]` | Claude dir | Claude `[package]` | Claude `[lib]` |
|---|---|---|---|---|---|
| `rust/connection-core` | `websocket-core` | **`websocket_core`** | `rust/ws-core` | `ws-core` | **`ws_core`** |
| `rust/websocket-driver` | `websocket-driver` | (default) | `rust/ws-driver` | `ws-driver` | `ws_driver` |
| `rust/websocket-testee` | `websocket-testee` | (default) | `rust/ws-testee` | `ws-testee` | `ws_testee` |
| — | — | — | `rust/ws-oracle-harness`, `rust/candidate-stub` | | Claude-only |

**The catalog's namespaces are the Codex plane's LIBRARY names, not its
directory names.** The directory that ships `websocket_core` is called
`connection-core`. This matters beyond bookkeeping — see §2.

### `websocket_core` ↔ `ws_core` — ancestry holds, identity does not

- Both descend from `66f33d4:rust/connection-core`.
- This plane renamed it at `9fe68ff`, "feat(us-009-prep): rename scaffold crate
  to ws_core per owner decision". `git show -M` reports pure renames:
  `rust/{connection-core => ws-core}/src/{close,connection,control,framing,handshake}.rs`,
  **zero changed lines**.
- Authority: `evidence/governance/decisions/us009-us008-owner-decisions-2026-08-27.json`,
  `us009_crate_naming = ws_core` — "The rust/connection-core scaffold is renamed
  to match; the PRD text's crates/websocket-core is superseded."
- The Codex plane kept the directory and set `[lib] name = "websocket_core"`.

**Why this is not an identity.** The owner decision is about THIS plane's own
scaffold; it names no Codex crate and does not reach across the planes. And the
shared scaffold is the thing both planes then replaced: Codex deleted
`framing.rs` and added `frame/{decode,encode,mask,mod}.rs` plus `utf8.rs`;
Claude kept `framing.rs` and added `config.rs`, `error.rs`, `event.rs`,
`message.rs`, `queue.rs`. **Verdict: SHARED_ANCESTRY_ONLY.**

### `websocket_driver` ↔ `ws_driver` — a recorded borrow, explicitly adapted

Neither plane had this crate at the fork. `borrow-receipt-batch-c.json` records
`rust/websocket-driver/src/lib.rs` (blob `43acb6c3`) adapted into
`rust/ws-driver/src/lib.rs` at `7867681`. The receipt's own summary enumerates
what was NOT taken: the AdmissionGate + `mpsc::sync_channel` producer machinery,
the StepResult-batch commit ledger, the `ProducersDropped` disposition.
**Verdict: BORROW_RECEIPT_RECORDS_AN_ADAPTATION.**

### `websocket_testee` ↔ `ws_testee`

Borrowed by the same receipt (five files by blob). **The catalog never names it**
— no obligation touches it, so it carries no weight here. Recorded for
completeness, not used.

### The four source paths

| catalog path | obligations | here? | candidate here | state |
|---|---:|---|---|---|
| `rust/connection-core/src/connection.rs` | 10 | no | `rust/ws-core/src/connection.rs` | SHARED_ANCESTRY_ONLY |
| `rust/connection-core/src/frame/decode.rs` | 9 | no | `rust/ws-core/src/framing.rs` | BORROW (many-to-one) |
| `rust/connection-core/src/frame/mask.rs` | 3 | no | — | NO_RECORDED_CORRESPONDENCE |
| `rust/websocket-driver/src/lib.rs` | 2 | no | `rust/ws-driver/src/lib.rs` | BORROW (one-to-one) |

- `connection.rs`: batch C records Codex's US-015 and US-016 arms as **"studied,
  NOT grafted"** and its close machinery as "NOT adopted — nearly every behavior
  diverges from shipped Java." This plane deliberately did not take it, twice.
- `frame/decode.rs`: batch A maps it AND `frame/encode.rs` into the single file
  `framing.rs`. Its summary says the borrowed body was rewritten because Codex's
  header-time validation order is RFC-strict where this plane's is Java-faithful
  — which is precisely what five of the nine obligations on this path assert.
- `frame/mask.rs`: **no receipt in the store names it as a source.** This plane
  has masking code (`Draft6455::apply_mask`), and that is exactly why the state
  is NO_RECORDED_CORRESPONDENCE rather than NO_COUNTERPART: the risk is not an
  empty tree, it is a plausible function being adopted as somebody else's proof
  subject without anyone deciding it is.

### The five production symbols

| catalog symbol | oblig. | nearest here (checked at its line) | what defeats substitution |
|---|---:|---|---|
| `websocket_core::ConnectionCore::step` | 9 | `ws-core/src/connection.rs:393` `pub fn handle(&mut self, input: Input<'_>) -> Result<(), TypedProtocolFailure> {` | Codex returns one `StepResult`; here it is `handle` + `next_write` + `next_event`. A property of a single-call result is not a property of a three-call drive-and-drain. |
| `websocket_core::FailureKind` | 1 | `ws-core/src/error.rs:38` `pub enum FailureCode {` | Different enum, different module, different name; no receipt or decision maps them. |
| `websocket_core::frame::decode::FrameHeaderDecoder::decode_header` | 9 | `ws-core/src/framing.rs:357` `pub fn decode_frame_header(` | No `FrameHeaderDecoder` here; entry point is inherent on `Draft6455`, and the receipt says the two reject different inputs by construction. |
| `websocket_core::frame::mask::apply_mask_in_place` | 3 | `ws-core/src/framing.rs:269` `pub fn apply_mask(payload: &mut [u8], key: [u8; 4]) {` | Codex's takes `payload_offset: usize`; this one takes a slice already cut. `obligation.mask-equation` is *about* that offset. |
| `websocket_driver::ConnectionOwner::poll` | 2 | `ws-driver/src/lib.rs:756` `pub fn poll<'owner>(&'owner mut self, input: DriverInput<'_>) -> PollResult<'owner> {` | Signature is character-identical to Codex's line 438. **The receiver is not**: line 643 here reads `impl ConnectionDriver {`, Codex's line 373 reads `pub struct ConnectionOwner {`. |

That last row is the trap: an identical signature on a differently named type
whose queueing machinery the receipt says was replaced. It is where a
name-normalising rule would be most tempting and most misleading.

### What I did NOT do

**I did not establish a correspondence.** No row reaches
`ESTABLISHED_BY_OWNER_DECISION`, and the verifier refuses one that tries without
a decision record in the protected store naming the key. The mapping is the
owner's to make.

---

## 2. The corrected diagnosis

### The reason codes were false as stated

| was | now |
|---|---|
| `CATALOG_RUST_SOURCE_PATH_EXISTS_IN_NO_TREE` | `CATALOG_RUST_SOURCE_PATH_ABSENT_FROM_THIS_PLANE` |
| `CATALOG_RUST_NAMESPACE_MATCHES_NO_SHIPPED_CRATE` | `CATALOG_RUST_NAMESPACE_NAMES_NO_CRATE_SHIPPED_BY_THIS_PLANE` |
| — | `CATALOG_IS_ABOUT_ANOTHER_PLANE_AND_NO_CORRESPONDENCE_TO_THIS_ONE_IS_ESTABLISHED` |

The path exists in the tree the catalog is about; the namespace names a library
that tree ships. The old codes indicted a document for a lookup performed
against the wrong subject. The symptoms stay (they are true of this tree); the
cause is added beside them. **24/24 still block; each now blocks for reasons
that are true, and each carries three Rust-side reasons where it carried two.**

### A latent defect of the same class, found in the checker itself

`shippedCrateNamespaces` derived the namespace from the **crate directory name**
(`strings.ReplaceAll(entry.Name(), "-", "_")`). Run against the Codex plane it
would have computed `connection_core` and reported the catalog's own
`websocket_core` as "matching no shipped crate" — **a false accusation on the
very plane the document is about.** It now reads `[lib] name` from each manifest
(falling back to `[package] name`). This is exactly *existence standing in for
identity*: a directory whose name looks right, accepted for the crate identity.

On this plane the fix changes no output — every directory here happens to agree
with its `[lib]` name — which is why the RED reading is written against a
**fixture** shaped like the origin plane. A test against this tree alone would
have passed with the old code and proved nothing.

### A basis pin that is absent is not a pin that drifted

New `BASIS_PIN_PATH_IS_ABSENT_FROM_THIS_PLANE`. `corpora/frame/codec.json` had
been reported as `BASIS_PIN_DOES_NOT_MATCH_FILE_ON_DISK` with
`on_disk: READ_FAILED`. Drift claims the pinned file moved; absence says the pin
is about another tree. Same class again, mirror direction.

### Independent recomputation of the five pins

I recomputed all five against both trees rather than trusting F006:

| pin | this plane | Codex plane |
|---|---|---|
| `assurance/developer-tools/port-seam-dossier.json` | MATCH | MATCH |
| `assurance/formal/proof-targets.json` | differs | differs (matches Codex `89ecf1e` blob `cb1baec1` exactly) |
| `corpora/frame/codec.json` | ABSENT | MATCH |
| `evidence/intake/compatibility-surface.json` | differs | MATCH |
| `evidence/intake/semantic-id-migration-map.json` | differs | MATCH |

**Zero of five are fabricated.** Four match Codex's current files, the fifth
matches a Codex commit that plane has since moved past (`89ecf1e` is an ancestor
of `origin/codex/race-catchup` and not of HEAD). The one that "works" here works
only because that file has not diverged since the fork — coincidence of
non-divergence, not binding.

### A finding I did not expect: the two planes' migration maps have forked

`evidence/intake/semantic-id-migration-map.json` on both planes carries the same
47 Java identities exactly. **33 of 47 rows point at different Rust
identities**, and not by spelling: Codex names designed Rust constructs
(`websocket_core::ServerRequestDescriptor`,
`websocket_core::frame::decode::FrameHeaderDecode`) where this plane names
transliterations of the Java type (`ws_core::connection::WebSocketAdapter`,
`ws_core::framing::IncompleteException`). The two documents describe **different
target designs**, not two spellings of one. That is additional weight against a
mechanical name mapping, and it is not in the artifact because 33 rows of it are
not needed to answer the question — recorded here instead.

---

## 3. The Java column, restated and unweakened

Nothing above touches it. Re-derived from the catalog in this session:

- All **24** `java_bindings` share **ONE** `source_sha256` — the whole-archive
  digest. The column distinguishes no two obligations by content.
- All **24** read `connection_state: DISCONNECTED`.
- Its 15 distinct `source_path` values are **synthesised** — they treat a METHOD
  as a file (`upstream-java/org/java_websocket/WebSocketAdapter/onWebsocketPing.java`)
  and exist on **neither** plane.

`TestTheJavaColumnFindingSurvivesTheCorrection` asserts all three, and fails if
any `java_bindings` source path ever appears on this plane. The plane record's
`not_claims` name the Java column explicitly, and a test pins that text so the
finding cannot be quietly dropped from the document that corrects the Rust one.

**The corrected diagnosis is about the Rust column only.** The Java column is
genuinely unbound, on every plane, and it is the real defect.

---

## 4. The owner question

Written into `assurance/formal/plane-correspondence.json` and verified non-empty
(both the question and its evidence requirement).

> **Can this plane be measured against master US-008's 24-obligation denominator
> at all?** The denominator is a Codex-plane document whose Rust column names
> Codex-plane crates, files and symbols. No row reaches
> `ESTABLISHED_BY_OWNER_DECISION`, so today the honest answer is **no**: a
> coverage number over this catalog computed here would be a number about a
> document that is about another tree.

The options, stated so the owner picks rather than infers:

- **(a)** Declare a plane correspondence, crate by crate and symbol by symbol,
  with §1 as its material.
- **(b)** Re-vendor the catalog from the Codex plane's current state and rebind
  its Rust column to this plane's crates — which changes the denominator and
  therefore every number over it.
- **(c)** Rule that US-008's denominator is measured on the Codex plane only,
  and this plane carries a denominator of its own.
- **(d)** What must NOT happen: a name-normalising rule rewriting
  `websocket_core` → `ws_core` inside the tooling. That makes an unbound column
  read as bound and is the defect this whole document exists to prevent.

**Evidence required to answer it** (also in the artifact):

1. An owner ruling on whether the crates are the same subject. The material is
   here — shared ancestry at `66f33d4`, borrow receipts, a per-file divergence
   list. What is missing is the ruling, and it cannot be inferred from any of it.
2. Per-symbol rulings. Three of five differ in a way that changes what the
   obligation *says*: `step` vs `handle`+drain, an offset parameter on one side
   only, an enum with a different name in a different module.
3. A ruling on the fifth basis pin: re-pin `proof-targets.json`, or read the
   denominator as of Codex `89ecf1e`.
4. Independent review. Everything here is owner-attested and was produced by the
   same agent that wrote the tool that reads it.

---

## 5. RED readings and deletion attacks

### Sweep 1 — the 35 plane-record checks

Harness: a uniform, compiling suppression in the `add` closure keyed on an env
var, one check dropped per run, full test suite each time, hook reverted after.

- **First run: 19 of 35 SURVIVED.** Green when deleted is not evidence. Exactly
  the failure mode the task warned about (an earlier track had eleven).
  Survivors included `AN_EQUAL_NAMESPACE_IS_NOT_SILENTLY_WEAKENED`,
  `CATALOG_STILL_VENDORED_BYTES`, all three `ONE_ROW_PER_*`, all three
  `ROW_NAMES_A_*_THE_CATALOG_USES`, `NEAREST_DECLARATION_FILE_EXISTS`,
  `NEAREST_DECLARATION_LINE_IS_IN_THE_FILE`,
  `OWNER_DECISION_LIVES_IN_THE_PROTECTED_STORE`,
  `ORIGIN_PLANE_IS_NOT_WRITABLE_FROM_HERE`, and both owner-question checks.
- Nineteen tests added, one per survivor.
- **Second run: 35 of 35 killed, 0 survivors.**

### Sweep 2 — the nine non-check changes

Every mutation was compiled before being tested; a mutation that breaks the
build proves nothing.

| mutation | first killing test |
|---|---|
| `CrateLibNamespace` reverts to the directory name | `TestACrateShipsTheNamespaceItsManifestDeclaresNotItsDirectoryName` |
| `CrateLibNamespace` ignores `[lib] name` | **SURVIVED first pass** → `TestALibNameThatDisagreesWithThePackageNameWins` |
| absent basis pin reported as DRIFT again | `TestRetainedReconciliationIsExactlyWhatTheDenominatorsDerive` |
| plane block reason never emitted | `TestRetainedReportsAreExactlyWhatTheEvidenceDerives` |
| every Rust row declared measurable here | `TestRetainedReconciliationIsExactlyWhatTheDenominatorsDerive` |
| a weak state authorises measurement | `TestRetainedReconciliationIsExactlyWhatTheDenominatorsDerive` |
| plane findings no longer refuse the reconciliation | `TestAPlaneRecordThatDoesNotCheckOutRefusesTheWholeReconciliation` |
| reason codes revert to indicting the catalog | `TestRetainedReportsAreExactlyWhatTheEvidenceDerives` |
| Rust mismatches filed as catalog defects again | `TestRetainedReportsAreExactlyWhatTheEvidenceDerives` |

The `[lib]`-name survivor is worth naming: on **both** planes the package name
with hyphens replaced happens to equal the library name, so nothing in either
tree distinguished the two branches. It only fell to a fixture where they
disagree.

**Second reading of sweep 2:** five of the nine died only on the retained-artifact
byte comparison, which detects that the output CHANGED and says nothing about
whether it is right. Four of those five are also caught semantically
(`TestEveryObligationBlocksOnTheUnestablishedPlaneCorrespondence`,
`TestCatalogBasisPinsAreComparedAgainstTheFilesOnDisk`). The fifth — the reason
codes — had no semantic guard, so
`TestTheRustReasonCodesNameThePlaneTheyAreTrueOf` and
`TestThePlaneBlockAppearsBesideTheSymptomsNotInsteadOfThem` were added.

**Final: 44 of 44 mutations die, 0 survivors.** `plane_test.go` carries 50
tests; 23 of them exist only because a check survived deletion.

### The counterpart reading

A blocking reason that can never be absent is not derived from anything.
`TestAnEstablishedCorrespondenceRemovesThePlaneBlockForThoseObligationsOnly`
grants an established correspondence inside a throwaway sandbox against a
decision record written for the purpose, and asserts the plane block clears for
**exactly** the 2 obligations on that path and stays on the other 22 — and that
the freeze still blocks **24/24**, because the plane correspondence was never
the only reason anything blocked.

---

## 6. Exit codes, read from the process

Read from a **built binary**, not `go run` (which returns 1 for any non-zero
child and would have hidden the 2):

```
formalcoverctl report      -repo .   exit=0
formalcoverctl verify      -repo .   exit=0   (was: exit 1, "the retained ... is not what the evidence derives")
formalcoverctl freeze-gate -repo .   exit=2   (BLOCKED, as it must be)
```

Headline lines from `verify`:

```
catalog_rust_binding_rows_with_source_path_absent_from_this_plane=24/24
catalog_is_about_plane=origin/codex/race-catchup (verified-java-websocket-port-codex (Codex authority plane)); catalog_rust_rows_measurable_on_this_plane=0/24
plane_mismatch rust/connection-core/src/connection.rs obligations=10 ... path_correspondence=SHARED_ANCESTRY_ONLY
plane_mismatch rust/connection-core/src/frame/decode.rs obligations=9 ... path_correspondence=BORROW_RECEIPT_RECORDS_AN_ADAPTATION
plane_mismatch rust/connection-core/src/frame/mask.rs obligations=3 ... path_correspondence=NO_RECORDED_CORRESPONDENCE_ON_THIS_PLANE
plane_mismatch rust/websocket-driver/src/lib.rs obligations=2 ... path_correspondence=BORROW_RECEIPT_RECORDS_AN_ADAPTATION
basis_pin_path_absent_from_this_plane corpora/frame/codec.json declared=sha256:984e59e8...
blocking_obligations=24/24
plane_correspondence_findings=0
```

Every coverage axis is still 0/24. Nothing moved a numerator.

---

## 7. Claim vocabulary

- **observed** — the plane facts: manifests, merge base, rename detection, file
  and line citations, the pin recomputations, the exit codes. All read from the
  process in this session.
- **differential** — the two planes' migration maps compared row by row (47
  identical Java ids, 33 differing Rust ids); the basis pins computed against
  both trees.
- **bounded** — the plane record's origin-plane columns. The Codex tree is
  fetch-only and a checkout is not required to have the ref, so those columns
  are recorded provenance, **not recomputed**, and the verifier says so in its
  own doc comment. Everything about *this* plane is recomputed every run.
- **not claimed** — proved-model, proved-production, refinement. Nothing here
  proves anything about either program.

---

## 8. What I did NOT do, by name

- **Did not establish any plane correspondence.** No row reaches
  `ESTABLISHED_BY_OWNER_DECISION`; the verifier refuses one that tries.
- **Did not invent a name-normalising rule.** `websocket_core` is not mapped to
  `ws_core` anywhere in the tooling, and `AuthorisesMeasurement` returns true for
  exactly one state.
- **Did not reduce the blocked count.** 24/24 before, 24/24 after, with one more
  true reason each.
- **Did not touch the vendored catalog or its schema.** Its sha256 and git blob
  id are still asserted and still pass, and a new check refuses a plane record
  that describes a catalog other than the vendored bytes.
- **Did not weaken `formalcoverctl` or `javabindctl`.** `javabindctl` untouched;
  `formalcoverctl` gained a verifier, a printed section and stricter refusals.
- **Did not touch the ledger, `internal/deltaledger`, or
  `assurance/concurrency/results.json`.**
- **Did not write to `origin/codex/race-catchup`.** Read-only throughout.
- **Did not run any owner gate.** No AWS, no benchmark, no Autobahn.
- **Did not verify the Codex plane's declaration lines by compilation.** They are
  grep-class reads of a fetched tree — reviewed-glancer strength, not semantic
  resolution — and are recorded as provenance rather than recomputed.
- **Did not recompute the origin plane inside the verifier.** A checkout without
  the ref would fail a check that has nothing to do with its tree, and the
  retained-artifact byte comparison would become environment-dependent. The
  cost is that the origin-plane columns are asserted; that cost is stated in the
  code and in the artifact's `not_claims`.
- **Did not decide whether `Draft6455::apply_mask` is the counterpart of
  `apply_mask_in_place`.** It is the obvious guess and it is exactly the guess
  this document exists to refuse taking.
- **Did not update `.claude/GOAL-LOOP.md`.** Mainline coordination; this branch
  does not merge.

---

## 9. Residual, and where this could still be wrong

- The plane record's origin-plane columns are **unverified by machine**. A
  future edit could change `origin_plane_lib_name` to anything and no test would
  notice. Closing that needs the ref fetched at test time, which would make the
  suite depend on a remote — a trade recorded rather than taken.
- `TestThePlaneRecordDoesNotWeakenTheJavaFinding` pins three phrases in the
  `not_claims` text. Prose pinned by substring is a weak guard; it catches
  deletion, not dilution.
- **`plane-correspondence.json` has no JSON Schema.** My first draft declared
  `$schema: ../../schemas/us023-plane-correspondence-1.0.0.schema.json`, which
  does not exist — a dangling reference that would have read as validation
  nobody performs. I removed the key rather than write a schema I would not have
  had time to test, which also matches its siblings:
  `denominator-reconciliation.json` and `catalog-correction-proposal.json`,
  written by the same package, carry no `$schema` either. The Go verifier is the
  only checker, and it checks content rather than shape.
- The correspondence states are my judgement of what the receipts say. The
  receipts' words ("adapted", "studied, NOT grafted", "NOT adopted") are quoted
  verbatim in the artifact so a reader can disagree with my reading of them
  without re-reading the store.

---

## 10. Gate readings

`make -C rust gates` with `VJWP_PROTECTED_STORE` set, read from the process:

```
GATES_EXIT=0
```

Nine PASS verdicts, zero non-PASS, run to completion through `oraclerankctl`:

- `gate=forbid-unsafe PASS` — 10 first-party crate roots all carry `#![forbid(unsafe_code)]`
- `gate=dependency-inventory PASS`, `gate=msrv PASS` (1.95.0), `gate=license PASS`,
  `gate=audit PASS`, `gate=lockfile PASS` (`Cargo.lock` byte-identical and git-clean)
- `gate=canaries PASS` — polarity proven: good-scaffold 0/0/0, bad-scaffold failed
  scan and clippy as required (1/101)
- `gate=adapter-linkage PASS` — exact over 5 production sources
- `ac1-gates verdict=PASS gates_passed=8/8`
- ledger integrity verified (frozen prefix through sequence 35,
  `unledgered_disagreements` recomputed = 0)
- `evidence/governance/owner-decision-digests.json` equals the derivation, 6 governance
  record digests recomputed from the protected store and matched
- `oraclerankctl`: 640 propositions adjudicated, 589 agreements, 38 overridden and every
  one enrolled

**A first attempt at this gate exited non-zero and it was my own fault, not the tree's:**
I omitted `VJWP_PROTECTED_STORE`, and the ledger gate REFUSED rather than skipping. That
is the gate working — a governance check that cannot read the protected store must not
quietly pass — and it is worth recording because "the gate failed" would have been the
wrong reading of it. Everything before that point had already reported
`ac1-gates verdict=PASS gates_passed=8/8` in that same run.

### Go suite

`internal/formalcoverage` and `cmd/formalcoverctl` green under `-count=1` across several
runs, including after every artifact regeneration. `internal/javabind` and
`cmd/javabindctl` green — that is where the vendored catalog's sha256 and git blob id are
asserted, so the immutability constraint is confirmed by a package this branch did not
touch. A whole-repository `-count=1` run was still executing when this record was written,
under load average 30 on 4 cores from sibling agents; its verdict is NOT read here and is
not claimed. The three declared baseline failures (`internal/lab`, `internal/portplan`,
`internal/formalplan`) were not investigated and were not expected to move.
