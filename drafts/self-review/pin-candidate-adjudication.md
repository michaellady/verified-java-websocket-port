# Adjudicating every dangling-pin candidate by reading it

Status: COMPLETE for what it claims. All 85 candidate objects read and classified; 9 are
real, 76 are the false positive the detector's own ceiling predicted. Zero were mechanically
fixable, and this record says why for each.

Branch `claude/pin-candidate-adjudication`, rebased onto mainline
`claude/feature/verified-java-websocket-port` at `047eea6`. Date 2026-09-03. Scope:
`cmd/pinconsumerctl/` (precision rules + 7 tests), one `.gitignore` line, and this record. No
evidence document, no ledger, no corpus and no `assurance/` file was modified:
`git diff --quiet origin/claude/feature/verified-java-websocket-port HEAD -- evidence/ assurance/ internal/ corpora/ rust/ drafts/ledger-proposals/`
exits **0**.

## 1. The headline: the number was never a defect count

The census began at **85** candidates on `fb72adb`. Mainline `420bed2` then landed
`pinsAFieldInside` and the reported figure became **77**. Both numbers describe the same 85
objects; the second silently subtracts 8 of them. This record adjudicates all 85.

| class | rows |
|---|---|
| FALSE POSITIVE — the digest covers something other than the co-located path | **76** |
| TRUE, not mechanically fixable (owner decision or hard stop) | **5** |
| TRUE, and must NOT be fixed — a dated attestation, not a live pin | **2** |
| TRUE — already filed as F014 | **2** |

**Nothing was fixed, and that is the finding.** The brief authorised fixing only pins whose
propagation is mechanical with no number moving. Not one of the 9 true pins qualifies: three
are the formal denominator's declared basis, two sit in the protected governance store, two
pin bytes that exist in no branch of this repository, and two are F014, already filed.
Section 4 gives the measurement for each.

## 2. What mainline's `pinsAFieldInside` retired, and the agreement it produced

`420bed2` exempts a digest that appears as a digest-valued string inside the named file — a
ledger head is not the ledger file's sha256. It retired exactly these 8 rows:

| row | why it is not a file pin |
|---|---|
| `assurance/concurrency/plan.json` `$.behavior_delta_ledger` | `observed_head` = `records[57].record_digest`, the LAST of 58 — the current head |
| `div05-…-correction.json` `$.targets_record` | `record_digest` = `records[53]`, and the object says `sequence: 54` |
| `delta-ledger-receipt.json` `$` | `ledger_head` = `records[31]` — the head when the receipt was written, `2026-08-27` |
| `legacy-record-adjudications.json` `$` | `accepted_root_digest` = the ledger's own top-level accepted root |
| `java-intake-manifest.json` `$.build` | `inherited_accepted_root_digest` — the same accepted root, inherited from US-002 |
| `proof-targets.json` `$.sources.quarantined_java_tree` | `archive_sha256` = `f44e7647…`, the value `portplan.SourceArchiveSHA256` pins for the `.tar.gz` |
| `assurance/mutation/denominator.json` `$.arms[0,1].separation.credential` | `declared` = `generator.secret_seed_commitment`, read out of the corpus manifests |

I had classified all 8 as false positives independently, before the rebase, by reading them.
The code and the reading agree row for row. **Rows retired by `420bed2` are dropped from this
record's prose and carried only in the census table**, marked as retired there.

The ledger moved under this work — 56 records to 58 — while a concurrent session appended
supersessions. Every ledger row above was re-measured on the rebased tree; `observed_head`
now resolves to `records[57]`, still the current head, which is the point of mainline's fix:
that pin is correct and no update could ever have cleared it.

## 3. The four shapes the reading found that code did not yet cover

None of these was classified by its key name. Each was proven by recomputing the value from
bytes in the tree and requiring an exact match.

**Tree envelope (25 rows).** `assurance/fuzz/manifest.json` and its 24 fixtures pin
`rust/rust-toolchain.toml` with `pin_digest: sha256:4a1f4893…` while the file hashes to
`70025e01…`. That file has had exactly **one** version in the whole history (`93f5444`), so
`4a1f4893…` was never its digest — which is the tell. `internal/fuzzpin.TreeDigest` digests a
file LIST as `"relpath\x00filedigest\n"` lines:

```
sha256("rust/rust-toolchain.toml" + 0x00 + "70025e01…" + "\n") = 4a1f489390955d74… == pinned
```

`internal/fuzzpin/check.go:102` compares against exactly this value, unconditionally, so the
gate is green and correct. Verified for all 25.

**Sibling line-array (14 rows).** Each run object in `assurance/fuzz/campaign/result.json`
carries `log_path` beside `outcome_digest`, and both runs of a campaign share one
`outcome_digest` — which no two distinct log files could. `fuzzpin.digestLines(outcome_lines)`
reproduces it for **14 of 14** runs, 0 mismatches: it digests the test-outcome lines, stable
across runs, while the logs differ in wall-clock timings.

**Mutation operand (5 rows).** `{"kind":"json_set","target":<path>,"pointer":…,"value":"sha256:cccc…"}`
is an instruction. The synthetic repeated-nibble digest is the payload a seeded defect
writes, not a pin that drifted. One of the five nests the operand a level deeper, as
`{"path":…,"sha256":…}` under `value` — the `us006-placeholder-receipt` fixture — and is
reported still, because the recomputable rule does not reach inside an operand's value.

**Realized fixture tree (22 rows).** Every `us006-cases.json` case pairs
`mutation_manifest_path` with `realized_tree_sha256`.
`internal/formalplan/backend_test.go:935` computes it as
`us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the tree produced by
APPLYING the mutation, not of `mutation.json`. Proven by construction from the code path; it
is **not** confirmed by execution here, and section 5 says why.

**Deliberate negative fixture (1 row).** `toolchain-pin-drift.json` pins `1111…`, and
`assurance/fuzz/fixtures/cases.json` requires that case to produce exit 1 and
`FUZZ_TOOLCHAIN_PIN_DRIFT`. Its mismatch is the assertion; repairing it would break the test.

## 4. The nine true pins, and why none was fixable

**The formal denominator's declared basis — 3 rows, hard stop.**
`assurance/formal/obligation-catalog.json` `$.denominator_basis[1,3,4]`. Genuine: each pinned
sha256 equals the sha256 of the `git.blob` recorded in the same object, so the digest is
unambiguously of that path at that commit.

The anchor commit `1ff89fa` is **not an ancestor of HEAD**. `git branch -a --contains 1ff89fa`
returns only `remotes/origin/codex/race-catchup`, which is read-only. The basis is a frozen
provenance record of the tree the catalog was vendored from, and
`internal/formalcoverage/reconcile.go:404` already measures the disagreement and publishes it
in `assurance/formal/denominator-reconciliation.json`, which today reads
`BASIS_PIN_DOES_NOT_MATCH_FILE_ON_DISK` for all three. It deliberately distinguishes that
code from `BASIS_PIN_PATH_IS_ABSENT_FROM_THIS_PLANE`, which a fifth entry carries:
`corpora/frame/codec.json` is untracked and absent, so `dangling` never saw it at all.

This drift is declared, not hidden. Updating the pins would erase the catalog's recorded
provenance and silently re-baseline the formal denominator. **Owner action required: decide
whether the vendored catalog is re-anchored to this branch. Nobody should do that as
propagation.**

**A corroboration receipt pinning bytes that never existed — 2 rows.**
`drafts/ledger-proposals/java-formal-binding-corroborations.json` `$.evidence_basis.receipt`
and `.projection`. The shape is a bare `{path, sha256}`, and the sibling `spec` entry matches
its file exactly, so the schema does mean "sha256 OF path". But `17290017…` and `62758083…`
match **no version of those files on any branch** — each has exactly one blob in all of
history (`4a4dff73…`, `02a9b130…`) and no canonicalisation (sorted, compact, re-indented,
trailing-newline) reproduces the pinned values. Nothing validates them:
`internal/deltaledger/proposal_drafts.go:50` excludes this file from `ProposalDraftPaths()`
by name, calling it a corroboration receipt rather than a record proposal.

This is not mechanically fixable in the sense the brief defines: there are **no retained
bytes to diff against**, so "show the non-digest changed-line count is zero" cannot be
performed at all. Writing the current digests in would assert a corroboration nobody
measured. **Owner action required: re-run the round-1 corroboration against current bytes,
or withdraw the two pins.**

**The E3 governance receipt — 2 rows, must NOT be fixed.**
`evidence/governance/decisions/e3-formal-receipt.json` `$.artifacts.results_documents[0,1]`
pin `frame-results.json` and `close-model-results.json` at digests the later review rounds
`185e8c2`, `ec52ff3` and `f97d04a` moved. The receipt is layered and already correct: the
current digests are recorded in the same document at
`$.review_round_5.artifacts_this_round.results[0]` and `[1]`. The top-level block is a dated
attestation of what the worker produced at `recorded_at 2026-08-28T01:28:46Z`; rewriting it
would make the receipt claim bytes the worker did not produce, inside the protected store.
No action needed — the document is internally consistent, and only looks like drift.

**F014 — 2 rows.** `evidence/java/test-manifest.json` pins `internal/lab/executor_darwin.go`
and `internal/lab/sandbox.go`, both drifted. Already filed as
`drafts/self-review/findings/F014-a-code-binding-verified-against-a-copy-of-itself.md`, and
still reported after every precision change on this branch, which is the calibration that
matters.

## 5. What I could not verify here, stated rather than papered over

**Four Go packages fail, and only three of them are environmental.**
`go test ./... -timeout 40m` exits **1** with four failing packages:
`internal/lab`, `internal/portplan`, `internal/formalplan` and `internal/deltaledger`.
41 packages pass.

*The three environmental ones.* The standing baseline names only `lab` and `portplan`;
`internal/formalplan` is a third, contributing **27** failing leaf tests. Every failure
message across all three traces to one cause — the quarantined Java tree. Reducing the whole
suite's failure detail lines to distinct causes leaves twelve, and eleven of them name
`JAVA_SOURCE_UNAVAILABLE_OFFLINE`, `JAVA_QUARANTINE_UNAVAILABLE`, or
`MODEL_CITATION_UNVERIFIED … quarantined Java tree unavailable`. The cause is outside the
repository: `.quarantine/` is empty and
`curl -L https://github.com/TooTallNate/Java-WebSocket/archive/da3cf2a….tar.gz` returns
**403** through this environment's proxy, whose own status reports `enabled: true` with no
relay failures. `internal/portplan` owns `EnsureQuarantinedSource`, so `formalplan` fails for
its neighbour's reason. **Owner action required: correct the baseline failing-package list to
`internal/lab`, `internal/portplan`, `internal/formalplan` for an environment without the
quarantined archive, or provision the archive.** No gated run was triggered to find this.

*The fourth is not environmental, and it is not mine.* `internal/deltaledger` fails three
subtests of `TestVerifyLegacyAdjudicationsRefusesEachWayAnEntryCanFailToBind`:

```
an_unresolved_entry_states_no_blocking_question
    the gate refused, but not for the reason under attack.
    wanted a message containing: says what WOULD
    got: sequence 19: examination is "evidence-settles-it" but a blocking_question
         is stated. A settled record has nothing blocking
an_entry_claims_both_a_class_and_that_the_evidence_does_not_settle_it
    the gate ACCEPTED a document in which an entry claims both a class and that
    the evidence does not settle it
the_published_residual_understates_the_chain
    the gate ACCEPTED a document in which the published residual understates the chain
```

Two of the three are the gate **accepting** a document it exists to refuse: deletion attacks
that no longer land. This branch does not touch `internal/deltaledger`, and the pre-rebase
suite on `c738b81` had **three** failing packages, not four. Checked out clean at mainline
`047eea6` in a scratch worktree, with no commit of mine present,
`go test ./internal/deltaledger/` exits **1** with the same three subtests failing. It is a
mainline regression, most plausibly from `07a60a2`, which changed sequence 19's examination
to `evidence-settles-it` — the exact field the first failure names. **Owner action required:
this is a live hole in the legacy-adjudication gate and it is outside this branch's remit to
fix.** Note that `make -C rust gates` exits **0** with this hole open, because the Go suite is
not in that chain — which is why the brief says to run both.

The consequence for this adjudication: the 22 `realized_tree_sha256` rows are proven false
positives **by construction**, from the code path that computes them, and are *not* confirmed
by execution, because `TestUS006FixtureCatalogThroughRealCLI` cannot realize a fixture tree
without the archive. `US006_REGENERATE=1` was **not** run: there is nothing to refreeze, and
running it here would rewrite 22 frozen digests from trees built without the Java source.

## 6. The detector now prints the proof for what it subtracts

Four of the shapes in section 3 are recomputable, so the tool no longer needs a human to
re-derive them. Against mainline's 77, this branch reports **34** candidates, and prints all
**51** subtractions — mainline's 8 included — on their own `gate=pin-dangling-explained`
lines carrying the reason and the subject:

```
gate=pin-dangling json_artifacts=1996 unparsable=0 candidates=34 explained=51
   tree-envelope 25 | sibling-lines 14 | field-inside-file 6 | mutation-operand 4 | field-provenance 2
```

The candidate set is a strict subset of mainline's: `comm` over the two sorted candidate
lists shows **0** rows reported here that mainline does not report. The rules only subtract,
and only what they can recompute.

The property that makes subtraction safe: **every rule reads an input that drifts too.** The
envelope rule hashes the file's current bytes, so editing the file makes the pin dangle
again. `TestTreeEnvelopeExplanationStopsApplyingWhenTheFileDrifts` edits the pinned toolchain
file and requires the candidate back — a rule keyed on the *name* `pin_digest` would pass the
firing test and fail that one. The field-pin decision is still `pinsAFieldInside`'s, called
rather than reimplemented, so there is one implementation of it; this branch only adds the
location so a reader auditing a subtraction need not go looking.

No rule trusts a key name. `realized_tree_sha256` therefore stays a candidate on all 22 rows
even though this record adjudicates it false, because the tool cannot realize a fixture tree.

`TestAdjudicatedTrueDanglingPinsAreStillReported` pins all nine true positives against future
precision work. **21 tests pass, exit 0** — mainline's 14, including the 7 deletion attacks,
the F014 guard and both field-pin direction tests, unchanged.

## 7. One repository-hygiene fix

`.gitignore` enumerates every CLI built into the repository root — 24 of them — and
`pinconsumerctl` was missing, which is why a 3.9 MiB binary of it is committed at `420bed2`
and why my own first commit added one too. The entry is added and the binary removed. This
moves no measurement.

## 8. The full census, all 85 rows

Row numbers are the detector's own sort order (artifact, then pointer). "Retired by" says which
mechanism now subtracts the row; "— still a candidate" means the tool reports it and a reader
must judge it.

| # | artifact | pointer | names | classification | retired by | evidence |
|---|---|---|---|---|---|---|
| 1 | `assurance/concurrency/plan.json` | `$.behavior_delta_ledger` | `evidence/java/behavior-delta-ledger.json` | FALSE POSITIVE | mainline `420bed2` | the digest is a value the named file CARRIES (ledger head / record / accepted root / archive digest) |
| 2 | `assurance/formal/obligation-catalog.json` | `$.denominator_basis[1]` | `assurance/formal/proof-targets.json` | TRUE, not mechanically fixable | — still a candidate | pin == sha256 of the recorded `git.blob`; anchor `1ff89fa` is NOT an ancestor of HEAD (only on read-only `origin/codex/race-catchup`). Already declared drifted in `denominator-reconciliation.json`. DENOMINATOR — hard stop |
| 3 | `assurance/formal/obligation-catalog.json` | `$.denominator_basis[3]` | `evidence/intake/compatibility-surface.json` | TRUE, not mechanically fixable | — still a candidate | same; reconciliation already reports `BASIS_PIN_DOES_NOT_MATCH_FILE_ON_DISK`. DENOMINATOR — hard stop |
| 4 | `assurance/formal/obligation-catalog.json` | `$.denominator_basis[4]` | `evidence/intake/semantic-id-migration-map.json` | TRUE, not mechanically fixable | — still a candidate | same; reconciliation already reports `BASIS_PIN_DOES_NOT_MATCH_FILE_ON_DISK`. DENOMINATOR — hard stop |
| 5 | `assurance/formal/proof-targets.json` | `$.sources.quarantined_java_tree` | `evidence/intake/source-pins.json` | FALSE POSITIVE | mainline `420bed2` | the digest is a value the named file CARRIES (ledger head / record / accepted root / archive digest) |
| 6 | `assurance/fuzz/campaign/result.json` | `$.campaigns[0].runs[0]` | `assurance/fuzz/campaign/handshake-client/handshake-client-run1.log` | FALSE POSITIVE | this branch (`sibling-lines`) | `outcome_digest` = `fuzzpin.digestLines(outcome_lines)`, this object's own array; 14/14 |
| 7 | `assurance/fuzz/campaign/result.json` | `$.campaigns[0].runs[1]` | `assurance/fuzz/campaign/handshake-client/handshake-client-run2.log` | FALSE POSITIVE | this branch (`sibling-lines`) | `outcome_digest` = `fuzzpin.digestLines(outcome_lines)`, this object's own array; 14/14 |
| 8 | `assurance/fuzz/campaign/result.json` | `$.campaigns[1].runs[0]` | `assurance/fuzz/campaign/handshake-server/handshake-server-run1.log` | FALSE POSITIVE | this branch (`sibling-lines`) | `outcome_digest` = `fuzzpin.digestLines(outcome_lines)`, this object's own array; 14/14 |
| 9 | `assurance/fuzz/campaign/result.json` | `$.campaigns[1].runs[1]` | `assurance/fuzz/campaign/handshake-server/handshake-server-run2.log` | FALSE POSITIVE | this branch (`sibling-lines`) | `outcome_digest` = `fuzzpin.digestLines(outcome_lines)`, this object's own array; 14/14 |
| 10 | `assurance/fuzz/campaign/result.json` | `$.campaigns[2].runs[0]` | `assurance/fuzz/campaign/frame-decode/frame-decode-run1.log` | FALSE POSITIVE | this branch (`sibling-lines`) | `outcome_digest` = `fuzzpin.digestLines(outcome_lines)`, this object's own array; 14/14 |
| 11 | `assurance/fuzz/campaign/result.json` | `$.campaigns[2].runs[1]` | `assurance/fuzz/campaign/frame-decode/frame-decode-run2.log` | FALSE POSITIVE | this branch (`sibling-lines`) | `outcome_digest` = `fuzzpin.digestLines(outcome_lines)`, this object's own array; 14/14 |
| 12 | `assurance/fuzz/campaign/result.json` | `$.campaigns[3].runs[0]` | `assurance/fuzz/campaign/message-utf8/message-utf8-run1.log` | FALSE POSITIVE | this branch (`sibling-lines`) | `outcome_digest` = `fuzzpin.digestLines(outcome_lines)`, this object's own array; 14/14 |
| 13 | `assurance/fuzz/campaign/result.json` | `$.campaigns[3].runs[1]` | `assurance/fuzz/campaign/message-utf8/message-utf8-run2.log` | FALSE POSITIVE | this branch (`sibling-lines`) | `outcome_digest` = `fuzzpin.digestLines(outcome_lines)`, this object's own array; 14/14 |
| 14 | `assurance/fuzz/campaign/result.json` | `$.campaigns[4].runs[0]` | `assurance/fuzz/campaign/fragment-control-sequences/fragment-control-sequences-run1.log` | FALSE POSITIVE | this branch (`sibling-lines`) | `outcome_digest` = `fuzzpin.digestLines(outcome_lines)`, this object's own array; 14/14 |
| 15 | `assurance/fuzz/campaign/result.json` | `$.campaigns[4].runs[1]` | `assurance/fuzz/campaign/fragment-control-sequences/fragment-control-sequences-run2.log` | FALSE POSITIVE | this branch (`sibling-lines`) | `outcome_digest` = `fuzzpin.digestLines(outcome_lines)`, this object's own array; 14/14 |
| 16 | `assurance/fuzz/campaign/result.json` | `$.campaigns[5].runs[0]` | `assurance/fuzz/campaign/close-eof/close-eof-run1.log` | FALSE POSITIVE | this branch (`sibling-lines`) | `outcome_digest` = `fuzzpin.digestLines(outcome_lines)`, this object's own array; 14/14 |
| 17 | `assurance/fuzz/campaign/result.json` | `$.campaigns[5].runs[1]` | `assurance/fuzz/campaign/close-eof/close-eof-run2.log` | FALSE POSITIVE | this branch (`sibling-lines`) | `outcome_digest` = `fuzzpin.digestLines(outcome_lines)`, this object's own array; 14/14 |
| 18 | `assurance/fuzz/campaign/result.json` | `$.campaigns[6].runs[0]` | `assurance/fuzz/campaign/owner-driver-command-byte-schedules/owner-driver-command-byte-schedules-run1.log` | FALSE POSITIVE | this branch (`sibling-lines`) | `outcome_digest` = `fuzzpin.digestLines(outcome_lines)`, this object's own array; 14/14 |
| 19 | `assurance/fuzz/campaign/result.json` | `$.campaigns[6].runs[1]` | `assurance/fuzz/campaign/owner-driver-command-byte-schedules/owner-driver-command-byte-schedules-run2.log` | FALSE POSITIVE | this branch (`sibling-lines`) | `outcome_digest` = `fuzzpin.digestLines(outcome_lines)`, this object's own array; 14/14 |
| 20 | `assurance/fuzz/fixtures/artifact-capture-absent.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | this branch (`tree-envelope`) | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, exact |
| 21 | `assurance/fuzz/fixtures/blocked-unavailable-while-engine-present.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | this branch (`tree-envelope`) | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, exact |
| 22 | `assurance/fuzz/fixtures/campaign-literal-drift.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | this branch (`tree-envelope`) | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, exact |
| 23 | `assurance/fuzz/fixtures/campaign-seed-drift.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | this branch (`tree-envelope`) | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, exact |
| 24 | `assurance/fuzz/fixtures/campaign-total-does-not-sum.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | this branch (`tree-envelope`) | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, exact |
| 25 | `assurance/fuzz/fixtures/campaign-zero-cases.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | this branch (`tree-envelope`) | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, exact |
| 26 | `assurance/fuzz/fixtures/corpus-digest-mismatch.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | this branch (`tree-envelope`) | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, exact |
| 27 | `assurance/fuzz/fixtures/corpus-file-count-mismatch.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | this branch (`tree-envelope`) | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, exact |
| 28 | `assurance/fuzz/fixtures/digest-scheme-drift.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | this branch (`tree-envelope`) | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, exact |
| 29 | `assurance/fuzz/fixtures/engine-source-drift.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | this branch (`tree-envelope`) | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, exact |
| 30 | `assurance/fuzz/fixtures/engine-unavailable-honestly-blocked.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | this branch (`tree-envelope`) | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, exact |
| 31 | `assurance/fuzz/fixtures/engine-unavailable-target-still-pinned.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | this branch (`tree-envelope`) | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, exact |
| 32 | `assurance/fuzz/fixtures/entrypoint-missing.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | this branch (`tree-envelope`) | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, exact |
| 33 | `assurance/fuzz/fixtures/entrypoint-not-a-test.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | this branch (`tree-envelope`) | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, exact |
| 34 | `assurance/fuzz/fixtures/family-unmapped.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | this branch (`tree-envelope`) | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, exact |
| 35 | `assurance/fuzz/fixtures/good-all-pinned.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | this branch (`tree-envelope`) | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, exact |
| 36 | `assurance/fuzz/fixtures/liveness-guard-is-an-iteration-count.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | this branch (`tree-envelope`) | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, exact |
| 37 | `assurance/fuzz/fixtures/liveness-guard-no-deadline.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | this branch (`tree-envelope`) | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, exact |
| 38 | `assurance/fuzz/fixtures/policy-incomplete.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | this branch (`tree-envelope`) | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, exact |
| 39 | `assurance/fuzz/fixtures/replay-command-absent.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | this branch (`tree-envelope`) | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, exact |
| 40 | `assurance/fuzz/fixtures/status-skipped-is-not-a-status.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | this branch (`tree-envelope`) | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, exact |
| 41 | `assurance/fuzz/fixtures/target-absent.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | this branch (`tree-envelope`) | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, exact |
| 42 | `assurance/fuzz/fixtures/toolchain-pin-drift.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | — still a candidate | deliberate negative fixture: `1111…` must NOT match. `fixtures/cases.json` requires exit 1 + `FUZZ_TOOLCHAIN_PIN_DRIFT` |
| 43 | `assurance/fuzz/fixtures/unavailable-as-success.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | this branch (`tree-envelope`) | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, exact |
| 44 | `assurance/fuzz/fixtures/unknown-engine-reference.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | this branch (`tree-envelope`) | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, exact |
| 45 | `assurance/fuzz/manifest.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | this branch (`tree-envelope`) | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, exact |
| 46 | `assurance/mutation/denominator.json` | `$.arms[0].separation.credential` | `corpora/hidden/manifest.json` | FALSE POSITIVE | mainline `420bed2` | `{declared,source,field}`: read from `generator.secret_seed_commitment`; resolved, exact |
| 47 | `assurance/mutation/denominator.json` | `$.arms[1].separation.credential` | `corpora/sealed/manifest.json` | FALSE POSITIVE | mainline `420bed2` | `{declared,source,field}`: read from `generator.secret_seed_commitment`; resolved, exact |
| 48 | `assurance/replay/fixtures/post-review-mutation/mutation.json` | `$.operations[0]` | `assurance/lifecycle.json` | FALSE POSITIVE | this branch (`mutation-operand`) | `json_set` operand: the value the mutation WRITES into `target`, deliberately wrong |
| 49 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[0]` | `assurance/replay/fixtures/us006-good-backend-executed/mutation.json` | FALSE POSITIVE | — still a candidate | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED TREE, not of `mutation.json` |
| 50 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[10]` | `assurance/replay/fixtures/us006-inflated-finite-claim/mutation.json` | FALSE POSITIVE | — still a candidate | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED TREE, not of `mutation.json` |
| 51 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[11]` | `assurance/replay/fixtures/us006-inflated-loom-proof/mutation.json` | FALSE POSITIVE | — still a candidate | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED TREE, not of `mutation.json` |
| 52 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[12]` | `assurance/replay/fixtures/us006-stale-attempt-binding/mutation.json` | FALSE POSITIVE | — still a candidate | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED TREE, not of `mutation.json` |
| 53 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[13]` | `assurance/replay/fixtures/us006-profile-digest-mismatch/mutation.json` | FALSE POSITIVE | — still a candidate | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED TREE, not of `mutation.json` |
| 54 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[14]` | `assurance/replay/fixtures/us006-missing-canary-pair/mutation.json` | FALSE POSITIVE | — still a candidate | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED TREE, not of `mutation.json` |
| 55 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[15]` | `assurance/replay/fixtures/us006-zero-obligations/mutation.json` | FALSE POSITIVE | — still a candidate | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED TREE, not of `mutation.json` |
| 56 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[16]` | `assurance/replay/fixtures/us006-evidence-run-incomplete/mutation.json` | FALSE POSITIVE | — still a candidate | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED TREE, not of `mutation.json` |
| 57 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[17]` | `assurance/replay/fixtures/us006-known-bad-canary-survived/mutation.json` | FALSE POSITIVE | — still a candidate | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED TREE, not of `mutation.json` |
| 58 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[18]` | `assurance/replay/fixtures/us006-profile-bytes-stale/mutation.json` | FALSE POSITIVE | — still a candidate | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED TREE, not of `mutation.json` |
| 59 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[19]` | `assurance/replay/fixtures/us006-profile-artifact-missing/mutation.json` | FALSE POSITIVE | — still a candidate | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED TREE, not of `mutation.json` |
| 60 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[1]` | `assurance/replay/fixtures/us006-disconnected-proof/mutation.json` | FALSE POSITIVE | — still a candidate | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED TREE, not of `mutation.json` |
| 61 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[20]` | `assurance/replay/fixtures/us006-probe-not-executed/mutation.json` | FALSE POSITIVE | — still a candidate | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED TREE, not of `mutation.json` |
| 62 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[21]` | `assurance/replay/fixtures/us006-disconnected-proof-symbol/mutation.json` | FALSE POSITIVE | — still a candidate | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED TREE, not of `mutation.json` |
| 63 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[2]` | `assurance/replay/fixtures/us006-doc-absent-proof-targets/mutation.json` | FALSE POSITIVE | — still a candidate | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED TREE, not of `mutation.json` |
| 64 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[3]` | `assurance/replay/fixtures/us006-schema-absent/mutation.json` | FALSE POSITIVE | — still a candidate | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED TREE, not of `mutation.json` |
| 65 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[4]` | `assurance/replay/fixtures/us006-invalid-json/mutation.json` | FALSE POSITIVE | — still a candidate | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED TREE, not of `mutation.json` |
| 66 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[5]` | `assurance/replay/fixtures/us006-schema-violation/mutation.json` | FALSE POSITIVE | — still a candidate | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED TREE, not of `mutation.json` |
| 67 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[6]` | `assurance/replay/fixtures/us006-selected-without-execution/mutation.json` | FALSE POSITIVE | — still a candidate | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED TREE, not of `mutation.json` |
| 68 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[7]` | `assurance/replay/fixtures/us006-placeholder-receipt/mutation.json` | FALSE POSITIVE | — still a candidate | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED TREE, not of `mutation.json` |
| 69 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[8]` | `assurance/replay/fixtures/us006-unavailable-as-success/mutation.json` | FALSE POSITIVE | — still a candidate | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED TREE, not of `mutation.json` |
| 70 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[9]` | `assurance/replay/fixtures/us006-unavailable-as-skip/mutation.json` | FALSE POSITIVE | — still a candidate | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED TREE, not of `mutation.json` |
| 71 | `assurance/replay/fixtures/us006-disconnected-proof-symbol/mutation.json` | `$.operations[8]` | `assurance/formal/backend-qualification.json` | FALSE POSITIVE | this branch (`mutation-operand`) | `json_set` operand: the value the mutation WRITES into `target`, deliberately wrong |
| 72 | `assurance/replay/fixtures/us006-good-backend-executed/mutation.json` | `$.operations[8]` | `assurance/formal/backend-qualification.json` | FALSE POSITIVE | this branch (`mutation-operand`) | `json_set` operand: the value the mutation WRITES into `target`, deliberately wrong |
| 73 | `assurance/replay/fixtures/us006-placeholder-receipt/mutation.json` | `$.operations[1].value` | `evidence/security-validation.json` | FALSE POSITIVE | — still a candidate | `json_set` operand nested one level: `value` is the `{path,sha256}` placeholder receipt. Synthetic `aaaa…` |
| 74 | `assurance/replay/fixtures/us006-profile-digest-mismatch/mutation.json` | `$.operations[1]` | `assurance/formal/backend-qualification.json` | FALSE POSITIVE | this branch (`mutation-operand`) | `json_set` operand: the value the mutation WRITES into `target`, deliberately wrong |
| 75 | `drafts/ledger-proposals/div05-close-overtakes-echo-description-correction.json` | `$.targets_record` | `evidence/java/behavior-delta-ledger.json` | FALSE POSITIVE | mainline `420bed2` | the digest is a value the named file CARRIES (ledger head / record / accepted root / archive digest) |
| 76 | `drafts/ledger-proposals/java-formal-binding-corroborations.json` | `$.evidence_basis.projection` | `evidence/java/formal-bindings/coverage-projection.json` | TRUE, not mechanically fixable | — still a candidate | bare `{path,sha256}` and the sibling `spec` entry matches its file, so the schema does mean "sha256 OF path". But `62758083…` matches NO version on any branch (only blob ever `02a9b130…`) and no canonicalisation reproduces it. `ProposalDraftPaths()` excludes this file, so nothing validates it |
| 77 | `drafts/ledger-proposals/java-formal-binding-corroborations.json` | `$.evidence_basis.receipt` | `evidence/java/formal-bindings/receipt.json` | TRUE, not mechanically fixable | — still a candidate | same; `17290017…` matches no version (only blob ever `4a4dff73…`). No retained bytes exist to diff, so the zero-changed-line test cannot be performed |
| 78 | `evidence/governance/decisions/delta-ledger-receipt.json` | `$` | `evidence/java/behavior-delta-ledger.json` | FALSE POSITIVE | mainline `420bed2` | the digest is a value the named file CARRIES (ledger head / record / accepted root / archive digest) |
| 79 | `evidence/governance/decisions/e3-formal-receipt.json` | `$.artifacts.results_documents[0]` | `assurance/formal/frame-results.json` | TRUE, must NOT be fixed | — still a candidate | a dated attestation, not a live pin: the current digest is already recorded in the same document at `$.review_round_5.artifacts_this_round.results[0]`. Protected store |
| 80 | `evidence/governance/decisions/e3-formal-receipt.json` | `$.artifacts.results_documents[1]` | `assurance/formal/close-model-results.json` | TRUE, must NOT be fixed | — still a candidate | same; current digest at `$.review_round_5.artifacts_this_round.results[1]`. Protected store |
| 81 | `evidence/intake/java-intake-manifest.json` | `$.build` | `evidence/java/build.json` | FALSE POSITIVE | mainline `420bed2` | the digest is a value the named file CARRIES (ledger head / record / accepted root / archive digest) |
| 82 | `evidence/java/legacy-record-adjudications.json` | `$` | `evidence/java/behavior-delta-ledger.json` | FALSE POSITIVE | mainline `420bed2` | the digest is a value the named file CARRIES (ledger head / record / accepted root / archive digest) |
| 83 | `evidence/java/legacy-record-adjudications.json` | `$.adjudications[12]` | `drafts/ledger-proposals/legacy-13-bare-lf-server-basis-correction.json` | FALSE POSITIVE | — still a candidate | known: a ledger `record_digest` beside an unrelated proposal path. Not recomputable, so the tool still reports it |
| 84 | `evidence/java/test-manifest.json` | `$.authoritative_run.execution_code_binding.sources[0]` | `internal/lab/executor_darwin.go` | TRUE — filed as F014 | — still a candidate | `internal/lab/executor_darwin.go` has drifted; code binding verified against a copy of itself |
| 85 | `evidence/java/test-manifest.json` | `$.authoritative_run.execution_code_binding.sources[2]` | `internal/lab/sandbox.go` | TRUE — filed as F014 | — still a candidate | `internal/lab/sandbox.go` has drifted; same finding |

## 9. Gates

Read from the process:

| command | exit |
|---|---|
| `go run ./cmd/pinconsumerctl dangling -root .` (mainline `420bed2`) | 1, `candidates=77` |
| `go run ./cmd/pinconsumerctl dangling -root .` (this branch) | 1, `candidates=34 explained=51` |
| `go build ./...` | 0 |
| `go test ./cmd/pinconsumerctl/` | 0, 21 tests |
| `make -C rust gates` | 0 |
| `go run ./cmd/recordguardctl precondition <this record>` | 0 |
| `go test ./... -timeout 40m` | 1 — 4 packages: 3 environmental, 1 a mainline regression, section 5 |

`make -C rust gates` refuses by design until `VJWP_PROTECTED_STORE` points at
`evidence/governance/decisions`; with it unset the run exits **2** at `ledger-gates` with an
explicit refusal, which is the gate working.

## 10. Weaknesses I can see and am not hiding

1. **The 22 us006 rows rest on reading code, not on running it.** Section 5 says why. If the
   archive were reachable the test would settle it in one run.
2. **`field-inside-file` is the broadest rule in play.** Its justification — a file cannot
   contain its own sha256 — is sound, but it would also explain a pin whose stale digest
   happened to appear inside the named document for an unrelated reason. It is mainline's
   rule, not mine; this branch only makes it print where it found the digest.
3. **The detector still cannot see a pin split across two objects**, unchanged, and the
   ceiling still says so. `denominator_basis[2]` shows the neighbouring gap: an absent path is
   invisible to `dangling` entirely, and only the reconciler catches it.
4. **I did not adjudicate whether the E3 receipt's layering is the right pattern**, only that
   it is internally consistent. A receipt whose top-level digests are stale by design is easy
   to misread as drift — which is exactly what happened here.
5. **The 9 true pins are reported, not resolved.** Each needs an owner decision this branch
   deliberately did not take.
6. **I did not fix the `internal/deltaledger` regression, or diagnose it beyond attribution.**
   I established that it fails on clean mainline without my commits and that two of its three
   failures are a gate accepting what it must refuse. Naming the commit that broke it is a
   guess from one field name, and I have marked it as one.
