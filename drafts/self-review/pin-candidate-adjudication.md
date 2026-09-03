# Adjudicating all 85 dangling-pin candidates by reading them

Status: COMPLETE for what it claims. All 85 candidates read and classified; 9 are real,
76 are the false positive the detector's own ceiling predicted. Zero were mechanically
fixable, and this record says exactly why for each.

Branch `claude/pin-candidate-adjudication` from `claude/feature/verified-java-websocket-port`
at `c738b81`. Date 2026-09-03. Scope: `cmd/pinconsumerctl/` (detector precision + 8 tests)
and this record. No evidence document, no ledger, no `assurance/` file and no `internal/`
package was modified:
`git diff --quiet c738b81 HEAD -- evidence/ assurance/ internal/ corpora/ rust/ drafts/ledger-proposals/`
exits **0**.

## 1. The headline: 85 was never 85 defects

`go run ./cmd/pinconsumerctl dangling -root .` at `fb72adb` reported 1996 JSON artifacts,
0 unparsable, **85 candidates**, exit **1** (read from the process).

Reading all 85:

| class | rows |
|---|---|
| FALSE POSITIVE — the digest covers something other than the co-located path | **76** |
| TRUE, not mechanically fixable (owner decision or hard stop) | **5** |
| TRUE, and must NOT be fixed — a dated attestation, not a live pin | **2** |
| TRUE — already filed as F014 | **2** |

**Nothing was fixed, and that is a finding, not a shortfall.** The brief authorised fixing
only pins where the propagation is mechanical and no number moves. Not one of the 9 true
pins qualifies: three are the formal denominator's declared basis, two are inside the
protected governance store, two pin bytes that exist in no branch of this repository, and
two are F014, already filed. Section 4 shows the measurement for each.

## 2. The four false-positive shapes, each proven by recomputation

Not one of these was classified by its key name. Each was proven by recomputing the value
from bytes in the tree and requiring an exact match.

**Tree envelope (25 rows).** `assurance/fuzz/manifest.json` and its 24 fixtures pin
`rust/rust-toolchain.toml` with `pin_digest: sha256:4a1f4893…`, while the file hashes to
`70025e01…`. That file has had exactly **one** version in the whole history (`93f5444`), so
`4a1f4893…` was never its digest — which is the tell. `internal/fuzzpin.TreeDigest` digests a
file LIST as `"relpath\x00filedigest\n"` lines:

```
sha256("rust/rust-toolchain.toml" + 0x00 + "70025e01…" + "\n") = 4a1f489390955d74… == pinned
```

`internal/fuzzpin/check.go:102` compares against exactly this value, unconditionally, so the
gate is green and correct. Verified for all 25.

**Sibling line-array (14 rows).** Every run object in `assurance/fuzz/campaign/result.json`
carries `log_path` beside `outcome_digest`. Both runs of a campaign share one
`outcome_digest`, which no two distinct log files could. `fuzzpin.digestLines(outcome_lines)`
reproduces it for **14 of 14** runs, 0 mismatches: it digests the test-outcome lines, which
are stable across runs, while the logs differ in wall-clock timings.

**Contained in the named document (6 rows).** `observed_head`, `ledger_head`,
`record_digest`, `accepted_root_digest` and `inherited_accepted_root_digest` sit beside
`evidence/java/behavior-delta-ledger.json`. They are chain values, and the ledger contains
them:

| pin | resolves to |
|---|---|
| `assurance/concurrency/plan.json` `observed_head` `a44191d3…` | `records[55].record_digest` — the last of 56, matching its own `observed_record_count: 56` |
| `div05-…-correction.json` `record_digest` `6410ab14…` | `records[53].record_digest`, and the object says `sequence: 54` |
| `delta-ledger-receipt.json` `ledger_head` `b7a84924…` | `records[31].record_digest` — the head when the receipt was written, `2026-08-27` |
| `legacy-record-adjudications.json` `accepted_root_digest` `57132454…` | the ledger's own top-level `accepted_root_digest` |
| `java-intake-manifest.json` `inherited_accepted_root_digest` | the same accepted root, inherited from US-002 |

A file cannot contain its own sha256, so a digest found inside the named document digests a
part of it, never the whole.

**Mutation operand (5 rows).** `{"kind":"json_set","target":<path>,"pointer":…,"value":"sha256:cccc…"}`
is an instruction. The synthetic repeated-nibble digest is the payload a seeded defect
writes, not a pin that drifted.

Two more shapes, both verified the same way: **field provenance** (2 rows) — `{declared,
source, field}` in `assurance/mutation/denominator.json` names `generator.secret_seed_commitment`,
and resolving that field in both corpus manifests returns `08ae5e87…` exactly; and the
**archive digest** in `proof-targets.json`, where `archive_sha256` is `f44e7647…`, the value
`internal/portplan.SourceArchiveSHA256` pins for the `.tar.gz`, sitting beside an unrelated
`source_pins_path`.

**Realized fixture tree (22 rows).** Every `us006-cases.json` case pairs
`mutation_manifest_path` with `realized_tree_sha256`. `internal/formalplan/backend_test.go:935`
computes it as `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole
tree produced by APPLYING the mutation, not of `mutation.json`. Proven by construction from
the code path. It is **not** confirmed by execution here, and section 5 says why.

**Deliberate negative fixture (1 row).** `toolchain-pin-drift.json` pins `1111…`.
`assurance/fuzz/fixtures/cases.json` requires that case to produce exit 1 and
`FUZZ_TOOLCHAIN_PIN_DRIFT`. Its mismatch is the assertion; repairing it would break the test.

## 3. The detector now proves what it subtracts

Five of those shapes are recomputable, so `cmd/pinconsumerctl` no longer needs a human to
re-derive them. `candidates` **85 → 34**, with `explained=51` printed on their own
`gate=pin-dangling-explained` lines carrying the reason and the subject. The census never
shrinks silently.

```
gate=pin-dangling json_artifacts=1996 unparsable=0 candidates=34 explained=51
   tree-envelope 25 | sibling-lines 14 | contained-in-document 6 | mutation-operand 4 | field-provenance 2
```

The property that makes this safe to subtract: **every rule reads an input that drifts too.**
The envelope rule hashes the file's current bytes, so editing the file makes the pin dangle
again. `TestTreeEnvelopeExplanationStopsApplyingWhenTheFileDrifts` edits the pinned toolchain
file and requires the candidate back — a rule keyed on the *name* `pin_digest` would pass the
firing test and fail that one. No rule trusts a key name; `realized_tree_sha256` therefore
stays a candidate on all 22 rows even though this record adjudicates it false, because the
tool cannot realize a fixture tree.

`TestAdjudicatedTrueDanglingPinsAreStillReported` pins all nine true positives against future
precision work. 18 tests pass, exit **0** — the 10 pre-existing ones, including all 7
deletion attacks and the F014 guard, unchanged.

## 4. The nine true pins, and why none was fixable

**The formal denominator's declared basis — 3 rows, hard stop.**
`assurance/formal/obligation-catalog.json` `$.denominator_basis[1,3,4]`. These are genuine:
each pinned sha256 equals the sha256 of the `git.blob` recorded in the same object, so the
digest is unambiguously of that path at that commit.

The anchor commit `1ff89fa` is **not an ancestor of HEAD**. `git branch -a --contains 1ff89fa`
returns only `remotes/origin/codex/race-catchup`, which is read-only. The basis is a frozen
provenance record of the tree the catalog was vendored from, and
`internal/formalcoverage/reconcile.go:404` already measures the disagreement and publishes it
in `assurance/formal/denominator-reconciliation.json`, which today reads
`BASIS_PIN_DOES_NOT_MATCH_FILE_ON_DISK` for all three. It deliberately distinguishes that
code from `BASIS_PIN_PATH_IS_ABSENT_FROM_THIS_PLANE`, which is what a fifth entry,
`corpora/frame/codec.json`, carries: it is untracked and absent, so the detector never saw it.

This drift is declared, not hidden. Updating the pins would erase the catalog's recorded
provenance and silently re-baseline the formal denominator. **Owner action required: decide
whether the vendored catalog is re-anchored to this branch — nobody should do that as
propagation.**

**A corroboration receipt pinning bytes that never existed — 2 rows.**
`drafts/ledger-proposals/java-formal-binding-corroborations.json` `$.evidence_basis.receipt`
and `.projection`. The shape is a bare `{path, sha256}`, and its sibling `spec` entry matches
its file exactly, so the schema does mean "sha256 OF path". But `17290017…` and `62758083…`
match **no version of those files on any branch** — each has exactly one blob in all of
history (`4a4dff73…`, `02a9b130…`), and no canonicalisation (sorted, compact, re-indented,
trailing-newline) reproduces the pinned values. Nothing validates them:
`internal/deltaledger/proposal_drafts.go:50` excludes this file from `ProposalDraftPaths()`
by name, with a comment saying it is a corroboration receipt rather than a record proposal.

This is not mechanically fixable in the sense the brief defines: there are **no retained
bytes to diff against**, so "show the non-digest changed-line count is zero" cannot be
performed. Writing the current digests in would assert a corroboration that was never
measured. **Owner action required: re-run the round-1 corroboration against the current
bytes, or withdraw the two pins.**

**The E3 governance receipt — 2 rows, must NOT be fixed.**
`evidence/governance/decisions/e3-formal-receipt.json` `$.artifacts.results_documents[0,1]`
pin `frame-results.json` and `close-model-results.json` at digests the later review rounds
`185e8c2`, `ec52ff3`, `f97d04a` moved. But the receipt is layered and already correct: the
current digests are recorded in the same document at
`$.review_round_5.artifacts_this_round.results[0]` and `[1]`. The top-level block is a dated
attestation of what the worker produced at `recorded_at 2026-08-28T01:28:46Z`. Rewriting it
would make the receipt claim bytes the worker did not produce, in the protected store. No
action needed; the document is internally consistent.

**F014 — 2 rows.** `evidence/java/test-manifest.json` pins `internal/lab/executor_darwin.go`
and `internal/lab/sandbox.go`, both drifted. Already filed as
`drafts/self-review/findings/F014-a-code-binding-verified-against-a-copy-of-itself.md`.

## 5. What I could not verify here, stated rather than papered over

**A third Go package fails on Linux, and it is environmental — but the standing claim that
only `internal/lab` and `internal/portplan` fail is now wrong.** `go test ./internal/formalplan/
-timeout 40m` exits **1** with **23** failing leaf tests. Every one of them traces to a single
cause: `JAVA_SOURCE_UNAVAILABLE_OFFLINE: pinned immutable URL returned HTTP 403`. Filtering the
failure detail lines for any cause that is not the quarantined-archive fetch leaves exactly one
line, `targets_test.go:37: real proof-targets document must verify`, which is the second
assertion of a test whose first line is the 403.

The cause is outside the repository: `.quarantine/` is empty, and
`curl -L https://github.com/TooTallNate/Java-WebSocket/archive/da3cf2a….tar.gz` returns
**403** through this environment's proxy, whose own status reports `enabled: true` with no
relay failures. `internal/portplan` owns `EnsureQuarantinedSource`, so this is the same root
cause as its known failure, reaching one package further than the standing list records.
**Owner action required: confirm the baseline failing-package list should read `internal/lab`,
`internal/portplan`, `internal/formalplan` in an environment without the quarantined archive —
or provision the archive.** No gated run was triggered to find this.

The consequence for this adjudication: the 22 `realized_tree_sha256` rows are proven false
positives **by construction**, from the code path that computes them, and are *not* confirmed
by execution, because `TestUS006FixtureCatalogThroughRealCLI` cannot realize a fixture tree
without the archive. `US006_REGENERATE=1` was **not** run: there is nothing to refreeze, and
running it here would rewrite 22 frozen digests from trees built without the Java source.

**A concurrent session is moving the ledger.** Another worktree is appending supersessions
that take `evidence/java/behavior-delta-ledger.json` from 56 records to 58. Every ledger
claim in section 2 was measured against this branch at `c738b81`, where the head is
`a44191d3…` at 56 records. Those rows stay false positives under any append — the digests
resolve to records 31, 53 and 55 — but the specific indices will shift.

## 6. The full census, all 85 rows

Row numbers are the detector's own sort order (artifact, then pointer).

| # | artifact | pointer | names | classification | evidence |
|---|---|---|---|---|---|
| 1 | `assurance/concurrency/plan.json` | `$.behavior_delta_ledger` | `evidence/java/behavior-delta-ledger.json` | FALSE POSITIVE | digest occurs INSIDE the named document (ledger record / chain head / accepted root), so it digests a part of it |
| 2 | `assurance/formal/obligation-catalog.json` | `$.denominator_basis[1]` | `assurance/formal/proof-targets.json` | TRUE, not mechanically fixable | pinned sha256 == sha256 of the recorded `git.blob`; anchored at 1ff89fa which is NOT an ancestor of HEAD (only on read-only `origin/codex/race-catchup`). Already declared drifted in `assurance/formal/denominator-reconciliation.json`. DENOMINATOR — hard stop |
| 3 | `assurance/formal/obligation-catalog.json` | `$.denominator_basis[3]` | `evidence/intake/compatibility-surface.json` | TRUE, not mechanically fixable | same: pin == recorded blob digest; reconciliation already reports BASIS_PIN_DOES_NOT_MATCH_FILE_ON_DISK. DENOMINATOR — hard stop |
| 4 | `assurance/formal/obligation-catalog.json` | `$.denominator_basis[4]` | `evidence/intake/semantic-id-migration-map.json` | TRUE, not mechanically fixable | same: pin == recorded blob digest; reconciliation already reports BASIS_PIN_DOES_NOT_MATCH_FILE_ON_DISK. DENOMINATOR — hard stop |
| 5 | `assurance/formal/proof-targets.json` | `$.sources.quarantined_java_tree` | `evidence/intake/source-pins.json` | FALSE POSITIVE | digest occurs INSIDE the named document (ledger record / chain head / accepted root), so it digests a part of it |
| 6 | `assurance/fuzz/campaign/result.json` | `$.campaigns[0].runs[0]` | `assurance/fuzz/campaign/handshake-client/handshake-client-run1.log` | FALSE POSITIVE | `outcome_digest` = `fuzzpin.digestLines(outcome_lines)` of this object's own array; recomputed for all 14 |
| 7 | `assurance/fuzz/campaign/result.json` | `$.campaigns[0].runs[1]` | `assurance/fuzz/campaign/handshake-client/handshake-client-run2.log` | FALSE POSITIVE | `outcome_digest` = `fuzzpin.digestLines(outcome_lines)` of this object's own array; recomputed for all 14 |
| 8 | `assurance/fuzz/campaign/result.json` | `$.campaigns[1].runs[0]` | `assurance/fuzz/campaign/handshake-server/handshake-server-run1.log` | FALSE POSITIVE | `outcome_digest` = `fuzzpin.digestLines(outcome_lines)` of this object's own array; recomputed for all 14 |
| 9 | `assurance/fuzz/campaign/result.json` | `$.campaigns[1].runs[1]` | `assurance/fuzz/campaign/handshake-server/handshake-server-run2.log` | FALSE POSITIVE | `outcome_digest` = `fuzzpin.digestLines(outcome_lines)` of this object's own array; recomputed for all 14 |
| 10 | `assurance/fuzz/campaign/result.json` | `$.campaigns[2].runs[0]` | `assurance/fuzz/campaign/frame-decode/frame-decode-run1.log` | FALSE POSITIVE | `outcome_digest` = `fuzzpin.digestLines(outcome_lines)` of this object's own array; recomputed for all 14 |
| 11 | `assurance/fuzz/campaign/result.json` | `$.campaigns[2].runs[1]` | `assurance/fuzz/campaign/frame-decode/frame-decode-run2.log` | FALSE POSITIVE | `outcome_digest` = `fuzzpin.digestLines(outcome_lines)` of this object's own array; recomputed for all 14 |
| 12 | `assurance/fuzz/campaign/result.json` | `$.campaigns[3].runs[0]` | `assurance/fuzz/campaign/message-utf8/message-utf8-run1.log` | FALSE POSITIVE | `outcome_digest` = `fuzzpin.digestLines(outcome_lines)` of this object's own array; recomputed for all 14 |
| 13 | `assurance/fuzz/campaign/result.json` | `$.campaigns[3].runs[1]` | `assurance/fuzz/campaign/message-utf8/message-utf8-run2.log` | FALSE POSITIVE | `outcome_digest` = `fuzzpin.digestLines(outcome_lines)` of this object's own array; recomputed for all 14 |
| 14 | `assurance/fuzz/campaign/result.json` | `$.campaigns[4].runs[0]` | `assurance/fuzz/campaign/fragment-control-sequences/fragment-control-sequences-run1.log` | FALSE POSITIVE | `outcome_digest` = `fuzzpin.digestLines(outcome_lines)` of this object's own array; recomputed for all 14 |
| 15 | `assurance/fuzz/campaign/result.json` | `$.campaigns[4].runs[1]` | `assurance/fuzz/campaign/fragment-control-sequences/fragment-control-sequences-run2.log` | FALSE POSITIVE | `outcome_digest` = `fuzzpin.digestLines(outcome_lines)` of this object's own array; recomputed for all 14 |
| 16 | `assurance/fuzz/campaign/result.json` | `$.campaigns[5].runs[0]` | `assurance/fuzz/campaign/close-eof/close-eof-run1.log` | FALSE POSITIVE | `outcome_digest` = `fuzzpin.digestLines(outcome_lines)` of this object's own array; recomputed for all 14 |
| 17 | `assurance/fuzz/campaign/result.json` | `$.campaigns[5].runs[1]` | `assurance/fuzz/campaign/close-eof/close-eof-run2.log` | FALSE POSITIVE | `outcome_digest` = `fuzzpin.digestLines(outcome_lines)` of this object's own array; recomputed for all 14 |
| 18 | `assurance/fuzz/campaign/result.json` | `$.campaigns[6].runs[0]` | `assurance/fuzz/campaign/owner-driver-command-byte-schedules/owner-driver-command-byte-schedules-run1.log` | FALSE POSITIVE | `outcome_digest` = `fuzzpin.digestLines(outcome_lines)` of this object's own array; recomputed for all 14 |
| 19 | `assurance/fuzz/campaign/result.json` | `$.campaigns[6].runs[1]` | `assurance/fuzz/campaign/owner-driver-command-byte-schedules/owner-driver-command-byte-schedules-run2.log` | FALSE POSITIVE | `outcome_digest` = `fuzzpin.digestLines(outcome_lines)` of this object's own array; recomputed for all 14 |
| 20 | `assurance/fuzz/fixtures/artifact-capture-absent.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, matches exactly |
| 21 | `assurance/fuzz/fixtures/blocked-unavailable-while-engine-present.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, matches exactly |
| 22 | `assurance/fuzz/fixtures/campaign-literal-drift.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, matches exactly |
| 23 | `assurance/fuzz/fixtures/campaign-seed-drift.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, matches exactly |
| 24 | `assurance/fuzz/fixtures/campaign-total-does-not-sum.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, matches exactly |
| 25 | `assurance/fuzz/fixtures/campaign-zero-cases.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, matches exactly |
| 26 | `assurance/fuzz/fixtures/corpus-digest-mismatch.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, matches exactly |
| 27 | `assurance/fuzz/fixtures/corpus-file-count-mismatch.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, matches exactly |
| 28 | `assurance/fuzz/fixtures/digest-scheme-drift.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, matches exactly |
| 29 | `assurance/fuzz/fixtures/engine-source-drift.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, matches exactly |
| 30 | `assurance/fuzz/fixtures/engine-unavailable-honestly-blocked.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, matches exactly |
| 31 | `assurance/fuzz/fixtures/engine-unavailable-target-still-pinned.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, matches exactly |
| 32 | `assurance/fuzz/fixtures/entrypoint-missing.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, matches exactly |
| 33 | `assurance/fuzz/fixtures/entrypoint-not-a-test.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, matches exactly |
| 34 | `assurance/fuzz/fixtures/family-unmapped.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, matches exactly |
| 35 | `assurance/fuzz/fixtures/good-all-pinned.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, matches exactly |
| 36 | `assurance/fuzz/fixtures/liveness-guard-is-an-iteration-count.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, matches exactly |
| 37 | `assurance/fuzz/fixtures/liveness-guard-no-deadline.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, matches exactly |
| 38 | `assurance/fuzz/fixtures/policy-incomplete.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, matches exactly |
| 39 | `assurance/fuzz/fixtures/replay-command-absent.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, matches exactly |
| 40 | `assurance/fuzz/fixtures/status-skipped-is-not-a-status.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, matches exactly |
| 41 | `assurance/fuzz/fixtures/target-absent.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, matches exactly |
| 42 | `assurance/fuzz/fixtures/toolchain-pin-drift.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | deliberate negative fixture: `1111…` must NOT match. `fixtures/cases.json` requires exit 1 + FUZZ_TOOLCHAIN_PIN_DRIFT. Fixing it would break the test |
| 43 | `assurance/fuzz/fixtures/unavailable-as-success.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, matches exactly |
| 44 | `assurance/fuzz/fixtures/unknown-engine-reference.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, matches exactly |
| 45 | `assurance/fuzz/manifest.json` | `$.engines[0].toolchain` | `rust/rust-toolchain.toml` | FALSE POSITIVE | `pin_digest` is `fuzzpin.TreeDigest([pin_file])` = sha256("path\0filedigest\n"); recomputed, matches exactly |
| 46 | `assurance/mutation/denominator.json` | `$.arms[0].separation.credential` | `corpora/hidden/manifest.json` | FALSE POSITIVE | `{declared,source,field}`: value read from `generator.secret_seed_commitment`; resolved and matches |
| 47 | `assurance/mutation/denominator.json` | `$.arms[1].separation.credential` | `corpora/sealed/manifest.json` | FALSE POSITIVE | `{declared,source,field}`: value read from `generator.secret_seed_commitment`; resolved and matches |
| 48 | `assurance/replay/fixtures/post-review-mutation/mutation.json` | `$.operations[0]` | `assurance/lifecycle.json` | FALSE POSITIVE | `json_set` operand: the value the mutation WRITES into `target`, deliberately wrong to seed a defect |
| 49 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[0]` | `assurance/replay/fixtures/us006-good-backend-executed/mutation.json` | FALSE POSITIVE | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED FIXTURE TREE, not of `mutation.json`. Enforced by `TestUS006FixtureCatalogThroughRealCLI` |
| 50 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[10]` | `assurance/replay/fixtures/us006-inflated-finite-claim/mutation.json` | FALSE POSITIVE | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED FIXTURE TREE, not of `mutation.json`. Enforced by `TestUS006FixtureCatalogThroughRealCLI` |
| 51 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[11]` | `assurance/replay/fixtures/us006-inflated-loom-proof/mutation.json` | FALSE POSITIVE | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED FIXTURE TREE, not of `mutation.json`. Enforced by `TestUS006FixtureCatalogThroughRealCLI` |
| 52 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[12]` | `assurance/replay/fixtures/us006-stale-attempt-binding/mutation.json` | FALSE POSITIVE | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED FIXTURE TREE, not of `mutation.json`. Enforced by `TestUS006FixtureCatalogThroughRealCLI` |
| 53 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[13]` | `assurance/replay/fixtures/us006-profile-digest-mismatch/mutation.json` | FALSE POSITIVE | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED FIXTURE TREE, not of `mutation.json`. Enforced by `TestUS006FixtureCatalogThroughRealCLI` |
| 54 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[14]` | `assurance/replay/fixtures/us006-missing-canary-pair/mutation.json` | FALSE POSITIVE | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED FIXTURE TREE, not of `mutation.json`. Enforced by `TestUS006FixtureCatalogThroughRealCLI` |
| 55 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[15]` | `assurance/replay/fixtures/us006-zero-obligations/mutation.json` | FALSE POSITIVE | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED FIXTURE TREE, not of `mutation.json`. Enforced by `TestUS006FixtureCatalogThroughRealCLI` |
| 56 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[16]` | `assurance/replay/fixtures/us006-evidence-run-incomplete/mutation.json` | FALSE POSITIVE | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED FIXTURE TREE, not of `mutation.json`. Enforced by `TestUS006FixtureCatalogThroughRealCLI` |
| 57 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[17]` | `assurance/replay/fixtures/us006-known-bad-canary-survived/mutation.json` | FALSE POSITIVE | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED FIXTURE TREE, not of `mutation.json`. Enforced by `TestUS006FixtureCatalogThroughRealCLI` |
| 58 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[18]` | `assurance/replay/fixtures/us006-profile-bytes-stale/mutation.json` | FALSE POSITIVE | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED FIXTURE TREE, not of `mutation.json`. Enforced by `TestUS006FixtureCatalogThroughRealCLI` |
| 59 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[19]` | `assurance/replay/fixtures/us006-profile-artifact-missing/mutation.json` | FALSE POSITIVE | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED FIXTURE TREE, not of `mutation.json`. Enforced by `TestUS006FixtureCatalogThroughRealCLI` |
| 60 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[1]` | `assurance/replay/fixtures/us006-disconnected-proof/mutation.json` | FALSE POSITIVE | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED FIXTURE TREE, not of `mutation.json`. Enforced by `TestUS006FixtureCatalogThroughRealCLI` |
| 61 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[20]` | `assurance/replay/fixtures/us006-probe-not-executed/mutation.json` | FALSE POSITIVE | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED FIXTURE TREE, not of `mutation.json`. Enforced by `TestUS006FixtureCatalogThroughRealCLI` |
| 62 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[21]` | `assurance/replay/fixtures/us006-disconnected-proof-symbol/mutation.json` | FALSE POSITIVE | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED FIXTURE TREE, not of `mutation.json`. Enforced by `TestUS006FixtureCatalogThroughRealCLI` |
| 63 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[2]` | `assurance/replay/fixtures/us006-doc-absent-proof-targets/mutation.json` | FALSE POSITIVE | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED FIXTURE TREE, not of `mutation.json`. Enforced by `TestUS006FixtureCatalogThroughRealCLI` |
| 64 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[3]` | `assurance/replay/fixtures/us006-schema-absent/mutation.json` | FALSE POSITIVE | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED FIXTURE TREE, not of `mutation.json`. Enforced by `TestUS006FixtureCatalogThroughRealCLI` |
| 65 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[4]` | `assurance/replay/fixtures/us006-invalid-json/mutation.json` | FALSE POSITIVE | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED FIXTURE TREE, not of `mutation.json`. Enforced by `TestUS006FixtureCatalogThroughRealCLI` |
| 66 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[5]` | `assurance/replay/fixtures/us006-schema-violation/mutation.json` | FALSE POSITIVE | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED FIXTURE TREE, not of `mutation.json`. Enforced by `TestUS006FixtureCatalogThroughRealCLI` |
| 67 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[6]` | `assurance/replay/fixtures/us006-selected-without-execution/mutation.json` | FALSE POSITIVE | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED FIXTURE TREE, not of `mutation.json`. Enforced by `TestUS006FixtureCatalogThroughRealCLI` |
| 68 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[7]` | `assurance/replay/fixtures/us006-placeholder-receipt/mutation.json` | FALSE POSITIVE | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED FIXTURE TREE, not of `mutation.json`. Enforced by `TestUS006FixtureCatalogThroughRealCLI` |
| 69 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[8]` | `assurance/replay/fixtures/us006-unavailable-as-success/mutation.json` | FALSE POSITIVE | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED FIXTURE TREE, not of `mutation.json`. Enforced by `TestUS006FixtureCatalogThroughRealCLI` |
| 70 | `assurance/replay/fixtures/us006-cases.json` | `$.cases[9]` | `assurance/replay/fixtures/us006-unavailable-as-skip/mutation.json` | FALSE POSITIVE | `realized_tree_sha256` is `us006CanonicalTreeDigest(us006RealizeCase(fixture))` — the digest of the whole REALIZED FIXTURE TREE, not of `mutation.json`. Enforced by `TestUS006FixtureCatalogThroughRealCLI` |
| 71 | `assurance/replay/fixtures/us006-disconnected-proof-symbol/mutation.json` | `$.operations[8]` | `assurance/formal/backend-qualification.json` | FALSE POSITIVE | `json_set` operand: the value the mutation WRITES into `target`, deliberately wrong to seed a defect |
| 72 | `assurance/replay/fixtures/us006-good-backend-executed/mutation.json` | `$.operations[8]` | `assurance/formal/backend-qualification.json` | FALSE POSITIVE | `json_set` operand: the value the mutation WRITES into `target`, deliberately wrong to seed a defect |
| 73 | `assurance/replay/fixtures/us006-placeholder-receipt/mutation.json` | `$.operations[1].value` | `evidence/security-validation.json` | FALSE POSITIVE | `json_set` operand nested one level: `value` is the `{path,sha256}` placeholder receipt written into `backend-qualification.json`. Synthetic `aaaa…` |
| 74 | `assurance/replay/fixtures/us006-profile-digest-mismatch/mutation.json` | `$.operations[1]` | `assurance/formal/backend-qualification.json` | FALSE POSITIVE | `json_set` operand: the value the mutation WRITES into `target`, deliberately wrong to seed a defect |
| 75 | `drafts/ledger-proposals/div05-close-overtakes-echo-description-correction.json` | `$.targets_record` | `evidence/java/behavior-delta-ledger.json` | FALSE POSITIVE | digest occurs INSIDE the named document (ledger record / chain head / accepted root), so it digests a part of it |
| 76 | `drafts/ledger-proposals/java-formal-binding-corroborations.json` | `$.evidence_basis.projection` | `evidence/java/formal-bindings/coverage-projection.json` | TRUE, not mechanically fixable | bare `{path,sha256}`; sibling `spec` entry matches its file, so the schema does mean "sha256 OF path". But `62758083…` matches NO version of the file in any branch (only blob ever: `02a9b130…`), and no canonicalisation reproduces it. Nothing validates it: `ProposalDraftPaths()` deliberately excludes this file |
| 77 | `drafts/ledger-proposals/java-formal-binding-corroborations.json` | `$.evidence_basis.receipt` | `evidence/java/formal-bindings/receipt.json` | TRUE, not mechanically fixable | same shape; `17290017…` matches no version (only blob ever: `4a4dff73…`). No retained bytes exist to diff against, so "propagate with zero non-digest change" is impossible |
| 78 | `evidence/governance/decisions/delta-ledger-receipt.json` | `$` | `evidence/java/behavior-delta-ledger.json` | FALSE POSITIVE | digest occurs INSIDE the named document (ledger record / chain head / accepted root), so it digests a part of it |
| 79 | `evidence/governance/decisions/e3-formal-receipt.json` | `$.artifacts.results_documents[0]` | `assurance/formal/frame-results.json` | TRUE, must NOT be fixed | a dated attestation, not a live pin: the CURRENT digest is already recorded in the same document at `$.review_round_5.artifacts_this_round.results[0]`. Rewriting the top level would make the receipt claim bytes the worker did not produce. Protected store |
| 80 | `evidence/governance/decisions/e3-formal-receipt.json` | `$.artifacts.results_documents[1]` | `assurance/formal/close-model-results.json` | TRUE, must NOT be fixed | same: current digest recorded at `$.review_round_5.artifacts_this_round.results[1]`. Protected store |
| 81 | `evidence/intake/java-intake-manifest.json` | `$.build` | `evidence/java/build.json` | FALSE POSITIVE | digest occurs INSIDE the named document (ledger record / chain head / accepted root), so it digests a part of it |
| 82 | `evidence/java/legacy-record-adjudications.json` | `$` | `evidence/java/behavior-delta-ledger.json` | FALSE POSITIVE | digest occurs INSIDE the named document (ledger record / chain head / accepted root), so it digests a part of it |
| 83 | `evidence/java/legacy-record-adjudications.json` | `$.adjudications[12]` | `drafts/ledger-proposals/legacy-13-bare-lf-server-basis-correction.json` | FALSE POSITIVE | known: `record_digest` of a ledger record sitting beside an unrelated proposal path. Not provable by recomputation, so the tool still reports it |
| 84 | `evidence/java/test-manifest.json` | `$.authoritative_run.execution_code_binding.sources[0]` | `internal/lab/executor_darwin.go` | TRUE — filed as F014 | code binding verified against a copy of itself; `internal/lab/executor_darwin.go` has drifted |
| 85 | `evidence/java/test-manifest.json` | `$.authoritative_run.execution_code_binding.sources[2]` | `internal/lab/sandbox.go` | TRUE — filed as F014 | `internal/lab/sandbox.go` has drifted; same finding |

## 7. Gates

Read from the process:

| command | exit |
|---|---|
| `go run ./cmd/pinconsumerctl dangling -root .` (before) | 1, `candidates=85` |
| `go run ./cmd/pinconsumerctl dangling -root .` (after) | 1, `candidates=34 explained=51` |
| `go build ./...` | 0 |
| `go test ./cmd/pinconsumerctl/` | 0, 18 tests |
| `make -C rust gates` | see section 7 |
| `go test ./internal/formalplan/` | 1 — environmental, section 5 |

## 8. Weaknesses I can see and am not hiding

1. **The 22 us006 rows rest on reading code, not on running it.** Section 5 says why. If the
   archive were reachable the test would settle it in one run.
2. **`contained-in-document` is the broadest rule I added.** Its justification is that a file
   cannot contain its own sha256, which is sound, but it would also explain a pin whose stale
   digest happened to appear inside the named document for an unrelated reason. It prints
   where it found the digest so a reader can check.
3. **The detector still cannot see a pin split across two objects**, unchanged from `fb72adb`,
   and the ceiling still says so. `denominator_basis[2]` shows the neighbouring gap: an
   absent path is invisible to `dangling` entirely, and only the reconciler catches it.
4. **I did not adjudicate whether the E3 receipt's layering is the right pattern**, only that
   it is internally consistent. A receipt whose top-level digests are stale by design is easy
   to misread as drift — which is precisely what happened here.
