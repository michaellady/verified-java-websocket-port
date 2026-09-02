# Landing record — claude/us017-ac2 → mainline (goal-loop, interactive, owner-approved to proceed)

Recorded 2026-09-02T09:56:48Z by the goal loop from tool output. Landing check, not an
independent review; the branch's substantive review is its own rounds.

## What landed

- Branch head before the forward merge: 4b187b8 (review PASS at round 4, per
  the merge-queue table in `.claude/HANDOFF.md`).
- Forward merge of mainline 2979883 into the branch: 0c0c4b0. One conflict,
  `assurance/replay/fixtures/us006-cases.json`: both sides had refrozen its 22
  `realized_tree_sha256` values (digest lines only). Resolved by refreezing on
  the merged tree with the sanctioned flag, both exits read:
  `US006_REGENERATE=1 go test ./internal/formalplan/ -run TestUS006FixtureCatalogThroughRealCLI`
  exit 0, then the same without the flag, exit 0. All 22 digests differ from
  both parents, as expected for a tree neither parent described.
- Post-merge re-binding commit on the branch: 20e216f. The forward merge left
  `assurance/concurrency/results.json` binding a `plan.json` digest
  (fe39048e…) that mainline had moved when `ledger-integrity` landed: three
  `behavior_delta_ledger` keys (observed_record_count 35 to 48,
  observed_head, append_blocker) and the escaping of two em dashes; a parsed
  key-level diff shows nothing else, and the bounds object is unchanged.
  `TestCommittedConcurrencyResultsBindTheCommittedTree` refused the stale
  binding as designed. Re-bound to 6370a157… with the disclosure in the
  document's revision_note and sha256_provenance, following the document's own
  precedent for the earlier stale digest; no counter was re-measured.
  `evidence/linkage/evidence-dag.json` binds that document's digest and was
  refreshed through the sanctioned path, both exits read:
  `LINKAGE_REGENERATE=1 go test ./internal/linkage/` exit 1 (reports
  LINKAGE_DAG_DRIFTED and a stale schedule-exploration digest while
  regenerating, by design), then `go test ./internal/linkage/` exit 0; one
  digest line changed, 71aa7982… to b0906ebd….
- Mainline merge commit: 7262a29. Mainline tree 6d70078 equals the branch tree.
- 19 files: `rust/ws-core/src/connection.rs`, `rust/ws-driver/src/lib.rs`,
  `rust/ws-testee/src/io_loop.rs`, their tests and seeds, the concurrency
  results and its new binding validator, linkage evidence, and the US-006
  fixture. `rust/ws-testee/tests/loopback.rs` auto-merged this branch's new
  loopback tests with mainline's kernel-independent stalled-writer fixture.

## Validation on the merged tree, exit codes read directly

- On 0c0c4b0 (Rust tree identical to what landed): `make -C rust gates` with
  the store exported, ac1-gates PASS 8/8, ledger-gates ok, `gates exit=0`.
- After the evidence re-binding (Rust tree unchanged, `git diff --quiet -- rust`
  exit 0): `make -C rust ac1-gates ledger-gates` exit 0, adapter-linkage PASS,
  ac1 8/8, ledger integrity ok, 4 governance digests matched.
- Behaviour-bearing paths changed, so the differential and exam were re-run on
  the merged tree with the harness rebuilt (sha256 e2898c13…): public and
  handshake request digests unchanged (0c1503c0…, e00d968f…); port 74/74 and
  49/49 (runtime neutralised); live Java 74/74 and 49/49 with 16 divergences;
  the two public transcripts differ only in the free-text error detail. No
  corpus shift.
- `go build ./...` exit 0. `go test -count=1 ./...` with the store exported
  and the pinned JDK on PATH: 29 packages ok, including `internal/formalplan`
  with the new binding tests and `internal/linkage`. Two environment-only
  failures, unchanged from the baseline: `internal/lab` (Darwin sandbox-exec)
  and `internal/portplan` derive-reproduction (jdk_vendor line).

## Findings

- None blocking.
- The evidence re-binding is a merge consequence, not a change in what the
  concurrency results measure; it is disclosed in the document, in commit
  20e216f, and here.
- One background gates invocation was denied by the session's auto-mode
  classifier; the affected targets were run directly in the foreground instead.
  No validation was skipped.
