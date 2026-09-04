# Landing record — claude/evidence-validation → mainline (goal-loop, interactive, owner-approved to proceed)

Recorded 2026-09-02 by the goal loop from tool output. The branch had no
recorded review PASS (round 5 was in flight on 2026-08-29), so this landing
carries its own self-review round, `drafts/self-review/evidence-validation-round-5.md`,
executed as one unit with the forward merge per the P1a plan in
`.claude/GOAL-LOOP.md`. Landing check plus self-review, not an independent
review: OWNER_ATTESTED_NOT_INDEPENDENT.

## What landed

- Branch head before the forward merge: 9aa73ab (r4).
- Forward merge of mainline 0bb5196 into the branch, resolved as a UNION with the
  landed claude/us017-ac2 (7262a29): ccd0cc0. Conflicts on
  `assurance/concurrency/results.json`, `evidence/linkage/evidence-dag.json`
  and `rust/ws-driver/tests/schedule_exploration.rs`, plus the duplicate
  `ValidateConcurrencyResults` in `internal/formalplan` that would not compile.
  Resolution: both validators kept (`ValidateConcurrencyResultsBindings`,
  `ValidateConcurrencyResults`, `ValidateConcurrencyResultsAll`), both test
  files kept and passing, the harness merged as a union (mainline's write-drop
  accounting plus this branch's invariant set, thirteen checked invariants),
  and the record made to satisfy both by running the merged harness and
  citing what it printed — the exploration line AND, new this round, the five
  fatal-termination sweep lines. Every counter is unchanged and re-measured.
- Sanctioned regenerations, both exits read each time:
  `US017_RETAIN=1` once for `silent-write-drop.seed` (gains `found_index=5`,
  six other lines byte-identical to the us017-ac2 pin; exit 0);
  `LINKAGE_REGENERATE=1 go test ./internal/linkage/` exit 1 by design
  (LINKAGE_DAG_DRIFTED while regenerating), then exit 0; one digest line
  changed, b0906ebd… → 0dcc7b74…, the results.json node. The US-006 fixture was
  not touched by this branch and was not refrozen.
- Mainline merge commit: 35edf8c (tree d99939e). Mainline tree equals the branch tree
  (`git diff --quiet` between the two, exit 0).
- Files: `internal/formalplan/concurrencyresults.go` (model and validators),
  `concurrency_results.go` / `concurrency_results_test.go` (renamed types, call
  sites), `concurrencyresults_test.go` (three retargeted probes),
  `concurrencyresults_leaves_test.go` (leaf count 162 → 327, residual list 11 →
  71 with class notes), new `concurrencyresults_union_test.go` (45 mutation
  cases plus the union-composition and raw-reader tests),
  `rust/ws-driver/tests/schedule_exploration.rs` (union harness plus the sweep
  citation), the seven minimized seeds (`found_index=` lines),
  `assurance/concurrency/results.json`, `evidence/linkage/evidence-dag.json`,
  and the two records under `drafts/self-review/`.

## Validation on the tree that landed, exit codes read directly

- `make -C rust gates` with the store exported: fmt-check, clippy, test,
  test-release, ac1-gates verdict=PASS gates_passed=8/8, adapter-linkage PASS
  over 5 production sources, ledger-gates ok (48 records, frozen prefix through
  sequence 35, 3 supersessions, unledgered_disagreements 0); 75 "test result:
  ok" blocks; `gates_exit=0`.
- Both harness citations against the committed document: the exploration
  citation (`bounded_exploration`) exit 0; the sweep citation
  (`fatal_termination_sweep_reports_every_abandoned_committed_write`) exit 0.
  The sweep citation was read RED first: exit 101 with "found 0" before the
  record carried the lines.
- `go build ./...` exit 0. `go test -count=1 ./internal/formalplan/` exit 0
  (all tests, including the committed leaf enumeration at 327 leaves / 71 inert
  and the omission walk at 0 holes of 394). `go test -count=1` over every other
  package: 28 packages ok (29 with `internal/formalplan`), `test_exit=1` only for the two Linux-environment failures recorded in `.claude/CLOUD-ENVIRONMENT.md` and unchanged from the baseline: `internal/lab` (`PLATFORM_EXECUTOR_UNSUPPORTED`, Darwin `sandbox-exec`) and `internal/portplan` (`ORACLE_REPRODUCTION_MISMATCH`, the vendor-bound derive-reproduction check under the owner decision F001).
- The public corpus differential and the handshake exam were NOT re-run and
  cannot have moved: `git diff --stat` against mainline over `rust/ws-core/src`,
  `rust/ws-driver/src`, `rust/ws-testee/src`, `rust/ws-oracle-harness`,
  `java-oracle`, `corpora`, `java-semantic-oracle`, `autobahn-endpoint` and
  `java-crosspeer` is empty; the only Rust bytes that differ from mainline are
  the harness test file and the seven seeds' `found_index` lines.

## Findings

- Blocking findings of the self-review round, all fixed before landing: the
  sweep magnitudes were transcribed (now cited and re-derived); the omission
  walk had reopened on the larger record (29 holes → 0); three r1–r4 probes had
  gone stale against the landed record (retargeted to read the document); seven
  document sentences collided with the branch's rules (resolved on the document
  side with disclosures, no rule weakened). Details in the round record.
- No refusal either review history proved was dropped; the union is measured by
  `TestConcurrencyResultsUnionComposesBothValidators`.
- Not done, named in the round record: RED readings' runtime values stay
  attested; `ws-core` is still not blob-pinned by the record.
- Background-command classifier: none denied this landing.
