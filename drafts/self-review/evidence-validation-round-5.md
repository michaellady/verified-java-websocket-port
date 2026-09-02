# Self-review round 5 — claude/evidence-validation (landing union with the landed claude/us017-ac2)

Recorded by the goal loop from tool output on 2026-09-02. This round stands in
for the review round the branch never had recorded (round 5 was in flight on
2026-08-29; the last committed round is r4 at 9aa73ab). It is a self-review by
the loop, not an independent review: OWNER_ATTESTED_NOT_INDEPENDENT.

Branch head reviewed: the forward merge of mainline 0bb5196 into
claude/evidence-validation plus the union edits described below, before the
landing commit. Every exit below was read from the process, never from piped
output.

## What was reconciled

Two validators for `assurance/concurrency/results.json` met in one package:

- `claude/us017-ac2` (landed 7262a29) added `internal/formalplan/concurrency_results.go`,
  binding target blobs, the plan digest, the two minimized reproductions and the
  seven retention seeds, with a document-enumerated polarity test pinned at 12
  bindings.
- this branch's `internal/formalplan/concurrencyresults.go` binds the document
  to the run it cites: the `executed_run` block, every counter re-derived in Go
  from the printed `US017_EXPLORATION` line, plan conformance and fairness
  against the plan, quoted-counter, narrative and claim-ceiling checks, strict
  decoding, the required-key pre-pass, the leaf enumeration, and the Rust half in
  the harness that refuses a document not citing this run.

Both are kept. The us017-ac2 validator is renamed
`ValidateConcurrencyResultsBindings`, the run-citation validator keeps the name
`ValidateConcurrencyResults`, and `ValidateConcurrencyResultsAll` runs the union.
Neither history's refusal was dropped: every mutation test from both test files
passes on the union, and the composition is measured by
`TestConcurrencyResultsUnionComposesBothValidators` (a fairness flip, a stale
seed digest, a stale harness blob and a stale regression-seed digest each
refused by BOTH halves through the union entry point; the committed document
passes it with zero blocking findings).

The harness merged as a union too: mainline's write-drop accounting and this
branch's invariant set, `CHECKED_INVARIANTS` extended from ten to the thirteen
properties the record lists, the printed line carrying the six write-drop and
receiver-drop tokens, and the retention test writing `found_index=` into every
seed (US017_RETAIN=1 regenerated `silent-write-drop.seed` once, exit 0; its six
other lines are byte-identical to the us017-ac2 pin).

## The document had grown; the model had not

The record this branch's validator modelled had 162 leaves. The landed record
has 327. Before this round the merged document did not even decode strictly
(`RESULTS_UNMODELED_FIELD` on `max_actions`, then on `added_by`), and once it
did, the leaf enumeration (`CR_LEAF_ENUM=print`) read:

| Reading | Leaves | Checked | Inert |
| --- | --- | --- | --- |
| r4 record under the r4 validator (from the r4 commit) | 162 | 151 | 11 |
| merged record, first strict decode, before any union check | 308 | 217 | 91 |
| after the sweep citation and the seed-naming bindings | 327 | 249 | 78 |
| after the late-clause and re-derived-number bindings | 327 | 256 | 71 |
| this round's committed reading (`crInertLeaves`) | 327 | 256 | 71 |

The 19 leaves between 308 and 327 are the fatal-termination sweep's run
citation and the two per-budget maps it made recordable.

## Attacks replayed, each refused (permanent tests in `concurrencyresults_union_test.go`)

Replays from both histories through the union entry point:

- evidence-validation r2, the reviewer's fairness flip → `RESULTS_FAIRNESS_CONTRADICTS_RUN`.
- evidence-validation r1 BLOCKING 3 / us017-ac2 round 3: stale harness blob →
  `RESULTS_SOURCE_BLOB_STALE` AND `RESULTS_TARGET_BLOB_STALE`.
- us017-ac2 round 3: stale retention seed digest and stale regression-seed
  digest → `RESULTS_SEED_DIGEST_STALE` AND `RESULTS_ARTIFACT_DIGEST_STALE`.
- evidence-validation r1 BLOCKING 1, the split read, re-encoded for the new
  `sweep_stdout_lines` key: the raw reader accepts three legal layouts and
  refuses two keys, no key, a non-array, an escape, a bare element and a
  missing separator (`TestConcurrencyResultsSweepLinesAreReadTheSameWayTwice`).

New refusals, one per binding the union added (45 cases; each was INERT on the
merged document before its check existed):

- `max_actions`: dropped where the seed carries it, disagreeing with the seed,
  claimed where the seed has none → `RESULTS_SEED_CONTENT_CONTRADICTED`; zero,
  or above the plan's ceiling → `RESULTS_PLAN_CONFORMANCE_VIOLATED`.
- `added_by`: dropped from the review-added fault, claimed by an adopted fault,
  naming another story, naming no review → `RESULTS_SEED_CONTENT_CONTRADICTED`.
  Presence is derived from the tree: a fault with a seed in
  `rust/ws-driver/fuzz-seeds/us017/` was adopted; one without was added.
- the ten-entry defect roll: the last defect dropped, two defects swapped, a
  test-side defect losing its note, a driver defect gaining one, the
  socket-level reproduction narrative dropped, and — after the omission walk
  found 28 removable regression references — any regression reference dropped,
  swapped or reordered → `RESULTS_DEFECT_ROLL_INCOMPLETE`. Each defect's shape
  AND its exact regression set are pinned in `crCanonicalDefects`.
- seed identity: a defect citing the counterexample pinned for a different
  defect → `RESULTS_SEED_CONTENT_CONTRADICTED` (the seed's `id` must be the
  defect's short id, or `regression-` plus it, the prefix the harness gives a
  review-minted pin).
- RED readings: a neighbour's reading, a reading that quotes nothing and
  attests nothing, a reading cut in half → `RESULTS_RED_READING_UNBOUND`. Each
  quoted assertion span or identifier is resolved into the BODY of a test the
  defect names (not the file), and the quotation must be whole.
- the fatal-termination sweep: a halted count moved in the cited line, a drop
  count moved in the block, either total moved by one, budgets reordered, the
  total line's per-budget list disagreeing with its own lines, a different
  enumeration, a budget missing from a map → `RESULTS_COUNTER_CONTRADICTS_RUN`;
  a line dropped or an unrecognised field → `RESULTS_EXECUTED_RUN_UNPARSED`;
  no citation → `RESULTS_EXECUTED_RUN_ABSENT`.
- fields that name seeds: a polarity control restating a schedule its seed
  does not carry, a regression entry quoting the wrong digest prefix or budget,
  the seed-format note or the sweep's `why` misquoting `MAX_ACTIONS_UNREACHED`
  (read from the harness with `crRustConstPattern`), the mechanism sentence
  dropping the found index → `RESULTS_SEED_CONTENT_CONTRADICTED`; the
  rerunnable control or a pinned regression seed dropped from its list, or the
  polarity read naming a control test the harness does not declare →
  `RESULTS_NAMED_ARTIFACT_MISSING`. Which seeds ARE polarity controls is
  derived: every seed under `minimized/` or `controls/` whose mutation is
  outside the adopted vocabulary.
- prose that quotes numbers: the drift limitation misquoting the toolchain pin
  (read from `rust/rust-toolchain.toml`), the frame-count limitation moving the
  counter it opens with, the coverage paragraph moving a dropped-write count,
  the outcome sentence's sweep total moving →
  `RESULTS_SEED_CONTENT_CONTRADICTED` / `RESULTS_CLAIM_CEILING_INFLATED` /
  `RESULTS_PROSE_CONTRADICTS_COUNTERS`.

## Findings of this round, and what was done

1. **The sweep magnitudes were transcribed, and the record said so.**
   `limitations[11]` of the landed record admitted every magnitude in
   `execution` was transcribed from printed output. The exploration line was
   already a citation; the sweep block — two totals and three per-budget maps —
   was not, and the enumeration read all of its numbers INERT. Fixed at the
   shape of the problem: the harness's sweep test now formats its five
   `US017_FATAL_SWEEP` lines, prints them and asserts the committed record
   cites them element-for-element (`assert_committed_results_cite_this_sweep`,
   the same contract as the exploration line); the record carries them under
   `execution.fatal_termination_sweep.executed_run.sweep_stdout_lines` with two
   per-budget maps the lines carry that the record had never transcribed
   (`per_budget_fatal_path_dropped_bytes`, `per_budget_clean_path_drop_runs`);
   `crValidateSweepRun` re-derives every field of the block from them, and the
   raw bytes are read by the harness's algorithm and compared with the
   structural parse. RED read first: the sweep exited 101 at the new citation
   check with the record carrying no lines ("found 0"); the five lines were
   copied from that run; the re-run exited 0. `limitations[11]` carries the
   supersession clause and the validator requires both halves of it.
2. **Omission holes reopened by the larger record.** The required-key pre-pass
   held, but the omission walk found 29 removable positions of 394: every
   single regression reference of the eight review-found defects (the two-kinds
   rule is satisfied as long as one harness reference and one direct reference
   remain), and `retention.polarity_controls[0]`. Fixed by pinning each
   defect's exact regression set in the roll and deriving the polarity-control
   census from seed mutations. After: 0 holes of 394.
3. **Three probes in the r1–r4 tests had gone stale against the landed
   record** (`deferred_command_turn=31397` is now 31383; the terminal split
   52924/26996 is now 56777/23143; `max_drain_polls_observed` is now 12, the
   value the probe substituted). Retargeted to read the committed values from
   the document rather than pin them, so they follow the record.
4. **Seven document sentences collided with this branch's phrase and counter
   rules** (retention.mechanism lost the found-index clause; the outcome
   sentence quotes the sweep total too; the pinned-artifacts disclosure no
   longer described what had happened; recorded_at_provenance lost its
   occasion; two regression references were descriptions rather than declared
   tests; defect 4's RED reading lacked the attestation clause the
   reproduction-bearing defects are held to). Each was resolved on the
   document side with a disclosure in `revision_note` (items a–g), except the
   outcome sentence, where the validator now derives the second total from the
   sweep's per-budget halted plus closed-terminal runs. No rule was weakened to
   admit a sentence.
5. **`recorded_at` re-captured.** The union rewrites the record, so its
   timestamp is this write's `date -u`, and the provenance sentence says so and
   names the previous value.

## Residual, transcribed not chosen

71 inert leaves of 327, listed individually in `crInertLeaves` with the class
each belongs to: 51 defect-narrative fields; seven RED readings (six defects and
the sweep's polarity read) that accept a number moved inside the runtime output
they quote; 11 prose fields that accept a number moved inside a citation token
or a truncation that keeps every load-bearing clause; `native_stress.rustc` and
`revision_note`. `results.json` stays PARTIAL by the receipt's own key; the
grade is not argued upward.

## Not done, named

- The RED readings' runtime values (the labels the pre-fix tests printed)
  exist nowhere in the committed tree, so they remain attested.
- `ws-core` is still not blob-pinned by the record; the exposure is the one the
  record's own limitation bounds.
- The differential and the handshake exam were NOT re-run this round and cannot
  have moved: `git diff --stat origin/<mainline> -- rust/ws-core/src
  rust/ws-driver/src rust/ws-testee/src rust/ws-oracle-harness java-oracle
  corpora java-semantic-oracle autobahn-endpoint java-crosspeer` is empty; the
  only Rust bytes that differ from mainline are the harness test file and the
  seven seeds' `found_index` lines.

## Gates, read at this head

See the landing record `drafts/self-review/evidence-validation-landing.md` for
the full gate table on the tree that landed.
