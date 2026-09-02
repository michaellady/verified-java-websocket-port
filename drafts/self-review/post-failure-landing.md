# Landing record — claude/post-failure → mainline (goal-loop, cloud session)

Recorded 2026-09-02T19:04:22Z by the goal loop from tool output; every exit
below was read from the process, never inferred from its text. Landing check,
not an independent review; the branch's substantive review is its own rounds
(PASS at round 3).

## What landed

- Branch head before the forward merge: `1d1a1e2`, 67 commits behind mainline.
  It fully contains `claude/vacuity-sweep`
  (`git merge-base --is-ancestor origin/claude/vacuity-sweep origin/claude/post-failure`
  exit 0), so landing it resolves that branch too.
- Merge base `dc07516`. Three forward merges were needed because mainline moved
  three times while this one was being validated:
  - `8f10cea` — mainline `8a7f713`. Fourteen conflicts, listed below.
  - `0335b03` — mainline `d433c21` (server-close parity, the F004 race-test fix,
    the criteria audit). Three conflicts.
  - `06fb927` — mainline `2534bfe` (divergence sweep, Java formal bindings). No
    conflict, and the reason was checked rather than assumed: the merge adds
    only NEW files under `rust/`, `assurance/concurrency/`, `evidence/linkage/`,
    `internal/formalplan/` and `internal/deltaledger/` and modifies none, so the
    tree the previous commit measured is byte-identical here.
- Mainline merge commit: `b62a979`, onto mainline `83a992c`. Its tree equals
  the branch tree exactly (`git rev-parse HEAD^{tree}` on both reads
  `9ac71c374b4ffe0575aafb3248438dd2874f7703`), so the tree validated below
  IS the landed tree.
- Branch head after the landing: `8c6320d`. Both refs pushed, first attempt,
  `git push` exit 0 each: `1d1a1e2..8c6320d claude/post-failure` and
  `83a992c..b62a979 -> claude/feature/verified-java-websocket-port`.

Every conflict was resolved as a UNION. The seams where the two sides had
genuinely different designs, and what the union does:

- `DriverOutput::Failure`. This branch made it carry a `FailureOrigin`, because
  C5 had made a locally rejected command indistinguishable from an inbound
  decode fatal and C6 then answered both with shipped Java's 1002 close.
  Mainline made it ORDERED strictly after every committed write, because a
  fatal core step can commit a write and fail in the same call and an adapter
  that halts at its first `Failure` abandoned those bytes. The union LATCHES
  the failure WITH its origin. Mainline's latch is strictly stronger than this
  branch's "the committed output drains on later polls" stance, which was true
  only for an adapter that keeps polling; the origin is what keeps C6 gated.
- `shutdown_latched` is reintroduced beside this branch's `pending_eofs` count.
  The count says how many EOF notifications the core has still to score and
  falls back to zero; mainline's write-drop accounting needs the irreversible
  fact that transport service ENDED. Collapsing them would silently re-open the
  post-shutdown write sweep and the suppressed automatic pong.
- `prepare_terminal` and `CommandDisposition::TerminalRejected` stay removed
  (owner decision `us017-post-terminal-owner-decision-2026-08-28`); mainline
  only carried the incumbent call sites. The fatal sweep's `terminals == 0`
  assertion read `left: 1` on the merged tree and now asserts the ORDERING, as
  the main sweep already did.
- `ws-testee`'s `io_loop` honours both: mainline's five new `Failure` sites take
  the origin, the three inside `drive_until_open` ignore it (that loop has not
  reached OPEN, which is `close`'s :464 guard) and the two in the connected loop
  call `send_violation_close`, because latching MOVED where a decode-path
  violation surfaces and did not remove Java's answer to it.
- `ws-oracle-harness` REFUSES `DriverOutput::WritesDropped` rather than
  absorbing it: it sends no `Shutdown`, so the disposition is unreachable there,
  and mapping it to `Idle` would have been the exact AC2 leak.
- The C6 ledger record is appended LAST, becoming sequence 49, so neither the
  frozen 35-record prefix nor mainline's sequences 36-48 move.

Generated artifacts were regenerated, never hand-edited. Both exits read each
time:

| step | exit |
| --- | --- |
| `go run ./cmd/deltaledgerctl --root .` | 0 (49 records, head `sha256:eaa6eac8…`) |
| `go run ./cmd/deltaledgerctl --root . --check` | 0 |
| `US006_REGENERATE=1 go test ./internal/formalplan/ -run TestUS006FixtureCatalogThroughRealCLI` | 0 |
| the same without the flag | 0 |
| `LINKAGE_REGENERATE=1 go test ./internal/linkage/` (three times) | 1 each, by design — it reports the drift it is fixing |
| `go test ./internal/linkage/` (three times) | 0 each |
| `US017_RETAIN=1 cargo test -p ws-driver --release --test schedule_exploration` | refroze three minimized seeds; that run exited 101 on the two results.json citation checks, which were then refreshed through the procedure the gate itself prints |

## Validation on the merged tree, exit codes read directly

| check | reading |
| --- | --- |
| `make -C rust gates` | **exit 0**; fmt-check and `clippy -D warnings` clean; 77 `test result: ok`, 0 FAILED; `ac1-gates verdict=PASS gates_passed=8/8`; `adapter-linkage verdict=PASS` over 5 production sources; ledger-gates ok (49 records, integrity verified, 6 governance digests recomputed from the protected store) |
| `cargo test --workspace --locked` | exit 0, 41 suites, 428 passed, 0 failed |
| `go build ./...` | exit 0 |
| `go test -count=1 ./...` | exit 1: 32 packages ok and exactly the two documented Linux-environment failures — `internal/lab` (`PLATFORM_EXECUTOR_UNSUPPORTED`, needs Darwin `sandbox-exec`) and `internal/portplan` `TestDeriveReproducesCommittedEvidence` (`ORACLE_REPRODUCTION_MISMATCH`, the committed report's `"jdk_vendor": "Homebrew"`) |

Behaviour-bearing Rust changed, so the corpus differential and the handshake
exam were re-run on the merged tree. Release harness sha256
`9193114e56d3684c876eafa27c11c4c86cda275eb240b4779782ba6e9bf63901` (it moves
because `ws-driver` and `ws-oracle-harness` changed; the transcripts do not).
Cargo was run from inside `rust/` for the toolchain pin, and the pinned JDK 17
was given `-Dsun.stdout.encoding=UTF-8`, both as `.claude/CLOUD-ENVIRONMENT.md`
records.

| run | reading |
| --- | --- |
| public requests | `0c1503c043172d0962f44aca068d57cac5588b9d933669e5221a11b880c72d85`, byte-identical to the pinned set |
| handshake requests | `e00d968f0ae623dd75a09842ad435642c0dca53ee5e9f9ef654ce26c1f814c49`, equal to the batch-B receipt |
| public tier, port | 74/74, `corporactl evaluate` exit 0 |
| handshake exam, port, runtime neutralised | 49/49 with 16 documented divergences, exit 0 |
| public tier, live pinned Java | 74/74, exit 0 |
| handshake exam, live pinned Java | 49/49, the same 16 divergences, exit 0 |
| java-oracle build and self-test | exit 0 |
| port vs live Java, public transcripts | 26 of 74 records differ, and all 26 differ ONLY on `/error/detail`, which the scorer never compares; nothing else moves but the runtime fields |
| port vs live Java, handshake transcripts | ZERO non-runtime differing fields on all 49 |

No corpus shift. Nothing was re-baselined.

## Findings

1. **The exploration's disposition split moved, and it moved on the branch, not
   in the merge.** `closed_terminal_runs` falls from 56,777 to 49 and
   `failure_halted_runs` rises from 23,143 to 81,131. Measured rather than
   argued: the pre-merge `claude/post-failure` tree, extracted with
   `git archive` and run on its own, already reads exactly those figures. The
   branch's per-notification EOF counting makes every abnormal-teardown schedule
   halt on its second scored termination — which is why the branch added the
   clean-finish scenario — and the merge adds only mainline's write-drop
   accounting on top (`distinct_trace_digests` 3089 → 3129, `accepted` 192,285 →
   195,694, `deferred_output_pending` 27,879 → 41,944, plus the six write-drop
   and receiver-drop counters).

2. **JUDGMENT CALL — the concurrency validator's vocabulary had to change, not
   just its numbers.** `internal/formalplan/concurrencyresults.go` modelled one
   program set with one `actions_per_schedule`; the branch explores two
   scenarios of 12 and 7 actions, so that figure describes neither. Extended,
   not relaxed: `bounds.scenarios` and `bounds.scenario_shapes` are modelled and
   every new leaf has a check (the scenario count re-derived from the run line
   AND from `len(scenario_shapes)`; each shape's program sentence re-counted;
   their action counts summed against the printed `actions_total`;
   `bounds.program_shape` required to BE `scenario_shapes[0].program_shape`);
   `crValidateShrink` takes the SET of full-schedule lengths so a seed minimized
   from either scenario is checked; the plan ceiling and the two limitations
   that quote the alphabet bind the LONGEST scenario.
   `execution.counters.terminal_rejections` is gone with the disposition it
   counted. Every polarity case that named a removed field or a moved number was
   retargeted, never deleted.

3. **JUDGMENT CALL — one required assertion was changed, deliberately.**
   `terminal_disposition_model` had to assert "exactly one typed terminal
   disposition". Since the post-terminal owner decision that is not what the
   harness proves — a run may take its one clean Terminal and only then reach a
   fatal — so demanding the sentence claim it would pin a claim nothing checks.
   The assertion now requires the ORDERING the harness does assert against the
   trace: "no terminal is ever recorded after a failure".

4. **JUDGMENT CALL — `plan.json`'s `append_blocker` was compressed to fit its
   schema.** `$defs/text` in `schemas/concurrency-plan-1.0.0.schema.json` caps
   it at 8192 characters and mainline's text was already 8176. The C6 record is
   therefore a clause inside the composition sentence rather than a paragraph,
   and sixteen sentences elsewhere lost filler words. No claim was dropped; the
   full, hashed C6 rationale lives in ledger record 49, which is where it is
   load-bearing.

5. **JUDGMENT CALL — four sentences were re-worded so the leaf battery could
   still refuse a wrong value.** The enumeration in
   `concurrencyresults_leaves_test.go` mutates the FIRST number in a sentence
   and truncates it to half. My first drafts put an owner-decision id
   (`us017-…-2026-08-28`) or a sub-1000 counter ahead of the pinned ones, so the
   battery moved a digit nothing reads and four leaves that had been CHECKED
   measured INERT. They are re-worded so the first digit run IS a pinned counter
   and a half-truncation loses a pinned counter or a required phrase — not added
   to the residual list. `crValidateQuotedCounters` now filters its expected
   sequence by the same four-digit threshold its tokenizer applies, because
   `closed_terminal_runs` is 49 and an unfiltered expectation would fail every
   sentence on arity rather than on a wrong number.

6. **The residual inert list grows by four, and by four only.**
   `crExpectedLeafCount` moves 327 → 337. `bounds.scenario_shapes[*].models` and
   `[*].why_explored` are prose about what a scenario stands for and why the
   owner asked for it — the same class as the defect narrative already pinned.
   The two NAMES beside them are not in the list: a name is an identity a reader
   takes at face value, it measured INERT with `"MUTATED"` accepted in either
   position, and the new `crValidateScenarioNames` derives both from the
   harness's own `SCENARIOS` table — the harness this record already pins by
   identity and `git_blob`.

7. **Two host-speed test flakes, one fixed here and one still open.** Both are
   the class `drafts/self-review/findings/F004-race-test-spin-bound-sized-to-a-host.md`
   names: a liveness guard written as a count of how many times a fast machine
   can do something.
   - `ws-core`'s `a_producer_racing_the_owner_drop_never_blocks_and_never_reports_a_stale_accept`
     failed two gate runs here with `ws-core` byte-identical, on
     `refusals_before_the_drop < 4096`. Mainline's `01ee515` replaced the count
     with a 30-second wall-clock deadline plus a `thread::yield_now()` after each
     capacity refusal; this branch took that fix verbatim before it landed, so
     the file did not conflict.
   - **STILL OPEN:** `ws-driver`'s
     `rust/ws-driver/tests/concurrency.rs::racing_producers_never_lose_or_duplicate_commands`
     failed one `test-release` run with `left: 179 right: 200` after spending
     its whole `POLL_BUDGET` of 2,000,000 owner polls, while three other agents'
     suites were running on the same box. The owner loop never yields, so a
     loaded scheduler can starve the producer threads for the whole budget. Run
     in isolation it passed 5 of 5, and `make -C rust gates` passed twice
     afterwards. The file is mainline's and this landing did not touch it, so
     the same remedy F004 prescribes — a wall-clock deadline instead of
     `POLL_BUDGET` — is left as a follow-up rather than folded into this merge.

8. **No owner gate was crossed.** No AWS run, no benchmark run and no Autobahn
   suite run was triggered. The Autobahn evidence this branch carries
   (`evidence/rust/autobahn-post-failure/`, `evidence/rust/autobahn-layer-split/`)
   came in with the branch and was not re-executed. The in-repo Java Autobahn
   BASELINE remains BLOCKED, which is why the ledger's `append_state` is
   unchanged.
