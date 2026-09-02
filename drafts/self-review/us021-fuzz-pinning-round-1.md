# US-021 fuzz pinning — round 1 (branch `claude/us021-fuzz-pinning`)

Recorded 2026-09-02T19:53:40Z from tool output. Base: mainline `57e881c`. Host:
Linux x86_64, 4 CPUs, 1-minute load average 18.63 with seven sibling agents
running. Every exit code below was read from the process, not inferred.

This is a self-review of my own branch, not an independent review.

## The finding I was sent to close, and what I actually found

The criteria audit said US-021's real gap is judgment, not evidence: AC3's
per-target pinning had never been assembled or checked. That is true. It is not
the whole gap. Assembling the pinning forced a per-target census, and the census
says AC2 is not met either, in a way the "not started → actually substantial"
correction had skipped over:

**three of AC2's seven named target families have no fuzz target at all.**

## Per-target census (AC2)

AC2 verbatim: "Fuzz targets cover handshake client/server, frame decode,
message/UTF-8, fragment/control sequences, close/EOF, and owner-driver
command/byte schedules; seeds include RFC vectors, Autobahn failures, Java
tests, differentials, mutants, and minimized regressions."

| family | verdict | what is actually there |
| --- | --- | --- |
| handshake client | **ABSENT** | 11 committed seeds in `rust/ws-core/fuzz-seeds/us010`, replayed at fixed expectations by `rust/ws-core/tests/handshake_seeds.rs`; fixed-example units in `handshake_client.rs`. No byte of handshake input is ever generated. |
| handshake server | **ABSENT** | Same shape: 17 seeds in `fuzz-seeds/us011`, fixed replay, fixed units. `ServerHandshake` never receives a generated request. |
| frame decode | **PINNED** | Real generative target: `adversarial_fuzz.rs` byte-soup (10,000), frame-soup (10,000), rechunk single (2,000) / multi (4,000), config boundaries (2,000), queue pressure (1,000), plus corpus anchors and declared-length headers. |
| message/UTF-8 | **PINNED** | Real generative differential: `adversarial_properties.rs` random byte soup (20,000) and corrupted/truncated encoded strings (5,000) against an independent in-test reference scanner, plus masking (2,000). |
| fragment/control sequences | **SHARED, no dedicated target** | Genuinely generated — `draw_frame` draws continuation/text/binary/close/ping/pong and reserved opcodes, clears FIN one time in five, sets RSV bits; `draw_stream` concatenates 1–10 frames with garbage tails and truncations — but only inside the frame-decode target. No target, campaign bound, or artifact of its own. |
| close/EOF | **SHARED, no dedicated target** | `draw_close_payload` draws hostile code/reason pairs over a 14-code table plus uniform random `u16` codes with invalid-UTF-8 reasons. But `FuzzStep::Eof` is drawn in exactly **one** family (`family_command_interleave`, one step in ten over 5,000 cases); byte-soup and frame-soup never emit EOF at all. |
| owner-driver command/byte schedules | **ABSENT** | `rust/ws-driver/tests/schedule_exploration.rs` exhaustively **enumerates** every interleaving of five fixed actor programs within a context-switch bound. Systematic and valuable, and not generative fuzzing: it draws nothing. The retained `fuzz-seeds/us017` corpus (16 files) is consumed as byte-for-byte **expected output of the minimizer**, not as seeds fed to a generator. `family_command_interleave` does interleave generated commands with bytes, but at the ws-core seam against `ConnectionCore` — no `ConnectionDriver`, no owner poll loop, no transport write path. A different seam from the one AC2 names. |

Two substitutions I refused to make, both instances of the defect class this
program keeps rediscovering — existence standing in for identity:

- **A seed corpus is not a campaign.** `fuzz-seeds/us010` and `us011` exist and
  are exercised. Nothing generates handshake input.
- **A property test is not a fuzz target, and an exhaustive enumerator is not
  one either.** `schedule_exploration.rs` is stronger than fuzzing within its
  bound and gives zero fuzz coverage outside it.

One further trap, worth naming because it looks like coverage:
`family_seed_corpus_anchors` **does** read the us010/us011 handshake hex files —
and feeds them to `ConnectionCore` as post-handshake **frame** bytes. It
exercises the frame decoder over handshake-shaped bytes and gives the handshake
parsers nothing.

## What I built (AC3 pinning as a checked artifact, not a document)

- `assurance/fuzz/manifest.json` — the AC3 exact target manifest and the census
  above, in machine-readable form.
- `internal/fuzzpin/` — the checker, as production code (the repo's own lesson
  from the ledger gate: a rule that lives only in a `_test.go` is run by no
  release path).
- `cmd/fuzzpinctl/` — the runner: `-check`, `-campaign`, `-replay-fixtures`,
  `-campaign-fixtures`, `-emit-digest`.

Nothing in the manifest is taken on trust. `-check` re-derives it:

- every declared entrypoint must be a real `#[test] fn` in the named file (a
  plain `fn` with a test-shaped name is refused: the harness never runs it);
- every declared campaign size and generator seed must appear **verbatim** as
  the loop literal in that source, so the manifest cannot claim a
  10,000-case campaign over a 10-case loop;
- corpus digests, the generator source digest, and the toolchain pin digest are
  recomputed from disk under `CANONICAL_PATH_SHA256_V1` (the scheme
  `assurance/replay/fixtures/us006-cases.json` already uses);
- a missing corpus root is an error, never an empty corpus;
- the timeout/OOM/crash policy must name all three;
- the artifact-capture directory must exist — a declared capture path that does
  not exist captured nothing;
- the campaign's liveness guard must be `wall_clock` with a positive deadline
  (finding **F005**, made mechanical: a bound written as a count of iterations
  is a host-speed measurement dressed as a bound). The deterministic case count
  is recorded separately as *work*; it may never be the guard.

## Unavailable tooling blocks instead of skipping

`cargo-fuzz` is **not installed** here and there is no nightly toolchain:

```
cargo fuzz --version   → exit 101 (read from ProcessState)
command -v cargo-fuzz  → exit 1
~/.cargo/bin           → cargo, clippy, miri, rustfmt … no cargo-fuzz
```

So **zero coverage-guided fuzz targets exist anywhere in the tree** — no
`fuzz/` directory, no `fuzz_target!`, no libFuzzer entrypoint. AC3's vocabulary
(pinned engine, dictionary, crash-artifact capture, replay of a minimized
crashing input) is libFuzzer/AFL vocabulary, and none of it is available.

Following the ledger gate's refusal when `VJWP_PROTECTED_STORE` is unreachable,
and `internal/formalplan`'s `UNAVAILABLE_REPRESENTED_AS_SKIP` /
`UNAVAILABLE_BACKEND_CLAIM`:

- the engine is declared in the manifest and probed; the probe's exit code is
  read from the real process state and printed verbatim;
- a failed probe raises `FUZZ_ENGINE_UNAVAILABLE` (**BLOCK**), unconditionally;
- any target claiming a campaign on an unavailable engine additionally raises
  `UNAVAILABLE_REPRESENTED_AS_SKIP` (**BLOCK**);
- the inverse evasion — parking a target as `BLOCKED_UNAVAILABLE` when the
  engine *is* installed — raises the same finding;
- claiming the AC met while any block stands raises
  `UNAVAILABLE_REPRESENTED_AS_SUCCESS` (**BLOCK**);
- `SKIPPED` is not a valid status. There is no skip disposition in the tool.

The load-bearing fixture is `engine-unavailable-honestly-blocked`: unavailability
recorded *honestly* still blocks. Missing tooling is a block, never a pass.

## The replay I executed

`assurance/fuzz/campaign/` holds eight captured logs. Each target's replay
command ran **twice** under its declared 900-second wall-clock deadline; every
exit code was read from `ProcessState`; the normalized outcome (per-test
verdicts and the summary, with host timing stripped) was digested and the two
runs required to match.

```
frame-decode                 run1 exit=0 wall=0.916s   run2 exit=0 wall=0.972s
                             REPRODUCED digest sha256:494d7a2f…65b054
message-utf8                 run1 exit=0 wall=0.538s   run2 exit=0 wall=0.145s
                             REPRODUCED digest sha256:9173f92d…ad42aa
fragment-control-sequences   REPRODUCED digest sha256:494d7a2f…65b054
close-eof                    REPRODUCED digest sha256:494d7a2f…65b054
```

The three `494d7a2f…` digests are identical because those targets share one test
binary — recorded, not hidden. The three ABSENT families print
`not_executed="no runnable target exists for this family; recorded, never
skipped"`.

## RED readings and deletion attacks

`assurance/fuzz/fixtures/cases.json` — 25 static-pin cases through the real
checker, each with an exact expected exit code, state and set of typed BLOCK
codes. `assurance/fuzz/fixtures/campaign/cases.json` — 5 campaign-runner cases.
**Exactly one case in each suite is green**, so a checker that blocked
unconditionally would fail its own suite. Both suites: exit 0, 0 failures.

Campaign-runner RED, all observed, not asserted: a replay command that exits 3
is recorded `exit=3` and fails; a command that outruns a 1-second deadline is
killed (`first_exit=-1`, `deadline_hit=true`) and fails; a command whose output
differs between runs fails on the digest comparison; a command that exits 0
having run nothing fails on "no test outcome lines".

**Deletion attack** — 28 checks neutered one at a time, each required to turn its
suite red. Script and transcript:
`/tmp/.../scratchpad/us021/attack.py`, `attack2.txt`.

The first pass found **two survivors**, and they are the most useful thing in
this record:

- `case-literal-identity` stayed green when deleted — the total-sum check fired
  in its place under the *same* finding code, and the fixture accepted it.
- `liveness-guard-is-wall-clock` stayed green when deleted — the
  positive-deadline check fired in its place under the same code.

Both were checks whose only witness was another check's finding. Fixed by giving
the four campaign/liveness rules distinct codes
(`FUZZ_CAMPAIGN_LITERAL_DRIFT`, `FUZZ_CAMPAIGN_TOTAL_MISMATCH`,
`FUZZ_CAMPAIGN_EMPTY`, `LIVENESS_GUARD_NOT_WALL_CLOCK`,
`LIVENESS_GUARD_DEADLINE_ABSENT`) and isolating the two fixtures to a single
mutation each. Second pass: **all 28 deletions RED**, attack exit 0.

I would not have found either without deleting the checks. Two of my 24
static checks were decorative until this pass.

## Honest state of every AC

**AC1 — properties. NOT MET, one named gap.** Coverage is genuinely broad:
mask equation/involution, canonical length forms and non-canonical escapes,
chunk-boundary invariance (whole / byte-at-a-time / seeded random splits),
cap-before-allocation, strict UTF-8 differential, control interleaving, close
at-most-once (exactly-once terminal oracle), deterministic replay, and
length/close round trips. The generator domains are documented in detail in the
module headers. **Shrinkers are absent**: `grep -ci shrink` over
`adversarial_properties.rs` and `adversarial_fuzz.rs` returns 0 and 0. The only
shrinker in the repository is the schedule minimizer in
`rust/ws-driver/tests/schedule_exploration.rs` (5 hits), at a different seam. A
failing case in the ws-core suites is reported by seed label, not minimized. AC1
asks for "documented generator domains and shrinkers"; half of that clause has
no implementation.

**AC2 — NOT MET.** 3 of 7 families absent, 2 more shared-only. See the census.

**AC3 — NOT MET, and it blocks.** For the two families that have real targets,
every AC3 field is now pinned, re-derived from the tree, and the replay
executed and reproduced. For the coverage-guided engine class the AC presumes,
the tooling is absent and blocks. `fuzzpinctl -check` exit **1**, state
BLOCKED, 4 blocking findings.

**AC4 — CANNOT BE COMPLETED IN THIS SESSION, and I did not attempt it.** AC4
requires runtime checks on **both** blocking platforms. Per
`evidence/governance/decisions/e6-stress-receipt.json` those are macOS arm64 and
Linux x86_64. This session is Linux x86_64 only, with no macOS host and no path
to one. Debug and release runtime checks exist in `make -C rust gates`
(`test` and `test-release`), and the F005 fix landed in mainline `57e881c`
converts the last iteration-count liveness guards in
`rust/ws-driver/tests/concurrency.rs` to wall-clock deadlines. **Exact owner
action needed:** run `make -C rust gates` plus the `cmd/stressrepeatctl` repeat
legs on a macOS arm64 host, and re-run
`go run ./cmd/fuzzpinctl -check -campaign -runs 2 -root .` there, so the
`assurance/fuzz/campaign/` reproduction digests are established on the second
blocking platform; then record both legs the way `e6-stress-receipt.json`
records US-017 AC4's. Race tooling (ThreadSanitizer) availability on that host
must be probed and, if absent, blocked rather than skipped — AC4's own rule.
I make no AC4 claim of any kind.

**AC5 — NOT ASSESSABLE while AC2/AC3 block, and partially in place.** Minimized
regressions are retained and byte-compared for the driver seam
(`fuzz-seeds/us017/minimized/`, 7 files) and the two named regressions in
`fuzz-seeds/us017/regressions/`. F005 (a real discovered flake) was minimized to
its cause and fixed in mainline rather than left open. But AC5 says "**every**
discovered failure" over the AC2 target set, and three of those targets do not
exist, so there is no population of discovered failures to have minimized. AC5
cannot be closed above AC2. Within what exists, I observed zero crashes, hangs,
panics, or invariant violations across the four executed campaigns, twice each.

## Claim grade

**bounded.** The executed campaigns are a deterministic bounded generative
campaign over two families — 29,000 and 27,000 fixed cases from committed seeds,
reproduced twice. That is bounded evidence. It is not proof, it is not
coverage-guided fuzzing, and it says nothing about the three absent families. I
am not arguing this grade upward.

## What I did NOT do, by name

- I did **not** write the three missing fuzz targets (handshake client,
  handshake server, owner-driver command/byte schedules). Recording the gap
  honestly and writing the targets are different jobs; the second is a
  substantial piece of new generative code per seam and would have arrived
  unreviewed alongside the checker that judges it.
- I did **not** install `cargo-fuzz` or add a nightly toolchain. Both would
  change the pinned toolchain the whole project depends on, and the correct
  response to absent tooling here is to block, which is what I built.
- I did **not** write a shrinker for the ws-core property/fuzz suites (AC1 gap).
- I did **not** wire `fuzzpinctl` into `make -C rust gates`. It exits 1 by
  design on the current tree, so wiring it in would turn every sibling branch
  red for a gap none of them introduced. The owner should wire it at the point
  US-021 is scheduled to close.
- I did **not** attempt AC4's macOS arm64 leg, and made no claim about it.
- I did **not** run Autobahn, any benchmark, or anything touching AWS.
- I did **not** modify `evidence/java/behavior-delta-ledger.json`,
  `internal/deltaledger`, or `assurance/concurrency/results.json`.
- I did **not** weaken, delete, skip or filter any existing test. The deletion
  attack mutated only my own new `internal/fuzzpin` sources and restored every
  file from a backup in a `finally` block; `git status` is clean of any
  modification to pre-existing files.
- I did **not** re-derive the seed corpora's provenance claims (RFC vectors,
  Autobahn failures, Java tests, differentials, mutants) that AC2's second
  clause names. The manifest pins the corpora by digest and cites where each
  came from in the existing headers; auditing that each seed really traces to
  the source it claims is a separate job I did not do.

## Exit codes read from the process

| command | exit |
| --- | --- |
| `go run ./cmd/fuzzpinctl -check -root .` | **1** (BLOCKED, 4 blocking findings) |
| `go run ./cmd/fuzzpinctl -check -campaign -runs 2 -root .` | **1** (4 campaigns REPRODUCED; the AC still blocks) |
| `go run ./cmd/fuzzpinctl -replay-fixtures …/cases.json` | **0** (25 cases, 0 failures) |
| `go run ./cmd/fuzzpinctl -campaign-fixtures …/campaign/cases.json` | **0** (5 cases, 0 failures) |
| deletion attack, 28 mutations | **0** (all 28 turned their suite RED) |
| `go build ./...` | **0** |
| `go vet ./...` | **0** |
| `go test ./internal/fuzzpin/ -count=1` | **0** (6 tests) |
| `go run ./cmd/deltaledgerctl --root . --check` (with `VJWP_PROTECTED_STORE` set) | **0** |
| `cargo fuzz --version` | **101** — the block |
