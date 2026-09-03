# Making the host-sized-fixture class detectable instead of rediscoverable

branch: `claude/host-sized-fixture-detector` (from mainline `claude/feature/verified-java-websocket-port`, head 57e881c)
date: 2026-09-02
scope: a new gate, `make -C rust fixture-guard`, wired into `make -C rust gates`. No test in the tree was changed, relaxed or deleted; the two Rust fixtures named below are byte-identical to 57e881c on this branch.

---

## 1. The rule

F005 filed the generalisation in prose:

> no fixture's own liveness guard may be a count of operations; it is a generous
> wall-clock deadline, and any counter kept alongside it may only REPORT in the
> failure message, never decide.

The mechanical form, implemented in `cmd/fixtureguardctl/scan.go`:

> **A count of operations may not decide whether a fixture's loop keeps going.**

It applies only to loops that can fail to terminate on their own — `loop` and
`while`. A `for` is bounded by its iterator and cannot carry a liveness guard,
so `for case in 0..247` and `for _ in 0..200_000` are out of scope by
construction rather than by exception.

It applies only to FIXTURE code: every `.rs` file under a crate's `tests/`
directory in full, and inside `src/` only the extent of a `#[cfg(test)] mod`.
A retry cap in production code is a design decision, not this rule's business.
(`rust/ws-testee/src/io_loop.rs:188` — `while report.polls < bounds.max_polls`
— is production and is deliberately not reported; see §5.)

Three shapes:

**SHAPE A — a count conjunct in the loop header.**
`while <...> && counter < K { counter += 1; ... }` where `counter` is a plain
local integer (or an atomic read with `.load(..)`) incremented UNCONDITIONALLY
in the body — at the body's own brace depth, so once per iteration — and `K` is
an integer literal or a `SCREAMING_SNAKE` constant. This is F005's text.

**SHAPE B1 — an in-loop abort on a count.**
`assert!(counter < K, "...")` or `if counter > K { panic!(..) }` inside the
loop body, where `counter` is incremented ANYWHERE in that loop. Only the
DECIDING position is read: argument 0 of the macro, or the `if` condition. This
is F004's text.

**SHAPE B2 — an in-loop silent break on a count.**
`if counter >= K { break }` where `counter` is incremented unconditionally.
Nothing in this repository's history has cost a red gate this way yet; it is
the same defect with the failure moved downstream, since everything asserted
after the loop is then asserted about a truncated run.

### The hard part, and how it is decided

`while disposed < 20 && started.elapsed() < POLL_DEADLINE` (a GOAL) and
`while applied.len() < TOTAL && polls < POLL_BUDGET` (a GUARD) are the same
shape. Both are two conjuncts; both compare a counter to a constant. The
discriminator is **how the counter is incremented**:

| | increment | what it counts |
|---|---|---|
| `polls` | `polls += 1;` at the top of the body, every iteration | iterations of the machine |
| `disposed` | `if result.command.is_some() { disposed += 1; }` | dispositions actually observed |
| `drained_idle_passes` | inside a `match` arm | idle passes actually observed |
| `applied` | `applied.push(text)` — a `Vec`, compared by `.len()` | commands actually applied |

An unconditionally incremented counter counts nothing but how many times this
host went round the loop. A conditionally incremented one counts progress, and
a loop that stops when progress reaches its target has reached its goal, not
its budget. So Shape A requires the increment to be unconditional, and Shape B2
does too. Shape B1 does not need the test: reaching an `assert!` or a `panic!`
is a FAILURE by construction, and a bound whose breach is a failure is a
liveness guard however the counter is incremented — which is why F004's
`refusals_before_the_drop`, incremented inside a `match` arm, is still caught.

A wall-clock deadline is exempt for free rather than by a vocabulary of
time-words: `started.elapsed() < POLL_DEADLINE` has no bare incremented
counter on its left, so no shape matches it. There is no list of "time-like"
identifiers to keep up to date.

### The trade I chose

**I chose the noisy direction on Shape B1, and the silent direction on
everything a `for` loop or production code can express.**

Shape B1 fires on any in-loop `assert!(counter < K)` over a counter the loop
increments — including one asserting a property OF THE SYSTEM UNDER TEST that
happens to be a count. I could not find a mechanical way to separate "the
producer must never spin unboundedly" (F004, a statement about the machine)
from "the queue must never accept a ninth command" (a statement about the
queue), because they are the same three tokens. I chose to fire, because:

* the cost of a false positive is one line of justification at the site, and
  the tool prints the exact remedy in the failure;
* the cost of a false negative is a red gate on someone else's landing plus an
  investigation to prove the crate under test had not changed — which this
  program has now paid three times, for about three hours in total;
* the tree currently has ZERO of these, so the noise is hypothetical while the
  silence was measured.

The mitigation that keeps this from being noisy in practice is the restriction
to `loop`/`while`: an assertion about the system under test is nearly always
placed AFTER the loop (as `assert!(accepted <= 8, "bounded capacity held")` is,
at `rust/ws-core/tests/concurrency_boundary.rs:308`), where nothing reports it.

---

## 2. Historical proof

The pre-fix text of both guards was extracted verbatim from git and committed
as polarity fixtures, with the blob hashes recorded in
`cmd/fixtureguardctl/testdata/polarity.json`:

| fixture | git provenance | blob |
|---|---|---|
| `history/F004-pre-fix-concurrency_boundary.rs` | `rust/ws-core/tests/concurrency_boundary.rs` at `01ee515^` | `be153ca719d3d1866d8f44226e0f1f835db10e31` |
| `history/F005-pre-fix-concurrency.rs` | `rust/ws-driver/tests/concurrency.rs` at `57e881c^` | `fac0e1246dc3883bd5d4d7d85a0ff1b33bc5dc23` |
| `fixed/F004-post-fix-concurrency_boundary.rs` | same file at `01ee515` | `ab760daf849bcbf56a78865925fc751a24efa303` |
| `fixed/F005-post-fix-concurrency.rs` | same file at `57e881c` | `8ee52ee4290fa0a737706c945e6f229079a03f87` |

The two `fixed/` blobs are the same objects the live tree holds at this
branch's HEAD, so the negative control is the shipped code, not a paraphrase.

The manifest declares the EXACT findings each fixture must produce
(`line|shape|counter|bound|waived`), not a count and not a boolean — because a
boolean would stay green through the deletion of either shape while the other
kept firing.

Read from `go run ./cmd/fixtureguardctl -root .`:

```
case=history/F004-pre-fix-concurrency_boundary.rs expect=1 found=1 loops=6 result=OK
    fires line=280 shape=B1 counter=refusals_before_the_drop bound=4096 loop=loop@233 | refusals_before_the_drop < 4096,
case=history/F005-pre-fix-concurrency.rs expect=3 found=3 loops=12 result=OK
    fires line=69  shape=A counter=polls bound=POLL_BUDGET loop=while@69  | while applied.len() < TOTAL && polls < POLL_BUDGET {
    fires line=157 shape=A counter=polls bound=POLL_BUDGET loop=while@157 | while disposed < 20 && polls < POLL_BUDGET {
    fires line=182 shape=A counter=polls bound=POLL_BUDGET loop=while@182 | while drained_idle_passes < 3 && polls < POLL_BUDGET {
case=fixed/F004-post-fix-concurrency_boundary.rs expect=0 found=0 loops=6  result=OK
case=fixed/F005-post-fix-concurrency.rs         expect=0 found=0 loops=12 result=OK
case=legit/bounded_domain_constants.rs          expect=0 found=0 loops=6  result=OK
case=synthetic/silent_break_and_waiver.rs       expect=5 found=5 loops=5  result=OK
step=selfcheck cases=6 firing=3 silent=3 result=PASS
step=scan files=43 loops=209 violations=0 waivers=0 max_waivers=0
result=PASS  -> exit 0
```

It catches all THREE of F005's loops, not only the one whose assertion happened
to fail; F005 records that two siblings carried the same guard.

It fires on F005's line 157 (`while disposed < 20 && polls < POLL_BUDGET`) and
stays silent on the fix's line 174 (`while disposed < 20 && started.elapsed() <
POLL_DEADLINE`). That single pair is the whole discrimination: same file, same
loop, same `disposed < 20` goal conjunct, and the verdict turns only on the
second conjunct.

### The same proof at the gate, on the live tree

Copying the two pre-fix blobs over the live files and running the gate:

```
$ cp .../history/F005-pre-fix-concurrency.rs        rust/ws-driver/tests/concurrency.rs
$ cp .../history/F004-pre-fix-concurrency_boundary.rs rust/ws-core/tests/concurrency_boundary.rs
$ make -C rust fixture-guard
  ...
  VIOLATION file=rust/ws-core/tests/concurrency_boundary.rs line=280 shape=B1 counter=refusals_before_the_drop bound=4096
  VIOLATION file=rust/ws-driver/tests/concurrency.rs line=69  shape=A counter=polls bound=POLL_BUDGET
  VIOLATION file=rust/ws-driver/tests/concurrency.rs line=157 shape=A counter=polls bound=POLL_BUDGET
  VIOLATION file=rust/ws-driver/tests/concurrency.rs line=182 shape=A counter=polls bound=POLL_BUDGET
  step=scan files=43 loops=209 violations=4 waivers=0 max_waivers=0
  result=FAIL reason="4 count-shaped liveness guard(s) in test fixtures"
  make: *** [Makefile:43: fixture-guard] Error 1
MAKE_EXIT=2
```

(`Makefile:43` is the `go test` line: the test half fails first, on
`TestThisRepositoryIsClean`, and the VIOLATION lines above are that test's
captured output. Running the `go run` half alone on the same tree exits 1; see
the table below.)

Isolated process exit codes, read from `$?`:

| tree state | `go run ./cmd/fixtureguardctl -root .` |
|---|---|
| F005 pre-fix restored into `rust/ws-driver/tests/` | **1** |
| F005 fix restored | **0** |
| F004 pre-fix restored into `rust/ws-core/tests/` | **1** |
| F004 fix restored | **0** |

Both files were restored to their HEAD blobs afterwards; `git status --porcelain rust/`
shows only `M rust/Makefile` and `M rust/README.md`.

---

## 3. RED first, and the deletion attacks

Fourteen mutations, each removing exactly one part, each followed by reading
the exit code of BOTH halves of the gate from the process. A part that could be
deleted with everything still green would not be evidence; the first run of
this table found three such parts, and the detector was changed until none
remained.

| # | part deleted | `go run` exit | `go test` exit | verdict |
|---|---|---|---|---|
| A1 | shape A (header count conjunct) | 1 | 1 | RED |
| A2 | shape B1 via `assert!` | 1 | 1 | RED |
| A3 | shape B via bail-out `if` | 1 | 1 | RED |
| A4 | the unconditional-increment discriminator | 1 | 1 | RED |
| A5 | the comment/string masker | 1 | 1 | RED |
| A6 | the "only argument 0 of `assert!`" restriction | 1 | 1 | RED |
| A7 | the minimum-justification requirement on waivers | 1 | 1 | RED |
| A8 | the `for`-is-out-of-scope rule | 1 | 1 | RED |
| A9 | the refusal to PASS on an empty scan | 0 | 1 | RED (tests only) |
| A10 | the self-check call itself | 0 | 1 | RED (tests only) |
| A11 | the live-tree scan | 0 | 1 | RED (tests only) |
| A12 | exact-row comparison, keeping "did anything fire?" | 0 | 1 | RED (tests only) |
| A13 | the waiver ceiling | 0 | 1 | RED (tests only) |
| A14 | atomic `fetch_add`/`load` counter recognition | 1 | 1 | RED |
| — | no mutation (control) | 0 | 0 | GREEN |

**First run of this table, before the detector was strengthened:** A9, A10 and
A11 were **STILL GREEN — NOT EVIDENCE**, and A3 and A7 were red only under
`go test`. The manifest then declared a boolean (`must_fire`) rather than the
exact rows, and there were no end-to-end tests of `run()`. Three changes fixed
it: the manifest now declares exact rows (killing A12 and A3's blind spot),
`main_test.go` exercises `run()` against fabricated repository roots (killing
A9/A10/A11/A13), and the target runs `go test` as well as `go run`.

**Five of the fourteen are caught only by the `go test` half.** That is exactly
the failure mode this repository's own `ledger-gates` comment records — "every
census and observation-integrity rule this repository had lived only in
`_test.go` files which no release or readiness path executed" — so the
`fixture-guard` target runs both halves, and the Makefile says why.

The attack harness is not committed (it rewrites source in place); it is
reproducible from the table: each row names the single construct removed.

---

## 4. The escape hatch

`// FIXTURE-COUNT-GUARD-ALLOWED: <justification>` on the reported line or up to
three lines above it. Three properties:

1. **Explicit** — it names the class, at the site, in the diff.
2. **Justified** — under 20 characters of justification is NOT a waiver; the
   marker is reported as a violation with the reason. `// FIXTURE-COUNT-GUARD-ALLOWED: ok`
   does not silence anything (proved by attack A7 and `TestWaiverNeedsRealJustification`).
3. **Countable and capped** — every waiver is printed on its own `waiver` line,
   the total is printed as `waivers=N`, and the gate FAILS when `N` exceeds
   `-max-waivers`, which `rust/Makefile` sets to **0**. Adding a waiver
   therefore requires editing the Makefile in the same change, where a reviewer
   sees the number go up. A pile cannot grow quietly.

Current count in the tree: **0**.

---

## 5. Errors this rule makes, by name

### False negatives I know of (the silent direction)

1. **F002's own shape is not detected.** F002 was a flood sized to a host's
   socket buffer — a magnitude assumption, not a loop guard. Nothing here would
   have caught `48 x 64 KiB`. The class is broader than the mechanism; this
   tool binds the two thirds of it that cost red gates as loop guards.
2. **Production loops bounded by a count, driven by fixtures.**
   `rust/ws-testee/src/io_loop.rs:188` and `:685` are
   `while report.polls < bounds.max_polls`, and the fixtures in
   `rust/ws-testee/tests/loopback.rs` supply the bound: `max_polls: 50_000`
   (line 466), `4_000` (1177), `64` (753), `prompt_bounds(2_000)` (1418, 1526,
   1595), `prompt_bounds(250)` (1477). These ARE fixture liveness bounds
   written as counts, one level of indirection away, and the rule does not
   report them because it does not report configuration values — that exclusion
   is what keeps `max_frames(1024)` and `command_queue_capacity` quiet. See §6
   for why I judged them live-but-low-risk rather than defects, and did not
   change them.
   **CLOSED 2026-09-03 by `claude/adapter-residuals`: SHAPE C
   (`cmd/fixtureguardctl/budget.go`) reports a count-shaped value supplied by a
   fixture to a DECLARED production budget, whose anchor is re-verified against
   the tree on every run. The two roles `max_polls` serves are separated by
   reading what REACHING the bound means — the same move shape B1 makes — so
   the `max_polls: 0` / `: 1` budget tests stay silent and untouched. All nine
   live instances were converted to stated durations rather than waived; both
   waiver ceilings remain 0. See `drafts/self-review/adapter-residuals.md`.**
3. **A counter incremented at depth 0 after an early `continue`** is treated as
   unconditional (over-approximation towards firing) — but a counter
   incremented inside an `if` that always runs is treated as conditional, and
   Shape A will miss it.
4. **`assert_eq!`/`assert_ne!` forms** are not read; only `assert!` and
   `debug_assert!`. `assert_ne!(polls, BUDGET)` as a liveness guard would pass.
5. **A budget expressed as a non-literal, non-`SCREAMING_SNAKE` bound** —
   `polls < budget` where `budget` is a lowercase local — is not reported. The
   bound must look like a constant.
6. **A sleep-accumulating counter** (`slept_ms += 10; while slept_ms < 5000`)
   would be reported even though it is time-shaped: that is a false POSITIVE,
   listed here for completeness. None exists in the tree.
7. **Go, Java and shell fixtures are not scanned at all.** The class is not
   Rust-specific; the gate is.
8. **A waiver comment can reach three lines down.** The lookback exists so a
   marker can sit above a multi-line `assert!`; a second guard written within
   those three lines would be waived by the first one's justification. The
   waiver count would still go up, so the ceiling still catches it, but the
   printed `why=` would belong to the wrong guard.
9. **A nested loop's guard is attributed to the outermost enclosing loop.**
   Findings are deduplicated by the position of the comparison, and the first
   loop encountered wins the `loop=` field. The file and line of the guard
   itself are always right; only the enclosing-loop annotation can point at an
   outer loop.

### False positives I know of (the noisy direction)

1. **An in-loop assertion about the system under test whose bound is a count.**
   Shape B1 cannot tell it from a liveness guard. Chosen deliberately; §1.
2. **A counted `while` loop** — `while i < 10 { i += 1; ... }` — is reported as
   Shape A. Arguably correct guidance (that loop should be a `for`), but it is
   a report on something that is not the defect. None exists in the tree.
3. **`if counter >= N { break }` on an unconditionally incremented counter**
   where reaching N is genuinely the goal. Rare, because a goal counter is
   normally incremented on progress.
4. **Structural parsing, not a Rust parser.** The scanner masks comments,
   strings, raw strings and char literals and then matches braces. A macro body
   with unbalanced braces, or a loop header containing an unparenthesised
   struct literal (which Rust forbids), would confuse it. Observed behaviour on
   the real tree: 43 files, 209 loops, no parse bail-outs, 0 findings.

### Things the tool refuses to do quietly

* It FAILS if the scan matched zero files or zero loops (`TestRunRefusesAnEmptyScan`).
  A scanner that looked at nothing and printed PASS is theatre.
* It FAILS if the polarity manifest is missing, empty, unparseable, or declares
  only one polarity (`TestSelfcheckNeedsBothPolarities`).
* It FAILS if the observed rows differ from the declared rows in any direction
  (`TestSelfcheckFailsOnADriftedManifest`).
* Exit 2 is reserved for usage errors; exit 1 means the tree has the defect.

---

## 6. Further live instances of the class found in the tree

**None that this rule reports.** `files=43 loops=209 violations=0`.
(As of 2026-09-03 the rule reports SHAPE C too, and the reading is
`files=48 loops=296 violations=0 waivers=0 budget_waivers=0`; the candidate
below was found by it and then fixed rather than waived.)

One candidate found by hand and deliberately NOT flagged, recorded here so the
next person does not have to find it again:

**`rust/ws-testee/tests/loopback.rs` — fixture-supplied `max_polls`.**
`ws_testee::io_loop::drive_connection` is bounded by
`while report.polls < bounds.max_polls`, and the fixtures choose the bound.
The sharpest one is `stalled_peer_reader_trips_the_bounded_write_deadline`
(the F002 fixture, line ~440): `max_polls: 50_000` alongside
`write_stall_limit: Duration::from_millis(300)`, then
`assert_eq!(report.outcome, LoopOutcome::WriteStalled)`. A count of polls is
racing a 300 ms wall-clock deadline; if the count runs out first the outcome is
`BudgetExhausted` and the assertion fails with a host-speed message, exactly
the F004/F005 shape.

Why I judged it low-risk and left it alone: `read_timeout` is 2 ms there (1 ms
in `prompt_bounds`), so an idle poll costs about a millisecond of wall clock
and 50,000 polls is on the order of a hundred seconds — two orders of magnitude
above the 300 ms it is racing. The count is a soft deadline rather than a pure
host-speed measurement, and the failure direction is a host that is too FAST,
which is the opposite of the loaded-host direction that produced F004 and F005.
It has never gone red. Changing production `IoBounds` to carry a wall-clock
deadline is a real change to shipped adapter behaviour and belongs to whoever
owns `ws-testee`, not to a gate-adding branch.

I did not observe a new flake of this class during this work: the full
`make -C rust gates` run on this branch was green first time, with seven other
agents on the host.

---

## 7. What I did NOT do, by name

* **Did not detect F002's shape.** No check for a fixture that encodes a host
  resource's magnitude. §5.1.
* **Did not change `rust/ws-testee/tests/loopback.rs` or `IoBounds`.** §6.
* **Did not scan Go, Java or shell fixtures.** The class is not Rust-specific.
* **Did not amend `drafts/self-review/findings/F002`, `F004` or `F005`.** They
  are historical records and seven agents are working concurrently; F005's
  closing sentence ("nothing does that today") is now out of date, and the
  cross-reference belongs to whoever lands this. Flagged in the branch report.
* **Did not add a Rust-side lint or `syn`-based parser.** The workspace is
  dependency-free by policy, with an enumerated-unsafe review requirement on
  any new dependency; a Go scanner is the repo-incumbent idiom
  (`cmd/rustgatectl`, `cmd/deltaledgerctl`).
* **Did not touch `evidence/java/behavior-delta-ledger.json` or
  `internal/deltaledger`** (another track owns the ledger this wave).
* **Did not run any owner gate** — no AWS, no benchmark, no Autobahn.
* **Did not commit the deletion-attack harness.** It rewrites source in place;
  the table in §3 names each mutation precisely enough to reproduce.
* **Did not weaken or delete any existing test.** The two Rust fixtures used as
  controls are byte-identical to their HEAD blobs.

---

## 8. The detector does not contain the defect it hunts

`cmd/fixtureguardctl` waits on nothing: no threads, no clock, no I/O beyond
reading files. Every loop in it walks a finite string or a finite file list, so
none of them has a liveness guard of any kind, count-shaped or otherwise.

Two constants in it are counts and are stated here so nobody has to wonder:
`headerEnd` gives up after 4000 characters and `nextBrace` after 400, when
looking for the `{` that opens a block. Those are deterministic domain bounds
over a finite string — the same character count on every host, on every run —
and their effect when exceeded is to SKIP a construct, never to abort. They are
the legitimate kind: exactly `max_frames`, not `POLL_BUDGET`.

Its own budget knob, `-max-waivers`, is a policy ceiling on a committed count,
not a bound on anything the machine does.

---

## 9. Readings

All exit codes read from the process.

| command | exit |
|---|---|
| `make -C rust fmt-check` | **0** |
| `make -C rust fixture-guard` (clean tree) | **0** |
| `make -C rust fixture-guard` (F004+F005 pre-fix text restored) | **2** (`Error 1` from the tool) |
| `go run ./cmd/fixtureguardctl -root .` | **0** |
| `go test ./cmd/fixtureguardctl/` — 22 tests | **0** |
| `make -C rust gates` with `VJWP_PROTECTED_STORE` exported | **0** |

`make -C rust gates` detail: fmt-check and `clippy -D warnings` clean;
`fixture-liveness-guard result=PASS` with `files=43 loops=209 violations=0
waivers=0`; `cargo test --workspace --all-targets --all-features` and
`cargo test --workspace --release` both clean, **77** `test result: ok` blocks
and **0** FAILED — the same count `drafts/self-review/post-failure-landing.md`
records for mainline, so nothing was lost;
`ac1-gates verdict=PASS gates_passed=8/8`; `canaries verdict=PASS`
(polarity proven, good-scaffold 0/0/0, bad-scaffold 1/101);
`adapter-linkage verdict=PASS` over 5 production sources; ledger-gates `ok` on
all four lines (49 records, integrity verified, 6 governance digests recomputed
from the protected store).

Go suites outside this change were not run; `internal/lab` and `internal/portplan`
are known-failing baselines that this branch does not touch.
