# Self-review round 3 — claude/us019-native-run: the fifth forward merge, a full deletion sweep, and the answer on landability

Recorded 2026-09-03 by the goal loop from tool output, on branch head `8c91f9d`
after forward-merging mainline `4a2b9c6`. Self-review by the loop, not an
independent review: **OWNER_ATTESTED_NOT_INDEPENDENT**.

Rounds 1 and 2 closed the amended AC3 bar and narrowed review finding 7. This
round does the three things the queue entry still needed: the forward merge,
a deletion sweep over **everything this branch adds** rather than a summary of
the earlier rounds, and a decision on the `#[allow(clippy::too_many_arguments)]`
residual.

**The answer on landability is NO, and the reasons are below.** Nothing in this
round changes the BLOCK from independent review `01a04961`.

---

## 1. The forward merge

`git merge origin/claude/feature/verified-java-websocket-port` reported three
conflicted files. It also produced **two collisions git did not report**, one of
which did not compile and one of which failed a gate. Both are recorded because
a merge that only lists what git listed is not a merge that was read.

### 1.1 The reported conflict in `rust/ws-testee/src/io_loop.rs` — resolved as a union

The signature and body of `drive_connection_from` are **byte-identical** on both
sides. Only prose differed, plus one `match` arm. The union keeps mainline's
`pending_chunk.is_empty()` witness paragraph (div05), this branch's
`HandshakeOutcome::carryover` and role paragraphs, and both eight-parameter
justifications merged into one.

The one genuine behavioural fork was the `match step.input` arm. This branch
dropped the chunk on `InputDisposition::Rejected(_)` — which is what the merge
base did — and mainline retains and re-offers it. **Neither can be told apart by
any test, because the arm is unreachable**: `ws_driver` builds `Rejected` only in
`reject_pending_eof_overflow` (reached from `Shutdown` and `TransportEof`) and in
the `InvalidWriteProgress` guard (`WriteProgress`), never for `Inbound`, and this
arm is inside the `DriverInput::Inbound(&chunk)` branch. Mainline's grouping was
taken and the unreachability is now stated in the code. **Claim: observed**, from
reading the producer sites; it is not proved by a test and cannot be, which is
the point of saying so.

### 1.2 Unreported collision 1 — the merged tree did not compile

Mainline's new div05 fixture `rust/ws-testee/tests/close_overtakes_echo.rs`
calls `drive_until_open(...)` in two `assert!`s expecting `bool`; this branch
changed that function to return `HandshakeOutcome` so the handshake-phase
carryover is not lost. Textual merge took both.

```
error[E0600]: cannot apply unary operator `!` to type `ws_testee::HandshakeOutcome`
  --> ws-testee/tests/close_overtakes_echo.rs:427:5 and 467:5
```

Both call sites adapted to `.opened`. Neither assertion was relaxed.

Worth recording for whoever fixes the underlying thing: mainline's fixture
carries a doc comment describing, as a "DIFFERENT and unfixed defect", the case
where a burst coalesces with the 101 into the handshake read and the message is
lost. **That is the defect this branch's `HandshakeOutcome::carryover` exists to
address.** The two tracks converged from opposite directions and neither cites
the other. I did not rewrite mainline's comment, and I did not verify that the
carryover path fully closes what the comment describes — that is a claim I have
not measured and am not making.

### 1.3 Unreported collision 2 — `fixture-guard` went red on a merge whose two sides were each green

Mainline landed shape C (a fixture supplying a count into a production loop
bound) on `claude/adapter-residuals`; this branch supplies four such counts.

```
gate=fixture-liveness-guard result=FAIL reason="4 count-shaped liveness guard(s) in test fixtures"
  rust/autobahn-controls/tests/mutants.rs:51          max_polls 20_000
  rust/autobahn-controls/tests/negative_control.rs:45 max_polls  4_000
  rust/ws-testee/tests/autobahn_agent.rs:222          max_polls 20_000
  rust/ws-testee/tests/autobahn_agent.rs:241          max_polls  2_000
```

Every one is the **LIVENESS** role, not the SUBJECT role, and each fixture's own
doc comment says so in its own words ("a larger budget than any probe, so the
probe is always the side that hangs up first"). That is F005's sentence exactly.

**The gate was not weakened and no waiver was taken.** All four now state the
wall-clock window they always meant and convert it through `read_timeout`, using
the same `polls_for` helper mainline's `loopback.rs` adopted for this shape. The
resulting counts are **identical by construction**, so no fixture's behaviour
moved: 40s/2ms = 20 000, 2s/1ms = 2 000, 8s/2ms = 4 000. The orderings those
fixtures depend on are now orderings of durations rather than of two chosen
magnitudes.

One observation about the remedy, since this round is supposed to be honest
about the instruments it uses: shape C is silent on `max_polls: polls_for(...)`
because the detector's `boundRe` matches only numeric literals and
SCREAMING_CASE constants. **The gate cannot distinguish a helper that genuinely
derives a count from a duration from one that returns a magnitude.** The four
helpers here do derive it, and that is checkable by reading them; the gate does
not check it. Recorded, not fixed.

### 1.4 The two generated linkage artifacts — regenerated, not pinned

Digest and line-number conflicts only. Taking mainline's side outright is
refused by the regenerator ("story node US-019 missing"), the same refusal round
1 recorded, and this round measured why: **mainline's DAG holds 174 nodes and
this branch's 196**, the 22-node difference being the US-019 evidence nodes plus
`ws_testee::agent::*`, `io_loop::HandshakeOutcome` and
`io_loop::drive_connection_from`.

Resolved through the sanctioned path, both exits read from the process:

```
LINKAGE_REGENERATE=1 go test -run TestRegenerateLinkageArtifacts ./internal/linkage/   exit 0
go test ./internal/linkage/                                                            exit 0
```

Delta measured against the branch's pre-merge head: **196 nodes before, 196
after — no node added, none removed**; 11 sha256 values, 6 line numbers, and one
title (mainline's schedule-exploration figure, 81180/2 scenarios → 92160/3,
which is mainline's own and is now carried).

---

## 2. The clippy allow on `drive_connection_from` — **KEPT**, and why

The residual list carried this as mine to decide. The decision is to keep it,
and the first reason is the one that settles it:

**Mainline already made the same decision on the same function.** Commit
`eedbef7` ("io_loop: state the eight-parameter seam rather than reshape it, and
refreeze"), landed via `claude/adapter-residuals` at `131b7b8`, puts
`#[allow(clippy::too_many_arguments)]` on `drive_connection_from` with a written
justification. Two tracks reached it independently. Restructuring now would mean
this branch unilaterally reverting a landed mainline decision from another
track, which is not a US-019 branch's call.

The second reason is measured rather than asserted: **a grouping struct
relocates the seam, it does not narrow it.** The same eight values must still be
supplied at every call site; `clippy::too_many_arguments` simply stops looking.
And on *this* branch `ws_testee::io_loop::drive_connection_from` and
`ws_testee::io_loop::HandshakeOutcome` are **pinned linkage nodes** (verified
above: both are among the 22 nodes mainline lacks), so a new public type adds
nodes to `evidence/linkage` on a branch already under BLOCK.

**Where I disagree with both existing justifications, mainline's included.**
They say a struct "would have to carry `role`" and that "a struct with a
`Default` would hand that back". A struct with **no** `Default` keeps every
field mandatory at construction, so that argument bounds the risk rather than
settling the question. The merged comment now says exactly that, and names the
two reasons that do settle it. I strengthened the reasoning; I did not weaken
the conclusion.

**Claim: observed.** The seam is stated, not measured to be minimal.

---

## 3. The deletion sweep

The measurement of this round. Every `if`-guarded check the branch adds to
`internal/autobahnsuite` was disabled one at a time with `false &&` — never by
removing code, because **a mutation that breaks compilation proves nothing** —
and the suite re-run after each.

| Outcome | Count |
| --- | --- |
| RED — something went red | 25 |
| **GREEN — survived deletion, nothing noticed** | **52** |
| BUILD-BREAK — proves nothing, counted separately | 8 |
| Total sites swept | 85 |

The 8 build-breaks are `if x, ok := m[k]; ok`-shaped sites where `false &&` does
not compile. They are **not** claimed as discriminated.

### 3.1 The sweep's own ceiling

Stated because it bounds the 52. The sweep covers **`if`-guarded checks only, in
four files**. The `switch` arms inside `VerifyRegisterIsExact` — the stale-entry
and class-mismatch arms round 1 worked on — are not `if` lines and were never
swept here. Nor were the Rust-side checks in `rust/autobahn-controls/src` and
`rust/ws-testee/src/agent.rs`, which this branch also adds. **85 is not "every
check on this branch"**; it is every check of one shape in four files, and the
52 is a floor on the survivors, not a total.

### 3.2 A second pass before believing the 52

The first sweep ran only `./internal/autobahnsuite/` and `./internal/linkage/`.
`cmd/autobahnsuitectl` also consumes this package and has five tests the sweep
never ran. Calling a check undiscriminated on that evidence would have been
round 1's finding-4 mistake in mirror image — a probe that was not isolated,
except pointing the other way. All 52 survivors were re-run with
`./cmd/autobahnsuitectl/` included: **52 still green, 0 rescued.**

### 3.3 What was closed — seven checks, eight probes

Each probe isolates ONE check by asserting on the disagreement **text** rather
than on a count. The count is what made the existing coverage non-isolating:
`TestAnIndexPairedWithAnotherRunsCasesDoesNotReconcile` pairs a clean index with
the negative control's cases and asserts only `Disagreements != 0`, which
whichever check fires first satisfies. Every fixture is a real committed
Autobahn report with one field rewritten, and
`TestTheUnmutatedCasesDirectoryReconciles` is the polarity control that stops
the other probes from measuring the copier.

RED reading, every one taken after the probe existed, exits read from the
process:

| Check deleted | Verdict | Exit | Probe that went red |
| --- | --- | --- | --- |
| `reconcile.go:231` index vs per-case-report behaviour | RED | 1 | `TestTheIndexAndItsPerCaseReportMustAgreeOnBehavior` |
| `reconcile.go:236` report filed under another agent | RED | 1 | `TestAPerCaseReportFiledUnderAnotherAgentIsRefused` |
| `reconcile.go:179` index entry naming NO reportfile | RED | 1 | `TestAnIndexEntryThatNamesNoReportfileIsReportedAsSuch` |
| `reconcile.go:184` reportfile that is not present | RED | 1 | `TestTheIndexReportfileMustNameAFileThatIsActuallyThere` |
| `reconcile.go:262` a scored case the manifest lacks | RED | 1 | `TestACaseTheIndexScoresButTheManifestDoesNotKnowIsReported` |
| `baseline.go:689` the MISSING-entry direction | RED | 1 | `TestTheMissingRegisterEntryDirectionIsIsolated` (also reds the role probe, which shares the arm) |
| `baseline.go:668` the register's role filter | RED | 1 | `TestTheRegisterRoleFilterIsLoadBearing` |

### 3.4 Two findings against the earlier rounds

**Finding A — round 1's "exact in both directions" was exact in one.** Round 1
records the divergence register as exact in both directions. The stale direction
is isolated, because round 1 found it green and fixed it. The **missing**
direction was not: the nearest test rewrites the single entry's `CaseID` to
`1.1.1`, which makes 5.15 unregistered **and** 1.1.1 stale at once, then asserts
only that the problem list is non-empty — so the stale arm satisfies it, and
deleting the missing arm stayed green. It is the same non-isolation round 1
diagnosed, in the mirror direction, one file over. Now isolated with an **empty**
register (nothing can be stale) plus a check that every problem produced is the
missing-entry message.

**Finding B — the register's role filter was accepted by nothing.** With
`entry.Role != agreement.Role` deleted, a register whose entries are all filed
against the SERVER role still accounted for the CLIENT run's divergences, and
every test in the tree stayed green. The role is part of what an entry claims to
have observed.

### 3.5 A finding against my own round-3 work

Kept in the test file rather than quietly fixed. My first probe for the
index-to-file binding renames the case files, which leaves every `reportfile`
value non-empty — so it exercises `!presentFiles[...]` and never reaches
`entry.ReportFile == ""`. **Measured: with that probe in place, deleting the
empty-reportfile arm stayed GREEN.** The two arms are not independent (blanking
a reportfile makes the second arm true as well), so a count-based probe cannot
separate them and only the message text can. A second probe was added and the
RED reading in §3.3 is the re-measurement.

### 3.6 What is NOT closed — 45 of the 52 survivors

Recorded rather than fixed, in three classes:

- **Defensive nil/empty guards on inputs no caller supplies (~12)** —
  `manifest == nil`, `register == nil`, `ledger == nil`, `agreement == nil`,
  `len(sources) == 0`. Deleting them turns an error return into a panic on input
  nothing produces. Real, low severity, undiscriminated.
- **Whole-feature control-flow selectors (~16)** — `casesDir != ""`,
  `filtered[entry.CaseID]`, the `maxDetail` cap, `subjectRan`/`baselineRan`, the
  `!ok` arms. Disabling one skips a feature wholesale and no test notices.
- **Checks carrying a claim that no probe reaches (~17)** — `len(byAgent) != 1`,
  `len(entries) != len(reports)`, `len(cases) != SelectedCaseCount`,
  `document.ExpectedCaseCount != len(manifest.Cases)`, and the rest.

One deserves naming. **`independence.go:108`** is the cross-source count check
that round 2's record presents as making "a drift between two independently
sourced numbers fail rather than silently agreeing". Both operands —
`lab.AutobahnSelectedCaseCount` and `autobahnsuite.SelectedCaseCount` — are
untyped compile-time constants equal to 247, so **no runtime test can make them
differ**. The check is structurally untestable by a deletion sweep, and nothing
binds it. That is not the same as vacuous, and this record says which it is
rather than letting round 2's sentence stand unqualified.

*Correction to the round-3 commit message:* it says 44 survivors remain open.
The arithmetic is 52 − 7 = **45**. This record is the correct figure.

---

## 4. Finding 7 — still NARROWED, NOT CLOSED, and the residual is still the real one

`TestTheResidualOfFinding7IsMeasuredNotClaimed` **passes at this head**
(exit 0), which means the gap it asserts is still open. Three things were
checked rather than assumed:

1. **The bindings did not move.** The merge changed `internal/lab/evidence.go`
   and `ledger.go`, but `internal/lab/autobahn.go` and
   `autobahn_controller.go` — which hold `AutobahnSelectedCaseCount`, the family
   policy, the case-identity grammar and the archive digest — are unchanged, and
   `internal/autobahnsuite/independence.go` and `evidence/autobahn/` are
   byte-identical to the pre-merge head.
2. **The check is not vacuous.** In the sweep, nine of `independence.go`'s
   constraint sites went RED under deletion (lines 113, 123, 128, 162, 171, 180,
   189, 194, 205). A function that refused nothing would have shown those green.
   The residual test and those nine bracket the check from both sides.
3. **Both routes to closing it are still shut, verified in this container, not
   repeated from the earlier record.**
   - The pinned archive URL answers **HTTP 403** (`curl` measured:
     `HTTP=403 SIZE=378`).
   - The `git cat-file` + `git archive` route that works for the pinned *Java*
     source **does not apply here**: `source-pins.json` gives the Autobahn
     provenance as `commit 6ed6f439… tree 7ac651d1…`, and both objects are
     absent from this repository (`git cat-file -t`, exit 128 for each). They
     belong to a third-party repository this session does not have.

So the residual is unchanged and still measured: `7.9.6` rewritten to `7.9.997`
satisfies every constraint this tree can apply.

**Owner action, unchanged:** make the pinned Autobahn source archive available in
the quarantine. No new code is needed — `ParsePinnedAutobahnRegistryArchive`
already exists.

---

## 5. Two defects inherited from mainline, neither this branch's to fix

### 5.1 `internal/formalcoverage` and `cmd/formalcoverctl` are RED on mainline

The declared baseline failures are `internal/lab`, `internal/portplan` and
`internal/formalplan`. The full suite at this head fails **five** packages: those
three plus `internal/formalcoverage` and `cmd/formalcoverctl`, with **35
failures all citing the same cause**:

```
formalcoverage: the plane-correspondence record does not check out
  websocket_driver::ConnectionOwner::poll/NEAREST_DECLARATION_IS_AT_THE_LINE_IT_CITES:
  rust/ws-driver/src/lib.rs:756 reads "/// Result of one bounded owner transition.",
  the record says "    pub fn poll<'owner>(&'owner mut self, input: DriverInput<'_>) -> PollResult<'owner> {"
```

**This is not caused by the merge.** `rust/ws-driver/src/lib.rs`,
`assurance/formal/plane-correspondence.json`, `internal/formalcoverage/` and
`cmd/formalcoverctl/` are all **byte-identical to mainline** on this branch, and
the mismatch is provable from mainline's own bytes: on
`origin/claude/feature/verified-java-websocket-port`, line 756 of
`rust/ws-driver/src/lib.rs` is the doc comment quoted above, and
`pub fn poll<'owner>` is at **line 1003**.

`claude/catalog-plane-correspondence` (`f8c748d`) recorded the line; `div05`
(`755b8c8`, merged at `4a2b9c6`) then added 426 lines to `ws-driver` and moved
it. Two mainline tracks landed in an order that invalidated one's evidence, and
nothing caught it because they never ran together until this merge.

**Owner/mainline action:** refresh `assurance/formal/plane-correspondence.json`
against current mainline. Doing it from this branch would mean editing another
track's artifact on a branch under BLOCK, so it is recorded, not done.

### 5.2 `.quarantine` is a tracked, self-referential symlink

Mainline commit `f1b98a4` tracks `.quarantine` as a symlink to the absolute path
`/home/user/verified-java-websocket-port/.quarantine` — which, in the main
worktree, **points at itself**. That is why `.quarantine/` is empty in this
container and why the pinned Java inputs are not present. `.gitignore` already
ignores `.quarantine/`, and the commit's message says "The diff is FIVE digest
lines and nothing else" without mentioning it.

Carried through this merge rather than reverted, because diverging from mainline
over an unrelated accidental artifact is not this branch's call. **Owner/mainline
action:** untrack it.

---

## 6. Readings at this head

All exits read from the process.

| Command | Result |
| --- | --- |
| `cargo fmt --check` (from `rust/`) | exit 0 |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | exit 0 |
| `make -C rust fixture-guard` | exit 0, PASS, `files=56 loops=331 violations=0 waivers=0 budget_waivers=0` |
| `make -C rust gates` | exit 0, `ac1-gates gates_passed=8/8`, 9 `verdict=PASS`, 110 `test result: ok`, 0 failed |
| `go test ./internal/autobahnsuite/ ./internal/linkage/ ./cmd/autobahnsuitectl/` | exit 0 |
| `go test ./... -timeout 40m` | 39 packages ok; 5 FAIL (3 declared baseline + the 2 mainline defects in §5.1) |
| `LINKAGE_REGENERATE=1 go test -run TestRegenerateLinkageArtifacts ./internal/linkage/` | exit 0 |
| `go test ./internal/linkage/` (verify) | exit 0 |

### The differential and the exam — re-run, and why they had to be

`rust/ws-driver/src/lib.rs` gained 426 lines in this merge, and
**`ws-oracle-harness` depends on `ws-driver`** (`rust/ws-oracle-harness/Cargo.toml`).
The byte-identity argument the `adapter-residuals` landing used does **not**
apply here, so both were re-run rather than carried.

| Reading | Result |
| --- | --- |
| Public tier, port | **74 of 74**, exit 0, 0 failed / 0 missing / 0 unmatched |
| Handshake exam, port, runtime neutralised | **49 of 49**, exit 0, the same 16 documented divergences |

Harness `sha256:1872e26c44a3d22998eeda3d9fe2e09e69ca96912a23318cfed86b79f96bc12c`,
built from the pinned toolchain (`rustc 1.95.0`) inside `rust/`. Neither reading
moved, which independently confirms div05's claim that `InboundFeedPolicy`'s
`WholeChunk` default keeps the two harness call sites at their previous
behaviour.

**Both figures are CASE counts and must never be quoted without their measured
ceilings** (`evidence/normalization-collisions/audit.json`): the 74 cases carry
**73** distinct scored observations and the 49 carry **26**.

**The live-Java leg was NOT taken and must not be inferred.** The pinned
JDK 17.0.19 is gone from this container and only OpenJDK 21 is on `PATH`
(`openjdk version "21.0.10"`), and `.quarantine` is the broken symlink of §5.2,
so the pinned jars are absent. Any Java reading takeable here would not be a
pinned-baseline reading. None was taken.

---

## 7. Is this branch landable? **No.**

What is closed: the amended AC3 bar (round 1), finding 7 narrowed with its
residual measured (round 2), the clippy residual decided (§2), the merge
resolved with both silent collisions found and the shape-C gate satisfied
without weakening it (§1), and seven undiscriminated checks given isolating
probes with RED readings (§3).

What still blocks it, none of which this session may act on:

1. **Review `01a04961` still stands.** This is round 3 of a self-review by the
   loop; it is `OWNER_ATTESTED_NOT_INDEPENDENT` and cannot lift an independent
   review's BLOCK.
2. **AC1's bounded-resources clause is unmet.** The native run read
   `memory.max` and `cpu.max` as unbounded. **Owner gate: a new AWS host.**
3. **AC4's mutant discrimination is OUTSTANDING** for the no-echo (66 of 247
   scored) and opcode-swap (181 of 247 scored) runs. **Owner gate: Autobahn
   re-runs.** Not triggered.
4. **Child US-009 AC1 requires the complete Rust gate replayed in the Docker
   sbx profile before US-019 acceptance.** sbx is the verified macOS profile;
   this is a Linux cloud session. **Owner gate.**
5. **Finding 7 is narrowed, not closed** (§4). **Owner gate: the pinned Autobahn
   archive in the quarantine.**
6. **45 checks this branch adds survive deletion** (§3.6), and the sweep's own
   ceiling means that is a floor, not a total.
7. **Mainline is red in two packages** (§5.1), so a green full suite is not
   currently reachable from this branch by any work done on this branch.

---

## 8. What I did NOT do, by name

- Did not run Autobahn, AWS or benchmarks. No owner gate was triggered.
- Did not take a live-Java reading, and did not present the OpenJDK 21 on this
  host as a pinned baseline.
- Did not fix `assurance/formal/plane-correspondence.json` (§5.1) or untrack
  `.quarantine` (§5.2); both are mainline artifacts from other tracks.
- Did not sweep the `switch`-arm checks, nor any Rust-side check in
  `rust/autobahn-controls/src` or `rust/ws-testee/src/agent.rs`. The 52 is a
  floor.
- Did not close the remaining 45 survivors.
- Did not verify that this branch's `carryover` mechanism fully closes the
  defect mainline's div05 fixture describes (§1.2); the two tracks converged and
  I measured neither against the other.
- Did not restructure `drive_connection_from`, and did not weaken, waive or
  re-baseline any existing check to make this branch pass.
- Did not merge to mainline or push anything but `claude/us019-native-run`.
