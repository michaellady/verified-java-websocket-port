# Two named residuals, closed — and one of them was not closable the way it was written down

branch: `claude/adapter-residuals`, from mainline `claude/feature/verified-java-websocket-port` at `58f3aa4`
date: 2026-09-03
scope: `rust/ws-testee/src/io_loop.rs` (+43/-4), `rust/ws-testee/tests/loopback.rs` (+236), `cmd/fixtureguardctl/*` (new `budget.go`, `budget_test.go`, one polarity fixture), `rust/Makefile`, `evidence/linkage/*` (refrozen digests only).
`ws-core`, `ws-driver` and `ws-oracle-harness` are **byte-identical to `58f3aa4`** — `git diff --stat 58f3aa4 HEAD` over the three is empty.

Both residuals were named by the work that created them rather than hidden, and
both are now bound by a check that has been proved able to fail.

---

## Residual 1 — `pending_chunk.is_empty()` had no failing witness

`drafts/self-review/server-close-parity-round-1.md`, attack A5: the third
operand of

```rust
if server_closes_transport(role, driver.state()) && !eof_seen && pending_chunk.is_empty() {
```

was deleted and the whole `ws-testee` suite stayed green — 4 + 22 + 8 passed,
exit 0.

### The first finding is why no witness existed, and it is structural

I did not go looking for a fixture that happened to work. I read the loop and
established that on mainline **the operand cannot be reached through
`drive_connection`'s own entry point at all**:

1. `pending_chunk` is filled in exactly one place, `stream.read`.
2. That read is reached only on the drained `Idle` path — *after* the role
   gate. On such a turn a SERVER already in `Closing` has hung up one statement
   earlier, so no read happens once the gate is armed.
3. So any pending bytes must predate the transition into `Closing`. But every
   route into `Closing` while a chunk is pending is either
   - the chunk itself, and `ConnectionCore::handle_bytes` consumes a chunk
     whole or refuses it whole, so consumption *empties* `pending_chunk`; or
   - a producer command, and a held command is applied on the preceding `Wake`
     turn (`DriverInput::Wake if self.held.is_some()`), which is the very turn
     that did the read.
4. `InputDisposition::Deferred` is the only disposition that keeps the chunk,
   and of the four deferral reasons only `Backpressure` can coincide with an
   `Idle` output: `OutputPending` implies a `Write`/`Failure`/`WritesDropped`
   output, `pending_eofs > 0` implies `eof_seen` is already true in the
   adapter, and `CommandTurn` applies a command, and every command either emits
   a write, emits an event, or is lifted into `pending_failure` by
   `finish_poll`.

**So A5 could not have gone red on this branch's entry points, whatever fixture
was written.** That is not the same fact as "the line is unnecessary", and it is
the fact the round-1 record was one step away from.

### The entry point that reaches it, and why it is not invented for the test

`drive_connection_from(.., carryover: Vec<u8>)`, with `drive_connection`
delegating to it with `Vec::new()` so no existing call site changes behaviour.
A peer may pipeline its first frames into the same TCP segment as the
handshake response — the Autobahn fuzzing server answers `/getCaseCount` with
the 101, the case-count text frame and a close frame back to back — leaving the
caller holding message-phase bytes no later socket read will return. This is the
shape `claude/us019-native-run` derived independently for the same reason
(`HandshakeOutcome::carryover` + `drive_connection_from` there). **Correction to
the brief: neither exists on mainline `58f3aa4`; `drive_until_open` returns
`bool` and drops the remainder. That is a second, separate defect, and this
branch does not fix it — see "What I did NOT do".**

### The witness

`a_server_must_not_hang_up_on_bytes_the_driver_has_not_taken_yet`
(`rust/ws-testee/tests/loopback.rs`). A SERVER driver in `InitialState::Closing`,
handed 21 pipelined masked PING frames as carryover.

The number 21 is **derived, not tuned**: `handle_bytes` runs an atomicity
precheck before it mutates anything, refusing the whole chunk unless the event
queue can hold `1 + EVENT_SLOTS_PER_FRAME*spans + CLOSE_ECHO_EVENT_SLOTS` =
`3 + 3*spans` records. At the default `event_queue_capacity` of 64 that is
satisfied to 20 frames (63) and refused from 21 (66), as **non-fatal**
backpressure — so the adapter keeps the identical bytes and retries them, which
is precisely the state the operand exists to notice.

Its control, `a_server_in_closing_hangs_up_once_the_driver_has_taken_every_inbound_byte`,
is the same fixture with an empty carryover.

### RED readings, exit codes read from the process

| mutation of `rust/ws-testee/src/io_loop.rs` | `cargo test -p ws-testee` | reading |
|---|---|---|
| none (control) | **exit 0** — 4 + 28 + 8 passed | |
| **A5** — operand removed: `server_closes_transport(role, driver.state()) && !eof_seen` | **exit 101**, 27 passed / **1 failed** | the witness |
| **A5b** — carryover dropped (`pending_chunk = Vec::new()`) | **exit 101**, 27 passed / 1 failed | the witness |
| **A1'** — whole gate disabled | **exit 101**, 24 passed / **4 failed** | the control + the three shipped server tests |
| restored | **exit 0** — 4 + 28 + 8 passed | `io_loop.rs` sha256 `1926916e…` at that point |

The A5 failure message, read from the run:

```
REGRESSION: the adapter hung up while the driver was still holding 126 deferred
inbound byte(s); ... report: outcome=ProtocolFailure(TypedProtocolFailure {
code: StateViolation, close_code: None }) texts=0 binaries=0 pings=0 pongs=0
close=1006:transport terminals=0
```

That is the whole mechanism visible in one line: without the operand the
adapter shuts the socket down both ways and pumps `TransportEof`, which carries
the core to `Closed`; the loop then re-offers the identical bytes it correctly
never dropped, and `handle_bytes` answers `closed + nonzero payload` with the
quirk-Q26 STATE VIOLATION. The A5b failure reads `outcome=Terminal … terminals=1`
— i.e. with the carryover gone the fixture degenerates into its own control,
which is what makes the carryover load-bearing rather than decorative.

**A1' passes the witness and fails the control; A5 fails the witness and passes
the control.** The two tests pin different things and neither is redundant.

### One thing the witness asserts that deserves stating plainly

Its green outcome is `BudgetExhausted`. That is honest, not a fudge: at this
event-queue capacity the chunk is *permanently* unconsumable, so the correct
behaviour is to keep offering the bytes and end by spending the budget, and the
peer never sees EOF. It also means the fixture is documenting a real
adapter-level livelock shape for a peer that pipelines more than 20 frames into
one segment. **That is a finding this branch does not fix**, and it is filed
below rather than folded into the test's rationale.

---

## Residual 2 — the fixture detector's named blind spot, which was a real instance

`drafts/self-review/fixture-liveness-guard-detector.md` §5.2 and §6, and F005's
bin note: `rust/ws-testee/tests/loopback.rs` supplies `max_polls` into the
PRODUCTION loop bound `while report.polls < bounds.max_polls`, so a fixture's
own liveness guard is a count of operations one indirection away from anything
the detector looked at.

### SHAPE C

`cmd/fixtureguardctl/budget.go`. A count-shaped value supplied by a fixture to
a **declared** production budget is reported. The declaration is data:

```go
{Field: "max_polls",
 Anchor: "rust/ws-testee/src/io_loop.rs",
 LoopText: "while report.polls < bounds.max_polls",
 Outcome: "BudgetExhausted"}
```

`verifyBudgetAnchors` re-reads the anchor on **every run** and fails the gate if
the loop condition or the outcome token is gone. A rule that reaches across a
file boundary has to prove the far end still exists, or it becomes a rule about
nothing while still printing PASS. `gate=… step=budget-anchors budgets=1
result=OK` is that proof, printed each run.

Forwarders (`prompt_bounds(2_000)`) are found by the **assignment the helper
makes**, not by its parameter's name, so a rename does not dodge the rule, and
arguments are matched by **position**.

### The two roles, and how they are told apart

`max_polls` is spelled identically in both:

| | shape | reaching the bound is |
|---|---|---|
| LIVENESS | `max_polls: 50_000` beside `write_stall_limit: 300ms`, then `assert_eq!(outcome, WriteStalled)` | a FAILURE with a host-speed message |
| SUBJECT | `max_polls: 0` / `: 1`, then `assert_eq!(outcome, BudgetExhausted)` | the ASSERTED RESULT |

The discriminator is the move shape B1 already makes — **read what reaching the
bound means.** B1 fires on an in-loop `assert!` because reaching it is a failure
by construction; shape C stays silent when the enclosing function names the
budget's own exhaustion outcome, because reaching it is then the expected result
by construction. **Nothing thresholds the value.** `max_polls: 64` is reported
in one test and `max_polls: 0` is silent in another, and the number is not what
decides. `TestTheDiscriminatorIsTheAssertedOutcome` is two fixtures differing in
one assertion, and the verdict turns only on it.

The four budget-mechanism tests were reported as guards on the first run of this
rule, and that was a defect in my code, not a hard case: `findFns` started its
brace search *after* the regex match, which had consumed the opening `(`, so no
parameter list balanced, so no function body was ever found, so no supply site
had an enclosing function. Fixed and commented at the site.

### The nine live instances: converted, not waived

The rule found nine, all in `loopback.rs`. None is waived. `polls_for(deadline,
read_timeout)` states the **wall-clock window** the bound buys and converts it
through the one cost a waiting poll actually pays. Every resulting number is
unchanged from the tree's values — 50_000 = 100 s at 2 ms, 2_000 = 2 s at 1 ms,
20_000 = 20 s at 1 ms — so this is a change of derivation, not of behaviour.
What it removes is the chosen magnitude, and one concrete bug with it: the F002
fixture's 50_000 would have silently become **1.6 seconds** of window if its
`read_timeout` had ever moved to 32 µs, while the 300 ms deadline it races
stayed put. F005's `POLL_BUDGET` was **2,000,000** and still lost its race,
which is why "the margin is generous" is not an argument this program may still
make.

`prompt_bounds` now takes a `Duration`. The tests whose SUBJECT is the budget
keep their inline counts and are untouched: `max_polls: 0` (×2), `max_polls: 1`,
`prompt_bounds(250)` in `a_client_does_not_close_the_tcp_connection_after_its_close_echo`
(which asserts `BudgetExhausted` — its budget IS its observation window), and
residual 1's new witness.

### Ceilings

Shape-C waivers are counted on their **own** ceiling, `-max-budget-waivers`, set
to 0 in `rust/Makefile` beside `-max-waivers 0`. Separate numbers on purpose:
admitting a backlog on the shape that reaches across an indirection must never
be able to raise the ceiling on the shapes F004 and F005 actually cost red gates
for. Current reading: `waivers=0 max_waivers=0 budget_waivers=0
max_budget_waivers=0`.

### Deletion attacks on shape C

Eight mutations, each removing exactly one part, each followed by reading the
exit code of BOTH halves of the gate from the process. **`go vet` was run first
on every mutation and passed on all eight — none of these is a mutation that
merely broke compilation.**

| # | part deleted | `go run` exit | `go test` exit | verdict |
|---|---|---|---|---|
| — | none (control) | 0 | 0 | GREEN |
| C1 | shape C removed from `scanFile` | 1 | 1 | RED |
| C2 | the two-role discriminator | 1 | 1 | RED |
| C3 | forwarder following | 1 | 1 | RED |
| C4 | the renamed-parameter path (name-keyed only) | 1 | 1 | RED |
| C5 | the forwarded ARGUMENT POSITION (always read arg 0) | 0 | 1 | RED (tests only) |
| C6 | the production-anchor verification | 0 | 1 | RED (tests only) |
| C7 | shape C's separate waiver ceiling | 0 | 1 | RED (tests only) |
| C8 | one fixture's chosen magnitude restored | 1 | 1 | RED |
| — | control after restore | 0 | 0 | GREEN |

Three of the eight are caught only by the `go test` half — the same proportion
the original fourteen showed, and the same reason the `fixture-guard` target
runs both halves. The attack driver is not committed (it rewrites source in
place); each row names the single construct removed precisely enough to redo.

### Polarity control

`cmd/fixtureguardctl/testdata/synthetic/production_budget_roles.rs`, declared
row-exactly in `polarity.json` and pinned again in `budget_test.go`:

```
fires  line=19  shape=C counter=max_polls bound=50_000   (a count racing a 300ms deadline)
fires  line=69  shape=C counter=max_polls bound=2_000    (through a forwarder)
fires  line=75  shape=C counter=max_polls bound=250      (through a RENAMED forwarder parameter)
waived line=89  shape=C counter=max_polls bound=8        (justified: counted, not reported)
fires  line=100 shape=C counter=max_polls bound=9        (unjustified marker: not a waiver)
```

Silent in the same file, which is the half that matters: a supply from a test
that asserts `BudgetExhausted`, a budget derived from a stated duration (the
remedy — a detector that condemns its own fix teaches people to disable it), and
prose quoting the defect.

---

## Readings, all exit codes read from the process

- `cargo test -p ws-testee` — **exit 0**: 4 (lib) + 28 (loopback) + 8 (process).
- `go test ./cmd/fixtureguardctl/` — **exit 0**.
- `go run ./cmd/fixtureguardctl -root .` — **exit 0**,
  `step=selfcheck cases=7 firing=4 silent=3 result=PASS`,
  `step=budget-anchors budgets=1 result=OK`,
  `step=scan files=48 loops=296 violations=0 waivers=0 max_waivers=0 budget_waivers=0 max_budget_waivers=0`.
- `make -C rust fixture-guard` — **exit 0**.
- `make -C rust gates` (store exported) — **exit 0** after one honest red: the
  first run came back **exit 2** on clippy,
  `error: this function has too many arguments (8/7) --> ws-testee/src/io_loop.rs:211:1`.
  Resolved with a narrow `#[allow(clippy::too_many_arguments)]` **on that one
  function**, with the reason at the site: the alternative is a grouping struct,
  and it would have to carry `role` — the one parameter the role-gated transport
  close made mandatory and positional so no call site could acquire the
  behaviour by omission. A struct with a `Default` hands that back. **This is a
  lint suppression I added, and it is named here rather than left for a reader
  to find.**
  Final reading: **87 `test result: ok` blocks, 0 failed**,
  `ac1-gates verdict=PASS gates_passed=8/8`, `gate=adapter-linkage verdict=PASS`
  over 5 production sources, `gate=fixture-liveness-guard result=PASS`, ledger
  integrity verified (56 records, frozen prefix through sequence 35,
  `unledgered_disagreements` recomputed = 0).

### Corpus differential and handshake exam, re-run because `rust/ws-testee/src` changed

Throwaway 32-byte hex protected root; public and handshake tiers only, which the
generator derives from the committed public seed and which do not consume the
secret. **Not a custodian-ledgered run**; no hidden or sealed tier was generated
or scored.

- handshake request digest
  `sha256:e00d968f0ae623dd75a09842ad435642c0dca53ee5e9f9ef654ce26c1f814c49`
  — **equal to the batch-B receipt. No corpus shift.**
  Public request digest `sha256:0c1503c043172d0962f44aca068d57cac5588b9d933669e5221a11b880c72d85`.
- **port**: public **74/74**, `evaluate` exit 0, 0 failed / 0 missing / 0
  unmatched. Handshake **49/49**, exit 0, with the **16 documented divergences**
  (hs.0013–0017, 0019–0022, 0027, 0029, 0030, 0034, 0046–0048). The raw
  transcript fails all 49 on the runtime pin by design, exit 1; the
  neutralisation touched the runtime field only — **49 records, 0 non-runtime
  fields moved, 0 remaining `ws-oracle-harness` mentions**.
- **live pinned Java** (`.quarantine/jdk-17.0.19+10`, `-Dsun.stdout.encoding=UTF-8`;
  jar sha256 `eae29213…` verified against the intake digest): `java-oracle`
  self-test **PASS 18**; public **74/74** exit 0; handshake **49/49** exit 0
  with the same 16 divergences. **Identical to the recorded baseline. No shift.**
- The exam and differential were taken before the clippy `allow` was added, and
  cannot have moved after it: `ws-oracle-harness` declares only `ws-core` and
  `ws-driver`, `cargo build --release -p ws-oracle-harness --locked` reported
  `Finished` with nothing to do, and the harness digest is unchanged at
  `sha256:a470eadd0170c3c28d04a6b516ccb6ded061b7353868ea199322ed0b30e31623`.
  **That digest is NOT the `e2898c13…` in the server-close-parity record and
  nothing is wrong**: a release binary embeds its build path and this is a
  worktree at a different absolute path. The claim that matters is source
  identity, and `git diff --stat 58f3aa4 HEAD` over `ws-core`, `ws-driver` and
  `ws-oracle-harness` is empty.

### Linkage

Refrozen **twice**, once per `io_loop.rs` edit, through the sanctioned path
(`LINKAGE_REGENERATE=1 go test -run TestRegenerateLinkageArtifacts
./internal/linkage/`, exit 0 both times), then verified (`go test
./internal/linkage/`, exit 0 both times). Before the first refreeze the
verification failed exactly as it must — `LINKAGE_VERIFICATION_DRIFTED`,
`LINKAGE_DAG_DRIFTED`, and two stale-digest rows — which is the reading that
proves the freeze is load-bearing.

The diff is **five digest lines and nothing else**, all of them `io_loop.rs`'s
new sha256 `72c30cf13d350de5d73978df31080ca6a66605c42cef82bc56ecf0c7e38fb847`,
checked against `sha256sum` of the real file. **No line number moved** —
`drive_connection`'s declaration is still line 171, because the new entry point
was added after it — no declaration text changed, no symbol lost a binding, no
verification flag flipped.

---

## Findings kept rather than folded away

**F-A. `drive_until_open` drops pipelined message-phase bytes on mainline.**
The brief states that `drive_until_open` returns a `HandshakeOutcome` carrying
`carryover`. On `58f3aa4` it returns `bool`, and any bytes its final read took
past the end of the handshake response are discarded. That is a real defect on
the Autobahn path and it is NOT fixed here: this branch adds the *entry point*
that can accept a carryover, and leaves the handshake side to
`claude/us019-native-run`, which has already rewritten that function. Fixing it
here would have meant rewriting the file that track is rewriting.

**F-B. A peer that pipelines more than 20 frames into one TCP segment livelocks
the adapter.** At the default `event_queue_capacity` of 64, `handle_bytes`'
atomicity precheck needs `3 + 3*spans` slots, so a 21-frame chunk is refused
*permanently* — the retry can never succeed, because nothing consumes and the
bound never falls. The loop then spends its whole budget re-offering the same
bytes and ends `BudgetExhausted`. Residual 1's witness is built on exactly this
shape, so the branch DEPENDS on the behaviour while disclosing it. It is not a
regression (it is reachable on `58f3aa4` through any pipelining peer) and it is
not this unit's to fix: the fix is either a larger event queue by default or a
partial-consumption protocol between core and adapter, and `us019-native-run`
has already built the second one (`InputDisposition::Consumed { bytes } if bytes
< chunk.len()`). Filed for whoever lands that.

**F-C. Shape C is silent on a budget derived by any helper, not only by
`polls_for`.** The rule reports a chosen magnitude; it cannot tell a principled
derivation from a laundering one. Mitigation: `polls_for` is a single reviewed
helper and the anchor check keeps the far end honest. Stated as a known false
negative, in the same register as §5's list.

**F-D. The `WriteProgress` acknowledgement discards a drained output.** In
`drive_connection`'s `Write` arm the `ack` poll's output is inspected only for
`Failure`; an `Event` drained there is neither recorded in the report nor
offered to the policy. I noticed this while tracing the gate and did not touch
it — it predates this branch and changing it moves observable adapter
accounting. Named so it is not rediscovered.

---

## What I did NOT do, by name

- **Did not fix `drive_until_open`'s dropped carryover** (F-A). The entry point
  to consume one now exists; the handshake side is untouched.
- **Did not fix the >20-frame pipelining livelock** (F-B), and the new witness
  depends on it.
- **Did not change `IoBounds` or add a wall-clock deadline to the production
  loop.** It is the remedy F005's sentence points at, and I judged it the wrong
  trade: a wall-clock abort inside a shipped adapter loop is itself a magnitude
  sized to a host, so it would move the defect rather than remove it. The
  fixtures state durations; production keeps its deterministic count. Stated
  because §6 of the detector record left this decision to whoever owns
  `ws-testee`, and this unit is the first to touch it and declined.
- **Did not touch `ws-core`, `ws-driver` or `ws-oracle-harness`.** Byte-identical
  to `58f3aa4`; another track owns `ws-core` close paths this wave.
- **Did not append to `evidence/java/behavior-delta-ledger.json`.** The gate
  reads 56 records; nothing here is a Java-behaviour disagreement.
- **Did not run any owner gate** — no AWS, no benchmark, no Autobahn.
- **Did not re-baseline anything.** The differential and exam readings match the
  recorded ones exactly; had they not, that would have been a hard stop.
- **Did not scan Go, Java or shell fixtures for shape C.** `max_polls` is the
  only declared budget; the table takes a second entry as data, not code.
- **Did not run the Go suite on pristine mainline myself.** I compared the
  failing set against the baseline the brief names rather than re-measuring it;
  the comparison is recorded below and any package outside that set would be a
  hard stop.
- **Did not commit the deletion-attack driver.** It rewrites source in place;
  the two tables above name each mutation.
- **Did not weaken or relax any existing test.** The `max_polls: 0` / `: 1`
  budget-exhaustion tests are byte-identical. Two existing assertions were
  UPDATED, not relaxed: `TestRunAlwaysRunsTheSelfcheck`'s pinned
  `cases=6 firing=3 silent=3` became `cases=7 firing=4 silent=3` (a new polarity
  case exists), and `summary()` in `scan_test.go` no longer fails a fixture with
  zero loops **if** it names a declared production budget — a shape-C fixture
  has no loops in it, and the guard's purpose ("the scanner found nothing to
  look at") is preserved by the added condition rather than dropped.
