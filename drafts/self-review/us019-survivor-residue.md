# US-019 survivor residue — the three unswept classes swept, 180 new sites, 75 closed, 15 proved unreachable, 16 still open

Recorded 2026-09-04 from tool output, on branch `claude/us019-survivor-residue`
in an isolated worktree at `/home/user/vjwp-surv`. Self-review by the loop, not
an independent review: **OWNER_ATTESTED_NOT_INDEPENDENT**.

The branch is mainline `claude/feature/verified-java-websocket-port` at `6986e95`
with `origin/claude/us019-survivor-closure-2` at `f9b9520` merged in (merge
`fe69b2c`, one conflict in `.gitignore`, resolved as a union). That merge is
necessary and it is also what makes this round's numbers comparable: `f9b9520`
is the exact head at which the 70-site floor was measured, and it carries both
the US-019 production code (which exists ONLY on `claude/us019-native-run`) and
round 4's closure probes. Sweeping without those probes would have inflated
every survivor count.

Nothing was merged or pushed to mainline. **No AWS run, no benchmark run and no
Autobahn re-run was taken.** `origin/codex/race-catchup` was neither read nor
written on this branch.

---

## 0. TWO HARD STOPS, REPORTED AND NOT RESOLVED

### 0.1 An independent enumeration of round 4's own site set finds 111, not 110

Round 4 reports **110** `if`-guarded sites across
`internal/autobahnsuite/{baseline,independence,reconcile,suite}.go`. A `go/ast`
enumeration of the same four files at the same head — every `*ast.IfStmt`
condition, `else if` included — finds **111**:

```
43  internal/autobahnsuite/baseline.go
16  internal/autobahnsuite/independence.go
27  internal/autobahnsuite/reconcile.go
25  internal/autobahnsuite/suite.go
--
111
```

**I did not resolve this and I did not re-baseline anything.** Round 4's
enumerator was `.sweep/mutate.py` in a worktree, and `.sweep/` is gitignored
(`f9b9520` added the ignore line), so the 110 cannot be re-derived from the
repository. Round 4's 110/70 stands exactly as it recorded it; this round's
numbers are a SEPARATE population and are never added to or subtracted from it.
The one-site difference is an owner/track item, not something a survivor sweep
should quietly decide.

### 0.2 This round moves a denominator by construction, upward, and says so

Round 4's denominator is 110 sites / 70 survivors over ONE site class in FOUR Go
files. This round adds 180 sites in three classes that round 4 declared unswept.
**Both denominators are reported side by side in §5. The new one is strictly
larger; it is not a correction of the old one, and nothing here shrinks or
redefines the old one.**

---

## 1. The scope boundary, and why it is the story's and not convenience's

Child US-019 is *"Pass both pinned Autobahn conformance modes"*, and its AC4 is
*"The same manifest proves the pinned Java baseline, empty/stub Rust negative
control, and planted protocol mutants discriminate as expected."* The in-scope
production surface is therefore the code the US-019 track ADDS to mainline, read
from `git diff --stat origin/claude/feature/verified-java-websocket-port HEAD`:

| path | status vs mainline |
| --- | --- |
| `internal/autobahnsuite/{baseline,independence,reconcile,suite}.go` | added |
| `cmd/autobahnsuitectl/main.go` | added |
| `rust/autobahn-controls/src/**.rs` | added |
| `rust/ws-testee/src/agent.rs` | added |
| `rust/ws-testee/src/{client,io_loop,lib,main,server}.rs` | modified |

Round 4's ceiling names three classes and, inside them, an exact scope: the four
`internal/autobahnsuite` files for switch arms and conjuncts, and
`rust/autobahn-controls/src` plus `rust/ws-testee/src/agent.rs` for "all
Rust-side checks". **I swept exactly that scope**, so the three classes this
round reports are the three classes round 4 named, at the same boundary. The two
surfaces in the table that round 4's ceiling does NOT name —
`cmd/autobahnsuitectl/main.go` and the five modified `ws-testee` files — stay
unswept and are enumerated in the new ceiling (§7) rather than quietly folded in.

**Nothing about this boundary shifts a denominator the project already reports.**
The 70-site floor is a count of `if`-guarded survivors in four Go files; nothing
here removes a site from it, and §0.1 is the one place where the old count is
questioned at all — reported, not resolved.

---

## 2. The three populations, derived

Every population below is enumerated by a program over the source, not counted
by hand and not estimated.

### 2.1 Class A — switch arms: **29**

Enumerated with `go/ast` over the four files: every `*ast.CaseClause` of every
`*ast.SwitchStmt` and `*ast.TypeSwitchStmt`, `default` included.

| file | arms |
| --- | ---: |
| `baseline.go` (5 switches) | 17 |
| `independence.go` (1 switch) | 2 |
| `reconcile.go` (2 switches) | 10 |
| `suite.go` (0 switches) | 0 |
| **total** | **29** |

`suite.go` contains no `switch` statement at all — that is a derivation, not an
omission.

### 2.2 Class B — all Rust-side checks: **84**

Enumerated over `rust/autobahn-controls/src/{cli,inert,lib,mutant}.rs`, the five
`src/bin/*.rs` control binaries, and `rust/ws-testee/src/agent.rs`, by a
comment- and string-aware lexical scan whose every hit was then read in source
and classified:

| kind | count |
| --- | ---: |
| `if` / `else if` conditions | 17 |
| `while` loop conditions | 1 |
| refutable `if let` | 2 |
| refutable `let ... else` | 6 |
| `match` arms (guards included) | 48 |
| `&&` / `\|\|` operands | 10 |
| **total** | **84** |

`lib.rs` and all five `src/bin/*.rs` contain **zero** decision points — they are
documentation, re-exports and a five-line `main` — which is why the population
is not larger. Rust conjuncts are counted HERE and not in Class C, so no site is
counted twice; Class C is the Go conjunct population.

### 2.3 Class C — conjuncts inside composite booleans: **67**

Enumerated with `go/ast` over the four files: for every maximal `&&`/`||`
expression tree, each LEAF operand is one site (so `A && B && C` is three).

| file | leaves |
| --- | ---: |
| `baseline.go` | 35 |
| `reconcile.go` | 26 |
| `suite.go` | 6 |
| `independence.go` | 0 |
| **total** | **67** |

`independence.go` contains no composite boolean expression. These 67 are NEW
mutants, not re-counts of round 4's 110: round 4 disabled whole `if`
conditions, and a conjunct is a strictly finer mutation of the same line.

---

## 3. The mutation operators, and the two ways a mutant can be no mutant

**Conjunct (Class C, and Class B's 10 Rust conjuncts).** A leaf under `&&`
becomes `(true || (LEAF))`; a leaf under `||` becomes `(false && (LEAF))`. The
whole replacement is parenthesised AND the leaf is parenthesised inside it, so a
top-level `||` cannot survive the rewrite — the trap that made round 3's naive
`false &&` prefix under-disable every such site. The form also keeps the leaf
syntactically present, so neutralising a conjunct that names a `:=`-bound
variable cannot produce a "declared and not used" build break and be mistaken
for a reading.

**Switch arm (Class A).** A tagless `case COND:` becomes `case false && (COND):`;
a tagless `default:` becomes `case false:`; a tagged `case K:` becomes an
unmatchable constant of the same type. The arm no longer fires and control falls
through exactly as if the arm were absent.

**Rust check (Class B).** `if COND` becomes `if false && (COND)`; `while COND`
likewise; a refutable `if let PAT = E` becomes `if let PAT = E && false` (edition
2024 let-chains, rustc 1.95.0); a `let PAT = E else` has its scrutinee replaced
by a value that cannot match, because the never-fire direction is not expressible
for a diverging `else` — that asymmetry is stated here rather than hidden. A
`match` arm is disabled with an `if false` guard where exhaustiveness survives,
and collapsed onto a sibling arm's outcome where it does not.

**Every edit is asserted onto its intended line.** The applier reads the target
line, requires the old text to occur on it EXACTLY once, rewrites, re-reads the
file from disk, asserts the target line changed and contains the new text, and
asserts that **no other line changed**. Any failure aborts that site as
`HARNESS_FAIL` rather than scoring it. Zero `HARNESS_FAIL` occurred in 355 site
applications. After every site the file is restored from a byte copy and its
sha256 is compared against the pre-mutation digest; a mismatch aborts the sweep.

**A mutation that does not compile is not a mutant.** Seven Class-B sites admit
no compiling arm-level mutation, and that is MEASURED, not asserted:

- `cli.rs:98,178,230,247,256` — `Ok(x) => x` on a two-arm `Result` match. Adding
  `if false` makes the match non-exhaustive: `error[E0004]: non-exhaustive
  patterns: 'Ok(_)' not covered`. There is no alternative value to collapse the
  arm onto (it yields the bound `TcpListener` / `CaseCountOutcome` / `Vec` /
  `ConnectionReport` itself).
- `mutant.rs:166,184` — the outer `Mutant::OpcodeSwap` / `Mutant::PayloadTruncate`
  arms of `on_event`, same `E0004`. Their whole body is an inner `match`, and all
  six of those inner arms ARE swept and all six are killed.

They are reported as **NON-MUTANT**, excluded from the scored denominator, and
never counted as kills. The same discipline caught one more: disabling
`reconcile.go:438`'s `default` arm by relabelling it produces
`internal/autobahnsuite/reconcile.go:441:1: missing return`, so that arm is
instead disabled by removing its entire observable contribution (its `Reason`
text; its `AsExpected` is already the zero value there). Both readings are from
the compiler, run deliberately, and both are in the transcript.

---

## 4. Results, class by class

Baselines were taken against the PRE-EXISTING suite; the closure sweeps were
taken with this branch's new probes in place. Adding a test can only increase
kills, so the closure sweeps re-ran the survivors rather than the whole
population, except in Go where the whole population was re-run anyway.

### 4.1 Class A — switch arms: 29 sites, 13 killed, 16 survived → 28 killed, 1 unreachable

| arm | line | baseline | after |
| --- | ---: | --- | --- |
| `baseline.go` 5 switches, 17 arms | 224-246, 303-323, 630-638, 674-679 | 7 killed, 10 survived | 17 killed |
| `independence.go` 1 switch, 2 arms | 135, 139 | 0 killed, 2 survived | 1 killed, 1 UNREACHABLE |
| `reconcile.go` 2 switches, 10 arms | 204-218, 377-439 | 6 killed, 4 survived | 10 killed |

**All 15 closable survivors are closed.** The one that is not:

**`independence.go:139` — `case !selected[family]:` — UNREACHABLE.** A case
identity reaches line 133 only by passing `caseIDGrammar` at line 123
(`^([1-7]|9|10|12|13)\.[0-9]+(?:\.[0-9]+)*$`), which `continue`s on failure. The
family it then computes is therefore one of `{1,2,3,4,5,6,7,9,10,12,13}.*`.
`internal/lab/autobahn.go:22-23` declares `selected = {1,2,3,4,5,6,7,10}.*` and
`excluded = {9,12,13}.*`, whose union is exactly that set. Every family that
reaches the switch is therefore either excluded (arm 135, which IS closed) or
selected, so `!selected[family]` cannot be true. It is a genuine third-case
guard for a drift between a regexp in this file and two lists in another
package, and no runtime input can distinguish the guarded from the unguarded
form. **RECOMMENDATION: keep it and say in the code that the grammar at 123 and
`lab.AutobahnFamilies()` are what make it unreachable**; a later reader will not
reconstruct that unaided, and it is exactly the pairing a future edit could
break.

The sharpest closure in this class: **`reconcile.go:377`, the
`SubjectUnderTest, SubjectJavaBaseline` arm of `Discriminate`, survived.**
Disabling it drops both subjects through to `default` and the whole literal AC3
verdict — the strongest statement this package can make about the real port —
comes back `as_expected=false, reason="unknown subject"` with nothing noticing.
`TestEveryDiscriminateSubjectArmIssuesItsOwnVerdict` now asserts the arm's own
reason text for both subjects, and the mutant/unknown arms alongside it.

### 4.2 Class C — conjuncts: 67 sites, 29 killed, 38 survived → 60 killed, 7 unreachable

**31 of the 38 survivors are closed.** The 7 that stay GREEN are exactly the 7
that were independently proved unreachable by reading the code **before** the
closure sweep ran — the sweep and the reading agree without either being fitted
to the other, which is the same agreement round 4 obtained on its 6.

| site | conjunct | why no input can distinguish it |
| --- | --- | --- |
| `baseline.go:176` | `!found` in `!found \|\| caseID == ""` | `strings.Cut(s, sep)` returns `(s, "", false)` when `sep` is absent, so `!found` IMPLIES `caseID == ""`. The second disjunct absorbs the first entirely. |
| `baseline.go:275` | `total == agreement.Expected` | `total` is the sum of the five class counters, and the loop at 219 increments EXACTLY one of them per manifest case (outer switch: `Unobserved`; its `default`: one of four in the inner switch). `Expected` is `len(manifest.Cases)`. The identity holds by construction of the walk that computes both sides. |
| `baseline.go:276` | `len(agreement.Cases) == agreement.Expected` | `agreement.Cases` is appended once per manifest case, unconditionally, at line 269. |
| `reconcile.go:307` | `scopeSum == ledger.Expected` | the walk at 191 takes exactly one of three exits per manifest case — `Filtered++`, `Missing++`, or `Executed++` — so `Filtered+Executed+Missing == len(manifest.Cases)` always. |
| `reconcile.go:308` | `classSum == ledger.Executed` | the switch at 203 has five cases and a `default` and is exhaustive over any string, so exactly one class counter increments per executed case. |
| `reconcile.go:320` | `ledger.Executed == ledger.Selected` (in `StrictPassAll`) | masked by the `Reconciles` conjunct one line above: `Reconciles` requires `Missing == 0` (line 313), and `Executed = Selected - Missing` from the walk above, so `Missing == 0` forces the equality. |
| `reconcile.go:322` | `ledger.StrictRequiredNotOK == 0` (in `StrictPassAll`) | masked by `Passed == Executed` one line above: `Passed` increments only in `case BehaviorOK`, so `Passed == Executed` means every executed case had behaviour `OK`, and line 223's `result.Behavior != BehaviorOK` can then never fire. |

The first five are **self-consistency assertions over a walk that establishes
them**, and the code says so itself (`reconcile.go:62-67`: *"The partition
identities are computed by that walk and are therefore self-consistent by
construction; this is an OUTSIDE observation…"*). That comment is correct, and
this sweep is the measurement behind it. **The two identities in the same
predicate that are NOT self-consistent — `len(UnexpectedCases) == 0` and
`IndexEntryCount == Executed + len(UnexpectedCases)` — were survivors and are
both now closed**, which is the useful half of the finding: the predicate's real
content is those two plus `Missing == 0` and `Disagreements == 0`, and the other
two cost a comparison to restate what the loop just did.

**RECOMMENDATION** for the five self-consistent ones: keep them as executable
documentation of the partition, but stop counting them as checks this suite
demonstrates. A reader counting "six conditions guard reconciliation" is
counting four.

### 4.3 Class B — Rust-side checks: 84 sites, 7 non-mutants, 77 scored; 25 killed, 52 survived → 54 killed, 23 open

**29 of the 52 survivors are closed.** The headline finding is not any single
site:

> **`rust/autobahn-controls/src/cli.rs` had no test at all.** It is the two-role
> entry point every control binary runs — the only code in the crate the
> Autobahn harness actually invokes — and all 36 of its enumerated sites
> survived, because no test file referenced `run_negative_control` or
> `run_mutant`. `manifest.rs`, `mutants.rs` and `negative_control.rs` test the
> LIBRARY the CLI calls, thoroughly; nothing tested the CLI.

A second, smaller one: `manifest.rs`'s identity check asserts that each
`Mutant::id()` is PRESENT in `manifest.json`, which is satisfied by two variants
returning the SAME id, or by two returning each other's. Three of the four
`deviation()` arms survived for the same reason. `cli_residue.rs` now binds each
arm to its own variant and requires the four to be distinct.

New Rust probes, all of them written to terminate rather than to hang:

| file | tests | closes |
| --- | ---: | --- |
| `rust/autobahn-controls/tests/cli_residue.rs` | 15 | the CLI's dispatch arms, argument guards, let-else bindings, setup-code propagation, the mutant identity/deviation/auto-response tables, and one real loopback client round trip |
| `rust/autobahn-controls/tests/inert_residue.rs` | 4 | the drain loop's EOF arm, its retryable-error arm, and BOTH of its bounding conjuncts |
| `rust/ws-testee/tests/agent_residue.rs` | 6 | `valid_agent_name`'s three conjuncts, the alphabet's two halves separately, and `run_one`'s own guard reached through `fetch_case_count` |

**A probe that hangs is not a kill, and this round measured that twice.** The
first version of the CLI probe used `0.0.0.0:0` as its non-loopback address; with
`cli.rs:57`'s loopback refusal neutralised the control BOUND that address and
blocked in `accept(2)`, stalling the sweep for ten minutes with no result. The
fixture now uses `192.0.2.1:9` (RFC 5737 TEST-NET-1, measured unbindable on this
host: `bind` → `EADDRNOTAVAIL`), so no mutation of that guard can leave a
listener waiting. The second was an acceptor thread waiting for eight
connections against a control that opens exactly `AGENT_PROTOCOL_ATTEMPTS` = 3.
Both are fixed in the fixtures, and the sweep runner now wraps `cargo test` in
`timeout --signal=KILL 420` and scores a timeout as **TIMEOUT**, never as
SURVIVED and never as KILLED.

---

## 5. BOTH DENOMINATORS, SIDE BY SIDE

These are two DIFFERENT populations measured by two different rounds. They are
printed together so the growth is visible; **they are never added, and the
right-hand column is not a correction of the left.**

| | round 4 (`us019-survivor-closure.md`, `f9b9520`) | this round |
| --- | ---: | ---: |
| site classes swept | 1 — `if`-guarded checks | 3 — switch arms, Rust checks, conjuncts |
| files in scope | 4 Go files | the same 4 Go files + 6 Rust files |
| **sites enumerated** | **110** | **180** |
| sites that admit no compiling mutant | 0 | 7 |
| **sites scored** | **110** | **173** |
| **survivors at baseline (the FLOOR)** | **70** | **106** |
| survivors closed by a named probe | 64 | 75 |
| survivors proved unreachable | 6 | 15 |
| survivors still open | 0 | 16 |

### The delta, broken down by class

| class | sites | non-mutants | scored | baseline survivors | closed | unreachable | still open |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| A — switch arms (Go, 4 files) | 29 | 0 | 29 | 16 | 15 | 1 | 0 |
| B — Rust-side checks (6 files) | 84 | 7 | 77 | 52 | 29 | 7 | 16 |
| C — conjuncts (Go, 4 files) | 67 | 0 | 67 | 38 | 31 | 7 | 0 |
| **this round** | **180** | **7** | **173** | **106** | **75** | **15** | **16** |
| round 4, for reference only | 110 | 0 | 110 | 70 | 64 | 6 | 0 |

**The honest reading: 70 was a floor, and this round shows by how much.** Sweeping
the three classes round 4 named produced 106 further survivors — more than the 70
it found — and 16 of them are still open, which round 4's `0 undecided` could not
have predicted for classes it never swept. The new floor is 106 and it is still a
floor (§7).

---

## 6. Every survivor still open, and its disposition

23 Class-B sites remain GREEN after the closure sweep. Class A and Class C have
none. Each is dispositioned; **none is unexplained.**

### 6.1 UNREACHABLE — 7 sites, with the construction that cannot exist

| site | check | proof |
| --- | --- | --- |
| `inert.rs:176` | `!peer.ip().is_loopback()` | the listener is bound by `cli.rs:56-73`, which refuses every non-loopback address; a listener bound to `127.0.0.1` can only be accepted from `127.0.0.1`. Every in-repo caller binds `127.0.0.1`. Reaching it requires binding a non-loopback listener, which the US-018 AC2/AC5 loopback-only contract forbids the suite from doing. Defence in depth for a caller that violates the contract. |
| `mutant.rs:277` | `!peer.ip().is_loopback()` | identical argument, identical call path. |
| `agent.rs:250` | `!valid_agent_name(fixture.agent)` in `run_case` | MASKED by `agent.rs:192`. After the guard, `run_case` calls `case_target` (a pure `format!`) then `run_one`, whose second statement is the SAME check returning the SAME `SetupOutcome::InvalidAgentName`. No observable differs. 192 IS discriminable and IS closed, by `fetch_case_count`, which carries no guard of its own. |
| `agent.rs:265` | `!valid_agent_name(fixture.agent)` in `update_reports` | identical argument through `reports_target`. |
| `cli.rs:69` | the early `return Err(EXIT_SETUP)` in the `local_addr()` error arm | `local_addr()` is `getsockname(2)` on a socket `TcpListener::bind` has just returned successfully. No input to this crate can make it fail. This proof rests on the OS contract rather than on repository code, and is labelled as such. |
| `cli.rs:114` | `EXIT_SETUP` in `negative_control_serve`'s `Err(setup)` arm | reached only when `serve_inert_sessions` returns `Err`, i.e. an `accept(2)` failure or a non-loopback peer — the same two constructions the loopback-only contract excludes. |
| `cli.rs:199` | `EXIT_SETUP` in `mutant_serve`'s `Err(setup)` arm | identical argument. |

### 6.2 OPEN, no owner gate — 10 sites, each with the probe it needs

| site | check | what a probe needs |
| --- | --- | --- |
| `cli.rs:57` | the loopback refusal itself | both the refusal and a failed bind return `EXIT_SETUP`; the only thing that separates them is the printed `setup=non-loopback-refused` line, which an in-process test cannot read. **Route: a subprocess probe** — `rust/ws-testee/tests/process.rs` already runs a built binary and reads its output, and the same shape reading `us019-negative-control`'s stdout closes this. |
| `cli.rs:66` | the `listening {bound}` line | same route, same reason: the line is the whole observable, and the harness waits on it. |
| `cli.rs:110` | `EXIT_OK` after a served session | a serve round trip needs the ephemeral port the CLI prints and does not return. The subprocess probe above supplies it: read the `listening` line, then connect. |
| `cli.rs:195` | `EXIT_OK` after a served mutant session | same, with a real `ws_core` client as the peer (the shape `mutants.rs` already uses). |
| `mutant.rs:287`, `mutant.rs:323`, `agent.rs:204` | `!handshake.opened` | a peer that never opens is easy (`negative_control.rs` builds one); the probe must then show that the `ConnectionReport` produced by continuing into `drive_connection_from` on an unopened connection DIFFERS from the one returned early. Not attempted this round. |
| `mutant.rs:318`, `agent.rs:199` | `if let Err(failure) = begin_client_handshake` | needs a target or host the driver rejects at handshake start, then an assertion that the report carries `LoopOutcome::ProtocolFailure`. Not attempted this round. |
| `inert.rs:130` | `Err(_) => break` | needs a NON-retryable read error. Route: a peer that sets `SO_LINGER 0` and closes, forcing `ECONNRESET`. Not attempted this round. |

### 6.3 OPEN, blocked on a live suite — 6 sites

`cli.rs:237` (`let Some(selected) = counted.count else`), `cli.rs:250`,
`cli.rs:259` (the `run_mutant_cases` / `mutant_update_reports` error arms) and
`cli.rs:276` with both of its conjuncts (`sweep.harness_faults() == 0`,
`sweep.reports_updated`) sit past step 1 of the mutant client pipeline: they are
reached only after a peer answers `/getCaseCount` with a usable count over a
completed WebSocket handshake.

**Two routes, and the loop may take neither on its own.** The first is a live
`wstest` run, which is `OA-autobahn-reruns` and an OWNER GATE this loop must not
trigger. The second needs no owner action at all: a hand-built fake suite in the
test — a `ws_driver` server with a custom `EventPolicy` that answers
`/getCaseCount` with a text frame carrying a count — which is a fixture, not a
conformance run. It was not built this round.

---

## 7. THE NEW CEILING — what is still unswept

**106 is a FLOOR, exactly as 70 was.** Three things bound it, and the first two
are enumerated rather than gestured at.

### 7.1 `cmd/autobahnsuitectl/main.go` — 74 sites, wholly unswept

Round 4's ceiling scoped its Rust class by file and its Go classes to four
files; this round kept that boundary rather than widening it silently. The CLI
that DRIVES those four files was in neither round:

| class | sites |
| --- | ---: |
| `if` conditions (`go/ast`) | 63 |
| switch arms (`go/ast`) | 7 |
| conjuncts (`go/ast`) | 4 |
| **total** | **74** |

### 7.2 The five modified `ws-testee` files — at least 185 decision points, unswept

`rust/ws-testee/src/{client,io_loop,lib,main,server}.rs` are MODIFIED by the
US-019 track (`io_loop.rs` by 205 lines, `main.rs` by 127) and were named by
neither ceiling. The same comment- and string-aware scan used for Class B counts
**50 `if`, 91 `match` arms, 4 `while`, and 19 `&&`/`||` operands** across them.
That is a lexical count, reported as a lower bound on the class rather than as a
derived population, because unlike Class B its hits were not each read and
classified.

### 7.3 What this round's operators cannot see

- **A multi-label `case` is disabled wholesale.** `reconcile.go:377` carries
  `SubjectUnderTest, SubjectJavaBaseline`; both labels were neutralised together,
  so a mutant that disables ONE of them was not tried. There are 1 such arm in
  Class A.
- **Only one direction per site.** A conjunct is neutralised, never inverted; an
  arm is disabled, never redirected to another arm. A check that fires on the
  wrong side of the right boundary survives every operator here.
- **A closed check is not a correct check.** A probe proves a check
  DISCRIMINATES. `TestTheNegativeControlExpectationIsConjunctByConjunct` proves
  each of the six negative-control conjuncts is load bearing; it does not prove
  that `broken == scoreable` is the right bar.
- **Statement- and value-level mutants were not attempted at all** — no
  off-by-one on a bound, no deleted statement, no swapped operand. Every
  operator here is a control-flow operator.
- **The Java leg was not taken.** No AWS run, no benchmark run and no Autobahn
  re-run. Every reading is a Go and Rust toolchain reading in this container.

---

## 8. Readings at this head

Every exit code below was read from the process that produced it.

| command | result |
| --- | --- |
| `go build ./...` | **exit 0** |
| `gofmt -l internal/autobahnsuite/ cmd/autobahnsuitectl/` | **exit 0**, no file listed |
| `go vet ./internal/autobahnsuite/ ./cmd/autobahnsuitectl/` | **exit 0** |
| `go test -count=1 -timeout 40m ./internal/autobahnsuite/ ./cmd/autobahnsuitectl/` | **exit 0** |
| `cargo fmt --all -- --check` | **exit 0** |
| `cargo test -p autobahn-controls -p ws-testee` | **exit 0**, 20 `test result: ok` |
| Class A sweep, 29 arms + 1 measured non-mutant probe | 13 RED, 16 GREEN, 1 build-break (deliberate) |
| Class A sweep with the new probes | 28 RED, 1 GREEN |
| Class C sweep, 67 conjuncts | 29 RED, 38 GREEN, 0 build-break |
| Class C sweep with the new probes | 60 RED, 7 GREEN |
| Class B sweep, 84 sites | 25 RED, 52 GREEN, 7 build-break (non-mutants) |
| Class B sweep with the new probes | 54 RED, 23 GREEN, 7 non-mutants |
| `df -h /` before believing any regression | 252G total, 7.0G available (81% used) — no reading here was taken on a full disk |

`make -C rust gates` is reported in §9.

---

## 9. Gates

Run with BOTH of the exports the gate needs:

```
export VJWP_PROTECTED_STORE=$PWD/evidence/governance/decisions
export PATH=/home/user/verified-java-websocket-port/.quarantine/jdk-17.0.19+10/bin:$PATH
make -C rust gates
```

The second export is not cosmetic and it is not a way around a check. The
container's default `javac` is **21.0.10**; the pinned laboratory JDK is
**17.0.19** and lives in the quarantine tree, verified here by running both
(`javac -version` → `javac 17.0.19` from that path, `javac 21.0.10` from
`PATH`). Without it `internal/portplan` fails `JAVAC_UNAVAILABLE`, which reads
like a broken pin and is not one. **Nothing about `PinnedJavacVersion`, the
version check in `internal/portplan/reproduce.go`, or the `go-suite` exclusion
list was touched** — retiring a real check to make an unrelated package green is
the exact substitution this record exists to refuse.

**`make -C rust gates` → EXIT 2.** It stops at `pin-guard`, and the failure is
NOT this branch's. Running the eleven targets individually gives the whole
picture rather than only the first stop:

| target | exit | whose |
| --- | ---: | --- |
| `fmt-check` | **0** | |
| `clippy` | **0** | |
| `fixture-guard` | **0** | `result=PASS files=59 loops=344 violations=0 waivers=0` |
| `record-guard` | **0** | `records=70 unfinished=0 superseded=1 finished=69` |
| `pin-guard` | **1** (chain exit **2**) | inherited — §9.1 |
| `plan-guard` | **0** | `nodes=33 done=16 ready=3 in_progress=2 blocked=12`, `result=PASS` |
| `go-suite` | **2** | inherited — §9.2 |
| `test` | **0** | `cargo test --workspace --all-targets --all-features` |
| `test-release` | **0** | |
| `ac1-gates` | **2** | inherited — §9.3 |
| `ledger-gates` | **0** | ran with `VJWP_PROTECTED_STORE` exported |
| `oracle-hierarchy-gates` | **0** | |

`ledger-gates` was NOT run without the store on this branch; the refusal it
would produce is a refusal, never a pass, and round 4 records that reading.

### 9.1 `pin-guard` — one drifted pin, arriving with the merge, measured

```
gate=pin-dangling json_artifacts=3500 unparsable=0 candidates=1 explained=53 covered=23 allowed=15 missing_targets=0
gate=pin-dangling artifact=evidence/formal/us023-coverage-report.json pointer=$.inputs[4]
  names=evidence/linkage/rust-identity-verification.json
  declared=sha256:afc0ef4f… actual=sha256:31a625e2…
```

Four readings, none inferred:

- `sha256sum evidence/linkage/rust-identity-verification.json` here → **31a625e2…**
- the same path at mainline `claude/feature/verified-java-websocket-port` →
  **afc0ef4f…**, which is exactly what the report pins. **Mainline is
  self-consistent and this gate passes there.**
- `git log -1 -- evidence/linkage/rust-identity-verification.json` → `6416805`,
  a `claude/us019-native-run` merge. That branch REGENERATED the file and did not
  refresh the pin.
- `git log -1 -- evidence/formal/us023-coverage-report.json` → `4ccf415`, a
  MAINLINE commit that fixed this very pin against mainline's copy of the file.

So the drift is created by merging `claude/us019-native-run`'s regenerated
artifact over mainline's refreshed pin. **This branch's commit touches six files
— a record, four test files and the task graph — and none of them is under
`evidence/`.** It is round 4 §4.3 and §4.4, unchanged, now firing because
mainline moved.

**NOT FIXED HERE, deliberately.** The remedy is regenerating derived US-023
artifacts, which is round 4's owner action 1 and belongs to
`claude/us019-native-run`'s own landing. The gate's own allowance text on the
neighbouring rows says `DENOMINATOR, HARD STOP … Never re-baseline`, and
re-pointing a digest from a survivor-sweep branch is the exact move this project
has paid to forbid.

### 9.2 `go-suite` — `internal/formalcoverage`, the same inherited cause

`internal/formalcoverage` fails four tests, all of them the retained-artifact
reconciliations (`TestRetainedReconciliationIsExactlyWhatTheDenominatorsDerive`,
`TestRetainedReportsAreExactlyWhatTheEvidenceDerives`,
`TestVerifyExitsZeroOnTheRetainedArtifacts`, `TestEveryAxisIsPrintedOnOneScreen`).
`assurance/formal/denominator-reconciliation.json` is byte-identical to mainline
on this branch (`git diff --stat` over that path is empty), and
`claude/us019-native-run` adds the `rust/autobahn-controls` crate to the Rust
workspace without refreshing it — round 4 §4.4 measured that the refresh changes
16 lines and moves NO denominator.

Two readings worth keeping from the same run, because they say the environment
was staged correctly rather than papered over:

- `internal/formalplan` — **ok, 344.088s**, with the `.quarantine` symlink in
  place.
- `internal/portplan` — **ok, 14.840s**, with the pinned JDK 17.0.19 on `PATH`.
  Without that export it fails `JAVAC_UNAVAILABLE` against the container's
  default `javac 21.0.10`, which reads like a broken pin and is not one.

### 9.3 `ac1-gates` — `adapter-linkage`, also inherited

```
gate=adapter-linkage finding=ADAPTER_PROTOCOL_BRANCH ws-testee/src/io_loop.rs:831 fn drive_until_open
gate=adapter-linkage finding=ADAPTER_PROTOCOL_BRANCH ws-testee/src/io_loop.rs:950 fn drive_until_open
gate=adapter-linkage finding=STALE_PROTOCOL_BRANCH_ALLOWANCE fingerprint 2c05c5aeae1c8921 matched no branch this run
ac1-gates verdict=FAIL gates_passed=7/8
```

`rust/ws-testee/src/io_loop.rs` differs from mainline by **167 insertions and 38
deletions**, all of them `claude/us019-native-run`'s, and `git log -1` on it
names that branch's merge `e8a9f06`. This branch adds no Rust production code at
all: its four new files are tests. The declared allowance's fingerprint no longer
matches because that branch moved the branch site, and the gate is doing exactly
what it exists to do. **Not fixed here for the same reason as §9.1** — F016 is
already an owner item about this gate's declarations, and re-fingerprinting an
allowance from a survivor sweep would retire a live architecture check.

### 9.4 The one thing this section must not be read as

Three gate failures, all three traced to `claude/us019-native-run` by a reading
of `git log` and a digest recomputation, are still THREE GATE FAILURES on this
branch's tree. `make -C rust gates` exits **2** here and this branch is not
landable on that basis alone, quite apart from the standing BLOCK on the US-019
work. Nothing in this round makes it landable and nothing here should be read as
saying so.

---

## 10. What a reader should NOT conclude

- **Not that US-019's code is now covered.** Three site classes in six files
  gained probes. `cmd/autobahnsuitectl` (74 sites) and five modified `ws-testee`
  files are unswept, 16 survivors are open, and the operators are control-flow
  only (§7).
- **Not that 106 replaces 70.** They are different populations from different
  rounds over different site classes. §5 prints both because neither is the
  other's correction.
- **Not that the 111-vs-110 question is settled.** It is reported (§0.1) and
  left to the owner; round 4's enumerator is not in the repository.
- **Not that this branch is landable.** The BLOCK from independent review
  `01a04961` on the US-019 work is untouched, `T-us019-ac4` is still incomplete
  at 66/247 and 181/247, and finding 7's pinned-archive HTTP 403 is unchanged.
- **Not that the Java or Autobahn legs were taken.** They were not.

## 11. Owner actions this round leaves

1. **Decide the 111-vs-110 site count** (§0.1). Round 4's `.sweep/mutate.py` is
   gitignored; either it is committed so the 110 can be re-derived, or the 110 is
   restated as the count that particular enumerator produced.
2. **On `claude/us019-native-run`, refresh the derived US-023 artifacts.** Round
   4 named this and it is now failing TWO gates rather than one: `pin-guard`
   (§9.1) and `go-suite`/`internal/formalcoverage` (§9.2). With
   `VJWP_PROTECTED_STORE` exported, `go run ./cmd/formalcoverctl reconcile -repo .`
   then `go run ./cmd/formalcoverctl report -repo .`, and commit what they
   rewrite. Round 4 measured that it moves no denominator. It is that branch's to
   apply, not a survivor sweep's.
3. **On `claude/us019-native-run`, re-declare the adapter-linkage allowance for
   `ws-testee/src/io_loop.rs` `drive_until_open`** (§9.3). That branch moved the
   branch site; the allowance fingerprint `2c05c5aeae1c8921` matches nothing and
   two sites are now undeclared. This is F016 territory and a declaration
   decision, not a sweep's to make.
4. **`OA-autobahn-reruns` still gates 6 of the 16 open survivors** (§6.3) —
   unless the fake-suite fixture route is taken, which needs no owner action.
5. **Unchanged from round 4:** the four unreachable-check dispositions in its
   §3.1-3.4, and `OA-autobahn-archive`.
