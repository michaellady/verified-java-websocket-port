# F016 — the protocol-branch half of US-018 AC1, built and attacked

STATUS: COMPLETE for what it claims. Every exit code below was read from the
process, not from a log line that said PASS. Every seeded probe was restored
byte-identically and the restore proved with `sha256sum -c` and
`git diff --quiet -- rust/`.

Worked in an isolated worktree, `/home/user/vjwp-f016`, on branch
`claude/f016-protocol-branch-gate`, from mainline `6a155a3`.

## The defect, reproduced before it was fixed

`docs/prd-pack/07b-child-prd-us009-us019.md:118`, US-018 AC1's third bullet:

> a seeded adapter-side parser or **protocol branch** fails the architecture
> gate.

`cmd/rustgatectl/adapter_linkage.go` delivered on "parser" and not on "protocol
branch". `forbiddenProtocolBranch` was thirteen parser-shaped patterns —
opcode and payload-length bitmasks and three wire literals. Nothing in it
looked at protocol STATE.

The second half of the reason is the one F016 asked me to handle:
`forbiddenProtocolSurface` is keyed on MODULE PATHS (`ws_core::close`,
`ws_core::framing`), while `Role` and `ReadyState` reach the adapter as ROOT
RE-EXPORTS — `pub use connection::{... ReadyState, Role}` at
`rust/ws-core/src/lib.rs:72-75`, imported at `rust/ws-testee/src/io_loop.rs:14`
as `use ws_core::{... ReadyState, Role ...}`. No module prefix can ever match
that spelling, so the surface list could not see the types even in principle.

I reproduced the F016 probe first. The same `match (role, state)` seeded into
`rust/ws-testee/src/io_loop.rs` above `fn retryable`:

```
gate=adapter-linkage verdict=PASS detail="adapter linkage exact over 5 production
  sources; edges exact; no protocol surface or parser branch"
ac1-gates verdict=PASS gates_passed=1/1                          exit 0
```

Byte-identical to the clean-tree reading. **The gate asserted in its own detail
string that there was no protocol branch while one sat in the file it had just
scanned.** That is the RED baseline, and it is inverted: the gate passes where
it must fail.

The probe is real code, not a compilation break: `cargo check -p ws-testee
--all-targets` exited 0 on it, with one `dead_code` warning and nothing else.
A mutation that does not compile proves nothing, so that reading matters.

Logs: `.f016-logs/baseline-clean.out`, `.f016-logs/red-probe-before-fix.out`,
`.f016-logs/red-probe-cargocheck.out` (worktree-local; the exit code of each is
in the sibling `.exit` file, written by the run).

## What the detector does

The forbidden thing is BRANCHING on protocol state, not TOUCHING it. The
adapter legitimately hands a `Role` to the driver constructor, stores one in a
report struct, and prints one. None of those decide anything.

So a finding requires a governed value in a DECISION POSITION. The rules, each
with its typed name in the gate output:

| rule | fires on |
|---|---|
| `variant-in-pattern` | a match arm pattern, an `if let`/`while let` pattern, a `matches!` pattern |
| `variant-in-equality` | an operand of `==` `!=` `<` `>` `<=` `>=` |
| `variant-in-comparison-call` | an operand of `.eq(` `.ne(` `.cmp(` `.contains(` … on either side |
| `variant-in-condition` | named in an `if`/`while` condition or a scrutinee, not as a call argument |
| `governed-binding-in-condition` | a governed-TYPED binding named in a condition or scrutinee |

and NOT on a value position: an argument, an initializer, a struct field value,
a return expression, a format argument. Passing a `Role` through, storing one
and printing one all stay legal, and each of those is a committed fixture in
`TestLegitimateAdapterUseOfProtocolTypesIsNotFlagged`.

The last rule exists because the first four only see a value whose VARIANT is
spelled out. `if s as u8 == 2` and `match r.wire_name() { "server" => .. }`
decide from protocol state while naming no variant at all; both name the
governed BINDING in a condition.

## Everything re-derives

Today's adversarial round defeated three same-day gates with one shared flaw:
each checked that a DECLARATION was well formed and never that its CLAIM was
still true. The two mechanisms that survived re-derive. Three things re-derive
here, on every run:

1. **The governed vocabulary.** `deriveGovernedEnums` reads the ws-core sources
   and extracts every `pub enum` with its variants, plus `pub type` aliases of
   one. 27 enums on this tree, printed on the gate's note line. Renaming `Role`,
   or adding a state enum beside it, changes what the gate governs with nobody
   updating a constant. An empty derived vocabulary FAILS CLOSED as
   `PROTOCOL_VOCABULARY_EMPTY` — a detector that has quietly stopped seeing any
   protocol type is indistinguishable from a clean tree, which is exactly the
   failure F016 recorded.
2. **The names the adapter can reach them by.** `buildAdapterVocabulary` parses
   the adapter's own `use` trees, so root re-exports, `as` aliases
   (`use ws_core::ReadyState as RS`), variant imports
   (`use ws_core::ReadyState::Closing`), renamed variant imports (`Open as O`)
   and `::*` globs all resolve rather than being guessed. This is what closes the
   root-re-export gap: what the adapter can branch on is exactly what the
   adapter can NAME, so the names are read off the imports instead of assumed.
3. **Whether each declaration is still true.** Every allowance is re-matched
   against a fingerprint recomputed from the current source, and the number of
   distinct functions it covers is recounted.

The declared event seam re-derives too. `SemanticEventKind` is exempt because
reacting to a drained event is the adapter's declared job — `io_loop.rs`'s own
module doc: "message-level policy (echo, scripted sends, close initiation) is
injected as an adapter policy over the drained events". That exemption fails as
`STALE_PROTOCOL_SEAM` if the enum it names stops existing in ws-core, so it
cannot outlive the type it exempts.

## The declared instances — there are two, not one

The owner ruled that `server_closes_transport` stays and the gate is fixed. On
its first run over the real tree the detector found a SECOND true instance the
F016 probe never reached. Both are declared in
`cmd/rustgatectl/protocol_branch.go`:

| site | rule | ruling |
|---|---|---|
| `rust/ws-testee/src/io_loop.rs:567` `fn server_closes_transport` | `variant-in-equality` on `Role::Server` and `ReadyState::Closing` | **OWNER RULING (F016)**: stays. Which endpoint hangs up is transport policy; the Sans-I/O core owns no socket, and Java's own answer lives in `WebSocketImpl.closeConnection`, not in `Draft_6455`. |
| `rust/ws-testee/src/io_loop.rs:745` `fn drive_until_open` | `variant-in-equality` on `ReadyState::NotYetConnected` | **NOT RULED ON.** `if driver.state() != ReadyState::NotYetConnected { return true; }` — a readiness poll before the message script starts. That is an argument for it, not a ruling. |

I am flagging the second one rather than quietly folding it under the first.
The owner ruled on `server_closes_transport`; nobody ruled on `drive_until_open`,
and an allowance that carries someone else's ruling is the same species of lie
as a stale one. OWNER ACTION recorded in the entry: rule on it, or replace the
state comparison with a driver-side readiness predicate so the adapter stops
naming a `ReadyState` variant at all.

### Why the allowance cannot rot

Each entry pins the **sha256 of the enclosing function's normalized token
stream** — comments stripped, whitespace and layout gone, string contents
collapsed.

- **Not a file:line.** A line number drifts under any edit above it. In the
  probe run the declared `drive_until_open` site moved from line 745 to 754 and
  stayed `declared=true`, because the fingerprint does not move when unrelated
  code above it does. That is the drift a plane correspondence was pinned loosely
  enough to suffer, and it is why the allowance is not keyed on a line.
- **Not a raw byte hash.** A rustfmt pass or a doc-comment edit must not
  invalidate an owner ruling. Pinned in
  `TestFingerprintSurvivesLayoutButNotDecisionChanges`.
- **Any change to what is decided moves it.** Variant swapped, operator flipped,
  arm added, operand renamed — all four proven to move the hash in the same test.
- **An allowance that matches nothing FAILS** as
  `STALE_PROTOCOL_BRANCH_ALLOWANCE`. A stale allowance claims coverage of
  something that is not there.
- **An unpinned allowance FAILS** as `UNPINNED_PROTOCOL_BRANCH_ALLOWANCE`,
  because an empty fingerprint would match any future edit of its function.
- **An allowance covering more than one function FAILS** as
  `DUPLICATE_PROTOCOL_BRANCH_ALLOWANCE`. That one is there because the attack
  worked; see below.

## The three directions, read from the process

All three run `go run ./cmd/rustgatectl -root . -gate adapter-linkage`, exit code
read from the process.

**1. The seeded probe FAILS.** The F016 `match (role, state)` re-seeded into
`io_loop.rs`:

```
finding=ADAPTER_PROTOCOL_BRANCH ... fn seeded_protocol_branch ... (Role::Server via variant-in-pattern)
  ... and six more rows across rules variant-in-pattern and governed-binding-in-condition
gate=adapter-linkage verdict=FAIL detail="7 adapter architecture findings"
ac1-gates verdict=FAIL gates_passed=0/1                          exit 1
```

Before the fix the identical tree read `verdict=PASS ... exit 0`. Restored:
`sha256sum -c` OK, `git diff` clean.

**2. The declared instances PASS.** Clean tree:

```
gate=adapter-linkage branch_site=ws-testee/src/io_loop.rs:568 fn=server_closes_transport
  rule=variant-in-equality fingerprint=f0996c86...411a9 declared=true
gate=adapter-linkage branch_site=ws-testee/src/io_loop.rs:745 fn=drive_until_open
  rule=variant-in-equality fingerprint=2c05c5ae...3e11e4 declared=true
gate=adapter-linkage verdict=PASS detail="... 3 protocol-state branch site(s) over
  27 governed core enums, all declared"
ac1-gates verdict=PASS gates_passed=1/1                          exit 0
```

**3a. The allowance FAILS when the instance is REMOVED.** Body replaced with
`let _ = (role, state); false`:

```
finding=STALE_PROTOCOL_BRANCH_ALLOWANCE detail="allowance for ws-testee/src/io_loop.rs
  fn server_closes_transport (fingerprint f0996c863a59ddb0) matched no branch this run:
  the site was removed or changed, so the allowance now claims coverage of something
  that is not there"
ac1-gates verdict=FAIL                                           exit 1
```

**3b. The allowance FAILS when the instance is CHANGED.** One token — the ruled
`Role::Server` flipped to `Role::Client`, same shape, same line count:

```
finding=ADAPTER_PROTOCOL_BRANCH ... fingerprint d550a398f810fb46   (the edited decision, undeclared)
finding=STALE_PROTOCOL_BRANCH_ALLOWANCE ... fingerprint f0996c863a59ddb0
ac1-gates verdict=FAIL                                           exit 1
```

An edited decision loses its ruling instead of inheriting it, and the loss is
reported twice — once as an undeclared branch, once as an allowance that has
outlived its site.

Restored byte-identically after each, proven each time.
Logs: `.f016-logs/proof1-probe-fails.*`, `proof2-declared-passes.*`,
`proof3a-removed.*`, `proof3b-changed.*`.

## Attacking my own gate

Seventeen attacks against the real tree, each seeded into shipped adapter code,
each read from the process, each restored byte-identically.

| # | attack | first reading | now |
|---|---|---|---|
| A17 | **verbatim copy of the ruled function into a nested `mod` of the same file** | **exit 0 PASS** | exit 1, `DUPLICATE_PROTOCOL_BRANCH_ALLOWANCE` |
| A02 | **`d.state().eq(&ReadyState::Closing)` — comparison as a METHOD** | **exit 0 PASS** | exit 1, `variant-in-comparison-call` |
| A08 | `[ReadyState::Closing, ReadyState::Closed].contains(&d.state())` | exit 1 | exit 1 |
| A09 | `PartialEq::eq(&d.state(), &ReadyState::Closing)` | — | exit 1 |
| A13 | branch hidden in a `macro_rules!` body | exit 1, **degenerate fingerprint** | exit 1, `fn macro_rules!decide`, real fingerprint |
| A01 | a brand-new adapter source file carrying a branch | exit 1 | exit 1 |
| A03 | `if state as u8 == 2` — no variant named | exit 1 | exit 1 |
| A04 | `use ws_core::ReadyState::*;` then bare `Closing` in an arm | exit 1 | exit 1 |
| A05 | an EXTRA branch added inside the ruled function | exit 1 | exit 1 |
| A06 | branch in an `impl` block method | exit 1 | exit 1 |
| A07 | branch inside a closure | exit 1 | exit 1 |
| A10 | two-step: `let n = s as u8;` then `if n == 2` | **exit 0** | **exit 0 — ceiling** |
| A11 | two-step: `let name = r.wire_name();` then `if name == "server"` | **exit 0** | **exit 0 — ceiling** |
| A12 | `if format!("{state:?}") == "Closing"` | **exit 0** | **exit 0 — ceiling** |
| A14 | the branch moved into the ws-driver crate | **exit 0** | **exit 0 — out of scope** |
| A15 | `Role` renamed to `Party` in ws-core, adapter follows | exit 1 | exit 1 |
| A16 | a `Role` guard hidden on the ALLOWED event-seam match | exit 1 | exit 1 |
| A18 | `use ws_core::ReadyState as SemanticEventKind;` — alias a governed enum to the seam's name | exit 1 | exit 1 |

### Three that did not get through, and why

**A15** renamed `Role` to `Party` throughout ws-core and pointed the adapter at
the new name. A hand-maintained list would have gone quiet; the derivation
followed the rename and reported `Party::Server via variant-in-pattern`. That is
the return on re-deriving the vocabulary rather than listing it.

**A16** hid a `Role` comparison in the GUARD of a match on `SemanticEventKind`
— inside the one construct the seam declaration exempts. The exemption covers
branching on the event kind, not connection state smuggled into the same
expression, and both the guard's `Role::Server` and its `role` binding were
reported.

**A18** imported `ReadyState` under the seam's own name
(`use ws_core::ReadyState as SemanticEventKind;`). The seam is keyed on the
CANONICAL enum name derived from ws-core, never on the adapter's local spelling,
so the alias borrowed nothing.

### The two that got through and are now closed

**A17 is the one that matters**, because it is the same species that killed the
three gates defeated earlier today. A byte-identical copy of
`server_closes_transport` placed in a nested `mod` of the same file normalizes
to the same fingerprint under the same name in the same file. It matched the
allowance, and the gate reported

```
verdict=PASS detail="... 5 protocol-state branch site(s) over 27 governed core enums,
  all declared"                                                  exit 0
```

with a second, unruled protocol branch in shipped adapter code. My allowance had
exactly the flaw I had set out to avoid: it checked that a declaration was well
formed and never that its claim — *there is ONE ruled instance here* — was still
true. The fix re-derives the claim: count the distinct enclosing functions each
allowance matched this run and fail above one. Two evidence rows from ONE
decision (`role == Role::Server && state == ReadyState::Closing` reports both
operands) stay one instance, pinned in
`TestTwoEvidenceRowsFromOneFunctionAreOneInstance`.

**A02** spelled the comparison as a method. The variant sits in a call argument,
which every other rule treats as a value position — correctly, since
`connection_driver(config, Role::Client)` must stay legal. Closed by recognising
the comparison METHODS by name, on both the argument side and the receiver side.

**A13** was caught but its fingerprint was garbage: a branch inside a
`macro_rules!` body has no enclosing `fn`, so the site hashed the EMPTY token
span — `e3b0c44298fc1c14…`, the sha256 of the empty string, shared by every such
site. It still failed, since an unallowed site always does, but the fingerprint
described nothing. Now `macro_rules!` bodies are named items, and any site with
no named item falls back to its innermost enclosing brace group.

### The mutation round, which changed the design twice

Green tests prove nothing until they can fail. I disabled each rule in turn and
read which tests died. Two findings changed the code:

- Disabling **rule 1's variant resolution killed no test at all.** Every
  hostile fixture was passing through rule 2, because they all used a typed
  parameter (`fn p(s: ReadyState)`) whose name appeared in the scrutinee. The
  fixtures now use an unannotated `d.state()` scrutinee, so bare-variant, glob,
  alias and renamed-variant resolution each have a test only they can pass.
- Relaxing rule 2 to fire after a `.` produced a **wrong-reasoning positive**:
  `driver.state()` matched because a DIFFERENT function has a parameter spelled
  `state`. It landed inside a genuine branch, so the tree stayed green and the
  error was invisible in the verdict. Governed names after a `.` are now honoured
  only for struct-FIELD origins, and only when they are not method calls.

Every rule now has at least one test that only it can pass.

## What this detector CANNOT see

Stated plainly, and pinned as tests in `TestDisclosedCeilings` and
`TestDisclosedCeilingScopeIsTheAdapterCrateOnly` so that a later change which
closes one of them FAILS and forces this section to be rewritten rather than
left to drift.

**One root cause for the first four: this is a token-level scan with NO type
inference.** It knows a value is protocol state only when a governed variant is
spelled out, or when a binding was annotated with a governed type IN THE SAME
FILE. Break either link and the value becomes opaque.

1. **Two-step laundering through a primitive (A10).** `let n = state as u8;`
   in one statement, `if n == 2` in the next. The cast is not in a condition, so
   rule 2 does not see it; the condition holds only an integer, so no rule does.
   Any adapter that converts protocol state to a number or a bool in one
   statement and decides in another is invisible.
2. **Two-step laundering through a projection (A11).**
   `let name = role.wire_name();` then `if name == "server"`. Same shape. I did
   NOT close this by forbidding the projection methods, because
   `format!("{}", role.wire_name())` is printing a role, which the design
   constraint requires to stay legal.
3. **Capture inside a string literal (A12).** `if format!("{state:?}") ==
   "Closing"`. String contents collapse to one token deliberately — otherwise a
   `=>` inside a string would invent match arms that do not exist — so the
   inline-captured identifier is never seen as an identifier.
4. **A method whose name collides with a governed field.** `d.state()` is not
   assumed to return protocol state. Assuming it would flag `driver.state()`
   throughout the shipped adapter purely because some struct there has a `state:`
   field.
5. **Scope: `rust/ws-testee/src` only (A14).** A protocol branch moved into
   ws-driver or ws-core is not reported. The RULE fires on that shape — proven in
   `TestDisclosedCeilingScopeIsTheAdapterCrateOnly` — only the gate's file scope
   excludes it. That is defensible, since "adapter-side" is what AC1 says, but it
   means this gate is not evidence about where protocol logic lives overall.
6. **`#[cfg(test)]` items are skipped**, and the count is printed
   (`cfg_test_items_skipped=1`) rather than applied silently. Such code is not
   compiled into the shipped adapter, so a decision inside it is not production
   logic — it is the polarity canary that proves the production decision behaves.
   Only the exact attribute `#[cfg(test)]` qualifies; `#[cfg(any(test, feature =
   "x"))]` can reach a shipped build and stays scanned, pinned as a hostile
   fixture.
7. **The `match` scrutinee is found by scanning to the first `{` at bracket
   depth zero.** A struct literal in a scrutinee position would confuse it. No
   such shape exists in this adapter; it is a real limit of a tokenizer that is
   not a Rust parser.
8. **It is not a proof.** This is an architecture scan over five production
   sources. It is evidence that the shapes it names are absent, and nothing
   stronger. The original gate's own scope note said the same thing about the
   parser half, and it stays true of this half.

The honest summary of the ceiling: **this gate catches protocol state being
decided on where it is named. It does not catch protocol state being decided on
after it has been converted into something else.** A determined author can get a
protocol branch past it in two statements. What it now does that it did not do
this morning is fail on every one-statement form, including the one AC1's third
bullet names, and refuse to let a ruled instance cover an unruled copy.

## Files

- `cmd/rustgatectl/protocol_branch.go` — the detector, the vocabulary
  derivation, the allowance table and its three staleness checks.
- `cmd/rustgatectl/protocol_branch_test.go` — polarity, evasion and ceiling
  fixtures.
- `cmd/rustgatectl/adapter_linkage.go` — wiring, the `readRustSources` helper,
  and the note lines that print the derived vocabulary, every branch site with
  its fingerprint, and whether each is declared.

Commits `c4b924e`, `77c6c52`, `2a949c5` on
`claude/f016-protocol-branch-gate`.
