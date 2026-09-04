# Adversarial review of three same-day gates — record-guard, go-suite, pin-guard

STATUS: COMPLETE for what it claims. Every exit code below was read from the
process, not from a log line that said PASS.

Target: `cmd/recordguardctl`, `cmd/gosuitectl` and `cmd/pinconsumerctl dangling`
at mainline `4cf3f8f`. Worked in an isolated worktree, `/home/user/vjwp-gateattack`
on branch `claude/gate-adversarial-review`, with `.quarantine` symlinked in.
The brief was to get a bad tree past each gate.

**All three were defeated.** Nine attacks got a bad tree to exit 0; four are now
closed with a fix and a regression fixture that the pre-fix code fails; five are
recorded unfixed because closing them would move a census denominator, which is
not mine to move. One attack on the strongest of the three mechanisms failed, and
one disclosed ceiling was measured and found to be stated accurately.

## Scoreboard

| # | gate | attack | before | after |
|---|---|---|---|---|
| A5 | record-guard | the motivating div05 stub + one unpaired `"` | exit 0 READS-FINISHED | exit 1, fixture pinned |
| A2b | record-guard | `` STATUS: `IN PROGRESS` `` in backticks | exit 0 | exit 1, fixture pinned |
| A1 | record-guard | a record that reads finished and says nothing | exit 0 | exit 0 — declared ceiling |
| B2 | go-suite | failing test behind `//go:build darwin` | exit 0, census identical | still exit 0, now COUNTED |
| B3 | go-suite | whole failing package behind a build tag | exit 0, census identical | still exit 0, recorded |
| B5 | go-suite | exclusion naming a package that PASSES | exit 0 | exit 1 |
| C1 | pin-guard | a second tracked path in the pin's object | exit 0, silent | recorded |
| C2 | pin-guard | a sibling digest that matches the file | exit 0, silent | recorded |
| C5 | pin-guard | `kind: json_set` + any `pointer` | exit 0 | exit 1 |
| C8 | pin-guard | one trailing comma in the artifact | exit 0 | exit 1, artifact named |
| C9 | pin-guard | untrack or delete the pinned file | exit 0, silent | recorded |
| D1 | pin-guard | `t.Skip` on the covering assertion | exit 0, `covered=23` | recorded |
| D2 | pin-guard | the assertion's literal moved to a comment | exit 0, `covered=23` | recorded |

---

## 1. record-guard — two escapes closed, the declared ceiling confirmed

### A5. One unpaired quote silenced three of five signals — on the motivating instance

`maskOtherVoices` masked line by line, carrying an unclosed delimiter forward and
masking to end of line on the way. Its own comment reasoned that a blank line
drops the carry and so bounds the damage "to one paragraph instead of the rest of
the record". The unexamined half of that sentence is that **the entire useful
content of a stub fits inside one paragraph** — the status declaration, the void
self-report and the open checklist are three consecutive lines.

`cmd/recordguardctl/testdata/synthetic/unpaired-delimiter.md` is the committed
proof. It is the div05 stub from `history/div05-close-overtakes-echo-STUB.md`,
substantively unchanged — it still declares itself IN PROGRESS and still reports
that nothing has been verified — with one stray `"` added to its title line and
one backticked path in its body:

```
# DIV-05: close overtakes echo (the "close-overtakes-echo case, ledger sequence 54)
STATUS: IN PROGRESS — stub pushed early to survive container restarts.
...
port, and report. See `src/close.rs`.
Nothing verified yet.
- [ ] run the differential
```

Against the scanner as written this exited **0** with verdict `READS-FINISHED`.
Four signals were defeated by two characters: the mask took `declared-status`,
`void-self-report` and `open-checklist`, and the backticked path satisfied
`cites-nothing`, which is the only signal reading the unmasked source and so the
last line of defence for the other four. This is the exact document F009 was filed
about, passing the gate F009 asked for.

Every quote fixture in the polarity manifest pairs its delimiters, so nothing in
the manifest could see it.

Fix: masking is resolved over the paragraph and only over spans that CLOSE. A
delimiter with no closer is not a quotation and masks nothing.

### A2b. The gate was anti-correlated with honesty

`STATUS: IN PROGRESS` was refused at exit 1. `` STATUS: `IN PROGRESS` `` exited 0
with `signals=0`. One matched backtick pair defeated two signals at once — the
mask hid the value from `declared-status`, and the same pair supplied the citation
`cites-nothing` demands — and the record that got through is the one written in
more idiomatic markdown. The tool's disclosed ceiling is that self-declarations
"bind honest authors and nothing else"; here an honest author writing normal
markdown was let through and a blunter one was caught.

Fix: the status VALUE is read from the raw line. A declaration anchored at the
start of a line is the record's own voice by construction — `statusRe` anchors on
exactly that — and both quote-control fixtures, `F009-quotes-the-stub.md` and
`synthetic/wrapped-quotation.md`, quote that same sentence mid-sentence and stay
silent, which is what bounds the change.

### What was NOT defeated, and one ceiling measured

- **Supersession laundering failed.** A stub cannot be excused by pointing at
  another stub: `Supersession` requires the named record to exist AND to read
  finished by the same `Scan`, and `precondition` refuses a superseded record
  regardless. There is no chain of mutual withdrawals that launders a landing.
- **The declared ceiling is stated accurately.** The disclosure says: strip the
  self-declarations from the six historical stubs and only 1 of 6 is still caught.
  I stripped them mechanically — status values rewritten to COMPLETE, title
  qualifiers removed, void phrases replaced with ordinary prose — and ran
  `precondition` over all six. **Caught 1 of 6**, `catalog-plane-correspondence`,
  and only by its three unchecked checkboxes. The number is right; it is not worse
  than stated.
- **A1 still passes and should.** A six-line record saying "Everything is fine"
  plus one backticked token exits 0. No content signal can catch a document that
  declares nothing and asserts nothing, and the tool says so.

### Evidence

- `go run ./cmd/recordguardctl gate` exit **0**; `cases=16 firing=8 silent=8`.
- `go test -count=1 ./cmd/recordguardctl/` exit **0**.
- The census over all 55 records in `drafts/self-review` is BYTE-IDENTICAL before
  and after — diffed the `UNFINISHED`/`SUPERSEDED` lines and the totals against a
  binary built from `HEAD:cmd/recordguardctl/*.go`, `records=55 unfinished=0
  superseded=1 finished=54` both times. The fix changes no verdict on any real
  record; it only closes the escapes.
- Deletion attacks: the pre-fix scanner POLARITY-FAILs both new fixtures with
  `observed []`; disabling only the raw-status read (`false && (...)`) fails
  exactly `backticked-status` and nothing else. Each fixture isolates one fix.

---

## 2. go-suite — the exclusion list was the least of it

### B5. An exclusion for a package that passes was accepted by every check

The header says the exclusions' reasons are "CHECKED". What is checked is the
package NAME: `!present[name]` fires a `STALE_EXCLUSION` when the package leaves
the module. Nothing asked whether the excluded package still FAILS.

I added `internal/rfcneutral` — which passes cleanly, `go test` exit 0 — with a
259-byte reason clearing the 80-byte floor and containing the word `Owner`:

```
"internal/rfcneutral": "TestRFCNeutralityHoldsForAllFrames depends on a
    locale-sensitive header comparison that mis-sorts under this container's
    C.UTF-8 collation. Owner decision: pin LC_ALL for the suite, or make the
    comparison collation-independent before re-enabling this package."
```

`go test -count=1 ./cmd/gosuitectl/` exit **0**. Every check the gate had accepted
a fabricated reason for a working package, and the gate would have printed
`run=58 excluded=3 result=PASS`. Its own comment says an exclusion "is not a place
to park a failure"; nothing stopped it being a place to park a success.

Fix: each declared exclusion is now RUN, and one that passes fails the gate with
`EXCLUSION_NO_LONGER_FAILS`. This is the refusal `pinconsumerctl` already makes
for a FIXED pin — `STALE_ALLOWANCE`. The asymmetry between the two sibling gates
was the defect. B5 replayed against the fix: exit **1**,
`excluded package "internal/rfcneutral" PASSES on this host`.

### The declared reason for internal/portplan does not describe how it fails here

The exclusion says the failure is one line of `jdk_vendor` — committed
`"Homebrew"`, regenerated Temurin — with "all 969 declarations identical".

As `go-suite` actually invokes it, with `javac` from PATH:

```
--- FAIL: TestDeriveReproducesCommittedEvidence
    Derive: JAVAC_UNAVAILABLE: javac reports "... javac 21.0.10", pinned JDK is 17.0.19
--- FAIL: TestDeriveFailsOnDeclarationLevelOracleTamper
    a declaration-level tamper must fail closed with ORACLE_REPRODUCTION_MISMATCH,
    got JAVAC_UNAVAILABLE
```

With `.quarantine/jdk-17.0.19+10/bin` prepended to PATH the declared reason IS
exactly right — `differing_lines=1 of committed_lines=1071; line 6: committed
"jdk_vendor": "Homebrew", regenerated "Eclipse Adoptium"` — and the second test
PASSES. So the reason is true under a PATH the gate never establishes and never
checks, and under the gate's own environment a second test fails that the reason
does not mention: `TestDeriveFailsOnDeclarationLevelOracleTamper`, a fail-closed
tamper detector, which asserts nothing because the run dies earlier. That is the
same shape as a coverage claim satisfied by an inert assertion, one gate over.

The gate now prints the observed first failing line beside the declared reason on
every run, so the two can be compared by a reader. It does not adjudicate them.
**Owner action:** decide whether `go-suite` should put the pinned JDK on PATH (in
which case portplan's exclusion covers one known line and one test) or should say
that it excludes two tests for two different reasons.

### B2 and B3 — the build-tag channel, which no exclusion machinery touches

`go list ./...` is not the complement people take it for.

- **B2.** A `_test.go` file behind `//go:build darwin` containing `t.Fatal` is not
  compiled. `go test ./internal/rfcneutral/` exit **0**. `go vet` exit **0**.
  `go list ./...` still reports **61**. The census is byte-identical:
  `packages=61 run=59 excluded=2 result=PASS`.
- **B3.** An entire package, `internal/attackpkg`, whose only files carry
  `//go:build darwin`: `go list ./...` reports **61** — the same 61 — with
  **nothing on stderr and exit 0**. The failing package is absent from the
  denominator without ever being an exclusion.
- A directory under `internal/testdata/` is likewise invisible to `./...`.

Neither needs an entry in `excluded`, so none of the 80-byte reason, the owner
action, or the staleness check applies. The gate's claim that "a package added
tomorrow is covered without anyone remembering to add it" is false for any package
or test file carrying a constraint this host does not satisfy.

**This is already live.** Five `_test.go` files in the run set sit behind
`javabinde2e`, `diffregress`, `normcollide` and `formalcovere2e`; two more sit
inside the excluded `internal/lab`. And **15 of the 59 run packages carry no test
file at all** and report `ok [no test files]` — a PASS over zero assertions.
Deleting a package's last test file moves it into that 15 and changes no number
the gate prints.

Partial fix, as far as is mine to make: the gate now prints `with_tests=44
no_test_files=15 unbuilt_test_files=5`, names every uncompiled test file with the
constraint that would build it, and refuses an empty run set — which would
otherwise `go test` the repository root, find no test files and PASS having run
nothing. It does NOT refuse the opt-in lanes; they are deliberate. Saying nothing
about them is what this gate exists to stop.

**Owner action, not taken here:** the tag-gated lanes should be DECLARED the way
the two excluded packages are, with a reason and the action that would run them.
Turning seven undeclared exclusions into declared ones is a policy decision.

### Evidence

- `go test -count=1 -timeout 40m ./cmd/gosuitectl/` exit **0**, 26s.
- `go vet ./cmd/gosuitectl/` exit **0**.
- The census test logs `run=59 with_tests=44 no_test_files=15
  unbuilt_test_files=5`.

---

## 3. pin-guard — the allowances are sound; the candidate set that feeds them is not

The allowance mechanism is **the strongest of the three declared-exemption
designs, and I could not defeat it on its own terms.** It pins the declared digest,
so an edited pin loses its allowance; an allowance whose row stops being a
candidate fails as `STALE_ALLOWANCE`. Hiding an ALLOWED row therefore orphans its
allowance and the gate fails — I confirmed that accidentally while untracking
`rust/rust-toolchain.toml`, which collapsed `explained` 51→26, `allowed` 11→10 and
gave exit 1. That is a real result: the allowance list resists tampering.

The attack surface is one layer down. A **NEW** drift never needs an allowance,
because five different edits stop it becoming a candidate at all.

Control, established first: a new object naming a tracked file beside a wrong
digest gives exit **1**, `candidates=1`, and the row is printed. All five attacks
below start from that exact object.

| attack | edit | result |
|---|---|---|
| C1 | add a second tracked path (`"see_also": "README.md"`) | exit **0**, `candidates=0 explained=51`, **no line printed at all** |
| C2 | add a sibling digest that DOES match the file | exit **0**, `candidates=0 explained=51`, **no line printed** |
| C9 | `git rm --cached` the pinned file, or delete it | exit **0**, `explained=51`, **no line printed** |
| C5 | add `"kind": "json_set"` and any `"pointer"` | exit **0**, `explained=52`, printed as explained |
| C8 | one trailing comma in the artifact | exit **0**, `unparsable` 0→1, no file named |

C1, C2 and C9 are the dangerous ones because they are **completely silent**: the
only trace is `json_artifacts` moving by one, and nothing asserts that number.

- **C1** — `splitPinFields` returns and `analyseDangling` skips on
  `len(paths) != 1`. Two tracked paths in one object means no candidate. The
  printed ceiling discloses that "a pin split across two objects is a false
  negative"; it does not say that a pin sharing an object with a second path is
  one.
- **C2** — the loop `if declared == actual { return }` exits the whole object on
  the first digest that matches, so one correct digest immunises every drifted
  digest beside it.
- **C9** — this is the one that should sting, because the gate is called
  `dangling`. A pin whose target no longer exists is the most dangling pin there
  is, and it is dropped in silence: an untracked path is not recognised as a path
  by `splitPinFields`, and `digestOf` failing returns before any check.

**Not fixed.** Each of these three changes what becomes a candidate across 1,996
JSON artifacts. Any of them may surface rows that then need adjudication, and
`explained=51`, `covered=23`, `allowed=11` are declared numbers. Moving them is a
corpus shift and a **HARD STOP** to report, not something to re-baseline from
inside a review. **Owner action:** decide each of the three, then re-run the census
and adjudicate whatever appears.

**Fixed:** C5 and C8, both of which leave the census at exactly
`json_artifacts=1996 unparsable=0 candidates=0 explained=51 covered=23
allowed=11`. No row moved.

### C5 — the one rule that read nothing at all

`explainPin`'s own comment: *"an explanation here is never a key name and never a
guess. Every rule recomputes a value from CURRENT bytes and requires an exact
match."* The printed ceiling: *"Every such rule reads a drifting input, so none
can go quiet when a real pin goes stale."*

R5 was `kind == "json_set"` plus the PRESENCE of a `pointer` key. No
recomputation, no input. Two key names added to any object explained away every
digest in it forever. I replaced a real fixture's declared digest with a fresh
random value and the row stayed `explained`, `explained=51`, exit 0.

Fix: R5 now requires the object to BE the operation it claims to be — an RFC 6901
pointer, a `target` naming THIS file, and the declared digest being that
operation's own `value`. C5 replayed: exit **1**, `candidates=1`. All four live
rows still explain.

This raises the forgery cost from two keys to four and **nothing more**, and I
verified that: dressing the object as a complete `json_set` still gets through at
exit 0. R5 cannot be made a recomputation — a mutation operand is a value
deliberately absent from the tree, and two of the four live rows write a key their
target does not have. So the ceiling now says R5 is STRUCTURAL and must be read as
declared, never as measured. **Owner action:** its 4 rows arguably belong in the
declared-exemption family (`allowance`/`coverage`) rather than in `explained`,
whose definition is recomputation. Moving them reshapes the census, so it is left
for a decision.

### The five `explained` rule classes, each verified by perturbing its input

The task asked me to check the "reads a drifting input" claim per rule rather than
trust it. There are **five** implemented rules, not six — `explained=51` is
25 + 14 + 6 + 4 + 2 — and the ceiling text names five.

| rule | rows | perturbation | reads a drifting input? |
|---|---|---|---|
| R1 tree-envelope | 25 | append a line to `rust/rust-toolchain.toml` | **YES.** All 25 return as candidates, `explained` 51→26, exit 1 |
| R2 sibling-lines | 14 | edit `result.json`'s `outcome_lines[0]` | **YES** of its own array: `candidates=1 explained=50`, exit 1 |
| R3 field-provenance | 2 | rewrite `corpora/hidden/manifest.json#generator.secret_seed_commitment` | **YES.** `candidates=2 explained=50`, exit 1 |
| R4 field-inside-file | 6 | see below | **YES, but document-wide** |
| R5 mutation-operand | 4 | replace the declared digest with a fresh random one | **NO. Reads nothing.** `explained=51`, exit 0 |

Two qualifications the ceiling did not carry, now added to it:

- **R2 is insensitive to the named file.** Appending to
  `handshake-client-run1.log` left its row explained at exit 0. That is correct by
  intent — the digest is of the artifact's own array, not of the log — but it means
  an R2 row can never re-fire on a change to the file it names. Forgery needs a
  sha256 preimage, so this is not exploitable; it is a scope statement.
- **R4 decides document-wide, not at the location it names.** Setting
  `$.head` in `evidence/java/behavior-delta-ledger.json` to a fresh value left the
  row explained at exit 0 — the declared digest occurs TWICE in that file, at
  `$.head` and at `$.records[54].record_digest`, and the explanation silently
  re-anchored to the second while printing the same sentence about the first. Only
  replacing every occurrence returned the row: `candidates=1`, exit 1.

  The consequence is a laundering primitive (**C5b**, verified): a stale
  whole-file pin of a JSON file is subtracted as `field-inside-file` if that file
  records the digest anywhere — for instance as a `previous_sha256`. The
  explanation then reads *"it pins a value the file carries, not the file's
  bytes"*, which is precisely wrong: it IS the file's bytes, just the old ones.
  Attestation and review-round documents record their own former digests as a
  matter of course.

  I checked the six live R4 rows against this: all six resolve to semantically
  named fields — `$.head`, `$.records[N].record_digest`, `$.accepted_root_digest`,
  `$.artifacts[0].sha256` — and none is a self-recorded whole-file digest. **The
  hole is real and not currently exercised.** Not fixed: distinguishing the two
  requires knowing which fields are self-digests, which is a schema question the
  tool deliberately refuses to have. **Owner action:** decide whether R4 should
  require the digest to sit at a field the pin NAMES.

### D1 and D2 — a coverage claim satisfied by an assertion that does nothing

`verifyCoverage` reads back a format-string literal from a named file. It never
checks that the assertion executes.

- **D1.** One line, `t.Skip("temporarily disabled while the fixture catalog is
  refrozen")`, at the top of `TestUS006FixtureCatalogThroughRealCLI`. The literal
  `realized digest %s != frozen %s` is untouched. `pinconsumerctl dangling` exit
  **0**, `covered=23`, no `STALE_COVERAGE_CLAIM`. And `go test -run
  TestUS006FixtureCatalogThroughRealCLI ./internal/formalplan/` reports **ok**,
  exit 0, because a skipped test passes. Both gates green; 23 pin rows declared
  "verified by a named check elsewhere" with nothing verifying them.
- **D2.** `false && (digest != fixture.RealizedTreeSHA256)` with the literal moved
  into a comment. Compiles, `go vet` clean, `dangling` exit **0**, `covered=23`.

Not fixed: proving an assertion is reachable and executed from another gate needs
a mechanism the family does not have — a coverage claim would have to name a test
and read back a result, not a string. **Owner action:** decide whether a coverage
claim must cite a run receipt rather than a source literal.

There is also an unguarded composition. `covered=23` rests on
`internal/formalplan/backend_test.go`. `go-suite` runs `internal/formalplan`
today, but nothing connects the two: adding `internal/formalplan` to `excluded`
required only an 80-byte string containing "Owner" before attack B5 was fixed, and
`pinconsumerctl` would have kept reporting `covered=23` for an assertion nothing
ran. The B5 fix now makes that particular route fail, since `internal/formalplan`
passes and a passing exclusion is refused — but that is luck, not design. Neither
gate knows the other exists.

### Evidence

- `go run ./cmd/pinconsumerctl dangling` exit **0**;
  `json_artifacts=1996 unparsable=0 candidates=0 explained=51 covered=23
  allowed=11` — identical to the pre-review census. No denominator moved.
- `go test -count=1 ./cmd/pinconsumerctl/` exit **0**, including the new
  `TestTheMutationOperandRuleIsNotSatisfiedByKeyNamesAlone`, which holds all four
  ways the C5 shape must stay a candidate.
- C5 replayed: exit **1**, `candidates=1`. C8 replayed: exit **1**, artifact named
  as `UNPARSABLE_ARTIFACT`.

---

## 4. The shared weakness — all three check the shape of a declaration, not the fact it asserts

The three gates were written by one author in one day with one idea of what a
declared exemption is, and the idea has a consistent hole in it. In each gate the
anti-rot check verifies that the DECLARATION is still well formed, and in none of
them does it verify the CLAIM the declaration makes.

| gate | what the exemption asserts | what the check verified |
|---|---|---|
| go-suite | "this package cannot pass here, for this reason" | the package still exists |
| pin-guard coverage | "a named assertion verifies these 23 rows" | that string is still in that file |
| pin-guard allowance | "this pin really has drifted and no one can fix it" | the row is still a candidate at that digest — **the claim itself** |
| record-guard | the record's own declaration that it is unfinished | replayed against 14 declared historical verdicts — **the claim itself** |

The bottom two rows are the ones that hold. The allowance list keys on the
declared digest and orphans when the finding goes away, and I could not defeat it.
The polarity manifest declares exact signal rows for real historical records in
both polarities, and it is what made my two record-guard fixes provable in
minutes. Where the same author checked the fact, the mechanism worked. Where the
same author checked the declaration's shape, I got a bad tree through in one edit.

Three narrower patterns run across all three:

**The census number that would reveal a hidden item is printed and unbound.**
`packages=61` — nothing asserts 61. `json_artifacts=1996 unparsable=0` — nothing
asserts either. `records=55` — only `> 0` is asserted. Every silent attack in this
review is visible ONLY as one of those numbers moving by one, and no gate would
notice. record-guard is the only one with an honesty floor at all ("a scanner that
matched nothing and reported PASS is theatre"), and it is the weakest form of it.

**The reason text is never validated against the world.** go-suite requires 80
bytes containing "Owner"; the allowance and coverage `owner`/`why` fields are
unvalidated prose. A fabricated reason is indistinguishable from a true one —
proved live in B5 — and a reason that has silently drifted away from what actually
happens is invisible, which is the `internal/portplan` case.

**Each gate delegates to another gate without checking that gate runs.** pin-guard
cites a test in `internal/formalplan`; go-suite decides whether `internal/formalplan`
runs; neither knows about the other. The exemptions compose, and nothing checks
the composition.

The one-sentence version: **an exemption should be re-derived, not re-read.**
Where the exemption's premise was re-derived from the tree, the gate held. Where
it was re-read as text, it did not.

## 5. What I did not attempt

- **No owner gates were triggered.** No AWS run, no benchmark run, no Autobahn
  re-run. `internal/lab` was executed only far enough to read
  `PLATFORM_EXECUTOR_UNSUPPORTED`, which is a local refusal.
- `origin/codex/race-catchup` was not touched, read-only as declared.
- **No corpus or denominator was shifted.** All five recorded-not-fixed pin-guard
  holes were left alone for exactly that reason, and every fix was checked to leave
  the census identical.
- I did not attack `pinconsumerctl consumers`, only `dangling`.
- I did not attack the other gates in the chain — `fixture-guard`, `ledger-gates`,
  `ac1-gates`, `oracle-hierarchy-gates`, `test`, `test-release`.
- I did not attempt to forge an R1 or R2 explanation, because both need a sha256
  preimage. I state that as a reason, not as a test.
- I did not verify the second coverage claim (`internal/deltaledger/legacy_adjudication.go`)
  by attack; it is the same `strings.Contains` mechanism as the first, and D1/D2
  apply to it unchanged.
- I did not check whether the six live R4 rows' declared digests match a HISTORICAL
  version of their named file's bytes. I checked the weaker thing: that all six
  resolve to semantically named fields rather than self-recorded whole-file
  digests.

## 6. Process discipline, including my own mistake

**I ran an unscoped `pkill`.** To stop a stray process of my own I ran
`pkill -f "gosuitectl -root"`. In this shared container that pattern also matches
other agents' `go run ./cmd/gosuitectl -root .`, and a second `make` terminated
and left `/home/user/vjwp-criteria/rust`. Whether that particular process was
mine or another agent's I cannot now separate, because — see below — the log path
itself was shared. An earlier `make` of mine also wrote into that tree's
`rust/target`. No source file outside my worktree was modified and no git state
was touched. I did not use `pkill` again; later runs were detached with `setsid`.

**A parallel agent then ran `pkill -x make cargo gosuitectl`, also unscoped**, and
the coordinator confirmed it removed every live `make`/`cargo`/`go` process on the
host. Two of my `make -C rust gates` runs died with SIGTERM as a result. **A
`Terminated` exit is not a reading**, and none of the SIGTERM runs is recorded
anywhere in this document as evidence about anything. Every exit code cited above
came from a process that ran to completion.

**The scratchpad directory is SHARED between agents in this session.** Another
agent's run was writing to, and `rm -f`-ing, the exact log path I had chosen under
`.../scratchpad/`, so one of my logs contains two runs' output interleaved and
another was unlinked underneath a live process. That log is discarded. The
authoritative run for this record writes to a private path outside the shared
scratchpad. If a future agent takes one thing from this section: a scratchpad path
is not private, and two agents will pick the same obvious filename.

**Load.** Three worktrees were running the full chain at once; `internal/assurance`
took 680s and `internal/deltaledger` 168s against baselines of a fraction of that.
Timings quoted in this record are not performance readings.

**Base.** This review targets `4cf3f8f`. Mainline moved to `c22eb3c` while it was
in flight; `git diff --stat 4cf3f8f origin/... -- cmd/recordguardctl cmd/gosuitectl
cmd/pinconsumerctl rust/Makefile` is EMPTY, so none of the three gates or the
chain changed under me and no finding here is stale. The four new commits add
findings and documents only.

## 7. Files changed

- `cmd/recordguardctl/scan.go` — paragraph-scoped masking of closed spans only;
  status value read from the raw line.
- `cmd/recordguardctl/testdata/synthetic/unpaired-delimiter.md`,
  `.../backticked-status.md`, `.../polarity.json` — two firing fixtures with
  declared rows, taking the manifest to 16 cases, 8 firing and 8 silent.
- `cmd/gosuitectl/main.go`, `main_test.go` — each exclusion is run and must still
  fail, with the observed failing line printed beside the declared reason;
  `with_tests=`, `no_test_files=`, `unbuilt_test_files=` reported with every
  uncompiled test file named and its constraint; an empty run set refused.
- `cmd/pinconsumerctl/main.go`, `main_test.go` — R5 requires the operation it
  claims to be; unparsable artifacts named and refused; the printed ceiling
  corrected on R5 and on R4's document-wide scope.
