# A landing precondition that reads a self-review record instead of counting it

STATUS: COMPLETE for what it claims. Branch `claude/record-content-precondition` from
mainline `claude/feature/verified-java-websocket-port` at `4a2b9c6`.
Date 2026-09-03. Scope: new `cmd/recordguardctl/` (5 Go files, 14 committed fixtures),
`rust/Makefile` (one new target, appended to the `gates` chain), `rust/README.md` (the target
listed and its ceiling-free choice explained), `.claude/GOAL-LOOP.md` step 6, and this record.
No Rust source, no evidence document, no ledger, no `internal/` package and no `assurance/`
file was touched:
`git diff --quiet 4a2b9c6 HEAD -- rust/ ':!rust/Makefile' ':!rust/README.md' evidence/ assurance/ internal/ java-oracle/`
exits **0**.

F009 named the rule in one line — **a record is read for its content, never counted for its
presence** — and filed the mechanical version as worth building and not built. This is that,
built, with its errors in both directions measured rather than asserted.

---

## 1. What went wrong, restated so the check can be aimed

Three wave-4 agents finished, pushed, and died silently. To decide whether their work was
landable the loop ran, per branch, `git log --oneline` and a count of files matching
`drafts/self-review`, and reported all three as "each ends with a self-review record". Two
did. `claude/div05-close-overtakes-echo` at `755b8c8` carried this, in full:

```
# DIV-05: close overtakes echo (ledger sequence 54)

STATUS: IN PROGRESS — stub pushed early to survive container restarts.

Task: establish shipped-Java behaviour when a Close arrives while a large (256 KiB)
echo is still draining, build the reproduction the ledger record asks for, fix the
port, and report.

Nothing verified yet.
```

Nine lines, behind seven commits and 983 insertions. The deciding command answered "is there
a file whose path contains `drafts/self-review`". It was read as "is the work reviewed".

The check therefore has to do exactly one thing the count could not: **open the file and
read what it says about itself.**

## 2. The discriminator, and how it was calibrated

Five signals, all of which read text. None is satisfied by a file existing, having a size,
or having a status *field* — the status signal reads the status *value*, which is the whole
point. `cmd/recordguardctl/scan.go`.

| signal | what it reads | instances it was derived from |
|---|---|---|
| `declared-status` | a line whose first token is `Status:` (after markdown decoration only), scanned for an unfinished term in its **value** | `755b8c8`, `df5642c`, `714614b`, `68fbc17`, `2421d6f` |
| `declared-title` | the record's first ATX heading, scanned for an unfinished term as a whole word | `df5642c`, `714614b`, `68fbc17`, `e784eb6` |
| `void-self-report` | an **unquoted** phrase reporting zero results | `755b8c8`, `df5642c`, `2421d6f` |
| `open-checklist` | an unchecked markdown task box — the record's own markdown saying "not done" | `e784eb6` |
| `cites-nothing` | the record contains **zero** citation tokens of any kind | `755b8c8` |

### The corpus it was calibrated on

Not invented: **82 document versions** — the 41 records currently under `drafts/self-review/`
(including `findings/`) and the 41 first-committed versions of every record ever added there,
recovered with `git log --all --diff-filter=A`. Labelled by reading each one: **10 of the 82
versions declare themselves unfinished, on 8 distinct paths** — six opening stubs (`755b8c8`,
`df5642c`, `714614b`, `46d902f`, `68fbc17`, `2421d6f`), this branch's own opening stub at
`8dbf6d4`, one set of working notes with 42 lines of real evidence in it (`e784eb6`), and
`normalization-collision-audit-WIP` in both its 9-line and its 88-line form. The remaining 72
are finished records.

### Two things the calibration ruled OUT, and this is the useful part

**Length is unusable, and inverted.** The shortest *finished* record in the tree is
`findings/F001-…` at **7 lines** — a complete finding with cost, deciding moment, evidence and
bin — and it is shorter than **every one** of the six committed unfinished records, which run
**8 to 42 lines**. Nine of the F00x findings sit at 7–18 lines, squarely inside that range. The
two classes do not separate by length in either direction, so no threshold exists to pick.
Pinned as a test, `TestLengthIsNotTheDiscriminator`.

**Evidence density is unusable as a tuned floor.** Counting citation tokens over all 82
versions: the leanest *finished* record carries **9**; the richest *stub*
(`concurrency-coverage-disclosure` at `68fbc17`, sixteen lines of real problem statement)
carries **8**. The separating margin is **one token**. A floor fitted at 9 would classify this
corpus perfectly and mean nothing. So `cites-nothing` is pinned at literally **zero** — the
degenerate case, "cites nothing at all" — where the margin to the nearest finished record is 9
rather than 1. It catches exactly one record in the corpus, and that record is the div05 stub.

### Quote-awareness, which is load-bearing rather than tidy

F009 itself quotes the stub verbatim: `*"STATUS: IN PROGRESS — stub pushed early to survive
container restarts. … Nothing verified yet."*`. A discriminator matching vocabulary rather than
voice refuses the finding that asked for it. So fenced blocks, blockquote lines, and paired
`"…"`, `“…”` and backtick spans are masked before any signal is read. `F009-quotes-the-stub.md`
is a committed fixture declared **silent**, and deletion attack A6 shows it is the only thing
holding that.

## 3. Where it binds, and why the two halves differ

**The refusal binds at the landing decision**, `.claude/GOAL-LOOP.md` step 6, immediately
before the `merge: <branch>` commit and before reporting any branch as finished:

```
go run ./cmd/recordguardctl precondition drafts/self-review/<record>.md
```

Exit 0 = the record reads as finished. Exit 1 = it does not, and the branch is unreviewed
whatever its diffstat looks like. Several branches can be named in one invocation; it refuses
the batch and says which one failed — that is the wave-4 shape exactly.

**The gate half deliberately carries no ceiling on unfinished records**, and this is the one
place it departs from `fixture-guard`'s shape. `make -C rust record-guard` does **not** refuse
unfinished records in the tree, and does not pin their number. I considered copying
`-max-waivers` and rejected it: this repository's own discipline tells an agent to commit and
push a stub within its first few tool calls so a container restart cannot lose the branch, and
a ceiling would gate against a practice the loop mandates. The gate's job is instead to keep
the refusal alive — replaying the discriminator over records extracted verbatim from git,
printing what fired and the sentence it was read from, and refusing to PASS if it read no
records at all. It also prints a census, so honestly-unfinished records are **visible without
being punished**:

```
gate=record-content-precondition census UNFINISHED record=drafts/self-review/normalization-collision-audit-WIP.md signals=2 first=declared-title@1
    not a gate failure: an honestly-unfinished record is CORRECT. It is refused only when a landing decision names it.
gate=record-content-precondition step=census records=41 unfinished=1 finished=40
```

Both halves run in `gates`, for the reason `fixture-guard` records: **one of the twelve
deletion attacks (A11) is caught only by `go test`**, because no tree scan can reach it — that
an **absent** record is a refusal and not a pass, which is F009's defect stated directly. A
twelfth (A12) was caught only by `go test` until the fixture that lets the gate see it was
added, which is itself the argument for running both.

*A check nobody runs is not a check.* The gate half runs on every `make -C rust gates`. The
refusal half is invoked by GOAL-LOOP step 6, which is the only place a landing decision is
made in this repository, and its absence there was the failure.

## 4. The historical proof — exit codes read from the process

The record at `755b8c8`, refused:

```
$ go run ./cmd/recordguardctl precondition -root . cmd/recordguardctl/testdata/history/div05-close-overtakes-echo-STUB.md
record=…/div05-close-overtakes-echo-STUB.md lines=10 signals=4 verdict=REFUSED
    line=3 signal=declared-status  term="in progress"      | STATUS: IN PROGRESS — stub pushed early …
    line=3 signal=declared-status  term="stub"             | STATUS: IN PROGRESS — stub pushed early …
    line=9 signal=void-self-report term="nothing verified" | Nothing verified yet.
    line=0 signal=cites-nothing    term=""                 | no exit code, commit, digest, path, symbol or claim-vocabulary term
result=FAIL reason="1 of 1 named record(s) do not read as finished"
                                                                                       exit 1
```

The same path after the branch finished, and the two records F009 names as the ones that did
land, accepted:

```
$ go run ./cmd/recordguardctl precondition -root . \
    cmd/recordguardctl/testdata/real/div05-close-overtakes-echo-FINAL.md \
    drafts/self-review/adapter-residuals.md \
    drafts/self-review/fixture-liveness-guard-detector.md
record=…/div05-close-overtakes-echo-FINAL.md  lines=553 signals=0 verdict=READS-FINISHED
record=drafts/self-review/adapter-residuals.md lines=422 signals=0 verdict=READS-FINISHED
record=drafts/self-review/fixture-liveness-guard-detector.md lines=443 signals=0 verdict=READS-FINISHED
records=3 result=PASS                                                                  exit 0
```

**This is a differential, not two observations.** `div05-close-overtakes-echo-STUB.md` (blob
`359940cd`) and `div05-close-overtakes-echo-FINAL.md` (blob `6928ddfb`) are the *same
repository path* at two commits of the same branch — 9 lines against 552, `STATUS: IN
PROGRESS` against `STATUS: COMPLETE for what it claims` on the same line 3. Same file, same
signal position, opposite verdict. That is what shows the check reads the status **value** and
is not merely noticing that a status line exists. A test refuses a manifest from which either
blob has gone missing (`TestTheMotivatingInstanceIsInTheManifest`).

Twelve of the fourteen fixtures are real records extracted verbatim from git with their blob
ids recorded; the gate prints each blob as provenance on every run. Six must fire, eight must
stay silent, and the expected rows are declared as `line|signal|term` — not a count and not a
boolean — so removing any one signal shows up rather than being masked by another still firing
on the same file.

### The full sweep

Running the finished discriminator over all 82 versions: **10 versions refused, on 8 distinct
paths.** All 8 are records that declare themselves unfinished. 72 versions pass, and none of
them is a stub by reading. Measured false positives on this corpus: **0**. Measured false
negatives: **0**. Section 7 says why that number is weaker than it looks.

## 5. The honest edge: writing the stub is correct, landing on it is the defect

F009's fourth point, and it is visible in the artifact rather than only in prose:

- `make -C rust record-guard` exits **0** on a tree containing an honestly-unfinished record,
  naming it in the census with the line "not a gate failure: an honestly-unfinished record is
  CORRECT."
- `recordguardctl precondition` on the **same file** exits **1**.
- `TestGateDoesNotFailOnAnHonestlyUnfinishedRecord` asserts both halves against one temporary
  tree in a single test, so the distinction cannot be quietly collapsed to one policy.

This record is its own dogfood. The stub pushed at `8dbf6d4` in this branch's first commit was
refused by the check being built in it; the gate's census listed it as unfinished and passed;
the finished version you are reading passes `precondition`. That transition is in this
branch's history, on this path, and can be replayed with `git show 8dbf6d4:drafts/self-review/record-content-precondition.md`.

## 6. RED readings and deletion attacks

**RED first.** The discriminator was written as a declared-but-unimplemented `Scan` returning
`nil`, with the 12 real-record fixtures and their declared rows already committed (the two
synthetic controls came later, each added because an attack survived), and the polarity suite
run against it. Read from the process, `go test ./cmd/recordguardctl/` exit **1**, six firing
fixtures each reporting `declared […rows…], observed []`, plus
`the same words unquoted did not fire` and `the 42-line UNFINISHED record stayed silent`. The
six silent fixtures passed against the empty scanner — which is the point of declaring rows:
silence proves nothing, so the firing half is the load-bearing half.

**Deletion attacks: 12 run, every mutation compiled.** A mutation that breaks compilation
proves nothing, so each is a `false &&` on a live condition or an equivalent-typed
substitution. Applied, `go test` and `go run … gate` run, exit codes read from the process,
then the file restored byte-exactly.

| # | mutation | `go test` | `gate` | caught by |
|---|---|---|---|---|
| A1 | `declared-status` disabled | 1 | 1 | POLARITY-FAIL on 5 fixtures |
| A2 | `declared-title` disabled | 1 | 1 | POLARITY-FAIL on 4 fixtures |
| A3 | `void-self-report` disabled | 1 | 1 | POLARITY-FAIL on 3 fixtures |
| A4 | `open-checklist` disabled | 1 | 1 | POLARITY-FAIL on `catalog-plane-correspondence-WIP` |
| A5 | `cites-nothing` disabled | 1 | 1 | POLARITY-FAIL on the div05 stub |
| A6 | quote-awareness deleted | 1 | 1 | `F009-quotes-the-stub.md` fires |
| A7 | word-boundary check deleted | 1 | 1 | **only** the synthetic substring control |
| A8 | whole discriminator a no-op | 1 | 1 | 6 fixtures + 2 unit assertions |
| A9 | status reads the line, not the value | 0 | 0 | **equivalent mutant — see below** |
| A10 | census stops counting records | 1 | 1 | "read no records at all" |
| A11 | a missing record passes | 1 | 0 | **only** `go test` |
| A12 | cross-line quotation carry dropped | 1 | 1 | `synthetic/wrapped-quotation.md` |

**Three attacks initially survived, and all three were real gaps, fixed in this branch rather
than filed.**

- **A7** — removing word boundaries makes `draft` match inside `drafts`, `started` inside
  `restarted`, `stub` inside `stubbed`, `wip` inside `wiped`, `pending` inside `appending`,
  `incomplete` inside `incompleteness`. No real record in the corpus happens to contain any of
  those in a title or a status value, so nothing caught it. Closed by
  `testdata/synthetic/substring-control.md`, the one hand-written fixture here, which puts all
  six substrings exactly where the title and status signals read. It is declared silent and
  fires six times under A7.
- **A11** — dropping the `refused++` on an unreadable record made a **missing** record pass.
  That is F009's defect wearing the tool's own clothes: absence read as satisfaction. Nothing
  in the package tested it. Closed by `TestAnAbsentRecordIsARefusalNotAPass`, which is why the
  Makefile target runs `go test` as well as the tool.

- **A12 was found by running the finished tool on this record.** The masker paired quote and
  code delimiters within a single line. This record quotes F009 quoting the div05 stub, and at
  a normal line width the closing backtick lands on the *next* line — so the trailing fragment
  was read as this record's own voice and **a finished record was refused, exit 1, signal
  `void-self-report` at line 81**. That is a real false positive, of exactly the class this
  tool exists to avoid, and it was invisible to all thirteen fixtures because none of them
  wrapped a quotation. Fixed by carrying an open delimiter across a line break and dropping it
  at a blank line, which bounds the damage a stray quote can do to one paragraph.
  `TestAQuotationThatWrapsALineBreakStaysMasked` pins both directions — the wrap stays masked,
  and a stray unbalanced quote does not swallow the status declaration after the next blank
  line — and `synthetic/wrapped-quotation.md` is what lets the *gate* half see A12 at all,
  which it could not before that fixture was added.

- **A9 is an equivalent mutant, and this is proved rather than assumed.** Scanning the whole
  status line instead of its value cannot change any verdict, because the text the pattern
  consumes before the value is only whitespace, the decoration characters `#*_+-`, the literal
  word `status`, and the colon — none of which contains a lexicon term as a whole word.
  `TestTheStatusPrefixCanNeverCarryATerm` measures this over every status line in every
  fixture and over the decoration alphabet directly: **127 prefixes examined, none can carry a
  term.** If the pattern is ever loosened to allow words before the colon, that test fails and
  A9 stops being equivalent.

**No existing check was weakened.** `fixture-guard`, `ac1-gates`, `ledger-gates` and
`oracle-hierarchy-gates` are untouched; the only edit to `rust/Makefile` adds a target and
appends it to the `gates` list.

**Validation, read from the process.** `make -C rust gates` with `VJWP_PROTECTED_STORE`
exported: `gate=record-content-precondition result=PASS` in the chain,
`gate=fixture-liveness-guard result=PASS`, `ac1-gates verdict=PASS gates_passed=8/8`,
**GATES_EXIT=0**. `go test ./cmd/recordguardctl/` exit 0, 15 tests (counted from
`go test -v | grep -c '^--- PASS'`, not from the sentence). `gofmt -l` empty,
`go vet` exit 0. Self-check on the finished tree: `cases=14 firing=6 silent=8 result=PASS`;
census `records=41 unfinished=1 finished=40`.

**The full Go suite, and a baseline correction the brief did not have.**
`go test -timeout 40m -count=1 ./...` with the store exported: **38 packages ok**, including
`cmd/recordguardctl`, `internal/deltaledger`, `internal/corpora` and `internal/oraclerank`.
**Five** packages fail — but the brief for this work named only three as environment baseline
(`internal/lab`, `internal/portplan`, `internal/formalplan`). The two extra are
`cmd/formalcoverctl` and `internal/formalcoverage`.

F008's rule is that a failing test's cause is what the process prints, not what the nearest
recent finding suggests, so I did not attribute them and did not reason about them. I measured
them. Checked out `4a2b9c6` in this worktree with my changes absent, ran both packages, saved
the failing test names; checked the branch back out, ran the same two packages, saved the
names again; stripped the durations and diffed:

```
$ diff <baseline 4a2b9c6 failures> <branch 461e2c0 failures>
                                                          exit 0   —   36 names, identical
```

**36 failing tests, the same 36 names, on both trees.** The two packages are pre-existing
mainline failures and nothing in this branch touches them. Their diagnosis is not mine to
assert here — F008 and the correction appended to F006 both establish it as stale retained
derived evidence after a merge, and neither has been repaired — but the fact that they are
baseline is measured above rather than borrowed from that story. **The environment note listing
three baseline packages is short by two**, which is worth the owner's attention independently
of this branch.

## 7. Claims, in the fixed vocabulary

- **Observed**: the discriminator fires on all six committed historical records that declare
  themselves unfinished, and is silent on all eight fixtures declared silent — the six real
  finished records, including the 421-, 442- and 552-line ones, plus the two synthetic controls.
  Exit codes read from the process.
- **Differential**: the div05 stub and the div05 final record are the same repository path at
  two commits; the verdict inverts with the status value while the status *field* is
  unchanged.
- **Bounded**: the 0 false positives and 0 false negatives are bounded by 82 document versions
  from one repository, labelled by me, and **the labelling is partly circular** — I classified
  each document by reading its self-description, and the discriminator reads self-descriptions.
  The three findings that are *not* circular are the ones worth keeping: the div05 differential
  (its label comes from the branch's history, not from my reading), the F009 quote control, and
  the length inversion.
- Nothing here is **proved-model** or **proved-production+refinement**. There is no model and
  no refinement obligation; this is a lexical discriminator over English prose.

## 8. False negatives, measured

**The dominant one, and it is large.** The check reads whether a record *claims* to be
finished. A record that is unfinished and does not say so is mostly invisible. Measured
directly: strip every honest self-declaration from each of the six historical fixtures — status
line deleted, title qualifier removed, void phrases and unchecked boxes deleted — and re-run:

```
catalog-plane-correspondence-WIP.md        PASSES (false negative)
concurrency-coverage-disclosure-STUB.md    PASSES (false negative)
div05-close-overtakes-echo-STUB.md         still REFUSED   (cites-nothing)
handshake-discrimination-STUB.md           PASSES (false negative)
legacy-record-adjudication-STUB.md         PASSES (false negative)
oracle-rank3-independence-STUB.md          PASSES (false negative)
```

**One of six.** Only the record that cites nothing at all survives its own dishonesty. The
check binds honest agents; it does not bind a record written to pass it. That is the ceiling,
and it is not a small one.

Others, none of which has an instance in the corpus:

- A record that is complete-looking and substantively **wrong, thin, or unearned** is entirely
  undetected. The tool reads the claim of completion, never the truth of the claims.
- A record whose only self-declaration sits inside a fenced block or a quotation is masked by
  design and therefore missed.
- A record that reads finished at the top and admits mid-prose that a section was abandoned.
- A record with **no ATX heading at all** never gets the title signal read, and one whose only
  status declaration sits below a heading it does not have is carried by the other four signals
  or not at all.
- `cites-nothing` counts citation tokens over the **unmasked** source on purpose — a citation
  inside backticks is still a citation — so a stub containing a single backticked path escapes
  that signal on one token. This branch's own opening stub did exactly that: it carried one
  code span and was caught by `declared-status` and `void-self-report`, not by `cites-nothing`.
- Anything not in English, and any status vocabulary outside the eleven terms.
- Six of the eleven unfinished terms (`todo`, `draft`, `incomplete`, `unfinished`,
  `not started`, `pending`) have **no instance in this corpus**. They are a deliberate widening
  and are not calibrated; they are recorded here so nobody later mistakes them for measured.

## 9. False positives, known

- `normalization-collision-audit-WIP.md` (88 lines) and `catalog-plane-correspondence-WIP.md`
  (42 lines) are refused. Both are correct, useful working notes with real evidence in them.
  This is refusal **by design** — the landing record for each of those branches is a different
  file, and working notes should not satisfy a landing precondition — but if someone ever names
  such a file *as* the landing record they will get a refusal that is arguably wrong. The
  remedy is a status line, not a change to the tool.
- **Found and fixed in this branch, by dogfooding**: a quotation wrapping a line break was read
  as the record's own voice, and this record was refused by its own check at exit 1. Section 6,
  A12. It is repeated here because it was a false positive on a *finished* record — the more
  damaging direction — and because it was found by running the tool, not by reasoning about it.
- A finished record whose **title** carries an unfinished word as a qualifier — "why the WIP
  discipline works" — would be refused. Zero instances in 82 versions; the word-boundary rule
  and the title-only scope keep it narrow, but it is a real surface.
- A finished record containing a line beginning `Status:` with an unfinished value inside an
  unquoted example. Zero instances in 82 versions.

## 10. The wider class, scoped honestly

The class is bigger than these records: a predicate answered by **presence** where **content**
was the question. This session filed four instances — F009 (a `grep -c` on a path answering
"is it reviewed"), F006 (a lookup run against the wrong tree, its mirror: absence read as
defect), F008 (the nearest recent explanation standing in for a diagnosis), and the loop's own
validation contract stating `74/74` and `49/49` without the ceilings measured for them.

**A general checker for that class is not feasible and I did not build one.** The predicate
differs per subject; "read the content" has no common mechanical shape across a review record,
a catalog binding and a coverage denominator. Claiming otherwise would be the same error one
level up.

**One sub-class is mechanically checkable**: existence tests used as the *answer* to a
precondition in the loop's own protocol and scripts — `grep -c`, `wc -l`, `test -f`, `[ -e ]`
on a path whose content is what matters. I measured rather than assumed the case for it:
`.claude/cloud-setup.sh` carries four such tests, and **every one is paired with a content
check in the same condition** — three with a `sha256sum` comparison, one with an executable
probe. `.claude/GOAL-LOOP.md`'s two hits are both prose *about* F009. So today the repository
has **zero committed instances** for such a lint to bind to, and the one real instance lived in
a turn of reasoning, not in a file. A lint with no subject is a check nobody runs. **Not built,
and the measurement is why, rather than a shrug.**

## 11. What I did NOT do

1. Did not make the gate refuse unfinished records in the tree, and did not pin a ceiling on
   them. Reasoned in section 3; it conflicts with the mandated stub-push discipline.
2. Did not build the general "content not presence" checker, nor the existence-test lint.
   Section 10 gives the measurement behind both.
3. Did not teach the tool to read git refs. It reads the working tree, so a landing decision
   made against a branch that is not checked out is **unprotected**. GOAL-LOOP step 6 runs
   after the forward merge, with the branch checked out, so the binding is sound where it is
   placed — but the gap is real for any other workflow.
4. Did not verify the discriminator against records outside this repository.
5. Did not touch the root `Makefile`, any CI configuration, the ledger, `internal/deltaledger`,
   or `assurance/concurrency/results.json`.
6. Did not run AWS, benchmark, or Autobahn anything.
7. Did not re-run the corpus differential or the handshake exam: no behaviour-bearing path
   changed. The two files touched under `rust/` are `Makefile` and `README.md`; excluding
   those, the diff over `rust/`, `evidence/`, `assurance/`, `internal/` and `java-oracle/`
   against `4a2b9c6` is empty (exit 0). **Corrected while writing this section:** the first
   draft of the header stated that exclusion with only `':!rust/Makefile'`, which was false
   once `rust/README.md` was edited. Caught by re-running the command instead of re-reading
   the sentence.
8. Did not retro-fit records already on mainline. The two the census names are left exactly as
   their authors wrote them.

## 12. Residual for the owner

The census currently reads `records=41 unfinished=1 finished=40`. That one,
`normalization-collision-audit-WIP.md`, is a landed retained working-notes file whose branch
also landed a finished record. Whether retained working notes should keep living under
`drafts/self-review/` alongside landing records, or move to a sibling directory the census does
not read, is a naming decision and an owner call — not something to change quietly under a
detector that would then have one fewer subject.
