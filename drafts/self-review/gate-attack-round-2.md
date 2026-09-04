# Adversarial round 2 — plan-guard, fixture-guard, ledger-gates, oracle-hierarchy-gates

STATUS: COMPLETE for what it claims. Every exit code below was read from the
process that produced it, never from a log line saying PASS.

Base: mainline `8e6007d`, worked in an isolated worktree `/home/user/vjwp-attack2`
on branch `claude/gate-attack-round-2` with `.quarantine` symlinked in. The brief
was round 1's central finding applied everywhere else:

> All three checked that the DECLARATION was well formed, never that the CLAIM
> was still true. The two mechanisms that survived RE-DERIVE.

**plan-guard was defeated fifteen ways and fixture-guard four.** All nineteen are
now closed with a fix and with a test that fails when that fix is removed —
sixteen removals, each of which still compiles, because a mutation that breaks the
build proves nothing.
**ledger-gates has one coverage gap that is a HARD STOP, not a fix.**
**oracle-hierarchy-gates resisted everything I threw at it**, which was not much,
and I say below exactly how much.

## Scoreboard

| # | gate | attack | before | after |
|---|---|---|---|---|
| P1 | plan-guard | `path_exists` with `"path": ""` | exit 0 | exit 1 |
| P2 | plan-guard | `path_exists "."` | exit 0 | exit 1 |
| P3 | plan-guard | `path_exists "../../../etc/hostname"` | exit 0 | exit 1 |
| P4 | plan-guard | `grep` with `"pattern": ""` | exit 0 | exit 1 |
| P5 | plan-guard | `grep` of the plan for its own pattern text | exit 0 | exit 1 |
| P6 | plan-guard | `grep_absent "^gates:"` with no `(?m)` | exit 0 | exit 1 |
| P7 | plan-guard | `path_absent` of a path git never knew | exit 0 | exit 1 |
| P8 | plan-guard | `git_not_tracked` with an empty path | exit 0 | exit 1 |
| P9 | plan-guard | a `done` node standing on a `blocked` one | exit 0 | exit 1 |
| P10 | plan-guard | the empty plan, `nodes: []` | exit 0 | exit 1 |
| P11 | plan-guard | an `open` owner action carrying its ruling | exit 0 | exit 1 |
| P12 | plan-guard | duplicate `"depends_on"` key, either order | exit 0 | exit 2 |
| P13 | plan-guard | `"depends_on"` misspelled `"dependsOn"` | exit 0 | exit 2 |
| P14 | plan-guard | duplicate `"kind"` key on an evidence item | exit 0 | exit 2 |
| P15 | plan-guard | the ceiling rewritten to claim sufficiency | exit 0 | exit 2 |
| H1 | fixture-guard | >400 bytes before the `#[cfg(test)]` brace | exit 0 | exit 1 |
| H2 | fixture-guard | `#[cfg(test)] mod tests;` in its own file | exit 0 | exit 1 |
| H2b | fixture-guard | …with a later brace standing in for it | exit 0 | exit 1 |
| H5 | fixture-guard | a closing brace the mask ate | exit 0 | exit 1 |
| L2 | ledger-gates | delete an UNMIRRORED governance record | exit 0 | exit 0 — HARD STOP |
| L3 | ledger-gates | edit an UNMIRRORED governance record | exit 0 | exit 0 — HARD STOP |
| L4 | ledger-gates | ADD a record to the protected store | exit 0 | exit 0 — HARD STOP |
| D1 | plan-guard | delete a node outright | exit 0 | exit 0 — HARD STOP |
| O1 | oracle-hierarchy | drop a register entry | exit 1 | not defeated |
| O2 | oracle-hierarchy | rename a register key | exit 1 | not defeated |

H2b's "before" is the one cell not read from a live tree: it is read from the
deletion attack on its own fix (disable `bodylessModule` and the suite goes green
on that fixture alone), because running it live means mutating `rust/` and a
50-minute chain run was in flight. Every other cell in the table is a process
exit code from a run against a real tree.

---

## 1. plan-guard — rule 5 asked whether evidence HOLDS, never whether it could fail

Control first, so nothing below rests on a gate that does not bite. Three
mutations of the committed plan, `go run ./cmd/taskgraphctl -root .`:

```
CTL-1  flip one open owner action to ruled   exit 1  STALE_BLOCK T-us019-ac4
CTL-2  point a done node's path_exists at a missing file
                                             exit 1  EVIDENCE_NO_LONGER_HOLDS
CTL-3  knock a ready node's dependency back to blocked
                                             exit 1  READY_ON_UNFINISHED_DEPENDENCY x2
```

The gate bites. Baseline on the untouched tree is exit **0**,
`nodes=29 done=13 ready=5 in_progress=1 blocked=10 owner_actions=14 open=10`.

### 1a. Eight items that are TRUE of this tree and say nothing about any work

Rule 5's text is *"a `done` node must cite evidence the gate can CHECK, and that
evidence must still hold"*. Each item below is checkable, holds on every run, and
was the ONLY evidence on a real done node when it exited **0**:

```
{"kind":"path_exists","path":""}                       -> stats the repository root
{"kind":"path_exists","path":"."}                      -> same
{"kind":"path_exists","path":"../../../etc/hostname"}  -> a file outside the tree
{"kind":"grep","path":"README.md","pattern":""}        -> the empty regex matches everything
{"kind":"grep","path":"assurance/plan/task-graph.json",
 "pattern":"ZZ_ONLY_MY_OWN_PATTERN_ZZ"}                -> the pattern is IN the file it greps
{"kind":"grep_absent","path":"rust/Makefile","pattern":"^gates:"}
{"kind":"path_absent","path":"no/such/file/ever"}
{"kind":"git_not_tracked","path":""}
```

Two deserve naming. The **self-satisfying grep** holds by construction: the plan
is a JSON file, the pattern is stored in it as a string, so any `grep` of the plan
for a token nobody else uses matches its own declaration forever. And
**`grep_absent "^gates:"` is the round-1 regex class in its fail-OPEN polarity.**
Round 1 found four patterns that silently never matched because Go anchors `^` to
start-of-TEXT without `(?m)`; there, never matching was a false negative. Here,
`rust/Makefile` plainly contains a `gates:` line, `(?m)^gates:` matches it, and
`^gates:` cannot — so the ABSENCE is guaranteed and the item can never fail. The
same mistake that made a detector go quiet one gate over makes evidence
unfalsifiable here.

**Fix — rule 6.** `evidenceShapeProblem` refuses evidence whose verdict does not
depend on the tree, before rule 5 counts it: an empty or root-resolving path, a
path that leaves the tree, an empty pattern, a grep of the plan itself, and an
anchored pattern with no `m` flag. `path_absent` and `git_not_tracked` are claims
about a REMOVAL, so the gate asks git whether there was ever anything to remove —
both live absence claims (`.quarantine`, `pinconsumerctl`) resolve inside this
checkout's 526 commits, and `no/such/file/ever` does not. A refused item is
reported as `VACUOUS_EVIDENCE` **and does not count toward rule 5**, so each of
the eight now produces two findings and exit **1**.

The caveat is stated rather than guarded: in a clone shallow enough that a removal
sits below the graft boundary, the absence check reports "never there" for a path
that was, and the gate fails. That is a loud refusal, not a silent pass.

### 1b. How weak is "weak but true"? Measured, not asserted

The disclosed ceiling admits the gate checks that evidence HOLDS, not that it is
SUFFICIENT. The brief asked for a measurement. For each of the 13 done nodes I
destroyed the work it names while leaving its citations true:

| node | what I did to the work | gate |
|---|---|---|
| T-record-guard | deleted `scan.go` AND `polarity.go` — the whole scanner | exit **0** |
| T-record-guard-escapes | emptied the fixture, deleted the fix it pins | exit **0** |
| T-go-suite | moved `EXCLUSION_NO_LONGER_FAILS` into dead code | exit **0** |
| T-pin-guard | moved `STALE_ALLOWANCE` into dead code | exit **0** |
| T-task-graph | deleted rule 5 from taskgraphctl, kept the token | exit **0** |
| T-F016-gate | replaced 1453 lines with a 3-line comment | exit **0** |
| T-plane-citation | corrupted every field but the cited line | exit **0** |
| T-record-prose-bound | gutted `recordbounds.go` to `package normcollide` | exit **0** |

Five nodes stay green with **the implementation of the work destroyed** — two of
them (`T-record-guard`, `T-record-guard-escapes`) with the scanner's source files
deleted outright, the rest with the cited identifier moved into dead code. The
files the citations NAME must still exist, which is the whole of what
`path_exists` establishes. A sixth survives its detector becoming a comment,
because its pattern is `ADAPTER_PROTOCOL_BRANCH|protocol_branch` and a three-line
comment carries either. The gate that certifies plan-guard itself as done is
satisfied by a `grep` for `UNVERIFIABLE_DONE` in plan-guard's own source, which
any dead mention of that string satisfies just as well.

The other seven cite a value the work produced, and six were broken by moving it:

```
"sequence": 59  -> 60        exit 1     "close_code":1009 -> 1002   exit 1
handshake 29    -> 28        exit 1     /pinconsumerctl removed     exit 1
"29 distinct scored observations" -> 26 exit 1
"nearest_declaration_line": 1003 -> 2003 exit 1
```

The seventh is `git_not_tracked .quarantine`. I did not perturb it: staging that
symlink is F011 itself, and the brief forbids it. Its polarity is covered by a
unit test instead.

**Three of those value greps were prefix-unanchored** and drifted upward in
silence: `"sequence": 59` matched `591`, `"close_code": ?1009` matched `10091`,
`"nearest_declaration_line": 1003` matched `10035`, all exit **0**. All four
numeric patterns now carry `\b`. This changes no verdict today.

The measured numbers — 5, a 6th, 7 — are now IN the ceiling, replacing the
unquantified "may cite a weak-but-true fact and pass".

### 1c. `done` was a total exemption from the structural rules

Rule 3 reads `ready` and `in-progress`; rule 4 reads `blocked`. Nothing read
`done`. So a finished node standing on a blocked prerequisite passed at exit
**0** — and the cheapest way past `READY_ON_UNFINISHED_DEPENDENCY` was always to
declare the node done, which rule 5 makes easy given 1a. New finding
`DONE_ON_UNFINISHED_DEPENDENCY`.

A design hole this exposes and I did not fix: **there is no state for "waiting on
an unfinished dependency"**. `ready` and `in-progress` both fail rule 3, `blocked`
requires an owner action or it is `BLOCKED_ON_NOTHING`, and `done` now fails rule
3's new twin. A node genuinely waiting on another node must therefore invent an
owner action. That is a schema decision, so it is left as one.

### 1d. The rot rule 4 exists for, arriving one field earlier

Rule 4's own comment: *"a ruling arrives from outside and nothing here notices"*.
It watches the NODE. It does not watch the owner action: writing the owner's
answer into `ruling` and leaving `state: "open"` exited **0** with no finding,
and every node blocked on it stays blocked forever with the answer sitting in the
file. `RULING_WITH_NO_CONTENT` already refuses the mirror image (`ruled` with no
ruling); `OPEN_WITH_A_RULING` now refuses this one.

### 1e. Two edits the JSON parser made invisible

`encoding/json` keeps the LAST of duplicate keys and reports nothing:

```
"id": "T-remaining-gates-attacked",
"depends_on": [],                     <- inserted; the real list follows
```

exit **0**, census byte-identical. Reversed order: also exit **0**. And
`"depends_on"` misspelled `"dependsOn"` is not caught by Go's case-insensitive
fallback — the underscore differs — so every dependency of that node vanished at
exit **0** with the same census. The same duplicate-key trick on `"kind"` is the
**only** way I found to make a `command` evidence item behave as a checkable one.
`parse` now walks the token stream and refuses a duplicate key by path, and sets
`DisallowUnknownFields`. All three are exit **2** with the object named.

### 1f. The gate printed a disclosure the audited artifact wrote

`gate=task-graph ceiling=...` was `graph.Ceiling` — read from the plan. Rewriting
it to *"This gate verifies that every done node's evidence is SUFFICIENT"* exited
**0** and the gate printed the rewrite as its own honesty statement. The ceiling
is now a constant in `cmd/taskgraphctl/main.go`; the plan mirrors it and a
difference is a load refusal.

### 1g. What plan-guard did NOT lose

- **The cycle detector held.** A self-dependency, a three-hop cycle among `done`
  nodes, and a two-node cycle both of whose nodes are `done` are each reported at
  exit **1**; an acyclic diamond stays silent at exit **0**. I found no ordering,
  colouring or state combination that hides a cycle.
- **`command` cannot smuggle a checkable kind by carrying its fields.** An item
  `{"kind":"command","cmd":"…","path":"…","pattern":"…"}` on a done node gives
  `UNVERIFIABLE_DONE`, exit 1. Kind is a map lookup on an exact string; the
  case-insensitive matching in `encoding/json` applies to FIELD NAMES, not values.
  The only smuggle was the duplicate-key one in 1e, now refused at load.
- **`STALE_BLOCK` could not be evaded except by an edge that looks real.** Adding
  a dependency on any non-done node, or naming a second still-open owner action,
  keeps a node blocked past its ruling — but both are legitimate plan shapes, so
  the finding is the forgery COST, not a defect. I am recording it as measured:
  the cost is one line of JSON.

### 1h. Deleting a node is silent — HARD STOP

`nodes=29` is printed and bound to nothing. Deleting one leaf `ready` node gave
exit **0**, `nodes=28`. Deleting all nine blocked nodes and their owner actions
gave exit **0**, `nodes=20 owner_actions=5 open=1` — a plan reporting one open
owner action where there were ten. Deleting a `depends_on` edge is likewise silent.

Only the floor is fixed: the empty plan, which used to print
`nodes=0 … result=PASS`, is now `EMPTY_PLAN`. That is the shape gosuitectl closed
one gate over in round 1 and this gate still had.

**Binding the count needs an external anchor** — every open finding in
`drafts/self-review/findings/` becoming a node, say — and that introduces a
denominator the gate would then be measured against. **Not mine to create.**

---

## 2. fixture-guard — a comment that was true of nothing

`regions.go` said, of a file carrying `#[cfg(test)]` whose module body it could
not locate: *"which is reported by the caller rather than silently treated as
nothing to scan"*. The caller was

```go
regions = cfgTestRegions(maskSource(src))
if len(regions) == 0 {
    return nil
}
```

— a silent skip that does not even reach `res.files++`. Four ways past it. Three
were run against a real tree and each exited **0** with `files=49 loops=310`
**UNMOVED**, so the only trace was a census number nothing asserts; the fourth
(H2b) is established by the deletion attack on its own fix. The control, an
inline `#[cfg(test)] mod tests { }` holding `assert!(polls < 4096, …)`, is exit
**1** with the violation named and `files=50 loops=311`.

- **H2 is ordinary Rust.** `#[cfg(test)] mod tests;` with the fixture in
  `tests.rs`. That file carries no `#[cfg(test)]` of its own, so it is skipped
  whole. No live crate here uses the idiom, which is luck.
- **H2b is the dangerous form.** With any later brace in the file, `nextBrace`
  adopts an unrelated function body as the fixture region: production code
  scanned as a fixture, the real fixture never opened, and PASS.
- **H1** is >400 bytes of attributes or comments before the `{`, which is
  `nextBrace`'s deterministic search bound, hit silently.
- **H5** is a closing brace the mask ate. Lower severity: the file would not
  compile — though an orphan `.rs` under `rust/` is never compiled by cargo and
  is still scanned by this tool.

**Fix.** `cfgTestRegions` returns a GAP for each, the gate prints
`UNSCANNED <file>: <reason>`, `unscanned=` joins the census line, and a nonzero
count fails the gate. A gap is not a liveness violation; it is a statement that
the rule was not APPLIED where it should have been, which is what this tool's
honesty contract (*"a scanner that matched nothing and reported PASS is theatre"*)
already refuses to leave unsaid. Live tree after the fix:
`files=49 loops=310 violations=0 unscanned=0`, exit **0** — identical.

One residual, unfixed and unexercised: a `#[cfg(test)]` attached to anything
OTHER than a module — `#[cfg(test)] use …;`, say — still falls through to
`nextBrace`, which adopts the next brace at depth zero as if it were the module's.
That is pre-existing and my change does not make it worse, but it is the same
defect as H2b in a different dress. All **16** `#[cfg(test)]` occurrences under
`rust/` today sit on a `mod` line, so nothing exercises it. Closing it means
requiring the attribute to be followed by `mod`, which would refuse a shape no
crate here uses; I left it and named it instead.

What fixture-guard did NOT lose: its polarity self-check (`cases=7 firing=4
silent=3`) is the re-derive mechanism of the family that survived round 1, and I
did not attack the A/B/C shape detectors themselves, the waiver ceiling, or
`budget.go`'s production-budget anchors.

---

## 3. ledger-gates — the mirror is sound and covers 7 of 64 — HARD STOP

`deltaledgerctl --check` is exit **0** on the tree and reports
*"7 governance record digest(s) recomputed from the protected store and matched"*.
The mechanism re-derives, and it resisted both controls:

```
L1  delete the MIRRORED ledger-frozen-prefix decision   exit 1  RECORD_ABSENT
L5  edit one byte of that same record                   exit 1  RECORD_DRIFTED
```

`evidence/governance/decisions/` holds **64 records**. Seven are mirrored. The
other **57** are unbound:

```
L2  delete us008-owner-attestation-2026-08-27.json      exit 0, message identical
L3  insert a key into its bytes                         exit 0, message identical
L4  add zz-forged-owner-decision.json to the store      exit 0, message identical
```

The mirror's derivation is honest about its own basis — records the ledger's
hashed rationales cite, plus the ones the gate design rests on. The **claim that
overstates it is in `rust/Makefile`**: *"Deleting or editing a governance record
fails this target."* That is true of 7 of 64 and false of 57.

**Not fixed, and this is a hard stop twice over.** Widening the mirror moves the
declared count `7`, which is a measurement denominator; and it is a DISCLOSURE
decision, because the records are deliberately uncommitted from a public
repository. Correcting only the Makefile sentence would be a documentation edit
that pre-empts the owner's answer about coverage. **Owner action:** decide whether
the mirror covers the store or the citations, then fix the sentence to match.

---

## 4. oracle-hierarchy-gates — not defeated, and here is how little I tried

`oraclerankctl --check` is exit **0**:
*"640 propositions adjudicated; 589 Java/Rust agreements, 39 of them overridden by
a higher oracle and every one enrolled"*. Two probes:

```
O1  drop one rank_binding from the committed register   exit 1  schema refusal
O2  rename one key in the register                      exit 1  schema refusal
```

Both refused before any adjudication ran. Reading the sources, the design is the
one that held in round 1: rank bindings hash their artifacts on every run, the
register is recomputed and is never an input to its own recomputation, and the
rank-three public-tier opinions are DERIVED on the run rather than read. The one
declaration-shaped surface I noticed and did not attack is the prose in each
binding (`Strength`, the narrative `basis` strings): those are checked for being
non-empty and for saying what they are not bound to, which is a form check on
text, exactly the class round 1 named. **A gate I could not defeat is a real
result and I am recording it as one** — with the qualification that two schema
probes are not an attack on adjudication, enrolment, join degeneracy, the
collision analysis or the neutrality derivation, none of which I touched.

---

## 5. The `^`-without-`(?m)` sweep

The brief asked for more of the class that shipped four silent non-matchers. I
scanned all **193** `regexp.MustCompile` literals in the repository. After
stripping escapes and character classes (`[^=]` is not an anchor), **80** use `^`
or `$` with no `m` flag. **56** of those are fully anchored `^…$` — a whole-string
validator, correct on a token. That leaves **24** partially anchored, which is the
risky shape, and I read every one:

- **8** use the explicit `(?:^|[\s(",])` idiom, which permits a non-line-start by
  construction: six in `internal/deltaledger/observations.go`, two in
  `cmd/fixtureguardctl/scan.go`.
- **16** are applied to one already-split line or one token, and they account for
  the 24 exactly: `recordguardctl`'s title, status, fence and blockquote patterns
  plus its `supersededRe` (**5**, all inside a `for i, line := range lines`);
  `fixtureguardctl`'s condition-shape matchers in `scan.go` and `budget.go`
  (**5**, on a trimmed comparison string); `internal/formalplan/model.go`'s
  `mpDefinitionStart` on `line`; `internal/formalcoverage/coverage_test.go:293`;
  `internal/fuzzpin/campaign.go`'s cargo-outcome pattern, applied after
  `strings.Split(output, "\n")`; `internal/lab/inventory.go`;
  `concurrencyresults.go:4128` on `rustc --version` output; and
  `internal/lab/supersession.go`, which says so in its own comment: *"ANCHORED at
  the start of the string it is applied to"*.

**I found no new instance of the round-1 defect in Go source.** That is a negative
result and I am reporting it as one.

The class reappeared somewhere else instead: in plan-guard's authored evidence
patterns, where a mis-anchored `grep_absent` fails OPEN. That is P6, and rule 6
now refuses it. The lesson generalises: this repository's regexes are correct
where a programmer wrote them and dangerous where a DATA FILE supplies them,
because nothing type-checks a pattern in JSON.

---

## 6. The shared shape, one round on

Round 1: *an exemption should be re-derived, not re-read.* Round 2 says the same
thing about EVIDENCE, and adds the sharper half:

**Re-deriving a fact is not enough if the fact is unfalsifiable.** plan-guard did
re-derive. Every one of the eight items in 1a was genuinely recomputed from the
tree on every run — and every one of them was going to come out true no matter
what happened to the repository. The gate had moved from checking a declaration's
FORM to checking a fact, which is the right move, and then landed on facts that
carry no information. A checkable claim and a falsifiable claim are different
things, and only the second is evidence.

The three narrower patterns from round 1 all recurred, unchanged:

- **The census number that nobody asserts.** `nodes=29`, `files=49 loops=310`,
  `7 governance record digest(s)`. Every silent attack in this document is
  visible only as one of those moving by one, or not moving at all.
- **The prose that is never validated against the world.** The plan's `ceiling`,
  the Makefile's "deleting a governance record fails this target", the oracle
  bindings' `basis` narratives.
- **Each gate delegates to another without checking it runs.** plan-guard's
  `command` evidence names `make -C rust gates`; plan-guard is inside
  `make -C rust gates`.

And one new pattern, which is really an old one: **the same author fixes a hole in
gate A on Monday and ships it again in gate B on Tuesday.** The empty-run-set
refusal was added to gosuitectl in round 1 and was missing from taskgraphctl,
written the same day by the same hand. The `(?m)` lesson was learned in
record-guard and re-lost in the plan data. A defect class does not stay fixed
where it was found.

---

## 7. What I did NOT attack

- **No owner gates.** No AWS run, no benchmark, no Autobahn, no `internal/lab`.
- **Nothing from round 1 was re-attacked**: `recordguardctl`, `gosuitectl`,
  `pinconsumerctl dangling`. I did not touch `pinconsumerctl consumers` either.
- **`adapter-linkage` and `protocol_branch.go` were excluded by the brief** as
  just-hardened, and I honoured that: I read `protocol_branch.go` only to build
  the T-F016-gate destruction, and I restored it.
- **The other `ac1-gates` members were READ, not attacked**: `forbid-unsafe`,
  `dependency-inventory`, `msrv`, `license`, `audit`, `lockfile`, `canaries`. Two
  readings I could not confirm by attack, because attacking them means mutating
  the tree under a 50-minute chain run that was in flight:
  - `gateForbidUnsafe` collects crate roots of kind `lib` and `bin` only. Each
    file under a crate's `tests/` directory is its own crate root of kind `test`.
    There are **32** such crate roots across four crates and **9** carry
    `#![forbid(unsafe_code)]`, so 23 are outside the scan surface. Stated as a
    reading, confirmed only by `ls rust/*/tests/*.rs` and `grep -l`, not by
    writing `unsafe` into one — that needs a tree mutation, and a 50-minute chain
    run was in flight. It is the same shape as round 1's B2/B3.
  - `compareDependencyInventory` requires `unsafe_usage` to be non-blank. It is
    prose, never compared to the dependency. That is round 1's B5 unattacked.
- **ledger-gates beyond the governance mirror**: I did not attack the frozen
  prefix, the observation envelope and uniqueness checks, the schema validation,
  the corpora re-derivation or the legacy-record adjudications.
- **oracle-hierarchy-gates beyond two register probes**, as set out in §4.
- **The Rust gates**: `fmt-check`, `clippy`, `test`, `test-release` were run as
  part of the chain and never attacked.
- I did not add or remove any node or owner action in the task graph, including
  for the owner actions this document raises. The plan's node set is the owner's,
  and §1h is why moving it is not mine.
- **The owner actions this round leaves open**, none of them taken here: whether
  the governance mirror covers the store or the citations (§3); whether anything
  should bind the plan's node count (§1h); and whether the plan schema needs a
  state for "waiting on an unfinished dependency", which today has no legal one
  (§1c).

## 8. Process

Isolated worktree throughout; `.quarantine` symlinked, never staged. **No `pkill`
was used.** My own chain run was stopped twice — once to correct the ceiling
before it shipped overstated, once to consolidate the remaining edits into a
single authoritative run — each time by `kill -TERM` on a pid list filtered by
`readlink /proc/<pid>/cwd` under my own worktree, with a second scan confirming
nothing of mine survived and nothing of anyone else's was touched. A partial run
that was terminated is not a reading and none is cited as one; §10 is the run that
completed. Logs live in my own worktree, not the shared scratchpad.
`df -h /home/user` was read before every diagnosis and before every restart: 8.9G
free at the start, 7.5G by the final run, with other worktrees building
throughout, so no timing here is a performance reading.
Mutations were applied to a file, run, and reverted with `git checkout -- .`
followed by a `git status --porcelain` assertion; that assertion is what caught me
having reverted my own uncommitted ceiling edit mid-experiment, which is why the
ceiling was committed before the last two perturbations were replayed.

Every fix carries a deletion attack. Twelve on `taskgraphctl` and four on
`fixtureguardctl`, each of them compiling — `false &&` on the deciding condition,
or an early `return nil` — because a mutation that breaks the build proves
nothing. Each is caught, and one was NOT at first: disabling the bodyless-module
rule left the suite green, because the brace-bound gap caught the same fixture by
accident. The test now carries H2b, the form where a later brace stands in for the
module, and the mutation is caught.

## 9. Base, and mainline moving under this review

This targets `8e6007d`. Mainline reached `07c2a86` while the review was in
flight, adding the vendor-agnostic portplan fix, its record, and two plan edits —
one of which is the node for THIS task.

`git diff --stat 8e6007d origin/… -- cmd/taskgraphctl cmd/fixtureguardctl
cmd/deltaledgerctl cmd/oraclerankctl cmd/rustgatectl internal/oraclerank
internal/deltaledger rust/Makefile` is **EMPTY**: not one line of the gate code
this review reads changed under it, so no finding here is stale. What mainline
touched is `cmd/gosuitectl/main.go` (round 1's target, not this one),
`internal/portplan`, `.claude/GOAL-LOOP.md`, a new record, and the plan DATA.

The plan data is the one place my branch and mainline both wrote, so I checked
the merge against the new rules rather than assuming: mainline's 30-node plan,
with my `ceiling` line spliced in as a merge would leave it, produces **no**
`VACUOUS_EVIDENCE`, `DONE_ON_UNFINISHED_DEPENDENCY`, `OPEN_WITH_A_RULING`,
duplicate-key, unknown-field or ceiling refusal. Its three new evidence items are
a real `path_exists`, an unanchored `grep`, and an unanchored `grep_absent`, all
of which rule 6 accepts. The only findings the preview produced are three
`EVIDENCE_NO_LONGER_HOLDS` for `T-jdk-vendor-agnostic`, which is correct and
expected: that node's evidence describes mainline's TREE, and my worktree's tree
is `8e6007d`. **The merge is compatible; it is not tested here, because testing it
means integrating, and integrating is not this task.**

## 10. Files changed

- `cmd/taskgraphctl/main.go` — rule 6 (`evidenceShapeProblem`, `anchorsLines`,
  `gitEverKnew`), `EMPTY_PLAN`, `DONE_ON_UNFINISHED_DEPENDENCY`,
  `OPEN_WITH_A_RULING`, `parse` with duplicate-key and unknown-field refusal, and
  `CeilingText` as a constant the plan must mirror.
- `cmd/taskgraphctl/main_test.go` — eight vacuous shapes and six accepted ones,
  the three structural rules, the three document-integrity refusals, and the
  cycle set including the self-loop and the acyclic diamond.
- `assurance/plan/task-graph.json` — the measured ceiling; `\b` on four value
  patterns.
- `cmd/fixtureguardctl/regions.go` — `cfgTestRegions` returns gaps,
  `bodylessModule`, `braceSearchLimit` named and reported when hit.
- `cmd/fixtureguardctl/main.go` — `result.unscanned`, the `UNSCANNED` lines,
  `unscanned=` in the census, and the failure it now causes.
- `cmd/fixtureguardctl/main_test.go`, `scan_test.go` — four unreachable-body
  fixtures and the inline-module control.

## 11. The chain

`make -C rust gates` was run detached, writing its own exit code to a file rather
than printing it: **exit 0**, read from that file. No `result=FAIL`, no
`verdict=FAIL`, no `*** Error` and no `FAIL` anywhere in its 1,864 lines. (`bad-scaffold` fails clippy on
purpose; that is the canary's declared polarity and the gate reports
`gates_passed=8/8` for it.)

```
gate=fixture-liveness-guard step=scan files=49 loops=310 violations=0 waivers=0
    max_waivers=0 budget_waivers=0 max_budget_waivers=0 unscanned=0
gate=fixture-liveness-guard result=PASS
gate=record-content-precondition step=census records=64 unfinished=0 superseded=1 finished=63
gate=record-content-precondition result=PASS
gate=pin-dangling json_artifacts=1997 unparsable=0 candidates=0 explained=51 covered=23 allowed=11
gate=pin-dangling result=PASS
gate=task-graph nodes=29 done=13 ready=5 in_progress=1 blocked=10 owner_actions=14 open=10
gate=task-graph result=PASS detail="every done node's evidence re-derived; 5 ready,
    10 blocked on 10 open owner action(s)"
gate=go-suite packages=62 run=60 excluded=2 with_tests=45 no_test_files=15 unbuilt_test_files=5
gate=go-suite result=PASS
ac1-gates verdict=PASS gates_passed=8/8
```

The two gates this review changed print exactly what they printed before it:
`files=49 loops=310 violations=0` with `unscanned=0` newly beside it, and
`nodes=29 done=13 ready=5 in_progress=1 blocked=10 owner_actions=14 open=10`.
**No denominator moved.** `records=64` is this document joining the census, and
`json_artifacts=1997`, `packages=62 run=60` are mainline's numbers at `8e6007d`,
not mine — this branch adds no JSON artifact and no Go package.

The chain ran on the working tree at commit `130dd44`. Three later commits touch
only this document's prose, and one of them landed while the chain was still in
`cargo test` — after `record-guard`, the one gate that reads it, had already read
it. So rather than assert that a prose edit cannot change a verdict, I re-ran the
gates that read this document and the plan, on the final tree, and read their
exit codes from the processes:

```
go test -count=1 ./cmd/recordguardctl/                     exit 0
go run ./cmd/recordguardctl gate -root .                   exit 0   records=64
go run ./cmd/recordguardctl precondition <this record>     exit 0   READS-FINISHED
go test -count=1 ./cmd/taskgraphctl/                       exit 0
go run ./cmd/taskgraphctl -root .                          exit 0   nodes=29 done=13
```

