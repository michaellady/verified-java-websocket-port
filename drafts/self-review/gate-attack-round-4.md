# Adversarial round 4 — oracle-hierarchy-gates, the eight unattacked ledger rules, fmt-check and clippy

STATUS: COMPLETE for what it claims. Every exit code below was read from the
process that produced it, never from a log line saying PASS. Where an attack was
caught by a SIBLING gate rather than by the one I was attacking, I say which.

Base: `claude/feature/verified-java-websocket-port` at `436994f`, worked in an
isolated worktree `/home/user/vjwp-attack4` on branch
`claude/gate-attack-round-4` with `.quarantine` symlinked in and never staged.

Scope is round 3's own section 8, verbatim: the gate nobody has defeated, the
eight ledger rules nobody attacked, and the two Rust gates that were "run, not
attacked". The organising question is the one three rounds have converged on:

> Does the check RE-DERIVE its claim, or does it verify that a DECLARATION is
> well formed?

**Five attacks got a bad tree past a gate at exit 0.** Three are on
`oracle-hierarchy-gates` and are now closed with a fix and a test that fails
when the fix is removed. Two are on `fmt-check` and `clippy` and are REPORTED
rather than fixed, because closing them needs a ceiling over a population that
is not empty. One further defect is LIVE IN THE COMMITTED TREE — not an attack I
planted, a hole I walked into — and is an owner action for the same reason.

Every one of the three oracle attacks left the printed census
**byte-identical**: `640 propositions adjudicated; 589 Java/Rust agreements, 39
of them overridden by a higher oracle`. That was the brief's prediction and it
held: the dangerous bypass here is the one that moves no number.

## Scoreboard

| # | gate | attack | before | after |
|---|---|---|---|---|
| O4a | oracle-hierarchy | rank three takes rank one's artifact group in both families it speaks in | exit 0, census identical, a BLOCKING finding deleted | exit 1 |
| O4b | oracle-hierarchy | rank one is split off rank four's artifact group in the handshake family | exit 0, census identical, co-votes inflated 18 -> 50 | exit 1 |
| O5 | oracle-hierarchy | one lookup row no committed case reaches is changed, source table edited and document re-rendered | exit 0, census identical, both join-degeneracy disclosures deleted | disclosure survives, statement names the unreachable counterexample |
| C1 | fmt-check | `#[rustfmt::skip]` on a deliberately mis-formatted item | exit 0 | OWNER ACTION |
| C2 | clippy | `#[allow(clippy::needless_bool)]` on an item that trips it | exit 0 | OWNER ACTION |
| B1 | ledger-gates | (not an attack) a rebuildable record proposal sits unledgered and outside the rule's population | exit 0 today | OWNER ACTION |
| L-lm | ledger-gates | O5's edit applied to the evidence document alone | exit 1 | held |
| O-rank4 | oracle-hierarchy | (not an attack) rank four declared CONTENT_BOUND while two of its four families record it weaker | exit 0 today | exit 1, and the register now discloses it |

"Census identical" is a byte comparison against the baseline line quoted in §6,
not an impression.

---

## 1. oracle-hierarchy-gates — what it actually checks

Round 3 read four files and ran one evidence probe. Here is the whole surface,
because naming it is half the work.

`make -C rust oracle-hierarchy-gates` runs exactly one command:
`go run ./cmd/oraclerankctl --root . --check`. That does four things in order.

1. **`ValidateAgainstSchema`** compiles the committed JSON Schema and validates
   the committed register against it, failing closed on a missing schema.
2. **`Verify`** recomputes the whole register from the evidence and refuses any
   byte difference. The committed register is never an input to its own
   recomputation.
3. **`VerifyRules`** re-checks the adjudication rules against the evidence
   independently of the document: every proposition adjudicates; the override
   list is exact in both directions; `ParityFromJavaRustAgreement` refuses on
   every overridden agreement and names the governing rank; the pure
   rank-four-against-rank-five family exhibits no override; no rank is declared
   and then silent, and no rank declared ABSENT votes.
4. It prints the census and exits.

**The gate does not run `go test ./internal/oraclerank/`.** `go-suite` does, and
that distinction decides two of the three findings below.

**What is genuinely anchored, and one correction to round 3.** Round 3 wrote
that "nothing asserts 640, 589 or 39". The first of those three is wrong. The
census sizes are Go constants the census asserts on every run and refuses to
proceed without — `PublicCorpusSize`, `HandshakeCorpusSize`, `DiffProbeCount` in
`internal/oraclerank/census.go` and `ExpectedCaseCount` in
`internal/divergencesweep/reports.go` — and the proposition total is their fixed
combination (twice the Autobahn case count, once each for the other three). A
corpus that grew or shrank fails on the constant before it reaches the total. I
measured that rather than reading it: with one line removed from the committed
handshake corpus and immediately restored byte-identical, the gate refuses
before it adjudicates anything —

```
oraclerankctl: handshake-verdict: corpora/handshake/cases.jsonl holds 48 cases, want 49
EXIT=1
```

— and the restored tree is back at exit 0 with the census line unchanged. So the
proposition count IS pinned. The agreement count and the override count are not,
and `OA-oracle-census-anchor` stands unchanged for those two. I did not touch
it: binding them creates a denominator.

**What the register carries beyond the adjudication**, and what nobody had
examined: an independence probe over all ten ordered rank pairs; a collision
analysis (`collision.go`) measuring how many distinguishable answers a pair's
co-votes carry; a join-degeneracy analysis (`joindegeneracy.go`) asking whether
the census's own lookup makes disagreement impossible; a per-rank binding with
recomputed artifact digests; and computed findings derived from those numbers.
The adjudication is honest — round 3 was right about that, and I did not break
it. **The analyses around it were the soft part, and all three of my successful
attacks are on them.**

### 1a. The artifact group was a free string, and it decides everything the probe says (O4a, O4b)

`IndependenceProbe` scores a rank pair inside a family only when the two ranks'
`ArtifactGroup` values differ; where they match, it returns
`NOT_PROBEABLE_SHARED_DERIVATION` and refuses to score, on the stated ground
that "reporting such a pair as NOT_DISTINGUISHED would be a manufactured
finding". `ArtifactGroup` was a string literal written beside the rank in
`census.go`. Nothing derived it from anything.

**O4b — split a group that the evidence does not split.** In the handshake
family, rank one is read from the `rfc_verdict` field and rank four from the
`java_observable` field of the SAME committed document, and both declare the
same `paths` list. They therefore shared a group and the probe declined to score
them. I gave rank one a group of its own — one string, one line:

```
-				ArtifactGroup: "handshake-live-mapping",
+				ArtifactGroup: "handshake-live-mapping-rfc-reading",
```

Regenerated, `--check` exits 0 with the census line byte-identical, the set of
findings unchanged, and the register now saying:

```
PAIR 1v4: DISTINGUISHED co_votes 50 dis 18
NOTE: rank1-rfc6455 differed from rank4-java-observation on 18 of 50 independently sourced shared propositions ([public-corpus-ready-state]).
    handshake-verdict NOT_DISTINGUISHED 32 0
```

Thirty-two of those "independently sourced shared propositions" are one file's
`rfc_verdict` against the same file's `java_observable`. `go-suite` does catch
this one, and I checked — but it catches it for the WRONG REASON, which is the
failure mode this round's method section warns about. The test that goes red is
`TestRedSchemaRefusesASharedDerivationProbeThatScoresDisagreements`, and its
message is `schema_test.go:121: no shared-derivation family probe to attack`: it
is a red-schema test that needs a shared-derivation probe as a FIXTURE, and my
edit removed the only one in the register. No test asserts the property. Split a
group in a tree that had two shared-derivation probes and nothing would fire.

**O4a — merge a group the evidence does not merge, and delete a BLOCKING
finding.** Rank one versus rank three is the pair the register calls
EMPIRICALLY INDISTINGUISHABLE, severity BLOCKING. I gave rank three rank one's
group in both families rank three speaks in: `handshake-corpus` ->
`handshake-live-mapping` and `rfc6455-mechanical-derivation` ->
`public-rfc-divergence-census`. Regenerated, exit 0, census byte-identical, and
the finding list moves:

```
< ORACLE-RANK-COVOTE-COLLISION-1-3-public-corpus-ready-state DISCLOSURE
< ORACLE-RANK-INDISTINGUISHABLE-1-3 BLOCKING
> ORACLE-RANK-UNPROBEABLE-1-3 DISCLOSURE
```

A BLOCKING finding downgraded to a DISCLOSURE by editing two strings, with every
printed number unchanged. `go-suite` catches this one properly, by assertion
(`TestTheOneToThreeIndistinguishabilityFindingIsInTheCommittedRegister`), but
the gate under attack did not.

**THE FIX (F1)** is in the production path, `checkArtifactGroupPartition` called
from `CheckFamilyRules`, so `oracle-hierarchy-gates` itself now refuses. The
rule re-derives the group PARTITION from the declared paths, in both directions:
inside one family, two ranks that declare the same artifacts may not be split
into two groups, and two ranks that declare different artifacts may not be
merged into one. A group split now costs a path split, and the paths are the
files the rank bindings hash on every run. Both directions of the refusal are in
§5.

### 1b. The join-degeneracy analysis could be blinded by a row nothing reads (O5)

`joindegeneracy.go` computes whether the census's own lookup makes disagreement
between two ranks structurally impossible. It computed that over the WHOLE
lookup table, deliberately, and said so: "a corpus that grew a new case must not
be able to change the answer". That width is right, and it was also the way past.

The committed corpus reaches only some of the table's keys. I took one row it
does NOT reach — `server_response` / `HS_OBS_FOLD`, whose RFC verdict and Java
observable are both `reject` — and made both `accept`. That is consistent with
every fail-closed assertion the family makes, including the one requiring
`divergent` and a `conditional` observable to coincide exactly. The whole-table
analysis then found a counterexample, reported "Disagreement is POSSIBLE ...
Agreement measured here is therefore a measurement" for BOTH pairs, and DELETED
both `ORACLE-RANK-JOIN-DEGENERATE` findings from the register. The surviving
BLOCKING finding then read:

```
... READ THE 66 WITH CARE: 17 in public-corpus-ready-state that carry one
distinct answer between them, leaving 49 co-vote(s) that could have come out
either way.
```

Forty-nine co-votes described as free to vary, when every one of them was still
forced by the join at a key the corpus does reach. Exit 0, census byte-identical.

I ran it in both polarities. Edited into the evidence document alone, ledger's
`live-mapping-source-binding` REFUSES it:

```
REFUSED: evidence/us005-handshake-live-mapping.json is not byte-identical to
corpora.HandshakeVerdictMapping(), the source-derived table it is rendered from.
```

So I did what the author of such a change actually does: edited the source table
in `internal/corpora`, re-rendered the document, and re-ran. `live-mapping-source-binding
PASSED` and `oraclerankctl --check` exited 0. `go-suite` catches this one, by
assertion, in `TestHandshakeJoinIsDegenerateOnTheCommittedMapping` — again, the
gate under attack did not.

**THE FIX (F2)**: the analysis now computes the property twice — over the whole
table AND over the keys the census's own corpus actually joins on, using the
same key function the propositions are built with — and the DISCLOSURE fires on
the second. A counterexample no case reaches can no longer make an observed
agreement into a measurement; it changes the statement text instead, and the
statement now names it. New schema fields were added and the committed schema
updated, so the register is still validated on every run.

### 1c. A rank's binding strength was a literal, and rank four's was flattering (O-rank4)

This is not an attack I planted. `Binding.Strength` is computed for rank one —
it turns on whether the pinned RFC bytes are present — and was a literal for the
other four. `Bindings` requires any binding weaker than `CONTENT_BOUND` to say
what it is NOT bound to, and `Findings` emits an `ORACLE-RANK-BINDING`
disclosure for exactly those, so writing `CONTENT_BOUND` suppressed both.

Rank four was written `CONTENT_BOUND` while the census's own per-family
`SourceStrength` records its handshake opinions as a `RECORDED_READING` of the
pinned Java SOURCES (its basis cites Java files by line, not a transcript) and
its public opinions as `AGGREGATE_DERIVED` from a clean sweep. Under the
binding's own definition — "those bytes are A RECORD OF THE ORACLE ITSELF" —
`CONTENT_BOUND` was false for half the families it speaks in, and the register
carried no `not_bound_to` text and no disclosure for it.

**THE FIX (F3)**: `checkBindingStrengthAgainstFamilies` compares each binding's
strength against the census families and refuses `CONTENT_BOUND` for any rank a
family records weaker; rank four's binding is downgraded, given the
`not_bound_to` text the rule now requires, and given an owner action that raises
the strength AUTOMATICALLY once a per-case Java transcript is committed. The
register gained `ORACLE-RANK-BINDING-4`. **No number in the census moved.** This
weakens a claim in a committed evidence document, which is the honest direction,
and the diff shows it plainly.

### 1d. What I attacked in oracle-hierarchy-gates and could NOT defeat

Said precisely, because round 3's paragraph doing this was the most useful thing
in it.

- **The adjudication itself.** I re-read `Adjudicate`, `ParityFromJavaRustAgreement`
  and `VerifyRules` looking for the shape round 3 found elsewhere — a check
  whose input is also its output. There isn't one: the override set is
  recomputed from the census and compared to the committed list in both
  directions, and the register is never an input to its own recomputation. I did
  not find a way to make an override disappear without moving the census.
- **The polarity control.** `CheckFamilyRules` refuses an override in the
  differential family. I confirmed it is a real control and not a tautology: the
  existing test hands it a FABRICATED diff-probe family that does contain a
  higher oracle and an override, and the production function refuses it. It
  would catch an `Adjudicate` that marked everything overridden.
- **The collision analysis.** I read `collision.go` and looked for a way to make
  a family look better resolved than it is. Every number in it is recounted from
  the propositions on each run; there is no declaration to edit. I could not
  move it without moving the evidence, and moving the evidence moves the census.
- **The 488 rank-two propositions.** This was on my list as a suspected
  same-bytes artifact: rank two's verdict and rank four's verdict are read from
  the same per-case report FILES, differing only in field. I could not score it
  as a defect, and here is why, so the next round does not redo it. Rank two's
  verdict is the endorsed arm of the suite's own `expected` map, the census
  asserts that map is byte-equal between the independently written Java leg and
  Rust leg before using it, and the pair DOES disagree twenty times. It is a
  measurement. The artifact groups there are correctly split and my F1 rule
  agrees with them, because the declared paths are split too.
- **The neutral derivation.** I did not attack `internal/rfcneutral`. I read the
  claim `oracle-hierarchy-gates` makes about it and confirmed the shape round 3
  named: the register's cross-check asserts, in prose, that the derivation
  ignores the recorded expectation, and cites a test THIS GATE DOES NOT RUN to
  support it. That is the same "a rule that lives only in a test binary" shape,
  softened by the fact that `go-suite` is in `gates` and does run it. I did not
  try to make the derivation read the corpus expectation, because that changes
  rank three's verdicts and therefore moves the census, which is the class this
  round was told to avoid re-litigating.
- **The evidence-integrity call.** I considered a deletion attack on
  `VerifyEvidenceIntegrity` — replacing the pinned-file count with a literal
  would leave the cross-check string identical and the register byte-identical —
  and did not run it, because it is a deletion attack on production code rather
  than a bad tree passing a gate, and round 3 already established that class
  three times. It is named here so it is not reported as covered.

---

## 2. ledger-gates — the eight rules round 3 never attacked

Baseline, with both exports set, `go run ./cmd/deltaledgerctl --root . --check`
exits 0 and prints, among others:

```
ok: ledger integrity verified (frozen prefix through sequence 35, ledger envelope, evidence document schemas, observation provenance, handshake mapping census, protocol-rejection class, census evidence and ledger binding, supersessions, adjudication, held proposal drafts, legacy-record adjudications, unledgered_disagreements recomputed = 0, records_without_mismatch_class recomputed = 49)
```

### 2a. The held proposal drafts: the population is a list, and it has drifted (B1)

`VerifyProposalDraftsAreLedgered` is strong about each draft it reads. It
rebuilds the disagreement from the draft's own digest preimages, requires the
declared identity to EQUAL the rebuilt one ("the draft's identity must be a
FUNCTION of the evidence it carries, never a value typed beside it"), requires a
committed record to carry it, and requires that record to state an adjudication.
I could not defeat any of that.

**The population it runs over is a hardcoded list of seven paths.** The list has
a stated justification — the drafts directory also holds a corroboration
receipt, and "a glob would silently demand a record for it" — which is a fair
reason for the exclusion it names, and no reason at all for the ones it does
not. I enumerated the directory and ran the rule's own reader over every file in
it. Four files are outside the list. Three of them are not record proposals and
the rule's own reader says so. The fourth is:

```
NOT-LISTED   drafts/ledger-proposals/legacy-13-bare-lf-server-basis-correction.json delta_id=delta-3905e4669f52383df8aa4bc2965d64f320f6e2f4fdb6b609904dba627112a906 subject=semantic:org.java-websocket.draft6455.server-handshake.bare-lf.hs0034.corrected:provisional-v1 in_ledger=false
```

It carries `digest_preimages`, `proposed_definition` and `proposed_record`, it
rebuilds cleanly, its declared identity equals the identity its own preimages
produce — and **no record in the committed chain carries it**. The rule's own
refusal text for exactly this case ("The draft was held BECAUSE the disposition
vocabulary could not express it; with the vocabulary in place it must be
appended, not left held") never fires, because the file is not in the list.
`ledger-gates` prints "held proposal drafts" as verified.

I did NOT fix this, and the reason is the standing rule. Deriving the population
from the directory takes `ledger-gates` RED on the committed tree, and the only
way back to green is appending a record to the ledger — which moves the chain
head, the frozen-prefix successor sequence and the `unledgered_disagreements`
recomputation. That is an owner action: `OA-held-draft-legacy-13`.

### 2b. The live-mapping source binding: held, and I say exactly how far I pushed

Probed in both polarities as part of O5. An edit to the evidence document alone
is REFUSED with the text quoted in §1b. An edit to the source table plus a
re-render PASSES — and that is by design, stated in the function's own comment:
"a measurement whose polarity cannot be demonstrated is the defect this whole
file exists to remove", so the source-table-plus-regeneration path is left open
on purpose. I did not find a way to make the document and the table disagree
undetected.

### 2c. Observation provenance, the handshake mapping census, the protocol-rejection class, the supersessions, VerifyAdjudication, the corpora re-derivation

Read, not defeated. What I looked for in each was the two shapes that have
worked in this repository: a population that is declared rather than derived
(which is how 2a fell), and a comparison whose expected side moves with the
attack.

- **Observation provenance** compares the committed provenance against the
  provenance DERIVED from each record's own hashed digest preimages, exactly and
  in both directions, and the reader asserts the provenance list and the
  observation list are the same length before the loop runs, so a short
  provenance list cannot hide the tail. Round 2 already found and closed the
  "resolves is not the same as right" hole; I found nothing left.
- **The handshake mapping census** is both-directional by construction: every
  divergent row must have a covering authoritative record, and no record may
  cite a row the evidence does not record as divergent, so it cannot be
  satisfied by inventing a token.
- **The protocol-rejection class** re-derives class membership by EXECUTING each
  scenario's own steps and requires the census to enumerate exactly the derived
  set, both directions, and refuses outright if the predicate matches nothing.
- **The supersession rules** require the committed sidecar to equal the map the
  record chain itself carries, require the links parsed out of the hashed
  rationales to equal the links the structured definitions declare, and refuse
  an empty map. Round 3's finding 4 hardened the text/structure gap already.
- **VerifyAdjudication** and the corpora re-derivation I READ and did not
  attack, and I am not going to call that "survived". They are listed in §4.

---

## 3. fmt-check and clippy — both fell, and neither fix is mine to make

These two targets are one command each and neither has a waiver ceiling, a
suppression scan, or a census. I checked for one elsewhere and there is none:
the only Go code in this repository that knows the word `clippy::` is
`clippyLintNames` in `cmd/rustgatectl`, which parses clippy's OUTPUT so the
scaffold canary's refusal can be shown to be a lint rather than a compile error,
and it never reads a workspace crate's source. `fixture-guard` in the same
Makefile has a ceiling, a scan and a census, and its comment explains at length
why a rule that lives only in prose binds nothing. The contrast is the finding.

**C1 — `fmt-check`.** `cargo fmt --all -- --check`. I appended a deliberately
mis-formatted public function to a first-party crate root and attached
`#[rustfmt::skip]`. Control first, with the attribute replaced by a comment, to
prove the mis-formatting is real:

```
CONTROL_EXIT=1
Diff in /home/user/vjwp-attack4/rust/ws-core/src/lib.rs:82:
-pub fn round4_fmt_attack_probe(a:u32,b:u32)->u32{   let  x =   a+b ;
-        x   }
+pub fn round4_fmt_attack_probe(a: u32, b: u32) -> u32 {
```

With the attribute restored: `FMT_ATTACK_EXIT=0`, and
`cargo check --workspace --all-targets --locked` exits 0, so it is a mutant and
not a non-mutant.

**C2 — `clippy`.** `cargo clippy --workspace --all-targets --all-features -- -D
warnings`. An item that trips `clippy::needless_bool`, control first:

```
error: this if-then-else expression returns a bool literal
CONTROL_EXIT=101
```

With `#[allow(clippy::needless_bool)]` on the same item: `ATTACK_EXIT=0`.

Both are the well-known escape hatches, and that is the point: nothing in this
repository binds them, while the neighbouring target binds its own escape hatch
to a ceiling of zero and calls raising it "a decision, not a formality".

**I did not fix these, and the reason is the standing rule.** A ceiling needs a
count. The first-party Rust tree already carries 14 granular
`#[allow(clippy::...)]` attributes, spread over four crates, so any ceiling I
wrote would be a measurement denominator I invented, which is a hard stop. The blanket forms are a different case: `#![allow(warnings)]`,
`allow(clippy::all)`, a `[lints]` table and `rustfmt::skip` do not occur in the
tree at all today, so those specific forms could be refused outright without a
denominator, the way `forbid-unsafe` is. Which of the two to build is
`OA-rust-lint-suppression-ceiling`.

---

## 4. What I did NOT attack, and what I could not defeat

- **No owner gates.** No AWS run, no benchmark, no Autobahn run, no
  `internal/lab` execution path. **No label was added to any pull request.**
  `origin/codex/race-catchup` was not touched.
- **Nothing from rounds 1, 2 and 3 was re-attacked.** `record-guard`,
  `pin-guard`, `plan-guard`, `go-suite`, `fixture-guard`, `ac1-gates` and the
  Rust test targets were left exactly as those rounds left them.
- **`unsafe_usage` prose: UNREACHABLE, as briefed, and I did not burn the round
  on it.** I confirmed round 3's mechanism from the Cargo manifest rather than
  re-deriving it: the workspace declares its members and explicitly EXCLUDES the
  two canary fixture crates, and the dependency inventory is empty because there
  is nothing out of workspace to inventory. Creating an entry needs egress or
  the vendored path dependency A7 now refuses first. I found no way in and it
  cost me about ten minutes, which is the honest figure.
- **`VerifyAdjudication` and `VerifyCommittedCorporaReDerive`**: READ, NOT
  ATTACKED. Two of the eight ledger rules in my brief. I ran out of round after
  2a turned into a live defect that needed proving by execution. Reporting them
  as survivors would be the exact lie this task was created to correct.
- **The Autobahn digest manifest and `LoadLeg`.** Read enough to establish that
  the manifest is verified in both directions before any report is read, and
  that a case added to one leg cannot enter the census silently because the leg
  size is asserted against a constant. Not attacked further.
- **`internal/rfcneutral` itself.** Not attacked; see §1d for why.
- **The oracle census anchor.** Untouched by ruling. I did NOT bind the
  agreement count or the override count, and I did not close
  `OA-oracle-census-anchor`.
- **No denominator moved.** The census line is identical before and after every
  fix in this record; the ledger's recomputed residual is unchanged at rest; no
  corpus size constant was edited.

---

## 5. The fixes, and both directions for each

**F1, artifact-group partition** (`internal/oraclerank/document.go`).

The attack, refused:

```
oraclerankctl: handshake-verdict: rank1-rfc6455 and rank4-java-observation declare the same paths [evidence/us005-handshake-live-mapping.json] and two artifact groups ("handshake-live-mapping-rfc-reading" and "handshake-live-mapping"); a group split no path split supports lets the independence probe score two ranks that read one body of evidence
EXIT=1
```

The other direction, also refused:

```
oraclerankctl: handshake-verdict: rank1-rfc6455 and rank3-neutral-expectation declare the artifact group "handshake-live-mapping" and different paths ([evidence/us005-handshake-live-mapping.json] and [corpora/handshake/cases.jsonl]); a group merge no path merge supports makes the independence probe refuse to score two ranks that read different bodies of evidence
EXIT=1
```

The unmodified tree, passing:

```
oraclerankctl: 640 propositions adjudicated; 589 Java/Rust agreements, 39 of them overridden by a higher oracle and every one enrolled in evidence/oracle-hierarchy/adjudication-register.json
EXIT=0
```

Tests: `TestASplitArtifactGroupWithNoPathSplitIsRefused` and
`TestAMergedArtifactGroupWithNoPathMergeIsRefused` call `CheckFamilyRules` — the
function the gate runs, not a re-implementation — with fabricated families, and
assert the REFUSAL TEXT rather than a nonzero return.
`TestTheCommittedFamiliesSatisfyTheGroupPartition` is the other polarity.

**F2, join degeneracy over the keys the census joins on**
(`internal/oraclerank/joindegeneracy.go`, `findings.go`, and the schema).

With the source table edited and the document re-rendered — the variant that
passes the ledger's source binding — the disclosure now survives:

```
findings with JOIN: ['ORACLE-RANK-JOIN-DEGENERATE-1-3', 'ORACLE-RANK-JOIN-DEGENERATE-3-4']

DISAGREEMENT IS STRUCTURALLY IMPOSSIBLE OVER THE KEYS THIS CENSUS JOINS ON in
handshake-verdict between rank3-neutral-expectation and rank4-java-observation.
The whole 42-key table ... does carry a counterexample (reject->accept), but NO
committed case reaches the key that carries it ... A counterexample no case
reaches does not make an observed agreement a measurement.
```

and the BLOCKING finding's qualifier is honest again: "leaving 0 co-vote(s) that
could have come out either way", where the blinded register said 49. On the
unmodified tree the statement is the unconditional one and the census is the
line quoted above. Test: `TestTheJoinAnalysisIgnoresAKeyNoCaseReaches`, which
asserts the whole-table analysis DID see the planted counterexample — otherwise
the test would be passing without exercising anything — and that the joined-key
analysis did not.

**F3, derived binding strength** (`internal/oraclerank/binding.go`).

Restoring the literal, refused:

```
oraclerankctl: rank4-java-observation is bound CONTENT_BOUND and the census declares its opinions in [handshake-verdict=RECORDED_READING public-corpus-ready-state=AGGREGATE_DERIVED] as something other than CONTENT; a rank may not claim one strength while its own families record a weaker one, and CONTENT_BOUND is the strength that carries the NOT bound to obligation and the ORACLE-RANK-BINDING disclosure
EXIT=1
```

The unmodified tree passes with the census line above, and the register's
bindings now read rank one, rank three and rank four as
CONTENT_BOUND_TO_RECORDED_READING with `not_bound_to` text, rank two and rank
five as CONTENT_BOUND. Tests:
`TestABindingMayNotClaimContentWhileItsFamiliesRecordLess` (both polarities) and
`TestTheCommittedRegisterDisclosesRankFour`.

One existing test fixture was updated rather than deleted:
`TestHollowCoVoteQualifierCountsRatherThanAsserts` builds a degenerate family by
hand and now sets the joined-key flag as well as the whole-table one. Its
assertions are unchanged.

---

## 6. The chain, and the full gates run

Baseline, before any change, both exports set:

```
oraclerankctl: 640 propositions adjudicated; 589 Java/Rust agreements, 39 of them overridden by a higher oracle and every one enrolled in evidence/oracle-hierarchy/adjudication-register.json
EXIT=0
```

After every fix in this record, the same line, byte-identical. The register's
bytes changed — three new schema fields, a downgraded rank-four binding, a new
disclosure, and two rewritten join statements — and the document was regenerated
by the tool that verifies it, which is the ordinary path.

`make -C rust gates`, run to completion with both exports set, exits **0**. Its
census lines:

```
gate=fixture-liveness-guard step=scan files=49 loops=310 violations=0 waivers=0 max_waivers=0 budget_waivers=0 max_budget_waivers=0 unscanned=0
gate=record-content-precondition step=census records=73 unfinished=0 superseded=1 finished=72
gate=record-prose step=census cardinality_sentences=268 with_enumerable_population=13 no_enumerable_population=255 bound=13 covered=0 undispositioned=0
gate=pin-dangling result=PASS detail="no undeclared drift; 15 acknowledged finding(s) each naming an owner action"
gate=task-graph nodes=42 done=21 ready=0 in_progress=0 blocked=21 owner_actions=28 open=24
gate=go-suite packages=62 run=61 excluded=1 with_tests=46 no_test_files=15 unbuilt_test_files=5
ac1-gates verdict=PASS gates_passed=8/8
ok: ledger integrity verified (frozen prefix through sequence 35, ledger envelope, evidence document schemas, observation provenance, handshake mapping census, protocol-rejection class, census evidence and ledger binding, supersessions, adjudication, held proposal drafts, legacy-record adjudications, unledgered_disagreements recomputed = 0, records_without_mismatch_class recomputed = 49)
oraclerankctl: 640 propositions adjudicated; 589 Java/Rust agreements, 39 of them overridden by a higher oracle and every one enrolled in evidence/oracle-hierarchy/adjudication-register.json
```

`fixture-guard`'s scan census, the record census, the plan census, the go-suite
census and the ledger's recomputed residual are all unchanged from the base
commit. The plan census moves by one node changing state and by the two owner
actions this round adds. **No denominator moved.**

The one line in that output worth a reader's attention is the ledger's: it
prints "held proposal drafts" as verified, and §2a is the reason that phrase is
narrower than it sounds.

**WHICH TREE THAT READING IS OF, exactly.** Every file this round changed was in
place before that run except THIS RECORD, whose last paragraphs were written
after it — a record that reports its own gates run is always finished after the
run it reports. This file is read by exactly one target, so the honest repair is
to re-run that one on the committed bytes rather than to imply the whole suite
saw them:

```
make -C rust record-guard          # exit 0
gate=record-content-precondition step=selfcheck cases=16 firing=8 silent=8 result=PASS
gate=record-content-precondition step=census records=73 unfinished=0 superseded=1 finished=72
gate=record-content-precondition result=PASS
gate=record-prose step=census cardinality_sentences=268 with_enumerable_population=13 no_enumerable_population=255 bound=13 covered=0 undispositioned=0
gate=record-prose step=bindings agreeing=16 allowed=6 covered_records=1
gate=record-prose result=PASS

go run ./cmd/recordguardctl precondition drafts/self-review/gate-attack-round-4.md   # exit 0
gate=record-content-precondition mode=precondition record=drafts/self-review/gate-attack-round-4.md lines=676 signals=0 verdict=READS-FINISHED
```

The census numbers in that block are the same ones the full run printed, so the
record's own bytes did not move them. The full suite was also run TWICE, and I
compared the two: every census line above is identical between the run before
the last edits and the run after them.

---

## 7. Owner actions this round raises

- **`OA-held-draft-legacy-13`** — `drafts/ledger-proposals/legacy-13-bare-lf-server-basis-correction.json`
  is a rebuildable record proposal that no committed record carries, and
  `ProposalDraftPaths()` does not list it, so the rule that exists to catch
  exactly this cannot see it. Deriving the population from the directory takes
  `ledger-gates` red until the record is appended, and appending moves the
  chain. Owner decides: append the record and then derive the population, or
  rule the draft withdrawn and record why.
- **`OA-rust-lint-suppression-ceiling`** — `fmt-check` and `clippy` are defeated
  by an in-source suppression and neither has a ceiling. The granular
  `#[allow(clippy::...)]` population is not empty, so a ceiling over it is a
  denominator; the blanket forms are absent today and could be refused outright.
  Owner decides which.
- **`OA-oracle-census-anchor`** stands, unchanged and untouched, for the
  agreement count and the override count. The proposition count is already
  pinned by constants; see §1.

---

## 8. Process

Isolated worktree throughout, `.quarantine` symlinked and never staged. **No
`pkill` was used and no process of mine was killed.** Long runs were detached
and wrote their exit code to a file inside my own worktree, never to the shared
scratchpad. `df -h /` read before starting and again before believing any
result: 8.7G free at the start and 8.4G at the tightest point of the Rust work, so no
timing or failure here is a disk reading.

Every mutation was applied by an anchored edit that asserted its own uniqueness,
then echoed the changed line back and asserted it had changed. **No anchor
failed to match this round**, so there are no non-results to report; where an
edit could have matched more than one site I asserted the count first and the
assertion held each time. Every mutant was compiled or `cargo check`ed before
being scored. Every revert was verified with `git status --porcelain` and, for
the two evidence documents, with `cmp` against a saved copy — the live mapping
came back byte-identical after the source-table attack was undone.

The two Rust attacks were run against a cold cargo cache built in my own
worktree rather than against the shared one, so nothing I did could disturb
another session's target directory. The one cross-gate probe I built
(`VerifyLiveMappingIsBoundToItsSourceTable` called directly) lived in a scratch
directory that is not committed.

## 9. The shape, four rounds on

Round 1: an exemption should be re-derived, not re-read. Round 2: evidence must
be falsifiable, not merely checkable. Round 3: a check inherits its answer
whenever the thing it verifies is also one of its inputs. Round 4 adds the one
that fits all three of this round's oracle findings:

**A check can re-derive its answer perfectly and still be steered by an input
nobody re-derives.** The adjudication in `internal/oraclerank` is recomputed
from the evidence, compared in both directions, and refuses everything it says
it refuses. It is also handed an artifact-group label written by hand, a lookup
table wider than the corpus it is read against, and a binding strength typed
beside the rank — and each of those three decided what the register CONCLUDED
without touching a single number the gate prints. The strongest arithmetic in
the repository sat downstream of three free strings.

And the older patterns recurred again, none of them fixed by having been named:

- **The population that is a list.** `ProposalDraftPaths()` names seven files in
  a directory that holds more, for a documented reason that covers one of the
  omissions and not the one that matters. This is round 2's "census number that
  nobody asserts" turned inside out: here the census is asserted exactly, and
  the SET it is asserted over is the declaration.
- **The prose that is never validated against the world**, now at
  `10 first-party crate roots` and `CONTENT_BOUND` and the cross-check citing a
  test the gate does not run.
- **The escape hatch with no ceiling.** `fixture-guard` learned this three
  times, wrote it down at length in the Makefile, and `fmt-check` and `clippy`
  sit four lines above that paragraph without it.
