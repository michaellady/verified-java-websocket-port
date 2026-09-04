# Every other record's prose, bound to the documents it cites

Branch `claude/record-prose-corpus`, based on mainline `6986e95`.

`internal/normcollide/recordbounds.go` binds **one** record. Its author said so
in the record that landed it, and F017 repeated it:

> **The prose of every OTHER record in the tree is still pinned to nothing.**
> `CheckRecordBounds` covers one record's numbers. The general defect — a
> regenerated artifact and a hand-written record that reads it, with no check
> between them — is closed for `normalization-collision-audit.md` only.

STATUS: COMPLETE. The corpus is derived and its denominator stated; twelve
records are bound by twenty bindings that re-derive every value from the tree;
four true positives are reported with their drift commits and none is fixed by
editing a number; the census that makes the binding table a floor rather than a
hand-picked list refuses a new unbound claim; and the ceiling is a number
(230 cardinality sentences this gate cannot enumerate), not a silence.

---

## 1. The corpus, and how it was derived

**The population.** Every `.md` under `drafts/self-review/` (including
`findings/`) — the same walk `cmd/recordguardctl`'s existing census makes, so the
two are comparable — plus every `.md` under `evidence/`, plus the `statement`
string field of every `.json` under `evidence/` that carries one.

The third source was added because **two of the four true positives below live
in a place a drafts-only walk cannot reach**, and one of them is not a markdown
file at all: it is a prose sentence inside a governance evidence document,
standing beside machine-derived fields that gates *do* check. A corpus that only
walked `drafts/self-review/` would have found one of the four.

**The denominator, stated as this gate prints it:**

```
gate=record-prose step=corpus records=77 markdown=71 statements=6 bindings=20
gate=record-prose step=census cardinality_sentences=241 with_enumerable_population=11
                              no_enumerable_population=230 bound=11 covered=0 undispositioned=0
gate=record-prose step=bindings agreeing=14 allowed=6 covered_records=1
```

Every number in that block is recomputed on every run. It counts this record too,
which is why it reads 77 and not the 76 it read before this file existed: the
corpus is a WALK, and a record added tomorrow is in the denominator without
anyone remembering to add it.

Read as a denominator, in words:

| quantity | value | how it is derived |
| --- | --- | --- |
| prose sources in the corpus | **77** | 66 `.md` under `drafts/self-review/` + 5 `.md` under `evidence/` + 6 `statement` fields |
| of which markdown records | **71** | the walk |
| cardinality sentences the records assert **in their own voice** | **241** | `N <countable noun>`, outside code fences and block quotations |
| of those, sentences naming a population this gate can **enumerate** | **11** | the candidate corpus that MUST be dispositioned |
| of those, dispositioned | **11** | 11 bound, 0 covered, 0 undispositioned |
| cardinality sentences with no enumerable population | **230** | **the ceiling**, §7 |
| records bound | **12** | 11 by a numeric binding, 1 by a non-numeric assertion |
| bindings | **20** | 19 numeric claims + 1 assertion |
| bindings whose prose **agrees** with the tree | **14** | silent |
| bindings whose prose **disagrees** and is declared | **6** | §5, §6 |

**Whose voice.** A record quoting an old gate line inside a code fence is
reporting history, not asserting a present-tense measurement. Binding those would
make every honest history a failure, so the scan reuses `maskOtherVoices` from
`cmd/recordguardctl/scan.go` — the same discriminator, and the same reasoning
`supersession-is-not-unfinished.md` gives for it. Fenced and quoted lines are
skipped; the mask decides *voice* only, and the raw line is what gets matched,
because the mask also blanks the inline code spans the citations live in. The two
measurements: a line scan that does not distinguish voice finds **270**
cardinality lines in the same markdown records; the gate counts **241** in the
records' own voice. The difference is transcripts, and almost every one of them
is a true statement about the past.

**Enumerable, and why that line is drawn by the document.** A sentence is a
candidate only when this gate could *count* the population it names, and that is
decided by asking the document, never by reading the sentence harder:

* a `.jsonl` is enumerable in rows, when the noun is one this corpus uses for a
  row (`rows`, `records`, `cases`, `entries`, `scenarios`, `observations`);
* a `.json` is enumerable **only if the prose's own countable noun is one of its
  top-level array keys** — a sentence of the shape *"`<document>.json` holds N
  records"* is a claim about `$.records` because the sentence itself says
  `records`, so the selector is read off the sentence rather than invented beside
  it;
* a directory is enumerable in files, for a record naming its own directory
  ("beside this README").

The first version of this rule accepted any number near any cited path and
produced 17 candidates of which 6 were nonsense — `18 files` beside a cited
`.rs` file read as a claim about that file. Asking the document instead took it
to 11, and every one of the 11 turned out to be bindable.

**Reproducing the derivation:**

```
go run ./cmd/recordguardctl prose -root .
```

## 2. Nothing here is checked against a copy of itself

The whole binding table carries **no expected value anywhere**. A `proseClaim`
holds a record path, a pattern with exactly one capture group, and a
`derive` *function*; a `proseAssertion` holds a predicate. A record that declares
"I claim 62" checked against a sidecar that also says 62 is a self-consistency
check, and this repository has filed that shape four times — F011, F014, F016 and
F017. `TestEveryClaimCapturesExactlyOneValueAndCarriesADerivation` refuses a
binding with no derivation, and `TestMutatingTheDocumentAlsoGoesRed` proves the
compared value follows the document: if it were authored here, moving the
document could not move it.

The four derivations, all of which read the tree on every run:

| derivation | reads |
| --- | --- |
| `deriveDirFileCount` | a directory listing (`evidence/governance/decisions/*.json`) |
| `deriveJSONArrayLen` | `len()` of one top-level array of one JSON document |
| `deriveJSONLRows` | the non-blank rows of a `.jsonl` corpus |
| `deriveOccurrences` | how many times a literal appears in a named document |
| `gitTracked` (assertion) | `git ls-files --error-unmatch` |

`gitTracked` distinguishes exit **1** ("git looked; not in the index") from any
other exit. Reading 128 — "not a git repository" — as *untracked* would make the
tracked-ness assertion HOLD in every checkout git cannot see, which is a refusal
read as an answer. `TestTheAssertionRefusesWhenGitCannotAnswer` pins it.

## 3. The exemption pattern, followed rather than invented

This codebase declares an exemption and then verifies the declaration is still
needed, four times: `STALE_EXCLUSION` and `EXCLUSION_NO_LONGER_FAILS`
(`cmd/gosuitectl`), `STALE_COVERAGE_CLAIM` and `STALE_ALLOWANCE`
(`cmd/pinconsumerctl`), `STALE_BLOCK` (`cmd/taskgraphctl`). This gate uses the
same three shapes and no others:

* **`STALE_COVERAGE_CLAIM`** — a claim declared covered by another checker. The
  covering *assertion string* is read back out of the covering file on every run,
  so the coverage claim cannot outlive the check it names.
* **`STALE_ALLOWANCE`** — a declared acknowledgement of a TRUE finding, pinned to
  the value the prose states **today**. Restate the sentence and the
  acknowledgement stops matching, which makes it either an unallowed mismatch or
  a stale allowance — **both of which FAIL**. Fix the document so the prose
  becomes true and the allowance orphans and fails. An allowance covers a
  finding, never an address.
* **`CLAIM_ABSENT`** — fail-closed on absence, inherited from
  `internal/normcollide`. If a missing sentence were a pass, the gate would be
  defeated by deleting the sentence, which is the cheapest possible way to stop a
  number being stale.

And one that is not an exemption at all but the thing that keeps the binding
table honest:

* **`UNDISPOSITIONED_CLAIM`** — a census candidate that no binding, coverage
  claim or allowance names. It **fails the gate**. This is what makes the corpus
  derived rather than hand-picked: I cannot quietly leave a claim out, and a
  record landing tomorrow with a cardinality claim about an enumerable population
  fails on the run it appears.

## 4. Both directions, read from the process

Every reading below is `go run ./cmd/recordguardctl prose -root .` on the live
tree, with the named mutation applied and then reverted. `git status` was clean
after each.

**CONTROL — a tree whose bound prose agrees stays silent.** Fourteen bindings
agree and print nothing at all:

```
gate=record-prose step=corpus records=77 markdown=71 statements=6 bindings=20
gate=record-prose step=census cardinality_sentences=241 with_enumerable_population=11 no_enumerable_population=230 bound=11 covered=0 undispositioned=0
gate=record-prose step=bindings agreeing=14 allowed=6 covered_records=1
gate=record-prose result=PASS                                                   exit 0
```

**A1 — mutate the PROSE, not the artifact.** This is the F017 probe and it is the
one that matters: F017 was a polarity test that bound the artifact to the census
and said nothing about the sentence quoting it, so it passed while the prose it
was meant to protect went stale underneath it. `969` → `970` in
`drafts/self-review/findings/F001-...md`, artifact untouched:

```
gate=record-prose finding=PROSE_DISAGREES_WITH_DOCUMENT record=drafts/self-review/findings/F001-reproduction-check-pinned-to-vendor-string.md field="semantic_id_oracle_declarations" line=3 detail="the record says 970, the tree derives 969 from evidence/intake/semantic-id-oracle.json $.declarations | all 970 declarations, totals and javac options were identical"
gate=record-prose result=FAIL blocking=1                                        exit 1
```

It names the record, the field, the line, both values, the document and pointer
the value came from, and quotes the sentence back.

**A2 — delete the sentence.** Fail-closed on absence:

```
gate=record-prose finding=CLAIM_ABSENT record=drafts/self-review/findings/F001-reproduction-check-pinned-to-vendor-string.md field="semantic_id_oracle_declarations" detail="the record no longer states this claim where this check reads it (the tree derives 969 from evidence/intake/semantic-id-oracle.json $.declarations). A record that stopped stating its claim is not a record that agrees with it"
gate=record-prose result=FAIL blocking=1                                        exit 1
```

**A3 — restate an ALLOWED claim to the correct value.** `62` → `63` in
`evidence/governance/decisions/README.md`. The allowance must not survive the
finding it acknowledges:

```
gate=record-prose finding=STALE_ALLOWANCE record=evidence/governance/decisions/README.md field="governance_decision_records (opening sentence)" detail="allowed at stated value \"62\", but that claim no longer disagrees with the document (or no longer reads as this value); the acknowledgement outlived the finding and must be deleted"
gate=record-prose result=FAIL blocking=1                                        exit 1
```

**A4 — mutate the DOCUMENT and leave the prose alone.** This is what proves the
compared value is re-derived rather than authored beside the claim. One case
appended to `assurance/fuzz/fixtures/campaign/cases.json`, prose untouched:

```
gate=record-prose finding=PROSE_DISAGREES_WITH_DOCUMENT record=drafts/self-review/us021-fuzz-pinning-round-1.md field="fuzz_campaign_runner_cases" line=139 detail="the record says 5, the tree derives 6 from assurance/fuzz/fixtures/campaign/cases.json $.cases | assurance/fuzz/fixtures/campaign/cases.json — 5 campaign-runner cases"
gate=record-prose result=FAIL blocking=1                                        exit 1
```

**A5 — a new record with an unbound claim.** A three-line synthetic record
citing a real corpus. The census refuses it, and the denominator moves by one in
the same run, visibly:

```
gate=record-prose step=corpus records=78 markdown=72 statements=6 bindings=20
gate=record-prose step=census cardinality_sentences=242 with_enumerable_population=12 no_enumerable_population=230 bound=11 covered=0 undispositioned=1
gate=record-prose finding=UNDISPOSITIONED_CLAIM record=drafts/self-review/zz-census-probe.md field="corpora/handshake/cases.jsonl (rows)" line=3 detail="this line states a cardinality about a population this gate can enumerate, and no binding, coverage claim or allowance names it | The corpus `corpora/handshake/cases.jsonl` carries 4096 cases."
gate=record-prose result=FAIL blocking=1                                        exit 1
```

**A6 — a differently-wrong value must not inherit an allowance.** `62` → `61`
fires BOTH, and both are correct: an allowance covers a finding, not an address.

```
gate=record-prose finding=PROSE_DISAGREES_WITH_DOCUMENT record=evidence/governance/decisions/README.md field="governance_decision_records (opening sentence)" line=3 detail="the record says 61, the tree derives 63 from evidence/governance/decisions/*.json | The 61 JSON files beside this README"
gate=record-prose finding=STALE_ALLOWANCE record=evidence/governance/decisions/README.md field="governance_decision_records (opening sentence)" detail="allowed at stated value \"62\", but that claim no longer disagrees with the document (or no longer reads as this value); the acknowledgement outlived the finding and must be deleted"
gate=record-prose result=FAIL blocking=2                                        exit 1
```

**A7 — the covering assertion vanishes.** The assertion string rewritten out of
`internal/normcollide/recordbounds.go`:

```
gate=record-prose finding=STALE_COVERAGE_CLAIM record=drafts/self-review/normalization-collision-audit.md field="internal/normcollide/recordbounds.go" detail="internal/normcollide/recordbounds.go no longer contains the covering assertion \"The 74 rows carry only (\\d+) distinct scored observations\"; the coverage claim outlived the check it names"
gate=record-prose result=FAIL blocking=1                                        exit 1
```

**A7's first run was a non-result and is recorded as one.** The `sed` expression
that was supposed to remove the assertion did not match — the backslash class in
a Go backtick literal survived one round of shell quoting too few — so the source
was never mutated and the run came back `result=PASS exit 0`. An unmutated run is
not a survivor, it is nothing at all. It was redone with an anchor asserted
before the write, which is what produced the reading above, and
`writeMutated` in the test file refuses an anchor that does not match for exactly
this reason.

**A8 — the assertion arm swings both ways.** The tracked-ness predicate returns
FALSE on this tree, which is the finding; a constant false would look identical
there. So the same predicate is run against a scratch repository where the
mirrored records genuinely are **not** committed, and it returns TRUE; the same
files are then added to the index with nothing else changed, and it returns
FALSE. `TestTheTrackednessAssertionSwingsBothWays`.

### The defect this work shipped, and the two red gate runs that found it

**`make -C rust gates` went red twice on this branch, and both were mine.**

Run 1 failed `cmd/securityctl`; run 2, on a tree differing only by two prose
corrections, failed `internal/assurance` with three subtests. Neither reproduced
standalone — `cmd/securityctl` passed three times in a row immediately after,
and the three assurance tests passed on demand — and my first reading was that
the host was contended. It was not.

```
--- FAIL: TestVerifyCanonicalLifecycle
    adapter_test.go:21: verify canonical lifecycle: assurance/lifecycle.json is not an immutable single-link file
```

`internal/assurance/adapter.go:1214` refuses `assurance/lifecycle.json` unless
`st_nlink == 1`, and `internal/securitygate/snapshot.go:296` reads the same
field. **`mirrorTree` in this branch's own test file hard-linked its mirror from
the live checkout**, so for as long as any mutation test held a mirror, every
file in the tree had two links — and `go test` runs packages in PARALLEL, so two
packages built to refuse exactly that saw exactly that. Which one went red
depended only on which was scheduled inside the window, which is why each run
blamed a different innocent package.

**The lesson is not "use copies".** It is that a test helper mutated GLOBAL
FILESYSTEM STATE that other packages read as evidence. Link count is part of a
file's identity in this repository, deliberately, and a mirror is not read-only
just because it never writes. I reached for hard links as an optimisation and
did not ask what else reads the thing I was changing.

The fix makes one byte COPY of the checkout per test binary and links the
per-test mirrors from THAT: the copy's own link counts rise and nothing inspects
those. `TestTheMirrorAddsNoLinkToTheCheckout` is the regression probe, and it is
a test about the test helper, because that is where the defect was.

**The race would not reproduce on demand, and the proof is therefore of the
MECHANISM and not of the race.** `go test ./cmd/recordguardctl/
./internal/assurance/` came back `ok` on both packages with the defective mirror
in place: `cmd/recordguardctl` finishes in eight seconds and the window simply
did not overlap the check. Saying "it passed, so it is fixed" from that run would
have been the same reading error F017 records. So the polarity was taken
deterministically instead, on the one thing that is not timing-dependent — the
link count itself:

```
--- FAIL: TestTheMirrorAddsNoLinkToTheCheckout
    the mirror raised assurance/lifecycle.json to 2 links. internal/assurance
    refuses that file unless nlink==1, and go test runs packages in parallel, so
    this makes an unrelated package fail from inside this one          exit 1
```

with the shipped form, and exit 0 with the fix. That plus the two red runs'
verbatim message — `assurance/lifecycle.json is not an immutable single-link
file` — is the whole chain: my mirror provably raises the count, and the failing
package provably refuses a raised count. What is NOT established is a
reproduction of the interleaving, and it is not claimed.

### A bug this work found in itself

`mirrorTree` in the test file skipped `.git` by returning `filepath.SkipDir`.
Returned from a **file** callback, `SkipDir` skips the remaining entries of the
*containing directory* — and in a `git worktree` checkout `.git` is a file, not a
directory. The mirror therefore stopped after five hard links and every mutation
test failed on a path that had never been mirrored. It is the same class as the
`(?m)` bug this brief warns about: a rule that silently did nothing while reading
as if it did something. Recorded because the failure was loud only by luck —
had the skipped entry been anything the tests did not touch, the mirror would
have been silently partial and the polarity proofs worthless.

That is also why `TestEveryBindingLocatesItsClaimInItsRecord` exists: it requires
every pattern to LOCATE its claim in its record. A pattern that matched nothing
would otherwise report `CLAIM_ABSENT`, which reads as a finding about the record
rather than a defect in the checker.

## 5. True positives

Four. None is fixed here by editing a number.

### TP-1 — a security assertion whose denominator is smaller than its corpus

`evidence/governance/decisions/README.md`, twice:

> line 3: **The 62 JSON files beside this README** are the owner-decision records
> that authorise the work on this plane…
>
> line 20–21: Across all **62 records** there are no credentials of any kind — no
> keys, no ARNs, no bucket names.

Re-derived: the tree holds **63** `.json` files in `evidence/governance/decisions/`,
beside this README.

**The drift commit is the commit that wrote the README.** `b6d3c6c`
("governance: publish the owner-decision records so any checkout can verify
them", 2026-09-01) added both the README and the records.
`git ls-tree -r --name-only b6d3c6c -- evidence/governance/decisions/ | grep -c
'\.json$'` is **63**, and `git diff b6d3c6c HEAD -- evidence/governance/decisions/`
is **empty**. No record was added afterwards: the count was wrong on the day it
was written, not drifted into.

**The assertion itself was re-derived over all 63 and it HOLDS.** 0 `arn:aws`, 0
`AKIA`/`ASIA` keys, 0 private-key headers, 0 `s3://` references, 0 non-loopback
IPv4 in the record bodies. Both redaction placeholders are present exactly where
the README's table says they are, and that is a *bound* claim now
(`aws_account_id_redaction_occurrences`,
`ec2_instance_id_redaction_occurrences`) — it agrees, and it is one of the twelve
silent bindings. So the correct reading is: **the assertion is true, its stated
scope is one short, and until this branch nothing re-derived either.**

### TP-2 — a governance statement superseded by a ruling that sits beside it

`evidence/governance/owner-decision-digests.json`, field `$.statement`:

> The records themselves live in the workspace orchestrator's immutable protected
> store and are **deliberately NOT committed**: this repository is public and
> those records carry internal deliberation, cost figures and infrastructure
> identifiers. Committing their sha256 gets tamper-detection without the
> disclosure…

Re-derived: **7 of 7** mirrored records are git-tracked under
`evidence/governance/decisions/`, and **7 of 7** are byte-identical to the digest
this file mirrors. The tracked tree *is* the store the statement says is not
committed.

**Drift commit: `f052795`** (2026-09-02, "Merge branch
'claude/feature/verified-java-websocket-port' into claude/ledger-integrity") — the
first commit on the path to HEAD that holds both halves. The statement entered at
`20722b9` (2026-08-28) when the records were genuinely uncommitted; `b6d3c6c`
published them on a line that did not yet carry the digests file
(`git show b6d3c6c:evidence/governance/owner-decision-digests.json` is
`fatal: … exists on disk, but not in 'b6d3c6c'`); the merge is where the two met.
The file has been edited twice since — `81ce746` and `9946dae` — without the
statement being corrected.

**This is not a disclosure incident.** The publication was ruled at
`governance-publish-records-owner-decision-2026-08-29.json`, the README beside it
records the supersession in full, and the redactions were performed and are
verified above. It is stale prose.

**And it is the sharpest instance of this branch's thesis.**
`internal/deltaledger.VerifyGovernance` requires the committed file to equal
`BuildOwnerDecisionManifest`'s output — whose `Statement` field is the Go constant
`internal/deltaledger.OwnerDecisionManifestStatement` at `governance.go:209`. The
statement is therefore checked, byte for byte, **against a copy of itself**, and
never against the tree. That is F014's shape ("a code binding verified against a
copy of itself") in the one file this repository treats as its root of
governance. It also means the finding cannot be closed by a prose edit: editing
the JSON alone fails `ledger-gates`, and editing the constant restates a
disclosure posture. See owner action **OA-governance-statement** below.

### TP-3 — a landing record stating a ledger size the ledger left behind

`drafts/self-review/story-criterion-sweep.md`, three times, present tense:

> line 100: `evidence/java/behavior-delta-ledger.json` holds **58 records**.
>
> line 110–111: So the correct **denominator** for step 3 is **all 58 records**,
> not the 6 with a modern disposition.
>
> line 714: `evidence/java/behavior-delta-ledger.json` — all **58 records** by
> subject and disposition; 15 rationales in full.

Re-derived: `evidence/java/behavior-delta-ledger.json` holds **59** records.

**Drift commit: `9946dae`** (2026-09-04, "ledger sequence 59: the disposition
sequence 58 held open was already ruled"). Walking the ledger's own history gives
`48 → 49 → 56 → 58 → 59` at `aa422e2`, `8f10cea`, `d4af3ce`, `81ce746`,
`9946dae`.

**The shape is F017's, exactly.** The record's last touch is `24715ef`
(2026-09-04), and `git merge-base --is-ancestor 24715ef 9946dae` is **true** — the
record was finished on an ancestor of the commit that moved the number, so every
gate stayed green while the sentence went false. F017 makes the same observation
about `70f104f` being an ancestor of `d90308a`. This is the second recorded
instance of the same mechanism, which is the argument for a gate rather than a
finding.

One of the three is a **DENOMINATOR**. It is reported and not re-baselined: its
allowance is marked `DENOMINATOR, HARD STOP`, on the same shape
`cmd/pinconsumerctl` uses for `$.denominator_basis`. Whether that record's step-3
sweep survives 59 records is a re-reading, and re-reading it is not this branch's
work.

### TP-4 — a census recited as a present-tense measurement, in six records

Found, reported, and deliberately **NOT bound**. `drafts/self-review/` has grown
from 41 records to 66 — this file is the 66th — and six records recite a count of it:

> `record-content-precondition.md:470`: The census **currently** reads
> `records=41 unfinished=1 finished=40`.
>
> `record-content-precondition.md:279`: census `records=41 unfinished=1 finished=40`.
>
> `story-criterion-sweep.md:701`: `record-guard` census: **55 records**,
> `unfinished=0`, `superseded=1`, `finished=54`.
>
> `jdk-vendor-agnostic.md:270`: `gate=record-content-precondition result=PASS`
> over `records=61 unfinished=0`.
>
> `gate-adversarial-review.md:113`: The census over all **55 records** in
> `drafts/self-review` is BYTE-IDENTICAL before and after.

Re-derived today: `gate=record-content-precondition step=census records=66
unfinished=0 superseded=1 finished=65`. Five of the ten sentences are inside code
fences and are honest transcripts; the five above are in the records' own voice,
and the first is explicitly present tense and false.

**Why it is not bound, stated rather than quietly scoped out.** The population is
`drafts/self-review/*.md` — the record corpus itself, which **this very
deliverable grew, from 65 to 66**. Binding it would make every future record
fail the gate against an unrelated older record until that record is restated: a
treadmill, and a gate that punishes writing records is a gate that discourages
writing records. Whether that cost is worth paying is a judgement about how this
project wants its history to read, not a measurement, so it is owner action
**OA-record-census-prose** and node `T-record-census-prose` is blocked on it.

## 6. The declared exemptions, and what re-checks each

Six allowances, all covering TP-1 to TP-3, each pinned to the value the prose
states today and each naming the owner action that would let it be deleted:

| record | field | states | tree derives | why it is declared and not fixed |
| --- | --- | --- | --- | --- |
| `evidence/governance/decisions/README.md` | opening sentence | 62 | 63 | SUPERSEDE, do not edit. A governance record change belongs to the owner. |
| `evidence/governance/decisions/README.md` | no-credentials denominator | 62 | 63 | SUPERSEDE. The assertion holds over all 63; the scope is one short. |
| `drafts/self-review/story-criterion-sweep.md` | holds sentence | 58 | 59 | SUPERSEDE. A landing record is corrected by a superseding record. |
| `drafts/self-review/story-criterion-sweep.md` | step-3 denominator | 58 | 59 | **DENOMINATOR, HARD STOP.** Reported, never re-baselined. |
| `drafts/self-review/story-criterion-sweep.md` | evidence list | 58 | 59 | SUPERSEDE. Same drift, third sentence. |
| `evidence/governance/owner-decision-digests.json#/statement` | not-committed assertion | asserted | refuted, 7/7 tracked | OWNER ACTION, and not a prose edit: the field must equal a Go constant. |

**Each one is re-checked on every run, three ways.** The claim is located in the
prose again; the value is re-derived from the tree again; and the allowance is
required to still match both. `TestRestatingAnAllowedClaimOrphansItsAllowance`
and `TestEditingAnAllowedClaimToSomeOtherWrongValueIsNotCovered` prove the two
directions of that. An exemption that is never re-checked is a bypass; these
fail the moment they stop being needed.

One coverage claim: `drafts/self-review/normalization-collision-audit.md` is
declared covered by `internal/normcollide/recordbounds.go`, naming the assertion
string `The 74 rows carry only (\d+) distinct scored observations`, which is read
back out of that file every run. **It currently exempts zero census candidates**
— none of that record's bound sentences carries an inline path citation, so the
census does not raise them — so it is documentation plus a staleness check rather
than an exemption in force, and it is printed as such. Naming that is better than
letting a declaration that binds nothing sit unexamined.

## 7. The ceiling

**230 of the 241 cardinality sentences this corpus asserts are still unbound**,
and here is what they are rather than a shrug:

1. **Sentences about a population this gate cannot enumerate.** `85 candidates`
   from `pinconsumerctl`, `77 test result: ok` from `cargo test`, `18 files` from
   a `git diff --stat`, `16,300 cases` from a fuzz seed budget. Each is a claim
   about the output of a program, not about the contents of a committed document,
   so re-deriving it means *running that program* — which for several of these is
   an owner gate (AWS, benchmark, Autobahn). Bounded by construction, not by
   effort.
2. **Claims about a document's contents that are not cardinalities.** "all 26
   differ ONLY on `/error/detail`", "sequence 55 is `unresolved`". These are
   re-derivable in principle and each needs its own predicate; the assertion arm
   exists and holds exactly one of them today.
3. **The census is line-scoped and the bindings are not.** A claim wrapped across
   a line break away from its citation is bound if a binding names it (the
   governance README's `Across all\n62 records` is), but the census does not raise
   it as a candidate. So the census is a FLOOR on what must be dispositioned, not
   a complete enumeration of what could be.
4. **`45/47 rows` binds the denominator only.** The numerator is a property of a
   scan this gate does not run. Named in the binding's own comment rather than
   implied.
5. **A record that quotes a number inside a fence is never checked**, deliberately
   (§1). A stale present-tense claim written inside a code fence is invisible to
   this gate.
6. **TP-4's class is unbound by decision**, §5.
7. **This binds prose to documents, not prose to truth.** A record can state
   something false about the world in a sentence that cites nothing, and nothing
   here reaches it. `recordbounds`'s ceiling was "one record"; this one's is "the
   claims whose subject is a committed file this gate can count".

## 8. Where it is gated

`rust/Makefile`, `record-guard`, as a third step beside the two that were there:

```
record-guard:
	cd .. && go test ./cmd/recordguardctl/
	cd .. && go run ./cmd/recordguardctl gate -root .
	cd .. && go run ./cmd/recordguardctl prose -root .
```

`record-guard` is the right home and a new `cmd/` or `internal/` package is not.
`gate` reads whether a record *says* it is finished; `prose` reads whether what a
record says is still *true*. Both halves run for the reason the neighbouring
targets give: `go test` executes the polarity a tree scan cannot reach (the F017
prose mutation, the document mutation, the deleted sentence, the orphaned
allowance, the assertion's TRUE direction against a scratch repository), and
`go run` applies the rule to the live tree and prints the census.

**A deliberate placement decision, and the constraint behind it.** The
implementation lives in `cmd/recordguardctl/prose.go` — an existing package —
rather than in a new `internal/recordprose` plus `cmd/recordprosectl`, which is
otherwise this repository's idiom. A new package would move `cmd/gosuitectl`'s
printed census from `packages=61 run=60 … with_tests=45` to 63/62/47, and that
tool's own doc comment quotes those five numbers as "Measured on 2026-09-04". A
measurement denominator is not a thing to move as a side effect of choosing a
directory, and it is certainly not a thing to absorb by editing the quoted
numbers to match. Verified: `go list ./...` reports the same package set before
and after this branch.

## 9. Owner actions, none taken

1. **OA-governance-statement.** `evidence/governance/owner-decision-digests.json`
   `$.statement` asserts a disclosure posture the owner reversed. It cannot be
   corrected by editing the file: `internal/deltaledger.VerifyGovernance` requires
   the document to equal a derivation whose statement is the Go constant
   `OwnerDecisionManifestStatement`. The correction is a change to that constant
   plus a regeneration, and it restates a governance posture, so it is an owner
   decision. Node `T-governance-statement-supersession` is blocked on it.
2. **OA-record-census-prose.** Decide whether prose reciting the size of
   `drafts/self-review/` should be bound to it. Binding makes every new record
   fail the gate until an unrelated older record is restated. Node
   `T-record-census-prose` is blocked on it.
3. **TP-1 and TP-3 are corrections by supersession**, and the superseding
   documents are the owner's or their authors' to write. This branch declares them
   and re-checks the declarations; it does not rewrite anyone's measurement.
4. **No AWS, benchmark or Autobahn run.** Owner gates, never triggered.

## 10. What I did not do

- **I did not edit a single stated number.** Not 62 to 63, not 58 to 59. Every
  one of the four true positives is declared, pinned and re-checked, and each
  names the owner action that retires it. Editing them would have made this gate
  green and destroyed the evidence that the numbers were ever wrong — and for the
  step-3 denominator it is the specific move this project forbids.
- **I did not touch `internal/normcollide`.** Its two checks are better than a
  second binding of the same eleven sentences would be; they are declared as
  coverage and their assertion string is verified.
- **I did not widen an existing checker's scan.** `record-content-precondition`
  still walks `drafts/self-review` alone and still prints its own `records=` count
  over that tree alone; the
  `evidence/` widening belongs to the new census and is declared in
  `proseRoots`'s own comment.
- **I did not add a Go package**, for the denominator reason in §8.
- **I did not run a hidden or sealed tier, an AWS host, a benchmark or Autobahn.**
- **`origin/codex/race-catchup` was not read or written.**
- **I did not label any pull request.**
