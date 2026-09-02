# Legacy record adjudication — round 1 self-review

Track: file the forty-nine pre-vocabulary delta-ledger records under US-020 AC3
(`java-quirk` / `rust-defect` / `underspecified-behavior`) without rewriting the
frozen prefix and without breaking the handshake or public-corpus censuses.

Branch `claude/legacy-record-adjudication`. **Nothing is appended to the ledger.
`evidence/java/behavior-delta-ledger.json` is byte-identical to mainline's** —
`git diff --quiet <mainline>...HEAD -- evidence/java/behavior-delta-ledger.json`
exits 0.

---

## 1. The problem, and the three designs I rejected

AC3 requires every mismatch to be filed as a Java quirk, a Rust defect or
underspecified behavior. The 1.2.0 landing gave the ledger the vocabulary and
used it on the seven records appended at sequences 50–56. The forty-nine sealed
before the field existed carry nothing, and the ledger publishes the honest
residual `records_without_mismatch_class = 49` on every check.

**Rejected: classify in place (all forty-nine).** A record's digest preimage is
the canonical JSON of its whole delta, so a byte added to any record from 1 to
35 rewrites the chain and breaks the prefix
`protected/ledger-frozen-prefix-owner-decision-2026-08-28.json` requires to stay
byte-identical.

**Rejected: classify in place, records 36–49 only.** This is the alternative the
first pass did not name, and it is not obviously wrong: the same owner decision
says records after sequence 35 are this branch's own appends and explicitly
contemplates rebuilding them. I rejected it on a checkable cost rather than on
principle. Rebuilding 36–49 changes fourteen record digests and therefore the
ledger head, and the head is pinned outside the ledger:
`assurance/concurrency/plan.json` carries
`"observed_head": "sha256:a44191d3…"` and `"observed_record_count": 56`. That
file's `append_blocker` is at 8178 of an 8192 cap, so the cheapest version of
this route ends in an edit to the one artifact this program is most careful
about — and it would still leave records 1–35 unclassed, i.e. it solves 14 of 49
and buys a chain rewrite for it. **A reviewer who holds that fourteen sealed
records are worth a head change should say so: that is a judgement, and this
paragraph is where to overturn it.**

**Rejected: forty-nine superseding records.** Concretely broken, not merely
heavy. `supersededSubjects` marks originals WITHDRAWN, and
`coveringDefinitionsForRow`, `VerifyCensusRowsAreLedgered` and
`UnledgeredEvidenceDemands` all refuse a superseded record as coverage, so the
handshake-mapping and public-corpus censuses would lose their coverage and
`unledgered_disagreements` would leave zero. That analysis is the
ledger-disposition round-1 review's; this branch did not repeat the mistake it
prevented, and the gate confirms the counter is still 0.

**Chosen: a sealed side document,
`evidence/java/legacy-record-adjudications.json`,** with
`internal/deltaledger/legacy_adjudication.go` as the rule that stops it being a
place to type words. Every entry is bound to its record by CONTENT — an identity
RECOMPUTED from the record's own disagreement digest, the record digest, the
subject, a verbatim quote of the record's own hashed rationale that appears in
no other record, a subset of the record's own RFC refs and its exact Java ref —
and the document is bound to the chain by the record digest at sequence 49,
which, the chain being hash-linked, pins every byte of records 1–49.

The 1.2.0 landing rejected a document-level side table AS A REPLACEMENT FOR
PER-RECORD FIELDS ON NEW RECORDS. That argument does not reach the forty-nine:
they cannot carry a field, so their choice is "side table or nothing". The range
rule enforces the distinction — an entry for a record after sequence 49 is
refused even when it is correct in every other respect
(`TestAnOtherwisePerfectEntryIsStillRefusedForAPostVocabularyRecord` builds one
out of record 50's own content and asserts the gate reports exactly one
problem).

---

## 2. The forty-nine, by class

| verdict | count | sequences |
|---|---|---|
| `java-quirk` | 26 | 1–12, 17, 18, 25–28, 30, 32, 35, 40, 41, 42, 44, 48 |
| `underspecified-behavior` | 20 | 13–16, 20–24, 29, 31, 34, 36–39, 43, 45, 46, 47 |
| `rust-defect` | 2 | 33, 49 |
| **honestly `evidence-does-not-settle-it`, with a stated blocking question** | **1** | **19** |
| **`not-examined` (I did not look)** | **0** | — |

**49 of 49 examined. One is honestly unresolved; none is unexamined, and the two
are different states the document can tell apart.** `not-examined` is a
first-class verdict in the vocabulary precisely so that "I did not look" is
representable; it counts against the published residual exactly as an unclassed
record does, and a probe (`an entry is filed not-examined, which is
representable and still counted`) proves the residual rises when it is used.

Sequence 19 is the unresolved one. Its own sealed `java_value` preimage reads
`undefined-in-evidence: negative signed-long length with untested downstream
behavior (outside the verified space)`. Section 5.2 is determinate, so the class
turns entirely on which side Java is on, and the committed evidence records no
Java observable there. The blocking question names the **OWNER ACTION**: execute
the high-bit-64 seed (`rust/ws-core/fuzz-seeds/us012/high-bit-64.hex`) against
the pinned Java-WebSocket 1.6.0 jar through the same oracle path the rest of the
ledger's Java observations use, and record whether the negative-long length
produces a 1002 close, some other typed rejection, or a hang. **No gate on this
branch may trigger a live Java execution and none did.**

### Honesty note on the arguments

All 49 arguments are distinct strings and all 49 rationale quotes are distinct.
But five families share a common argument body, differing only in an opening
sentence naming the specific clause and observable: sequences 1–5 (17 entries in
total across the families), 6–9, 11–12, 14–16 and 36–38. That is a fair
reflection of the records — five ways to omit or malform a handshake field, one
predicate — but a reader should know the reasoning is templated within a family
rather than written five times.

---

## 3. The counters, and why neither is pinned

Two counters answer two questions, and **both are recomputed**:

- `records_without_mismatch_class` (in the ledger document) counts records with
  no FIELD. It is **still 49** and its meaning is unchanged. Forty-nine sealed
  digest preimages cannot gain a field, so a side document that moved this
  number would be describing a chain we do not have.
  `TestEveryPreVocabularyRecordIsAdjudicated` asserts it recomputes to exactly
  `PreVocabularySequence`.
- `records_without_ac3_class` (in the adjudication document) counts records that
  state no AC3 class ANYWHERE — field or sealed entry. It is **1 of 56**: the
  one honestly unresolved record.

Neither is pinned. The schema for the new counter has no `const`, carries a
description saying there must never be one, and the value is recomputed over the
whole chain by `CountRecordsWithoutAC3Class` before it is compared. Two readings
prove that is not decoration:

- publishing `records_without_ac3_class: 0` on the committed document, gate at
  **exit 1**: `the document publishes records_without_ac3_class=0 but 1 of the
  56 records in the chain state no AC3 mismatch class …`;
- deleting the body of the counter so it always reports zero (attack D41) turns
  the committed baseline red — `recomputed residual 0, document publishes 1`.
  A counter rigged to zero cannot coexist with an honest document.

---

## 4. Records contested by later evidence

**Four of the forty-nine are contested. This is the section that changed most in
this round.**

### 4.1 Sequence 13 — contested, correction DRAFTED

Sequence 13's sealed `rfc_expectation` says RFC 9112 section 2.2 "forbids a bare
LF as a line terminator". Sequence 39 — later, same clause, client direction —
reads it correctly as a recipient **MAY**, and its `rfc_value` opens
`recipient-choice:`. One of the two readings is wrong and it is the earlier one.
The entry files sequence 13 as `underspecified-behavior` on the corrected
reading, sets `contests_record_basis`, and names
`drafts/ledger-proposals/legacy-13-bare-lf-server-basis-correction.json`.
`TestSequence13BareLFBasisIsContradictedBySequence39` re-verifies the finding's
premise from both records' digest preimages so it cannot quietly become false,
and `TestTheSequence13CorrectionDraftReproducesItsOwnIdentity` holds the draft
to the standard the seven landed drafts are held to — its declared `delta_id`
must be a function of its own six preimages — and asserts it is **not** in the
chain.

### 4.2 Sequences 14, 15 and 16 — contested, correction ALREADY IN THE CHAIN, and the first version of this document recorded that only in prose

These three bound the RFC basis "section 10.4 requires a handshake size bound",
their `rfc_value` opens `reject:`, and records 45, 46 and 47 later corrected it:
section 10.4 is scoped to FRAMES and to total message size after reassembly, the
opening handshake is neither, and the corrected `rfc_value` opens
`no-requirement:`. The chain records the supersession.

The first version of this document took the class from the corrected basis —
which is right — and said so **in the `argument` field**, the one field nothing
checks, while `contests_record_basis` stayed `false`. The schema even described
leaving it false as the design. **A finding recorded where nothing checks it is
a footnote**, which is exactly what the task said it must not be.

What changed: `VerifyLegacyAdjudications` now re-derives the supersession links
from the RECORDS' own hashed rationales (`ReadSupersessionLinks`, not the sidecar
that declares the same links) and refuses

- an entry adjudicating a superseded record that does not set
  `contests_record_basis`;
- a `superseded_by_sequence` the chain does not say, its absence when the chain
  does say one, and its presence when the chain says none;
- **a withdrawn record filed under a class different from the class filed for
  the record that replaced it** — two adjudications of one subject may not
  disagree about where the mismatch originates.

`contests_record_basis` now has two discharges rather than one: a held draft, or
a superseding sequence already in the chain. Drafting a correction for a record
the chain has already corrected would be proposing a record that exists.

**RED reading for the rule, taken from the process:** with the rule added and the
document unchanged, the committed document was refused with **six problems**
naming exactly sequences 14, 15 and 16 (`the chain records this record as
SUPERSEDED by sequence 45 … but the entry does not set contests_record_basis`,
and the matching `superseded_by_sequence 0` refusal, for each of the three).
Regenerating the document changed those three entries and nothing else.

### 4.3 Cross-referenced by later evidence but NOT contested — and why that is a judgement

- **Sequence 32** (invalid-UTF-8 close reason, runtime rejection) is
  *corroborated*, not contested: divergence sweep 3, which became record 53,
  cites "the rejection already ledgered at behavior-delta sequence 32" as its
  starting point. Both are filed `java-quirk`.
- **Sequence 34** (batch-drain echo/flush ordering, `underspecified-behavior`)
  and **record 54** (a close overtaking a large pending echo, `rust-defect`)
  are filed under different classes. Record 54's own sealed rationale says why:
  "It is NOT sequence 34: that record is about a FAILURE path's flush and this
  is a clean close with no protocol violation." I follow that distinction. It
  is a judgement, and the place to overturn it is here: **if a reviewer holds
  that the two are one observable, then one of the two classes is wrong.**
  Record 54 also states the condition under which it would be revisited — a
  reproduction showing the port cannot enqueue the echo without breaking
  sequence 34's ordering — and that would move record 54's DISPOSITION, not
  sequence 34's class.
- **The DIV-06 handshake fix** (`drafts/ledger-proposals/div06-handshake-response.json`)
  and **the server TCP close** (records 50 and 52,
  `drafts/ledger-proposals/server-close-parity.json`) changed the PORT. A port
  change is a disposition, not a class: the mismatch a legacy record binds is
  `(rfc_expectation, java_observation)`, and neither of those moves when the
  port is fixed. Both entered the chain as records 50–56, not as any of the 49.
  `server-close-parity.json` mentions sequence 35 only as the frozen-prefix
  boundary.

### 4.4 The sweep that found these

I grouped every record in the chain by the RFC clauses it cites and by the
observable its subject names, over the DIGEST PREIMAGES rather than over prose,
and looked for one clause normalized two ways. The 13/39 pair and the
14–16/45–47 triple are what came out. The sweep is a scratch script and is not
committed: it is an authoring aid, and the findings it produced are pinned by
committed tests instead (`TestSequence13BareLFBasisIsContradictedBySequence39`
for the first, and the supersession rules above for the second).

---

## 5. The frozen prefix — checked, not assumed

Three independent readings, all taken this round:

1. `git diff --quiet <mainline>...HEAD -- evidence/java/behavior-delta-ledger.json`
   → **exit 0**. This branch does not touch the ledger document at all.
2. Byte comparison of the canonical serialization of records 1–35 between this
   branch and mainline: `sha256 0fc1fec17d1f3db3…` on both — **identical**. The
   same comparison over records 1–49 is also identical
   (`88f329782d22f90a…`).
3. The record digest at sequence 35 reads
   `sha256:3fcd461cfea72e049628a0031bfbb90addecea2f2bb6997e62280cad1962656d`,
   which equals `deltaledger.FrozenPrefixHead`, and
   `deltaledgerctl --check` reports `frozen prefix through sequence 35` in a
   run that exits 0.

---

## 6. RED readings

### 6.1 The gate itself, at the process level

`VerifyLegacyAdjudications` is called from `VerifyIntegrity`, which is what
`rust/Makefile`'s `ledger-gates` target runs — not from a `_test.go` file. Three
readings against the real binary, all with
`VJWP_PROTECTED_STORE` pointed at `evidence/governance/decisions`:

| what | command | exit |
|---|---|---|
| committed state | `go run ./cmd/deltaledgerctl --root . --check` | **0** |
| one entry dropped and the residual corrected for it | same | **1**, `sequence 7 carries no adjudication…` |
| `records_without_ac3_class` faked to 0 | same | **1**, `publishes records_without_ac3_class=0 but 1 of the 56 records…` |
| `make -C rust ledger-gates oracle-hierarchy-gates` | | **0** |

The gate prints both counters side by side on success, deliberately: reading
either one alone misdescribes the chain.

### 6.2 The deletion matrix

**41 attacks, one rule deleted per attack, every one recompiled before running.**
Each mutation neuters a guard by conjoining `false` to it, which is deletion of
the check and cannot break compilation — a mutation that breaks compilation
proves nothing, and the driver checks `go build` before it believes any result.
The source was restored and asserted byte-identical after every attack and after
the run.

**Result: 41 red, exit 1 on every one. Zero attacks left the suite green.**
Every attack's red probe is the probe aimed at that rule.

**33 of the 41 isolate at the ADMISSION level** — with the rule deleted the gate
ACCEPTED the mutated document, so the rule is the only thing standing between
the chain and acceptance. **8 are red by MESSAGE only**: the document is still
refused, by a rule that overlaps. Naming them is the point of this section.

| attack | rule deleted | why it is message-only |
|---|---|---|
| D06 | the chain-length early return | Not a redundancy — **the gate PANICS** (`index out of range [48] with length 10` at `legacy_adjudication.go:288`). The probe catches it because a panic fails the test. A gate that panics is a gate whose result nobody reads, so this check is load-bearing in the strongest sense. |
| D09 | the duplicate-sequence refusal | A duplicated entry is also out of ascending order, so D10's rule refuses it. |
| D13 | the stored `delta_id` comparison | `AC3ClassFor` looks a record's class up by the delta_id the RECORD stores, so a drifted stored value also makes the record count as unclassed and the residual refuses. Redundant against the committed chain; kept because it names the actual defect. |
| D16 | a settled entry must state a class | All forty-nine lack a field, so an empty class also raises the residual. |
| D18 | an unsettled entry may not state a class | Symmetrically, it lowers the residual. |
| D26 | the quote length floor | A short quote is also non-unique, so the uniqueness rule refuses it. |
| D35 | a superseding sequence named without the flag | Always also either a supersession the chain does not record or a withdrawn record left undeclared. |
| D36 | a withdrawn record must be adjudicated as withdrawn | Overlaps D37 (the sequence must be the one the chain says). |

**The pair deletion D36+D37 is the reading that matters for §4.2**, because
either rule alone covers the other. With BOTH deleted the gate **accepted** a
document that adjudicates a withdrawn record in silence:

```
the gate accepted a document in which an entry adjudicates a withdrawn record
without saying it is withdrawn
the gate accepted a document in which an entry names a superseding sequence the
chain does not say
```

So the supersession rules are jointly load-bearing, and neither is individually.

### 6.3 The two attacks that did not isolate in the previous round — finished

Both are now isolated at the admission level, and both readings are quoted from
the process rather than paraphrased.

**D11, the totality rule.** The first probe dropped an entry, and the gate went
red on the RESIDUAL recomputation instead — the dropped record counted as
unclassed. A red light from the wrong check is not evidence about the check
under attack. The isolating probe drops the entry AND corrects the published
residual for it, which removes the residual's signal. With the totality rule
deleted:

```
the gate accepted a document in which an entry is dropped AND the residual is
corrected for it, so only totality can refuse
```

That is what stops "adjudicate 48 of 49 and publish an honest 2" from being a
way to make a record disappear rather than be judged.

**D12, the identity recomputed from the disagreement digest.** The first probe
changed only the entry's `delta_id`, and the cheaper stored-`delta_id`
comparison caught it. On the committed chain the two are always equal — the
builder derives the stored value from the digest — so that probe could say
nothing about the recomputation. The isolating probe tampers the RECORD's stored
`delta_id` to agree with the tampered entry, which is the shape a hand-edited
ledger document has and the only shape the committed chain cannot produce. With
the recomputation deleted:

```
the gate accepted an entry whose delta_id agrees with a TAMPERED stored delta_id
but not with the identity the record's own disagreement digest produces
```

### 6.4 Probe coverage

Nine top-level tests: two baselines (the committed document passes its own gate;
every pre-vocabulary record is adjudicated and both counters recompute), one
table of **forty** discrimination probes, four standalone refusal probes that
the table's shape cannot express, and two tests pinning the sequence-13 finding
and its draft. **Every
`fail()` site in `legacy_adjudication.go` now has a probe aimed at it except
two**, and those two are named rather than counted:

- the index/sequence sanity check (`record at index N carries sequence M`), and
- the identity-derivation error arm (`the record's disagreement digest does not
  yield an identity`).

Both need a malformed CHAIN rather than a malformed document, and the chain is
regenerated and verified by a different gate. I did not build a probe for
either.

Every probe mutates the COMMITTED document in a temporary root and calls
`VerifyLegacyAdjudications` — the exported function `VerifyIntegrity` calls — so
no rule can be strong in the test binary and absent from the gate. The tests
have no rules of their own.

---

## 7. What I did NOT do

- **I appended nothing to the ledger.** The one proposed correction (sequence
  13's RFC basis) is drafted under `drafts/ledger-proposals/` and a test asserts
  it is not in the chain.
- **I did not run any owner-gated work.** No AWS, no benchmark, no Autobahn
  execution, and no live Java execution — which is why sequence 19 is unresolved
  rather than classed. The owner action it needs is stated in §2.
- **I did not touch `assurance/concurrency/results.json` or
  `assurance/concurrency/plan.json`.** I read plan.json's pinned ledger head to
  argue §1 and changed nothing in it.
- **I did not weaken any existing check.** The only rules that changed shape are
  the contest obligation (one discharge → two, both checked) and the addition of
  the supersession rules; the previously existing refusals all still fire, and
  their probes still pass.
- **I did not probe two `fail()` sites** (§6.4), and I did not build the
  malformed-chain harness that would reach them.
- **I did not re-derive the Java observations.** Every adjudication argues from
  the records' own sealed preimages and the pinned source citations already in
  them; I read the pinned tree only where a record's own rationale cited a file
  and line.
- **The contest sweep script is not committed.** Its findings are pinned by
  tests; the script itself is an authoring aid and would rot.

## 8. Where this can be overturned

1. **Sequence 10** (`duplicate-header`, `java-quirk`) is the weakest of the
   java-quirk calls and the entry says so in its own argument: RFC 9110 section
   5.3's separator sentence is written for list-based fields, and a reader who
   holds that the RFC leaves a recipient's handling of a duplicated NON-list
   field open would file it `underspecified-behavior`. I followed the record's
   own sealed normalization (`reject:`) rather than overriding it.
2. **§1's rejection of an in-place rebuild of records 36–49** is a cost
   judgement, not a proof.
3. **§4.3's separation of sequence 34 from record 54** is a judgement I took
   from record 54's own sealed prose.
4. The class of a record whose port behaviour was later fixed does not move —
   that is the "a disposition is not a class" reading, applied throughout. A
   reviewer who reads AC3's classes as being about the CURRENT state of the port
   rather than about where the mismatch originated would reclass several of the
   26 java-quirks.
