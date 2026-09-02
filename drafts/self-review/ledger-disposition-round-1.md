# ledger-disposition — self-review round 1

- Written 2026-09-02. Branch `claude/ledger-disposition`, based on mainline
  `claude/feature/verified-java-websocket-port` at `57e881c`.
- Subject of the round: the behaviour-delta ledger's **disposition vocabulary**
  (criteria-audit finding 8), the seven records that were waiting for it, and
  the checks that keep it from being decorative.
- Every exit code below was read from the process. `VJWP_PROTECTED_STORE` was
  exported for every Go and gate invocation, so the governance arm ran rather
  than being skipped.
- OWNER_ATTESTED_NOT_INDEPENDENT. This is my own review of my own work.

## The finding, restated precisely

`schemas/behavior-delta-ledger-1.1.0.schema.json` admitted two dispositions,
`unresolved` and `rfc-governs`. `internal/deltaledger/build.go` assigned the
**literal** `"unresolved"` to every record it built. So all 49 committed records
read `unresolved` — not because 49 adjudications came out that way, but because
no definition could say anything else. The package doc said so in as many words
("the frozen 1.0.0 vocabulary has no java-faithful term"), and that same sentence
is inside every record's hashed rationale.

Child US-020 AC3 requires every mismatch to be recorded "as **Java quirk, Rust
defect, or underspecified behavior**". Those three classes were not in the
vocabulary at all, so that classification had never been made for any record.

Seven records were drafted under `drafts/ledger-proposals/` and held, because
none of them is `unresolved` or `rfc-governs`: one is a divergence the port
**adopts**, five are places the port is **short of its target**, one is a
difference the port **keeps deliberately**.

## The vocabulary, and what it is not

**Two fields, because there are two independent questions.**

`disposition` — what the program DOES. Extended, never redefined:

| term | meaning | provenance |
|---|---|---|
| `unresolved` | no adjudication; the decision is owed | frozen 1.0.0, unchanged |
| `rfc-governs` | the RFC governs and the port follows it | frozen 1.0.0, unchanged |
| `adopt-java` | the port reproduces Java, RFC departures included | foundation schema's `PRESERVE` |
| `fix-in-port` | the remedy is a change in the Rust port | the sweep's `FIX_IN_PORT` |
| `intentional-correction` | the port deliberately differs from Java and keeps it | foundation `INTENTIONALLY_CORRECT` / sweep `LEDGER_INTENTIONAL_CORRECTION` |

`mismatch_class` — where the mismatch ORIGINATES. US-020 AC3's three, and the
rule for choosing between them is stated once and applied seven times:

| term | the RFC | Java | the port |
|---|---|---|---|
| `java-quirk` | determinate | on the other side of it | — |
| `rust-defect` | agrees with Java, or leaves it open with Java as the target | correct | fails to reproduce it |
| `underspecified-behavior` | does not determine the observable | chose one way | chose another |

**Not one axis.** The seven records are the proof that one enum cannot work.
The RFC's silence about handshake field order yields BOTH a record the port
keeps deliberately (client request order, sequence 56) and one it still owes an
answer for (the 101 response's `Server`/`Date` fields, sequence 55): same class,
different disposition. A Java quirk yields both one the port adopts (sequence
50) and one nobody has ruled on (sequence 53). A single enum would need the
cross product and would force a record to misstate one axis to state the other.

**The new field is named `mismatch_class`, not `classification`, on purpose.**
The inherited foundation schema `assurance/schema/behavior-delta-ledger.schema.json`
already uses `classification` for the *adoption* axis
(`PRESERVE | INTENTIONALLY_CORRECT | UNRESOLVED`). Reusing that name for AC3's
*attribution* axis would have put two different meanings on one word across two
schemas in one repository.

## What I rejected, and why

**(a) Rewrite the 49 with the new terms.** Forbidden outright: the record digest
preimage is `{schema_version, sequence, previous_digest, delta}`, so changing a
delta rewrites the chain from that record on, and
`protected/ledger-frozen-prefix-owner-decision-2026-08-28.json` requires the
prefix through sequence 35 to stay byte-identical.

**(b) Bump the per-record `schema_version` to 1.1.0.** Same defect. The 1.1.0
document says this itself: the per-record version is inside the preimage.

**(c) 49 superseding "adjudication" records.** Not merely heavy — **concretely
broken**, and I checked the mechanism before rejecting it. A delta's identity
derives from its disagreement digest, so a second record about the same
disagreement collides on `DUPLICATE_ENTRY` unless its subject is perturbed; 49
synthetic subjects would have to be minted to carry a judgement. Worse,
`supersededSubjects` would then mark the originals withdrawn, and
`coveringDefinitionsForRow`, `VerifyCensusRowsAreLedgered` and
`UnledgeredEvidenceDemands` all refuse a superseded record as coverage — so
adjudicating the 49 this way would strip the handshake-mapping and public-corpus
censuses of their coverage and drive `unledgered_disagreements` off zero. The
shape that looks like the most respectful of history destroys the most evidence.

**(d) A document-level side table only,** in the shape of the 1.1.0
`supersessions` array, with no per-record field. It would let all 56 records be
adjudicated without touching a digest — but a new record's adjudication would
then live outside the hash chain, unsealed. Rejected for NEW records. The 49
necessarily depend on something like it, and the honest answer to that is the
published residual below, not a derived value dressed up as a sealed one.

**(e) Extend `disposition` only.** Cannot express AC3's three classes without
the cross product.

**What I chose: an OPTIONAL trailing field, plus a published residual.**
`intake.CanonicalJSON` is `json.Marshal` + compact, so a struct field carrying
`omitempty` and holding `""` contributes **zero bytes** to the preimage. The 49
keep their digests exactly; the head before this landing,
`sha256:eaa6eac8…`, is still the record digest at sequence 49, and sequence 35 is
still `sha256:3fcd461c…`. The cost is that the 49 carry no class, and the ledger
now **publishes that cost**: `records_without_mismatch_class = 49`, computed
never assigned, recomputed by `deltaledger.VerifyAdjudication` and again by
`lab.VerifyBaselineEvidence`. It is deliberately not schema-pinned to 0 — that
is exactly the fake gate `unledgered_disagreements` used to be.

**Absence is not silence.** `VerifyAdjudication` refuses an unclassed record
unless it is at or before `PreVocabularySequence` (49) **and** its own hashed
rationale carries one of the two retention statements the 49 actually contain
(45 carry the shared owner-decision sentence; 33, 34, 35 and 49 carry a bespoke
`DISPOSITION NOTE`). The grandfathering therefore rests on what a record SAYS,
inside its digest preimage, not on its position alone — and a record that says
"deliberately retained" may not declare `fix-in-port` or `intentional-correction`.

## The seven records

Appended at sequences 50-56 through the real path: a Go `Definition` added to
`internal/deltaledger` plus regeneration. Not one byte of the JSON was hand
edited. **Every one reproduces its draft's `delta_id` exactly**, and that is
checked by recomputing the identity from the draft's own six digest preimages
rather than by comparing names.

| seq | subject | disposition | mismatch_class | the argument |
|---|---|---|---|---|
| 50 | `adapter.role-gated-transport-close` | `adopt-java` | `java-quirk` | RFC 5.5.1 is determinate (close TCP after a Close is both sent AND received); Java gates on `isFlushAndClose()`, so a Java SERVER that INITIATES a close hangs up early. The port now carries that gate verbatim. |
| 51 | `websocketimpl.failure-close-frame-emission` | `fix-in-port` | `rust-defect` | RFC 7.1.7 and Java AGREE; the port was short of both on 122/247 server and 119/247 client cases. The fix (77d8c23) is in mainline; the RE-MEASUREMENT is not, and an Autobahn re-run is an owner gate. |
| 52 | `websocketimpl.server-tcp-close-after-close-handshake` | `fix-in-port` | `rust-defect` | RFC 7.1.1 and Java AGREE; 123/247 server cases, disjoint from 51's. The same landed change closes it; the two are different propositions (50 binds the RFC-divergent *initiated*-close half, 52 the *echo* half). |
| 53 | `closeframe.invalid-utf8-reason-transport-stall` | `unresolved` | `java-quirk` | RFC 8.1 + 7.1.6 are determinate and Java STALLS; the port is the side that agrees with the RFC. Reproducing Java means holding a socket a peer already misused — a safety tradeoff only the owner can weigh, and the record names that ruling. |
| 54 | `websocketimpl.pending-echo-versus-close-ordering` | `fix-in-port` | `rust-defect` | Java delivers a 256 KiB echo then answers 1000; the port drops both. RFC 5.5.1 licenses neither. The precondition is a reproduction — work the port can do, not a ruling — so it is a fix, with the precondition stated. |
| 55 | `draft6455.server-handshake.response-server-and-date-fields` | `unresolved` | `underspecified-behavior` | RFC 4.2.2 neither requires nor forbids `Server`/`Date`; 247/247 server cases differ. `Date` carries a CLOCK, and putting one into a deterministic core is a tradeoff only the owner can weigh. |
| 56 | `handshake.field-emission-order` | `intentional-correction` | `underspecified-behavior` | RFC 4.1 does not constrain order and RFC 7230 makes it insignificant; 247/247 client cases. No tradeoff at all, so the evidence settles it: the port's fixed order is kept and disclosed. |

**The rule I applied for `unresolved`**, stated so it can be argued with: the
disposition is the draft's own recommendation where the evidence settles it, and
`unresolved` where the two candidate answers trade off something only the owner
can weigh — safety (53), determinism (55). A condition that is merely WORK the
port can do (54's reproduction) does not make a disposition unresolved.

**The rationales are not the drafts' rationales, deliberately.** Each draft ends
in a RECOMMENDATION written by an author who could not record it; DIV-01's says
in as many words that the record "stays unresolved", which would contradict the
disposition it now carries. Each appended rationale keeps the draft's measured
extent and evidence and replaces the recommendation with the adjudication. The
rationale is outside the disagreement-digest preimage — the drafts say so
themselves — so `delta_id` is unmoved.

## RED first

Every check below was made to fail before it was trusted. The polarity probes
live in `internal/deltaledger/adjudication_test.go` and
`internal/lab/evidence_test.go` and call the same exported functions the gate
calls, so a rule cannot be strong in the test binary and absent from the gate.

Baseline before the round: `go test ./internal/deltaledger/` exit 0;
`go run ./cmd/deltaledgerctl --root . --check` exit 0. Baseline after: both 0.

| # | mutation | ran | exit | what it said |
|---|---|---|---|---|
| A1 | rule 2 deleted (a record after sequence 49 must be classed) | `go test ./internal/deltaledger/` | 1 | `TestVerifyAdjudicationRefusesEachWayARecordCanSayNothing` |
| A2 | rule 3 deleted (a non-`unresolved` disposition must carry a class) | same | 1 | same |
| A3 | rule 4 deleted (an unclassed record must state retention in its own hashed bytes) | same | 1 | same |
| A4 | rule 5 deleted (the field may not contradict the hashed prose) | same | 1 | same |
| A5 | the residual recomputation deleted from `VerifyAdjudication` | same | 1 | same |
| A6 | the residual recomputation deleted from `lab.VerifyBaselineEvidence` | `go test ./internal/lab/` | 1 | `TestReadinessRefusesAnUnderstatedMismatchClassResidual` |
| A7 | the disposition vocabulary opened in `lab.BehaviorDelta.Validate` | `go test ./internal/deltaledger/` | 1 | `TestTheDeltaVocabularyIsClosed` |
| A8 | the mismatch-class vocabulary opened there | same | 1 | same |
| A9 | `mismatch_class` removed from the 1.2.0 schema (`additionalProperties: false`) | `deltaledgerctl --check` | 1 | `ledger integrity: [evidence-document-schemas]` |
| A10 | **`omitempty` removed from `mismatch_class`** | `go test ./internal/deltaledger/` | 1 | `TestCommittedLedgerMatchesTheRecordedDivergenceDefinitions` — the whole chain rewrites, which is the point |
| A11* | an unclassed NEW record, document REGENERATED, adjudication call deleted | `deltaledgerctl --check` | 1 | did NOT isolate: the held-draft binding caught it instead (`[proposal-drafts-ledgered]`) |
| A11** | an EIGHTH unclassed record at sequence 57 — one no draft is about — regenerated | `deltaledgerctl --check` | 1 / **0** | with the call: `sequence 57 carries no mismatch_class`; **with the call deleted: exit 0**. The gate call is load-bearing. |
| A12 | the draft-binding call deleted AND `server-close-parity.json` edited | `deltaledgerctl --check` | **0** | paired probe: green is the expected half |
| A12b | the same edit with the call in place | same | 1 | `[proposal-drafts-ledgered] … declares delta_id … the disagreement rebuilt from its own six digest preimages is …` |
| A13* | the DIV-07 definition deleted, regenerated, draft-binding removed | `deltaledgerctl --check` | 1 | `[unledgered-disagreements] 1 observed disagreement(s) have no ledger record` — the observation set outlives the record |

**Two attacks did not isolate on the first attempt, and I say so rather than
counting them.** A11 and A13, run as plain deletions, both went red on the
BYTE-EQUALITY comparison (`does not equal the deterministic regeneration`)
rather than on the rule under attack. A red light from the wrong check is not
evidence about the check you were attacking. Both were redone with the document
regenerated after the mutation, which removes the byte-equality signal; A11 then
had to be redone a second time (A11\*\*) because the held-draft binding caught
the first defect independently. Only the third form isolates.

**The paired probe A12/A12b is the one that answers "is the draft binding a
gate?"** `divergencesweep` byte-verifies the six sweep drafts against the run
reports, so an edit to one of them is caught elsewhere; `server-close-parity.json`
is verified by **nothing else**, so editing it isolates my check exactly.

## What the checks bind, and the shape I was hunting

`VerifyProposalDraftsAreLedgered` deliberately does **not** check that a record
with the drafted SUBJECT exists. A subject reference is a name. It recomputes
the disagreement digest and the delta identity from the draft's own six preimage
STRINGS, by the same construction `internal/lab` uses, and requires (a) the
draft's declared `delta_id` to equal that recomputation and (b) a record in the
chain to carry exactly it. A12b plants one extra character in one preimage —
subject, `delta_id` and every reference untouched — and the check refuses it.

`AssertsRetention` matches two exact sentences. Those are CONTENT: each is
inside the digest preimage of every record that carries it, so a changed byte
breaks the record digest and `VerifyFrozenPrefix` fires. It is not a name test.

## Findings on my own work, each fixed before the round closed

**Finding 1 — a source-kind classifier that hands back a plausible label for a
record whose evidence is somewhere else.** `observationSourceKind` keys on
subject substrings. The new record
`draft6455.server-handshake.response-server-and-date-fields` carries the
`.server-handshake.` segment, so it was labelled
`live-handshake-exam-case-or-borrowed-seed` — and that is FALSE. The handshake
exam scores the accept/reject decision and the `Sec-WebSocket-Accept` value; it
never observes the response field SET, which is precisely why this divergence
went unrecorded until the executed native x86_64 run measured it on 247/247
cases. The subject is now named explicitly ABOVE the direction arms, with the
ordering dependency written down.

**Finding 2 — a record whose evidence nothing could open.** The provenance
recogniser matched `rust/ws-core/…` only. The role-gated transport close
record's entire in-repository evidence is `rust/ws-testee/src/io_loop.rs` and
`rust/ws-testee/tests/loopback.rs`, so its derived provenance came out EMPTY —
and the existing gate refused it (`provenance 49 … names no evidence`, plus a
schema `minItems` failure). That refusal was correct and I did not weaken it;
the pattern now matches any Rust crate, and `ProvenanceIsResolvable` requires
those paths to exist. Side effect, checked: two pre-existing records (33 and 34)
gained citations their hashed rationales already made and the recogniser could
not see. No pre-existing observation's digest tuple changed.

**Finding 3 — sequence 49 had no observation at all.** Regenerating the
observed-disagreement set added **eight** entries, not seven: the C6
protocol-violation record landed at sequence 49 without the observation set
being regenerated, so nothing in the digest arm outlived it. It does now. I
verified before committing to the regeneration that all 48 pre-existing
observations and all 48 provenance entries were byte-identical afterwards, so
the refreeze absorbed no drift.

**Finding 4 — a tripwire fired and I followed it rather than muting it.**
`internal/divergencesweep`'s `TestProposedLedgerRecordsHaveNotLandedYet`
asserts each proposed subject ref is ABSENT from the ledger. Appending the six
made it fail, exactly as designed, with the instruction "the proposal has
landed, so update this sweep's recommendation". The rule is now the CONSISTENCY
one and is **strictly stronger**: a proposal the ledger carries must be recorded
as landed at that exact sequence (so an unrecorded landing still fails, and a
wrong sequence now fails too), and a proposal it does not carry must not claim
to have landed. Both directions are checked and both arms have a vacuity guard.
I did **not** convert those classes to `ExistingLedgerSubjectRef`: that field
carries a second obligation — every case the class selects must be cited at that
same sequence by the committed behaviour-class divergence register, which is
MEASURED evidence from the run and must not be edited to accommodate a later
append.

**Finding 5 — a test fixture that would have passed for the wrong reason.**
`internal/lab`'s `TestReadinessRefusesAWithdrawnRecordAsCoverage` builds a
synthetic chain and left the committed document's residual in place, so the new
recomputation refused on THAT instead of on the withdrawn record. The fixture
now recomputes the residual for its own chain. This is a fixture correction, not
a relaxed check: the rule it exercises is unchanged and A6 shows the new rule is
independently load-bearing.

## The concurrency plan's `append_blocker`

`assurance/concurrency/plan.json`'s `behavior_delta_ledger.append_blocker` is
capped at 8192 characters by the schema's shared `$defs/text` bound — shared
with many other fields, so raising it would weaken a check across the whole
document and was not available. It stood at 8179, leaving 13 characters, and
four of its statements became false or incomplete:

1. "the ledger now carries 49 divergence records" — now 56.
2. the composition list stopped at sequence 49 and would have understated the chain.
3. "The two E5b follow-ups and sequence 49 are the only records whose
   `autobahn_result`/`autobahn_value` digests bind EXECUTED observations" — 51-56
   bind the executed native x86_64 provenance run.
4. "None of this changes the committed 35-record prefix" — the claim now has to
   cover 36-49 as well, and to say why a new record field left them alone.

Those four TRUTH edits cost +168 characters and were paid for by **23 FILLER
edits worth -169**: `to be`, `which made` → `making`, `they were`, `so it is`,
articles, two adverbs (`ever`, `genuinely`), sentence joins, and nine em-dashes
turned into colons, commas or parentheses. Final length **8178**, headroom 14.

**The word-by-word proof.** The new text was built by SURGICAL REPLACEMENT on
the committed bytes — 27 named edits, everything else byte-identical — and
checked mechanically: every content token of the old text (every
whitespace-separated word that is not a closed-list function word) must appear in
the new text at least as many times. Ten tokens lost an occurrence, and each is
accounted for:

| token | why it is not a claim |
|---|---|
| `49` (3→2) | one occurrence was "carries 49 divergence records", corrected to 56. The claim was FALSE, not dropped; the other two ("sequence 49") survive. |
| `appears`, `carry`, `documented`, `enrolled`, `leaves`, `made` | verb morphology: `appearing`, `carrying`, `documenting`, `enrolling`, `leaving`, `making`. Same propositions. |
| `ever`, `genuinely` | adverbs. |
| `—` (9→0) | punctuation. |

The script is `blocker_new.py` + `blocker_diff.py` in this round's scratchpad;
the edit table with a one-line justification per edit is in `blocker_new.py`.

**What I did NOT put in that field, and where it went instead.** The full
account of the vocabulary would not fit without deleting claim-bearing prose, so
the field carries only what its own statements now require. The account lives in
`schemas/behavior-delta-ledger-1.2.0.schema.json`'s descriptions, in
`internal/deltaledger/adjudication.go`'s header, and here.

## Liveness

Nothing on this branch adds a wait, a poll or a budget. No check here is bounded
by an iteration count, because no check here waits for anything: every one is a
pure function of committed bytes. The F005 class does not arise.

## What I did NOT do, by name

- **No Autobahn run, no benchmark run, no AWS run.** Records 51-56 carry the
  measured extent of the `518b77aa` build from run
  `us019-prov-20260828T183623Z` and each one says in its own rationale that no
  re-run has confirmed the fixes that have since landed. **Owner action needed
  to close 51 and 52: authorize an Autobahn re-run of the 247-case pinned
  manifest against current mainline in both roles.** The per-case sets in those
  records are the acceptance criteria it should be scored against.
- **I did not classify the 49 pre-vocabulary records.** They cannot be
  classified in place without rewriting sealed digests, and I rejected every
  shape that would classify them out of chain. `records_without_mismatch_class`
  publishes the number. Reducing it requires per-record adjudication work that
  is not this task.
- **I did not edit the seven draft files.** Six are byte-verified against the
  sweep by `internal/divergencesweep.VerifyProposals`, so their
  `draft_status: "NOT APPENDED — proposal only"` and their placeholder
  `disposition: "unresolved"` are now **stale for all seven**. The binding check
  compares digest preimages and identity, never those two fields. Correcting
  them means changing the sweep's proposal generator, which is a different
  track's artifact.
- **I did not verify the two `unresolved` records' owner rulings exist.** 53 and
  55 name the ruling each needs; neither has been made.
- **I did not re-measure DIV-02, DIV-03, DIV-05 or DIV-07 against current
  mainline.** The sweep's own round-1 review already records that gap; my
  records inherit it and say so.
- **`internal/lab`'s `TestControlledCanaryRequestIsClosedAndRequiresAuthenticatedPromotions`
  and `internal/portplan` fail on this branch.** Both are the documented
  baseline failures (Darwin `sandbox-exec`; vendor-bound) and neither is mine.

## What I could not establish

- **That the residual can only fall.** `VerifyAdjudication` refuses a NEW
  unclassed record (rule 2, A11\*\*), so the number cannot rise by an append.
  It could still rise if `PreVocabularySequence` were raised; that constant
  carries a comment saying so, but nothing mechanically forbids editing it.
- **That the two retention statements are the only ways the 49 state their
  adjudication.** I read all 49 rationales and found exactly these two wordings,
  and rule 4 refuses any record matching neither — so a third wording would fail
  the gate rather than pass silently. But the enumeration itself is mine.
- **That my seven adjudications are the RIGHT ones.** They are argued from the
  measured evidence and each argument is in the record's hashed rationale, where
  it can be disagreed with. `intentional-correction` on sequence 56 in
  particular is a judgement that byte-level handshake fidelity is out of scope,
  and the record says explicitly that this disposition is the thing an owner
  ruling would overturn.

## The concurrency results' plan digest, re-bound

`assurance/concurrency/results.json` pins `preregistered_plan.sha256` over
`assurance/concurrency/plan.json`, so editing the plan made
`TestCommittedConcurrencyResultsBindTheCommittedTree` refuse — as designed, and
it took thirteen tests in `internal/formalplan` with it. That artifact's own
`sha256_provenance` records the identical situation from the previous landing
(sequence 49 moved the same three keys), so I followed the recorded procedure:

1. **A parsed key-level diff of the plan over all 781 leaf keys** shows exactly
   three changed — `observed_head`, `observed_record_count` (49→56) and
   `append_blocker` — with no key added and none removed, and the `bounds`
   object byte-identical. The conformance statement therefore holds as written.
2. `preregistered_plan.sha256` re-bound to `sha256:3dfd5219…`, recomputed with
   `sha256sum`, and `sha256_provenance` rewritten to say what moved and why.
3. **Nothing else changed**: no counter re-measured, no seed or minimized
   artifact refrozen, neither the exploration nor the fatal-termination sweep
   re-executed. `git diff --numstat` on that file is `3 3`.
4. The sanctioned linkage refreeze that editing the file requires
   (`LINKAGE_REGENERATE=1`, exit 0; re-verified without the flag, exit 0)
   changed exactly one line — the evidence-dag digest of that document.

## Baseline failures, established by execution rather than assumed

`internal/formalplan` was NOT on the list of known baseline failures I was
given, and it fails on this branch. It also fails identically on **pristine
mainline `57e881c`**, extracted with `git archive` into a scratch tree and run
there:

```
--- FAIL: TestUS006FixtureCatalogThroughRealCLI
    ensure quarantined source: JAVA_SOURCE_UNAVAILABLE_OFFLINE: pinned immutable URL returned HTTP 403
--- FAIL: TestShippedModelArtifactsValidateClean/{FrameModel,CloseModel}
    advisory: MODEL_CITATION_UNVERIFIED …: quarantined Java tree unavailable
--- FAIL: TestTargetsRound1CloseClaimMatchesShippedReentrancy
    quarantined tree unavailable: JAVA_SOURCE_UNAVAILABLE_OFFLINE: … HTTP 403
```

The cause is `internal/portplan/acquire.go`'s re-acquisition of the pinned Java
archive over HTTP, which this sandbox's proxy answers with 403 — the same root
cause as the `internal/portplan` failures already on the list. It is a third
environmental baseline failure, not a fourth thing I broke.

**The discriminator that matters**:
`TestCommittedConcurrencyResultsBindTheCommittedTree` **passes** on that same
pristine tree. It was the one my plan edit broke and the re-binding above fixed,
and it is absent from the failure list on both trees now.

## Exit codes, read from the process

| command | exit |
|---|---|
| `go build ./...` | 0 |
| `go run ./cmd/deltaledgerctl --root . --check` | 0 — 56 records, head `sha256:a44191d3…`, document schema 1.2.0, `unledgered_disagreements=0`, `records_without_mismatch_class=49` |
| `make -C rust gates` | 0 — fmt-check, clippy, `cargo test --workspace --all-targets --all-features`, `cargo test --workspace --release`, `ac1-gates` 8/8, `ledger-gates` |
| `go test -count=1 -timeout 40m ./...` | 1, on the three environmental baseline packages only: `internal/lab` (Darwin `sandbox-exec`), `internal/portplan` (vendor-bound) and `internal/formalplan` (the same HTTP 403 on the pinned Java archive, shown above to fail identically on pristine mainline) |
| `go test ./internal/deltaledger/` | 0 |
| `go test ./internal/divergencesweep/` | 0 |
| `go test ./internal/linkage/` | 0 |
| `gofmt -l ./cmd ./internal` | lists only five files this branch does not touch |

### The baseline read exactly, test for test

`go test ./internal/formalplan/ ./internal/lab/ ./internal/portplan/` was run on
BOTH trees — this branch, and pristine mainline `57e881c` extracted with
`git archive` into a scratch directory. The failing set is **identical, all 17,
test for test**:

```
TestUS006FixtureCatalogThroughRealCLI                        TestFormalPreflightCloseDeliveryConsistency
TestShippedModelArtifactsValidateClean                       TestTargetsRound1CloseClaimMatchesShippedReentrancy
TestFormalPreflightBaseTreeDeepClean                         TestTargetsRound1ArithmeticClaimMatchesShippedOverflow
TestFormalPreflightDeepValidatesProofTargets                 TestTargetsRound1SweepClaimsMatchShippedSemantics
TestFormalPreflightDeepValidatesConcurrencyPlan              TestProofTargetsRealDocumentVerifies
TestFormalPreflightDeepValidatesConnectionModel              TestProofTargetsSeededDefectsBlockWithTypedFindings
TestFormalPreflightRealDocumentDeepRulesClean                TestControlledCanaryRequestIsClosedAndRequiresAuthenticatedPromotions
TestDeriveReproducesCommittedEvidence                        TestDeriveFailsWhenOracleDisagreesWithTree
TestDeriveFailsOnDeclarationLevelOracleTamper
```

This branch adds no failing test and removes none. The one it DID break —
`TestCommittedConcurrencyResultsBindTheCommittedTree` — passes on both trees
after the re-binding above, and is absent from both lists.
