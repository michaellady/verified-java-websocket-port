# Review round 1 — claude/oracle-hierarchy (US-020 AC2, criteria-audit finding 4)

Recorded 2026-09-02 from tool output on this branch. Assurance:
OWNER_ATTESTED_NOT_INDEPENDENT. Nothing here is independently reviewed.

## The finding this branch answers

US-020 AC2 (`docs/prd-pack/07c-child-prd-us020-us027.md`) reads:

> RFC 6455 is rank one, in-scope Autobahn is rank two, independent neutral
> expectations are rank three, Java observation is rank four, and Rust
> observation is rank five; agreement between Java and Rust cannot override a
> higher oracle.

Before this branch that sentence had no mechanism. A search of the Go and JSON
tree for a rank, an oracle hierarchy or an adjudication order returned one hit,
a prose string inside `internal/deltaledger/definitions_gap_closure.go:105`. No
type, no field, no check. The consequence was concrete: the 74/74 public-corpus
differential and the 247-case Autobahn per-case comparison this repository
cites as parity are both rank-four-against-rank-five comparisons — exactly the
comparison AC2 says cannot settle a question on its own — and nothing stopped
Java and Rust agreeing on something a higher oracle forbids.

## What is here

- `internal/oraclerank/rank.go` — the five ranks as a typed total order.
  `Outranks` is `<`; AC2's numbering is kept literal so it can be checked
  against the criterion without a translation table.
- `internal/oraclerank/adjudicate.go` — the override rule as executable logic.
  `Adjudicate` takes the governing rank to be the STRONGEST rank that gave a
  verdict (abstention passes governance down, disagreement does not), marks
  every subordinate dissent, and sets `JavaRustConsensusOverridden` exactly when
  ranks four and five agree and a strictly higher oracle said something else.
  `ParityFromJavaRustAgreement` is the guarded reading a consumer must come
  through to turn "Java and Rust behaved the same" into "parity"; it returns a
  typed `*ErrConsensusOverridden` naming the governing oracle when AC2 forbids
  the reading.
- `internal/oraclerank/binding.go` — per-rank binding with a computed strength.
- `internal/oraclerank/census.go` — four proposition families built from
  committed evidence, 640 propositions.
- `internal/oraclerank/probe.go` — the independence probe.
- `internal/oraclerank/findings.go` — conclusions COMPUTED from the register's
  own numbers, so a finding cannot drift from the evidence it summarizes.
- `internal/oraclerank/document.go` — the register, `Verify`, `VerifyRules`,
  `CheckFamilyRules`.
- `cmd/oraclerankctl` — `--check`, and the `oracle-hierarchy-gates` target in
  `rust/Makefile`, which `make -C rust gates` now runs.
- `evidence/oracle-hierarchy/adjudication-register.json` — the emitted register.

Nothing existing was modified except `rust/Makefile`, which gained one target
and one word on the `gates` line. `evidence/java/behavior-delta-ledger.json` and
`internal/deltaledger` were read and not touched.

## Which ranks are bound by content and which are only declared

Stated bluntly, because a rank that exists in name only is the defect class this
program keeps rediscovering and the point of the exercise was not to add
another instance.

| Rank | Strength | What it is actually attached to |
|---|---|---|
| 1 RFC 6455 | **CONTENT_BOUND_TO_RECORDED_READING** | Two committed HUMAN READINGS of the RFC (`evidence/us005-handshake-live-mapping.json` `rfc_verdict`, `evidence/us005-public-rfc-divergence-census.json` `rfc_strict_expectation`), hashed on every run. **NOT bound to the RFC text.** `evidence/intake/source-pins.json` pins `rfc6455-text` at sha256:76577532…0fa3b, 162067 bytes, and no file in this repository carries those bytes. A misreading of the RFC passes this gate unchanged. |
| 2 in-scope Autobahn | **CONTENT_BOUND** | The suite's own per-case `expected` map, read from the committed report bytes under `evidence/autobahn/native-x86_64-provenance/`, digest-manifest verified in both directions first. The map is a property of the CASE and that is asserted, not assumed: it must be byte-equal between the Java leg and the Rust leg on all 494 (case, role) pairs before it is used, so rank two's verdict is confirmed by two separately written report sets. |
| 3 neutral expectations | **CONTENT_BOUND_TO_RECORDED_READING** | The committed corpora, hashed every run — but the two tiers are not equally independent and the binding refuses to average them. All 74 public scenarios record `expectation_status = REFERENCE_MODEL_DERIVED_PENDING_ORACLE_CONFIRMATION`, and `internal/corpora.ReferenceBehavior`'s own doc comment says its defaults mirror the pinned Java-WebSocket 1.6.0 sources. **A rank-three verdict on the public tier is a restatement of a Java-shaped model, so it is not an independent check on rank four there.** |
| 4 Java observation | **CONTENT_BOUND** in three families, **AGGREGATE_DERIVED** in one, **RECORDED_READING** in one | Autobahn Java legs and `evidence/differential-regression/java-arm.jsonl` are process observations. On the public tier there is NO committed per-scenario Java transcript: the per-scenario opinion is DEDUCED from two clean-sweep aggregates (74/74/0) plus the recorded expectation, and the census refuses the deduction when either aggregate is short of a clean sweep. On the handshake tier rank four is a reading of Java SOURCES (`basis` cites `Draft_6455.java` by line), not of the process. |
| 5 Rust observation | **CONTENT_BOUND** where present, **ABSENT** on the handshake tier | Autobahn Rust legs, `evidence/differential-regression/rust-arm.jsonl`, and `rust/ws-oracle-harness/baseline/borrow-batch-c-public-transcript.jsonl` (74 records, each with its own `final_state`). **No per-case Rust handshake transcript is committed at all**, so rank five abstains on all 49 handshake propositions and that family cannot exercise AC2's final clause. |

The per-family strengths are in the register's `rank_sources`; the table above
is the summary and the register is the authority.

## The discriminating case — real, not planted

**20 (case, role) pairs, from committed evidence, no planting required.**

On Autobahn cases 3.2, 3.3, 4.1.3, 4.1.4, 4.2.3, 4.2.4, 6.4.1, 6.4.2, 6.4.3 and
6.4.4 — each on both subject roles — the pinned Java and the Rust port were
graded at the SAME behaviour class, `NON-STRICT`, and the suite's own per-case
`expected` map declares an `OK` arm neither reached. On 6.4.x the OK arm is
`[["timeout","A"]]` (fail fast on the second frame) and both produced
`[["timeout","A"],["timeout","B"]]`. On 3.2 and 4.1.3 the OK arm is
`[["message","Hello, world!",false]]` and both produced `[]`.

That is a rank-four/rank-five consensus that a rank-two oracle in this very tree
declines to endorse. Under AC2 that agreement cannot settle the question, and
before this branch nothing in the repository said so.

A further **18** come from the public tier: the 18 scenarios
`evidence/us005-public-rfc-divergence-census.json` enrols, where the recorded
RFC-strict ready state is `closed` and ranks three, four and five all record
`open`. Total 38 overridden agreements out of 589.

## The polarity control — two of them

The brief asked for a planted control if no real case existed. A real case did
exist, so both are here:

1. **Planted, in `TestAC2PolarityControl`**: two propositions identical except
   for rank one's verdict. The dissenting one must fire; the agreeing one must
   not. A check that fires on both is not discriminating; a check that fires on
   neither is not evidence.
2. **Real, in the census**: the 23 propositions of
   `differential-regression-probe` are a pure rank-four-against-rank-five
   comparison with no higher oracle present. All 23 exhibit a Java/Rust
   agreement and NONE may be marked overridden. `CheckFamilyRules` fails if one
   ever is, and `TestCheckFamilyRulesRefusesAnOverrideInThePolarityControlFamily`
   plants an override into a fabricated copy of that family to prove the guard
   fires.

## RED readings and exit codes, read from the process

- `go test ./internal/oraclerank/ -count=1` — **ok**, 31 tests. Full list in the
  `-v` output; every `TestRed*` plants exactly one difference in a mirror of the
  tree and asserts the gate refuses it.
- `go run ./cmd/oraclerankctl --root . --check` — stdout
  `640 propositions adjudicated; 589 Java/Rust agreements, 38 of them overridden
  by a higher oracle and every one enrolled`, **exit 0** read from the process.
- One byte appended to the committed register, same command — stdout names the
  60810-vs-60809 byte difference, **exit 1** read from the process.
- `make -C rust oracle-hierarchy-gates` — **exit 0**.

## Deletion attacks

Each check was deleted from the source in turn, the package rebuilt, and the
tests that should have covered it run. 17 attacks. Results as read from
`go test`'s exit status:

| # | Check deleted | Result |
|---|---|---|
| D1 | the `JavaRustConsensusOverridden` assignment | RED |
| D2 | the "higher oracle actually differs" condition (fire always) | RED |
| D3 | the "governing rank is strictly above rank four" guard | **STILL GREEN** — see below |
| D4 | governing rank taken as the weakest voter, not the strongest | RED |
| D5 | the exactness check (register may not enrol an unexhibited override) | RED |
| D6 | the enrolment check (evidence exhibits an override the register omits) | RED |
| D7 | the clean-sweep guard on the rank-four deduction | RED |
| D8 | the divergent/`conditional` coincidence assertion | RED |
| D9 | the cross-leg `expected`-map equality assertion | RED |
| D10 | the cross-check against the independent comparison document | RED |
| D11 | the RFC-text digest check | RED *(after a fix — see below)* |
| D12 | the declared-and-silent rank check | RED *(after a fix)* |
| D12b | the declared-ABSENT-but-speaking check | RED |
| D13 | the public-corpus size assertion | RED |
| D14 | the register byte-equality check in `Verify` | RED *(after a fix)* |
| D15 | the polarity-control guard | RED *(after a fix)* |
| D16 | the gate's assertion that the guarded parity reading refuses | **STILL GREEN** — see below |
| D17 | (not a deletion) the guarded parity reading made permissive | RED — the gate caught it on real evidence |

### Four attacks stayed green on the first pass and each exposed a real gap

- **D11.** Deleting the RFC-text digest check left the test green because the
  planted imposter was 21 bytes and the byte-SIZE check caught it first. The
  digest check itself was unexercised. Fixed: the test now plants an imposter of
  exactly the pinned 162067 bytes, so only the digest check can catch it. RED.
- **D12 and D15.** Deleting the declared-and-silent check and the
  polarity-control guard left their tests green because those tests
  RE-IMPLEMENTED the property (their own loop, their own assertion) instead of
  calling the production code. A test that restates the production logic proves
  nothing about the gate. Fixed: the per-family rules were extracted into
  `CheckFamilyRules`, which the gate calls, and new tests in `rules_test.go`
  call that function with fabricated families. RED.
- **D14** did not compile on the first pass (unused import); re-run with the
  import handled. RED.

### Two remain green and are reported rather than shipped as evidence

- **D3 — the `Governing.Outranks(javaRank)` clause is REDUNDANT.** Given the
  other two conditions it can never change the outcome: if the governing rank is
  four or five and a Java/Rust consensus exists, the governing verdict IS the
  consensus verdict, so `Verdict != ConsensusVerdict` is already false. The
  clause is kept because it makes AC2's "a HIGHER oracle" legible in the code,
  but it is documentation, not a load-bearing check, and the two remaining
  conditions carry the rule.
- **D16 — the gate's assertion that `ParityFromJavaRustAgreement` refuses is
  not independently exercised by deletion.** Deleting it leaves the tests green
  because `TestParityReadingRefusesExactlyWhenOverridden` covers the function
  directly. It is not useless: D17 shows that when the guarded reading itself is
  made permissive, the gate catches it on the committed evidence
  (`autobahn-behavior-class/client/3.2: ParityFromJavaRustAgreement returned
  "NON-STRICT" on an overridden agreement`). So it detects a real class of
  change — a divergence between the two code paths — but it is redundant with
  the unit test and should not be counted twice.

### A structural note on the Autobahn cross-checks

`divergencesweep.VerifyEvidenceIntegrity` hashes every file under the Autobahn
evidence root in both directions before this package reads a report. That means
a LONE edit to any report is caught by the digest manifest, and the cross-checks
this package adds on top — the cross-leg `expected` equality and the comparison
document — would never fire against one and would look like evidence while being
unreachable. `internal/oraclerank/autobahn_red_test.go` therefore plants
CONSISTENT edits: the report, the leg index that repeats it, and the digest
manifest are all repaired together, exactly as a regeneration would leave them.
Only then is this package's own cross-check the last thing standing, and D9 and
D10 above are RED under that condition.

## What the mechanism found, beyond the override count

The register's `findings` block is computed, not written. Two are BLOCKING:

1. **`ORACLE-RANK-INDISTINGUISHABLE-3-4`.** Rank three never once differed from
   rank four anywhere the two read different bytes: 32 shared propositions on
   the handshake tier, zero disagreements. On the public tier the pair is not
   even measurable, because rank four there is deduced from rank three's own
   expectation. AC2 gives rank three authority over rank four; nothing in this
   evidence shows it is a separate oracle rather than a relabelling.
   The mechanism of the handshake result is worth naming: the mapping records
   `java_observable: conditional` on **exactly** the 19 outcome keys it marks
   `divergent: true` (asserted in both directions by the census), and rank four
   abstains on `conditional`. So rank four declines to speak on precisely the
   cases where it is recorded as diverging from rank one, and the handshake
   family cannot exhibit a rank-one-overrides-rank-four adjudication at all.
2. **`ORACLE-RANK-AC2-OVERRIDES`.** The 38 overridden agreements above. The
   register states that the question is open on each; it does NOT answer it and
   it is **not a waiver list** — `VerifyRules` fails on an entry the evidence
   does not exhibit.

## Assurance ceiling

**OBSERVED.** Every verdict in the register is read from committed bytes and
compared. Nothing here is differential in the sense the vocabulary reserves for
it (the census READS existing differentials, it does not run one), nothing is
bounded, nothing is proved. The mechanism's own tests are the only thing that is
argued for at all, and they are unit and mutation tests over this package.

I am not arguing this up. In particular: finding that 38 agreements are
overridden is an OBSERVATION about committed evidence, not a verdict that the
port is wrong on those 38 — rank two's `NON-STRICT` grade and rank one's
recorded strict reading are both statements this repository has already
recorded, and adjudicating them is the owner's, not this branch's.

## What I did NOT do, by name

- **I did not fetch or commit the RFC 6455 text.** Egress to
  `www.rfc-editor.org` is denied from this environment (the agent proxy answered
  `CONNECT` with 403). Rank one is therefore declaration-bound to the normative
  text and the register says so in `owner_action_required`. The upgrade path is
  written and computes automatically once the bytes are present; it is exercised
  only in the negative (an imposter of the pinned length is refused).
- **I did not adjudicate any of the 38 overridden agreements.** No disposition,
  no Java-quirk/port-defect/underspecified classification, no ledger record.
  That is US-020 AC3 work and `evidence/java/behavior-delta-ledger.json` is
  owned by another track this wave.
- **I did not modify `evidence/java/behavior-delta-ledger.json` or
  `internal/deltaledger`.** Read only.
- **I did not touch any existing check.** The only edit to an existing file is
  the added `oracle-hierarchy-gates` target in `rust/Makefile`.
- **I did not run Autobahn, any benchmark, or anything on AWS.** No owner gate
  was triggered. The Autobahn evidence is read from the committed run.
- **I did not bind rank three's handshake tier to a second source.** Its
  expectations equal rank one's recorded reading on all 49 cases
  (`NOT_DISTINGUISHED`, 49 co-votes, 0 disagreements), which is reported and not
  resolved.
- **I did not resolve the 19 `conditional` Java handshake observables.**
  `evidence/java/behavior-delta-ledger.json` sequence 1 states a concrete Java
  observation (`accept`) for `us005.hs.0013` missing-host that the mapping
  declines to state; binding rank four to a ledger rationale string would be
  fragile and the ledger is another track's this wave. Named here as an open
  cross-document gap.
- **I did not run `internal/benchplan` or `internal/formalplan`** (8 minutes
  each under contention, and outside this change's blast radius). I ran
  `internal/divergencesweep`, `internal/corpora` and `internal/oraclerank`.
  `internal/lab` and `internal/portplan` are known-failing on this baseline and
  were not run.
- **I did not add a JSON schema** for the register under `schemas/`. Every other
  evidence document in this tree has one; this one is validated only by exact
  recomputation. That is a real gap and the next thing I would do.
