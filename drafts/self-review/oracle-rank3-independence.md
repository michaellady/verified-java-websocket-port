# Rank three independence: what was derived, what was measured, and what it cost

Branch `claude/oracle-rank3-independence`, off mainline `58f3aa4`.
Claim vocabulary: **OBSERVED**. Nothing here is proved.

---

## 1. The task and the result in one paragraph

`evidence/oracle-hierarchy/adjudication-register.json` carried two BLOCKING
findings saying rank three — US-020 AC2's "independent neutral expectations" —
had never once differed from rank four or rank five where the two read different
bytes. The recorded cause was that all 74 public expectations are
`REFERENCE_MODEL_DERIVED_PENDING_ORACLE_CONFIRMATION`, produced by
`internal/corpora.DeriveExpected` under a model whose doc comment says its
defaults mirror pinned Java-WebSocket 1.6.0.

A second derivation was written that does not pass through that model:
`internal/rfcneutral` transcribes the stated rules of RFC 6455 sections 5 and 7
into a table with a clause reference and the reading each rule rests on, and
applies them with a frame decoder to each scenario's own inbound octets. Rank
three's public-tier opinions now come from it.

**Measured, read from the process:**

| pair | before | after |
| --- | --- | --- |
| rank 3 vs rank 4 | NOT_DISTINGUISHED, 32 co-votes, 0 disagreements | **DISTINGUISHED, 79 co-votes, 18 disagreements** |
| rank 3 vs rank 5 | NOT_DISTINGUISHED, 74 co-votes, 0 disagreements | **DISTINGUISHED, 47 co-votes, 18 disagreements** |
| rank 1 vs rank 3 | DISTINGUISHED, 67 co-votes, 18 disagreements | **NOT_DISTINGUISHED, 66 co-votes, 0 disagreements** |

Both indistinguishability findings clear. **A third one opens**, on the pair
AC2 puts rank three directly under. That is reported below, not argued away.

---

## 2. The derivation

`internal/rfcneutral/rules.go` holds 20 rules: 15 that decide, 5 that abstain.
Each carries `rfc_clauses` and a `reading` — the sentence the rule encodes —
recorded so a wrong reading is visible as a wrong quote rather than hidden in
code.

### Rules that decide `closed` (RFC 6455 section 7.1.7 requires Failing the WebSocket Connection)

| rule | clauses |
| --- | --- |
| unmasked frame to a server | 5.1 |
| masked frame to a client | 5.1 |
| nonzero RSV with no extension negotiated | 5.2, 7.1.7 |
| reserved opcode | 5.2, 7.1.7 |
| non-minimal length encoding | 5.2, 7.1.7 |
| 64-bit length with the high bit set | 5.2, 7.1.7 |
| control frame over 125 octets | 5.5, 7.1.7 |
| fragmented control frame | 5.5, 5.4, 7.1.7 |
| continuation with no fragmented message in progress | 5.4, 7.1.7 |
| data frame inside a fragmented message | 5.4, 7.1.7 |
| Close body of exactly one octet | 5.5.1, 7.1.7 |
| Close status code not defined for the wire | 7.4, 7.4.1, 7.4.2, 7.1.7 |
| Close reason not valid UTF-8 | 5.5.1, 8.1 |
| text payload not valid UTF-8 (checked after reassembly) | 5.6, 8.1, 7.1.7 |

Plus the terminal rule: every step consumed with nothing fired ⇒ `open`.

### What it CANNOT cover, and why — by name

| abstention | count | reason |
| --- | --- | --- |
| `A-no-provision-governs-a-local-application-send` | 14 | RFC 6455 states no provision governing how an endpoint answers a local application request to send a frame, including one carrying an undefined status code. `evidence/us005-public-rfc-divergence-census.json` records this same correction in its own `completeness` field, for `us005.pub.0000`. |
| `A-readystate-not-defined-by-rfc6455-non-open-initial-state` | 6 | RFC 6455 defines *The WebSocket Closing Handshake is Started* (7.1.3) and *The WebSocket Connection is Closed* (7.1.4). It does not define `readyState`; a declared non-open initial state is a state of the W3C WebSocket API. |
| `A-readystate-not-defined-by-rfc6455-closing-handshake-started` | 4 | Receipt of a well-formed Close frame starts the closing handshake. Whether the endpoint is then CLOSING or CLOSED is the W3C API's distinction, and turns on transport state these octets do not carry. |
| `A-harness-limit-not-stated-by-rfc6455` | 3 | RFC 6455 permits payloads to 2^63-1 and states no bound on frames or octets. The scenario's own declared `max_input_bytes` / `max_frames` / `max_buffered_bytes` are the harness's. Applied mechanically from the scenario's own `limits`, never from its family label. |
| `A-frame-header-truncated-mid-stream` | 0 on this corpus | A frame whose header is incomplete is not malformed; the endpoint waits. Reached by a synthetic case in the tests. |

**27 of 74 abstain. 29 decide `open`. 18 decide `closed`.** The derivation
never emits `closing`, because RFC 6455 does not name it.

### What this derivation is NOT

It is **not bound to RFC 6455**. The text is pinned in
`evidence/intake/source-pins.json` at sha256 `765775326aee…0fa3b`, 162067 bytes,
and is not in this repository; egress to www.rfc-editor.org is denied here and
the fetch is already a recorded owner action. Every rule is a **recorded
reading** written by hand, exactly as rank one's readings in
`us005-handshake-live-mapping.json` and `us005-public-rfc-divergence-census.json`
are. Rank three's binding strength is `CONTENT_BOUND_TO_RECORDED_READING` — the
same as rank one's — and its `not_bound_to` says so in those words. **No claim
is made that rank three is better bound than rank one.**

What is claimed is narrower and mechanically checkable:

1. the rules are stated once, independently of any scenario;
2. they are applied uniformly by a decoder to the scenario's own octets;
3. no Java artifact and no reference-model output is read on the way.

(3) is proved structurally, not asserted:

- `rfcneutral.Scenario` decodes **exactly** `scenario_id`, `role`,
  `initial_state`, `limits`, `steps`. There is no `expected` field.
  `TestScenarioStructCarriesNoExpectation` fails if one is added.
- `TestDerivationIgnoresRecordedExpectation` rewrites **every** corpus line so
  its `expected` block contradicts what the derivation returns — `closed` where
  the derivation says open, `open` where it says closed — strips
  `expectation_status`, `expectation_basis` and `family`, re-derives, and
  requires **byte-identical** decisions.
- `TestDerivationReadsNoJavaArtifact` fails on an import of `internal/corpora`,
  `java-oracle`, `internal/deltaledger` or `internal/divergencesweep`.

---

## 3. The two independent readings compared, not reconciled

Rank one's committed reading enrols 18 public scenarios as RFC-strict failures.
The mechanical derivation returns `closed` on 18. **The sets are not the same
set.** The register records the symmetric difference by name, recomputed on
every run:

- **`us005.pub.0031`** — enrolled by rank one, **abstained** by rank three. It
  is the `buffer-limit-frame` scenario: the frame declares 80 octets and the
  scenario's own `max_buffered_bytes` is 64. Java rejects with close code 1009.
  RFC 6455 states no such limit, so on this reading the RFC does not *require*
  Failing the WebSocket Connection and rank three declines. **Two committed
  readings of RFC 6455 disagree here**, one saying `closed` and one saying "not
  decided". The register shows it; nothing reconciles it.
- **`us005.pub.0035`** — decided `closed` by rank three, **not enrolled** by
  rank one. A Close frame with a one-octet body (section 5.5.1: the body cannot
  hold the 2-byte status code). Rank one's census could not enrol it: its
  completeness predicate requires `expected.final_state == "open"` and this
  scenario's is `closing`. **The class the RFC divergence census claims
  completeness over does not cover a scenario where a rule of section 5 fires
  and the observable is `closing` rather than `open`.**

The census document is not modified by this branch. This is a finding about it.

### Post-hoc corroboration from documents the derivation does not read

Read by hand AFTER the measurement, from `evidence/java/behavior-delta-ledger.json`,
which `internal/rfcneutral` neither imports nor opens:

- **Ledger sequence 27**, `semantic:org.java-websocket.closeframe.one-byte-close-payload`,
  cites `rfc6455#section-5.5.1`. That is exactly the clause `RuleCloseBodyLength1`
  cites for `us005.pub.0035`. The derivation reached the same clause for the same
  scenario without reading the ledger.
- **Ledger sequence 24**, `semantic:org.java-websocket.draft6455.buffer-limit-check-sites`,
  cites `rfc6455#section-10.4` — Security Considerations — **not** a section 5 or 7
  provision. That is the ledger's own clause attribution for `us005.pub.0031`, the
  scenario rank three abstains on and rank one's census enrols as a section 7.1.7
  failure. The abstention agrees with the ledger's reading and disagrees with the
  census's.
- The ledger's rationale for `us005.pub.0005` records that the OTHER (Codex) plane's
  oracle-hierarchy document has a cell for that scenario's `/final_state` at
  authority `rfc6455.section-5-2`, rank 1, expecting `"closed"`. The derivation
  returned `closed` for `us005.pub.0005` under `R-5.2-nonzero-rsv-without-extension`,
  citing `rfc6455#section-5.2`. Same scenario, same clause, same verdict, from a
  document that is deliberately not in this repository.

None of this is wired into a gate, and none of it makes the readings correct — it
is three independent parties reading the same clauses the same way, which is
weaker than checking them against the text and is recorded as such.

`us005.pub.0035` is now the **39th** enrolled AC2 override (up from 38), and the
only one **governed by rank three alone** — Java and Rust agree on `closing`,
rank one abstains, rank three says `closed`. An override the register could not
previously see, found by the independent oracle rather than copied from rank one.
`TestRankThreeGovernsAtLeastOneOverrideAlone` asserts at least one such exists.

---

## 4. The cost, stated plainly

`ORACLE-RANK-INDISTINGUISHABLE-1-3` is now **BLOCKING**: 66 co-votes, 0
disagreements. A rank three genuinely derived from RFC 6455 is not
distinguishable from rank one, which is a recorded reading of the same document.
AC2 puts them at different ranks; on this evidence nothing shows they are
different oracles.

`TestTheOneToThreeIndistinguishabilityFindingIsInTheCommittedRegister` asserts
it, so it cannot be dropped quietly.

**And the finding is itself resting on nothing.** The register's own qualifier,
computed:

> READ THE 66 WITH CARE: 17 in `public-corpus-ready-state` that carry one
> distinct answer between them, and 49 in `handshake-verdict` where the census's
> own join makes disagreement structurally impossible, **leaving 0 co-vote(s)
> that could have come out either way.**

The trade this branch made is therefore: **two blocking findings that rested on
32 and 74 uninformative co-votes are replaced by one blocking finding that rests
on 0 informative co-votes, plus 18 real disagreements that did not exist before.**
That is an improvement in the evidence and a worsening in the tidiness of the
findings list, and the second must not be used to hide the first.

---

## 5. Was the co-voting a COLLISION rather than a relabelling? Both, of different pairs.

The parent asked whether the propositions where the ranks co-vote are ones the
observation can even distinguish. Measured, and the answer is different for each
mechanism.

### 5a. The census's own join makes disagreement impossible (`join_degeneracy`)

`handshakeOutcomeKey(c)` computes the mapping key from the corpus case's own
`expected.verdict` — **rank three's verdict** — and then reads two *other* ranks
at that key. Over all 42 keys of `evidence/us005-handshake-live-mapping.json`:

- every key reachable from a rank-three verdict *v* records `rfc_verdict` = *v*
  (0 of 42 keys make rank one abstain), so **rank one cannot disagree with rank
  three** in this family;
- every such key records `java_observable` ∈ {*v*, `conditional`}, and rank four
  abstains on `conditional` (19 of 42 keys), so **rank four cannot disagree with
  rank three** either.

Both are computed from the whole committed mapping, not from the 49 cases the
corpus happens to reach, so a corpus that grew a case cannot change the answer.
`ORACLE-RANK-JOIN-DEGENERATE-1-3` and `-3-4` disclose it.

**So the original `-3-4` finding's 32 co-votes were never a measurement.** The
independence probe's group test does not catch this: the two ranks *are* read
from different documents. The join is the second way agreement can be an
artifact, and it had no name in the register before.

### 5b. The projection collapses many propositions onto one answer (`family_resolution`)

`internal/normcollide` measured that the public differential's 74 rows carry 73
distinct observations and the handshake exam's 49 cases carry 26. This census
projects each of those onto a three-value verdict space, and collapses much
further:

| family | propositions | distinct opinion tuples | largest class |
| --- | --- | --- | --- |
| `autobahn-behavior-class` | 494 | **4** | 466 |
| `handshake-verdict` | 49 | **4** | 19 |
| `public-corpus-ready-state` | 74 | **7** | 29 |
| `differential-regression-probe` | 23 | **11** | 6 |

**640 propositions carry 26 distinguishable answers between them.** A probe
reporting 494 co-votes is reporting propositions, not questions.

`ORACLE-RANK-COVOTE-COLLISION-h-l-family` fires where a scored pair's co-votes
carry exactly ONE distinct (higher, lower) verdict pair. It fires three times,
and two of those are on **DISTINGUISHED** pairs — rank one's 18 disagreements
with rank four and with rank five in the public tier are one answer (`closed`
vs `open`) repeated 18 times. That qualifies a number the register previously
reported clean, and it is a disclosure against a pre-existing result rather than
against this branch's.

### Which mechanism explains what

- **rank 3 vs rank 4, handshake family (32/0):** the JOIN. Not a relabelling and
  not a projection collapse — disagreement was structurally impossible.
- **rank 3 vs rank 5, public family (74/0):** the RELABELLING the register
  already named. The Rust transcript is genuinely independent bytes; rank three
  was reading a Java-shaped model. Fixed, and it now disagrees 18 times.
- **rank 1 vs rank 3 (66/0), the new finding:** 49 by the join, 17 by the
  collapse. Nothing left.

---

## 6. Nothing was weakened

- `findings.go`'s F-3 fires on exactly the same condition as before
  (`p.Verdict == ProbeNotDistinguished`), at the same BLOCKING severity, from
  the same probe numbers. The only change is a computed qualifier **appended**
  to the statement, which changes neither when it fires nor its severity.
- The independence probe's scoring is unchanged. The handshake `3-4` family
  probe still reports its 32 co-votes and is still scored `NOT_DISTINGUISHED`;
  the degeneracy is **disclosed alongside**, not used to reclassify it. A
  reclassification would have been a reasonable reading of the probe's own
  doctrine, and it was deliberately not done, because it would have removed a
  BLOCKING finding's ability to fire in the pre-branch configuration.
- `ORACLE-RANK-COVOTE-COLLISION` and `ORACLE-RANK-JOIN-DEGENERATE` are strictly
  additive.
- One factual correction: the handshake rank-three note claimed the corpus
  expectations "disagree with the Java observable on a large fraction of cases".
  The probe measured zero. The note now says the claim was false, marked as
  having been false, rather than being deleted.

**Proof that the check was outrun rather than disabled:**
`TestIndistinguishabilityFindingStillFiresWhenTheEvidenceEarnsIt` takes the real
families, copies rank four's verdicts onto rank three — the pre-branch state —
and requires `ORACLE-RANK-INDISTINGUISHABLE-3-4` to come back BLOCKING. It does.

---

## 7. RED readings and deletion attacks

Every mutation below **compiles**. A mutation that breaks compilation proves
nothing, so none was used.

| # | attack | result |
| --- | --- | --- |
| A | Add an `Expected` field to `rfcneutral.Scenario` and consult it in `decide()` | `go test ./internal/rfcneutral/` **exit 1**: `TestDerivationIgnoresRecordedExpectation` names `us005.pub.0000` changing, and `TestScenarioStructCarriesNoExpectation` names the field |
| B | Point rank three back at `s.Expected.FinalState` in `censusPublicState` | `go test ./internal/oraclerank/` **exit 1** on four tests; probe returns to NOT_DISTINGUISHED at 106 co-votes / 0 disagreements. `oraclerankctl --check` **exit 1**: recomputation 92541 bytes vs committed 92382 |
| C | `if false && f.rsv != 0` — neuter the RSV rule in the decoder | `go test ./internal/rfcneutral/` **exit 1**: `TestEveryDecidingRuleFires/rsv_set`. `oraclerankctl --check` **exit 1**: recomputed 90124 vs committed 92382 |
| D | Delete `schemas/oracle-hierarchy-adjudication-register-1.0.0.schema.json` | `ValidateAgainstSchema` returns an error naming the missing file (`TestRedMissingSchemaFailsClosed`). **A validation that cannot run is not a validation that passed** — the F006 shape, refused explicitly |
| E–S | Fifteen single-field mutations of the committed register, each a well-formed JSON document | all refused by the schema gate; see §8 |

**Coverage floors** (a rule nothing can reach exists in name only):
`TestEveryDecidingRuleFires` drives all 15 deciding rules from octets built for
them and fails if a rule in the table is unreachable; `TestEveryAbstainingRuleFires`
does the same for all 5 abstentions.

**Negative controls** (the derivation must not be a rubber stamp):
- `TestFragmentedMessageCompletesCleanly` — a well-formed fragmented message with
  a Ping injected mid-message, as section 5.4 permits, must decide `open`.
- `TestFragmentedTextIsCheckedAfterReassembly` — two fragments neither of which
  is valid UTF-8 alone, whose concatenation is, must decide `open`; a per-fragment
  check would wrongly say `closed`.
- `TestValidCloseCodeBoundaries` — 1000-1003, 1007-1011, 3000-4999 accepted;
  0, 999, 1004, 1005, 1006, 1012, 1015, 1016, 2000, 2999, 5000, 65535 refused.
- `TestJoinDegeneracyDetectsANonDegenerateJoin` — one mapping entry changed to
  `java_observable: accept` under a reject key, and the detector must say
  POSSIBLE and name `reject->accept`.
- `TestNeutralDerivationCoversEveryPublicScenarioOrSaysWhyNot` — fails if the
  derivation never abstains (overclaiming) or never decides (silent).

**Exit codes read from the process, on the committed tree:**

```
go run ./cmd/oraclerankctl --root . --check   -> 0
go run ./cmd/oraclerankctl --root .           -> 0   (writes 92382 bytes)
go test ./internal/oraclerank/                -> 0
go test ./internal/rfcneutral/                -> 0
```

---

## 8. The schema the register was missing

`schemas/oracle-hierarchy-adjudication-register-1.0.0.schema.json`. Every other
evidence document in this tree had one; this one did not, and the branch that
built the register named writing it as the next thing to do.

It is a **gate, not a document**: `oraclerank.ValidateAgainstSchema` runs first
in `oraclerankctl --check` and again after every write, so a non-conforming
register exits 1 rather than sitting on disk looking committed. The
`santhosh-tekuri/jsonschema/v6` compiler was already a module dependency.

**It found a defect on its first run**: `co_vote_resolution.verdict_pairs` was
`null` on the family probes the pair declines to score. Fixed by measuring
resolution for every family probe with co-votes — how many distinguishable
answers they carry is a fact about the evidence, not about the scoring — and by
making the slice non-nil, since an absent measurement and a measurement of zero
are different facts.

Fifteen RED attacks, each refused:

a rank outside the closed AC2 set · a binding weaker than `CONTENT_BOUND` with
no `not_bound_to` · a `DISTINGUISHED` probe reporting zero disagreements · a
`NOT_DISTINGUISHED` probe reporting some · a shared-derivation probe that scores
disagreements at all · a rank pair not ordered strongest-first · an override
entry governed by rank four · a finding with an empty basis · a severity outside
{BLOCKING, DISCLOSURE} · an `assurance_note` claiming PROVEN · a family with four
rank sources instead of five · a speaking rank that names no artifact group · a
dropped probe pair (10 ordered pairs required) · an unknown top-level field such
as a waivers list · a deleted schema.

---

## 9. What I did NOT do, by name

- **I did not fetch RFC 6455.** Egress to www.rfc-editor.org is denied; the
  owner action (fetch to `third_party/rfc6455/rfc6455.txt`, sha256
  `765775326aee…0fa3b`, 162067 bytes) was already recorded and is untouched.
  **Every rule in `rules.go` is unverified against the text.** A misreading of a
  clause passes every gate here unchanged. That is why each rule records the
  sentence it rests on.
- **I did not verify any rule against Autobahn**, or against any external
  WebSocket implementation. No Autobahn, AWS or benchmark run was triggered.
- **I did not touch the delta ledger, `internal/deltaledger`, or
  `assurance/concurrency/results.json`.**
- **I did not modify `evidence/us005-public-rfc-divergence-census.json`**, even
  though this branch found that its completeness class misses `us005.pub.0035`.
  The finding is recorded; the document is left to its owner.
- **I did not modify `corpora/public/scenarios.jsonl`.** The reference-model
  expectations are still there and still feed rank four's clean-sweep deduction.
  Nothing was relabelled to make a number move.
- **I did not reclassify the handshake `3-4` family probe** to
  `NOT_PROBEABLE`, though the probe's own doctrine arguably requires it. Doing so
  would have removed a BLOCKING finding's ability to fire in the pre-branch
  configuration, which would be closing a finding by weakening it.
- **I did not weaken, relax or delete any existing check**, and I did not change
  when `ORACLE-RANK-INDISTINGUISHABLE-*` fires or at what severity.
- **I did not decide `closing` anywhere.** The distinction between CLOSING and
  CLOSED is not RFC 6455's, so the derivation abstains rather than guessing, and
  1 of the 18 disagreements (`us005.pub.0035`, `closed` vs `closing`) turns on
  that boundary. Discount it and 17 disagreements remain.
- **I did not make rank three's handshake tier independent.** It is still the
  committed corpus expectation, read at a key computed from itself. The
  `ORACLE-RANK-JOIN-DEGENERATE` findings name the owner action.
- **I did not claim rank three is better bound than rank one.** Both are
  `CONTENT_BOUND_TO_RECORDED_READING` and both say so.
- **I did not argue the register's claim ceiling upward.** It is OBSERVED, and
  the schema now refuses an `assurance_note` that does not open with it.

---

## 10. What the owner would have to do next

1. **Fetch RFC 6455** to `third_party/rfc6455/rfc6455.txt`. Rank one's binding
   computes `CONTENT_BOUND` automatically once the bytes are present; rank
   three's rules become checkable clause by clause against the sentences each
   one records. Neither needs a code change.
2. **Supply a per-case Java handshake observation** so rank four's handshake
   opinions stop being looked up by a key computed from rank three's own verdict.
   Until then the handshake family measures nothing about rank one, rank three or
   rank four's mutual independence.
3. **Decide `us005.pub.0031`**: rank one says the RFC requires closing on a
   frame that exceeds the harness's buffer limit; rank three says RFC 6455 states
   no such limit. One of the two readings is wrong.
4. **Widen the RFC divergence census's completeness class** to cover the case
   `us005.pub.0035` exhibits, or state why `closing` observables are out of scope.
5. **Adjudicate the 39 enrolled overrides.** The register states the question is
   open. It is not a waiver list.
