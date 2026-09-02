# Normalization collision audit — landing record

Branch `claude/normalization-collision-audit`, based on mainline `2c63205`.
Resumed after a container restart from the two commits that survived because
they were pushed early (`46d902f`, `e555425`).

A **normalization collision** is two genuinely different wire behaviours
mapping onto the same normalized observation, so the differential reads parity
where the wire differs. Three were known and, by the project's own record, all
three were found by accident. This audit enumerates the surface and decides
candidates by construction.

Deliverables: `internal/normcollide`, `cmd/normcollidectl`,
`evidence/normalization-collisions/audit.json`.

---

## 1. The enumerated normalization surface

Five projections exist. Nothing else can answer a request.

| projection | site | keys emitted (measured) | what the scorer compares |
| --- | --- | --- | --- |
| `behaviour.ok` | `response.rs ok_response` | 14 | the full observation surface |
| `behaviour.failure` | `response.rs failure_response` | 9 | `error.code`, `error.close_code`, `final_state`, `counts`×7 |
| `behaviour.output_limit` | `response.rs output_limit_response` | 6 | `error.code` only |
| `behaviour.envelope_error` | `response.rs envelope_error_response` | 5 | **nothing — the transcript cannot be loaded at all** |
| `handshake.judged` | `handshake_adapter.rs respond` | 6–8 | `java_observable`, `reject_channel`, `close_code`, `sec_websocket_accept` |

The key counts are **recomputed from real responses**, not authored;
`PartitionCensus` refuses any observed response shape that no projection
classifies, so the table cannot go stale silently.

The scorers are the real ones: `internal/corpora.EvaluateOracleResponse` and
`evaluateHandshakeLiveResponse`, plus `diffregress.CompareResponses`.

### The six dropped keys, refined

The lead I left before the restart was that the error-row projection drops six
top-level keys. On re-reading, **only four of the six are collision-bearing**.
`role` and `initial_state` are request echoes, recoverable from
`request_digest`, which IS compared; for a fixed request they carry no
behavioural information. The collision-bearing drops are `events`, `frames`,
`transitions`, `close`. That refinement made the finding smaller and truer.

---

## 2. Confirmed collisions (7), each with its proving seed

Every one was decided by executing the real harness on two seed requests and
applying `diffregress.CompareResponses` — the comparator the headline number
uses — to the two answers. Identity fields (`request_id`, `request_digest`,
`case_id`) are the only members stripped.

| id | projection | erases | witness | disclosed already? |
| --- | --- | --- | --- | --- |
| NC-01 | `behaviour.failure` | every observation stream on an error row | pair, moved `frames[0].payload_base64` | drop yes, consequence no |
| NC-02 | `behaviour.output_limit` | everything, **including `runtime`** | pair, moved 8 paths | drop yes, consequence no |
| NC-03 | `behaviour.ok` | frame mask keys | wire | yes — quirk Q28 |
| NC-04 | `behaviour.failure` | the FIN bit of a rejected frame, **in the shipped corpus** | pair, moved `frames[0].fin` | **no** |
| NC-07 | `handshake.judged` | the whole HTTP head incl. subprotocol/extension negotiation | wire | partly |
| NC-08 | `handshake.judged` | everything about an incomplete handshake | wire | **no** |
| NC-09 | `handshake.judged` | all distinction within one reject channel; `close_code` is a constant | wire | yes — the live mapping's own `granularity_statement` |

Three of the seven were already disclosed somewhere in the tree. I say so in
each probe's `Disclosure` field rather than presenting them as discoveries.
What is new for those three is the *measured size* of what they erase.

### The two that matter most

**NC-04 is not synthetic.** Its seeds are the shipped steps of
`us005.pub.0039` (`80 83 1c 9b ca df fe f5 41`, FIN=1) and `us005.pub.0066`
(`00 83 1d 39 be db ad 6d 44`, FIN=0) — two of the seventy-four public
scenarios. Different FIN bit, different payload in every octet, both rejected
as "Continuous frame sequence was not started", and their scored rows are
byte-identical once identity is removed. The witness pair feeds the same FIN
distinction on an accepted frame, where `frames[0].fin` moves — proving the
bit is representable and that the error projection is what destroys it.

**NC-02 erases `runtime`.** A response that trips `max_output_bytes` carries no
responder identity, so a Java row and a Rust row for the same request are
byte-identical. But it is **DORMANT**: no row of the current 74 reaches that
projection, because every public scenario carries the full 4 MiB budget. It
bounds what a future corpus could hide, not today's number, and the document
says so in `active_in_scored_corpora: false`.

---

## 3. The bound on 74/74 and 49/49

This is the deliverable that matters most, and both numbers are **measured, not
argued** — recomputed by `MeasureTranscript` from the committed evidence.

### 74/74

- 26 of the 74 rows are error rows. For those 26 the differential compares
  `error.code`, `error.close_code`, `final_state` and seven counters — **ten
  scalars** — and nothing about what the connection did. `error.detail` is
  classified non-semantic by `diffregress` (it is exactly the 26 `detail_only`
  rows in the headline).
- So 74/74 means: 74 requests were answered, **48 scored on the full
  observation surface and 26 scored on ten scalars**. It does not mean 74
  behaviours were compared.
- **The 74 rows carry only 73 distinct scored observations.** Two of them
  (NC-04) are indistinguishable. The ceiling is 73 distinguishable answers.

### 49/49

- The 49 handshake cases produce only **26 distinct scored observations**.
- **27 of the 49 cases share their observation with at least one other case.**
- The **largest equivalence class holds 11 cases** — eleven different
  handshakes, one scored row.
- Breakdown of the collapse: 11 cases → one `reject`/`invalid_handshake`/1002
  row; 9 → one `reject`/`not_matched`/1002 row; 4 → one bare `incomplete`; 3
  server-side accepts → one bare `accept`. Only 22 accepts carry a computed
  value (the accept key).
- So 49/49 certifies **at most 26 distinguishable answers, not 49**.

Both numbers were cross-checked: I computed the handshake census independently
in a throwaway script before writing the Go code, got 26/27/11, and the Go
census initially disagreed (25/27/12). The cause was a real defect — my `Seed`
dropped `context.client_key`, which ten `server_response` cases need — and
fixing it made the two agree. The disagreement is why I caught it.

### Claim vocabulary

**BOUNDED.** Each confirmed collision is an **observed** fact about the shipped
projection, established by running it. The **enumeration is not proved
complete**: it reads five named sites, and a distinction none of them mentions
cannot be found by reading them. DIV-02 is exactly that case and is in this
document only because a person had already found it out of band. Nothing here
is a proved-model or proved-production claim.

---

## 4. Undecided candidates (5) — all labelled HYPOTHESIS

None is counted as a finding. `TestEveryCandidateIsLabelledHypothesis` fails if
one loses its label.

| id | distinction | why not decided |
| --- | --- | --- |
| `CAND-TRANSPORT` | socket lifecycle, TCP FIN/RST | DIV-02's class. No oracle step feeds or observes a socket; the witness has to be a real peer socket (`ws-testee` loopback), not a transcript comparison. Confirmed elsewhere, out of scope here. |
| `CAND-CROSSARRAY` | relative order of an event, a frame and a transition | The known US-013 AC5 case. The harness generates all three arrays in one pass, so no request I can write makes it emit them in a different order — seeding it needs a mutated harness (`cmd/mutctl`), not this instrument. |
| `CAND-UTF8` | two octet sequences decoding to the same text | Whether such a pair exists depends on whether `ws_core` replaces malformed UTF-8 or rejects the frame. Not run. |
| `CAND-WIREBYTES` | non-minimal frame length encoding | `wire_bytes` is a total, so this may well be REPRESENTED — i.e. a refuted candidate. Untested either way. |
| `CAND-CHUNKING` | how input octets split across steps | Reasoned to be represented (`input_chunk` carries a per-step count), but a reasoned negative is not a measured one. |

---

## 5. RED readings and deletion attacks

**Nine attacks, all now RED.** Each disables ONE check with a compile-safe
mutation (`false &&`, forced-empty) — a mutation that breaks compilation
proves nothing — runs the suite, and is restored.

| attack | what it disabled | result |
| --- | --- | --- |
| A1 | same-request-seeds check | exit 1 RED — `TestDecideRejectsAProbeWhoseCollisionSeedsAreTheSameRequest` |
| A2 | witness-existence check | exit 1 RED — `TestDecideRejectsAnUnwitnessedProbe` |
| A3 | identity-moved check | exit 1 RED — `TestDecideRejectsWhenTheTwoAnswersShareEveryIdentityField` |
| A4 | witness-moved check | exit 1 RED — `TestDecideRejectsAWitnessPairThatMovedNothing` |
| A5 | REFUTED verdict made unreachable | exit 1 RED — `TestDecideRefutesWhenTheComparatorMoves` |
| A6 | identity stripping widened to swallow `final_state` | exit 1 RED — 2 tests |
| A7 | census collapses every row into one class | exit 1 RED — `TestPublicCensusMeasuresTheShippedTranscript` |
| A7b | census never collapses any row | exit 1 RED — same test |
| A8 | `PartitionCensus` check | exit 1 RED — `TestPartitionCensusRefusesAnUnclassifiedShape` |
| A9 | classifier guesses instead of refusing | exit 1 RED — `TestClassifyRefusesToGuess` |

**Two attacks initially failed to prove anything, and both are recorded rather
than quietly fixed:**

- **A7 did not compile** on its first form (`declared and not used: signature`).
  That proves nothing, so I say so and re-ran it compile-safe.
- **A8 left the suite GREEN.** The surface-partition check lived inside
  `Build`, which needs a harness binary, so nothing in the default suite
  covered it. I lifted it out as the exported `PartitionCensus` and attacked
  it directly. Without the deletion attack I would have shipped an uncovered
  check and not known.

**Tamper attacks on the verifier** (exit codes read from the built binary, not
from `go run`, which masks them):

| tamper | exit |
| --- | --- |
| untouched document | 0 |
| flip one verdict | 1, naming line 196 |
| change one census number | 1, naming line 673 |
| delete the document | 1 |
| point at a different binary (`/bin/true`) | 1 — "harness answered 0 lines for 4 requests" |
| omit `--harness` | 2 |
| unknown subcommand | 2 |

**The catalog refuted one of its own probes on the first real run.** NC-08's
truncation used a fixed `[:160]` slice that did not actually cut the shorter
request, so collision B was a *complete* handshake and the run reported
`REFUTED` with `collision_diff_paths = [java_observable sec_websocket_accept]`.
That refutation was correct. The fix computes the truncation instead of
guessing it, and the probe's own `wire_witness` field records the whole episode
— it is the best evidence in the package that CONFIRMED is not a constant.

**The live gate never skips.** `go test -tags normcollide` with
`WS_ORACLE_HARNESS` unset FAILS (exit 1) with "this gate is never skipped once
its tag is selected". A skipped collision audit that reports success is exactly
the failure mode this package exists to attack.

---

## 6. Exit codes read from the process

```
cargo build -p ws-oracle-harness                                    exit 0
ws-oracle-harness < public-requests.jsonl        exit 0, 74 lines
diffregressctl compare (java arm vs fresh rust arm)
  total=74 identical=48 detail_only=26 divergent=0 []               exit 0
diffregressctl compare on a transcript of envelope-error rows
  "line 1: response has no request_id"                              exit 2
normcollidectl report  --harness <debug binary>                     exit 0 (7/7 CONFIRMED)
normcollidectl write   --harness <debug binary>   38k document      exit 0
normcollidectl verify  --harness <debug binary>                     exit 0
normcollidectl verify  (no --harness)                               exit 2
go test ./internal/normcollide/                                     exit 0
go test -tags normcollide ./internal/normcollide/ (abs path)        exit 0, 11.2s
go test -tags normcollide (WS_ORACLE_HARNESS unset)                 exit 1 (fails, not skips)
gofmt -l, go vet on both new packages                               clean, exit 0
```

---

## 7. What I did NOT do

- **I did not run the pinned Java oracle.** Every probe was answered by the
  Rust harness alone. This is sound for the claim being made — a collision is a
  property of the *projection*, and both arms share the projection by
  construction — but it means **nothing in this audit is a Java-versus-Rust
  fidelity result**. It is recorded as the first scope limit in the document.
- **No AWS, benchmark or Autobahn run.** Owner gates, never triggered.
- **I did not modify the ledger, `internal/deltaledger`, or
  `assurance/concurrency/results.json`.**
- **I did not weaken any existing check, and did not adjust any normalization
  rule.** The collisions are the finding; making one disappear would have
  destroyed the evidence. `internal/diffregress`, `internal/corpora` and the
  Rust harness are untouched.
- **I did not decide the five candidates in §4.** They are hypotheses.
- **I did not prove the enumeration complete**, and the document says so in its
  `claim_vocabulary` rather than leaving it to be inferred.
- **I did not extend `internal/ac5class`** to register these as AC5 collision
  seeds. That is the natural next step — the register already has the exact
  `Collision{DivergenceID, Mechanism, Witness, BlindJudges}` shape for it — but
  it touches a US-020 acceptance artifact and I left that to the owner.
- **I did not run the full `make -C rust gates` or `fixture-guard`.** No Rust
  source changed; the only Rust interaction was executing the already-built
  harness.

## 8. Honest notes on the work itself

- The single most valuable thing in this package is the **refutation**. A
  catalog where every entry confirms is a catalog that might not be measuring
  anything. NC-08's first run coming out REFUTED, and A5 proving the REFUTED
  verdict is reachable, are what make the other six worth reading.
- **The A8 result is uncomfortable and is left in.** A check I wrote, that
  looked right, was covered by nothing. The deletion attack is the only reason
  I know.
- My pre-restart note said "six top-level keys". Two of the six were not
  collision-bearing. The corrected count is four, and the earlier claim is left
  visible in the WIP file rather than edited away.

---

## 9. Proposed owner actions (none taken here)

I deliberately did **not** write a `drafts/ledger-proposals/` record. The
behaviour delta ledger describes Java-versus-Rust *behaviour* deltas; a
normalization collision is a property of the *measuring instrument*, not a
behaviour delta. Forcing these into that schema would be a category error and
would also require reproducing `internal/deltaledger`'s digest construction,
which I was told not to touch. The actions below are for the owner to weigh.

1. **Register the seven in `internal/ac5class`.** The register already has the
   exact `Collision{DivergenceID, Mechanism, Witness, BlindJudges}` shape, and
   it currently carries two entries where this audit found seven. Its own
   doc-comment argues a collision seed should be found "by construction"; this
   package supplies the constructions. Not done here because `ac5class` is a
   US-020 acceptance artifact.
2. **Decide whether NC-04 costs the 74/74 a row.** Two shipped scenarios are
   indistinguishable. Either the corpus gains a scenario that separates them,
   or the headline is restated as 73 distinguishable observations. The census
   test pins 73 so the choice cannot be made silently.
3. **Consider whether `error.detail` should stay excused.** On an error row it
   is the *only* field carrying what actually went wrong, and `diffregress`
   classifies it non-semantic — which is why 26 of 74 rows land in
   `detail_only`. That classification is defensible; its interaction with
   NC-01 is what makes the error surface as thin as ten scalars.
4. **Note that NC-02 is a live hazard for future corpora.** Any scenario with a
   tight `max_output_bytes` produces rows with no `runtime` at all, so Java and
   Rust answers become byte-identical. A corpus generator that ever emits a
   small budget would silently create unfalsifiable rows.
5. **Decide the five candidates in §4**, particularly `CAND-CROSSARRAY`, which
   needs a mutated harness (`cmd/mutctl`) rather than a request seed.

---

## 10. The soundness question a reviewer should press on

**Objection.** The differential never compares row A against row B. It compares
`O_java(R)` against `O_rust(R)` for one request `R`. So what does a collision
between two *different requests* prove?

**Answer.** It proves the projection `O` is blind to a distinction, and `O` is
the same function on both arms. Every probe is built so its two requests differ
**only** in the content whose behavioural effect is at issue — the text payload
(NC-01), the frame octets (NC-03, NC-04), the handshake octets (NC-07..09) —
with limits, role and `initial_state` held equal. So an equal pair of answers
shows `O(b1) == O(b2)` for two behaviours `b1 != b2` that the same projection
maps together.

The differential consequence follows: if the port, on request A, produced `b2`
where Java produced `b1`, both arms' rows for A would be equal and the
differential would read parity. NC-01 makes that concrete — a port that emitted
the wrong outbound payload before failing is invisible. NC-04 makes it concrete
on a single bit — a port that mis-read the FIN flag of a frame it then rejected
is invisible.

**What this does NOT establish** is that any such port defect exists. A
collision bounds what the differential *could* detect. It is not a defect
report, and nothing in this audit claims one. The 74/74 and 49/49 results
remain true statements about what was run; what the audit changes is what they
can be taken to mean.
