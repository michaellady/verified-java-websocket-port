# Concurrency coverage disclosure — measurement record

Track: `claude/concurrency-coverage-disclosure`, branched from mainline
`claude/feature/verified-java-websocket-port` @ 2c63205.

Answering the two findings of `drafts/self-review/post-failure-landing-review.md`.

Self-review by the goal loop: **OWNER_ATTESTED_NOT_INDEPENDENT**. Nothing here
was reviewed by anyone else.

---

## The question, answered

> Is 49 clean-terminal runs in one scenario adequate coverage for properties
> that had 56,777?

**No — and the honest figure is worse than 49 and better than the comparison
suggests, in that order.**

1. **49 runs is 18 behaviours.** The 49 clean-terminal runs carried **18
   distinct semantic trace digests**. The four properties that hold ONLY on the
   clean route — convergence under weak fairness, the exactly-once
   reconciliation of every accepted command, post-terminal quiescence, and no
   write bypass — were exercised against eighteen behaviours, in one scenario.
   Eighteen is not adequate for four properties this record calls out by name.

2. **But the 56,777 was never clean-lifecycle coverage.** The
   79,920 → 81,180 movement is not a before/after of the same space:
   `abnormal-teardown` enumerates exactly 79,920 schedules ON ITS OWN, so the
   landing did not shrink a space, it APPENDED `clean-finish` (1,260). And all
   56,777 clean-terminal runs were in `abnormal-teardown`, whose own harness
   doc comment records that its clean convergence was an artifact of the
   driver's EOF-coalescing defect: two terminations silently merged into one.
   With that defect fixed the scenario yields **0** clean terminals, correctly.
   So the honest comparison is not 56,777 → 49. It is **0 genuine
   clean-lifecycle runs → 49**, i.e. → 18 behaviours.

3. **It can be partly restored, and was.** Scenario
   `clean-finish-inbound-ping` is appended: the same single-termination
   lifecycle as `clean-finish`, with the peer's keepalive ping ahead of its
   close. Measured: **closed_terminal_runs 49 → 1,176**, **distinct
   clean-terminal digests 18 → 403**, **scenarios reaching a clean terminal
   1 → 2**, whole-space distinct traces **3,129 → 4,587**.

4. **The ceiling that follows, and it is real.** 4,587 is still far under the
   pre-landing 18,755, and that residual gap is NOT recoverable here. The 18,755
   counted traces of runs that continued past a scored termination because the
   driver ABSORBED post-terminal work; the fixed driver refuses it, and the
   harness's `interpreter-halts-at-first-surfaced-failure` invariant stops the
   run there. 90,984 of 92,160 schedules now halt, and a halt truncates the
   trace, so a defect that manifests only after the halt point in
   `abnormal-teardown` is explored by none of them. Recovering that would mean
   either asserting the defect again (refused) or exploring past a surfaced
   failure (refused by an invariant the record claims). Widening the clean
   route further means ANOTHER scenario inside `schedule_count_max`, not a
   larger one.

Recorded in the document as `limitations[12]`, `CLEAN-ROUTE COVERAGE CEILING`,
with the measured numbers and with a bound pointer to the superseded reading.

### Why the clean route is intrinsically the thin half

All 1,211 halted runs of `clean-finish` halt on a `StateViolation`, and none of
them has taken a `Terminal` first (`halted_with_terminal=0`): 1,197 surface it
on a `Wake` poll and 14 on `TransportEof`. A clean finish requires both
producer enqueues to land before the peer's close; every interleaving that lets
`inbound-close` overtake a producer is a state violation. This is not the
post-terminal refusal swallowing clean runs — it is the closing handshake
starting before the application has finished. Lengthening the READ program
rather than the producer programs is what buys clean breadth, because it gives
the producers somewhere to be scheduled that is not a violation. That is the
whole design of scenario C.

---

## What the measurements were, and how they were taken

### Baseline, before anything was touched

`cargo test -p ws-driver --release --test schedule_exploration -- --nocapture`,
**exit 0 read from the cargo process**, `test result: ok. 11 passed; 0 failed`.
The printed `US017_EXPLORATION` line matched the committed
`execution.executed_run.stdout_line` byte for byte.

### Finding 1, measured with a temporary probe (run, then removed)

```
PROBE_SCENARIO name=abnormal-teardown schedules=79920 closed_terminal_runs=0
    failure_halted_runs=79920 halted_runs_with_a_clean_terminal_first=904
    distinct_trace_digests=2965
PROBE_SCENARIO name=clean-finish     schedules=1260  closed_terminal_runs=49
    failure_halted_runs=1211 halted_runs_with_a_clean_terminal_first=0
    distinct_trace_digests=164
PROBE2_COMMITTED name=abnormal-teardown distinct_clean_terminal_digests=0
PROBE2_COMMITTED name=clean-finish      distinct_clean_terminal_digests=18
```

A fourth fact the record did not carry: `bounded_exploration_...` computes
`halted_terminals` — a run that took its one clean `Terminal` and only then
halted — asserts it against `totals.terminals`, and throws it away. It was 904
and appeared in neither the printed line nor `results.json`. It is now printed
and recorded (910 at the current shape).

### Choosing the scenario, under the preregistered cap

`plan.json` preregisters `schedule_count_max = 100000` and this branch does not
touch `plan.json`, so a new scenario had at most 100,000 − 79,920 − 1,260 =
**18,820** schedules. Nine candidate clean-lifecycle shapes were enumerated and
measured, all with zero invariant violations:

```
PROBE4_BASE  schedules=81180 clean_runs=49 distinct_all=3129 distinct_clean=18
PROBE4 name=E1  added=10980 own_clean_runs=1127 own_distinct_clean=385
       union_clean_runs=1176 union_distinct_clean=403 union_distinct_all=4587
PROBE4 name=D8  added=10980 own_clean_runs=474  own_distinct_clean=251
PROBE3 name=D6  added=8040  own_clean_runs=827  own_distinct_clean=191
PROBE3 name=D4  added=13920 own_clean_runs=331  own_distinct_clean=185
```

E1 wins and is adopted as `clean-finish-inbound-ping`. It is APPENDED, so every
schedule index in scenarios A and B is unchanged and every pinned retention
`found_index` ordinal is untouched.

### The counters in the document come from a re-run, not a transcription

`cargo test -p ws-driver --release --test schedule_exploration -- --nocapture`
in this tree: **exit 0 read from the process**, `test result: ok. 11 passed;
0 failed; 0 ignored`. Verified by diff, not by eye:

* the single printed `US017_EXPLORATION` line is **byte-identical** to
  `execution.executed_run.stdout_line`;
* the five printed `US017_FATAL_SWEEP` lines are **byte-identical, in order**,
  to `execution.fatal_termination_sweep.executed_run.sweep_stdout_lines`.

The harness re-formats both from its own measured totals and compares them
itself, and `internal/formalplan` re-derives every counter in the document from
them.

---

## Finding 2 — `revision_note` replaced by a bound `revision_history`

`revision_note` was one string holding every accumulated paragraph, in no
stated order, with nothing marking which described the document and which
described a predecessor. The only rule any validator applied to it was that it
not be empty — which is why four enumeration rounds listed it INERT, and why it
could assert, in the present tense, counters the same document had superseded.

It is replaced by `revision_history`: eight paragraphs, kept verbatim, each now
carrying

* its own **identity**, stamped at BOTH ends of its text, so a truncated,
  swapped or number-shifted paragraph stops being that revision's paragraph;
* a **status**, CURRENT or SUPERSEDED, with exactly one CURRENT and it must be
  the last;
* a **`superseded_by` chain** to the paragraph that replaced it, so the order
  is a claim rather than an accident of array order;
* **`counters_quoted`** — the exploration reading the paragraph speaks about,
  hoisted out of the prose and held to the partition every exploration reading
  obeys (clean-terminal + failure-halted = schedules). A superseded block need
  not be RECOVERABLE to be CHECKABLE.

The CURRENT paragraph's counters must equal the document's; a SUPERSEDED
paragraph's must not equal the CURRENT one's, so today's numbers cannot wear a
history label either. The post-failure landing's own missing paragraph is
reconstructed and marked as such.

Two further things were bound on the way:

* **Scenario prose is DERIVED, not attested.** `bounds.scenario_shapes[*]
  .models` and `.why_explored` are now read out of the harness's own
  `RECORD <field>:` markers in each scenario constant's doc comment and
  compared as normalised word sequences (EQUALITY, not containment, so a
  truncation is refused). The harness is the file this record already pins by
  identity AND `git_blob`.
* **The ceiling limitation is bound as a ceiling, not as arithmetic.** See the
  self-inflicted finding below.

---

## Findings this branch made against ITSELF

Three, all found by running the instruments rather than by reasoning, and all
fixed here.

### A. The ceiling could be cut in half and nothing complained

With only the quoted-counter expectation in force, truncating the CLEAN-ROUTE
COVERAGE CEILING limitation to its first half was **accepted at zero
findings**: all four counters it must quote occur in the first 863 of its 1,726
characters. The cut removed what the ceiling forbids, why it cannot be widened,
and where the reading it replaced is recorded — the whole operative half of the
one limitation that exists to stop a coverage claim being strengthened.

`crValidateCleanRouteCeiling` now requires the three clauses AND **resolves**
the `revision_history` identity the last one names: the pointer must reach a
paragraph this document carries and that paragraph must be SUPERSEDED. A
dangling pointer, and a pointer aimed at the CURRENT paragraph, are both
refused.

### B. `revision_history` had an omission hole in its oldest paragraph

`TestConcurrencyResultsEveryModeledKeyIsRequired` walks every removable
position in the document. Against the first implementation it reported:

```
deleting revision_history[0] produces no finding: its absence decodes to a
zero value that agrees with everything
```

It was right. The forward chain is relative, so a history shortened from the
FRONT still chains, still carries exactly one CURRENT paragraph at its end, and
still agrees with the record's counters. Substitution could never have found
this — an absent element is not a wrong value — which is exactly why the
omission walk is a separate axis. The head is now anchored.

### C. A re-wording silently un-bound the scenario count

`preregistered_plan.conformance` was CHECKED before this branch and measured
INERT after it. One re-wording did it: appending a third scenario turned
"across BOTH scenarios" into "across ALL 3 scenarios", and the battery's
candidate for a sentence carrying a number moves the FIRST number — so
`across ALL 4 scenarios` was accepted at zero findings, because the prose
tokenizer that guards this document's counters applies a four-digit floor and
never looked at it. `crValidatePlanConformanceShape` now renders the three
scenario clauses from `bounds.scenario_shapes` and requires each verbatim.

### D. Nine stale probes, one of them worse than stale

Changing the explored space left nine negative cases citing the old one. Four
aimed at sentences containing 81131 / 81180 / 318661 that no longer exist (they
failed loudly, as designed); one bounds mutation had become a no-op
(`bounds.scenarios` 3 → 3, i.e. no mutation at all); four more in the union
suite. The tenth was worse than stale: the no-live-Java case addressed the last
limitation **by index**, and the appended ceiling silently made it delete the
ceiling instead of softening the disclosure it names — a test that had quietly
stopped testing what its name says. It is now located by content.

---

## RED readings and deletion attacks

Every check added here was proved capable of failing. A mutation that breaks
compilation proves nothing, so each deletion removes a CALL or a self-contained
BLOCK and the package still builds.

The clean-path floors in the sweep (`clean_terminal_digests >= 2`, `>= 100`,
`clean_terminal_scenarios >= 2`) are set BELOW what the tree measures (403,
403, 2) so ordinary drift does not trip them; they exist to catch the collapse,
which is the failure mode that actually happened. The three counters themselves
are printed into the cited line, which the harness compares byte-for-byte with
the document, so no edit of either side can go unnoticed.

### The Go side

Seven deletions, each of a CALL or a self-contained BLOCK so the package still
builds (`package built = True` asserted in every run), each followed by the
cases that claim to prove that check. "Accepted" means the validator returned
zero findings for a mutation it is supposed to refuse.

| deletion | `go test` exit | cases accepted at zero findings | cases still refused by another check |
| --- | --- | --- | --- |
| `crValidateRevisionHistory` (the call) | 1 | **12 of 13** | 1 — `the whole history is dropped`, caught by `RESULTS_CLEAN_ROUTE_CEILING_UNSOUND` |
| the `crRevisionHistoryAnchor` block only | 1 | **3 of 3** | 0 |
| `crValidateScenarioProse` (the call) | 1 | **3 of 4** | 1 — `the scenario is not one the harness enumerates`, caught by `RESULTS_SCENARIO_NAMES_CONTRADICTED` |
| `crValidateCleanRouteCeiling` (the call) | 1 | **5 of 7** | 2 — `the ceiling is removed from the record` and `PointingAtALiveParagraph` |
| `crValidatePlanConformanceShape` (the call) | 1 | **3 of 4** | 1 — `the widest schedule is understated`, caught by `RESULTS_ACCOUNTING_CONTRADICTION` |
| the clean-route relations in `crValidateAccounting` | 1 | **5 of 5**, after the cases were made isolating | 0 (before: 0 of 5, all caught by the run re-derivation — see below) |
| the `limitations.clean_route_ceiling` expectation | 1 | **1 of 3** | 2 — caught by `RESULTS_CLEAN_ROUTE_CEILING_UNSOUND` |

The non-isolating rows are recorded, not rounded off. Two of them are honest
overlap between two checks that both refuse the same document; the scenario-prose
one is structural (a name the harness's table does not bind fails the NAME
derivation before the prose derivation is reached).

**The accounting row is a finding about the tests, not about the checks.** On
the first measurement, deleting the clean-route relations changed nothing:
all five cases were still refused, by `RESULTS_COUNTER_CONTRADICTS_RUN`, because
each moved only the document's counter and every counter here is re-derived
from the line the record cites. The test was measuring the run binding and
would have gone on passing with the relations deleted. The cases now move the
cited line too — the document whose run line was fabricated CONSISTENTLY, which
is the only shape those relations exist for — and the deletion then accepts all
five.

### The Rust side, read from the cargo process

The floors are not deleted to prove they can fire; deleting an assert proves
nothing. The mutation is the tree they were written against — the exploration
WITHOUT the appended scenario, which is exactly the shape the post-failure
landing left behind. Removing `("clean-finish-inbound-ping", …)` from the
`SCENARIOS` table:

```
cargo exit = 101
test result: FAILED. 0 passed; 1 failed
panicked at ws-driver/tests/schedule_exploration.rs:1846:5:
clean-terminal BREADTH floor: 49 clean-terminal runs carry only 18 distinct
semantic traces, so the properties that hold only on the clean route
(convergence, exactly-once reconciliation, post-terminal quiescence, no write
bypass) are exercised against that many behaviours, not against the run count
```

49 and 18: the floor fires on precisely the reading the review asked about.
The harness was restored and re-run to exit 0 afterwards.

---

## Not done, by name

Recorded so the omissions are not read as coverage.

- The exclusivity assertion was **NOT restored and NOT weakened**. The ordering
  property ("no Terminal AFTER a Failure") stands as the post-failure landing
  left it.
- `assurance/concurrency/plan.json` was **not edited**: its
  `preregistered_plan.sha256` and `append_blocker` are untouched, and the new
  scenario had to fit the preregistered `schedule_count_max`.
- `evidence/java/behavior-delta-ledger.json` and `internal/deltaledger` were
  not touched.
- **No seed and no minimized artifact was refrozen.** `US017_RETAIN=1` was not
  used: the scenario is APPENDED, so every pinned `found_index` ordinal is
  unchanged and there was nothing to refreeze. The flag's second exit is
  therefore not reported here, because the flag was not run.
- No AWS, benchmark, Autobahn or native-stress run was executed. `native_stress`
  in the record is unchanged and still describes the darwin arm64 host of an
  earlier session; this branch adds no platform evidence.
- The whole-space discriminating power was **not** restored to its pre-landing
  figure, and section 4 above says why it cannot be.
- `drafts/self-review/evidence-validation-round-5.md` was **not** edited. Its
  "71 inert of 327" is that round's reading and is correct as history; the
  current reading lives in `crInertLeaves` and here.
