# Concurrency coverage disclosure — measurement record

Track: `claude/concurrency-coverage-disclosure`, branched from mainline
`claude/feature/verified-java-websocket-port` @ 2c63205.

Answering the two findings of `drafts/self-review/post-failure-landing-review.md`.

Self-review by the goal loop: **OWNER_ATTESTED_NOT_INDEPENDENT**. Nothing here
was reviewed by anyone else.

### The state this work was resumed from

A container restart interrupted this track at `fe736b3`. That commit had the
scenario, the `revision_history` field and the validator checks in it — and it
was RED, in four places nobody had run:

* `make -C rust gates` exit **2** at its first target, `fmt-check`;
* `go test ./internal/formalplan/` failing the pinned leaf enumeration (337
  leaves pinned against a document with 401), one omission hole, and ten
  negative cases addressed at a space the branch had changed;
* the evidence DAG carrying a stale digest AND a stale title;
* every new validator check GREEN-only — not one negative test between them.

None of that is a criticism of the interrupted work; it is where the work had
got to. It is recorded because "the branch existed" and "the branch was green"
are different claims and only the first was true.

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

**And it had been named once already.** Searching the tree for the superseded
counters turned up carried follow-up BP1 inside a protected owner decision,
`us017-c6-layer-split-owner-decision-2026-08-28`:

> BP1 from the same lane is treated as a real follow-up, not a footnote: the C5
> fix cuts clean-convergence exploration runs from 1108 to 49 (failure_halted
> 80072 → 81131, sum 81180 both ways), a 96 percent coverage drop on one
> branch, measured on both sides. It belongs to the interpreter's halt model
> rather than the driver.

So the review's "nobody has said whether 49 is adequate" is exact but generous:
somebody had said the drop was real, in August, in a governance record — and
it reached no limitation of the evidence document it constrains for the week
that followed. The ceiling now says where it came from, and the check RESOLVES
the decision it cites against `evidence/governance/decisions` rather than
reading it, because a citation nobody resolves is how "the owner already knows"
becomes a sentence rather than a fact. The governance record itself is
untouched: it is accurate as the history it is.

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

Five, all found by running the instruments rather than by reasoning, and all
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

### D. Ten probes stopped testing what they name

Changing the explored space left ten negative cases addressed at the old one.
Nine were stale: four aimed at sentences containing 81131 / 81180 / 318661 that
no longer exist (they failed loudly, as designed), one bounds mutation had
become a no-op (`bounds.scenarios` 3 → 3, i.e. no mutation at all), and four
more in the union suite cited run-line tokens that had moved. The tenth was
worse than stale, because it did not fail: the no-live-Java case addressed the
last limitation **by index**, and the appended ceiling silently made it delete
the ceiling instead of softening the disclosure its name promises. A green test
that had quietly stopped testing what it says is the worse of the two failure
modes. It is now located by content.

### E. A derivation a formatter could break

`cargo fmt` split the third `SCENARIOS` entry across lines and added a trailing
comma. `crScenarioEntryPattern` required the `ProgramSet` constant to be
followed directly by `)`, so the validator stopped finding the scenario at all
and reported `RESULTS_SCENARIO_PROSE_UNDERIVED` against a document that was
correct. Three tests went red on it — the artifact check, the union's
committed-document case, and the leaf enumeration's own pristine control. The
entry was short enough to fit on one line as hand-written and long enough to be
split the moment the formatter ran, so the derivation added to bind the
scenario prose was one `cargo fmt` away from failing on a correct tree.

A derivation a formatter can break is not a derivation. The pattern accepts the
trailing comma now, and the comment records why rather than just what.

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

## The inert-leaf reading, re-measured

`CR_LEAF_ENUM=print`, transcribed from the print, not chosen:

```
LEAF_ENUMERATION leaves=401 checked=331 inert=70
LEAF_BATTERY candidates=1 leaves=6      (the six booleans; one flip is exhaustive)
LEAF_BATTERY candidates=2 leaves=34
LEAF_BATTERY candidates=3 leaves=178
LEAF_BATTERY candidates=4 leaves=127
LEAF_BATTERY candidates=5 leaves=52
LEAF_BATTERY candidates=6 leaves=4
```

**75 inert of 337 before this branch, 70 of 401 after.** The pinned enumeration
in `internal/formalplan/concurrencyresults_leaves_test.go` is updated to match,
and the +64 leaves are accounted for leaf-path by leaf-path rather than
counted by hand:

| change | leaves |
| --- | --- |
| `revision_note` (one string) → `revision_history` (8 paragraphs × 7 leaves) | +56 −1 |
| the appended `clean-finish-inbound-ping` scenario shape | +5 |
| the three clean-route coverage readings in `execution` | +3 |
| `limitations[12]`, the clean-route coverage ceiling | +1 |

Six leaves changed class, in three directions:

* **`revision_note` is gone from the residual list.** It had been on it in
  every round since the list existed, always with the same justification —
  "session prose" — which was true only because nothing had been asked of it.
  All 56 leaves of the field replacing it are CHECKED.
* **The four scenario-prose leaves are gone.** `bounds.scenario_shapes[*]
  .models` and `.why_explored` were added to the list at the post-failure
  landing as "prose about history … nothing in this tree can contradict it".
  The harness contradicts it now. The two leaves of the THIRD scenario are
  checked from the moment it lands, so appending a scenario no longer appends
  inert leaves.
* **`preregistered_plan.conformance` went INERT and is checked again** — the
  regression described in finding C above.

`native_stress.rustc` is now the only survivor of the pair
("`native_stress.rustc` and `revision_note`") that this list has carried in
every round it has existed.

---

## Gates and suites, exits read from the process

| run | exit |
| --- | --- |
| `cargo test -p ws-driver --release --test schedule_exploration` (from `rust/`) | **0**, `11 passed; 0 failed` |
| `make -C rust gates`, first attempt | **2** — `fmt-check` refused the harness `fe736b3` left unformatted |
| `make -C rust gates`, after `cargo fmt --all` | **0** — `ac1-gates verdict=PASS gates_passed=8/8`, `adapter-linkage verdict=PASS`, ledger integrity verified at 56 records, 79 `test result: ok`, 0 FAILED |
| `go test ./internal/linkage/` before regeneration | **1** by design — `LINKAGE_DAG_DRIFTED`, `schedule-exploration digest is stale` |
| `LINKAGE_REGENERATE=1 go test ./internal/linkage/ -run TestRegenerateLinkageArtifacts` | **0** |
| `go test ./internal/linkage/` after regeneration | **0** |
| `go test ./internal/formalplan/ -run 'TestConcurrencyResults\|TestCommittedConcurrencyResults'` | see below |

`cargo fmt` moved the harness blob, so `target.harness.git_blob` is rebound
`53e08b8d…` → `800c0d51…` and the sweep re-run. Both cited runs remain
**byte-identical** after the reformat: the single `US017_EXPLORATION` line and
the five `US017_FATAL_SWEEP` lines, checked by `diff`, not by eye.

The evidence DAG's title had also gone stale — it said "81180 schedules across
2 scenarios" — and is now derived from the same reading as the rest.

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
