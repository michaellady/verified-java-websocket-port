# Concurrency coverage disclosure — measurement record

Track: `claude/concurrency-coverage-disclosure`, branched from mainline
`claude/feature/verified-java-websocket-port` @ 2c63205.

Answering the two findings of `drafts/self-review/post-failure-landing-review.md`.

Status: MEASUREMENT COMPLETE, changes in progress.

## Baseline read, before anything was touched

`cargo test -p ws-driver --release --test schedule_exploration -- --nocapture`,
**exit 0 read from the cargo process**, `test result: ok. 11 passed; 0 failed`.
The printed `US017_EXPLORATION` line matched the committed
`execution.executed_run.stdout_line` byte for byte, so the tree I measured is
the tree the record describes.

## Finding 1 — what the 49 actually is

The review asked whether 49 clean-terminal runs in one scenario is adequate
coverage for properties that previously had 56,777. Measured, not reasoned
about. A temporary probe (added to the harness, run, and removed again —
it is not in this branch's diff) split the committed space by scenario:

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

Four facts the record does not carry, each of which changes the answer:

1. **The 79,920/81,180 comparison is not a before/after of the same space.**
   Scenario A (`abnormal-teardown`) enumerates exactly 79,920 schedules on its
   own — the whole pre-landing space. The landing did not shrink a space; it
   ADDED scenario B (`clean-finish`, 1,260 schedules). 79,920 + 1,260 = 81,180.

2. **The 56,777 was never clean-finish coverage.** Every one of those runs was
   in scenario A, whose own doc comment records that its clean convergence was
   an artifact of the driver's EOF-coalescing defect (fixed in 8a7e3a4): two
   terminations silently merged into one. With the defect fixed, scenario A
   yields **0** clean terminals — correctly. So the honest comparison is not
   56,777 → 49. It is *0 genuine clean-finish runs → 49*.

3. **49 runs is not 49 behaviours. It is 18.** The 49 clean-terminal runs carry
   only **18 distinct semantic trace digests**. The clean-terminal properties
   — `Convergence`, the exactly-once reconciliation `accepted == disposed`,
   `PostTerminalActivity` quiescence, and `WriteBypass` — are therefore
   exercised against eighteen distinct behaviours. That is the real number, and
   it is thinner than the 49 the record prints.

4. **A counter that measures the loss exists in the harness and is discarded.**
   `bounded_exploration_...` computes `halted_terminals` — runs that took their
   one clean `Terminal` and only then halted. It is **904**, all of them in
   scenario A. It is asserted against `totals.terminals` and then thrown away:
   it is in neither the printed `US017_EXPLORATION` line nor `results.json`.

### Why scenario B is so thin

All 1,211 halted runs of scenario B halt on a `StateViolation`, and **none of
them has taken a `Terminal` first** (`halted_with_terminal=0`): 1,197 surface it
on a `Wake` poll and 14 on `TransportEof`. A clean finish requires both producer
enqueues to land before the peer's close; every interleaving that lets
`inbound-close` overtake a producer is a state violation, and with 7 actions
across 5 programs those are 1,211 of the 1,260. This is not the post-terminal
refusal path swallowing the clean runs — it is the closing handshake starting
before the application has finished.

### Answer: 18 is not adequate, and it CAN be restored

Nine candidate clean-lifecycle shapes were enumerated and measured for clean
coverage. The constraint is hard: `plan.json` preregisters
`schedule_count_max = 100000` and this branch must not touch `plan.json`, so a
new scenario has at most 100,000 − 79,920 − 1,260 = **18,820 schedules**.

Measured, all with zero invariant violations (`violations={}`):

```
PROBE4_BASE  schedules=81180 clean_runs=49 distinct_all=3129 distinct_clean=18
PROBE4 name=E1  added=10980 own_clean_runs=1127 own_distinct_clean=385
       union_clean_runs=1176 union_distinct_clean=403 union_distinct_all=4587
PROBE4 name=D8  added=10980 own_clean_runs=474  own_distinct_clean=251
PROBE3 name=D6  added=8040  own_clean_runs=827  own_distinct_clean=191
PROBE3 name=D4  added=13920 own_clean_runs=331  own_distinct_clean=185
```

E1 wins and is adopted as scenario C.

## Not done, by name

Recorded so the omissions are not read as coverage.

- The exclusivity assertion was NOT restored and NOT weakened.
- `assurance/concurrency/plan.json` was not edited, so its
  `preregistered_plan.sha256` and `append_blocker` are untouched.
- `evidence/java/behavior-delta-ledger.json` and `internal/deltaledger` were
  not touched.
- No AWS, benchmark or Autobahn run was triggered.
