# Loop review of the post-failure landing (after the fact)

Recorded 2026-09-02 by the goal loop. Track A landed `claude/post-failure` to
mainline itself (merge `b62a979`, then `f30c9a7`) rather than reporting the
branch for the loop to land, so this review is after the fact rather than
before. It is a self-review by the loop: OWNER_ATTESTED_NOT_INDEPENDENT.

**The landing stands.** Gates re-run by the loop at mainline `f30c9a7`: exit 0,
`ac1-gates verdict=PASS gates_passed=8/8`, `adapter-linkage verdict=PASS`,
ledger integrity verified at 49 records, 77 `test result: ok`, 0 failed.
Nothing below is a reason to revert. Two things need to be on the record that
are not on it.

## Verified, not assumed

- **The ledger append is a re-sequencing, not a new decision.** The
  `protocol-violation-close-reaction` record was already committed on the
  branch — at sequence 36 of the branch's own 36-record ledger, authored in
  `77d8c23`, the branch's DIV-01 fix commit. Mainline had reached 48, so the
  merge re-sequenced it to 49 with a recomputed `previous_digest` and
  `record_digest`. That is append-only reconciliation and it is why this append
  is not subject to the deferral the loop applied to the server-close-parity
  and divergence-sweep proposals: those seven records have no branch history and
  are genuinely new decisions.
- **The `plan.json` `append_blocker` compression drops no claim.** The field is
  schema-capped at 8192 characters and stood at 8176, so the C6 sentence had to
  be paid for. Diffed word by word: 33 spans changed, and every one is filler
  (`whole`, `populated`, `story`, `already`, `own`, `precisely`,
  `authoritative`, `themselves`, `previously`, `ITSELF`) or a meaning-preserving
  rephrase (`which matters more`→`worse`, `throughout the period when`→`while`,
  `WITHDRAWN outright`→`WITHDRAWN`). The only numeric change is 48→49. The one
  span that could have carried an obligation — "binds the SENDER, not a
  must-refuse on the recipient" → "binds the SENDER, not the recipient" — keeps
  the sender/recipient contrast intact. 8176 → 8179 characters, under the cap.

## Finding 1 — the exploration lost 83% of its discriminating power, and the record does not say so

The changed assertion is correct. Exclusivity ("every schedule reaches exactly
one typed terminal disposition") was true only because a converged connection
used to ABSORB work still pushed at it; now it REFUSES it, which is the defect
this branch fixed, so a run may take its one clean Terminal and only then reach
a fatal. Asserting exclusivity today would be asserting the defect. The
replacement — no Terminal AFTER a Failure, asserted against the trace — is the
strongest property that remains true. That reasoning holds.

What is not recorded is what the change cost:

| counter | before | after | |
| --- | --- | --- | --- |
| `explored_schedules` | 79,920 | 81,180 | +1.6% |
| `distinct_semantic_trace_digests` | 18,755 | **3,129** | **−83%** |
| `closed_terminal_runs` | 56,777 | **49** | **−99.9%** |
| `failure_halted_runs` | 23,143 | 81,131 | +250% |

The exploration now runs slightly MORE schedules and distinguishes far FEWER
behaviours: most schedules converge on hitting a refusal and halting. A defect
that only manifests in a trace now masked by an early refusal-halt would not be
explored. And the clean-terminal properties — the ones about reconciling every
accepted command exactly once on a clean finish — are now exercised by **49
runs confined to one scenario**, where they previously had 56,777 across the
space.

Each number is present in `results.json`, cited to the run line, and re-derived
by `internal/formalplan`, so nothing is false. But all twelve `limitations`
entries were checked and **none mentions the drop**. Nobody has said whether 49
clean-terminal runs is adequate coverage for the properties that had 56,777, and
that judgment is exactly what a reader needs. Until it is made, no claim about
this suite's concurrency coverage should be strengthened on the basis of the
81,180 schedule count — the schedule count went up while the behavioural
coverage went down.

## Finding 2 — `revision_note` now carries superseded counters, in a field no check can bind

`results.json`'s `revision_note` contains, in present-tense phrasing:

> SWEEP COUNTERS ARE UNCHANGED, re-executed and read identical: 79,920
> schedules, 315,070 branches, 18,755 distinct trace digests, 56,777/23,143
> closed/halted …

Every one of those is now superseded (81,180 / 318,661 / 3,129 / 49/81,131).
Read as the history of an earlier revision it is accurate; nothing marks it as
history, and a reader meeting that sentence in the committed document has no
signal that it describes a predecessor.

No check can catch this. `revision_note` is one of the leaves the
evidence-validation round-5 enumeration lists as INERT — 71 inert leaves of 327,
`native_stress.rustc` and `revision_note` among them. So the document contains a
field that looks like a counter attestation, contradicts the document's own
counters, and is bound by nothing. Same class as everything else this session
turned up.

Cheapest honest fix, not applied here because it belongs to the record's owner:
give each accumulated paragraph of `revision_note` an explicit revision tag, and
bind the tag — not the prose — so a superseded counter block is at least
addressable.

## Follow-up the landing named, now done: F005

The landing recorded a `test-release` failure in
`rust/ws-driver/tests/concurrency.rs::racing_producers_never_lose_or_duplicate_commands`
(`left: 179 right: 200` after the full 2,000,000-poll budget, under three other
agents' load), correctly declined to fix it inside the landing, and left it as a
follow-up. Done in this unit: all three loops in that file are now bounded by a
60-second `POLL_DEADLINE` instead of `POLL_BUDGET`, the poll counter is kept but
only to REPORT in failure messages, and every property assertion is unchanged.
Six consecutive release runs green; `make -C rust gates` exit 0, 8/8, 77
`test result: ok`, 0 failed.

Filed as `drafts/self-review/findings/F005-poll-budget-sized-to-a-host.md` —
the **third** sighting of the class (F002 buffer size, F004 spin count, F005
poll budget). That repetition is itself the finding: the portable rule has been
proposed twice and rediscovered twice, because it lives only in a findings file
and binds nothing. The generalisation to file against the family is in F005.
