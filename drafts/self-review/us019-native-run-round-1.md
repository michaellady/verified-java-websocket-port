# Self-review round 1 — claude/us019-native-run (goal loop, after the forward merge)

Recorded 2026-09-02 by the goal loop from tool output, on the forward-merged
branch (`b26be41`). This is the round the merge-queue entry has been waiting
for: the branch has carried a BLOCK from independent review 01a04961 since
2026-08-28, with six of its eight findings fixed at `518b77a`. Self-review by
the loop, not an independent review: OWNER_ATTESTED_NOT_INDEPENDENT.

Every exit below was read from the process. Every negative case was run
against the code BEFORE the check it exercises existed, or with that check
deleted, and observed to pass.

## What this round set out to close

The queue entry named a fixed list. This round closes the first item and the
half of the second that does not need an owner:

1. **The amended AC3 bar was not implemented.** The owner amended AC3's
   strict-pass clause on 2026-08-28 to read as per-case behavior-class
   agreement with the pinned Java baseline. The verdict still read the
   literal clause and was NEGATIVE, and the amended bar existed only as a
   sentence in a decision record.
2. **The comparison that carries the amended bar's numbers had no consumer.**
   `comparison/java-vs-rust-per-case.json` and its summary were generated and
   never read — the same shape review 01a04961 found in the digest manifest,
   recurring in the artifact the bar rests on.
3. **The native evidence tree was unpinned.** The digest manifest pins 1,506
   files of the emulated tree and zero of `native-x86_64-provenance`, so the
   four index files the bar is computed from, the Java baseline, and the
   comparison could all be edited with no gate noticing.

## Findings of this round

### Finding 1 — the amended bar had no implementation (closed)

`internal/autobahnsuite/baseline.go` adds `CompareToBaseline`,
`DiscriminateAgainstBaseline` and the register machinery. The verdict is
computed from the two runs' own report bytes, both read against the same
manifest.

Measured on the committed native run, both roles:

| Reading | Client | Server |
| --- | --- | --- |
| Cases agreeing with Java | 246 of 247 | 246 of 247 |
| Port weaker than Java | 1 (case 5.15) | 1 (case 5.15) |
| Port stricter than Java | 0 | 0 |
| Divergences registered / unregistered | 1 / 0 | 1 / 0 |
| Amended verdict | met | met |
| Literal verdict | NEGATIVE, unchanged | NEGATIVE, unchanged |

Both readings stay computed and both are printed by the new
`autobahnsuitectl amended-ac3` subcommand. The amendment changed which
reading AC3 is judged by; it did not repeal the other, and a reader is owed
both.

### Finding 2 — the owner decision's own figures are not what this tree holds

The decision text records "client 245/247, server 246/247". Measured here,
both roles are 246 of 247, and the single residual difference is case 5.15 in
both. The decision predates the native re-run, so its numbers came from the
earlier emulated run; measured against the native Java baseline the emulated
port run also scores 246. No pairing available in this tree reproduces 245.

Nothing is adjusted to match the decision. The test prints the numbers it
derived, so the figure can never again be quoted by anyone who did not read
it. **Owner action: none required** unless the owner wants the decision text
corrected; the amended bar is met either way.

### Finding 3 — my own first ledger check was existence standing in for identity

The first version required only that the behavior-delta ledger CITE the
diverging case. Attacked with a planted regression — case 1.1.1, which both
runs score OK, rewritten to FAILED in the subject's index — the bar
**ACCEPTED it**, because 1.1.1 is cited by ledger sequence 47, a superseding
correction about a handshake header-line limit that says nothing about any
Autobahn conformance divergence. A citation of a case is not a record of THAT
divergence.

Replaced with a committed divergence register
(`comparison/behavior-class-divergences.json`) that is exact in both
directions: each entry names the case, the role, and the two behavior classes
observed, plus the ledger record that analyses it; a divergence with no entry
fails, and an entry the runs do not exhibit fails. The register is not a
waiver list — its one entry records an open divergence whose ledger
disposition is `unresolved`.

### Finding 4 — two of my six checks were not isolated by any probe

The deletion sweep is the measurement of record. Each check was deleted in
turn, keeping the package compiling, and the suite re-run:

| Deleted check | Result |
| --- | --- |
| Self-comparison vacuity guard | red, the self-comparison test |
| Verdict's zero-unregistered condition | red, three tests |
| Register lookup's class match | red, the register test |
| Ledger resolution of a register entry | red, the ledger test |
| Register exactness, stale-entry direction | **GREEN — not discriminated** |
| Comparison document's value comparison | **GREEN — not discriminated** |

Both were my own new code, and both probes were wrong in the same way: they
changed two things at once, so another check fired and hid the deletion. The
stale-entry probe removed the real divergence at the same time as adding the
stale entry, so the missing-entry direction fired. The document probes each
tripped the row count, the agent name or the difference list before the value
comparison was ever reached.

Two isolating probes added:

- a register carrying the real entry AND an extra entry for an agreeing case,
  which leaves zero unregistered divergences so only the stale direction can
  fire;
- a comparison document with case 3.2 rewritten from NON-STRICT to OK in ALL
  FOUR columns, which stays internally consistent, stays correctly absent
  from the difference list, and changes no count.

Re-run with the same two deletions, both are now red. A compile break is not
evidence a check discriminates, so the document deletion was re-run as a
compiling one.

### Finding 5 — the native evidence tree was unpinned (closed)

`evidence/autobahn/native-digest-manifest.json` pins the 1,048 files of the
native tree, generated and verified through the existing sanctioned
subcommand (generate exit 0, verify exit 0). Two consumers: the existing
verification, and a test that names the six files the amended bar actually
reads and requires each to be pinned. A manifest that pins a thousand files
and misses the four that matter would verify clean and protect nothing.

## What this round did NOT close, and what each needs

- **AC1's bounded-resources clause stays unmet.** The native run read
  `memory.max` and `cpu.max` as unbounded. Recorded as unmet, not smoothed
  over. **Owner gate:** re-running bounded needs a new AWS host.
- **The no-echo and opcode-swap mutant runs are incomplete** (66 of 247 and
  181 of 247 never scored), so their discrimination is OUTSTANDING.
  **Owner gate:** completing them needs Autobahn re-runs, which the loop
  never triggers.
- **Finding 7 of review 01a04961, case-manifest independence,** is open. The
  manifest remains snapshot-derived; independent enumeration needs a source
  outside the run it constrains.
- **Ledger sequence 34 is `unresolved`.** The amended AC3 bar is met with the
  difference registered and ledgered, which is what the owner decision asks.
  Master US-020's rule that unresolved deltas block completion is a separate,
  higher gate and is untouched by this round.

## Validation at this head

Recorded in the landing preparation section of `.claude/GOAL-LOOP.md` and in
the commit message; gates, the Go suite, and the differential and exam
readings are all listed there with their exits.
