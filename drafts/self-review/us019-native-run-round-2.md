# Self-review round 2 — claude/us019-native-run (goal loop): review finding 7

Recorded 2026-09-02 by the goal loop from tool output, on branch head
`51c9fb4`. Round 1 closed the amended AC3 bar and left three items. This round
takes the one that is mine rather than the owner's: review 01a04961 finding 7,
case-manifest independence. Self-review by the loop, not an independent
review: OWNER_ATTESTED_NOT_INDEPENDENT.

## The finding

> the case manifest remains snapshot-derived and refreezable; independent
> enumeration needs a source outside the run it constrains.

`BuildManifest` expands the 247-case manifest from the wstest reports it then
holds to account. The expectation is computed by the thing under test.
`verify-manifest` re-expands from the same sources and compares bytes, which
proves the manifest is immutable and proves nothing about whether those
sources described the suite.

## What this round changed

`internal/autobahnsuite/independence.go` binds the manifest to every source
in this tree that no wstest report can influence:

- the frozen family policy and the suite's own case-identity grammar, from
  `internal/lab`, which derives both by static parsing of pinned source;
- the pinned selected-case count, also from `internal/lab`, compared against
  this package's own constant so a drift between two independently sourced
  numbers fails rather than silently agreeing;
- the committed wstest configurations the four legs were actually launched
  with, which nothing compared to the policy before.

`verify-manifest` now runs these and reports `independent-constraints=ok`
alongside the byte-equality result. Exit 0 on the committed manifest.

## Attacks, and which now fail

Each was applied to the committed manifest and run against the check. All
were accepted before this round, because the run-derived build path cannot
see any of them.

| Attack | Before | After |
| --- | --- | --- |
| A case is dropped | accepted | refused |
| A case duplicated to keep the count at 247 | accepted | refused |
| A case from an EXCLUDED family admitted | accepted | refused |
| A whole selected family disappears | accepted | refused |
| The manifest narrows its own declared selection | accepted | refused |
| An exclusion dropped from the declaration | accepted | refused |
| An identity that is not a case identity | accepted | refused |
| A suite config selecting different families | accepted | refused |
| No suite config supplied at all | accepted | refused |
| **A real identity swapped for a fabricated one** | accepted | **still accepted** |

## The residual, measured rather than described

`7.9.6` rewritten to `7.9.997` — the right shape, a selected family, the count
still exactly 247 — satisfies every constraint this tree can currently apply,
because none of them knows which identities the suite actually defines.

**Finding 7 is NARROWED, NOT CLOSED.** The round does not report it closed,
and `TestTheResidualOfFinding7IsMeasuredNotClaimed` asserts the gap so it
cannot be reported closed by anyone reading the other tests. That test is
written to FAIL the day the gap closes, demanding its own deletion.

**What closes it, exactly:** materialise the pinned Autobahn source archive
(digest `internal/lab.PinnedAutobahnSourceArchiveDigest`) into the quarantine,
parse it with the registry parser this repository already has
(`ParsePinnedAutobahnRegistryArchive`, which reads the suite's own Python case
definitions), and require every manifest identity to appear in the resulting
selection. That is the source outside the run the finding asks for, and the
code for it already exists.

**Why it was not done here:** the GitHub archive URL answers 403 through this
environment's agent proxy, so the archive cannot be fetched. It is a
third-party upstream repository, outside this session's repository scope, so
cloning it to reproduce the archive is not mine to decide.

**Owner action, if the owner wants finding 7 fully closed:** make the pinned
Autobahn source archive available in the quarantine, the way the pinned Java
inputs already are (`.claude/CLOUD-ENVIRONMENT.md`, "Pinned Java inputs"). No
new code is needed beyond the binding described above.

## Validation at this head

Gates, the Go suite and the unchanged-behaviour argument are recorded in the
commit message with their exits. No Rust byte changed this round, so the
differential and the exam cannot have moved.
