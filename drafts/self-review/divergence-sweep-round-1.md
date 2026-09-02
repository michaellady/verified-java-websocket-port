# divergence-sweep — self-review round 1

- Written 2026-09-02T18:13:19Z (`date -u`).
- Branch `claude/divergence-sweep`, based on mainline
  `claude/feature/verified-java-websocket-port` at `8a7f7130efd0fa44362590bddbaca9f5b1ae1f73`.
- Subject of the round: `internal/divergencesweep`, `cmd/divergencesweepctl`,
  `evidence/java/observed-close-divergences.json`,
  `drafts/ledger-proposals/divergence-sweep-{1..6}.json`.

Every exit code below was read from the process, never through a pipe.

## What was found before the attacks, and had to be fixed first

**Mainline does not contain the run this task names.** The task pointed at
`evidence/autobahn/native-x86_64-provenance/{rust,java}/{fuzzingclient,fuzzingserver}-run1/`.
That tree exists only on `claude/us019-native-run` (commit `4c45c6c`); mainline's
head commit *mentions* that branch's round 2 but has not merged it, and mainline
also has no `internal/autobahnsuite`. The 1048 files were brought onto this
branch verbatim (`git checkout claude/us019-native-run -- …`), blob-identical, in
their own commit, together with the digest manifest that pins them. Nothing was
re-baselined and no report byte was edited; the manifest verifies over the copy
in both directions on every run of the sweep.

**Two dimensions were withdrawn as not comparable, rather than reported as
divergences.** `rxOctetStats` and `txOctetStats` differ on 247/247 cases in both
roles, which looked at first like a finding. They are histograms of the sizes of
the chunks the suite read and wrote, i.e. TCP segmentation and scheduling, not a
subject-observable protocol behaviour — `txOctetStats` is the SUITE's own writes
and still differs. Reporting them would have inflated the divergence count by
703 differences with noise. They are now in the not-comparable group with that
reason recorded, and the protocol-level part they carried (the handshake head)
is recovered by the `subject_handshake_header_names` dimension, which is exact.

## Deletion attacks

Method: back up the subject, apply one mutation that removes the thing a check
protects, run the test that names it, read the failure, restore, and confirm the
suite returns to exit 0. The full round is
`/tmp/.../scratchpad/attacks.sh`; the mutations are in `mutate.py`. Baseline
before the round: `go test ./internal/divergencesweep/` exit 0. Baseline after:
exit 0.

| # | mutation | test | exit | what it said |
|---|---|---|---|---|
| A1 | one measured count in the committed document changed (`"agree": 125` → `126`) | `TestCommittedDocumentAgreesWithTheRunReports` | 1 | `first difference at line 382: committed "agree": 126, recomputed "agree": 125` |
| A2 | the `subject_close_reason` dimension deleted from `Dimensions()` (field kept classified so the partition still sums) | `TestCommittedDocumentAgreesWithTheRunReports` | 1 | `first difference at line 108: committed "remoteCloseReason", recomputed "result"` |
| A3 | the `DIV-05` divergence class deleted from `Classes()` | `TestEveryMeasuredDifferenceIsExplainedByAClass` + committed-document | 1 | `3 of 3058 measured differences are claimed by no divergence class`, naming client-role 7.1.6 on three dimensions; and `claimed_by_a_class: 3058` vs recomputed `3055` |
| A4 | the `VerifyEvidenceIntegrity` call deleted from `Run()` | `TestEvidenceIntegrityRefusesEditedPlantedAndMissingFiles` | 1 | `the sweep ran over an edited per-case report` |
| A5 | the `bindIndexEntry` call deleted from `LoadLeg()` | `TestIndexBindingAndComparisonCrossCheckAreEachIsolated/index_binding` | 1 | `expected the index binding to refuse, got: cross-check: leg rust/server case 3.1 field behavior: reports say "FAILED", the committed comparison says "OK"` |
| A6 | the `CrossCheckBehaviourClasses` call deleted from `Run()` | `…/behaviour-class_cross-check` | 1 | `the sweep accepted a tree this probe planted a defect in` |
| A7 | the `isServer`-derived subject-role refusal deleted from `LoadLeg()` | `TestLoadLegRefusesAMisdeclaredSubjectRole` | 1 | `a leg declared with the wrong subject role was accepted` |
| A8 | `checkFieldPartition` neutered to `return nil` | `TestFieldPartitionRefusesBothDirections` | 1 | `a report field nobody classified was accepted` |
| A9 | a committed ledger-proposal draft edited (`"server": 122` → `999`) | `TestCommittedLedgerProposalDraftsAgreeWithTheSweep` | 1 | `divergence-sweep-1.json disagrees with the sweep it is drafted from: … committed "server": 999, recomputed "server": 122` |
| A10 | `accept_response` in `rust/ws-core/src/handshake/server.rs` given the `Server` field it omits | `TestDIV06IsStillTrueOfThePortSourceItNames` | 1 | `accept_response now writes a Server field: DIV-06 … describes a port that has changed` |
| A11 | the `PartitionSum` assignment deleted from `Build` | `TestVerdictCountsPartitionTheCaseSet` | 1 | `server role, dimension subject_close_code: recorded partition sum 0, recomputed 247` |
| A12 | the `DIV-07` proposal deleted from `proposalSpecs()` | `TestCommittedLedgerProposalDraftsAgreeWithTheSweep` + `TestEveryClassIsEitherDraftedOrAlreadyLedgered` | 1 | `drafts/ledger-proposals holds 6 divergence-sweep drafts, the sweep produces 5` |

Every check I added can be made to fail. A10 was applied to a Rust source and
restored; `git status -- rust/` is empty afterwards, so no Rust byte is committed
on this branch.

## Findings on my own work, each fixed before the round closed

**Finding 1 — a probe that passed on another check's back (real, found by A4).**
The first form of the edited-report probe changed `remoteCloseCode` from `null`
to `1002` and then asserted only that `Run` returned *some* error. With
`VerifyEvidenceIntegrity` deleted from `Run`, that probe still passed: the index
binding refused the edit, because `index.json` repeats `remoteCloseCode`. The
probe therefore never proved the digest manifest was load-bearing inside `Run`.
Fixed two ways: the probe now edits `resultClose`, which neither the index nor
the committed comparison document carries, so nothing but the digest manifest can
refuse it; and it asserts the error text names the manifest
(`"the manifest pins"`) rather than merely being non-nil. A4 is red only after
that fix.

**Finding 2 — a class-coverage claim that could have been vacuous.** The
accounting reports `unclaimed = 0`. On its own that is satisfiable by declaring
one class that claims every dimension. Two things stop it: a class that selects
no case is a hard error (`a class that claims nothing is not a finding`), and
each class declares the dimensions it explains, so A3 leaves exactly the three
differences that class explained uncovered rather than being absorbed. The
overlap that does exist — five differences claimed by two classes — is counted
and listed in the document instead of being hidden by the single `unclaimed`
number.

**Finding 3 — the drafts quoted numbers by hand.** The first drafts of the
ledger proposals wrote `91`, `32`, `76`, `42`, `494` and `32 distinct reason
strings` as literals in the rationale prose, which is exactly "a number somebody
typed" and would have gone stale silently — and, because the rationale is a
hashed digest preimage, it would have baked a stale number into the `delta_id`.
Every one of those is now read out of the recomputed measurement
(`dimensionOf`, `javaValueCount`, `extent`), so a run in which the divergence
moved produces a different `delta_id` and A9's check fires.

**Finding 4 — the role mapping is the one error that changes no count.** If the
`fuzzingclient` leg were read as the subject's CLIENT role, every close finding
would be attributed to the wrong role and every count in the document would be
unchanged. Two independent things now stop it: the role is derived from the
reports' own `isServer` flag and must equal the leg's declaration (A7), and the
recomputed behaviour classes must equal the independently produced
`comparison/java-vs-rust-per-case.json` for all four (role, subject) pairs (A6).

## Residual gaps, stated rather than closed

- **The document is generated and verified by the same code.** Byte-equality
  catches a drifted artifact and a tampered report; it cannot catch a wrong
  comparison. That is why the sweep is bound to three sources it does not
  produce: the digest manifest, each leg's `index.json`, and the committed
  behaviour-class comparison. It is still not an independent implementation of
  the comparison, and this document does not claim one.
- **One run, one port build.** Everything measured is the `ws-testee` binary
  from commit `518b77aa` on `claude/us019-native-run`, captured
  `2026-08-28T18:48:27Z`. Mainline has moved. DIV-01's fix exists on
  `claude/post-failure` (commit `77d8c23`) and is not in mainline; DIV-06 is
  checked against the current mainline source and is still true there (A10).
  For DIV-02, DIV-03, DIV-05 and DIV-07 this branch establishes only what the
  run's bytes say; whether the current mainline port still does it was not
  re-measured, because re-running the Autobahn suite is an owner gate.
- **Coverage is the 247-case pinned manifest and what the suite records.** A
  divergence the suite does not observe is not measured here. In particular the
  suite records no close code the subject *would* have sent had it not dropped
  TCP, so DIV-01's 122 and 119 cases say the port sent nothing, not what it
  would have sent.
- **`TestProposedLedgerRecordsHaveNotLandedYet` and
  `TestDIV06IsStillTrueOfThePortSourceItNames` are tripwires.** They fail when
  the right thing happens — a proposal is appended, or the port is fixed. That
  is deliberate and the failure message says what to do, but a reader who is not
  expecting it will read the failure as a regression.
