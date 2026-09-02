# Landing record — claude/divergence-sweep → mainline (goal-loop, parallel-agent track C)

Recorded 2026-09-02 by the goal loop from tool output. The branch carries its
own review round, `drafts/self-review/divergence-sweep-round-1.md` (12 deletion
attacks, four findings on its own work fixed first). This record is the landing
check the loop ran on top of it: OWNER_ATTESTED_NOT_INDEPENDENT.

## What landed

Three commits, merged with mainline `d433c21`. Automatic merge, no conflicts.

- `d9eb616` — the native x86_64 Autobahn run, 1,049 files, copied verbatim.
- `b88a2d9` — `internal/divergencesweep` (9 files), `cmd/divergencesweepctl`,
  `evidence/java/observed-close-divergences.json`, six ledger-proposal drafts,
  the round-1 record. 20 files, no Rust.
- `1bb8f7b` — the branch's forward merge of mainline `01ee515`.

## The evidence copy from an unlanded branch, examined before accepting it

`evidence/autobahn/native-x86_64-provenance/` and the native digest manifest
exist only on `claude/us019-native-run`, which is still open as PR #4 and still
BLOCK from review `01a04961`. Landing them sideways through a different branch
is exactly how un-reviewed content reaches mainline without its review, so this
was checked rather than assumed:

- **Blob-identical.** `git diff` between `origin/claude/us019-native-run` and
  commit `d9eb616` over `evidence/autobahn/native-x86_64-provenance/` and
  `evidence/autobahn/native-digest-manifest.json` is **empty**. When us019
  lands, both sides add identical content and the merge is clean.
- **Confined to the raw run.** `d9eb616` touches only paths under
  `evidence/autobahn/`. It does **not** bring `internal/autobahnsuite`.
- **Therefore none of us019's contested judgment comes across.** Every open
  finding on that branch — AC3's amended per-case behaviour-class bar, AC1's
  unmet bounded-resources clause, AC4's outstanding mutant discrimination, and
  finding 7's narrowed-not-closed manifest independence — lives in
  `internal/autobahnsuite` and in the comparison and verdict documents, none of
  which are here. What mainline gains is the raw reports and their digest
  manifest, as INPUTS to this sweep.

**Stated plainly so nobody reads it otherwise: mainline now carries this
Autobahn run with NO acceptance claim attached to it.** Its acceptance remains
entirely a question for US-019 and PR #4.

## Independent re-derivation of the headline numbers

The branch's own caveat is the right one: "the document is generated and
verified by the same code — byte-equality catches drift and tampering, not a
wrong comparison." So the loop re-derived the load-bearing counts straight from
the 988 raw per-case JSON files, in throwaway Python, touching neither
`internal/divergencesweep` nor `observed-close-divergences.json`:

| Measure | Sweep reports | Re-derived independently |
| --- | --- | --- |
| Port sent no Close frame where Java did, subject-as-server | 122 | **122** |
| Same, subject-as-client | 119 | **119** |
| Java's codes on those server cases | 1007×76, 1002×42, 1000×4 | **1007×76, 1002×42, 1000×4** |
| Java's codes on those client cases | 1007×76, 1002×40, 1000×3 | **1007×76, 1002×40, 1000×3** |
| Close-code disagreements where both sent | 0 | **0** |
| Close-reason disagreements where both sent | 0 | **0** |

Every headline figure reproduces exactly, through code the branch never wrote.
That is the strongest check available here and it passes. (A cruder metric of my
own — cases where the suite's `droppedByMe` differs — reads 124 rather than the
sweep's 123 for DIV-02; that is a different, coarser dimension than the sweep's
derived "who closed TCP", not a contradiction. See the accounting below.)

## The arithmetic is honest about its own overlap

`difference_accounting` records `total_differences: 3058`,
`claimed_by_a_class: 3058`, `unclaimed: 0` — and separately
`class_claim_sum: 3063` with
`differences_claimed_by_more_than_one_class: 5`, each of the five detailed. It
does not quietly present 3063 as the total, and it does not hide the overlap to
make the partition look exact. It also names six dimensions measured at **zero**
divergence rather than reporting only where it found something.

Equally to its credit, two dimensions were **withdrawn rather than reported**:
`rxOctetStats`/`txOctetStats` differ on 247/247 in both roles, but they are
chunk-size histograms — TCP segmentation, not subject behaviour, and the suite's
own writes differ too. Reporting them would have inflated the count by 703 noise
differences. Withdrawing a finding that would have made the result look bigger
is the harder direction, and it was taken.

## How this meets track B, landed minutes earlier

DIV-02 — "after the closing handshake the port's server leaves the TCP
connection open", 123 server cases, recommendation FIX_IN_PORT — **is the defect
`claude/server-close-parity` just fixed** (mainline `d433c21`). Two tracks that
never saw each other's work, one reading shipped Java's source and one measuring
the pinned run, converged on the same defect.

**But the measurement predates the fix and this must not be read as closed.**
The sweep measures run `us019-prov-20260828T183623Z` at port build `518b77aa`.
Confirming DIV-02 is actually resolved needs a fresh Autobahn run against the
current mainline port, and re-running Autobahn is an **owner gate**. Until then
DIV-02's status is "fix landed, closure unconfirmed".

Similarly, DIV-01 (the port dropping TCP with no Close frame, 122 server / 119
client — the largest class by far) has its fix on `claude/post-failure` at
`77d8c23`, which is still in flight with track A and not on mainline.

## The ledger: six drafts, not appended, same deferral as track B

`drafts/ledger-proposals/divergence-sweep-{1..6}.json` carry authentic
`delta_id`s computed by the same construction `internal/deltaledger` uses, with
`previous_digest`/`record_digest` marked `PENDING_APPEND_POSITION` rather than
fabricated. **The ledger itself was only read, never written.**

They are held for the same reason track B's is, recorded in that landing:
the live ledger's `disposition` vocabulary is `["unresolved", "rfc-governs"]`
and all 48 records read `unresolved`, while US-020 AC3 requires Java quirk /
Rust defect / underspecified. These six span both a divergence to fix in the
port and one to record as an intentional correction — precisely the distinction
the current vocabulary cannot make. Settle the vocabulary first, then append
track B's record and these six together.

## Residual, named

- The document is generated and verified by the same code. Byte-equality catches
  drift and tampering, not a wrong comparison. Mitigated two ways: the branch
  binds it to three sources it does not produce, and the loop's independent
  re-derivation above covers the headline counts — but only those.
- Whether current mainline still exhibits DIV-02/03/05/07 is **not established**
  (owner gate: an Autobahn re-run). DIV-06 *is* checked against mainline source
  by a live test and is still true.
- `TestProposedLedgerRecordsHaveNotLandedYet` and
  `TestDIV06IsStillTrueOfThePortSourceItNames` are deliberate tripwires that
  fail when a proposal lands or the port is fixed, with a message saying so.
  Whoever appends the ledger records or fixes DIV-06 must expect them.
- 32 distinct Java close-reason strings were recorded that nothing in this
  repository had captured before (`bad rsv RSV1: false…`, `more than 125
  octets`, `Unknown opcode 3`, `closecode must not be sent over the wire: 1004`,
  …). They are new observed-behaviour surface, not yet consumed by anything but
  this document.

## Gates, read at the merged head

- `make -C rust gates` with the store exported: **exit 0**;
  `ac1-gates verdict=PASS gates_passed=8/8`; `adapter-linkage verdict=PASS` over
  5 production sources; ledger integrity verified (48 records, frozen prefix
  through 35, unledgered_disagreements 0); 75 `test result: ok`, **0 failed**.
- `go build ./...` exit 0. `go test -count=1 ./internal/divergencesweep/` exit 0.
- `go run ./cmd/divergencesweepctl --root . --check` **exit 0**: "the committed
  document and every ledger-proposal draft agree with the run reports".
- The branch adds **no Rust byte**, so the public differential and the handshake
  exam cannot have moved by it; they were re-run at `d433c21` for track B's
  landing and read port 74/74 and 49/49, live Java 74/74 and 49/49, same 16
  divergences.
