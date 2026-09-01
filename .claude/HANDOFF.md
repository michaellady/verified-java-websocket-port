# Handoff — verified Java to Rust WebSocket port, Claude plane

Written 2026-08-29. Everything below is read from tool output at the time of
writing, not from memory. Verify anything you are about to rely on.

## Where things stand

Mainline is `claude/feature/verified-java-websocket-port` at **fdeecfb**. It
contains two merged branches: `claude/differential-regression` and
`claude/sbx-launcher`.

**9 of the PRD's 27 user stories have `passes: true`** — US-001 through US-007,
US-009 and US-018. That count comes from the PRD itself, not from a summary.

The bottleneck is no longer review. It is **merging**: four branches have passed
independent review and none of them are on mainline yet.

## The merge queue

Order matters. Three pairs collide on shared files, so `post-failure` lands
LAST: it touches `rust/ws-driver` (shared with `us017-ac2`),
`assurance/concurrency/results.json` (shared with `evidence-validation`) and
`rust/ws-testee` (shared with `us019`).

| branch | head | review | behind mainline |
| --- | --- | --- | --- |
| `claude/us008-restart` | `10a1dc1` | PASS (round 5) | 37 |
| `claude/ledger-integrity` | `aa422e2` | PASS (round 4) | 24 |
| `claude/us017-ac2` | `4b187b8` | PASS (round 4) | 24 |
| `claude/evidence-validation` | `9aa73ab` | round 5 in flight | 13 |
| `claude/post-failure` | `1d1a1e2` | PASS (round 3) — merge LAST | 13 |
| `claude/us019-native-run` | `319d4c4` | BLOCK, partly fixed | 37 |

Each branch needs a forward merge before it can land, and each has drifted
further behind while under review. Merge strictly one at a time — every merge
moves mainline.

### Between every merge, run and read

- `make -C rust gates` — expect `ac1-gates verdict=PASS gates_passed=8/8` and
  `adapter-linkage verdict=PASS`
- `go build ./...`, `go test -count=1 ./...`, `cargo test --workspace`
- the public corpus differential — **74/74 with zero non-runtime diffs**
- the live handshake exam — **49/49**
- live-Java scored-field disagreement — **zero**

The corpus and exam have no Makefile target. They are
`go run ./cmd/corporactl {oracle-requests,evaluate}` invocations reconstructed
from the recorded `pipeline` fields in the committed baselines under
`rust/ws-oracle-harness/baseline/`.

**A corpus shift is an owner-ruled hard stop.** If the transcript moves by any
non-runtime byte, stop and report it as a finding about behaviour change. Never
re-baseline, and never use a retention or regenerate flag to make a difference
disappear.

## What is in this repository, and what is not

This matters more than anything else here.

**In the repository:** all the code, the gates, the evidence trees, the
behaviour-delta ledger, the corpora, and every `claude/*` branch. All 46 are now
pushed.

**Not in the repository, and never will be:**

- **62 owner-decision records**, at
  `workspace/orchestrator/verified-java-websocket-port-claude/protected/` in HQ.
  These are the rulings that authorise the work. The owner ruled that they are
  mirrored into the repository **as digests only**, never as content, because
  this repository is public and the records carry internal deliberation, cost
  figures and infrastructure identifiers.
- **38 review receipts**, at `workspace/reports/dev-team/reviews/` in HQ, each
  naming the reviewer session that produced its verdict.
- Orchestrator state, execution records, drafts, and the race scoreboard.

### The governance store is published — you do not hit this

An earlier version of this handoff warned that `ledger-gates` would refuse in
every cloud session and fresh clone, because the owner-decision records lived
only in HQ. That is no longer true. The records are published in this
repository at `evidence/governance/decisions/`; set

```bash
export VJWP_PROTECTED_STORE=<repo-root>/evidence/governance/decisions
```

and the gate runs anywhere.

What has not changed: an unreachable store is still a REFUSAL rather than a
skip, and that must not be weakened. Do not point the variable at a stub. The
canonical store is still HQ and is still append-only — the repository copy is a
mirror, and corrections are re-published rather than edited in place.

## The defect class this project keeps finding

Every lane here has produced the same shape at least once, and several produced
it *inside the fix for it*. Assume you will too.

**Checks that cannot fail.** Concretely, the forms it has taken:

- an expectation computed by the implementation under test, so the test agrees
  with whatever the code does
- existence standing in for identity — a path that resolves, a reference that
  appears somewhere, a digest of the wrong thing
- a substring standing in for a parse — a keyword matched anywhere in free text,
  so quoting it or writing it in a comment triggers the behaviour
- rejecting unknown fields while not requiring modelled ones, so deleting a
  field silently yields the zero value that agrees with everything
- a required argument on one function that a lower-level public function
  bypasses
- a test asserting only *that* something failed, satisfied by the wrong failure

**The remedy that works:** prove the gap by execution before fixing it. Corrupt
the artifact, mutate or delete the implementation, run the attack, and read the
passing exit. Then fix, then read the refusal. A green suite is not evidence
when the finding is that the checks cannot discriminate.

Two structural moves that ended recurring loops: replacing a guard with a
*direct* test of the property it was proxying, and making a constraint
unskippable **by construction** — an opaque verdict type only the gate can
produce — rather than by convention or visibility.

## Standing rules

- Only `claude/*` branches. `codex/*` is the parallel plane this is being raced
  against; writing to it corrupts the comparison.
- Never re-baseline evidence to make a difference disappear.
- Sanctioned regeneration flags exist (`LINKAGE_REGENERATE`, `US006_REGENERATE`,
  `US017_RETAIN`) but every use must be disclosed with both exits read.
- `#![forbid(unsafe_code)]` stays; zero new shipped non-path dependencies; the
  Rust 1.95.0 pin is untouchable and the MSRV gate fails hard without it.
- The adapter-linkage gate forbids `ws-testee` naming `ws_core::framing` or
  `Draft6455`. Hand-rolling bytes past the symbol scan counts as defeating the
  guard.
- Timestamps from `date -u` only — and check that a date copied out of git is
  UTC rather than a committer's local date.
- Never trust a piped exit code; piping launders the real status.

## Open items needing the owner

1. **Activate `Project` as a cost-allocation tag** from management account
   `113014686685`, so the budget can be scoped by tag.
2. **A bounded-resources AWS re-run** to close US-019 AC1. The last native run
   captured all five provenance artifacts truthfully, and those captures show
   the container ran **unbounded** — no memory, CPU or ulimit constraints were
   passed. AC1 requires bounded resources, so the criterion is honestly unmet.
3. **One stray untracked file** at
   `workspace/worktrees/vjwp-claude-native-run/Users/`, created by a
   mis-invoked command, awaiting a decision on how to clear it before
   `digest-manifest.json` is regenerated with a repo-relative output path.

## Two findings worth carrying forward

**The Java comparison largely exonerates the port.** Running shipped
Java-WebSocket 1.6.0 and the Rust port on the same host against the same
247-case Autobahn manifest: Java passes 234, the port passes 233. Ten of the
port's eleven non-strict cases are shipped Java's own behaviour. Only case 5.15
is a Rust-only divergence, and it is already ledger definition 34.

**But a larger divergence sits outside what Autobahn scores.** On 123 of 247
cases the port sent no close frame where Java sends one with a reason code —
invisible to the pass count because those cases do not require a clean close.
The `post-failure` branch already fixes this: its evidence shows 1007 on 76
cases and 1002 on 44, matching Java's counts exactly, with no-close-frame cases
dropping from 123 to 5. **It is fixed but unmerged**, which is the strongest
argument for landing that branch.

Genuinely still open: after echoing a close, shipped Java's *server* closes the
TCP connection and the port does not. Java does it with one role-gated check in
its I/O helper; the port's equivalent layer has no counterpart. Not yet
ledgered.
