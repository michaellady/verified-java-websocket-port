# Goal loop — every story implemented, Java equivalence at 100% confidence

Written 2026-09-02 (UTC) from tool output, not memory. This is the operating
record of the recurring goal loop: a Routine named `vjwp goal loop (every 2h)`
that fires into the originating Claude Code session every two hours. Every
firing reads this file first and appends to the log at the bottom. Verify any
fact below before relying on it; mainline moves.

## Goal

1. **Every PRD user story (27) implemented on the Claude plane**, with its
   acceptance criteria met and evidence retained, up to the owner-gated step
   where one exists.
2. **High confidence that the Rust port is functionally equivalent to shipped
   Java-WebSocket 1.6.0, quirks included.** Every observable divergence from
   Java is either fixed or ledgered with an owner decision. Disclosed
   adapter-safety divergences (for example the bounded write deadline) stay
   disclosed and do not count as failures.

## Owner decisions binding this loop (answered 2026-09-02)

- **Equivalence target:** shipped Java 1.6.0, quirks included. RFC departures
  are ledgered, never "fixed" toward the RFC.
- **Autonomy granted:** merge review-passed branches to mainline; borrow from
  Codex with borrow receipts (precedent: batches A to C); run adversarial
  self-review rounds. **Not granted:** pushing new story work straight to
  mainline. Story work goes on `claude/<topic>` branches with a PR based on
  `claude/feature/verified-java-websocket-port`.
- **Review PASS:** a branch with a recorded review PASS lands after a forward
  merge and green gates. A branch without one (`evidence-validation`,
  `us019-native-run`) gets an adversarial self-review round first; findings
  are fixed and the round is recorded in the branch, then it lands.
- **Owner gates:** never trigger AWS, benchmark, or additional Autobahn runs.
  Bring the story to the owner's step, record the exact action needed, count
  it as evidence-complete.
- **PRD:** the owner pastes it; it is committed at `docs/prd.json`. Until it
  exists the board below is PROVISIONAL and no acceptance criteria may be
  invented.
- **PR #3** (against `main`) is closed; `main` stays the shared root.
- **Cadence:** every two hours into the originating session.

## Hard rules (from `.claude/HANDOFF.md`; never relax)

- Only `claude/*` branches are written. `codex/*` is the parallel plane being
  raced against; writing to it corrupts the comparison. Reading it is fine.
- Never re-baseline evidence to make a difference disappear. A corpus shift by
  any non-runtime byte is an owner-ruled hard stop: stop, report it as a
  finding about behaviour change.
- Sanctioned regeneration flags (`LINKAGE_REGENERATE`, `US006_REGENERATE`,
  `US017_RETAIN`) may be used only with both exits read and disclosed.
- `#![forbid(unsafe_code)]` stays; zero new shipped non-path dependencies; the
  Rust 1.95.0 pin is untouchable; the MSRV gate fails hard without it.
- `ws-testee` never names `ws_core::framing` or `Draft6455`; hand-rolling bytes
  past the symbol scan is defeating the adapter-linkage guard.
- Timestamps from `date -u` only. Never trust a piped exit code.
- The protected store (`evidence/governance/decisions`) is an append-only
  mirror of HQ; corrections are re-published, never edited in place. Never
  point `VJWP_PROTECTED_STORE` at a stub.
- Never skip, disable, or quarantine a test to get green.

## Iteration protocol (every firing)

0. `git fetch origin '+refs/heads/*:refs/remotes/origin/*'`. Check out
   mainline; note its head in the log.
1. Read this file: board, queue, log. Read `docs/prd.json` if present.
2. Pick the top item of the priority queue whose preconditions hold.
3. Do ONE bounded unit of work (about 90 minutes at most): a merge, a review
   round, a story slice, a divergence fix with a ledger record, or an
   evidence run. Do not start a second unit in the same firing.
4. Validate, reading real exit codes (no pipes):

   ```
   export VJWP_PROTECTED_STORE=$PWD/evidence/governance/decisions
   make -C rust gates          # expect: ac1-gates verdict=PASS gates_passed=8/8, exit 0
   go build ./... && go test -count=1 ./...
   ```

   When behaviour-bearing code changed (`rust/ws-core`, `rust/ws-driver`,
   `rust/ws-testee/src`, `rust/ws-oracle-harness`, `java-oracle`), also run the
   public corpus differential and the live handshake exam, reconstructed from
   the `pipeline` fields in `rust/ws-oracle-harness/baseline/*.json`:

   ```
   go run ./cmd/corporactl oracle-requests --root . --protected-root <protected> --tier public --out requests.jsonl
   rust/target/release/ws-oracle-harness < requests.jsonl > transcript.jsonl
   go run ./cmd/corporactl evaluate --root . --protected-root <protected> --tier public --transcript transcript.jsonl
   ```

   Expect 74/74 with zero non-runtime diffs and the exam at 49/49. Iteration 1
   resolves `<protected>` from `cmd/corporactl` and confirms both pipelines run
   in this environment before any behaviour-bearing change is attempted.
5. Self-review round, adversarial: vacuous tests (cannot fail), over-claimed
   evidence, evidence not bound to the tree it describes, forbidden symbols,
   piped exits. Record it as `drafts/self-review/<branch>-round-<N>.md` with
   the head sha, each finding, and each fix.
6. Commit with `date -u` timestamps; push. Story work: PR based on mainline.
   Review-passed branches: forward-merge mainline into the branch, gates green
   on the branch, then a `merge: <branch> — <summary>` commit on mainline.
7. Update the board, append one UTC log line. Report in the session only when
   something changed or an owner action is needed; otherwise stay silent.

If GitHub tooling is unavailable in a firing, push the branch and record the
PR-to-open in the log; never block the work on it.

## Priority queue (ordered; each firing takes the first item whose preconditions hold)

- **P0 Environment proof (iteration 1).** Run the public corpus differential
  and the live handshake exam unchanged in this environment and record the
  exact commands and results. No `.quarantine` directory exists here; find how
  the pinned Java-WebSocket 1.6.0 inputs are materialised (the environment doc
  allowlists `repo1.maven.org` for it) and record it. Precondition for every
  behaviour-bearing change.
- **P1 Land the merge queue**, strictly one branch per firing, in the
  handoff's order: `claude/us008-restart` (PASS r5) → `claude/ledger-integrity`
  (PASS r4) → `claude/us017-ac2` (PASS r4) → `claude/evidence-validation`
  (self-review to PASS first) → `claude/post-failure` (PASS r3; lands LAST, it
  collides with `us017-ac2` on `rust/ws-driver`, with `evidence-validation` on
  `assurance/concurrency/results.json`, with `us019` on `rust/ws-testee`) →
  `claude/us019-native-run` (BLOCK, partly fixed; self-review to PASS first).
  Also decide `claude/us019-autobahn` (1 commit ahead) and
  `claude/vacuity-sweep` (9 ahead): merged as part of another branch, or
  queued.
- **P2 Java-equivalence gaps.** (a) Close-frame parity across the 247
  Autobahn cases is fixed on `post-failure` and lands with P1. (b) After
  echoing a close, shipped Java's *server* closes the TCP connection and the
  port does not: implement in the adapter layer with Java's role-gated check as
  the citation, add a ledger record, verify against the Java baseline.
  (c) Autobahn 5.15 is ledger definition 34 (disclosed). (d) Sweep for
  divergences that neither Autobahn scoring nor the public corpus sees:
  compare Java and port per case on close code, close reason, and who closes
  TCP, and ledger or fix each difference.
- **P3 Remaining stories** (provisional until the PRD lands). US-010 to
  US-017: closure receipts where borrowed code has none. US-019: to the owner
  gate (bounded-resources AWS re-run is the owner's). US-020 to US-027: study
  Codex's contracts and claims registers, borrow with receipts where our
  contracts fit, implement the rest.
- **P4 Confidence.** Expand differential coverage; mutation sensitivity on the
  Rust side; map retained Kani obligations to the Java behaviours they cover.
  Hidden and sealed corpora are protected: owner gate.

## Story board (PROVISIONAL: titles inferred from file names on both planes; replace from `docs/prd.json`)

Claude-plane status: "passes" means `passes: true` per the handoff's reading
of the PRD on 2026-08-29; everything else is read from branches and files on
2026-09-02. Codex-plane status is what Codex's own files claim, not a verified
result; its README states its maximum result is
`PASS_OWNER_RELAXED_MECHANICS` under `OWNER_ATTESTED_NOT_INDEPENDENT`.

| Story | Provisional title | Claude plane | Codex plane | Next on Claude plane |
| --- | --- | --- | --- | --- |
| US-001 | Immutable input intake | passes | complete (README) | none |
| US-002 | Autobahn laboratory qualification | passes | qualified; attempt budget consumed | none |
| US-003 | Intake freeze, exact pins | passes | referenced | none |
| US-004 | Evidence lifecycle | passes | 6 files | none |
| US-005 | Corpora, handshake verdicts, sbx candidates | passes | 2 files | none |
| US-006 | Formal concurrency model (TLA+/TLC) | passes | TLA+ model + Kani backend qualification | none |
| US-007 | Sandbox release firewall, resource supervisor | passes | 1 file | none |
| US-008 | Benchmark preregistration, confirmation host | not passing; `us008-restart` PASS r5 unmerged | 1 file | P1 merge |
| US-009 | Rust workspace core, AC1 gates, oracle harness | passes | 1 file | none |
| US-010 | Client handshake | exam 49/49 (drafts); borrowed batch B | contract + evidence DAG | closure receipt |
| US-011 | Server handshake | exam 49/49 (drafts); borrowed batch B | contract + frozen cases | closure receipt |
| US-012 | Frame codec, core data path; AC5 actual-code Kani | borrowed batch A; Kani qualified (merged) | contract + codec tests | closure receipt |
| US-013 | Messages, UTF-8 | borrowed batch A | contract | closure receipt |
| US-014 | Fragmentation | borrowed batch A | contract | closure receipt |
| US-015 | Control frames, ping/pong | e4 auto-pong merged | contract | closure receipt |
| US-016 | Close lifecycle | e4/e5b merged; owner decisions retained | contract | closure receipt |
| US-017 | Single-owner driver, schedule exploration | closure receipt in drafts; `us017-ac2` PASS r4 unmerged | contract | P1 merge |
| US-018 | Blocking adapters (loopback testee) | passes; fixture made kernel-independent 2026-09-02 | contract | receipt correction is owner's |
| US-019 | Autobahn client agent, native run | `us019-autobahn` 1 ahead; `us019-native-run` BLOCK; AC1 owner gate (AWS) | readiness only, no current-subject run | P1 self-review, then owner gate |
| US-020 | Differential, current-head qualification | not started | 4 files | P3 |
| US-021 | Verification campaign: property, fuzz, runtime | not started | 5 files | P3 |
| US-022 | Mutation denominators, protected | not started | 6 files | P3 |
| US-023 | Parity freeze, claims register, formal obligations | not started | 9 files; every gate BLOCKED in its own register | P3 |
| US-024 | Deterministic refinement | not started | "complete" for owner-relaxed mechanics; 8 blockers | P3 |
| US-025 | Resource envelope | not started | 1 file | P3, owner gate on hosts |
| US-026 | Cutover rehearsal | not started | contracts only | P3 |
| US-027 | Independent acceptance, projection, receipts | not started | receipts: codex/reality owner-attested, human NOT_EXECUTED | P3, owner gate |

## Plane comparison (read 2026-09-02)

| Measure | Claude plane | Codex plane |
| --- | --- | --- |
| Tip | `51962e5`, 2026-09-02 | `4110462`, 2026-08-30 |
| Commits since `main` / since the fork at `66f33d4` | 154 / 129 | 333 / 308 |
| Rust source | 24,515 lines, 65 files | 21,823 lines, 42 files |
| Stories with `passes: true` | 9 (per handoff) | not stated in-repo |
| Story ids with files | US-001 to US-019 | US-001 to US-027 |
| Public corpus differential | 74/74, zero non-runtime diffs | 74/74 normalized scenarios equal |
| Live handshake exam | 49/49 | client/server handshake evidence |
| Autobahn, current Rust subject | 247 cases run; Java 234 pass, port 233 | not executed; authority consumed |
| Formal | TLA+ (US-006); Kani qualified as source-level verifier over shipped `ws_core` | TLA+; Kani proofs retained for frames, fragments, controls, close, faults; coverage report all BLOCKED for the US-023 target |
| Independent review | external review rounds recorded per branch | codex/reality receipts owner-attested; human NOT_EXECUTED |
| Cloud environment | setup script + gates green (this session) | `cmd/cloudsetup` with pinned Kani 0.67 and CBMC 6.11 |

Reading: Codex is **broader** (scaffolding, contracts and receipts through
cutover, more retained formal artifacts, a fuller cloud toolchain) but its own
claims register marks essentially every gate BLOCKED or owner-attested. The
Claude plane is **deeper on executed evidence** (a current-subject Autobahn run
compared against Java on the same host, the live exam, closure receipts with
review rounds) but **narrower** (nothing past US-019) and has **six
review-passed branches unmerged**. On Java equivalence specifically the Claude
plane holds the strongest executed evidence and two known gaps: close-frame
parity (fixed on `post-failure`, unmerged) and the server-side TCP close after
a close echo (open, unledgered).

## Iteration log (UTC; one line per firing)

- 2026-09-02T05:24:42Z iteration 0 (interactive): fetched all heads; compared planes; built the provisional board; created Routine trig_019dqmkqgWGFkXwSSJrBYXqJ (cron 22 */2 * * *, next 06:22Z); closed PR #3; PRD still to be pasted by the owner. Mainline head 51962e5.
