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

   `go test` has three packages that fail on Linux for environment reasons
   (`internal/lab` needs Darwin `sandbox-exec`; `internal/formalplan` and
   `internal/portplan` need the quarantined Java source, see the owner action
   under P0). Read results per package: every other package must pass, and
   those three must fail with exactly those typed findings and nothing else.

   When behaviour-bearing code changed (`rust/ws-core`, `rust/ws-driver`,
   `rust/ws-testee/src`, `rust/ws-oracle-harness`, `java-oracle`), also run the
   public corpus differential and the handshake exam through both the port and
   the live Java oracle, using the recipe verified in iteration 1 and recorded
   in `CLOUD-ENVIRONMENT.md` under "Running the corpus differential and the
   handshake exam here": a throwaway 32-byte hex secret in a scratch protected
   root (public and handshake tiers are secret-independent, proven), the
   release harness, and the Java oracle run with `-Dstdout.encoding=UTF-8`.
   Expect the port at 74/74 and 49/49 (runtime field neutralised), live Java at
   74/74 and 49/49 with 16 documented divergences, and no non-runtime field
   difference between the two transcripts beyond the free-text error detail.
   Never run the hidden or sealed tiers against a throwaway secret.
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

- **P0 Environment proof: DONE in iteration 1 (2026-09-02).** Public
  differential port 74/74, live Java 74/74; handshake exam port 49/49 and live
  Java 49/49 with the 16 recorded divergences; request sets secret-independent
  and the handshake digest equal to the batch-B record; java-oracle self-test
  18 pass. Recipe and results are in `CLOUD-ENVIRONMENT.md`. **Residual owner
  action:** the quarantined Java source archive cannot be fetched here (the
  session proxy returns 403 for repositories not attached to the session, and
  attaching `TooTallNate/Java-WebSocket` was denied by the auto-mode
  classifier). Attach that repository to the environment's GitHub scope, or
  place the pinned archive at `.quarantine/java-websocket-source-archive.tar.gz`
  (sha256 `f44e7647b4aee40819b51947cf0bb5f35a48293a202b77704c3c79e98ed13cb4`).
  Until then `internal/formalplan` and `internal/portplan` tests cannot run
  here, and any work that needs Java source citations verified stops at this
  gate.
- **P1 Land the merge queue**, strictly one branch per firing, in the
  handoff's order: `claude/us008-restart` (PASS r5) LANDED e7a66a0 in
  iteration 2 → **next:** `claude/ledger-integrity`
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
| US-008 | Benchmark preregistration, confirmation host | `us008-restart` (PASS r5) landed on mainline 2026-09-02 as e7a66a0; story completion judged against the PRD once committed; confirmation-host run is an owner gate | 1 file | owner: PRD flag, benchmark host run |
| US-009 | Rust workspace core, AC1 gates, oracle harness | passes | 1 file | none |
| US-010 | Client handshake | exam 49/49 (drafts); borrowed batch B; reproduced here 2026-09-02, port and live Java both 49/49 | contract + evidence DAG | closure receipt |
| US-011 | Server handshake | exam 49/49 (drafts); borrowed batch B; reproduced here 2026-09-02, port and live Java both 49/49 | contract + frozen cases | closure receipt |
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
- 2026-09-02T06:35:20Z iteration 1 (routine): P0 environment proof. Public differential: port 74/74 (harness sha256 414d7e5b…adb9), live Java 74/74 with -Dstdout.encoding=UTF-8 (65/74 without, encoding artefact). Handshake exam: port 49/49 with the runtime field neutralised, live Java 49/49, 16 documented divergences; no non-runtime field differs between the two transcripts; public transcripts differ only in free-text error detail. Requests from two throwaway secrets byte-identical; handshake request digest e00d968f… equals the batch-B record. java-oracle self-test 18 PASS. go build ok; go test fails only in internal/lab (Darwin-only canary) and internal/formalplan + internal/portplan (quarantined Java source: archive 403 via session proxy; add_repo denied by the auto-mode classifier) — OWNER ACTION recorded under P0. No code changed. Next: P1 merge claude/us008-restart. Mainline head dbac020.
- 2026-09-02T08:30:28Z iteration 2 (routine): P1 landed claude/us008-restart. Forward merge 9096f07 (clean; tree 8d4801a equals the merge-tree dry run), mainline merge e7a66a0 with identical tree. Gates 8/8 exit 0; go build 0; go test 28 ok plus the three known environment packages only (same typed findings as iteration 1). rust/ unchanged, so the differential and exam were not re-run. Record: drafts/self-review/us008-restart-landing.md. Both branches pushed. PRD still absent. Next: P1 claude/ledger-integrity. Mainline head e7a66a0.
