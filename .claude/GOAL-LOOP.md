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

## Program context (from `docs/prd-pack/01-structure-and-index.md`)

This repository is Laboratory 1 of the four-laboratory program
`verified-java-to-rust-port`. The 27 stories below are the child lab's. The
canonical child (the Codex plane, `feature/verified-java-websocket-port`)
records all 27 done under owner-attested scope, `STORY_EXECUTION_COMPLETE`;
this Claude-runtime variant recorded 9 done as of 2026-08-25. The master gate
that everything downstream waits on is master US-008, independent acceptance
of this laboratory, deliberately still open: 0 of 26 claims strongly accepted,
24 formal obligations blocked, no independent custodian, no two-host resource
envelope, cutover blocked. Independence cannot be self-granted, so the loop's
job is to make every claim strong enough to survive that acceptance and to
record exactly which owner or independent step remains.

## External inputs the loop may draw on

- **port-* skill family** (relayed from the owner 2026-09-02): draft PR
  michaellady/mike-skills#7, branch `claude/port-jvm-to-rust-skills`, twelve
  skills orchestrated by `port-jvm-to-rust`, with `REFERENCE.md` carrying a
  ten-link confidence chain, a fixed claim vocabulary ("formally verified" only
  per named harness with bound; "calibrated differential assurance";
  "behavior-preserving on the reachable surface"), four questions before quoting
  any count, "checks that cannot fail" defect classes with canary forms per
  verifier, a JVM-to-Rust semantic impedance checklist, a nondeterminism
  census, and artifact schemas. Much of it was distilled from this repository.
  The owner's instruction: use or modify it as we see fit; no action required
  beyond awareness. Two gaps it names that this project does not yet have, both
  candidates for P4: a per-method oracle via bytecode instrumentation (the
  Syzygy decomposition) and a branch-coverage denominator on the Java (the
  alphabet audit). Feedback path: `port-learn` findings in its fixed shape,
  filed as a PR against the family, especially rediscoveries. The unified rig
  is not in the PR; binaries stay split between this repo's `cmd/` and
  `twitter-port-matrix/tools/cmd`.

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
- **PRD:** delivered from HQ as a six-part pack through a bridge session,
  stored verbatim under `docs/prd-pack/` as parts arrive (part 1 received
  2026-09-02). Board titles and status flags come from it. Acceptance criteria
  arrive in parts 2 to 6 and may not be invented before they land.
  `docs/prd.json` is added only if the owner supplies the JSON bytes; the pack
  is a rendering, so `prd.json` digests cannot be recomputed from it.
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
   mainline; note its head in the log. If `.quarantine/` lacks the four pinned
   Java inputs, copy them from `~/.cache/verified-java-websocket-port/quarantine/`
   or materialise them per `CLOUD-ENVIRONMENT.md`, "Pinned Java inputs".
1. Read this file: board, queue, log. Read `docs/prd.json` if present.
2. Pick the top item of the priority queue whose preconditions hold.
3. Do ONE bounded unit of work (about 90 minutes at most): a merge, a review
   round, a story slice, a divergence fix with a ledger record, or an
   evidence run. Do not start a second unit in the same firing.
4. Validate, reading real exit codes (no pipes):

   ```
   export VJWP_PROTECTED_STORE=$PWD/evidence/governance/decisions   # needed by ledger-gates AND go test
   export PATH=$PWD/.quarantine/jdk-17.0.19+10/bin:$PATH             # internal/portplan refuses any other javac
   make -C rust gates          # expect: ac1-gates 8/8, then ledger-gates ok, exit 0
   go build ./... && go test -count=1 ./...
   ```

   `go test` has two packages that fail on Linux for environment reasons
   (`internal/lab` needs Darwin `sandbox-exec`; `internal/portplan`'s
   derive-reproduction test is vendor-bound, see the owner decision under P0).
   Read results per package: every other package must pass, and those two must
   fail with exactly those typed findings and nothing else.

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
5. Self-review round, adversarial, against the port-* family's checklists
   (mike-skills#7, `port-jvm-to-rust/REFERENCE.md` sections 2 to 4):
   - **Polarity, checks that cannot fail:** an expectation computed by the
     implementation (or the host) under test; existence standing in for
     identity (a path that resolves, a digest of the wrong thing); a substring
     standing in for a parse; rejecting unknown fields without requiring the
     modelled ones; a required argument a lower-level function bypasses; a test
     asserting only *that* something failed; a harness whose `assume` empties
     the input space; a rung pointed at the unmutated original. Remedy: prove
     the gap by execution first (corrupt, plant, run, read the passing exit),
     fix, then read the refusal.
   - **Counts, four questions before quoting any:** did the verifier parse the
     file; can it reach the obligation (negation refuted, planted defect
     fails); can the program reach the branch on a real path; is the contract
     on the shipped symbol rather than a hand-written twin.
   - **Claims, fixed vocabulary:** "formally verified" only for named
     Kani-proved properties with bounds and the refinement check; "calibrated
     differential assurance" always with the kill table and coverage
     denominator; "behavior-preserving on the reachable surface" with the
     measured reachable number; every concurrency result "bounded", never
     "proved"; never "1:1", "absolutely correct", "formally verified port", or
     "equivalent" without qualification.
   - **Canaries:** injection and negation for deductive checks;
     planted-defect controls, one per spec clause, for Kani; clean-substitution
     for every gate runner.
   Also: forbidden symbols, piped exits, evidence not bound to the tree it
   describes. Record the round as `drafts/self-review/<branch>-round-<N>.md`
   with the head sha, each finding, and each fix. File anything that surprised,
   cost, or reversed a belief as a port-learn finding under
   `drafts/self-review/findings/F<nnn>-<slug>.md` in the family's fixed shape,
   binned REDISCOVERY | NEW RULE | TOOL GAP | TARGET-LOCAL; the first three are
   owed back to the family as a reviewed PR citing the finding.
6. Commit with `date -u` timestamps; push. Story work: PR based on mainline.
   Review-passed branches: forward-merge mainline into the branch, gates green
   on the branch, then a `merge: <branch> — <summary>` commit on mainline.
7. Update the board, append one UTC log line. Report in the session only when
   something changed or an owner action is needed; otherwise stay silent.

If GitHub tooling is unavailable in a firing, push the branch and record the
PR-to-open in the log; never block the work on it.

## Priority queue (ordered; each firing takes the first item whose preconditions hold)

- **P0 Environment proof: DONE (iterations 1 to 3, 2026-09-02).** Public
  differential port 74/74, live Java 74/74; handshake exam port 49/49 and live
  Java 49/49 with the 16 recorded divergences; request sets secret-independent
  and the handshake digest equal to the batch-B record; java-oracle self-test
  18 pass. The quarantined source archive is reproduced byte-exactly from an
  anonymous clone and the pinned Temurin JDK 17.0.19+10 is digest-verified and
  staged; with both, `internal/formalplan` passes and `internal/portplan`
  reaches its last check. Recipe and results in `CLOUD-ENVIRONMENT.md`.
  **Owner decision outstanding:** `TestDeriveReproducesCommittedEvidence`
  byte-compares the regenerated semantic-id oracle report with the committed
  one, which embeds `"jdk_vendor": "Homebrew"`; the Linux regeneration differs
  in that line alone (969 declarations identical). Decide whether the check
  becomes vendor-agnostic or the vendor is pinned as a host requirement. Until
  then that one test fails on Linux by construction.
- **P1 Land the merge queue**, strictly one branch per firing, in the
  handoff's order: `claude/us008-restart` (PASS r5) LANDED e7a66a0 in
  iteration 2 → `claude/ledger-integrity` (PASS r4) LANDED 2fbad99 on
  2026-09-02 → `claude/us017-ac2` (PASS r4) LANDED 7262a29 on 2026-09-02 (US-006
  fixture refrozen, plan digest re-bound, evidence-dag refreshed, all under
  sanctioned flags with both exits read) → `claude/evidence-validation`
  (self-review round 5 by the loop, PASS) LANDED 35edf8c on 2026-09-02 as a
  union with `us017-ac2` (branch commit ccd0cc0; records
  `drafts/self-review/evidence-validation-round-5.md` and
  `evidence-validation-landing.md`) → **next:** `claude/us019-native-run`
  (BLOCK, partly fixed; FORWARD-MERGED with mainline 6150e92 as b26be41 on
  2026-09-02, gates 8/8 + ledger ok, go 31 ok, differential and exam unchanged;
  draft PR opened against mainline; self-review round to PASS is the next
  unit, and its list is fixed: replay review 01a04961's eight findings as the
  owner-decision record summarises them; implement the amended AC3 bar
  (per-case behaviour-class agreement with the pinned Java baseline, owner
  decision 2026-08-28T03:37Z) — the verdict still reads the literal clause and
  is NEGATIVE; finding 7, case-manifest independence; AC1's bounded-resources
  clause is recorded unmet — owner item; the no-echo and opcode-swap mutant
  runs are incomplete (66/247, 181/247 never scored), discrimination
  OUTSTANDING, and completing them needs Autobahn re-runs — owner gate, never
  triggered by the loop) → `claude/post-failure`
  (PASS r3; lands LAST, it collides with `us017-ac2` on `rust/ws-driver`, with
  `evidence-validation` on `assurance/concurrency/results.json`, with `us019`
  on `rust/ws-testee`; its forward merge must keep both run citations in
  `results.json` and re-run both harness citation checks).
  Also decide `claude/us019-autobahn` (1 commit ahead) and
  `claude/vacuity-sweep` (9 ahead): merged as part of another branch, or
  queued.
- **P1a Reconciliation plan for `claude/evidence-validation`** — EXECUTED
  2026-09-02 as written (union kept, no refusal dropped, round 5 recorded,
  landed 35edf8c); retained here as the record of what was planned. (read
  2026-09-02 after `us017-ac2` landed; execute as one unit, self-review
  round included, since the branch has no recorded PASS: round 5 was in flight
  on 2026-08-29 and its last commit is r4 at 9aa73ab). Facts: the dry run
  conflicts on `assurance/concurrency/results.json`,
  `evidence/linkage/evidence-dag.json` and
  `rust/ws-driver/tests/schedule_exploration.rs`, and beyond the textual
  conflicts both branches add `func ValidateConcurrencyResults` to package
  `internal/formalplan` under different file names
  (`concurrencyresults.go`, 3202 lines, signature taking
  `ConcurrencyResultsInputs`; `concurrency_results.go`, 178 lines, taking a
  root path), so the merged package will not compile until they are unified.
  They bind different things and neither subsumes the other: `us017-ac2` binds
  target blobs, the plan digest, minimized reproductions and retention seeds
  with a document-enumerated polarity test; `evidence-validation` binds the
  document to the run it cites (an `executed_run` block with the exploration's
  `stdout_line`, counters re-derived in Go, plan-conformance and fairness
  against the plan, quoted-counter, narrative and claim-ceiling checks, and a
  Rust half in the harness that refuses a document not citing this run).
  Plan: keep the union. (1) Forward-merge; resolve the harness by keeping both
  sides' tests and constants. (2) Unify the validators into one
  `ValidateConcurrencyResults` that runs both binding sets, keeping every
  refusal both review histories proved; both test files stay and must pass.
  (3) Make `results.json` satisfy both: add the `executed_run` block by
  actually running the exploration on the merged tree and capturing its
  stdout line, keep every binding `us017-ac2` recorded, and disclose the
  merge in `revision_note`. (4) Refreeze the evidence-dag under
  `LINKAGE_REGENERATE=1` and the US-006 fixture under `US006_REGENERATE=1` if
  touched, both exits read each time. (5) Self-review round: replay every
  attack named in the five `evidence-validation` commit messages and the four
  `us017-ac2` ones against the unified validator; each must be refused; record
  the round in `drafts/self-review/evidence-validation-round-5.md`. (6) Full
  validation (gates with ledger, go suite per package, differential and exam
  since the harness changed), then land with a `merge:` commit and a landing
  record. If unifying would drop any refusal either history proved, stop and
  put the choice to the owner rather than pick a side.
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
  Hidden and sealed corpora are protected: owner gate. **The bar is master
  US-008** (PRD pack part 4, `docs/prd-pack/04-…`): independently recomputed
  Java-versus-Rust formal coverage over the language-neutral 24-obligation
  denominator with zero blocking gaps, 100% eligible mutation score with zero
  MISSED mutants, 247/247 client and 247/247 server Autobahn cases from the
  retained receipt without a rerun, two fresh adversarial reviews, and a
  production-shaped shadow/canary rehearsal. Its final child evaluator reads
  0/26 child entries strongly accepted and the Codex plane's owner-executed
  Kani lane at Rust proof 19/24, mutation sensitivity 19/24, Java formal
  binding 0/24, refinement 0/24, aggregate 0/24 (receipt 30ee613); the open
  blockers it names are Java/refinement coverage, independence, two-host
  performance, production-shaped cutover, publication, signing and
  Java-removal authority. Independence, performance hosts, cutover,
  publication and signing are owner gates; the Java/refinement side of the
  24-obligation denominator and the five remaining Rust/mutation obligations
  are where this plane can move the number.

## Story board (titles from the child PRD index in `docs/prd-pack/01-structure-and-index.md`; acceptance criteria pending the child-story parts of the seven-part pack)

Claude-plane status: "passes" means `passes: true` per the handoff's reading
of the PRD on 2026-08-29; everything else is read from branches and files on
2026-09-02. Codex-plane status is what the canonical child PRD flags and Codex's own
files claim, not a verified result; the PRD marks all 27 done under
owner-attested scope and Codex's README states its maximum result is
`PASS_OWNER_RELAXED_MECHANICS` under `OWNER_ATTESTED_NOT_INDEPENDENT`.

| Story | Title (child PRD) | Claude plane | Codex plane (canonical child) | Next on Claude plane |
| --- | --- | --- | --- | --- |
| US-001 | Promote every immutable laboratory input | passes | PRD done (owner-attested); complete (README) | none |
| US-002 | Establish the fresh Java authority and Autobahn baseline | passes | PRD done (owner-attested); qualified; attempt budget consumed | none |
| US-003 | Freeze intake, compatibility, semantic IDs, and port seams | passes; semantic-id oracle reproduced on Linux with pinned JDK 17.0.19 on 2026-09-02, 969 declarations identical, only `jdk_vendor` differs | PRD done (owner-attested); referenced | owner: vendor-agnostic reproduction check |
| US-004 | Instantiate the inherited evidence lifecycle | passes | PRD done (owner-attested); 6 files | none |
| US-005 | Calibrate public, hidden, sealed, and handshake corpora | passes | PRD done (owner-attested); 2 files | none |
| US-006 | Qualify implementation-linked proof and concurrency seams | passes | PRD done (owner-attested); TLA+ model + Kani backend qualification | none |
| US-007 | Prove sandbox and release-firewall isolation | passes | PRD done (owner-attested); 1 file | none |
| US-008 | Pre-register controlled Java and Rust resource benchmarks | `us008-restart` (PASS r5) landed on mainline 2026-09-02 as e7a66a0; story completion judged against the PRD once committed; confirmation-host run is an owner gate | PRD done (owner-attested); 1 file | owner: PRD flag, benchmark host run |
| US-009 | Establish the safe Rust ConnectionCore contract | passes | PRD done (owner-attested); 1 file | none |
| US-010 | Implement the client opening-handshake slice | exam 49/49 (drafts); borrowed batch B; reproduced here 2026-09-02, port and live Java both 49/49 | PRD done (owner-attested); contract + evidence DAG | closure receipt |
| US-011 | Implement the server opening-handshake slice | exam 49/49 (drafts); borrowed batch B; reproduced here 2026-09-02, port and live Java both 49/49 | PRD done (owner-attested); contract + frozen cases | closure receipt |
| US-012 | Implement canonical framing, masking, and allocation limits | borrowed batch A; Kani qualified (merged) | PRD done (owner-attested); contract + codec tests | closure receipt |
| US-013 | Deliver strict text and binary messages | borrowed batch A | PRD done (owner-attested); contract | closure receipt |
| US-014 | Reassemble fragmented messages with bounded state | borrowed batch A | PRD done (owner-attested); contract | closure receipt |
| US-015 | Implement ping and pong control behavior | e4 auto-pong merged | PRD done (owner-attested); contract | closure receipt |
| US-016 | Complete close, EOF, and terminal-state behavior | e4/e5b merged; owner decisions retained | PRD done (owner-attested); contract | closure receipt |
| US-017 | Drive bounded concurrent commands through one owner | closure receipt in drafts; `us017-ac2` (PASS r4) landed 2026-09-02 as 7262a29: typed receiver-drop and dropped-write dispositions, concurrency results bound to the tree by a checked gate; `evidence-validation` (r5) landed 2026-09-02 as 35edf8c: `results.json` cites both the exploration line and the five fatal-termination sweep lines, both compared by the harness and re-derived by `internal/formalplan`; 71 inert leaves of 327 remain, listed, record stays PARTIAL | PRD done (owner-attested); contract | judge against PRD criteria when they land |
| US-018 | Add thin blocking TCP client and server adapters | passes; fixture made kernel-independent 2026-09-02 | PRD done (owner-attested); contract | receipt correction is owner's |
| US-019 | Pass both pinned Autobahn conformance modes | `us019-autobahn` 1 ahead; `us019-native-run` BLOCK; AC1 owner gate (AWS) | PRD done (owner-attested); readiness only, no current-subject run | P1 self-review, then owner gate |
| US-020 | Close Java and Rust differential divergences | ledger-integrity landed 2026-09-02: delta ledger 48 records, 3 supersessions, unledgered_disagreements recomputed = 0 behind `ledger-gates`; public differential 74/74 for port and live Java; not yet judged against the PRD criteria | PRD done (owner-attested); 4 files | P2 gaps, then criteria |
| US-021 | Close property, fuzz, and runtime evidence | not started | PRD done (owner-attested); 5 files | P3 |
| US-022 | Pass normalized mutation and protected evaluation | not started | PRD done (owner-attested); 6 files | P3 |
| US-023 | Freeze the complete parity candidate | not started | PRD done (owner-attested); 9 files; every gate BLOCKED in its own register | P3 |
| US-024 | Refine idiomatic Rust without changing parity | not started | PRD done (owner-attested); "complete" for owner-relaxed mechanics; 8 blockers | P3 |
| US-025 | Decide every preregistered resource envelope | not started | PRD done (owner-attested); 1 file | P3, owner gate on hosts |
| US-026 | Rehearse shadow, canary, soak, and Java rollback | not started | PRD done (owner-attested); contracts only | P3 |
| US-027 | Independently accept and project the complete child snapshot | not started | PRD done (owner-attested); receipts: codex/reality owner-attested, human NOT_EXECUTED | P3, owner gate |

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
- 2026-09-02T09:19:02Z interactive: PRD pack part 1 of 6 received from HQ via bridge session; stored verbatim at docs/prd-pack/01-structure-and-index.md. Board titles replaced with the canonical child-PRD titles; program context added (master US-008 independent acceptance is the open gate). Acceptance criteria await parts 2 to 6. Mainline head before this commit 70a10bc.
- 2026-09-02T09:42:25Z interactive (owner approval to proceed): P1 landed claude/ledger-integrity — forward merge f052795, mainline merge 2fbad99, tree 122bd90 equal to the dry run; gates 8/8 + ledger-gates ok, exit 0; differential and exam unchanged to the digest through the port and live Java; go suite 29 ok with the store exported and JDK 17.0.19 on PATH, failing only lab (Darwin canary) and portplan derive-reproduction (jdk_vendor line). Environment: pinned source archive reproduced byte-exactly (git archive | gzip -n -6), Temurin JDK 17.0.19+10 digest-verified and staged, setup script now stages all four pinned Java inputs. PRD pack part 1 committed earlier; this cloud session cannot message the bridge session back. Record: drafts/self-review/ledger-integrity-landing.md. Next: P1 claude/us017-ac2. Mainline head 2fbad99.
- 2026-09-02T09:56:58Z interactive: P1 landed claude/us017-ac2 — forward merge 0c0c4b0 with the US-006 fixture refrozen (US006_REGENERATE=1 exit 0, verify exit 0), re-binding commit 20e216f (plan digest re-bound after ledger-integrity moved plan.json's ledger metadata; evidence-dag refreshed, LINKAGE_REGENERATE=1 exit 1 by design then verify exit 0), mainline merge 7262a29, tree 6d70078. Gates 8/8 + ledger ok on the Rust tree that landed; ac1 + ledger re-run after the evidence edits, exit 0; harness rebuilt e2898c13…; differential and exam unchanged to the digest, port and live Java 74/74 and 49/49; go 29 ok, only lab (Darwin) and portplan derive (jdk_vendor). Record: drafts/self-review/us017-ac2-landing.md. Next: P1 claude/evidence-validation (needs a self-review round to PASS). Mainline head 7262a29.
- 2026-09-02T09:58:54Z interactive: inspected claude/evidence-validation — conflicts on results.json, evidence-dag.json and schedule_exploration.rs, plus a duplicate ValidateConcurrencyResults in internal/formalplan against the landed us017-ac2 validator; wrote the P1a reconciliation plan (keep the union, self-review round stands in for its round 5). Not started. Mainline head 5b4e85d.
- 2026-09-02T09:59:58Z interactive: recorded the owner's port-* skill family (mike-skills#7) as an external input; two named gaps (per-method bytecode oracle, Java branch-coverage denominator) queued as P4 candidates; self-review rounds to borrow its 'checks that cannot fail' classes once REFERENCE.md is read. Mainline head 996abe7.
- 2026-09-02T10:01:52Z interactive: read mike-skills#7 REFERENCE.md (anonymous clone); folded its polarity forms, count questions, claim vocabulary and canary table into protocol step 5; filed three port-learn findings from today under drafts/self-review/findings (F001 vendor-bound reproduction check, F002 host-sized backpressure fixture, F003 toolchain home). Mainline head 7ec2ea3.
- 2026-09-02T10:19:07Z interactive: PRD pack part 2 of 6 received (master foundation-wave stories US-001..006, US-024, all passes:true); stored verbatim at docs/prd-pack/02-master-stories-foundation.md. No child-board change. Mainline head 4eea327.
- 2026-09-02T11:29:45Z interactive: P1 landed claude/evidence-validation — forward merge of mainline 0bb5196 resolved as a union with us017-ac2 (branch commit ccd0cc0): both validators kept (ValidateConcurrencyResultsBindings / ValidateConcurrencyResults / ValidateConcurrencyResultsAll), harness merged (13 checked invariants, found_index in every seed; US017_RETAIN=1 once for silent-write-drop.seed, exit 0), results.json now cites the exploration line AND the five US017_FATAL_SWEEP lines (RED first: sweep exit 101 with no lines recorded, then exit 0), max_actions/added_by/ten-defect roll with exact regression sets/seed identity/RED-reading/seed-naming/prose-number bindings added (45 permanent mutation cases), inert leaves 91→71 of 327, omission holes 29→0 of 394, three stale r1–r4 probes retargeted to read the document, seven document sentences reconciled with disclosures (revision_note a–g). Gates 8/8 + ledger ok, 75 test blocks; go 29 ok, only lab (Darwin) and portplan derive (vendor); LINKAGE_REGENERATE=1 exit 1 by design then verify 0 (one digest). Differential/exam not re-run: no behaviour-bearing byte differs from mainline. Mainline merge 35edf8c, tree d99939e. Records: drafts/self-review/evidence-validation-round-5.md, evidence-validation-landing.md. No PR: the topic branch is already contained in mainline and PR #3 against main stays closed by owner decision. Next: P1 claude/us019-native-run (self-review to PASS first). Mainline head 35edf8c before this record commit.
- 2026-09-02T12:12:03Z interactive: PRD pack part 3 of 6 received (master stories US-020..023 and US-007, all passes:true); stored verbatim at docs/prd-pack/03-master-stories-intake-lsp-protocol-labzero.md. Relevant to this child: US-007 confirms the 27-story child plan, the excluded surface (TLS/WSS, proxies, reconnect, Android, RFC 7692, Java API parity) and the two fail-closed gates already recorded (target-repository authorization, independent Linux benchmark host for child US-008); the 2026-08-28 denominator correction (11/24 Rust production-symbol proof coverage, 9/24 obligation-specific mutation sensitivity, 0/24 Java formal bindings, 0/24 refinement) is the P4 confidence baseline to beat. No child-board change. Awaiting parts 4 to 6 (child stories). Mainline head aef7032 before this record commit.
- 2026-09-02T12:14:29Z interactive: PRD pack part 4 of 7 received (the pack grew from six to seven parts): master US-008 (independent acceptance gate, passes:false) and US-009 (private skill draft, passes:false), stored verbatim at docs/prd-pack/04-master-stories-acceptance-gate-and-skill-draft.md. US-008's strong criteria recorded under P4 as the confidence bar: 24-obligation denominator (Codex plane at 19/24 Rust proof and mutation, 0/24 Java/refinement/aggregate), 100% eligible mutation score, 247/247 both Autobahn roles from the retained receipt, two fresh adversarial reviews, production-shaped rehearsal; its blockers split into owner gates (independence, two-host performance, cutover, publication, signing, Java removal) and plane work (Java/refinement side of the denominator, five Rust/mutation obligations). No child-board change. Awaiting parts 5 to 7. Mainline head aef7032 before this record commit.
- 2026-09-02T13:36:56Z routine: P1 claude/us019-native-run forward-merged with mainline 6150e92 → b26be41 (87 mainline commits in; four conflicts resolved as a union: io_loop.rs keeps the branch's HandshakeOutcome/carryover/byte-at-a-time handshake feed AND mainline's end_transport_service + failure surfacing on every exit incl. the per-byte loop and the ack path the auto-merge had left as bool; loopback.rs keeps mainline's producer fixture with the branch's .opened reading; evidence-dag and rust-identity-verification regenerated once, LINKAGE_REGENERATE=1 exit 1 by design then 0). First gates run exit 2: ws-core release test a_producer_racing_the_owner_drop_never_blocks_and_never_reports_a_stale_accept failed 2/5 in isolation on an iteration-count spin bound (host-speed assumption, ws-core untouched); bound made wall-clock (30 s) + yield_now after each capacity refusal, properties unchanged, 8/8 green; filed F004 (REDISCOVERY of F002's class). Second gates run exit 0: 8/8, adapter-linkage PASS over 6 sources, ledger ok, 96 test blocks. go 31 ok (+lab/portplan env). ws-testee/src changed → differential + exam re-run: digests unchanged, port 74/74 and 49/49 (16 divergences), live Java 74/74 (JDK 17 needs -Dsun.stdout.encoding=UTF-8; with -Dstdout.encoding alone it read 65/74) and 49/49, public transcripts differ only in /error/detail (26) + runtime, handshake only runtime. Two environment gotchas recorded in CLOUD-ENVIRONMENT.md (cargo must run from rust/ for the toolchain pin; JDK 17 encoding property). Branch pushed; draft PR against mainline opened. Not landed: self-review round pending (list in the queue). Mainline head 6150e92 before this record commit.
