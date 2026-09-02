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
  draft PR #4 opened against mainline; **self-review round 1 done 2026-09-02
  (51c9fb4, record `drafts/self-review/us019-native-run-round-1.md`)**: the
  amended AC3 bar is now implemented and met (246/247 agreement with the
  pinned Java baseline on both roles, the one residual difference at case 5.15
  registered against ledger sequence 34), the literal reading stays computed
  and NEGATIVE, the comparison document and the native evidence tree both
  gained consumers, and six new checks were each proven able to fail by
  deletion. **Round 2 done 2026-09-02 (4c45c6c, record
  `us019-native-run-round-2.md`)**: review finding 7 NARROWED, not closed —
  the manifest is now bound to the frozen family policy, the suite's identity
  grammar, the pinned case count and the configs the legs were launched with,
  all independent of the runs; nine attacks that were accepted are now
  refused, and the one that survives (a fabricated identity of the right
  shape) is asserted as a measured gap by a test written to fail the day it
  closes. **Everything left on this branch is an owner gate**: AC1's
  bounded-resources clause, recorded unmet — needs a new host; the no-echo
  and opcode-swap mutant runs incomplete at 66/247 and 181/247 with
  discrimination OUTSTANDING — needs Autobahn re-runs, never triggered by the
  loop; and finding 7's residual — needs the pinned Autobahn source archive
  in the quarantine (its GitHub URL 403s through this proxy and the upstream
  repo is outside session scope), after which the existing registry parser
  closes it with no new design) → `claude/post-failure`
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

## Story board (titles from the child PRD index in `docs/prd-pack/01-structure-and-index.md`)

**The board is no longer PROVISIONAL.** The seven-part PRD pack completed on
2026-09-02 and parts 7a to 7c carry all 27 child stories' acceptance criteria
verbatim under `docs/prd-pack/`. Judge every row against those criteria, not
against a reconstruction. Two cautions: master US-019 (the retrospective) is
NOT child US-019 (Autobahn conformance) — every US-0nn here is a child story
unless it says master; and the child PRD's `passes: true` on all 27 is
owner-attested with completionScope STORY_EXECUTION_COMPLETE, while master
US-008, the independent gate, reads 0 of 26 strongly accepted.

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
| US-018 | Add thin blocking TCP client and server adapters | passes; fixture made kernel-independent 2026-09-02; `server-close-parity` landed 2026-09-02 as d433c21 — a SERVER now closes the TCP connection once its close-handshake writes have drained and a client never does, matching `SocketChannelIOHelper.java:110-113` (citation re-read at source: `batch(` has exactly one caller, so "server write path only" is the complete call graph). Residual disclosed, not closed: the unit truth table survives deletion of the whole fix, and `pending_chunk.is_empty()` has no failing witness | PRD done (owner-attested); contract | receipt correction is owner's |
| US-019 | Pass both pinned Autobahn conformance modes | `us019-autobahn` 1 ahead; `us019-native-run` at 4c45c6c (rounds 1–2 done: amended AC3 bar implemented and met at 246/247 both roles; finding 7 narrowed). Open against the criteria: AC1's bounded-resources clause unmet; AC4's mutant discrimination OUTSTANDING for no-echo and opcode-swap; **and a clause nobody had recorded — child US-009 AC1 requires "final promoted evidence must replay the complete Rust gate in that [Docker sbx] profile before US-019 or release acceptance", which this Linux cloud session cannot satisfy** | PRD done (owner-attested); readiness only, no current-subject run | P1 self-review, then owner gate |
| US-020 | Close Java and Rust differential divergences | ledger-integrity landed 2026-09-02: delta ledger 48 records, 3 supersessions, unledgered_disagreements recomputed = 0 behind `ledger-gates`; public differential 74/74 for port and live Java. **Audited 2026-09-02 (second pass): AC2 is UNIMPLEMENTED — the five-rank oracle hierarchy exists nowhere in the tree as code or data (one prose hit, `internal/deltaledger/definitions_gap_closure.go:105`), so nothing enforces its clause that Java/Rust agreement cannot override a higher oracle, and the 74/74 IS that rank-4-vs-rank-5 agreement. AC5 is class-INCOMPLETE — of its seven seeded variant classes the 76 `mutctl` mutants cover two by name, reach three only through operators named for other things with no declared mapping, and seed neither Java-quirk emulation nor normalization-collision.** AC1/AC3/AC4 still unjudged. **`divergence-sweep` landed 2026-09-02 as f245ff6** and is the first real AC1 instrument: all 39 keys an Autobahn per-case report carries, partitioned 19 compared / 12 invariant / 8 not-comparable with the union asserted equal to the observed key set, giving 24 dimensions per case per role. 3058 differences, 0 unclaimed, 7 named classes, 6 dimensions at zero divergence, and the overlap disclosed (class_claim_sum 3063, 5 double-claimed, each detailed). Headline counts re-derived independently by the loop from the raw reports and exact: 122 server / 119 client cases where the port sent no Close frame and Java did, 1007x76/1002x42/1000x4 server and 1007x76/1002x40/1000x3 client, 0 code and 0 reason disagreements where both sent. DIV-02's fix landed the same hour (d433c21) but the measurement predates it (port build 518b77aa) — **status is 'fix landed, closure unconfirmed'; an Autobahn re-run is an owner gate**. DIV-01, the largest class, has its fix on the unlanded `claude/post-failure`. **AC3 is now blocked on finding 8: the ledger has no vocabulary for the classes AC3 requires** | PRD done (owner-attested); 4 files | P2: implement AC2's hierarchy; make AC5 class-complete (normalization-collision first); settle the ledger disposition vocabulary, then append the 7 drafted records |
| US-021 | Close property, fuzz, and runtime evidence | NOT "not started" — corrected 2026-09-02 against the real criteria: `rust/ws-core/tests/adversarial_properties.rs` holds 28 tests over 685 lines, `rust/ws-driver/fuzz-seeds/us017/` holds the retained corpus, and the gates run debug and release. What is missing is not the evidence but the JUDGMENT: AC3 demands a pinned engine/toolchain, dictionary/corpus digest, a minimum bounded campaign, timeout/OOM/crash policy, artifact capture, replay command and an exact target manifest per target, and none of that has been assembled or checked. Status: evidence exists, unjudged against AC1–AC5 | PRD done (owner-attested); 5 files | P3 |
| US-022 | Pass normalized mutation and protected evaluation | not started — CONFIRMED 2026-09-02 against the criteria: no `evidence/mutation` tree, zero PIT runs, zero cargo-mutants runs. Seed material that is NOT this story: `corpora/hidden/manifest.json` and `corpora/sealed/manifest.json` (US-005 outputs) and the 76 `mutctl` mutants (US-012..US-016 AC5). Nothing implements AC1's single signed denominator or AC4's separate identities, filesystems, caches, credentials and signing keys | PRD done (owner-attested); 6 files | P3 |
| US-023 | Freeze the complete parity candidate | not started — audited 2026-09-02. AC3's catalog IS seeded: `assurance/formal/proof-targets.json` holds 10 targets, 21 production symbols and 98 migration bindings, with exact Java anchors (file/line/sha256) and exact Java method signatures per symbol. Missing: the canonical machine-readable formal-coverage report, the human-readable report, and the per-side strength/method/bounds/assumptions/trusted-base/digests/refinement/counterexample record. **Ceiling now on the board: all 21 symbols read `PLANNED_PENDING_RESOLVER`, all 98 bindings `rust_identity_verified: false`, `resolver_verified_at: null`; the strongest linkage evidence (`evidence/linkage/rust-identity-verification.json`, 45/47 rows) self-labels 'declaration-scan (reviewed-glancer class), not rust-analyzer semantic resolution'. No formal obligation here binds to a resolver-verified shipped Rust symbol.** Also unreconciled: 10 targets / 11 property claims here vs master US-008's 24-obligation denominator. **`java-formal-bindings` landed 2026-09-02 as 66cefbd**: the 24-obligation catalog is vendored from the Codex plane (blob-identical, sha256 21112518..., asserted in a test), the Java column's 0/24 is explained (all 24 DISCONNECTED, synthesised per-method paths existing in no tree, one whole-archive `source_sha256` shared by all 24), and 4/24 now carry falsifiable Java evidence — span-resolved declarations, byte-exact pinned-JAR observations, and per-clause canaries with unmutated controls (10 declared, 10 killed). **The denominator does not move: 0/24 at required strength, refinement 0/24, aggregate 0/24**, observed strength EXECUTED_OBSERVATION_WITH_MUTATION_SENSITIVITY against a required PRODUCTION_REFINEMENT, and the tool prints the ceiling beside the numerator. See finding 9: five obligations are declared against the wrong Java symbols and cannot be bound as written | PRD done (owner-attested); 9 files; every gate BLOCKED in its own register | P3 |
| US-024 | Refine idiomatic Rust without changing parity | not started | PRD done (owner-attested); "complete" for owner-relaxed mechanics; 8 blockers | P3 |
| US-025 | Decide every preregistered resource envelope | not started — CONFIRMED 2026-09-02. The preregistration AC1 requires to predate the samples exists and is in order (`benchmarks/plan/workloads.json`, `benchmarks/environments/primary-macos.json` + `confirmation.json`, three schemas, the tiered-rigor contract amendment). Zero raw samples exist | PRD done (owner-attested); 1 file | P3, owner gate on hosts |
| US-026 | Rehearse shadow, canary, soak, and Java rollback | not started — CONFIRMED 2026-09-02. The one cutover artifact in the tree is `contract_id: cutover-contract.us003`, the US-003 intake freeze output consumed by `internal/portplan`; it is NOT US-026's CutoverContract. Named because a right-shaped `entity_type` in `evidence/intake/` is exactly what gets mistaken for progress | PRD done (owner-attested); contracts only | P3 |
| US-027 | Independently accept and project the complete child snapshot | not started — CONFIRMED 2026-09-02: one schema (`schemas/sbx-public-projection-1.0.0.schema.json`), nothing else | PRD done (owner-attested); receipts: codex/reality owner-attested, human NOT_EXECUTED | P3, owner gate |

## Criteria audit (first pass, 2026-09-02, after the PRD pack completed)

The board was PROVISIONAL until part 7 arrived. This is the first pass reading
the 27 rows against the real criteria rather than a reconstruction. It is a
first pass, not a full re-judgment: only findings that change what the board
says are recorded, and every row still marked "passes" from the pre-PRD era
remains unjudged against its criteria unless named below.

1. **US-021 was wrong, and in the direction that flatters us.** The row said
   "not started". The tree holds 28 property tests over 685 lines, the
   retained `us017` fuzz corpus, and debug plus release runtime checks in the
   gates. The gap is judgment, not evidence: AC3 requires a pinned engine and
   toolchain, a dictionary or corpus digest, a minimum bounded campaign, a
   timeout/OOM/crash policy, artifact capture, a replay command and an exact
   target manifest FOR EACH target, and none of that has been assembled. The
   row now says "evidence exists, unjudged", which is the honest state.

2. **A cross-story gate on US-019 that nobody had recorded.** Child US-009's
   first criterion ends: "final promoted evidence must replay the complete
   Rust gate in that profile before US-019 or release acceptance" — the
   profile being the accepted US-007 Docker sbx one. So US-019 acceptance
   depends on an sbx replay of the whole Rust gate, on top of its own AC1 and
   AC4 gaps. Two self-review rounds ran on that branch today without this in
   view. **Owner action: the sbx profile is the verified macOS one and this is
   a Linux cloud session, so either the replay happens on the owner's macOS
   host, or an equivalent runtime is qualified per the PRD's own fallback
   policy ("qualify a semantically equivalent runtime with adversarial
   canaries or block the affected claim; do not silently weaken controls").**

3. **Four stories require BOTH blocking platforms and this session has one.**
   US-017 AC4 (native-thread stress across both), US-018 AC2 (adapter
   behaviour on macOS arm64 AND Linux x86_64), US-021 AC4 (runtime checks on
   both) and US-023 AC1 (builds and tests pass on both) all name the pair.
   This session is Linux x86_64 only. Every "passes" on those rows therefore
   rests on evidence produced where macOS was available; nothing this session
   validates can complete them on its own. Recorded so a future round does not
   read a green Linux gate as satisfying a two-platform criterion.

Not audited in the first pass, and named rather than implied: US-001 to
US-016, US-020, and US-022 to US-027 kept their pre-PRD statuses. The second
pass below closes US-020 and US-022 to US-027; US-001 to US-016 and US-021's
own AC1/AC2/AC4/AC5 remain future work, one story at a time.

## Criteria audit (second pass, 2026-09-02: US-020 and the US-022..US-027 tail)

Same rule as the first pass: only findings that change what the board says are
recorded. Read against `docs/prd-pack/07c-child-prd-us020-us027.md` verbatim.
Every census below was taken from the tree, not from a recollection, and the
commands are named so a later round can re-take them.

4. **US-020 AC2 has no mechanism anywhere in the tree.** The criterion sets a
   five-rank oracle hierarchy — RFC 6455 rank one, in-scope Autobahn rank two,
   independent neutral expectations rank three, Java observation rank four,
   Rust observation rank five — and then states the load-bearing clause:
   *"agreement between Java and Rust cannot override a higher oracle."* A
   search of the Go and JSON tree for a rank, an oracle hierarchy or an
   adjudication order finds exactly one hit, and it is a prose string inside a
   ledger definition (`internal/deltaledger/definitions_gap_closure.go:105`).
   There is no type, no field, no check. The 74/74 public differential the row
   cites is a rank-four against rank-five comparison; it is precisely the
   comparison the clause says cannot settle a question on its own. Nothing in
   the tree stops Java and Rust agreeing on something RFC 6455 forbids and
   that agreement being read as parity. Status: **AC2 unimplemented**, and the
   differential's headline number does not speak to it.

5. **US-020 AC5's seven seeded variant classes were never put through the
   class-completeness discipline this repository already invented.**
   `cmd/mutctl/mutations.go` holds 76 Rust mutants over 43 operators, and
   carries an explicit section headed "AC5-named defect classes" whose comment
   says each entry exists "so the AC5 evidence is class-complete, not merely
   operator-complete". That discipline was applied to the AC5 lists of US-013
   through US-016. It was never applied to US-020's own list. Reading US-020's
   seven classes against the catalogue:
   - *Rust semantic defect* — covered, and it is most of the 76.
   - *event-order* — covered by name (`event-order-swap`,
     `m013-close-event-order-swap`).
   - *error-class*, *close-initiator*, *consumed-byte* — plausibly reachable
     through operators named for other things (`close-code-swap`;
     `close-echo-swap` / `close-transition-swap`; `payload-truncation` /
     `counter-increment-drop`), with **no declared mapping**. That supports the
     weak claim "an operator exists that might fire", not the criterion's claim
     "the class is detected".
   - *Java-quirk emulation* and *normalization-collision* — **no seeded
     variant of any kind**. The two planted Java mutants under `mutants/java/`
     (`us005-jm-close-code-1000`, `us005-jm-utf8-accept`) are US-005 corpus
     calibration, not US-020 detection variants.
   The missing normalization-collision class is not hypothetical today. It is
   the variant that seeds two genuinely different behaviours which the
   differential's normalization maps onto the same observation — which is
   exactly the failure mode a parallel track is chasing right now (shipped Java
   closes the TCP connection after echoing a close, the port does not, and the
   differential reads parity). A class-complete AC5 would have found that by
   construction instead of by someone noticing.

6. **US-022, US-025, US-026 and US-027: "not started" is CONFIRMED.** Recorded
   with the seed material named, so that a later round does not read an
   inherited artifact as story progress — the mistake US-021 nearly caused in
   the other direction:
   - **US-022** — there is no `evidence/mutation` tree, no PIT run and no
     cargo-mutants run anywhere. `corpora/hidden/manifest.json` and
     `corpora/sealed/manifest.json` exist, but they are US-005 corpus outputs;
     the 76 `mutctl` mutants are US-012..US-016 AC5 evidence. None of it is
     AC1's one signed denominator over normalized dispositions, and nothing
     implements AC4's separate identities, filesystems, caches, credentials,
     signing keys and workspaces.
   - **US-025** — `benchmarks/plan/workloads.json`,
     `benchmarks/environments/primary-macos.json` and `confirmation.json`,
     three benchmark schemas and the tiered-rigor contract amendment all
     exist. That is US-008's preregistration, which is the artifact AC1
     requires to *predate* the samples, so its existence is correct and in
     order. There are zero raw samples. Blocked on the owner's two hosts.
   - **US-026** — the only cutover artifact in the tree declares
     `"contract_id": "cutover-contract.us003"` and is consumed by
     `internal/portplan`. It is the US-003 intake freeze output, not US-026's
     CutoverContract. Recording it explicitly because a document with the right
     `entity_type` sitting in `evidence/intake/` is exactly the shape that gets
     mistaken for story progress.
   - **US-027** — one schema, `schemas/sbx-public-projection-1.0.0.schema.json`.
     Nothing else.

7. **US-023 is "not started", its AC3 catalog has a real seed, and the seed's
   own honesty is where the interesting fact is.**
   `assurance/formal/proof-targets.json` carries 10 targets, 21 production
   symbols and 98 migration bindings. Each target binds exact Java authority
   anchors (file, start and end line, sha256, behaviour) and each production
   symbol names exact Java method signatures in `java_authority_members` — so
   AC3's "maps every in-scope obligation separately to exact shipped Java and
   Rust production symbols" is genuinely seeded, not absent. What does not
   exist is the rest of AC3: no canonical machine-readable formal-coverage
   report, no human-readable coverage-style report, and no per-side record of
   evidence strength, method, bounds, assumptions, trusted base, tool/input/
   output digests, refinement link and counterexample sensitivity.
   The fact worth carrying forward is the resolution state. All 21 production
   symbols read `PLANNED_PENDING_RESOLVER` with `resolved_symbol: null`, all 98
   migration bindings read `rust_identity_verified: false`, and the document's
   own `rust_identity_resolution` block states
   `RUST_IDENTITIES_NOT_YET_RESOLVER_VERIFIED` with `planned_resolver:
   "rust-analyzer"` and `resolver_verified_at: null`. The stronger document,
   `evidence/linkage/rust-identity-verification.json`, does resolve 45 of 47
   rows — by a "deterministic declaration scan", and it labels its own strength
   "declaration-scan (reviewed-glancer class), not rust-analyzer semantic
   resolution". The two documents do not contradict each other (the US-003 map
   is frozen with `rust_identity_verified` pinned to const false by schema, and
   the linkage document is where the real reading lives). **The ceiling this
   sets has not been on the board: no formal obligation in this repository is
   bound to a resolver-verified shipped Rust symbol. Every claim that formal
   evidence reaches shipped code currently rests on a declaration scan that
   names itself the reviewed-glancer class.** That is not a defect and nothing
   here is overstated in its own file — but it is the honest ceiling on
   US-023 AC3 and on master US-008's formal denominator, and it should be
   stated once on the board rather than rediscovered.
   Also unreconciled: `proof-targets.json` holds 10 targets and 11 property
   claim references, while master US-008 counts a 24-obligation denominator.
   Nothing in the tree maps the one onto the other, and that reconciliation is
   itself an AC3 prerequisite.

8. **The behaviour delta ledger cannot express what US-020 AC3 requires of it.**
   Found while deciding a ledger-framing question raised by the server-close
   parity track. `schemas/behavior-delta-ledger-1.1.0.schema.json` defines
   `disposition` as `enum: ["unresolved", "rfc-governs"]`, and **all 48 records
   read `unresolved`.** US-020 AC3 requires every mismatch be appended "as Java
   quirk, Rust defect, or underspecified behavior" — three classes this
   vocabulary does not contain, so the classification AC3 demands has never been
   made for any record. Meanwhile the inherited foundation schema next door,
   `assurance/schema/behavior-delta-ledger.schema.json`, defines exactly the
   axis the pending records turn on — `classification: [PRESERVE,
   INTENTIONALLY_CORRECT, UNRESOLVED]` — and the live ledger does not use it.
   Consequence, and it is immediate: seven records are now drafted and waiting
   (one from server-close parity, six from the divergence sweep) that span both
   a divergence to fix in the port and one to record as an intentional
   correction. Filing them all as `unresolved` would put deliberately adopted,
   fully reasoned behaviours in the same bucket as 48 open questions — existence
   standing in for identity, one level up from where this program usually meets
   it. **The ledger is untouched and stays untouched until the vocabulary is
   settled**; then all seven append together as one deliberated batch, because
   the ledger is append-only with a frozen prefix and a wrong disposition cannot
   be taken back.

9. **Five of the 24 formal obligations are declared against the wrong Java
   symbols — a defect in the denominator itself.** Surfaced by the Java formal
   bindings track while trying to bind them. The mask obligations are declared
   against `Charsetfunctions.utf8Bytes`; `surface.control.ping-pong` against a
   method the oracle listener overrides; `messages.*` against an ambiguous
   interface overload. These are not "not yet bound" — they cannot be bound as
   written. Separately, the same track confirmed **why the Java column read
   0/24**: all 24 `java_bindings` carry `connection_state: DISCONNECTED`, their
   `source_path` values are synthesised paths that treat a *method* as a file
   (15 distinct such paths, none of which exist in any tree), and **all 24 share
   one `source_sha256` — the whole-archive digest**. Twenty-four distinct
   obligations, one archive-level digest, paths resolving to nothing. Add both
   to the US-023 audit: the denominator master US-008 measures against is itself
   defective in five places, and its Java column was populated in appearance
   only.

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
- 2026-09-02T13:36:56Z routine: P1 claude/us019-native-run forward-merged with mainline 6150e92 → b26be41 (87 mainline commits in; four conflicts resolved as a union: io_loop.rs keeps the branch's HandshakeOutcome/carryover/byte-at-a-time handshake feed AND mainline's end_transport_service + failure surfacing on every exit incl. the per-byte loop and the ack path the auto-merge had left as bool; loopback.rs keeps mainline's producer fixture with the branch's .opened reading; evidence-dag and rust-identity-verification regenerated once, LINKAGE_REGENERATE=1 exit 1 by design then 0). First gates run exit 2: ws-core release test a_producer_racing_the_owner_drop_never_blocks_and_never_reports_a_stale_accept failed 2/5 in isolation on an iteration-count spin bound (host-speed assumption, ws-core untouched); bound made wall-clock (30 s) + yield_now after each capacity refusal, properties unchanged, 8/8 green; filed F004 (REDISCOVERY of F002's class). Second gates run exit 0: 8/8, adapter-linkage PASS over 6 sources, ledger ok, 96 test blocks. go 31 ok (+lab/portplan env). ws-testee/src changed → differential + exam re-run: digests unchanged, port 74/74 and 49/49 (16 divergences), live Java 74/74 (JDK 17 needs -Dsun.stdout.encoding=UTF-8; with -Dstdout.encoding alone it read 65/74) and 49/49, public transcripts differ only in /error/detail (26) + runtime, handshake only runtime. Two environment gotchas recorded in CLOUD-ENVIRONMENT.md (cargo must run from rust/ for the toolchain pin; JDK 17 encoding property). Branch pushed; draft PR #4 (https://github.com/michaellady/verified-java-websocket-port/pull/4) opened against mainline and subscribed. Not landed: self-review round pending (list in the queue). Mainline head 6150e92 before this record commit.
- 2026-09-02T14:43:46Z routine: P1 self-review round 1 on claude/us019-native-run → 51c9fb4. Implemented the amended AC3 bar (owner decision 2026-08-28) as a checked verdict computed from both runs' report bytes: measured 246/247 agreement on BOTH roles, one residual difference (case 5.15), amended verdict MET, literal verdict still NEGATIVE and still computed; new autobahnsuitectl amended-ac3 prints both. Four findings on my own work, each fixed: (1) the first ledger check was existence-standing-in-for-identity — a planted regression on case 1.1.1 was ACCEPTED because the ledger cites that case for an unrelated handshake correction (sequence 47); replaced with an exact two-directional divergence register; (2) two of six checks were not isolated by any probe (the register's stale-entry direction, the document's value comparison) — both stayed GREEN when deleted, both now red via isolating probes; (3) the owner decision's own figures (client 245/247) are not what this tree holds — measured 246 on both roles, nothing adjusted to match; (4) the native evidence tree was UNPINNED (digest manifest pinned 1,506 emulated files, zero native) — new native-digest-manifest.json pins 1,048 with two consumers. Gates 8/8 + ledger ok, adapter-linkage over 6 sources; go 31 ok (+lab/portplan env); LINKAGE_REGENERATE=1 exit 0 then verify 0, no DAG delta; differential/exam not re-run and cannot have moved (no Rust byte changed). Not landed: three items remain, two of them owner gates (bounded-resources re-run; completing the two incomplete mutant runs). Mainline head 7c96266 before this record commit.
- 2026-09-02T16:33:03Z routine: P1 self-review round 2 on claude/us019-native-run → 4c45c6c, review 01a04961 finding 7. The manifest was snapshot-derived (BuildManifest expands it from the reports it then judges; verify-manifest re-expanded the same sources and compared bytes). Now bound to four independent sources: internal/lab's frozen family policy and case-identity grammar (static-parsed from pinned suite source), internal/lab's pinned selected-case count cross-checked against this package's own constant, and the three committed wstest configs the legs were launched with — nothing had compared configs to policy before. Nine attacks accepted before this round are refused now (dropped case, duplicate keeping the count, excluded-family case, vanished family, narrowed declaration, dropped exclusion, malformed identity, divergent config, no config at all). ONE survives: a fabricated identity of the right shape in a selected family with the count intact — nothing here knows which identities the suite defines. Finding 7 is NARROWED NOT CLOSED and is not reported closed: TestTheResidualOfFinding7IsMeasuredNotClaimed asserts the gap and fails the day it closes. Closing it needs the pinned Autobahn source archive in the quarantine (403 through this proxy; upstream repo outside session scope) — OWNER ACTION; the registry parser to consume it already exists. Gates 8/8 + ledger ok; go 31 ok (+lab/portplan env); verify-manifest exit 0 with independent-constraints=ok; no Rust byte changed so differential/exam cannot have moved. Mainline head 6adf8f8 before this record commit.
- 2026-09-02T17:38:03Z interactive: PRD pack COMPLETE — parts 5, 6a, 6b, 6c, 7a, 7b, 7c all received and stored verbatim under docs/prd-pack/. Part 5 = master US-010..US-019 (all passes:false behind US-008). Parts 6a-6c = the PRD metadata: 18 quality gates, reviewPolicy (fallbackAllowed:false, actualRuntimeReceiptRequired:true), nonGoals (which confirm this lab's exclusions: TLS/WSS, RFC 7692, proxies, reconnect, Android, Java API parity), the five assurance labels, the six readiness states, and the 21 owner decisions. Parts 7a-7c = THE CHILD PRD, this repository's own 27 stories with full acceptance criteria — the board is no longer PROVISIONAL. Recorded two reading cautions in the board header: master US-019 (retrospective) is not child US-019 (Autobahn conformance), and the child's 27 passes:true are owner-attested STORY_EXECUTION_COMPLETE while master US-008 reads 0/26 strongly accepted. Child US-019 AC3 confirms the literal strict-pass clause the owner amended on 2026-08-28, so the amended-bar work landed this session is judged against the right text. Mainline head 8a7f713 before this record commit.
- 2026-09-02T18:24:10Z routine: criteria audit, first pass, now that the PRD pack is complete and the board is no longer PROVISIONAL. Did NOT take a top-of-queue unit: post-failure, the server-close parity gap, the divergence sweep and the Java formal bindings are all in flight with parallel agents, and duplicating them was the wrong move. Three findings recorded in a new 'Criteria audit' section: (1) US-021 was wrong in the flattering direction — the row said 'not started' but the tree holds 28 property tests over 685 lines plus the retained us017 fuzz corpus and debug/release runtime checks; the real gap is that AC3's per-target pinning (engine, corpus digest, bounded campaign, crash policy, artifact capture, replay command, target manifest) has never been assembled, so the row now reads 'evidence exists, unjudged'. (2) A cross-story gate on US-019 nobody had recorded: child US-009 AC1 requires the complete Rust gate to be replayed in the Docker sbx profile before US-019 or release acceptance — two self-review rounds ran on that branch today without it in view; OWNER ACTION, since sbx is the verified macOS profile and this is a Linux session. (3) Four stories (US-017 AC4, US-018 AC2, US-021 AC4, US-023 AC1) require BOTH macOS arm64 and Linux x86_64; this session has one, so no green Linux gate here can complete them. US-001..016, US-020 and US-022..027 keep their pre-PRD statuses and are named as not yet audited. Mainline head 6c88487 before this record commit.
- 2026-09-02T18:35:07Z interactive (four parallel agents in flight): two units, neither of them a track any agent holds. (1) LANDED THE F004 FIX ON MAINLINE as 01ee515. Mainline carried the FINDING but not the FIX: F004 landed in d4b90dd with the us019-native-run forward-merge record, while the code change lived only inside b26be41 on that still-open branch (PR #4), so every worker running `make -C rust gates` on a mainline tree met a documented flake with no remedy in reach — the same shape as the class this program keeps rediscovering, the record of a thing standing in for the thing. `refusals_before_the_drop < 4096` is a count of mutex round-trips, i.e. a host-speed assumption; replaced by a 30-second wall-clock deadline plus `thread::yield_now()` after each capacity refusal, every property assertion unchanged, taken verbatim from us019-native-run so the two trees agree (it was the sole ws-core difference between them; now zero). RED reading is not mine: a parallel agent hit the pre-fix assertion at concurrency_boundary.rs:279 today on its own mainline-derived tree with ws-core byte-identical — an independent reproduction nobody was trying to provoke. Confirmation on mainline at 01ee515: fmt-check, clippy, test, test-release all clean, 75 "test result: ok" blocks and 0 failed, ac1-gates verdict=PASS gates_passed=8/8, adapter-linkage PASS over 5 production sources; the first background run exited 2 at ledger-gates with the store unset, which is the documented REFUSAL not a defect, and `VJWP_PROTECTED_STORE=$PWD/evidence/governance/decisions go run ./cmd/deltaledgerctl --root . --check` then read ok on all four lines (48 records, frozen prefix through 35, 3 supersessions, unledgered_disagreements 0, 4 governance digests recomputed). All four agents were messaged with the fix and told not to re-investigate. (2) CRITERIA AUDIT, SECOND PASS: US-020 and the US-022..US-027 tail, four findings. US-020 AC2 is unimplemented — the five-rank oracle hierarchy exists nowhere as code or data, so nothing enforces that Java/Rust agreement cannot override a higher oracle, and the cited 74/74 IS that rank-4-vs-rank-5 agreement. US-020 AC5 is class-incomplete — this repo already invented the class-completeness discipline (`mutctl`'s "AC5-named defect classes" section) and applied it to US-013..US-016, never to US-020: of seven classes, two are covered by name, three are only plausibly reachable through operators named for other things with no declared mapping, and Java-quirk emulation and normalization-collision have no seeded variant at all — the missing normalization-collision class is exactly the check that would have found the server-TCP-close divergence a parallel track is chasing today, by construction rather than by someone noticing. US-022/025/026/027 "not started" confirmed, each with its seed material named so an inherited artifact is not later read as progress (notably `cutover-contract.us003`, a US-003 intake output, not US-026's contract). US-023's AC3 catalog is genuinely seeded with exact Java anchors and method signatures, but a ceiling nobody had put on the board falls out of it: all 21 production symbols read PLANNED_PENDING_RESOLVER, all 98 migration bindings rust_identity_verified=false, resolver_verified_at=null, and the strongest linkage evidence self-labels "declaration-scan (reviewed-glancer class), not rust-analyzer semantic resolution" — no formal obligation in this repository binds to a resolver-verified shipped Rust symbol. Also unreconciled: 10 targets / 11 property claims vs master US-008's 24-obligation denominator. US-001..US-016 and US-021's AC1/AC2/AC4/AC5 remain unaudited and are named as such. Mainline head 01ee515 before this record commit.
- 2026-09-02T18:53:02Z interactive: LANDED THREE OF THE FOUR PARALLEL AGENT TRACKS, each reviewed rather than accepted on report. Track B `claude/server-close-parity` -> d433c21: a server now closes TCP once its close-handshake writes have drained, a client never does, `role` a required parameter so no call site acquires the behaviour by omission. I re-read the Java citation at source instead of taking it — SocketChannelIOHelper.java:110-113 verbatim, `batch(` has EXACTLY ONE caller in the whole tree so "server write path only" is the complete call graph not an inference, and the client counterpart genuinely does not exist (runWriteData has no closeConnection, its four call sites are all error paths). Approved the branch's linkage refreeze after reading the diff (six digest lines + drive_connection 159->164, exactly its new doc comment's five lines; derived-index recomputation, not re-baselining). Track C `claude/divergence-sweep` -> f245ff6: 24 dimensions per case per role over a 39-key partition, 3058 differences, 0 unclaimed, 7 classes. Before accepting its copy of 1049 evidence files from the UNLANDED us019-native-run I checked it is blob-identical, confined to evidence/autobahn/, and does NOT bring internal/autobahnsuite where every contested us019 item lives — so mainline gains raw reports with NO acceptance claim. Then I re-derived its headline counts independently from the 988 raw per-case JSONs in throwaway Python: 122/119 no-close-frame, the 1007x76/1002x42/1000x4 and 1007x76/1002x40/1000x3 splits, 0 code and 0 reason disagreements — all exact, through code the branch never wrote. Track D `claude/java-formal-bindings` -> 66cefbd: 26 files, all additions, zero modifications. Verified the Codex borrow blob-identical to origin/codex/race-catchup (plane read, never written) and probed the content binding myself rather than trusting the branch's report of its own attack — appended one whitespace byte to the catalog, verifier exited 1 with "the catalog on disk is not the catalog the spec pins", restored byte-identical. Two tracks converged on ONE defect without seeing each other: B fixed from Java's source what C measured as DIV-02's 123 server cases. Gates exit 0 at all three merged heads (8/8, ledger ok, 75 test blocks, 0 failed). TWO NEW AUDIT FINDINGS, both from doing the work rather than reading the docs: (8) the delta ledger CANNOT express what US-020 AC3 requires — disposition is enum ["unresolved","rfc-governs"], all 48 records read "unresolved", AC3 demands Java quirk / Rust defect / underspecified, and the foundation schema next door already defines the missing axis (PRESERVE / INTENTIONALLY_CORRECT / UNRESOLVED) unused. Seven records are now drafted and waiting; the ledger stays untouched until the vocabulary is settled, then all seven append as one batch. (9) FIVE of the 24 formal obligations are declared against the wrong Java symbols and cannot be bound as written, and the Java column's 0/24 is explained: all 24 DISCONNECTED with synthesised per-method paths existing in no tree and ONE whole-archive source_sha256 shared by all 24 — the denominator itself is defective. Track A (post-failure) still running; not landed. Mainline head 66cefbd before this record commit.
- 2026-09-02T18:59:24Z interactive: PR #4 kept mergeable after the four landings. Landing server-close-parity made claude/us019-native-run conflict, so it was forward-merged with mainline 2534bfe -> cd7ef90 and pushed. Two generated linkage files conflicted textually; taking mainline's side outright was tried FIRST and REFUSED by the regenerator with "story node US-019 missing" — mainline has no US-019 node, so that resolution would have silently dropped this branch's evidence. Resolved by taking the branch's side and regenerating through the sanctioned path, both exits read (LINKAGE_REGENERATE=1 exit 1 by design naming the run_client_once digest server-close-parity made stale, then verify exit 0; delta is digests and line numbers only, symmetric 12/12, no node added or removed). ONE SEMANTIC CONFLICT GIT DID NOT REPORT: io_loop.rs auto-merged cleanly and did not compile — this branch had split drive_connection into a wrapper over drive_connection_from, mainline had added `role: Role` to drive_connection, and the textual merge put the parameter on the wrapper while the loop that consults it lives in the callee (four rustc errors). Threaded `role` through drive_connection_from and gave ALL NINE call sites their role explicitly, each read from the connection_driver(..., Role::X) that builds that site's driver rather than inferred: client/server/agent(Client)/autobahn_agent mock(Server)/mutant.rs server+client/mutants.rs client+server. Server-close-parity's rule that the behaviour is never acquired by omission in either direction is preserved — still no default. ONE SUPPRESSION, NAMED NOT BURIED: eight arguments trips clippy too_many_arguments, and a struct would satisfy the lint by HIDING the role (and add public API surface the linkage evidence pins, on a branch already under review), so a targeted #[allow] with a written justification went on that one function, following the repo's existing narrow-allow practice (six in ws-core, none workspace-wide). It is a design-smell suppression introduced to resolve a merge, so it goes on the branch's residual list for the self-review round that must precede landing. Gates on the resolved tree exit 0: 8/8, adapter-linkage PASS over 6 sources, ledger ok, 96 test blocks, 0 failed. `git merge-tree` against mainline now exits 0. Nothing about the branch's BLOCK status changed: review 01a04961 still stands, AC1 bounded-resources unmet, AC4 mutant discrimination outstanding (owner gate), finding 7 narrowed not closed, and the sbx replay gate from the criteria audit unaffected. Track A (post-failure) still running. Mainline head 2534bfe before this record commit.
- 2026-09-02T19:16:36Z interactive: track A (post-failure) finished and LANDED ITSELF to mainline (b62a979, then f30c9a7) rather than reporting the branch, so the loop reviewed it AFTER the fact — `drafts/self-review/post-failure-landing-review.md`. THE LANDING STANDS: gates re-run at f30c9a7 exit 0, 8/8, adapter-linkage PASS, ledger integrity verified at 49 records, 77 test blocks, 0 failed; claude/vacuity-sweep is now an ancestor of mainline so it is resolved too. Two claims verified rather than assumed. (a) The ledger append is a RE-SEQUENCING, not a new decision: the protocol-violation-close-reaction record was already committed on the branch at its own sequence 36 in commit 77d8c23, and the merge re-sequenced it to 49 against mainline's 48 — which is why it is not subject to the deferral applied to the server-close-parity and divergence-sweep proposals, whose seven records have no branch history and are genuinely new. (b) The plan.json append_blocker compression (schema-capped at 8192, was at 8176) drops NO claim: diffed word by word, all 33 changed spans are filler or meaning-preserving rephrases, the only numeric change is 48->49, and the one span that could have carried an obligation ("binds the SENDER, not a must-refuse on the recipient" -> "not the recipient") keeps the contrast. TWO FINDINGS THE RECORD DOES NOT CARRY. (1) The changed assertion is right — exclusivity was true only because a converged connection used to ABSORB pushed work, and asserting it today would assert the defect this branch fixed; the replacement (no Terminal AFTER a Failure) is the strongest property still true. But the cost is unrecorded: distinct_semantic_trace_digests 18,755 -> 3,129 (-83%) and closed_terminal_runs 56,777 -> 49 (-99.9%) while explored_schedules went UP 79,920 -> 81,180. The exploration now runs more schedules and distinguishes far fewer behaviours, and the clean-terminal properties are exercised by 49 runs in ONE scenario where they had 56,777 across the space. All twelve limitations entries were checked and none mentions it. No claim about this suite's concurrency coverage should be strengthened on the 81,180 count until someone judges whether 49 is adequate. (2) results.json's revision_note now asserts, in present tense, "SWEEP COUNTERS ARE UNCHANGED ... 79,920 schedules, 315,070 branches, 18,755 distinct trace digests, 56,777/23,143 closed/halted" — every one superseded. Accurate as history, unmarked as history, and UNCATCHABLE: revision_note is one of the 71 inert leaves of 327. A field that looks like a counter attestation, contradicts the document's own counters, and binds nothing. FOLLOW-UP THE LANDING NAMED, NOW DONE: rust/ws-driver/tests/concurrency.rs bounded its three owner loops by POLL_BUDGET=2,000,000 and failed test-release under load with left:179 right:200; all three now use a 60s POLL_DEADLINE, the poll counter kept but only to REPORT in failure messages, every property assertion unchanged. Six release runs green, gates exit 0 (8/8, 77 blocks, 0 failed). Filed as F005 — the THIRD sighting of the class (F002 buffer size, F004 spin count, F005 poll budget), and that repetition is the finding: the rule has been proposed twice and rediscovered twice because it lives in a findings file and binds nothing. All four agent tracks are now landed. Mainline head f30c9a7 before this commit.
