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
   **NEVER STATE EITHER NUMBER WITHOUT ITS CEILING.** These count CASES, not
   behaviours: `evidence/normalization-collisions/audit.json` measured that the
   74 public rows carry only **73 distinct scored observations** (26 of them
   scored on ten scalars with every observation stream absent) and the 49
   handshake cases only **26**, with 27 sharing one and the largest equivalence
   class holding 11. Two SHIPPED scenarios — `us005.pub.0039` (FIN=1) and
   `us005.pub.0066` (FIN=0), sharing no payload octet — produce byte-identical
   rows. A green 74/74 is therefore consistent with an undetected divergence,
   and seven collisions are confirmed by construction.
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
  Java 49/49 with the 16 recorded divergences (**ceilings, measured 2026-09-03:
  73 distinct observations behind the 74, and 26 behind the 49 — these count
  cases, not behaviours**); request sets secret-independent
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
| US-018 | Add thin blocking TCP client and server adapters | passes; fixture made kernel-independent 2026-09-02; `server-close-parity` landed 2026-09-02 as d433c21 — a SERVER now closes the TCP connection once its close-handshake writes have drained and a client never does, matching `SocketChannelIOHelper.java:110-113` (citation re-read at source: `batch(` has exactly one caller, so "server write path only" is the complete call graph). Residual disclosed, not closed: the unit truth table survives deletion of the whole fix, and `pending_chunk.is_empty()` has no failing witness. **DIV-06 closed 2026-09-02** (`claude/div06-handshake-response`, landed ddc148d): the 101 response now carries Java's five fields in Java's TreeMap order. Reading the pinned Java found **a third divergence nothing had ever seen** — `Draft_6455.java:435-436` ECHOES the request's `Connection` value and the port hard-coded `Upgrade`; Autobahn sends exactly `Upgrade` on all 247 cases, so echo and hard-code were byte-identical in everything ever measured. The value looked right because the input made it right. `Date` is handled where determinism falls (format pinned over 22 instants, instant checked as a wall-clock property, ws-core still clockless), and the anti-circularity check holds: the port's six heads vs the pinned jar's six with only `Date` masked is diff exit 0, unmasked nonzero | PRD done (owner-attested); contract | receipt correction is owner's |
| US-019 | Pass both pinned Autobahn conformance modes | `us019-autobahn` 1 ahead; `us019-native-run` at 4c45c6c (rounds 1–2 done: amended AC3 bar implemented and met at 246/247 both roles; finding 7 narrowed). Open against the criteria: AC1's bounded-resources clause unmet; AC4's mutant discrimination OUTSTANDING for no-echo and opcode-swap; **and a clause nobody had recorded — child US-009 AC1 requires "final promoted evidence must replay the complete Rust gate in that [Docker sbx] profile before US-019 or release acceptance", which this Linux cloud session cannot satisfy** | PRD done (owner-attested); readiness only, no current-subject run | P1 self-review, then owner gate |
| US-020 | Close Java and Rust differential divergences | ledger-integrity landed 2026-09-02: delta ledger 48 records, 3 supersessions, unledgered_disagreements recomputed = 0 behind `ledger-gates`; public differential 74/74 for port and live Java. **Audited 2026-09-02 (second pass): AC2 is UNIMPLEMENTED — the five-rank oracle hierarchy exists nowhere in the tree as code or data (one prose hit, `internal/deltaledger/definitions_gap_closure.go:105`), so nothing enforces its clause that Java/Rust agreement cannot override a higher oracle, and the 74/74 IS that rank-4-vs-rank-5 agreement. AC5 is class-INCOMPLETE — of its seven seeded variant classes the 76 `mutctl` mutants cover two by name, reach three only through operators named for other things with no declared mapping, and seed neither Java-quirk emulation nor normalization-collision.** AC1/AC3/AC4 still unjudged. **`divergence-sweep` landed 2026-09-02 as f245ff6** and is the first real AC1 instrument: all 39 keys an Autobahn per-case report carries, partitioned 19 compared / 12 invariant / 8 not-comparable with the union asserted equal to the observed key set, giving 24 dimensions per case per role. 3058 differences, 0 unclaimed, 7 named classes, 6 dimensions at zero divergence, and the overlap disclosed (class_claim_sum 3063, 5 double-claimed, each detailed). Headline counts re-derived independently by the loop from the raw reports and exact: 122 server / 119 client cases where the port sent no Close frame and Java did, 1007x76/1002x42/1000x4 server and 1007x76/1002x40/1000x3 client, 0 code and 0 reason disagreements where both sent. DIV-02's fix landed the same hour (d433c21) but the measurement predates it (port build 518b77aa) — **status is 'fix landed, closure unconfirmed'; an Autobahn re-run is an owner gate**. DIV-01, the largest class, has its fix on the unlanded `claude/post-failure`. **AC3 is now blocked on finding 8: the ledger has no vocabulary for the classes AC3 requires**. **AC3's BLOCKER IS CLEARED and AC5 IS CLASS-COMPLETE** — `claude/ledger-disposition` landed as bceaecd and `claude/ac5-class-completeness` as ca0eb6c. AC3: the ledger gained two orthogonal fields — `disposition` (what the program does: the existing `unresolved`/`rfc-governs` kept verbatim plus `adopt-java`/`fix-in-port`/`intentional-correction`) and `mismatch_class` (AC3's three verbatim). The seven held records are appended at sequences 50–56 through the real path, and the FROZEN PREFIX IS PROVABLY INTACT (loop-verified: records 1–49 byte-identical to the pre-merge mainline, seq 35 and 49 digests unchanged; the mechanism is an optional trailing field, and an attack confirms removing `omitempty` rewrites the chain). **49 pre-vocabulary records remain unclassified and the number is recomputed and published, deliberately NOT pinned to 0.** AC5: of the five bindings the audit had called 'plausibly reachable', **four were REJECTED when measured** against the live Java oracle (only `counter-increment-drop`→consumed-byte holds); identity-precise seeds replace them and the rejections are kept in code. Both missing classes are seeded and BOTH are collisions — the normalization-collision reproduces DIV-02 (differential field-diff EMPTY over 97 requests, real-socket witness 0→101), and one Java-quirk-emulation seed is one the differential STRUCTURALLY cannot see, since emulating Java makes Java agree. **A second collision was found in the repo's own existing evidence**: the US-013 AC5 event-order seed moves nothing, because `Events []` and `Transitions []` are separate arrays (`internal/lab/oracle.go:315,:325`) so cross-array ordering is erased. **AC2 ALSO HAS A MECHANISM** — `claude/oracle-hierarchy` landed 2026-09-02 as d3110c0: `internal/oraclerank` types the five ranks, computes the governing rank as the strongest that gave a verdict, and exposes the guarded reading a consumer must use to turn Java/Rust agreement into parity. **First run found 38 real overrides of 589 agreements** — 20 Autobahn (case, role) pairs where both graded NON-STRICT while the suite's own `expected` map declares an OK arm (re-derived independently by the loop from the raw reports, exact), and 18 public scenarios where the RFC-strict state is `closed` and ranks 3/4/5 all say `open`. Two of its three BLOCKING findings are against ITS OWN construction: rank 3 is empirically indistinguishable from rank 4 (32 shared propositions, 0 disagreements) and rank 5 (74, 0). Rank binding is stated per rank — **rank 1 is bound to committed HUMAN READINGS, not the RFC text, which is absent from the repo**. Ceiling: OBSERVED; the overrides are an open question, not a verdict that the port is wrong. **RANK 3 MADE INDEPENDENT 2026-09-03** (`claude/oracle-rank3-independence`, landed f43843e): `internal/rfcneutral` transcribes RFC 6455 sections 5 and 7 into 15 deciding rules and 5 abstentions applied to each scenario's own inbound octets, importing nothing from `internal/corpora`, `java-oracle` or `internal/deltaledger`. Loop-verified from the register: 3-vs-4 NOT_DISTINGUISHED 32/0 -> **DISTINGUISHED 79/18**; 3-vs-5 74/0 -> **DISTINGUISHED 47/18**; overrides 38 -> 39. **But 1-vs-3 became NOT_DISTINGUISHED 66/0, a NEW BLOCKING finding** — a rank 3 genuinely derived from RFC 6455 is indistinguishable from rank 1, which is a recorded human reading of the same document. It also indicts its own apparatus twice: JOIN DEGENERACY (the mapping key is computed from rank 3's own verdict, so across all 42 keys disagreement was STRUCTURALLY IMPOSSIBLE — the original 32 co-votes were never a measurement) and PROJECTION COLLAPSE (640 propositions carry 26 distinct opinion tuples, and the collision finding now fires on two DISTINGUISHED pairs — rank 1's 18 disagreements are one question asked 18 times). **All 15 rules are UNVERIFIED against the RFC text, which is still absent from the repo** | PRD done (owner-attested); 4 files | P2: implement AC2's hierarchy; make AC5 class-complete (normalization-collision first); settle the ledger disposition vocabulary, then append the 7 drafted records |
| US-021 | Close property, fuzz, and runtime evidence | NOT "not started" — corrected 2026-09-02 against the real criteria: `rust/ws-core/tests/adversarial_properties.rs` holds 28 tests over 685 lines, `rust/ws-driver/fuzz-seeds/us017/` holds the retained corpus, and the gates run debug and release. What is missing is not the evidence but the JUDGMENT: AC3 demands a pinned engine/toolchain, dictionary/corpus digest, a minimum bounded campaign, timeout/OOM/crash policy, artifact capture, replay command and an exact target manifest per target, and none of that has been assembled or checked. **JUDGED 2026-09-02** by `claude/us021-fuzz-pinning` (landed 83ee895), and the answer is NOT MET: three of AC2's seven target families have NO generative target (handshake client, handshake server, owner-driver command/byte schedules); fragment/control and close/EOF are shared coverage inside another family's target; only frame-decode and message/UTF-8 are real. Verified independently by the loop: `cargo fuzz --version` exit 101, **zero** `fuzz_target!`/libfuzzer anywhere under `rust/`, **zero** occurrences of "shrink" across `rust/ws-core/tests/` — so AC1's required shrinkers are absent too. Two substitutions refused (a seed corpus for a campaign; an exhaustive enumerator for a fuzz target) and one trap caught: `family_seed_corpus_anchors` DOES read the us010/us011 handshake seeds and feeds them to the frame decoder as post-handshake bytes, giving the handshake parsers no coverage at all. AC3 pinning is now a checked artifact (`assurance/fuzz/manifest.json` + `internal/fuzzpin` + `cmd/fuzzpinctl`) whose `-check` exits **1 by design** with 4 blocking findings; deliberately NOT wired into `make gates` so it does not redden sibling branches — wire it when US-021 is scheduled to close. AC1/AC2/AC3 NOT MET, AC4 needs both platforms so it cannot be done here, AC5 not assessable above AC2. Grade: bounded | PRD done (owner-attested); 5 files | P3 |
| US-022 | Pass normalized mutation and protected evaluation | not started — CONFIRMED 2026-09-02 against the criteria: no `evidence/mutation` tree, zero PIT runs, zero cargo-mutants runs. Seed material that is NOT this story: `corpora/hidden/manifest.json` and `corpora/sealed/manifest.json` (US-005 outputs) and the 76 `mutctl` mutants (US-012..US-016 AC5). Nothing implements AC1's single signed denominator or AC4's separate identities, filesystems, caches, credentials and signing keys | PRD done (owner-attested); 6 files | P3 |
| US-023 | Freeze the complete parity candidate | not started — audited 2026-09-02. AC3's catalog IS seeded: `assurance/formal/proof-targets.json` holds 10 targets, 21 production symbols and 98 migration bindings, with exact Java anchors (file/line/sha256) and exact Java method signatures per symbol. Missing: the canonical machine-readable formal-coverage report, the human-readable report, and the per-side strength/method/bounds/assumptions/trusted-base/digests/refinement/counterexample record. **Ceiling now on the board: all 21 symbols read `PLANNED_PENDING_RESOLVER`, all 98 bindings `rust_identity_verified: false`, `resolver_verified_at: null`; the strongest linkage evidence (`evidence/linkage/rust-identity-verification.json`, 45/47 rows) self-labels 'declaration-scan (reviewed-glancer class), not rust-analyzer semantic resolution'. No formal obligation here binds to a resolver-verified shipped Rust symbol.** Also unreconciled: 10 targets / 11 property claims here vs master US-008's 24-obligation denominator. **`java-formal-bindings` landed 2026-09-02 as 66cefbd**: the 24-obligation catalog is vendored from the Codex plane (blob-identical, sha256 21112518..., asserted in a test), the Java column's 0/24 is explained (all 24 DISCONNECTED, synthesised per-method paths existing in no tree, one whole-archive `source_sha256` shared by all 24), and 4/24 now carry falsifiable Java evidence — span-resolved declarations, byte-exact pinned-JAR observations, and per-clause canaries with unmutated controls (10 declared, 10 killed). **The denominator does not move: 0/24 at required strength, refinement 0/24, aggregate 0/24**, observed strength EXECUTED_OBSERVATION_WITH_MUTATION_SENSITIVITY against a required PRODUCTION_REFINEMENT, and the tool prints the ceiling beside the numerator. See finding 9. **CORRECTED 2026-09-02 — see `drafts/self-review/findings/F006-a-vendored-catalog-judged-against-the-wrong-plane.md`. The claim landed in 92556bd that the denominator is 'unbound on BOTH sides' is WRONG on the Rust side and on the pins.** The catalog is vendored byte-identically from `origin/codex/race-catchup` and is bound to THAT plane: all 4 distinct Rust `source_path` values exist there, the Codex plane ships crates named `connection-core`/`websocket-driver`/`websocket-testee` (exactly what the namespaces name), and 4 of 5 `denominator_basis` pins match the Codex plane's CURRENT files byte-for-byte (the fifth matches a Codex commit it has since moved past). `corpora/frame/codec.json` 'exists in no tree' only because it exists on the Codex plane, which is read-only from here. **What SURVIVES, and is now sharper for being isolated: the JAVA column is genuinely unbound on EVERY plane** — 15 synthesised paths treating a method as a file, existing on neither Claude nor Codex, one whole-archive `source_sha256` shared by all 24, all `DISCONNECTED`. The real owner question is therefore not 'repair the pins' but whether a Codex-plane catalog can serve as the Claude plane's denominator at all. **ANSWERED 2026-09-03 by `claude/catalog-plane-correspondence` (landed f8c748d): today, NO — and NO correspondence is established.** Codex `connection-core` (`[lib] websocket_core`) to Claude `ws-core` is SHARED_ANCESTRY_ONLY (the rename is pure but its owner decision governs THIS plane's scaffold and names no Codex crate; since the fork Codex replaced `framing.rs` with `frame/{decode,encode,mask}.rs`); Codex `websocket-driver` to Claude `ws-driver` is BORROW_RECEIPT_RECORDS_AN_ADAPTATION (three mechanisms replaced, one disposition dropped); `websocket-testee` is borrowed and the catalog never names it. Per symbol, `apply_mask_in_place(..., payload_offset)` became `apply_mask(payload, key)` with NO OFFSET — which is exactly what `obligation.mask-equation` asserts. **No row reaches ESTABLISHED_BY_OWNER_DECISION and 24/24 still block**, with corrected reason codes (`..._ABSENT_FROM_THIS_PLANE`, `..._NAMES_NO_CRATE_SHIPPED_BY_THIS_PLANE`) and the cause added beside the symptoms. Owner options: (a) declare a correspondence, (b) re-vendor and rebind, (c) separate denominators — and explicitly NOT (d) a name-normalising rule. Also found: the two planes' migration maps share 47 identical Java ids but **33 rows name DIFFERENT Rust identities** — different target designs, not two spellings. Original (partly wrong) claim retained below for the record:** Loop-verified from the committed bytes: four of the catalog's five own `denominator_basis` pins are wrong (`proof-targets.json` pinned `fa75348c…`/hashes `bad1e069…`; `compatibility-surface.json` and `semantic-id-migration-map.json` likewise drifted; `corpora/frame/codec.json` EXISTS IN NO TREE; the one that matches is a 705-byte placeholder) — and **0 of 24 `rust_bindings` `source_path` values exist**, naming crates `websocket_core`/`websocket_driver` while the workspace ships `ws-core`/`ws-driver`/`ws-oracle-harness`/`ws-testee`. With track D's finding that all 24 `java_bindings` share ONE whole-archive digest, the Java column, the Rust column and four of five basis pins are each unbound. Also: 13/24 obligations map onto no proof target, 4/10 targets onto no obligation, and SEVEN obligations collapse onto one Java construct (24 obligations over 15 keys). Rust coverage computable here is 0/24; the 19/24 in the design doc has no artifact in this tree. Both AC3 reports exist with the no-hiding rule structural (the aggregate is an INTERSECTION, not a weighted sum; `freeze-gate` blocks 24/24 naming each obligation's reasons) | PRD done (owner-attested); 9 files; every gate BLOCKED in its own register | P3 |
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
| Public corpus differential | 74/74 cases, zero non-runtime diffs — **but only 73 distinct scored observations** (`evidence/normalization-collisions/audit.json`); two shipped scenarios collide | 74/74 normalized scenarios equal |
| Live handshake exam | 49/49 cases — **but only 26 distinct scored observations**, 27 cases sharing one, largest class 11 | client/server handshake evidence |
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
- 2026-09-02T19:27:34Z interactive: WAVE 2 — eight parallel Opus agents launched, each in its own worktree, each drawn from a recorded finding rather than invented. Every prompt carries the same standing constraints: RED-first (delete each check and read the failure), never weaken a check, hunt "existence standing in for identity", liveness guards are wall-clock deadlines never counts (F005), state the honest ceiling in the claim vocabulary, name what was NOT done, push the branch and DO NOT merge to mainline (track A merged itself in wave 1), and never trigger the owner gates (no AWS, no benchmark, no Autobahn re-runs). Ownership is partitioned so the tracks do not collide: exactly one track may touch the ledger, one may touch results.json, one may touch the ws-testee handshake. Tracks: (E) `claude/ledger-disposition` — finding 8, design a disposition vocabulary that can express US-020 AC3's Java-quirk / Rust-defect / underspecified classes plus the adopt-vs-correct axis the foundation schema already defines and the live one does not, then append the SEVEN waiting records (server-close-parity + the sweep's six) through the real append path, without rewriting the prefix frozen through sequence 35. (F) `claude/oracle-hierarchy` — finding 4, build the five-rank adjudication AC2 describes and make the override rule bite; the 74/74 differential this repo cites IS the rank-4-vs-rank-5 agreement AC2 says cannot settle a question, so the track must say bluntly which ranks are content-bound and which are declaration-bound. (G) `claude/ac5-class-completeness` — finding 5, seed the two AC5 classes that have no variant at all (Java-quirk emulation, normalization-collision — the latter being exactly what would have caught DIV-02 by construction), test whether the three implicit operators really discriminate their claimed class, and make class-completeness checkable rather than a comment. (H) `claude/div06-handshake-response` — DIV-06, the 101 response omitting Server and Date and not sorting headers on 247/247 server cases, the one sweep class still checkable against mainline source without an Autobahn re-run; includes correcting a doc comment that cites a Java method as authority for 3 fields while it writes 5. (I) `claude/host-sized-fixture-detector` — make F002/F004/F005's shared class DETECTABLE instead of rediscoverable, proven by firing on F004's and F005's real pre-fix text from git history; a detector that cannot catch the three instances that motivated it is not a detector. (J) `claude/concurrency-coverage-disclosure` — the post-failure review's two findings: answer whether 49 clean-terminal runs in one scenario is adequate where 56,777 across the space used to be (distinct traces fell 18,755 to 3,129 while schedules ROSE), and give revision_note a bound revision identity so a superseded counter block stops being an inert leaf that masquerades as current. (K) `claude/us021-fuzz-pinning` — finding 1, census AC2's six target families honestly (a property test is not a fuzz target, a seed corpus is not a campaign), assemble AC3's seven per-target pins with a replay command actually executed, and make unavailable tooling BLOCK rather than skip, following the ledger gate's own refusal precedent. (L) `claude/us023-formal-coverage` — findings 7 and 9, reconcile the 10-target and 24-obligation denominators as a checked mapping, diagnose the five obligations declared against the wrong Java symbols and propose corrections WITHOUT editing the byte-pinned vendored catalog, build AC3's two coverage reports with the no-weighted-aggregate-hides-a-blocker rule enforced mechanically, and keep visible the ceiling that no formal obligation here binds to a resolver-verified shipped Rust symbol. Mainline head 57e881c, tree clean, PR #4 mergeable.
- 2026-09-02T20:32:48Z routine (goal-loop firing at 20:22:17Z): top-of-queue items were all in flight with the four remaining wave-2 agents, so the unit taken was keeping PR #4 mergeable, plus this board catch-up. FOUR WAVE-2 TRACKS LANDED since the last entry, each reviewed by re-deriving its load-bearing claim rather than accepting the report. (I) `host-sized-fixture-detector` -> 48db05f: `make -C rust fixture-guard` refuses a count-shaped liveness guard in a Rust test fixture, discriminating on the INCREMENT not the shape (a counter incremented every iteration is host speed; one incremented on progress is a goal — which is what separates the two halves of `while disposed < 20 && polls < POLL_BUDGET`). VERIFIED BY THE LOOP: F004's and F005's real pre-fix blobs were restored into the live tree and the gate went RED on all four guards, then green on restore. Its own RED round had found three parts that stayed green when deleted. Named blind spot, a real instance: loopback.rs feeds `max_polls` into the PRODUCTION bound at io_loop.rs:188, one indirection outside scope; recorded in F005, whose stale "nothing does that today" sentence is now corrected. (F) `oracle-hierarchy` -> d3110c0: US-020 AC2 finally has a mechanism, and it found 38 overrides of 589 Java/Rust agreements on its first run. The loop re-derived the 20 Autobahn pairs straight from the raw per-case reports in throwaway Python — exact, including 6.4.1's OK arm requiring [["timeout","A"]] while both implementations produced [["timeout","A"],["timeout","B"]]. Two of its three BLOCKING findings indict its own construction (rank 3 empirically indistinguishable from ranks 4 and 5), and rank binding is stated per rank rather than implied. (H) `div06-handshake-response` -> ddc148d: closed DIV-06 and found a THIRD divergence no sweep could have found — Java echoes the request's Connection value, the port hard-coded Upgrade, and Autobahn sends exactly Upgrade on all 247 cases. Every citation re-read at source by the loop, including the "; " duplicate-join at Draft.java:120-122 and the empty-string return for an absent field at HandshakedataImpl1.java:59-65. (K) `us021-fuzz-pinning` -> 83ee895: US-021 judged NOT MET with a check that says so; the loop independently confirmed cargo fuzz exit 101, zero fuzz_target!/libfuzzer under rust/, and zero "shrink" in the ws-core suites. PR #4 was conflicted twice more by these landings and resolved both times (545dd25, 705a55a); the second was a real semantic union — the branch had MOVED EchoPolicy into io_loop while mainline's DIV-06 landing added server_date_epoch_seconds beside the old local copy — and merge-tree against mainline now exits 0. Gates read at every landing: exit 0, 8/8, ledger integrity verified, 0 failed (79 blocks on mainline, 100 on the us019 merge). NEW OWNER ACTION, exact and recorded: fetch https://www.rfc-editor.org/rfc/rfc6455.txt, require sha256:765775326aee...0fa3b and 162067 bytes, commit at third_party/rfc6455/rfc6455.txt — egress to rfc-editor.org is denied here (proxy answered CONNECT with 403) and until it lands, oracle rank one is bound to committed HUMAN READINGS rather than the normative text, so a misreading passes that gate unchanged. The upgrade computes automatically once the file exists; no code change. Four agents still running (ledger disposition vocabulary, AC5 class completeness, concurrency coverage disclosure, US-023 formal coverage); `claude/ac5-class-completeness` is pushed but has not reported, so it is NOT landed. No corpus shift anywhere: port 74/74 and 49/49, live Java the same, request digest e00d968f... unchanged. No owner gate crossed: no AWS, no benchmark, no Autobahn re-run. Mainline head 83ee895 before this record commit.
- 2026-09-02T21:30:48Z interactive: THREE MORE WAVE-2 TRACKS LANDED (seven of eight now in), each reviewed by re-deriving its load-bearing claim. (L) `us023-formal-coverage` -> 92556bd. The task was to reconcile two denominators; what it established is larger and the loop verified both halves from the committed bytes: FOUR OF THE CATALOG'S FIVE OWN denominator_basis PINS ARE WRONG (proof-targets.json pinned fa75348c... hashes bad1e069...; compatibility-surface.json and semantic-id-migration-map.json likewise; corpora/frame/codec.json exists in NO tree; the one that matches is a 705-byte placeholder) and 0 OF 24 rust_bindings source_path VALUES EXIST, naming crates websocket_core/websocket_driver while the workspace ships ws-core/ws-driver/ws-oracle-harness/ws-testee. Put with track D's finding that all 24 java_bindings share ONE whole-archive digest: the Java column, the Rust column and four of five basis pins are each unbound, so any coverage number computed against this catalog measures a document that binds nothing. Also 13/24 obligations map to no target, 4/10 targets to no obligation, and SEVEN obligations collapse onto one Java construct. Its first deletion sweep was INVALID (mutations broke compilation, and a build failure proves nothing) — re-run properly it found ELEVEN checks that survived deletion, then six more; final 47 attacks, 0 survivors. (G) `ac5-class-completeness` -> ca0eb6c. FOUR OF FIVE claimed operator-to-class bindings REJECTED when measured against the live Java oracle; only counter-increment-drop -> consumed-byte holds, and the rejections are kept in code so they cannot evaporate. Both missing classes seeded and both turned out to be collisions: normalization-collision reproduces DIV-02 (differential field-diff EMPTY over 97 requests while a real socket reads 0 -> 101), and one Java-quirk-emulation seed is one the differential STRUCTURALLY cannot see because emulating Java makes Java agree — registered as a collision with its blind judges named, which is AC2's clause turned into a check on the day AC2 got its mechanism. AND A SECOND COLLISION IN THE REPO'S OWN EXISTING EVIDENCE: the US-013 AC5 event-order seed moves nothing, because Events [] and Transitions [] are separate arrays (internal/lab/oracle.go:315 and :325) so cross-array ordering is erased — loop-confirmed in the model. Class names are now parsed OUT OF the PRD, so growing it an eighth class is reported. (E) `ledger-disposition` -> bceaecd. Two orthogonal fields, because the seven held records prove one enum cannot work (RFC silence on handshake field order yields both a record the port keeps deliberately and one it still owes an answer for — same class, different disposition). Seven records appended at sequences 50-56 through the real path, each reproducing its draft's delta_id from the draft's own six digest preimages. THE FROZEN PREFIX IS PROVABLY INTACT: loop-verified that records 1-49 are byte-identical to the pre-merge mainline with seq 35 and 49 digests unchanged. 49 pre-vocabulary records stay unclassified and the number is RECOMPUTED AND PUBLISHED, deliberately not pinned to 0 — that is the fake gate unledgered_disagreements used to be. Its rejected alternative is worth keeping: 49 superseding records is not merely heavy but concretely broken, since supersededSubjects would mark the originals withdrawn and the censuses refuse a superseded record as coverage, driving unledgered_disagreements off zero. Two of its 15 attacks did not isolate and it says so. Gates exit 0 at all three landings, 79 test blocks, 0 failed; deltaledgerctl --check exit 0 at 56 records. NEW OWNER ACTIONS: (i) authorize an Autobahn re-run of the 247-case pinned manifest against current mainline, BOTH roles, to close ledger sequences 51 and 52 — their per-case sets ARE the acceptance criteria; (ii) owner rulings for ledger sequences 53 (invalid-UTF-8 reason stall, reproducing it means holding a misused socket) and 55 (server 101 Server/Date, a clock in a deterministic core); (iii) the RFC 6455 text fetch already recorded. One agent still running (concurrency coverage disclosure), which owns results.json and will conflict with E's re-binding of preregistered_plan.sha256. PR #4 checked and still cleanly mergeable. No corpus shift, no owner gate crossed. Mainline head bceaecd before this record commit.
- 2026-09-02T21:42:23Z interactive: container restart lost wave-2 track J (concurrency coverage disclosure) before it pushed — the work is gone, no branch, nothing recoverable; every other branch and all of mainline survived. WAVE 3 launched: eight Opus agents, same standing constraints as wave 2 (RED-first with the explicit note that a mutation breaking COMPILATION proves nothing, never weaken a check, hunt existence-standing-in-for-identity, wall-clock liveness guards now enforced by `make -C rust fixture-guard`, honest claim ceilings, name what was NOT done, push the branch and DO NOT merge, never trigger the owner gates), and the same ownership partition so they cannot collide. Every track is drawn from something wave 2 surfaced rather than invented. (J2) `concurrency-coverage-disclosure` — the relaunch, told to push early after the loss. (M) `div05-close-overtakes-echo` — ledger sequence 54's own stated precondition is a reproduction, which is work rather than an owner ruling; Autobahn scores 7.1.6 INFORMATIONAL for both implementations and the public corpus has no such race, so no existing gate sees it, which is exactly why it is worth doing. (N) `us021-missing-targets` — write the three fuzz targets that do not exist (handshake client, handshake server, owner-driver command/byte schedules AT THE DRIVER SEAM, not the ws-core seam the existing family uses) plus a real shrinker, registered in the hostile manifest without weakening it; the engine block must REMAIN since cargo-fuzz is absent. (O) `oracle-rank3-independence` — the new hierarchy indicts itself twice, rank 3 being empirically indistinguishable from ranks 4 and 5 because all 74 public expectations derive from a model whose own doc comment says it mirrors pinned Java; derive neutral expectations from the standard instead, and if rank 3 still never disagrees, REPORT THAT rather than manufacture a disagreement. (P) `adapter-residuals` — the `pending_chunk.is_empty()` operand with no failing witness (constructible on the pipelined carryover path) and the fixture detector's named blind spot, `max_polls` feeding the production bound one indirection away, with the genuine difficulty that `max_polls: 0` and `: 1` are deliberate tests OF the budget mechanism and must keep working. (Q) `normalization-collision-audit` — three collisions have now been found BY ACCIDENT (DIV-02, the inert event-order seed, and Java-quirk emulation being structurally invisible), so the population is unknown; enumerate the normalization surface, decide each candidate by construction rather than argument, and state the honest bound this puts on the 74/74 and 49/49 headline numbers. (R) `catalog-rust-column` — resolve all 24 obligations to real shipped Rust symbols or record that none exists, explicitly WITHOUT inventing a websocket_core-to-ws_core normalising rule, which is the shortcut that would make an unbound column look bound; and characterise the four bad denominator pins precisely, since "drifted" and "never bound" are different diagnoses and the fourth names a file that may never have existed. (S) `legacy-record-adjudication` — the 49 pre-vocabulary ledger records cannot be classified in place (frozen prefix) and 49 superseding records is concretely broken (the censuses refuse a superseded record as coverage, driving unledgered_disagreements off zero), so find the shape that classifies them without rewriting or breaking the censuses, and make records_without_mismatch_class fall while staying RECOMPUTED and never pinned. Mainline head df05aae, tree clean, PR #4 mergeable.
- 2026-09-02T21:52:42Z interactive: SECOND container restart, minutes after wave 3 launched, killed all eight of its agents before ANY had pushed. Combined with the first restart that took wave-2 track J, roughly nine agent-hours produced nothing recoverable. DIAGNOSED RATHER THAN RELAUNCHED BLINDLY, because relaunching into the same condition would have repeated it: `git worktree list` showed 21 worktrees holding 8.9 GiB, of which 7.2 GiB was cargo target directories, against ~12 GiB of writable allowance. Eight concurrent agents each building a ~1.4 GiB target tree is ~11 GiB — i.e. the parallelism was almost certainly its own cause, and the timing fits (the second restart came minutes after launching eight). Cleanup: every landed track's worktree removed and its registration pruned (they were pure waste — the branches are pushed and merged), stale worktree-agent/* and us019-merge* local branches deleted. Result: 21 worktrees to 1, 8.9 GiB to 4 KB, free space 12 GiB to 20 GiB, tree clean. Wave 3 RELAUNCHED AT FOUR AGENTS RATHER THAN EIGHT — "as many as possible" now has a measured meaning, and four target trees is about 6 GiB against 20 GiB free, a real margin instead of a hope. Each prompt now opens with PUSH EARLY AND OFTEN, an instruction that is worth more than the parallelism it costs: the loss was never the compute, it was that nothing was pushed, and a stub commit in the first few tool calls would have saved all of it. Each also carries the disk lesson (prefer targeted `cargo test -p <crate>` over full workspace rebuilds). The four relaunched are the highest-value tracks of the eight: (Q) normalization-collision-audit — three collisions found so far were ALL accidents, so the population is unknown, and the deliverable that matters most is the honest bound this puts on the 74/74 and 49/49 headline numbers; (J2) concurrency-coverage-disclosure — now lost twice, hence the doubled push instruction; (N) us021-missing-targets — the three fuzz targets US-021 proved absent, at the driver seam the existing family does not reach; (S) legacy-record-adjudication — the 49 pre-vocabulary ledger records that cannot be classified in place and for which 49 superseding records is concretely broken. DEFERRED to a later wave, unstarted and not lost: div05-close-overtakes-echo (ledger seq 54's reproduction), oracle-rank3-independence (the register's two self-indictments), adapter-residuals (the pending_chunk witness and the max_polls blind spot), catalog-rust-column (24 unbound Rust bindings and four bad denominator pins). Mainline head 2c63205, tree clean, PR #4 mergeable, nothing lost from the repository itself — every wave-1 and wave-2 landing is intact.
- 2026-09-02T22:24:38Z interactive: THIRD container restart, and MY DISK DIAGNOSIS WAS WRONG. I said last entry that the parallelism was almost certainly its own cause — 8.9 GiB of worktrees against ~12 GiB free — and relaunched at four agents on that basis. The four then died to a restart anyway, with 18 GiB free, 14 of 15 GiB RAM free, and only 1.9 GiB of worktrees. The evidence does not support the disk story; the restarts are environmental and not caused by the load. Correcting it here rather than leaving a plausible-sounding wrong explanation on the record, which is exactly the failure mode this program keeps auditing out of its evidence. BUT THE MITIGATION WORKED, AND IT IS THE PART THAT MATTERED. Every one of the four agents had pushed before dying, because their prompts opened with PUSH EARLY AND OFTEN, so this restart cost re-orientation instead of everything: `claude/normalization-collision-audit` at e555425 (2 commits, and it had already found a lead — the error-row projection drops six top-level keys, which is precisely the unrepresentable-distinction category the audit hunts); `claude/concurrency-coverage-disclosure` at fe736b3 (3 commits, the 49 clean-terminal runs measured and both halves started); `claude/us021-missing-targets` at 1b73f13 (3 commits, all three generative targets plus a shrinker pin in some form); `claude/legacy-record-adjudication` at 5986426 (4 commits, 11 files — all 49 records filed, 19 discrimination probes, and it had stopped mid-way through isolating two attacks that did not isolate, which is the honest place to be stopped). Nine agent-hours were lost across the first two restarts; roughly none across this one. All four RELAUNCHED AS CONTINUATIONS rather than restarts: each prompt names its own branch, its own commits, and what it had already established, and tells it to read its own work before redoing anything. The push discipline stays doubled. Mainline head fde0c5e, tree clean, PR #4 mergeable, every wave-1 and wave-2 landing intact.
- 2026-09-02T22:28:43Z routine (goal-loop firing at 22:22:46Z): four agents hold the top-queue items, so the unit taken was the deferred `catalog-rust-column` track's first question — are the four bad `denominator_basis` pins DRIFTED or NEVER BOUND? — and the answer overturned a finding I landed. Filed as F006. Every one of the five pins was once correct, so not fabricated; but the decisive test was which TREE they are correct about, and four of five match `origin/codex/race-catchup`'s CURRENT files byte-for-byte. Following that: all 4 distinct Rust `source_path` values in the catalog exist on the Codex plane, which ships crates named connection-core, websocket-driver and websocket-testee — exactly the namespaces the catalog names; and `corpora/frame/codec.json` "exists in no tree" only because its creating commits (5307535, 8e5b19b) are reachable from `origin/codex/race-catchup` and nothing else. **So the claim I verified and landed in 92556bd — that the 24-obligation denominator "is unbound on BOTH sides" and that "any coverage number computed against it measures a document that binds nothing" — is FALSE as written, in the more damaging direction: it indicts the Codex plane's work for a mismatch created by reading its document against someone else's tree.** The Java-column half SURVIVES and is sharper isolated: its 15 synthesised paths treat a METHOD as a file and exist on NO plane, Codex included, with one whole-archive digest across all 24 — plane-independent and real. Board row corrected in place with the original claim retained rather than deleted. F006 files a NEW class beside this program's usual one: the recurring defect is existence standing in for identity, and this is its mirror image, ABSENCE STANDING IN FOR DEFECT — a lookup that fails against the wrong subject, read as proof the subject is broken. Same root: running a check without first pinning what it is a check ON. The portable rule: before concluding a document's references are unbound, establish which tree the document is ABOUT and test against that; a vendored artifact is about its origin until something rebinds it. What this changes for the owner: not "repair the pins", which point correctly, but whether a Codex-plane catalog can serve as the Claude plane's denominator at all — master US-008 counts its 24 obligations, and measuring this plane against it needs a plane-crossing correspondence (codex connection-core to claude ws-core, and so on) that nobody has established. That is also exactly the name-normalising rule the deferred catalog-rust-column track was told NOT to invent, and the instruction is better founded now than when I wrote it: the mapping is not a shortcut to avoid but a real decision to escalate. No gates run this unit (read-only investigation plus records); no owner gate crossed; no corpus touched. Mainline head 7b42cc2 before this record commit.
- 2026-09-03T00:07:25Z interactive: ALL FOUR WAVE-3 TRACKS LANDED and confirmed contained in mainline; nothing was lost to the three restarts beyond re-orientation, because every branch had pushed. (N) `us021-missing-targets` -> 85193d5: the three absent AC2 families now have real generative targets (handshake client/server at 16,300 cases each generating modeled heads predicted from the MODEL without re-parsing; owner-driver schedules at 9,000 cases at the DRIVER seam AC2 names, not the ws-core seam the old family used), plus dedicated fragment/control and close/EOF targets and two shrinkers with stated domain and bound. The anti-cheat check is what mattered and the loop ran it: `cmd/fuzzpinctl` and `internal/fuzzpin` are BYTE-IDENTICAL to mainline and no shipped Rust source is touched, so the three FUZZ_TARGET_ABSENT blocks cleared because the targets are real. Four planted defects caught at specific case indices while the existing suite passed 14/14 on every one; one plant MISSED by the whole suite and unfixable-by-test (the mutated check is unreachable), reported rather than papered over. (Q) `normalization-collision-audit` -> c8459fb: the systematic hunt, and it puts a MEASURED CEILING UNDER THE HEADLINE NUMBERS. Five projections enumerated with what each actually compares (behaviour.envelope_error compares NOTHING — the transcript cannot even be loaded; behaviour.output_limit compares error.code alone). Seven collisions CONFIRMED by running the real harness through the real comparator, five candidates left explicitly HYPOTHESIS. NC-04 is not synthetic and the loop verified it at the byte level: us005.pub.0039 opens 0x80 (FIN=1) with payload fef541, us005.pub.0066 opens 0x00 (FIN=0) with payload ad6d44 — a finished and an unfinished continuation sharing no payload octet — and their `expected` blocks are BYTE-IDENTICAL. So 74/74 has a ceiling of 73 distinct observations and 49/49 a ceiling of 26, with 27 cases sharing one and the largest class holding 11. These are claims about CASES, not behaviours. Grade BOUNDED; the enumeration is not proved complete and says so. (S) `legacy-record-adjudication` -> 665d768: all 49 pre-vocabulary records filed — 26 java-quirk, 20 underspecified-behavior, 2 rust-defect, 1 honest evidence-does-not-settle-it (seq 19, owner action named), 0 unexamined. Loop-verified: the ledger file is BYTE-IDENTICAL to pre-merge mainline and `records_without_ac3_class` appears nowhere as a const. Each adjudication binds by recomputed identity, record digest AND a unique verbatim rationale quote, so a classification cannot float free of what it classifies. It surfaced that sequences 14/15/16 were contested in-chain while the document said so only in `argument` prose, the one field nothing checks — RED first: with the new rule and the document unchanged, the COMMITTED document was refused naming exactly 14, 15, 16. 41 attacks, 41 red, with 8 red-by-message-only NAMED rather than counted, and D06 revealed not to be a redundancy at all (deleting the chain-length refusal makes the gate PANIC). (J2) `concurrency-coverage-disclosure` -> 58f3aa4: the answer is NO and the true figure was 18, not 49 — those 49 runs carried only 18 distinct semantic traces. It also corrected the comparison in the harder direction: all 56,777 old clean-terminal runs were in `abnormal-teardown`, whose clean convergence the harness records as an artifact of the EOF-coalescing defect, so the landing appended a space rather than shrinking one and the honest sequence is 0 genuine clean-lifecycle runs, then 49, then 18 behaviours. Restored by APPENDING a scenario inside the preregistered cap with plan.json byte-identical: 1,176 clean-terminal runs, 403 clean digests, 4,587 whole-space traces, limitations 12 -> 13. GOVERNANCE FINDING: the drop had already been named as carried follow-up BP1 inside the protected owner decision us017-c6-layer-split-owner-decision-2026-08-28 ("1108 to 49 … a 96 percent coverage drop") and sat there a week while the evidence document said nothing; the new ceiling cites it and the check RESOLVES the citation. WAVE 4 launched, the four deferred tracks, all with the push-early discipline: div05-close-overtakes-echo (ledger seq 54's own stated precondition), oracle-rank3-independence (told to REPORT continued indistinguishability rather than manufacture a disagreement, and to check whether collisions explain the co-voting), adapter-residuals (the pending_chunk witness and the max_polls blind spot, with the two roles of max_polls to separate), and catalog-plane-correspondence — REFRAMED BY F006 from "repair the Rust column" to establishing whether Codex `connection-core` corresponds to Claude `ws-core` at all, fixing the reason codes that mis-describe a plane mismatch as a broken catalog, and repairing the two test failures that have been miscounted as environment baseline all session. Gates exit 0 at every landing, 87 test blocks, 0 failed. Mainline head 58f3aa4, tree clean.
- 2026-09-03T00:25:22Z routine (goal-loop firing at 00:22:41Z): four agents hold the wave-4 tracks, so the unit taken was the collision audit's five UNDECIDED candidates — nobody owns `internal/normcollide` and each undecided candidate is a potential further bound on the headline numbers. Filed as F007. Reading the ws-core source settles or nearly settles THREE of the five, and two of those look like REFUTATIONS, which matters because a refuted candidate says the observation DOES carry that distinction and so narrows what the 73-of-74 and 26-of-49 ceilings can be blamed on. **CAND-UTF8 is provably empty**: `Charsetfunctions::string_utf8` is `String::from_utf8(bytes).map_err(|_| Utf8DecodeError)` (message.rs:187-189) with no `from_utf8_lossy`, no U+FFFD and no replacement anywhere under rust/ws-core/src, so UTF-8's injectivity on valid input means distinct accepted octet sequences give distinct Strings while invalid ones yield no text event at all — a proof about a total function, stronger than a sample. **CAND-WIREBYTES points to REFUTED** on two sites: ws-core deliberately ACCEPTS non-minimal extended lengths (framing.rs:37-39 records that Codex's non-canonical-length rejection was STRIPPED because Java accepts them, derive.go:400-420), so a pair CAN be built where an RFC-strict codec would have made the candidate empty; and `frames[].wire_bytes` is the consumed span (`frame.wire_bytes = span.size`, connection.rs:662), so a non-minimal header of two extra octets should move it. **CAND-CHUNKING** the audit already reasoned REPRESENTED and listed anyway, which was the right instinct. CAND-TRANSPORT and CAND-CROSSARRAY are correctly undecidable in that package and stay HYPOTHESIS — transport needs a real peer socket, and the harness generates all three arrays in one pass so cross-array ordering cannot be provoked. What I did NOT do: measure. The audit's own standard is decided by construction rather than argument, and two of my three are readings of source sites, not runs — so rather than write prose that does not meet the document's bar, a fifth agent (`claude/collision-candidates-decided`) is launched to decide all three by running them, encode the UTF-8 refutation as a probe that fails if the premise changes, and recompute the counts rather than edit them. It is told explicitly that if `wire_bytes` does NOT move it has found an eighth collision, which is the more interesting outcome. The audit deserves credit for the shape of this note being additive rather than a retraction: it set its bar at measurement and honoured it by leaving five open, where a weaker record would have reasoned three shut and reported twelve findings. Housekeeping this firing: PR #4 re-checked and still cleanly mergeable through all fifteen landings; eight stale worktrees pruned (3.5 GiB to 141 MB, free 16 to 19 GiB) with the four running agents' preserved. No gates run (read-only investigation plus records); no owner gate crossed. Mainline head 098a7f6 before this record commit.
- 2026-09-03T04:24:43Z routine (goal-loop firing at 04:22:12Z): three agents hold the remaining wave-4 tracks, so the unit was step 7 — the board had not caught up with two significant landings and a new finding. TWO WAVE-4 TRACKS LANDED since the last board entry. (catalog) `claude/catalog-plane-correspondence` -> f8c748d, and IT CORRECTED F006, WHICH WAS MINE. F006 blamed the `internal/formalcoverage` and `cmd/formalcoverctl` failures on their citing `corpora/frame/codec.json`; they do not fail for that. The retained us023-coverage-report pins `evidence/linkage/rust-identity-verification.json` at blob 7b231395 / sha 5370eb08... while disk holds 83419ff9..., every other input matching — ordinary stale derived evidence after DIV-06 refroze the linkage overlay and the merge regenerated nothing. The `codec.json ... READ_FAILED` line that misled me is a FIELD INSIDE the report's own output, and the refutation was in the same test run: the only test reading that pin PASSED while the report test failed. Both packages are green at the merged head. F006 corrected in place, class filed as **F008, "the most recent explanation standing in for the diagnosis"** — attaching a failure to the most salient recent finding instead of reading the failure, which is the same root as F006's own class one layer up. (Renumbered from the branch's F007, which collided with the F007 landed earlier.) The track also found the ORIGINAL class inside the checker: `shippedCrateNamespaces` derived the namespace from the crate DIRECTORY name, so run against the Codex plane it would have reported that plane's own `websocket_core` as matching no shipped crate — a false accusation on the very plane the document is about. And its deletion sweep is the harshest of the session, reported plainly: **19 of 35 record checks SURVIVED deletion**, plus one more found by a second sweep alive only because a package name with underscores coincidentally equals the lib name on BOTH planes; 44/44 die now and 23 of its 50 tests exist only because a check survived. (rank3) `claude/oracle-rank3-independence` -> f43843e: rank 3 is now derived from RFC 6455 sections 5 and 7 rather than from a Java-mirroring model, and is DISTINGUISHED from ranks 4 and 5 for the first time — but 1-vs-3 became NOT_DISTINGUISHED 66/0, a new BLOCKING finding, because a rank 3 genuinely derived from the RFC is indistinguishable from rank 1, a recorded human reading of the same document. Curing one indistinguishability created another and the branch does not argue that away. It indicts its own apparatus twice more: join degeneracy means the ORIGINAL 32 co-votes were never a measurement, and projection collapse fires the co-vote-collision finding on two DISTINGUISHED pairs. Its register finally has a schema, which found a defect on first run. **All 15 rules remain UNVERIFIED against the RFC text**, which is still absent — so that owner action now gates two things, not one. Housekeeping: PR #4 re-checked, still cleanly mergeable. Three agents running with all three branches already pushed (div05 755b8c8, adapter-residuals 9ef3978, collision-candidates e41bcf6) — the push-early discipline is holding. No gates run this unit (records only); no owner gate crossed. Mainline head f43843e before this record commit.
- 2026-09-03T06:29:26Z routine (goal-loop firing at 06:24:38Z): three agents still hold the remaining wave-4 tracks (all three pushed: div05 755b8c8, adapter-residuals 9ef3978, collision-candidates e41bcf6), so the unit was step 5 in the form that had become due — an audit of THIS FILE for claims that later work has contradicted. It found one, and it is the session's own recurring class turned on the loop's own record. The measured ceilings from `evidence/normalization-collisions/audit.json` were recorded in the US-020 row and the iteration log, but the VALIDATION CONTRACT — the per-firing instruction at step 4, the P0 done statement, and the plane-comparison table — still stated "74/74" and "49/49" bare, with no bound attached. Those are exactly the lines a future firing reads as "what good looks like", so the number most likely to be mistaken for parity was sitting in the place most likely to be read that way. Fixed in all four places, with the instruction now reading NEVER STATE EITHER NUMBER WITHOUT ITS CEILING and carrying the measurement: the 74 public rows carry only 73 distinct scored observations (26 of them scored on ten scalars with every observation stream absent), the 49 handshake cases only 26 with 27 sharing one and the largest class holding 11, and two SHIPPED scenarios — us005.pub.0039 at FIN=1 and us005.pub.0066 at FIN=0, sharing no payload octet — produce byte-identical rows. The operative consequence is stated rather than implied: a green 74/74 is consistent with an undetected divergence. This is F006's and F008's class one more level out — not a check run against the wrong subject, but a NUMBER REPEATED WITHOUT THE BOUND THAT WAS MEASURED FOR IT, in the document that tells future rounds what to check. PR #4 re-checked and still cleanly mergeable. No gates run (records only); no owner gate crossed. Mainline head a355866 before this record commit.
