# Self-review round 1 — claude/ac5-class-completeness

Recorded 2026-09-02 from tool output on branch `claude/ac5-class-completeness`,
branched from mainline `claude/feature/verified-java-websocket-port` at
`57e881c`. No file under `rust/` is touched by this branch: `git status`
reports one modified file (`cmd/mutctl/mutations.go`, comment only) and four new
paths (`cmd/ac5ctl/`, `cmd/mutctl/ac5_binding_test.go`, `internal/ac5class/`,
`evidence/ac5-class-completeness/`).

The finding being closed (criteria audit finding 5): US-020 AC5 names seven
defect classes; two had no seeded variant of any kind, three were claimed only
through operators named for other things, and the discipline that would have
caught this — `cmd/mutctl/mutations.go`'s `--- AC5-named defect classes ---`
section — is a comment, and a comment cannot fail.

The question asked of every claim on this branch: **is this operator detected as
this class, or merely detected?** Answered by execution against the real pinned
Java oracle, never by reading operator names.

---

## 1. The differential this branch measures against is the real one

Everything below is expressed in the `java-websocket-oracle` observation
vocabulary and computed with the repository's own comparator
(`internal/diffregress.CompareResponses`). Before measuring any seed, the
vocabulary was pinned to live Java:

| arm | how |
| --- | --- |
| Java | `java-oracle` built from `java-oracle/src/main/java` (`javac --release 17 -Xlint:all -Werror`, JDK 21.0.10) against the pinned `Java-WebSocket-1.6.0.jar` `sha256:eae29213…c22f` and `slf4j-api-2.0.13.jar` `sha256:e7c2a48e…04a9`; run as `OracleMain` with `-Dstdout.encoding=UTF-8`, **exit 0** read from the process |
| Rust | `cargo build -p ws-oracle-harness --locked`, **exit 0**; harness process **exit 0** |

`diffregressctl compare`, exit 0 each time:

| tier | cases | identical | identical_except_error_detail | **behaviorally divergent** |
| --- | --- | --- | --- | --- |
| public | 74 | 48 | 26 | **0** |
| differential-regression probes | 23 | 6 | 17 | **0** |
| handshake exam (49 cases, ad-hoc `case_id` walk — `diffregress` is `request_id`-keyed) | 49 | 49 | — | **0** |

Two provenance readings worth keeping, neither of which I went looking for:

- The Java public arm digests to
  `sha256:2eb11ca38caf9fef9b7edb8b83f3c7f6297b3e6e3d7ccbfc2a11c84e5221bd8b`,
  **byte-identical** to the live public transcript `mutants/manifest.json`
  already pins under `baselines.java_pristine.public_tier_separation`. A
  months-old recorded Java transcript reproduced exactly, on a different host.
- The freshly recorded Java probe arm compares **23/23 identical, 0 divergent,
  0 detail-only** against the committed
  `evidence/differential-regression/java-arm.jsonl`.

Recorded in `evidence/ac5-class-completeness/java-arm-parity.json`, with the
Java arm and request stream committed beside it.

---

## 2. What the three "implicit" classes actually discriminate

Each candidate was applied to an isolated scratch copy, the harness rebuilt, the
transcript re-recorded, and the result compared **against the live Java arm**.
`error.detail` is omitted from this table: it differs on 43 of the 97 cases in
the pristine baseline too (documented non-semantic wording), so it carries no
information about a seed.

| operator (as claimed) | mutant | fields it moves | verdict |
| --- | --- | --- | --- |
| `close-code-swap` → error-class | `m014-orphan-close-code-swap` | `error.close_code` (2 cases) | **REJECTED** — moves the close CODE; `error.code` never changes |
| `close-code-swap` → error-class | `m016-eof-code-swap` | `close.code`, `events[].code` (1 case) | **REJECTED** — same shape one layer over |
| `close-echo-swap` → close-initiator | `m016-echo-payload-swap` | `frames[].payload_base64`, `frames[].payload_bytes`, `frames[].wire_bytes` (5 cases) | **REJECTED** — moves the echoed PAYLOAD; no initiator field moves |
| `close-transition-swap` → close-initiator | `m016-echo-branch-flip` | `counts.frames`, `events.length`, `final_state`, `frames.length`, `transitions.length`, `transitions[].to` (8/3/5 cases) | **REJECTED** — moves the transition TARGET; `transitions[].cause`, `close.origin`, `close.remote` never move |
| `payload-truncation` → consumed-byte | `m013-payload-truncation` | 22 field paths — **none of them `counts.consumed_bytes`** | **REJECTED** — the loudest mutant in the table leaves the consumed-byte counter exactly right |
| `counter-increment-drop` → consumed-byte | `m012-consumed-chunk-drop` | `counts.consumed_bytes` **only** (42 public + 5 probe cases) | **ACCEPTED** — the one of the three claims that holds |

So one of the three implicit claims survived measurement and two did not. New
seeds were written for the two that failed, each constructed so that the class's
field is the only one that *can* move:

- **error-class** — `ac5-error-class-input-to-buffer`: the `max_input_bytes`
  refusal reports `BUFFER_LIMIT_EXCEEDED` instead of `INPUT_LIMIT_EXCEEDED`.
  Both classes carry **no** close code, so no close code can move; measured
  `error.code` + `error.detail`, nothing else.
- **close-initiator** — `ac5-close-initiator-remote-to-local`: a close frame
  arriving from the peer is recorded as locally initiated. Code, reason and
  `handshake_complete` untouched; measured `close.origin`, `close.remote`,
  `events[].origin`, `events[].remote` on 8 cases, nothing else.

These are recorded in code as `ac5class.RejectedBindings()`, with a test
(`TestRejectedBindingsRecordWhatWasTestedAndRejected`) that keeps them present.
The gap being closed is "an operator exists" standing in for "the class is
detected"; deleting the negative results is how it comes back.

---

## 3. Two more normalization collisions, found by construction

The register was built to make a collision a first-class outcome, and it
immediately found two nobody had reported:

- **`m013-close-event-order-swap`** — the *existing* US-013 AC5 event-order seed
  — moves **nothing at all** in the differential. It reorders a close EVENT
  against a TRANSITION, and the normalization projects `events[]` and
  `transitions[]` into separate arrays, so every ordering relation *between* the
  arrays is erased.
- The same is true of swapping `emit_outbound`'s own two emissions
  (`cand-event-order-outbound-pair-swap`, measured: nothing): one lands in
  `frames[]`, the other in `events[]`.

Only a swap of two **adjacent `events[]` entries** is observable, which is why
the registered event-order seed is `ac5-event-order-send-close-pair-swap` — the
`send_close` / `close_initiated` pair — measured at `events[].type` and its six
travelling companions on 6 cases.

This does not mean the event-order class was undetected: `cargo test -p ws-core`
kills `m013-close-event-order-swap` through
`close_ack_emits_the_close_event_before_the_terminal_transition`. It means the
US-020 **differential** never saw it, which is exactly the distinction AC5's own
normalization-collision clause exists to force.

---

## 4. The two seeded classes that had nothing

### 4a. Java-quirk emulation

Two seeds, because the class has two honest readings and only one of them the
differential can see.

**`ac5-jq-handshake-unbounded-head`** — the pure quirk. `HeadAccumulator::push`
stops enforcing `max_handshake_bytes`, so the port grows its handshake head
without bound exactly as shipped Java does. Behavior-delta ledger record 45
(subject
`…server-handshake.limit-total-bytes.hs0046.corrected:provisional-v1`) says in
words that this is the Java behaviour the port does **not** copy:
"JAVA_FAITHFUL_PLUS_SAFE: Java's unbounded growth is NOT emulated", and names
the pin.

RED reading, exit codes read from the process:

```
cargo test -p ws-core --test handshake_server        exit 101
  FAILED: configured_budgets_refuse_with_the_named_limit
  ws-core/tests/handshake_server.rs:342:9: expected total-bytes refusal
```

That is the exact test the ledger record names. **It is invisible to the
differential** — measured, not assumed: all 74 public, 23 probe and 49 handshake
observations are unchanged. That is not a hole in the seed; it is structural,
and it is the point. A Java-quirk emulation makes the port agree with Java by
construction, so a Java-versus-Rust *comparison* can never detect one. Only a
higher-ranked oracle can, which is US-020 AC2 ("agreement between Java and Rust
cannot override a higher oracle") turned into a check that runs. The seed
therefore carries a `Collision` record naming its blind judges rather than a
discriminating field set.

**`ac5-jq-violation-close-in-core`** — the layer-placement quirk, and the one
the differential *does* catch. `ws_core`'s translate-loop rejection arm acquires
shipped `WebSocketImpl`'s protocol-violation close reaction (compose the close
frame, `Open -> Closing`). Ledger record 49 places that reaction in the
**adapter** and forbids it in the core, because the core is the layer the
live-Java differential scores, and records the measurement: `final_state`
`open -> closing` and `counts.frames` +1.

Measured against the live Java arm: **`final_state` and `counts.frames` move on
14 of 74 public cases and 10 of 23 probes**, reproducing that signature on
exactly the fields the record names.

The case sets were compared rather than the counts. The record names 18 public
cases; this seed moves 14, and they are a **strict subset** — nothing moved that
the record does not list. The four it does not reach are `us005.pub.0039`,
`0042`, `0052` and `0066`. The record describes a whole-byte-path
implementation; this seed hooks the translate-loop rejection arm only, and those
four presumably reject elsewhere on the byte path — presumably, because I did
not open them to confirm it, and the subset relation is what I actually
measured.

RED reading:

```
cargo test -p ws-core                                exit 101
  FAILED: family_seed_corpus_anchors (+7 more)
  ws-core/tests/adversarial_fuzz.rs:265:21:
    transition (SendClose) emitted before its close notification
```

### 4b. Normalization-collision

**`ac5-collision-server-tcp-close`** — `server_closes_transport` in
`rust/ws-testee/src/io_loop.rs` returns `false`, so the port's server stops
closing the TCP connection after its close echo. That is precisely the wire
behaviour shipped Java has and the port lacked until `d433c21`;
`evidence/java/observed-close-divergences.json` measured it at **123 server
cases as DIV-02**, out of band, from Autobahn report bytes, because no
differential case could see it.

The two-sided reading `ac5ctl run` takes, every exit code read from the process:

| reading | pristine | with the seed applied |
| --- | --- | --- |
| out-of-band witness `cargo test -p ws-testee --test loopback` | **exit 0** | **exit 101** — `a_server_closes_the_tcp_connection_once_its_close_echo_has_drained`, `a_server_that_initiates_a_close_hangs_up_without_waiting_for_the_echo`, `the_server_fixture_reaches_its_terminal_without_the_peer_ever_closing` |
| `cargo test -p ws-core` (E1 judge 1) | exit 0 | **exit 0** |
| differential over 97 requests | — | **field-diff set empty** |

Kill detail, verbatim:
`ws-testee/tests/loopback.rs:1609:5: Java's server closes on flush-and-close, not on having received a Close (WebSocketImpl.java:494 -> :592, SocketChannelIOHelper.java:110-113)`.

Two genuinely different behaviours; one normalized observation. A
class-complete AC5 with this seed registered reports the collision by
construction instead of reading parity for weeks.

---

## 5. The checkability mechanism, and proof that it fails

`internal/ac5class` + `cmd/ac5ctl`, in two halves of very different cost.

**Static (`ac5ctl verify`, and `go test ./internal/ac5class`, seconds, no
cargo).** The seven class names are **parsed out of the PRD**
(`ClassesFromPRD`), never retyped, so the register is bound to the criterion
text. Every variant's exact literal must resolve in the shipped tree. A variant
with no discriminating fields and no registered collision fails. A collision
without an out-of-band witness fails. A detector named by suite instead of by
test fails.

**Executed (`ac5ctl run`).** Fresh scratch copy of `rust/` outside the
repository (resolved-path containment, `EvalSymlinks` + `filepath.Rel`, never a
string prefix), tree digested before and after; pristine `cargo test -p ws-core`
and harness run must be green before any seed is applied; per seed the named
detector runs and **the named test must be among the failures**; the harness is
rebuilt and the transcript compared to the pristine arm; the measured field set
must equal the declared one exactly; the scratch must digest back.

Final run, exit read from the process:

```
ac5ctl: baseline green — tests exit 0, harness exit 0, 97 requests
ac5ctl: Java-quirk emulation     ac5-jq-handshake-unbounded-head        COLLISION_DETECTED   detector_exit=101
ac5ctl: Java-quirk emulation     ac5-jq-violation-close-in-core         CLASS_DETECTED       detector_exit=101
ac5ctl: Rust semantic defect     m013-payload-truncation                CLASS_DETECTED       detector_exit=101
ac5ctl: event-order              ac5-event-order-send-close-pair-swap   CLASS_DETECTED       detector_exit=101
ac5ctl: error-class              ac5-error-class-input-to-buffer        CLASS_DETECTED       detector_exit=101
ac5ctl: close-initiator          ac5-close-initiator-remote-to-local    CLASS_DETECTED       detector_exit=101
ac5ctl: consumed-byte            m012-consumed-chunk-drop               CLASS_DETECTED       detector_exit=101
ac5ctl: normalization-collision  ac5-collision-server-tcp-close         COLLISION_DETECTED   detector_exit=101
AC5CTL_EXIT=0
```

### Attack matrix — every one run, every exit code read

| # | attack | result |
| --- | --- | --- |
| A1 | Drop every variant of a class from the register (`normalization-collision`, `error-class`, `close-initiator` in turn) | `VerifyRegister` reports `class "…" has NO seeded variant` — `TestVerifyFailsWhenAClassLosesItsSeededVariant` |
| A2 | Drift a seeded site's literal out of the tree | reports `not found` — `TestVerifyFailsWhenASeededSiteDriftsOutOfTheTree` |
| A3 | Empty a variant's discriminating set without registering a collision | reports `no collision is registered` — `TestVerifyFailsWhenAVariantStopsDiscriminatingWithoutRegisteringTheCollision` |
| A4 | Strip a collision's out-of-band witness | reports `cannot be told apart from an equivalent mutant` — `TestVerifyFailsWhenACollisionSeedHasNoOutOfBandWitness` |
| A5 | Name a detector by suite instead of by test | reports `no named detector` — `TestVerifyFailsWhenTheDetectorIsNamedBySuiteInsteadOfByTest` |
| A6 | Grow the PRD clause an eighth class (`mask-key-leak`) in a doctored root | reports the uncovered class by name — `TestVerifyFailsWhenThePRDGrowsAnEighthClass` |
| A7 | Declare a field set that does not match reality (the first real run, before the sets were corrected) | **`AC5CTL_EXIT=3`**, two `REGISTER_STALE` rows naming declared vs measured |
| A8 | Run a collision with `-skip-witness` | **`AC5CTL_EXIT=3`**, `COLLISION_UNCONFIRMED` — the flag makes the run cheaper and can never make the receipt greener |
| A9 | Point the collision's witness at a test that passes with the seed applied | **`AC5CTL_EXIT=3`** — "the out-of-band witness PASSES with the seed applied: … this is an equivalent mutant and not a collision" |
| A10 | Point a detector's `MustFail` at a real test that does not fail under the seed | **`AC5CTL_EXIT=3`** — "the detector exited 101 but `local_close_emits_frame_detail_and_transition` is not among the failures […]: an unrelated kill is existence, not identity" |

A9 and A10 were run against a temporarily doctored `register.go`, which was then
restored from a saved copy and re-verified (`go test ./internal/ac5class` ok,
`ATTACK 2` marker absent, `gofmt -l` clean).

The `cmd/mutctl` comment is bound to code by
`TestAC5RegisterCampaignBindingHolds`: a register row claiming
`InE1Campaign` must be a row of `CuratedMutations` **literal for literal**, and
a row not claiming it must be absent — so nobody can inherit the E1 campaign's
evidence for a seed the campaign never ran. Both halves are asserted non-empty,
so neither can silently become vacuous.

---

## 6. Findings recorded rather than hidden

1. **`m013-payload-truncation`, the loudest mutant in the E1 table, does not
   discriminate consumed-byte.** It moves 22 observation field paths and leaves
   `counts.consumed_bytes` exactly right. Breadth is not identity, and an audit
   that reads operator names would have accepted it.
2. **The US-013 AC5 event-order seed is invisible to the US-020 differential.**
   Cross-array ordering (`events[]` vs `transitions[]`, `frames[]` vs
   `events[]`) is erased by the normalization. Class-complete for US-013 through
   its ws-core tests; not class-complete for US-020's differential.
3. **A Java-quirk emulation is structurally undetectable by a Java-versus-Rust
   comparison.** Only the layer-placement kind (ledger record 49) is visible,
   because shipped Java has two entry points and the port is scored at one of
   them. Every other quirk the ledger declines to preserve is either invisible
   or, by the ledger's own words for quirk Q24, "identical observables".
4. **`cargo test` fail-fast truncates `mutctl`'s `allFailedTests`.** Running the
   handshake seed under the whole package reported only the two in-crate unit
   failures; the ledger-named integration test
   `configured_budgets_refuse_with_the_named_limit` did not appear until the run
   was narrowed with `--test handshake_server` (exit 101, "expected total-bytes
   refusal"). `mutctl`'s manifest rows may therefore under-list failures for any
   mutant that trips an early target. Not fixed here — it is `mutctl`'s
   extractor, and the committed E1 manifest is bound by a protected-store
   receipt.
5. **The handshake exam cannot reach the handshake budgets.** All 49 cases carry
   deliberately tight `config` budgets and all 49 still accept, on both arms,
   because the budgets are *head* budgets and every exam head fits. Ledger record
   45 says the same thing in prose; this is the measurement.

---

## 7. What I did NOT do, by name

- **I did not re-run the 76-mutant E1 campaign, and did not add the five new
  seeds to `cmd/mutctl.CuratedMutations`.** Doing so would leave
  `mutants/e1-ws-core-manifest.json` covering fewer mutants than the table, and
  regenerating it would contradict
  `evidence/governance/decisions/e1-adversarial-receipt.json`, which binds that
  manifest as a specific dated run. The new seeds carry `InE1Campaign: false`
  and their own executed receipt instead, and the binding test forbids them from
  claiming campaign coverage they do not have.
- **I did not modify `evidence/java/behavior-delta-ledger.json` or
  `internal/deltaledger`** — another track owns the ledger this wave. Records
  45 and 49 are cited, never edited. `ac5-collision-server-tcp-close` reproduces
  DIV-02, whose proposed ledger subject
  `…server-tcp-close-after-close-handshake:provisional-v1` is still a proposal;
  **no ledger record was appended for it.**
- **I did not touch any file under `rust/`.** Every seed is a table entry
  applied to a scratch copy; the shipped tree is never mutated. Another track is
  changing `rust/ws-testee` handshake code, and
  `ac5-collision-server-tcp-close`'s literal is the close gate, not handshake —
  but if that file is refactored the seed will fail loudly at
  `ResolveSite`, which is the intended failure mode, not a silent skip.
- **I did not trigger any owner gate**: no AWS, no benchmark, no Autobahn rerun.
  The Java oracle was built and run locally from the already-materialised pinned
  jars in `.quarantine/`.
- **I did not run the hidden or sealed corpus tiers.** The public request stream
  was generated with a throwaway protected store, which
  `.claude/CLOUD-ENVIRONMENT.md` sanctions for the public and handshake tiers
  and only those. Nothing here is a custodian-ledgered result.
- **I did not add a `measure` mode that regenerates the register's declared
  field sets automatically.** The sets are corrected by hand from a run that
  reports the disagreement (A7 above), so a change to the observation vocabulary
  has to be looked at by a person rather than absorbed silently.
- **I did not seed a second registered collision for quirk Q28** (Java randomizes
  client mask keys, the port derives them, and no observation records either —
  a genuine live collision in the same shape). `mprobe-mask-counter-stall`
  already exists as a mutant with an out-of-band killer, so registering it is
  cheap; it is left as the obvious next entry rather than added unmeasured.
- **I did not re-measure the 49-case handshake exam inside `ac5ctl`.** Its
  protocol is `case_id`-keyed and `internal/diffregress` is `request_id`-keyed;
  the single measurement lives in `java-arm-parity.json` and the register says
  so at the point of use rather than implying the gate re-checks it.
