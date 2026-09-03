# DIV-05: close overtakes echo (behavior-delta ledger sequence 54)

STATUS: COMPLETE for what it claims, with three residuals and one owner
question named in section 9.

Branch `claude/div05-close-overtakes-echo`, resumed at `755b8c8`.
Merge base with mainline `58f3aa4`; mainline head compared against `131b7b8`.
Everything below was executed in this session and every exit code was read
from the process, never inferred from output text.

## Why this record is written twice

The seven commits under this record were made by a predecessor session that
pushed code and never wrote the record. The loop caught it and filed
`drafts/self-review/findings/F009-i-read-a-record-by-its-existence.md`. This
file is therefore **not** a summary of those commits. Every claim in them was
re-derived here, and four of them turned out to be wrong or stale; those are
sections 2.1, 5.3, 7 and 8.

---

## 1. The Java citation — SOURCE CITATION, no Java process ran for it

The `java-oracle` is a JSONL request/response oracle that never opens a socket
and has no `decodeFrames`, so nothing in this repository can *execute* the
behaviour DIV-05 is about. Every Java claim in section 1 is a **citation of
pinned source**. (A live Java runtime WAS executed — section 6 — but only for
the corpus differential and handshake exam, which do not reach this path.)

### 1.1 Provenance of the tree, and what could NOT be checked

`.quarantine/` is git-ignored and was empty. The archive URL in
`evidence/intake/source-pins.json`
(`https://github.com/TooTallNate/Java-WebSocket/archive/da3cf2a....tar.gz`,
pinned sha256 `f44e7647b4aee40819b51947cf0bb5f35a48293a202b77704c3c79e98ed13cb4`)
**is not reachable from this environment.** The agent proxy answers it with
378 bytes of JSON, `GitHub access to this repository is not enabled for this
session` (sha256 `b3e03aaaff81d68730d67392a135ac3fdfdf022880c66632ab188d2fe084cda3`).
The repository's own acquisition path, `internal/portplan.EnsureQuarantinedSource`
(`internal/portplan/acquire.go:32-90`), fails the same way — that is the cause
of the `JAVA_SOURCE_UNAVAILABLE_OFFLINE: pinned immutable URL returned HTTP
403` baseline failures in section 8. **The pinned tarball digest was not
checked and this record does not claim it was.**

What was checked is the pin's *other* half. The artifact's `provenance` field
reads `git commit da3cf2a777aed862f2f5b5cf060cae7969958667 tree
30c108fd7b68663f645ee9cb8e3daaf4a39235ea tag v1.6.0`. The commit was fetched
over the anonymous git lane and read:

    git -C /home/user/tootallnate/java-websocket cat-file -p da3cf2a777aed862f2f5b5cf060cae7969958667
    tree 30c108fd7b68663f645ee9cb8e3daaf4a39235ea        <- equals the pin

then materialised with `git archive` into
`.quarantine/Java-WebSocket-da3cf2a777aed862f2f5b5cf060cae7969958667/`.

This is a **different check from the pinned one**, over a different
serialisation: git's Merkle hash of the tree contents versus sha256 of
GitHub's generated tarball. It establishes content identity of the tree; it
does not establish the tarball bytes. A reader who needs the tarball digest
must re-check it somewhere the archive endpoint is served.

Cross-check that the materialised tree is the one this repository's existing
records were written against — four citations lifted from
`drafts/ledger-proposals/server-close-parity.json`, all landing exactly:

| cited | reads |
| --- | --- |
| `WebSocketImpl.java:102` | `public final BlockingQueue<ByteBuffer> inQueue;` |
| `SocketChannelIOHelper.java:110-113` | the `outQueue.isEmpty() && isFlushAndClose() && role == SERVER` hang-up |
| `WebSocketImpl.java:573-578` | `public void closeConnection()` |
| `Draft_6455.java:1068` | `webSocketImpl.close(code, reason, true);` |

### 1.2 The chain that decides DIV-05

Paths below are relative to
`.quarantine/Java-WebSocket-da3cf2a.../src/main/java/org/java_websocket/`.

1. **`WebSocketImpl.decode` — `WebSocketImpl.java:220-242`.** Frame decoding is
   reached only from the OPEN arm (`:227-230`). While `NOT_YET_CONNECTED` the
   buffer goes to `decodeHandshake`, and only on success does `:232-240` run
   `decodeFrames` over whichever buffer still has remaining bytes.
2. **`WebSocketImpl.decodeFrames` — `WebSocketImpl.java:391-419`.** The whole
   socket buffer becomes a `List<Framedata>` in ONE call
   (`frames = draft.translateFrame(socketBuffer);`, `:394`; declared at
   `Draft_6455.java:724`), and the list is walked **one frame at a time**:

       395:       for (Framedata f : frames) {
       396:         log.trace("matched frame: {}", f);
       397:         draft.processFrame(this, f);
       398:       }

3. **`Draft_6455.processFrameText` — `Draft_6455.java:982-990`.** Inside that
   iteration, synchronously:

       985:       webSocketImpl.getWebSocketListener()
       986:           .onWebsocketMessage(webSocketImpl, Charsetfunctions.stringUtf8(frame.getPayloadData()));

   An echoing listener's `send()` has already appended the echo to `outQueue`
   (`WebSocketImpl.write`, `:736-740`, `outQueue.add(buf)`) before iteration
   two begins.
4. **`Draft_6455.processFrameClosing` — `Draft_6455.java:1054-1073`.** Only
   now: `webSocketImpl.close(code, reason, true)` (`:1068`).
5. **`WebSocketImpl.close(int,String,boolean)` — `WebSocketImpl.java:463-507`.**
   `sendFrame(closeFrame)` at `:486` appends the close BEHIND the echo in the
   same `outQueue`; then `flushAndClose` at `:494`.
6. **`WebSocketImpl.flushAndClose` — `WebSocketImpl.java:584` onward.** Its own
   comment is the load-bearing sentence:

       594:     wsl.onWriteDemand(
       595:         this); // ensures that all outgoing frames are flushed before closing the connection

7. **`SocketChannelIOHelper.batch` — `SocketChannelIOHelper.java:110-113`.**
   The TCP connection closes only once `ws.outQueue.isEmpty()`.

**Conclusion.** For `[completed data frame][close frame]` in ONE socket read,
shipped Java's wire answer is the echo, then the close echo, then (server role)
the hang-up. Nothing discards a message already fully received. The property
that produces this is the **synchronous per-frame dispatch** at `:395-398` —
not buffering, not size, not any close-specific rule.

---

## 2. The RED reading

The branch's fixture kept in place; the two port sources the branch changes
(`rust/ws-driver/src/lib.rs`, `rust/ws-testee/src/io_loop.rs`) replaced with
mainline `131b7b8`'s versions verbatim; nothing else touched.

    cargo test -p ws-testee --test close_overtakes_echo
    test result: FAILED. 0 passed; 3 failed
    exit code 101   (read from the process)

| test | subject wrote (left) | required (right) |
| --- | --- | --- |
| `a_close_sharing_one_read_with_a_completed_text_frame_does_not_cancel_the_echo` | `[(8, 6)]` | `[(1, 5), (8, 6)]` |
| `the_autobahn_7_1_6_burst_returns_both_echoes_before_the_close` | `[(8, 2)]` | `[(1, 262144), (1, 12), (8, 2)]` |
| `a_client_role_endpoint_echoes_before_answering_a_close_in_the_same_read` | `[(8, 6)]` | `[(1, 5), (8, 6)]` |

Each failure message names the divergence and cites the Java that decides it.
With the branch's own sources restored: `test result: ok. 4 passed`, **exit 0**
(four, because of the pin added in section 7).

### 2.1 FINDING — commit `0a4f32c`'s RED readings are not reproducible as written

That commit records the client case's RED left-hand side as `[]`. Against
mainline `131b7b8` it is `[(8, 6)]`. The difference is mainline's own
`server-close-parity` landing, present on `131b7b8` and absent from the
branch's merge base `58f3aa4`, which the commit measured against. Both are RED;
the reading this record carries is the one taken against mainline.

---

## 3. The ledger record's description does not hold up, in two places

Sequence 54's rationale says: *"with a 256 KiB text message followed
immediately by a Close, shipped Java delivers the echo and answers the close
with 1000; the port drops the echo and sends no close."*

**(a) The 256 KiB plays no causal part.** Run against unmodified mainline
sources: same 5-byte `hello`, same close, same single socket write by the peer,
only the SUBJECT's `IoBounds::read_buffer` varied.

| `read_buffer` | peer received | `report.outcome` |
| --- | --- | --- |
| 4096 — one read takes both frames | `[(0x8, 6)]`, echo dropped | `ProtocolFailure(StateViolation)` |
| 1 — no read can span the boundary | `[(0x1, 5), (0x8, 6)]`, Java's order | `Terminal` |

The discriminator is **chunk coalescing across a frame boundary**. The 256 KiB
makes coalescing certain on the wire; it is not the cause.

**(b) "sends no close" is stale.** At mainline `131b7b8` the port DOES put a
close frame on the wire — `(0x8, 6)` on the small burst, `(0x8, 2)` on the
7.1.6 shape. What it drops is the message echo. The ledger's observation was
recomputed from the `us019-prov-20260828T183623Z` run whose subject was commit
`518b77aa` (`evidence/java/observed-close-divergences.json`
`recomputed_from.subject_commit`); the close-composition and
server-close-parity landings postdate it.

**What held.** The disposition `fix-in-port`, the mismatch class `rust-defect`,
the measured extent (1 server case and 1 client case of 247) and the statement
that no existing gate sees it — all upheld and re-confirmed.

The corrected description is proposed as a DRAFT:
`drafts/ledger-proposals/div05-close-overtakes-echo-description-correction.json`.
Sequence 54 is inside an append-only chain whose prefix is frozen through
sequence 35 (`evidence/governance/decisions/ledger-frozen-prefix-owner-decision-2026-08-28.json`);
nothing on this branch appends to, edits, or re-digests it, and
`deltaledgerctl --check` still reads the chain intact (56 records, head
`sha256:a44191d3...`).

---

## 4. Why the fix belongs in `ws-driver` — re-derived, not quoted

Commit `755b8c8` says "the architecture gate said so". The gate is real and it
does say so.

**`ws-testee` is mechanically forbidden.** `cmd/rustgatectl/adapter_linkage.go`
walks `rust/ws-testee/src` (production sources only; tests exempt by design,
`:274-330`) and its `forbiddenProtocolSurface` list (`:48-65`) contains
`Draft6455`, `HeaderDecode` and `ws_core::framing` — the three symbols a
frame-boundary finder must name. Re-derived by seeding, not taken on trust:
adding `use ws_core::framing::{Draft6455, HeaderDecode};` to
`rust/ws-testee/src/io_loop.rs` and running
`go run ./cmd/rustgatectl -root . -gate adapter-linkage` reproduces exactly

    finding=ADAPTER_PROTOCOL_SURFACE ... forbidden protocol symbol "Draft6455"
    finding=ADAPTER_PROTOCOL_SURFACE ... forbidden protocol symbol "HeaderDecode"
    finding=ADAPTER_PROTOCOL_SURFACE ... forbidden protocol symbol "ws_core::framing"
    gate=adapter-linkage verdict=FAIL detail="3 adapter architecture findings"
    exit status 1                                          (exit 1, read)

Seed removed: `make -C rust gates` **exit 0**, `adapter-linkage verdict=PASS`,
`ac1-gates verdict=PASS gates_passed=8/8`. **The gate was not weakened** — the
fix names those symbols in `ws-driver`, which this gate does not scan and never
has.

**`ws-core` is excluded for a reason that was read, not asserted.**
`corpora/public/scenarios.jsonl` carries 38 `input_chunk` events of the shape
`{"bytes":7,"step":0,"type":"input_chunk"}` inside `expected.events`. A core
that split a chunk at a frame boundary would emit two records where the corpus
pins one.

**`ws-driver` is the right home, not merely the only legal one.** It is the
`WebSocketImpl` mirror and `decodeFrames`' dispatch loop is a `WebSocketImpl`
method — the same layering that already holds `AutoResponsePolicy`
(`Draft_6455.processFrame`'s ping arm) and `CloseEchoPolicy`
(`WebSocketImpl.close`'s composition). The corpus objection is answered by a
policy whose DEFAULT is the oracle observable: `InboundFeedPolicy::WholeChunk`
is `#[default]`; every `*_with_policies` and `*_in_state*` constructor keeps it
(`ws-driver/src/lib.rs:468-486`, `:494-542`); only `connection_driver`, the
fresh-connection full-stack constructor, opts into `OneFramePerTurn`.
`ws-oracle-harness` reaches the driver through
`connection_driver_in_state_with_policies` (`core_adapter.rs:717`, `:2175`).
Every call site in the workspace was read.

**Measured, not just argued** — see section 6.3: the release oracle harness
built from this branch and from mainline emits **byte-identical transcripts**
on all 74 public and all 49 handshake cases.

### 4.1 The fixture's own layering argument was stale and is withdrawn

`close_overtakes_echo.rs`'s module doc still carried the pre-move section *"Why
this file, and not `ws-core` or `ws-driver`"*, arguing for the `ws-testee` home
that `755b8c8` abandoned — including the claim that `ws-driver` "cannot
discriminate either" because the harness runs through it. That claim is false
by measurement. The section is replaced with the argument above.

---

## 5. Deletion attacks

Method: one mutation at a time against the working tree, then
`cargo test -p ws-driver -p ws-testee --all-targets`, then restore. **Every
mutation compiles** — a mutation that breaks the build proves nothing — using
`false &&`, `|| true`, or an `if false { … }` guard. Baseline for this scope:
exit 0 in ~10 s. Script and per-attack logs are reproducible from the mutation
table in the commit history; each anchor is asserted unique before it is
applied.

| # | what it deletes | verdict |
| --- | --- | --- |
| A | the `frame_dispatch_pending` quiescence gate | **CAUGHT** exit 101 — all 3 socket fixtures |
| B | frame-aligned feeding entirely (`framed = false && …`) | **CAUGHT** exit 101 — all 4 socket fixtures |
| C | the retained-head subtraction `total.saturating_sub(self.head.len())` | **CAUGHT** exit 101 — `a_frame_header_split_across_reads_still_lands_the_boundary` |
| D | the give-up latch on a header the grammar rejects | **CAUGHT** exit 101 — `an_unparsable_header_stops_splitting_and_defers_to_the_core` |
| E | **nothing** (control: a semantics-preserving rewrite of the same expression) | **SURVIVED** exit 0 — as it must; the harness is not trivially red |
| E2 | the `NotYetConnected` skip | **CAUGHT** exit 101 — all 3 socket fixtures |
| F | `io_loop`'s re-offer of the unapplied tail | **CAUGHT** exit 101 — but see 5.1 |
| G | `self.feed.advance(bytes)` | **CAUGHT** exit 101 — `the_autobahn_7_1_6_burst_returns_both_echoes_before_the_close` |
| H | the clear of `frame_dispatch_pending` on a quiescent turn | **CAUGHT** exit 101 — all 3 socket fixtures |
| I | the retained head itself (`head.extend_from_slice`) | **CAUGHT** exit 101 — `a_frame_header_split_across_reads_still_lands_the_boundary` |
| J | the honest partial-consumption report on the success path | **CAUGHT** exit 124 — but see 5.1 |
| K | the corpus-path guarantee (harness seam switched to `OneFramePerTurn`) | **CAUGHT** exit 101 — see 5.3 |
| L | the `#[default]` on `WholeChunk` (moved to `OneFramePerTurn`) | **CAUGHT** exit 101 — `the_inbound_feed_default_is_the_whole_chunk` |

### 5.1 The two that isolate only by LIVENESS — named

**F** and **J** are caught, but in two of the three socket fixtures the
discrimination is not an assertion — it is the poll budget. With the unapplied
tail dropped, the small-burst and 7.1.6 fixtures make no progress and spin to
`max_polls = 2_000_000` at a 1 ms read timeout, i.e. roughly half an hour of
wall clock each. F's run was killed after 600 s with
`a_client_role_endpoint_echoes_before_answering_a_close_in_the_same_read`
already `FAILED` and the other two still running; J's returned exit **124**
(a 300 s timeout) with the same single named failure and two slow tests.

That is a real property of the code, not only of the test: the io_loop tail
re-offer is load-bearing for TERMINATION, not merely for correctness. It is
recorded here rather than smoothed over, and it is the reason the verdict
column distinguishes 101 from 124.

### 5.2 FINDING — a counter that could not fail, and its fix

Commit `345e32e` added `deferred_frame_dispatch` to
`rust/ws-driver/tests/schedule_exploration.rs` with a field comment saying the
arm "is expected to stay zero here" because every driver that exploration
builds keeps `WholeChunk`. **Nothing asserted it.** The counter was summed into
`totals` and never read — a check green when deleted, in the purest form: it
was never a check at all.

It is asserted now (`schedule_exploration.rs:1832`), and the assertion
isolates: attack K fails exactly that line with exit 101. That turns the
exploration's counters — which `assurance/concurrency/results.json` cites
verbatim — into a check that the DIV-05 feed policy is INERT on the corpus
path, rather than an assumption about it.

### 5.3 What attack K found about the corpus guard

Before 5.2, K was caught only *incidentally*, by two `ws-driver` auto-response
tests (`a_close_that_already_moved_the_state_supersedes_the_reply`,
`every_ping_in_a_chunk_gets_its_own_pong_in_order`). Nothing NAMED the corpus
guarantee it breaks.

The corpus differential does catch it, though — measured. With K applied and
the release harness rebuilt, 3 of 74 public cases move, and they move in
exactly the predicted way: `us005.pub.0032` `.counts.input_chunk`-bearing
fields go `16 -> 8`, its `outcome` flips `error -> ok`, and its
`FRAME_LIMIT_EXCEEDED` error disappears because only one frame now reaches the
core per turn. So `WholeChunk` on the harness seam is a genuine guard, not a
convenience — and the `ws-driver` docs' claim about it is empirically right.

---

## 6. Corpus differential and handshake exam

Re-run because `rust/ws-driver/src` and `rust/ws-testee/src` both changed.
Throwaway 32-byte hex secret; public and handshake tiers only, per
`.claude/CLOUD-ENVIRONMENT.md`. Release harness clean-rebuilt
(`cargo clean --release -p ws-driver -p ws-core -p ws-oracle-harness`, then
`cargo build --release -p ws-oracle-harness --locked`, exit 0), so the binary
provably comes from this branch's sources; harness sha256
`1872e26c44a3d22998eeda3d9fe2e09e69ca96912a23318cfed86b79f96bc12c`, identical
before and after the clean and again on the final rebuild.

Handshake request digest
`e00d968f0ae623dd75a09842ad435642c0dca53ee5e9f9ef654ce26c1f814c49` —
**unchanged** from the batch-B receipt value.

| leg | reading | exit |
| --- | --- | --- |
| public tier, port | executed 74, passed 74, failed 0, missing 0, unmatched 0 | 0 |
| public tier, live Java 1.6.0 | executed 74, passed 74, failed 0 | 0 |
| handshake exam, port, runtime-neutralised | executed 49, passed 49, failed 0, **16 documented divergences** | 0 |
| handshake exam, live Java 1.6.0 | executed 49, passed 49, failed 0, **the same 16 divergences** | 0 |
| port vs live Java, public transcripts | only `.error.detail` differs, on 26 of 74; every other field equal on all 74 | — |
| port vs live Java, handshake transcripts | no non-runtime field differs on any of the 49 | — |
| `java-oracle` self-test | `PASS 18 java-oracle tests` | 0 |

No shift anywhere. Both readings were taken twice — once mid-session and once
after every source change — with identical results.

Runtime jars verified against their pinned digests before use:
`Java-WebSocket-1.6.0.jar`
`eae29213e4f16515639c28957200f011b3967fffcada1962cf0255d24919c22f`,
`slf4j-api-2.0.13.jar`
`e7c2a48e8515ba1f49fa637d57b4e2f590b3f5bd97407ac699c3aa5efb1204a9`.

### 6.1 Deviation, stated

The pinned JDK is a macOS Homebrew bottle (`openjdk-17.0.19-homebrew-bottle`,
`evidence/intake/toolchain-pins.json`) and the Temurin 17 fallback host is
refused by this environment's egress proxy (`api.adoptium.net` →
`connect_rejected`). The live Java legs ran on the container's **OpenJDK
21.0.10**, classes compiled `--release 17`, with all three encoding properties
(`-Dfile.encoding`, `-Dsun.stdout.encoding`, `-Dstdout.encoding`) set to UTF-8
as `.claude/CLOUD-ENVIRONMENT.md` prescribes for exactly this reason. 74/74
with no `?` substitutions is consistent with the documented UTF-8-correct
reading, but this is **not the pinned runtime** and the record says so.

### 6.2 What a green differential does and does not mean here

These are CASE counts against known ceilings — 73 distinct scored observations
behind the 74, 26 behind the 49. More decisively for DIV-05, the differential
path is *structurally* pinned to `InboundFeedPolicy::WholeChunk`.

### 6.3 So it was measured, and the answer is: it is blind, in both directions

The release oracle harness was built twice from the SAME request files — once
from this branch's sources (`1872e26c…`) and once from mainline `131b7b8`'s
`ws-driver/src/lib.rs` and `ws-testee/src/io_loop.rs` (`a470eadd…`) — and the
transcripts compared field by field:

    PUBLIC:    rows 74/74, cases_with_any_difference=0, NO non-runtime field differs
    HANDSHAKE: rows 49/49, cases_with_any_difference=0, NO non-runtime field differs

**The corpus differential and the handshake exam cannot see this change at
all.** A green 74/74 and 49/49 is evidence the change did not break the oracle
observable; it is not, and could not be, evidence that the fix works.

What WOULD make the fix visible: (i) the socket fixtures in
`rust/ws-testee/tests/close_overtakes_echo.rs`, which drive the full-stack
`connection_driver` seam over a real loopback socket and are RED against
mainline (section 2); (ii) the `ws-driver` unit tests in `inbound_feed_tests`;
(iii) an Autobahn run on case 7.1.6, which is an **owner gate and was not
run** — the reproduction was built specifically so that it need not be.

---

## 7. FINDING — the fix moves ledger sequence 34, whose disposition is `unresolved`

Sequence 54's own rationale names sequence 34 as the record to check against.
**No commit on this branch mentions it, and the fix moves it.**

Sequence 34 (`delta-71c02bf6...`, Autobahn 5.15, disposition `unresolved`)
describes the same Java mechanism from the other side: *"Java translates the
whole chop first, then dispatches frame by frame, so the echo is ENQUEUED
during the second fragment's dispatch and the failure path's flushAndClose
write demand flushes it; the Rust adapter's typed failure lands before the
completed message's Text event is delivered, so the echo is never enqueued at
all."* The DIV-05 policy installs that Java order in the full-stack path.

Measured over a real loopback socket, same wire in one chop — TEXT FIN=0
`fragment1`, CONTINUATION FIN=1 `fragment2` (a complete message), CONTINUATION
FIN=0 `fragment3` (the violation), TEXT FIN=1 `fragment4`:

| build | peer received | `texts` delivered | outcome |
| --- | --- | --- | --- |
| mainline `131b7b8` | `[(0x8, 2)]` — the 1002 close only | 0 | `ProtocolFailure(JavaInvalidData, 1002)` |
| this branch | `[(0x1, 18)="fragment1fragment2", (0x8, 2)]` | 1 | `ProtocolFailure(JavaInvalidData, 1002)` |

The branch's answer is shipped Java's. It is also the RFC-**less**-strict
answer: RFC 6455 7.1.7 permits failing immediately on the violation, which is
what the port did, and that permission is precisely why sequence 34 is
`unresolved` rather than a defect. **So this branch resolves an undecided
ledger record as a side effect.**

Nothing here decides it. It is pinned so it cannot happen silently —
`close_overtakes_echo.rs :: the_autobahn_5_15_chop_now_returns_the_completed_echo_before_the_violation_close`,
labelled in its own doc comment as a side-effect pin and not a DIV-05 check —
and the draft ledger proposal puts both readings in front of the owner. No
Autobahn run was made; the record notes the suite classes both behaviours as
passing (OK vs NON-STRICT), and that expectation is **untested here**.

---

## 8. FINDINGS — two evidence artifacts the branch left stale

Both were failing gates on the branch **as pushed at `755b8c8`**, and both were
verified NOT to be baseline by putting mainline's files in this same tree and
re-reading exit 0.

### 8.1 `evidence/linkage/*`

Commit `81decab` refroze the linkage after the io_loop change; commit
`755b8c8` then moved the fix into `ws-driver`, changing BOTH files again —
deleting io_loop's `use ws_core::framing::…` (undoing the +1 line shift
`81decab` had just frozen) and adding 426 lines to `ws-driver/src/lib.rs`
(moving four `ws_driver` declarations). No second refreeze; no one read the
gate afterwards.

    go test ./internal/linkage/     exit 1
      LINKAGE_VERIFICATION_DRIFTED, LINKAGE_DAG_DRIFTED
      row …wrappedioexception symbol ws_testee::io_loop::LoopOutcome::SocketError digest is stale
      symbol ws_driver::ConnectionDriver digest is stale

Refrozen deliberately, **both exits read**:
`LINKAGE_REGENERATE=1 go test ./internal/linkage/` exit **1** (by design), then
`go test ./internal/linkage/` exit **0**. Diff is digests and line numbers over
eight rows and nothing else; no row added, removed or re-pointed. A second
refreeze was needed later for this session's own `schedule_exploration.rs`
change (`evidence.linkage.schedule-exploration digest is stale`), run the same
way, one digest row.

### 8.2 `assurance/concurrency/results.json`

It anchors the US-017 bounded schedule exploration to two git blobs — the
driver under exploration and the harness that produced the counters — and this
branch changed both.

    go test ./internal/formalplan/     exit 1
      RESULTS_TARGET_BLOB_STALE  target.source   records ca05da2e…, tree hashes a9b69a3e…
      RESULTS_TARGET_BLOB_STALE  target.harness  records 800c0d51…, tree hashes 6f2115d3…

Rebound — but only after **re-executing the exploration** and reading every
counter back IDENTICAL (schedules 92160, branches 352598, executions 184320,
distinct_trace_digests 4587, closed_terminal_runs 1176, halted_terminals 910,
failure_halted_runs 90984, accepted 217142, refused_full 66946, applied 77505,
rejected 29454, events 359030, deferred_output_pending 48233,
deferred_command_turn 37381, deferred_backpressure 5410, rejected_inputs 52826,
write_drop_reports 37813, dropped_bytes 134430, receiver_drop_refusals 92160,
max_drain_polls 11). Because the counters were re-measured rather than assumed,
`recorded_at` is left where it is.

**Disclosed limitation, not an omission:** no `revision_history` entry was
added because none can be. `crValidateRevisionHistory`
(`internal/formalplan/concurrencyresults.go:5017`) refuses any superseded
paragraph whose `counters_quoted` equal the CURRENT paragraph's — so a revision
in which the TREE moved and the READING did not is **inexpressible in that
array**. The rebinding sentence appended to `recorded_at_provenance` names the
branch, quotes both old and new blob ids, lists the re-read counters, and says
this.

### 8.3 Baseline failures, confirmed against mainline in this same tree

`go test -timeout 40m ./...` exits 1. The failing packages are
`cmd/formalcoverctl`, `internal/formalcoverage`, `internal/formalplan`,
`internal/lab`, `internal/portplan` — the same five, with the same tests, when
mainline's versions of every file this branch touches are put back. Every
remaining `internal/formalplan` failure reads
`JAVA_SOURCE_UNAVAILABLE_OFFLINE: pinned immutable URL returned HTTP 403`, i.e.
section 1.1's blocked archive endpoint. Two of the five
(`cmd/formalcoverctl`, `internal/formalcoverage`) are not in the handoff's
named baseline list but are demonstrably baseline here.

---

## 9. Residuals, and the one owner question

1. **The handshake-phase coalescing defect is NOT fixed and is disclosed.**
   When a peer pipelines frames into the same read as the opening handshake,
   `ConnectionCore::finish_handshake_open` parks the remainder in `self.pending`
   (`rust/ws-core/src/connection.rs:1017-1034` — read and confirmed) and it is
   decoded only on a SUBSEQUENT bytes input, which may never arrive. Shipped
   Java handles that case at `WebSocketImpl.java:232-240`. The DIV-05 policy
   deliberately does not apply while `NotYetConnected` (attack E2 shows why: an
   HTTP request head read as a frame header hits an undefined opcode and
   disables alignment for the connection), so it neither fixes nor worsens
   this. Mainline's `drive_connection_from` carryover is an adjacent
   *adapter*-level mechanism and does not reach the core's `pending`.
2. **`connection_driver_in_state` is a "test and fixture seam" that keeps
   `WholeChunk`, and a real socket fixture uses it.**
   `rust/ws-testee/tests/loopback.rs` drives real sockets through it, so those
   fixtures do NOT exercise the shipped feed policy. The `adapter-linkage` gate
   requires `connection_driver(` to appear somewhere in `ws-testee/src` — it
   does — but nothing forbids a future production adapter from reaching for the
   in-state constructor and silently losing this fix.
3. **The 7.1.6 closure is not confirmed on the real suite.** That needs an
   Autobahn run, which is an owner gate; the reproduction was built so it is
   not needed, and this record claims only what the reproduction shows.

**The owner question** is section 7: this branch moves the subject of ledger
sequence 34, whose disposition is `unresolved`, in Java's direction and away
from the RFC-stricter behaviour. That is a tradeoff, and tradeoffs are not the
port's to weigh.

---

## 10. Final readings, all exits from the process

| command | exit |
| --- | --- |
| `cargo test --workspace --all-targets --all-features` (42 suites) | 0 |
| `cargo fmt --all -- --check` | 0 |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 |
| `make -C rust gates` — `ac1-gates PASS 8/8`, `adapter-linkage PASS`, ledger integrity ok | 0 |
| `make -C rust fixture-guard` — `PASS`, files 49, loops 308, violations 0, waivers 0 | 0 |
| `go test ./internal/linkage/` | 0 |
| `go run ./cmd/corporactl evaluate … --tier public` (port) | 0 |
| `go run ./cmd/corporactl evaluate … --tier handshake --live` (port, neutralised) | 0 |
| `cargo test -p ws-testee --test close_overtakes_echo` (4 passed) | 0 |
| `go test -timeout 40m ./...` — baseline five only, see 8.3 | 1 |
