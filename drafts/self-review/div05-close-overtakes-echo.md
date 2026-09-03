# DIV-05: close overtakes echo (behavior-delta ledger sequence 54)

STATUS: IN PROGRESS — resumed branch, record being rebuilt from scratch.
Sections below are only what has been executed and read in THIS session.
Deletion attacks and the corpus-visibility experiment are still outstanding.

Branch: `claude/div05-close-overtakes-echo`, resumed at `755b8c8`.
Merge base with mainline: `58f3aa4`. Mainline head fetched for comparison:
`131b7b8`.

## Why this record is being written twice

The seven commits on this branch were made by a predecessor session that
pushed code and never wrote the record. The loop caught it and filed
`drafts/self-review/findings/F009-i-read-a-record-by-its-existence.md`. This
file is not a summary of those commits' messages — every claim below was
re-derived here, and where the code or the commit message is wrong, it is
said so.

---

## 1. The Java citation (SOURCE CITATION — no Java process was run for it)

The `java-oracle` never opens a socket and has no `decodeFrames`, so nothing
in this repository can *execute* the Java behaviour DIV-05 is about. Every
Java claim in this record is a **citation of pinned source**, and is labelled
as one. (The live Java runtime WAS executed, but only for the corpus
differential and handshake exam in section 6, which do not exercise this
path.)

### Provenance of the tree the citations are read from

`.quarantine/` is git-ignored and was empty in this container, so the tree was
re-acquired. The archive URL in `evidence/intake/source-pins.json`
(`.../archive/da3cf2a....tar.gz`, sha256
`f44e7647b4aee40819b51947cf0bb5f35a48293a202b77704c3c79e98ed13cb4`) is **not
reachable from this environment** — the agent proxy answers GitHub archive
requests with `GitHub access to this repository is not enabled for this
session` (378 bytes of JSON, sha256
`b3e03aaaff81d68730d67392a135ac3fdfdf022880c66632ab188d2fe084cda3`). So the
pinned tarball digest could NOT be checked, and this record does not claim it
was.

What was checked instead is the **other half of the same pin**. The artifact's
`provenance` field reads `git commit da3cf2a777aed862f2f5b5cf060cae7969958667
tree 30c108fd7b68663f645ee9cb8e3daaf4a39235ea tag v1.6.0`. The commit was
fetched over the anonymous git lane into `/home/user/tootallnate/java-websocket`
and read:

    git -C /home/user/tootallnate/java-websocket cat-file -p da3cf2a777aed862f2f5b5cf060cae7969958667
    tree 30c108fd7b68663f645ee9cb8e3daaf4a39235ea      <- equals the pin

and materialised with `git archive` into
`.quarantine/Java-WebSocket-da3cf2a777aed862f2f5b5cf060cae7969958667/`. This
verifies the CONTENT identity of the tree (git's own Merkle hash over the
whole tree) but NOT the byte identity of the GitHub-generated tarball. They
are different digests over different serialisations; if a reader needs the
tarball digest, it has to be re-checked somewhere the archive endpoint is
reachable.

Cross-check that the materialised tree is the same one the repository's
existing records were written against — four citations taken from
`drafts/ledger-proposals/server-close-parity.json`, all landing exactly:

| cited | reads |
| --- | --- |
| `WebSocketImpl.java:102` | `public final BlockingQueue<ByteBuffer> inQueue;` |
| `SocketChannelIOHelper.java:110-113` | the `outQueue.isEmpty() && isFlushAndClose() && role == SERVER` hang-up |
| `WebSocketImpl.java:573-578` | `public void closeConnection()` |
| `Draft_6455.java:1068` | `webSocketImpl.close(code, reason, true);` |

### The chain that decides DIV-05

All line numbers are `.quarantine/Java-WebSocket-da3cf2a.../src/main/java/org/java_websocket/`.

1. **`WebSocketImpl.decode` — `WebSocketImpl.java:220-242`.** Frame decoding
   is reached only from the OPEN arm (`:227-230`); while `NOT_YET_CONNECTED`
   the buffer goes to `decodeHandshake`, and only if that succeeds does
   `:232-240` run `decodeFrames` over whichever buffer still has remaining
   bytes.
2. **`WebSocketImpl.decodeFrames` — `WebSocketImpl.java:391-419`.** The whole
   socket buffer is translated to a `List<Framedata>` in ONE call
   (`frames = draft.translateFrame(socketBuffer);`, `:394`; the declaration is
   `Draft_6455.java:724`), and the list is then walked **one frame at a time**:

       395:       for (Framedata f : frames) {
       396:         log.trace("matched frame: {}", f);
       397:         draft.processFrame(this, f);
       398:       }

3. **`Draft_6455.processFrameText` — `Draft_6455.java:982-990`.** Inside that
   iteration, synchronously:

       985:       webSocketImpl.getWebSocketListener()
       986:           .onWebsocketMessage(webSocketImpl, Charsetfunctions.stringUtf8(frame.getPayloadData()));

   An echoing listener's `send()` has therefore already appended the echo to
   `outQueue` (`WebSocketImpl.write`, `:736-740`, `outQueue.add(buf)`) before
   iteration 2 begins.
4. **`Draft_6455.processFrameClosing` — `Draft_6455.java:1054-1073`.** Only
   now: `webSocketImpl.close(code, reason, true)` (`:1068`).
5. **`WebSocketImpl.close(int,String,boolean)` — `WebSocketImpl.java:463-507`.**
   `sendFrame(closeFrame)` at `:486` appends the close frame BEHIND the echo
   in the same `outQueue`, then `flushAndClose(code, message, remote)` at
   `:494`.
6. **`WebSocketImpl.flushAndClose` — `WebSocketImpl.java:584-...`.** Its own
   comment is the load-bearing sentence:

       594:     wsl.onWriteDemand(
       595:         this); // ensures that all outgoing frames are flushed before closing the connection

7. **`SocketChannelIOHelper.batch` — `SocketChannelIOHelper.java:110-113`.**
   The TCP connection is closed only once `ws.outQueue.isEmpty()`.

**Conclusion of the citation.** For `[completed data frame][close frame]` in
ONE socket read, shipped Java's wire answer is: the echo, then the close echo,
then (server role) the hang-up. Nothing in the chain discards a message that
was already fully received. The property that produces this is the
*synchronous per-frame dispatch* at `:395-398` — not buffering, not size, not
any close-specific rule.

---

## 2. The RED reading

Method: the branch's fixture `rust/ws-testee/tests/close_overtakes_echo.rs`
kept in place; the two port sources the branch changes
(`rust/ws-driver/src/lib.rs`, `rust/ws-testee/src/io_loop.rs`) replaced with
mainline `131b7b8`'s versions verbatim (`git show
origin/claude/feature/verified-java-websocket-port:<path>`); nothing else
touched.

    cargo test -p ws-testee --test close_overtakes_echo
    test result: FAILED. 0 passed; 3 failed
    exit code 101   (read from the process)

| test | subject wrote (left) | required (right) |
| --- | --- | --- |
| `a_close_sharing_one_read_with_a_completed_text_frame_does_not_cancel_the_echo` | `[(8, 6)]` | `[(1, 5), (8, 6)]` |
| `the_autobahn_7_1_6_burst_returns_both_echoes_before_the_close` | `[(8, 2)]` | `[(1, 262144), (1, 12), (8, 2)]` |
| `a_client_role_endpoint_echoes_before_answering_a_close_in_the_same_read` | `[(8, 6)]` | `[(1, 5), (8, 6)]` |

Each failure message names the divergence and cites the Java that decides it.

With the branch's own sources restored, the same command reads
`test result: ok. 3 passed; 0 failed`, **exit code 0**.

### The RED readings in commit `0a4f32c` are not reproducible as written

That commit records the client case's RED left-hand side as `[]`. Against
mainline `131b7b8` it is `[(8, 6)]`. The difference is mainline's own
`server-close-parity` landing, which is on `131b7b8` and not on the branch's
merge base `58f3aa4` — the commit was measured against `58f3aa4`. Both are
RED; the record's reading is the one taken here, against mainline.

---

## 3. Is the ledger record's description right? No, in two places

Ledger sequence 54 rationale says: *"with a 256 KiB text message followed
immediately by a Close, shipped Java delivers the echo and answers the close
with 1000; the port drops the echo and sends no close."*

**(a) The 256 KiB plays no causal part.** Experiment run against unmodified
mainline sources, same 5-byte `hello` message, same close, same single socket
write from the peer, only the SUBJECT's read buffer changed:

| `IoBounds::read_buffer` | peer received | `report.outcome` |
| --- | --- | --- |
| 4096 (one read takes both frames) | `[(0x8, 6)]` — echo dropped | `ProtocolFailure(StateViolation)` |
| 1 (no read can span the boundary) | `[(0x1, 5), (0x8, 6)]` — Java's order | `Terminal` |

The discriminator is **chunk coalescing across a frame boundary**, not message
size. A 256 KiB message merely makes coalescing overwhelmingly likely on the
wire; a 5-byte one diverges identically when the frames share a read.

**(b) "sends no close" is stale.** At mainline `131b7b8` the port DOES send
the close echo — `(0x8, 6)` above, and `(0x8, 2)` on the 7.1.6 shape. What it
drops is the message echo. The ledger's observation was recomputed from the
`us019-prov-20260828T183623Z` Autobahn run whose subject was commit
`518b77aa` (`evidence/java/observed-close-divergences.json`
`recomputed_from.subject_commit`); the close-composition and
server-close-parity work landed after it. The measured extent (1 server case,
1 client case out of 247) is not challenged — only the prose description of
the port's behaviour.

A corrected record is proposed as a DRAFT under `drafts/ledger-proposals/`.
Sequence 54 is inside an append-only chain with a frozen prefix and is NOT
edited or appended to by this branch.

---

## 4. Why the fix is in `ws-driver` (verified, not taken on the commit's word)

The last commit says "the architecture gate said so". The gate is real, it is
`adapter-linkage` (`cmd/rustgatectl/adapter_linkage.go`), and it says exactly
that. Re-derived here rather than quoted:

* Scope (`gateAdapterLinkage`, `adapter_linkage.go:274-330`): it walks
  `rust/ws-testee/src` — **production sources only, tests exempt by design**.
* `forbiddenProtocolSurface` (`adapter_linkage.go:48-65`) lists 15 symbols
  including `Draft6455`, `HeaderDecode` and `ws_core::framing` — the three the
  boundary-finder must name.
* Seeded re-derivation: added `use ws_core::framing::{Draft6455, HeaderDecode};`
  to `rust/ws-testee/src/io_loop.rs` and ran
  `go run ./cmd/rustgatectl -root . -gate adapter-linkage`:

      gate=adapter-linkage finding=ADAPTER_PROTOCOL_SURFACE detail="ws-testee/src/io_loop.rs names forbidden protocol symbol \"Draft6455\""
      gate=adapter-linkage finding=ADAPTER_PROTOCOL_SURFACE detail="ws-testee/src/io_loop.rs names forbidden protocol symbol \"HeaderDecode\""
      gate=adapter-linkage finding=ADAPTER_PROTOCOL_SURFACE detail="ws-testee/src/io_loop.rs names forbidden protocol symbol \"ws_core::framing\""
      gate=adapter-linkage verdict=FAIL detail="3 adapter architecture findings"
      ac1-gates verdict=FAIL gates_passed=0/1
      exit status 1                                  (exit 1, read)

  Seed removed, whole gate set re-run: `make -C rust gates` **exit 0**,
  `gate=adapter-linkage verdict=PASS`, `ac1-gates verdict=PASS gates_passed=8/8`.

So `ws-testee` was mechanically wrong, and the gate was not weakened to make
the move: the fix names those symbols in `ws-driver`, which the gate does not
scan and never has.

**Why not `ws-core`.** The corpus scores per-chunk records. `corpora/public/
scenarios.jsonl` carries 38 `input_chunk` events of the shape
`{"bytes":7,"step":0,"type":"input_chunk"}` inside `expected.events`. A core
that split a chunk at a frame boundary would emit two such records where the
corpus pins one, moving bytes that are the oracle observable. Confirmed by
reading the corpus, not by assertion.

**Why `ws-driver` is the right home rather than merely the only legal one.**
`ws-driver` is the `WebSocketImpl` mirror; `decodeFrames`' dispatch loop is a
`WebSocketImpl` method. The same layering already holds `AutoResponsePolicy`
(`Draft_6455.processFrame`'s ping arm) and `CloseEchoPolicy`
(`WebSocketImpl.close`'s composition). The corpus objection is answered not by
exemption but by a policy whose DEFAULT is the oracle observable:
`InboundFeedPolicy::WholeChunk` is `#[default]`, every `*_with_policies` and
`*_in_state*` constructor keeps it (`ws-driver/src/lib.rs:468-486`, `:494-542`),
and only `connection_driver` — the fresh-connection full-stack constructor —
opts into `OneFramePerTurn`. `ws-oracle-harness` reaches the driver through
`connection_driver_in_state_with_policies` (`core_adapter.rs:717`, `:2175`),
so the differential path structurally keeps `WholeChunk`. Verified by reading
every call site in the workspace.

---

## 6. Corpus differential and handshake exam (re-run: `ws-driver/src` and `ws-testee/src` both changed)

Throwaway 32-byte hex secret, public and handshake tiers only, per
`.claude/CLOUD-ENVIRONMENT.md`. Release harness clean-rebuilt
(`cargo clean --release -p ws-driver -p ws-core -p ws-oracle-harness` then
`cargo build --release -p ws-oracle-harness --locked`, exit 0) so the binary
provably comes from this branch's sources; harness sha256
`1872e26c44a3d22998eeda3d9fe2e09e69ca96912a23318cfed86b79f96bc12c`,
identical before and after the clean.

Handshake request digest:
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

No shift anywhere. Runtime jars verified against their pinned digests before
use: `Java-WebSocket-1.6.0.jar`
`eae29213e4f16515639c28957200f011b3967fffcada1962cf0255d24919c22f`,
`slf4j-api-2.0.13.jar`
`e7c2a48e8515ba1f49fa637d57b4e2f590b3f5bd97407ac699c3aa5efb1204a9`.

**Deviation, stated:** the pinned JDK is a macOS Homebrew bottle
(`openjdk-17.0.19-homebrew-bottle`) and the Temurin 17 fallback host is
refused by this environment's egress proxy (`api.adoptium.net` →
`connect_rejected`). The live Java legs ran on the container's **OpenJDK
21.0.10**, with all three encoding properties
(`-Dfile.encoding`, `-Dsun.stdout.encoding`, `-Dstdout.encoding`) set to UTF-8
as `.claude/CLOUD-ENVIRONMENT.md` prescribes for exactly this reason. Classes
were compiled `--release 17`. The 74/74 with no `?` substitutions is
consistent with the documented UTF-8-correct reading.

**What a green differential does and does not mean here.** These are CASE
counts against known ceilings — 73 distinct scored observations behind the 74,
26 behind the 49 — and, more decisively for DIV-05, the differential path is
*structurally* pinned to `InboundFeedPolicy::WholeChunk`. So a green
differential is evidence that the change did not BREAK the oracle observable;
it is NOT evidence that the fix works, and it never could be. See section 7.

---

*(sections 5, 7 and the findings list follow in the next revision of this file)*
