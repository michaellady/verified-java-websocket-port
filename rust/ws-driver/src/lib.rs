//! # ws-driver: the pull-driven single-owner driver seam for `ws_core` (US-017)
//!
//! Multiple producers share only the bounded nonblocking
//! [`ws_core::CommandSender`] handle; exactly ONE owner holds the
//! [`ws_core::ConnectionCore`], drains its ordered outputs, tracks
//! partial-write progress, and delivers the terminal outcome exactly once.
//! Transports stay outside this crate (the US-018 adapters own sockets); the
//! driver is deterministic and clock-free like the core it wraps.
//!
//! The driver also owns the US-015 AC1 configurable automatic
//! ping-response policy ([`AutoResponsePolicy`]): the sans-io core is
//! Q18-faithful and never auto-pongs, while shipped Java-WebSocket 1.6.0
//! replies at the WebSocketImpl/listener layer above the Draft — the
//! layer this crate ports — so the automatic pong is injected here,
//! through the ordinary command seam, when the Ping event is delivered.
//!
//! For the same layering reason it owns the close-echo WIRE composition
//! ([`CloseEchoPolicy`], E5b): the core's Q19/Q10 echo is the Draft-level
//! observable the java-oracle harness produces, while the shipped full
//! stack answers an inbound close through `WebSocketImpl.close`, which
//! builds its OWN close frame from the RECEIVED code and reason
//! (WebSocketImpl.java:482-486). Autobahn 7.3.2 is the case that separates
//! them.
//!
//! ## Post-failure
//!
//! This contract did not exist anywhere in `contracts/`, `docs/` or `rust/`
//! before it was written here, which is why three separate rounds of the
//! exploration suite asserted around it. What the driver guarantees after a
//! fatal:
//!
//! **New work is refused.** The first fatal poisons
//! [`ws_core::ConnectionCore`], so every later input comes back as
//! `STATE_VIOLATION` (`ws_core::ConnectionCore::handle`).
//!
//! **Work committed BEFORE the failure still drains, in committed order.**
//! Poisoning gates INPUTS, not output drain: [`ConnectionDriver::poll`]
//! suppresses `next_output()` only on the single poll that carries the
//! failure, so queued writes and events drain on the polls after it and a
//! `Terminal` already earned (the core reached `Closed`) is still delivered
//! exactly once. **No quiescence is promised.** This half MATCHES shipped
//! Java, which flushes explicitly: `flushAndClose` calls `onWriteDemand`
//! with the comment "ensures that all outgoing frames are flushed before
//! closing the connection" (WebSocketImpl.java:594-595), and on the server
//! `SocketChannelIOHelper.batch` completes the shutdown only once
//! `outQueue` empties (SocketChannelIOHelper.java:110-113). Halting instead
//! would DROP committed output, contradicting the
//! `accepted-eventual-exactly-once` and `fifo-owner-order` properties the
//! same suite checks. Adapters that need a hard stop implement it
//! themselves — see `ws-testee`'s `io_loop`.
//!
//! **A fatal surfaces as [`DriverOutput::Failure`] however it arrived** —
//! as inbound bytes or as a rejected command. See
//! [`ConnectionDriver::finish_poll`] for the defect that made those two
//! paths distinguishable and the owner decision that closed it.
//!
//! **…but the ARRIVAL PATH itself is never erased.** Surfacing uniformly is
//! about the HALT: every fatal must stop an adapter. It is not a claim that
//! every fatal deserves the same wire REACTION, and conflating the two is a
//! landed defect: C5 made the two paths indistinguishable, C6 then answered
//! every failure as though it were an inbound decode violation, and a
//! locally rejected `send_close {code: 999}` — which the pinned Java oracle
//! records as leaving the connection `open` with nothing on the wire — put a
//! 1002 close frame on the socket. [`DriverOutput::Failure`] therefore
//! carries a [`FailureOrigin`] beside the failure, and the C6 reaction is
//! gated on [`FailureOrigin::InboundDecode`].
//!
//! **The driver takes NO action in RESPONSE to a fatal — and the owner has
//! ruled that this must change.** Measured on a real protocol violation
//! (RSV1 on TEXT; reserved opcode `0x3`): the stack composes no close
//! frame, performs no state transition, stays in `Open` and therefore never
//! converges or delivers a `Terminal`; the close code travels as failure
//! metadata, exactly the java-oracle `error.close_code` shape
//! (`OracleEngine.java:591-606`). Shipped `WebSocketImpl` on the identical
//! input does the opposite: it sends a 1002 close frame
//! (WebSocketImpl.java:405-408, :481-487) and moves `OPEN -> CLOSING`
//! (:503), later `-> CLOSED` (:566).
//!
//! Owner decision `us017-post-failure-owner-decisions-2026-08-28.json`
//! (`c6-match-java-fully`) rules that the stack must follow shipped
//! `WebSocketImpl` here. That change is IMPLEMENTED AND MEASURED but NOT
//! LANDED, because it trips the decision's own hard-stop condition: placing
//! the reaction in `ws_core` moves 18 of the 74 public corpus cases off
//! live Java on `final_state` (`open` -> `closing`) and `counts.frames`
//! (+1), taking scored-field disagreement with the live oracle from ZERO to
//! 18. The decision requires that shift be surfaced for an explicit
//! layer-split ruling rather than re-baselined. Until that ruling lands
//! this paragraph describes the behaviour, NOT an endorsement of it: the
//! full measurement is in
//! `workspace/orchestrator/verified-java-websocket-port-claude/drafts/post-failure-receipt.json`.
//!
//! ## Borrow attribution (owner strategy: borrow with attribution)
//!
//! Adapted from the Codex-plane US-017 `websocket-driver` (codex-import
//! 6a7606a): the pull-driven `poll(DriverInput) -> PollResult` shape, the
//! partial-write cursor with exact `WriteProgress` validation, the
//! inbound-vs-command alternation turn, EOF/shutdown latching and the
//! exactly-once `Terminal` delivery are their design. Their terminal
//! REJECTION of still-queued commands was adopted and has since been
//! REMOVED: under owner decision
//! `us017-post-terminal-owner-decision-2026-08-28.json`
//! (`post-terminal-command`) a command that arrives after convergence is
//! applied to the core like any other, so the refusal that surfaces is the
//! core's own `STATE_VIOLATION` rather than a driver-invented verdict. The
//! same decision (`post-terminal-inbound`) removed the `terminal_delivered`
//! gate on input application, which had made post-terminal inbound bytes
//! report `Consumed` while the core never saw them. `terminal_delivered`
//! remains what its name says: a DELIVERY latch keeping `Terminal`
//! once-only. **Adaptation to `ws_core`:** their
//! `AdmissionGate` + `mpsc::sync_channel` producer machinery is NOT adopted —
//! the incumbent `ws_core` bounded multi-producer command channel
//! ([`ws_core::CommandQueue`] / [`ws_core::CommandSender`], the US-009 AC4
//! boundary) is the single producer seam, so no second admission mechanism
//! can drift from it; their `StepResult`-batch commit ledger is NOT adopted —
//! the core's own bounded event/write queues are the ordered ledger and the
//! driver drains them, never duplicating protocol state (the US-009
//! "adapters cannot duplicate protocol state" promise). Their
//! `ProducersDropped` disposition is NOT adopted: PRODUCER lifecycle
//! belongs to the embedding adapter, and the `ws_core` channel carries no
//! producer-disconnect signal.
//!
//! The mirror-image RECEIVER lifecycle IS carried, and by the incumbent
//! seam rather than a parallel one: dropping the sole owner (this
//! [`ConnectionDriver`], which holds the [`ws_core::CommandQueue`])
//! publishes [`ws_core::CommandRefusalReason::ReceiverDropped`], so a
//! producer's `try_send` refuses instead of reporting accepted into a
//! queue nobody will drain (US-017 AC2 receiver-drop; story review
//! BLOCKING-1, session 01a04626 — the earlier stance pinned that accepted
//! send as correct).
//!
//! The six `fuzz-seeds/us017/*.seed` schedule seeds are adopted byte-verbatim
//! with attribution; `tests/driver_contract.rs` re-derives each seed's
//! property against this driver with a deterministic schedule interpreter.
//!
//! `tests/schedule_exploration.rs` is the story's bounded schedule
//! exploration: it exhaustively enumerates every interleaving of five fixed
//! actor programs within a declared context-switch bound, asserts the
//! driver-seam invariants on each schedule (twice, for replay determinism),
//! and retains a deterministically minimized reproduction for every failure
//! (`fuzz-seeds/us017/minimized/` for the demonstrated fault corpus,
//! `fuzz-seeds/us017/regressions/` for real found-and-fixed defects).
//! Results: `assurance/concurrency/results.json`. Systematic testing under
//! the declared bounds — never proof.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::VecDeque;

use ws_core::close::CloseOrigin;
use ws_core::framing::{CLOSE_CONSTRUCTOR_PAYLOAD, Draft6455, HeaderDecode, Opcode};
use ws_core::{
    CloseDetail, CommandQueue, CommandSender, ConnectionConfig, ConnectionCore, InitialState,
    Input, LocalCommand, ReadyState, Role, SemanticEvent, SemanticEventKind, TransportWrite,
    TypedProtocolFailure,
};

/// The configurable automatic control-frame response policy (US-015 AC1).
///
/// The sans-io core is Q18-faithful and never auto-pongs (pinned by the
/// public corpus and the live-oracle confirmation). Shipped Java-WebSocket
/// 1.6.0 replies one layer ABOVE the Draft: `Draft_6455.processFrame`
/// dispatches an inbound PING to the listener
/// (drafts/Draft_6455.java:898-899) and the DEFAULT listener
/// `WebSocketAdapter.onWebsocketPing` sends
/// `new PongFrame((PingFrame) f)` back (WebSocketAdapter.java:84-86),
/// whose constructor copies the ping's payload byte-for-byte
/// (framing/PongFrame.java:47-50) — proven live in the US-018 cross-peer
/// exam (protected/us018-closure/crosspeer/). The driver is the
/// WebSocketImpl pump's port-side home, so the reply lives here,
/// injected through the ordinary command seam
/// ([`ws_core::LocalCommand::SendPong`]) when the Ping semantic event is
/// delivered. The reply's state gate is Java's own `send(Collection)`
/// isOpen throw (WebSocketImpl.java:667-670): once the connection has left
/// Open, the reply produces no wire write — the driver drops it exactly as
/// Java's `sendFrame` would refuse it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AutoResponsePolicy {
    /// The shipped-Java default listener behavior: answer every delivered
    /// inbound Ping with a pong carrying the ping's payload
    /// byte-identically.
    #[default]
    PongInboundPing,
    /// No automatic response (a custom `onWebsocketPing` override in Java
    /// vocabulary): the embedding layer owns replies.
    Disabled,
}

/// How much of one inbound chunk reaches the core per turn (DIV-05,
/// behavior-delta ledger sequence 54).
///
/// # What shipped Java does
///
/// `WebSocketImpl.decodeFrames(ByteBuffer)` (WebSocketImpl.java:391-419)
/// translates the WHOLE socket buffer into a `List<Framedata>` in one call
/// (`frames = draft.translateFrame(socketBuffer)`, :394) and then walks that
/// list ONE FRAME AT A TIME:
/// `for (Framedata f : frames) { draft.processFrame(this, f); }` (:395-398).
/// `Draft_6455.processFrame` (drafts/Draft_6455.java:893-918) dispatches TEXT
/// to `processFrameText` (:982-990), which calls `onWebsocketMessage`
/// SYNCHRONOUSLY inside that iteration, so an echoing listener's frame is
/// already in `outQueue` (`WebSocketImpl.send(String)` :640-646 ->
/// `send(Collection)` :667-680) before the NEXT iteration reaches the close
/// frame. `processFrameClosing` (drafts/Draft_6455.java:1054-1073) then calls
/// `webSocketImpl.close(code, reason, true)` (:1068), which appends the close
/// BEHIND the echo (WebSocketImpl.java:481-487) and calls `flushAndClose`
/// (:494), whose `onWriteDemand` "ensures that all outgoing frames are
/// flushed before closing the connection" (:594-595);
/// `SocketChannelIOHelper.batch` (SocketChannelIOHelper.java:110-113) only
/// hangs up once `ws.outQueue.isEmpty()`.
///
/// So Java's wire answer to `[data frame][close frame]` in ONE read is the
/// echo, then the close echo, then the hang-up.
///
/// # Why the port needed a policy for it
///
/// `ws_core` is Sans-I/O: it CANNOT call back into the application mid-chunk.
/// `ConnectionCore::handle(TransportBytes)` applies every frame of a chunk in
/// one call and queues the semantic events for the owner to drain afterwards.
/// A close sharing a chunk with a completed data frame therefore moves the
/// core to `Closing` BEFORE the owner's policy is handed the message, and the
/// echo it then enqueues meets the core's `requireOpen` gate (quirk Q26 —
/// Java's own `send(Collection)` isOpen throw, WebSocketImpl.java:667-670)
/// and is refused with a fatal `STATE_VIOLATION`. The message is dropped.
/// Autobahn 7.1.6 is exactly that shape.
///
/// This crate is the `WebSocketImpl` mirror, so `decodeFrames`' per-frame
/// dispatch loop belongs here — the same layering decision as
/// [`AutoResponsePolicy`] and [`CloseEchoPolicy`], and the same one the
/// US-018 `adapter-linkage` architecture gate enforces by forbidding the
/// networking adapter to name `ws_core::framing` at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InboundFeedPolicy {
    /// The ORACLE observable, and the default: the whole chunk goes to the
    /// core in one `handle` call, producing one `input_chunk {bytes}` record
    /// for it. `corpora/public/scenarios.jsonl` SCORES those records, so the
    /// corpus differential path must keep this arm.
    #[default]
    WholeChunk,
    /// Shipped-Java full-stack behavior: at most ONE frame reaches the core
    /// per turn, and no further inbound is applied until everything that
    /// frame committed has drained — the port's image of `processFrame`
    /// having RETURNED. Partial consumption is reported honestly as
    /// [`InputDisposition::Consumed`] with the byte count actually applied,
    /// and a turn refused for dispatch is
    /// [`DeferredReason::FrameDispatchPending`].
    OneFramePerTurn,
}

/// The largest WebSocket frame header: 2 base bytes + 8 extended-length bytes
/// + a 4-byte mask key.
const MAX_FRAME_HEADER_BYTES: usize = 14;

/// Frame-boundary bookkeeping for [`InboundFeedPolicy::OneFramePerTurn`].
///
/// It finds BOUNDARIES ONLY, through the core's own
/// [`ws_core::framing::Draft6455::decode_frame_header`] and with NO frame-size
/// cap of its own (`u64::MAX`), so it can never accept anything the core would
/// reject or reject anything the core would accept: every limit, every
/// validity rule and every typed failure stays in the core. The moment the
/// grammar cannot place a boundary — a header the decoder rejects, or a
/// declared length wider than this platform's `usize` — it stops splitting and
/// hands the core whole chunks again, which is
/// [`InboundFeedPolicy::WholeChunk`]'s behaviour, and the core answers as the
/// authority.
///
/// Its state is bounded: at most [`MAX_FRAME_HEADER_BYTES`] of retained header
/// plus a byte counter, whatever the frame size.
#[derive(Debug)]
struct FrameAlignedFeed {
    /// Bytes of the frame currently being fed that the core has not been
    /// handed yet. `None` while the header is still too short to size.
    remaining: Option<usize>,
    /// The head of the frame currently being sized, at most
    /// [`MAX_FRAME_HEADER_BYTES`] bytes.
    head: Vec<u8>,
    /// Cleared once the wire stops parsing: from there on the core gets whole
    /// chunks and decides for itself.
    aligning: bool,
}

impl FrameAlignedFeed {
    fn new() -> FrameAlignedFeed {
        FrameAlignedFeed {
            remaining: None,
            head: Vec::with_capacity(MAX_FRAME_HEADER_BYTES),
            aligning: true,
        }
    }

    /// How many leading bytes of `chunk` may reach the core now without
    /// crossing a frame boundary. Never zero for a non-empty chunk, so the
    /// owner always makes progress.
    fn limit(&mut self, chunk: &[u8]) -> usize {
        if !self.aligning || chunk.is_empty() {
            return chunk.len();
        }
        if let Some(remaining) = self.remaining {
            return remaining.min(chunk.len());
        }
        let mut probe = self.head.clone();
        let want = MAX_FRAME_HEADER_BYTES
            .saturating_sub(probe.len())
            .min(chunk.len());
        probe.extend_from_slice(&chunk[..want]);
        match Draft6455::decode_frame_header(&probe, u64::MAX) {
            Ok(HeaderDecode::Header(header)) => {
                let Ok(payload) = usize::try_from(header.payload_len) else {
                    // A declared length this platform cannot address. The
                    // core's own frame-size gate is the right refusal, so stop
                    // splitting and let it see the bytes.
                    self.aligning = false;
                    return chunk.len();
                };
                let Some(total) = header.header_len.checked_add(payload) else {
                    self.aligning = false;
                    return chunk.len();
                };
                let owed = total.saturating_sub(self.head.len());
                self.remaining = Some(owed);
                owed.min(chunk.len())
            }
            // Everything held so far is shorter than one header, so the
            // boundary is past the end of this chunk: none of it can cross one.
            Ok(HeaderDecode::Insufficient) => chunk.len(),
            // The core is the authority on a rejection; hand it the bytes.
            Err(_) => {
                self.aligning = false;
                chunk.len()
            }
        }
    }

    /// Record that `fed` reached the core.
    fn advance(&mut self, fed: &[u8]) {
        if !self.aligning {
            return;
        }
        match self.remaining {
            Some(remaining) => {
                let left = remaining.saturating_sub(fed.len());
                if left == 0 {
                    self.head.clear();
                    self.remaining = None;
                } else {
                    self.remaining = Some(left);
                }
            }
            None => {
                // Still sizing: keep the head so the next chunk can complete
                // the header. Bounded by construction — `limit` only returns
                // an unsized span when everything held is shorter than one
                // header.
                let room = MAX_FRAME_HEADER_BYTES.saturating_sub(self.head.len());
                let take = room.min(fed.len());
                self.head.extend_from_slice(&fed[..take]);
            }
        }
    }
}

/// The close-echo WIRE composition policy (E5b).
///
/// `ws_core` answers an inbound close received while Open with the Q19
/// echo whose payload is the `CloseFrame` CONSTRUCTOR payload `[0x03,0xE8]`
/// (Q10) — the observable the java-oracle harness produces, because the
/// harness re-emits the RECEIVED frame object
/// (`java-oracle/src/main/java/OracleEngine.java:382`,
/// `emitOutbound(List.of(frame), index, "echo_close")`). That frame object
/// legitimately carries the constructor payload: `CloseFrame.setPayload`
/// overrides the base method and assigns only the `code`/`reason` fields,
/// never `super.setPayload` (framing/CloseFrame.java:246-271), so the
/// buffer built by the constructor (framing/CloseFrame.java:168-172,
/// `FramedataImpl1.get` returning `new CloseFrame()` at
/// framing/FramedataImpl1.java:241-242) survives the decode. That core
/// observable is LIVE-ORACLE-CONFIRMED and ledgered (delta-954132f2…,
/// delta-d509ac38…) and is NOT changed by this policy.
///
/// The shipped FULL STACK puts different bytes on the wire.
/// `Draft_6455.processFrame` routes CLOSING to `processFrameClosing`
/// (drafts/Draft_6455.java:896-897), which reads the decoded
/// `cf.getCloseCode()` / `cf.getMessage()` (drafts/Draft_6455.java:1055-1060)
/// and — TWOWAY handshake type (drafts/Draft_6455.java:1111-1113) — calls
/// `webSocketImpl.close(code, reason, true)` (drafts/Draft_6455.java:1067-1068).
/// `WebSocketImpl.close` then builds a BRAND NEW frame,
/// `new CloseFrame(); setReason(message); setCode(code); isValid();
/// sendFrame(closeFrame);` (WebSocketImpl.java:482-486), whose
/// `updatePayload` writes the low two bytes of the code big-endian followed
/// by the UTF-8 reason (framing/CloseFrame.java:294-302).
///
/// This crate is the `WebSocketImpl` mirror, so the full-stack composition
/// lives here — the same layering decision as [`AutoResponsePolicy`]. It is
/// the identical composition `ws_core`'s LOCAL close already emits
/// (`send_close`), because in shipped Java both paths are the same
/// `WebSocketImpl.close` method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CloseEchoPolicy {
    /// Shipped-Java full-stack behavior: the echo carries the RECEIVED close
    /// code and reason.
    #[default]
    WebSocketImplComposition,
    /// Leave the core's Draft-level/oracle-harness echo bytes untouched (the
    /// constructor payload). For callers scoring against the core observable
    /// rather than the shipped full stack.
    CoreDraftEcho,
}

/// Builds the bounded producer handle and its sole pull-driven owner for a
/// fresh (`NotYetConnected`) connection, under the default
/// [`AutoResponsePolicy::PongInboundPing`] (the shipped-Java listener
/// default), [`CloseEchoPolicy::WebSocketImplComposition`] (the shipped-Java
/// full-stack close composition) and
/// [`InboundFeedPolicy::OneFramePerTurn`] (shipped Java's `decodeFrames`
/// per-frame dispatch loop, DIV-05).
///
/// THIS IS THE FULL-STACK CONSTRUCTOR: all three policies are the shipped
/// ones, because a fresh connection is what a real peer talks to. It is
/// therefore NOT the same as
/// `connection_driver_with_policies(config, role, Default::default(), Default::default())`
/// — that pair keeps [`InboundFeedPolicy`]'s own default,
/// [`InboundFeedPolicy::WholeChunk`], which is the ORACLE observable the
/// public corpus scores. Callers that need the oracle observable must say so,
/// as `ws-oracle-harness` does.
#[must_use]
pub fn connection_driver(
    config: ConnectionConfig,
    role: Role,
) -> (CommandSender, ConnectionDriver) {
    connection_driver_with_all_policies(
        config,
        role,
        AutoResponsePolicy::default(),
        CloseEchoPolicy::default(),
        InboundFeedPolicy::OneFramePerTurn,
    )
}

/// [`connection_driver`] with all three adapter-layer policies stated
/// explicitly, including [`InboundFeedPolicy`].
#[must_use]
pub fn connection_driver_with_all_policies(
    config: ConnectionConfig,
    role: Role,
    policy: AutoResponsePolicy,
    close_echo: CloseEchoPolicy,
    inbound_feed: InboundFeedPolicy,
) -> (CommandSender, ConnectionDriver) {
    let (queue, sender) = CommandQueue::new(&config);
    let core = ConnectionCore::new(config, role);
    (
        sender,
        ConnectionDriver::new(core, queue, policy, close_echo, inbound_feed),
    )
}

/// [`connection_driver`] with an explicit automatic-response policy.
#[must_use]
pub fn connection_driver_with_policy(
    config: ConnectionConfig,
    role: Role,
    policy: AutoResponsePolicy,
) -> (CommandSender, ConnectionDriver) {
    connection_driver_with_policies(config, role, policy, CloseEchoPolicy::default())
}

/// [`connection_driver`] with both adapter-layer policies stated explicitly.
#[must_use]
pub fn connection_driver_with_policies(
    config: ConnectionConfig,
    role: Role,
    policy: AutoResponsePolicy,
    close_echo: CloseEchoPolicy,
) -> (CommandSender, ConnectionDriver) {
    let (queue, sender) = CommandQueue::new(&config);
    let core = ConnectionCore::new(config, role);
    (
        sender,
        ConnectionDriver::new(
            core,
            queue,
            policy,
            close_echo,
            InboundFeedPolicy::default(),
        ),
    )
}

/// Builds the driver for a post-handshake connection in a given corpus
/// state (test and fixture seam, mirroring
/// [`ws_core::ConnectionCore::new_in_state`]), under the default
/// [`AutoResponsePolicy::PongInboundPing`] and
/// [`CloseEchoPolicy::WebSocketImplComposition`].
#[must_use]
pub fn connection_driver_in_state(
    config: ConnectionConfig,
    role: Role,
    state: InitialState,
) -> (CommandSender, ConnectionDriver) {
    connection_driver_in_state_with_policy(config, role, state, AutoResponsePolicy::default())
}

/// [`connection_driver_in_state`] with an explicit automatic-response
/// policy.
#[must_use]
pub fn connection_driver_in_state_with_policy(
    config: ConnectionConfig,
    role: Role,
    state: InitialState,
    policy: AutoResponsePolicy,
) -> (CommandSender, ConnectionDriver) {
    connection_driver_in_state_with_policies(
        config,
        role,
        state,
        policy,
        CloseEchoPolicy::default(),
    )
}

/// [`connection_driver_in_state`] with both adapter-layer policies stated
/// explicitly.
#[must_use]
pub fn connection_driver_in_state_with_policies(
    config: ConnectionConfig,
    role: Role,
    state: InitialState,
    policy: AutoResponsePolicy,
    close_echo: CloseEchoPolicy,
) -> (CommandSender, ConnectionDriver) {
    let (queue, sender) = CommandQueue::new(&config);
    let core = ConnectionCore::new_in_state(config, role, state);
    (
        sender,
        ConnectionDriver::new(
            core,
            queue,
            policy,
            close_echo,
            InboundFeedPolicy::default(),
        ),
    )
}

/// One transport fact admitted to [`ConnectionDriver::poll`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverInput<'a> {
    /// Gives queued owner work (a command, a latched EOF, output draining)
    /// an execution turn without supplying transport facts.
    Wake,
    /// One borrowed inbound byte chunk; the driver never retains it — a
    /// deferred disposition means the adapter must retry the identical
    /// bytes.
    Inbound(&'a [u8]),
    /// Acknowledges that the transport accepted exactly this many bytes of
    /// the currently offered write suffix.
    WriteProgress {
        /// Bytes the transport accepted.
        bytes: usize,
    },
    /// The read side reached EOF.
    TransportEof,
    /// The adapter can provide no further transport service: pending wire
    /// output is undeliverable and is aborted; the protocol EOF still
    /// applies.
    Shutdown,
}

/// Why borrowed inbound bytes were not consumed by this poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeferredReason {
    /// A committed wire write is still in flight; it must finish before new
    /// inbound facts apply (queued events need no such gate — the core's
    /// FIFO event queue preserves their order across inputs).
    OutputPending,
    /// The fairness alternation assigned this turn to a queued command.
    CommandTurn,
    /// The core refused the chunk with its non-fatal backpressure code; the
    /// adapter drains outputs (by polling) and retries the identical bytes.
    Backpressure,
    /// [`InboundFeedPolicy::OneFramePerTurn`] only: the frame applied on an
    /// earlier turn has not finished dispatching — some output it committed,
    /// or a command an event of it provoked, is still undrained. The adapter
    /// drains outputs (by polling) and retries the identical bytes.
    FrameDispatchPending,
}

/// Why a driver input was rejected without any state change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverInputError {
    /// Write progress exceeded the offered suffix, or no write was offered.
    InvalidWriteProgress {
        /// Reported progress.
        attempted: usize,
        /// Currently offered suffix length.
        remaining: usize,
    },
    /// The bounded pending transport-EOF notification set is full, so this
    /// `TransportEof`/`Shutdown` was NOT admitted and nothing changed at
    /// all — including a `Shutdown`'s write-abandonment side effects. Drain
    /// by polling until pending notifications are consumed, then retry the
    /// identical input.
    ///
    /// This arm exists because the alternative — saturating the count — is
    /// the very defect the count replaced: at the ceiling a notification
    /// would be reported `Consumed` while never reaching the core (review
    /// 01a04899-5adb-78c3-b8ae-ec78ea14e377, blocking 1). The ceiling is
    /// unreachable in practice; that is deliberately NOT the justification.
    /// The counter's contract is that every admitted notification is
    /// preserved, and a refusal keeps that contract where a silent
    /// saturation would break it.
    PendingEofOverflow {
        /// Notifications already pending; none was added.
        pending: u32,
    },
}

/// Exact consumption result for the supplied driver input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputDisposition {
    /// The input fact was consumed; inbound reports its full byte count.
    Consumed {
        /// Borrowed inbound bytes consumed (zero for non-byte inputs).
        bytes: usize,
    },
    /// The adapter must retry the identical input.
    Deferred(DeferredReason),
    /// The input was invalid and changed nothing.
    Rejected(DriverInputError),
}

/// Exactly-once owner disposition of one accepted producer command.
///
/// Every disposition is the CORE's own verdict. There is deliberately no
/// driver-invented refusal: a command that arrives after the connection has
/// converged on `Closed` — even after the once-only terminal has been
/// delivered — is still applied to the core, which answers with its typed
/// `STATE_VIOLATION`, and that is what `Rejected` carries. The former
/// `TerminalRejected` variant, which the owner produced WITHOUT calling the
/// core, was removed under owner decision
/// `us017-post-terminal-owner-decision-2026-08-28.json` (`post-terminal-command`):
/// leaving one post-terminal path on a driver-invented verdict while the
/// inbound path passes through is how the next sibling defect hides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandDisposition {
    /// The core accepted and fully applied the command.
    Applied(LocalCommand),
    /// The core rejected the command with a typed failure.
    Rejected {
        /// The disposed command.
        command: LocalCommand,
        /// The exact typed core failure.
        failure: TypedProtocolFailure,
    },
}

/// The single normalized terminal result: the core reached its one
/// absorbing `Closed` state and every ordered output before it delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalOutcome;

/// WHERE a surfaced fatal arrived from.
///
/// Every fatal surfaces as [`DriverOutput::Failure`] whatever its origin —
/// that is the C5 halt property and it is not weakened here. This enum is
/// the orthogonal fact C5 accidentally erased: the failure's ARRIVAL PATH,
/// which decides what (if anything) shipped Java puts on the wire in answer.
/// Java reacts to a decode-path `InvalidDataException` with a close frame
/// (`decodeFrames` -> `close(e)`, WebSocketImpl.java:405-408, :631-633) and
/// to nothing else, so a reaction gated on anything coarser than this is a
/// reaction Java does not have.
///
/// Exhaustive over the four sites in [`ConnectionDriver::poll`] and
/// [`ConnectionDriver::next_output`] that can produce a fatal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailureOrigin {
    /// The core rejected INBOUND TRANSPORT BYTES — the port-side image of
    /// `decodeFrames`, and the ONLY origin shipped Java answers with a close
    /// frame.
    InboundDecode,
    /// The core rejected a transport-EOF notification
    /// (`DriverInput::TransportEof` / `DriverInput::Shutdown`). Java's `eot`
    /// path composes no frame — the peer is already gone.
    TransportEof,
    /// The core rejected a producer [`LocalCommand`] (owner decision
    /// `c5-fatal-command-rejection-surfaces-failure`). Nothing was decoded;
    /// the local caller asked for something the core refused, and the pinned
    /// oracle records no wire output for it.
    LocalCommand,
    /// The core rejected a DRIVER-INJECTED automatic reply (the US-015 AC1
    /// pong). No producer command and no inbound decode owns it.
    AutomaticReply,
}

/// The typed disposition of committed wire writes the adapter can no
/// longer deliver, reported once the transport service ends
/// ([`DriverInput::Shutdown`]).
///
/// US-017 AC2 requires adapter shutdown to have "explicit typed behavior"
/// and to not "leak". A write reaches this struct only after the core
/// COMMITTED it — the command was applied, its frame is in the ordered
/// wire stream, and the producer already saw
/// [`CommandDisposition::Applied`]. Abandoning it silently would leave the
/// producer believing bytes it will never see were sent, so the driver
/// hands the loss back as [`DriverOutput::WritesDropped`] before it
/// delivers [`DriverOutput::Terminal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DroppedWrites {
    /// Committed transport writes that will never be flushed. A partially
    /// drained front write counts as one.
    pub frames: usize,
    /// Undelivered bytes across those writes. For a partially drained
    /// front write only the UNDRAINED suffix counts — the bytes the
    /// transport already accepted did reach the wire.
    pub bytes: usize,
    /// Whether the front write had already put bytes on the wire, so the
    /// peer saw a truncated frame rather than no frame at all.
    pub partial_front: bool,
}

/// The next ordered driver output.
#[derive(Debug, PartialEq, Eq)]
pub enum DriverOutput<'owner> {
    /// Nothing is pending.
    Idle,
    /// The exact undrained suffix of the front transport write; the adapter
    /// reports progress with [`DriverInput::WriteProgress`].
    Write(&'owner [u8]),
    /// One owned semantic event (frame records, transitions, and detail
    /// events all travel this stream, as in the core).
    Event(SemanticEvent),
    /// One typed failure the core reported for an owner-applied input,
    /// together with the path it arrived on.
    ///
    /// Ordered strictly AFTER every write the core had committed when it
    /// failed, including any the failing step itself committed (US-017 AC2;
    /// pre-landing review round 2). An embedder that halts at its first
    /// `Failure` — the shipped adapter's contract — has therefore already
    /// been offered every committed byte, so halting abandons nothing and
    /// needs no [`DriverInput::Shutdown`] to account for a residue.
    Failure {
        /// The exact typed core failure.
        failure: TypedProtocolFailure,
        /// Where it arrived from. Never inferred from the failure's own
        /// contents: the same [`TypedProtocolFailure`] value is reachable
        /// from more than one origin.
        origin: FailureOrigin,
    },
    /// Committed wire writes the ended transport can no longer deliver
    /// (US-017 AC2 adapter shutdown). Reported before
    /// [`DriverOutput::Terminal`], never silently abandoned.
    WritesDropped(DroppedWrites),
    /// The exactly-once terminal delivery.
    Terminal(TerminalOutcome),
}

/// Result of one bounded owner transition.
#[derive(Debug, PartialEq, Eq)]
pub struct PollResult<'owner> {
    /// Disposition of the supplied input.
    pub input: InputDisposition,
    /// At most one command disposition surfaced by this poll.
    pub command: Option<CommandDisposition>,
    /// The next ordered output, or `Idle`.
    pub output: DriverOutput<'owner>,
    /// The core's current lifecycle state.
    pub state: ReadyState,
}

/// Sole mutable owner of the protocol core, output ordering, write
/// progress, and terminal delivery (US-017). Producers never touch it: they
/// hold only [`ws_core::CommandSender`] clones.
#[derive(Debug)]
pub struct ConnectionDriver {
    core: ConnectionCore,
    commands: CommandQueue,
    /// A command popped from the bounded channel and awaiting its turn.
    held: Option<LocalCommand>,
    /// The front transport write currently offered to the adapter.
    offered_write: Option<TransportWrite>,
    /// Bytes of the offered write already accepted by the transport.
    write_cursor: usize,
    /// Fairness alternation: after a command turn, inbound bytes get the
    /// next quiescent turn (borrowed design: codex 6a7606a `command_turn`).
    command_turn: bool,
    /// A transport EOF notification awaiting application to the core.
    /// PER-NOTIFICATION: cleared once the core consumes it, and re-armed by
    /// any later `TransportEof`/`Shutdown` input, because each notification
    /// is a scored event the core answers in its own right (owner decision
    /// us017-repeated-eof-owner-decision-2026-08-28).
    /// COUNT of admitted transport-EOF notifications awaiting application to
    /// the core — one per `TransportEof`/`Shutdown` input, decremented as
    /// each is consumed.
    ///
    /// This was a PAIR OF BOOLEANS, which silently coalesced: two
    /// notifications admitted before the arm could run (while a write is
    /// offered, say) set the same flag and produced ONE core action after the
    /// drain. Each notification is a scored event the core answers in its own
    /// right (owner decision us017-repeated-eof-owner-decision-2026-08-28), so
    /// the pending set must COUNT, not latch. Found by review
    /// 01a04866-df4b-7521-8abe-d8bad09edf38 after an earlier probe that only
    /// exercised immediately-applied notifications reported the property
    /// satisfied.
    pending_eofs: u32,
    /// Whether TRANSPORT SERVICE HAS ENDED — set by `DriverInput::Shutdown`
    /// and never cleared.
    ///
    /// This is NOT a duplicate of [`Self::pending_eofs`], and the two must
    /// not be collapsed again. `pending_eofs` counts EOF notifications the
    /// core has still to score, so it falls back to zero as each is
    /// consumed; this flag records the irreversible fact that no byte can
    /// reach the peer any more. US-017 AC2 needs exactly that fact and not
    /// the count: committed writes appearing after shutdown are swept into
    /// the [`DroppedWrites`] report rather than offered
    /// ([`Self::abort_pending_writes`], [`Self::next_output`]), and the
    /// US-015 AC1 automatic pong is suppressed, because a connection whose
    /// transport service has ended sends no automatic reply. Keying either
    /// on `pending_eofs > 0` would silently re-open both the moment the core
    /// consumed the notification.
    shutdown_latched: bool,
    terminal_delivered: bool,
    /// The configured automatic response policy (US-015 AC1).
    policy: AutoResponsePolicy,
    /// Automatic pong payloads whose injection the core refused with
    /// non-fatal backpressure; retried with priority over new owner work so
    /// the reply's wire position stays ahead of later sends (Java queues
    /// the pong during ping processing). In every explored schedule the
    /// byte-path admission bound leaves enough slack for immediate
    /// injection, so this queue is defensive — the eof-backpressure-livelock
    /// lesson says latching-and-losing is the one unacceptable outcome.
    pending_auto_pongs: VecDeque<Vec<u8>>,
    /// A fatal failure the core reported for an INJECTED automatic pong
    /// (no producer command exists to attach it to); surfaced as the next
    /// [`DriverOutput::Failure`].
    injected_failure: Option<TypedProtocolFailure>,
    /// A fatal failure the core reported for an owner-APPLIED input, held
    /// until every write the core had already committed — including the one
    /// the failing step itself committed — has been offered and drained
    /// (US-017 AC2; pre-landing review round 2).
    ///
    /// A fatal input can COMMIT a write and FAIL in the same core step: a
    /// server handshake rejection queues its HTTP error head and then
    /// returns the fatal `java_invalid_data`
    /// (`ws_core::connection::ConnectionCore::handle_handshake_bytes`), and
    /// a chunk carrying an inbound close followed by a data frame queues the
    /// close echo and then fails the second frame's state gate. Surfacing
    /// the failure first would abandon those bytes for every embedder that
    /// halts at its first `Failure` — which is exactly what the shipped
    /// adapter does by contract.
    ///
    /// The [`FailureOrigin`] travels WITH the latched failure. Holding the
    /// failure without its arrival path would re-erase the fact C6 is gated
    /// on, and the origin is not recoverable from the failure value:
    /// `java_invalid_data(1002)` is produced both by an inbound RSV1
    /// violation and by a locally rejected `send_close {code: 999}`.
    pending_failure: Option<(TypedProtocolFailure, FailureOrigin)>,
    /// Committed wire writes abandoned when the transport service ended,
    /// awaiting their exactly-once [`DriverOutput::WritesDropped`] report
    /// (US-017 AC2; story review BLOCKING-1/2, session 01a04626).
    dropped_writes: Option<DroppedWrites>,
    /// The configured close-echo wire composition policy (E5b).
    close_echo: CloseEchoPolicy,
    /// Armed for exactly the one core write that answers an inbound close
    /// consumed while Open — the Q19 echo whose wire bytes
    /// `WebSocketImpl.close` composes itself (WebSocketImpl.java:482-486).
    close_echo_armed: bool,
    /// The configured inbound feed policy (DIV-05).
    inbound_feed: InboundFeedPolicy,
    /// Frame-boundary bookkeeping for
    /// [`InboundFeedPolicy::OneFramePerTurn`]; inert under
    /// [`InboundFeedPolicy::WholeChunk`].
    feed: FrameAlignedFeed,
    /// [`InboundFeedPolicy::OneFramePerTurn`]: a frame has been applied and
    /// its dispatch has not finished. Set by every accepted inbound span and
    /// cleared only by a quiescent turn — the port's image of `processFrame`
    /// having RETURNED, which is where `decodeFrames`' loop takes its next
    /// frame (WebSocketImpl.java:395-398).
    ///
    /// A quiescent turn is the only honest signal available: the driver's
    /// [`Self::has_pending_output`] deliberately counts offered writes,
    /// dropped writes and a pending failure but NOT undrained EVENTS, so it
    /// cannot be used here — an event carrying the message the policy is
    /// about to echo is exactly what would still be queued.
    frame_dispatch_pending: bool,
}

impl ConnectionDriver {
    fn new(
        core: ConnectionCore,
        commands: CommandQueue,
        policy: AutoResponsePolicy,
        close_echo: CloseEchoPolicy,
        inbound_feed: InboundFeedPolicy,
    ) -> ConnectionDriver {
        ConnectionDriver {
            core,
            commands,
            held: None,
            offered_write: None,
            write_cursor: 0,
            command_turn: true,
            pending_eofs: 0,
            shutdown_latched: false,
            terminal_delivered: false,
            policy,
            pending_auto_pongs: VecDeque::new(),
            injected_failure: None,
            pending_failure: None,
            dropped_writes: None,
            close_echo,
            close_echo_armed: false,
            inbound_feed,
            feed: FrameAlignedFeed::new(),
            frame_dispatch_pending: false,
        }
    }

    /// Owner-side passthrough to
    /// [`ws_core::ConnectionCore::begin_client_handshake`] (the US-010
    /// construction entry point; not a producer command).
    ///
    /// # Errors
    ///
    /// Exactly the core's errors for that entry point.
    pub fn begin_client_handshake(
        &mut self,
        request_target: &str,
        host: &str,
    ) -> Result<(), TypedProtocolFailure> {
        self.core.begin_client_handshake(request_target, host)
    }

    /// The core's current lifecycle state.
    #[must_use]
    pub fn state(&self) -> ReadyState {
        self.core.state()
    }

    /// Snapshot of the core's corpus counters (read-only passthrough).
    #[must_use]
    pub fn counts(&self) -> ws_core::Counts {
        self.core.counts()
    }

    /// The governing close detail, once one exists (read-only passthrough).
    #[must_use]
    pub fn close_detail(&self) -> Option<&ws_core::CloseDetail> {
        self.core.close_detail()
    }

    /// The close frame shipped `WebSocketImpl` would put on the wire in
    /// answer to `failure`, or `None` when Java would send nothing.
    ///
    /// `origin` is the arrival path the SAME poll reported alongside the
    /// failure ([`DriverOutput::Failure`]); it is a required argument
    /// precisely so a caller cannot compose a reaction without saying what
    /// it is reacting to. That requirement is not merely local to this
    /// method: [`violation_close_frame`] takes a [`ViolationClose`] verdict
    /// that only [`violation_close_verdict`] can mint, so there is no
    /// lower-level door an adapter can use to compose the frame with an
    /// origin it never named. See [`violation_close_verdict`] for the
    /// carve-outs and the Java citations, [`ViolationClose`] for the bypass
    /// that shape closes, and [`violation_close_frame`] for why the
    /// composition lives in this crate rather than in the adapter that
    /// writes the bytes.
    ///
    /// Reads the lifecycle state from the core and RESERVES the mask key
    /// from the core's own masking sequence, so neither can drift from the
    /// connection actually being driven.
    ///
    /// # This is no longer inert, and that is the fix
    ///
    /// It used to be documented as pure. It is not any more: on the
    /// client role it advances the core's masking sequence
    /// ([`ws_core::ConnectionCore::reserve_mask_key`]) so the composed frame
    /// occupies a slot of its own instead of re-deriving a key the core may
    /// already have used. The previous derivation mixed `mask_key_seed` with
    /// the CLOSE CODE through the same SplitMix64 finalizer the core mixes
    /// with its frame counter, so the two agreed exactly whenever counter ==
    /// close code — a 1002 reaction after the 1002nd outbound frame reused
    /// that frame's key, against the distinct-successive-key contract
    /// (`mask_key_derivation_advances_per_outbound_frame`).
    ///
    /// What still holds: no path inside [`ConnectionDriver::poll`] calls
    /// this, so the differential corpus — which drives `poll` and never this
    /// method — cannot observe it. The reservation moves only the
    /// transcript-invisible masking sequence (quirk Q28); no frame, event,
    /// transition or corpus counter changes.
    pub fn compose_violation_close(
        &mut self,
        failure: &TypedProtocolFailure,
        origin: FailureOrigin,
    ) -> Option<(u16, Vec<u8>)> {
        let verdict = violation_close_verdict(failure, origin, self.core.state())?;
        // Reserved AFTER every carve-out: a decision to send nothing must
        // not consume a key.
        let mask = self.core.reserve_mask_key();
        Some((verdict.code(), violation_close_frame(verdict, mask)))
    }

    /// Performs at most one owner transition and returns the next ordered
    /// output. Deterministic: the same input sequence yields the same
    /// result sequence.
    pub fn poll<'owner>(&'owner mut self, input: DriverInput<'_>) -> PollResult<'owner> {
        let mut input_disposition = consumed(&input);
        match input {
            DriverInput::Shutdown => {
                if !self.admit_eof() {
                    // Refused: nothing changed, INCLUDING the write
                    // abandonment below.
                    return self.reject_pending_eof_overflow();
                }
                // Only now, past the refusal: transport service has ended
                // irreversibly. A REFUSED shutdown must not set this, for the
                // same reason it must not abandon a write — nothing changed.
                self.shutdown_latched = true;
                // Undeliverable wire output is aborted; the protocol EOF
                // below still applies (borrowed design: abort-undrainable-
                // writes on shutdown). US-017 story review BLOCKING-2
                // (session 01a04626): aborting is right, abandoning
                // SILENTLY is the AC2 leak — every committed write that
                // will never be flushed is accounted into the typed
                // `DroppedWrites` disposition surfaced below.
                self.abort_pending_writes();
                // Parked automatic replies are NOT committed writes: the
                // core refused them, so no frame exists and no producer was
                // ever told they were applied. They are dropped, not
                // reported (the reply's own state gate would refuse them
                // now anyway — see `inject_auto_pong`).
                self.pending_auto_pongs.clear();
                // The echo whose composition was armed is undeliverable too.
                self.close_echo_armed = false;
            }
            DriverInput::TransportEof => {
                if !self.admit_eof() {
                    return self.reject_pending_eof_overflow();
                }
            }
            DriverInput::WriteProgress { bytes } => {
                let remaining = self.write_remaining();
                if remaining == 0 || bytes > remaining {
                    input_disposition =
                        InputDisposition::Rejected(DriverInputError::InvalidWriteProgress {
                            attempted: bytes,
                            remaining,
                        });
                } else {
                    self.write_cursor += bytes;
                    if self.write_remaining() == 0 {
                        self.offered_write = None;
                        self.write_cursor = 0;
                    }
                }
                // Write progress is transport accounting and never applies
                // a producer command, so no disposition can surface here.
                let command = None;
                let state = self.core.state();
                let output = self.next_output();
                return PollResult {
                    input: input_disposition,
                    command,
                    output,
                    state,
                };
            }
            DriverInput::Wake | DriverInput::Inbound(_) => {}
        }

        let mut command_disposition = None;
        if self.has_pending_output() {
            // Committed order protects itself: nothing new is applied while
            // an offered write or undrained event exists.
            if matches!(input, DriverInput::Inbound(_)) {
                input_disposition = InputDisposition::Deferred(DeferredReason::OutputPending);
            }
        } else if self.pending_eofs > 0 {
            // A PENDING transport EOF gets the first quiescent turn. The
            // core owns the semantics (Q20). A NON-FATAL refusal is the
            // core's event-queue backpressure: the EOF stays pending and is
            // retried on the next quiescent turn once outputs drain (the
            // US-017 bounded schedule exploration retained the minimized
            // counterexample `enqueue-close-b,inbound-close,shutdown` —
            // fuzz-seeds/us017/regressions/eof-backpressure-livelock.seed —
            // where clearing the pending flag on a refused EOF lost the EOF
            // forever and the connection never terminated). A fatal
            // refusal is surfaced as a Failure output, never invented
            // around.
            if matches!(input, DriverInput::Inbound(_)) {
                input_disposition = InputDisposition::Deferred(DeferredReason::OutputPending);
            }
            // A backpressured automatic reply flushes before the EOF so its
            // wire position matches Java's (the pong entered the outQueue
            // during ping processing, before eot()); while one is still
            // pending the EOF stays latched and retries.
            self.flush_pending_auto_pongs();
            if !self.pending_auto_pongs.is_empty() {
                // The reply is still refused: this poll drains one queued
                // output below, so the retry makes progress.
            } else {
                // DEFECT FIX (owner ruling us017-ac5-eof-after-closed-driver-
                // defect): the latched EOF is handed to the core on EVERY
                // path, including the one where the core has already
                // converged on `Closed`. This arm used to short-circuit —
                // `else if self.core.state() == ReadyState::Closed {
                // self.eof_applied = true; }` — which set the latch WITHOUT
                // ever calling the core, so `ConnectionCore::handle_eof`'s
                // `derive.go eof: closed refuses` arm never ran and the
                // connection silently swallowed an event shipped Java
                // reports. Live Java-WebSocket 1.6.0 answers a transport EOF
                // in CLOSED with STATE_VIOLATION ("eof repeated in CLOSED
                // state") after counting the action, which the corpus pins
                // as `us005.pub.0070`; this plane is JAVA_FAITHFUL_PLUS_SAFE,
                // so absorbing it was a real behavioural change and not an
                // adapter convenience. Surfaced by routing the corpus
                // differential harness through this driver (US-017 AC5).
                //
                // AMENDING FIX (owner decision
                // us017-repeated-eof-owner-decision-2026-08-28, sha
                // f6270948, which AMENDS bd7849c3): the flags below are
                // PER-NOTIFICATION, not at-most-once-ever. The arm used to
                // carry `&& !self.eof_applied`, a latch that was set once
                // and never cleared, so a REPEATED `DriverInput::TransportEof`
                // (or a `Shutdown` after an applied EOF) never reached the
                // core at all. `DriverInput::TransportEof` is a SCORED EVENT
                // like any other input, not an idempotent transport fact the
                // owner may absorb: `ConnectionCore::handle_eof` counts the
                // action and refuses a repeat with `STATE_VIOLATION`, which
                // live Java reports as "eof repeated in CLOSED state". The
                // core decides.
                //
                // Clearing on application (rather than latching forever)
                // keeps BOTH properties: one notification is applied exactly
                // once, so a quiescent poll cannot re-apply it and spin; and
                // a NEW notification re-arms the flags and is scored in its
                // own right. The non-fatal arm deliberately leaves them set,
                // which is what preserves the eof-backpressure-livelock fix.
                match self.core.handle(Input::TransportEof) {
                    Ok(()) => self.consume_one_pending_eof(),
                    Err(failure) if !failure.code.is_fatal() => {
                        // Backpressure: nothing was consumed, so the pending
                        // COUNT is untouched and this notification is retried
                        // on the next quiescent turn. That is what preserves
                        // the eof-backpressure-livelock fix.
                    }
                    Err(failure) => {
                        self.consume_one_pending_eof();
                        return self.finish_poll(
                            input_disposition,
                            None,
                            Some((failure, FailureOrigin::TransportEof)),
                        );
                    }
                }
            }
        } else {
            // NOTE (owner decision us017-post-terminal-owner-decision-2026-08-28,
            // `post-terminal-inbound` / `post-terminal-command`): this arm was
            // gated on `!self.terminal_delivered`. That gate meant that once
            // the once-only terminal had been delivered NO branch ran, so
            // `poll` returned the initial `consumed(&input)` disposition —
            // reporting inbound bytes as `Consumed { bytes: N }` that the core
            // never saw. Reporting success for work never done is strictly
            // worse than absorbing it silently, because no correct adapter can
            // detect it. The gate is gone: post-terminal work is applied to the
            // core like any other input and the core's own typed refusal is
            // what surfaces. The terminal stays once-only via the
            // `terminal_delivered` latch in `next_output`, which is a
            // DELIVERY latch and was never meant to gate input application.
            //
            // A backpressured automatic reply holds priority over new owner
            // work (see the EOF arm above for why); until it lands, new
            // inbound facts and held commands wait like committed output.
            self.flush_pending_auto_pongs();
            if !self.pending_auto_pongs.is_empty() {
                if matches!(input, DriverInput::Inbound(_)) {
                    input_disposition = InputDisposition::Deferred(DeferredReason::OutputPending);
                }
            } else {
                self.fill_held();
                match input {
                    DriverInput::Inbound(_) if self.held.is_some() && self.command_turn => {
                        input_disposition = InputDisposition::Deferred(DeferredReason::CommandTurn);
                        command_disposition = self.apply_held_command();
                    }
                    // DIV-05: under `OneFramePerTurn` a frame already applied
                    // must finish dispatching before the next one is taken,
                    // exactly as `decodeFrames`' loop only reaches its next
                    // iteration once `processFrame` has RETURNED
                    // (WebSocketImpl.java:395-398).
                    DriverInput::Inbound(_)
                        if self.inbound_feed == InboundFeedPolicy::OneFramePerTurn
                            && self.frame_dispatch_pending =>
                    {
                        input_disposition =
                            InputDisposition::Deferred(DeferredReason::FrameDispatchPending);
                    }
                    DriverInput::Inbound(bytes) => {
                        self.command_turn = true;
                        let state_before = self.core.state();
                        // DIV-05: at most ONE frame reaches the core, and the
                        // partial consumption is reported honestly below.
                        //
                        // NOT during the opening handshake. `WebSocketImpl.decode`
                        // runs `decodeHandshake` while NOT_YET_CONNECTED and
                        // only reaches `decodeFrames` once the connection is
                        // OPEN (WebSocketImpl.java:220-242), so there is no
                        // frame grammar to align to yet — an HTTP request head
                        // read as a frame header is not a frame boundary, it
                        // is a category error, and `FrameAlignedFeed` would
                        // (correctly, for wire bytes) give up on the first
                        // undefined opcode and never align again.
                        let framed = self.inbound_feed == InboundFeedPolicy::OneFramePerTurn
                            && self.core.state() != ReadyState::NotYetConnected;
                        let bytes = if framed {
                            &bytes[..self.feed.limit(bytes)]
                        } else {
                            bytes
                        };
                        match self.core.handle(Input::TransportBytes(bytes)) {
                            Ok(()) => {
                                if framed {
                                    self.feed.advance(bytes);
                                    self.frame_dispatch_pending = true;
                                    input_disposition =
                                        InputDisposition::Consumed { bytes: bytes.len() };
                                }
                                self.arm_close_echo(state_before);
                            }
                            Err(failure) if !failure.code.is_fatal() => {
                                // Non-fatal backpressure: nothing was
                                // consumed; the adapter drains (by polling)
                                // and retries the identical bytes.
                                input_disposition =
                                    InputDisposition::Deferred(DeferredReason::Backpressure);
                            }
                            Err(failure) => {
                                // The decode path — the one origin shipped
                                // Java answers with a close frame. Only the
                                // span actually handed to the core may be
                                // reported consumed, whatever the caller
                                // offered.
                                if framed {
                                    input_disposition =
                                        InputDisposition::Consumed { bytes: bytes.len() };
                                }
                                return self.finish_poll(
                                    input_disposition,
                                    None,
                                    Some((failure, FailureOrigin::InboundDecode)),
                                );
                            }
                        }
                    }
                    DriverInput::Wake if self.held.is_some() => {
                        command_disposition = self.apply_held_command();
                    }
                    _ => {}
                }
            }
        }

        self.finish_poll(input_disposition, command_disposition, None)
    }

    /// The single funnel every `poll` return passes through, and therefore
    /// the ONE place a fatal's arrival path can be made invisible.
    ///
    /// Owner decision `us017-post-failure-owner-decisions-2026-08-28.json`,
    /// decision `c5-fatal-command-rejection-surfaces-failure`: a fatal
    /// arriving as a rejected COMMAND used to be handed back only as
    /// [`CommandDisposition::Rejected`], with `failure = None` reaching here,
    /// so `next_output()` ran and no [`DriverOutput::Failure`] was ever
    /// produced. [`ws_core::ConnectionCore::handle`] had nonetheless set
    /// `poisoned` on that same failure, so the core was dead while the
    /// output stream looked healthy. Both halt models in the tree key on
    /// `DriverOutput::Failure` — `ws-testee`'s `io_loop` and the exploration
    /// interpreter — so neither halted, and the poisoned connection could go
    /// on to deliver a clean `Terminal`.
    ///
    /// Lifting the failure out of the disposition HERE, rather than at
    /// either `apply_held_command` call site, is what makes the two arrival
    /// paths indistinguishable by construction: every future caller inherits
    /// it without having to remember to.
    ///
    /// The disposition is still returned alongside the failure. They are two
    /// views of one event, not two events: an adapter that reconciles
    /// commands needs the disposition, and one that halts on fatals needs
    /// the output. Suppressing either would trade this defect for its mirror
    /// image.
    ///
    /// # What this method must NOT erase
    ///
    /// Lifting the failure here makes the two paths indistinguishable FOR
    /// HALTING, which is all the owner decision asked for. It went one step
    /// too far: the arrival path vanished with it, and the C6 reaction
    /// downstream — which shipped Java performs for a decode-path
    /// `InvalidDataException` and for nothing else — began firing on locally
    /// rejected commands too, putting a 1002 close frame on the wire for a
    /// `send_close {code: 999}` the pinned oracle records as leaving the
    /// connection `open` and silent. So the origin travels WITH the failure
    /// ([`FailureOrigin`]), and the C5 lift below states its own:
    /// [`FailureOrigin::LocalCommand`], never the inbound decode path.
    ///
    /// # Latched, not returned
    ///
    /// US-017 AC2 (pre-landing review round 2): the failure — with its
    /// origin — is LATCHED rather than returned directly, and the ordinary
    /// output order runs. [`Self::next_output`] drains every committed write
    /// first and only then surfaces the latch, so a committed write can
    /// never be overtaken by the failure that ended the connection. The
    /// latch also counts as pending output ([`Self::has_pending_output`]),
    /// so no further input is applied while it is outstanding and the FIRST
    /// failure is the one delivered.
    ///
    /// That supersedes this lane's earlier "yield the failure first, the
    /// committed output drains on later polls" stance, which was true only
    /// for an adapter that keeps polling. It was reproduced FALSE for the
    /// one that halts at its first `Failure` — the shipped `ws-testee`
    /// contract — where a fatal step that had itself committed a write (a
    /// server handshake rejection's HTTP error head; a close echo followed
    /// by a refused data frame) abandoned those bytes with nothing counted.
    /// Latching keeps both properties: the fatal still surfaces however it
    /// arrived, and still carries the origin C6 is gated on.
    fn finish_poll<'owner>(
        &'owner mut self,
        input: InputDisposition,
        command: Option<CommandDisposition>,
        failure: Option<(TypedProtocolFailure, FailureOrigin)>,
    ) -> PollResult<'owner> {
        // `apply_held_command` only builds a `Rejected` for a fatal (a
        // non-fatal refusal re-holds the command and returns `None`), so the
        // `is_fatal` guard is belt-and-braces: it keeps the promise this
        // method's name makes even if that invariant ever changes.
        let failure = failure.or_else(|| match &command {
            Some(CommandDisposition::Rejected { failure, .. }) if failure.code.is_fatal() => {
                Some((failure.clone(), FailureOrigin::LocalCommand))
            }
            _ => None,
        });
        // Latched, never returned here: `next_output` surfaces it only once
        // every committed write has been offered and drained. `is_none()`
        // keeps the FIRST failure — a later one cannot overwrite the one the
        // adapter is entitled to see, and its origin cannot be replaced.
        if let Some(failure) = failure
            && self.pending_failure.is_none()
        {
            self.pending_failure = Some(failure);
        }
        let state = self.core.state();
        let output = self.next_output();
        PollResult {
            input,
            command,
            output,
            state,
        }
    }

    fn apply_held_command(&mut self) -> Option<CommandDisposition> {
        let command = self.held.take().expect("caller checked a held command");
        self.command_turn = false;
        match self.core.handle(Input::Command(command.clone())) {
            Ok(()) => Some(CommandDisposition::Applied(command)),
            Err(failure) if !failure.code.is_fatal() => {
                // Non-fatal backpressure: the command was not consumed; hold
                // it for the next turn after the adapter drains.
                self.held = Some(command);
                self.command_turn = true;
                None
            }
            Err(failure) => Some(CommandDisposition::Rejected { command, failure }),
        }
    }

    fn fill_held(&mut self) {
        if self.held.is_none() {
            self.held = self.commands.pop();
        }
    }

    /// Admits one transport-EOF notification, reporting whether there was
    /// room. Each admitted notification is scored separately by the core, so
    /// they accumulate rather than collapsing into a single flag.
    ///
    /// `checked_add`, NOT `saturating_add`: saturating would silently drop a
    /// notification at the ceiling while `poll` still reported it consumed,
    /// recreating false-consumption-without-a-core-call inside the very fix
    /// that eliminated it.
    fn admit_eof(&mut self) -> bool {
        match self.pending_eofs.checked_add(1) {
            Some(next) => {
                self.pending_eofs = next;
                true
            }
            None => false,
        }
    }

    /// The explicit typed refusal for a transport-EOF notification that did
    /// not fit. The input changed nothing; outputs still drain on this poll
    /// so the adapter can make room and retry (a refusal that also refused
    /// to drain would deadlock).
    fn reject_pending_eof_overflow(&mut self) -> PollResult<'_> {
        let pending = self.pending_eofs;
        let state = self.core.state();
        let output = self.next_output();
        PollResult {
            input: InputDisposition::Rejected(DriverInputError::PendingEofOverflow { pending }),
            command: None,
            output,
            state,
        }
    }

    /// Marks exactly ONE pending transport-EOF notification consumed by the
    /// core. Any others admitted alongside it stay pending and get their own
    /// core call on a later quiescent turn.
    fn consume_one_pending_eof(&mut self) {
        self.pending_eofs = self.pending_eofs.saturating_sub(1);
    }

    /// Abort every committed wire write the ended transport can no longer
    /// deliver, ACCOUNTING for it in the pending [`DroppedWrites`] report
    /// (US-017 AC2: adapter shutdown is typed and does not leak).
    ///
    /// Called at the shutdown instant and again from [`Self::next_output`]
    /// on every later poll, so a write the core commits after shutdown would
    /// be aborted and reported too rather than being offered to a dead
    /// transport. The later sweeps are a safety net, not a live path: the
    /// only post-shutdown input is the latched EOF, which emits events only,
    /// and automatic replies — the one step that could commit a write while
    /// draining an event — are suppressed after shutdown (see
    /// [`Self::next_output`]). That is what makes the report exactly once
    /// per run rather than a stream, and the pre-landing review's
    /// second-report path is pinned closed by
    /// `driver_contract.rs::a_ping_delivered_after_shutdown_injects_no_pong_and_emits_no_second_report`.
    ///
    /// The report can still carry MORE THAN ONE frame: an automatic pong is
    /// injected into the core's write queue while an event is being
    /// returned, so it does not occupy the offered slot, and a producer
    /// command applied on the next poll commits a second frame behind it
    /// (pinned by `..::a_shutdown_report_accounts_for_every_committed_frame`).
    fn abort_pending_writes(&mut self) {
        let mut frames = 0usize;
        let mut bytes = 0usize;
        let mut partial_front = false;
        if let Some(write) = self.offered_write.take() {
            frames += 1;
            // Only the UNDRAINED suffix is lost; the accepted prefix did
            // reach the wire, which is exactly what makes the peer's view
            // truncated rather than empty.
            bytes += write.bytes.len() - self.write_cursor;
            partial_front = self.write_cursor > 0;
            self.write_cursor = 0;
        }
        while let Some(write) = self.core.next_write() {
            frames += 1;
            bytes += write.bytes.len();
        }
        if frames == 0 {
            return;
        }
        let report = self.dropped_writes.get_or_insert(DroppedWrites {
            frames: 0,
            bytes: 0,
            partial_front: false,
        });
        report.frames += frames;
        report.bytes += bytes;
        report.partial_front |= partial_front;
    }

    fn write_remaining(&self) -> usize {
        self.offered_write
            .as_ref()
            .map_or(0, |write| write.bytes.len() - self.write_cursor)
    }

    /// Whether an undrained output is holding the owner's turn. Nothing new
    /// is applied while this is true, which is what stops committed order
    /// from being overtaken by a later step.
    ///
    /// An undelivered [`DroppedWrites`] report counts, and that is what
    /// closes the fatal-termination hole (US-017 story review round 2,
    /// session 01a0464f). A fatal failure can only be produced by APPLYING
    /// an input — the latched EOF or an inbound chunk — so refusing to
    /// apply anything until the report has been handed over means no
    /// `Failure` can exist to suppress it. The report is surfaced strictly
    /// before any failure rather than merely ordered ahead of one, so no
    /// adapter that halts at its first `Failure` can miss it.
    ///
    /// A latched [`Self::pending_failure`] counts for the mirror-image
    /// reason: once the connection has failed, nothing new may be applied,
    /// so the failure that is delivered is the FIRST one the core produced
    /// and the writes drained ahead of it are exactly the ones the core had
    /// already committed.
    fn has_pending_output(&self) -> bool {
        self.offered_write.is_some()
            || self.dropped_writes.is_some()
            || self.pending_failure.is_some()
    }

    /// Retry parked automatic pongs in order; stops on the first non-fatal
    /// refusal (retried on a later turn) and drops them all once the
    /// connection has left Open (Java's reply is unsendable there — see
    /// [`inject_auto_pong`]).
    fn flush_pending_auto_pongs(&mut self) {
        if self.pending_auto_pongs.is_empty() {
            return;
        }
        if self.core.state() != ReadyState::Open {
            self.pending_auto_pongs.clear();
            return;
        }
        while let Some(data) = self.pending_auto_pongs.pop_front() {
            match self.core.handle(Input::Command(LocalCommand::SendPong {
                data: data.clone(),
            })) {
                Ok(()) => {}
                Err(failure) if !failure.code.is_fatal() => {
                    self.pending_auto_pongs.push_front(data);
                    break;
                }
                Err(failure) => {
                    self.injected_failure = Some(failure);
                    self.pending_auto_pongs.clear();
                    break;
                }
            }
        }
    }

    /// Arm the close-echo recomposition when the core has just consumed an
    /// inbound close while Open: exactly the Q19 echo arm
    /// (`process_close_frame`), which is the port-side image of
    /// `Draft_6455.processFrameClosing` -> `webSocketImpl.close(code, reason,
    /// true)` (drafts/Draft_6455.java:1062-1071).
    fn arm_close_echo(&mut self, state_before: ReadyState) {
        if self.close_echo != CloseEchoPolicy::WebSocketImplComposition
            || state_before != ReadyState::Open
            || self.core.state() != ReadyState::Closing
        {
            return;
        }
        if self
            .core
            .close_detail()
            .is_some_and(|detail| detail.origin == CloseOrigin::Remote)
        {
            self.close_echo_armed = true;
        }
    }

    fn next_output(&mut self) -> DriverOutput<'_> {
        // US-017 AC2: once the transport service has ended, no committed
        // write can be delivered. Sweep any that appeared since the last
        // sweep into the report and surface the loss BEFORE any event or
        // the terminal, so no adapter can reach `Terminal` without having
        // been told what was abandoned.
        if self.shutdown_latched {
            self.abort_pending_writes();
            if let Some(dropped) = self.dropped_writes.take() {
                return DriverOutput::WritesDropped(dropped);
            }
        }
        // Writes drain before events so committed wire order can never be
        // reordered past a later step's output (FIFO owner order).
        if self.offered_write.is_none() {
            let mut write = self.core.next_write();
            if self.close_echo_armed
                && let Some(pending) = write.as_mut()
                && let Some(detail) = self.core.close_detail()
                && let Some(composed) = compose_close_echo(&pending.bytes, detail)
            {
                pending.bytes = composed;
                self.close_echo_armed = false;
            }
            self.offered_write = write;
            self.write_cursor = 0;
        }
        if let Some(write) = self.offered_write.as_ref() {
            return DriverOutput::Write(&write.bytes[self.write_cursor..]);
        }
        // Only now — with every committed write offered and drained — may a
        // fatal failure be surfaced (US-017 AC2; pre-landing review round
        // 2). The write queue is drained ABOVE this point, so an adapter
        // that halts at its first `Failure` has already been handed every
        // byte the core committed, including the bytes the failing step
        // itself committed (a server handshake rejection's HTTP error head,
        // a close echo followed by a refused data frame).
        if let Some((failure, origin)) = self.pending_failure.take() {
            return DriverOutput::Failure { failure, origin };
        }
        // A fatal failure from an injected automatic pong surfaces before
        // further event drain (there is no producer command to carry it).
        if let Some(failure) = self.injected_failure.take() {
            return DriverOutput::Failure {
                failure,
                origin: FailureOrigin::AutomaticReply,
            };
        }
        if let Some(event) = self.core.next_event() {
            // US-015 AC1: the automatic reply is injected exactly when the
            // Ping semantic event is DELIVERED — the port-side image of
            // Draft_6455.processFrame dispatching the ping to the listener
            // whose default answers with PongFrame(pingFrame)
            // (drafts/Draft_6455.java:898-899; WebSocketAdapter.java:84-86).
            // The reply's write is queued behind nothing (no write was
            // pending here), so it is the next wire output after this
            // event.
            //
            // NOT after shutdown (US-017 AC2; pre-landing review finding 1).
            // Draining an event is the one step that can commit a wire write
            // WITHOUT passing the offered-write gate, and the latched EOF is
            // refused with non-fatal backpressure whenever the event queue is
            // congested — so a Ping delivered on a post-shutdown poll finds
            // the core still `Open`, injects a pong, and commits a frame the
            // ended transport can never carry. That frame then comes back as
            // a SECOND `WritesDropped` report. This is the same stance the
            // shutdown arm already takes for parked replies
            // (`pending_auto_pongs.clear()`): a connection whose transport
            // service has ended sends no automatic reply, exactly as Java's
            // `sendFrame` would put nothing on a torn-down socket.
            if self.policy == AutoResponsePolicy::PongInboundPing
                && !self.shutdown_latched
                && let SemanticEventKind::Ping { data } = &event.kind
            {
                inject_auto_pong(
                    &mut self.core,
                    &mut self.pending_auto_pongs,
                    &mut self.injected_failure,
                    data.clone(),
                );
            }
            return DriverOutput::Event(event);
        }
        // Terminal convergence: the core is in its absorbing state AND no
        // producer work remains undisposed. Held/queued commands keep the
        // terminal waiting rather than being swept aside with a
        // driver-invented verdict (owner decision
        // us017-post-terminal-owner-decision-2026-08-28, `post-terminal-command`);
        // each is applied to the core on a later turn and surfaces the
        // core's own refusal.
        if self.core.state() == ReadyState::Closed
            && self.held.is_none()
            && self.commands.is_empty()
            && !self.terminal_delivered
        {
            self.terminal_delivered = true;
            return DriverOutput::Terminal(TerminalOutcome);
        }
        // DIV-05: nothing is offered, nothing is held, nothing is queued —
        // every output the last applied frame committed has drained and every
        // command its events provoked has been applied. That is `processFrame`
        // having RETURNED, and it is where `decodeFrames`' loop takes its next
        // frame (WebSocketImpl.java:395-398).
        self.frame_dispatch_pending = false;
        DriverOutput::Idle
    }
}

/// Feed one automatic pong through the ordinary command seam (a free
/// function over disjoint driver fields so the injection can run while a
/// drained event is being returned). The state gate is Java's
/// `send(Collection)` isOpen throw (WebSocketImpl.java:667-670): a
/// connection that has left Open gets no reply and no failure — Java's own
/// reply would throw there with nothing on the wire. A non-fatal refusal
/// parks the payload for the prioritized retry; a fatal one surfaces as
/// the next [`DriverOutput::Failure`].
fn inject_auto_pong(
    core: &mut ConnectionCore,
    pending: &mut VecDeque<Vec<u8>>,
    injected: &mut Option<TypedProtocolFailure>,
    data: Vec<u8>,
) {
    if core.state() != ReadyState::Open {
        return;
    }
    match core.handle(Input::Command(LocalCommand::SendPong {
        data: data.clone(),
    })) {
        Ok(()) => {}
        Err(failure) if !failure.code.is_fatal() => {
            pending.push_back(data);
        }
        Err(failure) => {
            *injected = Some(failure);
        }
    }
}

/// Java's `CloseFrame.ABNORMAL_CLOSE`. `WebSocketImpl.close` reaches
/// `CLOSING` on this code WITHOUT building or sending a frame
/// (WebSocketImpl.java:466-471), so it is the one close code whose reaction
/// puts nothing on the wire.
pub const ABNORMAL_CLOSE_CODE: u16 = 1006;

/// The origin gate's VERDICT: shipped `WebSocketImpl` does answer this
/// failure with a close frame, and this is the close code it carries.
///
/// # Opaque BY CONSTRUCTION, which is the whole point
///
/// The field is private and this crate exposes NO constructor, no
/// `Default`, and no `From` — so the only way any code outside `ws_driver`
/// can obtain a value of this type is [`violation_close_verdict`], the
/// origin gate. [`violation_close_frame`] demands one. An adapter therefore
/// cannot compose the C6 frame without having passed the gate, and it
/// cannot pass the gate without naming a [`FailureOrigin`].
///
/// Review 01a04899 round 2 blocked the previous shape, in which the gate
/// merely took the origin as a required ARGUMENT while
/// `violation_close_frame(code: u16, mask)` stayed reachable beside it. A
/// required argument constrains only the caller who chooses that function;
/// it does nothing to a caller who picks the other one. That was measured,
/// not argued: an adapter calling `violation_close_frame(1002, None)` with
/// no origin anywhere in scope produced exactly the shipped-Java bytes
/// `88 02 03 EA`. The requirement was conventional. It is now structural —
/// the bypass does not fail a check, it does not COMPILE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ViolationClose {
    code: u16,
}

impl ViolationClose {
    /// The close code this verdict authorises on the wire — the rejection's
    /// own code, which [`violation_close_verdict`] carried through.
    #[must_use]
    pub const fn code(self) -> u16 {
        self.code
    }
}

/// The origin gate. Returns the [`ViolationClose`] verdict when shipped
/// `WebSocketImpl` puts a frame on the wire in answer to a decode-path
/// protocol violation, or `None` when Java would send nothing (owner
/// decision `us017-c6-layer-split-owner-decision-2026-08-28.json`,
/// sha256 d41b5307…, resolving C6 from
/// `us017-post-failure-owner-decisions-2026-08-28.json`, sha256 612546e8…).
///
/// This is the SOLE producer of [`ViolationClose`], so it is the sole route
/// to a composed C6 frame.
///
/// `decodeFrames`' InvalidDataException arm (WebSocketImpl.java:405-408)
/// calls `close(e)` (:631-633) -> `close(int,String,boolean)` (:463-507),
/// which builds a `CloseFrame` carrying the rejection's OWN close code and
/// sends it (:481-487), flushes it (:494, :594-595) and moves `OPEN ->
/// CLOSING` (:503).
///
/// # The carve-outs, in evaluation order
///
/// 1. **`origin` is not [`FailureOrigin::InboundDecode`].** `decodeFrames`
///    is the ONLY site that reaches `close(e)`. A fatal that arrived as a
///    rejected command, a transport EOF, or a refused automatic reply never
///    passed through a decoder, so Java composes nothing. This carve-out is
///    FIRST because it is the one a caller cannot recover from the failure
///    value: `TypedProtocolFailure::java_invalid_data(1002)` is produced
///    both by an inbound RSV1 violation and by a locally rejected
///    `send_close {code: 999}`, and only the first may answer.
/// 2. **Not `Open`.** `close(int,String,boolean)`'s :464 guard makes the
///    whole method a no-op outside OPEN.
/// 3. **No close code.** No close code means no `InvalidDataException`, so
///    `decodeFrames` never reached `close(e)`: STATE_VIOLATION and the limit
///    codes land here.
/// 4. **1006.** `WebSocketImpl.close` answers `ABNORMAL_CLOSE` by reaching
///    CLOSING with nothing on the wire (:466-471).
#[must_use]
pub fn violation_close_verdict(
    failure: &TypedProtocolFailure,
    origin: FailureOrigin,
    state: ReadyState,
) -> Option<ViolationClose> {
    if origin != FailureOrigin::InboundDecode {
        return None;
    }
    if state != ReadyState::Open {
        return None;
    }
    let code = failure.close_code?;
    if code == ABNORMAL_CLOSE_CODE {
        return None;
    }
    Some(ViolationClose { code })
}

/// Encode the close frame for a [`ViolationClose`] verdict: shipped
/// `WebSocketImpl.close` builds its own `CloseFrame` (:482-486) rather than
/// asking the Draft for one, so this composes the two big-endian code bytes
/// directly.
///
/// # Why this takes a verdict and not a `u16`
///
/// A `u16` is manufacturable by anyone; a [`ViolationClose`] is not. Taking
/// the verdict is what makes the origin requirement unskippable rather than
/// conventional — there is no second door into this encoder, because the
/// only way to hold its argument is to have passed
/// [`violation_close_verdict`]. See [`ViolationClose`] for the bypass this
/// closes and the bytes that demonstrated it.
///
/// `mask` comes from the connection's OWN masking sequence — see
/// [`ConnectionDriver::compose_violation_close`], which reserves it. `None`
/// is the server role, which must not mask.
///
/// # Why this lives in `ws_driver` and not in the adapter that calls it
///
/// This crate is the WebSocketImpl mirror — it already owns the close-echo
/// WIRE composition for exactly this layering reason (see
/// [`CloseEchoPolicy`]) — and the `adapter-linkage` gate
/// (`cmd/rustgatectl`) forbids adapter sources from naming
/// `ws_core::framing` or `Draft6455` at all. Composing the frame inside
/// `ws-testee` tripped that gate, which was right to reject it: framing
/// belongs to the protocol layers, and an adapter that hand-rolls a frame is
/// the thing the gate exists to catch.
///
/// # Why this cannot move the differential corpus
///
/// Nothing inside [`ConnectionDriver::poll`] calls it or
/// [`violation_close_verdict`]. Only an embedding adapter invokes them, so the
/// oracle harness — which drives this crate but never this path — produces
/// byte-identical transcripts with and without them. That was measured, not
/// assumed.
///
/// # Departures from Java, stated rather than buried
///
/// The reason is EMPTY. Java sends `e.getMessage()`;
/// [`TypedProtocolFailure`] carries a code and a close code but no message,
/// and inventing a diagnostic string would put a fabricated Java message on
/// the wire.
#[must_use]
pub fn violation_close_frame(verdict: ViolationClose, mask: Option<[u8; 4]>) -> Vec<u8> {
    let mut payload = Vec::with_capacity(2);
    payload.extend_from_slice(&verdict.code().to_be_bytes());
    Draft6455::encode_frame(true, Opcode::Closing, &payload, mask)
}

/// Recompose the core's Q19 close echo into the frame shipped Java's
/// `WebSocketImpl.close(code, message, remote)` would actually send.
///
/// `encoded` is the core's own wire frame for the echo; `detail` is the
/// governing REMOTE close the core parsed out of the inbound frame. The
/// replacement is byte-for-byte what `new CloseFrame(); setReason(reason);
/// setCode(code); sendFrame(...)` produces (WebSocketImpl.java:482-486 ->
/// framing/CloseFrame.java:294-302): the low two bytes of the code,
/// big-endian, then the UTF-8 reason. The original frame's FIN bit and mask
/// key are reused, so a client-role echo stays masked under the core's own
/// deterministic key sequence (quirk Q28) instead of a second key source.
///
/// Returns `None` — leaving the core's bytes untouched — whenever this is
/// not that echo (not a close frame, not the constructor payload, an
/// unreadable header) or the composition is already byte-identical. Java's
/// `closeFrame.isValid()` (WebSocketImpl.java:485) cannot reject on this
/// path: the code and reason came from a received `CloseFrame` that already
/// passed the identical `CloseFrame.isValid` chain at translate time
/// (drafts/Draft_6455.java:595; framing/CloseFrame.java:226-243), which is
/// why no rejection arm is invented here.
fn compose_close_echo(encoded: &[u8], detail: &CloseDetail) -> Option<Vec<u8>> {
    let cap = u64::try_from(encoded.len()).ok()?;
    let HeaderDecode::Header(header) = Draft6455::decode_frame_header(encoded, cap).ok()? else {
        return None;
    };
    if header.opcode != Opcode::Closing {
        return None;
    }
    let payload_len = usize::try_from(header.payload_len).ok()?;
    let end = header.header_len.checked_add(payload_len)?;
    let mut payload = encoded.get(header.header_len..end)?.to_vec();
    if let Some(key) = header.mask_key {
        Draft6455::apply_mask(&mut payload, key);
    }
    if payload != CLOSE_CONSTRUCTOR_PAYLOAD {
        return None;
    }
    let code = u16::try_from(detail.code).ok()?;
    let mut composed = Vec::with_capacity(2 + detail.reason.len());
    composed.extend_from_slice(&code.to_be_bytes());
    composed.extend_from_slice(detail.reason.as_bytes());
    if composed == payload {
        return None;
    }
    Some(Draft6455::encode_frame(
        header.fin,
        Opcode::Closing,
        &composed,
        header.mask_key,
    ))
}

fn consumed(input: &DriverInput<'_>) -> InputDisposition {
    InputDisposition::Consumed {
        bytes: match input {
            DriverInput::Inbound(bytes) => bytes.len(),
            _ => 0,
        },
    }
}

#[cfg(test)]
mod pending_eof_ceiling_tests {
    use super::*;
    use ws_core::TransportWrite;
    use ws_core::config::ConnectionConfig;

    /// A driver carrying EVERY piece of state a `Shutdown` abandons, so a
    /// refusal has something to protect.
    ///
    /// Review 01a048b4-b557-7313-a895-f4575c6953f1 blocked the previous
    /// version of this fixture as VACUOUS: it seeded only `pending_eofs`,
    /// and `close_echo_armed` already starts `false`, so the
    /// "no side effects" assertions passed whether or not the early return
    /// protected anything. Every field below is seeded and its precondition
    /// asserted here, so the fixture cannot silently become empty again.
    fn fixture_with_abandonable_state() -> ConnectionDriver {
        let (_sender, mut driver) = connection_driver_in_state(
            ConnectionConfig::default(),
            Role::Server,
            InitialState::Open,
        );
        // 1. An OFFERED write, partially accepted, which Shutdown clears
        //    along with its cursor.
        driver.offered_write = Some(TransportWrite {
            bytes: vec![0x81, 0x03, b'h', b'e', b'y'],
        });
        driver.write_cursor = 2;
        // 2. A write still queued INSIDE THE CORE, which Shutdown drains via
        //    drop_pending_writes. Applied straight to the core so the driver
        //    has not yet taken it into `offered_write`.
        driver
            .core
            .handle(Input::Command(LocalCommand::SendText {
                text: "queued".to_owned(),
            }))
            .expect("the core accepts a send while Open");
        // 3. A parked automatic pong, which Shutdown clears.
        driver.pending_auto_pongs.push_back(vec![0xDE, 0xAD]);
        // 4. An armed close-echo recomposition, which Shutdown disarms.
        driver.close_echo_armed = true;

        assert!(
            driver.offered_write.is_some(),
            "precondition: offered write"
        );
        assert_eq!(driver.write_cursor, 2, "precondition: partial cursor");
        assert_eq!(
            driver.pending_auto_pongs.len(),
            1,
            "precondition: parked auto-pong"
        );
        assert!(driver.close_echo_armed, "precondition: close echo armed");
        driver
    }

    /// At the ceiling a further `TransportEof` is REFUSED with a typed
    /// error, not silently swallowed while being reported consumed
    /// (review 01a04899-5adb-78c3-b8ae-ec78ea14e377, blocking 1).
    #[test]
    fn transport_eof_at_the_ceiling_is_explicitly_refused() {
        let (_sender, mut driver) = connection_driver_in_state(
            ConnectionConfig::default(),
            Role::Server,
            InitialState::Open,
        );
        driver.pending_eofs = u32::MAX;
        let result = driver.poll(DriverInput::TransportEof);
        assert_eq!(
            result.input,
            InputDisposition::Rejected(DriverInputError::PendingEofOverflow { pending: u32::MAX }),
            "the notification must be refused, never reported consumed"
        );
        assert_eq!(
            driver.pending_eofs,
            u32::MAX,
            "a refused notification changes nothing"
        );
    }

    /// A `Shutdown` refused at the ceiling performs NONE of its
    /// abandonment side effects, on state that genuinely exists.
    #[test]
    fn shutdown_at_the_ceiling_abandons_nothing() {
        let mut driver = fixture_with_abandonable_state();
        driver.pending_eofs = u32::MAX;

        let result = driver.poll(DriverInput::Shutdown);
        assert!(
            matches!(
                result.input,
                InputDisposition::Rejected(DriverInputError::PendingEofOverflow { .. })
            ),
            "the notification must be refused"
        );

        assert_eq!(
            driver
                .offered_write
                .as_ref()
                .map(|write| write.bytes.clone()),
            Some(vec![0x81, 0x03, b'h', b'e', b'y']),
            "the offered write survives a refused shutdown"
        );
        assert_eq!(driver.write_cursor, 2, "the write cursor survives");
        assert_eq!(
            driver.pending_auto_pongs.front().cloned(),
            Some(vec![0xDE, 0xAD]),
            "the parked automatic pong survives"
        );
        assert!(driver.close_echo_armed, "the armed close echo survives");
        assert_eq!(
            driver.pending_eofs,
            u32::MAX,
            "the pending count is untouched"
        );
        // Consuming, so asserted last: the core's queued write was NOT
        // drained by drop_pending_writes.
        assert!(
            driver.core.next_write().is_some(),
            "the core's queued write survives a refused shutdown"
        );
    }

    /// POSITIVE CONTROL for the test above. Same fixture, room to admit the
    /// notification: the shutdown is ACCEPTED and every one of those fields
    /// is abandoned. Without this, `shutdown_at_the_ceiling_abandons_nothing`
    /// could not distinguish "the refusal protected the state" from "there
    /// was nothing to protect" — which is exactly how the previous version
    /// of that test was vacuous.
    #[test]
    fn shutdown_below_the_ceiling_does_abandon_all_of_it() {
        let mut driver = fixture_with_abandonable_state();
        assert_eq!(driver.pending_eofs, 0, "precondition: room to admit");

        let result = driver.poll(DriverInput::Shutdown);
        assert!(
            matches!(result.input, InputDisposition::Consumed { .. }),
            "with room, the notification is admitted"
        );

        assert!(
            driver.offered_write.is_none(),
            "an accepted shutdown clears the offered write"
        );
        assert_eq!(driver.write_cursor, 0, "and its cursor");
        assert!(
            driver.pending_auto_pongs.is_empty(),
            "and the parked automatic pong"
        );
        assert!(!driver.close_echo_armed, "and disarms the close echo");
        assert!(
            driver.core.next_write().is_none(),
            "and drains the core's queued write"
        );
    }

    /// Below the ceiling nothing changes: notifications still accumulate
    /// one per admission, which is the property the counter exists for.
    #[test]
    fn below_the_ceiling_notifications_still_accumulate() {
        let (_sender, mut driver) = connection_driver_in_state(
            ConnectionConfig::default(),
            Role::Server,
            InitialState::Open,
        );
        driver.pending_eofs = u32::MAX - 2;
        assert!(driver.admit_eof());
        assert_eq!(driver.pending_eofs, u32::MAX - 1);
        assert!(driver.admit_eof());
        assert_eq!(driver.pending_eofs, u32::MAX);
        assert!(!driver.admit_eof(), "the next one does not fit");
        assert_eq!(driver.pending_eofs, u32::MAX);
    }
}

/// DIV-05 (behavior-delta ledger sequence 54): the frame-boundary bookkeeping
/// behind [`InboundFeedPolicy::OneFramePerTurn`]. These are here rather than
/// in an integration test because the split they pin — a frame header cut by
/// a read boundary — is not reachable through a socket fixture that writes
/// its bytes in one go, and a check that cannot fail is not evidence.
#[cfg(test)]
mod inbound_feed_tests {
    use super::*;

    /// Replays `wire` through [`FrameAlignedFeed`] in reads of `read_size`
    /// and returns the byte spans it would hand the core, in order.
    fn spans_fed(wire: &[u8], read_size: usize) -> Vec<usize> {
        let mut feed = FrameAlignedFeed::new();
        let mut spans = Vec::new();
        let mut pending: Vec<u8> = Vec::new();
        let mut at = 0usize;
        while at < wire.len() || !pending.is_empty() {
            if pending.is_empty() {
                let end = (at + read_size).min(wire.len());
                pending = wire[at..end].to_vec();
                at = end;
            }
            let take = feed.limit(&pending);
            assert!(take > 0, "a non-empty chunk must always make progress");
            spans.push(take);
            feed.advance(&pending[..take]);
            pending = pending[take..].to_vec();
        }
        spans
    }

    fn wire_frame(opcode: u8, payload_len: usize) -> Vec<u8> {
        let mut frame = vec![0x80 | opcode];
        if payload_len < 126 {
            #[allow(clippy::cast_possible_truncation)]
            frame.push(0x80 | payload_len as u8);
        } else {
            frame.push(0x80 | 126);
            #[allow(clippy::cast_possible_truncation)]
            frame.extend_from_slice(&(payload_len as u16).to_be_bytes());
        }
        frame.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        frame.extend(std::iter::repeat_n(0x00u8, payload_len));
        frame
    }

    #[test]
    fn one_read_carrying_two_frames_is_split_at_the_boundary() {
        let mut wire = wire_frame(0x1, 5);
        wire.extend_from_slice(&wire_frame(0x8, 6));
        // 11 = 2 header + 4 mask + 5 payload; 12 = 2 + 4 + 6.
        assert_eq!(spans_fed(&wire, 4096), vec![11, 12]);
    }

    /// The retained-head arithmetic, which no socket fixture can reach: a
    /// header is only ever SPLIT when a read boundary falls inside it, and
    /// [`FrameAlignedFeed::limit`] must then subtract the bytes already fed
    /// (`total - self.head.len()`) rather than starting the frame's countdown
    /// over. Getting that wrong drifts every later boundary by the size of the
    /// retained head.
    #[test]
    fn a_frame_header_split_across_reads_still_lands_the_boundary() {
        let mut wire = wire_frame(0x1, 130); // 8-byte header (126 marker)
        wire.extend_from_slice(&wire_frame(0x8, 6));
        wire.extend_from_slice(&wire_frame(0x1, 3));
        // Reads of 5 bytes cut inside both extended headers AND never land on
        // a frame end, so the feed's own boundaries are the only ones here.
        let spans = spans_fed(&wire, 5);
        assert_eq!(
            spans.iter().sum::<usize>(),
            wire.len(),
            "every byte is fed exactly once: {spans:?}"
        );
        let mut boundaries = Vec::new();
        let mut running = 0usize;
        for span in &spans {
            running += span;
            boundaries.push(running);
        }
        for end in [138usize, 138 + 12, 138 + 12 + 9] {
            assert!(
                boundaries.contains(&end),
                "a frame boundary at byte {end} must be a feed boundary; \
                 the feed stopped at {boundaries:?}"
            );
        }
    }

    /// A header the grammar rejects (0x3 is not a defined opcode) must hand
    /// the CORE the bytes rather than making a decision here.
    #[test]
    fn an_unparsable_header_stops_splitting_and_defers_to_the_core() {
        let mut feed = FrameAlignedFeed::new();
        let chunk = [0x83u8, 0x80, 0x11, 0x22, 0x33, 0x44];
        assert_eq!(feed.limit(&chunk), chunk.len());
        assert!(
            !feed.aligning,
            "an unparsable header disables alignment for the rest of the run"
        );
        // And it stays disabled: every later chunk goes whole to the core.
        assert_eq!(feed.limit(&[0x81, 0x80, 0, 0, 0, 0][..]), 6);
    }

    /// The policy default is the ORACLE observable. The public corpus scores
    /// `input_chunk {bytes}` per surviving chunk, so a default that split
    /// chunks would move pinned bytes the moment anyone used a builder
    /// without stating the policy.
    #[test]
    fn the_inbound_feed_default_is_the_whole_chunk() {
        assert_eq!(InboundFeedPolicy::default(), InboundFeedPolicy::WholeChunk);
    }
}
