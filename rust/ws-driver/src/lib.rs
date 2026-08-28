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
//! `ProducersDropped` disposition is NOT adopted: the `ws_core` channel has
//! no disconnect signal by design, so producer lifecycle belongs to the
//! embedding adapter.
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
/// default) and [`CloseEchoPolicy::WebSocketImplComposition`] (the
/// shipped-Java full-stack close composition).
#[must_use]
pub fn connection_driver(
    config: ConnectionConfig,
    role: Role,
) -> (CommandSender, ConnectionDriver) {
    connection_driver_with_policy(config, role, AutoResponsePolicy::default())
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
        ConnectionDriver::new(core, queue, policy, close_echo),
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
        ConnectionDriver::new(core, queue, policy, close_echo),
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
    /// One typed failure the core reported for an owner-applied input.
    Failure(TypedProtocolFailure),
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
    /// The configured close-echo wire composition policy (E5b).
    close_echo: CloseEchoPolicy,
    /// Armed for exactly the one core write that answers an inbound close
    /// consumed while Open — the Q19 echo whose wire bytes
    /// `WebSocketImpl.close` composes itself (WebSocketImpl.java:482-486).
    close_echo_armed: bool,
}

impl ConnectionDriver {
    fn new(
        core: ConnectionCore,
        commands: CommandQueue,
        policy: AutoResponsePolicy,
        close_echo: CloseEchoPolicy,
    ) -> ConnectionDriver {
        ConnectionDriver {
            core,
            commands,
            held: None,
            offered_write: None,
            write_cursor: 0,
            command_turn: true,
            pending_eofs: 0,
            terminal_delivered: false,
            policy,
            pending_auto_pongs: VecDeque::new(),
            injected_failure: None,
            close_echo,
            close_echo_armed: false,
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
                // Undeliverable wire output is aborted; the protocol EOF
                // below still applies (borrowed design: abort-undrainable-
                // writes on shutdown). Undelivered automatic replies are
                // just as undeliverable.
                self.offered_write = None;
                self.write_cursor = 0;
                self.drop_pending_writes();
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
                        return self.finish_poll(input_disposition, None, Some(failure));
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
                    DriverInput::Inbound(bytes) => {
                        self.command_turn = true;
                        let state_before = self.core.state();
                        match self.core.handle(Input::TransportBytes(bytes)) {
                            Ok(()) => self.arm_close_echo(state_before),
                            Err(failure) if !failure.code.is_fatal() => {
                                // Non-fatal backpressure: nothing was
                                // consumed; the adapter drains (by polling)
                                // and retries the identical bytes.
                                input_disposition =
                                    InputDisposition::Deferred(DeferredReason::Backpressure);
                            }
                            Err(failure) => {
                                return self.finish_poll(input_disposition, None, Some(failure));
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
    fn finish_poll<'owner>(
        &'owner mut self,
        input: InputDisposition,
        command: Option<CommandDisposition>,
        failure: Option<TypedProtocolFailure>,
    ) -> PollResult<'owner> {
        let state = self.core.state();
        // `apply_held_command` only builds a `Rejected` for a fatal (a
        // non-fatal refusal re-holds the command and returns `None`), so the
        // `is_fatal` guard is belt-and-braces: it keeps the promise this
        // method's name makes even if that invariant ever changes.
        let failure = failure.or_else(|| match &command {
            Some(CommandDisposition::Rejected { failure, .. }) if failure.code.is_fatal() => {
                Some(failure.clone())
            }
            _ => None,
        });
        let output = match failure {
            // Committed output is NOT lost by yielding the failure first —
            // it is deferred exactly as the inbound-fatal path already
            // defers it, and drains on the following polls.
            Some(failure) => DriverOutput::Failure(failure),
            None => self.next_output(),
        };
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

    fn drop_pending_writes(&mut self) {
        while self.core.next_write().is_some() {}
    }

    fn write_remaining(&self) -> usize {
        self.offered_write
            .as_ref()
            .map_or(0, |write| write.bytes.len() - self.write_cursor)
    }

    fn has_pending_output(&self) -> bool {
        self.offered_write.is_some()
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
        // A fatal failure from an injected automatic pong surfaces before
        // further event drain (there is no producer command to carry it).
        if let Some(failure) = self.injected_failure.take() {
            return DriverOutput::Failure(failure);
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
            if self.policy == AutoResponsePolicy::PongInboundPing
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
