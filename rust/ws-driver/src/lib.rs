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
//! ## Borrow attribution (owner strategy: borrow with attribution)
//!
//! Adapted from the Codex-plane US-017 `websocket-driver` (codex-import
//! 6a7606a): the pull-driven `poll(DriverInput) -> PollResult` shape, the
//! partial-write cursor with exact `WriteProgress` validation, the
//! inbound-vs-command alternation turn, EOF/shutdown latching, the
//! exactly-once `Terminal` delivery, and the terminal rejection of still
//! queued commands are their design. **Adaptation to `ws_core`:** their
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
    /// Terminal convergence rejected a command that was still queued when
    /// the connection closed.
    TerminalRejected(LocalCommand),
}

/// The single normalized terminal result: the core reached its one
/// absorbing `Closed` state and every ordered output before it delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalOutcome;

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
    /// One typed failure the core reported for an owner-applied input.
    Failure(TypedProtocolFailure),
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
    eof_latched: bool,
    shutdown_latched: bool,
    eof_applied: bool,
    terminal_delivered: bool,
    /// Queued command dispositions not yet surfaced (terminal rejections).
    dispositions: VecDeque<CommandDisposition>,
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
            eof_latched: false,
            shutdown_latched: false,
            eof_applied: false,
            terminal_delivered: false,
            dispositions: VecDeque::new(),
            policy,
            pending_auto_pongs: VecDeque::new(),
            injected_failure: None,
            dropped_writes: None,
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
                self.eof_latched = true;
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
                let command = self.dispositions.pop_front();
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
        } else if (self.eof_latched || self.shutdown_latched) && !self.eof_applied {
            // The latched transport EOF gets the first quiescent turn. The
            // core owns the semantics (Q20). A NON-FATAL refusal is the
            // core's event-queue backpressure: the EOF stays latched and is
            // retried on the next quiescent turn once outputs drain (the
            // US-017 bounded schedule exploration retained the minimized
            // counterexample `enqueue-close-b,inbound-close,shutdown` —
            // fuzz-seeds/us017/regressions/eof-backpressure-livelock.seed —
            // where latching `eof_applied` on a refused EOF lost the EOF
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
            } else if self.core.state() == ReadyState::Closed {
                self.eof_applied = true;
            } else {
                match self.core.handle(Input::TransportEof) {
                    Ok(()) => self.eof_applied = true,
                    Err(failure) if !failure.code.is_fatal() => {
                        // Backpressure: this poll still drains one queued
                        // output below, so the retry makes progress.
                    }
                    Err(failure) => {
                        self.eof_applied = true;
                        return self.finish_poll(input_disposition, None, Some(failure));
                    }
                }
            }
        } else if !self.terminal_delivered {
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

        self.prepare_terminal();
        let command = command_disposition.or_else(|| self.dispositions.pop_front());
        self.finish_poll(input_disposition, command, None)
    }

    fn finish_poll<'owner>(
        &'owner mut self,
        input: InputDisposition,
        command: Option<CommandDisposition>,
        failure: Option<TypedProtocolFailure>,
    ) -> PollResult<'owner> {
        self.prepare_terminal();
        let state = self.core.state();
        let output = match failure {
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

    /// After the core reaches its absorbing `Closed` state and no queued
    /// output remains, still-queued commands are disposed as
    /// `TerminalRejected` exactly once each (borrowed design: codex
    /// terminal convergence).
    fn prepare_terminal(&mut self) {
        if self.core.state() != ReadyState::Closed {
            return;
        }
        if let Some(command) = self.held.take() {
            self.dispositions
                .push_back(CommandDisposition::TerminalRejected(command));
        }
        while let Some(command) = self.commands.pop() {
            self.dispositions
                .push_back(CommandDisposition::TerminalRejected(command));
        }
    }

    /// Abort every committed wire write the ended transport can no longer
    /// deliver, ACCOUNTING for it in the pending [`DroppedWrites`] report
    /// (US-017 AC2: adapter shutdown is typed and does not leak).
    ///
    /// Called at the shutdown instant and again from [`Self::next_output`]
    /// on every later poll, so a write the core commits after shutdown is
    /// aborted and reported too rather than being offered to a dead
    /// transport. On the shipped core no such write exists — the only
    /// post-shutdown input is the latched EOF, which emits events only —
    /// which is why the report is observed exactly once.
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
    fn has_pending_output(&self) -> bool {
        self.offered_write.is_some() || self.dropped_writes.is_some()
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
        if self.core.state() == ReadyState::Closed
            && self.dispositions.is_empty()
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
