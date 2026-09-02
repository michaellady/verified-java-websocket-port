//! The deterministic Sans-I/O `ConnectionCore` and its single-owner /
//! bounded-channel concurrency boundary (US-009 AC2 + AC4).
//!
//! One mutable owner holds the [`ConnectionCore`] and feeds it [`Input`]
//! values; the core returns ordered [`crate::event::SemanticEvent`]s,
//! [`TransportWrite`]s, [`ReadyState`], and
//! [`crate::error::TypedProtocolFailure`]s. No sockets, no clocks, no
//! callbacks, no interior mutability, no threads — enforced by construction
//! and by the `sans_io_contract` source-scan test.
//!
//! ## Scope
//!
//! US-009 fixed the contract: types, limits, ownership, determinism,
//! backpressure, counters, and poisoning. The US-012/US-013/US-014 core
//! data path is implemented (borrowed with attribution from the Codex
//! plane and reconciled site-by-site against the reference model — see the
//! `framing`/`message`/`fragment` module docs): the byte path scans,
//! translates, records, and processes frames; text/binary messages deliver
//! through the two-stage UTF-8 gates; fragments reassemble; and
//! `send_text`/`send_binary`/`send_fragment` emit real wire writes. The
//! handshake plane (US-010/US-011, borrow batch B) drives
//! `NotYetConnected` to open. Batch C (US-015/US-016) landed the control
//! and close lifecycles: inbound ping/pong deliver as events (Q18: no
//! automatic pong exists in the core), `send_ping`/`send_pong` emit real
//! control frames with NO payload-size cap (Q17), and the close lifecycle
//! — echo-while-open with the constructor payload (Q19/Q10), local
//! `send_close` through the US-009 pure close functions (Q13/Q14), and the
//! closing/closed completion — mirrors derive.go `processInbound` /
//! `sendClose` exactly. The US-016 AC3 closure retired the last honest
//! [`crate::error::FailureCode::Unimplemented`] refusals here: the
//! `NotYetConnected` command/EOF arms now mirror the shipped Java
//! pre-handshake lifecycle directly (`WebSocketImpl.eot()`'s
//! never-connected close, `close()`'s never-connected flush ladder, and
//! `send(Collection)`'s `WebsocketNotConnectedException`), staying — like
//! the handshake byte path — OUTSIDE the corpus counters and vocabulary
//! (no corpus scenario begins pre-handshake).
//!
//! ## Behavior authority
//!
//! Where the skeleton does encode behavior it mirrors the pinned Java
//! runtime through the reference model `internal/corpora/derive.go` exactly;
//! each site carries its citation and quirk id from the US-009 design draft.
//! The abstract lifecycle this machine refines is model-checked in
//! `assurance/formal/connection-model.tla` (ReadyState here is the one
//! production representation; the TLA+ model stays proved-model-only per
//! US-006 AC4). The port-side strengthenings (bounds enforced before
//! retained allocations, exactly-once terminal delivery planned as
//! note.close.exactly-once-terminal-delivery) become behavior-delta-ledger
//! records once their baseline observations exist.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};

use crate::close::{
    CloseDetail, CloseOrigin, NEVER_CONNECTED_CLOSE_CODE, close_code_rejection,
    normalize_send_close_code,
};
use crate::config::ConnectionConfig;
use crate::error::{FailureCode, QueueKind, TypedProtocolFailure};
use crate::event::{
    Counts, Direction, FrameRecord, OutboundCause, SemanticEvent, SemanticEventKind,
    TransitionCause,
};
use crate::framing::{CLOSE_CONSTRUCTOR_PAYLOAD, DecodedFrame, Draft6455, Opcode, ProcessOutcome};
use crate::handshake::{self, HandshakeDriver};
use crate::message::Charsetfunctions;
use crate::queue::BoundedQueue;

/// Connection role, mirroring `org.java_websocket.enums.Role` (corpus
/// `role`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// The connection initiator (masks outbound frames).
    Client,
    /// The connection acceptor.
    Server,
}

impl Role {
    /// The corpus wire string.
    #[must_use]
    pub fn wire_name(&self) -> &'static str {
        match self {
            Role::Client => "client",
            Role::Server => "server",
        }
    }
}

/// Connection lifecycle state, mirroring `org.java_websocket.enums.ReadyState`
/// (NOT_YET_CONNECTED, OPEN, CLOSING, CLOSED; enums/ReadyState.java:7).
/// `Closed` is absorbing: the port models one terminal state reached
/// identically from either side (migration map
/// `migration.org-java-websocket-websocket` known_non_equivalent_cases).
/// This enum is the ONE production state representation; abstract proof
/// models must refine it, never duplicate it (US-006 AC4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReadyState {
    /// Before the opening handshake completes (no corpus projection; the
    /// behavior corpora start post-handshake).
    NotYetConnected,
    /// Open for data.
    Open,
    /// Close handshake in progress.
    Closing,
    /// Terminal, absorbing.
    Closed,
}

impl ReadyState {
    /// The corpus `{open, closing, closed}` projection of this state, when
    /// one exists ([`ReadyState::NotYetConnected`] has none — the corpus
    /// `initial_state`/`final_state` vocabulary is post-handshake).
    #[must_use]
    pub fn corpus_state(&self) -> Option<&'static str> {
        match self {
            ReadyState::NotYetConnected => None,
            ReadyState::Open => Some("open"),
            ReadyState::Closing => Some("closing"),
            ReadyState::Closed => Some("closed"),
        }
    }
}

/// AC2 vocabulary alias: the acceptance criteria name this type
/// `ConnectionState`; the migration map's planned identity is
/// [`ReadyState`]. One type, both names.
pub type ConnectionState = ReadyState;

/// The corpus `initial_state` vocabulary for the oracle-harness seam
/// ([`ConnectionCore::new_in_state`]): the behavior corpora begin
/// post-handshake in one of exactly these states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InitialState {
    /// Begin open.
    Open,
    /// Begin closing.
    Closing,
    /// Begin closed.
    Closed,
}

impl InitialState {
    /// The [`ReadyState`] this initial state denotes.
    #[must_use]
    pub fn ready_state(&self) -> ReadyState {
        match self {
            InitialState::Open => ReadyState::Open,
            InitialState::Closing => ReadyState::Closing,
            InitialState::Closed => ReadyState::Closed,
        }
    }
}

/// Data opcode for [`LocalCommand::SendFragment`] (corpus `send_fragment`
/// `opcode` enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataOpcode {
    /// Text fragment sequence.
    Text,
    /// Binary fragment sequence.
    Binary,
}

/// Local commands — exactly the corpus action vocabulary
/// (`schemas/corpus-scenario-1.0.0.schema.json` `steps[kind=action]`), so a
/// harness maps scenario steps to commands with zero interpretation. The
/// `eof` action maps to [`Input::TransportEof`], not to a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalCommand {
    /// `send_text {text}`.
    SendText {
        /// The text to send.
        text: String,
    },
    /// `send_binary {data}`.
    SendBinary {
        /// The bytes to send.
        data: Vec<u8>,
    },
    /// `send_ping {data}`.
    SendPing {
        /// The ping payload.
        data: Vec<u8>,
    },
    /// `send_pong {data}`.
    SendPong {
        /// The pong payload.
        data: Vec<u8>,
    },
    /// `send_close {code, reason}`.
    SendClose {
        /// The requested close code (1015 normalizes to 1005 before
        /// validation — quirk Q14, wired in US-016).
        code: u16,
        /// The close reason.
        reason: String,
    },
    /// `send_fragment {opcode, data, fin}`.
    SendFragment {
        /// The declared data opcode.
        opcode: DataOpcode,
        /// The fragment payload.
        data: Vec<u8>,
        /// Whether this fragment ends the message.
        fin: bool,
    },
}

/// One input to the core. Transport bytes arrive in arbitrary chunks;
/// determinism under re-chunking is a contract property (AC4).
#[derive(Debug, Clone)]
pub enum Input<'a> {
    /// A chunk of transport bytes (corpus `steps[kind=bytes]`).
    TransportBytes(&'a [u8]),
    /// Transport EOF (corpus `steps[kind=action][action=eof]`; participates
    /// in action accounting exactly as the oracle's eof action does).
    TransportEof,
    /// A local command (corpus `steps[kind=action]`, all other actions).
    Command(LocalCommand),
}

/// Ordered wire output. The core never writes anywhere; the owner drains
/// via [`ConnectionCore::next_write`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportWrite {
    /// The bytes to hand to the transport, in order.
    pub bytes: Vec<u8>,
}

/// The largest number of event-queue slots one NON-BYTE input can require
/// (re-derived for the batch-C US-015/US-016 arms, as the US-009 docs
/// required): the worst case is `send_close` — one frame record, one
/// `send_close` cause event, the `close_initiated` detail event, and the
/// `open -> closing` transition record. Transport EOF needs 2 (the `eof`
/// detail plus the transition); every other send needs 2 (frame record +
/// cause). The per-input capacity precheck uses this bound to keep input
/// handling atomic — an input either fully processes or is refused with
/// [`FailureCode::Backpressure`] before any mutation.
///
/// Byte inputs use the dynamic bound
/// [`ConnectionCore::byte_input_event_bound`] instead: one chunk can
/// complete many frames, each contributing at most
/// [`EVENT_SLOTS_PER_FRAME`] slots on top of the `input_chunk` record,
/// plus [`CLOSE_ECHO_EVENT_SLOTS`] once per input.
pub const MAX_EVENT_SLOTS_PER_INPUT: usize = 4;

/// Worst-case event slots one processed inbound frame can emit, excluding
/// the once-per-input close echo (re-derived for the US-015/US-016 arms):
/// its frame record plus at most a close detail event and the terminal
/// transition record (a close frame in the closing state). Ping/pong and
/// data frames need at most the record plus one semantic event.
pub const EVENT_SLOTS_PER_FRAME: usize = 3;

/// Extra event slots the ONE possible close echo per byte input requires:
/// the echoed frame record plus its `echo_close` cause event. At most one
/// echo can occur per input — the first close while open transitions to
/// closing, a close in closing terminates, and no path re-enters open
/// within the same input (derive.go processInbound close arm).
pub const CLOSE_ECHO_EVENT_SLOTS: usize = 2;

/// The pending wire buffer's slack over `max_buffered_bytes`: the maximum
/// frame header size (2 base + 8 extended length + 4 mask = 14), the exact
/// Java slack the reference model pins (quirk Q24; derive.go:313-319
/// `WireTracker.accept` semantics).
pub const WIRE_PENDING_SLACK_BYTES: u64 = 14;

/// The pinned EOF reason for a transport EOF before the close handshake
/// completed (derive.go `eof`; quirk Q20).
const EOF_DEFAULT_REASON: &str = "transport EOF before close handshake completed";

/// The deterministic Sans-I/O connection core: single owner, no interior
/// mutability, no threads (US-009 AC2/AC4). See the module docs for the
/// story scope and the skeleton's honest refusals.
///
/// The migration map's planned identity for the single mutable owner is
/// [`WebSocketImpl`]; that alias and this struct are one type.
#[derive(Debug)]
pub struct ConnectionCore {
    config: ConnectionConfig,
    role: Role,
    state: ReadyState,
    /// Whether the opening handshake ever completed (Java: `readyState`
    /// left NOT_YET_CONNECTED through `open()`). Distinguishes the
    /// pre-handshake close lifecycle — `eot()`'s `flushandclosestate` arm
    /// reporting the RECORDED `closedremotely` — from the corpus-pinned
    /// post-handshake Q20 vocabulary, because a `send_close` before open
    /// leaves `Closing` with an otherwise identical governing detail.
    /// `new_in_state` (the corpus entry) begins with it true.
    handshake_completed: bool,
    /// Set by the first fatal failure; afterwards every input is refused
    /// with a StateViolation-class failure (partial-execution semantics:
    /// "errors retain counts and final state").
    poisoned: bool,
    /// Zero-based index of the next accepted input.
    step: u64,
    /// Pending (incomplete-frame) wire bytes, bounded by
    /// `max_buffered_bytes` + [`WIRE_PENDING_SLACK_BYTES`].
    pending: Vec<u8>,
    /// The wire-buffered length reported by [`ConnectionCore::counts`]. On a
    /// buffer-overflow failure this records the oversized leftover length
    /// (matching the oracle's failure counts) even though the port never
    /// retains the oversized buffer itself.
    wire_buffered_reported: u64,
    /// Message (fragment) reassembly accounting (corpus
    /// `message_buffered_bytes`), updated at exactly the reference model's
    /// sites (derive.go `messageBuffered`; US-014).
    message_buffered: u64,
    input_bytes: u64,
    consumed_bytes: u64,
    action_count: u64,
    frame_count: u64,
    close_detail: Option<CloseDetail>,
    events: BoundedQueue<SemanticEvent>,
    writes: BoundedQueue<TransportWrite>,
    /// The RFC 6455 codec seam with its continuation state (US-012/US-014).
    draft: Draft6455,
    /// Outbound masked-frame counter feeding the deterministic mask-key
    /// stream (quirk Q28: mask keys are never observable, so any
    /// deterministic source derived from `mask_key_seed` scores
    /// identically).
    mask_counter: u64,
    /// Opening-handshake driver for the `NotYetConnected` byte path
    /// (US-010/US-011; state logic lives in [`crate::handshake`], this
    /// struct only dispatches to it).
    handshake: HandshakeDriver,
}

/// Migration-map planned identity for the single-owner connection type
/// (proof-targets sym.concurrency.connection-owner plans
/// `ws_core::connection::WebSocketImpl`, consolidating
/// `org.java_websocket.WebSocketImpl`'s shared-mutable state into one
/// owner). Alias of [`ConnectionCore`], the AC2 name: one type, both names.
pub type WebSocketImpl = ConnectionCore;

impl ConnectionCore {
    /// A fresh connection in [`ReadyState::NotYetConnected`]. The handshake
    /// slices (US-010 client, US-011 server) drive it to open; until they
    /// land, every input here is refused with
    /// [`FailureCode::Unimplemented`].
    #[must_use]
    pub fn new(config: ConnectionConfig, role: Role) -> Self {
        Self::with_state(config, role, ReadyState::NotYetConnected)
    }

    /// Oracle-harness seam: begin post-handshake in the corpus
    /// `initial_state` (the behavior corpora never exercise the handshake —
    /// that is the separate handshake tier — so scoring requires this entry
    /// point).
    #[must_use]
    pub fn new_in_state(config: ConnectionConfig, role: Role, state: InitialState) -> Self {
        Self::with_state(config, role, state.ready_state())
    }

    fn with_state(config: ConnectionConfig, role: Role, state: ReadyState) -> Self {
        let events = BoundedQueue::new(config.event_queue_capacity());
        let writes = BoundedQueue::new(config.write_queue_capacity());
        ConnectionCore {
            config,
            role,
            state,
            handshake_completed: state != ReadyState::NotYetConnected,
            poisoned: false,
            step: 0,
            pending: Vec::new(),
            wire_buffered_reported: 0,
            message_buffered: 0,
            input_bytes: 0,
            consumed_bytes: 0,
            action_count: 0,
            frame_count: 0,
            close_detail: None,
            events,
            writes,
            draft: Draft6455::new(),
            mask_counter: 0,
            handshake: HandshakeDriver::Idle,
        }
    }

    /// Feed one input. `Ok(())` means the input was fully processed; drain
    /// [`ConnectionCore::next_event`] / [`ConnectionCore::next_write`].
    ///
    /// # Errors
    ///
    /// - [`FailureCode::Backpressure`]: a bounded queue lacks room; nothing
    ///   was consumed or mutated — drain and retry the identical input.
    /// - Any fatal code poisons the core into its final state; further
    ///   inputs return [`FailureCode::StateViolation`], mirroring the
    ///   oracle's partial-execution semantics ("errors retain counts and
    ///   final state").
    pub fn handle(&mut self, input: Input<'_>) -> Result<(), TypedProtocolFailure> {
        if self.poisoned {
            return Err(TypedProtocolFailure::protocol(FailureCode::StateViolation));
        }
        let result = match input {
            Input::TransportBytes(chunk) => self.handle_bytes(chunk),
            Input::TransportEof => self.handle_eof(),
            Input::Command(command) => self.handle_command(&command),
        };
        match &result {
            Ok(()) => self.step = self.step.saturating_add(1),
            Err(failure) if failure.code.is_fatal() => {
                self.poisoned = true;
                self.step = self.step.saturating_add(1);
            }
            Err(_) => {} // Backpressure: the input was not consumed.
        }
        result
    }

    /// Drain the next transport write (total, deterministic order). The
    /// US-009 skeleton emits none (outbound framing is US-012+).
    pub fn next_write(&mut self) -> Option<TransportWrite> {
        self.writes.pop()
    }

    /// Drain the next semantic event (total, deterministic order).
    pub fn next_event(&mut self) -> Option<SemanticEvent> {
        self.events.pop()
    }

    /// Current lifecycle state.
    #[must_use]
    pub fn state(&self) -> ReadyState {
        self.state
    }

    /// The connection's role.
    #[must_use]
    pub fn role(&self) -> Role {
        self.role
    }

    /// The immutable configuration this core was built with.
    #[must_use]
    pub fn config(&self) -> &ConnectionConfig {
        &self.config
    }

    /// Snapshot of the corpus `counts` object (checked arithmetic
    /// throughout; `buffered_bytes` = wire + message, derive.go `counts`).
    #[must_use]
    pub fn counts(&self) -> Counts {
        Counts {
            actions: self.action_count,
            buffered_bytes: self
                .wire_buffered_reported
                .saturating_add(self.message_buffered),
            consumed_bytes: self.consumed_bytes,
            frames: self.frame_count,
            input_bytes: self.input_bytes,
            message_buffered_bytes: self.message_buffered,
            wire_buffered_bytes: self.wire_buffered_reported,
        }
    }

    /// The governing close outcome, once one exists (corpus `close`).
    #[must_use]
    pub fn close_detail(&self) -> Option<&CloseDetail> {
        self.close_detail.as_ref()
    }

    // -- internal ---------------------------------------------------------

    fn backpressure(kind: QueueKind) -> TypedProtocolFailure {
        TypedProtocolFailure::protocol(FailureCode::Backpressure(kind))
    }

    fn state_violation() -> TypedProtocolFailure {
        TypedProtocolFailure::protocol(FailureCode::StateViolation)
    }

    /// Push an event whose capacity was prechecked. A failed push here is an
    /// internal contract bug (the precheck is the atomicity guarantee), so
    /// it fails loudly rather than silently dropping an observable.
    fn emit(&mut self, kind: SemanticEventKind) {
        let event = SemanticEvent {
            step: self.step,
            kind,
        };
        self.events
            .push(event)
            .expect("event-queue capacity was prechecked for this input");
    }

    /// Record a transition exactly as derive.go `transition` does: no-op
    /// when the state is unchanged (dedupe), otherwise a transitions-stream
    /// record then the state change.
    fn transition(&mut self, next: ReadyState, cause: TransitionCause) {
        if self.state == next {
            return;
        }
        self.emit(SemanticEventKind::Transition {
            from: self.state,
            to: next,
            cause,
        });
        self.state = next;
    }

    /// Worst-case event slots one byte input can require: the `input_chunk`
    /// record plus [`EVENT_SLOTS_PER_FRAME`] per frame that can actually be
    /// processed before the frame budget refuses (the budget check emits
    /// nothing, so spans past `max_frames - frames_so_far` contribute no
    /// slots beyond the one refused frame), plus the once-per-input close
    /// echo ([`CLOSE_ECHO_EVENT_SLOTS`]).
    fn byte_input_event_bound(&self, complete_spans: usize) -> usize {
        let frame_budget = self
            .config
            .max_frames()
            .saturating_sub(self.frame_count)
            .saturating_add(1);
        let budget = usize::try_from(frame_budget).unwrap_or(usize::MAX);
        1usize
            .saturating_add(EVENT_SLOTS_PER_FRAME.saturating_mul(complete_spans.min(budget)))
            .saturating_add(CLOSE_ECHO_EVENT_SLOTS)
    }

    /// Byte path, mirroring derive.go `inputStep` exactly: span scan,
    /// leftover cap (Q24), translate with per-site consumption (Q25),
    /// incomplete-header screen, then per-frame recording and processing
    /// with the frame budget checked before each record.
    fn handle_bytes(&mut self, chunk: &[u8]) -> Result<(), TypedProtocolFailure> {
        // Opening-handshake byte path (US-010/US-011): the state logic lives
        // in crate::handshake; this arm only dispatches. A surviving
        // handshake chunk emits at most one input_chunk event; the
        // open-state data path below does its own dynamic slot precheck.
        if self.state == ReadyState::NotYetConnected {
            if self.events.available() < 1 {
                return Err(Self::backpressure(QueueKind::Event));
            }
            return self.handle_handshake_bytes(chunk);
        }
        // Quirk Q26 / derive.go:292-294: closed + nonzero payload is a state
        // violation; an empty chunk is still recorded.
        if self.state == ReadyState::Closed && !chunk.is_empty() {
            return Err(Self::state_violation());
        }
        // addBounded input limit (derive.go:295-299): the counter updates
        // only when within bounds. A u64 overflow certainly exceeds every
        // permitted limit, so checked arithmetic maps it to the same
        // failure. Computed here, committed only after the backpressure
        // precheck below (the precheck must precede all mutation).
        let chunk_len = chunk.len() as u64;
        let max_input = self.config.max_input_bytes() as u64;
        let new_input_total = match self.input_bytes.checked_add(chunk_len) {
            Some(total) if total <= max_input => total,
            _ => {
                return Err(TypedProtocolFailure::protocol(
                    FailureCode::InputLimitExceeded,
                ));
            }
        };
        if chunk.is_empty() {
            // Atomicity precheck for the single input_chunk record.
            if self.events.available() < 1 {
                return Err(Self::backpressure(QueueKind::Event));
            }
            self.input_bytes = new_input_total;
            // derive.go:301: an empty chunk records input_chunk {bytes: 0}
            // and consumes nothing.
            self.emit(SemanticEventKind::InputChunk { bytes: 0 });
            return Ok(());
        }
        // Combined wire view (derive.go: combined := pending ++ payload).
        // Every bound guarding this allocation is already enforced: pending
        // <= max_buffered_bytes + slack, chunk <= max_input_bytes.
        let mut combined = Vec::with_capacity(self.pending.len() + chunk.len());
        combined.extend_from_slice(&self.pending);
        combined.extend_from_slice(chunk);
        // Span scan (WireTracker.frameLength): complete frames by length
        // grammar only; pure computation, safe before the precheck.
        let (spans, leftover_start) = Draft6455::scan_spans(&combined);
        // Atomicity precheck: nothing has mutated yet, so a refused input
        // can be retried identically after draining.
        if self.events.available() < self.byte_input_event_bound(spans.len()) {
            return Err(Self::backpressure(QueueKind::Event));
        }
        // Write precheck for the ONE possible close echo this input can emit
        // (US-016; see CLOSE_ECHO_EVENT_SLOTS for why at most one): a close
        // frame processed while open queues an echo write.
        if !spans.is_empty() && self.writes.available() < 1 {
            return Err(Self::backpressure(QueueKind::Write));
        }
        self.input_bytes = new_input_total;
        let chunk_start = self.pending.len();
        let leftover_len = (combined.len() - leftover_start) as u64;
        // Quirk Q24 (derive.go:313-319): pending is replaced by the leftover
        // BEFORE the overflow check, the overflow ends the scenario before
        // any translation, and consumed stays 0 for this chunk. Java (and
        // the reference model) retain the oversized buffer before checking;
        // the port checks before retaining — a JAVA_FAITHFUL_PLUS_SAFE
        // strengthening with identical observables (the failure counts
        // still report the oversized leftover length, as the oracle does).
        self.wire_buffered_reported = leftover_len;
        let cap =
            (self.config.max_buffered_bytes() as u64).saturating_add(WIRE_PENDING_SLACK_BYTES);
        if leftover_len > cap {
            self.pending = Vec::new();
            return Err(TypedProtocolFailure::protocol(
                FailureCode::BufferLimitExceeded,
            ));
        }
        self.pending = combined[leftover_start..].to_vec();
        // Translate stage: sequential decode with Java's validity order and
        // per-site consumption (quirk Q25). On a rejection the consumed
        // counter advances by the offset of the failure site relative to
        // this chunk's start (saturating at zero for a frame completed from
        // buffered bytes — a shape outside the reference model's verified
        // space, derive.go:330-334).
        let max_frame = self.config.max_frame_payload_bytes() as u64;
        let mut decoded: Vec<DecodedFrame> = Vec::with_capacity(spans.len());
        for span in &spans {
            match Draft6455::translate_single_frame(
                &combined[span.start..span.start + span.size],
                max_frame,
            ) {
                Ok(mut frame) => {
                    frame.wire_bytes = span.size;
                    decoded.push(frame);
                }
                Err(reject) => {
                    let site = (span.start + reject.consumed).saturating_sub(chunk_start) as u64;
                    self.consumed_bytes = self.consumed_bytes.saturating_add(site);
                    return Err(reject.failure);
                }
            }
        }
        // A fresh incomplete frame whose visible header already violates the
        // runtime rules is rejected during this step (translateSingleFrame
        // reads the header before noticing the frame is incomplete;
        // derive.go screenIncompleteHeader) — before the input_chunk event
        // and before any frame from this chunk is recorded.
        if combined.len() - leftover_start >= 2
            && let Err(reject) =
                Draft6455::decode_frame_header(&combined[leftover_start..], max_frame)
        {
            let site = (leftover_start + reject.consumed).saturating_sub(chunk_start) as u64;
            self.consumed_bytes = self.consumed_bytes.saturating_add(site);
            return Err(reject.failure);
        }
        // derive.go:358-359: the whole surviving chunk counts as consumed
        // through translation, then the input_chunk event is recorded.
        self.consumed_bytes = self.consumed_bytes.saturating_add(chunk_len);
        self.emit(SemanticEventKind::InputChunk { bytes: chunk_len });
        // Per-frame recording and processing (derive.go:360-368): the frame
        // budget is checked BEFORE each record; processing failures happen
        // after the record and after earlier frames' effects.
        for frame in decoded {
            if self.frame_count >= self.config.max_frames() {
                return Err(TypedProtocolFailure::protocol(
                    FailureCode::FrameLimitExceeded,
                ));
            }
            self.frame_count += 1;
            // Quirk Q10: close frame records carry the constructor payload,
            // never the wire payload (derive.go inboundFrameRecord).
            let record_payload = if frame.opcode == Opcode::Closing {
                CLOSE_CONSTRUCTOR_PAYLOAD.to_vec()
            } else {
                frame.payload.clone()
            };
            self.emit(SemanticEventKind::FrameObserved(FrameRecord {
                direction: Direction::Inbound,
                fin: frame.fin,
                masked: frame.masked,
                opcode: frame.opcode,
                payload: record_payload,
                rsv1: frame.rsv1,
                rsv2: frame.rsv2,
                rsv3: frame.rsv3,
                step: self.step,
                wire_bytes: frame.wire_bytes as u64,
            }));
            self.process_inbound(frame)?;
        }
        Ok(())
    }

    /// Process one recorded inbound frame (derive.go `processInbound`):
    /// state gates first, then the opcode dispatch — the close lifecycle
    /// (US-016), ping/pong delivery (US-015), and the data path
    /// (US-013/US-014).
    fn process_inbound(&mut self, frame: DecodedFrame) -> Result<(), TypedProtocolFailure> {
        // derive.go:637-641: closed refuses everything; closing refuses
        // every non-close frame.
        if self.state == ReadyState::Closed {
            return Err(Self::state_violation());
        }
        if self.state == ReadyState::Closing && frame.opcode != Opcode::Closing {
            return Err(Self::state_violation());
        }
        match frame.opcode {
            Opcode::Closing => return self.process_close_frame(&frame),
            // derive.go:671-678: ping and pong ONLY record their events —
            // no automatic pong exists in the reference model's observable
            // space (quirk Q18; the Codex AutomaticPongPolicy machinery is
            // deliberately not adopted), and neither arm touches the
            // fragment accumulator (interleave is transparent).
            Opcode::Ping => {
                self.emit(SemanticEventKind::Ping {
                    data: frame.payload,
                });
                return Ok(());
            }
            Opcode::Pong => {
                self.emit(SemanticEventKind::Pong {
                    data: frame.payload,
                });
                return Ok(());
            }
            _ => {}
        }
        let outcome = self.draft.process_frame(
            &frame,
            self.config.max_buffered_bytes(),
            self.config.max_message_bytes(),
            &mut self.message_buffered,
        )?;
        match outcome {
            ProcessOutcome::Buffered => {}
            ProcessOutcome::Text(text) => self.emit(SemanticEventKind::Text { text }),
            ProcessOutcome::Binary(data) => self.emit(SemanticEventKind::Binary { data }),
        }
        Ok(())
    }

    /// The inbound close arm (US-016), mirroring derive.go `processInbound`
    /// OpcodeClose exactly: parse the payload with the shipped CloseFrame
    /// semantics (Q11/Q12/Q13 — already applied at translate time, so a
    /// failure here is defensive), record the governing remote close, emit
    /// the `close` event, then either complete the handshake (closing ->
    /// closed) or echo while open (Q19) with the constructor payload (Q10)
    /// and transition to closing.
    fn process_close_frame(&mut self, frame: &DecodedFrame) -> Result<(), TypedProtocolFailure> {
        let (code, reason) = Draft6455::parse_close_payload(&frame.payload)?;
        let was_closing = self.state == ReadyState::Closing;
        let detail = CloseDetail {
            code: i32::from(code),
            reason,
            origin: CloseOrigin::Remote,
            remote: true,
            handshake_complete: true,
        };
        self.close_detail = Some(detail.clone());
        self.emit(SemanticEventKind::Close(detail));
        if was_closing {
            self.transition(ReadyState::Closed, TransitionCause::ReceiveClose);
            return Ok(());
        }
        // Q19 echo-while-open: the echoed frame OBJECT carries the
        // constructor payload [0x03, 0xe8] (Q10), never the wire payload —
        // the Codex exact code/reason acknowledgement echo is NOT Java. The
        // frame budget is checked inside emit_outbound, AFTER the close
        // event, exactly as derive.go orders it.
        self.emit_outbound(
            OutboundCause::EchoClose,
            true,
            Opcode::Closing,
            CLOSE_CONSTRUCTOR_PAYLOAD.to_vec(),
        )?;
        self.transition(ReadyState::Closing, TransitionCause::ReceiveClose);
        Ok(())
    }

    /// The next deterministic client mask key: SplitMix64 over
    /// `mask_key_seed` and the outbound masked-frame counter (quirk Q28:
    /// Java randomizes mask keys and no observation ever records them, so
    /// any deterministic derivation scores identically; the design draft's
    /// injected-mask-source seam).
    fn next_mask_key(&mut self) -> [u8; 4] {
        self.mask_counter = self.mask_counter.wrapping_add(1);
        let mut z = self
            .config
            .mask_key_seed()
            .wrapping_add(self.mask_counter.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        #[allow(clippy::cast_possible_truncation)]
        let word = z as u32;
        word.to_be_bytes()
    }

    /// Emit one outbound frame (derive.go `emitOutbound`): the frame budget
    /// check, the real wire write (encoded, client-masked from the
    /// deterministic seed), the outbound frame record, then the cause event
    /// carrying the opcode name.
    fn emit_outbound(
        &mut self,
        cause: OutboundCause,
        fin: bool,
        opcode: Opcode,
        payload: Vec<u8>,
    ) -> Result<(), TypedProtocolFailure> {
        if self.frame_count >= self.config.max_frames() {
            return Err(TypedProtocolFailure::protocol(
                FailureCode::FrameLimitExceeded,
            ));
        }
        let masked = self.role == Role::Client;
        // Wire size mirrors Draft_6455.createBinaryFrame accounting: header
        // + mask key (client role) + payload (frames.go outboundWireBytes).
        let wire_bytes = (Draft6455::header_size(payload.len())
            + payload.len()
            + if masked { 4 } else { 0 }) as u64;
        let mask = if masked {
            Some(self.next_mask_key())
        } else {
            None
        };
        let bytes = Draft6455::encode_frame(fin, opcode, &payload, mask);
        self.writes
            .push(TransportWrite { bytes })
            .expect("write-queue capacity was prechecked for this input");
        self.frame_count += 1;
        self.emit(SemanticEventKind::FrameObserved(FrameRecord {
            direction: Direction::Outbound,
            fin,
            masked,
            opcode,
            payload,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            step: self.step,
            wire_bytes,
        }));
        self.emit(SemanticEventKind::OutboundCause { cause, opcode });
        Ok(())
    }

    /// Begin the client opening handshake (US-010): render the deterministic
    /// upgrade request (nonce derived from the configured `mask_key_seed` —
    /// the determinism seam, quirk Q28) as a queued [`TransportWrite`] and
    /// await the server's response on the byte path. This is a port-side
    /// construction entry point (like [`ConnectionCore::new_in_state`]), not
    /// a corpus command: the behavior corpora start post-handshake, so no
    /// `LocalCommand` exists for it.
    ///
    /// # Errors
    ///
    /// - [`FailureCode::StateViolation`]: not `NotYetConnected`, not the
    ///   client role, or the handshake already started (non-fatal here would
    ///   lie; the misuse poisons the core exactly like other fatal codes).
    /// - [`FailureCode::Backpressure`]: no write-queue slot for the request;
    ///   nothing was mutated — drain and retry.
    pub fn begin_client_handshake(
        &mut self,
        request_target: &str,
        host: &str,
    ) -> Result<(), TypedProtocolFailure> {
        if self.poisoned
            || self.state != ReadyState::NotYetConnected
            || self.role != Role::Client
            || !matches!(self.handshake, HandshakeDriver::Idle)
        {
            self.poisoned = true;
            return Err(Self::state_violation());
        }
        let descriptor = handshake::client::ClientRequestDescriptor::try_new(request_target, host)
            .map_err(|_| {
                self.poisoned = true;
                Self::state_violation()
            })?;
        if self.writes.available() < 1 {
            return Err(Self::backpressure(QueueKind::Write));
        }
        let nonce = handshake::client::nonce_from_seed(self.config.mask_key_seed());
        let limits = handshake::HandshakeLimits::from_config(&self.config);
        let (machine, request) =
            handshake::client::ClientHandshake::start(&descriptor, nonce, limits);
        self.writes
            .push(TransportWrite { bytes: request })
            .expect("write-queue capacity was prechecked for this request");
        self.handshake = HandshakeDriver::Client(machine);
        Ok(())
    }

    /// `NotYetConnected` byte path (US-010/US-011 handshake entry hook). The
    /// handshake decision logic lives in [`crate::handshake`]; this method
    /// only maps outcomes onto core mutations. Handshake-phase bytes are
    /// deliberately OUTSIDE the corpus counters (`input_bytes` /
    /// `consumed_bytes` / `input_chunk` events are post-handshake corpus
    /// vocabulary; no corpus scenario observes this state), and the
    /// `NotYetConnected -> Open` change emits no transition record (the
    /// transcript `transitions` stream is the close lifecycle only,
    /// derive.go `transition` call sites).
    fn handle_handshake_bytes(&mut self, chunk: &[u8]) -> Result<(), TypedProtocolFailure> {
        // Atomicity precheck: any terminal handshake outcome writes at most
        // one response head.
        if self.writes.available() < 1 {
            return Err(Self::backpressure(QueueKind::Write));
        }
        if matches!(self.handshake, HandshakeDriver::Idle) {
            match self.role {
                Role::Server => {
                    let limits = handshake::HandshakeLimits::from_config(&self.config);
                    self.handshake =
                        HandshakeDriver::Server(handshake::server::ServerHandshake::new(limits));
                }
                Role::Client => {
                    // Bytes before begin_client_handshake: the port never
                    // reads a response it has not requested.
                    self.poisoned = true;
                    return Err(Self::state_violation());
                }
            }
        }
        match &mut self.handshake {
            HandshakeDriver::Idle => unreachable!("driver was just installed"),
            HandshakeDriver::Server(machine) => match machine.consume(chunk) {
                handshake::server::ServerHandshakeOutcome::Incomplete => Ok(()),
                handshake::server::ServerHandshakeOutcome::Accept {
                    response,
                    remainder,
                    ..
                } => {
                    self.writes
                        .push(TransportWrite { bytes: response })
                        .expect("write-queue capacity was prechecked for this input");
                    self.finish_handshake_open(remainder)
                }
                handshake::server::ServerHandshakeOutcome::Reject { response, .. } => {
                    // The collapsed Java observable: HTTP error head + close
                    // 1002 (InvalidHandshakeException carries PROTOCOL_ERROR).
                    self.writes
                        .push(TransportWrite { bytes: response })
                        .expect("write-queue capacity was prechecked for this input");
                    Err(TypedProtocolFailure::java_invalid_data(
                        handshake::HANDSHAKE_REJECT_CLOSE_CODE,
                    ))
                }
                handshake::server::ServerHandshakeOutcome::LimitExceeded(_) => {
                    // PLUS_SAFE configured-budget refusal (port
                    // strengthening; never a Java observable).
                    Err(TypedProtocolFailure::protocol(
                        FailureCode::BufferLimitExceeded,
                    ))
                }
                handshake::server::ServerHandshakeOutcome::NotAwaiting => {
                    Err(Self::state_violation())
                }
            },
            HandshakeDriver::Client(machine) => match machine.consume(chunk) {
                handshake::client::ClientHandshakeOutcome::Incomplete => Ok(()),
                handshake::client::ClientHandshakeOutcome::Accept { remainder } => {
                    self.finish_handshake_open(remainder)
                }
                handshake::client::ClientHandshakeOutcome::Reject { .. } => Err(
                    TypedProtocolFailure::java_invalid_data(handshake::HANDSHAKE_REJECT_CLOSE_CODE),
                ),
                handshake::client::ClientHandshakeOutcome::LimitExceeded(_) => Err(
                    TypedProtocolFailure::protocol(FailureCode::BufferLimitExceeded),
                ),
                handshake::client::ClientHandshakeOutcome::NotAwaiting => {
                    Err(Self::state_violation())
                }
            },
        }
    }

    /// Open the connection after an accepted handshake, stashing post-head
    /// remainder bytes into the pending wire buffer under the Q24 cap
    /// (bounded before retention, as everywhere in this core).
    fn finish_handshake_open(&mut self, remainder: Vec<u8>) -> Result<(), TypedProtocolFailure> {
        let cap =
            (self.config.max_buffered_bytes() as u64).saturating_add(WIRE_PENDING_SLACK_BYTES);
        let remainder_len = remainder.len() as u64;
        if remainder_len > cap {
            self.wire_buffered_reported = remainder_len;
            self.state = ReadyState::Open;
            self.handshake_completed = true;
            return Err(TypedProtocolFailure::protocol(
                FailureCode::BufferLimitExceeded,
            ));
        }
        self.pending = remainder;
        self.wire_buffered_reported = remainder_len;
        self.state = ReadyState::Open;
        self.handshake_completed = true;
        Ok(())
    }

    /// Transport EOF, mirroring derive.go `eof` (quirk Q20) inside the
    /// action accounting of derive.go `actionStep` — and, before the
    /// handshake ever completed, `WebSocketImpl.eot()` directly (US-016
    /// AC3 "EOF before open"; no corpus scenario reaches that arm).
    fn handle_eof(&mut self) -> Result<(), TypedProtocolFailure> {
        // Atomicity precheck: the eof detail event plus the transition.
        if self.events.available() < MAX_EVENT_SLOTS_PER_INPUT {
            return Err(Self::backpressure(QueueKind::Event));
        }
        if self.state == ReadyState::NotYetConnected {
            // WebSocketImpl.eot():608-610: NOT_YET_CONNECTED ->
            // closeConnection(CloseFrame.NEVER_CONNECTED, true) — the
            // two-arg overload (:569-571) supplies reason "", NEVER_CONNECTED
            // is the shipped -1 (framing/CloseFrame.java:140), and
            // closeConnection reports onWebsocketClose(-1, "", true) exactly
            // once before landing in the absorbing CLOSED state (:557,
            // :566). Like the handshake byte path, this pre-handshake arm
            // stays OUTSIDE the corpus action counters (the corpus `eof`
            // action vocabulary is post-handshake).
            let detail = CloseDetail {
                code: NEVER_CONNECTED_CLOSE_CODE,
                reason: String::new(),
                origin: CloseOrigin::Transport,
                remote: true,
                handshake_complete: false,
            };
            self.close_detail = Some(detail.clone());
            self.emit(SemanticEventKind::Eof(detail));
            self.transition(ReadyState::Closed, TransitionCause::Eof);
            return Ok(());
        }
        if self.handshake_completed {
            // derive.go actionStep: the counter increments before the limit
            // check, so a rejected action is included in the failure counts.
            self.action_count = self.action_count.saturating_add(1);
            if self.action_count > self.config.max_actions() {
                return Err(TypedProtocolFailure::protocol(
                    FailureCode::ActionLimitExceeded,
                ));
            }
            // derive.go eof: closed refuses.
            if self.state == ReadyState::Closed {
                return Err(Self::state_violation());
            }
        } else {
            // WebSocketImpl.eot() is transport-driven and never passes
            // through the action counters; the corpus `eof` action
            // vocabulary is post-handshake only (review 01a04556-87df).
            // On a never-connected CLOSED connection, closeConnection
            // dedupes (:531-533): nothing further happens in Java. The
            // port surfaces that absorption as its uniform typed
            // closed-state refusal (no counter, no events) — the pinned
            // no-duplicate-terminal discipline.
            if self.state == ReadyState::Closed {
                return Err(Self::state_violation());
            }
        }
        // Q20 vocabulary: open (or closing without a governing close) uses
        // 1006 with the pinned reason; closing with a governing close echoes
        // its code/reason; `remote` records whether the state was closing;
        // `handshake_complete` echoes the prior detail's flag (false when
        // none exists).
        let (code, reason) = match (&self.state, &self.close_detail) {
            (ReadyState::Closing, Some(detail)) => (detail.code, detail.reason.clone()),
            _ => (1006, EOF_DEFAULT_REASON.to_owned()),
        };
        let handshake_complete = self
            .close_detail
            .as_ref()
            .is_some_and(|detail| detail.handshake_complete);
        // Q20 (derive.go eof, corpus-pinned): `remote` records whether the
        // state was closing. That projection is calibrated for connections
        // whose handshake completed; a `Closing` reached from the
        // pre-handshake `close()` ladder instead follows
        // WebSocketImpl.eot()'s `flushandclosestate` arm (:611-612) —
        // closeConnection(closecode, closemessage, closedremotely) with the
        // RECORDED closedremotely, which the never-connected ladder set to
        // false (:501). The gate is inert for every corpus path
        // (`new_in_state` begins handshake-completed).
        let remote = if self.handshake_completed {
            self.state == ReadyState::Closing
        } else {
            self.close_detail
                .as_ref()
                .is_some_and(|detail| detail.remote)
        };
        let detail = CloseDetail {
            code,
            reason,
            origin: CloseOrigin::Transport,
            remote,
            handshake_complete,
        };
        self.close_detail = Some(detail.clone());
        self.emit(SemanticEventKind::Eof(detail));
        self.transition(ReadyState::Closed, TransitionCause::Eof);
        Ok(())
    }

    /// Command path: the contract gates of derive.go `actionStep`, then the
    /// per-action tails — outbound data sends (US-012/US-013),
    /// `send_fragment` (US-014), control sends (US-015), and `send_close`
    /// (US-016).
    fn handle_command(&mut self, command: &LocalCommand) -> Result<(), TypedProtocolFailure> {
        // Atomicity precheck before any mutation: the worst-case command is
        // send_close (frame record + cause + close_initiated + transition —
        // MAX_EVENT_SLOTS_PER_INPUT) and every send emits at most one
        // transport write. The pre-open arm needs at most two event slots
        // and no write; sharing the one conservative precheck keeps every
        // refusal retryable.
        if self.events.available() < MAX_EVENT_SLOTS_PER_INPUT {
            return Err(Self::backpressure(QueueKind::Event));
        }
        if self.writes.available() < 1 {
            return Err(Self::backpressure(QueueKind::Write));
        }
        if self.state == ReadyState::NotYetConnected {
            return self.handle_pre_open_command(command);
        }
        // Action accounting before the limit check (derive.go actionStep).
        self.action_count = self.action_count.saturating_add(1);
        if self.action_count > self.config.max_actions() {
            return Err(TypedProtocolFailure::protocol(
                FailureCode::ActionLimitExceeded,
            ));
        }
        // Quirk Q26 / derive.go requireOpen (:811-816): every send action
        // requires the open state.
        if self.state != ReadyState::Open {
            return Err(Self::state_violation());
        }
        // Send-path payload gate (derive.go requirePayloadLimit ->
        // BUFFER_LIMIT_EXCEEDED, checked BEFORE any encoding allocation).
        // Quirk Q17 asymmetry: ping/pong payloads are deliberately NOT
        // size-checked — ControlFrame.isValid checks only fin and reserved
        // bits, so the pinned runtime sends oversized control payloads
        // successfully.
        let payload_len = match command {
            LocalCommand::SendText { text } => Some(text.len()),
            LocalCommand::SendBinary { data } | LocalCommand::SendFragment { data, .. } => {
                Some(data.len())
            }
            LocalCommand::SendPing { .. }
            | LocalCommand::SendPong { .. }
            | LocalCommand::SendClose { .. } => None,
        };
        if let Some(len) = payload_len
            && len > self.config.max_buffered_bytes()
        {
            return Err(TypedProtocolFailure::protocol(
                FailureCode::BufferLimitExceeded,
            ));
        }
        // Per-action tails, each mirroring its derive.go actionStep arm.
        match command {
            // derive.go send_text: one fin text frame. The payload is
            // already valid UTF-8 by construction (Rust String), exactly as
            // Java's String-typed sendText input is.
            LocalCommand::SendText { text } => self.emit_outbound(
                OutboundCause::SendText,
                true,
                Opcode::Text,
                text.clone().into_bytes(),
            ),
            // derive.go send_binary: one fin binary frame.
            LocalCommand::SendBinary { data } => self.emit_outbound(
                OutboundCause::SendBinary,
                true,
                Opcode::Binary,
                data.clone(),
            ),
            // derive.go sendFragment / Draft.continuousFrame (written fresh
            // against the reference model — the borrowed chain has no
            // outbound fragment path): the FIRST frame of a text sequence
            // runs the translate-time DFA (Draft.continuousFrame builds a
            // TextFrame whose isValid applies the DFA; rejected content is
            // NotSendable -> IllegalArgumentException, reported as
            // JAVA_NOT_SENDABLE; truncated tails pass — derive.go:938-943),
            // AFTER the payload-limit gate above and BEFORE the sequence
            // state advances.
            LocalCommand::SendFragment { opcode, data, fin } => {
                let declared = match opcode {
                    DataOpcode::Text => Opcode::Text,
                    DataOpcode::Binary => Opcode::Binary,
                };
                if !self.draft.send_sequence_open()
                    && declared == Opcode::Text
                    && !Charsetfunctions::is_valid_utf8(data)
                {
                    return Err(TypedProtocolFailure::protocol(FailureCode::JavaNotSendable));
                }
                let wire_opcode = self.draft.continuous_send_opcode(declared, *fin)?;
                self.emit_outbound(OutboundCause::SendFragment, *fin, wire_opcode, data.clone())
            }
            // derive.go send_ping/send_pong (US-015): sendControl performs
            // NO payload-size check (Q17 — ControlFrame.isValid checks only
            // fin and reserved bits, so oversized control payloads send
            // successfully; the Codex encoder's >125 preflight rejection is
            // deliberately not adopted). One fin control frame.
            LocalCommand::SendPing { data } => {
                self.emit_outbound(OutboundCause::SendPing, true, Opcode::Ping, data.clone())
            }
            LocalCommand::SendPong { data } => {
                self.emit_outbound(OutboundCause::SendPong, true, Opcode::Pong, data.clone())
            }
            // The local close sequence (US-016).
            LocalCommand::SendClose { code, reason } => self.send_close(*code, reason),
        }
    }

    /// The local close tail (US-016), mirroring derive.go `sendClose`
    /// exactly: quirk Q14 normalization then the quirk Q13 validity chain —
    /// BOTH through the existing US-009 pure functions
    /// [`normalize_send_close_code`] and [`close_code_rejection`] (this
    /// method wires the lifecycle around them; it does not reimplement
    /// them) — then the big-endian code + reason frame, the
    /// `close_initiated` detail, and the `open -> closing` transition.
    fn send_close(&mut self, code: u16, reason: &str) -> Result<(), TypedProtocolFailure> {
        // Q14: CloseFrame.setCode maps 1015 -> 1005 BEFORE validation.
        let code = normalize_send_close_code(code);
        // Q13: the CloseFrame.isValid rejection chain; the reported close
        // code is the failure's, and NO frame is emitted (derive.go
        // sendClose rejects before emitOutbound).
        if let Some(reported) = close_code_rejection(code, reason) {
            // NO TRANSITION HERE, and that is a MEASURED result, not an
            // oversight. The owner ruled (protected/us012-us016-owner-decisions
            // -2026-08-28-formal.json, sha256 d7a54e2c…, decision
            // rejected-close-transition-divergence) that this site should
            // follow shipped WebSocketImpl.close():488-503 into CLOSING, with
            // an explicit escape clause if re-verification contradicted a
            // live-confirmed observable. It does. The pinned Java oracle's own
            // recorded run of us005.pub.0000 (send_close code 999) reports
            // final_state "open"; making this arm transition turns the public
            // corpus differential into 73/74 with the single failure
            // "us005.pub.0000: final_state closing, expected open". The reason
            // is that this command mirrors OracleEngine.sendClose:461-475,
            // which builds a CloseFrame and lets isValid's InvalidDataException
            // PROPAGATE, never calling WebSocketImpl.close() and so never
            // reaching its line 503. See the behavior-delta ledger record and
            // drafts/close-transition-receipt.json. Do not "fix" this arm
            // without re-reading that evidence.
            return Err(TypedProtocolFailure::java_invalid_data(reported));
        }
        let mut payload = Vec::with_capacity(2 + reason.len());
        payload.extend_from_slice(&code.to_be_bytes());
        payload.extend_from_slice(reason.as_bytes());
        self.emit_outbound(OutboundCause::SendClose, true, Opcode::Closing, payload)?;
        let detail = CloseDetail {
            code: i32::from(code),
            reason: reason.to_owned(),
            origin: CloseOrigin::Local,
            remote: false,
            handshake_complete: false,
        };
        self.close_detail = Some(detail.clone());
        self.emit(SemanticEventKind::CloseInitiated(detail));
        self.transition(ReadyState::Closing, TransitionCause::SendClose);
        Ok(())
    }

    /// Commands in the pre-handshake `NotYetConnected` state (US-016 AC3;
    /// no corpus scenario reaches this arm, so the shipped Java source is
    /// the direct authority). Like the handshake byte path, the arm stays
    /// OUTSIDE the corpus action counters.
    ///
    /// - Every send routes through `WebSocketImpl.send(Collection)`:667-670,
    ///   whose `!isOpen()` gate throws `WebsocketNotConnectedException`; the
    ///   oracle vocabulary projects that exception as `STATE_VIOLATION`
    ///   (the same projection the post-handshake requireOpen gate uses,
    ///   Q26), and the port's fatal-poison discipline applies uniformly.
    /// - `sendFragmentedFrame`:683-685 evaluates `draft.continuousFrame`
    ///   as the ARGUMENT of `send(...)`, so an invalid first text fragment
    ///   throws `IllegalArgumentException` from `isValid`
    ///   (Draft.java:210-239) BEFORE the isOpen gate — projected
    ///   `JAVA_NOT_SENDABLE`, exactly like the post-handshake first-fragment
    ///   DFA (derive.go:938-943).
    /// - `close(code, reason)`:463-506 outside OPEN/CLOSING/CLOSED runs the
    ///   never-connected flush ladder: PROTOCOL_ERROR (1002) keeps its code
    ///   (:498-500), everything else records `NEVER_CONNECTED` (:501; the
    ///   FLASHPOLICY -3 arm is inexpressible in the u16 command
    ///   vocabulary), reason preserved, `closedremotely=false`, then
    ///   `readyState = CLOSING` (:503). No CloseFrame is built — the Q13
    ///   validity chain and the Q14 setCode normalization live in the OPEN
    ///   branch only (:481-486) — so no wire frame is emitted.
    fn handle_pre_open_command(
        &mut self,
        command: &LocalCommand,
    ) -> Result<(), TypedProtocolFailure> {
        match command {
            LocalCommand::SendFragment {
                opcode,
                data,
                fin: _,
            } => {
                if *opcode == DataOpcode::Text && !Charsetfunctions::is_valid_utf8(data) {
                    return Err(TypedProtocolFailure::protocol(FailureCode::JavaNotSendable));
                }
                Err(Self::state_violation())
            }
            LocalCommand::SendText { .. }
            | LocalCommand::SendBinary { .. }
            | LocalCommand::SendPing { .. }
            | LocalCommand::SendPong { .. } => Err(Self::state_violation()),
            LocalCommand::SendClose { code, reason } => {
                let code = if *code == 1002 {
                    1002
                } else {
                    NEVER_CONNECTED_CLOSE_CODE
                };
                let detail = CloseDetail {
                    code,
                    reason: reason.clone(),
                    origin: CloseOrigin::Local,
                    remote: false,
                    handshake_complete: false,
                };
                self.close_detail = Some(detail.clone());
                self.emit(SemanticEventKind::CloseInitiated(detail));
                self.transition(ReadyState::Closing, TransitionCause::SendClose);
                Ok(())
            }
        }
    }
}

/// A refused command send: the bounded channel was full and the command
/// comes back to the producer intact (explicit backpressure, never silent
/// drop or unbounded growth).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandRefused {
    /// The command that was not enqueued.
    pub command: LocalCommand,
    /// Why the channel refused it.
    pub reason: CommandRefusalReason,
}

/// Why [`CommandSender::try_send`] handed a command back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandRefusalReason {
    /// The bounded queue is at capacity; retry after the owner drains.
    Full,
    /// Another producer momentarily holds the queue; retry immediately.
    /// Surfaced instead of waiting so `try_send` NEVER blocks (US-009 AC4).
    Contended,
}

#[derive(Debug)]
struct CommandChannel {
    queue: Mutex<VecDeque<LocalCommand>>,
    capacity: usize,
}

impl CommandChannel {
    fn lock(&self) -> std::sync::MutexGuard<'_, VecDeque<LocalCommand>> {
        // A poisoned lock only means another producer panicked mid-push;
        // the queue itself is always in a consistent state (push_back is the
        // only mutation), so recover the guard.
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Producer half of the bounded multi-producer command channel (US-009
/// AC4; US-017 delivers the driven-concurrency behavior). Clone one per
/// producer. `try_send` never blocks and never allocates past the fixed
/// capacity; Loom-style exploration of this type is classified as
/// systematic testing, not proof (US-006 AC5).
#[derive(Debug, Clone)]
pub struct CommandSender {
    channel: Arc<CommandChannel>,
}

impl CommandSender {
    /// Enqueue a command, or hand it back when the channel is full.
    ///
    /// # Errors
    ///
    /// [`CommandRefused`] carries the rejected command; the producer decides
    /// whether to retry after the owner drains.
    pub fn try_send(&self, command: LocalCommand) -> Result<(), CommandRefused> {
        // Review round 1 (session 01a04407): a blocking Mutex::lock here could
        // stall behind another producer, violating the try-send-only contract.
        // try_lock refuses with Contended instead of ever waiting; a poisoned
        // lock is recovered for the same reason as CommandChannel::lock.
        let mut queue = match self.channel.queue.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                return Err(CommandRefused {
                    command,
                    reason: CommandRefusalReason::Contended,
                });
            }
        };
        if queue.len() >= self.channel.capacity {
            return Err(CommandRefused {
                command,
                reason: CommandRefusalReason::Full,
            });
        }
        queue.push_back(command);
        Ok(())
    }
}

/// Owner half of the bounded command channel: the single connection owner
/// drains it into [`ConnectionCore::handle`]. FIFO total order (which
/// implies FIFO per producer); capacity is
/// [`ConnectionConfig::command_queue_capacity`], allocated once.
#[derive(Debug)]
pub struct CommandQueue {
    channel: Arc<CommandChannel>,
}

impl CommandQueue {
    /// Build the channel from the connection's configuration; returns the
    /// owner half and the first producer handle.
    #[must_use]
    pub fn new(config: &ConnectionConfig) -> (CommandQueue, CommandSender) {
        let capacity = config.command_queue_capacity();
        let channel = Arc::new(CommandChannel {
            queue: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
        });
        (
            CommandQueue {
                channel: Arc::clone(&channel),
            },
            CommandSender { channel },
        )
    }

    /// Dequeue the oldest pending command.
    pub fn pop(&mut self) -> Option<LocalCommand> {
        self.channel.lock().pop_front()
    }

    /// Number of commands currently queued.
    #[must_use]
    pub fn len(&self) -> usize {
        self.channel.lock().len()
    }

    /// Whether the channel is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The fixed capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.channel.capacity
    }
}

#[cfg(test)]
mod command_channel_tests {
    use super::*;
    use crate::config::ConnectionConfig;

    fn any_command() -> LocalCommand {
        LocalCommand::SendPing { data: Vec::new() }
    }

    /// Review round 1 (session 01a04407): try_send must NEVER block. With the
    /// queue mutex deliberately held by this thread (standing in for another
    /// producer mid-push), try_send must return immediately with a Contended
    /// refusal instead of waiting for the guard.
    #[test]
    fn try_send_refuses_with_contended_instead_of_blocking_on_a_held_lock() {
        let config = ConnectionConfig::default();
        let (_queue, sender) = CommandQueue::new(&config);
        let guard = sender.channel.queue.lock().expect("test holds the lock");
        let refused = sender
            .try_send(any_command())
            .expect_err("held lock must refuse, not block");
        assert_eq!(refused.reason, CommandRefusalReason::Contended);
        drop(guard);
        assert!(
            sender.try_send(any_command()).is_ok(),
            "after the lock is released the same send succeeds"
        );
    }
}
