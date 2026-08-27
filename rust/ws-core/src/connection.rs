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
//! ## Scope of this story (US-009)
//!
//! This is the *contract*: types, limits, ownership, determinism,
//! backpressure, counters, and poisoning. The state machine is deliberately
//! skeletal — the byte path buffers (bounded) without decoding frames, the
//! send commands run their contract gates and then refuse with the honest
//! non-oracle [`crate::error::FailureCode::Unimplemented`] code, and only the
//! EOF transition (quirk Q20, fully pinned by the reference model) is
//! encoded. Handshake behavior is US-010/US-011, framing US-012, messages
//! US-013, fragmentation US-014, control US-015, and the close sequence
//! US-016; per AC4, "handshake or frame behavior cannot be marked complete by
//! this story", and a corpus evaluation of this skeleton must fail (the
//! protocol-stub gate).
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

use crate::close::{CloseDetail, CloseOrigin};
use crate::config::ConnectionConfig;
use crate::error::{FailureCode, QueueKind, TypedProtocolFailure};
use crate::event::{Counts, SemanticEvent, SemanticEventKind, TransitionCause};
use crate::framing::{Draft6455, HeaderDecode};
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

/// The largest number of event-queue slots one input can require in this
/// skeleton (transport EOF: the `eof` detail event plus the transition
/// record). The per-input capacity precheck uses this bound to keep input
/// handling atomic — an input either fully processes or is refused with
/// [`FailureCode::Backpressure`] before any mutation. The
/// `event_queue_capacity` minimum (4) covers it with headroom; stories that
/// raise the per-input worst case (US-012+ frame decoding) must revisit both.
pub const MAX_EVENT_SLOTS_PER_INPUT: usize = 2;

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
    /// Message (fragment) reassembly accounting; always 0 until US-014.
    message_buffered: u64,
    input_bytes: u64,
    consumed_bytes: u64,
    action_count: u64,
    frame_count: u64,
    close_detail: Option<CloseDetail>,
    events: BoundedQueue<SemanticEvent>,
    writes: BoundedQueue<TransportWrite>,
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

    /// Byte path, mirroring derive.go `inputStep` with the US-012 decode
    /// loop stubbed to "consume nothing".
    fn handle_bytes(&mut self, chunk: &[u8]) -> Result<(), TypedProtocolFailure> {
        // Atomicity precheck: a surviving chunk emits exactly one
        // input_chunk event in this skeleton.
        if self.events.available() < 1 {
            return Err(Self::backpressure(QueueKind::Event));
        }
        // The handshake plane (buffering, limits, verdicts) is US-010/US-011
        // behavior; the skeleton refuses it honestly.
        if self.state == ReadyState::NotYetConnected {
            return Err(TypedProtocolFailure::protocol(FailureCode::Unimplemented));
        }
        // Quirk Q26 / derive.go:292-294: closed + nonzero payload is a state
        // violation; an empty chunk is still recorded.
        if self.state == ReadyState::Closed && !chunk.is_empty() {
            return Err(Self::state_violation());
        }
        // addBounded input limit (derive.go:295-299): the counter updates
        // only when within bounds. A u64 overflow certainly exceeds every
        // permitted limit, so checked arithmetic maps it to the same
        // failure.
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
        self.input_bytes = new_input_total;
        if chunk.is_empty() {
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
        // Translate seam. US-012 replaces this with the real scan/decode
        // loop (complete frames consumed BEFORE the leftover cap check, with
        // Q25 error-site consumption and Q21/Q17 validity ordering). The
        // skeleton decoder always answers Insufficient, so nothing is
        // consumed and no frame behavior can be claimed.
        match Draft6455::decode_frame_header(
            &combined,
            self.config.max_frame_payload_bytes() as u64,
        )? {
            HeaderDecode::Insufficient => {}
            HeaderDecode::Header(_) => {
                // Unreachable until US-012 rewrites this path; refusing (and
                // poisoning) is safer than silently dropping a frame.
                return Err(TypedProtocolFailure::protocol(FailureCode::Unimplemented));
            }
        }
        let leftover_len = combined.len() as u64;
        // Quirk Q24 (derive.go:313-319): the leftover cap is
        // max_buffered_bytes + 14, the overflow ends the scenario before any
        // translation, and consumed stays 0 for this chunk. Java (and the
        // reference model) retain the oversized buffer before checking; the
        // port checks before retaining — a JAVA_FAITHFUL_PLUS_SAFE
        // strengthening with identical observables (the failure counts
        // still report the oversized leftover length, as the oracle does).
        let cap =
            (self.config.max_buffered_bytes() as u64).saturating_add(WIRE_PENDING_SLACK_BYTES);
        if leftover_len > cap {
            self.wire_buffered_reported = leftover_len;
            self.pending = Vec::new();
            return Err(TypedProtocolFailure::protocol(
                FailureCode::BufferLimitExceeded,
            ));
        }
        self.pending = combined;
        self.wire_buffered_reported = self.pending.len() as u64;
        // derive.go: the whole surviving chunk counts as consumed through
        // translation, then the input_chunk event is recorded.
        self.consumed_bytes = self.consumed_bytes.saturating_add(chunk_len);
        self.emit(SemanticEventKind::InputChunk { bytes: chunk_len });
        Ok(())
    }

    /// Transport EOF, mirroring derive.go `eof` (quirk Q20) inside the
    /// action accounting of derive.go `actionStep`.
    fn handle_eof(&mut self) -> Result<(), TypedProtocolFailure> {
        // Atomicity precheck: the eof detail event plus the transition.
        if self.events.available() < MAX_EVENT_SLOTS_PER_INPUT {
            return Err(Self::backpressure(QueueKind::Event));
        }
        if self.state == ReadyState::NotYetConnected {
            // Java's eot() NOT_YET_CONNECTED ladder (WebSocketImpl.java:
            // 608-610, close code -1 NEVER_CONNECTED) belongs to the
            // handshake/close stories; never observable in the corpus.
            return Err(TypedProtocolFailure::protocol(FailureCode::Unimplemented));
        }
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
        let detail = CloseDetail {
            code,
            reason,
            origin: CloseOrigin::Transport,
            remote: self.state == ReadyState::Closing,
            handshake_complete,
        };
        self.close_detail = Some(detail.clone());
        self.emit(SemanticEventKind::Eof(detail));
        self.transition(ReadyState::Closed, TransitionCause::Eof);
        Ok(())
    }

    /// Command path: the contract gates of derive.go `actionStep`, then the
    /// honest skeleton refusal (outbound behavior is US-012..US-016).
    fn handle_command(&mut self, command: &LocalCommand) -> Result<(), TypedProtocolFailure> {
        if self.state == ReadyState::NotYetConnected {
            return Err(TypedProtocolFailure::protocol(FailureCode::Unimplemented));
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
        // Everything past the gates is later-story behavior: outbound
        // framing and masking (US-012), the send-path DFA quirk Q16
        // (US-013), fragment sequencing (US-014), control frames (US-015),
        // and the close sequence with quirks Q13/Q14 via
        // crate::close::{normalize_send_close_code, close_code_rejection}
        // (US-016). The skeleton refuses honestly so the protocol-stub gate
        // fails the corpus.
        Err(TypedProtocolFailure::protocol(FailureCode::Unimplemented))
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
