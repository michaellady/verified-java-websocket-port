//! Semantic events, frame records, transitions, and counts (US-009 AC2).
//!
//! The oracle transcript carries four observation streams — `events`,
//! `frames`, `transitions`, and `counts` (plus the `close` detail). To keep
//! the story's "adapters cannot duplicate protocol state" promise, the core
//! emits all of them as typed values on one ordered event queue; the harness
//! only serializes: [`SemanticEventKind::event_type`] returning `Some` routes
//! to `events[]`, [`SemanticEventKind::FrameObserved`] to `frames[]`, and
//! [`SemanticEventKind::Transition`] to `transitions[]`. Vocabulary authority:
//! `internal/corpora/derive.go` and `schemas/corpus-scenario-1.0.0.schema.json`.

use crate::close::CloseDetail;
use crate::connection::ReadyState;
use crate::framing::Opcode;

/// One semantic event, tagged with the input step index that caused it (the
/// corpus `events[].{type, step}` contract; `step` is the zero-based index of
/// the accepted input, counting bytes and action inputs alike).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticEvent {
    /// Zero-based index of the input that caused this event.
    pub step: u64,
    /// What was observed.
    pub kind: SemanticEventKind,
}

/// Direction of an observed frame (`frames[].direction`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Frame received from the transport.
    Inbound,
    /// Frame emitted toward the transport.
    Outbound,
}

impl Direction {
    /// The corpus wire string.
    #[must_use]
    pub fn wire_name(&self) -> &'static str {
        match self {
            Direction::Inbound => "inbound",
            Direction::Outbound => "outbound",
        }
    }
}

/// The cause tag of an outbound frame event (derive.go `emitOutbound`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutboundCause {
    /// `send_text` action produced the frame.
    SendText,
    /// `send_binary` action produced the frame.
    SendBinary,
    /// `send_ping` action produced the frame.
    SendPing,
    /// `send_pong` action produced the frame.
    SendPong,
    /// `send_close` action produced the frame.
    SendClose,
    /// `send_fragment` action produced the frame.
    SendFragment,
    /// A remote close while open was echoed (quirk Q19; the echoed frame
    /// carries the constructor payload, quirk Q10).
    EchoClose,
}

impl OutboundCause {
    /// The corpus wire string.
    #[must_use]
    pub fn wire_name(&self) -> &'static str {
        match self {
            OutboundCause::SendText => "send_text",
            OutboundCause::SendBinary => "send_binary",
            OutboundCause::SendPing => "send_ping",
            OutboundCause::SendPong => "send_pong",
            OutboundCause::SendClose => "send_close",
            OutboundCause::SendFragment => "send_fragment",
            OutboundCause::EchoClose => "echo_close",
        }
    }
}

/// The cause of a state transition (`transitions[].cause`; derive.go
/// `transition` call sites).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransitionCause {
    /// A local `send_close` was accepted.
    SendClose,
    /// A remote close frame was processed.
    ReceiveClose,
    /// Transport EOF.
    Eof,
}

impl TransitionCause {
    /// The corpus wire string.
    #[must_use]
    pub fn wire_name(&self) -> &'static str {
        match self {
            TransitionCause::SendClose => "send_close",
            TransitionCause::ReceiveClose => "receive_close",
            TransitionCause::Eof => "eof",
        }
    }
}

/// One observed frame: the corpus `frames[]` record. Payloads are semantic
/// (unmasked) bytes; client mask keys are deliberately absent from every
/// observation (quirk Q28 — Java randomizes them and the transcript never
/// records them).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameRecord {
    /// Frame direction.
    pub direction: Direction,
    /// FIN bit.
    pub fin: bool,
    /// Whether the wire frame was masked.
    pub masked: bool,
    /// Frame opcode.
    pub opcode: Opcode,
    /// Semantic (unmasked) payload bytes.
    pub payload: Vec<u8>,
    /// RSV1 bit.
    pub rsv1: bool,
    /// RSV2 bit.
    pub rsv2: bool,
    /// RSV3 bit.
    pub rsv3: bool,
    /// Zero-based index of the input step that carried the frame.
    pub step: u64,
    /// Total wire size of the frame (header + mask + payload).
    pub wire_bytes: u64,
}

impl FrameRecord {
    /// Payload length in bytes (`frames[].payload_bytes`).
    #[must_use]
    pub fn payload_bytes(&self) -> u64 {
        self.payload.len() as u64
    }
}

/// What one semantic event observed. Variant payloads mirror the corpus
/// per-event fields exactly (derive.go `event` call sites).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticEventKind {
    /// `input_chunk` with `{bytes}` — one per surviving `TransportBytes`
    /// input, emitted only after the chunk passes limits and translation
    /// (derive.go:301, 359).
    InputChunk {
        /// The chunk's byte length.
        bytes: u64,
    },
    /// A delivered text message (`text` with `{text, utf8_bytes}`; US-013).
    Text {
        /// The decoded text.
        text: String,
    },
    /// A delivered binary message (`binary` with `{data, bytes}`; US-013).
    Binary {
        /// The message bytes.
        data: Vec<u8>,
    },
    /// An inbound ping observation (`ping`; NO automatic pong is emitted by
    /// the core — quirk Q18; auto-pong policy lives above the core, US-015).
    Ping {
        /// The ping payload.
        data: Vec<u8>,
    },
    /// An inbound pong observation (`pong`).
    Pong {
        /// The pong payload.
        data: Vec<u8>,
    },
    /// A remote close was observed (`close`).
    Close(CloseDetail),
    /// A local `send_close` was accepted (`close_initiated`).
    CloseInitiated(CloseDetail),
    /// Transport EOF was observed (`eof`, quirk Q20).
    Eof(CloseDetail),
    /// One outbound frame's cause event (`send_text` .. `echo_close`),
    /// carrying the opcode name (derive.go `emitOutbound`).
    OutboundCause {
        /// The causing action.
        cause: OutboundCause,
        /// The emitted frame's opcode.
        opcode: Opcode,
    },
    /// A frame record for the transcript `frames[]` stream (not an
    /// `events[]` entry).
    FrameObserved(FrameRecord),
    /// A state transition for the transcript `transitions[]` stream (not an
    /// `events[]` entry).
    Transition {
        /// State before.
        from: ReadyState,
        /// State after.
        to: ReadyState,
        /// Why.
        cause: TransitionCause,
    },
}

impl SemanticEventKind {
    /// The corpus `events[].type` string, or `None` for the kinds that
    /// project onto the `frames[]` / `transitions[]` streams instead.
    #[must_use]
    pub fn event_type(&self) -> Option<&'static str> {
        match self {
            SemanticEventKind::InputChunk { .. } => Some("input_chunk"),
            SemanticEventKind::Text { .. } => Some("text"),
            SemanticEventKind::Binary { .. } => Some("binary"),
            SemanticEventKind::Ping { .. } => Some("ping"),
            SemanticEventKind::Pong { .. } => Some("pong"),
            SemanticEventKind::Close(_) => Some("close"),
            SemanticEventKind::CloseInitiated(_) => Some("close_initiated"),
            SemanticEventKind::Eof(_) => Some("eof"),
            SemanticEventKind::OutboundCause { cause, .. } => Some(cause.wire_name()),
            SemanticEventKind::FrameObserved(_) | SemanticEventKind::Transition { .. } => None,
        }
    }
}

/// The corpus `counts` object, maintained by the core with checked
/// arithmetic and snapshot on demand. Invariant: `buffered_bytes` =
/// `wire_buffered_bytes + message_buffered_bytes` (derive.go `counts`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    /// Action steps observed (including a limit-rejected action, which is
    /// counted before the limit check — derive.go actionStep).
    pub actions: u64,
    /// `wire_buffered_bytes + message_buffered_bytes`.
    pub buffered_bytes: u64,
    /// Bytes consumed through translation (whole surviving chunks; the
    /// error-site offset on translate rejections, quirk Q25).
    pub consumed_bytes: u64,
    /// Frames observed (inbound and outbound).
    pub frames: u64,
    /// Transport bytes accepted within `max_input_bytes` (addBounded: never
    /// partially updated — derive.go:295-299).
    pub input_bytes: u64,
    /// Bytes held in message (fragment) reassembly.
    pub message_buffered_bytes: u64,
    /// Bytes held in the pending wire buffer.
    pub wire_buffered_bytes: u64,
}
