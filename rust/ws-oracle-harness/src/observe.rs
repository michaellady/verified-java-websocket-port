//! Typed observation vocabulary and its 1:1 transcript projection.
//!
//! These types mirror the US-009 ConnectionCore contract draft (§1.3): the
//! core emits typed observation streams; this module serializes them into
//! the exact `java-websocket-oracle` 1.0.0 transcript vocabulary defined by
//! `internal/corpora/derive.go` / `OracleEngine` and pinned by
//! `schemas/corpus-scenario-1.0.0.schema.json` (`events`, `frames`,
//! `transitions`, `close`, `counts`). The projection makes **no protocol
//! decisions**: every field is a mechanical rendering of a typed value.

use std::collections::BTreeMap;

use crate::base64;
use crate::json::Value;

/// Post-handshake connection state — the corpus `initial_state` /
/// `final_state` vocabulary (`open`, `closing`, `closed`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionState {
    /// Java `ReadyState.OPEN`.
    Open,
    /// Java `ReadyState.CLOSING`.
    Closing,
    /// Java `ReadyState.CLOSED` (absorbing).
    Closed,
}

impl ConnectionState {
    /// The exact transcript wire string.
    pub fn wire(self) -> &'static str {
        match self {
            ConnectionState::Open => "open",
            ConnectionState::Closing => "closing",
            ConnectionState::Closed => "closed",
        }
    }
}

/// Frame opcode names as the transcript records them (Java `Opcode` enum
/// lowercased — note `closing`, not `close`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opcode {
    /// Continuation frame.
    Continuous,
    /// Text frame.
    Text,
    /// Binary frame.
    Binary,
    /// Close frame (`closing` on the wire, mirroring Java's enum name).
    Closing,
    /// Ping frame.
    Ping,
    /// Pong frame.
    Pong,
}

impl Opcode {
    /// The exact transcript wire string.
    pub fn wire(self) -> &'static str {
        match self {
            Opcode::Continuous => "continuous",
            Opcode::Text => "text",
            Opcode::Binary => "binary",
            Opcode::Closing => "closing",
            Opcode::Ping => "ping",
            Opcode::Pong => "pong",
        }
    }
}

/// Frame direction relative to the connection under observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Bytes arriving from the peer.
    Inbound,
    /// Frames the connection sends.
    Outbound,
}

impl Direction {
    /// The exact transcript wire string.
    pub fn wire(self) -> &'static str {
        match self {
            Direction::Inbound => "inbound",
            Direction::Outbound => "outbound",
        }
    }
}

/// Close origin vocabulary (`remote` | `local` | `transport`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseOrigin {
    /// Peer-initiated close.
    Remote,
    /// Locally-initiated close.
    Local,
    /// Transport EOF.
    Transport,
}

impl CloseOrigin {
    /// The exact transcript wire string.
    pub fn wire(self) -> &'static str {
        match self {
            CloseOrigin::Remote => "remote",
            CloseOrigin::Local => "local",
            CloseOrigin::Transport => "transport",
        }
    }
}

/// Corpus `close` object: `{code, handshake_complete, origin, reason,
/// remote}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloseDetail {
    /// Close code (Java uses -1 for NEVER_CONNECTED, hence signed).
    pub code: i64,
    /// Close reason text.
    pub reason: String,
    /// Which side/layer originated the close.
    pub origin: CloseOrigin,
    /// Whether the close came from the peer.
    pub remote: bool,
    /// Whether the close handshake completed.
    pub handshake_complete: bool,
}

/// Outbound cause vocabulary — one event per outbound frame, named for the
/// action that produced it (`OracleEngine.emitOutbound` / derive.go).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutboundCause {
    /// `send_text` action.
    SendText,
    /// `send_binary` action.
    SendBinary,
    /// `send_ping` action.
    SendPing,
    /// `send_pong` action.
    SendPong,
    /// `send_close` action.
    SendClose,
    /// `send_fragment` action.
    SendFragment,
    /// Automatic close echo while OPEN (Java two-way close handshake).
    EchoClose,
}

impl OutboundCause {
    /// The exact transcript event-type string.
    pub fn wire(self) -> &'static str {
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

/// One semantic event, tagged with the input step index that caused it —
/// the corpus `events[].{type, step}` contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticEvent {
    /// Zero-based index of the request step that caused the event.
    pub step: u32,
    /// The typed event payload.
    pub kind: SemanticEventKind,
}

/// The typed event vocabulary (corpus `events[]` stream).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SemanticEventKind {
    /// `input_chunk` with `{bytes}` — one per surviving bytes step.
    InputChunk {
        /// Decoded chunk size in bytes.
        bytes: i64,
    },
    /// `text` with `{text, utf8_bytes}` — a delivered text message.
    Text {
        /// The decoded message text.
        text: String,
    },
    /// `binary` with `{data_base64, bytes}` — a delivered binary message.
    Binary {
        /// The message payload.
        data: Vec<u8>,
    },
    /// `ping` with `{data_base64, bytes}` — inbound ping observation.
    Ping {
        /// The control payload.
        data: Vec<u8>,
    },
    /// `pong` with `{data_base64, bytes}` — inbound pong observation.
    Pong {
        /// The control payload.
        data: Vec<u8>,
    },
    /// `close` — remote close observed.
    Close(CloseDetail),
    /// `close_initiated` — local `send_close` accepted.
    CloseInitiated(CloseDetail),
    /// `eof` — transport EOF close detail.
    Eof(CloseDetail),
    /// Outbound cause event carrying the opcode name.
    OutboundCause {
        /// Which action (or echo) produced the outbound frame.
        cause: OutboundCause,
        /// The outbound frame's opcode.
        opcode: Opcode,
    },
}

/// Corpus `frames[]` record. Client mask keys are deliberately absent
/// (quirk Q28): frames are observed semantically, with unmasked payloads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameRecord {
    /// Frame direction.
    pub direction: Direction,
    /// FIN flag.
    pub fin: bool,
    /// Whether the wire frame was masked.
    pub masked: bool,
    /// Frame opcode.
    pub opcode: Opcode,
    /// Semantic (unmasked) payload; `payload_bytes` is its length.
    pub payload: Vec<u8>,
    /// RSV1 flag.
    pub rsv1: bool,
    /// RSV2 flag.
    pub rsv2: bool,
    /// RSV3 flag.
    pub rsv3: bool,
    /// Zero-based index of the request step that carried/caused the frame.
    pub step: u32,
    /// Full wire size of the frame in bytes (header + mask + payload).
    pub wire_bytes: i64,
}

/// Transition cause vocabulary (`send_close`, `receive_close`, `eof`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionCause {
    /// Local close initiation.
    SendClose,
    /// Remote close frame.
    ReceiveClose,
    /// Transport EOF.
    Eof,
}

impl TransitionCause {
    /// The exact transcript wire string.
    pub fn wire(self) -> &'static str {
        match self {
            TransitionCause::SendClose => "send_close",
            TransitionCause::ReceiveClose => "receive_close",
            TransitionCause::Eof => "eof",
        }
    }
}

/// Corpus `transitions[]` record: `{cause, from, step, to}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transition {
    /// State before the transition.
    pub from: ConnectionState,
    /// State after the transition.
    pub to: ConnectionState,
    /// What caused the transition.
    pub cause: TransitionCause,
    /// Zero-based index of the request step that caused the transition.
    pub step: u32,
}

/// Corpus `counts` object (7 exact counters).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// Local actions attempted (including a rejected final action).
    pub actions: i64,
    /// `wire_buffered_bytes + message_buffered_bytes`.
    pub buffered_bytes: i64,
    /// Input bytes consumed by frame translation.
    pub consumed_bytes: i64,
    /// Frames recorded (inbound + outbound).
    pub frames: i64,
    /// Decoded input bytes accepted within `max_input_bytes`.
    pub input_bytes: i64,
    /// Fragment-reassembly buffer occupancy.
    pub message_buffered_bytes: i64,
    /// Incomplete-wire-frame buffer occupancy.
    pub wire_buffered_bytes: i64,
}

/// The complete observation surface of one executed scenario.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Observations {
    /// The `events[]` stream, in observation order.
    pub events: Vec<SemanticEvent>,
    /// The `frames[]` stream, in observation order.
    pub frames: Vec<FrameRecord>,
    /// The `transitions[]` stream, in observation order.
    pub transitions: Vec<Transition>,
    /// The final close detail, if any close was observed.
    pub close: Option<CloseDetail>,
    /// The final counters snapshot.
    pub counts: CountsWithState,
}

/// Final counters plus final state, kept together so a partial-execution
/// failure retains both (the oracle's "Partial execution errors retain
/// counts and final state" contract).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CountsWithState {
    /// The final counters snapshot.
    pub counts: Counts,
    /// The final connection state.
    pub final_state: ConnectionState,
}

impl Default for CountsWithState {
    fn default() -> Self {
        CountsWithState {
            counts: Counts::default(),
            final_state: ConnectionState::Open,
        }
    }
}

fn obj(pairs: Vec<(&str, Value)>) -> Value {
    let mut members = BTreeMap::new();
    for (key, value) in pairs {
        members.insert(key.to_string(), value);
    }
    Value::Obj(members)
}

/// Projects one close detail onto the transcript `close` object.
pub fn close_value(detail: &CloseDetail) -> Value {
    obj(vec![
        ("code", Value::Int(detail.code)),
        ("handshake_complete", Value::Bool(detail.handshake_complete)),
        ("origin", Value::Str(detail.origin.wire().to_string())),
        ("reason", Value::Str(detail.reason.clone())),
        ("remote", Value::Bool(detail.remote)),
    ])
}

/// Projects one semantic event onto the transcript `events[]` object,
/// mirroring `derive.go`'s `event()` (detail fields + `step` + `type`).
pub fn event_value(event: &SemanticEvent) -> Value {
    let step = Value::Int(i64::from(event.step));
    let (event_type, mut fields): (&str, Vec<(&str, Value)>) = match &event.kind {
        SemanticEventKind::InputChunk { bytes } => {
            ("input_chunk", vec![("bytes", Value::Int(*bytes))])
        }
        SemanticEventKind::Text { text } => (
            "text",
            vec![
                ("text", Value::Str(text.clone())),
                ("utf8_bytes", Value::Int(text.len() as i64)),
            ],
        ),
        SemanticEventKind::Binary { data } => (
            "binary",
            vec![
                ("bytes", Value::Int(data.len() as i64)),
                ("data_base64", Value::Str(base64::encode(data))),
            ],
        ),
        SemanticEventKind::Ping { data } => (
            "ping",
            vec![
                ("bytes", Value::Int(data.len() as i64)),
                ("data_base64", Value::Str(base64::encode(data))),
            ],
        ),
        SemanticEventKind::Pong { data } => (
            "pong",
            vec![
                ("bytes", Value::Int(data.len() as i64)),
                ("data_base64", Value::Str(base64::encode(data))),
            ],
        ),
        SemanticEventKind::Close(detail) => ("close", close_detail_fields(detail)),
        SemanticEventKind::CloseInitiated(detail) => {
            ("close_initiated", close_detail_fields(detail))
        }
        SemanticEventKind::Eof(detail) => ("eof", close_detail_fields(detail)),
        SemanticEventKind::OutboundCause { cause, opcode } => (
            cause.wire(),
            vec![("opcode", Value::Str(opcode.wire().to_string()))],
        ),
    };
    fields.push(("step", step));
    fields.push(("type", Value::Str(event_type.to_string())));
    obj(fields)
}

fn close_detail_fields(detail: &CloseDetail) -> Vec<(&'static str, Value)> {
    vec![
        ("code", Value::Int(detail.code)),
        ("handshake_complete", Value::Bool(detail.handshake_complete)),
        ("origin", Value::Str(detail.origin.wire().to_string())),
        ("reason", Value::Str(detail.reason.clone())),
        ("remote", Value::Bool(detail.remote)),
    ]
}

/// Projects one frame record onto the transcript `frames[]` object.
pub fn frame_value(frame: &FrameRecord) -> Value {
    obj(vec![
        ("direction", Value::Str(frame.direction.wire().to_string())),
        ("fin", Value::Bool(frame.fin)),
        ("masked", Value::Bool(frame.masked)),
        ("opcode", Value::Str(frame.opcode.wire().to_string())),
        ("payload_base64", Value::Str(base64::encode(&frame.payload))),
        ("payload_bytes", Value::Int(frame.payload.len() as i64)),
        ("rsv1", Value::Bool(frame.rsv1)),
        ("rsv2", Value::Bool(frame.rsv2)),
        ("rsv3", Value::Bool(frame.rsv3)),
        ("step", Value::Int(i64::from(frame.step))),
        ("wire_bytes", Value::Int(frame.wire_bytes)),
    ])
}

/// Projects one transition onto the transcript `transitions[]` object.
pub fn transition_value(transition: &Transition) -> Value {
    obj(vec![
        ("cause", Value::Str(transition.cause.wire().to_string())),
        ("from", Value::Str(transition.from.wire().to_string())),
        ("step", Value::Int(i64::from(transition.step))),
        ("to", Value::Str(transition.to.wire().to_string())),
    ])
}

/// Projects the counters onto the transcript `counts` object.
pub fn counts_value(counts: &Counts) -> Value {
    obj(vec![
        ("actions", Value::Int(counts.actions)),
        ("buffered_bytes", Value::Int(counts.buffered_bytes)),
        ("consumed_bytes", Value::Int(counts.consumed_bytes)),
        ("frames", Value::Int(counts.frames)),
        ("input_bytes", Value::Int(counts.input_bytes)),
        (
            "message_buffered_bytes",
            Value::Int(counts.message_buffered_bytes),
        ),
        (
            "wire_buffered_bytes",
            Value::Int(counts.wire_buffered_bytes),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden test against the committed public corpus: the expected
    /// transcript fragments of `us005.pub.0001` (fragmented-binary), copied
    /// byte-for-byte from `corpora/public/scenarios.jsonl`.
    #[test]
    fn events_project_to_us005_pub_0001_golden() {
        let payload = base64::decode_canonical("qDYKU6FxopAajSnjYg==").unwrap();
        let events = [
            SemanticEvent {
                step: 0,
                kind: SemanticEventKind::InputChunk { bytes: 7 },
            },
            SemanticEvent {
                step: 1,
                kind: SemanticEventKind::InputChunk { bytes: 18 },
            },
            SemanticEvent {
                step: 1,
                kind: SemanticEventKind::Binary { data: payload },
            },
        ];
        let rendered: Vec<String> = events.iter().map(|e| event_value(e).canonical()).collect();
        assert_eq!(
            rendered[0],
            "{\"bytes\":7,\"step\":0,\"type\":\"input_chunk\"}"
        );
        assert_eq!(
            rendered[1],
            "{\"bytes\":18,\"step\":1,\"type\":\"input_chunk\"}"
        );
        assert_eq!(
            rendered[2],
            "{\"bytes\":13,\"data_base64\":\"qDYKU6FxopAajSnjYg==\",\"step\":1,\"type\":\"binary\"}"
        );
    }

    #[test]
    fn frames_project_to_us005_pub_0001_golden() {
        let first = FrameRecord {
            direction: Direction::Inbound,
            fin: false,
            masked: true,
            opcode: Opcode::Binary,
            payload: base64::decode_canonical("qA==").unwrap(),
            rsv1: false,
            rsv2: false,
            rsv3: false,
            step: 0,
            wire_bytes: 7,
        };
        let second = FrameRecord {
            direction: Direction::Inbound,
            fin: true,
            masked: true,
            opcode: Opcode::Continuous,
            payload: base64::decode_canonical("NgpToXGikBqNKeNi").unwrap(),
            rsv1: false,
            rsv2: false,
            rsv3: false,
            step: 1,
            wire_bytes: 18,
        };
        assert_eq!(
            frame_value(&first).canonical(),
            "{\"direction\":\"inbound\",\"fin\":false,\"masked\":true,\
             \"opcode\":\"binary\",\"payload_base64\":\"qA==\",\"payload_bytes\":1,\
             \"rsv1\":false,\"rsv2\":false,\"rsv3\":false,\"step\":0,\"wire_bytes\":7}"
        );
        assert_eq!(
            frame_value(&second).canonical(),
            "{\"direction\":\"inbound\",\"fin\":true,\"masked\":true,\
             \"opcode\":\"continuous\",\"payload_base64\":\"NgpToXGikBqNKeNi\",\
             \"payload_bytes\":12,\"rsv1\":false,\"rsv2\":false,\"rsv3\":false,\
             \"step\":1,\"wire_bytes\":18}"
        );
    }

    #[test]
    fn transition_close_and_counts_projections_are_exact() {
        let transition = Transition {
            from: ConnectionState::Open,
            to: ConnectionState::Closing,
            cause: TransitionCause::SendClose,
            step: 2,
        };
        assert_eq!(
            transition_value(&transition).canonical(),
            "{\"cause\":\"send_close\",\"from\":\"open\",\"step\":2,\"to\":\"closing\"}"
        );
        let close = CloseDetail {
            code: 1000,
            reason: "done".to_string(),
            origin: CloseOrigin::Remote,
            remote: true,
            handshake_complete: true,
        };
        assert_eq!(
            close_value(&close).canonical(),
            "{\"code\":1000,\"handshake_complete\":true,\"origin\":\"remote\",\
             \"reason\":\"done\",\"remote\":true}"
        );
        let counts = Counts {
            actions: 1,
            ..Counts::default()
        };
        assert_eq!(
            counts_value(&counts).canonical(),
            "{\"actions\":1,\"buffered_bytes\":0,\"consumed_bytes\":0,\"frames\":0,\
             \"input_bytes\":0,\"message_buffered_bytes\":0,\"wire_buffered_bytes\":0}"
        );
    }

    #[test]
    fn event_vocabulary_covers_all_cause_and_control_shapes() {
        let ping = SemanticEvent {
            step: 3,
            kind: SemanticEventKind::Ping { data: vec![1, 2] },
        };
        assert_eq!(
            event_value(&ping).canonical(),
            "{\"bytes\":2,\"data_base64\":\"AQI=\",\"step\":3,\"type\":\"ping\"}"
        );
        let text = SemanticEvent {
            step: 0,
            kind: SemanticEventKind::Text {
                text: "hé".to_string(),
            },
        };
        assert_eq!(
            event_value(&text).canonical(),
            "{\"step\":0,\"text\":\"hé\",\"type\":\"text\",\"utf8_bytes\":3}"
        );
        let cause = SemanticEvent {
            step: 5,
            kind: SemanticEventKind::OutboundCause {
                cause: OutboundCause::EchoClose,
                opcode: Opcode::Closing,
            },
        };
        assert_eq!(
            event_value(&cause).canonical(),
            "{\"opcode\":\"closing\",\"step\":5,\"type\":\"echo_close\"}"
        );
    }
}
