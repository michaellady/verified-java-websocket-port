//! US-009 AC2 contract-type tests: the typed vocabulary of the Sans-I/O core.
//!
//! Every observable name asserted here is pinned to the java-oracle transcript
//! vocabulary (`java-oracle/README.md` protocol 1.0.0, `internal/corpora/
//! derive.go`, `schemas/corpus-scenario-1.0.0.schema.json`) so the harness
//! crate can serialize the core's typed outputs with zero protocol decisions
//! of its own.

use ws_core::close::{CloseDetail, CloseOrigin, close_code_rejection, normalize_send_close_code};
use ws_core::config::ConnectionConfig;
use ws_core::connection::{
    ConnectionCore, ConnectionState, InitialState, ReadyState, Role, WebSocketImpl,
};
use ws_core::error::{FailureCode, QueueKind, TypedProtocolFailure};
use ws_core::event::{Direction, OutboundCause, SemanticEventKind, TransitionCause};
use ws_core::framing::{Draft6455, HeaderDecode, Opcode};

// ---------------------------------------------------------------------------
// Corpus vocabulary projections
// ---------------------------------------------------------------------------

#[test]
fn role_wire_names_match_corpus_role_vocabulary() {
    assert_eq!(Role::Client.wire_name(), "client");
    assert_eq!(Role::Server.wire_name(), "server");
}

#[test]
fn ready_state_projects_onto_corpus_state_vocabulary() {
    // ReadyState mirrors org.java_websocket.enums.ReadyState; the corpus
    // {open, closing, closed} vocabulary is its post-handshake projection.
    assert_eq!(ReadyState::NotYetConnected.corpus_state(), None);
    assert_eq!(ReadyState::Open.corpus_state(), Some("open"));
    assert_eq!(ReadyState::Closing.corpus_state(), Some("closing"));
    assert_eq!(ReadyState::Closed.corpus_state(), Some("closed"));
}

#[test]
fn connection_state_alias_is_ready_state() {
    // AC2 speaks of "ConnectionState"; the migration map's planned identity
    // is ws_core::connection::ReadyState. Both names must denote one type.
    let s: ConnectionState = ReadyState::Open;
    assert_eq!(s, ReadyState::Open);
}

#[test]
fn websocket_impl_alias_is_connection_core() {
    // proof-targets sym.concurrency.connection-owner plans
    // ws_core::connection::WebSocketImpl as the single mutable owner.
    let core: WebSocketImpl = ConnectionCore::new_in_state(
        ConnectionConfig::default(),
        Role::Server,
        InitialState::Open,
    );
    assert_eq!(core.state(), ReadyState::Open);
}

#[test]
fn opcode_wire_names_match_corpus_frame_opcodes() {
    // schemas/corpus-scenario-1.0.0.schema.json frames[].opcode enum. The
    // "closing" name is Java's Opcode.CLOSING, mirrored deliberately.
    assert_eq!(Opcode::Continuous.wire_name(), "continuous");
    assert_eq!(Opcode::Text.wire_name(), "text");
    assert_eq!(Opcode::Binary.wire_name(), "binary");
    assert_eq!(Opcode::Closing.wire_name(), "closing");
    assert_eq!(Opcode::Ping.wire_name(), "ping");
    assert_eq!(Opcode::Pong.wire_name(), "pong");
}

#[test]
fn failure_codes_carry_exact_oracle_wire_strings() {
    // java-oracle/README.md stable error vocabulary; derive.go protocolError
    // call sites.
    assert_eq!(
        FailureCode::JavaInvalidData.wire_code(),
        Some("JAVA_INVALID_DATA")
    );
    assert_eq!(
        FailureCode::JavaRuntimeRejection.wire_code(),
        Some("JAVA_RUNTIME_REJECTION")
    );
    assert_eq!(
        FailureCode::JavaNotSendable.wire_code(),
        Some("JAVA_NOT_SENDABLE")
    );
    assert_eq!(
        FailureCode::StateViolation.wire_code(),
        Some("STATE_VIOLATION")
    );
    assert_eq!(
        FailureCode::InputLimitExceeded.wire_code(),
        Some("INPUT_LIMIT_EXCEEDED")
    );
    assert_eq!(
        FailureCode::BufferLimitExceeded.wire_code(),
        Some("BUFFER_LIMIT_EXCEEDED")
    );
    assert_eq!(
        FailureCode::ActionLimitExceeded.wire_code(),
        Some("ACTION_LIMIT_EXCEEDED")
    );
    assert_eq!(
        FailureCode::FrameLimitExceeded.wire_code(),
        Some("FRAME_LIMIT_EXCEEDED")
    );
    assert_eq!(
        FailureCode::OutputLimitExceeded.wire_code(),
        Some("OUTPUT_LIMIT_EXCEEDED")
    );
    // Backpressure is a port-side contract output (US-009 AC4), never an
    // oracle transcript code; Unimplemented is the US-009 skeleton's honest
    // refusal, removed as US-010..US-016 land. Neither may leak a wire code.
    assert_eq!(
        FailureCode::Backpressure(QueueKind::Event).wire_code(),
        None
    );
    assert_eq!(FailureCode::Unimplemented.wire_code(), None);
}

#[test]
fn only_backpressure_is_non_fatal() {
    assert!(!FailureCode::Backpressure(QueueKind::Event).is_fatal());
    assert!(!FailureCode::Backpressure(QueueKind::Write).is_fatal());
    assert!(!FailureCode::Backpressure(QueueKind::Command).is_fatal());
    for fatal in [
        FailureCode::JavaInvalidData,
        FailureCode::JavaRuntimeRejection,
        FailureCode::JavaNotSendable,
        FailureCode::StateViolation,
        FailureCode::InputLimitExceeded,
        FailureCode::BufferLimitExceeded,
        FailureCode::ActionLimitExceeded,
        FailureCode::FrameLimitExceeded,
        FailureCode::OutputLimitExceeded,
        FailureCode::Unimplemented,
    ] {
        assert!(fatal.is_fatal(), "{fatal:?} must be fatal");
    }
}

#[test]
fn typed_protocol_failure_close_code_present_exactly_when_oracle_reports_one() {
    let with_close = TypedProtocolFailure::java_invalid_data(1002);
    assert_eq!(with_close.code, FailureCode::JavaInvalidData);
    assert_eq!(with_close.close_code, Some(1002));
    let plain = TypedProtocolFailure::protocol(FailureCode::StateViolation);
    assert_eq!(plain.close_code, None);
}

#[test]
fn event_kinds_project_onto_corpus_event_types() {
    // derive.go event() call sites: the events[] stream vocabulary.
    assert_eq!(
        SemanticEventKind::InputChunk { bytes: 3 }.event_type(),
        Some("input_chunk")
    );
    assert_eq!(
        SemanticEventKind::Text {
            text: String::new()
        }
        .event_type(),
        Some("text")
    );
    assert_eq!(
        SemanticEventKind::Binary { data: Vec::new() }.event_type(),
        Some("binary")
    );
    assert_eq!(
        SemanticEventKind::Ping { data: Vec::new() }.event_type(),
        Some("ping")
    );
    assert_eq!(
        SemanticEventKind::Pong { data: Vec::new() }.event_type(),
        Some("pong")
    );
    let detail = CloseDetail {
        code: 1000,
        reason: String::new(),
        origin: CloseOrigin::Remote,
        remote: true,
        handshake_complete: true,
    };
    assert_eq!(
        SemanticEventKind::Close(detail.clone()).event_type(),
        Some("close")
    );
    assert_eq!(
        SemanticEventKind::CloseInitiated(detail.clone()).event_type(),
        Some("close_initiated")
    );
    assert_eq!(SemanticEventKind::Eof(detail).event_type(), Some("eof"));
    // Outbound cause events carry the causing action's name.
    assert_eq!(
        SemanticEventKind::OutboundCause {
            cause: OutboundCause::SendText,
            opcode: Opcode::Text
        }
        .event_type(),
        Some("send_text")
    );
}

#[test]
fn frame_and_transition_streams_are_not_events_stream_entries() {
    // FrameObserved projects onto the transcript frames[] stream and
    // Transition onto transitions[]; neither belongs to events[].
    assert_eq!(
        SemanticEventKind::Transition {
            from: ReadyState::Open,
            to: ReadyState::Closing,
            cause: TransitionCause::ReceiveClose,
        }
        .event_type(),
        None
    );
}

#[test]
fn outbound_cause_wire_names_match_derive_emit_outbound() {
    assert_eq!(OutboundCause::SendText.wire_name(), "send_text");
    assert_eq!(OutboundCause::SendBinary.wire_name(), "send_binary");
    assert_eq!(OutboundCause::SendPing.wire_name(), "send_ping");
    assert_eq!(OutboundCause::SendPong.wire_name(), "send_pong");
    assert_eq!(OutboundCause::SendClose.wire_name(), "send_close");
    assert_eq!(OutboundCause::SendFragment.wire_name(), "send_fragment");
    assert_eq!(OutboundCause::EchoClose.wire_name(), "echo_close");
}

#[test]
fn transition_causes_match_corpus_transition_vocabulary() {
    assert_eq!(TransitionCause::SendClose.wire_name(), "send_close");
    assert_eq!(TransitionCause::ReceiveClose.wire_name(), "receive_close");
    assert_eq!(TransitionCause::Eof.wire_name(), "eof");
}

#[test]
fn direction_and_close_origin_match_corpus_vocabulary() {
    assert_eq!(Direction::Inbound.wire_name(), "inbound");
    assert_eq!(Direction::Outbound.wire_name(), "outbound");
    assert_eq!(CloseOrigin::Remote.wire_name(), "remote");
    assert_eq!(CloseOrigin::Local.wire_name(), "local");
    assert_eq!(CloseOrigin::Transport.wire_name(), "transport");
}

// ---------------------------------------------------------------------------
// Close-code model (pure, US-016 wires it into the state machine)
// ---------------------------------------------------------------------------

#[test]
fn send_close_1015_silently_normalizes_to_1005() {
    // Quirk Q14: CloseFrame.setCode maps TLS_ERROR 1015 to NOCODE 1005
    // before validation (derive.go:888-893).
    assert_eq!(normalize_send_close_code(1015), 1005);
    assert_eq!(normalize_send_close_code(1000), 1000);
    assert_eq!(normalize_send_close_code(1005), 1005);
}

#[test]
fn close_code_rejection_chain_mirrors_close_frame_is_valid() {
    // Quirk Q13, derive.go closeIsValidRejection (mirroring
    // CloseFrame.isValid), in Java's exact order:
    // 1007 with empty reason -> 1007.
    assert_eq!(close_code_rejection(1007, ""), Some(1007));
    assert_eq!(close_code_rejection(1007, "x"), None);
    // 1005 with a reason -> 1002.
    assert_eq!(close_code_rejection(1005, "x"), Some(1002));
    // 1016..=2999 -> 1002.
    assert_eq!(close_code_rejection(1016, ""), Some(1002));
    assert_eq!(close_code_rejection(2999, "r"), Some(1002));
    // Reserved singletons and out-of-range codes -> 1002.
    assert_eq!(close_code_rejection(1006, ""), Some(1002));
    assert_eq!(close_code_rejection(1015, ""), Some(1002));
    assert_eq!(close_code_rejection(1005, ""), Some(1002));
    assert_eq!(close_code_rejection(1004, ""), Some(1002));
    assert_eq!(close_code_rejection(999, ""), Some(1002));
    assert_eq!(close_code_rejection(0, ""), Some(1002));
    assert_eq!(close_code_rejection(5000, ""), Some(1002));
    // Accepted codes.
    assert_eq!(close_code_rejection(1000, ""), None);
    assert_eq!(close_code_rejection(1002, "why"), None);
    assert_eq!(close_code_rejection(1011, ""), None);
    assert_eq!(close_code_rejection(3000, ""), None);
    assert_eq!(close_code_rejection(4999, ""), None);
}

// ---------------------------------------------------------------------------
// Framing seam: the two US-006-named proof-target symbols
// ---------------------------------------------------------------------------

#[test]
fn apply_mask_is_an_involution() {
    // proof-targets sym.framing.apply-mask (property.framing.mask-involution):
    // XOR masking applied twice with the same key is the identity
    // (Draft_6455.java:511-517 encode, 558-563 decode).
    let key = [0x12, 0x34, 0x56, 0x78];
    let original: Vec<u8> = (0u8..=255).collect();
    let mut data = original.clone();
    Draft6455::apply_mask(&mut data, key);
    assert_ne!(data, original, "a non-zero key must change the payload");
    Draft6455::apply_mask(&mut data, key);
    assert_eq!(data, original, "mask must be an involution");
}

#[test]
fn apply_mask_known_answer_and_zero_key_identity() {
    let mut data = vec![0x00, 0xFF, 0x0F, 0xF0, 0xAA];
    Draft6455::apply_mask(&mut data, [0x01, 0x02, 0x03, 0x04]);
    // Byte i XORs with key[i % 4].
    assert_eq!(data, vec![0x01, 0xFD, 0x0C, 0xF4, 0xAB]);
    let mut same = vec![0xDE, 0xAD, 0xBE, 0xEF];
    Draft6455::apply_mask(&mut same, [0, 0, 0, 0]);
    assert_eq!(same, vec![0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn decode_frame_header_decodes_real_headers_and_buffers_short_prefixes() {
    // US-012 replaced the US-009 skeleton (which always answered
    // Insufficient — the protocol-stub gate) with the real proof-target
    // decoder (sym.framing.decode-frame-header). A short prefix still
    // buffers; a complete header decodes.
    for buf in [&[][..], &[0x81][..]] {
        assert_eq!(
            Draft6455::decode_frame_header(buf, 65_536),
            Ok(HeaderDecode::Insufficient),
            "prefix {buf:?} lacks the 2-byte base header"
        );
    }
    let decoded = Draft6455::decode_frame_header(&[0x81, 0x05, 0xAA], 65_536)
        .expect("a well-formed header decodes");
    let HeaderDecode::Header(header) = decoded else {
        panic!("2 header bytes are sufficient for a 7-bit length: {decoded:?}");
    };
    assert!(header.fin);
    assert_eq!(header.opcode, Opcode::Text);
    assert!(!header.masked);
    assert_eq!(header.payload_len, 5);
    assert_eq!(header.header_len, 2);
}
