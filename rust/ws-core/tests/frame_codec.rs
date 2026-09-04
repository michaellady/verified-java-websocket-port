//! US-012 frame-codec tests: decode/translate/screen site-exactness against
//! the reference model (`internal/corpora/derive.go`), outbound encoding,
//! and the borrowed deterministic seed corpus replayed with Java-faithful
//! expectations.
//!
//! Seed provenance: `fuzz-seeds/us012/*.hex` are adopted with attribution
//! from the Codex plane (codex-import 8e5b19b..dca0fdb). The seed BYTES are
//! borrowed; every EXPECTATION below is re-derived from derive.go, which
//! CORRECTS the originals where their chain rejected what shipped Java
//! accepts: non-minimal 16/64-bit lengths are accepted (noncanonical-16/64),
//! mask-direction mismatches are accepted toward either role
//! (wrong-mask-client/server), and a 64-bit length with the high bit set is
//! an ordinary oversized length (1009 at the length site), not a dedicated
//! rejection (high-bit-64).

use ws_core::config::ConnectionConfig;
use ws_core::connection::{ConnectionCore, InitialState, Input, LocalCommand, ReadyState, Role};
use ws_core::error::{FailureCode, TypedProtocolFailure};
use ws_core::event::{Counts, Direction, SemanticEvent, SemanticEventKind};
use ws_core::framing::{Draft6455, Opcode};

fn seed(name: &str) -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz-seeds")
        .join(name);
    let hex = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("seed {name} must be readable: {err}"));
    let hex = hex.trim();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("seed files are lowercase hex"))
        .collect()
}

struct Replay {
    result: Result<(), TypedProtocolFailure>,
    events: Vec<SemanticEvent>,
    counts: Counts,
    state: ReadyState,
}

fn replay(role: Role, bytes: &[u8]) -> Replay {
    let mut core =
        ConnectionCore::new_in_state(ConnectionConfig::default(), role, InitialState::Open);
    let result = core.handle(Input::TransportBytes(bytes));
    let events = std::iter::from_fn(|| core.next_event()).collect();
    Replay {
        result,
        events,
        counts: core.counts(),
        state: core.state(),
    }
}

fn replay_seed(name: &str) -> Replay {
    // Seeds are unmasked-or-mixed wire streams; the pinned runtime accepts
    // either masking toward either role (derive.go:439-447), so the client
    // role replays every seed.
    replay(Role::Client, &seed(name))
}

fn expect_err(replay: &Replay, code: FailureCode, close: Option<u16>) {
    let err = replay
        .result
        .as_ref()
        .expect_err("seed must reject under the reference semantics");
    assert_eq!(err.code, code);
    assert_eq!(err.close_code, close);
}

fn message_events(replay: &Replay) -> Vec<&SemanticEventKind> {
    replay
        .events
        .iter()
        .filter(|e| {
            matches!(
                e.kind,
                SemanticEventKind::Text { .. } | SemanticEventKind::Binary { .. }
            )
        })
        .map(|e| &e.kind)
        .collect()
}

// ---------------------------------------------------------------------------
// Java-fidelity corrections the borrow applied (the three stripped
// rejections — these seeds originally asserted the opposite)
// ---------------------------------------------------------------------------

#[test]
fn noncanonical_extended_lengths_are_accepted_like_shipped_java() {
    // derive.go:400-420 reads whatever length the wire declares; shipped
    // Java-WebSocket 1.6.0 never enforces minimal encoding. Both seeds
    // declare small lengths through extended escapes and simply buffer as
    // incomplete frames.
    for (name, buffered) in [
        ("us012/noncanonical-16.hex", 4),
        ("us012/noncanonical-64.hex", 10),
    ] {
        let obs = replay_seed(name);
        assert!(obs.result.is_ok(), "{name} must be accepted, not rejected");
        assert_eq!(obs.counts.frames, 0, "{name}: incomplete frame");
        assert_eq!(obs.counts.wire_buffered_bytes, buffered, "{name}");
        assert_eq!(obs.counts.consumed_bytes, buffered, "{name}");
    }
}

#[test]
fn mask_direction_mismatches_are_accepted_toward_either_role() {
    // derive.go:439-447: the pinned runtime accepts either masking toward
    // either role (the corpus scopes itself to spec-conformant masking, so
    // this is corpus-invisible; the port mirrors the runtime).
    let masked_toward_client = replay(Role::Client, &seed("us012/wrong-mask-client.hex"));
    assert!(masked_toward_client.result.is_ok());
    assert_eq!(masked_toward_client.counts.frames, 1);
    assert_eq!(
        message_events(&masked_toward_client),
        vec![&SemanticEventKind::Binary { data: vec![] }]
    );
    let unmasked_toward_server = replay(Role::Server, &seed("us012/wrong-mask-server.hex"));
    assert!(unmasked_toward_server.result.is_ok());
    assert_eq!(unmasked_toward_server.counts.frames, 1);
}

#[test]
fn high_bit_64_length_is_an_ordinary_oversized_length_at_site_10() {
    // The length parses unsigned; 2^63 exceeds the frame cap, so the header
    // screen rejects 1009 after the 10 length bytes (derive.go site
    // vocabulary), not a dedicated high-bit failure.
    let obs = replay_seed("us012/high-bit-64.hex");
    expect_err(&obs, FailureCode::JavaInvalidData, Some(1009));
    assert_eq!(obs.counts.consumed_bytes, 10, "length site consumed");
    assert_eq!(obs.counts.frames, 0);
    assert_eq!(
        obs.counts.wire_buffered_bytes, 10,
        "leftover retained first"
    );
}

// ---------------------------------------------------------------------------
// Site-exact header rejections (quirk Q25)
// ---------------------------------------------------------------------------

#[test]
fn unknown_opcode_rejects_1002_after_two_header_bytes() {
    let obs = replay_seed("us012/reserved-opcode.hex");
    expect_err(&obs, FailureCode::JavaInvalidData, Some(1002));
    assert_eq!(obs.counts.consumed_bytes, 2, "derive.go:393-394 site 2");
    assert_eq!(obs.counts.frames, 0);
}

#[test]
fn extended_length_control_marker_rejects_1002_before_reading_the_length() {
    // derive.go:403-407: an extended-length control frame rejects at header
    // byte 2, BEFORE the extended length bytes are read.
    let obs = replay_seed("us012/oversized-control.hex");
    expect_err(&obs, FailureCode::JavaInvalidData, Some(1002));
    assert_eq!(obs.counts.consumed_bytes, 2);
    assert_eq!(obs.counts.frames, 0);
}

#[test]
fn oversized_declared_length_rejects_1009_at_the_length_site() {
    let obs = replay_seed("us012/frame-limit.hex");
    expect_err(&obs, FailureCode::JavaInvalidData, Some(1009));
    assert_eq!(obs.counts.consumed_bytes, 10, "64-bit length site");
    assert_eq!(obs.counts.input_bytes, 14);
}

#[test]
fn reserved_bits_reject_1002_only_after_the_full_frame() {
    // Java validates RSV bits AFTER the payload is read
    // (DefaultExtension.isFrameValid; derive.go:452-453), so the whole
    // 2-byte frame is consumed — not a header-time rejection.
    for name in ["us012/rsv1.hex", "us012/rsv2.hex", "us012/rsv3.hex"] {
        let obs = replay_seed(name);
        expect_err(&obs, FailureCode::JavaInvalidData, Some(1002));
        assert_eq!(obs.counts.consumed_bytes, 2, "{name}: full frame consumed");
        assert_eq!(
            obs.counts.frames, 0,
            "{name}: no record on translate failure"
        );
    }
}

#[test]
fn non_fin_control_frame_rejects_1002_after_the_full_frame() {
    // ControlFrame.isValid runs post-payload (derive.go:456-457).
    let obs = replay_seed("us012/fragmented-control.hex");
    expect_err(&obs, FailureCode::JavaInvalidData, Some(1002));
    assert_eq!(obs.counts.consumed_bytes, 6, "header 2 + mask 4, len 0");
    assert_eq!(obs.counts.frames, 0);
}

// ---------------------------------------------------------------------------
// Accepted decodes: canonical lengths, masks, partial frames, multi-frame
// ---------------------------------------------------------------------------

#[test]
fn canonical_seven_bit_frame_delivers_an_empty_binary_message() {
    let obs = replay_seed("us012/canonical-7.hex");
    assert!(obs.result.is_ok());
    assert_eq!(obs.counts.frames, 1);
    assert_eq!(
        message_events(&obs),
        vec![&SemanticEventKind::Binary { data: vec![] }]
    );
}

#[test]
fn canonical_extended_lengths_buffer_as_incomplete_frames() {
    for (name, buffered) in [
        ("us012/canonical-16.hex", 4),
        ("us012/canonical-64.hex", 10),
    ] {
        let obs = replay_seed(name);
        assert!(obs.result.is_ok(), "{name}");
        assert_eq!(obs.counts.frames, 0, "{name}");
        assert_eq!(obs.counts.wire_buffered_bytes, buffered, "{name}");
    }
}

#[test]
fn partial_header_and_partial_payload_buffer_without_frames() {
    for (name, buffered) in [
        ("us012/partial-header-eof.hex", 5),
        ("us012/partial-payload-eof.hex", 7),
    ] {
        let obs = replay_seed(name);
        assert!(obs.result.is_ok(), "{name}");
        assert_eq!(obs.counts.frames, 0, "{name}");
        assert_eq!(obs.counts.wire_buffered_bytes, buffered, "{name}");
        assert_eq!(obs.state, ReadyState::Open, "{name}");
    }
}

#[test]
fn rfc_6455_masked_hello_vector_decodes() {
    // The RFC 6455 section 5.7 masked "Hello" example.
    let obs = replay_seed("us012/rfc-mask.hex");
    assert!(obs.result.is_ok());
    assert_eq!(obs.counts.frames, 1);
    assert_eq!(
        message_events(&obs),
        vec![&SemanticEventKind::Text {
            text: "Hello".to_owned()
        }]
    );
    assert_eq!(obs.counts.consumed_bytes, 11);
}

#[test]
fn multi_frame_chunks_decode_every_complete_frame_in_order() {
    for (name, expected) in [
        (
            "us012/event-limit.hex",
            vec![
                SemanticEventKind::Text {
                    text: "a".to_owned(),
                },
                SemanticEventKind::Text {
                    text: "a".to_owned(),
                },
            ],
        ),
        (
            "us012/total-limit.hex",
            vec![
                SemanticEventKind::Binary {
                    data: vec![1, 2, 3, 4],
                },
                SemanticEventKind::Binary {
                    data: vec![5, 6, 7, 8],
                },
            ],
        ),
    ] {
        let obs = replay_seed(name);
        assert!(obs.result.is_ok(), "{name}");
        assert_eq!(obs.counts.frames, 2, "{name}");
        let got: Vec<_> = message_events(&obs).into_iter().cloned().collect();
        assert_eq!(got, expected, "{name}");
    }
}

#[test]
fn frame_count_limit_fires_before_the_over_budget_frame_is_recorded() {
    // derive.go:361-362: the frame budget is checked before each record;
    // the input_chunk event and earlier frames' effects survive.
    let config = ConnectionConfig::builder()
        .max_frames(1)
        .build()
        .expect("valid test config");
    let mut core = ConnectionCore::new_in_state(config, Role::Client, InitialState::Open);
    // Two complete empty binary frames in one chunk.
    let err = core
        .handle(Input::TransportBytes(&[0x82, 0x00, 0x82, 0x00]))
        .expect_err("second frame exceeds max_frames 1");
    assert_eq!(err.code, FailureCode::FrameLimitExceeded);
    assert_eq!(core.counts().frames, 1, "first frame was recorded");
    assert_eq!(
        core.counts().consumed_bytes,
        4,
        "whole chunk consumed first"
    );
}

#[test]
fn translate_rejection_mid_chunk_discards_earlier_frames_of_the_same_chunk() {
    // derive.go builds the whole decoded list before recording ANY frame:
    // a valid frame followed by an invalid one in the same chunk records
    // nothing and consumes up to the failing frame's error site.
    let mut stream = vec![0x82, 0x01, 0xAA]; // valid binary, 3 bytes
    stream.extend_from_slice(&[0x83, 0x00]); // reserved opcode at offset 3
    let obs = replay(Role::Client, &stream);
    expect_err(&obs, FailureCode::JavaInvalidData, Some(1002));
    assert_eq!(obs.counts.frames, 0, "the valid frame is NOT recorded");
    assert_eq!(obs.counts.consumed_bytes, 3 + 2, "span start + site 2");
    assert!(message_events(&obs).is_empty());
}

#[test]
fn incomplete_header_screen_fires_after_complete_frames_but_blocks_the_chunk() {
    // derive.go:344-357: a fresh incomplete frame whose visible header is
    // invalid rejects during this step, BEFORE the input_chunk event and
    // before any frame from the chunk is recorded.
    let mut stream = vec![0x82, 0x01, 0xAA]; // complete valid binary frame
    stream.extend_from_slice(&[0x89, 0xFE]); // incomplete oversized-control header
    let obs = replay(Role::Client, &stream);
    expect_err(&obs, FailureCode::JavaInvalidData, Some(1002));
    assert_eq!(obs.counts.frames, 0);
    assert_eq!(obs.counts.consumed_bytes, 3 + 2, "leftover start + site 2");
    assert!(
        obs.events.is_empty(),
        "no input_chunk on a screened rejection"
    );
}

// ---------------------------------------------------------------------------
// Outbound path: encode_frame, deterministic masking, send commands
// ---------------------------------------------------------------------------

#[test]
fn encode_frame_matches_the_reference_wire_layout() {
    // Mirrors internal/corpora/frames.go EncodeFrame.
    assert_eq!(
        Draft6455::encode_frame(true, Opcode::Text, b"hi", None),
        vec![0x81, 0x02, b'h', b'i']
    );
    let masked =
        Draft6455::encode_frame(true, Opcode::Text, b"Hello", Some([0x37, 0xfa, 0x21, 0x3d]));
    assert_eq!(
        masked,
        vec![
            0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58
        ],
        "the RFC 6455 masked Hello vector"
    );
    // 16-bit and 64-bit length escapes.
    let payload_16 = vec![0u8; 126];
    let encoded_16 = Draft6455::encode_frame(true, Opcode::Binary, &payload_16, None);
    assert_eq!(&encoded_16[..4], &[0x82, 0x7e, 0x00, 0x7e]);
    let payload_64 = vec![0u8; 65_536];
    let encoded_64 = Draft6455::encode_frame(false, Opcode::Binary, &payload_64, None);
    assert_eq!(
        &encoded_64[..10],
        &[0x02, 0x7f, 0, 0, 0, 0, 0, 1, 0, 0],
        "non-fin 64-bit length escape"
    );
}

#[test]
fn send_text_emits_frame_record_cause_event_and_real_write() {
    // Server role: unmasked write, wire = header + payload (derive.go
    // emitOutbound + frames.go outboundWireBytes).
    let mut core = ConnectionCore::new_in_state(
        ConnectionConfig::default(),
        Role::Server,
        InitialState::Open,
    );
    core.handle(Input::Command(LocalCommand::SendText {
        text: "ok".to_owned(),
    }))
    .expect("send_text in open succeeds");
    let write = core.next_write().expect("one wire write");
    assert_eq!(write.bytes, vec![0x81, 0x02, b'o', b'k']);
    assert!(core.next_write().is_none());
    let events: Vec<_> = std::iter::from_fn(|| core.next_event()).collect();
    assert_eq!(events.len(), 2, "frame record + cause event");
    let SemanticEventKind::FrameObserved(frame) = &events[0].kind else {
        panic!("first event is the frame record: {events:?}");
    };
    assert_eq!(frame.direction, Direction::Outbound);
    assert!(frame.fin);
    assert!(!frame.masked);
    assert_eq!(frame.opcode, Opcode::Text);
    assert_eq!(frame.payload, b"ok");
    assert_eq!(frame.wire_bytes, 4);
    assert!(matches!(
        events[1].kind,
        SemanticEventKind::OutboundCause {
            cause: ws_core::event::OutboundCause::SendText,
            opcode: Opcode::Text,
        }
    ));
    assert_eq!(core.counts().frames, 1);
}

#[test]
fn client_sends_are_masked_deterministically_and_roundtrip() {
    // Quirk Q28: mask keys are never observable; the port derives them
    // deterministically from mask_key_seed. Two cores with the same seed
    // produce byte-identical writes; the masked payload unmasks back.
    let make = || {
        ConnectionCore::new_in_state(
            ConnectionConfig::builder()
                .mask_key_seed(7)
                .build()
                .expect("valid test config"),
            Role::Client,
            InitialState::Open,
        )
    };
    let send = |core: &mut ConnectionCore| {
        core.handle(Input::Command(LocalCommand::SendBinary {
            data: vec![1, 2, 3],
        }))
        .expect("send_binary in open succeeds");
        core.next_write().expect("one write").bytes
    };
    let (mut a, mut b) = (make(), make());
    let (wire_a, wire_b) = (send(&mut a), send(&mut b));
    assert_eq!(wire_a, wire_b, "identical seeds -> identical writes");
    assert_eq!(wire_a.len(), 2 + 4 + 3, "header + mask + payload");
    assert_eq!(wire_a[0], 0x82);
    assert_eq!(wire_a[1], 0x80 | 3, "masked bit + length 3");
    let mut payload = wire_a[6..].to_vec();
    let key = [wire_a[2], wire_a[3], wire_a[4], wire_a[5]];
    Draft6455::apply_mask(&mut payload, key);
    assert_eq!(payload, vec![1, 2, 3], "masking round-trips");
    // The frame record carries the SEMANTIC payload and the masked wire
    // size (derive.go emitOutbound: wire = header + payload + 4).
    let events: Vec<_> = std::iter::from_fn(|| a.next_event()).collect();
    let SemanticEventKind::FrameObserved(frame) = &events[0].kind else {
        panic!("frame record first");
    };
    assert!(frame.masked);
    assert_eq!(frame.payload, vec![1, 2, 3]);
    assert_eq!(frame.wire_bytes, 9);
}

#[test]
fn outbound_send_hits_the_frame_budget_before_recording() {
    // derive.go emitOutbound:784-785: FRAME_LIMIT_EXCEEDED before the
    // record; the action was already counted.
    let config = ConnectionConfig::builder()
        .max_frames(1)
        .build()
        .expect("valid test config");
    let mut core = ConnectionCore::new_in_state(config, Role::Server, InitialState::Open);
    core.handle(Input::Command(LocalCommand::SendText {
        text: "a".to_owned(),
    }))
    .expect("first send fits the budget");
    let err = core
        .handle(Input::Command(LocalCommand::SendText {
            text: "b".to_owned(),
        }))
        .expect_err("second send exceeds max_frames 1");
    assert_eq!(err.code, FailureCode::FrameLimitExceeded);
    assert_eq!(core.counts().frames, 1);
    assert_eq!(core.counts().actions, 2, "the rejected action is counted");
}
