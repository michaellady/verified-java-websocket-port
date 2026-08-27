#![forbid(unsafe_code)]

use websocket_core::{
    ClientRequestDescriptor, ConnectionConfig, ConnectionCore, ConnectionLimits, ConnectionState,
    CoreInput, CoreOutput, FailureKind, Frame, FrameEncoder, FrameFailure, FrameHeaderDecode,
    FrameHeaderDecoder, LimitKind, LocalCommand, Opcode, OutboundFrame, ProtocolStory, QueueKind,
    Role, SemanticEvent, TransportBytes, apply_mask_in_place,
};

const RFC_REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
const RFC_RESPONSE: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
const RFC_KEY: [u8; 4] = [0x37, 0xfa, 0x21, 0x3d];

fn config_with(mut change: impl FnMut(&mut ConnectionLimits)) -> ConnectionConfig {
    let mut limits = ConnectionLimits::default();
    change(&mut limits);
    ConnectionConfig::try_from(limits).expect("test limits are valid")
}

fn open_core(role: Role, config: ConnectionConfig) -> ConnectionCore {
    let mut core = ConnectionCore::new(config, role);
    match role {
        Role::Client => {
            let descriptor =
                ClientRequestDescriptor::try_new("/chat", "server.example.com").unwrap();
            let started = core.step(CoreInput::Command(LocalCommand::StartClientHandshake {
                descriptor,
                nonce: *b"the sample nonce",
            }));
            assert_eq!(started.failure(), None);
            let opened = core.step(CoreInput::Transport(TransportBytes::new(RFC_RESPONSE)));
            assert_eq!(opened.failure(), None);
        }
        Role::Server => {
            let opened = core.step(CoreInput::Transport(TransportBytes::new(RFC_REQUEST)));
            assert_eq!(opened.failure(), None);
        }
    }
    assert_eq!(core.state(), ConnectionState::Open);
    core
}

fn encoded(
    role: Role,
    config: &ConnectionConfig,
    fin: bool,
    opcode: Opcode,
    payload: &[u8],
) -> Vec<u8> {
    let encoder = FrameEncoder::new(config.clone(), role);
    let key = (role == Role::Client).then_some(RFC_KEY);
    encoder
        .encode(OutboundFrame::new(fin, opcode, payload), key)
        .expect("valid frame encodes")
        .as_slice()
        .to_vec()
}

fn frames(result: &websocket_core::StepResult) -> Vec<&Frame> {
    result
        .outputs()
        .filter_map(|output| match output {
            CoreOutput::SemanticEvent(SemanticEvent::FrameReceived { frame }) => Some(frame),
            _ => None,
        })
        .collect()
}

fn assert_frame(frame: &Frame, fin: bool, opcode: Opcode, masked: bool, payload: &[u8]) {
    assert_eq!(frame.fin(), fin);
    assert_eq!(frame.opcode(), opcode);
    assert_eq!(frame.masked(), masked);
    assert_eq!(frame.payload(), payload);
}

fn header_bytes(fin: bool, opcode: u8, masked: bool, payload_length: u64) -> Vec<u8> {
    let mut bytes = vec![if fin { 0x80 | opcode } else { opcode }];
    let mask = if masked { 0x80 } else { 0 };
    if payload_length <= 125 {
        bytes.push(mask | u8::try_from(payload_length).unwrap());
    } else if payload_length <= u64::from(u16::MAX) {
        bytes.push(mask | 126);
        bytes.extend_from_slice(&u16::try_from(payload_length).unwrap().to_be_bytes());
    } else {
        bytes.push(mask | 127);
        bytes.extend_from_slice(&payload_length.to_be_bytes());
    }
    if masked {
        bytes.extend_from_slice(&RFC_KEY);
    }
    bytes
}

fn decode_hex_seed(hex: &str) -> Vec<u8> {
    fn nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("seed is not canonical lowercase hex"),
        }
    }

    hex.trim_end()
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
        .collect()
}

#[test]
fn canonical_length_classes_have_exact_headers_and_streaming_round_trips() {
    let config = config_with(|_| {});
    let lengths = [0usize, 1, 124, 125, 126, 127, 65_534, 65_535, 65_536];

    for length in lengths {
        let payload: Vec<u8> = (0..length).map(|index| index as u8).collect();
        for outbound_role in [Role::Client, Role::Server] {
            let inbound_role = match outbound_role {
                Role::Client => Role::Server,
                Role::Server => Role::Client,
            };
            let wire = encoded(outbound_role, &config, true, Opcode::Binary, &payload);
            let header_length = match length {
                0..=125 => 2,
                126..=65_535 => 4,
                _ => 10,
            } + if outbound_role == Role::Client { 4 } else { 0 };
            assert_eq!(wire[0], 0x82);
            assert_eq!(wire.len(), header_length + length);
            match length {
                0..=125 => assert_eq!(wire[1] & 0x7f, length as u8),
                126..=65_535 => {
                    assert_eq!(wire[1] & 0x7f, 126);
                    assert_eq!(u16::from_be_bytes([wire[2], wire[3]]) as usize, length);
                }
                _ => {
                    assert_eq!(wire[1] & 0x7f, 127);
                    assert_eq!(
                        u64::from_be_bytes(wire[2..10].try_into().unwrap()) as usize,
                        length
                    );
                }
            }

            let mut core = open_core(inbound_role, config.clone());
            let mut observed = None;
            for byte in &wire {
                let result = core.step(CoreInput::Transport(TransportBytes::new(
                    core::slice::from_ref(byte),
                )));
                assert_eq!(
                    result.failure(),
                    None,
                    "length={length} role={outbound_role:?}"
                );
                let emitted = frames(&result);
                assert!(observed.is_none() || emitted.is_empty());
                if let Some(frame) = emitted.first() {
                    assert_frame(
                        frame,
                        true,
                        Opcode::Binary,
                        outbound_role == Role::Client,
                        &payload,
                    );
                    observed = Some((*frame).clone());
                }
            }
            assert!(observed.is_some(), "length={length} role={outbound_role:?}");
        }
    }
}

#[test]
fn every_cut_and_multi_frame_tail_preserve_wire_order() {
    let config = config_with(|_| {});
    let first = encoded(Role::Client, &config, true, Opcode::Text, b"first");
    let second = encoded(Role::Client, &config, false, Opcode::Binary, b"second");

    for split in 0..=first.len() {
        let mut core = open_core(Role::Server, config.clone());
        let a = core.step(CoreInput::Transport(TransportBytes::new(&first[..split])));
        assert_eq!(a.failure(), None, "split={split}");
        let b = core.step(CoreInput::Transport(TransportBytes::new(&first[split..])));
        assert_eq!(b.failure(), None, "split={split}");
        let all: Vec<_> = frames(&a).into_iter().chain(frames(&b)).collect();
        assert_eq!(all.len(), 1, "split={split}");
        assert_frame(all[0], true, Opcode::Text, true, b"first");
    }

    let mut joined = first.clone();
    joined.extend_from_slice(&second);
    joined.extend_from_slice(&[0x81]);
    let mut core = open_core(Role::Server, config);
    let result = core.step(CoreInput::Transport(TransportBytes::new(&joined)));
    assert_eq!(result.failure(), None);
    let emitted = frames(&result);
    assert_eq!(emitted.len(), 2);
    assert_frame(emitted[0], true, Opcode::Text, true, b"first");
    assert_frame(emitted[1], false, Opcode::Binary, true, b"second");
    assert_eq!(result.state(), ConnectionState::Open);
}

#[test]
fn empty_chunks_preserve_partial_header_and_payload_state() {
    let config = config_with(|_| {});
    let wire = encoded(Role::Client, &config, true, Opcode::Binary, b"payload");

    let mut header_partial = open_core(Role::Server, config.clone());
    let first = header_partial.step(CoreInput::Transport(TransportBytes::new(&wire[..1])));
    assert_eq!(first.failure(), None);
    let empty = header_partial.step(CoreInput::Transport(TransportBytes::new(&[])));
    assert_eq!(empty.failure(), None);
    assert_eq!(empty.outputs().len(), 0);
    assert_eq!(empty.state(), ConnectionState::Open);
    let complete = header_partial.step(CoreInput::Transport(TransportBytes::new(&wire[1..])));
    assert_eq!(complete.failure(), None);
    assert_frame(frames(&complete)[0], true, Opcode::Binary, true, b"payload");

    let mut payload_partial = open_core(Role::Server, config);
    let payload_start = 6;
    let first = payload_partial.step(CoreInput::Transport(TransportBytes::new(
        &wire[..payload_start + 2],
    )));
    assert_eq!(first.failure(), None);
    assert_eq!(first.outputs().len(), 0);
    let empty = payload_partial.step(CoreInput::Transport(TransportBytes::new(&[])));
    assert_eq!(empty.failure(), None);
    assert_eq!(empty.outputs().len(), 0);
    let complete = payload_partial.step(CoreInput::Transport(TransportBytes::new(
        &wire[payload_start + 2..],
    )));
    assert_eq!(complete.failure(), None);
    assert_frame(frames(&complete)[0], true, Opcode::Binary, true, b"payload");
}

#[test]
fn exact_header_boundary_empty_frames_emit_without_a_followup_input() {
    let config = config_with(|_| {});
    let mut client = open_core(Role::Client, config.clone());
    let unmasked = client.step(CoreInput::Transport(TransportBytes::new(&[0x82, 0])));
    assert_eq!(unmasked.failure(), None);
    assert_frame(frames(&unmasked)[0], true, Opcode::Binary, false, b"");

    let mut server = open_core(Role::Server, config);
    let masked_wire = [0x82, 0x80, 1, 2, 3, 4];
    let masked = server.step(CoreInput::Transport(TransportBytes::new(&masked_wire)));
    assert_eq!(masked.failure(), None);
    assert_frame(frames(&masked)[0], true, Opcode::Binary, true, b"");
}

#[test]
fn protocol_failure_after_a_complete_frame_preserves_the_prior_event() {
    let config = config_with(|_| {});
    let mut bytes = encoded(Role::Client, &config, true, Opcode::Binary, b"accepted");
    bytes.extend_from_slice(&[0x83, 0x80]);

    let mut core = open_core(Role::Server, config);
    let result = core.step(CoreInput::Transport(TransportBytes::new(&bytes)));
    let emitted = frames(&result);
    assert_eq!(emitted.len(), 1);
    assert_frame(emitted[0], true, Opcode::Binary, true, b"accepted");
    assert_eq!(
        result.failure().map(|failure| &failure.kind),
        Some(&FailureKind::Frame(FrameFailure::ReservedOpcode {
            opcode: 0x3,
        }))
    );
    assert_eq!(result.state(), ConnectionState::Closed);
    assert_eq!(
        result.outputs().last(),
        Some(&CoreOutput::StateChanged(ConnectionState::Closed))
    );
}

#[test]
fn frozen_public_frame_family_literals_decode_at_the_frame_seam() {
    let config = config_with(|_| {});
    let public_text_single = b"\x81\x06aiojkx";
    let public_binary_single = b"\x82\x17\x17\x20\xb4\x21\xb3\xaf\xe5\x1c\xae\xd4\xb4\xf0\x37\x83\x27\x9e\x5d\x7c\x33\x60\x37\x6a\xbf";
    let public_masked_text_empty = b"\x81\x80\x3d\x68\xe4\x5a";

    let mut client = open_core(Role::Client, config.clone());
    for (wire, opcode, payload) in [
        (
            public_text_single.as_slice(),
            Opcode::Text,
            b"aiojkx".as_slice(),
        ),
        (
            public_binary_single.as_slice(),
            Opcode::Binary,
            &public_binary_single[2..],
        ),
    ] {
        let result = client.step(CoreInput::Transport(TransportBytes::new(wire)));
        assert_eq!(result.failure(), None);
        assert_frame(frames(&result)[0], true, opcode, false, payload);
    }

    let mut server = open_core(Role::Server, config);
    let result = server.step(CoreInput::Transport(TransportBytes::new(
        public_masked_text_empty,
    )));
    assert_eq!(result.failure(), None);
    assert_frame(frames(&result)[0], true, Opcode::Text, true, b"");
}

#[test]
fn all_valid_and_reserved_opcodes_and_each_rsv_bit_are_typed() {
    let config = config_with(|_| {});
    let valid = [
        (0x0, Opcode::Continuation),
        (0x1, Opcode::Text),
        (0x2, Opcode::Binary),
        (0x8, Opcode::Close),
        (0x9, Opcode::Ping),
        (0xa, Opcode::Pong),
    ];
    for (wire_opcode, expected) in valid {
        let prefix = header_bytes(true, wire_opcode, false, 0);
        let result = FrameHeaderDecoder::decode_header(&config, Role::Client, 0, &prefix);
        let FrameHeaderDecode::Complete(header) = result.unwrap() else {
            panic!("valid opcode {wire_opcode:#x} was incomplete");
        };
        assert_eq!(header.opcode(), expected);
    }

    for reserved in [0x3, 0x4, 0x5, 0x6, 0x7, 0xb, 0xc, 0xd, 0xe, 0xf] {
        let error = FrameHeaderDecoder::decode_header(
            &config,
            Role::Client,
            0,
            &header_bytes(true, reserved, false, 0),
        )
        .unwrap_err();
        assert_eq!(
            error,
            FailureKind::Frame(FrameFailure::ReservedOpcode { opcode: reserved })
        );
    }

    for rsv in [0x40, 0x20, 0x10] {
        let error = FrameHeaderDecoder::decode_header(&config, Role::Client, 0, &[0x82 | rsv, 0])
            .unwrap_err();
        assert_eq!(error, FailureKind::Frame(FrameFailure::ReservedBits));
    }
}

#[test]
fn validation_precedence_and_role_mask_matrix_are_stable() {
    let config = config_with(|_| {});
    for (role, masked, accepted) in [
        (Role::Client, false, true),
        (Role::Client, true, false),
        (Role::Server, false, false),
        (Role::Server, true, true),
    ] {
        let prefix = header_bytes(true, 0x2, masked, 0);
        let decoded = FrameHeaderDecoder::decode_header(&config, role, 0, &prefix);
        if accepted {
            assert!(matches!(decoded, Ok(FrameHeaderDecode::Complete(_))));
        } else {
            assert_eq!(
                decoded.unwrap_err(),
                FailureKind::Frame(FrameFailure::IncorrectMasking {
                    expected_masked: role == Role::Server,
                    actual_masked: masked,
                })
            );
        }
    }

    assert!(matches!(
        FrameHeaderDecoder::decode_header(&config, Role::Client, 0, &[0x82]),
        Ok(FrameHeaderDecode::Incomplete { minimum: 2 })
    ));
    assert_eq!(
        FrameHeaderDecoder::decode_header(&config, Role::Client, 0, &[0xc3, 0]).unwrap_err(),
        FailureKind::Frame(FrameFailure::ReservedBits),
        "RSV precedes reserved-opcode and incompleteness after the base bytes"
    );
    assert_eq!(
        FrameHeaderDecoder::decode_header(&config, Role::Client, 0, &[0x09, 126, 0, 126])
            .unwrap_err(),
        FailureKind::Frame(FrameFailure::FragmentedControl {
            opcode: Opcode::Ping,
        }),
        "fragmented control precedes extended-length validation"
    );
}

#[test]
fn noncanonical_lengths_high_bit_and_control_boundaries_fail_exactly() {
    let config = config_with(|_| {});
    let cases = [
        (
            vec![0x82, 126, 0, 125],
            FrameFailure::NonCanonicalLength16 { length: 125 },
        ),
        (
            vec![0x82, 127, 0, 0, 0, 0, 0, 0, 0xff, 0xff],
            FrameFailure::NonCanonicalLength64 { length: 65_535 },
        ),
        (
            vec![0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 0],
            FrameFailure::PayloadLengthHighBitSet,
        ),
        (
            vec![0x09, 0],
            FrameFailure::FragmentedControl {
                opcode: Opcode::Ping,
            },
        ),
        (
            vec![0x89, 126, 0, 126],
            FrameFailure::ControlPayloadTooLarge { length: 126 },
        ),
    ];
    for (prefix, expected) in cases {
        assert_eq!(
            FrameHeaderDecoder::decode_header(&config, Role::Client, 0, &prefix).unwrap_err(),
            FailureKind::Frame(expected)
        );
    }

    let control_125 = header_bytes(true, 0x9, false, 125);
    assert!(matches!(
        FrameHeaderDecoder::decode_header(&config, Role::Client, 0, &control_125),
        Ok(FrameHeaderDecode::Complete(_))
    ));
}

#[test]
fn mask_equation_involution_offsets_chunks_and_rfc_literal_hold() {
    let keys = [RFC_KEY, [0, 1, 2, 3], [0xff, 0x55, 0xaa, 0x11]];
    for key in keys {
        for offset in 0..4 {
            let original: Vec<u8> = (0..37).map(|value| value * 3).collect();
            let mut masked = original.clone();
            apply_mask_in_place(&mut masked, key, offset);
            for (index, (&actual, &before)) in masked.iter().zip(&original).enumerate() {
                assert_eq!(actual, before ^ key[(offset + index) % 4]);
            }
            apply_mask_in_place(&mut masked, key, offset);
            assert_eq!(masked, original);
        }
    }

    let original = b"Hello";
    let mut chunked = original.to_vec();
    apply_mask_in_place(&mut chunked[..1], RFC_KEY, 0);
    apply_mask_in_place(&mut chunked[1..3], RFC_KEY, 1);
    apply_mask_in_place(&mut chunked[3..], RFC_KEY, 3);
    assert_eq!(chunked, [0x7f, 0x9f, 0x4d, 0x51, 0x58]);
    apply_mask_in_place(&mut chunked, RFC_KEY, 0);
    assert_eq!(chunked, original);
}

#[test]
fn encoder_role_control_and_limit_rejections_precede_allocation() {
    let config = config_with(|_| {});
    let client = FrameEncoder::new(config.clone(), Role::Client);
    let server = FrameEncoder::new(config, Role::Server);
    assert_eq!(
        client
            .encode(OutboundFrame::new(true, Opcode::Binary, b"x"), None)
            .unwrap_err(),
        FailureKind::Frame(FrameFailure::MissingMaskKey)
    );
    assert_eq!(
        server
            .encode(
                OutboundFrame::new(true, Opcode::Binary, b"x"),
                Some(RFC_KEY)
            )
            .unwrap_err(),
        FailureKind::Frame(FrameFailure::UnexpectedMaskKey)
    );
    assert_eq!(
        server
            .encode(OutboundFrame::new(false, Opcode::Ping, b""), None)
            .unwrap_err(),
        FailureKind::Frame(FrameFailure::FragmentedControl {
            opcode: Opcode::Ping,
        })
    );
    assert_eq!(
        server
            .encode(OutboundFrame::new(true, Opcode::Pong, &[0; 126]), None)
            .unwrap_err(),
        FailureKind::Frame(FrameFailure::ControlPayloadTooLarge { length: 126 })
    );

    let bounded = config_with(|limits| {
        limits.frame_bytes = 5;
        limits.message_bytes = 5;
        limits.total_buffered_bytes = 16;
    });
    let encoder = FrameEncoder::new(bounded, Role::Server);
    assert!(
        encoder
            .encode(OutboundFrame::new(true, Opcode::Binary, &[0; 5]), None)
            .is_ok()
    );
    assert_eq!(
        encoder
            .encode(OutboundFrame::new(true, Opcode::Binary, &[0; 6]), None)
            .unwrap_err(),
        FailureKind::LimitExceeded {
            limit: LimitKind::FrameBytes,
            attempted: 6,
            maximum: 5,
        }
    );

    let total = config_with(|limits| {
        limits.frame_bytes = 5;
        limits.message_bytes = 5;
        limits.total_buffered_bytes = 6;
    });
    assert_eq!(
        FrameEncoder::new(total, Role::Server)
            .encode(OutboundFrame::new(true, Opcode::Binary, &[0; 5]), None)
            .unwrap_err(),
        FailureKind::LimitExceeded {
            limit: LimitKind::TotalBufferedBytes,
            attempted: 7,
            maximum: 6,
        }
    );
}

#[test]
fn decoder_frame_total_and_event_limits_are_exact_and_preserve_prior_events() {
    let frame_bounded = config_with(|limits| {
        limits.frame_bytes = 5;
        limits.message_bytes = 5;
        limits.total_buffered_bytes = 32;
    });
    let permissive = config_with(|_| {});
    let accepted_wire = encoded(Role::Client, &permissive, true, Opcode::Binary, &[0; 5]);
    let mut exact = open_core(Role::Server, frame_bounded.clone());
    let accepted = exact.step(CoreInput::Transport(TransportBytes::new(&accepted_wire)));
    assert_eq!(accepted.failure(), None);
    assert_eq!(frames(&accepted)[0].payload().len(), 5);
    let wire = encoded(Role::Client, &permissive, true, Opcode::Binary, &[0; 6]);
    let mut core = open_core(Role::Server, frame_bounded);
    let rejected = core.step(CoreInput::Transport(TransportBytes::new(&wire)));
    assert_eq!(
        rejected.failure().map(|failure| &failure.kind),
        Some(&FailureKind::LimitExceeded {
            limit: LimitKind::FrameBytes,
            attempted: 6,
            maximum: 5,
        })
    );
    assert_eq!(rejected.state(), ConnectionState::Closed);
    assert!(frames(&rejected).is_empty());

    let total_bounded = config_with(|limits| {
        limits.frame_bytes = 5;
        limits.message_bytes = 5;
        limits.total_buffered_bytes = 5;
    });
    let first = encoded(Role::Client, &permissive, true, Opcode::Binary, &[1; 3]);
    let exact_second = encoded(Role::Client, &permissive, true, Opcode::Binary, &[2; 2]);
    let second = encoded(Role::Client, &permissive, true, Opcode::Binary, &[2; 3]);
    let mut exact_combined = first.clone();
    exact_combined.extend_from_slice(&exact_second);
    let mut exact = open_core(Role::Server, total_bounded.clone());
    let accepted = exact.step(CoreInput::Transport(TransportBytes::new(&exact_combined)));
    assert_eq!(accepted.failure(), None);
    assert_eq!(frames(&accepted).len(), 2);
    let mut combined = first;
    combined.extend_from_slice(&second);
    let mut core = open_core(Role::Server, total_bounded);
    let rejected = core.step(CoreInput::Transport(TransportBytes::new(&combined)));
    assert_eq!(frames(&rejected).len(), 1);
    assert_eq!(
        rejected.failure().map(|failure| &failure.kind),
        Some(&FailureKind::LimitExceeded {
            limit: LimitKind::TotalBufferedBytes,
            attempted: 6,
            maximum: 5,
        })
    );
    assert_eq!(
        rejected.outputs().last(),
        Some(&CoreOutput::StateChanged(ConnectionState::Closed))
    );

    let event_bounded = config_with(|limits| limits.event_queue_entries = 1);
    let first = encoded(Role::Client, &event_bounded, true, Opcode::Binary, b"a");
    let second = encoded(Role::Client, &event_bounded, true, Opcode::Binary, b"b");
    let mut combined = first;
    combined.extend_from_slice(&second);
    let mut core = open_core(Role::Server, event_bounded);
    let rejected = core.step(CoreInput::Transport(TransportBytes::new(&combined)));
    assert_eq!(frames(&rejected).len(), 1);
    assert_eq!(
        rejected.failure().map(|failure| &failure.kind),
        Some(&FailureKind::Backpressure(QueueKind::Event))
    );
    assert_eq!(rejected.state(), ConnectionState::Closed);
}

#[test]
fn eof_at_every_header_boundary_and_during_payload_is_a_frame_failure() {
    let config = config_with(|_| {});
    let wire = encoded(Role::Client, &config, true, Opcode::Binary, &[7; 126]);
    let header_length = 8;
    for split in 1..header_length {
        let mut core = open_core(Role::Server, config.clone());
        let partial = core.step(CoreInput::Transport(TransportBytes::new(&wire[..split])));
        assert_eq!(partial.failure(), None, "split={split}");
        let eof = core.step(CoreInput::TransportEof);
        assert_eq!(
            eof.failure().map(|failure| &failure.kind),
            Some(&FailureKind::Frame(FrameFailure::UnexpectedEof)),
            "split={split}"
        );
        assert_eq!(eof.state(), ConnectionState::Closed);
    }

    let mut payload_partial = open_core(Role::Server, config);
    let partial = payload_partial.step(CoreInput::Transport(TransportBytes::new(
        &wire[..header_length + 1],
    )));
    assert_eq!(partial.failure(), None);
    let eof = payload_partial.step(CoreInput::TransportEof);
    assert_eq!(
        eof.failure().map(|failure| &failure.kind),
        Some(&FailureKind::Frame(FrameFailure::UnexpectedEof))
    );
}

#[test]
fn frame_events_do_not_implement_later_story_semantics() {
    let config = config_with(|_| {});
    let wire = encoded(Role::Client, &config, true, Opcode::Text, &[0xff]);
    let mut core = open_core(Role::Server, config);
    let result = core.step(CoreInput::Transport(TransportBytes::new(&wire)));
    assert_eq!(result.failure(), None, "US-013 owns UTF-8 validation");
    assert_eq!(frames(&result).len(), 1);
    assert_eq!(result.outputs().len(), 1, "only FrameReceived is emitted");

    for (command, owner_story) in [
        (
            LocalCommand::SendText("later".into()),
            ProtocolStory::Messages,
        ),
        (
            LocalCommand::SendPing(b"later".to_vec().into_boxed_slice()),
            ProtocolStory::ControlFrames,
        ),
        (
            LocalCommand::Close {
                code: 1000,
                reason: "later".into(),
            },
            ProtocolStory::CloseAndEof,
        ),
    ] {
        let result = core.step(CoreInput::Command(command));
        assert_eq!(
            result.failure().map(|failure| &failure.kind),
            Some(&FailureKind::ProtocolSliceUnavailable { owner_story })
        );
        assert_eq!(result.state(), ConnectionState::Open);
    }
    let eof = core.step(CoreInput::TransportEof);
    assert_eq!(
        eof.failure().map(|failure| &failure.kind),
        Some(&FailureKind::ProtocolSliceUnavailable {
            owner_story: ProtocolStory::CloseAndEof,
        })
    );
    assert_eq!(eof.state(), ConnectionState::Open);
}

#[test]
fn us012_formal_actual_code_obligations() {
    #[derive(Default)]
    struct Counts {
        control_fin_and_length: u64,
        length_canonical_16: u64,
        length_canonical_64_high_bit_zero: u64,
        length_canonical_7: u64,
        preallocation_cap: u64,
        role_masking: u64,
        mask_equation: u64,
        mask_involution: u64,
    }

    let config = config_with(|_| {});
    let mut counts = Counts::default();

    for length in 0..=125 {
        let prefix = header_bytes(true, 0x2, false, length);
        assert!(matches!(
            FrameHeaderDecoder::decode_header(&config, Role::Client, 0, &prefix),
            Ok(FrameHeaderDecode::Complete(_))
        ));
        counts.length_canonical_7 += 1;
    }
    for length in [126, 127, 255, 256, 65_534, 65_535] {
        let prefix = header_bytes(true, 0x2, false, length);
        assert!(matches!(
            FrameHeaderDecoder::decode_header(&config, Role::Client, 0, &prefix),
            Ok(FrameHeaderDecode::Complete(_))
        ));
        counts.length_canonical_16 += 1;
    }
    for length in [65_536, 65_537, 1_048_576] {
        let prefix = header_bytes(true, 0x2, false, length);
        assert!(matches!(
            FrameHeaderDecoder::decode_header(&config, Role::Client, 0, &prefix),
            Ok(FrameHeaderDecode::Complete(_))
        ));
        counts.length_canonical_64_high_bit_zero += 1;
    }
    for (prefix, expected) in [
        (
            vec![0x82, 126, 0, 125],
            FrameFailure::NonCanonicalLength16 { length: 125 },
        ),
        (
            vec![0x82, 127, 0, 0, 0, 0, 0, 0, 0xff, 0xff],
            FrameFailure::NonCanonicalLength64 { length: 65_535 },
        ),
        (
            vec![0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 0],
            FrameFailure::PayloadLengthHighBitSet,
        ),
    ] {
        assert_eq!(
            FrameHeaderDecoder::decode_header(&config, Role::Client, 0, &prefix).unwrap_err(),
            FailureKind::Frame(expected)
        );
    }
    for (fin, opcode, length, accepted) in [
        (true, 0x8, 0, true),
        (true, 0x9, 125, true),
        (true, 0xa, 125, true),
        (false, 0x8, 0, false),
        (false, 0x9, 1, false),
        (true, 0xa, 126, false),
    ] {
        let result = FrameHeaderDecoder::decode_header(
            &config,
            Role::Client,
            0,
            &header_bytes(fin, opcode, false, length),
        );
        assert_eq!(result.is_ok(), accepted);
        counts.control_fin_and_length += 1;
    }
    for (role, masked, accepted) in [
        (Role::Client, false, true),
        (Role::Client, true, false),
        (Role::Server, false, false),
        (Role::Server, true, true),
    ] {
        let result = FrameHeaderDecoder::decode_header(
            &config,
            role,
            0,
            &header_bytes(true, 0x2, masked, 0),
        );
        assert_eq!(result.is_ok(), accepted);
        counts.role_masking += 1;
    }
    let bounded = config_with(|limits| {
        limits.frame_bytes = 4;
        limits.message_bytes = 4;
        limits.total_buffered_bytes = 5;
    });
    for (retained, length, limit) in [
        (0, 5, LimitKind::FrameBytes),
        (2, 4, LimitKind::TotalBufferedBytes),
    ] {
        let error = FrameHeaderDecoder::decode_header(
            &bounded,
            Role::Client,
            retained,
            &header_bytes(true, 0x2, false, length),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            FailureKind::LimitExceeded {
                limit: actual,
                ..
            } if actual == limit
        ));
        counts.preallocation_cap += 1;
    }

    for key in [RFC_KEY, [0, 0, 0, 0], [0xff, 0x55, 0xaa, 0x11]] {
        for offset in 0..4 {
            for length in 0..=16usize {
                let original: Vec<u8> = (0..length)
                    .map(|index| (index as u8).wrapping_mul(17).wrapping_add(3))
                    .collect();
                let mut candidate = original.clone();
                apply_mask_in_place(&mut candidate, key, offset);
                for (index, (&actual, &before)) in candidate.iter().zip(&original).enumerate() {
                    assert_eq!(actual, before ^ key[(offset + index) % 4]);
                    counts.mask_equation += 1;
                }
                apply_mask_in_place(&mut candidate, key, offset);
                assert_eq!(candidate, original);
                counts.mask_involution += 1;
            }
        }
    }

    let stable = [
        counts.control_fin_and_length,
        counts.length_canonical_16,
        counts.length_canonical_64_high_bit_zero,
        counts.length_canonical_7,
        counts.preallocation_cap,
        counts.role_masking,
        counts.mask_equation,
        counts.mask_involution,
    ];
    assert_eq!(stable, [6, 6, 3, 126, 2, 4, 1_632, 204]);
    println!(
        "US012_ACTUAL_CODE_COUNTS control_fin_and_length={} length_canonical_16={} length_canonical_64_high_bit_zero={} length_canonical_7={} preallocation_cap={} role_masking={} mask_equation={} mask_involution={}",
        stable[0], stable[1], stable[2], stable[3], stable[4], stable[5], stable[6], stable[7]
    );
}

#[test]
fn us012_fuzz_seed_inventory_is_inert_and_hex_canonical() {
    let seeds = [
        (
            "canonical-7",
            include_str!("../fuzz-seeds/us012/canonical-7.hex"),
        ),
        (
            "canonical-16",
            include_str!("../fuzz-seeds/us012/canonical-16.hex"),
        ),
        (
            "canonical-64",
            include_str!("../fuzz-seeds/us012/canonical-64.hex"),
        ),
        ("rfc-mask", include_str!("../fuzz-seeds/us012/rfc-mask.hex")),
        ("rsv1", include_str!("../fuzz-seeds/us012/rsv1.hex")),
        ("rsv2", include_str!("../fuzz-seeds/us012/rsv2.hex")),
        ("rsv3", include_str!("../fuzz-seeds/us012/rsv3.hex")),
        (
            "reserved-opcode",
            include_str!("../fuzz-seeds/us012/reserved-opcode.hex"),
        ),
        (
            "fragmented-control",
            include_str!("../fuzz-seeds/us012/fragmented-control.hex"),
        ),
        (
            "oversized-control",
            include_str!("../fuzz-seeds/us012/oversized-control.hex"),
        ),
        (
            "noncanonical-16",
            include_str!("../fuzz-seeds/us012/noncanonical-16.hex"),
        ),
        (
            "noncanonical-64",
            include_str!("../fuzz-seeds/us012/noncanonical-64.hex"),
        ),
        (
            "high-bit-64",
            include_str!("../fuzz-seeds/us012/high-bit-64.hex"),
        ),
        (
            "wrong-mask-client",
            include_str!("../fuzz-seeds/us012/wrong-mask-client.hex"),
        ),
        (
            "wrong-mask-server",
            include_str!("../fuzz-seeds/us012/wrong-mask-server.hex"),
        ),
        (
            "partial-header-eof",
            include_str!("../fuzz-seeds/us012/partial-header-eof.hex"),
        ),
        (
            "partial-payload-eof",
            include_str!("../fuzz-seeds/us012/partial-payload-eof.hex"),
        ),
        (
            "frame-limit",
            include_str!("../fuzz-seeds/us012/frame-limit.hex"),
        ),
        (
            "total-limit",
            include_str!("../fuzz-seeds/us012/total-limit.hex"),
        ),
        (
            "event-limit",
            include_str!("../fuzz-seeds/us012/event-limit.hex"),
        ),
    ];
    assert_eq!(seeds.len(), 20);
    for (name, seed) in seeds {
        let hex = seed.trim_end();
        assert!(!hex.is_empty(), "{name}");
        assert_eq!(hex.len() % 2, 0, "{name}");
        assert!(
            hex.bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "{name}"
        );
    }

    let config = config_with(|_| {});
    for seed in [
        include_str!("../fuzz-seeds/us012/canonical-7.hex"),
        include_str!("../fuzz-seeds/us012/canonical-16.hex"),
        include_str!("../fuzz-seeds/us012/canonical-64.hex"),
    ] {
        assert!(matches!(
            FrameHeaderDecoder::decode_header(&config, Role::Client, 0, &decode_hex_seed(seed)),
            Ok(FrameHeaderDecode::Complete(_))
        ));
    }
    assert!(matches!(
        FrameHeaderDecoder::decode_header(
            &config,
            Role::Server,
            0,
            &decode_hex_seed(include_str!("../fuzz-seeds/us012/rfc-mask.hex"))
        ),
        Ok(FrameHeaderDecode::Complete(_))
    ));

    let direct_failures = [
        ("rsv1.hex", FrameFailure::ReservedBits, Role::Client),
        ("rsv2.hex", FrameFailure::ReservedBits, Role::Client),
        ("rsv3.hex", FrameFailure::ReservedBits, Role::Client),
        (
            "reserved-opcode.hex",
            FrameFailure::ReservedOpcode { opcode: 3 },
            Role::Client,
        ),
        (
            "fragmented-control.hex",
            FrameFailure::FragmentedControl {
                opcode: Opcode::Ping,
            },
            Role::Server,
        ),
        (
            "oversized-control.hex",
            FrameFailure::ControlPayloadTooLarge { length: 126 },
            Role::Server,
        ),
        (
            "noncanonical-16.hex",
            FrameFailure::NonCanonicalLength16 { length: 125 },
            Role::Client,
        ),
        (
            "noncanonical-64.hex",
            FrameFailure::NonCanonicalLength64 { length: 65_535 },
            Role::Client,
        ),
        (
            "high-bit-64.hex",
            FrameFailure::PayloadLengthHighBitSet,
            Role::Client,
        ),
        (
            "wrong-mask-client.hex",
            FrameFailure::IncorrectMasking {
                expected_masked: false,
                actual_masked: true,
            },
            Role::Client,
        ),
        (
            "wrong-mask-server.hex",
            FrameFailure::IncorrectMasking {
                expected_masked: true,
                actual_masked: false,
            },
            Role::Server,
        ),
    ];
    for (name, expected, role) in direct_failures {
        let seed = match name {
            "rsv1.hex" => include_str!("../fuzz-seeds/us012/rsv1.hex"),
            "rsv2.hex" => include_str!("../fuzz-seeds/us012/rsv2.hex"),
            "rsv3.hex" => include_str!("../fuzz-seeds/us012/rsv3.hex"),
            "reserved-opcode.hex" => {
                include_str!("../fuzz-seeds/us012/reserved-opcode.hex")
            }
            "fragmented-control.hex" => {
                include_str!("../fuzz-seeds/us012/fragmented-control.hex")
            }
            "oversized-control.hex" => {
                include_str!("../fuzz-seeds/us012/oversized-control.hex")
            }
            "noncanonical-16.hex" => {
                include_str!("../fuzz-seeds/us012/noncanonical-16.hex")
            }
            "noncanonical-64.hex" => {
                include_str!("../fuzz-seeds/us012/noncanonical-64.hex")
            }
            "high-bit-64.hex" => include_str!("../fuzz-seeds/us012/high-bit-64.hex"),
            "wrong-mask-client.hex" => {
                include_str!("../fuzz-seeds/us012/wrong-mask-client.hex")
            }
            "wrong-mask-server.hex" => {
                include_str!("../fuzz-seeds/us012/wrong-mask-server.hex")
            }
            _ => unreachable!(),
        };
        assert_eq!(
            FrameHeaderDecoder::decode_header(&config, role, 0, &decode_hex_seed(seed))
                .unwrap_err(),
            FailureKind::Frame(expected),
            "{name}"
        );
    }

    let partial_header =
        decode_hex_seed(include_str!("../fuzz-seeds/us012/partial-header-eof.hex"));
    assert!(matches!(
        FrameHeaderDecoder::decode_header(&config, Role::Client, 0, &partial_header),
        Ok(FrameHeaderDecode::Incomplete { .. })
    ));
    let partial_payload =
        decode_hex_seed(include_str!("../fuzz-seeds/us012/partial-payload-eof.hex"));
    let mut partial = open_core(Role::Server, config.clone());
    assert_eq!(
        partial
            .step(CoreInput::Transport(TransportBytes::new(&partial_payload)))
            .failure(),
        None
    );
    assert_eq!(
        partial
            .step(CoreInput::TransportEof)
            .failure()
            .map(|failure| &failure.kind),
        Some(&FailureKind::Frame(FrameFailure::UnexpectedEof))
    );

    let frame_bounded = config_with(|limits| {
        limits.frame_bytes = 1_024;
        limits.message_bytes = 1_024;
        limits.total_buffered_bytes = 1_024;
    });
    assert!(matches!(
        FrameHeaderDecoder::decode_header(
            &frame_bounded,
            Role::Server,
            0,
            &decode_hex_seed(include_str!("../fuzz-seeds/us012/frame-limit.hex"))
        ),
        Err(FailureKind::LimitExceeded {
            limit: LimitKind::FrameBytes,
            ..
        })
    ));

    let total_seed = decode_hex_seed(include_str!("../fuzz-seeds/us012/total-limit.hex"));
    let total_bounded = config_with(|limits| {
        limits.frame_bytes = 4;
        limits.message_bytes = 4;
        limits.total_buffered_bytes = 7;
    });
    assert!(matches!(
        FrameHeaderDecoder::decode_header(&total_bounded, Role::Server, 4, &total_seed[10..]),
        Err(FailureKind::LimitExceeded {
            limit: LimitKind::TotalBufferedBytes,
            ..
        })
    ));

    let event_seed = decode_hex_seed(include_str!("../fuzz-seeds/us012/event-limit.hex"));
    let event_bounded = config_with(|limits| limits.event_queue_entries = 1);
    let mut core = open_core(Role::Server, event_bounded);
    let result = core.step(CoreInput::Transport(TransportBytes::new(&event_seed)));
    assert_eq!(frames(&result).len(), 1);
    assert_eq!(
        result.failure().map(|failure| &failure.kind),
        Some(&FailureKind::Backpressure(QueueKind::Event))
    );
}
