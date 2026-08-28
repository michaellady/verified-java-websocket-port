#![forbid(unsafe_code)]

use websocket_core::{
    BinaryMessage, ClientRequestDescriptor, ConnectionConfig, ConnectionCore, ConnectionLimits,
    ConnectionState, CoreInput, CoreOutput, FailureKind, FrameEncoder, LimitKind, LocalCommand,
    Opcode, OutboundFrame, QueueKind, Role, SemanticEvent, TextMessage, TransportBytes,
    Utf8Failure,
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
            assert_eq!(
                core.step(CoreInput::Command(LocalCommand::StartClientHandshake {
                    descriptor,
                    nonce: *b"the sample nonce",
                }))
                .failure(),
                None
            );
            assert_eq!(
                core.step(CoreInput::Transport(TransportBytes::new(RFC_RESPONSE)))
                    .failure(),
                None
            );
        }
        Role::Server => {
            assert_eq!(
                core.step(CoreInput::Transport(TransportBytes::new(RFC_REQUEST)))
                    .failure(),
                None
            );
        }
    }
    assert_eq!(core.state(), ConnectionState::Open);
    core
}

fn encoded(
    outbound_role: Role,
    config: &ConnectionConfig,
    fin: bool,
    opcode: Opcode,
    payload: &[u8],
) -> Vec<u8> {
    FrameEncoder::new(config.clone(), outbound_role)
        .encode(
            OutboundFrame::new(fin, opcode, payload),
            (outbound_role == Role::Client).then_some(RFC_KEY),
        )
        .expect("valid frame encodes")
        .as_slice()
        .to_vec()
}

fn text_event(event: &SemanticEvent) -> Option<&TextMessage> {
    match event {
        SemanticEvent::Text { message } => Some(message),
        _ => None,
    }
}

fn binary_event(event: &SemanticEvent) -> Option<&BinaryMessage> {
    match event {
        SemanticEvent::Binary { message } => Some(message),
        _ => None,
    }
}

fn decode_hex_seed(hex: &str) -> Vec<u8> {
    fn nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("seed is not canonical lowercase hex"),
        }
    }

    let bytes = hex.trim_end().as_bytes();
    assert_eq!(bytes.len() % 2, 0, "seed hex must contain complete octets");
    bytes
        .chunks_exact(2)
        .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
        .collect()
}

#[test]
fn utf8_above_unicode_max_has_its_exact_failure_class() {
    let config = config_with(|_| {});
    let mut core = open_core(Role::Server, config.clone());
    let wire = encoded(
        Role::Client,
        &config,
        true,
        Opcode::Text,
        &[0xf4, 0x90, 0x80, 0x80],
    );
    let result = core.step(CoreInput::Transport(TransportBytes::new(&wire)));
    assert_eq!(
        result.failure().map(|failure| &failure.kind),
        Some(&FailureKind::Utf8(Utf8Failure::CodePointOutOfRange {
            offset: 0,
        }))
    );
}

#[test]
fn utf8_noncontinuation_after_f4_is_not_relabeled_as_a_unicode_range_error() {
    let config = config_with(|_| {});
    let mut core = open_core(Role::Server, config.clone());
    let wire = encoded(
        Role::Client,
        &config,
        true,
        Opcode::Text,
        &[0xf4, 0xc0, 0x80, 0x80],
    );
    let result = core.step(CoreInput::Transport(TransportBytes::new(&wire)));
    assert_eq!(
        result.failure().map(|failure| &failure.kind),
        Some(&FailureKind::Utf8(Utf8Failure::InvalidContinuation {
            offset: 1,
            byte: 0xc0,
        }))
    );
}

#[test]
fn completed_fragment_delivery_counts_against_later_frames_in_one_batch() {
    let config = config_with(|limits| {
        limits.frame_bytes = 5;
        limits.message_bytes = 3;
        limits.total_buffered_bytes = 5;
    });
    let wire_config = config_with(|_| {});
    let mut core = open_core(Role::Server, config.clone());
    let start = encoded(Role::Client, &wire_config, false, Opcode::Text, b"ab");
    assert_eq!(
        core.step(CoreInput::Transport(TransportBytes::new(&start)))
            .failure(),
        None
    );

    let final_fragment = encoded(Role::Client, &wire_config, true, Opcode::Continuation, b"c");
    let later = encoded(Role::Client, &wire_config, true, Opcode::Binary, &[1, 2]);
    let mut coalesced = final_fragment;
    coalesced.extend_from_slice(&later);
    let result = core.step(CoreInput::Transport(TransportBytes::new(&coalesced)));
    assert_eq!(
        result.failure().map(|failure| &failure.kind),
        Some(&FailureKind::LimitExceeded {
            limit: LimitKind::TotalBufferedBytes,
            attempted: 6,
            maximum: 5,
        })
    );
    assert!(result.outputs().any(|output| matches!(
        output,
        CoreOutput::SemanticEvent(SemanticEvent::Text { message }) if message.as_str() == "abc"
    )));
}

#[test]
fn final_text_emits_frame_then_text_with_one_shared_payload() {
    let config = config_with(|_| {});
    let wire = encoded(
        Role::Client,
        &config,
        true,
        Opcode::Text,
        "hi 🦀".as_bytes(),
    );
    let mut core = open_core(Role::Server, config);

    let result = core.step(CoreInput::Transport(TransportBytes::new(&wire)));

    assert_eq!(result.failure(), None);
    assert_eq!(result.outputs().len(), 2);
    let outputs: Vec<_> = result.outputs().collect();
    let CoreOutput::SemanticEvent(SemanticEvent::FrameReceived { frame }) = outputs[0] else {
        panic!("first output must be the frame observation");
    };
    let CoreOutput::SemanticEvent(event) = outputs[1] else {
        panic!("second output must be the text observation");
    };
    let message = text_event(event).expect("second event is typed text");
    assert_eq!(frame.payload(), "hi 🦀".as_bytes());
    assert_eq!(message.as_str(), "hi 🦀");
    assert_eq!(message.as_bytes(), frame.payload());
    assert!(core::ptr::eq(
        message.as_bytes().as_ptr(),
        frame.payload().as_ptr()
    ));
}

#[test]
fn final_binary_preserves_every_octet_and_shares_the_frame_payload() {
    let config = config_with(|_| {});
    let payload: Vec<u8> = (0..=u8::MAX).collect();
    let wire = encoded(Role::Server, &config, true, Opcode::Binary, &payload);
    let mut core = open_core(Role::Client, config);

    let result = core.step(CoreInput::Transport(TransportBytes::new(&wire)));

    assert_eq!(result.failure(), None);
    let outputs: Vec<_> = result.outputs().collect();
    let CoreOutput::SemanticEvent(SemanticEvent::FrameReceived { frame }) = outputs[0] else {
        panic!("first output must be the frame observation");
    };
    let CoreOutput::SemanticEvent(event) = outputs[1] else {
        panic!("second output must be the binary observation");
    };
    let message = binary_event(event).expect("second event is typed binary");
    assert_eq!(message.as_slice(), payload);
    assert!(core::ptr::eq(
        message.as_slice().as_ptr(),
        frame.payload().as_ptr()
    ));
}

#[test]
fn payload_owner_keeps_the_reserved_vec_backing_and_shares_one_pointer() {
    let decoder_source = include_str!("../src/frame/decode.rs");
    let frame_source = include_str!("../src/frame/mod.rs");

    assert!(
        frame_source.contains("payload: Arc<Vec<u8>>"),
        "the shared owner must retain the decoder's reserved Vec backing"
    );
    assert!(
        decoder_source.contains("let payload = Arc::new(payload);"),
        "completion must move the reserved Vec directly into the shared owner"
    );
    assert!(
        !decoder_source.contains("Arc<[u8]>"),
        "slice conversion would allocate and copy the payload a second time"
    );
}

fn assert_text_pair(result: &websocket_core::StepResult, expected: &str) {
    assert_eq!(result.failure(), None);
    let outputs: Vec<_> = result.outputs().collect();
    assert_eq!(outputs.len(), 2);
    let CoreOutput::SemanticEvent(SemanticEvent::FrameReceived { frame }) = outputs[0] else {
        panic!("first output must be the frame observation");
    };
    let CoreOutput::SemanticEvent(SemanticEvent::Text { message }) = outputs[1] else {
        panic!("second output must be the text observation");
    };
    assert_eq!(frame.payload(), expected.as_bytes());
    assert_eq!(message.as_str(), expected);
}

#[test]
fn canonical_utf8_survives_every_transport_cut_masking_and_empty_chunks() {
    let config = config_with(|_| {});
    let text = "\0\u{7f}\u{80}\u{7ff}\u{800}\u{d7ff}\u{e000}\u{ffff}\u{10000}\u{10ffff}";

    for outbound_role in [Role::Client, Role::Server] {
        let inbound_role = match outbound_role {
            Role::Client => Role::Server,
            Role::Server => Role::Client,
        };
        let wire = encoded(outbound_role, &config, true, Opcode::Text, text.as_bytes());
        for split in 0..=wire.len() {
            let mut core = open_core(inbound_role, config.clone());
            let first = core.step(CoreInput::Transport(TransportBytes::new(&wire[..split])));
            assert_eq!(
                first.failure(),
                None,
                "role={outbound_role:?} split={split}"
            );
            let empty = core.step(CoreInput::Transport(TransportBytes::new(&[])));
            assert_eq!(
                empty.failure(),
                None,
                "role={outbound_role:?} split={split}"
            );
            let last = core.step(CoreInput::Transport(TransportBytes::new(&wire[split..])));
            let completed = if last.outputs().len() == 0 {
                &first
            } else {
                &last
            };
            assert_text_pair(completed, text);
        }

        let mut core = open_core(inbound_role, config.clone());
        let mut completed = None;
        for byte in &wire {
            let result = core.step(CoreInput::Transport(TransportBytes::new(
                core::slice::from_ref(byte),
            )));
            assert_eq!(result.failure(), None);
            if result.outputs().len() != 0 {
                completed = Some(result);
            }
        }
        assert_text_pair(&completed.expect("one-byte feeding completes"), text);
    }
}

#[test]
fn sampled_unicode_scalar_property_matches_the_standard_string_invariant() {
    let sampled: String = (0..=0x10ffff)
        .step_by(251)
        .filter_map(char::from_u32)
        .collect();
    assert!(sampled.chars().count() > 4_000);
    let config = config_with(|_| {});

    for outbound_role in [Role::Client, Role::Server] {
        let inbound_role = match outbound_role {
            Role::Client => Role::Server,
            Role::Server => Role::Client,
        };
        let wire = encoded(
            outbound_role,
            &config,
            true,
            Opcode::Text,
            sampled.as_bytes(),
        );
        let result = open_core(inbound_role, config.clone())
            .step(CoreInput::Transport(TransportBytes::new(&wire)));
        assert_text_pair(&result, &sampled);
    }
}

#[test]
fn strict_utf8_failures_are_typed_stable_and_emit_no_offending_frame() {
    let cases: &[(&[u8], Utf8Failure)] = &[
        (
            &[0x80],
            Utf8Failure::UnexpectedContinuation {
                offset: 0,
                byte: 0x80,
            },
        ),
        (&[0xc0, 0x80], Utf8Failure::OverlongEncoding { offset: 0 }),
        (
            &[0xf8],
            Utf8Failure::InvalidLeadingByte {
                offset: 0,
                byte: 0xf8,
            },
        ),
        (
            &[0xc2, b' '],
            Utf8Failure::InvalidContinuation {
                offset: 1,
                byte: b' ',
            },
        ),
        (
            &[0xe0, b' ', 0x80],
            Utf8Failure::InvalidContinuation {
                offset: 1,
                byte: b' ',
            },
        ),
        (
            &[0xed, 0xff, 0x80],
            Utf8Failure::InvalidContinuation {
                offset: 1,
                byte: 0xff,
            },
        ),
        (
            &[0xe0, 0x80, 0x80],
            Utf8Failure::OverlongEncoding { offset: 0 },
        ),
        (
            &[0xed, 0xa0, 0x80],
            Utf8Failure::SurrogateCodePoint { offset: 0 },
        ),
        (
            &[0xf4, 0x90, 0x80, 0x80],
            Utf8Failure::CodePointOutOfRange { offset: 0 },
        ),
        (
            &[0xc2],
            Utf8Failure::TruncatedSequence {
                length: 1,
                remaining: 1,
            },
        ),
        (
            &[0xe1, 0x80],
            Utf8Failure::TruncatedSequence {
                length: 2,
                remaining: 1,
            },
        ),
        (
            &[0xf0, 0x90, 0x80],
            Utf8Failure::TruncatedSequence {
                length: 3,
                remaining: 1,
            },
        ),
    ];
    let config = config_with(|_| {});

    for (payload, expected) in cases {
        for outbound_role in [Role::Client, Role::Server] {
            let inbound_role = match outbound_role {
                Role::Client => Role::Server,
                Role::Server => Role::Client,
            };
            let wire = encoded(outbound_role, &config, true, Opcode::Text, payload);
            for split in 0..=wire.len() {
                let mut core = open_core(inbound_role, config.clone());
                let first = core.step(CoreInput::Transport(TransportBytes::new(&wire[..split])));
                let last = if first.failure().is_some() {
                    first
                } else {
                    core.step(CoreInput::Transport(TransportBytes::new(&wire[split..])))
                };
                assert_eq!(
                    last.failure().map(|failure| &failure.kind),
                    Some(&FailureKind::Utf8(expected.clone())),
                    "payload={payload:02x?} role={outbound_role:?} split={split}"
                );
                assert_eq!(last.state(), ConnectionState::Closed);
                assert_eq!(
                    last.outputs().collect::<Vec<_>>(),
                    vec![&CoreOutput::StateChanged(ConnectionState::Closed)]
                );
            }
        }
    }
}

#[test]
fn several_frames_repeat_pairs_and_later_utf8_failure_preserves_prior_pairs() {
    let config = config_with(|_| {});
    let mut valid = encoded(Role::Client, &config, true, Opcode::Text, b"first");
    valid.extend_from_slice(&encoded(
        Role::Client,
        &config,
        true,
        Opcode::Binary,
        b"second",
    ));
    let mut core = open_core(Role::Server, config.clone());
    let result = core.step(CoreInput::Transport(TransportBytes::new(&valid)));
    assert_eq!(result.failure(), None);
    let outputs: Vec<_> = result.outputs().collect();
    assert_eq!(outputs.len(), 4);
    assert!(matches!(
        outputs.as_slice(),
        [
            CoreOutput::SemanticEvent(SemanticEvent::FrameReceived { .. }),
            CoreOutput::SemanticEvent(SemanticEvent::Text { .. }),
            CoreOutput::SemanticEvent(SemanticEvent::FrameReceived { .. }),
            CoreOutput::SemanticEvent(SemanticEvent::Binary { .. })
        ]
    ));

    valid.extend_from_slice(&encoded(Role::Client, &config, true, Opcode::Text, &[0x80]));
    let mut core = open_core(Role::Server, config);
    let result = core.step(CoreInput::Transport(TransportBytes::new(&valid)));
    assert_eq!(
        result.failure().map(|failure| &failure.kind),
        Some(&FailureKind::Utf8(Utf8Failure::UnexpectedContinuation {
            offset: 0,
            byte: 0x80,
        }))
    );
    let outputs: Vec<_> = result.outputs().collect();
    assert_eq!(outputs.len(), 5);
    assert!(matches!(
        outputs.as_slice(),
        [
            CoreOutput::SemanticEvent(SemanticEvent::FrameReceived { .. }),
            CoreOutput::SemanticEvent(SemanticEvent::Text { .. }),
            CoreOutput::SemanticEvent(SemanticEvent::FrameReceived { .. }),
            CoreOutput::SemanticEvent(SemanticEvent::Binary { .. }),
            CoreOutput::StateChanged(ConnectionState::Closed)
        ]
    ));
}

#[test]
fn message_event_and_total_limits_admit_exact_boundaries_and_reject_plus_one() {
    let message_config = config_with(|limits| {
        limits.frame_bytes = 4;
        limits.message_bytes = 3;
        limits.total_buffered_bytes = 4;
    });
    let exact = encoded(
        Role::Server,
        &config_with(|_| {}),
        true,
        Opcode::Binary,
        b"123",
    );
    assert_eq!(
        open_core(Role::Client, message_config.clone())
            .step(CoreInput::Transport(TransportBytes::new(&exact)))
            .failure(),
        None
    );
    let over = encoded(
        Role::Server,
        &config_with(|_| {}),
        true,
        Opcode::Binary,
        b"1234",
    );
    let result = open_core(Role::Client, message_config)
        .step(CoreInput::Transport(TransportBytes::new(&over)));
    assert_eq!(
        result.failure().map(|failure| &failure.kind),
        Some(&FailureKind::LimitExceeded {
            limit: LimitKind::MessageBytes,
            attempted: 4,
            maximum: 3,
        })
    );

    let one_event = config_with(|limits| limits.event_queue_entries = 1);
    let wire = encoded(Role::Server, &one_event, true, Opcode::Text, b"");
    let result =
        open_core(Role::Client, one_event).step(CoreInput::Transport(TransportBytes::new(&wire)));
    assert_eq!(
        result.failure().map(|failure| &failure.kind),
        Some(&FailureKind::Backpressure(QueueKind::Event))
    );

    let exact_events = config_with(|limits| limits.event_queue_entries = 2);
    let wire = encoded(Role::Server, &exact_events, true, Opcode::Text, b"");
    let result = open_core(Role::Client, exact_events)
        .step(CoreInput::Transport(TransportBytes::new(&wire)));
    assert_text_pair(&result, "");

    let total_config = config_with(|limits| {
        limits.frame_bytes = 8;
        limits.message_bytes = 8;
        limits.total_buffered_bytes = 8;
        limits.event_queue_entries = 4;
    });
    let mut exact = encoded(Role::Server, &total_config, true, Opcode::Binary, b"1234");
    exact.extend_from_slice(&encoded(
        Role::Server,
        &total_config,
        true,
        Opcode::Binary,
        b"5678",
    ));
    let result = open_core(Role::Client, total_config.clone())
        .step(CoreInput::Transport(TransportBytes::new(&exact)));
    assert_eq!(result.failure(), None);
    assert_eq!(result.outputs().len(), 4);

    let mut over = exact;
    over.truncate(6);
    over.extend_from_slice(&encoded(
        Role::Server,
        &total_config,
        true,
        Opcode::Binary,
        b"56789",
    ));
    let result = open_core(Role::Client, total_config)
        .step(CoreInput::Transport(TransportBytes::new(&over)));
    assert_eq!(
        result.failure().map(|failure| &failure.kind),
        Some(&FailureKind::LimitExceeded {
            limit: LimitKind::TotalBufferedBytes,
            attempted: 9,
            maximum: 8,
        })
    );
    assert_eq!(result.outputs().len(), 3);

    let mixed_exact = config_with(|limits| limits.event_queue_entries = 4);
    let mut mixed = encoded(Role::Server, &mixed_exact, true, Opcode::Ping, b"");
    mixed.extend_from_slice(&encoded(
        Role::Server,
        &mixed_exact,
        true,
        Opcode::Text,
        b"x",
    ));
    let result = open_core(Role::Client, mixed_exact)
        .step(CoreInput::Transport(TransportBytes::new(&mixed)));
    assert_eq!(result.failure(), None);
    assert_eq!(result.outputs().len(), 4);

    let mixed_over = config_with(|limits| limits.event_queue_entries = 3);
    let result =
        open_core(Role::Client, mixed_over).step(CoreInput::Transport(TransportBytes::new(&mixed)));
    assert_eq!(
        result.failure().map(|failure| &failure.kind),
        Some(&FailureKind::Backpressure(QueueKind::Event))
    );
    assert_eq!(result.outputs().len(), 3);
}

#[test]
fn nonfinal_data_starts_remain_frame_only_and_outbound_message_commands_emit_final_frames() {
    let config = config_with(|_| {});
    let fragments = [
        (false, Opcode::Text, &[0xf0, 0x90][..]),
        (false, Opcode::Binary, b"binary".as_slice()),
    ];
    for (fin, opcode, payload) in fragments {
        let wire = encoded(Role::Server, &config, fin, opcode, payload);
        let result = open_core(Role::Client, config.clone())
            .step(CoreInput::Transport(TransportBytes::new(&wire)));
        assert_eq!(result.failure(), None);
        assert!(matches!(
            result.outputs().collect::<Vec<_>>().as_slice(),
            [CoreOutput::SemanticEvent(
                SemanticEvent::FrameReceived { .. }
            )]
        ));
    }

    let mut core = open_core(Role::Client, config);
    for command in [
        LocalCommand::SendText {
            payload: "now available".into(),
            mask_key: Some(RFC_KEY),
        },
        LocalCommand::SendBinary {
            payload: vec![1, 2, 3].into_boxed_slice(),
            mask_key: Some(RFC_KEY),
        },
    ] {
        let result = core.step(CoreInput::Command(command));
        assert_eq!(result.outputs().len(), 1);
        assert_eq!(result.state(), ConnectionState::Open);
        assert_eq!(result.failure(), None);
    }
}

#[test]
fn us013_seed_inventory_is_canonical_executable_and_inert() {
    let seeds = [
        include_str!("../fuzz-seeds/us013/valid-empty-text.hex"),
        include_str!("../fuzz-seeds/us013/valid-ascii.hex"),
        include_str!("../fuzz-seeds/us013/valid-two-byte.hex"),
        include_str!("../fuzz-seeds/us013/valid-three-byte.hex"),
        include_str!("../fuzz-seeds/us013/valid-four-byte.hex"),
        include_str!("../fuzz-seeds/us013/valid-binary.hex"),
        include_str!("../fuzz-seeds/us013/unexpected-continuation.hex"),
        include_str!("../fuzz-seeds/us013/overlong-two-c0.hex"),
        include_str!("../fuzz-seeds/us013/overlong-two-c1.hex"),
        include_str!("../fuzz-seeds/us013/invalid-leading.hex"),
        include_str!("../fuzz-seeds/us013/invalid-continuation.hex"),
        include_str!("../fuzz-seeds/us013/overlong-three.hex"),
        include_str!("../fuzz-seeds/us013/overlong-four.hex"),
        include_str!("../fuzz-seeds/us013/surrogate.hex"),
        include_str!("../fuzz-seeds/us013/out-of-range.hex"),
        include_str!("../fuzz-seeds/us013/truncated-two.hex"),
        include_str!("../fuzz-seeds/us013/truncated-three.hex"),
        include_str!("../fuzz-seeds/us013/truncated-four.hex"),
        include_str!("../fuzz-seeds/us013/prior-valid-then-invalid.hex"),
        include_str!("../fuzz-seeds/us013/nonfinal-prefix.hex"),
    ];
    assert_eq!(seeds.len(), 20);
    let config = config_with(|_| {});

    for (index, seed) in seeds.into_iter().enumerate() {
        assert_eq!(seed.trim_end().len() % 2, 0, "seed={index}");
        assert!(
            seed.trim_end()
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "seed={index}"
        );
        let wire = decode_hex_seed(seed);
        let result = open_core(Role::Client, config.clone())
            .step(CoreInput::Transport(TransportBytes::new(&wire)));
        match index {
            0..=5 => {
                assert_eq!(result.failure(), None, "seed={index}");
                assert_eq!(result.outputs().len(), 2, "seed={index}");
            }
            6..=17 => {
                assert!(
                    matches!(
                        result.failure().map(|failure| &failure.kind),
                        Some(FailureKind::Utf8(_))
                    ),
                    "seed={index}"
                );
            }
            18 => {
                assert!(matches!(
                    result.failure().map(|failure| &failure.kind),
                    Some(FailureKind::Utf8(_))
                ));
                assert_eq!(result.outputs().len(), 3);
            }
            19 => {
                assert_eq!(result.failure(), None);
                assert_eq!(result.outputs().len(), 1);
            }
            _ => unreachable!(),
        }
    }
}
