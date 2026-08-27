#![forbid(unsafe_code)]

use websocket_core::{
    ClientRequestDescriptor, ConnectionConfig, ConnectionCore, ConnectionLimits, ConnectionState,
    CoreInput, CoreOutput, FailureKind, FragmentFailure, FrameEncoder, LimitKind, LocalCommand,
    Opcode, OutboundFrame, QueueKind, Role, SemanticEvent, TransportBytes, Utf8Failure,
};

const RFC_REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
const RFC_RESPONSE: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
const MASK: [u8; 4] = [0x37, 0xfa, 0x21, 0x3d];

fn config_with(mut change: impl FnMut(&mut ConnectionLimits)) -> ConnectionConfig {
    let mut limits = ConnectionLimits::default();
    change(&mut limits);
    ConnectionConfig::try_from(limits).expect("test limits are valid")
}

fn feed_one_byte_at_a_time(core: &mut ConnectionCore, wire: &[u8]) -> Vec<CoreOutput> {
    let mut outputs = Vec::new();
    for byte in wire {
        let result = core.step(CoreInput::Transport(TransportBytes::new(
            core::slice::from_ref(byte),
        )));
        assert_eq!(result.failure(), None);
        outputs.extend(result.outputs().cloned());
    }
    outputs
}

fn frame_payloads(outputs: &[CoreOutput]) -> Vec<&[u8]> {
    outputs
        .iter()
        .filter_map(|output| match output {
            CoreOutput::SemanticEvent(SemanticEvent::FrameReceived { frame }) => {
                Some(frame.payload())
            }
            _ => None,
        })
        .collect()
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
            (outbound_role == Role::Client).then_some(MASK),
        )
        .expect("valid frame encodes")
        .as_slice()
        .to_vec()
}

#[test]
fn fragmented_text_emits_each_frame_then_one_complete_message() {
    let config = config_with(|_| {});
    let mut wire = encoded(Role::Client, &config, false, Opcode::Text, b"hel");
    wire.extend_from_slice(&encoded(
        Role::Client,
        &config,
        false,
        Opcode::Continuation,
        b"lo ",
    ));
    wire.extend_from_slice(&encoded(
        Role::Client,
        &config,
        true,
        Opcode::Continuation,
        "🦀".as_bytes(),
    ));

    let result =
        open_core(Role::Server, config).step(CoreInput::Transport(TransportBytes::new(&wire)));

    assert_eq!(result.failure(), None);
    let outputs: Vec<_> = result.outputs().collect();
    assert!(matches!(
        outputs.as_slice(),
        [
            CoreOutput::SemanticEvent(SemanticEvent::FrameReceived { .. }),
            CoreOutput::SemanticEvent(SemanticEvent::FrameReceived { .. }),
            CoreOutput::SemanticEvent(SemanticEvent::FrameReceived { .. }),
            CoreOutput::SemanticEvent(SemanticEvent::Text { message }),
        ] if message.as_str() == "hello 🦀"
    ));
}

#[test]
fn orphan_continuation_is_stable_terminal_failure_without_frame_event() {
    let config = config_with(|_| {});
    let wire = encoded(Role::Server, &config, true, Opcode::Continuation, b"orphan");
    let result =
        open_core(Role::Client, config).step(CoreInput::Transport(TransportBytes::new(&wire)));

    assert_eq!(
        result.failure().map(|failure| &failure.kind),
        Some(&FailureKind::Fragment(
            FragmentFailure::ContinuationWithoutMessage
        ))
    );
    assert_eq!(
        result.outputs().collect::<Vec<_>>(),
        vec![&CoreOutput::StateChanged(ConnectionState::Closed)]
    );
}

#[test]
fn binary_and_empty_fragments_preserve_octets_and_deliver_exactly_once() {
    let config = config_with(|_| {});
    let mut wire = encoded(Role::Server, &config, false, Opcode::Binary, b"");
    wire.extend_from_slice(&encoded(
        Role::Server,
        &config,
        false,
        Opcode::Continuation,
        &[0, 1, 0xff],
    ));
    wire.extend_from_slice(&encoded(
        Role::Server,
        &config,
        true,
        Opcode::Continuation,
        b"",
    ));
    wire.extend_from_slice(&encoded(Role::Server, &config, false, Opcode::Text, b""));
    wire.extend_from_slice(&encoded(
        Role::Server,
        &config,
        true,
        Opcode::Continuation,
        b"",
    ));

    let result =
        open_core(Role::Client, config).step(CoreInput::Transport(TransportBytes::new(&wire)));
    assert_eq!(result.failure(), None);
    let outputs: Vec<_> = result.outputs().collect();
    assert_eq!(outputs.len(), 7);
    assert!(matches!(
        outputs[3],
        CoreOutput::SemanticEvent(SemanticEvent::Binary { message })
            if message.as_slice() == [0, 1, 0xff]
    ));
    assert!(matches!(
        outputs[6],
        CoreOutput::SemanticEvent(SemanticEvent::Text { message })
            if message.as_str().is_empty()
    ));
}

#[test]
fn utf8_scalar_crosses_every_fragment_boundary_under_one_byte_transport_feeds() {
    let config = config_with(|_| {});
    let scalar = "🦀".as_bytes();
    for cut in 0..=scalar.len() {
        for outbound_role in [Role::Client, Role::Server] {
            let inbound_role = match outbound_role {
                Role::Client => Role::Server,
                Role::Server => Role::Client,
            };
            let mut wire = encoded(outbound_role, &config, false, Opcode::Text, &scalar[..cut]);
            wire.extend_from_slice(&encoded(
                outbound_role,
                &config,
                true,
                Opcode::Continuation,
                &scalar[cut..],
            ));
            let mut core = open_core(inbound_role, config.clone());
            let outputs = feed_one_byte_at_a_time(&mut core, &wire);
            assert_eq!(outputs.len(), 3, "role={outbound_role:?} cut={cut}");
            assert!(matches!(
                outputs.last(),
                Some(CoreOutput::SemanticEvent(SemanticEvent::Text { message }))
                    if message.as_str() == "🦀"
            ));
        }
    }
}

#[test]
fn controls_are_observed_and_do_not_disturb_active_text_or_order() {
    let config = config_with(|_| {});
    let mut wire = encoded(Role::Server, &config, false, Opcode::Text, b"a");
    for (opcode, payload) in [
        (Opcode::Ping, b"p".as_slice()),
        (Opcode::Pong, b"q".as_slice()),
        (Opcode::Close, b"".as_slice()),
    ] {
        wire.extend_from_slice(&encoded(Role::Server, &config, true, opcode, payload));
    }
    wire.extend_from_slice(&encoded(
        Role::Server,
        &config,
        true,
        Opcode::Continuation,
        b"b",
    ));

    let result =
        open_core(Role::Client, config).step(CoreInput::Transport(TransportBytes::new(&wire)));
    assert_eq!(result.failure(), None);
    let outputs: Vec<_> = result.outputs().cloned().collect();
    assert_eq!(
        frame_payloads(&outputs),
        [
            b"a".as_slice(),
            b"p".as_slice(),
            b"q".as_slice(),
            b"".as_slice(),
            b"b".as_slice(),
        ]
    );
    assert!(matches!(
        outputs[2],
        CoreOutput::SemanticEvent(SemanticEvent::Ping { ref payload })
            if payload.as_slice() == b"p"
    ));
    assert!(matches!(
        outputs[4],
        CoreOutput::SemanticEvent(SemanticEvent::Pong { ref payload })
            if payload.as_slice() == b"q"
    ));
    assert!(matches!(
        outputs.last(),
        Some(CoreOutput::SemanticEvent(SemanticEvent::Text { message }))
            if message.as_str() == "ab"
    ));
}

#[test]
fn new_data_during_active_message_is_typed_and_preserves_only_valid_prefix() {
    for active in [Opcode::Text, Opcode::Binary] {
        for received in [Opcode::Text, Opcode::Binary] {
            for fin in [false, true] {
                let config = config_with(|_| {});
                let mut wire = encoded(Role::Server, &config, false, active, b"kept");
                wire.extend_from_slice(&encoded(
                    Role::Server,
                    &config,
                    fin,
                    received,
                    b"offending",
                ));
                let result = open_core(Role::Client, config)
                    .step(CoreInput::Transport(TransportBytes::new(&wire)));
                assert_eq!(
                    result.failure().map(|failure| &failure.kind),
                    Some(&FailureKind::Fragment(
                        FragmentFailure::DataFrameWhileFragmented { active, received }
                    ))
                );
                let outputs: Vec<_> = result.outputs().collect();
                assert!(matches!(
                    outputs.as_slice(),
                    [
                        CoreOutput::SemanticEvent(SemanticEvent::FrameReceived { frame }),
                        CoreOutput::StateChanged(ConnectionState::Closed),
                    ] if frame.payload() == b"kept"
                ));
            }
        }
    }
}

#[test]
fn fragmented_text_utf8_failures_use_global_offsets_and_hide_offending_frames() {
    let config = config_with(|_| {});
    let cases: &[(&[u8], &[u8], bool, Utf8Failure)] = &[
        (
            b"a",
            &[0x80],
            false,
            Utf8Failure::UnexpectedContinuation {
                offset: 1,
                byte: 0x80,
            },
        ),
        (
            &[0xf0],
            b"",
            true,
            Utf8Failure::TruncatedSequence {
                length: 1,
                remaining: 3,
            },
        ),
    ];
    for (initial, continuation, final_frame, expected) in cases {
        let mut wire = encoded(Role::Server, &config, false, Opcode::Text, initial);
        wire.extend_from_slice(&encoded(
            Role::Server,
            &config,
            *final_frame,
            Opcode::Continuation,
            continuation,
        ));
        let result = open_core(Role::Client, config.clone())
            .step(CoreInput::Transport(TransportBytes::new(&wire)));
        assert_eq!(
            result.failure().map(|failure| &failure.kind),
            Some(&FailureKind::Utf8(expected.clone()))
        );
        assert_eq!(result.outputs().len(), 2);
        assert!(matches!(
            result.outputs().last(),
            Some(CoreOutput::StateChanged(ConnectionState::Closed))
        ));
    }
}

#[test]
fn accumulated_message_limit_admits_exact_and_rejects_plus_one_before_frame_event() {
    let exact = config_with(|limits| {
        limits.frame_bytes = 4;
        limits.message_bytes = 4;
        limits.total_buffered_bytes = 8;
    });
    let mut exact_wire = encoded(Role::Server, &exact, false, Opcode::Binary, b"ab");
    exact_wire.extend_from_slice(&encoded(
        Role::Server,
        &exact,
        true,
        Opcode::Continuation,
        b"cd",
    ));
    let exact_result =
        open_core(Role::Client, exact).step(CoreInput::Transport(TransportBytes::new(&exact_wire)));
    assert_eq!(exact_result.failure(), None);
    assert_eq!(exact_result.outputs().len(), 3);

    let over = config_with(|limits| {
        limits.frame_bytes = 4;
        limits.message_bytes = 3;
        limits.total_buffered_bytes = 8;
    });
    let mut over_wire = encoded(Role::Server, &over, false, Opcode::Binary, b"ab");
    over_wire.extend_from_slice(&encoded(
        Role::Server,
        &over,
        true,
        Opcode::Continuation,
        b"cd",
    ));
    let over_result =
        open_core(Role::Client, over).step(CoreInput::Transport(TransportBytes::new(&over_wire)));
    assert_eq!(
        over_result.failure().map(|failure| &failure.kind),
        Some(&FailureKind::LimitExceeded {
            limit: LimitKind::MessageBytes,
            attempted: 4,
            maximum: 3,
        })
    );
    assert_eq!(over_result.outputs().len(), 2);
}

#[test]
fn duplicate_retention_and_event_limits_admit_exact_and_reject_plus_one() {
    for total in [8, 7] {
        let config = config_with(|limits| {
            limits.frame_bytes = total;
            limits.message_bytes = total;
            limits.total_buffered_bytes = total;
        });
        let mut wire = encoded(Role::Server, &config, false, Opcode::Binary, b"ab");
        wire.extend_from_slice(&encoded(
            Role::Server,
            &config,
            true,
            Opcode::Continuation,
            b"cd",
        ));
        let result =
            open_core(Role::Client, config).step(CoreInput::Transport(TransportBytes::new(&wire)));
        if total == 8 {
            assert_eq!(result.failure(), None);
        } else {
            assert_eq!(
                result.failure().map(|failure| &failure.kind),
                Some(&FailureKind::LimitExceeded {
                    limit: LimitKind::TotalBufferedBytes,
                    attempted: 8,
                    maximum: 7,
                })
            );
            assert_eq!(result.outputs().len(), 2);
        }
    }

    for entries in [3, 2] {
        let config = config_with(|limits| limits.event_queue_entries = entries);
        let mut wire = encoded(Role::Server, &config, false, Opcode::Binary, b"a");
        wire.extend_from_slice(&encoded(
            Role::Server,
            &config,
            true,
            Opcode::Continuation,
            b"b",
        ));
        let result =
            open_core(Role::Client, config).step(CoreInput::Transport(TransportBytes::new(&wire)));
        if entries == 3 {
            assert_eq!(result.failure(), None);
        } else {
            assert_eq!(
                result.failure().map(|failure| &failure.kind),
                Some(&FailureKind::Backpressure(QueueKind::Event))
            );
            assert_eq!(result.outputs().len(), 2);
        }
    }
}

#[test]
fn eof_precedence_distinguishes_partial_frame_from_between_fragment_frames() {
    let config = config_with(|_| {});
    let initial = encoded(Role::Server, &config, false, Opcode::Text, b"abc");

    let mut between = open_core(Role::Client, config.clone());
    assert_eq!(
        between
            .step(CoreInput::Transport(TransportBytes::new(&initial)))
            .failure(),
        None
    );
    let eof = between.step(CoreInput::TransportEof);
    assert_eq!(
        eof.failure().map(|failure| &failure.kind),
        Some(&FailureKind::Fragment(FragmentFailure::UnexpectedEof {
            active: Opcode::Text,
            accumulated: 3,
        }))
    );

    let continuation = encoded(Role::Server, &config, true, Opcode::Continuation, b"z");
    let mut partial = open_core(Role::Client, config);
    assert_eq!(
        partial
            .step(CoreInput::Transport(TransportBytes::new(&initial)))
            .failure(),
        None
    );
    assert_eq!(
        partial
            .step(CoreInput::Transport(TransportBytes::new(
                &continuation[..1]
            )))
            .failure(),
        None
    );
    let eof = partial.step(CoreInput::TransportEof);
    assert!(matches!(
        eof.failure().map(|failure| &failure.kind),
        Some(FailureKind::Frame(
            websocket_core::FrameFailure::UnexpectedEof
        ))
    ));
}

#[test]
fn successful_finish_clears_state_for_immediate_next_message() {
    let config = config_with(|_| {});
    let mut wire = encoded(Role::Server, &config, false, Opcode::Text, b"a");
    wire.extend_from_slice(&encoded(
        Role::Server,
        &config,
        true,
        Opcode::Continuation,
        b"b",
    ));
    wire.extend_from_slice(&encoded(Role::Server, &config, true, Opcode::Text, b"c"));
    let result =
        open_core(Role::Client, config).step(CoreInput::Transport(TransportBytes::new(&wire)));
    assert_eq!(result.failure(), None);
    let texts: Vec<_> = result
        .outputs()
        .filter_map(|output| match output {
            CoreOutput::SemanticEvent(SemanticEvent::Text { message }) => Some(message.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(texts, ["ab", "c"]);
}

#[test]
fn deterministic_segment_and_transport_schedule_property_preserves_byte_model() {
    let config = config_with(|_| {});
    let model = b"fragment-property-model";
    for continuation_count in 1..=5 {
        for outbound_role in [Role::Client, Role::Server] {
            let inbound_role = match outbound_role {
                Role::Client => Role::Server,
                Role::Server => Role::Client,
            };
            let mut wire = Vec::new();
            let mut start = 0usize;
            for index in 0..=continuation_count {
                let end = if index == continuation_count {
                    model.len()
                } else {
                    model.len() * (index + 1) / (continuation_count + 1)
                };
                wire.extend_from_slice(&encoded(
                    outbound_role,
                    &config,
                    index == continuation_count,
                    if index == 0 {
                        Opcode::Binary
                    } else {
                        Opcode::Continuation
                    },
                    &model[start..end],
                ));
                start = end;
            }
            for split in 0..=wire.len() {
                let mut core = open_core(inbound_role, config.clone());
                let first = core.step(CoreInput::Transport(TransportBytes::new(&wire[..split])));
                assert_eq!(first.failure(), None);
                let mut outputs: Vec<_> = first.outputs().cloned().collect();
                let second = core.step(CoreInput::Transport(TransportBytes::new(&wire[split..])));
                assert_eq!(second.failure(), None);
                outputs.extend(second.outputs().cloned());
                let delivered: Vec<_> = outputs
                    .iter()
                    .filter_map(|output| match output {
                        CoreOutput::SemanticEvent(SemanticEvent::Binary { message }) => {
                            Some(message.as_slice())
                        }
                        _ => None,
                    })
                    .collect();
                assert_eq!(delivered, [model.as_slice()]);
                assert_eq!(
                    frame_payloads(&outputs).concat(),
                    model,
                    "role={outbound_role:?} continuations={continuation_count} split={split}"
                );
            }
        }
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
    assert_eq!(bytes.len() % 2, 0);
    bytes
        .chunks_exact(2)
        .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
        .collect()
}

#[test]
fn us014_seed_inventory_is_canonical_executable_and_inert() {
    let seeds = [
        include_str!("../fuzz-seeds/us014/legal-text.hex"),
        include_str!("../fuzz-seeds/us014/legal-binary.hex"),
        include_str!("../fuzz-seeds/us014/utf8-cross-frame.hex"),
        include_str!("../fuzz-seeds/us014/orphan-continuation.hex"),
        include_str!("../fuzz-seeds/us014/data-restart.hex"),
        include_str!("../fuzz-seeds/us014/control-interleave.hex"),
        include_str!("../fuzz-seeds/us014/empty-message.hex"),
        include_str!("../fuzz-seeds/us014/invalid-middle-utf8.hex"),
        include_str!("../fuzz-seeds/us014/truncated-final-utf8.hex"),
        include_str!("../fuzz-seeds/us014/prior-valid-orphan.hex"),
        include_str!("../fuzz-seeds/us014/double-delivery.hex"),
        include_str!("../fuzz-seeds/us014/exact-retention.hex"),
        include_str!("../fuzz-seeds/us014/plus-one-retention.hex"),
        include_str!("../fuzz-seeds/us014/reset-next-message.hex"),
    ];
    assert_eq!(seeds.len(), 14);

    for (index, seed) in seeds.into_iter().enumerate() {
        assert!(
            seed.trim_end()
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "seed={index}"
        );
        let config = if index == 11 || index == 12 {
            config_with(|limits| {
                let total = if index == 11 { 8 } else { 7 };
                limits.frame_bytes = total;
                limits.message_bytes = total;
                limits.total_buffered_bytes = total;
            })
        } else {
            config_with(|_| {})
        };
        let wire = decode_hex_seed(seed);
        let result =
            open_core(Role::Client, config).step(CoreInput::Transport(TransportBytes::new(&wire)));
        match index {
            0..=2 | 5..=6 | 10..=11 | 13 => assert_eq!(result.failure(), None, "seed={index}"),
            3..=4 | 9 => assert!(
                matches!(
                    result.failure().map(|failure| &failure.kind),
                    Some(FailureKind::Fragment(_))
                ),
                "seed={index}"
            ),
            7..=8 => assert!(
                matches!(
                    result.failure().map(|failure| &failure.kind),
                    Some(FailureKind::Utf8(_))
                ),
                "seed={index}"
            ),
            12 => assert!(matches!(
                result.failure().map(|failure| &failure.kind),
                Some(FailureKind::LimitExceeded {
                    limit: LimitKind::TotalBufferedBytes,
                    ..
                })
            )),
            _ => unreachable!(),
        }
    }
}
