#![forbid(unsafe_code)]

use websocket_core::{
    AutomaticPongPolicy, ClientRequestDescriptor, ConnectionConfig, ConnectionCore,
    ConnectionLimits, ConnectionState, CoreInput, CoreOutput, FailureKind, FrameEncoder,
    FrameFailure, LimitKind, LocalCommand, Opcode, OutboundFrame, QueueKind, Role, SemanticEvent,
    TransportBytes,
};

const RFC_REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
const RFC_RESPONSE: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
const MASK: [u8; 4] = [0x37, 0xfa, 0x21, 0x3d];

fn config(policy: AutomaticPongPolicy) -> ConnectionConfig {
    ConnectionConfig::try_from(ConnectionLimits::default())
        .expect("default limits")
        .with_automatic_pong_policy(policy)
}

fn config_with(
    policy: AutomaticPongPolicy,
    mut change: impl FnMut(&mut ConnectionLimits),
) -> ConnectionConfig {
    let mut limits = ConnectionLimits::default();
    change(&mut limits);
    ConnectionConfig::try_from(limits)
        .expect("test limits")
        .with_automatic_pong_policy(policy)
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
        Role::Server => assert_eq!(
            core.step(CoreInput::Transport(TransportBytes::new(RFC_REQUEST)))
                .failure(),
            None
        ),
    }
    assert_eq!(core.state(), ConnectionState::Open);
    core
}

fn encoded(role: Role, config: &ConnectionConfig, opcode: Opcode, payload: &[u8]) -> Vec<u8> {
    encoded_frame(role, config, true, opcode, payload)
}

fn encoded_frame(
    role: Role,
    config: &ConnectionConfig,
    fin: bool,
    opcode: Opcode,
    payload: &[u8],
) -> Vec<u8> {
    FrameEncoder::new(config.clone(), role)
        .encode(
            OutboundFrame::new(fin, opcode, payload),
            (role == Role::Client).then_some(MASK),
        )
        .unwrap()
        .as_slice()
        .to_vec()
}

#[test]
fn server_auto_pong_is_an_indivisible_frame_event_write_group() {
    let config = config(AutomaticPongPolicy::ServerOnly);
    let wire = encoded(Role::Client, &config, Opcode::Ping, b"\0ping\xff");
    let result =
        open_core(Role::Server, config).step(CoreInput::Transport(TransportBytes::new(&wire)));

    assert_eq!(result.failure(), None);
    let outputs: Vec<_> = result.outputs().collect();
    assert!(matches!(
        outputs.as_slice(),
        [
            CoreOutput::SemanticEvent(SemanticEvent::FrameReceived { frame }),
            CoreOutput::SemanticEvent(SemanticEvent::Ping { payload }),
            CoreOutput::TransportWrite(write),
        ] if frame.opcode() == Opcode::Ping
            && frame.payload() == b"\0ping\xff"
            && payload.as_slice() == b"\0ping\xff"
            && write.as_slice() == b"\x8a\x06\0ping\xff"
    ));
}

#[test]
fn pong_is_observed_but_never_replied_to() {
    for role in [Role::Client, Role::Server] {
        let config = config(AutomaticPongPolicy::ServerOnly);
        let outbound = if role == Role::Client {
            Role::Server
        } else {
            Role::Client
        };
        let wire = encoded(outbound, &config, Opcode::Pong, b"answer");
        let result = open_core(role, config).step(CoreInput::Transport(TransportBytes::new(&wire)));
        assert_eq!(result.failure(), None);
        let outputs: Vec<_> = result.outputs().collect();
        assert!(matches!(
            outputs.as_slice(),
            [
                CoreOutput::SemanticEvent(SemanticEvent::FrameReceived { frame }),
                CoreOutput::SemanticEvent(SemanticEvent::Pong { payload }),
            ] if frame.opcode() == Opcode::Pong && payload.as_slice() == b"answer"
        ));
    }
}

#[test]
fn client_policy_is_observe_only_and_never_invents_a_mask_key() {
    let config = config(AutomaticPongPolicy::ServerOnly);
    let wire = encoded(Role::Server, &config, Opcode::Ping, b"manual");
    let result =
        open_core(Role::Client, config).step(CoreInput::Transport(TransportBytes::new(&wire)));
    assert_eq!(result.failure(), None);
    assert_eq!(result.outputs().len(), 2);
    assert!(
        result
            .outputs()
            .all(|output| !matches!(output, CoreOutput::TransportWrite(_)))
    );
}

#[test]
fn local_commands_obey_role_masking_and_are_nonterminal_on_failure() {
    let config = config(AutomaticPongPolicy::Disabled);
    let mut client = open_core(Role::Client, config.clone());
    let sent = client.step(CoreInput::Command(LocalCommand::SendPing {
        payload: b"hi".to_vec().into_boxed_slice(),
        mask_key: Some([1, 2, 3, 4]),
    }));
    assert_eq!(sent.failure(), None);
    assert!(
        matches!(sent.outputs().next(), Some(CoreOutput::TransportWrite(write)) if write.as_slice() == [0x89, 0x82, 1, 2, 3, 4, b'h' ^ 1, b'i' ^ 2])
    );

    let missing = client.step(CoreInput::Command(LocalCommand::SendPong {
        payload: Box::new([]),
        mask_key: None,
    }));
    assert_eq!(
        missing.failure().map(|failure| &failure.kind),
        Some(&FailureKind::Frame(FrameFailure::MissingMaskKey))
    );
    assert_eq!(missing.state(), ConnectionState::Open);
    assert_eq!(missing.outputs().len(), 0);

    let mut server = open_core(Role::Server, config);
    let unexpected = server.step(CoreInput::Command(LocalCommand::SendPing {
        payload: Box::new([]),
        mask_key: Some([1, 2, 3, 4]),
    }));
    assert_eq!(
        unexpected.failure().map(|failure| &failure.kind),
        Some(&FailureKind::Frame(FrameFailure::UnexpectedMaskKey))
    );
    assert_eq!(unexpected.state(), ConnectionState::Open);
}

#[test]
fn control_payload_126_is_rejected_without_an_offending_group() {
    let config = config(AutomaticPongPolicy::ServerOnly);
    let mut wire = encoded(Role::Client, &config, Opcode::Ping, b"ok");
    wire.extend_from_slice(&[0x89, 0xfe, 0, 126]);
    let result =
        open_core(Role::Server, config).step(CoreInput::Transport(TransportBytes::new(&wire)));
    assert_eq!(
        result.failure().map(|failure| &failure.kind),
        Some(&FailureKind::Frame(FrameFailure::ControlPayloadTooLarge {
            length: 126
        }))
    );
    assert_eq!(result.state(), ConnectionState::Closed);
    assert_eq!(result.outputs().len(), 4, "valid Ping group then Closed");
}

#[test]
fn default_policy_is_disabled_and_payload_boundaries_cover_both_roles() {
    let default = ConnectionConfig::try_from(ConnectionLimits::default()).unwrap();
    assert_eq!(
        default.automatic_pong_policy(),
        AutomaticPongPolicy::Disabled
    );

    for payload in [Vec::new(), vec![0xa5; 125]] {
        for inbound_role in [Role::Client, Role::Server] {
            let outbound_role = if inbound_role == Role::Client {
                Role::Server
            } else {
                Role::Client
            };
            let policy = AutomaticPongPolicy::ServerOnly;
            let config = config(policy);
            let wire = encoded(outbound_role, &config, Opcode::Ping, &payload);
            for split in 0..=wire.len() {
                let mut core = open_core(inbound_role, config.clone());
                let first = core.step(CoreInput::Transport(TransportBytes::new(&wire[..split])));
                let second = core.step(CoreInput::Transport(TransportBytes::new(&wire[split..])));
                assert_eq!(first.failure(), None, "role={inbound_role:?} split={split}");
                assert_eq!(
                    second.failure(),
                    None,
                    "role={inbound_role:?} split={split}"
                );
                let outputs: Vec<_> = first.outputs().chain(second.outputs()).cloned().collect();
                let expected = if inbound_role == Role::Server { 3 } else { 2 };
                assert_eq!(
                    outputs.len(),
                    expected,
                    "role={inbound_role:?} split={split}"
                );
                assert!(matches!(
                    outputs.get(1),
                    Some(CoreOutput::SemanticEvent(SemanticEvent::Ping { payload: observed }))
                        if observed.as_slice() == payload
                ));
            }
        }
    }

    for role in [Role::Client, Role::Server] {
        let mask_key = (role == Role::Client).then_some([9, 8, 7, 6]);
        let mut core = open_core(role, default.clone());
        let result = core.step(CoreInput::Command(LocalCommand::SendPing {
            payload: vec![0; 126].into_boxed_slice(),
            mask_key,
        }));
        assert_eq!(
            result.failure().map(|failure| &failure.kind),
            Some(&FailureKind::Frame(FrameFailure::ControlPayloadTooLarge {
                length: 126,
            }))
        );
        assert_eq!(result.state(), ConnectionState::Open);
        assert_eq!(result.outputs().len(), 0);
    }
}

#[test]
fn coalesced_controls_keep_complete_wire_order() {
    let config = config(AutomaticPongPolicy::ServerOnly);
    let mut wire = encoded(Role::Client, &config, Opcode::Ping, b"a");
    wire.extend_from_slice(&encoded(Role::Client, &config, Opcode::Pong, b"b"));
    wire.extend_from_slice(&encoded(Role::Client, &config, Opcode::Ping, b"c"));
    let result =
        open_core(Role::Server, config).step(CoreInput::Transport(TransportBytes::new(&wire)));
    assert_eq!(result.failure(), None);
    let outputs: Vec<_> = result.outputs().collect();
    assert_eq!(outputs.len(), 8);
    assert!(
        matches!(outputs[0], CoreOutput::SemanticEvent(SemanticEvent::FrameReceived { frame }) if frame.payload() == b"a")
    );
    assert!(
        matches!(outputs[1], CoreOutput::SemanticEvent(SemanticEvent::Ping { payload }) if payload.as_slice() == b"a")
    );
    assert!(
        matches!(outputs[2], CoreOutput::TransportWrite(write) if write.as_slice() == b"\x8a\x01a")
    );
    assert!(
        matches!(outputs[3], CoreOutput::SemanticEvent(SemanticEvent::FrameReceived { frame }) if frame.payload() == b"b")
    );
    assert!(
        matches!(outputs[4], CoreOutput::SemanticEvent(SemanticEvent::Pong { payload }) if payload.as_slice() == b"b")
    );
    assert!(
        matches!(outputs[5], CoreOutput::SemanticEvent(SemanticEvent::FrameReceived { frame }) if frame.payload() == b"c")
    );
    assert!(
        matches!(outputs[6], CoreOutput::SemanticEvent(SemanticEvent::Ping { payload }) if payload.as_slice() == b"c")
    );
    assert!(
        matches!(outputs[7], CoreOutput::TransportWrite(write) if write.as_slice() == b"\x8a\x01c")
    );
}

#[test]
fn controls_preserve_fragmented_utf8_state_and_finish_order() {
    let config = config(AutomaticPongPolicy::ServerOnly);
    let scalar = "🦀".as_bytes();
    let mut wire = encoded_frame(Role::Client, &config, false, Opcode::Text, &scalar[..2]);
    wire.extend_from_slice(&encoded(Role::Client, &config, Opcode::Ping, b"between"));
    wire.extend_from_slice(&encoded(Role::Client, &config, Opcode::Pong, b"still"));
    wire.extend_from_slice(&encoded_frame(
        Role::Client,
        &config,
        true,
        Opcode::Continuation,
        &scalar[2..],
    ));
    let result =
        open_core(Role::Server, config).step(CoreInput::Transport(TransportBytes::new(&wire)));
    assert_eq!(result.failure(), None);
    let outputs: Vec<_> = result.outputs().collect();
    assert_eq!(outputs.len(), 8);
    assert!(
        matches!(outputs[1], CoreOutput::SemanticEvent(SemanticEvent::FrameReceived { frame }) if frame.opcode() == Opcode::Ping)
    );
    assert!(
        matches!(outputs[2], CoreOutput::SemanticEvent(SemanticEvent::Ping { payload }) if payload.as_slice() == b"between")
    );
    assert!(matches!(outputs[3], CoreOutput::TransportWrite(_)));
    assert!(
        matches!(outputs[4], CoreOutput::SemanticEvent(SemanticEvent::FrameReceived { frame }) if frame.opcode() == Opcode::Pong)
    );
    assert!(
        matches!(outputs[5], CoreOutput::SemanticEvent(SemanticEvent::Pong { payload }) if payload.as_slice() == b"still")
    );
    assert!(
        matches!(outputs[7], CoreOutput::SemanticEvent(SemanticEvent::Text { message }) if message.as_str() == "🦀")
    );
}

#[test]
fn event_write_and_total_boundaries_admit_exact_and_retain_only_valid_prefix() {
    let event_exact = config_with(AutomaticPongPolicy::Disabled, |limits| {
        limits.event_queue_entries = 2;
    });
    let wire = encoded(Role::Server, &event_exact, Opcode::Ping, b"");
    let exact =
        open_core(Role::Client, event_exact).step(CoreInput::Transport(TransportBytes::new(&wire)));
    assert_eq!(exact.failure(), None);
    assert_eq!(exact.outputs().len(), 2);

    let event_over = config_with(AutomaticPongPolicy::Disabled, |limits| {
        limits.event_queue_entries = 1;
    });
    let over =
        open_core(Role::Client, event_over).step(CoreInput::Transport(TransportBytes::new(&wire)));
    assert_eq!(
        over.failure().map(|failure| &failure.kind),
        Some(&FailureKind::Backpressure(QueueKind::Event))
    );
    assert_eq!(over.outputs().len(), 1);
    assert_eq!(over.state(), ConnectionState::Closed);

    let write_exact = config_with(AutomaticPongPolicy::ServerOnly, |limits| {
        limits.write_queue_entries = 2;
    });
    let mut two = encoded(Role::Client, &write_exact, Opcode::Ping, b"a");
    two.extend_from_slice(&encoded(Role::Client, &write_exact, Opcode::Ping, b"b"));
    let exact =
        open_core(Role::Server, write_exact).step(CoreInput::Transport(TransportBytes::new(&two)));
    assert_eq!(exact.failure(), None);
    assert_eq!(exact.outputs().len(), 6);

    let write_over = config_with(AutomaticPongPolicy::ServerOnly, |limits| {
        limits.write_queue_entries = 1;
    });
    let over =
        open_core(Role::Server, write_over).step(CoreInput::Transport(TransportBytes::new(&two)));
    assert_eq!(
        over.failure().map(|failure| &failure.kind),
        Some(&FailureKind::Backpressure(QueueKind::Write))
    );
    assert_eq!(over.outputs().len(), 4, "one full Ping group then Closed");

    let total_exact = config_with(AutomaticPongPolicy::ServerOnly, |limits| {
        limits.frame_bytes = 4;
        limits.message_bytes = 4;
        limits.total_buffered_bytes = 10;
    });
    let wire = encoded(Role::Client, &total_exact, Opcode::Ping, b"1234");
    let exact =
        open_core(Role::Server, total_exact).step(CoreInput::Transport(TransportBytes::new(&wire)));
    assert_eq!(exact.failure(), None);

    let total_over = config_with(AutomaticPongPolicy::ServerOnly, |limits| {
        limits.frame_bytes = 4;
        limits.message_bytes = 4;
        limits.total_buffered_bytes = 9;
    });
    let over =
        open_core(Role::Server, total_over).step(CoreInput::Transport(TransportBytes::new(&wire)));
    assert_eq!(
        over.failure().map(|failure| &failure.kind),
        Some(&FailureKind::LimitExceeded {
            limit: LimitKind::TotalBufferedBytes,
            attempted: 10,
            maximum: 9,
        })
    );
    assert_eq!(over.outputs().len(), 1);
}

#[test]
fn local_exact_wire_budget_and_distinct_client_keys_are_observable() {
    let server_exact = config_with(AutomaticPongPolicy::Disabled, |limits| {
        limits.frame_bytes = 125;
        limits.message_bytes = 125;
        limits.total_buffered_bytes = 127;
    });
    let mut server = open_core(Role::Server, server_exact);
    let exact = server.step(CoreInput::Command(LocalCommand::SendPong {
        payload: vec![7; 125].into_boxed_slice(),
        mask_key: None,
    }));
    assert_eq!(exact.failure(), None);
    assert_eq!(
        exact.outputs().next().and_then(|output| match output {
            CoreOutput::TransportWrite(write) => Some(write.as_slice().len()),
            _ => None,
        }),
        Some(127)
    );

    let server_over = config_with(AutomaticPongPolicy::Disabled, |limits| {
        limits.frame_bytes = 125;
        limits.message_bytes = 125;
        limits.total_buffered_bytes = 126;
    });
    let over =
        open_core(Role::Server, server_over).step(CoreInput::Command(LocalCommand::SendPong {
            payload: vec![7; 125].into_boxed_slice(),
            mask_key: None,
        }));
    assert_eq!(
        over.failure().map(|failure| &failure.kind),
        Some(&FailureKind::LimitExceeded {
            limit: LimitKind::TotalBufferedBytes,
            attempted: 127,
            maximum: 126,
        })
    );

    let config = config(AutomaticPongPolicy::Disabled);
    let mut client = open_core(Role::Client, config);
    let first = client.step(CoreInput::Command(LocalCommand::SendPing {
        payload: b"same".to_vec().into_boxed_slice(),
        mask_key: Some([1, 1, 1, 1]),
    }));
    let second = client.step(CoreInput::Command(LocalCommand::SendPing {
        payload: b"same".to_vec().into_boxed_slice(),
        mask_key: Some([2, 2, 2, 2]),
    }));
    let wire = |result: &websocket_core::StepResult| match result.outputs().next().unwrap() {
        CoreOutput::TransportWrite(write) => write.as_slice().to_vec(),
        _ => panic!("local command must write"),
    };
    let first_wire = wire(&first);
    let second_wire = wire(&second);
    assert_eq!(&first_wire[2..6], &[1, 1, 1, 1]);
    assert_eq!(&second_wire[2..6], &[2, 2, 2, 2]);
    assert_ne!(first_wire, second_wire);
}

#[test]
fn bounded_control_model_covers_every_legal_length_opcode_and_role() {
    for length in 0..=125usize {
        let payload: Vec<u8> = (0..length)
            .map(|index| (index as u8).wrapping_mul(37).wrapping_add(length as u8))
            .collect();
        for inbound_role in [Role::Client, Role::Server] {
            let outbound_role = if inbound_role == Role::Client {
                Role::Server
            } else {
                Role::Client
            };
            for opcode in [Opcode::Ping, Opcode::Pong] {
                let config = config(AutomaticPongPolicy::ServerOnly);
                let wire = encoded(outbound_role, &config, opcode, &payload);
                let result = open_core(inbound_role, config)
                    .step(CoreInput::Transport(TransportBytes::new(&wire)));
                assert_eq!(
                    result.failure(),
                    None,
                    "length={length} role={inbound_role:?} opcode={opcode:?}"
                );
                let outputs: Vec<_> = result.outputs().collect();
                let automatic = inbound_role == Role::Server && opcode == Opcode::Ping;
                assert_eq!(outputs.len(), 2 + usize::from(automatic));
                assert!(matches!(
                    outputs[0],
                    CoreOutput::SemanticEvent(SemanticEvent::FrameReceived { frame })
                        if frame.opcode() == opcode && frame.payload() == payload
                ));
                match opcode {
                    Opcode::Ping => assert!(matches!(
                        outputs[1],
                        CoreOutput::SemanticEvent(SemanticEvent::Ping { payload: observed })
                            if observed.as_slice() == payload
                    )),
                    Opcode::Pong => assert!(matches!(
                        outputs[1],
                        CoreOutput::SemanticEvent(SemanticEvent::Pong { payload: observed })
                            if observed.as_slice() == payload
                    )),
                    _ => unreachable!(),
                }
                if automatic {
                    assert!(matches!(outputs[2], CoreOutput::TransportWrite(_)));
                }
            }
        }
    }
}

#[test]
fn us015_seed_inventory_is_small_canonical_and_inert() {
    let seeds = [
        (
            "coalesced-controls.hex",
            include_str!("../fuzz-seeds/us015/coalesced-controls.hex"),
        ),
        (
            "empty-ping.hex",
            include_str!("../fuzz-seeds/us015/empty-ping.hex"),
        ),
        (
            "empty-pong.hex",
            include_str!("../fuzz-seeds/us015/empty-pong.hex"),
        ),
        (
            "event-limit.hex",
            include_str!("../fuzz-seeds/us015/event-limit.hex"),
        ),
        (
            "fragment-interleave.hex",
            include_str!("../fuzz-seeds/us015/fragment-interleave.hex"),
        ),
        (
            "fragmented-control.hex",
            include_str!("../fuzz-seeds/us015/fragmented-control.hex"),
        ),
        (
            "masked-ping.hex",
            include_str!("../fuzz-seeds/us015/masked-ping.hex"),
        ),
        (
            "masked-pong.hex",
            include_str!("../fuzz-seeds/us015/masked-pong.hex"),
        ),
        (
            "no-unwanted-reply.hex",
            include_str!("../fuzz-seeds/us015/no-unwanted-reply.hex"),
        ),
        (
            "payload-126.hex",
            include_str!("../fuzz-seeds/us015/payload-126.hex"),
        ),
        (
            "payload-loss.hex",
            include_str!("../fuzz-seeds/us015/payload-loss.hex"),
        ),
        (
            "total-limit.hex",
            include_str!("../fuzz-seeds/us015/total-limit.hex"),
        ),
        (
            "valid-prefix-reserved.hex",
            include_str!("../fuzz-seeds/us015/valid-prefix-reserved.hex"),
        ),
        (
            "write-limit.hex",
            include_str!("../fuzz-seeds/us015/write-limit.hex"),
        ),
        (
            "wrong-mask-client.hex",
            include_str!("../fuzz-seeds/us015/wrong-mask-client.hex"),
        ),
        (
            "wrong-mask-server.hex",
            include_str!("../fuzz-seeds/us015/wrong-mask-server.hex"),
        ),
    ];
    assert_eq!(seeds.len(), 16);
    for (name, seed) in seeds {
        let hex = seed.trim_end();
        assert!(!hex.is_empty(), "{name}");
        assert_eq!(hex.len() % 2, 0, "{name}");
        assert!(
            hex.bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "{name}"
        );
        assert!(hex.len() <= 512, "{name}");
    }
}
