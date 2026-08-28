#![forbid(unsafe_code)]

use websocket_core::{
    AutomaticPongPolicy, ClientRequestDescriptor, CloseCodeRejection, CloseFailure, CloseInitiator,
    ConnectionConfig, ConnectionCore, ConnectionLimits, ConnectionState, CoreInput, CoreOutput,
    FailureKind, FragmentFailure, FrameEncoder, FrameFailure, HandshakeFailure, InputKind,
    LimitKind, LocalCommand, Opcode, OutboundFrame, QueueKind, Role, SemanticEvent, TransportBytes,
    Utf8Failure,
};

const RFC_REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
const RFC_RESPONSE: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";

fn config() -> ConnectionConfig {
    ConnectionConfig::try_from(ConnectionLimits::default()).expect("default limits")
}

fn config_with(mut change: impl FnMut(&mut ConnectionLimits)) -> ConnectionConfig {
    let mut limits = ConnectionLimits::default();
    change(&mut limits);
    ConnectionConfig::try_from(limits).expect("test limits")
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

fn encoded(role: Role, payload: &[u8]) -> Vec<u8> {
    encoded_with(role, &config(), Opcode::Close, payload)
}

fn encoded_with(role: Role, config: &ConnectionConfig, opcode: Opcode, payload: &[u8]) -> Vec<u8> {
    FrameEncoder::new(config.clone(), role)
        .encode(
            OutboundFrame::new(true, opcode, payload),
            (role == Role::Client).then_some([1, 2, 3, 4]),
        )
        .unwrap()
        .as_slice()
        .to_vec()
}

fn close_payload(code: Option<u16>, reason: &[u8]) -> Vec<u8> {
    match code {
        Some(code) => code
            .to_be_bytes()
            .into_iter()
            .chain(reason.iter().copied())
            .collect(),
        None => {
            assert!(reason.is_empty());
            Vec::new()
        }
    }
}

fn local_close(role: Role, code: Option<u16>, reason: &str) -> LocalCommand {
    LocalCommand::Close {
        code,
        reason: reason.into(),
        mask_key: (role == Role::Client).then_some([9, 8, 7, 6]),
    }
}

fn failure(result: &websocket_core::StepResult) -> Option<&FailureKind> {
    result.failure().map(|failure| &failure.kind)
}

#[test]
fn local_first_close_waits_for_peer_and_write_flush() {
    let mut core = open_core(Role::Server, config());
    let local = core.step(CoreInput::Command(LocalCommand::Close {
        code: None,
        reason: "".into(),
        mask_key: None,
    }));
    assert_eq!(local.failure(), None);
    assert_eq!(local.state(), ConnectionState::Closing);
    assert!(matches!(
        local.outputs().collect::<Vec<_>>().as_slice(),
        [
            CoreOutput::TransportWrite(write),
            CoreOutput::StateChanged(ConnectionState::Closing),
        ] if write.as_slice() == [0x88, 0]
    ));

    let flushed = core.step(CoreInput::TransportWriteFlushed);
    assert_eq!(flushed.failure(), None);
    assert_eq!(flushed.outputs().len(), 0);
    assert_eq!(flushed.state(), ConnectionState::Closing);

    let peer_wire = encoded(Role::Client, &[]);
    let peer = core.step(CoreInput::Transport(TransportBytes::new(&peer_wire)));
    assert_eq!(peer.failure(), None);
    assert_eq!(peer.state(), ConnectionState::Closed);
    assert!(matches!(
        peer.outputs().collect::<Vec<_>>().as_slice(),
        [
            CoreOutput::SemanticEvent(SemanticEvent::FrameReceived { frame }),
            CoreOutput::SemanticEvent(SemanticEvent::CloseReceived { close, initiator }),
            CoreOutput::StateChanged(ConnectionState::Closed),
        ] if frame.opcode() == Opcode::Close
            && close.code().is_none()
            && close.reason().is_empty()
            && *initiator == CloseInitiator::Local
    ));
}

#[test]
fn local_close_exact_payload_total_budget_and_role_masks_are_independent() {
    let exact = config_with(|limits| {
        limits.frame_bytes = 252;
        limits.message_bytes = 252;
        limits.total_buffered_bytes = 252;
    });
    let mut server = open_core(Role::Server, exact);
    let reason = "x".repeat(123);
    let admitted = server.step(CoreInput::Command(LocalCommand::Close {
        code: Some(1000),
        reason: reason.clone().into_boxed_str(),
        mask_key: None,
    }));
    assert_eq!(admitted.failure(), None);
    let CoreOutput::TransportWrite(write) = admitted.outputs().next().unwrap() else {
        panic!("exact close must produce one wire frame");
    };
    assert_eq!(write.as_slice().len(), 127);
    assert_eq!(&write.as_slice()[..4], &[0x88, 125, 0x03, 0xe8]);
    assert_eq!(&write.as_slice()[4..], reason.as_bytes());

    let mut client = open_core(Role::Client, config());
    let missing = client.step(CoreInput::Command(LocalCommand::Close {
        code: Some(1000),
        reason: "".into(),
        mask_key: None,
    }));
    assert_eq!(
        failure(&missing),
        Some(&FailureKind::Frame(FrameFailure::MissingMaskKey))
    );
    assert_eq!(missing.state(), ConnectionState::Open);

    let mut server = open_core(Role::Server, config());
    let unexpected = server.step(CoreInput::Command(LocalCommand::Close {
        code: Some(1000),
        reason: "".into(),
        mask_key: Some([1, 2, 3, 4]),
    }));
    assert_eq!(
        failure(&unexpected),
        Some(&FailureKind::Frame(FrameFailure::UnexpectedMaskKey))
    );
    assert_eq!(unexpected.state(), ConnectionState::Open);
}

#[test]
fn peer_first_server_echoes_exact_close_then_closes_on_flush() {
    let mut payload = 1000_u16.to_be_bytes().to_vec();
    payload.extend_from_slice(b"bye");
    let peer_wire = encoded(Role::Client, &payload);
    let mut core = open_core(Role::Server, config());

    let peer = core.step(CoreInput::Transport(TransportBytes::new(&peer_wire)));
    assert_eq!(peer.failure(), None);
    assert_eq!(peer.state(), ConnectionState::Closing);
    assert!(matches!(
        peer.outputs().collect::<Vec<_>>().as_slice(),
        [
            CoreOutput::SemanticEvent(SemanticEvent::FrameReceived { frame }),
            CoreOutput::SemanticEvent(SemanticEvent::CloseReceived { close, initiator }),
            CoreOutput::StateChanged(ConnectionState::Closing),
            CoreOutput::TransportWrite(write),
        ] if frame.payload() == payload
            && close.code() == Some(1000)
            && close.reason() == "bye"
            && *initiator == CloseInitiator::Peer
            && write.as_slice() == [0x88, 5, 0x03, 0xe8, b'b', b'y', b'e']
    ));

    let flushed = core.step(CoreInput::TransportWriteFlushed);
    assert_eq!(flushed.failure(), None);
    assert_eq!(flushed.state(), ConnectionState::Closed);
    assert_eq!(
        flushed.outputs().collect::<Vec<_>>(),
        vec![&CoreOutput::StateChanged(ConnectionState::Closed)]
    );
}

#[test]
fn local_close_code_table_and_reason_boundaries_are_role_exact_and_atomic() {
    let common = [
        1000, 1001, 1002, 1003, 1007, 1008, 1009, 1011, 1012, 1013, 1014, 3000, 4999,
    ];
    for role in [Role::Client, Role::Server] {
        for code in common {
            let result = open_core(role, config()).step(CoreInput::Command(local_close(
                role,
                Some(code),
                "ok",
            )));
            assert_eq!(failure(&result), None, "role={role:?} code={code}");
            assert_eq!(result.state(), ConnectionState::Closing);
        }
    }

    let client_1010 = open_core(Role::Client, config()).step(CoreInput::Command(local_close(
        Role::Client,
        Some(1010),
        "extension request",
    )));
    assert_eq!(failure(&client_1010), None);
    let server_1010 = open_core(Role::Server, config()).step(CoreInput::Command(local_close(
        Role::Server,
        Some(1010),
        "forbidden sender",
    )));
    assert_eq!(
        failure(&server_1010),
        Some(&FailureKind::Close(CloseFailure::InvalidCode {
            code: 1010,
            rejection: CloseCodeRejection::WrongSenderRole,
        }))
    );
    assert_eq!(server_1010.state(), ConnectionState::Open);
    assert_eq!(server_1010.outputs().len(), 0);

    let client_missing_key =
        open_core(Role::Client, config()).step(CoreInput::Command(LocalCommand::Close {
            code: Some(1000),
            reason: "".into(),
            mask_key: None,
        }));
    assert_eq!(
        failure(&client_missing_key),
        Some(&FailureKind::Frame(FrameFailure::MissingMaskKey))
    );
    assert_eq!(client_missing_key.state(), ConnectionState::Open);
    let server_unexpected_key =
        open_core(Role::Server, config()).step(CoreInput::Command(LocalCommand::Close {
            code: Some(1000),
            reason: "".into(),
            mask_key: Some([1, 2, 3, 4]),
        }));
    assert_eq!(
        failure(&server_unexpected_key),
        Some(&FailureKind::Frame(FrameFailure::UnexpectedMaskKey))
    );
    assert_eq!(server_unexpected_key.state(), ConnectionState::Open);

    for (code, rejection) in [
        (999, CloseCodeRejection::OutsideWireRange),
        (5000, CloseCodeRejection::OutsideWireRange),
        (1004, CloseCodeRejection::ForbiddenWireCode),
        (1005, CloseCodeRejection::ForbiddenWireCode),
        (1006, CloseCodeRejection::ForbiddenWireCode),
        (1015, CloseCodeRejection::ForbiddenWireCode),
        (1016, CloseCodeRejection::UnassignedOrExtensionReserved),
        (2999, CloseCodeRejection::UnassignedOrExtensionReserved),
    ] {
        let result = open_core(Role::Server, config()).step(CoreInput::Command(local_close(
            Role::Server,
            Some(code),
            "",
        )));
        assert_eq!(
            failure(&result),
            Some(&FailureKind::Close(CloseFailure::InvalidCode {
                code,
                rejection,
            }))
        );
        assert_eq!(result.state(), ConnectionState::Open);
        assert_eq!(result.outputs().len(), 0);
    }

    let reason_without_code =
        open_core(Role::Server, config()).step(CoreInput::Command(LocalCommand::Close {
            code: None,
            reason: "not empty".into(),
            mask_key: None,
        }));
    assert_eq!(
        failure(&reason_without_code),
        Some(&FailureKind::Close(CloseFailure::ReasonWithoutCode))
    );
    assert_eq!(reason_without_code.state(), ConnectionState::Open);

    let exact = "x".repeat(123);
    let exact_result = open_core(Role::Server, config()).step(CoreInput::Command(local_close(
        Role::Server,
        Some(1000),
        &exact,
    )));
    assert_eq!(failure(&exact_result), None);
    let over = "x".repeat(124);
    let over_result = open_core(Role::Server, config()).step(CoreInput::Command(local_close(
        Role::Server,
        Some(1000),
        &over,
    )));
    assert_eq!(
        failure(&over_result),
        Some(&FailureKind::Frame(FrameFailure::ControlPayloadTooLarge {
            length: 126,
        }))
    );
    assert_eq!(over_result.state(), ConnectionState::Open);
}

#[test]
fn inbound_close_grammar_code_role_and_utf8_failures_are_terminal() {
    let invalid_cases: Vec<(Role, Vec<u8>, FailureKind)> = vec![
        (
            Role::Server,
            vec![0],
            FailureKind::Close(CloseFailure::PayloadLengthOne),
        ),
        (
            Role::Server,
            close_payload(Some(1005), b""),
            FailureKind::Close(CloseFailure::InvalidCode {
                code: 1005,
                rejection: CloseCodeRejection::ForbiddenWireCode,
            }),
        ),
        (
            Role::Client,
            close_payload(Some(1010), b""),
            FailureKind::Close(CloseFailure::InvalidCode {
                code: 1010,
                rejection: CloseCodeRejection::WrongSenderRole,
            }),
        ),
        (
            Role::Server,
            close_payload(Some(1000), &[0x80]),
            FailureKind::Close(CloseFailure::InvalidReason(
                Utf8Failure::UnexpectedContinuation {
                    offset: 0,
                    byte: 0x80,
                },
            )),
        ),
        (
            Role::Server,
            close_payload(Some(1000), &[0xf8]),
            FailureKind::Close(CloseFailure::InvalidReason(
                Utf8Failure::InvalidLeadingByte {
                    offset: 0,
                    byte: 0xf8,
                },
            )),
        ),
        (
            Role::Server,
            close_payload(Some(1000), &[0xc2, 0x20]),
            FailureKind::Close(CloseFailure::InvalidReason(
                Utf8Failure::InvalidContinuation {
                    offset: 1,
                    byte: 0x20,
                },
            )),
        ),
        (
            Role::Server,
            close_payload(Some(1000), &[0xe0, 0x80, 0x80]),
            FailureKind::Close(CloseFailure::InvalidReason(Utf8Failure::OverlongEncoding {
                offset: 0,
            })),
        ),
        (
            Role::Server,
            close_payload(Some(1000), &[0xed, 0xa0, 0x80]),
            FailureKind::Close(CloseFailure::InvalidReason(
                Utf8Failure::SurrogateCodePoint { offset: 0 },
            )),
        ),
        (
            Role::Server,
            close_payload(Some(1000), &[0xf5]),
            FailureKind::Close(CloseFailure::InvalidReason(
                Utf8Failure::CodePointOutOfRange { offset: 0 },
            )),
        ),
        (
            Role::Server,
            close_payload(Some(1000), &[0xf0, 0x9f]),
            FailureKind::Close(CloseFailure::InvalidReason(
                Utf8Failure::TruncatedSequence {
                    length: 2,
                    remaining: 2,
                },
            )),
        ),
    ];
    for (endpoint, payload, expected) in invalid_cases {
        let sender = if endpoint == Role::Client {
            Role::Server
        } else {
            Role::Client
        };
        let wire = encoded(sender, &payload);
        for split in 0..=wire.len() {
            let mut core = open_core(endpoint, config());
            let first = core.step(CoreInput::Transport(TransportBytes::new(&wire[..split])));
            let second = core.step(CoreInput::Transport(TransportBytes::new(&wire[split..])));
            let rejected = if first.failure().is_some() {
                &first
            } else {
                &second
            };
            assert_eq!(failure(rejected), Some(&expected), "split={split}");
            assert_eq!(rejected.state(), ConnectionState::Closed, "split={split}");
            assert_eq!(
                rejected.outputs().collect::<Vec<_>>(),
                vec![&CoreOutput::StateChanged(ConnectionState::Closed)],
                "offending close hidden split={split}"
            );
        }
    }

    let valid_client_1010 = encoded(Role::Client, &close_payload(Some(1010), b"ok"));
    let result = open_core(Role::Server, config()).step(CoreInput::Transport(TransportBytes::new(
        &valid_client_1010,
    )));
    assert_eq!(failure(&result), None);
    assert!(matches!(
        result.outputs().nth(1),
        Some(CoreOutput::SemanticEvent(SemanticEvent::CloseReceived { close, .. }))
            if close.code() == Some(1010) && close.reason() == "ok"
    ));
}

#[test]
fn peer_first_client_requires_an_exact_explicit_key_acknowledgement() {
    let payload = close_payload(Some(1001), "going away 🦀".as_bytes());
    let wire = encoded(Role::Server, &payload);
    let mut core = open_core(Role::Client, config());
    let peer = core.step(CoreInput::Transport(TransportBytes::new(&wire)));
    assert_eq!(failure(&peer), None);
    assert_eq!(peer.state(), ConnectionState::Closing);
    assert_eq!(peer.outputs().len(), 3);
    assert!(
        peer.outputs()
            .all(|output| !matches!(output, CoreOutput::TransportWrite(_)))
    );

    let mismatch = core.step(CoreInput::Command(local_close(
        Role::Client,
        Some(1000),
        "going away 🦀",
    )));
    assert_eq!(
        failure(&mismatch),
        Some(&FailureKind::Close(CloseFailure::AcknowledgementMismatch))
    );
    assert_eq!(mismatch.state(), ConnectionState::Closing);
    assert_eq!(mismatch.outputs().len(), 0);

    let missing_key = core.step(CoreInput::Command(LocalCommand::Close {
        code: Some(1001),
        reason: "going away 🦀".into(),
        mask_key: None,
    }));
    assert_eq!(
        failure(&missing_key),
        Some(&FailureKind::Frame(FrameFailure::MissingMaskKey))
    );
    assert_eq!(missing_key.state(), ConnectionState::Closing);

    let ack = core.step(CoreInput::Command(local_close(
        Role::Client,
        Some(1001),
        "going away 🦀",
    )));
    assert_eq!(failure(&ack), None);
    assert_eq!(ack.state(), ConnectionState::Closing);
    assert!(matches!(
        ack.outputs().collect::<Vec<_>>().as_slice(),
        [CoreOutput::TransportWrite(write)] if write.as_slice()[0] == 0x88
            && write.as_slice()[1] & 0x80 != 0
    ));
    let done = core.step(CoreInput::TransportWriteFlushed);
    assert_eq!(failure(&done), None);
    assert_eq!(done.state(), ConnectionState::Closed);
    assert_eq!(done.outputs().len(), 1);
}

#[test]
fn duplicate_close_windows_are_typed_and_exactly_once() {
    let mut local_first = open_core(Role::Server, config());
    assert_eq!(
        failure(&local_first.step(CoreInput::Command(local_close(
            Role::Server,
            Some(1000),
            "first",
        )))),
        None
    );
    let duplicate_local = local_first.step(CoreInput::Command(local_close(
        Role::Server,
        Some(1001),
        "second",
    )));
    assert_eq!(
        failure(&duplicate_local),
        Some(&FailureKind::Close(CloseFailure::DuplicateLocalClose))
    );
    assert_eq!(duplicate_local.state(), ConnectionState::Closing);
    assert_eq!(duplicate_local.outputs().len(), 0);

    let wire = encoded(Role::Client, &close_payload(Some(1000), b"peer"));
    let mut peer_first = open_core(Role::Server, config());
    assert_eq!(
        failure(&peer_first.step(CoreInput::Transport(TransportBytes::new(&wire)))),
        None
    );
    let duplicate_peer = peer_first.step(CoreInput::Transport(TransportBytes::new(&wire)));
    assert_eq!(
        failure(&duplicate_peer),
        Some(&FailureKind::Close(CloseFailure::DuplicatePeerClose))
    );
    assert_eq!(duplicate_peer.state(), ConnectionState::Closed);
    assert_eq!(
        duplicate_peer.outputs().collect::<Vec<_>>(),
        vec![&CoreOutput::StateChanged(ConnectionState::Closed)]
    );

    let repeated_eof = peer_first.step(CoreInput::TransportEof);
    assert_eq!(
        failure(&repeated_eof),
        Some(&FailureKind::InvalidState {
            input: InputKind::TransportEof,
            state: ConnectionState::Closed,
        })
    );
    assert_eq!(repeated_eof.state(), ConnectionState::Closed);
    assert_eq!(repeated_eof.outputs().len(), 0);

    let repeated_flush = peer_first.step(CoreInput::TransportWriteFlushed);
    assert_eq!(failure(&repeated_flush), None);
    assert_eq!(repeated_flush.state(), ConnectionState::Closed);
    assert_eq!(repeated_flush.outputs().len(), 0);
}

#[test]
fn closing_observes_ping_pong_without_reply_and_rejects_data() {
    let config = config().with_automatic_pong_policy(AutomaticPongPolicy::ServerOnly);
    let mut core = open_core(Role::Server, config.clone());
    assert_eq!(
        failure(&core.step(CoreInput::Command(local_close(
            Role::Server,
            Some(1000),
            "",
        )))),
        None
    );
    let mut controls = encoded_with(Role::Client, &config, Opcode::Ping, b"p");
    controls.extend_from_slice(&encoded_with(Role::Client, &config, Opcode::Pong, b"q"));
    let observed = core.step(CoreInput::Transport(TransportBytes::new(&controls)));
    assert_eq!(failure(&observed), None);
    assert_eq!(observed.state(), ConnectionState::Closing);
    assert_eq!(observed.outputs().len(), 4);
    assert!(
        observed
            .outputs()
            .all(|output| !matches!(output, CoreOutput::TransportWrite(_)))
    );

    let data = encoded_with(Role::Client, &config, Opcode::Text, b"forbidden");
    let rejected = core.step(CoreInput::Transport(TransportBytes::new(&data)));
    assert_eq!(
        failure(&rejected),
        Some(&FailureKind::InvalidState {
            input: InputKind::TransportBytes,
            state: ConnectionState::Closing,
        })
    );
    assert_eq!(rejected.state(), ConnectionState::Closing);
    assert_eq!(rejected.outputs().len(), 0);
}

#[test]
fn eof_precedence_covers_open_fragment_closing_and_closed() {
    let mut connecting = ConnectionCore::new(config(), Role::Client);
    let connecting_eof = connecting.step(CoreInput::TransportEof);
    assert_eq!(
        failure(&connecting_eof),
        Some(&FailureKind::Handshake(HandshakeFailure::UnexpectedEof))
    );
    assert_eq!(connecting_eof.state(), ConnectionState::Closed);

    let open_eof = open_core(Role::Server, config()).step(CoreInput::TransportEof);
    assert_eq!(
        failure(&open_eof),
        Some(&FailureKind::Close(CloseFailure::UnexpectedEofOpen))
    );

    let mut partial = open_core(Role::Server, config());
    assert_eq!(
        failure(&partial.step(CoreInput::Transport(TransportBytes::new(&[0x81])))),
        None
    );
    assert_eq!(
        failure(&partial.step(CoreInput::TransportEof)),
        Some(&FailureKind::Frame(FrameFailure::UnexpectedEof))
    );

    let fragment_config = config();
    let first_fragment = FrameEncoder::new(fragment_config.clone(), Role::Client)
        .encode(
            OutboundFrame::new(false, Opcode::Text, b"part"),
            Some([1, 2, 3, 4]),
        )
        .unwrap();
    let mut fragmented = open_core(Role::Server, fragment_config);
    assert_eq!(
        failure(&fragmented.step(CoreInput::Transport(TransportBytes::new(
            first_fragment.as_slice(),
        )))),
        None
    );
    assert_eq!(
        failure(&fragmented.step(CoreInput::TransportEof)),
        Some(&FailureKind::Fragment(FragmentFailure::UnexpectedEof {
            active: Opcode::Text,
            accumulated: 4,
        }))
    );

    let mut local_only = open_core(Role::Server, config());
    local_only.step(CoreInput::Command(local_close(
        Role::Server,
        Some(1000),
        "",
    )));
    assert_eq!(
        failure(&local_only.step(CoreInput::TransportEof)),
        Some(&FailureKind::Close(CloseFailure::EofBeforePeerClose))
    );

    let peer_wire = encoded(Role::Server, &close_payload(Some(1000), b""));
    let mut peer_only = open_core(Role::Client, config());
    peer_only.step(CoreInput::Transport(TransportBytes::new(&peer_wire)));
    assert_eq!(
        failure(&peer_only.step(CoreInput::TransportEof)),
        Some(&FailureKind::Close(CloseFailure::EofBeforeAcknowledgement))
    );

    let peer_wire = encoded(Role::Client, &close_payload(Some(1000), b""));
    let mut pending = open_core(Role::Server, config());
    pending.step(CoreInput::Command(local_close(
        Role::Server,
        Some(1000),
        "",
    )));
    pending.step(CoreInput::Transport(TransportBytes::new(&peer_wire)));
    assert_eq!(
        failure(&pending.step(CoreInput::TransportEof)),
        Some(&FailureKind::Close(
            CloseFailure::EofBeforeCloseWriteFlushed
        ))
    );
}

#[test]
fn close_abandons_fragments_and_stops_a_coalesced_batch() {
    let frame_config = config();
    let fragment = FrameEncoder::new(frame_config.clone(), Role::Client)
        .encode(
            OutboundFrame::new(false, Opcode::Text, b"stale"),
            Some([1, 2, 3, 4]),
        )
        .unwrap();
    let close = encoded_with(
        Role::Client,
        &frame_config,
        Opcode::Close,
        &close_payload(Some(1000), b"done"),
    );
    let data = encoded_with(Role::Client, &frame_config, Opcode::Binary, b"after");
    let mut wire = fragment.as_slice().to_vec();
    wire.extend_from_slice(&close);
    wire.extend_from_slice(&data);
    let result =
        open_core(Role::Server, config()).step(CoreInput::Transport(TransportBytes::new(&wire)));
    assert_eq!(
        failure(&result),
        Some(&FailureKind::Close(CloseFailure::DataAfterClose {
            opcode: Opcode::Binary,
        }))
    );
    assert_eq!(result.state(), ConnectionState::Closed);
    let outputs: Vec<_> = result.outputs().collect();
    assert!(outputs.iter().any(|output| matches!(
        output,
        CoreOutput::SemanticEvent(SemanticEvent::CloseReceived { .. })
    )));
    assert!(!outputs.iter().any(|output| matches!(
        output,
        CoreOutput::SemanticEvent(SemanticEvent::Text { .. } | SemanticEvent::Binary { .. })
    )));
    assert_eq!(
        outputs
            .iter()
            .filter(|output| matches!(output, CoreOutput::StateChanged(ConnectionState::Closed)))
            .count(),
        1
    );
}

#[test]
fn close_maps_decoder_fragment_failures_to_data_after_close() {
    let frame_config = config();
    let close = encoded_with(
        Role::Client,
        &frame_config,
        Opcode::Close,
        &close_payload(Some(1000), b"done"),
    );

    let continuation = encoded_with(Role::Client, &frame_config, Opcode::Continuation, b"orphan");
    let mut orphan_wire = close.clone();
    orphan_wire.extend_from_slice(&continuation);
    let orphan = open_core(Role::Server, config())
        .step(CoreInput::Transport(TransportBytes::new(&orphan_wire)));
    assert_eq!(
        failure(&orphan),
        Some(&FailureKind::Close(CloseFailure::DataAfterClose {
            opcode: Opcode::Continuation,
        }))
    );

    let first_fragment = FrameEncoder::new(frame_config.clone(), Role::Client)
        .encode(
            OutboundFrame::new(false, Opcode::Text, b"active"),
            Some([1, 2, 3, 4]),
        )
        .unwrap();
    let replacement_data =
        encoded_with(Role::Client, &frame_config, Opcode::Binary, b"replacement");
    let mut fragmented = open_core(Role::Server, config());
    assert_eq!(
        failure(&fragmented.step(CoreInput::Transport(TransportBytes::new(
            first_fragment.as_slice(),
        )))),
        None
    );
    let mut fragmented_wire = close;
    fragmented_wire.extend_from_slice(&replacement_data);
    let replacement = fragmented.step(CoreInput::Transport(TransportBytes::new(&fragmented_wire)));
    assert_eq!(
        failure(&replacement),
        Some(&FailureKind::Close(CloseFailure::DataAfterClose {
            opcode: Opcode::Binary,
        }))
    );
}

#[test]
fn close_chunking_and_trailing_partial_bytes_are_deterministic() {
    for endpoint in [Role::Client, Role::Server] {
        let sender = if endpoint == Role::Client {
            Role::Server
        } else {
            Role::Client
        };
        let wire = encoded(sender, &close_payload(None, b""));
        for split in 0..=wire.len() {
            let mut core = open_core(endpoint, config());
            let first = core.step(CoreInput::Transport(TransportBytes::new(&wire[..split])));
            let second = core.step(CoreInput::Transport(TransportBytes::new(&wire[split..])));
            assert_eq!(failure(&first), None, "endpoint={endpoint:?} split={split}");
            assert_eq!(
                failure(&second),
                None,
                "endpoint={endpoint:?} split={split}"
            );
            assert_eq!(core.state(), ConnectionState::Closing);
            let close_events = first
                .outputs()
                .chain(second.outputs())
                .filter(|output| {
                    matches!(
                        output,
                        CoreOutput::SemanticEvent(SemanticEvent::CloseReceived { .. })
                    )
                })
                .count();
            assert_eq!(close_events, 1, "endpoint={endpoint:?} split={split}");
        }
    }

    let mut wire = encoded(Role::Client, &close_payload(Some(1000), b""));
    wire.push(0x81);
    let trailing =
        open_core(Role::Server, config()).step(CoreInput::Transport(TransportBytes::new(&wire)));
    assert_eq!(
        failure(&trailing),
        Some(&FailureKind::Close(CloseFailure::TrailingBytesAfterClose))
    );
    assert_eq!(trailing.state(), ConnectionState::Closed);
}

#[test]
fn close_admission_enforces_event_write_and_total_bounds() {
    let event_config = config_with(|limits| limits.event_queue_entries = 1);
    let wire = encoded_with(Role::Client, &event_config, Opcode::Close, &[]);
    let event = open_core(Role::Server, event_config)
        .step(CoreInput::Transport(TransportBytes::new(&wire)));
    assert_eq!(
        failure(&event),
        Some(&FailureKind::Backpressure(QueueKind::Event))
    );
    assert_eq!(event.state(), ConnectionState::Closed);
    assert_eq!(event.outputs().len(), 1);

    let write_config = config_with(|limits| limits.write_queue_entries = 1)
        .with_automatic_pong_policy(AutomaticPongPolicy::ServerOnly);
    let mut wire = encoded_with(Role::Client, &write_config, Opcode::Ping, b"before");
    wire.extend_from_slice(&encoded_with(
        Role::Client,
        &write_config,
        Opcode::Close,
        &[],
    ));
    let write = open_core(Role::Server, write_config)
        .step(CoreInput::Transport(TransportBytes::new(&wire)));
    assert_eq!(
        failure(&write),
        Some(&FailureKind::Backpressure(QueueKind::Write))
    );
    assert_eq!(write.state(), ConnectionState::Closed);
    assert_eq!(write.outputs().len(), 4, "complete Ping group then Closed");

    let total_config = config_with(|limits| {
        limits.frame_bytes = 10;
        limits.message_bytes = 10;
        limits.total_buffered_bytes = 10;
    });
    let total = open_core(Role::Server, total_config).step(CoreInput::Command(local_close(
        Role::Server,
        Some(1000),
        "abc",
    )));
    assert_eq!(
        failure(&total),
        Some(&FailureKind::LimitExceeded {
            limit: LimitKind::TotalBufferedBytes,
            attempted: 12,
            maximum: 10,
        })
    );
    assert_eq!(total.state(), ConnectionState::Open);
    assert_eq!(total.outputs().len(), 0);
}

#[test]
fn closing_decoder_counts_the_retained_peer_close_in_total_budget() {
    let limited = config_with(|limits| {
        limits.frame_bytes = 125;
        limits.message_bytes = 125;
        limits.total_buffered_bytes = 125;
    });
    let close_payload = close_payload(Some(1000), &[b'r'; 123]);
    let peer_close = encoded_with(Role::Server, &config(), Opcode::Close, &close_payload);
    let mut core = open_core(Role::Client, limited);
    let admitted = core.step(CoreInput::Transport(TransportBytes::new(&peer_close)));
    assert_eq!(failure(&admitted), None);
    assert_eq!(admitted.state(), ConnectionState::Closing);

    let peer_ping = encoded_with(Role::Server, &config(), Opcode::Ping, &[b'p'; 125]);
    let rejected = core.step(CoreInput::Transport(TransportBytes::new(&peer_ping)));
    assert_eq!(
        failure(&rejected),
        Some(&FailureKind::LimitExceeded {
            limit: LimitKind::TotalBufferedBytes,
            attempted: 250,
            maximum: 125,
        })
    );
    assert_eq!(rejected.state(), ConnectionState::Closed);
    assert_eq!(
        rejected.outputs().collect::<Vec<_>>(),
        vec![&CoreOutput::StateChanged(ConnectionState::Closed)]
    );
}

#[test]
fn closing_data_opcode_precedes_message_validation_and_event_admission() {
    let mut invalid_utf8 = open_core(Role::Server, config());
    invalid_utf8.step(CoreInput::Command(local_close(Role::Server, None, "")));
    let invalid_text = encoded_with(Role::Client, &config(), Opcode::Text, &[0xff]);
    let rejected = invalid_utf8.step(CoreInput::Transport(TransportBytes::new(&invalid_text)));
    assert_eq!(
        failure(&rejected),
        Some(&FailureKind::InvalidState {
            input: InputKind::TransportBytes,
            state: ConnectionState::Closing,
        })
    );
    assert_eq!(rejected.state(), ConnectionState::Closing);
    assert_eq!(rejected.outputs().len(), 0);

    for opcode in [Opcode::Text, Opcode::Binary, Opcode::Continuation] {
        let event_limited = config_with(|limits| limits.event_queue_entries = 1);
        let mut backpressured = open_core(Role::Server, event_limited);
        backpressured.step(CoreInput::Command(local_close(Role::Server, None, "")));
        let data = encoded_with(Role::Client, &config(), opcode, &[]);
        let rejected = backpressured.step(CoreInput::Transport(TransportBytes::new(&data)));
        assert_eq!(
            failure(&rejected),
            Some(&FailureKind::InvalidState {
                input: InputKind::TransportBytes,
                state: ConnectionState::Closing,
            }),
            "closing opcode {opcode:?} must be rejected before event admission"
        );
        assert_eq!(rejected.state(), ConnectionState::Closing);
        assert_eq!(rejected.outputs().len(), 0);
    }

    let mut malformed = open_core(Role::Server, config());
    malformed.step(CoreInput::Command(local_close(Role::Server, None, "")));
    let reserved_bit_text = [0xc1, 0x80, 1, 2, 3, 4];
    let syntax = malformed.step(CoreInput::Transport(TransportBytes::new(
        &reserved_bit_text,
    )));
    assert_eq!(
        failure(&syntax),
        Some(&FailureKind::Frame(FrameFailure::ReservedBits)),
        "frame syntax still precedes closing data legality"
    );
}

#[test]
fn closed_rejects_new_protocol_inputs_and_eof_but_flush_is_a_noop() {
    let mut core = open_core(Role::Server, config());
    let wire = encoded(Role::Client, &[]);
    core.step(CoreInput::Transport(TransportBytes::new(&wire)));
    core.step(CoreInput::TransportWriteFlushed);
    assert_eq!(core.state(), ConnectionState::Closed);

    let command = core.step(CoreInput::Command(LocalCommand::SendPing {
        payload: Box::new([]),
        mask_key: None,
    }));
    assert_eq!(
        failure(&command),
        Some(&FailureKind::InvalidState {
            input: InputKind::LocalCommand,
            state: ConnectionState::Closed,
        })
    );
    let eof = core.step(CoreInput::TransportEof);
    assert_eq!(
        failure(&eof),
        Some(&FailureKind::InvalidState {
            input: InputKind::TransportEof,
            state: ConnectionState::Closed,
        })
    );
    assert_eq!(eof.state(), ConnectionState::Closed);
    assert_eq!(eof.outputs().len(), 0);

    let flush = core.step(CoreInput::TransportWriteFlushed);
    assert_eq!(failure(&flush), None);
    assert_eq!(flush.state(), ConnectionState::Closed);
    assert_eq!(flush.outputs().len(), 0);
}

#[test]
fn bounded_close_code_model_covers_each_sender_role_and_frozen_class() {
    let all_codes = [
        0,
        999,
        1000,
        1001,
        1002,
        1003,
        1004,
        1005,
        1006,
        1007,
        1008,
        1009,
        1010,
        1011,
        1012,
        1013,
        1014,
        1015,
        1016,
        2999,
        3000,
        4999,
        5000,
        u16::MAX,
    ];
    let mut cases = 0_u64;
    for sender in [Role::Client, Role::Server] {
        let endpoint = if sender == Role::Client {
            Role::Server
        } else {
            Role::Client
        };
        for code in all_codes {
            let wire = encoded(sender, &close_payload(Some(code), b""));
            let result = open_core(endpoint, config())
                .step(CoreInput::Transport(TransportBytes::new(&wire)));
            let accepted = matches!(
                code,
                1000 | 1001 | 1002 | 1003 | 1007 | 1008 | 1009 | 1011 | 1012 | 1013 | 1014 | 3000
                    ..=4999
            ) || (code == 1010 && sender == Role::Client);
            assert_eq!(
                failure(&result).is_none(),
                accepted,
                "sender={sender:?} code={code}"
            );
            assert_eq!(
                result.state(),
                if accepted {
                    ConnectionState::Closing
                } else {
                    ConnectionState::Closed
                },
                "sender={sender:?} code={code}"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 48);
    eprintln!("US016_BOUNDED_CODE_MODEL_CASES={cases}");
}

#[test]
fn us016_retained_seeds_execute_through_the_connection_core() {
    let seeds = [
        include_str!("../fuzz-seeds/us016/wrong-code.seed").trim(),
        include_str!("../fuzz-seeds/us016/missing-ack.seed").trim(),
        include_str!("../fuzz-seeds/us016/data-after-close.seed").trim(),
        include_str!("../fuzz-seeds/us016/duplicate-terminal.seed").trim(),
        include_str!("../fuzz-seeds/us016/premature-closed.seed").trim(),
        include_str!("../fuzz-seeds/us016/stale-fragment.seed").trim(),
    ];
    for seed in seeds {
        match seed {
            "inbound-invalid-code-1005" => {
                let wire = encoded(Role::Client, &close_payload(Some(1005), b""));
                let result = open_core(Role::Server, config())
                    .step(CoreInput::Transport(TransportBytes::new(&wire)));
                assert!(matches!(
                    failure(&result),
                    Some(FailureKind::Close(CloseFailure::InvalidCode {
                        code: 1005,
                        ..
                    }))
                ));
            }
            "peer-first-client-eof" => {
                let wire = encoded(Role::Server, &close_payload(Some(1000), b""));
                let mut core = open_core(Role::Client, config());
                core.step(CoreInput::Transport(TransportBytes::new(&wire)));
                assert_eq!(
                    failure(&core.step(CoreInput::TransportEof)),
                    Some(&FailureKind::Close(CloseFailure::EofBeforeAcknowledgement))
                );
            }
            "local-close-then-text" => {
                let frame_config = config();
                let wire = encoded_with(Role::Client, &frame_config, Opcode::Text, b"bad");
                let mut core = open_core(Role::Server, frame_config);
                core.step(CoreInput::Command(local_close(
                    Role::Server,
                    Some(1000),
                    "",
                )));
                assert!(matches!(
                    failure(&core.step(CoreInput::Transport(TransportBytes::new(&wire)))),
                    Some(FailureKind::InvalidState {
                        input: InputKind::TransportBytes,
                        state: ConnectionState::Closing,
                    })
                ));
            }
            "peer-close-twice" => {
                let wire = encoded(Role::Client, &[]);
                let mut core = open_core(Role::Server, config());
                core.step(CoreInput::Transport(TransportBytes::new(&wire)));
                assert_eq!(
                    failure(&core.step(CoreInput::Transport(TransportBytes::new(&wire)))),
                    Some(&FailureKind::Close(CloseFailure::DuplicatePeerClose))
                );
            }
            "local-peer-before-flush" => {
                let wire = encoded(Role::Client, &[]);
                let mut core = open_core(Role::Server, config());
                core.step(CoreInput::Command(local_close(Role::Server, None, "")));
                let peer = core.step(CoreInput::Transport(TransportBytes::new(&wire)));
                assert_eq!(peer.state(), ConnectionState::Closing);
                assert!(!peer.outputs().any(|output| matches!(
                    output,
                    CoreOutput::StateChanged(ConnectionState::Closed)
                )));
                assert_eq!(
                    core.step(CoreInput::TransportWriteFlushed).state(),
                    ConnectionState::Closed
                );
            }
            "fragment-local-close-continuation" => {
                let frame_config = config();
                let fragment = FrameEncoder::new(frame_config.clone(), Role::Client)
                    .encode(
                        OutboundFrame::new(false, Opcode::Text, b"stale"),
                        Some([1, 2, 3, 4]),
                    )
                    .unwrap();
                let continuation =
                    encoded_with(Role::Client, &frame_config, Opcode::Continuation, b"tail");
                let mut core = open_core(Role::Server, frame_config);
                core.step(CoreInput::Transport(TransportBytes::new(
                    fragment.as_slice(),
                )));
                core.step(CoreInput::Command(local_close(Role::Server, None, "")));
                let rejected = core.step(CoreInput::Transport(TransportBytes::new(&continuation)));
                assert_eq!(
                    failure(&rejected),
                    Some(&FailureKind::InvalidState {
                        input: InputKind::TransportBytes,
                        state: ConnectionState::Closing,
                    })
                );
                assert_eq!(rejected.state(), ConnectionState::Closing);
                assert_eq!(rejected.outputs().len(), 0);
            }
            other => panic!("unrecognized executable US016 seed: {other}"),
        }
    }
    assert_eq!(seeds.len(), 6);
}

#[test]
fn flush_is_an_idempotent_noop_before_closing() {
    let mut connecting = ConnectionCore::new(config(), Role::Client);
    let before = connecting.step(CoreInput::TransportWriteFlushed);
    assert_eq!(failure(&before), None);
    assert_eq!(before.state(), ConnectionState::Connecting);
    assert_eq!(before.outputs().len(), 0);

    let mut open = open_core(Role::Server, config());
    let after = open.step(CoreInput::TransportWriteFlushed);
    assert_eq!(failure(&after), None);
    assert_eq!(after.state(), ConnectionState::Open);
    assert_eq!(after.outputs().len(), 0);
}
