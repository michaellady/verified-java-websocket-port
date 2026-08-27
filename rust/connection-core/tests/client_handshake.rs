#![forbid(unsafe_code)]

use websocket_core::{
    ClientRequestDescriptor, ClientRequestDescriptorError, ConnectionConfig, ConnectionCore,
    ConnectionLimits, ConnectionState, CoreInput, CoreOutput, FailureKind, HandshakeFailure,
    InputKind, LimitKind, LimitRelationship, LocalCommand, Role, SemanticEvent, TransportBytes,
};

fn client() -> ConnectionCore {
    let config = ConnectionConfig::try_from(ConnectionLimits::default()).unwrap();
    ConnectionCore::new(config, Role::Client)
}

#[test]
fn descriptor_and_fixed_nonce_emit_the_exact_canonical_request() {
    let descriptor = ClientRequestDescriptor::try_new("/chat", "server.example.com").unwrap();
    let mut core = client();

    let result = core.step(CoreInput::Command(LocalCommand::StartClientHandshake {
        descriptor: descriptor.clone(),
        nonce: *b"the sample nonce",
    }));

    assert_eq!(descriptor.request_target(), "/chat");
    assert_eq!(descriptor.host(), "server.example.com");
    assert_eq!(result.state(), ConnectionState::Connecting);
    assert_eq!(result.failure(), None);
    let outputs: Vec<_> = result.outputs().collect();
    assert_eq!(outputs.len(), 1);
    let CoreOutput::TransportWrite(write) = outputs[0] else {
        panic!("start emits only one transport write");
    };
    assert_eq!(
        write.as_slice(),
        b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
}

#[test]
fn descriptor_rejects_ambiguous_or_injectable_wire_fields() {
    assert_eq!(
        ClientRequestDescriptor::try_new("chat", "example.com"),
        Err(ClientRequestDescriptorError::RequestTargetNotOriginForm)
    );
    assert_eq!(
        ClientRequestDescriptor::try_new("/chat\r\nX-Evil: yes", "example.com"),
        Err(ClientRequestDescriptorError::InvalidRequestTargetByte)
    );
    assert_eq!(
        ClientRequestDescriptor::try_new("/chat", ""),
        Err(ClientRequestDescriptorError::EmptyHost)
    );
    assert_eq!(
        ClientRequestDescriptor::try_new("/chat", "example.com\nX-Evil: yes"),
        Err(ClientRequestDescriptorError::InvalidHostByte)
    );
    assert_eq!(
        ClientRequestDescriptor::try_new("/café", "example.com"),
        Err(ClientRequestDescriptorError::InvalidRequestTargetByte)
    );
}

#[test]
fn rfc_accept_literal_opens_the_client_after_the_fixed_nonce_request() {
    let descriptor = ClientRequestDescriptor::try_new("/chat", "server.example.com").unwrap();
    let mut core = client();
    core.step(CoreInput::Command(LocalCommand::StartClientHandshake {
        descriptor: descriptor.clone(),
        nonce: *b"the sample nonce",
    }));

    let response = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    let result = core.step(CoreInput::Transport(TransportBytes::new(response)));

    assert_eq!(result.failure(), None);
    assert_eq!(result.state(), ConnectionState::Open);
    assert_eq!(
        result.outputs().collect::<Vec<_>>(),
        vec![
            &CoreOutput::StateChanged(ConnectionState::Open),
            &CoreOutput::SemanticEvent(SemanticEvent::ClientHandshakeOpened { descriptor }),
        ]
    );
}

#[test]
fn frozen_server_response_keys_replay_with_literal_accept_values() {
    let vectors = [
        (
            [
                0x86, 0x7b, 0x7c, 0x99, 0xb9, 0x16, 0xf0, 0xa4, 0x72, 0x9d, 0xb2, 0xef, 0x24, 0x74,
                0xa8, 0x19,
            ],
            "hnt8mbkW8KRynbLvJHSoGQ==",
            "y3pK1tkFwbrj23aiGd+rFdQN4fI=",
        ),
        (
            [
                0xb2, 0x06, 0xdd, 0xab, 0xe6, 0xd5, 0xb1, 0xd6, 0xec, 0x37, 0xeb, 0x96, 0x25, 0x7c,
                0x1d, 0xc6,
            ],
            "sgbdq+bVsdbsN+uWJXwdxg==",
            "FhAb7/RcPGGRdRJreneD/TwSTIc=",
        ),
        (
            [
                0x9f, 0xcd, 0x02, 0x28, 0x23, 0xf1, 0xc3, 0xb7, 0x5a, 0x33, 0xb6, 0x7c, 0x6d, 0xbd,
                0x1f, 0x10,
            ],
            "n80CKCPxw7daM7Z8bb0fEA==",
            "eHYxjrDXEUmbD08CSrWkuQObZWI=",
        ),
    ];

    for (nonce, key, accept) in vectors {
        let descriptor = ClientRequestDescriptor::try_new("/", "example.com").unwrap();
        let mut core = client();
        let start = core.step(CoreInput::Command(LocalCommand::StartClientHandshake {
            descriptor,
            nonce,
        }));
        let CoreOutput::TransportWrite(write) = start.outputs().next().unwrap() else {
            panic!("start must write");
        };
        assert!(
            write
                .as_slice()
                .windows(key.len())
                .any(|window| window == key.as_bytes()),
            "frozen key must be serialized literally"
        );

        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        );
        let result = core.step(CoreInput::Transport(TransportBytes::new(
            response.as_bytes(),
        )));
        assert_eq!(result.failure(), None, "frozen accept {accept}");
        assert_eq!(result.state(), ConnectionState::Open);
    }
}

#[test]
fn valid_response_is_equivalent_at_every_single_split_point() {
    let response = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nX-Trace: fixed\r\n\r\n";

    for split in 0..=response.len() {
        let descriptor = ClientRequestDescriptor::try_new("/chat", "server.example.com").unwrap();
        let mut core = client();
        core.step(CoreInput::Command(LocalCommand::StartClientHandshake {
            descriptor: descriptor.clone(),
            nonce: *b"the sample nonce",
        }));

        let first = core.step(CoreInput::Transport(TransportBytes::new(
            &response[..split],
        )));
        if split < response.len() {
            assert_eq!(first.failure(), None, "split {split} first chunk");
            assert_eq!(first.state(), ConnectionState::Connecting, "split {split}");
            assert_eq!(first.outputs().len(), 0, "split {split} first chunk");
        }
        let final_result = if split == response.len() {
            first
        } else {
            core.step(CoreInput::Transport(TransportBytes::new(
                &response[split..],
            )))
        };
        assert_eq!(final_result.failure(), None, "split {split} final chunk");
        assert_eq!(final_result.state(), ConnectionState::Open, "split {split}");
        assert_eq!(
            final_result.outputs().collect::<Vec<_>>(),
            vec![
                &CoreOutput::StateChanged(ConnectionState::Open),
                &CoreOutput::SemanticEvent(SemanticEvent::ClientHandshakeOpened {
                    descriptor: descriptor.clone(),
                }),
            ],
            "split {split} ordered outputs"
        );
    }
}

fn start_default_client() -> ConnectionCore {
    let mut core = client();
    let descriptor = ClientRequestDescriptor::try_new("/", "example.com").unwrap();
    let result = core.step(CoreInput::Command(LocalCommand::StartClientHandshake {
        descriptor,
        nonce: *b"the sample nonce",
    }));
    assert_eq!(result.failure(), None);
    core
}

fn assert_fatal_response(response: &[u8], expected: HandshakeFailure) {
    let mut core = start_default_client();
    let result = core.step(CoreInput::Transport(TransportBytes::new(response)));
    assert_eq!(
        result.failure().map(|failure| &failure.kind),
        Some(&FailureKind::Handshake(expected))
    );
    assert_eq!(result.state(), ConnectionState::Closed);
    assert_eq!(
        result.outputs().collect::<Vec<_>>(),
        vec![&CoreOutput::StateChanged(ConnectionState::Closed)]
    );

    let repeated = core.step(CoreInput::Transport(TransportBytes::new(b"ignored")));
    assert_eq!(repeated.state(), ConnectionState::Closed);
    assert_eq!(
        repeated.outputs().len(),
        0,
        "Closed transition is not repeated"
    );
    assert_eq!(
        repeated.failure().map(|failure| &failure.kind),
        Some(&FailureKind::InvalidState {
            input: InputKind::TransportBytes,
            state: ConnectionState::Closed,
        })
    );
}

#[test]
fn adversarial_responses_have_exact_fatal_failures_and_ordering() {
    let cases: &[(&[u8], HandshakeFailure)] = &[
        (
            b"not-http\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
            HandshakeFailure::MalformedStatusLine,
        ),
        (
            b"HTTP/1.0 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
            HandshakeFailure::HttpVersionNot11,
        ),
        (
            b"HTTP/1.1 200 OK\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
            HandshakeFailure::StatusNotSwitchingProtocols { received: 200 },
        ),
        (
            b"HTTP/1.1 101 Switching Protocols\nUpgrade: websocket\n\n",
            HandshakeFailure::BareLineEnding,
        ),
        (
            b"HTTP/1.1 101 Switching Protocols\r\n Upgrade: websocket\r\n\r\n",
            HandshakeFailure::ObsoleteLineFolding,
        ),
        (
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade websocket\r\n\r\n",
            HandshakeFailure::MalformedHeader,
        ),
        (
            b"HTTP/1.1 101 Switching Protocols\r\nUp grade: websocket\r\n\r\n",
            HandshakeFailure::InvalidHeaderName,
        ),
        (
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nuPgRaDe: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
            HandshakeFailure::DuplicateHeader,
        ),
        (
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
            HandshakeFailure::MissingUpgrade,
        ),
        (
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: not-a-websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
            HandshakeFailure::InvalidUpgrade,
        ),
        (
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
            HandshakeFailure::MissingConnection,
        ),
        (
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: not-an-upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
            HandshakeFailure::InvalidConnection,
        ),
        (
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
            HandshakeFailure::MissingAccept,
        ),
        (
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: t3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
            HandshakeFailure::AcceptMismatch,
        ),
        (
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Extensions:\r\n\r\n",
            HandshakeFailure::UnexpectedExtension,
        ),
        (
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Protocol: chat\r\n\r\n",
            HandshakeFailure::UnexpectedSubprotocol,
        ),
        (
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n\x81",
            HandshakeFailure::TrailingData { bytes: 1 },
        ),
    ];

    for (response, expected) in cases {
        assert_fatal_response(response, expected.clone());
    }
}

#[test]
fn client_handshake_misuse_is_typed_and_non_mutating_until_request_emission() {
    let descriptor = ClientRequestDescriptor::try_new("/", "example.com").unwrap();
    let config = ConnectionConfig::try_from(ConnectionLimits::default()).unwrap();
    let mut server = ConnectionCore::new(config, Role::Server);
    let wrong_role = server.step(CoreInput::Command(LocalCommand::StartClientHandshake {
        descriptor: descriptor.clone(),
        nonce: [0; 16],
    }));
    assert_eq!(
        wrong_role.failure().map(|failure| &failure.kind),
        Some(&FailureKind::Handshake(HandshakeFailure::WrongRole))
    );
    assert_eq!(wrong_role.outputs().len(), 0);
    assert_eq!(wrong_role.state(), ConnectionState::Connecting);

    let mut not_started = client();
    let premature = not_started.step(CoreInput::Transport(TransportBytes::new(b"HTTP/1.1")));
    assert_eq!(
        premature.failure().map(|failure| &failure.kind),
        Some(&FailureKind::Handshake(
            HandshakeFailure::ResponseBeforeClientRequest
        ))
    );
    assert_eq!(premature.outputs().len(), 0);
    assert_eq!(premature.state(), ConnectionState::Connecting);

    let mut started = start_default_client();
    let repeated = started.step(CoreInput::Command(LocalCommand::StartClientHandshake {
        descriptor,
        nonce: [0; 16],
    }));
    assert_eq!(
        repeated.failure().map(|failure| &failure.kind),
        Some(&FailureKind::Handshake(
            HandshakeFailure::ClientHandshakeAlreadyStarted
        ))
    );
    assert_eq!(repeated.outputs().len(), 0);
    assert_eq!(repeated.state(), ConnectionState::Connecting);
}

#[test]
fn partial_response_eof_is_fatal_and_typed() {
    let mut core = start_default_client();
    let incomplete = core.step(CoreInput::Transport(TransportBytes::new(
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n",
    )));
    assert_eq!(incomplete.failure(), None);

    let eof = core.step(CoreInput::TransportEof);
    assert_eq!(
        eof.failure().map(|failure| &failure.kind),
        Some(&FailureKind::Handshake(HandshakeFailure::UnexpectedEof))
    );
    assert_eq!(eof.state(), ConnectionState::Closed);
    assert_eq!(
        eof.outputs().collect::<Vec<_>>(),
        vec![&CoreOutput::StateChanged(ConnectionState::Closed)]
    );
}

fn client_with_limits(limits: ConnectionLimits) -> ConnectionCore {
    let config = ConnectionConfig::try_from(limits).unwrap();
    let mut core = ConnectionCore::new(config, Role::Client);
    let descriptor = ClientRequestDescriptor::try_new("/", "e").unwrap();
    let start = core.step(CoreInput::Command(LocalCommand::StartClientHandshake {
        descriptor,
        nonce: *b"the sample nonce",
    }));
    assert_eq!(start.failure(), None, "test config must admit request");
    core
}

fn assert_limit_failure(result: &websocket_core::StepResult, expected: FailureKind) {
    assert_eq!(
        result.failure().map(|failure| &failure.kind),
        Some(&expected)
    );
    assert_eq!(result.state(), ConnectionState::Closed);
    assert_eq!(
        result.outputs().collect::<Vec<_>>(),
        vec![&CoreOutput::StateChanged(ConnectionState::Closed)]
    );
}

#[test]
fn handshake_header_limits_are_checked_during_configuration() {
    let defaults = ConnectionLimits::default();
    assert_eq!(defaults.handshake_header_count, 32);
    assert_eq!(defaults.handshake_header_line_bytes, 512);

    for kind in [
        LimitKind::HandshakeHeaderCount,
        LimitKind::HandshakeHeaderLineBytes,
    ] {
        let mut zero = ConnectionLimits::default();
        match kind {
            LimitKind::HandshakeHeaderCount => zero.handshake_header_count = 0,
            LimitKind::HandshakeHeaderLineBytes => zero.handshake_header_line_bytes = 0,
            _ => unreachable!(),
        }
        assert_eq!(
            ConnectionConfig::try_from(zero),
            Err(websocket_core::ConfigError::Zero(kind))
        );
    }

    let line_over_total = ConnectionLimits {
        handshake_bytes: 64,
        handshake_header_line_bytes: 65,
        ..ConnectionLimits::default()
    };
    assert_eq!(
        ConnectionConfig::try_from(line_over_total),
        Err(websocket_core::ConfigError::InvalidRelationship(
            LimitRelationship::HandshakeHeaderLineWithinHandshakeBytes
        ))
    );
}

#[test]
fn total_line_and_header_count_limits_fail_before_open() {
    let mut total = client_with_limits(ConnectionLimits {
        handshake_bytes: 256,
        handshake_header_line_bytes: 256,
        ..ConnectionLimits::default()
    });
    let total_bytes = [b'x'; 257];
    let result = total.step(CoreInput::Transport(TransportBytes::new(&total_bytes)));
    assert_limit_failure(
        &result,
        FailureKind::LimitExceeded {
            limit: LimitKind::HandshakeBytes,
            attempted: 257,
            maximum: 256,
        },
    );

    let mut line = client_with_limits(ConnectionLimits {
        handshake_bytes: 512,
        handshake_header_line_bytes: 64,
        ..ConnectionLimits::default()
    });
    let mut long_line = b"HTTP/1.1 101 Switching Protocols\r\nX-Long: ".to_vec();
    long_line.extend_from_slice(&[b'a'; 55]);
    long_line.extend_from_slice(b"\r\n");
    let result = line.step(CoreInput::Transport(TransportBytes::new(&long_line)));
    assert_limit_failure(
        &result,
        FailureKind::LimitExceeded {
            limit: LimitKind::HandshakeHeaderLineBytes,
            attempted: 65,
            maximum: 64,
        },
    );

    let mut count = client_with_limits(ConnectionLimits {
        handshake_bytes: 512,
        handshake_header_count: 5,
        ..ConnectionLimits::default()
    });
    let response = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nX-One: 1\r\nX-Two: 2\r\nX-Three: 3\r\n\r\n";
    let result = count.step(CoreInput::Transport(TransportBytes::new(response)));
    assert_limit_failure(
        &result,
        FailureKind::LimitExceeded {
            limit: LimitKind::HandshakeHeaderCount,
            attempted: 6,
            maximum: 5,
        },
    );
}

#[test]
fn canonical_request_obeys_the_receiving_cores_smaller_limits() {
    let descriptor = ClientRequestDescriptor::try_new("/", "example.com").unwrap();
    let limits = ConnectionLimits {
        handshake_header_count: 4,
        ..ConnectionLimits::default()
    };
    let config = ConnectionConfig::try_from(limits).unwrap();
    let mut core = ConnectionCore::new(config, Role::Client);
    let result = core.step(CoreInput::Command(LocalCommand::StartClientHandshake {
        descriptor,
        nonce: [0; 16],
    }));
    assert_eq!(
        result.failure().map(|failure| &failure.kind),
        Some(&FailureKind::LimitExceeded {
            limit: LimitKind::HandshakeHeaderCount,
            attempted: 5,
            maximum: 4,
        })
    );
    assert_eq!(result.outputs().len(), 0);
    assert_eq!(result.state(), ConnectionState::Connecting);
}
