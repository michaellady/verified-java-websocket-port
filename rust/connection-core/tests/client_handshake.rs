#![forbid(unsafe_code)]

use websocket_core::{
    ClientRequestDescriptor, ClientRequestDescriptorError, ConnectionConfig, ConnectionCore,
    ConnectionLimits, ConnectionState, CoreInput, CoreOutput, LocalCommand, Role, SemanticEvent,
    TransportBytes,
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
