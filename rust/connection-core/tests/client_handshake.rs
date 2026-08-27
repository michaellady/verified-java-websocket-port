#![forbid(unsafe_code)]

use websocket_core::{
    ClientRequestDescriptor, ClientRequestDescriptorError, ConnectionConfig, ConnectionCore,
    ConnectionLimits, ConnectionState, CoreInput, CoreOutput, LocalCommand, Role,
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
