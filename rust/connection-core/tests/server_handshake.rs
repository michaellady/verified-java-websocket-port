#![forbid(unsafe_code)]

use websocket_core::{
    ConnectionConfig, ConnectionCore, ConnectionLimits, ConnectionState, CoreInput, CoreOutput,
    Role, SemanticEvent, TransportBytes,
};

fn server() -> ConnectionCore {
    let config = ConnectionConfig::try_from(ConnectionLimits::default()).unwrap();
    ConnectionCore::new(config, Role::Server)
}

const RFC_REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";

const RFC_RESPONSE: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";

#[test]
fn rfc_request_emits_canonical_response_before_open_and_descriptor() {
    let mut core = server();
    let result = core.step(CoreInput::Transport(TransportBytes::new(RFC_REQUEST)));

    assert_eq!(result.failure(), None);
    assert_eq!(result.state(), ConnectionState::Open);
    assert_eq!(core.state(), ConnectionState::Open);
    let outputs: Vec<_> = result.outputs().collect();
    assert_eq!(outputs.len(), 3);
    let CoreOutput::TransportWrite(write) = outputs[0] else {
        panic!("the 101 transport write must be first");
    };
    assert_eq!(write.as_slice(), RFC_RESPONSE);
    assert_eq!(outputs[1], &CoreOutput::StateChanged(ConnectionState::Open));
    let CoreOutput::SemanticEvent(SemanticEvent::ServerHandshakeOpened { descriptor }) = outputs[2]
    else {
        panic!("the parser-produced descriptor event must be last");
    };
    assert_eq!(descriptor.request_target(), "/chat");
    assert_eq!(descriptor.host(), "server.example.com");
}
