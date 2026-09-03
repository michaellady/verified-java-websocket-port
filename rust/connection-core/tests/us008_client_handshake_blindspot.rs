//! US-008 suite-calibration blind spot: client `Sec-WebSocket-Accept` octets.
//!
//! NEW in US-008. The existing `client_handshake` suite pins the literal RFC
//! 6455 accept value and seven frozen invalid responses, but never presents a
//! near-miss accept that differs from the expected value in a single octet.
//! A comparison that ignores any one octet therefore survived the whole
//! workspace. This test pins every octet position independently.

#![forbid(unsafe_code)]

use websocket_core::{
    ClientRequestDescriptor, ConnectionConfig, ConnectionCore, ConnectionLimits, ConnectionState,
    CoreInput, FailureKind, HandshakeFailure, LocalCommand, Role, TransportBytes,
};

const RFC_ACCEPT: &[u8; 28] = b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

fn response_with_accept(accept: &[u8]) -> Vec<u8> {
    let mut response = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ".to_vec();
    response.extend_from_slice(accept);
    response.extend_from_slice(b"\r\n\r\n");
    response
}

fn started_client() -> ConnectionCore {
    let config = ConnectionConfig::try_from(ConnectionLimits::default()).expect("default limits");
    let mut core = ConnectionCore::new(config, Role::Client);
    let descriptor =
        ClientRequestDescriptor::try_new("/chat", "server.example.com").expect("descriptor");
    assert_eq!(
        core.step(CoreInput::Command(LocalCommand::StartClientHandshake {
            descriptor,
            nonce: *b"the sample nonce",
        }))
        .failure(),
        None
    );
    core
}

#[test]
fn every_accept_octet_position_is_load_bearing() {
    // The exact accept still opens the connection.
    let mut core = started_client();
    let result = core.step(CoreInput::Transport(TransportBytes::new(
        &response_with_accept(RFC_ACCEPT),
    )));
    assert_eq!(result.failure(), None);
    assert_eq!(result.state(), ConnectionState::Open);

    // Flipping any single octet — including the final base64 pad octet, which
    // is constant for every derived accept — must be an AcceptMismatch.
    for index in 0..RFC_ACCEPT.len() {
        let mut accept = *RFC_ACCEPT;
        accept[index] = if accept[index] == b'A' { b'B' } else { b'A' };
        let mut core = started_client();
        let result = core.step(CoreInput::Transport(TransportBytes::new(
            &response_with_accept(&accept),
        )));
        assert_eq!(
            result.failure().map(|failure| &failure.kind),
            Some(&FailureKind::Handshake(HandshakeFailure::AcceptMismatch)),
            "octet {index} must be compared, accept={:?}",
            core::str::from_utf8(&accept)
        );
        assert_eq!(result.state(), ConnectionState::Closed, "octet {index}");
    }

    // A truncated and an over-long accept are also mismatches.
    for accept in [&RFC_ACCEPT[..27], b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=A".as_slice()] {
        let mut core = started_client();
        let result = core.step(CoreInput::Transport(TransportBytes::new(
            &response_with_accept(accept),
        )));
        assert_eq!(
            result.failure().map(|failure| &failure.kind),
            Some(&FailureKind::Handshake(HandshakeFailure::AcceptMismatch)),
            "length {} must be compared",
            accept.len()
        );
    }
}
