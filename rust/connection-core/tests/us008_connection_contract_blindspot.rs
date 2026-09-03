//! US-008 suite-calibration blind spot: consumed-prefix accounting in `Closing`.
//!
//! NEW in US-008. `connection_contract` already pins the authoritative consumed
//! prefix for header rejections in `Open`, but every `Closing` case reachable
//! from the existing suites happens to consume the whole offered chunk. A core
//! that stopped routing `Closing` transport input through the decoder's
//! consumed-byte accounting therefore survived the whole workspace.

#![forbid(unsafe_code)]

use websocket_core::{
    ConnectionConfig, ConnectionCore, ConnectionLimits, ConnectionState, CoreInput, FailureKind,
    FrameFailure, LocalCommand, Role, TransportBytes,
};

const RFC_REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";

fn closing_server() -> ConnectionCore {
    let config = ConnectionConfig::try_from(ConnectionLimits::default()).expect("default limits");
    let mut core = ConnectionCore::new(config, Role::Server);
    assert_eq!(
        core.step(CoreInput::Transport(TransportBytes::new(RFC_REQUEST)))
            .failure(),
        None
    );
    assert_eq!(core.state(), ConnectionState::Open);
    assert_eq!(
        core.step(CoreInput::Command(LocalCommand::Close {
            code: Some(1000),
            reason: "".into(),
            mask_key: None,
        }))
        .failure(),
        None
    );
    assert_eq!(core.state(), ConnectionState::Closing);
    core
}

#[test]
fn closing_header_rejection_reports_only_the_authoritative_consumed_prefix() {
    // A masked client Ping whose 16-bit extended length declares 128 payload
    // octets. The control-payload ceiling is decided from the first two header
    // octets, so exactly those two octets are authoritative.
    let mut wire = vec![0x89, 0x80 | 126, 0x00, 0x80];
    wire.extend_from_slice(&[1, 2, 3, 4]);
    wire.extend(core::iter::repeat_n(0_u8, 128));

    let mut core = closing_server();
    let result = core.step(CoreInput::Transport(TransportBytes::new(&wire)));
    assert_eq!(
        result.failure().map(|failure| &failure.kind),
        Some(&FailureKind::Frame(FrameFailure::ControlPayloadTooLarge {
            length: 126
        }))
    );
    assert_eq!(result.state(), ConnectionState::Closed);

    let accounting = core.last_step_observation().accounting();
    assert_eq!(accounting.pre_state, ConnectionState::Closing);
    assert_eq!(accounting.post_state, ConnectionState::Closed);
    assert_eq!(
        accounting.bytes_consumed, 2,
        "a Closing header rejection consumes only the authoritative prefix, \
         not the whole offered chunk of {} octets",
        wire.len()
    );
}
