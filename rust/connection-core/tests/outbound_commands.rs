#![forbid(unsafe_code)]

use websocket_core::{
    ClientRequestDescriptor, ConnectionConfig, ConnectionCore, ConnectionLimits, ConnectionState,
    CoreInput, CoreOutput, FailureKind, FragmentKind, FrameFailure, LimitKind, LocalCommand, Role,
    TransportBytes,
};

const RFC_REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
const RFC_RESPONSE: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";

fn config_with(mut change: impl FnMut(&mut ConnectionLimits)) -> ConnectionConfig {
    let mut limits = ConnectionLimits::default();
    change(&mut limits);
    ConnectionConfig::try_from(limits).expect("test limits")
}

#[test]
fn outbound_fragments_use_one_data_opcode_then_continuations() {
    let config = config_with(|_| {});
    let mut server = open_server(config);
    let first = server.step(CoreInput::Command(LocalCommand::SendFragment {
        kind: FragmentKind::Text,
        final_fragment: false,
        payload: b"snng".to_vec().into_boxed_slice(),
        mask_key: None,
    }));
    assert_eq!(first.failure(), None);
    assert_eq!(wire(&first), b"\x01\x04snng");

    let final_fragment = server.step(CoreInput::Command(LocalCommand::SendFragment {
        kind: FragmentKind::Text,
        final_fragment: true,
        payload: "éjé".as_bytes().to_vec().into_boxed_slice(),
        mask_key: None,
    }));
    assert_eq!(final_fragment.failure(), None);
    assert_eq!(wire(&final_fragment), b"\x80\x05\xc3\xa9j\xc3\xa9");
}

#[test]
fn client_fragment_mask_keys_are_explicit_and_repeatable() {
    let config = config_with(|_| {});
    let mut client = open_client(config);
    let first = client.step(CoreInput::Command(LocalCommand::SendFragment {
        kind: FragmentKind::Binary,
        final_fragment: false,
        payload: b"K8B\xa4T".to_vec().into_boxed_slice(),
        mask_key: Some([1, 2, 3, 4]),
    }));
    assert_eq!(first.failure(), None);
    assert_eq!(wire(&first), b"\x02\x85\x01\x02\x03\x04J:A\xa0U");

    let final_fragment = client.step(CoreInput::Command(LocalCommand::SendFragment {
        kind: FragmentKind::Binary,
        final_fragment: true,
        payload: b"\xc2/\xbaE".to_vec().into_boxed_slice(),
        mask_key: Some([5, 6, 7, 8]),
    }));
    assert_eq!(final_fragment.failure(), None);
    assert_eq!(wire(&final_fragment), b"\x80\x84\x05\x06\x07\x08\xc7)\xbdM");
}

#[test]
fn outbound_fragment_state_kind_and_exact_message_limit_are_enforced() {
    let config = config_with(|limits| limits.message_bytes = 3);
    let mut core = open_server(config);
    let first = core.step(CoreInput::Command(LocalCommand::SendFragment {
        kind: FragmentKind::Text,
        final_fragment: false,
        payload: vec![b'a'].into_boxed_slice(),
        mask_key: None,
    }));
    assert_eq!(first.failure(), None);
    assert_eq!(wire(&first), b"\x01\x01a");

    let complete_data = core.step(CoreInput::Command(LocalCommand::SendBinary {
        payload: vec![b'b'].into_boxed_slice(),
        mask_key: None,
    }));
    assert_eq!(
        complete_data.failure().map(|failure| &failure.kind),
        Some(&FailureKind::Fragment(
            websocket_core::FragmentFailure::DataFrameWhileFragmented {
                active: websocket_core::Opcode::Text,
                received: websocket_core::Opcode::Binary,
            }
        ))
    );

    let wrong_kind = core.step(CoreInput::Command(LocalCommand::SendFragment {
        kind: FragmentKind::Binary,
        final_fragment: false,
        payload: Box::new([]),
        mask_key: None,
    }));
    assert_eq!(
        wrong_kind.failure().map(|failure| &failure.kind),
        Some(&FailureKind::Fragment(
            websocket_core::FragmentFailure::DataFrameWhileFragmented {
                active: websocket_core::Opcode::Text,
                received: websocket_core::Opcode::Binary,
            }
        ))
    );

    let exact = core.step(CoreInput::Command(LocalCommand::SendFragment {
        kind: FragmentKind::Text,
        final_fragment: true,
        payload: vec![b'b', b'c'].into_boxed_slice(),
        mask_key: None,
    }));
    assert_eq!(exact.failure(), None);
    assert_eq!(wire(&exact), b"\x80\x02bc");

    let independent = core.step(CoreInput::Command(LocalCommand::SendText {
        payload: "xyz".into(),
        mask_key: None,
    }));
    assert_eq!(independent.failure(), None);
    assert_eq!(wire(&independent), b"\x81\x03xyz");
}

fn open_server(config: ConnectionConfig) -> ConnectionCore {
    let mut core = ConnectionCore::new(config, Role::Server);
    assert_eq!(
        core.step(CoreInput::Transport(TransportBytes::new(RFC_REQUEST)))
            .failure(),
        None
    );
    assert_eq!(core.state(), ConnectionState::Open);
    core
}

fn open_client(config: ConnectionConfig) -> ConnectionCore {
    let mut core = ConnectionCore::new(config, Role::Client);
    let descriptor = ClientRequestDescriptor::try_new("/chat", "server.example.com").unwrap();
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
    assert_eq!(core.state(), ConnectionState::Open);
    core
}

fn wire(result: &websocket_core::StepResult) -> &[u8] {
    match result.outputs().next().expect("one transport write") {
        CoreOutput::TransportWrite(write) => write.as_slice(),
        other => panic!("expected write, got {other:?}"),
    }
}

#[test]
fn server_text_and_binary_commands_emit_canonical_final_frames() {
    let config = config_with(|_| {});
    let mut core = open_server(config);
    let text = core.step(CoreInput::Command(LocalCommand::SendText {
        payload: "hello".into(),
        mask_key: None,
    }));
    assert_eq!(text.failure(), None);
    assert_eq!(wire(&text), b"\x81\x05hello");

    let binary = core.step(CoreInput::Command(LocalCommand::SendBinary {
        payload: vec![0, 1, 2].into_boxed_slice(),
        mask_key: None,
    }));
    assert_eq!(binary.failure(), None);
    assert_eq!(wire(&binary), b"\x82\x03\x00\x01\x02");
}

#[test]
fn client_data_commands_require_and_apply_the_explicit_mask_key() {
    let config = config_with(|_| {});
    let mut client = open_client(config);
    let missing = client.step(CoreInput::Command(LocalCommand::SendText {
        payload: "hello".into(),
        mask_key: None,
    }));
    assert_eq!(
        missing.failure().map(|failure| &failure.kind),
        Some(&FailureKind::Frame(FrameFailure::MissingMaskKey))
    );
    assert_eq!(missing.outputs().len(), 0);
    let masked = client.step(CoreInput::Command(LocalCommand::SendText {
        payload: "hello".into(),
        mask_key: Some([1, 2, 3, 4]),
    }));
    assert_eq!(masked.failure(), None);
    assert_eq!(
        wire(&masked),
        b"\x81\x85\x01\x02\x03\x04\x69\x67\x6f\x68\x6e"
    );

    let config = config_with(|_| {});
    let mut server = open_server(config);
    let unexpected = server.step(CoreInput::Command(LocalCommand::SendBinary {
        payload: vec![1].into_boxed_slice(),
        mask_key: Some([1, 2, 3, 4]),
    }));
    assert_eq!(
        unexpected.failure().map(|failure| &failure.kind),
        Some(&FailureKind::Frame(FrameFailure::UnexpectedMaskKey))
    );
    assert_eq!(unexpected.outputs().len(), 0);
    assert_eq!(unexpected.state(), ConnectionState::Open);
}

#[test]
fn outbound_empty_and_125_byte_boundaries_are_exact() {
    let config = config_with(|_| {});
    let mut core = open_server(config);
    let empty = core.step(CoreInput::Command(LocalCommand::SendBinary {
        payload: Box::new([]),
        mask_key: None,
    }));
    assert_eq!(wire(&empty), b"\x82\x00");

    let payload = vec![b'x'; 125].into_boxed_slice();
    let boundary = core.step(CoreInput::Command(LocalCommand::SendBinary {
        payload: payload.clone(),
        mask_key: None,
    }));
    assert_eq!(&wire(&boundary)[..2], b"\x82\x7d");
    assert_eq!(&wire(&boundary)[2..], payload.as_ref());
}

#[test]
fn outbound_data_preflights_payload_and_total_caps_without_state_change() {
    let frame_limited = config_with(|limits| {
        limits.frame_bytes = 4;
        limits.message_bytes = 16;
        limits.total_buffered_bytes = 16;
    });
    let mut core = open_server(frame_limited);
    let before = core.state();
    let over = core.step(CoreInput::Command(LocalCommand::SendText {
        payload: "12345".into(),
        mask_key: None,
    }));
    assert_eq!(
        over.failure().map(|failure| &failure.kind),
        Some(&FailureKind::LimitExceeded {
            limit: LimitKind::FrameBytes,
            attempted: 5,
            maximum: 4,
        })
    );
    assert_eq!(over.outputs().len(), 0);
    assert_eq!(over.state(), before);
}
