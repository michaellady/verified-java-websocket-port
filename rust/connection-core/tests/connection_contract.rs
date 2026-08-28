#![forbid(unsafe_code)]

use websocket_core::{
    ClientRequestDescriptor, ConfigError, ConnectionConfig, ConnectionCore, ConnectionLimits,
    ConnectionState, CoreInput, CoreOutput, FailureKind, FrameDirection, LimitKind,
    LimitRelationship, LocalCommand, Role, TransportBytes,
};

#[test]
fn defaults_create_an_immutable_connecting_core() {
    let limits = ConnectionLimits::default();
    let config = ConnectionConfig::try_from(limits).expect("documented defaults are valid");
    let core = ConnectionCore::new(config, Role::Client);

    assert_eq!(core.state(), ConnectionState::Connecting);
}

#[test]
fn step_accounting_reports_exact_partial_consumption_and_retention() {
    const REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    let config = ConnectionConfig::try_from(ConnectionLimits::default()).unwrap();
    let mut core = ConnectionCore::new(config, Role::Server);
    assert_eq!(
        core.step(CoreInput::Transport(TransportBytes::new(REQUEST)))
            .state(),
        ConnectionState::Open
    );
    let handshake = core.last_step_observation().accounting();
    assert_eq!(handshake.bytes_consumed, REQUEST.len());
    assert_eq!(handshake.pre_state, ConnectionState::Connecting);
    assert_eq!(handshake.post_state, ConnectionState::Open);

    let partial = core.step(CoreInput::Transport(TransportBytes::new(&[0x83])));
    let accounting = core.last_step_observation().accounting();
    assert_eq!(accounting.bytes_consumed, 1);
    assert_eq!(accounting.wire_buffered_bytes, 1);
    assert_eq!(accounting.message_buffered_bytes, 0);
    assert_eq!(accounting.pre_state, ConnectionState::Open);
    assert_eq!(accounting.post_state, ConnectionState::Open);
    assert_eq!(partial.state(), ConnectionState::Open);

    let rejected = core.step(CoreInput::Transport(TransportBytes::new(&[0x00])));
    let accounting = core.last_step_observation().accounting();
    assert_eq!(accounting.bytes_consumed, 1);
    assert_eq!(accounting.wire_buffered_bytes, 0);
    assert_eq!(accounting.message_buffered_bytes, 0);
    assert_eq!(accounting.pre_state, ConnectionState::Open);
    assert_eq!(accounting.post_state, ConnectionState::Closed);
    assert_eq!(rejected.state(), ConnectionState::Closed);
}

#[test]
fn public_limit_names_are_stable_transport_diagnostics() {
    let cases = [
        (LimitKind::HandshakeBytes, "handshake bytes"),
        (LimitKind::HandshakeHeaderCount, "handshake header count"),
        (
            LimitKind::HandshakeHeaderLineBytes,
            "handshake header-line bytes",
        ),
        (LimitKind::FrameBytes, "frame bytes"),
        (LimitKind::MessageBytes, "message bytes"),
        (LimitKind::TotalBufferedBytes, "total buffered bytes"),
        (LimitKind::EventQueueEntries, "event queue entries"),
        (LimitKind::CommandQueueEntries, "command queue entries"),
        (LimitKind::WriteQueueEntries, "write queue entries"),
    ];
    for (kind, expected) in cases {
        assert_eq!(kind.to_string(), expected);
    }
}

#[test]
fn outbound_frame_observations_pin_every_public_field() {
    const REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    let config = ConnectionConfig::try_from(ConnectionLimits::default()).unwrap();
    let mut core = ConnectionCore::new(config, Role::Server);
    let _ = core.step(CoreInput::Transport(TransportBytes::new(REQUEST)));

    let _ = core.step(CoreInput::Command(LocalCommand::SendFragment {
        kind: websocket_core::FragmentKind::Binary,
        final_fragment: false,
        payload: vec![0x11, 0x22].into_boxed_slice(),
        mask_key: None,
    }));
    let observation = core.last_step_observation();
    let frames = observation.frames().collect::<Vec<_>>();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].direction(), FrameDirection::Outbound);
    assert!(!frames[0].fin());
    assert_eq!(frames[0].opcode(), websocket_core::Opcode::Binary);
    assert!(!frames[0].masked());
    assert_eq!(frames[0].payload(), [0x11, 0x22]);
    assert_eq!(frames[0].wire_length(), 4);

    let _ = core.step(CoreInput::Command(LocalCommand::SendFragment {
        kind: websocket_core::FragmentKind::Binary,
        final_fragment: true,
        payload: vec![0x33].into_boxed_slice(),
        mask_key: None,
    }));
    let frames = core.last_step_observation().frames().collect::<Vec<_>>();
    assert_eq!(frames.len(), 1);
    assert!(frames[0].fin());
    assert_eq!(frames[0].opcode(), websocket_core::Opcode::Continuation);
    assert_eq!(frames[0].payload(), [0x33]);
    assert_eq!(frames[0].wire_length(), 3);

    const RESPONSE: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    let config = ConnectionConfig::try_from(ConnectionLimits::default()).unwrap();
    let mut client = ConnectionCore::new(config, Role::Client);
    let descriptor = ClientRequestDescriptor::try_new("/chat", "server.example.com").unwrap();
    let _ = client.step(CoreInput::Command(LocalCommand::StartClientHandshake {
        descriptor,
        nonce: *b"the sample nonce",
    }));
    let _ = client.step(CoreInput::Transport(TransportBytes::new(RESPONSE)));
    let _ = client.step(CoreInput::Command(LocalCommand::SendBinary {
        payload: vec![0x44].into_boxed_slice(),
        mask_key: Some([1, 2, 3, 4]),
    }));
    let frames = client.last_step_observation().frames().collect::<Vec<_>>();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].direction(), FrameDirection::Outbound);
    assert!(frames[0].fin());
    assert_eq!(frames[0].opcode(), websocket_core::Opcode::Binary);
    assert!(frames[0].masked());
    assert_eq!(frames[0].payload(), [0x44]);
    assert_eq!(frames[0].wire_length(), 7);
}

#[test]
fn public_rsv_rejection_consumes_the_offered_chunk_then_closes() {
    const REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    const US005_PUBLIC_0005: &[u8] = b"\xa1\x83\x74\xb3\xd8\xd2\x08\xe9\x85";
    let config = ConnectionConfig::try_from(ConnectionLimits::default()).unwrap();
    let mut core = ConnectionCore::new(config, Role::Server);
    assert_eq!(
        core.step(CoreInput::Transport(TransportBytes::new(REQUEST)))
            .state(),
        ConnectionState::Open
    );

    let rejected = core.step(CoreInput::Transport(TransportBytes::new(US005_PUBLIC_0005)));
    assert_eq!(
        rejected.failure().map(|failure| &failure.kind),
        Some(&FailureKind::Frame(
            websocket_core::FrameFailure::ReservedBits
        ))
    );
    assert_eq!(rejected.state(), ConnectionState::Closed);
    assert_eq!(
        rejected.outputs().collect::<Vec<_>>(),
        vec![&CoreOutput::StateChanged(ConnectionState::Closed)]
    );
    let accounting = core.last_step_observation().accounting();
    assert_eq!(accounting.bytes_consumed, US005_PUBLIC_0005.len());
    assert_eq!(accounting.wire_buffered_bytes, 0);
    assert_eq!(accounting.message_buffered_bytes, 0);
    assert_eq!(accounting.pre_state, ConnectionState::Open);
    assert_eq!(accounting.post_state, ConnectionState::Closed);
}

#[test]
fn public_closed_state_rejection_does_not_consume_unaccepted_bytes() {
    const REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    const US005_PUBLIC_0015: &[u8] = b"\x5d\x87\x0a";
    let config = ConnectionConfig::try_from(ConnectionLimits::default()).unwrap();
    let mut core = ConnectionCore::new(config, Role::Server);
    assert_eq!(
        core.step(CoreInput::Transport(TransportBytes::new(REQUEST)))
            .state(),
        ConnectionState::Open
    );
    assert_eq!(
        core.step(CoreInput::TransportEof).state(),
        ConnectionState::Closed
    );

    let rejected = core.step(CoreInput::Transport(TransportBytes::new(US005_PUBLIC_0015)));
    assert_eq!(
        rejected.failure().map(|failure| &failure.kind),
        Some(&FailureKind::InvalidState {
            input: websocket_core::InputKind::TransportBytes,
            state: ConnectionState::Closed,
        })
    );
    assert_eq!(rejected.state(), ConnectionState::Closed);
    assert_eq!(rejected.outputs().len(), 0);
    let accounting = core.last_step_observation().accounting();
    assert_eq!(accounting.bytes_consumed, 0);
    assert_eq!(accounting.wire_buffered_bytes, 0);
    assert_eq!(accounting.message_buffered_bytes, 0);
    assert_eq!(accounting.pre_state, ConnectionState::Closed);
    assert_eq!(accounting.post_state, ConnectionState::Closed);
}

#[test]
fn public_empty_bytes_in_closed_are_a_no_op_distinct_from_eof() {
    const REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    let config = ConnectionConfig::try_from(ConnectionLimits::default()).unwrap();
    let mut core = ConnectionCore::new(config, Role::Server);
    assert_eq!(
        core.step(CoreInput::Transport(TransportBytes::new(REQUEST)))
            .state(),
        ConnectionState::Open
    );
    assert_eq!(
        core.step(CoreInput::TransportEof).state(),
        ConnectionState::Closed
    );

    let empty_bytes = core.step(CoreInput::Transport(TransportBytes::new(&[])));
    assert_eq!(empty_bytes.failure(), None);
    assert_eq!(empty_bytes.state(), ConnectionState::Closed);
    assert_eq!(empty_bytes.outputs().len(), 0);
    let accounting = core.last_step_observation().accounting();
    assert_eq!(accounting.bytes_consumed, 0);
    assert_eq!(accounting.wire_buffered_bytes, 0);
    assert_eq!(accounting.message_buffered_bytes, 0);
    assert_eq!(accounting.pre_state, ConnectionState::Closed);
    assert_eq!(accounting.post_state, ConnectionState::Closed);
}

#[test]
fn public_header_rejections_report_the_authoritative_consumed_prefix() {
    const REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    const CONTROL_NONFIN: &[u8] = b"\x09\x84\xae\xdd\xf2\xad\x29\xaa\x22\x8a";
    let config = ConnectionConfig::try_from(ConnectionLimits::default()).unwrap();
    let mut core = ConnectionCore::new(config.clone(), Role::Server);
    assert_eq!(
        core.step(CoreInput::Transport(TransportBytes::new(REQUEST)))
            .state(),
        ConnectionState::Open
    );
    let fragmented_control = core.step(CoreInput::Transport(TransportBytes::new(CONTROL_NONFIN)));
    assert_eq!(
        fragmented_control.failure().map(|failure| &failure.kind),
        Some(&FailureKind::Frame(
            websocket_core::FrameFailure::FragmentedControl {
                opcode: websocket_core::Opcode::Ping,
            }
        ))
    );
    assert_eq!(
        core.last_step_observation().accounting().bytes_consumed,
        CONTROL_NONFIN.len()
    );

    let mut oversized = ConnectionCore::new(config, Role::Server);
    assert_eq!(
        oversized
            .step(CoreInput::Transport(TransportBytes::new(REQUEST)))
            .state(),
        ConnectionState::Open
    );
    let rejected = oversized.step(CoreInput::Transport(TransportBytes::new(&[
        0x89, 0xfe, 0x00, 0x7e,
    ])));
    assert_eq!(
        rejected.failure().map(|failure| &failure.kind),
        Some(&FailureKind::Frame(
            websocket_core::FrameFailure::ControlPayloadTooLarge { length: 126 }
        ))
    );
    assert_eq!(
        oversized
            .last_step_observation()
            .accounting()
            .bytes_consumed,
        2
    );
}

#[test]
fn public_fragment_sequence_failures_observe_the_rejected_frame_and_retained_message() {
    const REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    const UNEXPECTED_CONTINUATION: &[u8] = b"\x80\x83\x1c\x9b\xca\xdf\xfe\xf5\x41";
    const FRAGMENT_START: &[u8] = b"\x01\x83\x06\x5e\x10\x39\x51\x23\x2d";
    const DATA_DURING_FRAGMENT: &[u8] = b"\x82\x83\x7a\x82\x41\x89\x25\x26\xaa";
    let config = ConnectionConfig::try_from(ConnectionLimits::default()).unwrap();

    let mut continuation = ConnectionCore::new(config.clone(), Role::Server);
    let _ = continuation.step(CoreInput::Transport(TransportBytes::new(REQUEST)));
    let rejected = continuation.step(CoreInput::Transport(TransportBytes::new(
        UNEXPECTED_CONTINUATION,
    )));
    assert_eq!(
        rejected.failure().map(|failure| &failure.kind),
        Some(&FailureKind::Fragment(
            websocket_core::FragmentFailure::ContinuationWithoutMessage
        ))
    );
    let observation = continuation.last_step_observation();
    assert_eq!(observation.accounting().bytes_consumed, 9);
    assert_eq!(observation.frames().len(), 1);

    let mut active = ConnectionCore::new(config, Role::Server);
    let _ = active.step(CoreInput::Transport(TransportBytes::new(REQUEST)));
    assert_eq!(
        active
            .step(CoreInput::Transport(TransportBytes::new(FRAGMENT_START)))
            .failure(),
        None
    );
    assert_eq!(
        active
            .last_step_observation()
            .accounting()
            .message_buffered_bytes,
        3
    );
    let rejected = active.step(CoreInput::Transport(TransportBytes::new(
        DATA_DURING_FRAGMENT,
    )));
    assert_eq!(
        rejected.failure().map(|failure| &failure.kind),
        Some(&FailureKind::Fragment(
            websocket_core::FragmentFailure::DataFrameWhileFragmented {
                active: websocket_core::Opcode::Text,
                received: websocket_core::Opcode::Binary,
            }
        ))
    );
    let observation = active.last_step_observation();
    assert_eq!(observation.accounting().bytes_consumed, 9);
    assert_eq!(observation.accounting().message_buffered_bytes, 3);
    assert_eq!(observation.frames().len(), 1);
}

#[test]
fn public_data_frame_in_closing_is_observed_then_rejected_without_transition() {
    const REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    const DATA_IN_CLOSING: &[u8] = b"\x81\x83\xb0\xd2\x35\x2c\x9b\xf5\x6e";
    let config = ConnectionConfig::try_from(ConnectionLimits::default()).unwrap();
    let mut core = ConnectionCore::new(config, Role::Server);
    let _ = core.step(CoreInput::Transport(TransportBytes::new(REQUEST)));
    assert_eq!(
        core.step(CoreInput::Command(LocalCommand::Close {
            code: Some(1000),
            reason: "".into(),
            mask_key: None,
        }))
        .state(),
        ConnectionState::Closing
    );

    let rejected = core.step(CoreInput::Transport(TransportBytes::new(DATA_IN_CLOSING)));
    assert_eq!(
        rejected.failure().map(|failure| &failure.kind),
        Some(&FailureKind::InvalidState {
            input: websocket_core::InputKind::TransportBytes,
            state: ConnectionState::Closing,
        })
    );
    assert_eq!(rejected.state(), ConnectionState::Closing);
    assert_eq!(rejected.outputs().len(), 0);
    let observation = core.last_step_observation();
    assert_eq!(
        observation.accounting().bytes_consumed,
        DATA_IN_CLOSING.len()
    );
    assert_eq!(observation.frames().len(), 1);
    assert_eq!(observation.accounting().pre_state, ConnectionState::Closing);
    assert_eq!(
        observation.accounting().post_state,
        ConnectionState::Closing
    );
}

#[test]
fn public_eof_in_closed_is_a_typed_state_violation() {
    const REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    let config = ConnectionConfig::try_from(ConnectionLimits::default()).unwrap();
    let mut core = ConnectionCore::new(config, Role::Server);
    let _ = core.step(CoreInput::Transport(TransportBytes::new(REQUEST)));
    assert_eq!(
        core.step(CoreInput::TransportEof).state(),
        ConnectionState::Closed
    );
    let rejected = core.step(CoreInput::TransportEof);
    assert_eq!(
        rejected.failure().map(|failure| &failure.kind),
        Some(&FailureKind::InvalidState {
            input: websocket_core::InputKind::TransportEof,
            state: ConnectionState::Closed,
        })
    );
    assert_eq!(rejected.state(), ConnectionState::Closed);
    assert_eq!(rejected.outputs().len(), 0);
}

const BYTE_CEILING: u64 = 1_048_576;
const QUEUE_CEILING: u64 = 4_096;

fn set_limit(limits: &mut ConnectionLimits, kind: LimitKind, value: u64) {
    match kind {
        LimitKind::HandshakeBytes => {
            limits.handshake_bytes = value;
            if value > 0 {
                limits.handshake_header_line_bytes = limits.handshake_header_line_bytes.min(value);
            }
        }
        LimitKind::HandshakeHeaderCount => limits.handshake_header_count = value,
        LimitKind::HandshakeHeaderLineBytes => {
            limits.handshake_header_line_bytes = value;
            if value <= BYTE_CEILING && value > limits.handshake_bytes {
                limits.handshake_bytes = value;
            }
        }
        LimitKind::FrameBytes => limits.frame_bytes = value,
        LimitKind::MessageBytes => limits.message_bytes = value,
        LimitKind::TotalBufferedBytes => {
            limits.total_buffered_bytes = value;
            if value > 0 {
                limits.frame_bytes = limits.frame_bytes.min(value);
                limits.message_bytes = limits.message_bytes.min(value);
            }
        }
        LimitKind::EventQueueEntries => limits.event_queue_entries = value,
        LimitKind::CommandQueueEntries => limits.command_queue_entries = value,
        LimitKind::WriteQueueEntries => limits.write_queue_entries = value,
    }
}

fn ceiling(kind: LimitKind) -> u64 {
    match kind {
        LimitKind::HandshakeBytes
        | LimitKind::HandshakeHeaderLineBytes
        | LimitKind::FrameBytes
        | LimitKind::MessageBytes
        | LimitKind::TotalBufferedBytes => BYTE_CEILING,
        LimitKind::HandshakeHeaderCount
        | LimitKind::EventQueueEntries
        | LimitKind::CommandQueueEntries
        | LimitKind::WriteQueueEntries => QUEUE_CEILING,
    }
}

#[test]
fn all_nine_limits_enforce_zero_boundary_and_overflow_inputs() {
    let kinds = [
        LimitKind::HandshakeBytes,
        LimitKind::HandshakeHeaderCount,
        LimitKind::HandshakeHeaderLineBytes,
        LimitKind::FrameBytes,
        LimitKind::MessageBytes,
        LimitKind::TotalBufferedBytes,
        LimitKind::EventQueueEntries,
        LimitKind::CommandQueueEntries,
        LimitKind::WriteQueueEntries,
    ];

    for kind in kinds {
        let mut zero = ConnectionLimits::default();
        set_limit(&mut zero, kind, 0);
        assert_eq!(
            ConnectionConfig::try_from(zero),
            Err(ConfigError::Zero(kind))
        );

        let mut one = ConnectionLimits::default();
        set_limit(&mut one, kind, 1);
        assert!(
            ConnectionConfig::try_from(one).is_ok(),
            "{kind} accepts one"
        );

        let maximum = ceiling(kind);
        let mut boundary = ConnectionLimits::default();
        set_limit(&mut boundary, kind, maximum);
        assert!(
            ConnectionConfig::try_from(boundary).is_ok(),
            "{kind} accepts its hard boundary"
        );

        for attempted in [maximum + 1, u64::MAX] {
            let mut over = ConnectionLimits::default();
            set_limit(&mut over, kind, attempted);
            assert_eq!(
                ConnectionConfig::try_from(over),
                Err(ConfigError::ExceedsHardCeiling {
                    limit: kind,
                    attempted,
                    maximum,
                }),
                "{kind} rejects {attempted} before allocation"
            );
        }
    }
}

#[test]
fn frame_and_message_must_fit_the_total_buffer_budget() {
    let frame_over = ConnectionLimits {
        frame_bytes: 101,
        message_bytes: 100,
        total_buffered_bytes: 100,
        ..ConnectionLimits::default()
    };
    assert_eq!(
        ConnectionConfig::try_from(frame_over),
        Err(ConfigError::InvalidRelationship(
            LimitRelationship::FrameWithinTotalBufferedBytes
        ))
    );

    let message_over = ConnectionLimits {
        frame_bytes: 100,
        message_bytes: 101,
        total_buffered_bytes: 100,
        ..ConnectionLimits::default()
    };
    assert_eq!(
        ConnectionConfig::try_from(message_over),
        Err(ConfigError::InvalidRelationship(
            LimitRelationship::MessageWithinTotalBufferedBytes
        ))
    );
}

#[test]
fn accepted_config_preserves_exact_values_and_checked_aggregate() {
    let limits = ConnectionLimits {
        handshake_bytes: 3,
        handshake_header_count: 2,
        handshake_header_line_bytes: 1,
        frame_bytes: 4,
        message_bytes: 5,
        total_buffered_bytes: 6,
        event_queue_entries: 7,
        command_queue_entries: 8,
        write_queue_entries: 9,
    };
    let config = ConnectionConfig::try_from(limits).expect("valid worked example");

    assert_eq!(config.limits(), &limits);
    assert_eq!(config.aggregate_capacity(), 45);
}

#[test]
fn every_protocol_bearing_input_is_an_explicit_non_success() {
    let config = ConnectionConfig::try_from(ConnectionLimits::default()).unwrap();
    let mut client = ConnectionCore::new(config, Role::Client);
    let wire = b"GET / HTTP/1.1\r\n\r\n";

    let before_request = client.step(CoreInput::Transport(TransportBytes::new(wire)));
    assert_eq!(before_request.outputs().len(), 0);
    assert_eq!(before_request.state(), ConnectionState::Connecting);
    assert_eq!(
        before_request
            .failure()
            .map(|failure| (&failure.kind, failure.state_after)),
        Some((
            &FailureKind::Handshake(websocket_core::HandshakeFailure::ResponseBeforeClientRequest),
            ConnectionState::Connecting,
        ))
    );
    let cases = [
        LocalCommand::SendText {
            payload: "text".into(),
            mask_key: None,
        },
        LocalCommand::SendBinary {
            payload: vec![1, 2].into_boxed_slice(),
            mask_key: None,
        },
    ];
    for command in cases {
        let result = client.step(CoreInput::Command(command));
        assert_eq!(result.outputs().len(), 0);
        assert_eq!(result.state(), ConnectionState::Connecting);
        assert_eq!(
            result.failure().map(|failure| &failure.kind),
            Some(&FailureKind::InvalidState {
                input: websocket_core::InputKind::LocalCommand,
                state: ConnectionState::Connecting,
            })
        );
    }
    let close = client.step(CoreInput::Command(LocalCommand::Close {
        code: Some(1000),
        reason: "done".into(),
        mask_key: Some([1, 2, 3, 4]),
    }));
    assert_eq!(close.outputs().len(), 0);
    assert_eq!(
        close.failure().map(|failure| &failure.kind),
        Some(&FailureKind::InvalidState {
            input: websocket_core::InputKind::LocalCommand,
            state: ConnectionState::Connecting,
        })
    );
    for command in [
        LocalCommand::SendPing {
            payload: vec![3].into_boxed_slice(),
            mask_key: Some([1, 2, 3, 4]),
        },
        LocalCommand::SendPong {
            payload: vec![4].into_boxed_slice(),
            mask_key: Some([5, 6, 7, 8]),
        },
    ] {
        let result = client.step(CoreInput::Command(command));
        assert_eq!(result.outputs().len(), 0);
        assert_eq!(
            result.failure().map(|failure| &failure.kind),
            Some(&FailureKind::InvalidState {
                input: websocket_core::InputKind::LocalCommand,
                state: ConnectionState::Connecting,
            })
        );
    }
    let eof = client.step(CoreInput::TransportEof);
    assert_eq!(
        eof.failure().map(|failure| &failure.kind),
        Some(&FailureKind::Handshake(
            websocket_core::HandshakeFailure::UnexpectedEof,
        ))
    );
    assert_eq!(eof.state(), ConnectionState::Closed);
    assert_eq!(client.state(), ConnectionState::Closed);
}

#[test]
fn equal_cores_return_identical_results_for_identical_ordered_inputs() {
    let config = ConnectionConfig::try_from(ConnectionLimits::default()).unwrap();
    let mut left = ConnectionCore::new(config.clone(), Role::Client);
    let mut right = ConnectionCore::new(config, Role::Client);
    let bytes = b"same input";

    let left_results = [
        left.step(CoreInput::Transport(TransportBytes::new(bytes))),
        left.step(CoreInput::Command(LocalCommand::SendText {
            payload: "same".into(),
            mask_key: None,
        })),
        left.step(CoreInput::TransportEof),
    ];
    let right_results = [
        right.step(CoreInput::Transport(TransportBytes::new(bytes))),
        right.step(CoreInput::Command(LocalCommand::SendText {
            payload: "same".into(),
            mask_key: None,
        })),
        right.step(CoreInput::TransportEof),
    ];

    assert_eq!(left_results, right_results);
    assert_eq!(left.state(), right.state());
}

#[test]
fn transport_bytes_preserve_the_callers_borrow() {
    let source = [9, 8, 7];
    let borrowed = TransportBytes::new(&source);

    assert_eq!(borrowed.as_slice(), &source);
    assert!(core::ptr::eq(borrowed.as_slice().as_ptr(), source.as_ptr()));
}

#[test]
fn connection_core_is_send_without_internal_sharing() {
    fn assert_send<T: Send>() {}
    assert_send::<ConnectionCore>();
}

#[test]
fn zero_handshake_limit_is_rejected_before_core_creation() {
    let limits = ConnectionLimits {
        handshake_bytes: 0,
        ..ConnectionLimits::default()
    };

    assert_eq!(
        ConnectionConfig::try_from(limits),
        Err(ConfigError::Zero(LimitKind::HandshakeBytes))
    );
}
