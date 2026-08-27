#![forbid(unsafe_code)]

use websocket_core::{
    ConfigError, ConnectionConfig, ConnectionCore, ConnectionLimits, ConnectionState, CoreInput,
    FailureKind, LimitKind, LimitRelationship, LocalCommand, Role, TransportBytes,
};

#[test]
fn defaults_create_an_immutable_connecting_core() {
    let limits = ConnectionLimits::default();
    let config = ConnectionConfig::try_from(limits).expect("documented defaults are valid");
    let core = ConnectionCore::new(config, Role::Client);

    assert_eq!(core.state(), ConnectionState::Connecting);
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
