#![forbid(unsafe_code)]

use websocket_core::{
    CloseInitiator, ConnectionConfig, ConnectionLimits, ConnectionState, FailureKind, InputKind,
    LocalCommand, Role, SemanticEvent, TransportBytes,
};
use websocket_driver::{
    ClosedObservationInput, CommandDisposition, DeferredReason, DriverInput, DriverInputError,
    DriverOutput, EnqueueError, InputDisposition, connection_driver,
};

const RFC_REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";

fn config(command_queue_entries: u64) -> ConnectionConfig {
    ConnectionConfig::try_from(ConnectionLimits {
        command_queue_entries,
        ..ConnectionLimits::default()
    })
    .unwrap()
}

fn text(payload: &str) -> LocalCommand {
    LocalCommand::SendText {
        payload: payload.into(),
        mask_key: None,
    }
}

fn open_server(owner: &mut websocket_driver::ConnectionOwner) {
    let opening = owner.poll(DriverInput::Inbound(TransportBytes::new(RFC_REQUEST)));
    let opening_len = match opening.output {
        DriverOutput::Write(bytes) => bytes.len(),
        other => panic!("expected opening write, got {other:?}"),
    };
    assert!(matches!(
        owner
            .poll(DriverInput::WriteProgress { bytes: opening_len })
            .output,
        DriverOutput::StateChanged(ConnectionState::Open)
    ));
    assert!(matches!(
        owner.poll(DriverInput::Wake).output,
        DriverOutput::Event(SemanticEvent::ServerHandshakeOpened { .. })
    ));
    assert!(matches!(
        owner.poll(DriverInput::Wake).output,
        DriverOutput::Idle
    ));
}

#[test]
fn command_handle_is_exactly_bounded_and_returns_rejected_ownership() {
    let (handle, _owner) = connection_driver(config(1), Role::Server);
    handle.try_enqueue(text("first")).unwrap();
    assert_eq!(
        handle.try_enqueue(text("second")),
        Err(EnqueueError::Full(text("second")))
    );
}

#[test]
fn owner_preserves_front_write_suffix_and_defers_inbound_until_it_drains() {
    let (_handle, mut owner) = connection_driver(config(2), Role::Server);
    let opened = owner.poll(DriverInput::Inbound(TransportBytes::new(RFC_REQUEST)));
    let full = match opened.output {
        DriverOutput::Write(bytes) => bytes.len(),
        other => panic!("expected opening write, got {other:?}"),
    };
    assert_eq!(
        opened.input,
        InputDisposition::Consumed {
            bytes: RFC_REQUEST.len()
        }
    );

    let partial = owner.poll(DriverInput::WriteProgress { bytes: 3 });
    match partial.output {
        DriverOutput::Write(bytes) => assert_eq!(bytes.len(), full - 3),
        other => panic!("expected retained suffix, got {other:?}"),
    }
    let deferred = owner.poll(DriverInput::Inbound(TransportBytes::new(b"\x89\x00")));
    assert_eq!(
        deferred.input,
        InputDisposition::Deferred(DeferredReason::OutputPending)
    );
    assert!(matches!(deferred.output, DriverOutput::Write(_)));
}

#[test]
fn queued_command_is_applied_once_and_driver_never_encodes_it() {
    let (handle, mut owner) = connection_driver(config(2), Role::Server);
    let opening = owner.poll(DriverInput::Inbound(TransportBytes::new(RFC_REQUEST)));
    let opening_len = match opening.output {
        DriverOutput::Write(bytes) => bytes.len(),
        other => panic!("{other:?}"),
    };
    let _ = owner.poll(DriverInput::WriteProgress { bytes: opening_len });
    let _ = owner.poll(DriverInput::Wake);
    let _ = owner.poll(DriverInput::Wake);

    handle.try_enqueue(text("ok")).unwrap();
    let applied = owner.poll(DriverInput::Wake);
    assert_eq!(
        applied.command,
        Some(CommandDisposition::Applied(text("ok")))
    );
    match applied.output {
        DriverOutput::Write(bytes) => assert_eq!(bytes, b"\x81\x02ok"),
        other => panic!("expected canonical core write, got {other:?}"),
    }
    assert_eq!(applied.state, ConnectionState::Open);
}

#[test]
fn owner_exposes_read_only_core_step_accounting() {
    let (_handle, mut owner) = connection_driver(config(2), Role::Server);
    open_server(&mut owner);
    let result = owner.poll(DriverInput::Inbound(TransportBytes::new(&[0x81])));
    assert_eq!(result.input, InputDisposition::Consumed { bytes: 1 });
    let accounting = owner
        .last_core_observation()
        .expect("inbound reached the core")
        .accounting();
    assert_eq!(accounting.bytes_consumed, 1);
    assert_eq!(accounting.wire_buffered_bytes, 1);
    assert_eq!(accounting.message_buffered_bytes, 0);
    assert_eq!(accounting.pre_state, ConnectionState::Open);
    assert_eq!(accounting.post_state, ConnectionState::Open);
}

#[test]
fn shutdown_closes_admission_and_terminal_is_delivered_exactly_once() {
    let (handle, mut owner) = connection_driver(config(2), Role::Server);
    let first = owner.poll(DriverInput::Shutdown);
    assert!(matches!(first.output, DriverOutput::Failure(_)));
    assert_eq!(
        handle.try_enqueue(text("late")),
        Err(EnqueueError::ShuttingDown(text("late")))
    );
    let terminal = owner.poll(DriverInput::Wake);
    assert!(matches!(terminal.output, DriverOutput::Terminal(_)));
    for _ in 0..3 {
        assert!(matches!(
            owner.poll(DriverInput::Wake).output,
            DriverOutput::Idle
        ));
    }
}

#[test]
fn accepted_commands_are_terminal_rejected_before_the_single_terminal() {
    let (handle, mut owner) = connection_driver(config(2), Role::Server);
    handle.try_enqueue(text("one")).unwrap();
    handle.try_enqueue(text("two")).unwrap();
    assert!(matches!(
        owner.poll(DriverInput::Shutdown).output,
        DriverOutput::Failure(_)
    ));
    for expected in [text("one"), text("two")] {
        let drained = owner.poll(DriverInput::Wake);
        assert_eq!(
            drained.command,
            Some(CommandDisposition::TerminalRejected(expected))
        );
        assert!(matches!(drained.output, DriverOutput::Idle));
    }
    assert!(matches!(
        owner.poll(DriverInput::Wake).output,
        DriverOutput::Terminal(_)
    ));
}

#[test]
fn invalid_write_progress_is_rejected_without_advancing_the_suffix() {
    let (_handle, mut owner) = connection_driver(config(2), Role::Server);
    let offered = owner.poll(DriverInput::Inbound(TransportBytes::new(RFC_REQUEST)));
    let length = match offered.output {
        DriverOutput::Write(bytes) => bytes.len(),
        other => panic!("expected write, got {other:?}"),
    };
    let rejected = owner.poll(DriverInput::WriteProgress { bytes: length + 1 });
    assert_eq!(
        rejected.input,
        InputDisposition::Rejected(DriverInputError::InvalidWriteProgress {
            attempted: length + 1,
            remaining: length,
        })
    );
    match rejected.output {
        DriverOutput::Write(bytes) => assert_eq!(bytes.len(), length),
        other => panic!("write suffix changed after rejection: {other:?}"),
    }
}

#[test]
fn shutdown_aborts_an_undrainable_write_and_converges_without_progress() {
    let (_handle, mut owner) = connection_driver(config(2), Role::Server);
    assert!(matches!(
        owner
            .poll(DriverInput::Inbound(TransportBytes::new(RFC_REQUEST)))
            .output,
        DriverOutput::Write(_)
    ));
    let mut terminal = 0;
    for input in
        std::iter::once(DriverInput::Shutdown).chain(std::iter::repeat_n(DriverInput::Wake, 8))
    {
        match owner.poll(input).output {
            DriverOutput::Write(_) => panic!("shutdown retained an undrainable write"),
            DriverOutput::Terminal(_) => terminal += 1,
            _ => {}
        }
    }
    assert_eq!(terminal, 1);
}

#[test]
fn queued_command_envelopes_share_the_total_buffer_budget() {
    let limits = ConnectionLimits {
        frame_bytes: 8,
        message_bytes: 8,
        total_buffered_bytes: 8,
        command_queue_entries: 2,
        ..ConnectionLimits::default()
    };
    let (handle, _owner) =
        connection_driver(ConnectionConfig::try_from(limits).unwrap(), Role::Server);
    handle.try_enqueue(text("12345")).unwrap();
    assert_eq!(
        handle.try_enqueue(text("67890")),
        Err(EnqueueError::LimitExceeded {
            command: text("67890"),
            attempted: 10,
            maximum: 8,
        })
    );
}

#[test]
fn public_driver_applies_binary_and_producer_ping_with_canonical_writes() {
    let (handle, mut owner) = connection_driver(config(2), Role::Server);
    open_server(&mut owner);

    let binary = LocalCommand::SendBinary {
        payload: vec![0, 255].into_boxed_slice(),
        mask_key: None,
    };
    handle.try_enqueue(binary.clone()).unwrap();
    let applied = owner.poll(DriverInput::Wake);
    assert_eq!(applied.command, Some(CommandDisposition::Applied(binary)));
    assert!(matches!(applied.output, DriverOutput::Write(bytes) if bytes == [0x82, 2, 0, 255]));
    assert!(matches!(
        owner.poll(DriverInput::WriteProgress { bytes: 4 }).output,
        DriverOutput::Idle
    ));
    assert!(matches!(
        owner.poll(DriverInput::Wake).output,
        DriverOutput::Idle
    ));

    let ping = LocalCommand::SendPing {
        payload: Box::new([b'p']),
        mask_key: None,
    };
    handle.try_enqueue(ping.clone()).unwrap();
    let applied = owner.poll(DriverInput::Wake);
    assert_eq!(applied.command, Some(CommandDisposition::Applied(ping)));
    assert!(matches!(applied.output, DriverOutput::Write(bytes) if bytes == [0x89, 1, b'p']));
}

#[test]
fn public_driver_orders_local_and_simultaneous_peer_close_before_one_terminal() {
    const MASKED_EMPTY_CLOSE: &[u8] = b"\x88\x80\x01\x02\x03\x04";
    let (handle, mut owner) = connection_driver(config(2), Role::Server);
    open_server(&mut owner);
    let close = LocalCommand::Close {
        code: None,
        reason: "".into(),
        mask_key: None,
    };
    handle.try_enqueue(close.clone()).unwrap();
    let local = owner.poll(DriverInput::Wake);
    assert_eq!(local.command, Some(CommandDisposition::Applied(close)));
    assert_eq!(local.state, ConnectionState::Closing);
    assert!(matches!(local.output, DriverOutput::Write(bytes) if bytes == [0x88, 0]));

    let deferred = owner.poll(DriverInput::Inbound(TransportBytes::new(
        MASKED_EMPTY_CLOSE,
    )));
    assert_eq!(
        deferred.input,
        InputDisposition::Deferred(DeferredReason::OutputPending)
    );
    assert!(matches!(deferred.output, DriverOutput::Write(_)));
    assert!(matches!(
        owner.poll(DriverInput::WriteProgress { bytes: 2 }).output,
        DriverOutput::StateChanged(ConnectionState::Closing)
    ));
    assert_eq!(
        owner
            .poll(DriverInput::Inbound(TransportBytes::new(
                MASKED_EMPTY_CLOSE
            )))
            .input,
        InputDisposition::Deferred(DeferredReason::FlushPending)
    );
    let peer = owner.poll(DriverInput::Inbound(TransportBytes::new(
        MASKED_EMPTY_CLOSE,
    )));
    assert_eq!(
        peer.input,
        InputDisposition::Consumed {
            bytes: MASKED_EMPTY_CLOSE.len()
        }
    );
    assert!(matches!(
        peer.output,
        DriverOutput::Event(SemanticEvent::FrameReceived { .. })
    ));
    assert!(matches!(
        owner.poll(DriverInput::Wake).output,
        DriverOutput::Event(SemanticEvent::CloseReceived {
            initiator: CloseInitiator::Local,
            ..
        })
    ));
    assert!(matches!(
        owner.poll(DriverInput::Wake).output,
        DriverOutput::Terminal(_)
    ));
    assert!(matches!(
        owner.poll(DriverInput::Wake).output,
        DriverOutput::Idle
    ));
}

#[test]
fn public_driver_echoes_peer_close_then_flushes_to_terminal() {
    const MASKED_EMPTY_CLOSE: &[u8] = b"\x88\x80\x01\x02\x03\x04";
    let (_handle, mut owner) = connection_driver(config(2), Role::Server);
    open_server(&mut owner);
    assert!(matches!(
        owner
            .poll(DriverInput::Inbound(TransportBytes::new(
                MASKED_EMPTY_CLOSE
            )))
            .output,
        DriverOutput::Event(SemanticEvent::FrameReceived { .. })
    ));
    assert!(matches!(
        owner.poll(DriverInput::Wake).output,
        DriverOutput::Event(SemanticEvent::CloseReceived {
            initiator: CloseInitiator::Peer,
            ..
        })
    ));
    assert!(matches!(
        owner.poll(DriverInput::Wake).output,
        DriverOutput::StateChanged(ConnectionState::Closing)
    ));
    assert!(matches!(
        owner.poll(DriverInput::Wake).output,
        DriverOutput::Write(bytes) if bytes == [0x88, 0]
    ));
    assert!(matches!(
        owner.poll(DriverInput::WriteProgress { bytes: 2 }).output,
        DriverOutput::Idle
    ));
    assert!(matches!(
        owner.poll(DriverInput::Wake).output,
        DriverOutput::Terminal(_)
    ));
}

#[test]
fn public_driver_surfaces_transport_eof_and_both_drop_dispositions() {
    let (_handle, mut owner) = connection_driver(config(2), Role::Server);
    open_server(&mut owner);
    let eof = owner.poll(DriverInput::TransportEof);
    assert_eq!(eof.input, InputDisposition::Consumed { bytes: 0 });
    assert_eq!(eof.state, ConnectionState::Closed);
    assert!(matches!(eof.output, DriverOutput::Failure(_)));
    assert!(matches!(
        owner.poll(DriverInput::Wake).output,
        DriverOutput::Terminal(_)
    ));

    let (receiver_probe, receiver) = connection_driver(config(1), Role::Server);
    drop(receiver);
    let command = text("receiver-dropped");
    assert_eq!(
        receiver_probe.try_enqueue(command.clone()),
        Err(EnqueueError::ReceiverDropped(command))
    );

    let (producer, mut producer_probe) = connection_driver(config(1), Role::Server);
    drop(producer);
    assert_eq!(
        producer_probe.poll(DriverInput::Wake).command,
        Some(CommandDisposition::ProducersDropped)
    );
    assert_eq!(producer_probe.poll(DriverInput::Wake).command, None);
}

#[test]
fn closed_observation_distinguishes_empty_from_nonempty_bytes() {
    const US005_PUBLIC_0015: &[u8] = b"\x5d\x87\x0a";
    let (_handle, mut owner) = connection_driver(config(2), Role::Server);
    open_server(&mut owner);
    assert_eq!(
        owner.poll(DriverInput::TransportEof).state,
        ConnectionState::Closed
    );
    assert!(matches!(
        owner.poll(DriverInput::Wake).output,
        DriverOutput::Terminal(_)
    ));

    let empty = owner
        .observe_closed(ClosedObservationInput::Inbound(TransportBytes::new(&[])))
        .expect("empty bytes remain observable against the closed core");
    assert_eq!(empty.failure, None);
    assert_eq!(empty.state, ConnectionState::Closed);
    assert_eq!(
        owner
            .last_core_observation()
            .unwrap()
            .accounting()
            .bytes_consumed,
        0
    );

    let rejected = owner
        .observe_closed(ClosedObservationInput::Inbound(TransportBytes::new(
            US005_PUBLIC_0015,
        )))
        .expect("owner must retain read-only observation access to the closed core");
    assert_eq!(
        rejected.failure.map(|failure| failure.kind),
        Some(FailureKind::InvalidState {
            input: InputKind::TransportBytes,
            state: ConnectionState::Closed,
        })
    );
    assert_eq!(rejected.state, ConnectionState::Closed);
    let accounting = owner.last_core_observation().unwrap().accounting();
    assert_eq!(accounting.bytes_consumed, 0);
    assert_eq!(accounting.pre_state, ConnectionState::Closed);
    assert_eq!(accounting.post_state, ConnectionState::Closed);
}
