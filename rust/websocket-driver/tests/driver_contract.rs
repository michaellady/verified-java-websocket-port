#![forbid(unsafe_code)]

use websocket_core::{
    ConnectionConfig, ConnectionLimits, ConnectionState, LocalCommand, Role, TransportBytes,
};
use websocket_driver::{
    CommandDisposition, DeferredReason, DriverInput, DriverInputError, DriverOutput, EnqueueError,
    InputDisposition, connection_driver,
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
