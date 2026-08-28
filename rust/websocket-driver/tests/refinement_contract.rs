#![forbid(unsafe_code)]

use websocket_core::{
    ClientRequestDescriptor, ConnectionConfig, ConnectionLimits, LocalCommand, Role, TransportBytes,
};
use websocket_driver::{
    CommandDisposition, DeferredReason, DriverInput, DriverInputError, DriverOutput, EnqueueError,
    InputDisposition, connection_driver,
};

fn limits() -> ConnectionConfig {
    ConnectionConfig::try_from(ConnectionLimits::default()).expect("default limits")
}

fn open_client() -> (
    websocket_driver::CommandHandle,
    websocket_driver::ConnectionOwner,
) {
    let (handle, mut owner) = connection_driver(limits(), Role::Client);
    handle
        .try_enqueue(LocalCommand::StartClientHandshake {
            descriptor: ClientRequestDescriptor::try_new("/chat", "example.test")
                .expect("descriptor"),
            nonce: [7; 16],
        })
        .expect("enqueue handshake");
    assert!(matches!(
        owner.poll(DriverInput::Wake).command,
        Some(CommandDisposition::Applied(_))
    ));
    (handle, owner)
}

#[test]
fn write_progress_preserves_exact_suffix_and_rejects_without_mutation() {
    let (_handle, mut owner) = open_client();
    let initial = match owner.poll(DriverInput::Wake).output {
        DriverOutput::Write(bytes) => bytes.to_vec(),
        other => panic!("expected write, got {other:?}"),
    };
    let same = match owner.poll(DriverInput::WriteProgress { bytes: 0 }).output {
        DriverOutput::Write(bytes) => bytes.to_vec(),
        other => panic!("expected retained write, got {other:?}"),
    };
    assert_eq!(same, initial);

    let one = match owner.poll(DriverInput::WriteProgress { bytes: 1 }).output {
        DriverOutput::Write(bytes) => bytes.to_vec(),
        other => panic!("expected suffix, got {other:?}"),
    };
    assert_eq!(one, initial[1..]);
    let rejected = owner.poll(DriverInput::WriteProgress {
        bytes: one.len() + 1,
    });
    assert_eq!(
        rejected.input,
        InputDisposition::Rejected(DriverInputError::InvalidWriteProgress {
            attempted: one.len() + 1,
            remaining: one.len(),
        })
    );
    assert!(matches!(rejected.output, DriverOutput::Write(bytes) if bytes == one));
}

#[test]
fn inbound_is_deferred_during_output_partial_write_and_due_flush() {
    let (_handle, mut owner) = open_client();
    let write = match owner.poll(DriverInput::Wake).output {
        DriverOutput::Write(bytes) => bytes.to_vec(),
        other => panic!("expected write, got {other:?}"),
    };
    let inbound = TransportBytes::new(b"x");
    let deferred = owner.poll(DriverInput::Inbound(inbound));
    assert_eq!(
        deferred.input,
        InputDisposition::Deferred(DeferredReason::OutputPending)
    );
    let partial = owner.poll(DriverInput::WriteProgress { bytes: 1 });
    assert!(matches!(partial.output, DriverOutput::Write(_)));
    let inbound = TransportBytes::new(b"x");
    assert_eq!(
        owner.poll(DriverInput::Inbound(inbound)).input,
        InputDisposition::Deferred(DeferredReason::OutputPending)
    );

    let remaining = write.len() - 1;
    assert!(matches!(
        owner
            .poll(DriverInput::WriteProgress { bytes: remaining })
            .output,
        DriverOutput::Idle
    ));
    let inbound = TransportBytes::new(b"x");
    assert_eq!(
        owner.poll(DriverInput::Inbound(inbound)).input,
        InputDisposition::Deferred(DeferredReason::FlushPending)
    );
}

#[test]
fn shutdown_aborts_writes_and_delivers_one_terminal() {
    let (handle, mut owner) = open_client();
    let write = match owner.poll(DriverInput::Wake).output {
        DriverOutput::Write(bytes) => bytes.len(),
        other => panic!("expected write, got {other:?}"),
    };
    assert!(write > 1);
    let shutdown = owner.poll(DriverInput::Shutdown);
    assert!(!matches!(shutdown.output, DriverOutput::Write(_)));
    assert!(matches!(
        handle.try_enqueue(LocalCommand::SendPing {
            payload: vec![1].try_into().expect("payload"),
            mask_key: None,
        }),
        Err(EnqueueError::ShuttingDown(_))
    ));

    let mut terminals = usize::from(matches!(shutdown.output, DriverOutput::Terminal(_)));
    for _ in 0..32 {
        terminals += usize::from(matches!(
            owner.poll(DriverInput::Wake).output,
            DriverOutput::Terminal(_)
        ));
    }
    assert_eq!(terminals, 1);
}

#[test]
fn receiver_drop_and_exact_entry_backpressure_remain_typed() {
    let (handle, owner) = connection_driver(limits(), Role::Server);
    drop(owner);
    assert!(matches!(
        handle.try_enqueue(LocalCommand::SendPing {
            payload: vec![].try_into().expect("payload"),
            mask_key: None,
        }),
        Err(EnqueueError::ReceiverDropped(_))
    ));

    let (handle, _owner) = connection_driver(limits(), Role::Server);
    let command = || LocalCommand::SendPing {
        payload: vec![].try_into().expect("payload"),
        mask_key: None,
    };
    for _ in 0..ConnectionLimits::default().command_queue_entries {
        handle.try_enqueue(command()).expect("within entry bound");
    }
    assert!(matches!(
        handle.try_enqueue(command()),
        Err(EnqueueError::Full(_))
    ));
}
