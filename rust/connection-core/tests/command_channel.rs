#![forbid(unsafe_code)]

use websocket_core::{
    CommandReceiveError, CommandSendError, ConnectionConfig, ConnectionLimits, LocalCommand,
    command_channel,
};

fn text(value: &str) -> LocalCommand {
    LocalCommand::SendText(value.into())
}

fn config_with_command_capacity(command_queue_entries: u64) -> ConnectionConfig {
    ConnectionConfig::try_from(ConnectionLimits {
        command_queue_entries,
        ..ConnectionLimits::default()
    })
    .unwrap()
}

#[test]
fn exact_capacity_is_bounded_and_full_preserves_accepted_fifo_work() {
    let config = config_with_command_capacity(2);
    let (sender, mut receiver) = command_channel(&config);

    sender.try_send(text("first")).unwrap();
    sender.try_send(text("second")).unwrap();
    assert_eq!(
        sender.try_send(text("third")),
        Err(CommandSendError::Full(text("third")))
    );
    assert_eq!(receiver.try_recv(), Ok(text("first")));
    assert_eq!(receiver.try_recv(), Ok(text("second")));
    assert_eq!(receiver.try_recv(), Err(CommandReceiveError::Empty));
}

#[test]
fn cloned_sender_preserves_each_producers_fifo_order() {
    let config = config_with_command_capacity(4);
    let (sender, mut receiver) = command_channel(&config);
    let clone = sender.clone();

    sender.try_send(text("a1")).unwrap();
    sender.try_send(text("a2")).unwrap();
    clone.try_send(text("b1")).unwrap();
    clone.try_send(text("b2")).unwrap();

    assert_eq!(receiver.try_recv(), Ok(text("a1")));
    assert_eq!(receiver.try_recv(), Ok(text("a2")));
    assert_eq!(receiver.try_recv(), Ok(text("b1")));
    assert_eq!(receiver.try_recv(), Ok(text("b2")));
}

#[test]
fn dropped_endpoints_have_typed_terminal_dispositions() {
    let config = config_with_command_capacity(1);
    let (sender, receiver) = command_channel(&config);
    drop(receiver);
    assert_eq!(
        sender.try_send(text("returned")),
        Err(CommandSendError::ReceiverDropped(text("returned")))
    );

    let (sender, mut receiver) = command_channel(&config);
    sender.try_send(text("accepted")).unwrap();
    drop(sender);
    assert_eq!(receiver.try_recv(), Ok(text("accepted")));
    assert_eq!(receiver.try_recv(), Err(CommandReceiveError::SenderDropped));
}

#[test]
fn configured_capacity_is_the_channel_bound_without_a_second_capacity_input() {
    let config = config_with_command_capacity(1);
    let (sender, mut receiver) = command_channel(&config);

    sender.try_send(text("accepted")).unwrap();
    assert_eq!(
        sender.try_send(text("full")),
        Err(CommandSendError::Full(text("full")))
    );
    assert_eq!(receiver.try_recv(), Ok(text("accepted")));
    assert_eq!(receiver.try_recv(), Err(CommandReceiveError::Empty));
}
