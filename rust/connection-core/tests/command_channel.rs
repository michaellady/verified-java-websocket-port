#![forbid(unsafe_code)]

use websocket_core::{
    CommandQueueCapacity, CommandReceiveError, CommandSendError, LocalCommand, command_channel,
};

fn text(value: &str) -> LocalCommand {
    LocalCommand::SendText(value.into())
}

#[test]
fn exact_capacity_is_bounded_and_full_preserves_accepted_fifo_work() {
    let capacity = CommandQueueCapacity::try_from(2).unwrap();
    let (sender, mut receiver) = command_channel(capacity);

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
    let capacity = CommandQueueCapacity::try_from(4).unwrap();
    let (sender, mut receiver) = command_channel(capacity);
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
    let capacity = CommandQueueCapacity::try_from(1).unwrap();
    let (sender, receiver) = command_channel(capacity);
    drop(receiver);
    assert_eq!(
        sender.try_send(text("returned")),
        Err(CommandSendError::ReceiverDropped(text("returned")))
    );

    let (sender, mut receiver) = command_channel(capacity);
    sender.try_send(text("accepted")).unwrap();
    drop(sender);
    assert_eq!(receiver.try_recv(), Ok(text("accepted")));
    assert_eq!(receiver.try_recv(), Err(CommandReceiveError::SenderDropped));
}

#[test]
fn command_capacity_uses_the_same_zero_and_ceiling_contract() {
    assert!(CommandQueueCapacity::try_from(1).is_ok());
    assert!(CommandQueueCapacity::try_from(4_096).is_ok());
    assert!(CommandQueueCapacity::try_from(0).is_err());
    assert!(CommandQueueCapacity::try_from(4_097).is_err());
    assert!(CommandQueueCapacity::try_from(u64::MAX).is_err());
}
