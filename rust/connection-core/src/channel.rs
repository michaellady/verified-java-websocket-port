use std::sync::mpsc;

use crate::{ConnectionConfig, LocalCommand};

/// Cloneable producer for the bounded local-command channel.
#[derive(Clone, Debug)]
pub struct CommandSender {
    inner: mpsc::SyncSender<LocalCommand>,
}

/// Single consumer for the bounded local-command channel.
#[derive(Debug)]
pub struct CommandReceiver {
    inner: mpsc::Receiver<LocalCommand>,
}

/// A nonblocking send failure that returns ownership of the command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandSendError {
    /// The bounded channel is full; accepted work remains queued.
    Full(LocalCommand),
    /// The single receiver was dropped.
    ReceiverDropped(LocalCommand),
}

/// A nonblocking receive failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandReceiveError {
    /// No command is currently available, but a sender remains.
    Empty,
    /// Every sender was dropped and no accepted command remains.
    SenderDropped,
}

impl CommandSender {
    /// Attempts to enqueue a command without blocking.
    pub fn try_send(&self, command: LocalCommand) -> Result<(), CommandSendError> {
        self.inner.try_send(command).map_err(|error| match error {
            mpsc::TrySendError::Full(command) => CommandSendError::Full(command),
            mpsc::TrySendError::Disconnected(command) => CommandSendError::ReceiverDropped(command),
        })
    }
}

impl CommandReceiver {
    /// Attempts to receive the next accepted command without blocking.
    pub fn try_recv(&mut self) -> Result<LocalCommand, CommandReceiveError> {
        self.inner.try_recv().map_err(|error| match error {
            mpsc::TryRecvError::Empty => CommandReceiveError::Empty,
            mpsc::TryRecvError::Disconnected => CommandReceiveError::SenderDropped,
        })
    }
}

/// Creates the dependency-free MPSC channel with the configuration's exact
/// validated command-queue capacity.
#[must_use]
pub fn command_channel(config: &ConnectionConfig) -> (CommandSender, CommandReceiver) {
    let (sender, receiver) = mpsc::sync_channel(config.command_queue_entries());
    (
        CommandSender { inner: sender },
        CommandReceiver { inner: receiver },
    )
}
