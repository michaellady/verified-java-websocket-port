use std::sync::mpsc::{
    Receiver, SyncSender, TryRecvError as StdTryRecvError, TrySendError as StdTrySendError,
    sync_channel,
};

use crate::{ConfigError, LimitKind, LocalCommand};

/// Checked nonzero capacity for the bounded command channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandQueueCapacity(usize);

impl CommandQueueCapacity {
    /// Returns the checked platform capacity.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }
}

impl TryFrom<u64> for CommandQueueCapacity {
    type Error = ConfigError;

    fn try_from(attempted: u64) -> Result<Self, Self::Error> {
        if attempted == 0 {
            return Err(ConfigError::Zero(LimitKind::CommandQueueEntries));
        }
        if attempted > 4_096 {
            return Err(ConfigError::ExceedsHardCeiling {
                limit: LimitKind::CommandQueueEntries,
                attempted,
                maximum: 4_096,
            });
        }
        let capacity = usize::try_from(attempted).map_err(|_| ConfigError::DoesNotFitPlatform {
            limit: LimitKind::CommandQueueEntries,
            attempted,
        })?;
        Ok(Self(capacity))
    }
}

/// Cloneable producer for the bounded local-command channel.
#[derive(Clone, Debug)]
pub struct CommandSender {
    inner: SyncSender<LocalCommand>,
}

/// Single consumer for the bounded local-command channel.
#[derive(Debug)]
pub struct CommandReceiver {
    inner: Receiver<LocalCommand>,
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
            StdTrySendError::Full(command) => CommandSendError::Full(command),
            StdTrySendError::Disconnected(command) => CommandSendError::ReceiverDropped(command),
        })
    }
}

impl CommandReceiver {
    /// Attempts to receive the next accepted command without blocking.
    pub fn try_recv(&mut self) -> Result<LocalCommand, CommandReceiveError> {
        self.inner.try_recv().map_err(|error| match error {
            StdTryRecvError::Empty => CommandReceiveError::Empty,
            StdTryRecvError::Disconnected => CommandReceiveError::SenderDropped,
        })
    }
}

/// Creates a dependency-free bounded MPSC local-command channel.
#[must_use]
pub fn command_channel(capacity: CommandQueueCapacity) -> (CommandSender, CommandReceiver) {
    let (sender, receiver) = sync_channel(capacity.get());
    (
        CommandSender { inner: sender },
        CommandReceiver { inner: receiver },
    )
}
