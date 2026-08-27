//! Private single-frame message admission and delivery values.

use alloc::sync::Arc;

use crate::frame::{Frame, Opcode};
use crate::{ConnectionConfig, FailureKind, LimitKind, QueueKind};

/// An immutable, already-validated UTF-8 message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextMessage {
    payload: Arc<Vec<u8>>,
}

impl TextMessage {
    /// Borrows this message as validated UTF-8 text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.payload).expect("text messages are validated before creation")
    }

    /// Borrows the validated UTF-8 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.payload
    }

    fn from_frame(frame: &Frame) -> Self {
        Self {
            payload: frame.payload_owner(),
        }
    }
}

/// An immutable binary message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinaryMessage {
    payload: Arc<Vec<u8>>,
}

impl BinaryMessage {
    /// Borrows every uninterpreted message octet.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.payload
    }

    fn from_frame(frame: &Frame) -> Self {
        Self {
            payload: frame.payload_owner(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeliveryKind {
    Text,
    Binary,
}

impl DeliveryKind {
    pub(crate) const fn for_frame(fin: bool, opcode: Opcode) -> Option<Self> {
        if !fin {
            return None;
        }
        match opcode {
            Opcode::Text => Some(Self::Text),
            Opcode::Binary => Some(Self::Binary),
            Opcode::Continuation | Opcode::Close | Opcode::Ping | Opcode::Pong => None,
        }
    }

    pub(crate) fn admit(
        self,
        config: &ConnectionConfig,
        payload_length: usize,
        staged_event_count: usize,
    ) -> Result<usize, FailureKind> {
        if payload_length > config.message_bytes() {
            return Err(FailureKind::LimitExceeded {
                limit: LimitKind::MessageBytes,
                attempted: u64::try_from(payload_length).unwrap_or(u64::MAX),
                maximum: config.limits().message_bytes,
            });
        }
        admit_events(config, staged_event_count, 2)
    }

    pub(crate) fn deliver(self, frame: &Frame) -> MessageDelivery {
        match self {
            Self::Text => MessageDelivery::Text(TextMessage::from_frame(frame)),
            Self::Binary => MessageDelivery::Binary(BinaryMessage::from_frame(frame)),
        }
    }
}

pub(crate) enum MessageDelivery {
    Text(TextMessage),
    Binary(BinaryMessage),
}

pub(crate) fn admit_frame_event(
    config: &ConnectionConfig,
    staged_event_count: usize,
) -> Result<usize, FailureKind> {
    admit_events(config, staged_event_count, 1)
}

fn admit_events(
    config: &ConnectionConfig,
    staged_event_count: usize,
    required: usize,
) -> Result<usize, FailureKind> {
    let admitted = staged_event_count
        .checked_add(required)
        .ok_or(FailureKind::Backpressure(QueueKind::Event))?;
    if admitted > config.event_queue_entries() {
        return Err(FailureKind::Backpressure(QueueKind::Event));
    }
    Ok(admitted)
}
