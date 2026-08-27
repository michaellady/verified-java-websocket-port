//! Dependency-free RFC 6455 frame coding and masking.
//!
//! This module exposes frame-level observations while the connection core may
//! share final data payloads with typed messages. Fragmentation policy,
//! control responses, and close semantics remain owned by later stories.

use alloc::sync::Arc;

pub mod decode;
pub mod encode;
pub mod mask;

pub use decode::{FrameHeader, FrameHeaderDecode, FrameHeaderDecoder};
pub use encode::{EncodedFrame, FrameEncoder};
pub use mask::apply_mask_in_place;

/// One of the six RFC 6455 opcodes supported without extensions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Opcode {
    /// A continuation frame.
    Continuation = 0x0,
    /// A text frame. UTF-8 validation belongs to US-013.
    Text = 0x1,
    /// A binary frame.
    Binary = 0x2,
    /// A close control frame. Payload semantics belong to US-016.
    Close = 0x8,
    /// A ping control frame. Response policy belongs to US-015.
    Ping = 0x9,
    /// A pong control frame.
    Pong = 0xa,
}

impl Opcode {
    pub(crate) const fn from_wire(value: u8) -> Option<Self> {
        match value {
            0x0 => Some(Self::Continuation),
            0x1 => Some(Self::Text),
            0x2 => Some(Self::Binary),
            0x8 => Some(Self::Close),
            0x9 => Some(Self::Ping),
            0xa => Some(Self::Pong),
            _ => None,
        }
    }

    pub(crate) const fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }

    pub(crate) const fn wire(self) -> u8 {
        self as u8
    }
}

/// An immutable decoded frame observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    fin: bool,
    opcode: Opcode,
    masked: bool,
    payload: Arc<[u8]>,
}

impl Frame {
    pub(crate) fn new(fin: bool, opcode: Opcode, masked: bool, payload: Arc<[u8]>) -> Self {
        Self {
            fin,
            opcode,
            masked,
            payload,
        }
    }

    /// Returns whether this is the final frame of its message.
    #[must_use]
    pub const fn fin(&self) -> bool {
        self.fin
    }

    /// Returns the frame opcode.
    #[must_use]
    pub const fn opcode(&self) -> Opcode {
        self.opcode
    }

    /// Returns whether the payload was masked on the wire.
    #[must_use]
    pub const fn masked(&self) -> bool {
        self.masked
    }

    /// Borrows the decoded, unmasked payload bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub(crate) fn payload_owner(&self) -> Arc<[u8]> {
        Arc::clone(&self.payload)
    }
}

/// Borrowed input to the deterministic frame encoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboundFrame<'a> {
    fin: bool,
    opcode: Opcode,
    payload: &'a [u8],
}

impl<'a> OutboundFrame<'a> {
    /// Creates one borrowed outbound frame.
    #[must_use]
    pub const fn new(fin: bool, opcode: Opcode, payload: &'a [u8]) -> Self {
        Self {
            fin,
            opcode,
            payload,
        }
    }

    pub(crate) const fn fin(self) -> bool {
        self.fin
    }

    pub(crate) const fn opcode(self) -> Opcode {
        self.opcode
    }

    pub(crate) const fn payload(self) -> &'a [u8] {
        self.payload
    }
}
