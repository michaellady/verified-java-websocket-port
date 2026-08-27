//! Deterministic explicit-key RFC 6455 frame encoding.

use crate::frame::{OutboundFrame, apply_mask_in_place};
use crate::{ConnectionConfig, FailureKind, FrameFailure, LimitKind, Role};

/// Immutable owned bytes produced by [`FrameEncoder`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedFrame {
    bytes: Box<[u8]>,
}

impl EncodedFrame {
    /// Borrows the complete encoded wire frame.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

/// A role-bound deterministic frame encoder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrameEncoder {
    config: ConnectionConfig,
    role: Role,
}

impl FrameEncoder {
    /// Constructs an encoder from an already checked configuration and role.
    #[must_use]
    pub const fn new(config: ConnectionConfig, role: Role) -> Self {
        Self { config, role }
    }

    /// Encodes one frame using an explicit client mask key.
    ///
    /// Client role requires `mask_key`; server role forbids it. This API does
    /// not source ambient randomness or expose later-story local commands.
    pub fn encode(
        &self,
        frame: OutboundFrame<'_>,
        mask_key: Option<[u8; 4]>,
    ) -> Result<EncodedFrame, FailureKind> {
        let opcode = frame.opcode();
        let payload = frame.payload();
        let payload_length = u64::try_from(payload.len()).map_err(|_| {
            FailureKind::Frame(FrameFailure::LengthDoesNotFitPlatform { length: u64::MAX })
        })?;
        if opcode.is_control() && !frame.fin() {
            return Err(FailureKind::Frame(FrameFailure::FragmentedControl {
                opcode,
            }));
        }
        if opcode.is_control() && payload_length > 125 {
            return Err(FailureKind::Frame(FrameFailure::ControlPayloadTooLarge {
                length: payload_length,
            }));
        }
        match (self.role, mask_key) {
            (Role::Client, None) => {
                return Err(FailureKind::Frame(FrameFailure::MissingMaskKey));
            }
            (Role::Server, Some(_)) => {
                return Err(FailureKind::Frame(FrameFailure::UnexpectedMaskKey));
            }
            _ => {}
        }
        if payload.len() > self.config.frame_bytes() {
            return Err(FailureKind::LimitExceeded {
                limit: LimitKind::FrameBytes,
                attempted: payload_length,
                maximum: self.config.limits().frame_bytes,
            });
        }

        let extended_length = match payload.len() {
            0..=125 => 0usize,
            126..=65_535 => 2,
            _ => 8,
        };
        let header_length = 2usize
            .checked_add(extended_length)
            .and_then(|length| length.checked_add(if mask_key.is_some() { 4 } else { 0 }))
            .ok_or(FailureKind::Frame(FrameFailure::ArithmeticOverflow))?;
        let wire_length = header_length
            .checked_add(payload.len())
            .ok_or(FailureKind::Frame(FrameFailure::ArithmeticOverflow))?;
        if wire_length > self.config.total_buffered_bytes() {
            return Err(FailureKind::LimitExceeded {
                limit: LimitKind::TotalBufferedBytes,
                attempted: u64::try_from(wire_length).unwrap_or(u64::MAX),
                maximum: self.config.limits().total_buffered_bytes,
            });
        }

        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(wire_length)
            .map_err(|_| FailureKind::Frame(FrameFailure::AllocationFailed))?;
        bytes.push((if frame.fin() { 0x80 } else { 0 }) | opcode.wire());
        let mask_bit = if mask_key.is_some() { 0x80 } else { 0 };
        match payload.len() {
            length @ 0..=125 => bytes.push(mask_bit | length as u8),
            length @ 126..=65_535 => {
                bytes.push(mask_bit | 126);
                bytes.extend_from_slice(&(length as u16).to_be_bytes());
            }
            length => {
                bytes.push(mask_bit | 127);
                bytes.extend_from_slice(&(length as u64).to_be_bytes());
            }
        }
        if let Some(key) = mask_key {
            bytes.extend_from_slice(&key);
            let payload_start = bytes.len();
            bytes.extend_from_slice(payload);
            apply_mask_in_place(&mut bytes[payload_start..], key, 0);
        } else {
            bytes.extend_from_slice(payload);
        }
        debug_assert_eq!(bytes.len(), wire_length);
        Ok(EncodedFrame {
            bytes: bytes.into_boxed_slice(),
        })
    }
}
