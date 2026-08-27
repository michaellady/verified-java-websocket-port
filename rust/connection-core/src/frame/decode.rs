//! Incremental RFC 6455 frame-header and payload decoding.

use alloc::sync::Arc;

use crate::fragment::{FragmentAccumulator, FragmentPlan};
use crate::frame::{Frame, Opcode, apply_mask_in_place};
use crate::message::{DeliveryKind, MessageDelivery};
use crate::utf8::Utf8Validator;
use crate::{ConnectionConfig, FailureKind, FrameFailure, LimitKind, Role};

const MAX_HEADER_BYTES: usize = 14;

/// An immutable, validated frame header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrameHeader {
    fin: bool,
    opcode: Opcode,
    masked: bool,
    payload_length: usize,
    mask_key: Option<[u8; 4]>,
    header_length: usize,
}

impl FrameHeader {
    /// Returns whether this is the final frame of its message.
    #[must_use]
    pub const fn fin(&self) -> bool {
        self.fin
    }

    /// Returns the validated opcode.
    #[must_use]
    pub const fn opcode(&self) -> Opcode {
        self.opcode
    }

    /// Returns whether the payload is masked on the wire.
    #[must_use]
    pub const fn masked(&self) -> bool {
        self.masked
    }

    /// Returns the checked platform payload length.
    #[must_use]
    pub const fn payload_length(&self) -> usize {
        self.payload_length
    }

    /// Returns the mask key when the wire payload is masked.
    #[must_use]
    pub const fn mask_key(&self) -> Option<[u8; 4]> {
        self.mask_key
    }

    /// Returns the complete wire-header length including a mask key.
    #[must_use]
    pub const fn header_length(&self) -> usize {
        self.header_length
    }
}

/// Result of inspecting an available frame-header prefix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FrameHeaderDecode {
    /// More bytes are required before validation can continue.
    Incomplete {
        /// Smallest complete prefix length needed for the next decision.
        minimum: usize,
    },
    /// The prefix contains one complete, validated header.
    Complete(FrameHeader),
}

/// Stateless validator for the canonical RFC 6455 frame header.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FrameHeaderDecoder;

impl FrameHeaderDecoder {
    /// Decodes and validates a frame header from `prefix`.
    ///
    /// `retained_payload_bytes` accounts for completed payloads staged by the
    /// caller in the current result. No payload allocation occurs here.
    pub fn decode_header(
        config: &ConnectionConfig,
        role: Role,
        retained_payload_bytes: usize,
        prefix: &[u8],
    ) -> Result<FrameHeaderDecode, FailureKind> {
        if prefix.len() < 2 {
            return Ok(FrameHeaderDecode::Incomplete { minimum: 2 });
        }

        let first = prefix[0];
        let second = prefix[1];
        if first & 0x70 != 0 {
            return Err(FailureKind::Frame(FrameFailure::ReservedBits));
        }
        let wire_opcode = first & 0x0f;
        let opcode = Opcode::from_wire(wire_opcode).ok_or(FailureKind::Frame(
            FrameFailure::ReservedOpcode {
                opcode: wire_opcode,
            },
        ))?;
        let fin = first & 0x80 != 0;
        if opcode.is_control() && !fin {
            return Err(FailureKind::Frame(FrameFailure::FragmentedControl {
                opcode,
            }));
        }

        let length_code = second & 0x7f;
        let extended_bytes = match length_code {
            126 => 2,
            127 => 8,
            _ => 0,
        };
        let length_end = 2usize
            .checked_add(extended_bytes)
            .ok_or(FailureKind::Frame(FrameFailure::ArithmeticOverflow))?;
        if prefix.len() < length_end {
            return Ok(FrameHeaderDecode::Incomplete {
                minimum: length_end,
            });
        }

        let payload_length_u64 = match length_code {
            126 => u64::from(u16::from_be_bytes([prefix[2], prefix[3]])),
            127 => {
                let bytes: [u8; 8] = prefix[2..10]
                    .try_into()
                    .map_err(|_| FailureKind::Frame(FrameFailure::ArithmeticOverflow))?;
                if bytes[0] & 0x80 != 0 {
                    return Err(FailureKind::Frame(FrameFailure::PayloadLengthHighBitSet));
                }
                u64::from_be_bytes(bytes)
            }
            value => u64::from(value),
        };
        if length_code == 126 && payload_length_u64 < 126 {
            return Err(FailureKind::Frame(FrameFailure::NonCanonicalLength16 {
                length: payload_length_u64,
            }));
        }
        if length_code == 127 && payload_length_u64 <= u64::from(u16::MAX) {
            return Err(FailureKind::Frame(FrameFailure::NonCanonicalLength64 {
                length: payload_length_u64,
            }));
        }
        if opcode.is_control() && payload_length_u64 > 125 {
            return Err(FailureKind::Frame(FrameFailure::ControlPayloadTooLarge {
                length: payload_length_u64,
            }));
        }

        let masked = second & 0x80 != 0;
        let expected_masked = role == Role::Server;
        if masked != expected_masked {
            return Err(FailureKind::Frame(FrameFailure::IncorrectMasking {
                expected_masked,
                actual_masked: masked,
            }));
        }

        let payload_length = usize::try_from(payload_length_u64).map_err(|_| {
            FailureKind::Frame(FrameFailure::LengthDoesNotFitPlatform {
                length: payload_length_u64,
            })
        })?;
        let mask_bytes = if masked { 4usize } else { 0 };
        let header_length = length_end
            .checked_add(mask_bytes)
            .ok_or(FailureKind::Frame(FrameFailure::ArithmeticOverflow))?;
        let _wire_length = header_length
            .checked_add(payload_length)
            .ok_or(FailureKind::Frame(FrameFailure::ArithmeticOverflow))?;

        if payload_length > config.frame_bytes() {
            return Err(FailureKind::LimitExceeded {
                limit: LimitKind::FrameBytes,
                attempted: payload_length_u64,
                maximum: config.limits().frame_bytes,
            });
        }
        let retained_total = retained_payload_bytes
            .checked_add(payload_length)
            .ok_or(FailureKind::Frame(FrameFailure::ArithmeticOverflow))?;
        if retained_total > config.total_buffered_bytes() {
            return Err(FailureKind::LimitExceeded {
                limit: LimitKind::TotalBufferedBytes,
                attempted: u64::try_from(retained_total).unwrap_or(u64::MAX),
                maximum: config.limits().total_buffered_bytes,
            });
        }

        if prefix.len() < header_length {
            return Ok(FrameHeaderDecode::Incomplete {
                minimum: header_length,
            });
        }
        let mask_key = masked.then(|| {
            prefix[length_end..header_length]
                .try_into()
                .expect("validated four-byte mask-key range")
        });
        Ok(FrameHeaderDecode::Complete(FrameHeader {
            fin,
            opcode,
            masked,
            payload_length,
            mask_key,
            header_length,
        }))
    }
}

#[derive(Debug)]
pub(crate) struct FrameDecoder {
    header: [u8; MAX_HEADER_BYTES],
    header_length: usize,
    active: Option<FrameHeader>,
    plan: Option<FragmentPlan>,
    payload: Vec<u8>,
    utf8: Utf8Validator,
    fragments: FragmentAccumulator,
}

impl FrameDecoder {
    pub(crate) const fn new() -> Self {
        Self {
            header: [0; MAX_HEADER_BYTES],
            header_length: 0,
            active: None,
            plan: None,
            payload: Vec::new(),
            utf8: Utf8Validator::new(),
            fragments: FragmentAccumulator::new(),
        }
    }

    pub(crate) const fn is_partial(&self) -> bool {
        self.header_length != 0 || self.active.is_some()
    }

    pub(crate) fn fragment_eof_failure(&self) -> Option<crate::FragmentFailure> {
        self.fragments.unexpected_eof()
    }

    pub(crate) fn consume(
        &mut self,
        config: &ConnectionConfig,
        role: Role,
        bytes: &[u8],
    ) -> FrameDecodeBatch {
        let mut offset = 0usize;
        let mut staged_payload_bytes = 0usize;
        let mut staged_event_count = 0usize;
        let mut records = Vec::new();

        while offset < bytes.len() || self.header_length != 0 || self.ready_empty_payload() {
            if self.active.is_none() {
                let retained_payload_bytes = match self
                    .fragments
                    .retained_bytes()
                    .checked_add(staged_payload_bytes)
                {
                    Some(value) => value,
                    None => {
                        self.reset();
                        return FrameDecodeBatch::failed(
                            records,
                            FailureKind::Frame(FrameFailure::ArithmeticOverflow),
                        );
                    }
                };
                let decode = FrameHeaderDecoder::decode_header(
                    config,
                    role,
                    retained_payload_bytes,
                    &self.header[..self.header_length],
                );
                match decode {
                    Ok(FrameHeaderDecode::Incomplete { minimum }) => {
                        let needed = minimum.saturating_sub(self.header_length);
                        let available = bytes.len().saturating_sub(offset);
                        let copied = needed.min(available);
                        if copied == 0 {
                            break;
                        }
                        let end = self.header_length + copied;
                        self.header[self.header_length..end]
                            .copy_from_slice(&bytes[offset..offset + copied]);
                        self.header_length = end;
                        offset += copied;
                        continue;
                    }
                    Ok(FrameHeaderDecode::Complete(header)) => {
                        let payload_length = header.payload_length();
                        let plan = match self.fragments.plan(
                            config,
                            &header,
                            staged_payload_bytes,
                            staged_event_count,
                        ) {
                            Ok(plan) => plan,
                            Err(failure) => {
                                self.reset();
                                return FrameDecodeBatch::failed(records, failure);
                            }
                        };
                        if payload_length != 0
                            && self.payload.try_reserve_exact(payload_length).is_err()
                        {
                            self.reset();
                            return FrameDecodeBatch::failed(
                                records,
                                FailureKind::Frame(FrameFailure::AllocationFailed),
                            );
                        }
                        if let Err(failure) = self.fragments.prepare(plan, payload_length) {
                            self.reset();
                            return FrameDecodeBatch::failed(records, failure);
                        }
                        self.utf8.reset();
                        self.active = Some(header);
                        self.plan = Some(plan);
                    }
                    Err(failure) => {
                        self.reset();
                        return FrameDecodeBatch::failed(records, failure);
                    }
                }
            }

            let header = self.active.as_ref().expect("active header was installed");
            let remaining = header.payload_length() - self.payload.len();
            let available = bytes.len().saturating_sub(offset);
            let copied = remaining.min(available);
            if copied != 0 {
                let prior_payload_offset = self.payload.len();
                self.payload
                    .extend_from_slice(&bytes[offset..offset + copied]);
                if let Some(mask_key) = header.mask_key() {
                    apply_mask_in_place(
                        &mut self.payload[prior_payload_offset..],
                        mask_key,
                        prior_payload_offset,
                    );
                }
                if header.fin()
                    && header.opcode() == Opcode::Text
                    && let Err(failure) = self.utf8.feed(&self.payload[prior_payload_offset..])
                {
                    self.reset();
                    return FrameDecodeBatch::failed(records, FailureKind::Utf8(failure));
                }
                let plan = self.plan.expect("an active header has a fragment plan");
                if let Err(failure) = self
                    .fragments
                    .feed(plan, &self.payload[prior_payload_offset..])
                {
                    self.reset();
                    return FrameDecodeBatch::failed(records, FailureKind::Utf8(failure));
                }
                offset += copied;
            }
            if self.payload.len() != header.payload_length() {
                break;
            }

            let plan = self.plan.expect("a complete header has a fragment plan");
            if plan == FragmentPlan::Unfragmented(Some(DeliveryKind::Text))
                && let Err(failure) = self.utf8.finish()
            {
                self.reset();
                return FrameDecodeBatch::failed(records, FailureKind::Utf8(failure));
            }
            if records.try_reserve(1).is_err() {
                self.reset();
                return FrameDecodeBatch::failed(
                    records,
                    FailureKind::Frame(FrameFailure::AllocationFailed),
                );
            }
            let fragment_delivery = match self.fragments.commit(plan, &self.payload) {
                Ok(delivery) => delivery,
                Err(failure) => {
                    self.reset();
                    return FrameDecodeBatch::failed(records, FailureKind::Utf8(failure));
                }
            };
            let header = self.active.take().expect("complete active header");
            self.plan = None;
            let payload = core::mem::take(&mut self.payload);
            let payload_backing = payload.as_ptr();
            let payload = Arc::new(payload);
            debug_assert_eq!(
                payload_backing,
                payload.as_ptr(),
                "moving the reserved Vec into Arc must preserve its byte backing"
            );
            let additional_message_bytes = fragment_delivery
                .as_ref()
                .map_or(0, MessageDelivery::payload_len);
            staged_payload_bytes = staged_payload_bytes
                .checked_add(payload.len())
                .and_then(|value| value.checked_add(additional_message_bytes))
                .expect("header admission checked staged payload arithmetic");
            staged_event_count = staged_event_count
                .checked_add(plan.event_slots())
                .expect("header admission checked event arithmetic");
            let delivery = match (plan, fragment_delivery) {
                (_, Some(delivery)) => Some(DecodedDelivery::Message(delivery)),
                (FragmentPlan::Unfragmented(Some(kind)), None) => {
                    Some(DecodedDelivery::Frame(kind))
                }
                _ => None,
            };
            let retained_payload_bytes =
                match staged_payload_bytes.checked_add(self.fragments.retained_bytes()) {
                    Some(value) => value,
                    None => {
                        self.reset();
                        return FrameDecodeBatch::failed(
                            records,
                            FailureKind::Frame(FrameFailure::ArithmeticOverflow),
                        );
                    }
                };
            records.push(DecodedFrame {
                frame: Frame::new(header.fin(), header.opcode(), header.masked(), payload),
                delivery,
                retained_payload_bytes,
            });
            self.header_length = 0;
        }

        FrameDecodeBatch {
            records,
            failure: None,
        }
    }

    fn ready_empty_payload(&self) -> bool {
        self.active
            .as_ref()
            .is_some_and(|header| header.payload_length() == 0)
    }

    pub(crate) fn reset(&mut self) {
        self.header_length = 0;
        self.active = None;
        self.plan = None;
        self.payload = Vec::new();
        self.utf8.reset();
        self.fragments.reset();
    }
}

pub(crate) struct DecodedFrame {
    pub(crate) frame: Frame,
    pub(crate) delivery: Option<DecodedDelivery>,
    pub(crate) retained_payload_bytes: usize,
}

pub(crate) enum DecodedDelivery {
    Frame(DeliveryKind),
    Message(MessageDelivery),
}

impl DecodedDelivery {
    pub(crate) fn deliver(self, frame: &Frame) -> MessageDelivery {
        match self {
            Self::Frame(kind) => kind.deliver(frame),
            Self::Message(delivery) => delivery,
        }
    }
}

pub(crate) struct FrameDecodeBatch {
    pub(crate) records: Vec<DecodedFrame>,
    pub(crate) failure: Option<FailureKind>,
}

impl FrameDecodeBatch {
    fn failed(records: Vec<DecodedFrame>, failure: FailureKind) -> Self {
        Self {
            records,
            failure: Some(failure),
        }
    }
}
