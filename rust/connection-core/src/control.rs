//! Private admission and encoding for RFC 6455 Ping/Pong controls.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::frame::decode::DecodedFrame;
use crate::frame::{Frame, FrameEncoder, Opcode, OutboundFrame};
use crate::{ConnectionConfig, FailureKind, FrameFailure, LimitKind, QueueKind, Role};

/// Checked policy for same-step automatic Pong responses.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum AutomaticPongPolicy {
    /// Observe inbound Ping frames without replying automatically.
    #[default]
    Disabled,
    /// Emit an automatic Pong only for a server-role connection.
    ServerOnly,
}

/// Shared immutable bytes carried by a Ping or Pong semantic event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlPayload {
    owner: Arc<Vec<u8>>,
}

impl ControlPayload {
    pub(crate) fn from_frame(frame: &Frame) -> Self {
        Self {
            owner: frame.payload_owner(),
        }
    }

    /// Borrows the exact decoded and unmasked control payload.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.owner
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BatchPlan {
    pub(crate) accepted_records: usize,
    pub(crate) output_capacity: usize,
    pub(crate) failure: Option<FailureKind>,
}

pub(crate) fn plan_batch(
    config: &ConnectionConfig,
    role: Role,
    records: &[DecodedFrame],
) -> BatchPlan {
    let encoder = FrameEncoder::new(config.clone(), Role::Server);
    let mut accepted_records = 0usize;
    let mut output_capacity = 0usize;
    let mut write_entries = 0usize;
    let mut generated_wire_bytes = 0usize;

    for record in records {
        let automatic = should_automatically_pong(config, role, record.frame.opcode());
        let group_outputs = 1usize
            .checked_add(usize::from(record.delivery.is_some()))
            .and_then(|value| value.checked_add(usize::from(is_observed_control(&record.frame))))
            .and_then(|value| value.checked_add(usize::from(automatic)));
        let Some(next_output_capacity) =
            group_outputs.and_then(|group| output_capacity.checked_add(group))
        else {
            return failed(
                accepted_records,
                output_capacity,
                FailureKind::Frame(FrameFailure::ArithmeticOverflow),
            );
        };

        let mut next_generated_wire_bytes = generated_wire_bytes;
        if automatic {
            let Some(next_write_entries) = write_entries.checked_add(1) else {
                return failed(
                    accepted_records,
                    output_capacity,
                    FailureKind::Backpressure(QueueKind::Write),
                );
            };
            if next_write_entries > config.write_queue_entries() {
                return failed(
                    accepted_records,
                    output_capacity,
                    FailureKind::Backpressure(QueueKind::Write),
                );
            }
            let frame = OutboundFrame::new(true, Opcode::Pong, record.frame.payload());
            let wire_length = match encoder.preflight(frame, None) {
                Ok(length) => length,
                Err(failure) => return failed(accepted_records, output_capacity, failure),
            };
            next_generated_wire_bytes = match generated_wire_bytes.checked_add(wire_length) {
                Some(value) => value,
                None => {
                    return failed(
                        accepted_records,
                        output_capacity,
                        FailureKind::Frame(FrameFailure::ArithmeticOverflow),
                    );
                }
            };
            write_entries = next_write_entries;
        }

        let retained_total = match record
            .retained_payload_bytes
            .checked_add(next_generated_wire_bytes)
        {
            Some(value) => value,
            None => {
                return failed(
                    accepted_records,
                    output_capacity,
                    FailureKind::Frame(FrameFailure::ArithmeticOverflow),
                );
            }
        };
        if retained_total > config.total_buffered_bytes() {
            return failed(
                accepted_records,
                output_capacity,
                FailureKind::LimitExceeded {
                    limit: LimitKind::TotalBufferedBytes,
                    attempted: u64::try_from(retained_total).unwrap_or(u64::MAX),
                    maximum: config.limits().total_buffered_bytes,
                },
            );
        }

        accepted_records += 1;
        output_capacity = next_output_capacity;
        generated_wire_bytes = next_generated_wire_bytes;
    }

    BatchPlan {
        accepted_records,
        output_capacity,
        failure: None,
    }
}

fn failed(accepted_records: usize, output_capacity: usize, failure: FailureKind) -> BatchPlan {
    BatchPlan {
        accepted_records,
        output_capacity,
        failure: Some(failure),
    }
}

pub(crate) fn is_observed_control(frame: &Frame) -> bool {
    matches!(frame.opcode(), Opcode::Ping | Opcode::Pong)
}

pub(crate) fn should_automatically_pong(
    config: &ConnectionConfig,
    role: Role,
    opcode: Opcode,
) -> bool {
    role == Role::Server
        && config.automatic_pong_policy() == AutomaticPongPolicy::ServerOnly
        && opcode == Opcode::Ping
}

pub(crate) fn encode_automatic_pong(
    config: &ConnectionConfig,
    payload: &[u8],
) -> Result<Box<[u8]>, FailureKind> {
    FrameEncoder::new(config.clone(), Role::Server)
        .encode(OutboundFrame::new(true, Opcode::Pong, payload), None)
        .map(|frame| frame.into_bytes())
}

pub(crate) fn encode_local_control(
    config: &ConnectionConfig,
    role: Role,
    opcode: Opcode,
    payload: &[u8],
    mask_key: Option<[u8; 4]>,
) -> Result<Box<[u8]>, FailureKind> {
    let encoder = FrameEncoder::new(config.clone(), role);
    let frame = OutboundFrame::new(true, opcode, payload);
    encoder.preflight(frame, mask_key)?;
    encoder
        .encode(frame, mask_key)
        .map(|frame| frame.into_bytes())
}
