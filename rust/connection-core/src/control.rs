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

#[cfg(kani)]
mod proofs {
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    use super::{
        AutomaticPongPolicy, ControlPayload, encode_automatic_pong, is_observed_control,
        should_automatically_pong,
    };
    use crate::frame::{Frame, Opcode};
    use crate::{ConnectionConfig, ConnectionLimits, Role};

    #[kani::proof]
    #[kani::unwind(12)]
    fn prove_ping_pong_policy_and_encoding() {
        let endpoint_role = if kani::any::<bool>() {
            Role::Client
        } else {
            Role::Server
        };
        let opcode = if kani::any::<bool>() {
            Opcode::Ping
        } else {
            Opcode::Pong
        };
        let policy = if kani::any::<bool>() {
            AutomaticPongPolicy::Disabled
        } else {
            AutomaticPongPolicy::ServerOnly
        };
        let payload_length = usize::from(kani::any::<u8>() % 5);
        let mut payload = Vec::new();
        for _ in 0..payload_length {
            payload.push(kani::any::<u8>());
        }

        let config = ConnectionConfig::try_from(ConnectionLimits::default())
            .expect("default limits are valid")
            .with_automatic_pong_policy(policy);
        let frame = Frame::new(true, opcode, kani::any::<bool>(), Arc::new(payload.clone()));
        assert!(is_observed_control(&frame));
        assert_eq!(
            ControlPayload::from_frame(&frame).as_slice(),
            payload.as_slice()
        );

        let expected_automatic = endpoint_role == Role::Server
            && policy == AutomaticPongPolicy::ServerOnly
            && opcode == Opcode::Ping;
        assert_eq!(
            should_automatically_pong(&config, endpoint_role, opcode),
            expected_automatic
        );
        if expected_automatic {
            let wire =
                encode_automatic_pong(&config, &payload).expect("bounded server Pong is encodable");
            assert_eq!(wire[0], 0x8a);
            assert_eq!(usize::from(wire[1]), payload_length);
            assert_eq!(&wire[2..], payload.as_slice());
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use super::is_observed_control;
    use crate::frame::{Frame, Opcode};

    fn frame_with(opcode: Opcode) -> Frame {
        Frame::new(true, opcode, false, Arc::new(vec![0x01, 0x02]))
    }

    /// `is_observed_control` is the sole predicate deciding whether a decoded
    /// frame contributes a `ControlPayload` clone and an extra reserved output
    /// slot. Every downstream consumer either re-checks the opcode in a `match`
    /// that dominates the predicate, or folds it into a `try_reserve_exact`
    /// capacity, so no end-to-end connection assertion can distinguish the real
    /// predicate from a constant `true`. A direct assertion can, and this test
    /// is the one that does.
    ///
    /// Kills the cargo-mutants survivor `control.rs:155:5` (genre `FnValue`,
    /// `is_observed_control` body replaced with `true`), recorded as
    /// `ALLOCATION_SHAPE_ONLY` in
    /// `evidence/mutation/external-38428a5/adjudication.json`.
    #[test]
    fn is_observed_control_admits_ping_and_pong_and_rejects_every_other_opcode() {
        assert!(
            is_observed_control(&frame_with(Opcode::Ping)),
            "Ping is an observed control frame"
        );
        assert!(
            is_observed_control(&frame_with(Opcode::Pong)),
            "Pong is an observed control frame"
        );

        for opcode in [
            Opcode::Continuation,
            Opcode::Text,
            Opcode::Binary,
            Opcode::Close,
        ] {
            assert!(
                !is_observed_control(&frame_with(opcode)),
                "{opcode:?} must not be observed as a Ping/Pong control frame"
            );
        }
    }
}
