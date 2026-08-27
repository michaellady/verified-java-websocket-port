//! Private single-message fragmentation state and admission.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::frame::{FrameHeader, Opcode};
use crate::message::{DeliveryKind, MessageDelivery, admit_events, admit_frame_event};
use crate::utf8::Utf8Validator;
use crate::{ConnectionConfig, FailureKind, FragmentFailure, FrameFailure, LimitKind, Utf8Failure};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FragmentPlan {
    Unfragmented(Option<DeliveryKind>),
    Control,
    Begin(DeliveryKind),
    Continue {
        kind: DeliveryKind,
        final_frame: bool,
    },
}

impl FragmentPlan {
    pub(crate) const fn event_slots(self) -> usize {
        match self {
            Self::Unfragmented(Some(_))
            | Self::Continue {
                final_frame: true, ..
            } => 2,
            Self::Unfragmented(None)
            | Self::Control
            | Self::Begin(_)
            | Self::Continue {
                final_frame: false, ..
            } => 1,
        }
    }
}

#[derive(Debug)]
enum ActiveFragment {
    Text {
        payload: Vec<u8>,
        utf8: Utf8Validator,
    },
    Binary {
        payload: Vec<u8>,
    },
}

impl ActiveFragment {
    fn kind(&self) -> DeliveryKind {
        match self {
            Self::Text { .. } => DeliveryKind::Text,
            Self::Binary { .. } => DeliveryKind::Binary,
        }
    }

    fn opcode(&self) -> Opcode {
        match self.kind() {
            DeliveryKind::Text => Opcode::Text,
            DeliveryKind::Binary => Opcode::Binary,
        }
    }

    fn payload(&self) -> &Vec<u8> {
        match self {
            Self::Text { payload, .. } | Self::Binary { payload } => payload,
        }
    }

    fn payload_mut(&mut self) -> &mut Vec<u8> {
        match self {
            Self::Text { payload, .. } | Self::Binary { payload } => payload,
        }
    }
}

#[derive(Debug)]
pub(crate) struct FragmentAccumulator {
    active: Option<ActiveFragment>,
}

impl FragmentAccumulator {
    pub(crate) const fn new() -> Self {
        Self { active: None }
    }

    pub(crate) fn retained_bytes(&self) -> usize {
        self.active
            .as_ref()
            .map_or(0, |active| active.payload().len())
    }

    pub(crate) fn plan(
        &self,
        config: &ConnectionConfig,
        header: &FrameHeader,
        staged_payload_bytes: usize,
        staged_event_count: usize,
    ) -> Result<FragmentPlan, FailureKind> {
        let active = self.active.as_ref();
        let plan = match (active, header.opcode()) {
            (None, Opcode::Continuation) => {
                return Err(FailureKind::Fragment(
                    FragmentFailure::ContinuationWithoutMessage,
                ));
            }
            (None, Opcode::Text) if header.fin() => {
                FragmentPlan::Unfragmented(Some(DeliveryKind::Text))
            }
            (None, Opcode::Binary) if header.fin() => {
                FragmentPlan::Unfragmented(Some(DeliveryKind::Binary))
            }
            (None, Opcode::Text) => FragmentPlan::Begin(DeliveryKind::Text),
            (None, Opcode::Binary) => FragmentPlan::Begin(DeliveryKind::Binary),
            (None, Opcode::Close | Opcode::Ping | Opcode::Pong) => FragmentPlan::Control,
            (Some(active), Opcode::Text | Opcode::Binary) => {
                return Err(FailureKind::Fragment(
                    FragmentFailure::DataFrameWhileFragmented {
                        active: active.opcode(),
                        received: header.opcode(),
                    },
                ));
            }
            (Some(active), Opcode::Continuation) => FragmentPlan::Continue {
                kind: active.kind(),
                final_frame: header.fin(),
            },
            (Some(_), Opcode::Close | Opcode::Ping | Opcode::Pong) => FragmentPlan::Control,
        };

        match plan {
            FragmentPlan::Unfragmented(Some(kind)) => {
                kind.admit(config, header.payload_length(), staged_event_count)?;
            }
            FragmentPlan::Unfragmented(None) | FragmentPlan::Control => {
                admit_frame_event(config, staged_event_count)?;
            }
            FragmentPlan::Begin(_) | FragmentPlan::Continue { .. } => {
                let accumulated = self
                    .retained_bytes()
                    .checked_add(header.payload_length())
                    .ok_or(FailureKind::Frame(FrameFailure::ArithmeticOverflow))?;
                if accumulated > config.message_bytes() {
                    return Err(FailureKind::LimitExceeded {
                        limit: LimitKind::MessageBytes,
                        attempted: u64::try_from(accumulated).unwrap_or(u64::MAX),
                        maximum: config.limits().message_bytes,
                    });
                }
                let duplicate_peak = self
                    .retained_bytes()
                    .checked_add(staged_payload_bytes)
                    .and_then(|value| value.checked_add(header.payload_length()))
                    .and_then(|value| value.checked_add(header.payload_length()))
                    .ok_or(FailureKind::Frame(FrameFailure::ArithmeticOverflow))?;
                if duplicate_peak > config.total_buffered_bytes() {
                    return Err(FailureKind::LimitExceeded {
                        limit: LimitKind::TotalBufferedBytes,
                        attempted: u64::try_from(duplicate_peak).unwrap_or(u64::MAX),
                        maximum: config.limits().total_buffered_bytes,
                    });
                }
                admit_events(config, staged_event_count, plan.event_slots())?;
            }
        }
        Ok(plan)
    }

    pub(crate) fn prepare(
        &mut self,
        plan: FragmentPlan,
        payload_length: usize,
    ) -> Result<(), FailureKind> {
        match plan {
            FragmentPlan::Begin(kind) => {
                let mut payload = Vec::new();
                if payload_length != 0 && payload.try_reserve_exact(payload_length).is_err() {
                    return Err(FailureKind::Frame(FrameFailure::AllocationFailed));
                }
                self.active = Some(match kind {
                    DeliveryKind::Text => ActiveFragment::Text {
                        payload,
                        utf8: Utf8Validator::new(),
                    },
                    DeliveryKind::Binary => ActiveFragment::Binary { payload },
                });
            }
            FragmentPlan::Continue { .. } => {
                let payload = self
                    .active
                    .as_mut()
                    .expect("a planned continuation has an active message")
                    .payload_mut();
                if payload_length != 0 && payload.try_reserve_exact(payload_length).is_err() {
                    return Err(FailureKind::Frame(FrameFailure::AllocationFailed));
                }
            }
            FragmentPlan::Unfragmented(_) | FragmentPlan::Control => {}
        }
        Ok(())
    }

    pub(crate) fn feed(&mut self, plan: FragmentPlan, bytes: &[u8]) -> Result<(), Utf8Failure> {
        if matches!(
            plan,
            FragmentPlan::Begin(DeliveryKind::Text)
                | FragmentPlan::Continue {
                    kind: DeliveryKind::Text,
                    ..
                }
        ) && let Some(ActiveFragment::Text { utf8, .. }) = self.active.as_mut()
        {
            utf8.feed(bytes)?;
        }
        Ok(())
    }

    pub(crate) fn commit(
        &mut self,
        plan: FragmentPlan,
        payload: &[u8],
    ) -> Result<Option<MessageDelivery>, Utf8Failure> {
        match plan {
            FragmentPlan::Begin(_) | FragmentPlan::Continue { .. } => {
                if matches!(
                    plan,
                    FragmentPlan::Continue {
                        kind: DeliveryKind::Text,
                        final_frame: true,
                    }
                ) && let Some(ActiveFragment::Text { utf8, .. }) = self.active.as_ref()
                {
                    utf8.finish()?;
                }
                self.active
                    .as_mut()
                    .expect("a prepared fragment has active state")
                    .payload_mut()
                    .extend_from_slice(payload);

                if matches!(
                    plan,
                    FragmentPlan::Continue {
                        final_frame: true,
                        ..
                    }
                ) {
                    let active = self.active.take().expect("final continuation is active");
                    let kind = active.kind();
                    let payload = match active {
                        ActiveFragment::Text { payload, .. }
                        | ActiveFragment::Binary { payload } => payload,
                    };
                    return Ok(Some(MessageDelivery::from_payload(kind, Arc::new(payload))));
                }
            }
            FragmentPlan::Unfragmented(_) | FragmentPlan::Control => {}
        }
        Ok(None)
    }

    pub(crate) fn unexpected_eof(&self) -> Option<FragmentFailure> {
        self.active
            .as_ref()
            .map(|active| FragmentFailure::UnexpectedEof {
                active: active.opcode(),
                accumulated: u64::try_from(active.payload().len()).unwrap_or(u64::MAX),
            })
    }

    pub(crate) fn reset(&mut self) {
        self.active = None;
    }
}
