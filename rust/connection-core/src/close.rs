//! Private RFC 6455 close validation and handshake state.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::frame::{Frame, FrameEncoder, Opcode, OutboundFrame};
use crate::utf8::Utf8Validator;
use crate::{
    BehaviorProfile, ConnectionConfig, FailureKind, FrameFailure, LimitKind, Role, Utf8Failure,
};

/// Payload exposed by a newly constructed Java-WebSocket close-frame object
/// before its wire payload has been parsed (Java-WebSocket 1.6.0 quirk Q10).
/// Adapted from Claude's independently developed `ws-core` at `dc07516`, then
/// reverified through this core and the live 74-scenario differential path.
pub(crate) const JAVA_CLOSE_CONSTRUCTOR_PAYLOAD: &[u8; 2] = &[0x03, 0xe8];

/// Which endpoint admitted the first close in this core's ordered input stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseInitiator {
    /// A local close command was admitted first.
    Local,
    /// A peer close frame was admitted first.
    Peer,
}

/// Why a close code is not legal in the bounded no-extension profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseCodeRejection {
    /// The value is outside the RFC 6455 wire-code range.
    OutsideWireRange,
    /// The value is a forbidden wire sentinel or reservation.
    ForbiddenWireCode,
    /// The value is legal only when sent by the opposite endpoint role.
    WrongSenderRole,
    /// The value is not assigned by the bounded no-extension profile.
    UnassignedOrExtensionReserved,
}

/// Stable close-handshake and EOF rejection vocabulary.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CloseFailure {
    /// A close payload contained only one byte and therefore no complete code.
    PayloadLengthOne,
    /// A local empty-payload close supplied a reason without a code.
    ReasonWithoutCode,
    /// A close code is not legal for its sender role and profile.
    InvalidCode {
        /// The rejected code.
        code: u16,
        /// The exact code-table rejection class.
        rejection: CloseCodeRejection,
    },
    /// The inbound close reason was not strict canonical UTF-8.
    InvalidReason(Utf8Failure),
    /// A second local close was submitted after the local half was admitted.
    DuplicateLocalClose,
    /// A second peer close arrived before terminal completion.
    DuplicatePeerClose,
    /// A peer-first client acknowledgement did not exactly echo code and reason.
    AcknowledgementMismatch,
    /// Application data arrived after the closing handshake began.
    DataAfterClose {
        /// The rejected application opcode.
        opcode: Opcode,
    },
    /// Bytes or another record followed the first close in one transport input.
    TrailingBytesAfterClose,
    /// EOF arrived in Open before either endpoint sent a close.
    UnexpectedEofOpen,
    /// EOF arrived after a local close but before the peer close.
    EofBeforePeerClose,
    /// EOF arrived after a peer-first close but before the client acknowledgement.
    EofBeforeAcknowledgement,
    /// EOF arrived before the admitted close write was confirmed flushed.
    EofBeforeCloseWriteFlushed,
}

/// Immutable, zero-copy semantic view of one validated inbound close payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloseFrame {
    owner: Arc<Vec<u8>>,
    code: Option<u16>,
    reason_start: usize,
}

impl CloseFrame {
    /// Returns the optional wire close code; an empty payload has no code.
    #[must_use]
    pub const fn code(&self) -> Option<u16> {
        self.code
    }

    /// Returns the strict UTF-8 reason, which is empty when no code was sent.
    #[must_use]
    pub fn reason(&self) -> &str {
        core::str::from_utf8(&self.owner[self.reason_start..])
            .expect("CloseFrame construction validates strict UTF-8")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreparedClose {
    pub(crate) payload: Box<[u8]>,
    pub(crate) wire: Box<[u8]>,
}

#[derive(Debug)]
pub(crate) struct CloseMachine {
    initiator: Option<CloseInitiator>,
    local_payload: Option<LocalClose>,
    peer: Option<CloseFrame>,
    write_pending: bool,
}

#[derive(Debug)]
enum LocalClose {
    Owned(Box<[u8]>),
    PeerEcho,
}

impl CloseMachine {
    pub(crate) const fn new() -> Self {
        Self {
            initiator: None,
            local_payload: None,
            peer: None,
            write_pending: false,
        }
    }

    pub(crate) fn reset(&mut self) {
        *self = Self::new();
    }

    pub(crate) const fn has_local(&self) -> bool {
        self.local_payload.is_some()
    }

    pub(crate) const fn has_peer(&self) -> bool {
        self.peer.is_some()
    }

    pub(crate) const fn write_pending(&self) -> bool {
        self.write_pending
    }

    pub(crate) fn retained_bytes(&self) -> usize {
        let peer = self.peer.as_ref().map_or(0, |peer| peer.owner.len());
        let local = match self.local_payload.as_ref() {
            Some(LocalClose::Owned(payload)) => payload.len(),
            Some(LocalClose::PeerEcho) | None => 0,
        };
        peer.saturating_add(local)
    }

    pub(crate) const fn initiator(&self) -> Option<CloseInitiator> {
        self.initiator
    }

    pub(crate) fn begin_local(&mut self, payload: Box<[u8]>) {
        debug_assert!(self.initiator.is_none());
        self.initiator = Some(CloseInitiator::Local);
        self.local_payload = Some(LocalClose::Owned(payload));
        self.write_pending = true;
    }

    pub(crate) fn begin_peer(&mut self, peer: CloseFrame) {
        debug_assert!(self.initiator.is_none());
        self.initiator = Some(CloseInitiator::Peer);
        self.peer = Some(peer);
    }

    pub(crate) fn accept_peer(&mut self, peer: CloseFrame) {
        debug_assert!(self.peer.is_none());
        self.peer = Some(peer);
    }

    pub(crate) fn admit_local_half(&mut self, payload: Box<[u8]>) {
        debug_assert!(self.local_payload.is_none());
        self.local_payload = Some(LocalClose::Owned(payload));
        self.write_pending = true;
    }

    pub(crate) fn admit_peer_echo(&mut self) {
        debug_assert!(self.local_payload.is_none());
        debug_assert!(self.peer.is_some());
        self.local_payload = Some(LocalClose::PeerEcho);
        self.write_pending = true;
    }

    pub(crate) fn acknowledgement_matches(&self, code: Option<u16>, reason: &str) -> bool {
        self.peer
            .as_ref()
            .is_some_and(|peer| peer.code() == code && peer.reason() == reason)
    }

    pub(crate) fn mark_write_flushed(&mut self) {
        self.write_pending = false;
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.local_payload.is_some() && self.peer.is_some() && !self.write_pending
    }

    pub(crate) fn eof_failure(&self) -> CloseFailure {
        match (
            self.local_payload.is_some(),
            self.peer.is_some(),
            self.write_pending,
        ) {
            (true, false, _) => CloseFailure::EofBeforePeerClose,
            (false, true, _) => CloseFailure::EofBeforeAcknowledgement,
            (true, true, _) => CloseFailure::EofBeforeCloseWriteFlushed,
            (false, false, _) => CloseFailure::UnexpectedEofOpen,
        }
    }
}

pub(crate) fn prepare_local_close(
    config: &ConnectionConfig,
    role: Role,
    code: Option<u16>,
    reason: &str,
    mask_key: Option<[u8; 4]>,
    additional_retained_bytes: usize,
) -> Result<PreparedClose, FailureKind> {
    if code.is_none() && !reason.is_empty() {
        return Err(FailureKind::Close(CloseFailure::ReasonWithoutCode));
    }
    if let Some(code) = code {
        validate_code(code, role).map_err(FailureKind::Close)?;
    }

    let payload_length = if code.is_some() {
        2usize
            .checked_add(reason.len())
            .ok_or(FailureKind::Frame(FrameFailure::ArithmeticOverflow))?
    } else {
        0
    };
    if payload_length > 125 {
        return Err(FailureKind::Frame(FrameFailure::ControlPayloadTooLarge {
            length: u64::try_from(payload_length).unwrap_or(u64::MAX),
        }));
    }
    validate_mask_key(role, mask_key)?;
    let encoder = FrameEncoder::new(config.clone(), role);
    let placeholder = [0_u8; 125];
    let frame = OutboundFrame::new(true, Opcode::Close, &placeholder[..payload_length]);
    let wire_length = encoder.preflight(frame, mask_key)?;
    let retained_total = payload_length
        .checked_add(wire_length)
        .and_then(|bytes| bytes.checked_add(additional_retained_bytes))
        .ok_or(FailureKind::Frame(FrameFailure::ArithmeticOverflow))?;
    if retained_total > config.total_buffered_bytes() {
        return Err(FailureKind::LimitExceeded {
            limit: LimitKind::TotalBufferedBytes,
            attempted: u64::try_from(retained_total).unwrap_or(u64::MAX),
            maximum: config.limits().total_buffered_bytes,
        });
    }

    let mut payload = Vec::new();
    if payload_length != 0 && payload.try_reserve_exact(payload_length).is_err() {
        return Err(FailureKind::Frame(FrameFailure::AllocationFailed));
    }
    if let Some(code) = code {
        payload.extend_from_slice(&code.to_be_bytes());
        payload.extend_from_slice(reason.as_bytes());
    }
    let wire = encoder
        .encode(OutboundFrame::new(true, Opcode::Close, &payload), mask_key)?
        .into_bytes();
    Ok(PreparedClose {
        payload: payload.into_boxed_slice(),
        wire,
    })
}

pub(crate) fn parse_peer_close(
    frame: &Frame,
    endpoint_role: Role,
    behavior_profile: BehaviorProfile,
) -> Result<CloseFrame, FailureKind> {
    debug_assert_eq!(frame.opcode(), Opcode::Close);
    let payload = frame.payload();
    if payload.len() == 1 && behavior_profile == BehaviorProfile::Rfc6455Strict {
        return Err(FailureKind::Close(CloseFailure::PayloadLengthOne));
    }
    let code = if payload.is_empty() && behavior_profile == BehaviorProfile::JavaWebSocketV1_6_0 {
        Some(1000)
    } else if payload.len() == 1 {
        Some(1002)
    } else if payload.len() >= 2 {
        let code = u16::from_be_bytes([payload[0], payload[1]]);
        validate_code(code, peer_role(endpoint_role)).map_err(FailureKind::Close)?;
        Some(code)
    } else {
        None
    };
    let reason_start = match payload.len() {
        0 => 0,
        1 => 1,
        _ if code.is_some() => 2,
        _ => 0,
    };
    let mut validator = Utf8Validator::new();
    validator
        .feed(&payload[reason_start..])
        .and_then(|()| validator.finish())
        .map_err(|failure| FailureKind::Close(CloseFailure::InvalidReason(failure)))?;
    Ok(CloseFrame {
        owner: frame.payload_owner(),
        code,
        reason_start,
    })
}

pub(crate) fn encode_peer_echo(
    config: &ConnectionConfig,
    payload: &[u8],
) -> Result<Box<[u8]>, FailureKind> {
    FrameEncoder::new(config.clone(), Role::Server)
        .encode(OutboundFrame::new(true, Opcode::Close, payload), None)
        .map(|encoded| encoded.into_bytes())
}

fn validate_mask_key(role: Role, mask_key: Option<[u8; 4]>) -> Result<(), FailureKind> {
    match (role, mask_key) {
        (Role::Client, None) => Err(FailureKind::Frame(FrameFailure::MissingMaskKey)),
        (Role::Server, Some(_)) => Err(FailureKind::Frame(FrameFailure::UnexpectedMaskKey)),
        _ => Ok(()),
    }
}

fn validate_code(code: u16, sender: Role) -> Result<(), CloseFailure> {
    let rejection = match code {
        0..=999 | 5000..=u16::MAX => Some(CloseCodeRejection::OutsideWireRange),
        1004 | 1005 | 1006 | 1015 => Some(CloseCodeRejection::ForbiddenWireCode),
        1010 if sender == Role::Server => Some(CloseCodeRejection::WrongSenderRole),
        1000
        | 1001
        | 1002
        | 1003
        | 1007
        | 1008
        | 1009
        | 1010
        | 1011
        | 1012
        | 1013
        | 1014
        | 3000..=4999 => None,
        1016..=2999 => Some(CloseCodeRejection::UnassignedOrExtensionReserved),
    };
    match rejection {
        Some(rejection) => Err(CloseFailure::InvalidCode { code, rejection }),
        None => Ok(()),
    }
}

#[cfg(kani)]
mod proofs {
    use super::{CloseCodeRejection, CloseFailure, validate_code};
    use crate::Role;

    fn reference_rejection(code: u16, sender: Role) -> Option<CloseCodeRejection> {
        if code < 1000 || code >= 5000 {
            Some(CloseCodeRejection::OutsideWireRange)
        } else if code == 1004 || code == 1005 || code == 1006 || code == 1015 {
            Some(CloseCodeRejection::ForbiddenWireCode)
        } else if code == 1010 && sender == Role::Server {
            Some(CloseCodeRejection::WrongSenderRole)
        } else if (1016..=2999).contains(&code) {
            Some(CloseCodeRejection::UnassignedOrExtensionReserved)
        } else {
            None
        }
    }

    #[kani::proof]
    #[kani::unwind(2)]
    fn prove_close_code_classification() {
        let code: u16 = kani::any();
        let sender = if kani::any::<bool>() {
            Role::Client
        } else {
            Role::Server
        };
        let expected = match reference_rejection(code, sender) {
            Some(rejection) => Err(CloseFailure::InvalidCode { code, rejection }),
            None => Ok(()),
        };

        assert_eq!(validate_code(code, sender), expected);
    }
}

const fn peer_role(endpoint_role: Role) -> Role {
    match endpoint_role {
        Role::Client => Role::Server,
        Role::Server => Role::Client,
    }
}

#[cfg(test)]
mod tests {
    use super::{CloseInitiator, CloseMachine};

    #[test]
    fn reset_releases_every_retained_close_field() {
        let mut machine = CloseMachine::new();
        machine.begin_local(vec![0x03, 0xe8, b'x'].into_boxed_slice());
        assert_eq!(machine.initiator(), Some(CloseInitiator::Local));
        assert_eq!(machine.retained_bytes(), 3);
        assert!(machine.write_pending());

        machine.reset();
        assert_eq!(machine.initiator(), None);
        assert_eq!(machine.retained_bytes(), 0);
        assert!(!machine.has_local());
        assert!(!machine.has_peer());
        assert!(!machine.write_pending());
    }
}
