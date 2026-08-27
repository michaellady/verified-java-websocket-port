//! Typed protocol failures (US-009 AC2).
//!
//! [`TypedProtocolFailure`] is the scenario-scoped projection of the
//! java-oracle's stable error vocabulary (`java-oracle/README.md` "Output";
//! `internal/corpora/derive.go`). The harness serializes [`FailureCode::wire_code`]
//! verbatim, so no mapping table can drift outside the core. Two codes are
//! deliberately port-side only and yield no wire code: [`FailureCode::Backpressure`]
//! (the AC4 bounded-queue refusal, drained away by any correct owner before a
//! transcript exists) and [`FailureCode::Unimplemented`] (the US-009 skeleton's
//! honest refusal of behavior owned by US-010..US-016, guaranteeing the
//! protocol-stub gate fails the corpus instead of silently faking Java).

use std::error::Error;
use std::fmt;

/// Which bounded queue refused an input (US-009 AC4).
///
/// Queues are fixed-capacity, allocated once at construction from
/// [`crate::config::ConnectionConfig`] limits; overflow surfaces as
/// [`FailureCode::Backpressure`] carrying this discriminator, never as
/// reallocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QueueKind {
    /// The semantic-event queue drained by [`crate::connection::ConnectionCore::next_event`].
    Event,
    /// The transport-write queue drained by [`crate::connection::ConnectionCore::next_write`].
    Write,
    /// The bounded multi-producer command channel
    /// ([`crate::connection::CommandQueue`]).
    Command,
}

/// The failure vocabulary of the core.
///
/// Variants with a `Some` [`FailureCode::wire_code`] mirror the oracle's
/// observable error codes exactly; see each variant's citation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailureCode {
    /// Java `InvalidDataException` path; carries a close code such as
    /// 1002/1007/1009 (oracle code `JAVA_INVALID_DATA`; derive.go
    /// `javaInvalid`).
    JavaInvalidData,
    /// `NullPointerException`-class runtime rejection with no close code
    /// (oracle code `JAVA_RUNTIME_REJECTION`; derive.go
    /// `javaRuntimeRejection`, quirk Q12).
    JavaRuntimeRejection,
    /// `NotSendableException` on the send path (oracle code
    /// `JAVA_NOT_SENDABLE`; derive.go send-path DFA rejection, quirk Q16).
    JavaNotSendable,
    /// An action or byte chunk arrived in a state that forbids it (oracle
    /// code `STATE_VIOLATION`; derive.go `requireOpen` and the closed-state
    /// gates, quirk Q26). Also returned for every input after the core is
    /// poisoned by a fatal failure (partial-execution semantics).
    StateViolation,
    /// `max_input_bytes` would be exceeded; checked before the counter
    /// updates (addBounded, derive.go:295-299). Oracle code
    /// `INPUT_LIMIT_EXCEEDED`.
    InputLimitExceeded,
    /// A buffered-byte bound would be exceeded (wire pending buffer over
    /// `max_buffered_bytes + 14`, quirk Q24, or a send payload over
    /// `max_buffered_bytes`). Oracle code `BUFFER_LIMIT_EXCEEDED`; carries no
    /// close code (adapter-level accounting, derive.go:683-687).
    BufferLimitExceeded,
    /// `max_actions` exceeded; the rejected action is still counted
    /// (derive.go actionStep). Oracle code `ACTION_LIMIT_EXCEEDED`.
    ActionLimitExceeded,
    /// `max_frames` exceeded (oracle code `FRAME_LIMIT_EXCEEDED`;
    /// derive.go:362, 785). Unreachable in the US-009 skeleton, which decodes
    /// no frames.
    FrameLimitExceeded,
    /// `max_output_bytes` exceeded (oracle code `OUTPUT_LIMIT_EXCEEDED`).
    /// Unreachable in the US-009 skeleton, which emits no wire output.
    OutputLimitExceeded,
    /// A bounded queue is full; the caller must drain and may retry the
    /// identical input (US-009 AC4). Non-fatal, harness-invisible (a correct
    /// owner drains eagerly, so no transcript records it), and it never
    /// consumes the refused input or a step index.
    Backpressure(QueueKind),
    /// Honest refusal of behavior no landed story owns. After the
    /// US-010..US-016 slices landed (including the US-016 AC3
    /// `NotYetConnected` command/EOF arms), the ONE surviving refusal site
    /// is the defensive control arm of `Draft6455::process_frame`
    /// (unreachable via `ConnectionCore`). No oracle wire code exists, so a
    /// refusal can never impersonate Java — the `empty_rust_target_fails`
    /// discipline.
    Unimplemented,
}

impl FailureCode {
    /// The exact oracle wire string, so the harness serializes without a
    /// mapping table of its own. `None` for the two port-side codes
    /// ([`FailureCode::Backpressure`], [`FailureCode::Unimplemented`]), which
    /// must never appear in a transcript.
    #[must_use]
    pub fn wire_code(&self) -> Option<&'static str> {
        match self {
            FailureCode::JavaInvalidData => Some("JAVA_INVALID_DATA"),
            FailureCode::JavaRuntimeRejection => Some("JAVA_RUNTIME_REJECTION"),
            FailureCode::JavaNotSendable => Some("JAVA_NOT_SENDABLE"),
            FailureCode::StateViolation => Some("STATE_VIOLATION"),
            FailureCode::InputLimitExceeded => Some("INPUT_LIMIT_EXCEEDED"),
            FailureCode::BufferLimitExceeded => Some("BUFFER_LIMIT_EXCEEDED"),
            FailureCode::ActionLimitExceeded => Some("ACTION_LIMIT_EXCEEDED"),
            FailureCode::FrameLimitExceeded => Some("FRAME_LIMIT_EXCEEDED"),
            FailureCode::OutputLimitExceeded => Some("OUTPUT_LIMIT_EXCEEDED"),
            FailureCode::Backpressure(_) | FailureCode::Unimplemented => None,
        }
    }

    /// Whether this failure poisons the core (ends the scenario). Only
    /// [`FailureCode::Backpressure`] is recoverable: the refused input was
    /// not consumed and may be retried after draining.
    #[must_use]
    pub fn is_fatal(&self) -> bool {
        !matches!(self, FailureCode::Backpressure(_))
    }
}

/// A typed protocol failure: the failure code plus the close code exactly
/// when the oracle reports one (`error.close_code` in the transcript schema;
/// present only on `JAVA_INVALID_DATA`-class rejections).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedProtocolFailure {
    /// The failure vocabulary entry.
    pub code: FailureCode,
    /// The close code the oracle reports with this failure, when it reports
    /// one (e.g. 1002/1007/1009 on `JAVA_INVALID_DATA`).
    pub close_code: Option<u16>,
}

impl TypedProtocolFailure {
    /// A failure with no close code (limit codes, state violations,
    /// backpressure, runtime rejections).
    #[must_use]
    pub fn protocol(code: FailureCode) -> Self {
        TypedProtocolFailure {
            code,
            close_code: None,
        }
    }

    /// A `JAVA_INVALID_DATA` failure carrying its close code.
    #[must_use]
    pub fn java_invalid_data(close_code: u16) -> Self {
        TypedProtocolFailure {
            code: FailureCode::JavaInvalidData,
            close_code: Some(close_code),
        }
    }
}

impl fmt::Display for TypedProtocolFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.code.wire_code(), self.close_code) {
            (Some(wire), Some(close)) => write!(f, "{wire} (close code {close})"),
            (Some(wire), None) => write!(f, "{wire}"),
            (None, _) => write!(f, "{:?} (port-side, no wire code)", self.code),
        }
    }
}

impl Error for TypedProtocolFailure {}
