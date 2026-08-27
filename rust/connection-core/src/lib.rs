//! Dependency-free, safe-Rust Sans-I/O connection contract.
//!
//! US-009 establishes admission, configuration, ordering, typed failure, and
//! bounded command-channel seams. US-010 and US-011 add opening handshakes;
//! US-012 adds canonical frame coding and masking; US-013 delivers final Text
//! and Binary messages; US-014 adds strict inbound fragment reassembly; US-015
//! adds bounded Ping/Pong observation and explicit control writes; US-016 adds
//! the bounded closing handshake and typed EOF lifecycle. Sockets, runtimes,
//! and callbacks remain owned by later stories.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

extern crate alloc;

mod close;
mod connection;
mod control;
mod fragment;
pub mod frame;
mod handshake;
mod message;
mod utf8;

pub use close::{CloseCodeRejection, CloseFailure, CloseFrame, CloseInitiator};
pub use connection::{
    ConfigError, ConnectionConfig, ConnectionCore, ConnectionLimits, ConnectionState, CoreInput,
    CoreOutput, CoreStepObservation, FailureKind, FragmentFailure, FrameDirection, FrameFailure,
    FrameObservation, HandshakeFailure, InputKind, LimitKind, LimitRelationship, LocalCommand,
    ProtocolStory, QueueKind, Role, SemanticEvent, StepAccounting, StepResult, TransportBytes,
    TransportWrite, TypedProtocolFailure, Utf8Failure,
};
pub use control::{AutomaticPongPolicy, ControlPayload};
pub use fragment::FragmentKind;
pub use frame::decode::{FrameHeader, FrameHeaderDecode, FrameHeaderDecoder};
pub use frame::{EncodedFrame, Frame, FrameEncoder, Opcode, OutboundFrame, apply_mask_in_place};
pub use handshake::{
    ClientRequestDescriptor, ClientRequestDescriptorError, ServerRequestDescriptor,
};
pub use message::{BinaryMessage, TextMessage};
