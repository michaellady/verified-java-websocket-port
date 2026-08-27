//! Dependency-free, safe-Rust Sans-I/O connection contract.
//!
//! US-009 establishes admission, configuration, ordering, typed failure, and
//! bounded command-channel seams. US-010 adds the client opening handshake,
//! and US-011 begins the server opening handshake. Frames, messages,
//! fragmentation, controls, protocol close behavior, sockets, runtimes, and
//! callbacks remain unavailable and are owned by later stories.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod channel;
mod close;
mod connection;
mod control;
pub mod frame;
mod handshake;

pub use channel::{
    CommandReceiveError, CommandReceiver, CommandSendError, CommandSender, command_channel,
};
pub use connection::{
    CloseFailure, ConfigError, ConnectionConfig, ConnectionCore, ConnectionLimits, ConnectionState,
    CoreInput, CoreOutput, FailureKind, FrameFailure, HandshakeFailure, InputKind, LimitKind,
    LimitRelationship, LocalCommand, ProtocolStory, QueueKind, Role, SemanticEvent, StepResult,
    TransportBytes, TransportWrite, TypedProtocolFailure, Utf8Failure,
};
pub use handshake::{
    ClientRequestDescriptor, ClientRequestDescriptorError, ServerRequestDescriptor,
};
