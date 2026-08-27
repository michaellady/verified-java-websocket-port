use core::fmt;

use crate::frame::Frame;
use crate::frame::decode::FrameDecoder;
use crate::handshake::{
    ClientHandshake, ClientLimitExceeded, ClientRequestDescriptor, ClientResponse, ServerHandshake,
    ServerRequest, ServerRequestDescriptor,
};
use crate::message::MessageDelivery;

/// The role this endpoint has in the WebSocket protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// The endpoint initiates the opening handshake.
    Client,
    /// The endpoint accepts the opening handshake.
    Server,
}

/// The externally observable lifecycle state of a connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionState {
    /// The opening handshake has not completed.
    Connecting,
    /// The connection may exchange data frames.
    Open,
    /// A closing handshake is in progress.
    Closing,
    /// The connection is terminal.
    Closed,
}

/// Identifies one configured resource limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LimitKind {
    /// Maximum bytes retained for an opening handshake.
    HandshakeBytes,
    /// Maximum header fields in an opening handshake.
    HandshakeHeaderCount,
    /// Maximum bytes in one opening-handshake line, including CRLF.
    HandshakeHeaderLineBytes,
    /// Maximum bytes retained for one frame.
    FrameBytes,
    /// Maximum bytes retained for one message.
    MessageBytes,
    /// Maximum bytes retained across all protocol buffers.
    TotalBufferedBytes,
    /// Maximum queued semantic events.
    EventQueueEntries,
    /// Maximum queued local commands.
    CommandQueueEntries,
    /// Maximum queued transport writes.
    WriteQueueEntries,
}

impl fmt::Display for LimitKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::HandshakeBytes => "handshake bytes",
            Self::HandshakeHeaderCount => "handshake header count",
            Self::HandshakeHeaderLineBytes => "handshake header-line bytes",
            Self::FrameBytes => "frame bytes",
            Self::MessageBytes => "message bytes",
            Self::TotalBufferedBytes => "total buffered bytes",
            Self::EventQueueEntries => "event queue entries",
            Self::CommandQueueEntries => "command queue entries",
            Self::WriteQueueEntries => "write queue entries",
        })
    }
}

/// Public, transport-friendly limit values accepted during configuration.
///
/// Values remain `u64` until validation so inputs cannot silently truncate on
/// a platform whose address space is narrower than the configuration source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionLimits {
    /// Maximum opening-handshake bytes.
    pub handshake_bytes: u64,
    /// Maximum opening-handshake header fields.
    pub handshake_header_count: u64,
    /// Maximum bytes in one opening-handshake line, including CRLF.
    pub handshake_header_line_bytes: u64,
    /// Maximum bytes in one frame.
    pub frame_bytes: u64,
    /// Maximum bytes in one reassembled message.
    pub message_bytes: u64,
    /// Maximum bytes retained across all protocol buffers.
    pub total_buffered_bytes: u64,
    /// Maximum queued semantic events.
    pub event_queue_entries: u64,
    /// Maximum queued local commands.
    pub command_queue_entries: u64,
    /// Maximum queued transport writes.
    pub write_queue_entries: u64,
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        Self {
            handshake_bytes: 4_096,
            handshake_header_count: 32,
            handshake_header_line_bytes: 512,
            frame_bytes: 1_048_576,
            message_bytes: 1_048_576,
            total_buffered_bytes: 1_048_576,
            event_queue_entries: 64,
            command_queue_entries: 64,
            write_queue_entries: 64,
        }
    }
}

/// A relationship between limits that cannot be satisfied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LimitRelationship {
    /// A header line could not fit in the complete handshake budget.
    HandshakeHeaderLineWithinHandshakeBytes,
    /// A frame could not fit in the total byte budget.
    FrameWithinTotalBufferedBytes,
    /// A message could not fit in the total byte budget.
    MessageWithinTotalBufferedBytes,
}

/// Why raw connection limits could not become a checked configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    /// A limit was zero, which would make progress impossible.
    Zero(LimitKind),
    /// A limit exceeded its fixed hard ceiling.
    ExceedsHardCeiling {
        /// The offending limit.
        limit: LimitKind,
        /// The supplied value.
        attempted: u64,
        /// The largest accepted value.
        maximum: u64,
    },
    /// A value could not be represented by the platform allocation type.
    DoesNotFitPlatform {
        /// The offending limit.
        limit: LimitKind,
        /// The supplied value.
        attempted: u64,
    },
    /// Individually valid limits violated a cross-field invariant.
    InvalidRelationship(LimitRelationship),
    /// Aggregate capacity arithmetic overflowed.
    AggregateCapacityOverflow,
}

/// Immutable, fully checked configuration for a [`ConnectionCore`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionConfig {
    limits: ConnectionLimits,
    checked: CheckedLimits,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CheckedLimits {
    handshake_bytes: usize,
    handshake_header_count: usize,
    handshake_header_line_bytes: usize,
    frame_bytes: usize,
    message_bytes: usize,
    total_buffered_bytes: usize,
    event_queue_entries: usize,
    command_queue_entries: usize,
    write_queue_entries: usize,
    aggregate_capacity: usize,
}

impl ConnectionConfig {
    /// Returns the validated external limit values.
    #[must_use]
    pub const fn limits(&self) -> &ConnectionLimits {
        &self.limits
    }

    /// Returns the checked aggregate capacity used for admission accounting.
    #[must_use]
    pub const fn aggregate_capacity(&self) -> usize {
        self.checked.aggregate_capacity
    }

    pub(crate) const fn command_queue_entries(&self) -> usize {
        self.checked.command_queue_entries
    }

    pub(crate) const fn frame_bytes(&self) -> usize {
        self.checked.frame_bytes
    }

    pub(crate) const fn message_bytes(&self) -> usize {
        self.checked.message_bytes
    }

    pub(crate) const fn total_buffered_bytes(&self) -> usize {
        self.checked.total_buffered_bytes
    }

    pub(crate) const fn event_queue_entries(&self) -> usize {
        self.checked.event_queue_entries
    }

    const fn handshake_limit(&self, limit: LimitKind) -> u64 {
        match limit {
            LimitKind::HandshakeBytes => self.limits.handshake_bytes,
            LimitKind::HandshakeHeaderCount => self.limits.handshake_header_count,
            LimitKind::HandshakeHeaderLineBytes => self.limits.handshake_header_line_bytes,
            _ => 0,
        }
    }
}

impl TryFrom<ConnectionLimits> for ConnectionConfig {
    type Error = ConfigError;

    fn try_from(limits: ConnectionLimits) -> Result<Self, Self::Error> {
        const ONE_MIB: u64 = 1_048_576;
        const QUEUE_MAX: u64 = 4_096;

        let raw = [
            (LimitKind::HandshakeBytes, limits.handshake_bytes, ONE_MIB),
            (
                LimitKind::HandshakeHeaderCount,
                limits.handshake_header_count,
                QUEUE_MAX,
            ),
            (
                LimitKind::HandshakeHeaderLineBytes,
                limits.handshake_header_line_bytes,
                ONE_MIB,
            ),
            (LimitKind::FrameBytes, limits.frame_bytes, ONE_MIB),
            (LimitKind::MessageBytes, limits.message_bytes, ONE_MIB),
            (
                LimitKind::TotalBufferedBytes,
                limits.total_buffered_bytes,
                ONE_MIB,
            ),
            (
                LimitKind::EventQueueEntries,
                limits.event_queue_entries,
                QUEUE_MAX,
            ),
            (
                LimitKind::CommandQueueEntries,
                limits.command_queue_entries,
                QUEUE_MAX,
            ),
            (
                LimitKind::WriteQueueEntries,
                limits.write_queue_entries,
                QUEUE_MAX,
            ),
        ];

        for (kind, attempted, maximum) in raw {
            if attempted == 0 {
                return Err(ConfigError::Zero(kind));
            }
            if attempted > maximum {
                return Err(ConfigError::ExceedsHardCeiling {
                    limit: kind,
                    attempted,
                    maximum,
                });
            }
        }

        if limits.handshake_header_line_bytes > limits.handshake_bytes {
            return Err(ConfigError::InvalidRelationship(
                LimitRelationship::HandshakeHeaderLineWithinHandshakeBytes,
            ));
        }
        if limits.frame_bytes > limits.total_buffered_bytes {
            return Err(ConfigError::InvalidRelationship(
                LimitRelationship::FrameWithinTotalBufferedBytes,
            ));
        }
        if limits.message_bytes > limits.total_buffered_bytes {
            return Err(ConfigError::InvalidRelationship(
                LimitRelationship::MessageWithinTotalBufferedBytes,
            ));
        }

        let convert = |kind, attempted| {
            usize::try_from(attempted).map_err(|_| ConfigError::DoesNotFitPlatform {
                limit: kind,
                attempted,
            })
        };
        let handshake_bytes = convert(LimitKind::HandshakeBytes, limits.handshake_bytes)?;
        let handshake_header_count = convert(
            LimitKind::HandshakeHeaderCount,
            limits.handshake_header_count,
        )?;
        let handshake_header_line_bytes = convert(
            LimitKind::HandshakeHeaderLineBytes,
            limits.handshake_header_line_bytes,
        )?;
        let frame_bytes = convert(LimitKind::FrameBytes, limits.frame_bytes)?;
        let message_bytes = convert(LimitKind::MessageBytes, limits.message_bytes)?;
        let total_buffered_bytes =
            convert(LimitKind::TotalBufferedBytes, limits.total_buffered_bytes)?;
        let event_queue_entries =
            convert(LimitKind::EventQueueEntries, limits.event_queue_entries)?;
        let command_queue_entries =
            convert(LimitKind::CommandQueueEntries, limits.command_queue_entries)?;
        let write_queue_entries =
            convert(LimitKind::WriteQueueEntries, limits.write_queue_entries)?;

        let aggregate_capacity = [
            handshake_bytes,
            handshake_header_count,
            handshake_header_line_bytes,
            frame_bytes,
            message_bytes,
            total_buffered_bytes,
            event_queue_entries,
            command_queue_entries,
            write_queue_entries,
        ]
        .into_iter()
        .try_fold(0usize, usize::checked_add)
        .ok_or(ConfigError::AggregateCapacityOverflow)?;

        Ok(Self {
            limits,
            checked: CheckedLimits {
                handshake_bytes,
                handshake_header_count,
                handshake_header_line_bytes,
                frame_bytes,
                message_bytes,
                total_buffered_bytes,
                event_queue_entries,
                command_queue_entries,
                write_queue_entries,
                aggregate_capacity,
            },
        })
    }
}

/// Borrowed transport input. Construction never copies the bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportBytes<'a> {
    bytes: &'a [u8],
}

impl<'a> TransportBytes<'a> {
    /// Borrows a transport buffer without allocating or copying.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Returns the borrowed transport bytes.
    #[must_use]
    pub const fn as_slice(&self) -> &'a [u8] {
        self.bytes
    }
}

/// One caller-originated protocol command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalCommand {
    /// Starts the deterministic client opening handshake.
    StartClientHandshake {
        /// Validated request target and Host wire fields.
        descriptor: ClientRequestDescriptor,
        /// Exact caller-provided random nonce bytes.
        nonce: [u8; 16],
    },
    /// Requests a text message.
    SendText(Box<str>),
    /// Requests a binary message.
    SendBinary(Box<[u8]>),
    /// Requests a ping control frame.
    SendPing(Box<[u8]>),
    /// Requests a pong control frame.
    SendPong(Box<[u8]>),
    /// Requests the closing handshake.
    Close {
        /// WebSocket close code.
        code: u16,
        /// Human-readable close reason.
        reason: Box<str>,
    },
}

/// One input admitted at the single mutable core seam.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreInput<'a> {
    /// Bytes observed from the transport.
    Transport(TransportBytes<'a>),
    /// A local protocol command.
    Command(LocalCommand),
    /// End-of-file observed from the transport.
    TransportEof,
}

/// Owned bytes to write to a transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportWrite {
    bytes: Box<[u8]>,
}

impl TransportWrite {
    /// Returns the owned wire bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

/// Typed semantic events emitted by completed protocol slices.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SemanticEvent {
    /// A client opening handshake completed successfully.
    ClientHandshakeOpened {
        /// The descriptor whose request was accepted by the peer.
        descriptor: ClientRequestDescriptor,
    },
    /// A server opening handshake completed successfully.
    ServerHandshakeOpened {
        /// The descriptor accepted from the peer's request.
        descriptor: ServerRequestDescriptor,
    },
    /// One complete, validated frame was decoded from the transport.
    FrameReceived {
        /// Immutable frame-level observation for later protocol stories.
        frame: Frame,
    },
    /// One complete, strictly validated UTF-8 text message was received.
    Text {
        /// Shared immutable validated message bytes.
        message: crate::message::TextMessage,
    },
    /// One complete binary message was received.
    Binary {
        /// Shared immutable uninterpreted message bytes.
        message: crate::message::BinaryMessage,
    },
}

/// One output in exact occurrence order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreOutput {
    /// Bytes destined for the transport.
    TransportWrite(TransportWrite),
    /// A semantic event destined for the caller.
    SemanticEvent(SemanticEvent),
    /// An observable lifecycle transition.
    StateChanged(ConnectionState),
}

/// Story that owns protocol behavior not implemented by US-009.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolStory {
    /// Client opening handshake (US-010).
    ClientOpeningHandshake,
    /// Server opening handshake (US-011).
    ServerOpeningHandshake,
    /// Frame coding and masking (US-012).
    FrameCoding,
    /// Text and binary delivery (US-013).
    Messages,
    /// Fragment reassembly (US-014).
    Fragmentation,
    /// Ping and pong behavior (US-015).
    ControlFrames,
    /// Close and EOF behavior (US-016).
    CloseAndEof,
}

/// Stable opening-handshake rejection vocabulary.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HandshakeFailure {
    /// This endpoint's role cannot perform a client handshake.
    WrongRole,
    /// A client handshake was already started.
    ClientHandshakeAlreadyStarted,
    /// Response bytes arrived before the request was emitted.
    ResponseBeforeClientRequest,
    /// The HTTP status line did not match its fixed grammar.
    MalformedStatusLine,
    /// The HTTP reason phrase contained a forbidden control or DEL octet.
    InvalidReasonPhraseOctet,
    /// The response used an HTTP version other than HTTP/1.1.
    HttpVersionNot11,
    /// The response status was not 101.
    StatusNotSwitchingProtocols {
        /// The parsed three-digit status.
        received: u16,
    },
    /// A CR or LF was not part of an exact CRLF pair.
    BareLineEnding,
    /// A header used obsolete line folding.
    ObsoleteLineFolding,
    /// A header line had no valid name/value separator.
    MalformedHeader,
    /// A field name contained a byte outside the HTTP token grammar.
    InvalidHeaderName,
    /// A field value contained a forbidden control or DEL octet.
    InvalidHeaderValueOctet,
    /// A field name appeared more than once, ignoring ASCII case.
    DuplicateHeader,
    /// The required Upgrade field was absent.
    MissingUpgrade,
    /// Upgrade did not contain the `websocket` token.
    InvalidUpgrade,
    /// The required Connection field was absent.
    MissingConnection,
    /// Connection did not contain the `upgrade` token.
    InvalidConnection,
    /// The required Sec-WebSocket-Accept field was absent.
    MissingAccept,
    /// Sec-WebSocket-Accept did not match the request nonce derivation.
    AcceptMismatch,
    /// An extension was returned even though none was offered.
    UnexpectedExtension,
    /// A subprotocol was returned even though none was offered.
    UnexpectedSubprotocol,
    /// EOF arrived before a complete response.
    UnexpectedEof,
    /// Bytes followed the completed HTTP response in the same input.
    TrailingData {
        /// Number of bytes after the terminal CRLF.
        bytes: u64,
    },
    /// The HTTP request line did not match its fixed grammar.
    MalformedRequestLine,
    /// The request method was not the exact uppercase `GET` token.
    MethodNotGet,
    /// The request target was not a valid origin-form target.
    InvalidRequestTarget,
    /// The required Host field was absent.
    MissingHost,
    /// The Host field was empty or contained a forbidden byte.
    InvalidHost,
    /// The required Sec-WebSocket-Key field was absent.
    MissingKey,
    /// Sec-WebSocket-Key was not canonical standard Base64 for 16 bytes.
    InvalidKeyEncoding,
    /// Sec-WebSocket-Key decoded to a nonce of the wrong length.
    InvalidKeyLength {
        /// Number of decoded bytes.
        decoded: u64,
    },
    /// The required Sec-WebSocket-Version field was absent.
    MissingVersion,
    /// Sec-WebSocket-Version was not the exact supported value `13`.
    UnsupportedVersion,
    /// A request body length was supplied where no body is accepted.
    UnexpectedContentLength,
    /// Transfer coding was supplied where no request body is accepted.
    UnexpectedTransferEncoding,
}

/// Stable frame-codec rejection vocabulary.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FrameFailure {
    /// At least one RSV bit was set without a negotiated extension.
    ReservedBits,
    /// The four-bit opcode is not assigned by RFC 6455.
    ReservedOpcode {
        /// Rejected four-bit opcode value.
        opcode: u8,
    },
    /// A control frame did not set FIN.
    FragmentedControl {
        /// Rejected control opcode.
        opcode: crate::frame::Opcode,
    },
    /// A control payload exceeded 125 bytes.
    ControlPayloadTooLarge {
        /// Declared payload length.
        length: u64,
    },
    /// A value below 126 used the 16-bit length form.
    NonCanonicalLength16 {
        /// Decoded noncanonical value.
        length: u64,
    },
    /// A value below 65,536 used the 64-bit length form.
    NonCanonicalLength64 {
        /// Decoded noncanonical value.
        length: u64,
    },
    /// The forbidden high bit of the 64-bit length was set.
    PayloadLengthHighBitSet,
    /// The inbound MASK bit did not match the endpoint role.
    IncorrectMasking {
        /// Required MASK-bit value for this endpoint role.
        expected_masked: bool,
        /// Received MASK-bit value.
        actual_masked: bool,
    },
    /// A payload length could not be represented by the platform.
    LengthDoesNotFitPlatform {
        /// Unrepresentable wire value.
        length: u64,
    },
    /// Checked frame-size arithmetic overflowed.
    ArithmeticOverflow,
    /// A bounded exact allocation request failed.
    AllocationFailed,
    /// EOF arrived during a partial frame header or payload.
    UnexpectedEof,
    /// Client-role encoding was attempted without an explicit key.
    MissingMaskKey,
    /// Server-role encoding was attempted with a mask key.
    UnexpectedMaskKey,
}

/// Stable UTF-8 rejection vocabulary.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Utf8Failure {
    /// A continuation byte appeared without an active scalar.
    UnexpectedContinuation {
        /// Absolute message byte offset.
        offset: u64,
        /// Rejected octet.
        byte: u8,
    },
    /// An octet cannot begin a canonical UTF-8 scalar.
    InvalidLeadingByte {
        /// Absolute message byte offset.
        offset: u64,
        /// Rejected octet.
        byte: u8,
    },
    /// A scalar expected a continuation octet in a different range.
    InvalidContinuation {
        /// Absolute message byte offset.
        offset: u64,
        /// Rejected octet.
        byte: u8,
    },
    /// A scalar used more bytes than its value requires.
    OverlongEncoding {
        /// Absolute offset where the scalar began.
        offset: u64,
    },
    /// A scalar encoded a UTF-16 surrogate code point.
    SurrogateCodePoint {
        /// Absolute offset where the scalar began.
        offset: u64,
    },
    /// A scalar exceeded Unicode's U+10FFFF ceiling.
    CodePointOutOfRange {
        /// Absolute offset where the scalar began.
        offset: u64,
    },
    /// The final payload ended within a multibyte scalar.
    TruncatedSequence {
        /// Total validated payload bytes.
        length: u64,
        /// Number of missing continuation bytes.
        remaining: u8,
    },
}

/// Reserved close failure vocabulary.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CloseFailure {}

/// Identifies a bounded queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueKind {
    /// The semantic-event queue.
    Event,
    /// The local-command queue.
    Command,
    /// The transport-write queue.
    Write,
}

/// Identifies an input category for invalid-state failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputKind {
    /// Transport bytes.
    TransportBytes,
    /// A local command.
    LocalCommand,
    /// Transport EOF.
    TransportEof,
}

/// A protocol failure category represented as data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FailureKind {
    /// The input belongs to a protocol story that has not landed.
    ProtocolSliceUnavailable {
        /// Story that must implement the behavior.
        owner_story: ProtocolStory,
    },
    /// Opening-handshake failure reserved for US-010 and US-011.
    Handshake(HandshakeFailure),
    /// Frame failure reserved for US-012.
    Frame(FrameFailure),
    /// UTF-8 failure reserved for US-013.
    Utf8(Utf8Failure),
    /// Close failure reserved for US-016.
    Close(CloseFailure),
    /// A runtime operation exceeded a configured limit.
    LimitExceeded {
        /// Limit that rejected the operation.
        limit: LimitKind,
        /// Requested amount.
        attempted: u64,
        /// Configured maximum.
        maximum: u64,
    },
    /// A bounded queue refused more work.
    Backpressure(QueueKind),
    /// The current lifecycle state forbids an input category.
    InvalidState {
        /// Rejected input category.
        input: InputKind,
        /// State in which it was rejected.
        state: ConnectionState,
    },
}

/// A typed protocol failure and its documented state effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedProtocolFailure {
    /// Failure category.
    pub kind: FailureKind,
    /// Core state after the failure is committed.
    pub state_after: ConnectionState,
}

/// Result of one [`ConnectionCore::step`] call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StepResult {
    outputs: Box<[CoreOutput]>,
    failure: Option<TypedProtocolFailure>,
    state: ConnectionState,
}

impl StepResult {
    /// Iterates outputs in exact occurrence order.
    pub fn outputs(&self) -> impl ExactSizeIterator<Item = &CoreOutput> {
        self.outputs.iter()
    }

    /// Returns the typed failure, if this input failed.
    #[must_use]
    pub const fn failure(&self) -> Option<&TypedProtocolFailure> {
        self.failure.as_ref()
    }

    /// Returns the state after this step.
    #[must_use]
    pub const fn state(&self) -> ConnectionState {
        self.state
    }
}

/// Deterministic, single-owner Sans-I/O connection core.
#[derive(Debug)]
pub struct ConnectionCore {
    config: ConnectionConfig,
    role: Role,
    state: ConnectionState,
    client_handshake: ClientHandshake,
    server_handshake: ServerHandshake,
    frame_decoder: FrameDecoder,
}

impl ConnectionCore {
    /// Creates a core in [`ConnectionState::Connecting`].
    #[must_use]
    pub const fn new(config: ConnectionConfig, role: Role) -> Self {
        let server_handshake = ServerHandshake::new(
            config.checked.handshake_bytes,
            config.checked.handshake_header_line_bytes,
            config.checked.handshake_header_count,
        );
        Self {
            config,
            role,
            state: ConnectionState::Connecting,
            client_handshake: ClientHandshake::new(),
            server_handshake,
            frame_decoder: FrameDecoder::new(),
        }
    }

    /// Admits one input through the only mutating core operation.
    ///
    /// Implemented protocol slices return ordered outputs; behavior owned by a
    /// later story returns a typed unavailable failure without side effects.
    pub fn step(&mut self, input: CoreInput<'_>) -> StepResult {
        if self.state == ConnectionState::Closed {
            let input = match input {
                CoreInput::Transport(_) => InputKind::TransportBytes,
                CoreInput::Command(_) => InputKind::LocalCommand,
                CoreInput::TransportEof => InputKind::TransportEof,
            };
            return StepResult {
                outputs: Box::new([]),
                failure: Some(TypedProtocolFailure {
                    kind: FailureKind::InvalidState {
                        input,
                        state: self.state,
                    },
                    state_after: self.state,
                }),
                state: self.state,
            };
        }
        if let CoreInput::Command(LocalCommand::StartClientHandshake { descriptor, nonce }) = input
        {
            if self.role != Role::Client {
                let failure = TypedProtocolFailure {
                    kind: FailureKind::Handshake(HandshakeFailure::WrongRole),
                    state_after: self.state,
                };
                return StepResult {
                    outputs: Box::new([]),
                    failure: Some(failure),
                    state: self.state,
                };
            }
            if self.client_handshake.has_started() {
                return StepResult {
                    outputs: Box::new([]),
                    failure: Some(TypedProtocolFailure {
                        kind: FailureKind::Handshake(
                            HandshakeFailure::ClientHandshakeAlreadyStarted,
                        ),
                        state_after: self.state,
                    }),
                    state: self.state,
                };
            }
            return match self.client_handshake.start(
                descriptor,
                nonce,
                self.config.checked.handshake_bytes,
                self.config.checked.handshake_header_line_bytes,
                self.config.checked.handshake_header_count,
            ) {
                Ok(bytes) => StepResult {
                    outputs: Box::new([CoreOutput::TransportWrite(TransportWrite { bytes })]),
                    failure: None,
                    state: self.state,
                },
                Err(ClientLimitExceeded { limit, attempted }) => StepResult {
                    outputs: Box::new([]),
                    failure: Some(TypedProtocolFailure {
                        kind: FailureKind::LimitExceeded {
                            limit,
                            attempted,
                            maximum: self.config.handshake_limit(limit),
                        },
                        state_after: self.state,
                    }),
                    state: self.state,
                },
            };
        }
        if let CoreInput::Transport(bytes) = input
            && self.role == Role::Client
            && self.client_handshake.awaiting_response()
        {
            match self.client_handshake.consume_response(bytes.as_slice()) {
                ClientResponse::Incomplete => {
                    return StepResult {
                        outputs: Box::new([]),
                        failure: None,
                        state: self.state,
                    };
                }
                ClientResponse::Opened(descriptor) => {
                    self.state = ConnectionState::Open;
                    debug_assert_eq!(self.state, ConnectionState::Open);
                    return StepResult {
                        outputs: Box::new([
                            CoreOutput::StateChanged(ConnectionState::Open),
                            CoreOutput::SemanticEvent(SemanticEvent::ClientHandshakeOpened {
                                descriptor,
                            }),
                        ]),
                        failure: None,
                        state: self.state,
                    };
                }
                ClientResponse::Rejected(failure) => {
                    self.client_handshake.mark_failed();
                    return self.close_with_failure(FailureKind::Handshake(failure));
                }
                ClientResponse::LimitExceeded { limit, attempted } => {
                    self.client_handshake.mark_failed();
                    return self.close_with_failure(FailureKind::LimitExceeded {
                        limit,
                        attempted,
                        maximum: self.config.handshake_limit(limit),
                    });
                }
                ClientResponse::NotAwaiting => {}
            }
        }
        if let CoreInput::Transport(bytes) = input
            && self.role == Role::Server
            && self.server_handshake.awaiting_request()
        {
            match self.server_handshake.consume_request(bytes.as_slice()) {
                ServerRequest::Incomplete => {
                    return StepResult {
                        outputs: Box::new([]),
                        failure: None,
                        state: self.state,
                    };
                }
                ServerRequest::Opened {
                    descriptor,
                    response,
                } => {
                    self.state = ConnectionState::Open;
                    debug_assert_eq!(self.state, ConnectionState::Open);
                    return StepResult {
                        outputs: Box::new([
                            CoreOutput::TransportWrite(TransportWrite { bytes: response }),
                            CoreOutput::StateChanged(ConnectionState::Open),
                            CoreOutput::SemanticEvent(SemanticEvent::ServerHandshakeOpened {
                                descriptor,
                            }),
                        ]),
                        failure: None,
                        state: self.state,
                    };
                }
                ServerRequest::Rejected(failure) => {
                    self.server_handshake.mark_failed();
                    return self.close_with_failure(FailureKind::Handshake(failure));
                }
                ServerRequest::LimitExceeded { limit, attempted } => {
                    self.server_handshake.mark_failed();
                    return self.close_with_failure(FailureKind::LimitExceeded {
                        limit,
                        attempted,
                        maximum: self.config.handshake_limit(limit),
                    });
                }
                ServerRequest::NotAwaiting => {}
            }
        }
        if let CoreInput::Transport(bytes) = input
            && self.state == ConnectionState::Open
        {
            return self.consume_frames(bytes.as_slice());
        }
        if let CoreInput::TransportEof = input
            && self.state == ConnectionState::Open
            && self.frame_decoder.is_partial()
        {
            return self.close_with_failure(FailureKind::Frame(FrameFailure::UnexpectedEof));
        }
        if let CoreInput::Transport(_) = input
            && self.role == Role::Client
            && !self.client_handshake.has_started()
        {
            return StepResult {
                outputs: Box::new([]),
                failure: Some(TypedProtocolFailure {
                    kind: FailureKind::Handshake(HandshakeFailure::ResponseBeforeClientRequest),
                    state_after: self.state,
                }),
                state: self.state,
            };
        }
        if let CoreInput::TransportEof = input
            && self.role == Role::Client
            && self.client_handshake.awaiting_response()
        {
            self.client_handshake.mark_failed();
            return self
                .close_with_failure(FailureKind::Handshake(HandshakeFailure::UnexpectedEof));
        }
        if let CoreInput::TransportEof = input
            && self.role == Role::Server
            && self.server_handshake.awaiting_request()
        {
            self.server_handshake.mark_failed();
            return self
                .close_with_failure(FailureKind::Handshake(HandshakeFailure::UnexpectedEof));
        }
        let owner_story = match input {
            CoreInput::Transport(_) => match (self.role, self.state) {
                (Role::Client, ConnectionState::Open) => ProtocolStory::FrameCoding,
                (Role::Client, _) => ProtocolStory::ClientOpeningHandshake,
                (Role::Server, ConnectionState::Open) => ProtocolStory::FrameCoding,
                (Role::Server, _) => ProtocolStory::ServerOpeningHandshake,
            },
            CoreInput::Command(LocalCommand::StartClientHandshake { .. }) => {
                ProtocolStory::ClientOpeningHandshake
            }
            CoreInput::Command(LocalCommand::SendText(_) | LocalCommand::SendBinary(_)) => {
                ProtocolStory::Messages
            }
            CoreInput::Command(LocalCommand::SendPing(_) | LocalCommand::SendPong(_)) => {
                ProtocolStory::ControlFrames
            }
            CoreInput::Command(LocalCommand::Close { .. }) | CoreInput::TransportEof => {
                ProtocolStory::CloseAndEof
            }
        };
        let failure = TypedProtocolFailure {
            kind: FailureKind::ProtocolSliceUnavailable { owner_story },
            state_after: self.state,
        };
        StepResult {
            outputs: Box::new([]),
            failure: Some(failure),
            state: self.state,
        }
    }

    /// Returns the current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> ConnectionState {
        self.state
    }

    /// Returns this endpoint's fixed role.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Returns this core's immutable checked configuration.
    #[must_use]
    pub const fn config(&self) -> &ConnectionConfig {
        &self.config
    }

    fn close_with_failure(&mut self, kind: FailureKind) -> StepResult {
        self.frame_decoder.reset();
        self.state = ConnectionState::Closed;
        StepResult {
            outputs: Box::new([CoreOutput::StateChanged(ConnectionState::Closed)]),
            failure: Some(TypedProtocolFailure {
                kind,
                state_after: self.state,
            }),
            state: self.state,
        }
    }

    fn consume_frames(&mut self, bytes: &[u8]) -> StepResult {
        let batch = self.frame_decoder.consume(&self.config, self.role, bytes);
        let extra = usize::from(batch.failure.is_some());
        let Some(output_capacity) = batch
            .records
            .iter()
            .map(|record| 1 + usize::from(record.delivery.is_some()))
            .try_fold(extra, usize::checked_add)
        else {
            return self.close_with_failure(FailureKind::Frame(FrameFailure::ArithmeticOverflow));
        };
        let mut outputs = Vec::new();
        if outputs.try_reserve_exact(output_capacity).is_err() {
            return self.close_with_failure(FailureKind::Frame(FrameFailure::AllocationFailed));
        }
        for record in batch.records {
            let delivery = record
                .delivery
                .map(|delivery| delivery.deliver(&record.frame));
            outputs.push(CoreOutput::SemanticEvent(SemanticEvent::FrameReceived {
                frame: record.frame,
            }));
            match delivery {
                Some(MessageDelivery::Text(message)) => {
                    outputs.push(CoreOutput::SemanticEvent(SemanticEvent::Text { message }));
                }
                Some(MessageDelivery::Binary(message)) => {
                    outputs.push(CoreOutput::SemanticEvent(SemanticEvent::Binary { message }));
                }
                None => {}
            }
        }
        if let Some(kind) = batch.failure {
            self.state = ConnectionState::Closed;
            outputs.push(CoreOutput::StateChanged(ConnectionState::Closed));
            return StepResult {
                outputs: outputs.into_boxed_slice(),
                failure: Some(TypedProtocolFailure {
                    kind,
                    state_after: self.state,
                }),
                state: self.state,
            };
        }
        StepResult {
            outputs: outputs.into_boxed_slice(),
            failure: None,
            state: self.state,
        }
    }
}
