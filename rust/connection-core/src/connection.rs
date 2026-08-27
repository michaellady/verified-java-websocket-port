use core::fmt;

use crate::close::{CloseMachine, encode_peer_echo, parse_peer_close, prepare_local_close};
use crate::control::{
    AutomaticPongPolicy, ControlPayload, encode_automatic_pong, encode_local_control,
    is_observed_control, plan_batch, should_automatically_pong,
};
use crate::fragment::{FragmentKind, OutboundFragmentState};
use crate::frame::decode::{DecodedFrame, FrameDecoder};
use crate::frame::{Frame, FrameEncoder, Opcode, OutboundFrame};
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
    automatic_pong_policy: AutomaticPongPolicy,
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

    pub(crate) const fn write_queue_entries(&self) -> usize {
        self.checked.write_queue_entries
    }

    /// Returns a copy configured with the requested automatic Pong policy.
    #[must_use]
    pub const fn with_automatic_pong_policy(mut self, policy: AutomaticPongPolicy) -> Self {
        self.automatic_pong_policy = policy;
        self
    }

    /// Returns the checked automatic Pong policy.
    #[must_use]
    pub const fn automatic_pong_policy(&self) -> AutomaticPongPolicy {
        self.automatic_pong_policy
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
            automatic_pong_policy: AutomaticPongPolicy::Disabled,
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
    /// Requests one final text message frame.
    SendText {
        /// Strictly valid UTF-8 text payload.
        payload: Box<str>,
        /// One caller-supplied client mask key; forbidden for servers.
        mask_key: Option<[u8; 4]>,
    },
    /// Requests one final binary message frame.
    SendBinary {
        /// Immutable uninterpreted binary payload.
        payload: Box<[u8]>,
        /// One caller-supplied client mask key; forbidden for servers.
        mask_key: Option<[u8; 4]>,
    },
    /// Requests one frame in an outbound fragmented data-message sequence.
    SendFragment {
        /// Text or binary kind for the complete fragmented message.
        kind: FragmentKind,
        /// Whether this frame terminates the fragmented message.
        final_fragment: bool,
        /// Exact payload bytes for this fragment.
        payload: Box<[u8]>,
        /// One caller-supplied client mask key; forbidden for servers.
        mask_key: Option<[u8; 4]>,
    },
    /// Requests a ping control frame.
    SendPing {
        /// Exact control payload, limited to 125 bytes.
        payload: Box<[u8]>,
        /// One caller-supplied client mask key; forbidden for servers.
        mask_key: Option<[u8; 4]>,
    },
    /// Requests a pong control frame.
    SendPong {
        /// Exact control payload, limited to 125 bytes.
        payload: Box<[u8]>,
        /// One caller-supplied client mask key; forbidden for servers.
        mask_key: Option<[u8; 4]>,
    },
    /// Requests the closing handshake.
    Close {
        /// Optional WebSocket close code; `None` encodes an empty payload.
        code: Option<u16>,
        /// Human-readable close reason.
        reason: Box<str>,
        /// One caller-supplied client mask key; forbidden for servers.
        mask_key: Option<[u8; 4]>,
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
    /// Confirms that every previously emitted transport write has drained.
    TransportWriteFlushed,
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
    /// One validated Ping control frame was received.
    Ping {
        /// Shared immutable decoded control bytes.
        payload: ControlPayload,
    },
    /// One validated Pong control frame was received.
    Pong {
        /// Shared immutable decoded control bytes.
        payload: ControlPayload,
    },
    /// One validated Close control frame was received.
    CloseReceived {
        /// Shared immutable code and reason observation.
        close: crate::close::CloseFrame,
        /// Which side initiated this core's closing sequence.
        initiator: crate::close::CloseInitiator,
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

/// Stable fragmented-message sequence and EOF rejection vocabulary.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FragmentFailure {
    /// A continuation arrived without an active Text or Binary message.
    ContinuationWithoutMessage,
    /// A new data frame arrived before the active fragmented message finished.
    DataFrameWhileFragmented {
        /// The opcode that began the active fragmented message.
        active: crate::frame::Opcode,
        /// The Text or Binary opcode received while it was active.
        received: crate::frame::Opcode,
    },
    /// EOF arrived between frames before a fragmented message completed.
    UnexpectedEof {
        /// The opcode that began the active fragmented message.
        active: crate::frame::Opcode,
        /// Number of message bytes retained before EOF.
        accumulated: u64,
    },
}

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
    /// Fragmented-message failure implemented by US-014.
    Fragment(FragmentFailure),
    /// Close failure reserved for US-016.
    Close(crate::close::CloseFailure),
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

/// Read-only accounting captured at the sole core step seam.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StepAccounting {
    /// Lifecycle state before the step.
    pub pre_state: ConnectionState,
    /// Lifecycle state after the step.
    pub post_state: ConnectionState,
    /// Exact bytes consumed from this step's borrowed transport input.
    pub bytes_consumed: usize,
    /// Bytes retained by the incremental frame decoder after the step.
    pub wire_buffered_bytes: usize,
    /// Bytes retained for an incomplete fragmented message after the step.
    pub message_buffered_bytes: usize,
}

/// Immutable observation of the most recently completed core step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreStepObservation {
    accounting: StepAccounting,
    frames: Vec<FrameObservation>,
}

impl CoreStepObservation {
    const fn initial() -> Self {
        Self {
            accounting: StepAccounting {
                pre_state: ConnectionState::Connecting,
                post_state: ConnectionState::Connecting,
                bytes_consumed: 0,
                wire_buffered_bytes: 0,
                message_buffered_bytes: 0,
            },
            frames: Vec::new(),
        }
    }

    /// Returns the exact counters and lifecycle states for the step.
    #[must_use]
    pub const fn accounting(&self) -> &StepAccounting {
        &self.accounting
    }

    /// Iterates exact inbound and outbound frame observations in occurrence order.
    pub fn frames(&self) -> impl ExactSizeIterator<Item = &FrameObservation> {
        self.frames.iter()
    }
}

/// Direction of one frame observed at an incumbent decoder or encoder seam.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameDirection {
    /// A validated frame decoded from transport input.
    Inbound,
    /// A frame encoded for transport output.
    Outbound,
}

/// Read-only frame description captured without reparsing transport bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrameObservation {
    direction: FrameDirection,
    fin: bool,
    opcode: Opcode,
    masked: bool,
    payload: Box<[u8]>,
    wire_length: usize,
}

impl FrameObservation {
    /// Returns the direction at the core seam.
    #[must_use]
    pub const fn direction(&self) -> FrameDirection {
        self.direction
    }

    /// Returns the exact FIN bit.
    #[must_use]
    pub const fn fin(&self) -> bool {
        self.fin
    }

    /// Returns the exact validated opcode.
    #[must_use]
    pub const fn opcode(&self) -> Opcode {
        self.opcode
    }

    /// Returns whether the wire frame carries a mask.
    #[must_use]
    pub const fn masked(&self) -> bool {
        self.masked
    }

    /// Returns the unmasked payload.
    #[must_use]
    pub const fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns the exact encoded wire length.
    #[must_use]
    pub const fn wire_length(&self) -> usize {
        self.wire_length
    }
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
    outbound_fragments: OutboundFragmentState,
    close: CloseMachine,
    last_step_observation: CoreStepObservation,
    last_decoder_consumed: usize,
    step_frames: Vec<FrameObservation>,
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
            outbound_fragments: OutboundFragmentState::new(),
            close: CloseMachine::new(),
            last_step_observation: CoreStepObservation::initial(),
            last_decoder_consumed: 0,
            step_frames: Vec::new(),
        }
    }

    /// Admits one input through the only mutating core operation.
    ///
    /// Implemented protocol slices return ordered outputs; behavior owned by a
    /// later story returns a typed unavailable failure without side effects.
    pub fn step(&mut self, input: CoreInput<'_>) -> StepResult {
        let pre_state = self.state;
        let offered_bytes = match &input {
            CoreInput::Transport(bytes) => Some(bytes.as_slice().len()),
            _ => None,
        };
        let decoder_path = offered_bytes.is_some()
            && matches!(pre_state, ConnectionState::Open | ConnectionState::Closing);
        self.last_decoder_consumed = 0;
        self.step_frames.clear();
        let result = self.step_protocol(input);
        let bytes_consumed = offered_bytes.map_or(0, |offered| {
            if decoder_path {
                self.last_decoder_consumed
            } else {
                offered
            }
        });
        self.last_step_observation = CoreStepObservation {
            accounting: StepAccounting {
                pre_state,
                post_state: result.state(),
                bytes_consumed,
                wire_buffered_bytes: self.frame_decoder.retained_wire_bytes(),
                message_buffered_bytes: self.frame_decoder.retained_message_bytes(),
            },
            frames: core::mem::take(&mut self.step_frames),
        };
        result
    }

    fn step_protocol(&mut self, input: CoreInput<'_>) -> StepResult {
        if self.state == ConnectionState::Closed {
            if matches!(
                input,
                CoreInput::TransportEof | CoreInput::TransportWriteFlushed
            ) {
                return StepResult {
                    outputs: Box::new([]),
                    failure: None,
                    state: self.state,
                };
            }
            let input = match input {
                CoreInput::Transport(_) => InputKind::TransportBytes,
                CoreInput::Command(_) => InputKind::LocalCommand,
                CoreInput::TransportEof => InputKind::TransportEof,
                CoreInput::TransportWriteFlushed => unreachable!("handled above"),
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
        if let CoreInput::TransportWriteFlushed = input {
            if self.state == ConnectionState::Closing && self.close.write_pending() {
                self.close.mark_write_flushed();
                if self.close.is_complete() {
                    return self.finish_clean(Vec::new());
                }
            }
            return StepResult {
                outputs: Box::new([]),
                failure: None,
                state: self.state,
            };
        }
        if let CoreInput::Command(LocalCommand::Close {
            code,
            reason,
            mask_key,
        }) = input
        {
            return self.local_close(code, &reason, mask_key);
        }
        if self.state == ConnectionState::Closing && matches!(input, CoreInput::Command(_)) {
            return self.invalid_state(InputKind::LocalCommand);
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
        if let CoreInput::Command(
            command @ (LocalCommand::SendPing { .. } | LocalCommand::SendPong { .. }),
        ) = input
        {
            if self.state != ConnectionState::Open {
                return StepResult {
                    outputs: Box::new([]),
                    failure: Some(TypedProtocolFailure {
                        kind: FailureKind::InvalidState {
                            input: InputKind::LocalCommand,
                            state: self.state,
                        },
                        state_after: self.state,
                    }),
                    state: self.state,
                };
            }
            let (opcode, payload, mask_key) = match command {
                LocalCommand::SendPing { payload, mask_key } => (Opcode::Ping, payload, mask_key),
                LocalCommand::SendPong { payload, mask_key } => (Opcode::Pong, payload, mask_key),
                _ => unreachable!("command pattern was restricted to Ping/Pong"),
            };
            return match encode_local_control(&self.config, self.role, opcode, &payload, mask_key) {
                Ok(bytes) => StepResult {
                    outputs: {
                        self.record_outbound_frame(
                            true,
                            opcode,
                            &payload,
                            mask_key.is_some(),
                            bytes.len(),
                        );
                        Box::new([CoreOutput::TransportWrite(TransportWrite { bytes })])
                    },
                    failure: None,
                    state: self.state,
                },
                Err(kind) => StepResult {
                    outputs: Box::new([]),
                    failure: Some(TypedProtocolFailure {
                        kind,
                        state_after: self.state,
                    }),
                    state: self.state,
                },
            };
        }
        if let CoreInput::Command(
            command @ (LocalCommand::SendText { .. } | LocalCommand::SendBinary { .. }),
        ) = input
        {
            if self.state != ConnectionState::Open {
                return self.invalid_state(InputKind::LocalCommand);
            }
            let (opcode, payload, mask_key) = match &command {
                LocalCommand::SendText { payload, mask_key } => {
                    (Opcode::Text, payload.as_bytes(), *mask_key)
                }
                LocalCommand::SendBinary { payload, mask_key } => {
                    (Opcode::Binary, payload.as_ref(), *mask_key)
                }
                _ => unreachable!("command pattern was restricted to Text/Binary"),
            };
            if let Some(active) = self.outbound_fragments.active_opcode() {
                return self.nonterminal_failure(FailureKind::Fragment(
                    FragmentFailure::DataFrameWhileFragmented {
                        active,
                        received: opcode,
                    },
                ));
            }
            let attempted = u64::try_from(payload.len()).unwrap_or(u64::MAX);
            if payload.len() > self.config.message_bytes() {
                return self.nonterminal_failure(FailureKind::LimitExceeded {
                    limit: LimitKind::MessageBytes,
                    attempted,
                    maximum: self.config.limits.message_bytes,
                });
            }
            return match FrameEncoder::new(self.config.clone(), self.role)
                .encode(OutboundFrame::new(true, opcode, payload), mask_key)
            {
                Ok(encoded) => StepResult {
                    outputs: {
                        let wire_length = encoded.as_slice().len();
                        self.record_outbound_frame(
                            true,
                            opcode,
                            payload,
                            mask_key.is_some(),
                            wire_length,
                        );
                        Box::new([CoreOutput::TransportWrite(TransportWrite {
                            bytes: encoded.into_bytes(),
                        })])
                    },
                    failure: None,
                    state: self.state,
                },
                Err(kind) => self.nonterminal_failure(kind),
            };
        }
        if let CoreInput::Command(LocalCommand::SendFragment {
            kind,
            final_fragment,
            payload,
            mask_key,
        }) = input
        {
            if self.state != ConnectionState::Open {
                return self.invalid_state(InputKind::LocalCommand);
            }
            let plan = match self.outbound_fragments.plan(
                &self.config,
                kind,
                final_fragment,
                payload.len(),
            ) {
                Ok(plan) => plan,
                Err(kind) => return self.nonterminal_failure(kind),
            };
            return match FrameEncoder::new(self.config.clone(), self.role).encode(
                OutboundFrame::new(final_fragment, plan.opcode, &payload),
                mask_key,
            ) {
                Ok(encoded) => {
                    let wire_length = encoded.as_slice().len();
                    self.record_outbound_frame(
                        final_fragment,
                        plan.opcode,
                        &payload,
                        mask_key.is_some(),
                        wire_length,
                    );
                    self.outbound_fragments.commit(plan);
                    StepResult {
                        outputs: Box::new([CoreOutput::TransportWrite(TransportWrite {
                            bytes: encoded.into_bytes(),
                        })]),
                        failure: None,
                        state: self.state,
                    }
                }
                Err(kind) => self.nonterminal_failure(kind),
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
            && matches!(self.state, ConnectionState::Open | ConnectionState::Closing)
        {
            return self.consume_frames(bytes.as_slice());
        }
        if let CoreInput::TransportEof = input
            && self.state == ConnectionState::Open
            && self.frame_decoder.is_partial()
        {
            return self.close_with_failure(FailureKind::Frame(FrameFailure::UnexpectedEof));
        }
        if let CoreInput::TransportEof = input
            && self.state == ConnectionState::Open
            && let Some(failure) = self.frame_decoder.fragment_eof_failure()
        {
            return self.close_with_failure(FailureKind::Fragment(failure));
        }
        if let CoreInput::TransportEof = input
            && self.state == ConnectionState::Open
        {
            return self.close_with_failure(FailureKind::Close(
                crate::close::CloseFailure::UnexpectedEofOpen,
            ));
        }
        if let CoreInput::TransportEof = input
            && self.state == ConnectionState::Closing
        {
            return self.close_with_failure(FailureKind::Close(self.close.eof_failure()));
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
        if let CoreInput::TransportEof = input
            && self.state == ConnectionState::Connecting
        {
            self.client_handshake.mark_failed();
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
            CoreInput::Command(
                LocalCommand::SendText { .. }
                | LocalCommand::SendBinary { .. }
                | LocalCommand::SendFragment { .. },
            ) => ProtocolStory::Messages,
            CoreInput::Command(LocalCommand::SendPing { .. } | LocalCommand::SendPong { .. }) => {
                ProtocolStory::ControlFrames
            }
            CoreInput::Command(LocalCommand::Close { .. }) | CoreInput::TransportEof => {
                ProtocolStory::CloseAndEof
            }
            CoreInput::TransportWriteFlushed => ProtocolStory::CloseAndEof,
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

    /// Returns the immutable observation captured by the most recent step.
    #[must_use]
    pub const fn last_step_observation(&self) -> &CoreStepObservation {
        &self.last_step_observation
    }

    fn close_with_failure(&mut self, kind: FailureKind) -> StepResult {
        self.frame_decoder.reset();
        self.outbound_fragments.reset();
        self.close.reset();
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
        let closing = self.state == ConnectionState::Closing;
        let retained_close_bytes = if closing {
            self.close.retained_bytes()
        } else {
            0
        };
        let mut batch = self.frame_decoder.consume(
            &self.config,
            self.role,
            bytes,
            retained_close_bytes,
            closing,
        );
        self.last_decoder_consumed = batch.consumed_bytes;
        if self.state == ConnectionState::Closing
            || batch
                .records
                .iter()
                .any(|record| record.frame.opcode() == Opcode::Close)
        {
            let decoder_partial = self.frame_decoder.is_partial();
            return self.consume_close_aware(batch.records, batch.failure.take(), decoder_partial);
        }
        let plan = plan_batch(&self.config, self.role, &batch.records);
        let terminal_failure = plan.failure.or(batch.failure.take());
        if terminal_failure.is_some() {
            batch.records.truncate(plan.accepted_records);
            self.frame_decoder.reset();
        }
        let output_capacity = match plan
            .output_capacity
            .checked_add(usize::from(terminal_failure.is_some()))
        {
            Some(capacity) => capacity,
            None => {
                return self
                    .close_with_failure(FailureKind::Frame(FrameFailure::ArithmeticOverflow));
            }
        };
        let mut outputs = Vec::new();
        if outputs.try_reserve_exact(output_capacity).is_err() {
            return self.close_with_failure(FailureKind::Frame(FrameFailure::AllocationFailed));
        }
        for record in batch.records {
            self.record_inbound_frame(&record);
            let automatic =
                should_automatically_pong(&self.config, self.role, record.frame.opcode());
            let encoded_pong = if automatic {
                match encode_automatic_pong(&self.config, record.frame.payload()) {
                    Ok(bytes) => Some(bytes),
                    Err(kind) => return self.close_after_prefix(outputs, kind),
                }
            } else {
                None
            };
            let control_payload = is_observed_control(&record.frame)
                .then(|| ControlPayload::from_frame(&record.frame));
            let control_opcode = record.frame.opcode();
            let delivery = record
                .delivery
                .map(|delivery| delivery.deliver(&record.frame));
            outputs.push(CoreOutput::SemanticEvent(SemanticEvent::FrameReceived {
                frame: record.frame,
            }));
            match (control_opcode, control_payload) {
                (Opcode::Ping, Some(payload)) => {
                    outputs.push(CoreOutput::SemanticEvent(SemanticEvent::Ping { payload }));
                }
                (Opcode::Pong, Some(payload)) => {
                    outputs.push(CoreOutput::SemanticEvent(SemanticEvent::Pong { payload }));
                }
                _ => {}
            }
            match delivery {
                Some(MessageDelivery::Text(message)) => {
                    outputs.push(CoreOutput::SemanticEvent(SemanticEvent::Text { message }));
                }
                Some(MessageDelivery::Binary(message)) => {
                    outputs.push(CoreOutput::SemanticEvent(SemanticEvent::Binary { message }));
                }
                None => {}
            }
            if let Some(bytes) = encoded_pong {
                outputs.push(CoreOutput::TransportWrite(TransportWrite { bytes }));
            }
        }
        if let Some(kind) = terminal_failure {
            return self.close_after_prefix(outputs, kind);
        }
        StepResult {
            outputs: outputs.into_boxed_slice(),
            failure: None,
            state: self.state,
        }
    }

    fn consume_close_aware(
        &mut self,
        records: Vec<DecodedFrame>,
        decoder_failure: Option<FailureKind>,
        decoder_partial: bool,
    ) -> StepResult {
        let started_open = self.state == ConnectionState::Open;
        let mut prefix_end = records.len();
        let mut close_index = None;
        let mut terminal_failure = None;

        for (index, record) in records.iter().enumerate() {
            match (self.state, record.frame.opcode()) {
                (_, Opcode::Close) => {
                    prefix_end = index;
                    close_index = Some(index);
                    break;
                }
                (
                    ConnectionState::Closing,
                    opcode @ (Opcode::Text | Opcode::Binary | Opcode::Continuation),
                ) => {
                    prefix_end = index;
                    terminal_failure = Some(FailureKind::Close(
                        crate::close::CloseFailure::DataAfterClose { opcode },
                    ));
                    break;
                }
                _ => {}
            }
        }

        let planned_prefix_outputs = if started_open {
            let plan = plan_batch(&self.config, self.role, &records[..prefix_end]);
            if let Some(failure) = plan.failure {
                prefix_end = plan.accepted_records;
                close_index = None;
                terminal_failure = Some(failure);
            }
            plan.output_capacity
        } else {
            match records[..prefix_end]
                .iter()
                .try_fold(0usize, |total, record| {
                    let group = 1usize
                        .checked_add(usize::from(is_observed_control(&record.frame)))
                        .and_then(|value| {
                            value.checked_add(usize::from(record.delivery.is_some()))
                        })?;
                    total.checked_add(group)
                }) {
                Some(value) => value,
                None => {
                    prefix_end = 0;
                    close_index = None;
                    terminal_failure = Some(FailureKind::Frame(FrameFailure::ArithmeticOverflow));
                    0
                }
            }
        };

        let mut parsed_close = None;
        let mut echo_wire = None;
        if let Some(index) = close_index {
            if self.state == ConnectionState::Closing && self.close.has_peer() {
                terminal_failure = Some(FailureKind::Close(
                    crate::close::CloseFailure::DuplicatePeerClose,
                ));
                close_index = None;
            } else {
                match parse_peer_close(&records[index].frame, self.role) {
                    Ok(close) => parsed_close = Some(close),
                    Err(failure) => {
                        terminal_failure = Some(failure);
                        close_index = None;
                    }
                }
            }
        }

        if let Some(index) = close_index
            && started_open
            && self.role == Role::Server
        {
            let automatic_writes = records[..prefix_end]
                .iter()
                .filter(|record| {
                    should_automatically_pong(&self.config, self.role, record.frame.opcode())
                })
                .count();
            let write_entries = automatic_writes.checked_add(1);
            if write_entries.is_none_or(|count| count > self.config.write_queue_entries()) {
                terminal_failure = Some(FailureKind::Backpressure(QueueKind::Write));
                close_index = None;
                parsed_close = None;
            } else {
                match encode_peer_echo(&self.config, records[index].frame.payload()) {
                    Ok(wire) => {
                        let generated_prefix = records[..prefix_end]
                            .iter()
                            .filter(|record| {
                                should_automatically_pong(
                                    &self.config,
                                    self.role,
                                    record.frame.opcode(),
                                )
                            })
                            .try_fold(0usize, |total, record| {
                                total.checked_add(2usize.checked_add(record.frame.payload().len())?)
                            });
                        let retained = generated_prefix
                            .and_then(|bytes| bytes.checked_add(wire.len()))
                            .and_then(|bytes| {
                                bytes.checked_add(records[index].retained_payload_bytes)
                            });
                        if retained.is_none_or(|bytes| bytes > self.config.total_buffered_bytes()) {
                            terminal_failure = Some(FailureKind::LimitExceeded {
                                limit: LimitKind::TotalBufferedBytes,
                                attempted: retained
                                    .and_then(|bytes| u64::try_from(bytes).ok())
                                    .unwrap_or(u64::MAX),
                                maximum: self.config.limits().total_buffered_bytes,
                            });
                            close_index = None;
                            parsed_close = None;
                        } else {
                            echo_wire = Some(wire);
                        }
                    }
                    Err(failure) => {
                        terminal_failure = Some(failure);
                        close_index = None;
                        parsed_close = None;
                    }
                }
            }
        }

        if let Some(index) = close_index {
            let trailing_record = records.get(index + 1);
            if let Some(record) = trailing_record {
                terminal_failure = Some(FailureKind::Close(match record.frame.opcode() {
                    opcode @ (Opcode::Text | Opcode::Binary | Opcode::Continuation) => {
                        crate::close::CloseFailure::DataAfterClose { opcode }
                    }
                    _ => crate::close::CloseFailure::TrailingBytesAfterClose,
                }));
            } else if let Some(failure) = decoder_failure.as_ref() {
                terminal_failure = Some(match failure {
                    FailureKind::Fragment(FragmentFailure::DataFrameWhileFragmented {
                        received,
                        ..
                    }) => FailureKind::Close(crate::close::CloseFailure::DataAfterClose {
                        opcode: *received,
                    }),
                    FailureKind::Fragment(FragmentFailure::ContinuationWithoutMessage) => {
                        FailureKind::Close(crate::close::CloseFailure::DataAfterClose {
                            opcode: Opcode::Continuation,
                        })
                    }
                    _ => FailureKind::Close(crate::close::CloseFailure::TrailingBytesAfterClose),
                });
            } else if decoder_partial {
                terminal_failure = Some(FailureKind::Close(
                    crate::close::CloseFailure::TrailingBytesAfterClose,
                ));
            }
        } else if terminal_failure.is_none() {
            terminal_failure = decoder_failure.map(|failure| {
                if self.state == ConnectionState::Closing {
                    match failure {
                        FailureKind::Fragment(FragmentFailure::ContinuationWithoutMessage) => {
                            FailureKind::Close(crate::close::CloseFailure::DataAfterClose {
                                opcode: Opcode::Continuation,
                            })
                        }
                        other => other,
                    }
                } else {
                    failure
                }
            });
        }

        let clean_terminal = close_index.is_some()
            && !started_open
            && !self.close.write_pending()
            && terminal_failure.is_none();
        let close_outputs = usize::from(close_index.is_some())
            .checked_mul(2)
            .and_then(|value| value.checked_add(usize::from(close_index.is_some() && started_open)))
            .and_then(|value| value.checked_add(usize::from(echo_wire.is_some())))
            .and_then(|value| value.checked_add(usize::from(clean_terminal)));
        let Some(total_capacity) = close_outputs
            .and_then(|value| planned_prefix_outputs.checked_add(value))
            .and_then(|value| value.checked_add(usize::from(terminal_failure.is_some())))
        else {
            return self.close_with_failure(FailureKind::Frame(FrameFailure::ArithmeticOverflow));
        };
        let mut outputs = Vec::new();
        if outputs.try_reserve_exact(total_capacity).is_err() {
            return self.close_with_failure(FailureKind::Frame(FrameFailure::AllocationFailed));
        }

        let mut iterator = records.into_iter();
        for _ in 0..prefix_end {
            let record = iterator.next().expect("planned prefix record");
            let automatic = started_open
                && should_automatically_pong(&self.config, self.role, record.frame.opcode());
            if let Err(failure) = self.append_record_outputs(&mut outputs, record, automatic) {
                return self.close_after_prefix(outputs, failure);
            }
        }

        if close_index.is_some() {
            let record = iterator.next().expect("planned close record");
            self.record_inbound_frame(&record);
            let close_payload = record.frame.payload().to_vec();
            let close = parsed_close.expect("validated close record");
            let initiator = if started_open {
                crate::close::CloseInitiator::Peer
            } else {
                self.close
                    .initiator()
                    .expect("Closing always records an initiator")
            };
            outputs.push(CoreOutput::SemanticEvent(SemanticEvent::FrameReceived {
                frame: record.frame,
            }));
            outputs.push(CoreOutput::SemanticEvent(SemanticEvent::CloseReceived {
                close: close.clone(),
                initiator,
            }));

            self.frame_decoder.reset();
            self.outbound_fragments.reset();
            if started_open {
                self.close.begin_peer(close);
                self.state = ConnectionState::Closing;
                outputs.push(CoreOutput::StateChanged(ConnectionState::Closing));
                if let Some(wire) = echo_wire {
                    self.record_outbound_frame(
                        true,
                        Opcode::Close,
                        &close_payload,
                        false,
                        wire.len(),
                    );
                    self.close.admit_peer_echo();
                    outputs.push(CoreOutput::TransportWrite(TransportWrite { bytes: wire }));
                }
            } else {
                self.close.accept_peer(close);
            }

            if let Some(failure) = terminal_failure {
                return self.close_after_prefix(outputs, failure);
            }
            if self.close.is_complete() {
                return self.finish_clean(outputs);
            }
            return StepResult {
                outputs: outputs.into_boxed_slice(),
                failure: None,
                state: self.state,
            };
        }

        debug_assert!(outputs.len() <= total_capacity);
        if let Some(failure) = terminal_failure {
            return self.close_after_prefix(outputs, failure);
        }
        StepResult {
            outputs: outputs.into_boxed_slice(),
            failure: None,
            state: self.state,
        }
    }

    fn append_record_outputs(
        &mut self,
        outputs: &mut Vec<CoreOutput>,
        record: DecodedFrame,
        automatic_pong: bool,
    ) -> Result<(), FailureKind> {
        self.record_inbound_frame(&record);
        let encoded_pong = if automatic_pong {
            Some(encode_automatic_pong(&self.config, record.frame.payload())?)
        } else {
            None
        };
        let control_payload =
            is_observed_control(&record.frame).then(|| ControlPayload::from_frame(&record.frame));
        let opcode = record.frame.opcode();
        let delivery = record
            .delivery
            .map(|delivery| delivery.deliver(&record.frame));
        outputs.push(CoreOutput::SemanticEvent(SemanticEvent::FrameReceived {
            frame: record.frame,
        }));
        match (opcode, control_payload) {
            (Opcode::Ping, Some(payload)) => {
                outputs.push(CoreOutput::SemanticEvent(SemanticEvent::Ping { payload }));
            }
            (Opcode::Pong, Some(payload)) => {
                outputs.push(CoreOutput::SemanticEvent(SemanticEvent::Pong { payload }));
            }
            _ => {}
        }
        match delivery {
            Some(MessageDelivery::Text(message)) => {
                outputs.push(CoreOutput::SemanticEvent(SemanticEvent::Text { message }));
            }
            Some(MessageDelivery::Binary(message)) => {
                outputs.push(CoreOutput::SemanticEvent(SemanticEvent::Binary { message }));
            }
            None => {}
        }
        if let Some(bytes) = encoded_pong {
            outputs.push(CoreOutput::TransportWrite(TransportWrite { bytes }));
        }
        Ok(())
    }

    fn close_after_prefix(
        &mut self,
        mut outputs: Vec<CoreOutput>,
        kind: FailureKind,
    ) -> StepResult {
        self.frame_decoder.reset();
        self.outbound_fragments.reset();
        self.close.reset();
        self.state = ConnectionState::Closed;
        outputs.push(CoreOutput::StateChanged(ConnectionState::Closed));
        StepResult {
            outputs: outputs.into_boxed_slice(),
            failure: Some(TypedProtocolFailure {
                kind,
                state_after: self.state,
            }),
            state: self.state,
        }
    }

    fn record_inbound_frame(&mut self, record: &DecodedFrame) {
        self.step_frames.push(FrameObservation {
            direction: FrameDirection::Inbound,
            fin: record.frame.fin(),
            opcode: record.frame.opcode(),
            masked: record.frame.masked(),
            payload: record.frame.payload().to_vec().into_boxed_slice(),
            wire_length: record.wire_length,
        });
    }

    fn record_outbound_frame(
        &mut self,
        fin: bool,
        opcode: Opcode,
        payload: &[u8],
        masked: bool,
        wire_length: usize,
    ) {
        self.step_frames.push(FrameObservation {
            direction: FrameDirection::Outbound,
            fin,
            opcode,
            masked,
            payload: payload.to_vec().into_boxed_slice(),
            wire_length,
        });
    }

    fn invalid_state(&self, input: InputKind) -> StepResult {
        StepResult {
            outputs: Box::new([]),
            failure: Some(TypedProtocolFailure {
                kind: FailureKind::InvalidState {
                    input,
                    state: self.state,
                },
                state_after: self.state,
            }),
            state: self.state,
        }
    }

    fn local_close(
        &mut self,
        code: Option<u16>,
        reason: &str,
        mask_key: Option<[u8; 4]>,
    ) -> StepResult {
        if self.state == ConnectionState::Connecting {
            return self.invalid_state(InputKind::LocalCommand);
        }
        if self.state == ConnectionState::Closing {
            if self.close.has_local() {
                return self.nonterminal_failure(FailureKind::Close(
                    crate::close::CloseFailure::DuplicateLocalClose,
                ));
            }
            if self.role != Role::Client || !self.close.has_peer() {
                return self.invalid_state(InputKind::LocalCommand);
            }
            if !self.close.acknowledgement_matches(code, reason) {
                return self.nonterminal_failure(FailureKind::Close(
                    crate::close::CloseFailure::AcknowledgementMismatch,
                ));
            }
            return match prepare_local_close(
                &self.config,
                self.role,
                code,
                reason,
                mask_key,
                self.close.retained_bytes(),
            ) {
                Ok(prepared) => {
                    self.record_outbound_frame(
                        true,
                        Opcode::Close,
                        &prepared.payload,
                        mask_key.is_some(),
                        prepared.wire.len(),
                    );
                    self.close.admit_local_half(prepared.payload);
                    StepResult {
                        outputs: Box::new([CoreOutput::TransportWrite(TransportWrite {
                            bytes: prepared.wire,
                        })]),
                        failure: None,
                        state: self.state,
                    }
                }
                Err(kind) => self.nonterminal_failure(kind),
            };
        }

        match prepare_local_close(&self.config, self.role, code, reason, mask_key, 0) {
            Ok(prepared) => {
                self.record_outbound_frame(
                    true,
                    Opcode::Close,
                    &prepared.payload,
                    mask_key.is_some(),
                    prepared.wire.len(),
                );
                self.close.begin_local(prepared.payload);
                self.frame_decoder.reset();
                self.outbound_fragments.reset();
                self.state = ConnectionState::Closing;
                StepResult {
                    outputs: Box::new([
                        CoreOutput::TransportWrite(TransportWrite {
                            bytes: prepared.wire,
                        }),
                        CoreOutput::StateChanged(ConnectionState::Closing),
                    ]),
                    failure: None,
                    state: self.state,
                }
            }
            Err(kind) => self.nonterminal_failure(kind),
        }
    }

    fn nonterminal_failure(&self, kind: FailureKind) -> StepResult {
        StepResult {
            outputs: Box::new([]),
            failure: Some(TypedProtocolFailure {
                kind,
                state_after: self.state,
            }),
            state: self.state,
        }
    }

    fn finish_clean(&mut self, mut outputs: Vec<CoreOutput>) -> StepResult {
        self.frame_decoder.reset();
        self.outbound_fragments.reset();
        self.close.reset();
        self.state = ConnectionState::Closed;
        outputs.push(CoreOutput::StateChanged(ConnectionState::Closed));
        StepResult {
            outputs: outputs.into_boxed_slice(),
            failure: None,
            state: self.state,
        }
    }
}
