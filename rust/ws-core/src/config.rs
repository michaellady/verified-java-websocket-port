//! Immutable, validated connection configuration (US-009 AC3).
//!
//! Every limit is explicit, every conversion checked, every default
//! deterministic. Construction goes only through [`ConnectionConfigBuilder`],
//! which validates zero, boundary, and oversized values against the pinned
//! limit table ([`LimitField`]).
//!
//! Sources of the table:
//! - oracle-tier ceilings: `java-oracle/README.md` ("A request cannot relax
//!   the 1 MiB line/input/buffer ceilings, 1,024-action ceiling, 4,096-frame
//!   ceiling, or 4 MiB output ceiling") and
//!   `schemas/corpus-scenario-1.0.0.schema.json` minima;
//! - handshake defaults: the handshake corpus configuration
//!   (`corpora/handshake/cases.jsonl` config: 4096 / 32 / 512). Java itself
//!   has NO handshake byte/header limits (`translateHandshakeHttp` reads
//!   unboundedly, WebSocketImpl.java:370-387); carrying and enforcing these
//!   limits is a deliberate port-side strengthening under the owner's
//!   JAVA_FAITHFUL_PLUS_SAFE decision, to be recorded in the behavior-delta
//!   ledger once its baseline observations exist (enforcement lands with
//!   US-010/US-011);
//! - queue capacities: port-side constants for the AC4 bounded ownership
//!   boundary (Java's `outQueue` is unbounded, WebSocketImpl.java:98/206; the
//!   port's bounded queues are the recorded divergence
//!   `divergence.bounded-command-queue`).

use std::fmt;

/// Names of every explicit limit, with the pinned minimum / default /
/// ceiling table. Table-driven so tests and the builder share one source of
/// truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LimitField {
    /// Opening-handshake byte cap (port strengthening; see module docs).
    MaxHandshakeBytes,
    /// Opening-handshake header-count cap (port strengthening).
    MaxHeaderCount,
    /// Opening-handshake header-line byte cap (port strengthening).
    MaxHeaderLineBytes,
    /// Single-frame payload cap. Projects Java's `maxFrameSize` knob; the
    /// oracle harness maps the corpus `max_buffered_bytes` here ("Java-
    /// WebSocket receives max_buffered_bytes as its maximum frame/message
    /// size", java-oracle/README.md).
    MaxFramePayloadBytes,
    /// Reassembled-message cap (fragment reassembly, US-014). Same corpus
    /// mapping as [`LimitField::MaxFramePayloadBytes`].
    MaxMessageBytes,
    /// Buffered-byte cap: bounds the pending wire buffer (with the Java `+14`
    /// header slack, quirk Q24) and the send-path payload gate.
    MaxBufferedBytes,
    /// Total transport-input byte cap (`max_input_bytes`, addBounded
    /// accounting).
    MaxInputBytes,
    /// Action-count cap (`max_actions`). The corpus schema minimum is 0: a
    /// scenario may forbid all actions.
    MaxActions,
    /// Frame-count cap (`max_frames`).
    MaxFrames,
    /// Wire-output byte cap (`max_output_bytes`).
    MaxOutputBytes,
    /// Capacity of the semantic-event queue (AC4 bounded queue). The minimum
    /// is [`crate::connection::MAX_EVENT_SLOTS_PER_INPUT`] rounded up with
    /// headroom so no input is permanently unprocessable.
    EventQueueCapacity,
    /// Capacity of the bounded multi-producer command channel (AC4).
    CommandQueueCapacity,
    /// Capacity of the transport-write queue (AC4 bounded queue).
    WriteQueueCapacity,
}

impl LimitField {
    /// Every limit field, for table-driven validation and tests.
    pub const ALL: [LimitField; 13] = [
        LimitField::MaxHandshakeBytes,
        LimitField::MaxHeaderCount,
        LimitField::MaxHeaderLineBytes,
        LimitField::MaxFramePayloadBytes,
        LimitField::MaxMessageBytes,
        LimitField::MaxBufferedBytes,
        LimitField::MaxInputBytes,
        LimitField::MaxActions,
        LimitField::MaxFrames,
        LimitField::MaxOutputBytes,
        LimitField::EventQueueCapacity,
        LimitField::CommandQueueCapacity,
        LimitField::WriteQueueCapacity,
    ];

    /// The field's snake_case name (deterministic error messages).
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            LimitField::MaxHandshakeBytes => "max_handshake_bytes",
            LimitField::MaxHeaderCount => "max_header_count",
            LimitField::MaxHeaderLineBytes => "max_header_line_bytes",
            LimitField::MaxFramePayloadBytes => "max_frame_payload_bytes",
            LimitField::MaxMessageBytes => "max_message_bytes",
            LimitField::MaxBufferedBytes => "max_buffered_bytes",
            LimitField::MaxInputBytes => "max_input_bytes",
            LimitField::MaxActions => "max_actions",
            LimitField::MaxFrames => "max_frames",
            LimitField::MaxOutputBytes => "max_output_bytes",
            LimitField::EventQueueCapacity => "event_queue_capacity",
            LimitField::CommandQueueCapacity => "command_queue_capacity",
            LimitField::WriteQueueCapacity => "write_queue_capacity",
        }
    }

    /// Smallest accepted value. Oracle-tier minima come from the corpus
    /// scenario schema; handshake and queue minima are port-side.
    #[must_use]
    pub fn minimum(&self) -> u64 {
        match self {
            LimitField::MaxActions => 0,
            LimitField::MaxOutputBytes => 512,
            LimitField::EventQueueCapacity => 4,
            _ => 1,
        }
    }

    /// Deterministic default (US-009 design draft section 4: the public-tier
    /// scenario values and the handshake corpus configuration).
    #[must_use]
    pub fn default_value(&self) -> u64 {
        match self {
            LimitField::MaxHandshakeBytes => 4096,
            LimitField::MaxHeaderCount => 32,
            LimitField::MaxHeaderLineBytes => 512,
            LimitField::MaxFramePayloadBytes
            | LimitField::MaxMessageBytes
            | LimitField::MaxBufferedBytes
            | LimitField::MaxInputBytes => 65_536,
            LimitField::MaxActions | LimitField::MaxFrames => 64,
            LimitField::MaxOutputBytes => 4_194_304,
            LimitField::EventQueueCapacity
            | LimitField::CommandQueueCapacity
            | LimitField::WriteQueueCapacity => 64,
        }
    }

    /// Largest accepted value (the oracle adapter ceilings where one exists;
    /// documented port-side ceilings elsewhere).
    #[must_use]
    pub fn ceiling(&self) -> u64 {
        match self {
            LimitField::MaxHandshakeBytes
            | LimitField::MaxFramePayloadBytes
            | LimitField::MaxMessageBytes
            | LimitField::MaxBufferedBytes
            | LimitField::MaxInputBytes => 1_048_576,
            LimitField::MaxHeaderCount => 1024,
            LimitField::MaxHeaderLineBytes => 65_536,
            LimitField::MaxActions => 1024,
            LimitField::MaxFrames => 4096,
            LimitField::MaxOutputBytes => 4_194_304,
            // Raised from 4096 for US-012 multi-frame decoding: one byte
            // input can complete up to the whole remaining frame budget, so
            // an owner sizing the event queue for single-drain operation
            // needs room for EVENT_SLOTS_PER_FRAME * (max_frames + 1) + 1
            // slots (8195 at the max_frames ceiling).
            LimitField::EventQueueCapacity => 16_384,
            LimitField::CommandQueueCapacity | LimitField::WriteQueueCapacity => 4096,
        }
    }
}

/// Why a limit value was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigErrorKind {
    /// The value is below the field's minimum.
    BelowMinimum {
        /// The field's minimum.
        minimum: u64,
    },
    /// The value is above the field's ceiling.
    AboveCeiling {
        /// The field's ceiling.
        ceiling: u64,
    },
    /// The value passed range validation but cannot be represented in this
    /// platform's `usize` (checked conversion; unreachable on 64-bit hosts
    /// because every ceiling fits in 32 bits, kept as a structural guarantee
    /// that no conversion is unchecked).
    Unrepresentable,
}

/// A rejected configuration value: which field, the offending value, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigError {
    /// The rejected field.
    pub field: LimitField,
    /// The offending raw value.
    pub value: u64,
    /// The rejection reason.
    pub kind: ConfigErrorKind,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.field.name();
        match self.kind {
            ConfigErrorKind::BelowMinimum { minimum } => {
                write!(f, "{name} = {} is below the minimum {minimum}", self.value)
            }
            ConfigErrorKind::AboveCeiling { ceiling } => {
                write!(f, "{name} = {} is above the ceiling {ceiling}", self.value)
            }
            ConfigErrorKind::Unrepresentable => {
                write!(
                    f,
                    "{name} = {} is not representable as usize on this platform",
                    self.value
                )
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// Immutable, validated configuration for one connection (US-009 AC2/AC3).
///
/// All fields are private and set only by [`ConnectionConfigBuilder::build`];
/// there is no mutating API after construction. Cloning is cheap value
/// copying — the core takes the config by value and never shares it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionConfig {
    max_handshake_bytes: usize,
    max_header_count: usize,
    max_header_line_bytes: usize,
    max_frame_payload_bytes: usize,
    max_message_bytes: usize,
    max_buffered_bytes: usize,
    max_input_bytes: usize,
    max_actions: u64,
    max_frames: u64,
    max_output_bytes: usize,
    event_queue_capacity: usize,
    command_queue_capacity: usize,
    write_queue_capacity: usize,
    mask_key_seed: u64,
}

impl ConnectionConfig {
    /// Start a checked builder pre-loaded with the deterministic defaults.
    #[must_use]
    pub fn builder() -> ConnectionConfigBuilder {
        ConnectionConfigBuilder::new()
    }

    /// Opening-handshake byte cap (enforcement lands with US-010/US-011).
    #[must_use]
    pub fn max_handshake_bytes(&self) -> usize {
        self.max_handshake_bytes
    }

    /// Opening-handshake header-count cap (US-010/US-011).
    #[must_use]
    pub fn max_header_count(&self) -> usize {
        self.max_header_count
    }

    /// Opening-handshake header-line byte cap (US-010/US-011).
    #[must_use]
    pub fn max_header_line_bytes(&self) -> usize {
        self.max_header_line_bytes
    }

    /// Single-frame payload cap (US-012 header-time length gate).
    #[must_use]
    pub fn max_frame_payload_bytes(&self) -> usize {
        self.max_frame_payload_bytes
    }

    /// Reassembled-message cap (US-014).
    #[must_use]
    pub fn max_message_bytes(&self) -> usize {
        self.max_message_bytes
    }

    /// Buffered-byte cap: pending wire buffer (`+14` slack at the use site,
    /// quirk Q24) and send-path payload gate.
    #[must_use]
    pub fn max_buffered_bytes(&self) -> usize {
        self.max_buffered_bytes
    }

    /// Total transport-input byte cap.
    #[must_use]
    pub fn max_input_bytes(&self) -> usize {
        self.max_input_bytes
    }

    /// Action-count cap.
    #[must_use]
    pub fn max_actions(&self) -> u64 {
        self.max_actions
    }

    /// Frame-count cap.
    #[must_use]
    pub fn max_frames(&self) -> u64 {
        self.max_frames
    }

    /// Wire-output byte cap.
    #[must_use]
    pub fn max_output_bytes(&self) -> usize {
        self.max_output_bytes
    }

    /// Semantic-event queue capacity.
    #[must_use]
    pub fn event_queue_capacity(&self) -> usize {
        self.event_queue_capacity
    }

    /// Bounded multi-producer command channel capacity.
    #[must_use]
    pub fn command_queue_capacity(&self) -> usize {
        self.command_queue_capacity
    }

    /// Transport-write queue capacity.
    #[must_use]
    pub fn write_queue_capacity(&self) -> usize {
        self.write_queue_capacity
    }

    /// Seed for the injected deterministic client mask-key source (design
    /// draft section 1.4; quirk Q28: mask keys are never observable, so any
    /// deterministic source scores identically). Consumed by US-012's
    /// encoder; carried here so the construction seam exists from the start.
    #[must_use]
    pub fn mask_key_seed(&self) -> u64 {
        self.mask_key_seed
    }
}

impl Default for ConnectionConfig {
    /// The pinned deterministic default table. Constructed directly from
    /// [`LimitField::default_value`] (known-valid), so no panic path exists.
    fn default() -> Self {
        // Defaults are compile-time constants well below usize::MAX on every
        // supported platform; the `as` conversions here are lossless.
        ConnectionConfig {
            max_handshake_bytes: LimitField::MaxHandshakeBytes.default_value() as usize,
            max_header_count: LimitField::MaxHeaderCount.default_value() as usize,
            max_header_line_bytes: LimitField::MaxHeaderLineBytes.default_value() as usize,
            max_frame_payload_bytes: LimitField::MaxFramePayloadBytes.default_value() as usize,
            max_message_bytes: LimitField::MaxMessageBytes.default_value() as usize,
            max_buffered_bytes: LimitField::MaxBufferedBytes.default_value() as usize,
            max_input_bytes: LimitField::MaxInputBytes.default_value() as usize,
            max_actions: LimitField::MaxActions.default_value(),
            max_frames: LimitField::MaxFrames.default_value(),
            max_output_bytes: LimitField::MaxOutputBytes.default_value() as usize,
            event_queue_capacity: LimitField::EventQueueCapacity.default_value() as usize,
            command_queue_capacity: LimitField::CommandQueueCapacity.default_value() as usize,
            write_queue_capacity: LimitField::WriteQueueCapacity.default_value() as usize,
            mask_key_seed: 0,
        }
    }
}

/// Checked builder for [`ConnectionConfig`]. Setters record raw `u64`
/// values; [`ConnectionConfigBuilder::build`] validates every field against
/// the [`LimitField`] table (minimum, ceiling) and performs the checked
/// `u64 -> usize` conversion, surfacing failures as [`ConfigError`] — no
/// wrapping, no truncation, no panics.
#[derive(Debug, Clone, Default)]
pub struct ConnectionConfigBuilder {
    raw: [Option<u64>; 13],
    mask_key_seed: u64,
}

impl ConnectionConfigBuilder {
    /// A builder pre-loaded with the deterministic defaults.
    #[must_use]
    pub fn new() -> Self {
        ConnectionConfigBuilder::default()
    }

    fn index(field: LimitField) -> usize {
        LimitField::ALL
            .iter()
            .position(|f| *f == field)
            .expect("LimitField::ALL enumerates every variant")
    }

    fn set(mut self, field: LimitField, value: u64) -> Self {
        self.raw[Self::index(field)] = Some(value);
        self
    }

    /// Set the opening-handshake byte cap.
    #[must_use]
    pub fn max_handshake_bytes(self, value: u64) -> Self {
        self.set(LimitField::MaxHandshakeBytes, value)
    }

    /// Set the opening-handshake header-count cap.
    #[must_use]
    pub fn max_header_count(self, value: u64) -> Self {
        self.set(LimitField::MaxHeaderCount, value)
    }

    /// Set the opening-handshake header-line byte cap.
    #[must_use]
    pub fn max_header_line_bytes(self, value: u64) -> Self {
        self.set(LimitField::MaxHeaderLineBytes, value)
    }

    /// Set the single-frame payload cap.
    #[must_use]
    pub fn max_frame_payload_bytes(self, value: u64) -> Self {
        self.set(LimitField::MaxFramePayloadBytes, value)
    }

    /// Set the reassembled-message cap.
    #[must_use]
    pub fn max_message_bytes(self, value: u64) -> Self {
        self.set(LimitField::MaxMessageBytes, value)
    }

    /// Set the buffered-byte cap.
    #[must_use]
    pub fn max_buffered_bytes(self, value: u64) -> Self {
        self.set(LimitField::MaxBufferedBytes, value)
    }

    /// Set the total transport-input byte cap.
    #[must_use]
    pub fn max_input_bytes(self, value: u64) -> Self {
        self.set(LimitField::MaxInputBytes, value)
    }

    /// Set the action-count cap.
    #[must_use]
    pub fn max_actions(self, value: u64) -> Self {
        self.set(LimitField::MaxActions, value)
    }

    /// Set the frame-count cap.
    #[must_use]
    pub fn max_frames(self, value: u64) -> Self {
        self.set(LimitField::MaxFrames, value)
    }

    /// Set the wire-output byte cap.
    #[must_use]
    pub fn max_output_bytes(self, value: u64) -> Self {
        self.set(LimitField::MaxOutputBytes, value)
    }

    /// Set the semantic-event queue capacity.
    #[must_use]
    pub fn event_queue_capacity(self, value: u64) -> Self {
        self.set(LimitField::EventQueueCapacity, value)
    }

    /// Set the bounded command-channel capacity.
    #[must_use]
    pub fn command_queue_capacity(self, value: u64) -> Self {
        self.set(LimitField::CommandQueueCapacity, value)
    }

    /// Set the transport-write queue capacity.
    #[must_use]
    pub fn write_queue_capacity(self, value: u64) -> Self {
        self.set(LimitField::WriteQueueCapacity, value)
    }

    /// Set the deterministic mask-key seed (any value is valid; not a limit).
    #[must_use]
    pub fn mask_key_seed(mut self, seed: u64) -> Self {
        self.mask_key_seed = seed;
        self
    }

    /// Validate one field and convert it checked into `usize`.
    fn checked_usize(field: LimitField, value: u64) -> Result<usize, ConfigError> {
        Self::validate(field, value)?;
        usize::try_from(value).map_err(|_| ConfigError {
            field,
            value,
            kind: ConfigErrorKind::Unrepresentable,
        })
    }

    fn validate(field: LimitField, value: u64) -> Result<u64, ConfigError> {
        if value < field.minimum() {
            return Err(ConfigError {
                field,
                value,
                kind: ConfigErrorKind::BelowMinimum {
                    minimum: field.minimum(),
                },
            });
        }
        if value > field.ceiling() {
            return Err(ConfigError {
                field,
                value,
                kind: ConfigErrorKind::AboveCeiling {
                    ceiling: field.ceiling(),
                },
            });
        }
        Ok(value)
    }

    fn value_of(&self, field: LimitField) -> u64 {
        self.raw[Self::index(field)].unwrap_or_else(|| field.default_value())
    }

    /// Validate every field and produce the immutable configuration.
    ///
    /// # Errors
    ///
    /// Returns the first [`ConfigError`] in [`LimitField::ALL`] order (a
    /// deterministic order, so identical inputs yield identical errors).
    pub fn build(self) -> Result<ConnectionConfig, ConfigError> {
        use LimitField as F;
        // Validate all fields in pinned order first so the reported error is
        // deterministic regardless of setter call order.
        for field in F::ALL {
            Self::validate(field, self.value_of(field))?;
        }
        Ok(ConnectionConfig {
            max_handshake_bytes: Self::checked_usize(
                F::MaxHandshakeBytes,
                self.value_of(F::MaxHandshakeBytes),
            )?,
            max_header_count: Self::checked_usize(
                F::MaxHeaderCount,
                self.value_of(F::MaxHeaderCount),
            )?,
            max_header_line_bytes: Self::checked_usize(
                F::MaxHeaderLineBytes,
                self.value_of(F::MaxHeaderLineBytes),
            )?,
            max_frame_payload_bytes: Self::checked_usize(
                F::MaxFramePayloadBytes,
                self.value_of(F::MaxFramePayloadBytes),
            )?,
            max_message_bytes: Self::checked_usize(
                F::MaxMessageBytes,
                self.value_of(F::MaxMessageBytes),
            )?,
            max_buffered_bytes: Self::checked_usize(
                F::MaxBufferedBytes,
                self.value_of(F::MaxBufferedBytes),
            )?,
            max_input_bytes: Self::checked_usize(
                F::MaxInputBytes,
                self.value_of(F::MaxInputBytes),
            )?,
            max_actions: Self::validate(F::MaxActions, self.value_of(F::MaxActions))?,
            max_frames: Self::validate(F::MaxFrames, self.value_of(F::MaxFrames))?,
            max_output_bytes: Self::checked_usize(
                F::MaxOutputBytes,
                self.value_of(F::MaxOutputBytes),
            )?,
            event_queue_capacity: Self::checked_usize(
                F::EventQueueCapacity,
                self.value_of(F::EventQueueCapacity),
            )?,
            command_queue_capacity: Self::checked_usize(
                F::CommandQueueCapacity,
                self.value_of(F::CommandQueueCapacity),
            )?,
            write_queue_capacity: Self::checked_usize(
                F::WriteQueueCapacity,
                self.value_of(F::WriteQueueCapacity),
            )?,
            mask_key_seed: self.mask_key_seed,
        })
    }
}
