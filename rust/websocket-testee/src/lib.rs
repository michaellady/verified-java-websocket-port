//! Thin blocking loopback adapter for the exact WebSocket connection owner.
//!
//! The crate owns only one TCP connect or accept and bounded blocking I/O. All
//! protocol decisions are delegated to `websocket-driver` and its sole owner.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod client;
mod io_loop;
mod server;

use core::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use websocket_core::{
    ClientRequestDescriptor, ConnectionConfig, ConnectionState, Role, SemanticEvent,
};

pub use client::run_client_once;
pub use server::run_server_once;

/// Maximum accepted duration for one blocking transport operation.
pub const MAX_IO_DURATION: Duration = Duration::from_secs(30);
/// Maximum owner turns admitted by one adapter run.
pub const MAX_OWNER_TURNS: u64 = 1_000_000;
/// Minimum owner-turn budget that preserves one work turn and terminal drain.
pub const MIN_OWNER_TURNS: u64 = TERMINAL_DRAIN_TURN_ALLOWANCE + 1;
/// Maximum normalized observations retained by one adapter report.
pub const MAX_REPORT_ENTRIES: usize = 4_096;

// The exact core caps its event queue at 4,096 entries. The private fixture can
// admit at most its one client-start command, while Shutdown discards queued
// writes synchronously. Eight further turns cover that command and the fixed
// EOF, failure, state, and terminal transitions.
pub(crate) const TERMINAL_DRAIN_TURN_ALLOWANCE: u64 = 4_096 + 8;

/// Raw values checked together before a socket operation or allocation occurs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoBoundsSpec {
    /// Size of the sole inbound allocation.
    pub read_buffer_bytes: usize,
    /// Largest prefix passed to one socket write.
    pub max_write_chunk_bytes: usize,
    /// Maximum duration of the one client connect.
    pub connect_timeout: Duration,
    /// Maximum duration of the one server accept.
    pub accept_timeout: Duration,
    /// Maximum duration of each logical read operation.
    pub read_timeout: Duration,
    /// Maximum duration of each logical write operation.
    pub write_timeout: Duration,
    /// Maximum calls into the sole connection owner.
    pub max_owner_turns: u64,
    /// Maximum normalized entries retained in the report.
    pub max_report_entries: usize,
}

impl Default for IoBoundsSpec {
    fn default() -> Self {
        Self {
            read_buffer_bytes: 4_096,
            max_write_chunk_bytes: 4_096,
            connect_timeout: Duration::from_secs(2),
            accept_timeout: Duration::from_secs(2),
            read_timeout: Duration::from_secs(2),
            write_timeout: Duration::from_secs(2),
            max_owner_turns: 100_000,
            max_report_entries: 1_024,
        }
    }
}

/// Field rejected while checking [`IoBoundsSpec`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoBoundField {
    /// [`IoBoundsSpec::read_buffer_bytes`].
    ReadBufferBytes,
    /// [`IoBoundsSpec::max_write_chunk_bytes`].
    MaxWriteChunkBytes,
    /// [`IoBoundsSpec::connect_timeout`].
    ConnectTimeout,
    /// [`IoBoundsSpec::accept_timeout`].
    AcceptTimeout,
    /// [`IoBoundsSpec::read_timeout`].
    ReadTimeout,
    /// [`IoBoundsSpec::write_timeout`].
    WriteTimeout,
    /// [`IoBoundsSpec::max_owner_turns`].
    MaxOwnerTurns,
    /// [`IoBoundsSpec::max_report_entries`].
    MaxReportEntries,
}

/// Typed rejection from checking adapter resource bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoBoundsError {
    /// A progress-enabling bound was zero.
    Zero(IoBoundField),
    /// A bound could not preserve its required reserved capacity.
    BelowMinimum {
        /// Rejected field.
        field: IoBoundField,
        /// Caller-supplied scalar value.
        attempted: u128,
        /// Smallest accepted scalar value.
        minimum: u128,
    },
    /// A bound exceeded the core budget or adapter hard ceiling.
    ExceedsMaximum {
        /// Rejected field.
        field: IoBoundField,
        /// Caller-supplied scalar value (durations use nanoseconds).
        attempted: u128,
        /// Largest accepted scalar value (durations use nanoseconds).
        maximum: u128,
    },
}

/// Fully checked transport and report resource bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoBounds {
    pub(crate) spec: IoBoundsSpec,
    configured_total_buffered_bytes: u64,
}

impl IoBounds {
    /// Checks every bound against fixed ceilings and the supplied core budget.
    pub fn try_new(config: &ConnectionConfig, spec: IoBoundsSpec) -> Result<Self, IoBoundsError> {
        let total = config.limits().total_buffered_bytes;
        check_nonzero_usize(IoBoundField::ReadBufferBytes, spec.read_buffer_bytes)?;
        check_max_usize(IoBoundField::ReadBufferBytes, spec.read_buffer_bytes, total)?;
        check_nonzero_usize(IoBoundField::MaxWriteChunkBytes, spec.max_write_chunk_bytes)?;
        check_max_usize(
            IoBoundField::MaxWriteChunkBytes,
            spec.max_write_chunk_bytes,
            total,
        )?;
        for (field, duration) in [
            (IoBoundField::ConnectTimeout, spec.connect_timeout),
            (IoBoundField::AcceptTimeout, spec.accept_timeout),
            (IoBoundField::ReadTimeout, spec.read_timeout),
            (IoBoundField::WriteTimeout, spec.write_timeout),
        ] {
            check_duration(field, duration)?;
        }
        if spec.max_owner_turns == 0 {
            return Err(IoBoundsError::Zero(IoBoundField::MaxOwnerTurns));
        }
        if spec.max_owner_turns < MIN_OWNER_TURNS {
            return Err(IoBoundsError::BelowMinimum {
                field: IoBoundField::MaxOwnerTurns,
                attempted: u128::from(spec.max_owner_turns),
                minimum: u128::from(MIN_OWNER_TURNS),
            });
        }
        if spec.max_owner_turns > MAX_OWNER_TURNS {
            return Err(IoBoundsError::ExceedsMaximum {
                field: IoBoundField::MaxOwnerTurns,
                attempted: u128::from(spec.max_owner_turns),
                maximum: u128::from(MAX_OWNER_TURNS),
            });
        }
        check_nonzero_usize(IoBoundField::MaxReportEntries, spec.max_report_entries)?;
        if spec.max_report_entries > MAX_REPORT_ENTRIES {
            return Err(IoBoundsError::ExceedsMaximum {
                field: IoBoundField::MaxReportEntries,
                attempted: spec.max_report_entries as u128,
                maximum: MAX_REPORT_ENTRIES as u128,
            });
        }
        Ok(Self {
            spec,
            configured_total_buffered_bytes: total,
        })
    }

    pub(crate) fn validate_for(&self, config: &ConnectionConfig) -> Result<(), IoBoundsError> {
        let total = config.limits().total_buffered_bytes;
        if total != self.configured_total_buffered_bytes {
            return Err(IoBoundsError::ExceedsMaximum {
                field: IoBoundField::ReadBufferBytes,
                attempted: self.spec.read_buffer_bytes as u128,
                maximum: u128::from(total),
            });
        }
        Self::try_new(config, self.spec).map(|_| ())
    }
}

fn check_nonzero_usize(field: IoBoundField, value: usize) -> Result<(), IoBoundsError> {
    if value == 0 {
        Err(IoBoundsError::Zero(field))
    } else {
        Ok(())
    }
}

fn check_max_usize(field: IoBoundField, value: usize, maximum: u64) -> Result<(), IoBoundsError> {
    if value as u128 > u128::from(maximum) {
        Err(IoBoundsError::ExceedsMaximum {
            field,
            attempted: value as u128,
            maximum: u128::from(maximum),
        })
    } else {
        Ok(())
    }
}

fn check_duration(field: IoBoundField, value: Duration) -> Result<(), IoBoundsError> {
    if value.is_zero() {
        return Err(IoBoundsError::Zero(field));
    }
    if value > MAX_IO_DURATION {
        return Err(IoBoundsError::ExceedsMaximum {
            field,
            attempted: value.as_nanos(),
            maximum: MAX_IO_DURATION.as_nanos(),
        });
    }
    Ok(())
}

/// Inputs for the one bounded client connect and owner run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientFixture {
    /// Numeric loopback peer address; DNS is intentionally absent.
    pub address: SocketAddr,
    /// Checked core configuration transferred to the exact driver.
    pub config: ConnectionConfig,
    /// Checked client opening-handshake fields.
    pub descriptor: ClientRequestDescriptor,
    /// Explicit deterministic opening-handshake nonce.
    pub nonce: [u8; 16],
    /// Checked transport and report bounds.
    pub bounds: IoBounds,
}

/// Inputs for one accept on a caller-bound loopback listener.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerFixture {
    /// Checked core configuration transferred to the exact driver.
    pub config: ConnectionConfig,
    /// Checked transport and report bounds.
    pub bounds: IoBounds,
}

/// Stable, non-sensitive classification of one socket error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketErrorKind {
    /// The peer refused the connection.
    ConnectionRefused,
    /// The peer reset the connection.
    ConnectionReset,
    /// The write side was broken.
    BrokenPipe,
    /// The operation timed out.
    TimedOut,
    /// The operation would block before its bounded deadline.
    WouldBlock,
    /// The peer or local endpoint was not connected.
    NotConnected,
    /// Any other stable standard-library error class.
    Other,
}

/// Outcome of acquiring and configuring the sole socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupOutcome {
    /// A checked loopback socket reached the exact driver.
    Connected,
    /// Bounds were checked against a different core configuration.
    InvalidBounds(IoBoundsError),
    /// A local or peer socket address was not loopback.
    NonLoopback,
    /// The one bounded connect failed.
    ConnectFailed(SocketErrorKind),
    /// The process fixture could not bind its numeric loopback address.
    BindFailed(SocketErrorKind),
    /// The one bounded accept reached its deadline.
    AcceptTimeout,
    /// The one bounded accept failed.
    AcceptFailed(SocketErrorKind),
    /// Blocking socket configuration failed.
    SocketConfigurationFailed(SocketErrorKind),
    /// The explicit client start command could not enter its checked queue.
    ClientCommandRejected,
}

/// Cause that ended transport service after owner construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdapterTermination {
    /// The driver delivered its sole terminal observation without prior adapter loss.
    DriverTerminal,
    /// The peer delivered transport EOF.
    PeerEof,
    /// A bounded read reached its deadline.
    ReadTimeout,
    /// A bounded write or flush reached its deadline.
    WriteTimeout,
    /// A non-timeout read failed.
    ReadIo(SocketErrorKind),
    /// A non-timeout write or flush failed.
    WriteIo(SocketErrorKind),
    /// The transport returned zero progress for a required write.
    PeerServiceLost,
    /// The bounded observation report was exhausted.
    ReportLimit,
    /// Checked adapter counter arithmetic overflowed.
    CounterOverflow,
    /// The configured owner-turn budget was exhausted.
    OwnerTurnLimit,
    /// Driver input accounting violated the promoted seam.
    InvariantViolation,
}

/// Payload-free classification of a semantic driver event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventKind {
    /// Client opening handshake completed.
    ClientHandshakeOpened,
    /// Server opening handshake completed.
    ServerHandshakeOpened,
    /// One complete frame was decoded.
    FrameReceived,
    /// One complete text message was delivered.
    Text,
    /// One complete binary message was delivered.
    Binary,
    /// One Ping was observed.
    Ping,
    /// One Pong was observed.
    Pong,
    /// One Close was observed.
    CloseReceived,
    /// A future payload-bearing core event was normalized without retaining it.
    Other,
}

impl From<&SemanticEvent> for EventKind {
    fn from(event: &SemanticEvent) -> Self {
        match event {
            SemanticEvent::ClientHandshakeOpened { .. } => Self::ClientHandshakeOpened,
            SemanticEvent::ServerHandshakeOpened { .. } => Self::ServerHandshakeOpened,
            SemanticEvent::FrameReceived { .. } => Self::FrameReceived,
            SemanticEvent::Text { .. } => Self::Text,
            SemanticEvent::Binary { .. } => Self::Binary,
            SemanticEvent::Ping { .. } => Self::Ping,
            SemanticEvent::Pong { .. } => Self::Pong,
            SemanticEvent::CloseReceived { .. } => Self::CloseReceived,
            _ => Self::Other,
        }
    }
}

/// One bounded, payload-free observation at the adapter seam.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdapterObservation {
    /// The owner offered an exact remaining write suffix.
    WriteOffered {
        /// Length of the offered suffix.
        bytes: usize,
    },
    /// The socket accepted an exact write prefix.
    WriteProgress {
        /// Count supplied unchanged to the owner.
        bytes: usize,
    },
    /// A producer command was applied by the owner.
    CommandApplied,
    /// A producer command was rejected by the core.
    CommandRejected,
    /// Terminal convergence rejected an admitted producer command.
    CommandTerminalRejected,
    /// Every producer handle was dropped.
    ProducersDropped,
    /// One payload-free semantic event was observed.
    Event(EventKind),
    /// One core lifecycle transition was observed.
    StateChanged(ConnectionState),
    /// One typed protocol failure was observed; payload details remain in the core.
    Failure {
        /// Core state after the typed failure.
        state_after: ConnectionState,
    },
    /// Transport EOF was supplied to the owner.
    TransportEof,
    /// Adapter shutdown was supplied to the owner.
    Shutdown,
    /// The one normalized driver terminal was delivered.
    Terminal,
    /// The adapter stopped admitting ordinary observations at its report bound.
    AdapterFailure(AdapterTermination),
}

/// Checked counters from one adapter run.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AdapterCounters {
    /// Calls to the blocking socket read operation.
    pub read_calls: u64,
    /// Bytes read from the socket.
    pub bytes_read: u64,
    /// Read calls returning less than the sole buffer capacity.
    pub partial_reads: u64,
    /// Calls to the blocking socket write operation.
    pub write_calls: u64,
    /// Calls to flush after accepted write progress.
    pub flush_calls: u64,
    /// Bytes accepted by the socket.
    pub bytes_written: u64,
    /// Write progress smaller than the owner's offered suffix.
    pub partial_writes: u64,
    /// Interrupted operations retried without resetting their deadline.
    pub interruptions: u64,
    /// Read deadlines reached.
    pub read_timeouts: u64,
    /// Write deadlines reached.
    pub write_timeouts: u64,
    /// EOF facts supplied to the owner.
    pub eof_inputs: u64,
    /// Shutdown facts supplied to the owner.
    pub shutdown_inputs: u64,
    /// Calls to [`websocket_driver::ConnectionOwner::poll`].
    pub owner_turns: u64,
}

/// Sole bounded output of a client or server adapter run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterReport {
    /// Fixed protocol role for the sole socket.
    pub role: Role,
    /// Socket acquisition and setup result.
    pub setup: SetupOutcome,
    /// First transport, resource, or driver cause that ended the run.
    pub termination: Option<AdapterTermination>,
    /// Ordered payload-free observations, bounded by [`IoBoundsSpec::max_report_entries`].
    pub observations: Vec<AdapterObservation>,
    /// Checked socket and owner counters.
    pub counters: AdapterCounters,
    /// Last state observed from a constructed driver.
    pub final_state: Option<ConnectionState>,
    /// Count of normalized terminal driver deliveries.
    pub terminal_count: u8,
}

impl AdapterReport {
    pub(crate) fn setup_failure(role: Role, setup: SetupOutcome) -> Self {
        Self {
            role,
            setup,
            termination: None,
            observations: Vec::new(),
            counters: AdapterCounters::default(),
            final_state: None,
            terminal_count: 0,
        }
    }

    /// Returns a stable one-line summary without peer bytes or credentials.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "role={} setup={} termination={} terminal={} reads={} read_bytes={} writes={} write_bytes={} owner_turns={}",
            role_name(self.role),
            setup_name(self.setup),
            self.termination.map_or("none", termination_name),
            self.terminal_count,
            self.counters.read_calls,
            self.counters.bytes_read,
            self.counters.write_calls,
            self.counters.bytes_written,
            self.counters.owner_turns,
        )
    }

    /// Stable process exit class for the report.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self.setup {
            SetupOutcome::Connected => match self.termination {
                Some(AdapterTermination::DriverTerminal | AdapterTermination::PeerEof)
                    if self.terminal_count == 1 =>
                {
                    0
                }
                Some(
                    AdapterTermination::ReadTimeout
                    | AdapterTermination::WriteTimeout
                    | AdapterTermination::ReadIo(_)
                    | AdapterTermination::WriteIo(_)
                    | AdapterTermination::PeerServiceLost,
                ) => 4,
                Some(
                    AdapterTermination::ReportLimit
                    | AdapterTermination::CounterOverflow
                    | AdapterTermination::OwnerTurnLimit
                    | AdapterTermination::InvariantViolation,
                )
                | None => 5,
                Some(AdapterTermination::DriverTerminal | AdapterTermination::PeerEof) => 5,
            },
            SetupOutcome::InvalidBounds(_)
            | SetupOutcome::NonLoopback
            | SetupOutcome::ClientCommandRejected => 2,
            SetupOutcome::ConnectFailed(_)
            | SetupOutcome::BindFailed(_)
            | SetupOutcome::AcceptTimeout
            | SetupOutcome::AcceptFailed(_)
            | SetupOutcome::SocketConfigurationFailed(_) => 3,
        }
    }
}

fn role_name(role: Role) -> &'static str {
    match role {
        Role::Client => "client",
        Role::Server => "server",
    }
}

fn setup_name(setup: SetupOutcome) -> &'static str {
    match setup {
        SetupOutcome::Connected => "connected",
        SetupOutcome::InvalidBounds(_) => "invalid-bounds",
        SetupOutcome::NonLoopback => "non-loopback",
        SetupOutcome::ConnectFailed(_) => "connect-failed",
        SetupOutcome::BindFailed(_) => "bind-failed",
        SetupOutcome::AcceptTimeout => "accept-timeout",
        SetupOutcome::AcceptFailed(_) => "accept-failed",
        SetupOutcome::SocketConfigurationFailed(_) => "socket-config-failed",
        SetupOutcome::ClientCommandRejected => "client-command-rejected",
    }
}

fn termination_name(termination: AdapterTermination) -> &'static str {
    match termination {
        AdapterTermination::DriverTerminal => "driver-terminal",
        AdapterTermination::PeerEof => "peer-eof",
        AdapterTermination::ReadTimeout => "read-timeout",
        AdapterTermination::WriteTimeout => "write-timeout",
        AdapterTermination::ReadIo(_) => "read-io",
        AdapterTermination::WriteIo(_) => "write-io",
        AdapterTermination::PeerServiceLost => "peer-service-lost",
        AdapterTermination::ReportLimit => "report-limit",
        AdapterTermination::CounterOverflow => "counter-overflow",
        AdapterTermination::OwnerTurnLimit => "owner-turn-limit",
        AdapterTermination::InvariantViolation => "invariant-violation",
    }
}

impl fmt::Display for IoBoundsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}
