//! The empty/stub NEGATIVE CONTROL (US-019 AC4).
//!
//! This module implements NO WebSocket behavior: no opening handshake, no
//! framing, no control frames, no close. It never touches `ws_core` or
//! `ws_driver` — there is deliberately nothing here for a protocol library
//! to do. A session accepts (or opens) a TCP connection, reads whatever the
//! peer sends until EOF or its bounded budget expires, writes NOTHING, and
//! shuts the socket down.
//!
//! That is the whole artifact, and it is the point: it stands in for an
//! "empty Rust port" — a target that compiles, listens, and answers no
//! WebSocket question at all. Every Autobahn case must FAIL against it. If a
//! case passes, the suite wiring is measuring something other than the
//! testee.
//!
//! ## Both roles, one inert behavior
//!
//! `wstest --mode fuzzingclient` dials IN (the control is the server) and
//! `wstest --mode fuzzingserver` LISTENS (the control is the client agent).
//! The control's behavior is identical in both directions, because "no
//! protocol" has no role-specific form. In client mode it still opens the
//! three connections the agent protocol expects — `/getCaseCount`,
//! `/runCase`, `/updateReports` — so the suite RECORDS failures rather than
//! simply seeing nothing on the wire; it sends zero bytes on each of them.
//!
//! ## Bounded by construction
//!
//! Nothing here can block indefinitely: every read carries
//! [`InertBounds::read_timeout`], the attempt count is capped by
//! [`InertBounds::max_reads`], and the whole session is capped by the
//! wall-clock [`InertBounds::linger`] deadline.

use std::io::{ErrorKind, Read};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use ws_testee::{SetupOutcome, loopback_only};

/// How many connections the fuzzingserver-mode agent protocol expects the
/// testee to open: `/getCaseCount`, one `/runCase`, and `/updateReports`.
pub const AGENT_PROTOCOL_ATTEMPTS: usize = 3;

/// Bounded parameters for one inert session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InertBounds {
    /// Socket read timeout per attempt.
    pub read_timeout: Duration,
    /// Wall-clock ceiling on ONE session. The control has no protocol event
    /// to end on, so this deadline — not a state transition — is what makes
    /// a session terminate.
    pub linger: Duration,
    /// Read attempts budget per session.
    pub max_reads: u32,
    /// Read buffer size in bytes. Everything read is discarded; the buffer
    /// exists only so the peer's bytes are drained off the socket rather
    /// than left to fill a kernel buffer.
    pub read_buffer: usize,
}

impl Default for InertBounds {
    fn default() -> InertBounds {
        InertBounds {
            read_timeout: Duration::from_millis(25),
            linger: Duration::from_millis(250),
            max_reads: 256,
            read_buffer: 4096,
        }
    }
}

/// What one inert session observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InertSession {
    /// Bytes read off the socket and discarded — normally the peer's
    /// opening-handshake request, which this control never answers.
    pub bytes_read: usize,
    /// Bytes written back. Structurally ALWAYS zero: this module has no
    /// write path. The field exists so the property can be asserted from
    /// the outside rather than merely claimed in prose.
    pub bytes_written: usize,
    /// Read attempts spent.
    pub reads: u32,
    /// Whether the peer hung up before the session's own budget expired.
    pub peer_eof: bool,
}

impl InertSession {
    /// One deterministic summary line for the CLI harness.
    ///
    /// `handshake=none` is not a status to be interpreted — it is the
    /// invariant this control exists to hold, printed on every session.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "bytes-read={} bytes-written={} reads={} peer-eof={} handshake=none",
            self.bytes_read, self.bytes_written, self.reads, self.peer_eof,
        )
    }
}

/// Read errors that mean "nothing yet", not "the transport is gone".
fn retryable(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
    )
}

/// Drains one already-established socket without speaking any protocol on
/// it, then shuts it down. This is the entire behavior of the control.
fn drain(stream: &mut TcpStream, bounds: &InertBounds) -> InertSession {
    let mut session = InertSession {
        bytes_read: 0,
        bytes_written: 0,
        reads: 0,
        peer_eof: false,
    };
    let _ = stream.set_read_timeout(Some(bounds.read_timeout.max(Duration::from_millis(1))));
    let mut buffer = vec![0u8; bounds.read_buffer.max(1)];
    let deadline = Instant::now() + bounds.linger;
    while session.reads < bounds.max_reads && Instant::now() < deadline {
        session.reads += 1;
        match stream.read(&mut buffer) {
            Ok(0) => {
                session.peer_eof = true;
                break;
            }
            Ok(read) => session.bytes_read += read,
            Err(error) if retryable(error.kind()) => {}
            Err(_) => break,
        }
    }
    // No close frame, no goodbye: the transport simply goes away.
    let _ = stream.shutdown(Shutdown::Both);
    session
}

/// Accepts `sessions` connections in sequence, implementing no WebSocket
/// behavior on any of them.
///
/// The listener stays bound between sessions with no accept gap, matching
/// the shipped adapter's fuzzingclient wiring: the fuzzer opens one fresh
/// connection per case, strictly sequentially.
///
/// # Errors
///
/// The first [`SetupOutcome`] (accept failure / non-loopback peer) ends the
/// run early; sessions already served have been reported.
pub fn serve_inert_sessions(
    listener: &TcpListener,
    bounds: &InertBounds,
    sessions: u64,
    on_session: &mut dyn FnMut(u64, &InertSession),
) -> Result<(), SetupOutcome> {
    for index in 1..=sessions {
        let session = serve_inert_once(listener, bounds)?;
        on_session(index, &session);
    }
    Ok(())
}

/// Accepts ONE connection and implements no WebSocket behavior on it.
///
/// # Errors
///
/// [`SetupOutcome::SocketFailed`] when the accept fails, or
/// [`SetupOutcome::NonLoopback`] for a non-loopback peer (the US-018 AC2/AC5
/// loopback-only contract binds the calibration instruments too).
pub fn serve_inert_once(
    listener: &TcpListener,
    bounds: &InertBounds,
) -> Result<InertSession, SetupOutcome> {
    let (mut stream, peer) = listener
        .accept()
        .map_err(|error| SetupOutcome::SocketFailed(format!("{:?}", error.kind())))?;
    if !peer.ip().is_loopback() {
        return Err(SetupOutcome::NonLoopback);
    }
    Ok(drain(&mut stream, bounds))
}

/// Connects ONCE and implements no WebSocket behavior on the connection: it
/// sends no upgrade request, so no handshake can complete.
///
/// # Errors
///
/// [`SetupOutcome::NonLoopback`] for a non-loopback address, or
/// [`SetupOutcome::SocketFailed`] when the connect fails.
pub fn connect_inert_once(
    address: SocketAddr,
    bounds: &InertBounds,
) -> Result<InertSession, SetupOutcome> {
    loopback_only(&address)?;
    let mut stream = TcpStream::connect(address)
        .map_err(|error| SetupOutcome::SocketFailed(format!("{:?}", error.kind())))?;
    Ok(drain(&mut stream, bounds))
}

/// Makes the [`AGENT_PROTOCOL_ATTEMPTS`] fuzzingserver agent-protocol
/// connection attempts, speaking no WebSocket on any of them.
///
/// The attempts exist so the suite records three failed connections instead
/// of an absent agent; the control sends zero bytes on each, so none of them
/// can carry a request target.
///
/// # Errors
///
/// [`SetupOutcome::NonLoopback`] for a non-loopback address, or the first
/// [`SetupOutcome::SocketFailed`] from a failed connect.
pub fn run_inert_agent_attempts(
    address: SocketAddr,
    bounds: &InertBounds,
) -> Result<Vec<InertSession>, SetupOutcome> {
    loopback_only(&address)?;
    let mut attempts = Vec::with_capacity(AGENT_PROTOCOL_ATTEMPTS);
    for _ in 0..AGENT_PROTOCOL_ATTEMPTS {
        attempts.push(connect_inert_once(address, bounds)?);
    }
    Ok(attempts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_bounds_terminate_a_session_without_any_protocol_event() {
        // The control has no state machine to end on, so both a read budget
        // and a wall-clock deadline must be present and finite.
        let bounds = InertBounds::default();
        assert!(bounds.max_reads > 0);
        assert!(bounds.linger > Duration::ZERO);
        assert!(bounds.read_timeout > Duration::ZERO);
    }

    #[test]
    fn timeout_kinds_are_retryable_transport_loss_is_not() {
        assert!(retryable(ErrorKind::WouldBlock));
        assert!(retryable(ErrorKind::TimedOut));
        assert!(retryable(ErrorKind::Interrupted));
        assert!(!retryable(ErrorKind::ConnectionReset));
    }

    #[test]
    fn the_summary_always_states_the_no_handshake_invariant() {
        let session = InertSession {
            bytes_read: 12,
            bytes_written: 0,
            reads: 3,
            peer_eof: true,
        };
        assert_eq!(
            session.summary(),
            "bytes-read=12 bytes-written=0 reads=3 peer-eof=true handshake=none"
        );
    }
}
