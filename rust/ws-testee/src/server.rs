//! The loopback Rust SERVER adapter (US-018): accept one connection, real
//! `ws_core` server opening handshake, echo every delivered message, let
//! the core run the close handshake, terminal on EOF.

use std::net::TcpListener;
use std::time::{SystemTime, UNIX_EPOCH};

use ws_core::{ConnectionConfig, Role};
use ws_driver::connection_driver;

use crate::SetupOutcome;
use crate::io_loop::{
    ConnectionReport, EchoPolicy, IoBounds, drive_connection_from, drive_until_open, empty_report,
};

/// One server run's parameters (the caller owns the bound listener so
/// tests can use an ephemeral port).
#[derive(Debug, Clone)]
pub struct ServerFixture {
    /// Connection configuration (protocol limits live in the core).
    pub config: ConnectionConfig,
    /// Bounded I/O parameters.
    pub bounds: IoBounds,
}

/// The wall clock, as a Unix epoch second, for the 101 response's `Date`
/// field.
///
/// This is the adapter's job, not the core's: `ws-core` is dependency-free
/// and clockless by design, and Java's own clock read sits in the library
/// (`Draft_6455.java:818-824` calls `Calendar.getInstance()`). The port
/// keeps the read here and hands the core a value.
///
/// A clock before 1970 (only reachable if the host clock is set that way)
/// yields a negative epoch second, which
/// [`ws_core::handshake::server::java_server_time`] formats correctly; the
/// saturating conversion only bounds the absurd, and never panics.
fn server_date_epoch_seconds() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(since) => i64::try_from(since.as_secs()).unwrap_or(i64::MAX),
        Err(before) => {
            i64::try_from(before.duration().as_secs()).map_or(i64::MIN, |seconds| -seconds)
        }
    }
}

/// Sequentially accepts and serves `sessions` connections on ONE bound
/// listener (E5 Autobahn fuzzingclient wiring: the fuzzer opens one fresh
/// connection per case, strictly sequentially, so the listener must stay
/// bound between sessions with no accept gap). Each session is a full
/// [`run_server_once`] echo run; `on_report` observes every session's
/// report in order (1-based index) as it completes.
///
/// # Errors
///
/// The first [`SetupOutcome`] (accept failure / non-loopback peer) ends
/// the run early; sessions already served have been reported.
pub fn run_server_sessions(
    listener: &TcpListener,
    fixture: &ServerFixture,
    sessions: u64,
    on_report: &mut dyn FnMut(u64, &ConnectionReport),
) -> Result<(), SetupOutcome> {
    for index in 1..=sessions {
        let report = run_server_once(listener, fixture)?;
        on_report(index, &report);
    }
    Ok(())
}

/// Accepts and runs ONE loopback connection to its terminal outcome.
///
/// # Errors
///
/// [`SetupOutcome`] when the accept fails; every post-setup condition is
/// reported inside the [`ConnectionReport`].
pub fn run_server_once(
    listener: &TcpListener,
    fixture: &ServerFixture,
) -> Result<ConnectionReport, SetupOutcome> {
    let (mut stream, peer) = listener
        .accept()
        .map_err(|error| SetupOutcome::SocketFailed(format!("{:?}", error.kind())))?;
    if !peer.ip().is_loopback() {
        return Err(SetupOutcome::NonLoopback);
    }
    // THE one clock read on the server path. Java reads its wall clock once
    // per handshake, inside postProcessHandshakeResponseAsServer
    // (Draft_6455.java:450 -> getServerTime, :818-824), so this is read per
    // ACCEPTED CONNECTION and not once per fixture: a server that stamped
    // one instant onto every connection's `Date` would not be faithful, and
    // `fixture.config` outlives every session on this listener.
    let config = fixture
        .config
        .clone()
        .with_server_date_epoch_seconds(server_date_epoch_seconds());
    let (sender, mut driver) = connection_driver(config, Role::Server);
    let mut report = empty_report();
    let handshake = drive_until_open(&mut driver, &mut stream, &fixture.bounds, &mut report);
    if !handshake.opened {
        return Ok(report);
    }
    let mut policy = EchoPolicy;
    drive_connection_from(
        &mut driver,
        &sender,
        &mut stream,
        &fixture.bounds,
        Role::Server,
        &mut policy,
        &mut report,
        handshake.carryover,
    );
    Ok(report)
}
