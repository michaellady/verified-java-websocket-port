//! The loopback Rust SERVER adapter (US-018): accept one connection, real
//! `ws_core` server opening handshake, echo every delivered message, let
//! the core run the close handshake, terminal on EOF.

use std::net::TcpListener;

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
    let (sender, mut driver) = connection_driver(fixture.config.clone(), Role::Server);
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
        &mut policy,
        &mut report,
        handshake.carryover,
    );
    Ok(report)
}
