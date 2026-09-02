//! The loopback Rust SERVER adapter (US-018): accept one connection, real
//! `ws_core` server opening handshake, echo every delivered message, let
//! the core run the close handshake, terminal on EOF.

use std::net::TcpListener;

use ws_core::{CommandSender, ConnectionConfig, LocalCommand, Role, SemanticEvent};
use ws_driver::connection_driver;

use crate::SetupOutcome;
use crate::io_loop::{
    ConnectionReport, EventPolicy, IoBounds, drive_connection, drive_until_open, empty_report,
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

/// Echo policy: every delivered text/binary message is re-sent through the
/// bounded command handle. Control and close behavior is deliberately NOT
/// mirrored here — the core owns it (no adapter-side protocol, US-018 AC1).
struct EchoPolicy;

impl EventPolicy for EchoPolicy {
    fn on_event(&mut self, event: &SemanticEvent, sender: &CommandSender) {
        match &event.kind {
            ws_core::SemanticEventKind::Text { text } => {
                let _ = sender.try_send(LocalCommand::SendText { text: text.clone() });
            }
            ws_core::SemanticEventKind::Binary { data } => {
                let _ = sender.try_send(LocalCommand::SendBinary { data: data.clone() });
            }
            _ => {}
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
    let (sender, mut driver) = connection_driver(fixture.config.clone(), Role::Server);
    let mut report = empty_report();
    if !drive_until_open(&mut driver, &mut stream, &fixture.bounds, &mut report) {
        return Ok(report);
    }
    let mut policy = EchoPolicy;
    drive_connection(
        &mut driver,
        &sender,
        &mut stream,
        &fixture.bounds,
        Role::Server,
        &mut policy,
        &mut report,
    );
    Ok(report)
}
