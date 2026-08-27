//! The loopback Rust CLIENT adapter (US-018): connect, real `ws_core`
//! client opening handshake, one scripted echo round-trip, clean local
//! close, terminal.

use std::net::{SocketAddr, TcpStream};

use ws_core::{CommandSender, ConnectionConfig, LocalCommand, Role, SemanticEvent};
use ws_driver::connection_driver;

use crate::io_loop::{
    ConnectionReport, EventPolicy, IoBounds, drive_connection, drive_until_open, empty_report,
};
use crate::{SetupOutcome, loopback_only};

/// One client run's parameters.
#[derive(Debug, Clone)]
pub struct ClientFixture<'a> {
    /// Loopback server address.
    pub address: SocketAddr,
    /// Connection configuration (protocol limits live in the core).
    pub config: ConnectionConfig,
    /// HTTP request target for the upgrade request.
    pub request_target: &'a str,
    /// Host header value.
    pub host: &'a str,
    /// The text message to send and expect echoed.
    pub message: &'a str,
    /// Bounded I/O parameters.
    pub bounds: IoBounds,
}

/// Scripted client policy: after the echoed text arrives, initiate the
/// clean close (1000). Pure adapter routing — the close semantics
/// (Q13/Q14, echo, transitions) all stay in the core.
struct ClientScript {
    expected: String,
    close_sent: bool,
}

impl EventPolicy for ClientScript {
    fn on_event(&mut self, event: &SemanticEvent, sender: &CommandSender) {
        if self.close_sent {
            return;
        }
        if let ws_core::SemanticEventKind::Text { text } = &event.kind
            && *text == self.expected
        {
            self.close_sent = true;
            let _ = sender.try_send(LocalCommand::SendClose {
                code: 1000,
                reason: "done".to_owned(),
            });
        }
    }
}

/// Runs one loopback client connection to its terminal outcome.
///
/// # Errors
///
/// [`SetupOutcome`] when the address is non-loopback or the connect fails;
/// every post-setup condition is reported inside the [`ConnectionReport`].
pub fn run_client_once(fixture: &ClientFixture<'_>) -> Result<ConnectionReport, SetupOutcome> {
    loopback_only(&fixture.address)?;
    let mut stream = TcpStream::connect(fixture.address)
        .map_err(|error| SetupOutcome::SocketFailed(format!("{:?}", error.kind())))?;
    let (sender, mut driver) = connection_driver(fixture.config.clone(), Role::Client);
    let mut report = empty_report();
    if let Err(failure) = driver.begin_client_handshake(fixture.request_target, fixture.host) {
        report.outcome = crate::io_loop::LoopOutcome::ProtocolFailure(failure);
        return Ok(report);
    }
    if !drive_until_open(&mut driver, &mut stream, &fixture.bounds, &mut report) {
        return Ok(report);
    }
    // Scripted send through the SAME bounded producer handle any thread
    // would use.
    let _ = sender.try_send(LocalCommand::SendText {
        text: fixture.message.to_owned(),
    });
    let mut policy = ClientScript {
        expected: fixture.message.to_owned(),
        close_sent: false,
    };
    drive_connection(
        &mut driver,
        &sender,
        &mut stream,
        &fixture.bounds,
        &mut policy,
        &mut report,
    );
    Ok(report)
}
