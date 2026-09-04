//! The loopback Rust CLIENT adapter (US-018): connect, real `ws_core`
//! client opening handshake, one scripted echo round-trip, clean local
//! close, terminal.

use std::net::{SocketAddr, TcpStream};

use ws_core::{CommandSender, ConnectionConfig, LocalCommand, Role, SemanticEvent};
use ws_driver::connection_driver;

use crate::io_loop::{
    ConnectionReport, EventPolicy, IoBounds, drive_connection_from, drive_until_open, empty_report,
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
    /// Optional scripted ping payload sent alongside the text (US-018 AC4
    /// control integration). When set, the script also waits for a pong
    /// before initiating the clean close — so it is only meaningful against
    /// peers whose adapter layer answers pings (shipped Java's
    /// `WebSocketImpl` default does; the ported core itself never replies
    /// on its own, Q18).
    pub ping: Option<Vec<u8>>,
    /// Bounded I/O parameters.
    pub bounds: IoBounds,
}

/// Scripted client policy: once the echoed text has arrived — and, when a
/// ping was scripted, a pong as well — initiate the clean close (1000).
/// Pure adapter routing — the close semantics (Q13/Q14, echo, transitions)
/// all stay in the core.
struct ClientScript {
    expected: String,
    await_pong: bool,
    echo_seen: bool,
    pong_seen: bool,
    close_sent: bool,
}

impl ClientScript {
    fn maybe_close(&mut self, sender: &CommandSender) {
        if self.close_sent || !self.echo_seen || (self.await_pong && !self.pong_seen) {
            return;
        }
        self.close_sent = true;
        let _ = sender.try_send(LocalCommand::SendClose {
            code: 1000,
            reason: "done".to_owned(),
        });
    }
}

impl EventPolicy for ClientScript {
    fn on_event(&mut self, event: &SemanticEvent, sender: &CommandSender) {
        match &event.kind {
            ws_core::SemanticEventKind::Text { text } if *text == self.expected => {
                self.echo_seen = true;
            }
            ws_core::SemanticEventKind::Pong { .. } => {
                self.pong_seen = true;
            }
            _ => {}
        }
        self.maybe_close(sender);
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
    let handshake = drive_until_open(&mut driver, &mut stream, &fixture.bounds, &mut report);
    if !handshake.opened {
        return Ok(report);
    }
    // Scripted sends through the SAME bounded producer handle any thread
    // would use.
    if let Some(data) = &fixture.ping {
        let _ = sender.try_send(LocalCommand::SendPing { data: data.clone() });
    }
    let _ = sender.try_send(LocalCommand::SendText {
        text: fixture.message.to_owned(),
    });
    let mut policy = ClientScript {
        expected: fixture.message.to_owned(),
        await_pong: fixture.ping.is_some(),
        echo_seen: false,
        pong_seen: false,
        close_sent: false,
    };
    drive_connection_from(
        &mut driver,
        &sender,
        &mut stream,
        &fixture.bounds,
        Role::Client,
        &mut policy,
        &mut report,
        handshake.carryover,
    );
    Ok(report)
}
