use std::io::{Error, ErrorKind, Result as IoResult};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use websocket_core::{LocalCommand, Role};
use websocket_driver::connection_driver;

use crate::io_loop::{drive_connected, socket_error_kind};
use crate::{AdapterReport, ClientFixture, SetupOutcome};

/// Connects once to a numeric loopback peer and drives the exact sole owner.
#[must_use]
pub fn run_client_once(fixture: ClientFixture) -> AdapterReport {
    if let Err(error) = fixture.bounds.validate_for(&fixture.config) {
        return AdapterReport::setup_failure(Role::Client, SetupOutcome::InvalidBounds(error));
    }
    if !fixture.address.ip().is_loopback() {
        return AdapterReport::setup_failure(Role::Client, SetupOutcome::NonLoopback);
    }
    let stream = match connect_once(fixture.address, fixture.bounds.spec.connect_timeout) {
        Ok(stream) => stream,
        Err(error) => {
            return AdapterReport::setup_failure(
                Role::Client,
                SetupOutcome::ConnectFailed(socket_error_kind(&error)),
            );
        }
    };
    let addresses_are_loopback = stream
        .local_addr()
        .map(|address| address.ip().is_loopback())
        .unwrap_or(false)
        && stream
            .peer_addr()
            .map(|address| address.ip().is_loopback())
            .unwrap_or(false);
    if !addresses_are_loopback {
        return AdapterReport::setup_failure(Role::Client, SetupOutcome::NonLoopback);
    }
    if let Err(error) = stream.set_nonblocking(false) {
        return AdapterReport::setup_failure(
            Role::Client,
            SetupOutcome::SocketConfigurationFailed(socket_error_kind(&error)),
        );
    }

    let (handle, owner) = connection_driver(fixture.config, Role::Client);
    if handle
        .try_enqueue(LocalCommand::StartClientHandshake {
            descriptor: fixture.descriptor,
            nonce: fixture.nonce,
        })
        .is_err()
    {
        return AdapterReport::setup_failure(Role::Client, SetupOutcome::ClientCommandRejected);
    }
    drive_connected(stream, handle, owner, fixture.bounds, Role::Client)
}

fn connect_once(address: SocketAddr, timeout: Duration) -> IoResult<TcpStream> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Error::from(ErrorKind::TimedOut));
        }
        match TcpStream::connect_timeout(&address, remaining) {
            Err(error) if error.kind() == ErrorKind::Interrupted && Instant::now() < deadline => {}
            result => return result,
        }
    }
}
