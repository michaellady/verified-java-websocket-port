use std::io::ErrorKind;
use std::net::{TcpListener, TcpStream};
use std::thread::sleep;
use std::time::{Duration, Instant};

use websocket_core::Role;
use websocket_driver::connection_driver;

use crate::io_loop::{drive_connected, socket_error_kind};
use crate::{AdapterReport, ServerFixture, SetupOutcome};

const ACCEPT_BACKOFF: Duration = Duration::from_millis(1);

/// Accepts one connection from a pre-bound loopback listener and drives one owner.
#[must_use]
pub fn run_server_once(listener: TcpListener, fixture: ServerFixture) -> AdapterReport {
    if let Err(error) = fixture.bounds.validate_for(&fixture.config) {
        return AdapterReport::setup_failure(Role::Server, SetupOutcome::InvalidBounds(error));
    }
    let local = match listener.local_addr() {
        Ok(address) => address,
        Err(error) => {
            return AdapterReport::setup_failure(
                Role::Server,
                SetupOutcome::AcceptFailed(socket_error_kind(&error)),
            );
        }
    };
    if !local.ip().is_loopback() {
        return AdapterReport::setup_failure(Role::Server, SetupOutcome::NonLoopback);
    }
    if let Err(error) = listener.set_nonblocking(true) {
        return AdapterReport::setup_failure(
            Role::Server,
            SetupOutcome::SocketConfigurationFailed(socket_error_kind(&error)),
        );
    }

    let stream = match accept_once(&listener, fixture.bounds.spec.accept_timeout) {
        Ok(stream) => stream,
        Err(SetupOutcome::AcceptTimeout) => {
            return AdapterReport::setup_failure(Role::Server, SetupOutcome::AcceptTimeout);
        }
        Err(other) => return AdapterReport::setup_failure(Role::Server, other),
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
        return AdapterReport::setup_failure(Role::Server, SetupOutcome::NonLoopback);
    }
    if let Err(error) = stream.set_nonblocking(false) {
        return AdapterReport::setup_failure(
            Role::Server,
            SetupOutcome::SocketConfigurationFailed(socket_error_kind(&error)),
        );
    }

    let (handle, owner) = connection_driver(fixture.config, Role::Server);
    drive_connected(stream, handle, owner, fixture.bounds, Role::Server)
}

fn accept_once(listener: &TcpListener, timeout: Duration) -> Result<TcpStream, SetupOutcome> {
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Ok(stream),
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(SetupOutcome::AcceptTimeout);
                }
                sleep(remaining.min(ACCEPT_BACKOFF));
            }
            Err(error) => {
                return Err(SetupOutcome::AcceptFailed(socket_error_kind(&error)));
            }
        }
        if Instant::now() >= deadline {
            return Err(SetupOutcome::AcceptTimeout);
        }
    }
}
