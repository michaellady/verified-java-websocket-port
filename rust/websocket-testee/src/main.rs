#![forbid(unsafe_code)]

use std::env::args;
use std::io::ErrorKind;
use std::net::{SocketAddr, TcpListener};
use std::process::exit;
use std::time::Duration;

use websocket_core::{ClientRequestDescriptor, ConnectionConfig, ConnectionLimits, Role};
use websocket_testee::{
    AdapterCounters, AdapterReport, ClientFixture, IoBounds, IoBoundsSpec, ServerFixture,
    SetupOutcome, SocketErrorKind, run_client_once, run_server_once,
};

const USAGE_EXIT: i32 = 2;

fn main() {
    let arguments: Vec<String> = args().collect();
    let result = match arguments.get(1).map(String::as_str) {
        Some("client") => client(&arguments[2..]),
        Some("server") => server(&arguments[2..]),
        _ => Err(USAGE_EXIT),
    };
    match result {
        Ok(report) => {
            println!("{}", report.summary());
            exit(i32::from(report.exit_code()));
        }
        Err(code) => {
            eprintln!("usage-error");
            exit(code);
        }
    }
}

fn client(arguments: &[String]) -> Result<AdapterReport, i32> {
    if arguments.len() != 12 {
        return Err(USAGE_EXIT);
    }
    let address = parse_address(&arguments[0])?;
    let descriptor =
        ClientRequestDescriptor::try_new(&arguments[1], &arguments[2]).map_err(|_| USAGE_EXIT)?;
    let nonce = parse_nonce(&arguments[3])?;
    let config = default_config()?;
    let bounds = parse_bounds(&config, &arguments[4..])?;
    Ok(run_client_once(ClientFixture {
        address,
        config,
        descriptor,
        nonce,
        bounds,
    }))
}

fn server(arguments: &[String]) -> Result<AdapterReport, i32> {
    if arguments.len() != 9 {
        return Err(USAGE_EXIT);
    }
    let address = parse_address(&arguments[0])?;
    if !address.ip().is_loopback() {
        return Ok(setup_report(Role::Server, SetupOutcome::NonLoopback));
    }
    let config = default_config()?;
    let bounds = parse_bounds(&config, &arguments[1..])?;
    let listener = match TcpListener::bind(address) {
        Ok(listener) => listener,
        Err(error) => {
            return Ok(setup_report(
                Role::Server,
                SetupOutcome::BindFailed(normalize_socket_error(error.kind())),
            ));
        }
    };
    Ok(run_server_once(listener, ServerFixture { config, bounds }))
}

fn default_config() -> Result<ConnectionConfig, i32> {
    ConnectionConfig::try_from(ConnectionLimits::default()).map_err(|_| USAGE_EXIT)
}

fn parse_address(value: &str) -> Result<SocketAddr, i32> {
    value.parse().map_err(|_| USAGE_EXIT)
}

fn parse_bounds(config: &ConnectionConfig, values: &[String]) -> Result<IoBounds, i32> {
    if values.len() != 8 {
        return Err(USAGE_EXIT);
    }
    let spec = IoBoundsSpec {
        read_buffer_bytes: parse_number(&values[0])?,
        max_write_chunk_bytes: parse_number(&values[1])?,
        connect_timeout: Duration::from_millis(parse_number(&values[2])?),
        accept_timeout: Duration::from_millis(parse_number(&values[3])?),
        read_timeout: Duration::from_millis(parse_number(&values[4])?),
        write_timeout: Duration::from_millis(parse_number(&values[5])?),
        max_owner_turns: parse_number(&values[6])?,
        max_report_entries: parse_number(&values[7])?,
    };
    IoBounds::try_new(config, spec).map_err(|_| USAGE_EXIT)
}

fn parse_number<T: core::str::FromStr>(value: &str) -> Result<T, i32> {
    value.parse().map_err(|_| USAGE_EXIT)
}

fn parse_nonce(value: &str) -> Result<[u8; 16], i32> {
    if value.len() != 32 || !value.is_ascii() {
        return Err(USAGE_EXIT);
    }
    let mut nonce = [0_u8; 16];
    for (slot, pair) in nonce.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let high = hex_digit(pair[0]).ok_or(USAGE_EXIT)?;
        let low = hex_digit(pair[1]).ok_or(USAGE_EXIT)?;
        *slot = (high << 4) | low;
    }
    Ok(nonce)
}

fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn setup_report(role: Role, setup: SetupOutcome) -> AdapterReport {
    AdapterReport {
        role,
        setup,
        termination: None,
        observations: Vec::new(),
        counters: AdapterCounters::default(),
        final_state: None,
        terminal_count: 0,
    }
}

fn normalize_socket_error(kind: ErrorKind) -> SocketErrorKind {
    match kind {
        ErrorKind::ConnectionRefused => SocketErrorKind::ConnectionRefused,
        ErrorKind::ConnectionReset => SocketErrorKind::ConnectionReset,
        ErrorKind::BrokenPipe => SocketErrorKind::BrokenPipe,
        ErrorKind::TimedOut => SocketErrorKind::TimedOut,
        ErrorKind::WouldBlock => SocketErrorKind::WouldBlock,
        ErrorKind::NotConnected => SocketErrorKind::NotConnected,
        _ => SocketErrorKind::Other,
    }
}
