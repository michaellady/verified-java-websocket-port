#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use websocket_core::{
    ClientRequestDescriptor, ConnectionConfig, ConnectionLimits, ConnectionState,
};
use websocket_testee::{
    AdapterObservation, AdapterReport, AdapterTermination, ClientFixture, EventKind, IoBoundField,
    IoBounds, IoBoundsError, IoBoundsSpec, MIN_OWNER_TURNS, ServerFixture, SetupOutcome,
    run_client_once, run_server_once,
};

const RFC_REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
const RFC_RESPONSE: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";

fn config() -> ConnectionConfig {
    ConnectionConfig::try_from(ConnectionLimits::default()).unwrap()
}

fn bounds(config: &ConnectionConfig) -> IoBounds {
    IoBounds::try_new(
        config,
        IoBoundsSpec {
            read_buffer_bytes: 1,
            max_write_chunk_bytes: 3,
            connect_timeout: Duration::from_millis(500),
            accept_timeout: Duration::from_millis(500),
            read_timeout: Duration::from_millis(500),
            write_timeout: Duration::from_millis(500),
            max_owner_turns: 10_000,
            max_report_entries: 1_024,
        },
    )
    .unwrap()
}

fn descriptor() -> ClientRequestDescriptor {
    ClientRequestDescriptor::try_new("/chat", "server.example.com").unwrap()
}

fn read_headers(stream: &mut TcpStream) -> Vec<u8> {
    let mut result = Vec::new();
    let mut byte = [0_u8; 1];
    while !result.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).unwrap();
        result.push(byte[0]);
    }
    result
}

#[test]
fn public_adapter_seam_is_available_to_external_callers() {
    let _ = std::mem::size_of::<AdapterReport>();
    let _ = std::mem::size_of::<ClientFixture>();
    let _ = std::mem::size_of::<ServerFixture>();
    let _ = std::mem::size_of::<IoBounds>();
    let _ = run_client_once;
    let _ = run_server_once;
}

#[test]
fn server_preserves_one_byte_reads_and_three_byte_write_progress() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let configuration = config();
    let server_bounds = bounds(&configuration);
    let worker = thread::spawn(move || {
        run_server_once(
            listener,
            ServerFixture {
                config: configuration,
                bounds: server_bounds,
            },
        )
    });

    let mut peer = TcpStream::connect(address).unwrap();
    for byte in RFC_REQUEST {
        peer.write_all(&[*byte]).unwrap();
    }
    peer.shutdown(Shutdown::Write).unwrap();
    let mut response = Vec::new();
    peer.read_to_end(&mut response).unwrap();
    let report = worker.join().unwrap();

    assert_eq!(response, RFC_RESPONSE);
    assert_eq!(report.setup, SetupOutcome::Connected);
    assert_eq!(report.termination, Some(AdapterTermination::PeerEof));
    assert_eq!(report.terminal_count, 1);
    assert_eq!(report.final_state, Some(ConnectionState::Closed));
    assert!(report.counters.read_calls > RFC_REQUEST.len() as u64);
    assert_eq!(report.counters.bytes_read, RFC_REQUEST.len() as u64);
    assert!(report.counters.write_calls > 1);
    assert!(report.counters.partial_writes > 1);
    assert!(
        report
            .observations
            .contains(&AdapterObservation::Event(EventKind::ServerHandshakeOpened))
    );
}

#[test]
fn client_uses_exact_descriptor_nonce_and_chunked_owner_write() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let peer = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_headers(&mut stream);
        assert_eq!(request, RFC_REQUEST);
        for chunk in RFC_RESPONSE.chunks(2) {
            stream.write_all(chunk).unwrap();
        }
        stream.shutdown(Shutdown::Write).unwrap();
        let mut discarded = Vec::new();
        let _ = stream.read_to_end(&mut discarded);
    });

    let configuration = config();
    let client_bounds = bounds(&configuration);
    let report = run_client_once(ClientFixture {
        address,
        config: configuration,
        descriptor: descriptor(),
        nonce: *b"the sample nonce",
        bounds: client_bounds,
    });
    peer.join().unwrap();

    assert_eq!(report.setup, SetupOutcome::Connected);
    assert_eq!(report.termination, Some(AdapterTermination::PeerEof));
    assert_eq!(report.terminal_count, 1);
    assert_eq!(report.final_state, Some(ConnectionState::Closed));
    assert!(report.counters.write_calls > 1);
    assert!(report.counters.read_calls > 1);
    assert!(
        report
            .observations
            .contains(&AdapterObservation::Event(EventKind::ClientHandshakeOpened))
    );
}

#[test]
fn failed_connect_and_accept_deadline_are_typed_setup_results() {
    let unused = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = unused.local_addr().unwrap();
    drop(unused);
    let configuration = config();
    let client_bounds = bounds(&configuration);
    let client = run_client_once(ClientFixture {
        address,
        config: configuration,
        descriptor: descriptor(),
        nonce: *b"the sample nonce",
        bounds: client_bounds,
    });
    assert!(matches!(client.setup, SetupOutcome::ConnectFailed(_)));
    assert_eq!(client.final_state, None);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let configuration = config();
    let server_bounds = IoBounds::try_new(
        &configuration,
        IoBoundsSpec {
            accept_timeout: Duration::from_millis(10),
            ..IoBoundsSpec::default()
        },
    )
    .unwrap();
    let server = run_server_once(
        listener,
        ServerFixture {
            config: configuration,
            bounds: server_bounds,
        },
    );
    assert_eq!(server.setup, SetupOutcome::AcceptTimeout);
    assert_eq!(server.final_state, None);
}

#[test]
fn stalled_peer_becomes_one_shutdown_and_one_terminal() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let peer = thread::spawn(move || {
        let _stream = TcpStream::connect(address).unwrap();
        thread::sleep(Duration::from_millis(100));
    });
    let configuration = config();
    let server_bounds = IoBounds::try_new(
        &configuration,
        IoBoundsSpec {
            read_timeout: Duration::from_millis(10),
            ..IoBoundsSpec::default()
        },
    )
    .unwrap();
    let report = run_server_once(
        listener,
        ServerFixture {
            config: configuration,
            bounds: server_bounds,
        },
    );
    peer.join().unwrap();

    assert_eq!(report.termination, Some(AdapterTermination::ReadTimeout));
    assert_eq!(report.counters.read_timeouts, 1);
    assert_eq!(report.counters.shutdown_inputs, 1);
    assert_eq!(report.terminal_count, 1);
}

#[test]
fn bounds_reject_every_zero_and_plus_one_ceiling() {
    let configuration = config();
    let total = configuration.limits().total_buffered_bytes as usize;
    for (field, spec) in [
        (
            IoBoundField::ReadBufferBytes,
            IoBoundsSpec {
                read_buffer_bytes: 0,
                ..IoBoundsSpec::default()
            },
        ),
        (
            IoBoundField::MaxWriteChunkBytes,
            IoBoundsSpec {
                max_write_chunk_bytes: 0,
                ..IoBoundsSpec::default()
            },
        ),
        (
            IoBoundField::ConnectTimeout,
            IoBoundsSpec {
                connect_timeout: Duration::ZERO,
                ..IoBoundsSpec::default()
            },
        ),
        (
            IoBoundField::AcceptTimeout,
            IoBoundsSpec {
                accept_timeout: Duration::ZERO,
                ..IoBoundsSpec::default()
            },
        ),
        (
            IoBoundField::ReadTimeout,
            IoBoundsSpec {
                read_timeout: Duration::ZERO,
                ..IoBoundsSpec::default()
            },
        ),
        (
            IoBoundField::WriteTimeout,
            IoBoundsSpec {
                write_timeout: Duration::ZERO,
                ..IoBoundsSpec::default()
            },
        ),
        (
            IoBoundField::MaxOwnerTurns,
            IoBoundsSpec {
                max_owner_turns: 0,
                ..IoBoundsSpec::default()
            },
        ),
        (
            IoBoundField::MaxReportEntries,
            IoBoundsSpec {
                max_report_entries: 0,
                ..IoBoundsSpec::default()
            },
        ),
    ] {
        assert_eq!(
            IoBounds::try_new(&configuration, spec),
            Err(IoBoundsError::Zero(field))
        );
    }
    assert!(matches!(
        IoBounds::try_new(
            &configuration,
            IoBoundsSpec {
                read_buffer_bytes: total + 1,
                ..IoBoundsSpec::default()
            }
        ),
        Err(IoBoundsError::ExceedsMaximum {
            field: IoBoundField::ReadBufferBytes,
            ..
        })
    ));
    assert_eq!(
        IoBounds::try_new(
            &configuration,
            IoBoundsSpec {
                max_owner_turns: MIN_OWNER_TURNS - 1,
                ..IoBoundsSpec::default()
            }
        ),
        Err(IoBoundsError::BelowMinimum {
            field: IoBoundField::MaxOwnerTurns,
            attempted: u128::from(MIN_OWNER_TURNS - 1),
            minimum: u128::from(MIN_OWNER_TURNS),
        })
    );
    assert!(matches!(
        IoBounds::try_new(
            &configuration,
            IoBoundsSpec {
                max_report_entries: 4_097,
                ..IoBoundsSpec::default()
            }
        ),
        Err(IoBoundsError::ExceedsMaximum {
            field: IoBoundField::MaxReportEntries,
            ..
        })
    ));
}

#[test]
fn report_exhaustion_stops_observations_and_drains_once_to_terminal() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let peer = thread::spawn(move || {
        let mut stream = TcpStream::connect(address).unwrap();
        stream.write_all(RFC_REQUEST).unwrap();
        let _ = stream.shutdown(Shutdown::Write);
        let mut discarded = Vec::new();
        let _ = stream.read_to_end(&mut discarded);
    });
    let configuration = config();
    let total_owner_turns = MIN_OWNER_TURNS + 4;
    let limited = IoBounds::try_new(
        &configuration,
        IoBoundsSpec {
            max_report_entries: 1,
            max_owner_turns: total_owner_turns,
            ..IoBoundsSpec::default()
        },
    )
    .unwrap();
    let report = run_server_once(
        listener,
        ServerFixture {
            config: configuration,
            bounds: limited,
        },
    );
    peer.join().unwrap();
    assert_eq!(report.termination, Some(AdapterTermination::ReportLimit));
    assert_eq!(report.observations.len(), 1);

    assert_eq!(report.counters.shutdown_inputs, 1);
    assert_eq!(report.terminal_count, 1);
    assert!(report.counters.owner_turns <= total_owner_turns);
}

#[test]
fn owner_turn_exhaustion_uses_bounded_reserved_turns_to_reach_one_terminal() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let peer = thread::spawn(move || {
        let _stream = listener.accept().unwrap().0;
    });
    let configuration = config();
    let limited = IoBounds::try_new(
        &configuration,
        IoBoundsSpec {
            max_owner_turns: MIN_OWNER_TURNS,
            ..IoBoundsSpec::default()
        },
    )
    .unwrap();
    let report = run_client_once(ClientFixture {
        address,
        config: configuration,
        descriptor: descriptor(),
        nonce: *b"the sample nonce",
        bounds: limited,
    });
    peer.join().unwrap();
    assert_eq!(report.termination, Some(AdapterTermination::OwnerTurnLimit));
    assert_eq!(report.counters.shutdown_inputs, 1);
    assert_eq!(report.terminal_count, 1);
    assert!(report.counters.owner_turns > 1);
    assert!(report.counters.owner_turns <= MIN_OWNER_TURNS);
}
