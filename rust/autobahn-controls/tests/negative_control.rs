//! US-019 AC4 negative control: the empty/stub Rust target must never
//! complete a WebSocket opening handshake, in EITHER Autobahn role.
//!
//! The peers in these tests are the real shipped `ws_core` + `ws_driver`
//! stack (through `ws_testee`'s public adapters and I/O loop) — never the
//! control's own code — so a passing assertion is a statement about what a
//! genuine WebSocket peer observes when it is pointed at the control.
//!
//! Every wait here is bounded twice over: the control's own
//! [`InertBounds`] deadline, and the probing peer's [`IoBounds::max_polls`]
//! budget at a millisecond-scale read timeout. Nothing in this file can
//! block for more than a few seconds even if every assertion is wrong.

use std::io::Read;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use autobahn_controls::inert::{
    InertBounds, InertSession, connect_inert_once, run_inert_agent_attempts, serve_inert_once,
};
use ws_core::close::NEVER_CONNECTED_CLOSE_CODE;
use ws_core::{ReadyState, Role};
use ws_driver::connection_driver;
use ws_testee::io_loop::{IoBounds, drive_until_open, empty_report};
use ws_testee::{ServerFixture, SetupOutcome, autobahn_config, run_server_once};

/// Tight bounds for the control under test: a session may linger for at most
/// 150 ms, so no test can wait on it for longer than that.
fn inert_bounds() -> InertBounds {
    InertBounds {
        read_timeout: Duration::from_millis(2),
        linger: Duration::from_millis(150),
        max_reads: 128,
        read_buffer: 4096,
    }
}

/// Bounds for the REAL peer probing the control. Larger than the control's
/// linger so the control is always the side that hangs up first.
fn peer_bounds() -> IoBounds {
    IoBounds {
        read_timeout: Duration::from_millis(2),
        write_timeout: Duration::from_millis(2),
        max_polls: 4_000,
        ..IoBounds::default()
    }
}

/// Accepts `count` raw connections and records how many bytes each peer sent
/// before hanging up. Used to prove the control emits NO handshake bytes.
fn raw_listener_sessions(count: usize) -> (SocketAddr, thread::JoinHandle<Vec<usize>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let address = listener.local_addr().expect("bound address");
    let handle = thread::spawn(move || {
        let mut totals = Vec::with_capacity(count);
        for _ in 0..count {
            let (mut stream, _peer) = listener.accept().expect("raw accept");
            stream
                .set_read_timeout(Some(Duration::from_millis(2)))
                .expect("read timeout");
            let mut buffer = [0u8; 4096];
            let mut total = 0usize;
            for _ in 0..256 {
                match stream.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(read) => total += read,
                    Err(_) => {}
                }
            }
            let _ = stream.shutdown(Shutdown::Both);
            totals.push(total);
        }
        totals
    });
    (address, handle)
}

#[test]
fn a_real_ws_core_client_never_opens_against_the_inert_server() {
    // fuzzingclient-mode shape: Autobahn connects OUT to the testee. Here a
    // real `ws_core` CLIENT plays the suite's part.
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let address = listener.local_addr().expect("bound address");
    let control = thread::spawn(move || {
        serve_inert_once(&listener, &inert_bounds()).expect("inert control accept")
    });

    let mut stream = TcpStream::connect(address).expect("connect to the inert control");
    let (_sender, mut driver) = connection_driver(autobahn_config(), Role::Client);
    driver
        .begin_client_handshake("/runCase?case=1&agent=probe", "localhost")
        .expect("client handshake start");
    let mut report = empty_report();
    let handshake = drive_until_open(&mut driver, &mut stream, &peer_bounds(), &mut report);
    let _ = stream.shutdown(Shutdown::Both);
    let session: InertSession = control.join().expect("control thread");

    assert!(
        !handshake.opened,
        "the negative control must never complete an opening handshake: {}",
        report.summary()
    );
    assert_ne!(
        driver.state(),
        ReadyState::Open,
        "the peer never reached Open"
    );
    // The peer's own governing close states the invariant in the shipped
    // Java vocabulary: the transport ended (origin Transport, quirk Q20)
    // with `handshake_complete` FALSE, reported as
    // `CloseFrame.NEVER_CONNECTED` (-1) — the code Java reports when the
    // connection died before the opening handshake ever completed.
    let close = driver.close_detail().expect("governing close");
    assert!(
        !close.handshake_complete,
        "the opening handshake must never have completed: {close:?}"
    );
    assert_eq!(close.code, NEVER_CONNECTED_CLOSE_CODE);
    assert_eq!(close.origin.wire_name(), "transport");
    assert!(
        report.texts.is_empty() && report.binaries.is_empty(),
        "no message can be delivered through a handshake that never happened"
    );
    assert!(
        session.bytes_read > 0,
        "the control did accept the connection and read the peer's upgrade request"
    );
    assert_eq!(
        session.bytes_written, 0,
        "the control has no write path at all: it answers nothing"
    );
}

#[test]
fn the_real_ws_testee_server_never_opens_against_the_inert_client() {
    // fuzzingserver-mode shape: the suite LISTENS and the testee dials out.
    // Here the shipped `ws_testee` SERVER plays the suite's part.
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let address = listener.local_addr().expect("bound address");
    let peer = thread::spawn(move || {
        let fixture = ServerFixture {
            config: autobahn_config(),
            bounds: peer_bounds(),
        };
        run_server_once(&listener, &fixture).expect("peer server setup")
    });

    let session = connect_inert_once(address, &inert_bounds()).expect("inert control connect");
    let report = peer.join().expect("peer thread");

    assert_eq!(
        session.bytes_written, 0,
        "the inert client sends no upgrade request at all"
    );
    assert!(
        !report.clean(),
        "a real server peer cannot reach a clean terminal outcome against the inert client: {}",
        report.summary()
    );
    assert!(
        report.texts.is_empty() && report.binaries.is_empty(),
        "nothing is exchanged: {}",
        report.summary()
    );
    assert_eq!(report.terminals, 0, "no connection was ever established");
}

#[test]
fn the_inert_client_makes_the_three_agent_protocol_attempts_and_sends_nothing() {
    // The suite must RECORD three failures rather than simply see nothing,
    // so the control still opens the three connections the fuzzingserver
    // agent protocol expects — while speaking no WebSocket on any of them.
    let (address, server) = raw_listener_sessions(3);
    let attempts = run_inert_agent_attempts(address, &inert_bounds()).expect("inert agent run");
    let received = server.join().expect("raw listener thread");

    assert_eq!(
        attempts.len(),
        3,
        "three agent-protocol connection attempts"
    );
    assert_eq!(
        received,
        vec![0, 0, 0],
        "every attempt sent ZERO bytes: no handshake, no framing"
    );
    for attempt in &attempts {
        assert_eq!(attempt.bytes_written, 0, "the control writes nothing");
    }
}

#[test]
fn the_inert_control_honours_the_loopback_only_contract() {
    // The US-018 AC2/AC5 loopback-only contract binds the calibration
    // instruments too; the Autobahn container is reached through a
    // loopback-published port, never a routable address.
    let address: SocketAddr = "203.0.113.7:9001".parse().expect("test address");
    assert_eq!(
        connect_inert_once(address, &inert_bounds()).unwrap_err(),
        SetupOutcome::NonLoopback
    );
    assert_eq!(
        run_inert_agent_attempts(address, &inert_bounds()).unwrap_err(),
        SetupOutcome::NonLoopback
    );
}
