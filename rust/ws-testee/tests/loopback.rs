//! US-018 loopback integrations: Rust client <-> Rust server over real TCP
//! sockets, driving ONLY the shipped `ws_core` + `ws_driver` behavior —
//! real opening handshakes on both roles, echo round-trip, the core-owned
//! close handshake, partial I/O, and peer loss.

use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use ws_core::ConnectionConfig;
use ws_testee::{
    ClientFixture, ConnectionReport, IoBounds, LoopOutcome, ServerFixture, SetupOutcome,
    loopback_only, run_client_once, run_server_once,
};

fn server_thread(listener: TcpListener, bounds: IoBounds) -> thread::JoinHandle<ConnectionReport> {
    thread::spawn(move || {
        let fixture = ServerFixture {
            config: ConnectionConfig::default(),
            bounds,
        };
        run_server_once(&listener, &fixture).expect("server setup")
    })
}

fn client_fixture(
    address: std::net::SocketAddr,
    message: &str,
    bounds: IoBounds,
) -> ConnectionReport {
    let fixture = ClientFixture {
        address,
        config: ConnectionConfig::default(),
        request_target: "/chat",
        host: "localhost",
        message,
        ping: None,
        bounds,
    };
    run_client_once(&fixture).expect("client setup")
}

#[test]
fn echo_round_trip_with_clean_close() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let address = listener.local_addr().expect("bound address");
    let server = server_thread(listener, IoBounds::default());
    let client = client_fixture(address, "ping-hello", IoBounds::default());
    let server = server.join().expect("server thread");

    // Client: echoed text delivered, then the clean close handshake — the
    // server's echo close (constructor payload, Q10) completes it.
    assert!(client.clean(), "client: {}", client.summary());
    assert_eq!(client.texts, vec!["ping-hello".to_owned()]);
    let client_close = client.close.expect("client governing close");
    assert_eq!(client_close.code, 1000);
    assert!(client_close.remote, "completed by the server's echo close");

    // Server: delivered then echoed the message; EOF after the close
    // handshake carries the governing close (code 1000, reason from the
    // client's close frame) — Java's Q20 vocabulary, not an error.
    assert!(server.clean(), "server: {}", server.summary());
    assert_eq!(server.texts, vec!["ping-hello".to_owned()]);
    let server_close = server.close.expect("server governing close");
    assert_eq!(server_close.code, 1000);
    assert_eq!(server_close.reason, "done");
}

#[test]
fn one_byte_write_chunks_still_complete_the_round_trip() {
    // Partial-write discipline: every socket write is capped at ONE byte,
    // so the driver's WriteProgress suffix path runs for real on both
    // sides (handshake bytes included).
    let tiny = IoBounds {
        write_chunk: 1,
        ..IoBounds::default()
    };
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let address = listener.local_addr().expect("bound address");
    let server = server_thread(listener, tiny);
    let client = client_fixture(address, "split", tiny);
    let server = server.join().expect("server thread");
    assert!(client.clean(), "client: {}", client.summary());
    assert_eq!(client.texts, vec!["split".to_owned()]);
    assert!(server.clean(), "server: {}", server.summary());
    assert_eq!(server.texts, vec!["split".to_owned()]);
}

#[test]
fn peer_loss_after_handshake_is_the_1006_transport_close() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let address = listener.local_addr().expect("bound address");
    let server = server_thread(listener, IoBounds::default());
    // A raw client that completes a real handshake through ws_core and
    // then vanishes without a close frame.
    {
        let mut stream = TcpStream::connect(address).expect("connect");
        let (_sender, mut driver) = ws_driver::connection_driver(
            ConnectionConfig::default(),
            ws_core::connection::Role::Client,
        );
        driver
            .begin_client_handshake("/chat", "localhost")
            .expect("handshake start");
        let mut report = ws_testee::io_loop::empty_report();
        assert!(ws_testee::io_loop::drive_until_open(
            &mut driver,
            &mut stream,
            &IoBounds::default(),
            &mut report,
        ));
        // Drop the socket with no close handshake.
    }
    let server = server.join().expect("server thread");
    assert!(server.clean(), "server: {}", server.summary());
    let close = server.close.expect("server close detail");
    assert_eq!(close.code, 1006, "abnormal transport close (Q20)");
    assert!(!close.remote, "no close handshake was in progress");
}

#[test]
fn ping_scripted_client_completes_against_a_ponging_peer() {
    // Cross-peer control rehearsal (US-018 AC4): the client fixture sends a
    // scripted ping alongside its text; the peer routes Ping->SendPong at
    // the ADAPTER layer (mirroring shipped Java's WebSocketImpl default
    // auto-pong, which lives above the ported core — the core itself never
    // replies on its own, Q18). The client must observe the pong semantic
    // event and only then run the clean close.
    use ws_core::{CommandSender, LocalCommand, SemanticEvent, SemanticEventKind};
    use ws_testee::io_loop::EventPolicy;

    struct PongingEcho;
    impl EventPolicy for PongingEcho {
        fn on_event(&mut self, event: &SemanticEvent, sender: &CommandSender) {
            match &event.kind {
                SemanticEventKind::Ping { data } => {
                    let _ = sender.try_send(LocalCommand::SendPong { data: data.clone() });
                }
                SemanticEventKind::Text { text } => {
                    let _ = sender.try_send(LocalCommand::SendText { text: text.clone() });
                }
                _ => {}
            }
        }
    }

    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let address = listener.local_addr().expect("bound address");
    let server = thread::spawn(move || {
        let (mut stream, _peer) = listener.accept().expect("accept");
        let (sender, mut driver) = ws_driver::connection_driver(
            ConnectionConfig::default(),
            ws_core::connection::Role::Server,
        );
        let mut report = ws_testee::io_loop::empty_report();
        assert!(ws_testee::io_loop::drive_until_open(
            &mut driver,
            &mut stream,
            &IoBounds::default(),
            &mut report,
        ));
        let mut policy = PongingEcho;
        ws_testee::io_loop::drive_connection(
            &mut driver,
            &sender,
            &mut stream,
            &IoBounds::default(),
            &mut policy,
            &mut report,
        );
        report
    });

    let fixture = ClientFixture {
        address,
        config: ConnectionConfig::default(),
        request_target: "/chat",
        host: "localhost",
        message: "with-ping",
        ping: Some(b"cp-ping".to_vec()),
        bounds: IoBounds::default(),
    };
    let client = run_client_once(&fixture).expect("client setup");
    let server = server.join().expect("server thread");

    assert!(client.clean(), "client: {}", client.summary());
    assert_eq!(client.texts, vec!["with-ping".to_owned()]);
    assert_eq!(
        client.pongs,
        vec![b"cp-ping".to_vec()],
        "pong echoes the ping payload"
    );
    assert!(server.clean(), "server: {}", server.summary());
    assert_eq!(
        server.pings,
        vec![b"cp-ping".to_vec()],
        "server observed the ping event"
    );
}

#[test]
fn failed_connect_is_a_normalized_setup_outcome() {
    // Bind then drop a listener so the port is (momentarily) closed; the
    // connect must fail with the normalized socket-error vocabulary, not a
    // panic or a fabricated report.
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let address = listener.local_addr().expect("bound address");
    drop(listener);
    let fixture = ClientFixture {
        address,
        config: ConnectionConfig::default(),
        request_target: "/chat",
        host: "localhost",
        message: "never-sent",
        ping: None,
        bounds: IoBounds::default(),
    };
    match run_client_once(&fixture) {
        Err(SetupOutcome::SocketFailed(kind)) => {
            assert_eq!(kind, "ConnectionRefused", "normalized error kind");
        }
        other => panic!("expected SocketFailed setup outcome, got {other:?}"),
    }
}

#[test]
fn slow_writer_peer_completes_after_read_timeout_stalls() {
    // AC2 slow reader/writer: the server stalls well past the client's
    // per-attempt read timeout before accepting, so the client's read path
    // takes many WouldBlock/TimedOut retries — the run must still complete
    // cleanly with the same observables.
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let address = listener.local_addr().expect("bound address");
    let impatient = IoBounds {
        read_timeout: Duration::from_millis(2),
        ..IoBounds::default()
    };
    let server = thread::spawn(move || {
        thread::sleep(Duration::from_millis(150));
        let fixture = ServerFixture {
            config: ConnectionConfig::default(),
            bounds: IoBounds::default(),
        };
        run_server_once(&listener, &fixture).expect("server setup")
    });
    let client = client_fixture(address, "slow-peer", impatient);
    let server = server.join().expect("server thread");
    assert!(client.clean(), "client: {}", client.summary());
    assert_eq!(client.texts, vec!["slow-peer".to_owned()]);
    assert!(server.clean(), "server: {}", server.summary());
}

#[test]
fn non_loopback_addresses_are_refused() {
    let address: std::net::SocketAddr = "192.0.2.1:9001".parse().expect("test address");
    assert_eq!(loopback_only(&address), Err(SetupOutcome::NonLoopback));
    let fixture = ClientFixture {
        address,
        config: ConnectionConfig::default(),
        request_target: "/chat",
        host: "localhost",
        message: "x",
        ping: None,
        bounds: IoBounds::default(),
    };
    assert_eq!(run_client_once(&fixture), Err(SetupOutcome::NonLoopback));
}

#[test]
fn budget_exhaustion_is_reported_honestly() {
    // A server with a 1-poll budget cannot even finish the handshake; the
    // report says so instead of pretending.
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let address = listener.local_addr().expect("bound address");
    let starved = IoBounds {
        max_polls: 1,
        read_timeout: Duration::from_millis(5),
        ..IoBounds::default()
    };
    let server = thread::spawn(move || {
        let fixture = ServerFixture {
            config: ConnectionConfig::default(),
            bounds: starved,
        };
        run_server_once(&listener, &fixture).expect("accept")
    });
    let _client = TcpStream::connect(address).expect("connect");
    let report = server.join().expect("server thread");
    assert_eq!(report.outcome, LoopOutcome::BudgetExhausted);
    assert!(!report.clean());
}
