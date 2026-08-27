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

/// US-015 AC1 cross-peer assertion (the rust->rust mirror of the US-018
/// cross-peer exam's Java direction): a LIVE ping from a real TCP client
/// peer is answered by the server testee's driver-level automatic pong with
/// a byte-identical payload — the shipped-Java default
/// (`WebSocketAdapter.onWebsocketPing` -> `PongFrame(PingFrame)` payload
/// copy), which the sans-io core itself never does (Q18).
#[test]
fn server_driver_auto_pongs_a_live_client_ping() {
    struct PingScript {
        payload: Vec<u8>,
        close_sent: bool,
    }
    impl ws_testee::io_loop::EventPolicy for PingScript {
        fn on_event(&mut self, event: &ws_core::SemanticEvent, sender: &ws_core::CommandSender) {
            if self.close_sent {
                return;
            }
            if let ws_core::SemanticEventKind::Pong { data } = &event.kind
                && *data == self.payload
            {
                self.close_sent = true;
                let _ = sender.try_send(ws_core::connection::LocalCommand::SendClose {
                    code: 1000,
                    reason: "ponged".to_owned(),
                });
            }
        }
    }

    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let address = listener.local_addr().expect("bound address");
    let server = server_thread(listener, IoBounds::default());

    let mut stream = TcpStream::connect(address).expect("connect");
    let (sender, mut driver) = ws_driver::connection_driver(
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
    let payload = vec![0xAB, 0xCD, 0xEF];
    sender
        .try_send(ws_core::connection::LocalCommand::SendPing {
            data: payload.clone(),
        })
        .expect("enqueue ping");
    let mut policy = PingScript {
        payload: payload.clone(),
        close_sent: false,
    };
    ws_testee::io_loop::drive_connection(
        &mut driver,
        &sender,
        &mut stream,
        &IoBounds::default(),
        &mut policy,
        &mut report,
    );
    // The client is terminal; drop its socket so the server observes the
    // post-close EOF (the same lifetime the client fixture gives it).
    drop(stream);
    let server = server.join().expect("server thread");

    assert!(report.clean(), "client: {}", report.summary());
    assert_eq!(
        report.pongs,
        vec![payload.clone()],
        "the live pong carries the ping's payload byte-identically"
    );
    assert!(server.clean(), "server: {}", server.summary());
    assert_eq!(
        server.pings,
        vec![payload],
        "the server's Ping semantic event delivered alongside the reply (AC1)"
    );
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
fn non_loopback_addresses_are_refused() {
    let address: std::net::SocketAddr = "192.0.2.1:9001".parse().expect("test address");
    assert_eq!(loopback_only(&address), Err(SetupOutcome::NonLoopback));
    let fixture = ClientFixture {
        address,
        config: ConnectionConfig::default(),
        request_target: "/chat",
        host: "localhost",
        message: "x",
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
