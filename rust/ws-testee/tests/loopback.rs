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
    // server's echo close completes it. That echo is composed by the
    // WebSocketImpl mirror from the received code and reason
    // (ws_driver::CloseEchoPolicy; WebSocketImpl.java:482-486), so for this
    // 1000/"done" close it carries 1000 plus the reason.
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
fn ping_scripted_client_completes_against_a_ponging_peer() {
    // Cross-peer control rehearsal (US-018 AC4): the client fixture sends a
    // scripted ping alongside its text; the peer routes Ping->SendPong at
    // the ADAPTER layer (mirroring shipped Java's WebSocketImpl default
    // auto-pong, which lives above the ported core — the core itself never
    // replies on its own, Q18). The client must observe the pong semantic
    // event and only then run the clean close.
    use ws_core::{CommandSender, LocalCommand, SemanticEvent, SemanticEventKind};
    use ws_testee::io_loop::EventPolicy;

    // The driver's Java-faithful default (AutoResponsePolicy::PongInboundPing,
    // e4) supplies the pong exactly like shipped Java's listener default; a
    // policy that ALSO ponged manually would double-pong, just as a Java app
    // overriding onWebsocketPing while calling the default would.
    struct PongingEcho;
    impl EventPolicy for PongingEcho {
        fn on_event(&mut self, event: &SemanticEvent, sender: &CommandSender) {
            if let SemanticEventKind::Text { text } = &event.kind {
                let _ = sender.try_send(LocalCommand::SendText { text: text.clone() });
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
fn stalled_peer_reader_trips_the_bounded_write_deadline() {
    // REAL socket backpressure (US-018 AC2 slow reader, review round 2):
    // the peer completes a genuine ws_core handshake and then STOPS READING
    // FOREVER. The client floods 48 x 64 KiB binary messages (3 MiB, under
    // the core's 4 MiB output ceiling and 64 KiB message limit); loopback
    // kernel socket buffers (macOS ~128 KiB snd + ~128 KiB rcv defaults;
    // std cannot shrink SO_SNDBUF/SO_RCVBUF, so the kernel default IS the
    // documented bound) absorb well under that, the socket write actually
    // blocks, and the bounded write deadline must fire with the typed
    // WriteStalled outcome instead of hanging forever.
    //
    // Java-fidelity note: shipped Java has NO socket-layer write deadline —
    // WebSocketClient.WebsocketWriteThread blocks in ostream.write()
    // indefinitely (Socket soTimeout bounds reads only); its only liveness
    // bound is the adapter-layer connectionLostTimeout keepalive. The
    // bounded write deadline here is US-018 adapter SAFETY policy (AC2
    // bounded write resources), a disclosed divergence, not core protocol.
    use std::sync::mpsc;
    use std::time::Instant;

    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let address = listener.local_addr().expect("bound address");
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let peer = thread::spawn(move || {
        let (mut stream, _peer) = listener.accept().expect("accept");
        let (_sender, mut driver) = ws_driver::connection_driver(
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
        // drive_until_open returns at state-open; the queued 101 response
        // bytes may still be undrained. Flush them through the driver seam,
        // then never touch the socket again (the never-reading peer).
        loop {
            use std::io::Write as _;
            let pending: Option<Vec<u8>> = {
                let result = driver.poll(ws_driver::DriverInput::Wake);
                match result.output {
                    ws_driver::DriverOutput::Write(suffix) => Some(suffix.to_vec()),
                    ws_driver::DriverOutput::Idle => None,
                    _ => Some(Vec::new()),
                }
            };
            match pending {
                None => break,
                Some(bytes) if bytes.is_empty() => {}
                Some(bytes) => {
                    let written = stream.write(&bytes).expect("flush 101 response");
                    let _ = driver.poll(ws_driver::DriverInput::WriteProgress { bytes: written });
                }
            }
        }
        // Hold the socket open until the asserting side releases us
        // (bounded at 60s so a failure cannot wedge the test binary).
        let _ = release_rx.recv_timeout(Duration::from_secs(60));
    });

    let mut stream = TcpStream::connect(address).expect("connect");
    let (sender, mut driver) = ws_driver::connection_driver(
        ConnectionConfig::default(),
        ws_core::connection::Role::Client,
    );
    driver
        .begin_client_handshake("/chat", "localhost")
        .expect("handshake start");
    let bounds = IoBounds {
        read_timeout: Duration::from_millis(2),
        write_timeout: Duration::from_millis(10),
        write_stall_limit: Duration::from_millis(300),
        max_polls: 50_000,
        ..IoBounds::default()
    };
    let mut report = ws_testee::io_loop::empty_report();
    assert!(ws_testee::io_loop::drive_until_open(
        &mut driver,
        &mut stream,
        &bounds,
        &mut report,
    ));
    for _ in 0..48 {
        sender
            .try_send(ws_core::LocalCommand::SendBinary {
                data: vec![0x42u8; 65_536],
            })
            .expect("command queue admits the flood (capacity 64)");
    }
    let started = Instant::now();
    let mut policy = ws_testee::io_loop::ObserveOnly;
    ws_testee::io_loop::drive_connection(
        &mut driver,
        &sender,
        &mut stream,
        &bounds,
        &mut policy,
        &mut report,
    );
    let elapsed = started.elapsed();
    let _ = release_tx.send(());
    peer.join().expect("peer thread");

    assert_eq!(
        report.outcome,
        LoopOutcome::WriteStalled,
        "stalled write must trip the typed deadline outcome: {}",
        report.summary()
    );
    assert!(!report.clean());
    assert!(
        elapsed < Duration::from_secs(15),
        "deadline must fire within the documented bound, took {elapsed:?}"
    );
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

#[test]
fn sequential_sessions_reuse_the_listener() {
    // E5 Autobahn wiring: the fuzzingclient opens one fresh connection per
    // case, sequentially. run_server_sessions must serve N connections on
    // ONE bound listener with no accept gap between sessions, echoing on
    // every one, and report each session in order.
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let address = listener.local_addr().expect("bound address");
    let server = thread::spawn(move || {
        let fixture = ServerFixture {
            config: ConnectionConfig::default(),
            bounds: IoBounds::default(),
        };
        let mut reports: Vec<(u64, ConnectionReport)> = Vec::new();
        ws_testee::run_server_sessions(&listener, &fixture, 2, &mut |index, report| {
            reports.push((index, report.clone()));
        })
        .expect("sessions setup");
        reports
    });
    let first = client_fixture(address, "case-one", IoBounds::default());
    let second = client_fixture(address, "case-two", IoBounds::default());
    let reports = server.join().expect("server thread");

    assert!(first.clean(), "first client: {}", first.summary());
    assert!(second.clean(), "second client: {}", second.summary());
    assert_eq!(reports.len(), 2);
    assert_eq!(reports[0].0, 1);
    assert_eq!(reports[1].0, 2);
    assert_eq!(reports[0].1.texts, vec!["case-one".to_owned()]);
    assert_eq!(reports[1].1.texts, vec!["case-two".to_owned()]);
    assert!(
        reports[0].1.clean(),
        "session 1: {}",
        reports[0].1.summary()
    );
    assert!(
        reports[1].1.clean(),
        "session 2: {}",
        reports[1].1.summary()
    );
}

#[test]
fn autobahn_7_3_2_wire_reply_is_1002_end_to_end() {
    // E5b: the WIRE-LEVEL reply the Autobahn 7.3.2 case observes, driven
    // through the real io_loop over a real socket. The stimulus is exactly
    // wstest's: a masked close frame whose payload is ONE byte. wstest
    // requires close code 1002 or a TCP drop; the merged E5 run recorded
    // FAILED (WRONG CODE, reply close code 1000) here.
    //
    // Shipped Java's full stack replies 1002 because
    // `Draft_6455.processFrameClosing` reads the decoded code (1002 for a
    // 1-byte payload, framing/CloseFrame.java:252-253) and calls
    // `webSocketImpl.close(code, reason, true)` (drafts/Draft_6455.java:1067),
    // which builds its OWN close frame from that code
    // (WebSocketImpl.java:482-486). That composition lives in the
    // WebSocketImpl mirror (`ws_driver::CloseEchoPolicy`), never in the
    // live-oracle-confirmed core.
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let address = listener.local_addr().expect("bound address");
    let server = server_thread(listener, IoBounds::default());

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

    // Raw wire from here on: the core would refuse to SEND a malformed
    // close, so the poisoned frame goes straight onto the socket the way
    // wstest puts it there (mask key zeroed so the masked byte is literal).
    use std::io::{Read, Write};
    stream
        .write_all(&[0x88, 0x81, 0x00, 0x00, 0x00, 0x00, 0x03])
        .expect("write the 7.3.2 close frame");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let mut reply = Vec::new();
    let mut buffer = [0u8; 64];
    while reply.len() < 4 {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => reply.extend_from_slice(&buffer[..n]),
            Err(error) => panic!("reading the server's close reply: {error:?}"),
        }
    }
    drop(stream);
    let served = server.join().expect("server thread");

    assert_eq!(
        reply,
        vec![0x88, 0x02, 0x03, 0xEA],
        "the server's wire reply must carry close code 1002 (Autobahn 7.3.2)"
    );
    let close = served.close.expect("server governing close");
    assert_eq!(
        close.code, 1002,
        "the core's governing close (delta-d509ac38)"
    );
    assert!(close.remote);
}

/// C6 LAYER SPLIT, MEASURED AT THE WIRE (owner decision
/// `us017-c6-layer-split-owner-decision-2026-08-28.json`, sha256 d41b5307…).
///
/// On a PURE protocol violation — RSV1 set on a TEXT frame — shipped
/// `WebSocketImpl` answers with a 1002 close frame before the connection
/// goes away (WebSocketImpl.java:405-408 -> :631-633 -> :481-487, flushed by
/// :494/:594-595). Before this decision we sent NOTHING and dropped TCP,
/// which is what all 17 Autobahn section-3/4 cases recorded
/// (`close_frames=0`, `remoteCloseCode: null`).
///
/// The reaction deliberately does NOT live in `ws_core`: placing it there
/// moved 18 of the 74 public corpus cases off live Java. It lives in
/// `ws_testee`'s `io_loop`, which the corpus harness cannot reach.
///
/// This test is the difference between the two states, on a real socket.
#[test]
fn a_protocol_violation_gets_the_shipped_java_1002_close_on_the_wire() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let address = listener.local_addr().expect("bound address");
    let server = server_thread(listener, IoBounds::default());

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

    // Raw wire: FIN=1, RSV1=1, opcode=TEXT -> 0xC1; MASK=1, len=0 -> 0x80;
    // zeroed mask key. The core would never SEND this, so it goes straight
    // onto the socket the way wstest puts it there.
    use std::io::{Read, Write};
    stream
        .write_all(&[0xC1, 0x80, 0x00, 0x00, 0x00, 0x00])
        .expect("write the RSV1 violation frame");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let mut reply = Vec::new();
    let mut buffer = [0u8; 64];
    while reply.len() < 4 {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => reply.extend_from_slice(&buffer[..n]),
            Err(error) => panic!("reading the server's violation close: {error:?}"),
        }
    }
    drop(stream);
    let served = server.join().expect("server thread");

    assert_eq!(
        reply,
        vec![0x88, 0x02, 0x03, 0xEA],
        "REGRESSION: a protocol violation must put shipped Java's 1002 close frame on the \
         wire (unmasked, server role) instead of dropping TCP silently"
    );
    assert_eq!(
        served.violation_close_sent,
        Some(1002),
        "the adapter must report the close code it actually wrote"
    );
    assert!(
        matches!(
            served.outcome,
            ws_testee::io_loop::LoopOutcome::ProtocolFailure(_)
        ),
        "the halt itself is unchanged — only what goes on the wire on the way out: {:?}",
        served.outcome
    );
}
