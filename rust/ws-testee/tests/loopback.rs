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
        ws_core::connection::Role::Client,
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
            ws_core::connection::Role::Server,
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
    // FOREVER. A producer thread keeps the bounded command queue topped up
    // with 64 KiB binary messages (the core's message limit) for as long as
    // the adapter runs, so the kernel -- not a flood size chosen in advance
    // -- decides when the socket write stops making progress. Once the
    // loopback socket buffers are exhausted the write actually blocks, and
    // the bounded write deadline must fire with the typed WriteStalled
    // outcome instead of hanging forever.
    //
    // Why the flood is open-ended (fixture change 2026-09-02): the original
    // fixture sent a fixed 48 x 64 KiB (3 MiB), sized against macOS
    // loopback defaults of ~128 KiB send + ~128 KiB receive. Linux autotunes
    // the send buffer up to net.ipv4.tcp_wmem[2] (4 MiB by default): a
    // Claude Code cloud host (Linux 6.18 x86_64) absorbed 4.05 MiB of a
    // never-read loopback connection under this adapter's own write pattern
    // before the first write blocked, so the 3 MiB flood drained without
    // ever stalling, the client idled on read timeouts, and when the peer's
    // 60 s hold expired and dropped a socket with unread data the kernel
    // answered with RST -- SocketError("ConnectionReset") instead of
    // WriteStalled. The US-018 closure receipt's Linux legs ran inside
    // Docker linuxkit VMs and did not meet that profile. std cannot shrink
    // SO_SNDBUF/SO_RCVBUF, so the kernel default IS the documented bound;
    // feeding until the kernel refuses is the only fixture that holds on
    // every buffer size. The property under test is unchanged.
    //
    // Budget note: the core's max_output_bytes is not enforced on the send
    // path; what bounds an open-ended flood are the per-connection scenario
    // budgets max_frames and max_actions (default 64 each, derive.go
    // fidelity). At the defaults the core stops after 64 frames (4.0 MiB on
    // the wire), which this kernel absorbs with ~50 KiB to spare, and every
    // later command becomes a Rejected disposition that the adapter loop
    // drops without touching the socket -- so nothing ever stalled. The
    // client config below raises both budgets to their ceilings: 1024
    // actions x 64 KiB is 64 MiB of headroom, sixteen times the Linux
    // default send-buffer cap. The driver applies the next queued command
    // only after the offered write drains, so pending output never exceeds
    // one message however long the producer runs.
    //
    // Java-fidelity note: shipped Java has NO socket-layer write deadline —
    // WebSocketClient.WebsocketWriteThread blocks in ostream.write()
    // indefinitely (Socket soTimeout bounds reads only); its only liveness
    // bound is the adapter-layer connectionLostTimeout keepalive. The
    // bounded write deadline here is US-018 adapter SAFETY policy (AC2
    // bounded write resources), a disclosed divergence, not core protocol.
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, mpsc};
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
    let client_config = ConnectionConfig::builder()
        .max_actions(1024)
        .max_frames(4096)
        .build()
        .expect("ceiling-valued scenario budgets are a valid config");
    let (sender, mut driver) =
        ws_driver::connection_driver(client_config, ws_core::connection::Role::Client);
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
    // Producer: refill the bounded queue (capacity 64) whenever the owner
    // drains it, through the same try-send-only handle real producers use.
    // A refusal (full or momentarily contended) is retried after a short
    // yield; the flag stops the producer once the adapter has returned.
    let stop = Arc::new(AtomicBool::new(false));
    let producer = {
        let sender = sender.clone();
        let stop = Arc::clone(&stop);
        thread::spawn(move || {
            let message = || ws_core::LocalCommand::SendBinary {
                data: vec![0x42u8; 65_536],
            };
            let mut admitted: u64 = 0;
            let mut next = message();
            while !stop.load(Ordering::Acquire) {
                match sender.try_send(next) {
                    Ok(()) => {
                        admitted += 1;
                        next = message();
                    }
                    Err(refused) => {
                        next = refused.command;
                        thread::sleep(Duration::from_micros(200));
                    }
                }
            }
            admitted
        })
    };
    let started = Instant::now();
    let mut policy = ws_testee::io_loop::ObserveOnly;
    ws_testee::io_loop::drive_connection(
        &mut driver,
        &sender,
        &mut stream,
        &bounds,
        ws_core::connection::Role::Client,
        &mut policy,
        &mut report,
    );
    let elapsed = started.elapsed();
    stop.store(true, Ordering::Release);
    let admitted = producer.join().expect("producer thread");
    let _ = release_tx.send(());
    peer.join().expect("peer thread");

    assert_eq!(
        report.outcome,
        LoopOutcome::WriteStalled,
        "stalled write must trip the typed deadline outcome: {} (producer admitted {admitted} x 64 KiB commands; {} polls in {elapsed:?})",
        report.summary(),
        report.polls
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

// ---------------------------------------------------------------------------
// Pre-landing review findings 2 and 4 (session 01a04960): every adapter exit
// that ends transport service must pump `DriverInput::Shutdown` before the
// caller drops the driver, and the `ConnectionReport`'s dropped-write
// accounting must have a FAILING WITNESS. Before these tests, deleting both
// `dropped_write_frames`/`dropped_write_bytes` increments in `io_loop::pump`
// left `make -C rust gates` at exit 0 (75 `test result: ok`, ac1-gates 8/8):
// nothing in the tree read either field.
// ---------------------------------------------------------------------------

/// A real connected loopback TCP pair. The peer end is returned so the
/// caller keeps it alive (dropping it would close the connection).
fn socket_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let address = listener.local_addr().expect("bound address");
    let near = TcpStream::connect(address).expect("connect");
    let (far, _peer) = listener.accept().expect("accept");
    (near, far)
}

/// Drive the open driver until its next committed frame is OFFERED, and
/// return those wire bytes.
fn offered_frame(driver: &mut ws_driver::ConnectionDriver) -> Vec<u8> {
    for _ in 0..64 {
        match driver.poll(ws_driver::DriverInput::Wake).output {
            ws_driver::DriverOutput::Write(suffix) => return suffix.to_vec(),
            ws_driver::DriverOutput::Idle => panic!("no committed write was offered"),
            _ => {}
        }
    }
    panic!("no committed write was offered within the drain bound");
}

#[test]
fn an_exhausted_poll_budget_shuts_down_and_reports_the_abandoned_committed_writes() {
    // Finding 2's budget exit, with finding 4's failing witness on top: the
    // connected loop's `while report.polls < bounds.max_polls` condition is
    // itself an exit that ends transport service, and what it abandons must
    // come back in the returned `ConnectionReport`.
    use std::io::Write as _;

    for partial in [false, true] {
        let (mut stream, _peer) = socket_pair();
        let (sender, mut driver) = ws_driver::connection_driver_in_state(
            ConnectionConfig::default(),
            ws_core::connection::Role::Server,
            ws_core::connection::InitialState::Open,
        );
        sender
            .try_send(ws_core::LocalCommand::SendText {
                text: "abandoned".to_owned(),
            })
            .expect("enqueue");
        let frame = offered_frame(&mut driver);
        assert_eq!(
            frame.len(),
            11,
            "server text frame [0x81,0x09,\"abandoned\"]"
        );
        let mut on_the_wire = 0usize;
        if partial {
            // One byte GENUINELY reaches the wire, so only the suffix is
            // lost — the partial-front polarity.
            on_the_wire = stream.write(&frame[..1]).expect("one byte to a live peer");
            assert_eq!(on_the_wire, 1);
            let _ = driver.poll(ws_driver::DriverInput::WriteProgress { bytes: on_the_wire });
        }

        // A budget already spent (by the handshake phase, as the fixtures
        // seed it) means the connected loop exits without a single poll.
        let mut report = ws_testee::io_loop::empty_report();
        let bounds = IoBounds {
            max_polls: 0,
            ..IoBounds::default()
        };
        let mut policy = ws_testee::io_loop::ObserveOnly;
        ws_testee::io_loop::drive_connection(
            &mut driver,
            &sender,
            &mut stream,
            &bounds,
            ws_core::connection::Role::Server,
            &mut policy,
            &mut report,
        );

        assert_eq!(report.outcome, LoopOutcome::BudgetExhausted);
        assert_eq!(
            report.dropped_write_frames, 1,
            "the abandoned committed frame is reported (partial={partial})"
        );
        assert_eq!(
            report.dropped_write_bytes,
            (frame.len() - on_the_wire) as u64,
            "only the UNDELIVERED suffix is lost (partial={partial})"
        );
    }
}

#[test]
fn a_shutdown_report_carrying_two_frames_is_accounted_whole_by_the_adapter() {
    // The plural arm of the driver's `abort_pending_writes` reaches the
    // adapter's accounting too: an automatic pong is committed while a
    // semantic event is being returned (so it never occupies the offered
    // slot), and the next poll applies a producer command behind it.
    use std::io::Write as _;

    let (mut stream, _peer) = socket_pair();
    let (sender, mut driver) = ws_driver::connection_driver_in_state(
        ConnectionConfig::default(),
        ws_core::connection::Role::Server,
        ws_core::connection::InitialState::Open,
    );
    // Masked (client-to-server) ping with an all-zero mask key.
    let ping = [0x89u8, 0x83, 0, 0, 0, 0, 1, 2, 3];
    assert!(matches!(
        driver.poll(ws_driver::DriverInput::Inbound(&ping)).input,
        ws_driver::InputDisposition::Consumed { .. }
    ));
    let mut delivered = false;
    for _ in 0..8 {
        if let ws_driver::DriverOutput::Event(event) =
            driver.poll(ws_driver::DriverInput::Wake).output
            && matches!(event.kind, ws_core::SemanticEventKind::Ping { .. })
        {
            delivered = true;
            break;
        }
    }
    assert!(delivered, "the Ping semantic event is delivered");
    sender
        .try_send(ws_core::LocalCommand::SendText {
            text: "behind-the-pong".to_owned(),
        })
        .expect("enqueue");
    let pong = offered_frame(&mut driver);
    assert_eq!(pong, [0x8A, 0x03, 1, 2, 3], "the automatic pong is offered");
    let on_the_wire = stream.write(&pong[..2]).expect("two bytes to a live peer");
    assert_eq!(on_the_wire, 2);
    let _ = driver.poll(ws_driver::DriverInput::WriteProgress { bytes: on_the_wire });

    let mut report = ws_testee::io_loop::empty_report();
    let bounds = IoBounds {
        max_polls: 0,
        ..IoBounds::default()
    };
    let mut policy = ws_testee::io_loop::ObserveOnly;
    ws_testee::io_loop::drive_connection(
        &mut driver,
        &sender,
        &mut stream,
        &bounds,
        ws_core::connection::Role::Server,
        &mut policy,
        &mut report,
    );

    assert_eq!(report.outcome, LoopOutcome::BudgetExhausted);
    assert_eq!(
        report.dropped_write_frames, 2,
        "the partially written pong AND the whole text frame behind it"
    );
    assert_eq!(
        report.dropped_write_bytes,
        // 5-byte pong less the 2 bytes on the wire, plus the 17-byte text
        // frame [0x81,0x0F,"behind-the-pong"].
        (5 - 2) + 17,
        "exactly the undelivered bytes across both frames"
    );
}

#[test]
fn a_hard_handshake_write_error_shuts_down_and_reports_the_committed_request() {
    // Finding 2's named path: `drive_until_open` used to `return false` on a
    // hard write error WITHOUT pumping `Shutdown`, and `run_client_once`
    // then dropped the driver — losing the committed handshake frame with no
    // `WritesDropped` of any kind. Shutting the LOCAL write half makes the
    // very first socket write fail with `BrokenPipe` deterministically, with
    // zero bytes on the wire.
    let (mut stream, _peer) = socket_pair();
    stream
        .shutdown(std::net::Shutdown::Write)
        .expect("close the local write half");
    let (_sender, mut driver) = ws_driver::connection_driver(
        ConnectionConfig::default(),
        ws_core::connection::Role::Client,
    );
    driver
        .begin_client_handshake("/chat", "localhost")
        .expect("handshake start commits the request frame");
    let mut report = ws_testee::io_loop::empty_report();
    let bounds = IoBounds {
        read_timeout: Duration::from_millis(5),
        max_polls: 64,
        ..IoBounds::default()
    };
    let opened =
        ws_testee::io_loop::drive_until_open(&mut driver, &mut stream, &bounds, &mut report);
    assert!(
        !opened,
        "the handshake cannot complete on a dead write half"
    );
    assert!(
        matches!(report.outcome, LoopOutcome::SocketError(_)),
        "hard write error, not a retryable stall: {}",
        report.summary()
    );
    assert_eq!(
        report.dropped_write_frames, 1,
        "the committed handshake request is reported, not abandoned"
    );
    assert!(
        report.dropped_write_bytes > 0,
        "no byte of the request reached the wire, so the whole frame is lost"
    );
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

/// Drive `driver`'s already-committed handshake output onto `stream`.
///
/// `drive_until_open` returns as soon as the core leaves `NotYetConnected`,
/// which for the SERVER role happens on the poll that consumes the client's
/// request — one poll BEFORE the response write is drained. The shipped
/// `run_server_once` flushes it inside `drive_connection`; a peer that wants
/// the raw wire afterwards has to drain it explicitly. Public driver seam
/// only (`poll` + `WriteProgress`); no protocol knowledge lives here.
fn flush_committed_writes(driver: &mut ws_driver::ConnectionDriver, stream: &mut TcpStream) {
    use std::io::Write;
    for _ in 0..256 {
        let pending = match driver.poll(ws_driver::DriverInput::Wake).output {
            ws_driver::DriverOutput::Write(suffix) => suffix.to_vec(),
            ws_driver::DriverOutput::Idle => return,
            _ => continue,
        };
        let written = stream.write(&pending).expect("peer flush write");
        driver.poll(ws_driver::DriverInput::WriteProgress { bytes: written });
    }
}

/// Read whatever the peer puts on the wire until EOF or the read timeout.
fn read_raw_until_eof(stream: &mut TcpStream) -> Vec<u8> {
    use std::io::{ErrorKind, Read};
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let mut raw = Vec::new();
    let mut buffer = [0u8; 256];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => return raw,
            Ok(n) => raw.extend_from_slice(&buffer[..n]),
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return raw;
            }
            Err(_) => return raw,
        }
    }
}

/// C6 MUST NOT ANSWER A LOCALLY REJECTED COMMAND (review finding: "C6 loses
/// failure provenance").
///
/// C5 (`us017-post-failure-owner-decisions-2026-08-28.json`,
/// `c5-fatal-command-rejection-surfaces-failure`) makes a fatal COMMAND
/// rejection surface as `DriverOutput::Failure`, exactly like an inbound
/// decode fatal. C6 (`us017-c6-layer-split-owner-decision-2026-08-28.json`)
/// answers a decode-path violation with shipped Java's 1002 close. Their
/// intersection made every failure look like an inbound decode violation.
///
/// `send_close {code: 999}` is rejected LOCALLY by the Q13 validity chain
/// (`close_code_rejection`, reported close code 1002) and emits no frame —
/// the pinned Java oracle's own run of `us005.pub.0000` reports
/// `final_state: "open"`, i.e. NOTHING went on the wire. So nothing may go
/// on the wire here either: `decodeFrames` never ran, so `close(e)` was
/// never reached and there is no `InvalidDataException` to answer.
#[test]
fn a_locally_rejected_command_puts_no_violation_close_on_the_wire() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let address = listener.local_addr().expect("bound address");

    // The peer completes a real server handshake through ws_core, then stops
    // driving the protocol and records the raw bytes the subject sends.
    let peer = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
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
        flush_committed_writes(&mut driver, &mut stream);
        read_raw_until_eof(&mut stream)
    });

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

    // The reviewer's exact case: a command the CORE rejects, arriving from
    // the local producer seam and never off the wire.
    sender
        .try_send(ws_core::connection::LocalCommand::SendClose {
            code: 999,
            reason: String::new(),
        })
        .expect("bounded command queue has room");
    let mut policy = ws_testee::io_loop::ObserveOnly;
    ws_testee::io_loop::drive_connection(
        &mut driver,
        &sender,
        &mut stream,
        &IoBounds::default(),
        // The subject is the CLIENT half, which never hangs up on its own
        // (WebSocketClient's write thread closes only when it ends), so the
        // role-gated transport close cannot fire here and the raw bytes this
        // test reads are the whole of what the subject put on the wire.
        ws_core::connection::Role::Client,
        &mut policy,
        &mut report,
    );
    drop(stream);
    let raw = peer.join().expect("peer thread");

    // The halt is unchanged: C5 still surfaces the fatal.
    assert!(
        matches!(
            report.outcome,
            ws_testee::io_loop::LoopOutcome::ProtocolFailure(_)
        ),
        "C5 must still surface the locally rejected fatal: {:?}",
        report.outcome
    );
    assert!(
        raw.is_empty(),
        "REGRESSION: a locally rejected send_close put {} byte(s) on the wire \
         ({raw:02x?}); C6's 1002 close answers an INBOUND decode violation only",
        raw.len()
    );
    assert_eq!(
        report.violation_close_sent, None,
        "REGRESSION: a LOCALLY rejected command must not report C6's \
         inbound-violation close"
    );
}

// ---------------------------------------------------------------------------
// Pre-landing review ROUND 2 (session 01a04960 re-review): "the protocol-
// failure exception still leaks committed writes". A fatal core step can
// COMMIT a wire write and FAIL in the same step, and the adapter halts at its
// first `Failure` by contract — so the committed bytes were abandoned with
// nothing counted. Reproduced before the fix, over real sockets, through the
// real adapter:
//
//   PROBE-C (server open, one chunk = masked close + masked text):
//     peer received 0 post-handshake bytes
//     report outcome=ProtocolFailure(StateViolation) dropped_frames=0
//
// The committed close echo the peer was waiting for was gone and unreported.
// The fix orders `DriverOutput::Failure` strictly AFTER the committed write
// stream, so the exception now covers only connections that have already
// handed over every committed byte. These three tests are the failing
// witnesses at the PEER, which is the only place "delivered" is observable.
// ---------------------------------------------------------------------------

/// A well-formed HTTP GET that is NOT a websocket upgrade: the version-only
/// draft match fails, so the server core queues its error head and returns
/// the fatal `JavaInvalidData` in the same step.
const NON_UPGRADE_REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: localhost\r\n\r\n";

/// The deterministic rejection head `ws_core` commits for that request.
const REJECT_HEAD: &[u8] = b"HTTP/1.1 404 Not Found\r\n\r\n";

/// A minimal valid client upgrade request, hand-written so the peer in these
/// tests is raw TCP rather than a second adapter.
fn upgrade_request() -> Vec<u8> {
    let mut request = Vec::new();
    request.extend_from_slice(b"GET /chat HTTP/1.1\r\n");
    request.extend_from_slice(b"Host: localhost\r\n");
    request.extend_from_slice(b"Upgrade: websocket\r\n");
    request.extend_from_slice(b"Connection: Upgrade\r\n");
    request.extend_from_slice(b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n");
    request.extend_from_slice(b"Sec-WebSocket-Version: 13\r\n\r\n");
    request
}

/// Read from `peer` until EOF or the read timeout expires.
fn read_to_end_or_timeout(peer: &mut TcpStream) -> Vec<u8> {
    use std::io::Read as _;
    let mut received = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        match peer.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => received.extend_from_slice(&buffer[..n]),
            Err(_) => break,
        }
    }
    received
}

#[test]
fn a_rejected_server_handshake_delivers_its_committed_error_head_before_failing() {
    use std::io::Write as _;

    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let address = listener.local_addr().expect("bound address");
    let bounds = IoBounds {
        max_polls: 4_000,
        ..IoBounds::default()
    };
    let server = server_thread(listener, bounds);

    let mut peer = TcpStream::connect(address).expect("connect");
    peer.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    peer.write_all(NON_UPGRADE_REQUEST).expect("write request");
    peer.flush().expect("flush");
    let received = read_to_end_or_timeout(&mut peer);
    let report = server.join().expect("server thread");

    assert_eq!(
        received, REJECT_HEAD,
        "the rejection head the core COMMITTED must reach the peer, not be abandoned with the failure"
    );
    match &report.outcome {
        LoopOutcome::ProtocolFailure(failure) => assert_eq!(
            failure.code,
            ws_core::FailureCode::JavaInvalidData,
            "the rejection's typed failure"
        ),
        other => panic!(
            "a rejected handshake must end on its typed protocol failure, not {other:?}; \
             before the fix the ignored Failure left this run spinning to BudgetExhausted"
        ),
    }
    assert_eq!(
        (report.dropped_write_frames, report.dropped_write_bytes),
        (0, 0),
        "nothing is owed once the head is delivered"
    );
}

#[test]
fn a_protocol_failure_after_a_committed_close_echo_still_delivers_the_echo() {
    use std::io::{Read as _, Write as _};
    use ws_core::framing::{Draft6455, Opcode};

    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let address = listener.local_addr().expect("bound address");
    let server = server_thread(listener, IoBounds::default());

    let mut peer = TcpStream::connect(address).expect("connect");
    peer.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    peer.write_all(&upgrade_request()).expect("request");
    peer.flush().expect("flush");
    let mut head = [0u8; 4096];
    let head_len = peer.read(&mut head).expect("101 head");
    assert!(
        head[..head_len].starts_with(b"HTTP/1.1 101 "),
        "the handshake must complete before the failure case"
    );

    // ONE chunk, TWO frames: the close is processed while Open and COMMITS
    // the Q19 echo write; the text frame that follows is refused by the
    // Closing state gate with the fatal `StateViolation`. Both effects come
    // out of the same `ConnectionCore::handle` call, which is what makes the
    // echo a committed-but-undelivered write at the failure instant.
    let key = [0x11u8, 0x22, 0x33, 0x44];
    let mut chunk = Draft6455::encode_frame(true, Opcode::Closing, &[0x03, 0xE8], Some(key));
    chunk.extend_from_slice(&Draft6455::encode_frame(
        true,
        Opcode::Text,
        b"late",
        Some(key),
    ));
    peer.write_all(&chunk).expect("write the two-frame chunk");
    peer.flush().expect("flush");

    let received = read_to_end_or_timeout(&mut peer);
    let report = server.join().expect("server thread");

    assert_eq!(
        received,
        vec![0x88, 0x02, 0x03, 0xE8],
        "the committed close echo must reach the peer before the connection fails \
         (it read as 0 bytes before the fix)"
    );
    match &report.outcome {
        LoopOutcome::ProtocolFailure(failure) => assert_eq!(
            failure.code,
            ws_core::FailureCode::StateViolation,
            "the refused post-close data frame's typed failure"
        ),
        other => panic!("expected the typed protocol failure, got {other:?}"),
    }
    assert_eq!(
        (report.dropped_write_frames, report.dropped_write_bytes),
        (0, 0),
        "a delivered write is not a dropped one"
    );
}

#[test]
fn a_protocol_failure_whose_committed_write_cannot_be_delivered_is_accounted() {
    // The other polarity: when the transport cannot carry the committed
    // write, the adapter must ACCOUNT for it rather than lose it. The local
    // write side is shut down before driving, so `stream.write` fails
    // deterministically with a hard error instead of racing a peer teardown.
    use std::io::Write as _;

    let (mut near, peer) = socket_pair();
    let mut writer = peer;
    writer.write_all(NON_UPGRADE_REQUEST).expect("request");
    writer.flush().expect("flush");
    near.shutdown(std::net::Shutdown::Write)
        .expect("local write shutdown");

    let (_sender, mut driver) = ws_driver::connection_driver(
        ConnectionConfig::default(),
        ws_core::connection::Role::Server,
    );
    let mut report = ws_testee::io_loop::empty_report();
    let opened = ws_testee::io_loop::drive_until_open(
        &mut driver,
        &mut near,
        &IoBounds::default(),
        &mut report,
    );
    drop(writer);

    assert!(!opened, "a rejected handshake never opens");
    // The transport died BEFORE the held failure could surface, so the
    // governing outcome is the socket error rather than the protocol failure
    // — and that exit is one of the ones round 1 routed through
    // `end_transport_service`, which is what turns the undeliverable head
    // into the typed disposition instead of a silent loss.
    assert_eq!(
        report.outcome,
        LoopOutcome::SocketError("BrokenPipe".to_owned()),
        "{}",
        report.summary()
    );
    assert_eq!(
        (report.dropped_write_frames, report.dropped_write_bytes),
        (1, REJECT_HEAD.len() as u64),
        "an undeliverable committed head is reported, not silently abandoned: {}",
        report.summary()
    );
}

// ---------------------------------------------------------------------------
// Java-equivalence gap (goal loop P2 item b): who closes the TCP connection
// once the close handshake's writes have drained. Shipped Java's SERVER
// closes it; a CLIENT does not, and waits for the peer.
//
// The gate is `SocketChannelIOHelper.batch`, whose only caller is the server
// write path at `WebSocketServer.java:586` (Java-WebSocket 1.6.0, pinned
// commit da3cf2a777aed862f2f5b5cf060cae7969958667,
// src/main/java/org/java_websocket/SocketChannelIOHelper.java:110-113):
//
//     if (ws.outQueue.isEmpty() && ws.isFlushAndClose() && ws.getDraft() != null
//         && ws.getDraft().getRole() != null && ws.getDraft().getRole() == Role.SERVER) {
//       ws.closeConnection();
//     }
//
// `closeConnection()` reaches `channel.close()` at WebSocketImpl.java:546.
// The client's write loop (`WebSocketClient.WebsocketWriteThread.runWriteData`,
// WebSocketClient.java:837-851) has no such branch: it closes its socket only
// when the write thread itself ends.
//
// Before the adapter carried this gate, the port's server left the socket open
// after echoing and waited for the peer's EOF, so the peer of a Rust server saw
// the echo and then nothing.
// ---------------------------------------------------------------------------

/// The unmasked server->client CLOSE frame for 1000/"done" — also exactly the
/// echo a server composes for it (`ws_driver::CloseEchoPolicy`).
const CLOSE_1000_DONE_UNMASKED: &[u8] = &[0x88, 0x06, 0x03, 0xE8, b'd', b'o', b'n', b'e'];

/// The mask key these tests use for client->server frames.
const TEST_MASK: [u8; 4] = [0x11, 0x22, 0x33, 0x44];

/// A masked client->server CLOSE frame for 1000/"done", hand-assembled so the
/// raw peer in these tests stays raw TCP and the adapter crate's fixtures do
/// not reach into the core's framing module for wire bytes.
fn masked_close_1000_done() -> Vec<u8> {
    let payload: [u8; 6] = [0x03, 0xE8, b'd', b'o', b'n', b'e'];
    let mut frame = vec![0x88, 0x80 | payload.len() as u8];
    frame.extend_from_slice(&TEST_MASK);
    for (index, byte) in payload.iter().enumerate() {
        frame.push(byte ^ TEST_MASK[index % 4]);
    }
    frame
}

/// Read from `peer` until the ADAPTER closes the connection (EOF) or the read
/// timeout expires. Returns the bytes and whether EOF was actually observed —
/// `read_to_end_or_timeout` deliberately collapses that distinction, and this
/// gap is precisely about which of the two happens.
fn drain_until_eof_or_timeout(peer: &mut TcpStream) -> (Vec<u8>, bool) {
    use std::io::Read as _;
    let mut received = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        match peer.read(&mut buffer) {
            Ok(0) => return (received, true),
            Ok(n) => received.extend_from_slice(&buffer[..n]),
            Err(_) => return (received, false),
        }
    }
}

/// Bounds with a 1ms socket read timeout and an explicit poll budget. An
/// endpoint that does NOT close the transport spends this whole budget waiting
/// on its peer, so the budget is also the window in which a wrongly-closing
/// endpoint would have had every chance to close.
fn prompt_bounds(max_polls: u64) -> IoBounds {
    IoBounds {
        read_timeout: Duration::from_millis(1),
        max_polls,
        ..IoBounds::default()
    }
}

#[test]
fn a_server_closes_the_tcp_connection_once_its_close_echo_has_drained() {
    use std::io::Write as _;

    let (mut stream, mut peer) = socket_pair();
    peer.set_read_timeout(Some(Duration::from_millis(750)))
        .expect("peer read timeout");
    let (sender, mut driver) = ws_driver::connection_driver_in_state(
        ConnectionConfig::default(),
        ws_core::connection::Role::Server,
        ws_core::connection::InitialState::Open,
    );

    peer.write_all(&masked_close_1000_done())
        .expect("peer close frame");
    peer.flush().expect("flush");

    let mut report = ws_testee::io_loop::empty_report();
    let mut policy = ws_testee::io_loop::ObserveOnly;
    ws_testee::io_loop::drive_connection(
        &mut driver,
        &sender,
        &mut stream,
        &prompt_bounds(2_000),
        ws_core::connection::Role::Server,
        &mut policy,
        &mut report,
    );

    // `stream` is still owned here and deliberately NOT dropped: the only way
    // the peer can see EOF is the adapter having closed it itself.
    let (received, saw_eof) = drain_until_eof_or_timeout(&mut peer);

    assert_eq!(
        received, CLOSE_1000_DONE_UNMASKED,
        "the server's composed close echo must reach the peer"
    );
    assert!(
        saw_eof,
        "shipped Java's server closes the TCP connection once the echo has drained \
         (SocketChannelIOHelper.java:110-113 -> WebSocketImpl.java:546); the peer saw \
         the echo and then no EOF, so this endpoint left the socket open"
    );
    assert!(
        report.clean(),
        "closing the transport is what carries this run to its terminal: {}",
        report.summary()
    );
    let close = report.close.expect("governing close");
    assert_eq!(
        close.code, 1000,
        "Java reports closecode from the close frame"
    );
    assert_eq!(close.reason, "done", "and closemessage with it");
}

#[test]
fn a_client_does_not_close_the_tcp_connection_after_its_close_echo() {
    use std::io::Write as _;

    // The other half of the same gate: Java's role check is what keeps a
    // CLIENT from doing this, so an adapter that closed unconditionally would
    // be just as wrong as one that never closed.
    let (mut stream, mut peer) = socket_pair();
    peer.set_read_timeout(Some(Duration::from_millis(750)))
        .expect("peer read timeout");
    let (sender, mut driver) = ws_driver::connection_driver_in_state(
        ConnectionConfig::default(),
        ws_core::connection::Role::Client,
        ws_core::connection::InitialState::Open,
    );

    peer.write_all(CLOSE_1000_DONE_UNMASKED)
        .expect("peer close frame");
    peer.flush().expect("flush");

    let mut report = ws_testee::io_loop::empty_report();
    let mut policy = ws_testee::io_loop::ObserveOnly;
    ws_testee::io_loop::drive_connection(
        &mut driver,
        &sender,
        &mut stream,
        &prompt_bounds(250),
        ws_core::connection::Role::Client,
        &mut policy,
        &mut report,
    );

    let (received, saw_eof) = drain_until_eof_or_timeout(&mut peer);

    // A masked client close echo: 2 header bytes + 4 mask bytes + 6 payload.
    assert_eq!(
        received.len(),
        12,
        "a masked client close echo: {received:?}"
    );
    assert_eq!(received[0], 0x88, "FIN + CLOSING opcode");
    assert_eq!(received[1], 0x86, "MASK bit set, 6-byte payload");
    let key = &received[2..6];
    let unmasked: Vec<u8> = received[6..]
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ key[index % 4])
        .collect();
    assert_eq!(
        unmasked,
        vec![0x03, 0xE8, b'd', b'o', b'n', b'e'],
        "the client echoes 1000/\"done\" back"
    );
    assert!(
        !saw_eof,
        "shipped Java's CLIENT has no such branch (WebSocketClient.java:837-851): it \
         echoes and waits for the peer to close. An unconditional adapter close would \
         make this endpoint tear down the connection Java leaves to the server."
    );
    assert_eq!(
        report.outcome,
        LoopOutcome::BudgetExhausted,
        "the client is still waiting on the peer when the budget runs out: {}",
        report.summary()
    );
}

#[test]
fn the_server_fixture_reaches_its_terminal_without_the_peer_ever_closing() {
    use std::io::{Read as _, Write as _};

    // The same gate through the SHIPPED server fixture and a real opening
    // handshake, so the witness is the adapter a caller actually runs.
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let address = listener.local_addr().expect("bound address");
    let server = server_thread(listener, prompt_bounds(2_000));

    let mut peer = TcpStream::connect(address).expect("connect");
    peer.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    peer.write_all(&upgrade_request()).expect("request");
    peer.flush().expect("flush");
    let mut head = [0u8; 4096];
    let head_len = peer.read(&mut head).expect("101 head");
    assert!(
        head[..head_len].starts_with(b"HTTP/1.1 101 "),
        "the handshake must complete before the close case"
    );

    peer.write_all(&masked_close_1000_done())
        .expect("peer close frame");
    peer.flush().expect("flush");

    let (received, saw_eof) = drain_until_eof_or_timeout(&mut peer);
    let report = server.join().expect("server thread");

    assert_eq!(
        received, CLOSE_1000_DONE_UNMASKED,
        "the composed close echo reaches the peer"
    );
    assert!(saw_eof, "and the server closes the connection behind it");
    assert!(
        report.clean(),
        "the peer never closed its side, so only a server-side close can carry this \
         run to its exactly-once terminal: {}",
        report.summary()
    );
}

#[test]
fn a_server_that_initiates_a_close_hangs_up_without_waiting_for_the_echo() {
    // Java's gate is `isFlushAndClose()`, NOT "a Close has been received":
    // `close(int, String, boolean)` reaches `flushAndClose` at
    // WebSocketImpl.java:494 on the same path that moves readyState to CLOSING
    // at :503, for a locally initiated close exactly as for an echoed one. So a
    // Java server that initiates a close tears the TCP connection down as soon
    // as its own close frame has flushed, without waiting for the peer's Close.
    //
    // This is the sub-case where the gate DIVERGES from a strict RFC 6455
    // section 5.5.1 reading ("after both sending and receiving a Close ... the
    // server MUST close the underlying TCP connection immediately"), and the
    // port follows shipped Java rather than the RFC. Drafted for the
    // behaviour-delta ledger as drafts/ledger-proposals/server-close-parity.json.
    let (mut stream, mut peer) = socket_pair();
    peer.set_read_timeout(Some(Duration::from_millis(750)))
        .expect("peer read timeout");
    let (sender, mut driver) = ws_driver::connection_driver_in_state(
        ConnectionConfig::default(),
        ws_core::connection::Role::Server,
        ws_core::connection::InitialState::Open,
    );
    sender
        .try_send(ws_core::connection::LocalCommand::SendClose {
            code: 1000,
            reason: "bye".to_owned(),
        })
        .expect("enqueue the locally initiated close");

    let mut report = ws_testee::io_loop::empty_report();
    let mut policy = ws_testee::io_loop::ObserveOnly;
    ws_testee::io_loop::drive_connection(
        &mut driver,
        &sender,
        &mut stream,
        &prompt_bounds(2_000),
        ws_core::connection::Role::Server,
        &mut policy,
        &mut report,
    );

    // The peer sent NOTHING: it never echoed, and it never closed its side.
    let (received, saw_eof) = drain_until_eof_or_timeout(&mut peer);

    assert_eq!(
        received,
        vec![0x88, 0x05, 0x03, 0xE8, b'b', b'y', b'e'],
        "the server's own close frame (1000, \"bye\")"
    );
    assert!(
        saw_eof,
        "Java's server closes on flush-and-close, not on having received a Close \
         (WebSocketImpl.java:494 -> :592, SocketChannelIOHelper.java:110-113)"
    );
    assert!(
        report.clean(),
        "and the run reaches its exactly-once terminal without any peer close: {}",
        report.summary()
    );
}
