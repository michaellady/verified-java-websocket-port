//! US-019 AC4 planted mutants: each control speaks the REAL `ws_core`
//! protocol and differs from the shipped adapters in exactly one documented
//! way, and that one way is observable on the wire.
//!
//! Every mutant assertion is paired with the same probe run against the
//! shipped `ws_testee` adapter, so each test states a DISCRIMINATION — the
//! real port does X, the mutant does not — rather than an isolated fact
//! about the mutant.
//!
//! Bounded by construction: the probe and the mock both carry an explicit
//! poll budget at a millisecond read timeout, and whichever side this file
//! controls shuts its socket down once its bounded drive returns, so the
//! peer's Java-faithful "terminal arrives with transport EOF" wait always
//! ends.

use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use autobahn_controls::mutant::{
    Mutant, MutantAgentFixture, MutantServerFixture, run_mutant_case, run_mutant_server_sessions,
};
use ws_core::{CommandSender, LocalCommand, Role, SemanticEvent, SemanticEventKind};
use ws_driver::connection_driver;
use ws_testee::io_loop::{
    ConnectionReport, EventPolicy, IoBounds, drive_connection_from, drive_until_open, empty_report,
};
use ws_testee::{ServerFixture, SetupOutcome, autobahn_config, run_server_once};

const PROBE_TEXT: &str = "mutant-probe";
const PROBE_BINARY: &[u8] = b"0123";

/// Bounds for the peer that this file controls. `budget` is the poll ceiling:
/// a probe that is waiting for something the mutant will never send spends it
/// and stops, which is how "no echo" is proven in bounded time.
fn probe_bounds(budget: u64) -> IoBounds {
    IoBounds {
        read_timeout: Duration::from_millis(1),
        write_timeout: Duration::from_millis(1),
        max_polls: budget,
        ..IoBounds::default()
    }
}

/// A poll budget stated as the WALL-CLOCK window it buys, instead of chosen as
/// a magnitude (shape C of `make -C rust fixture-guard`; the full rationale is
/// on the identical helper in `rust/ws-testee/tests/loopback.rs`).
///
/// `IoBounds` gives the shared I/O loop only a count, so the fixture states the
/// deadline it actually means and converts it through the one cost a WAITING
/// adapter pays per poll — `read_timeout`, the socket read it blocks in when it
/// has nothing to do. A waiting run therefore cannot spend this budget in less
/// than `deadline` however fast this host is, and the count follows
/// `read_timeout` instead of silently shrinking the window whenever that
/// changes.
fn polls_for(deadline: Duration, read_timeout: Duration) -> u64 {
    let per_poll = read_timeout.max(Duration::from_micros(1));
    let polls = deadline.as_micros() / per_poll.as_micros();
    u64::try_from(polls).unwrap_or(u64::MAX).max(1)
}

/// Bounds for the server under test: a larger budget than any probe, so the
/// probe is always the side that hangs up first.
fn under_test_bounds() -> IoBounds {
    let read_timeout = Duration::from_millis(2);
    IoBounds {
        read_timeout,
        write_timeout: Duration::from_millis(2),
        // 40s, the window the old `max_polls: 20_000` bought at this
        // read_timeout, and far longer than any probe's budget so the probe
        // is still always the side that hangs up first.
        max_polls: polls_for(Duration::from_secs(40), read_timeout),
        ..IoBounds::default()
    }
}

/// What the probe sends and how long it waits for answers.
#[derive(Clone)]
struct ProbeScript {
    texts: Vec<String>,
    binaries: Vec<Vec<u8>>,
    ping: Option<Vec<u8>>,
    /// Text + binary deliveries to wait for before initiating the close.
    /// Zero means "never close": the probe spends its budget and hangs up,
    /// which is exactly the observation a silent peer deserves.
    expect_deliveries: usize,
    budget: u64,
}

impl ProbeScript {
    fn echo_probe(expect_deliveries: usize, budget: u64) -> ProbeScript {
        ProbeScript {
            texts: vec![PROBE_TEXT.to_owned()],
            binaries: vec![PROBE_BINARY.to_vec()],
            ping: None,
            expect_deliveries,
            budget,
        }
    }
}

/// Closes once the scripted number of deliveries has arrived.
struct ProbePolicy {
    expect_deliveries: usize,
    seen: usize,
    close_sent: bool,
}

impl EventPolicy for ProbePolicy {
    fn on_event(&mut self, event: &SemanticEvent, sender: &CommandSender) {
        match &event.kind {
            SemanticEventKind::Text { .. } | SemanticEventKind::Binary { .. } => self.seen += 1,
            _ => {}
        }
        if self.close_sent || self.expect_deliveries == 0 || self.seen < self.expect_deliveries {
            return;
        }
        self.close_sent = true;
        let _ = sender.try_send(LocalCommand::SendClose {
            code: 1000,
            reason: "probe-done".to_owned(),
        });
    }
}

/// Runs ONE real `ws_core` client probe against whatever is listening at
/// `address`, and reports what came back.
fn probe(address: SocketAddr, script: &ProbeScript) -> ConnectionReport {
    let bounds = probe_bounds(script.budget);
    let mut stream = TcpStream::connect(address).expect("probe connect");
    let (sender, mut driver) = connection_driver(autobahn_config(), Role::Client);
    driver
        .begin_client_handshake("/runCase?case=1&agent=probe", "localhost")
        .expect("probe handshake start");
    let mut report = empty_report();
    let handshake = drive_until_open(&mut driver, &mut stream, &bounds, &mut report);
    assert!(
        handshake.opened,
        "the probe's own handshake must open against a real protocol peer: {}",
        report.summary()
    );
    if let Some(data) = &script.ping {
        sender
            .try_send(LocalCommand::SendPing { data: data.clone() })
            .expect("probe enqueue ping");
    }
    for text in &script.texts {
        sender
            .try_send(LocalCommand::SendText { text: text.clone() })
            .expect("probe enqueue text");
    }
    for data in &script.binaries {
        sender
            .try_send(LocalCommand::SendBinary { data: data.clone() })
            .expect("probe enqueue binary");
    }
    let mut policy = ProbePolicy {
        expect_deliveries: script.expect_deliveries,
        seen: 0,
        close_sent: false,
    };
    drive_connection_from(
        &mut driver,
        &sender,
        &mut stream,
        &bounds,
        Role::Client,
        &mut policy,
        &mut report,
        handshake.carryover,
    );
    // This file controls the probe, so the probe hangs up: the peer's
    // Q20 terminal outcome arrives with transport EOF.
    let _ = stream.shutdown(Shutdown::Both);
    report
}

/// Stands the SHIPPED `ws_testee` echo server on an ephemeral loopback port.
fn real_server(sessions: u64) -> (SocketAddr, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let address = listener.local_addr().expect("bound address");
    let handle = thread::spawn(move || {
        let fixture = ServerFixture {
            config: autobahn_config(),
            bounds: under_test_bounds(),
        };
        for _ in 0..sessions {
            run_server_once(&listener, &fixture).expect("real server setup");
        }
    });
    (address, handle)
}

/// Stands a MUTANT server on an ephemeral loopback port.
fn mutant_server(mutant: Mutant, sessions: u64) -> (SocketAddr, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let address = listener.local_addr().expect("bound address");
    let handle = thread::spawn(move || {
        let fixture = MutantServerFixture {
            mutant,
            config: autobahn_config(),
            bounds: under_test_bounds(),
        };
        run_mutant_server_sessions(&listener, &fixture, sessions, &mut |_, _| {})
            .expect("mutant server setup");
    });
    (address, handle)
}

#[test]
fn the_shipped_server_echoes_both_payloads_faithfully() {
    // The calibration baseline every mutant assertion is measured against.
    let (address, server) = real_server(1);
    let report = probe(address, &ProbeScript::echo_probe(2, 6_000));
    server.join().expect("real server thread");

    assert_eq!(report.texts, vec![PROBE_TEXT.to_owned()]);
    assert_eq!(report.binaries, vec![PROBE_BINARY.to_vec()]);
    assert!(report.clean(), "baseline round trip: {}", report.summary());
}

#[test]
fn the_no_echo_mutant_returns_nothing_where_the_shipped_server_echoes() {
    let (address, server) = mutant_server(Mutant::NoEcho, 1);
    // expect_deliveries = 0: nothing will come back, so the probe spends its
    // (small) budget and hangs up rather than waiting on a silent peer.
    let report = probe(address, &ProbeScript::echo_probe(0, 1_500));
    server.join().expect("mutant server thread");

    assert!(
        report.texts.is_empty(),
        "the echo obligation is removed: {:?}",
        report.texts
    );
    assert!(
        report.binaries.is_empty(),
        "the echo obligation is removed: {:?}",
        report.binaries
    );
}

#[test]
fn the_opcode_swap_mutant_returns_text_as_binary_and_binary_as_text() {
    let (address, server) = mutant_server(Mutant::OpcodeSwap, 1);
    let report = probe(address, &ProbeScript::echo_probe(2, 6_000));
    server.join().expect("mutant server thread");

    assert_eq!(
        report.binaries,
        vec![PROBE_TEXT.as_bytes().to_vec()],
        "the text payload came back on the BINARY opcode"
    );
    assert_eq!(
        report.texts,
        vec![String::from_utf8(PROBE_BINARY.to_vec()).expect("ascii probe payload")],
        "the binary payload came back on the TEXT opcode"
    );
}

#[test]
fn the_payload_truncate_mutant_drops_the_final_byte_of_every_non_empty_echo() {
    let (address, server) = mutant_server(Mutant::PayloadTruncate, 1);
    let script = ProbeScript {
        texts: vec!["abcd".to_owned()],
        binaries: vec![b"wxyz".to_vec()],
        ping: None,
        expect_deliveries: 2,
        budget: 6_000,
    };
    let report = probe(address, &script);
    server.join().expect("mutant server thread");

    assert_eq!(report.texts, vec!["abc".to_owned()]);
    assert_eq!(report.binaries, vec![b"wxy".to_vec()]);
}

#[test]
fn the_payload_truncate_mutant_leaves_empty_payloads_unchanged() {
    // An empty payload has no final byte to drop, so this case is echoed
    // faithfully — the deviation is exactly "drop the final byte", nothing
    // more.
    let (address, server) = mutant_server(Mutant::PayloadTruncate, 1);
    let script = ProbeScript {
        texts: vec![String::new()],
        binaries: vec![Vec::new()],
        ping: None,
        expect_deliveries: 2,
        budget: 6_000,
    };
    let report = probe(address, &script);
    server.join().expect("mutant server thread");

    assert_eq!(report.texts, vec![String::new()]);
    assert_eq!(report.binaries, vec![Vec::new()]);
}

#[test]
fn the_pong_suppressed_mutant_still_echoes_but_never_answers_a_ping() {
    let payload = vec![0xAB, 0xCD, 0xEF];
    let script = ProbeScript {
        texts: vec![PROBE_TEXT.to_owned()],
        binaries: Vec::new(),
        ping: Some(payload.clone()),
        expect_deliveries: 1,
        budget: 6_000,
    };

    // Baseline: the shipped adapter answers the ping (the shipped-Java
    // listener default, ws_driver::AutoResponsePolicy::PongInboundPing).
    let (address, server) = real_server(1);
    let baseline = probe(address, &script);
    server.join().expect("real server thread");
    assert_eq!(
        baseline.pongs,
        vec![payload.clone()],
        "baseline: the pong carries the ping payload byte-identically"
    );

    // Mutant: the ping goes unanswered, and NOTHING else changes.
    let (address, server) = mutant_server(Mutant::PongSuppressed, 1);
    let report = probe(address, &script);
    server.join().expect("mutant server thread");
    assert!(
        report.pongs.is_empty(),
        "the auto-pong is disabled: {:?}",
        report.pongs
    );
    assert_eq!(
        report.texts,
        vec![PROBE_TEXT.to_owned()],
        "the echo obligation is untouched: exactly ONE deviation"
    );
}

// ---------------------------------------------------------------------
// fuzzingserver mode: the same deviation must ride the CLIENT agent role.
// ---------------------------------------------------------------------

/// What one mock fuzzing-server connection got back from the agent.
struct MockSession {
    texts: Vec<String>,
    binaries: Vec<Vec<u8>>,
    pongs: Vec<Vec<u8>>,
}

/// Counts what the agent sent back and closes once the expected number of
/// deliveries has arrived.
struct MockPolicy {
    expect_deliveries: usize,
    seen: usize,
    close_sent: bool,
}

impl EventPolicy for MockPolicy {
    fn on_event(&mut self, event: &SemanticEvent, sender: &CommandSender) {
        match &event.kind {
            SemanticEventKind::Text { .. } | SemanticEventKind::Binary { .. } => self.seen += 1,
            _ => {}
        }
        if self.close_sent || self.expect_deliveries == 0 || self.seen < self.expect_deliveries {
            return;
        }
        self.close_sent = true;
        let _ = sender.try_send(LocalCommand::SendClose {
            code: 1000,
            reason: "mock-done".to_owned(),
        });
    }
}

/// Serves ONE mock fuzzing-server connection built from the shipped
/// `ws_core` server role: push a text, a binary and (optionally) a ping,
/// then observe what the agent under test sends back.
fn serve_mock(
    listener: &TcpListener,
    ping: Option<Vec<u8>>,
    expect_deliveries: usize,
    budget: u64,
) -> MockSession {
    let bounds = probe_bounds(budget);
    let (mut stream, _peer) = listener.accept().expect("mock accept");
    let (sender, mut driver) = connection_driver(autobahn_config(), Role::Server);
    let mut report = empty_report();
    let handshake = drive_until_open(&mut driver, &mut stream, &bounds, &mut report);
    assert!(
        handshake.opened,
        "the mock suite peer must open against a real protocol agent: {}",
        report.summary()
    );
    if let Some(data) = &ping {
        sender
            .try_send(LocalCommand::SendPing { data: data.clone() })
            .expect("mock enqueue ping");
    }
    sender
        .try_send(LocalCommand::SendText {
            text: PROBE_TEXT.to_owned(),
        })
        .expect("mock enqueue text");
    sender
        .try_send(LocalCommand::SendBinary {
            data: PROBE_BINARY.to_vec(),
        })
        .expect("mock enqueue binary");
    let mut policy = MockPolicy {
        expect_deliveries,
        seen: 0,
        close_sent: false,
    };
    drive_connection_from(
        &mut driver,
        &sender,
        &mut stream,
        &bounds,
        Role::Server,
        &mut policy,
        &mut report,
        handshake.carryover,
    );
    // The real suite hangs up at the end of every case; so does the mock.
    let _ = stream.shutdown(Shutdown::Both);
    MockSession {
        texts: report.texts,
        binaries: report.binaries,
        pongs: report.pongs,
    }
}

/// Stands the mock fuzzing server for ONE case connection.
fn mock_suite(
    ping: Option<Vec<u8>>,
    expect_deliveries: usize,
    budget: u64,
) -> (SocketAddr, thread::JoinHandle<MockSession>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let address = listener.local_addr().expect("bound address");
    let handle = thread::spawn(move || serve_mock(&listener, ping, expect_deliveries, budget));
    (address, handle)
}

fn agent_fixture(mutant: Mutant, address: SocketAddr, agent: &str) -> MutantAgentFixture<'_> {
    MutantAgentFixture {
        mutant,
        address,
        host: "localhost",
        agent,
        config: autobahn_config(),
        bounds: under_test_bounds(),
    }
}

#[test]
fn the_no_echo_mutant_agent_answers_the_suite_with_nothing() {
    let (address, suite) = mock_suite(None, 0, 1_500);
    let report = run_mutant_case(&agent_fixture(Mutant::NoEcho, address, "no-echo"), 1)
        .expect("agent setup");
    let session = suite.join().expect("mock suite thread");

    assert!(
        session.texts.is_empty() && session.binaries.is_empty(),
        "the client-role deviation matches the server-role one: {:?} / {:?}",
        session.texts,
        session.binaries
    );
    assert!(
        report.polls > 0,
        "the agent really ran the case: {}",
        report.summary()
    );
}

#[test]
fn the_opcode_swap_mutant_agent_swaps_the_opcodes_back_to_the_suite() {
    let (address, suite) = mock_suite(None, 2, 6_000);
    let _report = run_mutant_case(
        &agent_fixture(Mutant::OpcodeSwap, address, "opcode-swap"),
        1,
    )
    .expect("agent setup");
    let session = suite.join().expect("mock suite thread");

    assert_eq!(session.binaries, vec![PROBE_TEXT.as_bytes().to_vec()]);
    assert_eq!(
        session.texts,
        vec![String::from_utf8(PROBE_BINARY.to_vec()).expect("ascii probe payload")]
    );
}

#[test]
fn the_payload_truncate_mutant_agent_truncates_what_it_returns_to_the_suite() {
    let (address, suite) = mock_suite(None, 2, 6_000);
    let _report = run_mutant_case(
        &agent_fixture(Mutant::PayloadTruncate, address, "payload-truncate"),
        1,
    )
    .expect("agent setup");
    let session = suite.join().expect("mock suite thread");

    let mut want_text = PROBE_TEXT.to_owned();
    want_text.pop();
    assert_eq!(session.texts, vec![want_text]);
    assert_eq!(
        session.binaries,
        vec![PROBE_BINARY[..PROBE_BINARY.len() - 1].to_vec()]
    );
}

#[test]
fn the_pong_suppressed_mutant_agent_echoes_but_leaves_the_suites_ping_unanswered() {
    let payload = vec![0x01, 0x02, 0x03];

    // Baseline: the shipped agent answers the suite's ping.
    let (address, suite) = mock_suite(Some(payload.clone()), 2, 6_000);
    let _report =
        ws_testee::run_case(&baseline_fixture(address, "baseline-agent"), 1).expect("agent setup");
    let baseline = suite.join().expect("mock suite thread");
    assert_eq!(baseline.pongs, vec![payload.clone()]);

    // Mutant: same echoes, no pong.
    let (address, suite) = mock_suite(Some(payload), 2, 6_000);
    let _report = run_mutant_case(
        &agent_fixture(Mutant::PongSuppressed, address, "pong-suppressed"),
        1,
    )
    .expect("agent setup");
    let session = suite.join().expect("mock suite thread");
    assert!(
        session.pongs.is_empty(),
        "the auto-pong is disabled in the client role too: {:?}",
        session.pongs
    );
    assert_eq!(session.texts, vec![PROBE_TEXT.to_owned()]);
    assert_eq!(session.binaries, vec![PROBE_BINARY.to_vec()]);
}

fn baseline_fixture(address: SocketAddr, agent: &str) -> ws_testee::AgentFixture<'_> {
    ws_testee::AgentFixture {
        address,
        host: "localhost",
        agent,
        config: autobahn_config(),
        bounds: under_test_bounds(),
    }
}

#[test]
fn mutant_agents_honour_loopback_only_and_the_agent_name_policy() {
    let routable: SocketAddr = "203.0.113.7:9001".parse().expect("test address");
    assert_eq!(
        run_mutant_case(&agent_fixture(Mutant::NoEcho, routable, "agent"), 1).unwrap_err(),
        SetupOutcome::NonLoopback
    );
    let loopback: SocketAddr = "127.0.0.1:1".parse().expect("test address");
    assert_eq!(
        run_mutant_case(&agent_fixture(Mutant::NoEcho, loopback, "a&case=9"), 1).unwrap_err(),
        SetupOutcome::InvalidAgentName
    );
}
