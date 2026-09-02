//! US-019 AC3: the Autobahn **fuzzingserver-mode** client agent.
//!
//! The E5/E5b lanes exercised fuzzingclient mode only (wstest drives the
//! Rust SERVER). Autobahn's other mode inverts the roles: `wstest
//! --mode fuzzingserver` listens, and the TESTEE is a WebSocket CLIENT that
//! must speak the suite's small agent protocol —
//! `/getCaseCount`, `/runCase?case=N&agent=NAME`, `/updateReports?agent=NAME`
//! — echoing every delivered message during a case.
//!
//! These tests stand a MOCK fuzzing server on loopback built from the
//! shipped `ws_core` + `ws_driver` server role (never the agent's own code),
//! and assert the agent's wire-visible behavior: the request targets it
//! sends, the case count it parses, and the echo it performs.

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use ws_core::{CommandSender, ConnectionConfig, LocalCommand, Role, SemanticEvent};
use ws_driver::connection_driver;
use ws_testee::io_loop::{
    EventPolicy, IoBounds, drive_connection_from, drive_until_open, empty_report,
};
use ws_testee::{AgentFixture, LoopOutcome, SetupOutcome};

/// What one mock fuzzing-server connection observed.
struct MockSession {
    /// The raw HTTP request head the agent sent (captured by peeking the
    /// socket, so the driver still consumes the identical bytes).
    request_head: String,
    /// Text messages the agent sent back.
    texts: Vec<String>,
    /// Binary messages the agent sent back.
    binaries: Vec<Vec<u8>>,
    /// How the mock's own connection ended. Reported for diagnosis on
    /// failure; the mock is bounded by [`mock_bounds`] and may legitimately
    /// end its post-close wait with an exhausted budget, so no test asserts
    /// a specific value here — the AGENT's outcome is the product property.
    #[allow(dead_code)]
    outcome: LoopOutcome,
}

/// A mock server script: messages pushed to the agent once open, and how
/// many echoes to wait for before closing.
#[derive(Clone)]
struct MockScript {
    send_texts: Vec<String>,
    send_binaries: Vec<Vec<u8>>,
    expect_texts: usize,
    expect_binaries: usize,
}

impl MockScript {
    /// `/getCaseCount`: one text carrying the count, then close.
    fn case_count(count: &str) -> MockScript {
        MockScript {
            send_texts: vec![count.to_owned()],
            send_binaries: Vec::new(),
            expect_texts: 0,
            expect_binaries: 0,
        }
    }

    /// A case: push one text and one binary, expect both echoed.
    fn echo_case() -> MockScript {
        MockScript {
            send_texts: vec!["case-text".to_owned()],
            send_binaries: vec![vec![0x00, 0xFF, 0x10, 0x7F]],
            expect_texts: 1,
            expect_binaries: 1,
        }
    }

    /// `/updateReports`: nothing to exchange, close immediately.
    fn immediate_close() -> MockScript {
        MockScript {
            send_texts: Vec::new(),
            send_binaries: Vec::new(),
            expect_texts: 0,
            expect_binaries: 0,
        }
    }
}

/// Counts echoes and closes once the script's expectations are met.
struct MockPolicy {
    expect_texts: usize,
    expect_binaries: usize,
    seen_texts: usize,
    seen_binaries: usize,
    close_sent: bool,
}

impl MockPolicy {
    fn maybe_close(&mut self, sender: &CommandSender) {
        if self.close_sent
            || self.seen_texts < self.expect_texts
            || self.seen_binaries < self.expect_binaries
        {
            return;
        }
        self.close_sent = true;
        let _ = sender.try_send(LocalCommand::SendClose {
            code: 1000,
            reason: "mock-done".to_owned(),
        });
    }
}

impl EventPolicy for MockPolicy {
    fn on_event(&mut self, event: &SemanticEvent, sender: &CommandSender) {
        match &event.kind {
            ws_core::SemanticEventKind::Text { .. } => self.seen_texts += 1,
            ws_core::SemanticEventKind::Binary { .. } => self.seen_binaries += 1,
            _ => {}
        }
        self.maybe_close(sender);
    }
}

/// Peeks (does NOT consume) the HTTP request head so the assertions can see
/// the exact request target while the driver still parses the same bytes.
fn peek_request_head(stream: &TcpStream) -> String {
    let mut buffer = [0u8; 1024];
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        match stream.peek(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                let text = String::from_utf8_lossy(&buffer[..read]).to_string();
                if text.contains("\r\n") {
                    return text;
                }
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {}
            Err(_) => break,
        }
        thread::sleep(Duration::from_millis(2));
    }
    String::from_utf8_lossy(&buffer).to_string()
}

/// Serves ONE mock fuzzing-server connection to its terminal outcome.
fn serve_mock(listener: &TcpListener, script: &MockScript) -> MockSession {
    let (mut stream, _peer) = listener.accept().expect("mock accept");
    let request_head = peek_request_head(&stream);
    let (sender, mut driver) = connection_driver(ConnectionConfig::default(), Role::Server);
    let bounds = mock_bounds();
    let mut report = empty_report();
    let handshake = drive_until_open(&mut driver, &mut stream, &bounds, &mut report);
    if !handshake.opened {
        return MockSession {
            request_head,
            texts: Vec::new(),
            binaries: Vec::new(),
            outcome: report.outcome,
        };
    }
    for text in &script.send_texts {
        sender
            .try_send(LocalCommand::SendText { text: text.clone() })
            .expect("mock enqueue text");
    }
    for data in &script.send_binaries {
        sender
            .try_send(LocalCommand::SendBinary { data: data.clone() })
            .expect("mock enqueue binary");
    }
    let mut policy = MockPolicy {
        expect_texts: script.expect_texts,
        expect_binaries: script.expect_binaries,
        seen_texts: 0,
        seen_binaries: 0,
        close_sent: false,
    };
    // Nothing to wait for: close right after the scripted sends.
    policy.maybe_close(&sender);
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
    // The suite hangs up at the end of every case; the mock does the same,
    // so the agent's own Q20 terminal outcome can arrive.
    let _ = stream.shutdown(std::net::Shutdown::Both);
    MockSession {
        request_head,
        texts: report.texts,
        binaries: report.binaries,
        outcome: report.outcome,
    }
}

/// Stands the mock server on an ephemeral loopback port and serves the given
/// scripts in order, one connection each.
fn mock_server(scripts: Vec<MockScript>) -> (SocketAddr, thread::JoinHandle<Vec<MockSession>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let address = listener.local_addr().expect("bound address");
    let handle = thread::spawn(move || {
        scripts
            .iter()
            .map(|script| serve_mock(&listener, script))
            .collect()
    });
    (address, handle)
}

/// Test-only I/O bounds for the AGENT under test. The production default
/// (200k polls at a 25 ms read timeout) lets a wedged connection sit for
/// over an hour; a test must fail fast and visibly instead. Behavior under
/// test is unchanged — only the give-up point moves.
fn test_bounds() -> IoBounds {
    IoBounds {
        read_timeout: Duration::from_millis(2),
        write_timeout: Duration::from_millis(2),
        max_polls: 20_000,
        ..IoBounds::default()
    }
}

/// Bounds for the MOCK side, deliberately tighter than the agent's.
///
/// Both peers follow the Java-faithful Q20 rule that the terminal outcome
/// arrives with transport EOF, so after a completed close handshake each
/// side can be left waiting for the other to hang up. The REAL Autobahn
/// fuzzing server never leaves that ambiguity — it closes the TCP
/// connection at the end of every case — so the mock models the suite by
/// bounding its post-close wait and then shutting the socket down
/// ([`serve_mock`]). The agent keeps the larger budget precisely so the
/// mock is always the side that hangs up first.
fn mock_bounds() -> IoBounds {
    IoBounds {
        read_timeout: Duration::from_millis(1),
        write_timeout: Duration::from_millis(1),
        max_polls: 2_000,
        ..IoBounds::default()
    }
}

fn fixture<'a>(address: SocketAddr, agent: &'a str) -> AgentFixture<'a> {
    AgentFixture {
        address,
        host: "localhost",
        agent,
        config: ws_testee::autobahn_config(),
        bounds: test_bounds(),
    }
}

#[test]
fn get_case_count_requests_the_suite_target_and_parses_the_count() {
    let (address, server) = mock_server(vec![MockScript::case_count("247")]);
    let outcome = ws_testee::fetch_case_count(&fixture(address, "rust-agent")).expect("setup");
    let sessions = server.join().expect("mock thread");

    assert_eq!(
        outcome.count,
        Some(247),
        "count parsed from the suite's text"
    );
    assert_eq!(
        sessions[0].request_head.lines().next(),
        Some("GET /getCaseCount HTTP/1.1"),
        "head: {:?}",
        sessions[0].request_head
    );
}

#[test]
fn run_case_requests_the_indexed_case_target_and_echoes_both_payloads() {
    let (address, server) = mock_server(vec![MockScript::echo_case()]);
    let report = ws_testee::run_case(&fixture(address, "rust-agent"), 42).expect("setup");
    let sessions = server.join().expect("mock thread");

    assert_eq!(
        sessions[0].request_head.lines().next(),
        Some("GET /runCase?case=42&agent=rust-agent HTTP/1.1"),
        "head: {:?}",
        sessions[0].request_head
    );
    // The agent echoed text as text and binary as binary, byte-identically.
    assert_eq!(sessions[0].texts, vec!["case-text".to_owned()]);
    assert_eq!(sessions[0].binaries, vec![vec![0x00, 0xFF, 0x10, 0x7F]]);
    // The agent's own run is the assertion that matters: exactly-once
    // terminal, reached through the core-owned close handshake.
    assert!(report.clean(), "agent side: {}", report.summary());
    assert_eq!(report.outcome, LoopOutcome::Terminal);
}

#[test]
fn update_reports_requests_the_agent_scoped_report_target() {
    let (address, server) = mock_server(vec![MockScript::immediate_close()]);
    let report = ws_testee::update_reports(&fixture(address, "rust-agent")).expect("setup");
    let sessions = server.join().expect("mock thread");

    assert_eq!(
        sessions[0].request_head.lines().next(),
        Some("GET /updateReports?agent=rust-agent HTTP/1.1"),
        "head: {:?}",
        sessions[0].request_head
    );
    assert!(report.clean(), "agent side: {}", report.summary());
}

#[test]
fn a_full_agent_sweep_runs_every_case_in_order_then_updates_reports() {
    // The whole fuzzingserver-mode protocol end to end: count, then one
    // connection per case, then the report flush.
    let scripts = vec![
        MockScript::case_count("3"),
        MockScript::echo_case(),
        MockScript::echo_case(),
        MockScript::echo_case(),
        MockScript::immediate_close(),
    ];
    let (address, server) = mock_server(scripts);
    let sweep = ws_testee::run_agent_sweep(&fixture(address, "sweep-agent"), None).expect("setup");
    let sessions = server.join().expect("mock thread");

    assert_eq!(sweep.case_count, 3);
    assert_eq!(sweep.cases.len(), 3);
    assert_eq!(
        sweep.harness_faults(),
        0,
        "every case ran to a real outcome"
    );
    assert_eq!(sweep.terminal(), 3);
    assert!(sweep.reports_updated, "report flush connection completed");
    let targets: Vec<Option<&str>> = sessions
        .iter()
        .map(|session| session.request_head.lines().next())
        .collect();
    assert_eq!(
        targets,
        vec![
            Some("GET /getCaseCount HTTP/1.1"),
            Some("GET /runCase?case=1&agent=sweep-agent HTTP/1.1"),
            Some("GET /runCase?case=2&agent=sweep-agent HTTP/1.1"),
            Some("GET /runCase?case=3&agent=sweep-agent HTTP/1.1"),
            Some("GET /updateReports?agent=sweep-agent HTTP/1.1"),
        ],
        "the exact fuzzingserver agent protocol, in order"
    );
}

#[test]
fn a_sweep_can_be_restricted_to_an_explicit_case_range() {
    // Rerunning a subset (the E5 run2 discipline) must address the SAME
    // 1-based indices the full sweep used, never a renumbered set.
    let scripts = vec![
        MockScript::case_count("9"),
        MockScript::echo_case(),
        MockScript::echo_case(),
        MockScript::immediate_close(),
    ];
    let (address, server) = mock_server(scripts);
    let sweep =
        ws_testee::run_agent_sweep(&fixture(address, "range-agent"), Some((4, 5))).expect("setup");
    let sessions = server.join().expect("mock thread");

    assert_eq!(sweep.case_count, 9, "the suite's own count is still read");
    assert_eq!(sweep.cases.len(), 2, "only the requested range ran");
    let targets: Vec<Option<&str>> = sessions
        .iter()
        .map(|session| session.request_head.lines().next())
        .collect();
    assert_eq!(
        targets,
        vec![
            Some("GET /getCaseCount HTTP/1.1"),
            Some("GET /runCase?case=4&agent=range-agent HTTP/1.1"),
            Some("GET /runCase?case=5&agent=range-agent HTTP/1.1"),
            Some("GET /updateReports?agent=range-agent HTTP/1.1"),
        ]
    );
}

#[test]
fn non_loopback_targets_are_refused_before_any_connect() {
    // The US-018 AC2/AC5 loopback-only contract binds the agent too: the
    // Autobahn container is reached through a loopback-published port, never
    // a routable address.
    let address: SocketAddr = "203.0.113.7:9001".parse().expect("test address");
    assert_eq!(
        ws_testee::fetch_case_count(&fixture(address, "rust-agent")).unwrap_err(),
        SetupOutcome::NonLoopback
    );
    assert_eq!(
        ws_testee::run_case(&fixture(address, "rust-agent"), 1).unwrap_err(),
        SetupOutcome::NonLoopback
    );
    assert_eq!(
        ws_testee::update_reports(&fixture(address, "rust-agent")).unwrap_err(),
        SetupOutcome::NonLoopback
    );
}

#[test]
fn agent_names_that_could_forge_query_parameters_are_rejected() {
    // The agent name lands in the request target verbatim. A name carrying
    // `&`, `?`, `#`, `=`, whitespace or a non-visible byte could forge a
    // different case selection or report scope, so it is refused at the
    // construction seam rather than sanitized silently.
    for good in ["rust-agent", "ws_core.1.6.0", "a", "Rust-Testee-x86-64"] {
        assert!(
            ws_testee::valid_agent_name(good),
            "{good} should be accepted"
        );
    }
    for bad in [
        "", "a&case=9", "a?x", "a=b", "a b", "a#f", "a/b", "a%20b", "üü",
    ] {
        assert!(!ws_testee::valid_agent_name(bad), "{bad} should be refused");
    }
}

/// Serves ONE connection that answers the opening handshake and its first
/// message-phase frames in a SINGLE TCP write.
///
/// Every driver write is buffered instead of being sent, so the 101
/// response, a text frame and a close frame leave the mock as one segment —
/// exactly what the real Autobahn fuzzing server does on `/getCaseCount`
/// (captured on the wire: a single 215-byte response carrying the HTTP head,
/// `81 03 32 34 37` and `88 00`). Built directly on the public `ws_driver`
/// poll contract so the mock never shares the adapter code under test.
fn serve_pipelining_mock(listener: &TcpListener, text: &str) {
    use ws_driver::{DriverInput, DriverOutput};

    let (mut stream, _peer) = listener.accept().expect("mock accept");
    stream
        .set_read_timeout(Some(Duration::from_millis(20)))
        .expect("read timeout");
    let (sender, mut driver) = connection_driver(ConnectionConfig::default(), Role::Server);
    let mut outbound: Vec<u8> = Vec::new();
    let mut inbound = [0u8; 4096];
    let mut queued = false;
    let mut idle_streak = 0_u32;

    for _ in 0..200_000 {
        let result = driver.poll(DriverInput::Wake);
        match result.output {
            DriverOutput::Write(suffix) => {
                // Buffer, never send: this is what makes the response
                // arrive as one pipelined segment.
                let bytes = suffix.to_vec();
                outbound.extend_from_slice(&bytes);
                let _ = driver.poll(DriverInput::WriteProgress { bytes: bytes.len() });
                idle_streak = 0;
                continue;
            }
            DriverOutput::Idle => idle_streak += 1,
            _ => idle_streak = 0,
        }
        if driver.state() != ws_core::ReadyState::NotYetConnected && !queued {
            queued = true;
            idle_streak = 0;
            sender
                .try_send(LocalCommand::SendText {
                    text: text.to_owned(),
                })
                .expect("mock enqueue count text");
            sender
                .try_send(LocalCommand::SendClose {
                    code: 1000,
                    reason: String::new(),
                })
                .expect("mock enqueue close");
            continue;
        }
        // Everything the mock intends to say has been composed.
        if queued && idle_streak > 64 {
            break;
        }
        if queued {
            continue;
        }
        match stream.read(&mut inbound) {
            Ok(0) => break,
            Ok(read) => {
                let chunk = inbound[..read].to_vec();
                let _ = driver.poll(DriverInput::Inbound(&chunk));
                idle_streak = 0;
            }
            Err(_) => {}
        }
    }
    // ONE write carrying handshake response + text frame + close frame.
    stream.write_all(&outbound).expect("mock single write");
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

#[test]
fn a_handshake_response_pipelined_with_the_first_frames_is_not_lost() {
    // REGRESSION (US-019): the Autobahn fuzzing server answers
    // `/getCaseCount` with the 101 response, the case-count text frame and a
    // close frame in ONE TCP segment, then hangs up. If the adapter hands
    // the core a chunk that straddles the handshake boundary, the core
    // stashes the frame bytes in its pending wire buffer, where nothing can
    // ever drain them (the reference model only drains pending on a LATER
    // non-empty chunk), and the whole case count is lost to a bare EOF —
    // the connection ends 1006/transport with zero texts.
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let address = listener.local_addr().expect("bound address");
    let server = thread::spawn(move || serve_pipelining_mock(&listener, "247"));

    let outcome = ws_testee::fetch_case_count(&fixture(address, "pipelined")).expect("setup");
    server.join().expect("mock thread");

    assert_eq!(
        outcome.count,
        Some(247),
        "pipelined case count must survive: {}",
        outcome.report.summary()
    );
    assert_eq!(outcome.report.texts, vec!["247".to_owned()]);
    let close = outcome.report.close.expect("governing close");
    assert_eq!(
        close.code, 1000,
        "the pipelined close frame is processed too, not swallowed as a 1006 transport EOF"
    );
}

#[test]
fn a_case_count_the_suite_never_sent_is_reported_as_absent_not_guessed() {
    // An empty or unparseable count must never be silently treated as zero
    // cases (which would make a sweep "succeed" having tested nothing).
    let (address, server) = mock_server(vec![MockScript::case_count("not-a-number")]);
    let outcome = ws_testee::fetch_case_count(&fixture(address, "rust-agent")).expect("setup");
    let _ = server.join().expect("mock thread");
    assert_eq!(outcome.count, None);

    let (address, server) = mock_server(vec![MockScript::immediate_close()]);
    let outcome = ws_testee::fetch_case_count(&fixture(address, "rust-agent")).expect("setup");
    let _ = server.join().expect("mock thread");
    assert_eq!(outcome.count, None, "no text at all is absent, not zero");
}

#[test]
fn an_explicit_zero_case_count_is_refused_rather_than_swept() {
    // The suite always selects at least one case. An explicit "0" therefore
    // means the suite refused, was misconfigured, or is not the suite --
    // never that there is legitimately nothing to run. Accepting it would
    // produce a sweep that reports SUCCESS having executed no case at all,
    // which is the exact vacuous outcome the case count exists to prevent.
    let (address, server) = mock_server(vec![MockScript::case_count("0")]);
    let outcome = ws_testee::fetch_case_count(&fixture(address, "rust-agent")).expect("setup");
    let _ = server.join().expect("mock thread");
    assert_eq!(
        outcome.count, None,
        "an explicit zero is no better evidence than a missing count"
    );

    // And the whole sweep must fail closed on it, not return an empty success.
    let (address, server) = mock_server(vec![MockScript::case_count("0")]);
    let swept = ws_testee::run_agent_sweep(&fixture(address, "zero-agent"), None);
    let _ = server.join().expect("mock thread");
    assert_eq!(
        swept.err(),
        Some(SetupOutcome::NoCaseCount),
        "a zero-case sweep must be refused, never reported as a successful run"
    );
}

#[test]
fn an_empty_or_inverted_case_range_is_refused_rather_than_swept() {
    // A restricted rerun whose range selects nothing would otherwise run the
    // loop zero times and return a "successful" empty sweep.
    for range in [(1_u32, 0_u32), (5, 4), (0, 0)] {
        let (address, server) = mock_server(vec![MockScript::case_count("9")]);
        let swept = ws_testee::run_agent_sweep(&fixture(address, "range-agent"), Some(range));
        let _ = server.join().expect("mock thread");
        assert_eq!(
            swept.err(),
            Some(SetupOutcome::EmptyCaseRange),
            "range {range:?} selects no case and must be refused"
        );
    }
}
