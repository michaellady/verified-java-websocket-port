//! US-010 client-handshake behavior tests: deterministic request
//! generation plus shipped Java-WebSocket 1.6.0 response acceptance
//! (authority: `internal/corpora/handshake_live.go` `javaClientObservable`
//! and the live mapping's `server_response` rows), and the ConnectionCore
//! handshake entry hook for both roles.

mod data;

use data::nonce_vectors::DETERMINISTIC_NONCE_VECTORS;
use ws_core::framing::Draft6455;
use ws_core::handshake::client::{
    ClientHandshake, ClientHandshakeOutcome, ClientRequestDescriptor, nonce_from_seed,
};
use ws_core::handshake::{HandshakeLimits, RejectChannel};
use ws_core::{ConnectionConfig, ConnectionCore, FailureCode, Input, ReadyState, Role};

const SAMPLE_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

fn exam(client_key: &str) -> ClientHandshake {
    ClientHandshake::for_recorded_key(client_key, HandshakeLimits::hard_ceilings())
}

fn judge(client_key: &str, raw: &[u8]) -> ClientHandshakeOutcome {
    exam(client_key).consume(raw)
}

fn reject_channel_of(client_key: &str, raw: &[u8]) -> RejectChannel {
    match judge(client_key, raw) {
        ClientHandshakeOutcome::Reject { channel } => channel,
        other => panic!("expected reject, got {other:?}"),
    }
}

const VALID_RESPONSE: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";

#[test]
fn valid_response_accepts() {
    assert!(matches!(
        judge(SAMPLE_KEY, VALID_RESPONSE),
        ClientHandshakeOutcome::Accept { .. }
    ));
}

#[test]
fn status_token_is_compared_literally_before_the_http_version() {
    // Draft.java:164-180 via the live mapping's HS_MALFORMED_STATUS_LINE
    // note: exactly three tokens and the literal "101".
    assert_eq!(
        reject_channel_of(SAMPLE_KEY, b"HTTP/1.1 0101 X\r\n\r\n"),
        RejectChannel::InvalidHandshake
    );
    assert_eq!(
        reject_channel_of(SAMPLE_KEY, b"HTTP/1.1 101\r\n\r\n"),
        RejectChannel::InvalidHandshake
    );
    assert_eq!(
        reject_channel_of(SAMPLE_KEY, b"HTTP/1.1 404 Not Found\r\n\r\n"),
        RejectChannel::InvalidHandshake
    );
    // equalsIgnoreCase on the version token: a lowercase spelling accepts.
    let lower = b"http/1.1 101 ok\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    assert!(matches!(
        judge(SAMPLE_KEY, lower),
        ClientHandshakeOutcome::Accept { .. }
    ));
    // Wrong version with a correct 101 status: invalid_handshake.
    assert_eq!(
        reject_channel_of(SAMPLE_KEY, b"HTTP/1.0 101 X\r\n\r\n"),
        RejectChannel::InvalidHandshake
    );
}

#[test]
fn basic_accept_gates_upgrade_and_connection_on_the_not_matched_channel() {
    // HS_MISSING_UPGRADE / HS_UPGRADE_VALUE / HS_MISSING_CONNECTION /
    // HS_CONNECTION_VALUE (server_response rows): basicAccept, quirk Q9.
    let missing_upgrade = b"HTTP/1.1 101 X\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    assert_eq!(
        reject_channel_of(SAMPLE_KEY, missing_upgrade),
        RejectChannel::NotMatched
    );
    let wrong_upgrade = b"HTTP/1.1 101 X\r\nUpgrade: h2c\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    assert_eq!(
        reject_channel_of(SAMPLE_KEY, wrong_upgrade),
        RejectChannel::NotMatched
    );
    let missing_connection = b"HTTP/1.1 101 X\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    assert_eq!(
        reject_channel_of(SAMPLE_KEY, missing_connection),
        RejectChannel::NotMatched
    );
    // Connection CONTAINING "upgrade" case-insensitively accepts.
    let keep_alive = b"HTTP/1.1 101 X\r\nUpgrade: WebSocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    assert!(matches!(
        judge(SAMPLE_KEY, keep_alive),
        ClientHandshakeOutcome::Accept { .. }
    ));
}

#[test]
fn accept_field_is_required_present_and_literally_equal() {
    // HS_MISSING_ACCEPT / HS_ACCEPT_MISMATCH (Draft_6455.java:312-325).
    let missing = b"HTTP/1.1 101 X\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
    assert_eq!(
        reject_channel_of(SAMPLE_KEY, missing),
        RejectChannel::NotMatched
    );
    let mismatch = b"HTTP/1.1 101 X\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n";
    assert_eq!(
        reject_channel_of(SAMPLE_KEY, mismatch),
        RejectChannel::NotMatched
    );
    // A duplicated accept joins with "; " and can no longer equal the
    // derived value (HS_DUPLICATE_HEADER, server_response row).
    let duplicated = b"HTTP/1.1 101 X\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    assert_eq!(
        reject_channel_of(SAMPLE_KEY, duplicated),
        RejectChannel::NotMatched
    );
}

#[test]
fn an_absent_recorded_client_key_rejects_not_matched() {
    // Draft_6455.java:312-316: a missing request key can never match.
    assert_eq!(
        reject_channel_of("", VALID_RESPONSE),
        RejectChannel::NotMatched
    );
}

#[test]
fn incomplete_responses_keep_buffering() {
    assert_eq!(
        judge(SAMPLE_KEY, b"HTTP/1.1 101 Switching Protocols\r"),
        ClientHandshakeOutcome::Incomplete
    );
    // Bare-LF-only responses never complete a line (seed us010/bare-lf).
    assert_eq!(
        judge(SAMPLE_KEY, b"HTTP/1.1 101 X\nUpgrade: websocket\n\n"),
        ClientHandshakeOutcome::Incomplete
    );
}

#[test]
fn obs_fold_with_a_colon_is_a_space_prefixed_header_name_in_java() {
    // Seed us010/obs-fold: " Upgrade: websocket" parses as header name
    // " upgrade" (never token-validated), so Upgrade is MISSING and
    // basicAccept rejects NOT_MATCHED — not Codex's ObsoleteLineFolding.
    let raw = b"HTTP/1.1 101 Switching Protocols\r\n Upgrade: websocket\r\n\r\n";
    assert_eq!(
        reject_channel_of(SAMPLE_KEY, raw),
        RejectChannel::NotMatched
    );
}

#[test]
fn every_split_of_a_valid_response_reaches_the_same_accept() {
    let expected = judge(SAMPLE_KEY, VALID_RESPONSE);
    assert!(matches!(expected, ClientHandshakeOutcome::Accept { .. }));
    for split in 1..VALID_RESPONSE.len() {
        let mut machine = exam(SAMPLE_KEY);
        let first = machine.consume(&VALID_RESPONSE[..split]);
        let outcome = match first {
            ClientHandshakeOutcome::Incomplete => machine.consume(&VALID_RESPONSE[split..]),
            terminal => terminal,
        };
        assert_eq!(outcome, expected, "split at {split}");
    }
}

// ---------------------------------------------------------------------------
// Accept derivation vectors (borrowed table, independently spot-verified)
// ---------------------------------------------------------------------------

#[test]
fn all_256_nonce_vectors_derive_their_recorded_accept_values() {
    for (key, accept) in DETERMINISTIC_NONCE_VECTORS {
        assert_eq!(&Draft6455::generate_accept_key(key), accept, "key {key}");
    }
}

// ---------------------------------------------------------------------------
// Deterministic request generation (mask_key_seed seam)
// ---------------------------------------------------------------------------

#[test]
fn request_generation_is_deterministic_in_the_seed() {
    let descriptor = ClientRequestDescriptor::try_new("/chat", "example.com").expect("valid");
    let limits = HandshakeLimits::hard_ceilings();
    let (_, first) = ClientHandshake::start(&descriptor, nonce_from_seed(7), limits);
    let (_, second) = ClientHandshake::start(&descriptor, nonce_from_seed(7), limits);
    assert_eq!(first, second, "same seed, same request bytes");
    let (_, third) = ClientHandshake::start(&descriptor, nonce_from_seed(8), limits);
    assert_ne!(first, third, "different seed, different key");
    let rendered = String::from_utf8(first).expect("ASCII request");
    assert!(rendered.starts_with("GET /chat HTTP/1.1\r\nHost: example.com\r\n"));
    assert!(rendered.contains("Upgrade: websocket\r\n"));
    assert!(rendered.contains("Connection: Upgrade\r\n"));
    assert!(rendered.contains("Sec-WebSocket-Version: 13\r\n"));
    assert!(rendered.ends_with("\r\n\r\n"));
}

#[test]
fn descriptor_validation_guards_header_injection() {
    assert!(ClientRequestDescriptor::try_new("/ok", "host").is_ok());
    assert!(ClientRequestDescriptor::try_new("nope", "host").is_err());
    assert!(ClientRequestDescriptor::try_new("/a b", "host").is_err());
    assert!(ClientRequestDescriptor::try_new("/ok", "").is_err());
    assert!(ClientRequestDescriptor::try_new("/ok", "h\r\nX: y").is_err());
}

// ---------------------------------------------------------------------------
// ConnectionCore handshake entry hook (batch-B connection.rs dispatch)
// ---------------------------------------------------------------------------

fn extract_key(request: &str) -> String {
    request
        .lines()
        .find_map(|line| line.strip_prefix("Sec-WebSocket-Key: "))
        .expect("request carries a key")
        .to_string()
}

#[test]
fn client_connection_opens_through_begin_client_handshake() {
    let mut core = ConnectionCore::new(ConnectionConfig::default(), Role::Client);
    core.begin_client_handshake("/chat", "example.com")
        .expect("fresh client core starts the handshake");
    let request = core.next_write().expect("the upgrade request is queued");
    let key = extract_key(&String::from_utf8(request.bytes).expect("ASCII request"));
    let accept = Draft6455::generate_accept_key(&key);
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    core.handle(Input::TransportBytes(response.as_bytes()))
        .expect("a matching response opens the connection");
    assert_eq!(core.state(), ReadyState::Open);
    // Handshake-phase bytes stay outside the corpus counters.
    assert_eq!(core.counts().input_bytes, 0);
    assert!(core.next_event().is_none(), "no corpus events pre-open");
}

#[test]
fn client_connection_rejects_a_mismatched_response_with_close_1002() {
    let mut core = ConnectionCore::new(ConnectionConfig::default(), Role::Client);
    core.begin_client_handshake("/chat", "example.com")
        .expect("start");
    let _request = core.next_write().expect("request queued");
    let err = core
        .handle(Input::TransportBytes(
            b"HTTP/1.1 101 X\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n",
        ))
        .expect_err("mismatched accept rejects");
    assert_eq!(err.code, FailureCode::JavaInvalidData);
    assert_eq!(err.close_code, Some(1002));
    // Poisoned thereafter (partial-execution semantics).
    let err = core
        .handle(Input::TransportBytes(b"x"))
        .expect_err("poisoned");
    assert_eq!(err.code, FailureCode::StateViolation);
}

#[test]
fn client_bytes_before_begin_are_a_state_violation() {
    let mut core = ConnectionCore::new(ConnectionConfig::default(), Role::Client);
    let err = core
        .handle(Input::TransportBytes(b"HTTP/1.1 101 X\r\n"))
        .expect_err("an unrequested response is refused");
    assert_eq!(err.code, FailureCode::StateViolation);
}

#[test]
fn server_connection_opens_and_writes_the_101_head() {
    let mut core = ConnectionCore::new(ConnectionConfig::default(), Role::Server);
    let request = b"GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    // Chunked arrival: incomplete first, then open on the terminator.
    core.handle(Input::TransportBytes(&request[..10]))
        .expect("buffering");
    assert_eq!(core.state(), ReadyState::NotYetConnected);
    core.handle(Input::TransportBytes(&request[10..]))
        .expect("accept");
    assert_eq!(core.state(), ReadyState::Open);
    let response = core.next_write().expect("101 head queued");
    let rendered = String::from_utf8(response.bytes).expect("ASCII head");
    assert!(rendered.starts_with("HTTP/1.1 101 "));
    assert!(rendered.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"));
    // Post-open bytes flow through the ordinary corpus byte path.
    core.handle(Input::TransportBytes(b"\x81"))
        .expect("open-state bytes buffer");
    assert_eq!(core.counts().input_bytes, 1);
}

#[test]
fn server_connection_rejects_with_the_collapsed_java_observable() {
    let mut core = ConnectionCore::new(ConnectionConfig::default(), Role::Server);
    let err = core
        .handle(Input::TransportBytes(
            b"GET / HTTP/1.1\r\nSec-WebSocket-Version: 12\r\n\r\n",
        ))
        .expect_err("version 12 rejects");
    assert_eq!(err.code, FailureCode::JavaInvalidData);
    assert_eq!(err.close_code, Some(1002));
    let error_head = core.next_write().expect("error head queued");
    assert!(error_head.bytes.starts_with(b"HTTP/1.1 404"));
}

#[test]
fn server_connection_enforces_the_configured_handshake_budget() {
    // The connection path (unlike the exam posture) enforces the configured
    // limits — the pinned US-009 PLUS_SAFE strengthening.
    let config = ConnectionConfig::builder()
        .max_handshake_bytes(16)
        .build()
        .expect("valid config");
    let mut core = ConnectionCore::new(config, Role::Server);
    let err = core
        .handle(Input::TransportBytes(
            b"GET /chat HTTP/1.1\r\nHost: example.com\r\n",
        ))
        .expect_err("16-byte budget refuses");
    assert_eq!(err.code, FailureCode::BufferLimitExceeded);
}

#[test]
fn begin_client_handshake_misuse_is_refused() {
    // Wrong role.
    let mut server = ConnectionCore::new(ConnectionConfig::default(), Role::Server);
    let err = server
        .begin_client_handshake("/x", "h")
        .expect_err("server role cannot start a client handshake");
    assert_eq!(err.code, FailureCode::StateViolation);
    // Double start.
    let mut client = ConnectionCore::new(ConnectionConfig::default(), Role::Client);
    client.begin_client_handshake("/x", "h").expect("first");
    let err = client
        .begin_client_handshake("/x", "h")
        .expect_err("second start is refused");
    assert_eq!(err.code, FailureCode::StateViolation);
}
