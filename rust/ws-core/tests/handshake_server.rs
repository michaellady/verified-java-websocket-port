//! US-011 server-handshake behavior tests: shipped Java-WebSocket 1.6.0
//! fidelity, live-mapping family by family.
//!
//! Expectation authority: `evidence/us005-handshake-live-mapping.json` and
//! the live-verified Go model (`internal/corpora/handshake_live.go`,
//! 49/49 against the real pinned jar). Every RFC-reject-but-Java-accept
//! divergence the live run recorded must ACCEPT here; the Codex-borrowed
//! parser's RFC rejections for those families were stripped, and these
//! tests are the regression armor holding that line.

use ws_core::framing::Draft6455;
use ws_core::handshake::http::{JavaHeadParse, parse_java_head};
use ws_core::handshake::server::{HandshakeState, ServerHandshake, ServerHandshakeOutcome};
use ws_core::handshake::{HandshakeLimitKind, HandshakeLimits, RejectChannel};

fn exam() -> ServerHandshake {
    ServerHandshake::new(HandshakeLimits::hard_ceilings())
}

fn judge(raw: &[u8]) -> ServerHandshakeOutcome {
    exam().consume(raw)
}

fn accept_key_of(raw: &[u8]) -> String {
    match judge(raw) {
        ServerHandshakeOutcome::Accept { accept_key, .. } => accept_key,
        other => panic!("expected accept, got {other:?}"),
    }
}

fn reject_channel_of(raw: &[u8]) -> RejectChannel {
    match judge(raw) {
        ServerHandshakeOutcome::Reject { channel, .. } => channel,
        other => panic!("expected reject, got {other:?}"),
    }
}

/// A valid request template around the RFC sample key.
const VALID: &[u8] = b"GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
const SAMPLE_ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

#[test]
fn valid_request_accepts_with_the_rfc_sample_accept_value() {
    let outcome = judge(VALID);
    let ServerHandshakeOutcome::Accept {
        accept_key,
        response,
        remainder,
    } = outcome
    else {
        panic!("expected accept, got {outcome:?}");
    };
    assert_eq!(accept_key, SAMPLE_ACCEPT);
    assert!(response.starts_with(b"HTTP/1.1 101 "));
    assert!(
        String::from_utf8(response.clone())
            .expect("ASCII response head")
            .contains(&format!("Sec-WebSocket-Accept: {SAMPLE_ACCEPT}\r\n"))
    );
    assert!(remainder.is_empty());
}

/// Live corpus case us005.hs.0000, byte-for-byte: the recorded pinned-jar
/// run produced exactly this accept value.
#[test]
fn live_corpus_case_0000_reproduces_the_recorded_java_accept() {
    let raw = b"GET /socket/35ae55c9 HTTP/1.1\r\nHost: host-87cb10.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: 7Qg8Jw3qQL4ERr/n83YN7w==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    assert_eq!(accept_key_of(raw), "FJGDqEtc/7v2gIxV23nYHrpYQtU=");
}

// ---------------------------------------------------------------------------
// The 16 live-recorded RFC-reject-but-Java-accept divergences (server side)
// ---------------------------------------------------------------------------

#[test]
fn missing_host_upgrade_connection_and_their_values_are_never_examined() {
    // HS_MISSING_HOST / HS_MISSING_UPGRADE / HS_UPGRADE_VALUE /
    // HS_MISSING_CONNECTION / HS_CONNECTION_VALUE: acceptHandshakeAsServer
    // checks only the version; postProcess only the key
    // (Draft_6455.java:262-286, 432-441).
    let bare = b"GET / HTTP/1.1\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    assert_eq!(accept_key_of(bare), SAMPLE_ACCEPT);
    let wrong_values = b"GET / HTTP/1.1\r\nHost: h\r\nUpgrade: h2c\r\nConnection: close\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    assert_eq!(accept_key_of(wrong_values), SAMPLE_ACCEPT);
}

#[test]
fn non_base64_and_wrong_length_keys_are_hashed_as_is() {
    // HS_KEY_NOT_BASE64 / HS_KEY_LENGTH: generateFinalKey hashes any
    // non-empty trimmed string (Draft_6455.java:832-841).
    let raw = b"GET / HTTP/1.1\r\nSec-WebSocket-Key: !!definitely-not-base64!!\r\nSec-WebSocket-Version: 13\r\n\r\n";
    assert_eq!(
        accept_key_of(raw),
        Draft6455::generate_accept_key("!!definitely-not-base64!!")
    );
    let short = b"GET / HTTP/1.1\r\nSec-WebSocket-Key: AAAA\r\nSec-WebSocket-Version: 13\r\n\r\n";
    assert_eq!(accept_key_of(short), Draft6455::generate_accept_key("AAAA"));
}

#[test]
fn duplicated_key_joins_and_hashes_the_joined_string() {
    // HS_DUPLICATE_HEADER seed 0 (live case us005.hs.0027): duplicates join
    // with "; " and the accept value hashes the joined string.
    let raw = b"GET / HTTP/1.1\r\nSec-WebSocket-Key: k1\r\nSec-WebSocket-Key: k2\r\nSec-WebSocket-Version: 13\r\n\r\n";
    assert_eq!(accept_key_of(raw), Draft6455::generate_accept_key("k1; k2"));
}

#[test]
fn duplicated_version_joins_to_an_unparseable_value_and_rejects_not_matched() {
    // HS_DUPLICATE_HEADER seed 1 (live case us005.hs.0028): "13; 13" fails
    // Integer.parseInt -> readVersion -1 -> NOT_MATCHED.
    let raw = b"GET / HTTP/1.1\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Version: 13\r\n\r\n";
    assert_eq!(reject_channel_of(raw), RejectChannel::NotMatched);
}

#[test]
fn header_names_are_never_token_validated() {
    // HS_HEADER_NAME_NOT_TOKEN (live cases us005.hs.0029/0030): "Ho st" is
    // stored as an ordinary header and ignored.
    let raw = b"GET / HTTP/1.1\r\nHo st: value\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    assert_eq!(accept_key_of(raw), SAMPLE_ACCEPT);
}

#[test]
fn bare_lf_folds_into_the_next_line_and_still_accepts() {
    // HS_BARE_LF (live case us005.hs.0034): readLine terminates only on
    // CRLF, so the bare-LF line folds into the following one; the version
    // and key fields survive, so Java accepts.
    let raw = b"GET / HTTP/1.1\r\nUpgrade: websocket\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    assert_eq!(accept_key_of(raw), SAMPLE_ACCEPT);
}

#[test]
fn exam_posture_ignores_per_case_config_limits_like_java() {
    // HS_LIMIT_* (live cases us005.hs.0046-0048): Java has no handshake
    // limits, so a 173-byte valid request accepts even where a case config
    // says 172 bytes / 2 headers / 8-byte lines. The hard-ceiling posture
    // reproduces that while still bounding memory.
    assert!(matches!(
        judge(VALID),
        ServerHandshakeOutcome::Accept { .. }
    ));
}

// ---------------------------------------------------------------------------
// Java's genuine rejections, channel by channel
// ---------------------------------------------------------------------------

#[test]
fn parse_level_rejections_use_the_invalid_handshake_channel() {
    // One-token request line (us005.hs.0031).
    assert_eq!(
        reject_channel_of(b"GET/pathHTTP/1.1\r\n\r\n"),
        RejectChannel::InvalidHandshake
    );
    // Extra token folds into the version token and fails the HTTP/1.1
    // comparison (us005.hs.0032).
    assert_eq!(
        reject_channel_of(b"GET / HTTP/1.1 EXTRA\r\nSec-WebSocket-Version: 13\r\n\r\n"),
        RejectChannel::InvalidHandshake
    );
    // Obs-fold continuation with no colon (us005.hs.0033).
    assert_eq!(
        reject_channel_of(b"GET / HTTP/1.1\r\nUpgrade: websocket\r\n folded\r\n\r\n"),
        RejectChannel::InvalidHandshake
    );
    // Method and HTTP-version rejections (us005.hs.0009-0012).
    assert_eq!(
        reject_channel_of(b"PUT / HTTP/1.1\r\nSec-WebSocket-Version: 13\r\n\r\n"),
        RejectChannel::InvalidHandshake
    );
    assert_eq!(
        reject_channel_of(b"GET / HTTP/1.0\r\nSec-WebSocket-Version: 13\r\n\r\n"),
        RejectChannel::InvalidHandshake
    );
}

#[test]
fn method_and_http_version_compare_case_insensitively() {
    // equalsIgnoreCase granularity (mapping notes on HS_METHOD_NOT_GET and
    // HS_HTTP_VERSION): lowercase spellings ACCEPT in Java.
    let lower = b"get / http/1.1\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    assert_eq!(accept_key_of(lower), SAMPLE_ACCEPT);
}

#[test]
fn missing_or_empty_key_rejects_on_the_invalid_handshake_channel() {
    // HS_MISSING_KEY (us005.hs.0018): version MATCHED, response build throws.
    assert_eq!(
        reject_channel_of(b"GET / HTTP/1.1\r\nSec-WebSocket-Version: 13\r\n\r\n"),
        RejectChannel::InvalidHandshake
    );
    assert_eq!(
        reject_channel_of(
            b"GET / HTTP/1.1\r\nSec-WebSocket-Key:\r\nSec-WebSocket-Version: 13\r\n\r\n"
        ),
        RejectChannel::InvalidHandshake
    );
}

#[test]
fn version_gate_is_integer_parse_int_after_trim() {
    // HS_MISSING_VERSION / HS_VERSION_UNSUPPORTED (us005.hs.0023-0026).
    assert_eq!(
        reject_channel_of(b"GET / HTTP/1.1\r\nSec-WebSocket-Key: k\r\n\r\n"),
        RejectChannel::NotMatched
    );
    assert_eq!(
        reject_channel_of(
            b"GET / HTTP/1.1\r\nSec-WebSocket-Key: k\r\nSec-WebSocket-Version: 8\r\n\r\n"
        ),
        RejectChannel::NotMatched
    );
    assert_eq!(
        reject_channel_of(
            b"GET / HTTP/1.1\r\nSec-WebSocket-Key: k\r\nSec-WebSocket-Version: thirteen\r\n\r\n"
        ),
        RejectChannel::NotMatched
    );
    // Integer.parseInt spellings of 13 all MATCH (live-mapping granularity
    // note): "+13", "0013", " 13 ".
    for spelling in ["+13", "0013", " 13 "] {
        let raw = format!(
            "GET / HTTP/1.1\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: {spelling}\r\n\r\n"
        );
        assert_eq!(
            accept_key_of(raw.as_bytes()),
            SAMPLE_ACCEPT,
            "spelling {spelling:?} must match version 13"
        );
    }
}

#[test]
fn accept_handshake_as_server_is_the_version_only_predicate() {
    // The proof-target symbol checks ONLY the version field.
    let JavaHeadParse::Complete(head) =
        parse_java_head(b"GET / HTTP/1.1\r\nSec-WebSocket-Version: 13\r\n\r\n")
    else {
        panic!("head parses");
    };
    assert_eq!(
        Draft6455::accept_handshake_as_server(&head.headers),
        HandshakeState::Matched
    );
    let JavaHeadParse::Complete(head) = parse_java_head(b"GET / HTTP/1.1\r\n\r\n") else {
        panic!("head parses");
    };
    assert_eq!(
        Draft6455::accept_handshake_as_server(&head.headers),
        HandshakeState::NotMatched
    );
}

// ---------------------------------------------------------------------------
// Incremental behavior: chunking invariance and adversarial splits
// ---------------------------------------------------------------------------

#[test]
fn incomplete_until_the_terminator_arrives() {
    let mut machine = exam();
    let head = &VALID[..VALID.len() - 1];
    assert_eq!(machine.consume(head), ServerHandshakeOutcome::Incomplete);
    let outcome = machine.consume(&VALID[VALID.len() - 1..]);
    assert!(matches!(outcome, ServerHandshakeOutcome::Accept { .. }));
}

#[test]
fn every_split_of_a_valid_request_reaches_the_same_accept() {
    // Adversarial split coverage (the Codex US-011 remediation theme,
    // re-executed under our gates): every 2-chunk split, plus fully
    // byte-at-a-time, must reach the identical terminal outcome.
    let expected = judge(VALID);
    for split in 1..VALID.len() {
        let mut machine = exam();
        let first = machine.consume(&VALID[..split]);
        let outcome = match first {
            ServerHandshakeOutcome::Incomplete => machine.consume(&VALID[split..]),
            terminal => terminal,
        };
        assert_eq!(outcome, expected, "split at {split}");
    }
    let mut machine = exam();
    let mut last = ServerHandshakeOutcome::Incomplete;
    for byte in VALID {
        last = machine.consume(std::slice::from_ref(byte));
    }
    assert_eq!(last, expected);
}

#[test]
fn every_split_of_a_rejecting_request_reaches_the_same_reject() {
    let raw: &[u8] = b"GET / HTTP/1.1 EXTRA\r\nSec-WebSocket-Version: 13\r\n\r\n";
    let expected = judge(raw);
    assert!(matches!(expected, ServerHandshakeOutcome::Reject { .. }));
    for split in 1..raw.len() {
        let mut machine = exam();
        let first = machine.consume(&raw[..split]);
        let outcome = match first {
            ServerHandshakeOutcome::Incomplete => machine.consume(&raw[split..]),
            terminal => terminal,
        };
        assert_eq!(outcome, expected, "split at {split}");
    }
}

#[test]
fn trailing_bytes_after_the_head_are_remainder_not_rejection() {
    // Codex rejected TrailingData; Java hands post-head bytes to the frame
    // layer. (Seed us011/valid-plus-suffix.)
    let mut raw = VALID.to_vec();
    raw.extend_from_slice(b"\x81\x00");
    let ServerHandshakeOutcome::Accept { remainder, .. } = judge(&raw) else {
        panic!("expected accept");
    };
    assert_eq!(remainder, b"\x81\x00");
}

#[test]
fn terminal_machines_refuse_further_bytes() {
    let mut machine = exam();
    assert!(matches!(
        machine.consume(VALID),
        ServerHandshakeOutcome::Accept { .. }
    ));
    assert_eq!(machine.consume(b"x"), ServerHandshakeOutcome::NotAwaiting);
}

// ---------------------------------------------------------------------------
// PLUS_SAFE configured-limit posture (the connection-path strengthening)
// ---------------------------------------------------------------------------

#[test]
fn configured_budgets_refuse_with_the_named_limit() {
    let tiny = |bytes, count, line| HandshakeLimits {
        max_handshake_bytes: bytes,
        max_header_count: count,
        max_header_line_bytes: line,
    };
    let mut machine = ServerHandshake::new(tiny(16, 1024, 65536));
    let ServerHandshakeOutcome::LimitExceeded(refusal) = machine.consume(VALID) else {
        panic!("expected total-bytes refusal");
    };
    assert_eq!(refusal.limit, HandshakeLimitKind::TotalBytes);
    assert_eq!(refusal.attempted, 17);

    let mut machine = ServerHandshake::new(tiny(1_048_576, 2, 65536));
    let ServerHandshakeOutcome::LimitExceeded(refusal) = machine.consume(VALID) else {
        panic!("expected header-count refusal");
    };
    assert_eq!(refusal.limit, HandshakeLimitKind::HeaderCount);
    assert_eq!(refusal.attempted, 3);

    let mut machine = ServerHandshake::new(tiny(1_048_576, 1024, 8));
    let ServerHandshakeOutcome::LimitExceeded(refusal) = machine.consume(VALID) else {
        panic!("expected line refusal");
    };
    assert_eq!(refusal.limit, HandshakeLimitKind::HeaderLineBytes);
    assert_eq!(refusal.attempted, 9);
}
