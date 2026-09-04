//! Deterministic replay of the borrowed handshake seed corpora
//! (`fuzz-seeds/us010`, `fuzz-seeds/us011` <- codex `19f7067`/`b6d4b99`).
//!
//! The seed BYTES are adopted as regression armor; the EXPECTATIONS are NOT
//! the Codex ones. Codex asserted RFC-strict verdicts (and tiny per-seed
//! limits); this plane's authority is shipped Java-WebSocket 1.6.0 as
//! live-verified (`internal/corpora/handshake_live.go`), so every
//! expectation below was re-derived from the Java model under the
//! Java-fidelity exam posture (hard-ceiling budgets). Each case cites its
//! reasoning; several outcomes deliberately INVERT the Codex assertion
//! (e.g. `content-length`, `noncanonical-key`, `wrong-key-length`,
//! `invalid-header-name` are Java accepts or NOT_MATCHED rejections, never
//! the Codex typed RFC failures).

use ws_core::framing::Draft6455;
use ws_core::handshake::client::{ClientHandshake, ClientHandshakeOutcome};
use ws_core::handshake::server::{ServerHandshake, ServerHandshakeOutcome};
use ws_core::handshake::{HandshakeLimits, RejectChannel};

fn decode_hex(seed: &str) -> Vec<u8> {
    let cleaned: String = seed.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(cleaned.len().is_multiple_of(2), "seed hex must pair up");
    (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).expect("seed is hex"))
        .collect()
}

/// The client key the US-010 seeds were generated against (the RFC sample
/// nonce; their embedded accept values equal its derivation).
const SEED_CLIENT_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

#[derive(Debug, PartialEq, Eq)]
enum Expect {
    Accept,
    /// Server-side accept with this exact accept-key derivation input.
    AcceptWithKey(&'static str),
    Reject(RejectChannel),
    Incomplete,
}

/// Neither helper here reads the 101 head, so the instant the machine
/// stamps into `Date` (Draft_6455.java:450) only has to be fixed. The head
/// is examined in `handshake_server_response.rs`.
const FIXED_INSTANT: i64 = 1_787_943_099;

fn judge_server(raw: &[u8]) -> Expect {
    let mut machine = ServerHandshake::new(HandshakeLimits::hard_ceilings(), FIXED_INSTANT);
    match machine.consume(raw) {
        ServerHandshakeOutcome::Incomplete => Expect::Incomplete,
        ServerHandshakeOutcome::Accept { .. } => Expect::Accept,
        ServerHandshakeOutcome::Reject { channel, .. } => Expect::Reject(channel),
        other => panic!("unexpected outcome {other:?}"),
    }
}

fn server_accept_key(raw: &[u8]) -> String {
    let mut machine = ServerHandshake::new(HandshakeLimits::hard_ceilings(), FIXED_INSTANT);
    match machine.consume(raw) {
        ServerHandshakeOutcome::Accept { accept_key, .. } => accept_key,
        other => panic!("expected accept, got {other:?}"),
    }
}

fn judge_client(raw: &[u8]) -> Expect {
    let mut machine =
        ClientHandshake::for_recorded_key(SEED_CLIENT_KEY, HandshakeLimits::hard_ceilings());
    match machine.consume(raw) {
        ClientHandshakeOutcome::Incomplete => Expect::Incomplete,
        ClientHandshakeOutcome::Accept { .. } => Expect::Accept,
        ClientHandshakeOutcome::Reject { channel, .. } => Expect::Reject(channel),
        other => panic!("unexpected outcome {other:?}"),
    }
}

#[test]
fn us011_server_seeds_replay_with_java_model_expectations() {
    let cases: [(&str, &str, Expect, &str); 17] = [
        (
            "bare-lf",
            include_str!("../fuzz-seeds/us011/bare-lf.hex"),
            Expect::Incomplete,
            "a lone LF never completes a Java (CRLF-only) line",
        ),
        (
            "content-length",
            include_str!("../fuzz-seeds/us011/content-length.hex"),
            Expect::Reject(RejectChannel::NotMatched),
            "Java ignores Content-Length entirely; the missing version rejects NOT_MATCHED",
        ),
        (
            "count-limit",
            include_str!("../fuzz-seeds/us011/count-limit.hex"),
            Expect::Incomplete,
            "no empty line yet, and Java has no header-count limit",
        ),
        (
            "duplicate-casing",
            include_str!("../fuzz-seeds/us011/duplicate-casing.hex"),
            Expect::Reject(RejectChannel::NotMatched),
            "duplicates join case-insensitively; the missing version rejects NOT_MATCHED",
        ),
        (
            "extension",
            include_str!("../fuzz-seeds/us011/extension.hex"),
            Expect::AcceptWithKey("dGhlIHNhbXBsZSBub25jZQ=="),
            "the default extension accepts anything (DefaultExtension.java:52-58)",
        ),
        (
            "forbidden-value-control",
            include_str!("../fuzz-seeds/us011/forbidden-value-control.hex"),
            Expect::Reject(RejectChannel::NotMatched),
            "Java never polices value octets; the missing version rejects NOT_MATCHED",
        ),
        (
            "incomplete-crlf",
            include_str!("../fuzz-seeds/us011/incomplete-crlf.hex"),
            Expect::Incomplete,
            "a bare CR is not a terminator",
        ),
        (
            "invalid-header-name",
            include_str!("../fuzz-seeds/us011/invalid-header-name.hex"),
            Expect::Reject(RejectChannel::NotMatched),
            "'Bad Name' is stored unvalidated; the missing version rejects NOT_MATCHED",
        ),
        (
            "line-limit",
            include_str!("../fuzz-seeds/us011/line-limit.hex"),
            Expect::Incomplete,
            "Java has no line limit; without CRLF this is an incomplete head",
        ),
        (
            "malformed-request-line",
            include_str!("../fuzz-seeds/us011/malformed-request-line.hex"),
            Expect::Reject(RejectChannel::InvalidHandshake),
            "one-token first line fails split(\" \", 3)",
        ),
        (
            "noncanonical-key",
            include_str!("../fuzz-seeds/us011/noncanonical-key.hex"),
            Expect::AcceptWithKey("AAAAAAAAAAAAAAAAAAAAAB=="),
            "Java hashes the raw header string; key canonicality is never checked",
        ),
        (
            "obs-fold",
            include_str!("../fuzz-seeds/us011/obs-fold.hex"),
            Expect::Reject(RejectChannel::InvalidHandshake),
            "' folded' has no colon: Java's only parse-level header rejection",
        ),
        (
            "subprotocol",
            include_str!("../fuzz-seeds/us011/subprotocol.hex"),
            Expect::AcceptWithKey("dGhlIHNhbXBsZSBub25jZQ=="),
            "the empty default protocol accepts anything (Protocol.java:58-61)",
        ),
        (
            "total-limit",
            include_str!("../fuzz-seeds/us011/total-limit.hex"),
            Expect::Incomplete,
            "Java has no total-bytes limit; without CRLF this is incomplete",
        ),
        (
            "transfer-encoding",
            include_str!("../fuzz-seeds/us011/transfer-encoding.hex"),
            Expect::Reject(RejectChannel::NotMatched),
            "Transfer-Encoding is ignored; the missing version rejects NOT_MATCHED",
        ),
        (
            "valid-plus-suffix",
            include_str!("../fuzz-seeds/us011/valid-plus-suffix.hex"),
            Expect::AcceptWithKey("dGhlIHNhbXBsZSBub25jZQ=="),
            "post-head bytes are frame-layer remainder, never a rejection",
        ),
        (
            "wrong-key-length",
            include_str!("../fuzz-seeds/us011/wrong-key-length.hex"),
            Expect::AcceptWithKey("AAAA"),
            "decoded key length is never validated",
        ),
    ];
    for (name, seed, expected, why) in cases {
        let raw = decode_hex(seed);
        match expected {
            Expect::AcceptWithKey(key) => {
                assert_eq!(
                    server_accept_key(&raw),
                    Draft6455::generate_accept_key(key),
                    "seed us011/{name}: {why}"
                );
            }
            other => assert_eq!(judge_server(&raw), other, "seed us011/{name}: {why}"),
        }
    }
}

#[test]
fn us010_client_seeds_replay_with_java_model_expectations() {
    let cases: [(&str, &str, Expect, &str); 11] = [
        (
            "bare-lf",
            include_str!("../fuzz-seeds/us010/bare-lf.hex"),
            Expect::Incomplete,
            "LF-only responses never complete a Java line",
        ),
        (
            "count-limit",
            include_str!("../fuzz-seeds/us010/count-limit.hex"),
            Expect::Accept,
            "extra headers are ignored and Java has no count limit",
        ),
        (
            "duplicate-casing",
            include_str!("../fuzz-seeds/us010/duplicate-casing.hex"),
            Expect::Reject(RejectChannel::NotMatched),
            "Upgrade joins to 'websocket; websocket', failing basicAccept",
        ),
        (
            "extension",
            include_str!("../fuzz-seeds/us010/extension.hex"),
            Expect::Accept,
            "the client side never rejects offered extensions",
        ),
        (
            "incomplete-crlf",
            include_str!("../fuzz-seeds/us010/incomplete-crlf.hex"),
            Expect::Incomplete,
            "a bare CR is not a terminator",
        ),
        (
            "invalid-token",
            include_str!("../fuzz-seeds/us010/invalid-token.hex"),
            Expect::Reject(RejectChannel::NotMatched),
            "'Up grade' is stored unvalidated, so Upgrade is missing for basicAccept",
        ),
        (
            "line-limit",
            include_str!("../fuzz-seeds/us010/line-limit.hex"),
            Expect::Incomplete,
            "no empty line yet, and Java has no line limit",
        ),
        (
            "obs-fold",
            include_str!("../fuzz-seeds/us010/obs-fold.hex"),
            Expect::Reject(RejectChannel::NotMatched),
            "' Upgrade' parses as a space-prefixed name, so Upgrade is missing",
        ),
        (
            "subprotocol",
            include_str!("../fuzz-seeds/us010/subprotocol.hex"),
            Expect::Accept,
            "the client side never rejects offered subprotocols",
        ),
        (
            "total-limit",
            include_str!("../fuzz-seeds/us010/total-limit.hex"),
            Expect::Incomplete,
            "no CRLF at all: an incomplete head, not a limit rejection",
        ),
        (
            "valid-plus-suffix",
            include_str!("../fuzz-seeds/us010/valid-plus-suffix.hex"),
            Expect::Accept,
            "post-head bytes are remainder, never a rejection",
        ),
    ];
    for (name, seed, expected, why) in cases {
        let raw = decode_hex(seed);
        assert_eq!(judge_client(&raw), expected, "seed us010/{name}: {why}");
    }
}
