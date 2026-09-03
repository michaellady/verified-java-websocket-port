//! End-to-end handshake-protocol tests (US-010/US-011 borrow batch B): the
//! REAL committed handshake corpus lines (byte-identical to the recorded
//! live run's `requests.jsonl`, whose digests bind the canonical request
//! bytes) driven through `run_lines`, with the live-transcript vocabulary
//! and the recorded pinned-jar observables as the expectations.

use ws_oracle_harness::core_adapter::active_core;
use ws_oracle_harness::response::RuntimeIdentity;
use ws_oracle_harness::run_lines;

/// `us005.hs.0000` exactly as `corporactl oracle-requests --tier handshake
/// --wire` emits it (a valid client upgrade request; the recorded live jar
/// answered accept with `FJGDqEtc/7v2gIxV23nYHrpYQtU=`).
const HS_0000: &str = r#"{"case_id":"us005.hs.0000","config":{"max_handshake_bytes":4096,"max_header_count":32,"max_header_line_bytes":512},"context":{},"direction":"client_request","protocol":"java-websocket-handshake-oracle","raw_base64":"R0VUIC9zb2NrZXQvMzVhZTU1YzkgSFRUUC8xLjENCkhvc3Q6IGhvc3QtODdjYjEwLmV4YW1wbGUNClVwZ3JhZGU6IHdlYnNvY2tldA0KQ29ubmVjdGlvbjogVXBncmFkZQ0KU2VjLVdlYlNvY2tldC1LZXk6IDdRZzhKdzNxUUw0RVJyL244M1lON3c9PQ0KU2VjLVdlYlNvY2tldC1WZXJzaW9uOiAxMw0KDQo=","request_digest":"sha256:f3d3b69115bbbd49725e5ea059fb730cd726da8962c484d995c8ede57b1b99db","version":"1.0.0"}"#;

/// `us005.hs.0006`: a valid server response judged by the CLIENT slice
/// (`context.client_key` seam; the reported accept value is the client's own
/// `generateFinalKey(trim(client_key))` derivation, which the acceptance
/// predicate had to match for this case to accept at all).
const HS_0006: &str = r#"{"case_id":"us005.hs.0006","config":{"max_handshake_bytes":4096,"max_header_count":32,"max_header_line_bytes":512},"context":{"client_key":"hnt8mbkW8KRynbLvJHSoGQ=="},"direction":"server_response","protocol":"java-websocket-handshake-oracle","raw_base64":"SFRUUC8xLjEgMTAxIFN3aXRjaGluZyBQcm90b2NvbHMNClVwZ3JhZGU6IHdlYnNvY2tldA0KQ29ubmVjdGlvbjogVXBncmFkZQ0KU2VjLVdlYlNvY2tldC1BY2NlcHQ6IHkzcEsxdGtGd2JyajIzYWlHZCtyRmRRTjRmST0NCg0K","request_digest":"sha256:0f0142ffb3697999e8d24ad2e29b1b09ae35242fd677b127b1ac10dbc372faf9","version":"1.0.0"}"#;

/// `us005.hs.0042`: the zero-byte partial input (recorded observable:
/// incomplete).
const HS_0042: &str = r#"{"case_id":"us005.hs.0042","config":{"max_handshake_bytes":4096,"max_header_count":32,"max_header_line_bytes":512},"context":{},"direction":"client_request","protocol":"java-websocket-handshake-oracle","raw_base64":"","request_digest":"sha256:08eba0fcebcfc60fc11dc0dc742127e0f5de6d052500c7412077af447304294e","version":"1.0.0"}"#;

fn test_runtime() -> RuntimeIdentity {
    RuntimeIdentity {
        artifact: "ws-oracle-harness".to_string(),
        sha256: concat!(
            "sha256:2222222222222222222222222222222222222222",
            "222222222222222222222222"
        )
        .to_string(),
    }
}

fn run(input: &str) -> String {
    let mut core = active_core();
    let mut output = Vec::new();
    run_lines(input.as_bytes(), &mut output, &mut core, &test_runtime()).expect("streaming");
    String::from_utf8(output).expect("responses are UTF-8")
}

#[test]
fn real_client_request_case_reproduces_the_recorded_java_accept() {
    let transcript = run(&format!("{HS_0000}\n"));
    let expected = concat!(
        "{\"case_id\":\"us005.hs.0000\",\"java_observable\":\"accept\",",
        "\"protocol\":\"java-websocket-handshake-oracle\",",
        "\"request_digest\":\"sha256:f3d3b69115bbbd49725e5ea059fb730cd726",
        "da8962c484d995c8ede57b1b99db\",",
        "\"runtime\":{\"artifact\":\"ws-oracle-harness\",",
        "\"sha256\":\"sha256:2222222222222222222222222222222222222222",
        "222222222222222222222222\"},",
        "\"sec_websocket_accept\":\"FJGDqEtc/7v2gIxV23nYHrpYQtU=\",",
        "\"version\":\"1.0.0\"}\n"
    );
    assert_eq!(transcript, expected);
}

/// A client-side acceptance reports the accept value it MATCHED. The client
/// does not SEND one, but `acceptHandshakeAsClient` returns MATCHED only when
/// `generateFinalKey(trim(key))` equals the response field literally
/// (Draft_6455.java:318-325), so the value below is this slice's OWN
/// derivation over `context.client_key` — not an echo of the response bytes.
/// The pin is the whole response line: a value that drifted, vanished, or
/// picked up any other field fails here.
#[test]
fn real_server_response_case_reports_the_accept_value_it_matched() {
    let transcript = run(&format!("{HS_0006}\n"));
    let expected = concat!(
        "{\"case_id\":\"us005.hs.0006\",\"java_observable\":\"accept\",",
        "\"protocol\":\"java-websocket-handshake-oracle\",",
        "\"request_digest\":\"sha256:0f0142ffb3697999e8d24ad2e29b1b09ae35",
        "242fd677b127b1ac10dbc372faf9\",",
        "\"runtime\":{\"artifact\":\"ws-oracle-harness\",",
        "\"sha256\":\"sha256:2222222222222222222222222222222222222222",
        "222222222222222222222222\"},",
        "\"sec_websocket_accept\":\"y3pK1tkFwbrj23aiGd+rFdQN4fI=\",",
        "\"version\":\"1.0.0\"}\n"
    );
    assert_eq!(
        transcript, expected,
        "the client-side accept value is the derivation over client_key"
    );
}

#[test]
fn zero_byte_partial_input_reports_incomplete() {
    let transcript = run(&format!("{HS_0042}\n"));
    assert!(
        transcript.contains("\"java_observable\":\"incomplete\""),
        "got {transcript}"
    );
    assert!(!transcript.contains("reject_channel"));
    assert!(!transcript.contains("reject_stage"));
    assert!(!transcript.contains("close_code"));
}

/// Builds a digest-bound handshake request line for crafted inputs (the
/// same canonical-JSON-minus-digest scheme the Go tooling and the recorded
/// corpus use).
fn bound_line(case_id: &str, direction: &str, client_key: Option<&str>, raw: &[u8]) -> String {
    use std::collections::BTreeMap;
    use ws_oracle_harness::json::Value;
    let mut config = BTreeMap::new();
    config.insert("max_handshake_bytes".to_string(), Value::Int(4096));
    config.insert("max_header_count".to_string(), Value::Int(32));
    config.insert("max_header_line_bytes".to_string(), Value::Int(512));
    let mut context = BTreeMap::new();
    if let Some(key) = client_key {
        context.insert("client_key".to_string(), Value::Str(key.to_string()));
    }
    let mut request = BTreeMap::new();
    request.insert("case_id".to_string(), Value::Str(case_id.to_string()));
    request.insert("config".to_string(), Value::Obj(config));
    request.insert("context".to_string(), Value::Obj(context));
    request.insert("direction".to_string(), Value::Str(direction.to_string()));
    request.insert(
        "protocol".to_string(),
        Value::Str("java-websocket-handshake-oracle".to_string()),
    );
    request.insert(
        "raw_base64".to_string(),
        Value::Str(ws_oracle_harness::base64::encode(raw)),
    );
    request.insert("version".to_string(), Value::Str("1.0.0".to_string()));
    let digest = ws_oracle_harness::sha256::digest_identity(
        Value::Obj(request.clone()).canonical().as_bytes(),
    );
    request.insert("request_digest".to_string(), Value::Str(digest));
    Value::Obj(request).canonical()
}

#[test]
fn rejections_carry_the_channel_and_the_1002_close_code() {
    // Version 12 -> NOT_MATCHED (Draft_6455.java:262-268); parse-level
    // garbage -> invalid_handshake. Both carry close_code 1002 (the one
    // collapsed Java rejection observable).
    let not_matched = bound_line(
        "crafted.version12",
        "client_request",
        None,
        b"GET / HTTP/1.1\r\nSec-WebSocket-Key: k\r\nSec-WebSocket-Version: 12\r\n\r\n",
    );
    let transcript = run(&format!("{not_matched}\n"));
    assert!(
        transcript.contains("\"java_observable\":\"reject\""),
        "{transcript}"
    );
    assert!(transcript.contains("\"reject_channel\":\"not_matched\""));
    assert!(transcript.contains("\"close_code\":1002"));

    let invalid = bound_line("crafted.oneword", "client_request", None, b"BAD\r\n\r\n");
    let transcript = run(&format!("{invalid}\n"));
    assert!(transcript.contains("\"reject_channel\":\"invalid_handshake\""));
    assert!(transcript.contains("\"close_code\":1002"));
}

/// Every rejection also names WHICH draft-API call decided it, and the three
/// stages are reachable and distinct. The `invalid_handshake` channel covers
/// two of them, which is the whole reason the key exists: `translate` means no
/// `Handshakedata` was ever built and shipped Java never reached the
/// application listener, while `response_build` means the predicate MATCHED,
/// `onWebsocketHandshakeReceivedAsServer` was already called
/// (WebSocketImpl.java:284-301), and only `postProcessHandshakeResponseAsServer`
/// refused (Draft_6455.java:438-440).
///
/// Deleting the `reject_stage` insertion in `handshake_adapter.rs::respond`
/// leaves every other assertion in this file green; only this one falls.
#[test]
fn rejections_name_the_draft_api_call_that_decided() {
    struct Expect {
        case_id: &'static str,
        direction: &'static str,
        client_key: Option<&'static str>,
        raw: &'static [u8],
        channel: &'static str,
        stage: &'static str,
    }
    let cases = [
        // Head never parsed: one token on the request line.
        Expect {
            case_id: "crafted.oneword",
            direction: "client_request",
            client_key: None,
            raw: b"BAD\r\n\r\n",
            channel: "invalid_handshake",
            stage: "translate",
        },
        // Head parsed; acceptHandshakeAsServer said NOT_MATCHED on version.
        Expect {
            case_id: "crafted.version12",
            direction: "client_request",
            client_key: None,
            raw: b"GET / HTTP/1.1\r\nSec-WebSocket-Key: k\r\nSec-WebSocket-Version: 12\r\n\r\n",
            channel: "not_matched",
            stage: "accept_predicate",
        },
        // Head parsed AND the predicate MATCHED; the response could not be
        // built because Sec-WebSocket-Key is absent. Same CHANNEL as the first
        // row, different STAGE — the collision this key resolves.
        Expect {
            case_id: "crafted.nokey",
            direction: "client_request",
            client_key: None,
            raw: b"GET / HTTP/1.1\r\nSec-WebSocket-Version: 13\r\n\r\n",
            channel: "invalid_handshake",
            stage: "response_build",
        },
        // Client side: a non-101 status throws inside translateHandshakeHttp.
        Expect {
            case_id: "crafted.notonehundredone",
            direction: "server_response",
            client_key: Some("hnt8mbkW8KRynbLvJHSoGQ=="),
            raw: b"HTTP/1.1 404 Not Found\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
            channel: "invalid_handshake",
            stage: "translate",
        },
    ];
    for case in cases {
        let line = bound_line(case.case_id, case.direction, case.client_key, case.raw);
        let transcript = run(&format!("{line}\n"));
        assert!(
            transcript.contains(&format!("\"reject_channel\":\"{}\"", case.channel)),
            "{}: wrong channel in {transcript}",
            case.case_id
        );
        assert!(
            transcript.contains(&format!("\"reject_stage\":\"{}\"", case.stage)),
            "{}: expected stage {} in {transcript}",
            case.case_id,
            case.stage
        );
    }
}

#[test]
fn tampered_raw_fails_the_digest_binding() {
    assert!(HS_0000.contains("xMw0KDQo="), "tamper target must exist");
    let tampered = HS_0000.replace("xMw0KDQo=", "xMg0KDQo=");
    let transcript = run(&format!("{tampered}\n"));
    assert!(
        transcript.contains("\"code\":\"REQUEST_DIGEST_MISMATCH\""),
        "tampered raw must fail the digest binding, got {transcript}"
    );
    assert!(transcript.contains("\"protocol\":\"java-websocket-handshake-oracle\""));
}

#[test]
fn handshake_and_behavior_lines_interleave_on_one_stream() {
    const PUB_0000: &str = concat!(
        "{\"initial_state\":\"open\",\"limits\":{\"max_actions\":64,",
        "\"max_buffered_bytes\":65536,\"max_frames\":64,\"max_input_bytes\":65536,",
        "\"max_output_bytes\":4194304},\"protocol\":\"java-websocket-oracle\",",
        "\"request_digest\":\"sha256:332b88dac25b405b3d9ce3b6a82b4ec8821296a9a4",
        "92aa70a26ce867d817e0c9\",\"request_id\":\"us005.pub.0000\",",
        "\"role\":\"client\",\"steps\":[{\"action\":\"send_close\",\"code\":999,",
        "\"kind\":\"action\",\"reason\":\"bad\"}],\"version\":\"1.0.0\"}"
    );
    let transcript = run(&format!("{HS_0000}\n{PUB_0000}\n"));
    let lines: Vec<&str> = transcript.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("\"java_observable\":\"accept\""));
    assert!(lines[1].contains("\"protocol\":\"java-websocket-oracle\""));
    assert!(lines[1].contains("\"request_id\":\"us005.pub.0000\""));
}

#[test]
fn handshake_responses_are_byte_identical_across_reruns() {
    let input = format!("{HS_0000}\n{HS_0006}\n{HS_0042}\n");
    assert_eq!(run(&input), run(&input), "deterministic transcripts");
}
