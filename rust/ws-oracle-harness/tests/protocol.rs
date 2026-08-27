//! End-to-end JSONL protocol tests for the unwired harness: one response
//! line per request, deterministic byte-identical reruns, truthful
//! `CORE_NOT_WIRED` failure envelopes, and java-oracle line-level guards.

use ws_oracle_harness::core_adapter::{UNWIRED_DETAIL, active_core};
use ws_oracle_harness::response::RuntimeIdentity;
use ws_oracle_harness::{identify, run_lines};

/// The exact `us005.pub.0000` request line `corporactl oracle-requests
/// --tier public` emits.
const PUB_0000: &str = concat!(
    "{\"initial_state\":\"open\",\"limits\":{\"max_actions\":64,",
    "\"max_buffered_bytes\":65536,\"max_frames\":64,\"max_input_bytes\":65536,",
    "\"max_output_bytes\":4194304},\"protocol\":\"java-websocket-oracle\",",
    "\"request_digest\":\"sha256:332b88dac25b405b3d9ce3b6a82b4ec8821296a9a4",
    "92aa70a26ce867d817e0c9\",\"request_id\":\"us005.pub.0000\",",
    "\"role\":\"client\",\"steps\":[{\"action\":\"send_close\",\"code\":999,",
    "\"kind\":\"action\",\"reason\":\"bad\"}],\"version\":\"1.0.0\"}"
);

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
fn unwired_harness_answers_every_request_with_core_not_wired() {
    let transcript = run(&format!("{PUB_0000}\n"));
    let lines: Vec<&str> = transcript.lines().collect();
    assert_eq!(lines.len(), 1);
    let expected = format!(
        concat!(
            "{{\"counts\":{{\"actions\":0,\"buffered_bytes\":0,\"consumed_bytes\":0,",
            "\"frames\":0,\"input_bytes\":0,\"message_buffered_bytes\":0,",
            "\"wire_buffered_bytes\":0}},\"error\":{{\"code\":\"CORE_NOT_WIRED\",",
            "\"detail\":\"{detail}\"}},\"final_state\":\"open\",",
            "\"outcome\":\"error\",\"protocol\":\"java-websocket-oracle\",",
            "\"request_digest\":\"sha256:332b88dac25b405b3d9ce3b6a82b4ec88212",
            "96a9a492aa70a26ce867d817e0c9\",\"request_id\":\"us005.pub.0000\",",
            "\"runtime\":{{\"artifact\":\"ws-oracle-harness\",",
            "\"sha256\":\"sha256:22222222222222222222222222222222222222222222",
            "22222222222222222222\"}},\"version\":\"1.0.0\"}}"
        ),
        detail = UNWIRED_DETAIL,
    );
    assert_eq!(lines[0], expected);
}

#[test]
fn reruns_are_byte_identical_and_one_line_per_request() {
    let input = format!("{PUB_0000}\n{PUB_0000}\n");
    let first = run(&input);
    let second = run(&input);
    assert_eq!(first, second, "reruns must be byte-identical");
    assert_eq!(first.lines().count(), 2, "one response line per request");
    for line in first.lines() {
        assert!(line.contains("\"request_id\":\"us005.pub.0000\""));
        assert!(line.contains("\"code\":\"CORE_NOT_WIRED\""));
        assert!(
            !line.contains(&format!("sha256:{}", "0".repeat(64))),
            "the harness must never carry the stub's all-zero identity"
        );
    }
}

#[test]
fn line_level_guards_mirror_oracle_main() {
    // Interior empty line -> EMPTY_LINE typed response, stream continues.
    let transcript = run(&format!("\n{PUB_0000}\n"));
    let lines: Vec<&str> = transcript.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("\"code\":\"EMPTY_LINE\""));
    assert!(lines[0].contains("\"request_id\":null"));
    assert!(lines[1].contains("\"request_id\":\"us005.pub.0000\""));

    // Invalid JSON -> INVALID_JSON typed response.
    let transcript = run("not json\n");
    assert!(transcript.contains("\"code\":\"INVALID_JSON\""));

    // Invalid UTF-8 -> INVALID_UTF8 typed response.
    let mut core = active_core();
    let mut output = Vec::new();
    run_lines(
        &b"{\"a\":\"\xff\"}\n"[..],
        &mut output,
        &mut core,
        &test_runtime(),
    )
    .expect("streaming");
    let transcript = String::from_utf8(output).unwrap();
    assert!(transcript.contains("\"code\":\"INVALID_UTF8\""));

    // Oversized line -> LINE_LIMIT_EXCEEDED typed response.
    let oversized = format!("{{\"pad\":\"{}\"}}\n", "a".repeat(1_048_576));
    let transcript = run(&oversized);
    assert!(transcript.contains("\"code\":\"LINE_LIMIT_EXCEEDED\""));

    // Digest-tampered request -> REQUEST_DIGEST_MISMATCH before the core.
    let tampered = PUB_0000.replace("\"code\":999", "\"code\":998");
    let transcript = run(&format!("{tampered}\n"));
    assert!(transcript.contains("\"code\":\"REQUEST_DIGEST_MISMATCH\""));
}

#[test]
fn final_line_without_newline_is_still_answered() {
    let transcript = run(PUB_0000);
    assert_eq!(transcript.lines().count(), 1);
    assert!(transcript.contains("\"request_id\":\"us005.pub.0000\""));
}

#[test]
fn identify_is_stable_and_truthful() {
    assert_eq!(
        identify(),
        concat!(
            "{\"artifact\":\"ws-oracle-harness\",\"core\":\"unwired\",",
            "\"protocol\":\"java-websocket-oracle\",",
            "\"purpose\":\"us009-oracle-candidate-harness\",\"version\":\"1.0.0\"}"
        )
    );
}
