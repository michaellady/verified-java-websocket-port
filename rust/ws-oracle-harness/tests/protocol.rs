//! End-to-end JSONL protocol tests for the wired harness: one response
//! line per request, deterministic byte-identical reruns, the real
//! `ws_core`-backed execution path (with its honest
//! `CORE_BEHAVIOR_UNIMPLEMENTED` refusals), the retained `CORE_NOT_WIRED`
//! shape of the historical [`UnwiredCore`], and java-oracle line-level
//! guards.

use ws_oracle_harness::core_adapter::{
    UNIMPLEMENTED_CODE, UNIMPLEMENTED_DETAIL, UNWIRED_DETAIL, UnwiredCore, active_core,
};
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

/// The historical UnwiredCore keeps its exact pre-merge envelope shape
/// (`CORE_NOT_WIRED`, zero counts, `final_state == initial_state`) — it is
/// no longer the default, but its honesty discipline is pinned here.
#[test]
fn unwired_core_answers_every_request_with_core_not_wired() {
    let mut core = UnwiredCore;
    let mut output = Vec::new();
    run_lines(
        format!("{PUB_0000}\n").as_bytes(),
        &mut output,
        &mut core,
        &test_runtime(),
    )
    .expect("streaming");
    let transcript = String::from_utf8(output).expect("responses are UTF-8");
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

/// The WIRED default drives PUB_0000 (send_close 999 while OPEN) through
/// the real ws_core: the gates pass, the skeleton refuses the close
/// behavior with the honest non-oracle code, the core-counted action and
/// retained state ride the failure envelope, byte-exact.
#[test]
fn wired_harness_reports_honest_unimplemented_for_skeleton_sends() {
    let transcript = run(&format!("{PUB_0000}\n"));
    let lines: Vec<&str> = transcript.lines().collect();
    assert_eq!(lines.len(), 1);
    let expected = format!(
        concat!(
            "{{\"counts\":{{\"actions\":1,\"buffered_bytes\":0,\"consumed_bytes\":0,",
            "\"frames\":0,\"input_bytes\":0,\"message_buffered_bytes\":0,",
            "\"wire_buffered_bytes\":0}},\"error\":{{\"code\":\"{code}\",",
            "\"detail\":\"{detail}\"}},\"final_state\":\"open\",",
            "\"outcome\":\"error\",\"protocol\":\"java-websocket-oracle\",",
            "\"request_digest\":\"sha256:332b88dac25b405b3d9ce3b6a82b4ec88212",
            "96a9a492aa70a26ce867d817e0c9\",\"request_id\":\"us005.pub.0000\",",
            "\"runtime\":{{\"artifact\":\"ws-oracle-harness\",",
            "\"sha256\":\"sha256:22222222222222222222222222222222222222222222",
            "22222222222222222222\"}},\"version\":\"1.0.0\"}}"
        ),
        code = UNIMPLEMENTED_CODE,
        detail = UNIMPLEMENTED_DETAIL,
    );
    assert_eq!(lines[0], expected);
}

/// The wired core executes the behavior the skeleton DOES own: an `eof`
/// scenario completes ok with the Q20 vocabulary (1006 transport close,
/// eof event, open->closed transition) — the corpus now genuinely scores
/// the Rust on this path.
#[test]
fn wired_harness_completes_eof_scenarios_with_real_core_behavior() {
    let line = line_with_steps("[{\"action\":\"eof\",\"kind\":\"action\"}]");
    let transcript = run(&format!("{line}\n"));
    assert!(
        transcript.contains("\"outcome\":\"ok\""),
        "got: {transcript}"
    );
    assert!(
        transcript.contains(concat!(
            "\"close\":{\"code\":1006,\"handshake_complete\":false,",
            "\"origin\":\"transport\",\"reason\":\"transport EOF before close ",
            "handshake completed\",\"remote\":false}"
        )),
        "got: {transcript}"
    );
    assert!(transcript.contains("\"type\":\"eof\""), "got: {transcript}");
    assert!(
        transcript.contains(concat!(
            "\"transitions\":[{\"cause\":\"eof\",\"from\":\"open\",",
            "\"step\":0,\"to\":\"closed\"}]"
        )),
        "got: {transcript}"
    );
    assert!(
        transcript.contains("\"final_state\":\"closed\""),
        "got: {transcript}"
    );
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
        assert!(line.contains(&format!("\"code\":\"{UNIMPLEMENTED_CODE}\"")));
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

/// Rebuilds `PUB_0000` with the given raw `steps` array (canonical form,
/// fresh digest) so step-shape experiments stay digest-bound.
fn line_with_steps(steps_json: &str) -> String {
    use ws_oracle_harness::json::{self, Value};
    use ws_oracle_harness::request::canonical_request_digest;
    let Value::Obj(mut request) = json::parse(PUB_0000).unwrap() else {
        unreachable!()
    };
    let steps = json::parse(steps_json).expect("steps fixture parses");
    request.insert("steps".to_string(), steps);
    let digest = canonical_request_digest(&request);
    request.insert("request_digest".to_string(), Value::Str(digest));
    Value::Obj(request).canonical()
}

/// Java validates step SHAPE during execution, not at envelope parse time:
/// a malformed step never produces a `request_id: null` line-level error.
/// With the wired core, construction succeeds and each malformed step
/// fails request-bound with its exact execution-time code (Java's
/// `Execution.run` order against the real core state).
#[test]
fn malformed_steps_are_not_envelope_level_rejections() {
    for (steps, expected_code) in [
        (
            "[{\"data_base64\":\"!!!\",\"kind\":\"bytes\"}]",
            "INVALID_BASE64",
        ),
        ("[{\"bogus\":1,\"kind\":\"bytes\"}]", "UNKNOWN_FIELD"),
        ("[{\"kind\":\"warp\"}]", "INVALID_ENUM"),
        // Initial state is OPEN, so requireOpen passes and the missing
        // `text` field is reached (Java's field-read order).
        (
            "[{\"action\":\"send_text\",\"kind\":\"action\"}]",
            "MISSING_FIELD",
        ),
        ("[42]", "TYPE_MISMATCH"),
    ] {
        let transcript = run(&format!("{}\n", line_with_steps(steps)));
        assert!(
            transcript.contains("\"request_id\":\"us005.pub.0000\""),
            "step-shape problems must stay request-bound, got: {transcript}"
        );
        assert!(
            !transcript.contains("\"request_id\":null"),
            "step-shape problems must not be line-level errors, got: {transcript}"
        );
        assert!(
            transcript.contains(&format!("\"code\":\"{expected_code}\"")),
            "expected {expected_code}, got: {transcript}"
        );
    }
}

/// A minimal wired test double: every hook succeeds, `finish` returns the
/// default (empty) observation surface. Lets integration tests reach the
/// completed/failed response paths that the honest UnwiredCore cannot.
struct TestSession {
    fail_bytes_detail: Option<String>,
}

impl ws_oracle_harness::core_adapter::ScenarioSession for TestSession {
    fn bytes(
        &mut self,
        _data: &[u8],
        _step: u32,
    ) -> Result<(), ws_oracle_harness::core_adapter::ScenarioFailure> {
        match &self.fail_bytes_detail {
            Some(detail) => Err(ws_oracle_harness::core_adapter::ScenarioFailure {
                code: "JAVA_INVALID_DATA".to_string(),
                close_code: Some(1002),
                detail: detail.clone(),
            }),
            None => Ok(()),
        }
    }
    fn begin_action(
        &mut self,
        _step: u32,
    ) -> Result<(), ws_oracle_harness::core_adapter::ScenarioFailure> {
        Ok(())
    }
    fn require_open(
        &mut self,
        _action: &str,
    ) -> Result<(), ws_oracle_harness::core_adapter::ScenarioFailure> {
        Ok(())
    }
    fn send_text(
        &mut self,
        _text: &str,
        _step: u32,
    ) -> Result<(), ws_oracle_harness::core_adapter::ScenarioFailure> {
        Ok(())
    }
    fn send_binary(
        &mut self,
        _data: &[u8],
        _step: u32,
    ) -> Result<(), ws_oracle_harness::core_adapter::ScenarioFailure> {
        Ok(())
    }
    fn send_ping(
        &mut self,
        _data: &[u8],
        _step: u32,
    ) -> Result<(), ws_oracle_harness::core_adapter::ScenarioFailure> {
        Ok(())
    }
    fn send_pong(
        &mut self,
        _data: &[u8],
        _step: u32,
    ) -> Result<(), ws_oracle_harness::core_adapter::ScenarioFailure> {
        Ok(())
    }
    fn send_close(
        &mut self,
        _code: i64,
        _reason: &str,
        _step: u32,
    ) -> Result<(), ws_oracle_harness::core_adapter::ScenarioFailure> {
        Ok(())
    }
    fn send_fragment(
        &mut self,
        _opcode: ws_oracle_harness::request::DataOpcode,
        _data: &[u8],
        _fin: bool,
        _step: u32,
    ) -> Result<(), ws_oracle_harness::core_adapter::ScenarioFailure> {
        Ok(())
    }
    fn eof(&mut self, _step: u32) -> Result<(), ws_oracle_harness::core_adapter::ScenarioFailure> {
        Ok(())
    }
    fn snapshot(&self) -> ws_oracle_harness::observe::CountsWithState {
        ws_oracle_harness::observe::CountsWithState::default()
    }
    fn finish(self: Box<Self>) -> ws_oracle_harness::observe::Observations {
        ws_oracle_harness::observe::Observations::default()
    }
}

struct TestCore {
    fail_bytes_detail: Option<String>,
}

impl ws_oracle_harness::core_adapter::CandidateCore for TestCore {
    fn begin(
        &mut self,
        _request: &ws_oracle_harness::request::OracleRequest,
    ) -> Result<
        Box<dyn ws_oracle_harness::core_adapter::ScenarioSession>,
        ws_oracle_harness::core_adapter::ScenarioFailure,
    > {
        Ok(Box::new(TestSession {
            fail_bytes_detail: self.fail_bytes_detail.clone(),
        }))
    }
}

/// Rebuilds `PUB_0000` with the given `max_output_bytes` and raw `steps`
/// (fresh digest), returning both the line and its digest.
fn line_with_output_limit(max_output_bytes: i64, steps_json: &str) -> (String, String) {
    use ws_oracle_harness::json::{self, Value};
    use ws_oracle_harness::request::canonical_request_digest;
    let Value::Obj(mut request) = json::parse(PUB_0000).unwrap() else {
        unreachable!()
    };
    let Some(Value::Obj(limits)) = request.get_mut("limits") else {
        unreachable!()
    };
    limits.insert("max_output_bytes".to_string(), Value::Int(max_output_bytes));
    request.insert(
        "steps".to_string(),
        json::parse(steps_json).expect("steps fixture parses"),
    );
    let digest = canonical_request_digest(&request);
    request.insert("request_digest".to_string(), Value::Str(digest.clone()));
    (Value::Obj(request).canonical(), digest)
}

/// BLOCKING-3: a canonicalized response larger than the request's
/// `max_output_bytes` is replaced with Java's minimal
/// `OUTPUT_LIMIT_EXCEEDED` envelope (`Execution.failure(error, true)`):
/// base fields + error object only — no counts, final_state, or runtime.
#[test]
fn oversized_responses_are_replaced_with_minimal_output_limit_envelope() {
    // 512 is the smallest legal max_output_bytes; even the empty completed
    // envelope (counts + runtime + digest binding) exceeds it.
    let (line, digest) = line_with_output_limit(512, "[]");
    let mut core = TestCore {
        fail_bytes_detail: None,
    };
    let rendered = ws_oracle_harness::respond(&line, &mut core, &test_runtime());
    let expected = format!(
        concat!(
            "{{\"error\":{{\"code\":\"OUTPUT_LIMIT_EXCEEDED\",",
            "\"detail\":\"normalized response exceeds max_output_bytes\"}},",
            "\"outcome\":\"error\",\"protocol\":\"java-websocket-oracle\",",
            "\"request_digest\":\"{digest}\",\"request_id\":\"us005.pub.0000\",",
            "\"version\":\"1.0.0\"}}"
        ),
        digest = digest,
    );
    assert_eq!(rendered, expected);

    // Java applies the same replacement to FAILURE responses (the check
    // guards whatever Execution produced).
    let (line, digest) =
        line_with_output_limit(512, "[{\"data_base64\":\"AQI=\",\"kind\":\"bytes\"}]");
    let mut core = TestCore {
        fail_bytes_detail: Some("x".repeat(600)),
    };
    let rendered = ws_oracle_harness::respond(&line, &mut core, &test_runtime());
    assert!(
        rendered.contains("\"code\":\"OUTPUT_LIMIT_EXCEEDED\""),
        "oversized failure responses are replaced too, got: {rendered}"
    );
    assert!(rendered.contains(&format!("\"request_digest\":\"{digest}\"")));
    assert!(
        !rendered.contains("\"counts\""),
        "minimal envelope has no counts"
    );
    assert!(
        !rendered.contains("\"runtime\""),
        "minimal envelope has no runtime"
    );

    // A comfortable limit leaves the completed response untouched.
    let (line, _) = line_with_output_limit(4_194_304, "[]");
    let mut core = TestCore {
        fail_bytes_detail: None,
    };
    let rendered = ws_oracle_harness::respond(&line, &mut core, &test_runtime());
    assert!(rendered.contains("\"outcome\":\"ok\""));
}

/// BLOCKING-1(d): the JSONL reader buffers at most `HARD_LINE_BYTES` per
/// record (`OracleMain.BoundedLineReader` semantics) — the excess of an
/// oversized line is consumed but never buffered, and the stream stays in
/// sync for the next record.
#[test]
fn line_reader_buffers_at_most_the_hard_limit() {
    use ws_oracle_harness::{HARD_LINE_BYTES, read_bounded_line};
    let mut input = Vec::new();
    input.extend(std::iter::repeat_n(b'a', HARD_LINE_BYTES * 3));
    input.push(b'\n');
    input.extend(PUB_0000.as_bytes());
    input.push(b'\n');
    let mut reader = &input[..];

    let first = read_bounded_line(&mut reader, HARD_LINE_BYTES)
        .expect("read")
        .expect("first record");
    assert!(first.too_long);
    assert_eq!(
        first.bytes.len(),
        HARD_LINE_BYTES,
        "buffering must stop at the limit even though the line was 3x longer"
    );

    let second = read_bounded_line(&mut reader, HARD_LINE_BYTES)
        .expect("read")
        .expect("second record");
    assert!(!second.too_long);
    assert_eq!(second.bytes, PUB_0000.as_bytes());

    assert!(
        read_bounded_line(&mut reader, HARD_LINE_BYTES)
            .expect("read")
            .is_none(),
        "end of input"
    );

    // A record of exactly the limit is NOT too long (Java flags only the
    // byte that crosses the limit).
    let mut exact: &[u8] = &[b"x".repeat(HARD_LINE_BYTES), b"\n".to_vec()].concat();
    let line = read_bounded_line(&mut exact, HARD_LINE_BYTES)
        .expect("read")
        .expect("record");
    assert!(!line.too_long);
    assert_eq!(line.bytes.len(), HARD_LINE_BYTES);
}

/// The PRD quality gate requires `#![forbid(unsafe_code)]` on every crate
/// root; `src/main.rs` is the bin target's own crate root and needs the
/// attribute independently of `src/lib.rs`.
#[test]
fn bin_target_forbids_unsafe_code() {
    let main_rs = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs"),
    )
    .expect("src/main.rs is readable");
    assert!(
        main_rs.contains("#![forbid(unsafe_code)]"),
        "src/main.rs must contain #![forbid(unsafe_code)] (PRD quality gate)"
    );
}

#[test]
fn identify_is_stable_and_truthful() {
    assert_eq!(
        identify(),
        concat!(
            "{\"artifact\":\"ws-oracle-harness\",\"core\":\"wired\",",
            "\"protocol\":\"java-websocket-oracle\",",
            "\"purpose\":\"us009-oracle-candidate-harness\",\"version\":\"1.0.0\"}"
        )
    );
}
