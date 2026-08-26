//! # candidate-stub (US-005 candidate-execution instruments)
//!
//! Inert stub target plus planted Rust mutants for the US-005 behavior-corpus
//! calibration gates. Every binary in this crate speaks the java-oracle JSONL
//! protocol on stdin/stdout (`corporactl oracle-requests` lines in, one
//! response line per request out) but implements **no WebSocket behavior**:
//!
//! - `us005-candidate-stub` — the negative control. Mirrors the committed
//!   Go-side `synthesizeStubResponse` shape exactly (outcome `ok`, zero
//!   counts, no events/frames/transitions, `final_state == initial_state`).
//!   Its purpose is to FAIL the corpus: `corporactl evaluate` must report
//!   zero passes against every behavior tier.
//! - `us005-mutant-rs-eager-reject` — planted deviation analogous to a
//!   wrong-close-code protocol rejecter: answers every request with outcome
//!   `error`, code `JAVA_INVALID_DATA`, close code 1002, `final_state`
//!   `closed`, zero counts.
//! - `us005-mutant-rs-digest-unbind` — planted deviation that breaks the
//!   request-digest binding discipline: the stub response with
//!   `request_digest` replaced by an all-zero digest, so every response fails
//!   `request_digest does not bind this scenario`.
//!
//! The deviations are documented in `mutants/manifest.json` at the repo root.
//! These are calibration instruments only; no story acceptance, production,
//! or publication claim is made by this crate.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::io::{BufRead, Write};

/// Oracle protocol name pinned by the vendored java-oracle adapter.
pub const PROTOCOL: &str = "java-websocket-oracle";
/// Oracle protocol version pinned by the vendored java-oracle adapter.
pub const VERSION: &str = "1.0.0";
/// All-zero SHA-256 identity used by inert candidates (mirrors the Go stub).
pub const ZERO_SHA256: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Which planted deviation a binary carries. `Inert` is the stub baseline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Deviation {
    /// No deviation: the inert stub negative control.
    Inert,
    /// Planted mutant: unconditional protocol rejection with close code 1002.
    EagerReject,
    /// Planted mutant: responses carry an all-zero request digest.
    DigestUnbind,
}

impl Deviation {
    /// Stable artifact identifier for transcripts and `--identify` output.
    pub fn artifact(self) -> &'static str {
        match self {
            // The inert stub uses the exact artifact identity of the
            // committed Go negative control (`synthesizeStubResponse`).
            Deviation::Inert => "stub-target",
            Deviation::EagerReject => "us005-mutant-rs-eager-reject",
            Deviation::DigestUnbind => "us005-mutant-rs-digest-unbind",
        }
    }
}

/// Extracts a top-level string field from one canonical JSONL request line.
///
/// This is deliberately NOT a JSON parser. `corporactl oracle-requests`
/// emits canonical JSON (sorted keys, no insignificant whitespace) and the
/// four fields the candidates need (`request_id`, `request_digest`, `role`,
/// `initial_state`) are constrained to escape-free character sets by the
/// oracle protocol. The extractor therefore scans for `"key":"` and reads to
/// the next quote, failing closed (`None`) if the value contains a backslash
/// or the pattern is absent.
pub fn extract_string_field(line: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    let end = rest.find('"')?;
    let value = &rest[..end];
    if value.contains('\\') {
        return None;
    }
    Some(value.to_string())
}

fn zero_counts() -> String {
    concat!(
        "{\"actions\":0,\"buffered_bytes\":0,\"consumed_bytes\":0,",
        "\"frames\":0,\"input_bytes\":0,\"message_buffered_bytes\":0,",
        "\"wire_buffered_bytes\":0}"
    )
    .to_string()
}

fn runtime_object(deviation: Deviation) -> String {
    format!(
        "{{\"artifact\":\"{}\",\"sha256\":\"{ZERO_SHA256}\"}}",
        deviation.artifact()
    )
}

/// Envelope fields extracted from one request line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// `request_id` of the scenario (echoed so the evaluator matches it).
    pub request_id: String,
    /// Canonical `request_digest` binding the scenario.
    pub request_digest: String,
    /// Declared connection role (`client` or `server`).
    pub role: String,
    /// Declared initial state.
    pub initial_state: String,
}

/// Parses the envelope from a canonical request line, failing closed.
pub fn parse_envelope(line: &str) -> Option<Envelope> {
    Some(Envelope {
        request_id: extract_string_field(line, "request_id")?,
        request_digest: extract_string_field(line, "request_digest")?,
        role: extract_string_field(line, "role")?,
        initial_state: extract_string_field(line, "initial_state")?,
    })
}

fn inert_response(envelope: &Envelope, request_digest: &str, deviation: Deviation) -> String {
    format!(
        "{{\"close\":null,\"counts\":{counts},\"events\":[],\
         \"final_state\":\"{state}\",\"frames\":[],\
         \"initial_state\":\"{state}\",\"outcome\":\"ok\",\
         \"protocol\":\"{PROTOCOL}\",\"request_digest\":\"{digest}\",\
         \"request_id\":\"{id}\",\"role\":\"{role}\",\
         \"runtime\":{runtime},\"transitions\":[],\"version\":\"{VERSION}\"}}",
        counts = zero_counts(),
        state = envelope.initial_state,
        digest = request_digest,
        id = envelope.request_id,
        role = envelope.role,
        runtime = runtime_object(deviation),
    )
}

fn eager_reject_response(envelope: &Envelope) -> String {
    format!(
        "{{\"counts\":{counts},\"error\":{{\"close_code\":1002,\
         \"code\":\"JAVA_INVALID_DATA\",\"detail\":\"planted mutant \
         us005-rm-eager-reject-1002: unconditional protocol rejection\"}},\
         \"final_state\":\"closed\",\"outcome\":\"error\",\
         \"protocol\":\"{PROTOCOL}\",\"request_digest\":\"{digest}\",\
         \"request_id\":\"{id}\",\"runtime\":{runtime},\
         \"version\":\"{VERSION}\"}}",
        counts = zero_counts(),
        digest = envelope.request_digest,
        id = envelope.request_id,
        runtime = runtime_object(Deviation::EagerReject),
    )
}

/// Response emitted when a request line cannot be parsed. It never matches a
/// scenario (the evaluator counts it as unmatched), which is itself a
/// failure signal — candidates must not silently drop input lines.
pub fn parse_failure_response() -> String {
    format!(
        "{{\"error\":{{\"code\":\"CANDIDATE_PARSE_FAILURE\",\
         \"detail\":\"candidate could not extract the request envelope\"}},\
         \"outcome\":\"error\",\"protocol\":\"{PROTOCOL}\",\
         \"request_id\":\"unparsed\",\"version\":\"{VERSION}\"}}"
    )
}

/// Builds the single response line (no trailing newline) for one request.
pub fn respond(line: &str, deviation: Deviation) -> String {
    let Some(envelope) = parse_envelope(line) else {
        return parse_failure_response();
    };
    match deviation {
        Deviation::Inert => inert_response(&envelope, &envelope.request_digest, deviation),
        Deviation::EagerReject => eager_reject_response(&envelope),
        Deviation::DigestUnbind => inert_response(&envelope, ZERO_SHA256, deviation),
    }
}

/// `--identify` output: a stable JSON identity line for sbx smoke probes.
pub fn identify(deviation: Deviation) -> String {
    let deviation_name = match deviation {
        Deviation::Inert => "none",
        Deviation::EagerReject => "eager-reject-1002",
        Deviation::DigestUnbind => "digest-unbind",
    };
    format!(
        "{{\"artifact\":\"{}\",\"deviation\":\"{deviation_name}\",\
         \"protocol\":\"{PROTOCOL}\",\"purpose\":\"us005-candidate-execution\",\
         \"version\":\"{VERSION}\"}}",
        deviation.artifact()
    )
}

/// Streams JSONL requests to responses. Empty lines are ignored.
///
/// # Errors
///
/// Returns any I/O error from the underlying reader or writer.
pub fn run_lines<R: BufRead, W: Write>(
    input: R,
    mut output: W,
    deviation: Deviation,
) -> std::io::Result<()> {
    for line in input.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        writeln!(output, "{}", respond(&line, deviation))?;
    }
    output.flush()
}

/// Shared binary entry point: handles `--identify`, otherwise streams stdin.
///
/// # Errors
///
/// Returns any I/O error from stdin/stdout streaming.
pub fn run_main(deviation: Deviation) -> std::io::Result<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.iter().any(|a| a == "--identify") {
        println!("{}", identify(deviation));
        return Ok(());
    }
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    run_lines(stdin.lock(), stdout.lock(), deviation)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = concat!(
        "{\"initial_state\":\"open\",\"limits\":{\"max_actions\":64},",
        "\"protocol\":\"java-websocket-oracle\",",
        "\"request_digest\":\"sha256:00112233445566778899aabbccddeeff",
        "00112233445566778899aabbccddeeff\",",
        "\"request_id\":\"us005.pub.0001\",\"role\":\"server\",\"steps\":[],",
        "\"version\":\"1.0.0\"}"
    );

    #[test]
    fn extracts_plain_fields() {
        assert_eq!(
            extract_string_field(SAMPLE, "request_id").as_deref(),
            Some("us005.pub.0001")
        );
        assert_eq!(
            extract_string_field(SAMPLE, "role").as_deref(),
            Some("server")
        );
        assert_eq!(
            extract_string_field(SAMPLE, "initial_state").as_deref(),
            Some("open")
        );
    }

    #[test]
    fn extraction_fails_closed() {
        assert_eq!(extract_string_field(SAMPLE, "absent"), None);
        assert_eq!(
            extract_string_field("{\"request_id\":\"a\\\"b\"}", "request_id"),
            None,
            "escaped values must fail closed"
        );
        assert_eq!(
            extract_string_field("{\"request_id\":42}", "request_id"),
            None
        );
    }

    #[test]
    fn stub_response_matches_go_negative_control_shape() {
        let response = respond(SAMPLE, Deviation::Inert);
        let expected = concat!(
            "{\"close\":null,\"counts\":{\"actions\":0,\"buffered_bytes\":0,",
            "\"consumed_bytes\":0,\"frames\":0,\"input_bytes\":0,",
            "\"message_buffered_bytes\":0,\"wire_buffered_bytes\":0},",
            "\"events\":[],\"final_state\":\"open\",\"frames\":[],",
            "\"initial_state\":\"open\",\"outcome\":\"ok\",",
            "\"protocol\":\"java-websocket-oracle\",",
            "\"request_digest\":\"sha256:00112233445566778899aabbccddeeff",
            "00112233445566778899aabbccddeeff\",",
            "\"request_id\":\"us005.pub.0001\",\"role\":\"server\",",
            "\"runtime\":{\"artifact\":\"stub-target\",\"sha256\":\"sha256:",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "\"},\"transitions\":[],\"version\":\"1.0.0\"}"
        );
        assert_eq!(response, expected);
    }

    #[test]
    fn eager_reject_carries_wrong_close_code_everywhere() {
        let response = respond(SAMPLE, Deviation::EagerReject);
        assert!(response.contains("\"outcome\":\"error\""));
        assert!(response.contains("\"close_code\":1002"));
        assert!(response.contains("\"code\":\"JAVA_INVALID_DATA\""));
        assert!(response.contains("\"final_state\":\"closed\""));
        assert!(response.contains("\"request_id\":\"us005.pub.0001\""));
        // The digest binding is intact: this mutant is killed by outcome and
        // error-shape divergence, not by digest divergence.
        assert!(response.contains(
            "\"request_digest\":\"sha256:00112233445566778899aabbccddeeff\
             00112233445566778899aabbccddeeff\""
        ));
    }

    #[test]
    fn digest_unbind_breaks_only_the_digest_binding() {
        let response = respond(SAMPLE, Deviation::DigestUnbind);
        assert!(response.contains(&format!("\"request_digest\":\"{ZERO_SHA256}\"")));
        assert!(response.contains("\"outcome\":\"ok\""));
        assert!(response.contains("\"request_id\":\"us005.pub.0001\""));
    }

    #[test]
    fn unparsable_lines_produce_unmatched_responses() {
        let response = respond("{\"no_envelope\":true}", Deviation::Inert);
        assert!(response.contains("\"request_id\":\"unparsed\""));
        assert!(response.contains("CANDIDATE_PARSE_FAILURE"));
    }

    #[test]
    fn run_lines_streams_one_response_per_request() {
        let input = format!("{SAMPLE}\n\n{SAMPLE}\n");
        let mut output = Vec::new();
        run_lines(input.as_bytes(), &mut output, Deviation::Inert).unwrap();
        let rendered = String::from_utf8(output).unwrap();
        assert_eq!(rendered.lines().count(), 2);
        for line in rendered.lines() {
            assert!(line.contains("\"request_id\":\"us005.pub.0001\""));
        }
    }

    #[test]
    fn identify_lines_are_stable() {
        assert!(identify(Deviation::Inert).contains("\"artifact\":\"stub-target\""));
        assert!(identify(Deviation::EagerReject).contains("\"deviation\":\"eager-reject-1002\""));
        assert!(identify(Deviation::DigestUnbind).contains("\"deviation\":\"digest-unbind\""));
    }
}
