//! # ws-oracle-harness (US-009 lane B)
//!
//! JSONL oracle-candidate harness for the Rust `ws_core` ConnectionCore.
//! It speaks exactly the `java-websocket-oracle` 1.0.0 protocol the vendored
//! java-oracle adapter speaks (`java-oracle/README.md`), so the pipeline
//! `corporactl oracle-requests | ws-oracle-harness | corporactl evaluate`
//! scores the Rust candidate against the SAME committed corpora that score
//! the Java oracle. The harness contains **no protocol decisions**: it
//! serializes the core's typed observation streams 1:1 into the transcript
//! vocabulary (`internal/corpora/derive.go`, `schemas/corpus-scenario-1.0.0`).
//!
//! ## Round-honesty stance
//!
//! Lane A builds the real `ws_core` ConnectionCore in parallel on another
//! branch. Until its API lands, the single coupling seam
//! ([`core_adapter`]) holds a truthfully-labeled unwired stub: every
//! scenario is answered with a typed `CORE_NOT_WIRED` failure envelope
//! (zero counts, `final_state == initial_state`) — the same declared-inertness
//! discipline as the US-005 `candidate-stub`, honestly labeled as awaiting the
//! core rather than pretending behavior. The expected public-tier result this
//! round is therefore 0 passes, recorded as the baseline in
//! `baseline/us009-public-unwired-baseline.json`. No story acceptance is
//! claimed by this crate.
//!
//! ## Protocol compatibility surface
//!
//! - Request side mirrors `OracleEngine.process`: strict JSON (duplicate and
//!   unknown fields rejected at every object boundary), `request_id` charset,
//!   protocol/version pins, `request_digest` = SHA-256 over the UTF-8
//!   canonical JSON object minus the `request_digest` member (recomputed and
//!   verified before any scenario byte reaches the core), limits validated
//!   against the java-oracle hard ceilings, steps validated with the exact
//!   per-kind field sets and canonical base64.
//! - Response side mirrors `OracleEngine.success`/`failure` and the
//!   candidate-stub envelope: lexical key order, one line per request,
//!   byte-identical reruns, `runtime` carrying the harness's real artifact
//!   name and the SHA-256 of its own executable (never the stub's all-zero
//!   digest).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod base64;
pub mod core_adapter;
pub mod json;
pub mod observe;
pub mod request;
pub mod response;
pub mod sha256;

use std::io::{BufRead, Write};

use core_adapter::{CandidateCore, ScenarioOutcome};
use response::RuntimeIdentity;

/// Oracle protocol name pinned by the vendored java-oracle adapter.
pub const PROTOCOL: &str = "java-websocket-oracle";
/// Oracle protocol version pinned by the vendored java-oracle adapter.
pub const VERSION: &str = "1.0.0";
/// Handshake-protocol id (routed by java-oracle; NOT implemented here yet).
pub const HANDSHAKE_PROTOCOL: &str = "java-websocket-handshake-oracle";
/// Hard JSONL line ceiling, mirroring `OracleMain.HARD_LINE_BYTES`.
pub const HARD_LINE_BYTES: usize = 1_048_576;
/// Stable artifact identifier for transcripts and `--identify` output.
pub const ARTIFACT: &str = "ws-oracle-harness";

/// Builds the single response line (no trailing newline) for one raw JSONL
/// record, mirroring `OracleMain.run` line handling: line-limit, empty-line,
/// and UTF-8 guards precede request processing, and every protocol-level
/// rejection is a typed error response on stdout (never a crash).
pub fn respond_bytes(
    raw: &[u8],
    core: &mut dyn CandidateCore,
    runtime: &RuntimeIdentity,
) -> String {
    if raw.len() > HARD_LINE_BYTES {
        return response::envelope_error_response(&request::ProtocolError::new(
            "LINE_LIMIT_EXCEEDED",
            format!("JSONL record exceeds {HARD_LINE_BYTES} bytes"),
        ));
    }
    if raw.is_empty() {
        return response::envelope_error_response(&request::ProtocolError::new(
            "EMPTY_LINE",
            "empty JSONL records are forbidden",
        ));
    }
    let Ok(line) = std::str::from_utf8(raw) else {
        return response::envelope_error_response(&request::ProtocolError::new(
            "INVALID_UTF8",
            "JSONL record is not valid UTF-8",
        ));
    };
    respond(line, core, runtime)
}

/// Builds the single response line (no trailing newline) for one request
/// line that already passed the byte-level guards.
pub fn respond(line: &str, core: &mut dyn CandidateCore, runtime: &RuntimeIdentity) -> String {
    let parsed = match request::parse_request(line) {
        Ok(parsed) => parsed,
        Err(error) => return response::envelope_error_response(&error),
    };
    match core.run_scenario(&parsed) {
        ScenarioOutcome::Completed(observations) => {
            response::ok_response(&parsed, &observations, runtime)
        }
        ScenarioOutcome::Failed {
            failure,
            counts,
            final_state,
        } => response::failure_response(&parsed, &failure, &counts, final_state, runtime),
        ScenarioOutcome::NotWired { detail } => {
            let failure = core_adapter::ScenarioFailure {
                code: "CORE_NOT_WIRED".to_string(),
                close_code: None,
                detail,
            };
            response::failure_response(
                &parsed,
                &failure,
                &observe::Counts::default(),
                parsed.initial_state.connection_state(),
                runtime,
            )
        }
    }
}

/// Streams JSONL requests to responses, one response line per input line.
///
/// # Errors
///
/// Returns any I/O error from the underlying reader or writer. Protocol
/// failures never abort the stream; they are typed response lines.
pub fn run_lines<R: BufRead, W: Write>(
    mut input: R,
    mut output: W,
    core: &mut dyn CandidateCore,
    runtime: &RuntimeIdentity,
) -> std::io::Result<()> {
    let mut buffer = Vec::new();
    loop {
        buffer.clear();
        let read = input.read_until(b'\n', &mut buffer)?;
        if read == 0 {
            break;
        }
        if buffer.last() == Some(&b'\n') {
            buffer.pop();
        }
        writeln!(output, "{}", respond_bytes(&buffer, core, runtime))?;
        output.flush()?;
    }
    output.flush()
}

/// `--identify` output: a stable JSON identity line for sbx smoke probes,
/// mirroring the candidate-stub's identify discipline with a truthful core
/// wiring status.
pub fn identify() -> String {
    format!(
        "{{\"artifact\":\"{ARTIFACT}\",\"core\":\"unwired\",\
         \"protocol\":\"{PROTOCOL}\",\"purpose\":\"us009-oracle-candidate-harness\",\
         \"version\":\"{VERSION}\"}}"
    )
}
