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
//! Both US-009 lanes are merged: the single coupling seam
//! ([`core_adapter`]) now drives the REAL `ws_core` ConnectionCore
//! (`WiredCore`), so the corpus genuinely scores the Rust. The core is
//! still the deliberately skeletal US-009 contract — only EOF, state-gate,
//! and limit behavior exist; send paths refuse with the honest non-oracle
//! `Unimplemented` code, which the seam reports as the truthful
//! `CORE_BEHAVIOR_UNIMPLEMENTED` envelope (never a fabricated oracle
//! code). The public-tier result therefore stays near zero: the recorded
//! wired baseline is 7/74 passes, every one a state/EOF/limit-only
//! scenario the skeleton genuinely encodes (see
//! `baseline/us009-public-wired-baseline.json`; the pre-merge
//! `baseline/us009-public-unwired-baseline.json` is retained as history).
//! No story acceptance beyond US-009 is claimed by this crate.
//!
//! ## Protocol compatibility surface
//!
//! - Request side mirrors `OracleEngine.process`: strict JSON with
//!   StrictJson's limits (duplicate and unknown fields rejected at the
//!   envelope boundaries, `MAX_DEPTH` nesting, `MAX_CONTAINER_ENTRIES`
//!   entries, `INVALID_UNICODE` surrogate rejections), `request_id` charset,
//!   protocol/version pins, `request_digest` = SHA-256 over the UTF-8
//!   canonical JSON object minus the `request_digest` member (recomputed and
//!   verified before any scenario byte reaches the core), and limits
//!   validated against the java-oracle hard ceilings. Steps are validated at
//!   EXECUTION time exactly like `OracleEngine.Execution.run` (see
//!   [`core_adapter::drive_scenario`]): a malformed step mid-scenario is a
//!   request-bound partial failure retaining counts-so-far, current state,
//!   and runtime — never an envelope-level `request_id: null` rejection.
//! - Response side mirrors `OracleEngine.success`/`failure` and the
//!   candidate-stub envelope: lexical key order, one line per request,
//!   byte-identical reruns, `runtime` carrying the harness's real artifact
//!   name and the SHA-256 of its own executable (never the stub's all-zero
//!   digest). A completed or failed response whose canonical form exceeds
//!   the request's `max_output_bytes` is replaced by Java's minimal
//!   `OUTPUT_LIMIT_EXCEEDED` envelope, exactly as in `OracleEngine.process`.
//! - Line side mirrors `OracleMain`: the JSONL reader buffers at most
//!   `HARD_LINE_BYTES` per record (`BoundedLineReader` semantics — bytes
//!   past the limit are consumed, never buffered) and answers oversized
//!   records with `LINE_LIMIT_EXCEEDED`.
//!
//! ## Narrowings (full honesty)
//!
//! One deliberate narrowing remains against the shipped java-oracle:
//!
//! - **Integer-only numbers.** Java's `StrictJson` parses every JSON number
//!   into a `BigDecimal` and defers integer-ness to each consumer
//!   (`intValueExact`), so a hand-crafted line whose canonical form spells
//!   an integral value with fraction or exponent syntax (`2.0`, `2e1` —
//!   `toPlainString` keeps `2.0` and expands `2e1` to `20`) could pass
//!   Java's digest binding and be accepted, while a non-integral value
//!   (`2.5`) fails there as `TYPE_MISMATCH`. This parser accepts only plain
//!   integer forms and rejects fraction/exponent syntax as `INVALID_JSON` at
//!   parse time. Unreachable for every real corpus line: the corpora are
//!   emitted by the canonical writer (`canonical.go` / `StrictJson.write`),
//!   which only produces plain integers, and the request digest binds those
//!   canonical bytes — the divergence needs a hand-crafted non-canonical
//!   number. Matching it exactly would require BigDecimal-equivalent
//!   arbitrary-precision semantics for zero corpus benefit.
//!
//! Additionally (a detail-text note, not a code narrowing): Java's
//! StrictJson rejection details carry an ` at character N` position suffix;
//! this parser's details do not. `corporactl evaluate` compares typed codes,
//! close codes, states, and counts — never detail prose.
//!
//! The round-1 base64 narrowing (steps validated eagerly at parse time) is
//! GONE: base64 and all other step-shape validation now happen at execution
//! time through the core adapter path, exactly like Java.

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
    let rendered = match core_adapter::drive_scenario(&parsed, core) {
        ScenarioOutcome::Completed(observations) => {
            response::ok_response(&parsed, &observations, runtime)
        }
        ScenarioOutcome::Failed {
            failure,
            counts,
            final_state,
        } => response::failure_response(&parsed, &failure, &counts, final_state, runtime),
        ScenarioOutcome::ConstructionFailed { failure } => {
            // Construction-path failure: Java's runtime-unavailable
            // responses return before (and are exempt from) the
            // output-limit replacement, which guards only
            // Execution-produced responses.
            return response::failure_response(
                &parsed,
                &failure,
                &observe::Counts::default(),
                parsed.initial_state.connection_state(),
                runtime,
            );
        }
    };
    // OracleEngine.process: after canonicalizing whatever the execution
    // produced (ok or failure), a response larger than max_output_bytes is
    // replaced with the minimal OUTPUT_LIMIT_EXCEEDED envelope. String::len
    // is the UTF-8 byte length, matching StrictJson.utf8Length.
    if rendered.len() as i64 > parsed.limits.max_output_bytes {
        return response::output_limit_response(&parsed);
    }
    rendered
}

/// One raw JSONL record read with `OracleMain.BoundedLineReader` semantics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundedLine {
    /// The record's bytes, capped at the reader's limit.
    pub bytes: Vec<u8>,
    /// True when the record crossed the limit (excess bytes were consumed
    /// from the stream but never buffered).
    pub too_long: bool,
}

/// Reads the next newline-terminated record, buffering at most `limit`
/// bytes, mirroring `OracleMain.BoundedLineReader.next`: bytes past the
/// limit are consumed and flagged via `too_long` but never buffered, so
/// memory stays bounded regardless of line length. Returns `None` at end of
/// input (a final unterminated record is still returned first).
///
/// # Errors
///
/// Returns any I/O error from the underlying reader.
pub fn read_bounded_line<R: BufRead>(
    input: &mut R,
    limit: usize,
) -> std::io::Result<Option<BoundedLine>> {
    let mut bytes = Vec::new();
    let mut too_long = false;
    let mut saw_any = false;
    loop {
        let available = input.fill_buf()?;
        if available.is_empty() {
            return Ok(saw_any.then_some(BoundedLine { bytes, too_long }));
        }
        saw_any = true;
        let newline = available.iter().position(|&b| b == b'\n');
        let chunk_len = newline.unwrap_or(available.len());
        let room = limit - bytes.len();
        if chunk_len > room {
            bytes.extend_from_slice(&available[..room]);
            too_long = true;
        } else {
            bytes.extend_from_slice(&available[..chunk_len]);
        }
        let consumed = chunk_len + usize::from(newline.is_some());
        input.consume(consumed);
        if newline.is_some() {
            return Ok(Some(BoundedLine { bytes, too_long }));
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
    while let Some(line) = read_bounded_line(&mut input, HARD_LINE_BYTES)? {
        let rendered = if line.too_long {
            // Mirrors OracleMain.run's tooLong branch: the record is
            // answered without ever having been buffered past the limit.
            response::envelope_error_response(&request::ProtocolError::new(
                "LINE_LIMIT_EXCEEDED",
                format!("JSONL record exceeds {HARD_LINE_BYTES} bytes"),
            ))
        } else {
            respond_bytes(&line.bytes, core, runtime)
        };
        writeln!(output, "{rendered}")?;
        output.flush()?;
    }
    output.flush()
}

/// `--identify` output: a stable JSON identity line for sbx smoke probes,
/// mirroring the candidate-stub's identify discipline with a truthful core
/// wiring status.
pub fn identify() -> String {
    format!(
        "{{\"artifact\":\"{ARTIFACT}\",\"core\":\"wired\",\
         \"protocol\":\"{PROTOCOL}\",\"purpose\":\"us009-oracle-candidate-harness\",\
         \"version\":\"{VERSION}\"}}"
    )
}
