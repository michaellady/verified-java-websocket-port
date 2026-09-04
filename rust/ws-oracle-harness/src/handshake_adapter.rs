//! Handshake-protocol adapter (US-010/US-011 borrow batch B): the
//! `java-websocket-handshake-oracle` 1.0.0 side of this harness.
//!
//! It accepts the exact digest-bound JSONL request lines
//! `corporactl oracle-requests --tier handshake --wire` emits (the same
//! lines the recorded live Java run consumed,
//! `protected/us005-corpora/live/handshake/requests.jsonl`), drives the
//! `ws_core::handshake` slices, and answers in the live-transcript
//! vocabulary `corporactl evaluate --tier handshake --live` scores:
//! `java_observable` (`accept` / `reject` / `incomplete`), the draft-API
//! `reject_channel` plus `close_code` 1002 on rejections, and the derived
//! `sec_websocket_accept` on server-side accepts.
//!
//! ## Honesty stance
//!
//! - **Runtime identity**: every response line carries THIS harness's real
//!   identity (artifact name + SHA-256 of its own executable). The live
//!   evaluator additionally pins the recorded Java jar's identity in its
//!   runtime-binding check; this adapter NEVER claims that identity — the
//!   transcript attests what actually executed, and the evaluator's
//!   runtime-binding verdict on a Rust transcript is reported as observed.
//! - **Limit posture**: the per-case `config` limits are parsed, validated,
//!   and then deliberately NOT enforced on the verdict path
//!   (`HandshakeLimits::hard_ceilings` bounds memory instead). Shipped
//!   Java-WebSocket 1.6.0 has no handshake limits, and the live-recorded
//!   corpus (cases us005.hs.0046-0048) shows the real Java ACCEPTING the
//!   limit-family inputs; enforcing the case config here would fabricate
//!   rejections the pinned runtime does not produce. The configured-limit
//!   strengthening lives on the connection path (see
//!   `ws_core::handshake` module docs).
//! - Non-ASCII handshake bytes are outside the calibrated live mapping;
//!   the ws_core parser projects bytes as Latin-1 and fidelity is claimed
//!   for ASCII input only (the whole committed corpus is ASCII).

use std::collections::BTreeMap;

use ws_core::handshake::client::{ClientHandshake, ClientHandshakeOutcome};
use ws_core::handshake::server::{ServerHandshake, ServerHandshakeOutcome};
use ws_core::handshake::{
    HANDSHAKE_REJECT_CLOSE_CODE, HandshakeLimits, RejectChannel, RejectStage,
};

use crate::json::{self, Value};
use crate::request::{self, ProtocolError};
use crate::response::RuntimeIdentity;
use crate::{HANDSHAKE_PROTOCOL, HANDSHAKE_VERSION};

const REQUEST_FIELDS: [&str; 8] = [
    "case_id",
    "config",
    "context",
    "direction",
    "protocol",
    "raw_base64",
    "request_digest",
    "version",
];
const CONFIG_FIELDS: [&str; 3] = [
    "max_handshake_bytes",
    "max_header_count",
    "max_header_line_bytes",
];
const CONTEXT_FIELDS: [&str; 1] = ["client_key"];

/// Answers the line if (and only if) it is a handshake-protocol request:
/// a JSON object whose `protocol` field is the handshake-oracle pin.
/// Behavior-protocol lines (and non-JSON lines) return `None` and flow to
/// the behavior path unchanged.
pub fn try_respond(line: &str, runtime: &RuntimeIdentity) -> Option<String> {
    let Ok(Value::Obj(request)) = json::parse(line) else {
        return None;
    };
    if request.get("protocol") != Some(&Value::Str(HANDSHAKE_PROTOCOL.to_string())) {
        return None;
    }
    Some(match respond(&request, runtime) {
        Ok(response) => response,
        Err(error) => envelope_error(&error),
    })
}

/// One validated handshake case ready to drive.
struct HandshakeRequest {
    case_id: String,
    request_digest: String,
    direction: Direction,
    client_key: String,
    raw: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    /// A client's upgrade request judged by OUR SERVER slice (US-011).
    ClientRequest,
    /// A server's response judged by OUR CLIENT slice (US-010).
    ServerResponse,
}

fn parse_handshake_request(
    request: &BTreeMap<String, Value>,
) -> Result<HandshakeRequest, ProtocolError> {
    request::reject_unknown(request, &REQUEST_FIELDS, "request")?;
    let case_id = request::string(request, "case_id")?;
    if !valid_case_id(&case_id) {
        return Err(ProtocolError::new(
            "INVALID_REQUEST_ID",
            "case_id must match [A-Za-z0-9._:-]{1,128}",
        ));
    }
    if request::string(request, "version")? != HANDSHAKE_VERSION {
        return Err(ProtocolError::new(
            "UNSUPPORTED_PROTOCOL",
            "version must equal 1.0.0",
        ));
    }
    let request_digest = request::string(request, "request_digest")?;
    let computed = request::canonical_request_digest(request);
    if computed != request_digest {
        return Err(ProtocolError::new(
            "REQUEST_DIGEST_MISMATCH",
            "request_digest does not bind the canonical request",
        ));
    }
    let direction = match request::string(request, "direction")?.as_str() {
        "client_request" => Direction::ClientRequest,
        "server_response" => Direction::ServerResponse,
        _ => {
            return Err(ProtocolError::new(
                "INVALID_ENUM",
                "direction has unsupported value",
            ));
        }
    };
    // The three limit fields must be well-formed positive integers within
    // the pinned hard ceilings; they are then deliberately NOT applied to
    // the verdict (module-level limit-posture note).
    let Value::Obj(config) = request::required(request, "config")? else {
        return Err(ProtocolError::new(
            "TYPE_MISMATCH",
            "config must be an object",
        ));
    };
    request::reject_unknown(config, &CONFIG_FIELDS, "config")?;
    let ceilings = HandshakeLimits::hard_ceilings();
    let ceiling_of = |field: &str| -> i64 {
        match field {
            "max_handshake_bytes" => ceilings.max_handshake_bytes as i64,
            "max_header_count" => ceilings.max_header_count as i64,
            _ => ceilings.max_header_line_bytes as i64,
        }
    };
    for field in CONFIG_FIELDS {
        let value = request::integer(config, field)?;
        if value < 1 || value > ceiling_of(field) {
            return Err(ProtocolError::new(
                "LIMIT_OUT_OF_RANGE",
                format!("{field} must be between 1 and {}", ceiling_of(field)),
            ));
        }
    }
    let Value::Obj(context) = request::required(request, "context")? else {
        return Err(ProtocolError::new(
            "TYPE_MISMATCH",
            "context must be an object",
        ));
    };
    request::reject_unknown(context, &CONTEXT_FIELDS, "context")?;
    let client_key = match context.get("client_key") {
        None => String::new(),
        Some(Value::Str(key)) => key.clone(),
        Some(_) => {
            return Err(ProtocolError::new(
                "TYPE_MISMATCH",
                "client_key must be a string",
            ));
        }
    };
    let raw = request::base64_field(request, "raw_base64")?;
    Ok(HandshakeRequest {
        case_id,
        request_digest,
        direction,
        client_key,
        raw,
    })
}

/// The judged observable of one case.
enum Observable {
    Accept {
        sec_websocket_accept: Option<String>,
    },
    Reject {
        channel: RejectChannel,
        stage: RejectStage,
    },
    Incomplete,
}

/// The instant this oracle stamps into 101 heads it never emits (epoch 0).
/// Fixed so a transcript is reproducible; see the use site.
const HANDSHAKE_ORACLE_INSTANT: i64 = 0;

fn judge(request: &HandshakeRequest) -> Result<Observable, ProtocolError> {
    let limits = HandshakeLimits::hard_ceilings();
    match request.direction {
        Direction::ClientRequest => {
            // A FIXED instant, deliberately. This oracle scores
            // `java_observable`, `reject_channel`, `close_code` and
            // `sec_websocket_accept` — never the response head, which it
            // discards below. Reading a real clock here would put a value in
            // this harness's answers that nothing compares and that would
            // make its transcripts irreproducible. The `Date` field's
            // fidelity is examined where it is actually observable:
            // `ws-core/tests/handshake_server_response.rs` for the format
            // and `ws-testee/tests/loopback.rs` for the live clock.
            let mut machine = ServerHandshake::new(limits, HANDSHAKE_ORACLE_INSTANT);
            match machine.consume(&request.raw) {
                ServerHandshakeOutcome::Incomplete => Ok(Observable::Incomplete),
                ServerHandshakeOutcome::Accept { accept_key, .. } => Ok(Observable::Accept {
                    sec_websocket_accept: Some(accept_key),
                }),
                ServerHandshakeOutcome::Reject { channel, stage, .. } => {
                    Ok(Observable::Reject { channel, stage })
                }
                // Unreachable through this protocol: the raw payload is
                // bounded by the 1 MiB JSONL line ceiling, below the
                // hard-ceiling budgets. Fails closed if it ever fires.
                ServerHandshakeOutcome::LimitExceeded(_) | ServerHandshakeOutcome::NotAwaiting => {
                    Err(ProtocolError::new(
                        "HANDSHAKE_ADAPTER_UNREACHABLE",
                        "hard-ceiling refusal on a line-bounded payload",
                    ))
                }
            }
        }
        Direction::ServerResponse => {
            let mut machine = ClientHandshake::for_recorded_key(&request.client_key, limits);
            match machine.consume(&request.raw) {
                ClientHandshakeOutcome::Incomplete => Ok(Observable::Incomplete),
                // The client side reports the accept value it MATCHED —
                // `generateFinalKey(trim(client_key))`, the same SHA-1
                // derivation the server side reports, computed by the client
                // on every acceptance (Draft_6455.java:318-325). The earlier
                // adapter emitted nothing here, on the reading that "no
                // accept value is observable on the client side"; what is
                // true is that the client does not SEND one. It derives one,
                // and matching it is the whole acceptance predicate.
                ClientHandshakeOutcome::Accept {
                    sec_websocket_accept,
                    ..
                } => Ok(Observable::Accept {
                    sec_websocket_accept: Some(sec_websocket_accept),
                }),
                ClientHandshakeOutcome::Reject { channel, stage } => {
                    Ok(Observable::Reject { channel, stage })
                }
                ClientHandshakeOutcome::LimitExceeded(_) | ClientHandshakeOutcome::NotAwaiting => {
                    Err(ProtocolError::new(
                        "HANDSHAKE_ADAPTER_UNREACHABLE",
                        "hard-ceiling refusal on a line-bounded payload",
                    ))
                }
            }
        }
    }
}

fn respond(
    request: &BTreeMap<String, Value>,
    runtime: &RuntimeIdentity,
) -> Result<String, ProtocolError> {
    let parsed = parse_handshake_request(request)?;
    let observable = judge(&parsed)?;
    let mut response = BTreeMap::new();
    response.insert("case_id".to_string(), Value::Str(parsed.case_id));
    response.insert(
        "protocol".to_string(),
        Value::Str(HANDSHAKE_PROTOCOL.to_string()),
    );
    response.insert(
        "version".to_string(),
        Value::Str(HANDSHAKE_VERSION.to_string()),
    );
    response.insert(
        "request_digest".to_string(),
        Value::Str(parsed.request_digest),
    );
    let mut runtime_value = BTreeMap::new();
    runtime_value.insert("artifact".to_string(), Value::Str(runtime.artifact.clone()));
    runtime_value.insert("sha256".to_string(), Value::Str(runtime.sha256.clone()));
    response.insert("runtime".to_string(), Value::Obj(runtime_value));
    match observable {
        Observable::Accept {
            sec_websocket_accept,
        } => {
            response.insert(
                "java_observable".to_string(),
                Value::Str("accept".to_string()),
            );
            if let Some(accept) = sec_websocket_accept {
                response.insert("sec_websocket_accept".to_string(), Value::Str(accept));
            }
        }
        Observable::Reject { channel, stage } => {
            response.insert(
                "java_observable".to_string(),
                Value::Str("reject".to_string()),
            );
            response.insert(
                "reject_channel".to_string(),
                Value::Str(channel.wire_name().to_string()),
            );
            response.insert(
                "reject_stage".to_string(),
                Value::Str(stage.wire_name().to_string()),
            );
            response.insert(
                "close_code".to_string(),
                Value::Int(i64::from(HANDSHAKE_REJECT_CLOSE_CODE)),
            );
        }
        Observable::Incomplete => {
            response.insert(
                "java_observable".to_string(),
                Value::Str("incomplete".to_string()),
            );
        }
    }
    Ok(Value::Obj(response).canonical())
}

fn valid_case_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

/// Envelope-level rejection with the handshake protocol pin (the behavior
/// path's envelope carries the behavior pin; a handshake line must not
/// masquerade as one).
fn envelope_error(error: &ProtocolError) -> String {
    let mut detail = BTreeMap::new();
    detail.insert("code".to_string(), Value::Str(error.code.to_string()));
    detail.insert("detail".to_string(), Value::Str(error.detail.clone()));
    let mut response = BTreeMap::new();
    response.insert("error".to_string(), Value::Obj(detail));
    response.insert("outcome".to_string(), Value::Str("error".to_string()));
    response.insert(
        "protocol".to_string(),
        Value::Str(HANDSHAKE_PROTOCOL.to_string()),
    );
    response.insert("case_id".to_string(), Value::Null);
    response.insert(
        "version".to_string(),
        Value::Str(HANDSHAKE_VERSION.to_string()),
    );
    Value::Obj(response).canonical()
}
