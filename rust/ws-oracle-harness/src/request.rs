//! Strict request-ENVELOPE parsing and canonical request-digest
//! verification.
//!
//! Mirrors `OracleEngine.process` (java-oracle) check-for-check and in the
//! same order: strict JSON, unknown/duplicate field rejection at the request
//! and limits boundaries, `request_id` charset, protocol/version pins,
//! digest format, canonical digest recomputation (SHA-256 over the canonical
//! JSON object minus the `request_digest` member — verified before any
//! scenario byte reaches the core), role/state enums, and limits against the
//! hard adapter ceilings. `steps` is validated ONLY as being an array here,
//! exactly like Java: individual steps are validated during execution
//! (`OracleEngine.Execution.run`), so a malformed step mid-scenario is a
//! request-bound partial failure, never an envelope-level `request_id: null`
//! rejection. The execution-time step walk lives in
//! [`crate::core_adapter::drive_scenario`].

use std::collections::BTreeMap;

use crate::json::{self, Value};
use crate::observe::ConnectionState;
use crate::sha256;
use crate::{HANDSHAKE_PROTOCOL, PROTOCOL, VERSION};

/// Hard adapter ceilings, mirroring `OracleEngine` exactly.
pub const HARD_INPUT_BYTES: i64 = 1_048_576;
/// Hard buffered-bytes ceiling.
pub const HARD_BUFFERED_BYTES: i64 = 1_048_576;
/// Hard action-count ceiling.
pub const HARD_ACTIONS: i64 = 1_024;
/// Hard frame-count ceiling.
pub const HARD_FRAMES: i64 = 4_096;
/// Hard output-bytes ceiling.
pub const HARD_OUTPUT_BYTES: i64 = 4_194_304;

/// One typed protocol-level rejection with the java-oracle's stable code
/// vocabulary and a bounded detail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolError {
    /// Stable typed code (`^[A-Z0-9_]+$`).
    pub code: &'static str,
    /// Bounded human-readable detail.
    pub detail: String,
}

impl ProtocolError {
    /// Builds a typed protocol error.
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        ProtocolError {
            code,
            detail: detail.into(),
        }
    }
}

/// Declared connection role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Client role (outbound frames masked).
    Client,
    /// Server role (inbound frames masked).
    Server,
}

impl Role {
    /// The exact wire string.
    pub fn wire(self) -> &'static str {
        match self {
            Role::Client => "client",
            Role::Server => "server",
        }
    }
}

/// Declared initial state (`open` | `closing` | `closed`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitialState {
    /// Begin in OPEN.
    Open,
    /// Begin in CLOSING.
    Closing,
    /// Begin in CLOSED.
    Closed,
}

impl InitialState {
    /// The exact wire string.
    pub fn wire(self) -> &'static str {
        self.connection_state().wire()
    }

    /// The corresponding typed connection state.
    pub fn connection_state(self) -> ConnectionState {
        match self {
            InitialState::Open => ConnectionState::Open,
            InitialState::Closing => ConnectionState::Closing,
            InitialState::Closed => ConnectionState::Closed,
        }
    }
}

/// Fragment opcode for `send_fragment` (`text` | `binary`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataOpcode {
    /// Text fragment sequence.
    Text,
    /// Binary fragment sequence.
    Binary,
}

/// The request `limits` object, validated against the hard ceilings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Decoded-input ceiling (1 ..= 1 MiB).
    pub max_input_bytes: i64,
    /// Frame/message buffer ceiling (1 ..= 1 MiB).
    pub max_buffered_bytes: i64,
    /// Action-count ceiling (0 ..= 1024).
    pub max_actions: i64,
    /// Frame-count ceiling (1 ..= 4096).
    pub max_frames: i64,
    /// Normalized-response ceiling (512 ..= 4 MiB).
    pub max_output_bytes: i64,
}

/// One oracle request with a fully validated envelope. `steps` holds the
/// RAW parsed step values: Java validates each step at execution time
/// (`Execution.run`), and so does [`crate::core_adapter::drive_scenario`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OracleRequest {
    /// Scenario id, echoed on the response.
    pub request_id: String,
    /// Verified canonical request digest, echoed on the response.
    pub request_digest: String,
    /// Declared role.
    pub role: Role,
    /// Declared initial state.
    pub initial_state: InitialState,
    /// Validated limits.
    pub limits: Limits,
    /// Raw step values in order, validated during execution.
    pub steps: Vec<Value>,
}

const REQUEST_FIELDS: [&str; 8] = [
    "initial_state",
    "limits",
    "protocol",
    "request_digest",
    "request_id",
    "role",
    "steps",
    "version",
];
const LIMIT_FIELDS: [&str; 5] = [
    "max_actions",
    "max_buffered_bytes",
    "max_frames",
    "max_input_bytes",
    "max_output_bytes",
];

/// Parses and fully validates one request ENVELOPE, verifying the canonical
/// request digest before returning. Step contents are deliberately NOT
/// validated here (Java defers them to execution).
///
/// # Errors
///
/// Returns the java-oracle's typed envelope rejection vocabulary
/// (`INVALID_JSON`, `INVALID_UNICODE`, `JSON_DEPTH_LIMIT`,
/// `JSON_CONTAINER_LIMIT`, `DUPLICATE_FIELD`, `UNKNOWN_FIELD`,
/// `MISSING_FIELD`, `TYPE_MISMATCH`, `INVALID_REQUEST_ID`,
/// `UNSUPPORTED_PROTOCOL`, `INVALID_REQUEST_DIGEST`,
/// `REQUEST_DIGEST_MISMATCH`, `INVALID_ENUM`, `LIMIT_OUT_OF_RANGE`).
pub fn parse_request(line: &str) -> Result<OracleRequest, ProtocolError> {
    let parsed = json::parse(line)?;
    let Value::Obj(request) = parsed else {
        return Err(ProtocolError::new(
            "TYPE_MISMATCH",
            "request must be an object",
        ));
    };
    if request.get("protocol") == Some(&Value::Str(HANDSHAKE_PROTOCOL.to_string())) {
        return Err(ProtocolError::new(
            "UNSUPPORTED_PROTOCOL",
            "handshake adapter is not wired in ws-oracle-harness yet \
             (awaits ws_core handshake entry points, US-010/US-011)",
        ));
    }
    reject_unknown(&request, &REQUEST_FIELDS, "request")?;

    let request_id = string(&request, "request_id")?;
    if !valid_request_id(&request_id) {
        return Err(ProtocolError::new(
            "INVALID_REQUEST_ID",
            "request_id must match [A-Za-z0-9._:-]{1,128}",
        ));
    }
    require_literal(&request, "protocol", PROTOCOL)?;
    require_literal(&request, "version", VERSION)?;
    let request_digest = string(&request, "request_digest")?;
    if !valid_digest_form(&request_digest) {
        return Err(ProtocolError::new(
            "INVALID_REQUEST_DIGEST",
            "request_digest must be a lowercase SHA-256 identity",
        ));
    }
    let computed = canonical_request_digest(&request);
    if computed != request_digest {
        return Err(ProtocolError::new(
            "REQUEST_DIGEST_MISMATCH",
            "request_digest does not bind the canonical request",
        ));
    }
    let role = match string(&request, "role")?.as_str() {
        "client" => Role::Client,
        "server" => Role::Server,
        _ => return Err(invalid_enum("role")),
    };
    let initial_state = match string(&request, "initial_state")?.as_str() {
        "open" => InitialState::Open,
        "closing" => InitialState::Closing,
        "closed" => InitialState::Closed,
        _ => return Err(invalid_enum("initial_state")),
    };
    let limits = parse_limits(required(&request, "limits")?)?;
    let Value::Arr(raw_steps) = required(&request, "steps")? else {
        return Err(ProtocolError::new(
            "TYPE_MISMATCH",
            "steps must be an array",
        ));
    };
    // Java only asserts "steps is an array" at envelope time; each step's
    // shape is validated during execution (Execution.run), so malformed
    // steps become request-bound partial failures there.
    let steps = raw_steps.clone();
    Ok(OracleRequest {
        request_id,
        request_digest,
        role,
        initial_state,
        limits,
        steps,
    })
}

/// Recomputes the canonical request digest: SHA-256 over the UTF-8 canonical
/// JSON object after removing the `request_digest` member (identical to
/// `OracleEngine.canonicalRequestDigest` and Go `OracleRequest`).
pub fn canonical_request_digest(request: &BTreeMap<String, Value>) -> String {
    let mut unsigned = request.clone();
    unsigned.remove("request_digest");
    let canonical = Value::Obj(unsigned).canonical();
    sha256::digest_identity(canonical.as_bytes())
}

fn valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

fn valid_digest_form(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Java `enumValue` rejection: `INVALID_ENUM` with "<field> has
/// unsupported value".
pub(crate) fn invalid_enum(field: &str) -> ProtocolError {
    ProtocolError::new("INVALID_ENUM", format!("{field} has unsupported value"))
}

/// Java `OracleEngine.rejectUnknown`: any field outside `allowed` rejects
/// with `UNKNOWN_FIELD` and a clipped field name.
pub(crate) fn reject_unknown(
    object: &BTreeMap<String, Value>,
    allowed: &[&str],
    location: &str,
) -> Result<(), ProtocolError> {
    for field in object.keys() {
        if !allowed.contains(&field.as_str()) {
            let mut shown = field.clone();
            if shown.len() > 80 {
                let mut end = 80;
                while !shown.is_char_boundary(end) {
                    end -= 1;
                }
                shown.truncate(end);
            }
            return Err(ProtocolError::new(
                "UNKNOWN_FIELD",
                format!("unknown field in {location}: {shown}"),
            ));
        }
    }
    Ok(())
}

/// Java `OracleEngine.required`: `MISSING_FIELD` when absent.
pub(crate) fn required<'a>(
    object: &'a BTreeMap<String, Value>,
    field: &str,
) -> Result<&'a Value, ProtocolError> {
    object.get(field).ok_or_else(|| {
        ProtocolError::new("MISSING_FIELD", format!("missing required field: {field}"))
    })
}

/// Java `OracleEngine.string`: required + `TYPE_MISMATCH` when not a string.
pub(crate) fn string(
    object: &BTreeMap<String, Value>,
    field: &str,
) -> Result<String, ProtocolError> {
    match required(object, field)? {
        Value::Str(value) => Ok(value.clone()),
        _ => Err(ProtocolError::new(
            "TYPE_MISMATCH",
            format!("{field} must be a string"),
        )),
    }
}

/// Java `OracleEngine.bool`: required + `TYPE_MISMATCH` when not a boolean.
pub(crate) fn boolean(
    object: &BTreeMap<String, Value>,
    field: &str,
) -> Result<bool, ProtocolError> {
    match required(object, field)? {
        Value::Bool(value) => Ok(*value),
        _ => Err(ProtocolError::new(
            "TYPE_MISMATCH",
            format!("{field} must be a boolean"),
        )),
    }
}

/// Java `OracleEngine.integer`: required + `TYPE_MISMATCH` when not an
/// integer (see the crate-level integer-number narrowing note).
pub(crate) fn integer(object: &BTreeMap<String, Value>, field: &str) -> Result<i64, ProtocolError> {
    match required(object, field)? {
        Value::Int(value) => Ok(*value),
        _ => Err(ProtocolError::new(
            "TYPE_MISMATCH",
            format!("{field} must be an integer"),
        )),
    }
}

fn require_literal(
    object: &BTreeMap<String, Value>,
    field: &str,
    expected: &str,
) -> Result<(), ProtocolError> {
    if string(object, field)? == expected {
        Ok(())
    } else {
        Err(ProtocolError::new(
            "UNSUPPORTED_PROTOCOL",
            format!("{field} must equal {expected}"),
        ))
    }
}

fn bounded_int(
    object: &BTreeMap<String, Value>,
    field: &str,
    min: i64,
    max: i64,
) -> Result<i64, ProtocolError> {
    let value = integer(object, field)?;
    if value < min || value > max {
        return Err(ProtocolError::new(
            "LIMIT_OUT_OF_RANGE",
            format!("{field} must be between {min} and {max}"),
        ));
    }
    Ok(value)
}

fn parse_limits(value: &Value) -> Result<Limits, ProtocolError> {
    let Value::Obj(object) = value else {
        return Err(ProtocolError::new(
            "TYPE_MISMATCH",
            "limits must be an object",
        ));
    };
    reject_unknown(object, &LIMIT_FIELDS, "limits")?;
    for field in LIMIT_FIELDS {
        if !object.contains_key(field) {
            return Err(ProtocolError::new(
                "MISSING_FIELD",
                format!("missing required field in limits: {field}"),
            ));
        }
    }
    Ok(Limits {
        max_input_bytes: bounded_int(object, "max_input_bytes", 1, HARD_INPUT_BYTES)?,
        max_buffered_bytes: bounded_int(object, "max_buffered_bytes", 1, HARD_BUFFERED_BYTES)?,
        max_actions: bounded_int(object, "max_actions", 0, HARD_ACTIONS)?,
        max_frames: bounded_int(object, "max_frames", 1, HARD_FRAMES)?,
        max_output_bytes: bounded_int(object, "max_output_bytes", 512, HARD_OUTPUT_BYTES)?,
    })
}

/// Java `OracleEngine.base64`: canonical (round-tripping) base64 only,
/// rejecting with `INVALID_BASE64`.
pub(crate) fn base64_field(
    object: &BTreeMap<String, Value>,
    field: &str,
) -> Result<Vec<u8>, ProtocolError> {
    let encoded = string(object, field)?;
    crate::base64::decode_canonical(&encoded).ok_or_else(|| {
        ProtocolError::new("INVALID_BASE64", format!("{field} is not canonical base64"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact `us005.pub.0000` request line `corporactl oracle-requests
    /// --tier public` emits (canonical form; digest recorded by the accepted
    /// US-005 live public run). This pins byte-compatibility of the canonical
    /// writer + SHA-256 digest chain against the real corpus.
    pub const PUB_0000: &str = concat!(
        "{\"initial_state\":\"open\",\"limits\":{\"max_actions\":64,",
        "\"max_buffered_bytes\":65536,\"max_frames\":64,\"max_input_bytes\":65536,",
        "\"max_output_bytes\":4194304},\"protocol\":\"java-websocket-oracle\",",
        "\"request_digest\":\"sha256:332b88dac25b405b3d9ce3b6a82b4ec8821296a9a4",
        "92aa70a26ce867d817e0c9\",\"request_id\":\"us005.pub.0000\",",
        "\"role\":\"client\",\"steps\":[{\"action\":\"send_close\",\"code\":999,",
        "\"kind\":\"action\",\"reason\":\"bad\"}],\"version\":\"1.0.0\"}"
    );

    #[test]
    fn real_public_request_line_digest_verifies() {
        let request = parse_request(PUB_0000).expect("the committed public request verifies");
        assert_eq!(request.request_id, "us005.pub.0000");
        assert_eq!(request.role, Role::Client);
        assert_eq!(request.initial_state, InitialState::Open);
        assert_eq!(request.limits.max_actions, 64);
        // Steps stay RAW at envelope time (execution validates them).
        assert_eq!(request.steps.len(), 1);
        assert_eq!(
            request.steps[0].canonical(),
            "{\"action\":\"send_close\",\"code\":999,\"kind\":\"action\",\"reason\":\"bad\"}"
        );
    }

    /// Java validates step contents during execution, so envelope parsing
    /// must ACCEPT structurally arbitrary steps entries (they fail later,
    /// request-bound, in the execution driver).
    #[test]
    fn malformed_steps_still_parse_at_envelope_time() {
        let mut request = match json::parse(PUB_0000).unwrap() {
            Value::Obj(map) => map,
            _ => unreachable!(),
        };
        request.insert(
            "steps".to_string(),
            Value::Arr(vec![Value::Int(42), Value::Str("junk".to_string())]),
        );
        let digest = canonical_request_digest(&request);
        request.insert("request_digest".to_string(), Value::Str(digest));
        let line = Value::Obj(request).canonical();
        let parsed = parse_request(&line).expect("malformed steps defer to execution");
        assert_eq!(parsed.steps.len(), 2);
    }

    #[test]
    fn tampered_request_fails_digest_binding() {
        let tampered = PUB_0000.replace("\"code\":999", "\"code\":1000");
        let error = parse_request(&tampered).unwrap_err();
        assert_eq!(error.code, "REQUEST_DIGEST_MISMATCH");
    }

    #[test]
    fn envelope_validation_mirrors_java_oracle_vocabulary() {
        let unknown = PUB_0000.replace("\"role\":\"client\"", "\"role\":\"client\",\"x\":1");
        assert_eq!(parse_request(&unknown).unwrap_err().code, "UNKNOWN_FIELD");

        // request_id is read before the digest binding (OracleEngine order),
        // so its absence reports MISSING_FIELD; a missing later field (role)
        // breaks the digest binding first, exactly as in java-oracle.
        let missing = PUB_0000.replace("\"request_id\":\"us005.pub.0000\",", "");
        assert_eq!(parse_request(&missing).unwrap_err().code, "MISSING_FIELD");
        let missing_role = PUB_0000.replace(",\"role\":\"client\"", "");
        assert_eq!(
            parse_request(&missing_role).unwrap_err().code,
            "REQUEST_DIGEST_MISMATCH"
        );

        let bad_id = PUB_0000.replace("us005.pub.0000", "bad id");
        assert_eq!(
            parse_request(&bad_id).unwrap_err().code,
            "INVALID_REQUEST_ID"
        );

        let bad_version = PUB_0000.replace("\"version\":\"1.0.0\"", "\"version\":\"9.9.9\"");
        assert_eq!(
            parse_request(&bad_version).unwrap_err().code,
            "UNSUPPORTED_PROTOCOL"
        );

        let bad_digest_form = PUB_0000.replace("sha256:332b", "sha999:332b");
        assert_eq!(
            parse_request(&bad_digest_form).unwrap_err().code,
            "INVALID_REQUEST_DIGEST"
        );

        assert_eq!(parse_request("not json").unwrap_err().code, "INVALID_JSON");
        assert_eq!(parse_request("[1]").unwrap_err().code, "TYPE_MISMATCH");
    }

    #[test]
    fn limits_are_validated_against_hard_ceilings() {
        // Rebuild the line with an out-of-range limit and a fresh digest so
        // only the limit check can fail.
        let mut request = match json::parse(PUB_0000).unwrap() {
            Value::Obj(map) => map,
            _ => unreachable!(),
        };
        let Some(Value::Obj(limits)) = request.get_mut("limits") else {
            unreachable!()
        };
        limits.insert("max_actions".to_string(), Value::Int(2048));
        let digest = canonical_request_digest(&request);
        request.insert("request_digest".to_string(), Value::Str(digest));
        let line = Value::Obj(request).canonical();
        let error = parse_request(&line).unwrap_err();
        assert_eq!(error.code, "LIMIT_OUT_OF_RANGE");
    }

    #[test]
    fn zero_and_below_minimum_limits_fail_closed() {
        let mut request = match json::parse(PUB_0000).unwrap() {
            Value::Obj(map) => map,
            _ => unreachable!(),
        };
        let Some(Value::Obj(limits)) = request.get_mut("limits") else {
            unreachable!()
        };
        limits.insert("max_output_bytes".to_string(), Value::Int(0));
        let digest = canonical_request_digest(&request);
        request.insert("request_digest".to_string(), Value::Str(digest));
        let line = Value::Obj(request).canonical();
        assert_eq!(parse_request(&line).unwrap_err().code, "LIMIT_OUT_OF_RANGE");
    }

    #[test]
    fn handshake_protocol_lines_are_reported_unwired() {
        let line = format!("{{\"protocol\":\"{HANDSHAKE_PROTOCOL}\",\"version\":\"1.0.0\"}}");
        let error = parse_request(&line).unwrap_err();
        assert_eq!(error.code, "UNSUPPORTED_PROTOCOL");
        assert!(error.detail.contains("handshake adapter is not wired"));
    }
}
