//! Response envelope construction.
//!
//! Mirrors `OracleEngine.success` / `OracleEngine.failure` / `OracleMain.error`
//! and the candidate-stub envelope byte-for-byte: canonical (lexically
//! ordered, whitespace-free) JSON, one line per request, the digest binding
//! echoed on every request-scoped response, and a `runtime` object carrying
//! the candidate's honest identity.

use std::collections::BTreeMap;

use crate::core_adapter::ScenarioFailure;
use crate::json::Value;
use crate::observe::{self, ConnectionState, Counts, Observations};
use crate::request::{OracleRequest, ProtocolError};
use crate::{ARTIFACT, PROTOCOL, VERSION};

/// The candidate's runtime identity reported on every request-scoped
/// response: the real artifact name and the SHA-256 of the executable that
/// produced the transcript. This deliberately replaces the candidate-stub's
/// all-zero digest so an inert stub and this harness are always
/// distinguishable in transcripts (US-005 calibration discipline).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeIdentity {
    /// Artifact name (`ws-oracle-harness`).
    pub artifact: String,
    /// `sha256:<hex>` of the running executable.
    pub sha256: String,
}

impl RuntimeIdentity {
    /// Reads the harness's own executable and digests it. The I/O lives here
    /// in the harness, never in the core.
    ///
    /// # Errors
    ///
    /// Returns a bounded diagnostic when the executable path or bytes cannot
    /// be read; callers must fail closed (refuse to start) rather than
    /// fabricate an identity.
    pub fn from_current_exe() -> Result<RuntimeIdentity, String> {
        let path = std::env::current_exe()
            .map_err(|e| format!("cannot resolve current executable: {e}"))?;
        let bytes =
            std::fs::read(&path).map_err(|e| format!("cannot read current executable: {e}"))?;
        Ok(RuntimeIdentity {
            artifact: ARTIFACT.to_string(),
            sha256: crate::sha256::digest_identity(&bytes),
        })
    }

    fn value(&self) -> Value {
        let mut runtime = BTreeMap::new();
        runtime.insert("artifact".to_string(), Value::Str(self.artifact.clone()));
        runtime.insert("sha256".to_string(), Value::Str(self.sha256.clone()));
        Value::Obj(runtime)
    }
}

fn base(request: &OracleRequest, outcome: &str) -> BTreeMap<String, Value> {
    let mut response = BTreeMap::new();
    response.insert("outcome".to_string(), Value::Str(outcome.to_string()));
    response.insert("protocol".to_string(), Value::Str(PROTOCOL.to_string()));
    response.insert(
        "request_digest".to_string(),
        Value::Str(request.request_digest.clone()),
    );
    response.insert(
        "request_id".to_string(),
        Value::Str(request.request_id.clone()),
    );
    response.insert("version".to_string(), Value::Str(VERSION.to_string()));
    response
}

/// Builds one success response line (no trailing newline), mirroring
/// `OracleEngine.success` field-for-field.
pub fn ok_response(
    request: &OracleRequest,
    observations: &Observations,
    runtime: &RuntimeIdentity,
) -> String {
    let mut response = base(request, "ok");
    response.insert(
        "close".to_string(),
        observations
            .close
            .as_ref()
            .map_or(Value::Null, observe::close_value),
    );
    response.insert(
        "counts".to_string(),
        observe::counts_value(&observations.counts.counts),
    );
    response.insert(
        "events".to_string(),
        Value::Arr(
            observations
                .events
                .iter()
                .map(observe::event_value)
                .collect(),
        ),
    );
    response.insert(
        "final_state".to_string(),
        Value::Str(observations.counts.final_state.wire().to_string()),
    );
    response.insert(
        "frames".to_string(),
        Value::Arr(
            observations
                .frames
                .iter()
                .map(observe::frame_value)
                .collect(),
        ),
    );
    response.insert(
        "initial_state".to_string(),
        Value::Str(request.initial_state.wire().to_string()),
    );
    response.insert(
        "role".to_string(),
        Value::Str(request.role.wire().to_string()),
    );
    response.insert("runtime".to_string(), runtime.value());
    response.insert(
        "transitions".to_string(),
        Value::Arr(
            observations
                .transitions
                .iter()
                .map(observe::transition_value)
                .collect(),
        ),
    );
    Value::Obj(response).canonical()
}

/// Builds one failure response line (no trailing newline), mirroring
/// `OracleEngine.failure`: the typed error object plus the retained counts,
/// final state, and runtime identity ("Partial execution errors retain
/// counts and final state").
pub fn failure_response(
    request: &OracleRequest,
    failure: &ScenarioFailure,
    counts: &Counts,
    final_state: ConnectionState,
    runtime: &RuntimeIdentity,
) -> String {
    let mut response = base(request, "error");
    let mut error = BTreeMap::new();
    error.insert("code".to_string(), Value::Str(failure.code.clone()));
    if let Some(close_code) = failure.close_code {
        error.insert("close_code".to_string(), Value::Int(close_code));
    }
    error.insert("detail".to_string(), Value::Str(failure.detail.clone()));
    response.insert("error".to_string(), Value::Obj(error));
    response.insert("counts".to_string(), observe::counts_value(counts));
    response.insert(
        "final_state".to_string(),
        Value::Str(final_state.wire().to_string()),
    );
    response.insert("runtime".to_string(), runtime.value());
    Value::Obj(response).canonical()
}

/// Builds one envelope-level error response line for a request that never
/// reached scenario execution, mirroring `OracleMain.error` exactly —
/// including its `request_id: null` (java-oracle reports line-level
/// rejections without an id binding).
pub fn envelope_error_response(error: &ProtocolError) -> String {
    let mut detail = BTreeMap::new();
    detail.insert("code".to_string(), Value::Str(error.code.to_string()));
    detail.insert("detail".to_string(), Value::Str(error.detail.clone()));
    let mut response = BTreeMap::new();
    response.insert("error".to_string(), Value::Obj(detail));
    response.insert("outcome".to_string(), Value::Str("error".to_string()));
    response.insert("protocol".to_string(), Value::Str(PROTOCOL.to_string()));
    response.insert("request_id".to_string(), Value::Null);
    response.insert("version".to_string(), Value::Str(VERSION.to_string()));
    Value::Obj(response).canonical()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observe::{
        CloseDetail, CloseOrigin, CountsWithState, SemanticEvent, SemanticEventKind, Transition,
        TransitionCause,
    };
    use crate::request::parse_request;

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
            artifact: ARTIFACT.to_string(),
            sha256: concat!(
                "sha256:1111111111111111111111111111111111111111",
                "111111111111111111111111"
            )
            .to_string(),
        }
    }

    #[test]
    fn ok_response_matches_oracle_envelope_shape_byte_for_byte() {
        let request = parse_request(PUB_0000).unwrap();
        let observations = Observations {
            events: vec![SemanticEvent {
                step: 0,
                kind: SemanticEventKind::InputChunk { bytes: 0 },
            }],
            frames: vec![],
            transitions: vec![Transition {
                from: ConnectionState::Open,
                to: ConnectionState::Closing,
                cause: TransitionCause::SendClose,
                step: 0,
            }],
            close: Some(CloseDetail {
                code: 1000,
                reason: "done".to_string(),
                origin: CloseOrigin::Local,
                remote: false,
                handshake_complete: false,
            }),
            counts: CountsWithState {
                counts: Counts {
                    actions: 1,
                    ..Counts::default()
                },
                final_state: ConnectionState::Closing,
            },
        };
        let rendered = ok_response(&request, &observations, &test_runtime());
        let expected = concat!(
            "{\"close\":{\"code\":1000,\"handshake_complete\":false,",
            "\"origin\":\"local\",\"reason\":\"done\",\"remote\":false},",
            "\"counts\":{\"actions\":1,\"buffered_bytes\":0,\"consumed_bytes\":0,",
            "\"frames\":0,\"input_bytes\":0,\"message_buffered_bytes\":0,",
            "\"wire_buffered_bytes\":0},",
            "\"events\":[{\"bytes\":0,\"step\":0,\"type\":\"input_chunk\"}],",
            "\"final_state\":\"closing\",\"frames\":[],\"initial_state\":\"open\",",
            "\"outcome\":\"ok\",\"protocol\":\"java-websocket-oracle\",",
            "\"request_digest\":\"sha256:332b88dac25b405b3d9ce3b6a82b4ec88212",
            "96a9a492aa70a26ce867d817e0c9\",\"request_id\":\"us005.pub.0000\",",
            "\"role\":\"client\",\"runtime\":{\"artifact\":\"ws-oracle-harness\",",
            "\"sha256\":\"sha256:11111111111111111111111111111111111111111111",
            "11111111111111111111\"},",
            "\"transitions\":[{\"cause\":\"send_close\",\"from\":\"open\",",
            "\"step\":0,\"to\":\"closing\"}],\"version\":\"1.0.0\"}"
        );
        assert_eq!(rendered, expected);
    }

    #[test]
    fn failure_response_retains_counts_state_and_binding() {
        let request = parse_request(PUB_0000).unwrap();
        let failure = ScenarioFailure {
            code: "JAVA_INVALID_DATA".to_string(),
            close_code: Some(1002),
            detail: "planted detail".to_string(),
        };
        let rendered = failure_response(
            &request,
            &failure,
            &Counts {
                actions: 1,
                ..Counts::default()
            },
            ConnectionState::Open,
            &test_runtime(),
        );
        let expected = concat!(
            "{\"counts\":{\"actions\":1,\"buffered_bytes\":0,\"consumed_bytes\":0,",
            "\"frames\":0,\"input_bytes\":0,\"message_buffered_bytes\":0,",
            "\"wire_buffered_bytes\":0},\"error\":{\"close_code\":1002,",
            "\"code\":\"JAVA_INVALID_DATA\",\"detail\":\"planted detail\"},",
            "\"final_state\":\"open\",\"outcome\":\"error\",",
            "\"protocol\":\"java-websocket-oracle\",",
            "\"request_digest\":\"sha256:332b88dac25b405b3d9ce3b6a82b4ec88212",
            "96a9a492aa70a26ce867d817e0c9\",\"request_id\":\"us005.pub.0000\",",
            "\"runtime\":{\"artifact\":\"ws-oracle-harness\",",
            "\"sha256\":\"sha256:11111111111111111111111111111111111111111111",
            "11111111111111111111\"},\"version\":\"1.0.0\"}"
        );
        assert_eq!(rendered, expected);
    }

    #[test]
    fn envelope_error_mirrors_oracle_main_null_request_id() {
        let rendered = envelope_error_response(&ProtocolError::new(
            "EMPTY_LINE",
            "empty JSONL records are forbidden",
        ));
        assert_eq!(
            rendered,
            concat!(
                "{\"error\":{\"code\":\"EMPTY_LINE\",",
                "\"detail\":\"empty JSONL records are forbidden\"},",
                "\"outcome\":\"error\",\"protocol\":\"java-websocket-oracle\",",
                "\"request_id\":null,\"version\":\"1.0.0\"}"
            )
        );
    }
}
