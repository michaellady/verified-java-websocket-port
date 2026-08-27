//! The single `ws_core` coupling seam (MERGE-TIME WIRING POINT) and the
//! execution-time step driver.
//!
//! Everything the harness knows about the Rust ConnectionCore lives in this
//! module, so lane A's real API (built in parallel on another branch) can be
//! connected in one place without touching the protocol machinery. The
//! module has two halves:
//!
//! 1. [`drive_scenario`] / `run_step` — the mirror of
//!    `OracleEngine.Execution.run` and its per-action handlers. Java
//!    validates each step DURING execution, not at envelope parse time, so a
//!    malformed step mid-scenario is a request-bound partial failure that
//!    retains counts-so-far, the current state, and the runtime identity.
//!    The driver replicates Java's validation order check-for-check (see
//!    `run_step`); every count/state/protocol effect is a [`ScenarioSession`]
//!    hook so the ordering is pinned here once and the core supplies only
//!    behavior.
//! 2. [`CandidateCore`] — the constructor seam. `begin` mirrors
//!    `new Execution(...)`: construction failure (Java's
//!    `NoClassDefFoundError` path) precedes ALL step validation.
//!
//! ## This round: truthfully unwired
//!
//! The `ws_core` crate on this branch is still the committed UNIMPLEMENTED
//! scaffold (no ConnectionCore API exists to call), so the active
//! implementation is [`UnwiredCore`]: `begin` fails with the typed
//! `CORE_NOT_WIRED` detail, mirroring how Java answers the
//! runtime-unavailable construction path before any step is examined. Every
//! scenario — including one with malformed steps — is therefore answered
//! with the request-bound `CORE_NOT_WIRED` failure envelope (zero counts,
//! `final_state == initial_state`). **No behavior is fabricated.** The
//! wiring commit that replaces [`active_core`]'s body with a real
//! `ws_core`-backed session happens at merge time by the integrating parent,
//! against lane A's landed API.

use crate::json::Value;
use crate::observe::{ConnectionState, Counts, CountsWithState, Observations};
use crate::request::{
    DataOpcode, Limits, OracleRequest, ProtocolError, base64_field, boolean, integer, invalid_enum,
    reject_unknown, string,
};

/// One scenario-scoped typed failure, mirroring the oracle's stable error
/// vocabulary (`JAVA_INVALID_DATA` + close code, `STATE_VIOLATION`, the
/// limit codes, …) plus the harness's own truthful `CORE_NOT_WIRED`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioFailure {
    /// Stable typed code (`^[A-Z0-9_]+$`).
    pub code: String,
    /// Close code, present exactly when the oracle vocabulary carries one.
    pub close_code: Option<i64>,
    /// Bounded human-readable detail.
    pub detail: String,
}

impl From<ProtocolError> for ScenarioFailure {
    /// A step-validation `ProtocolError` becomes a request-bound scenario
    /// failure (Java: `catch (ProtocolException e) { execution.failure(e) }`
    /// — validation exceptions never carry a close code).
    fn from(error: ProtocolError) -> Self {
        ScenarioFailure {
            code: error.code.to_string(),
            close_code: None,
            detail: error.detail,
        }
    }
}

/// The outcome of driving one validated scenario through the core.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScenarioOutcome {
    /// Every step executed; the full observation surface is reported.
    Completed(Observations),
    /// A typed failure ended the scenario; counts and final state are
    /// retained (the oracle's partial-execution contract).
    Failed {
        /// The typed failure that ended the scenario.
        failure: ScenarioFailure,
        /// Counters at the failure point.
        counts: Counts,
        /// Connection state at the failure point.
        final_state: ConnectionState,
    },
    /// The core API is not wired yet; the harness must report this
    /// truthfully instead of fabricating behavior.
    NotWired {
        /// Honest explanation serialized into the failure detail.
        detail: String,
    },
}

/// One live scenario execution — the seam onto Java's
/// `OracleEngine.Execution`. The driver owns step SHAPE validation and its
/// order; the session owns every count, state, limit, and protocol effect.
/// Each hook is documented with the exact Java site it mirrors so the
/// merge-time `ws_core` implementation inherits the order contract.
pub trait ScenarioSession {
    /// `Execution.input` (after the driver's unknown-field rejection and
    /// canonical base64 decode, which Java performs first): CLOSED-state
    /// check, `max_input_bytes` accounting, frame translation, inbound
    /// processing.
    fn bytes(&mut self, data: &[u8], step: u32) -> Result<(), ScenarioFailure>;

    /// `Execution.action` prelude: `actionCount++` and the `max_actions`
    /// check fire BEFORE the `action` field is even read.
    fn begin_action(&mut self, step: u32) -> Result<(), ScenarioFailure>;

    /// `Execution.requireOpen`: fires after the action's unknown-field
    /// rejection and BEFORE its payload fields are read (Java reads `text`,
    /// `data_base64`, `code`/`reason`, `opcode`/`fin` only after this
    /// check).
    fn require_open(&mut self, action: &str) -> Result<(), ScenarioFailure>;

    /// `Execution.sendText` tail: createFrames + emitOutbound.
    fn send_text(&mut self, text: &str, step: u32) -> Result<(), ScenarioFailure>;

    /// `Execution.sendBinary` tail.
    fn send_binary(&mut self, data: &[u8], step: u32) -> Result<(), ScenarioFailure>;

    /// `Execution.sendControl` tail for ping (`isValid` + emitOutbound; no
    /// buffered-payload limit — Java applies none to control frames).
    fn send_ping(&mut self, data: &[u8], step: u32) -> Result<(), ScenarioFailure>;

    /// `Execution.sendControl` tail for pong.
    fn send_pong(&mut self, data: &[u8], step: u32) -> Result<(), ScenarioFailure>;

    /// `Execution.sendClose` tail.
    fn send_close(&mut self, code: i64, reason: &str, step: u32) -> Result<(), ScenarioFailure>;

    /// `Execution.sendFragment` tail.
    fn send_fragment(
        &mut self,
        opcode: DataOpcode,
        data: &[u8],
        fin: bool,
        step: u32,
    ) -> Result<(), ScenarioFailure>;

    /// `Execution.eof` (state check included — `eof` is legal outside OPEN).
    fn eof(&mut self, step: u32) -> Result<(), ScenarioFailure>;

    /// Counters and state at this instant, retained on partial failure
    /// (Java `Execution.failure`).
    fn snapshot(&self) -> CountsWithState;

    /// `Execution.success` observation surface after every step executed.
    fn finish(self: Box<Self>) -> Observations;
}

/// The narrow constructor surface the harness needs from a Rust oracle
/// candidate.
pub trait CandidateCore {
    /// Constructs one scenario session (Java `new Execution(...)`), or
    /// truthfully reports that no core is wired. Construction precedes all
    /// step validation, exactly as Java's `NoClassDefFoundError`
    /// construction path precedes `Execution.run`.
    ///
    /// # Errors
    ///
    /// The honest not-wired detail, serialized into the request-bound
    /// `CORE_NOT_WIRED` failure envelope.
    fn begin(&mut self, request: &OracleRequest) -> Result<Box<dyn ScenarioSession>, String>;
}

/// Drives one envelope-validated request through the core: constructs the
/// session, then walks the RAW steps, validating each at execution time in
/// `OracleEngine.Execution.run`'s exact order. The first failure ends the
/// scenario with the session's retained counts and state.
pub fn drive_scenario(request: &OracleRequest, core: &mut dyn CandidateCore) -> ScenarioOutcome {
    let mut session = match core.begin(request) {
        Ok(session) => session,
        Err(detail) => return ScenarioOutcome::NotWired { detail },
    };
    for (index, raw) in request.steps.iter().enumerate() {
        if let Err(failure) = run_step(session.as_mut(), &request.limits, raw, index) {
            let snapshot = session.snapshot();
            return ScenarioOutcome::Failed {
                failure,
                counts: snapshot.counts,
                final_state: snapshot.final_state,
            };
        }
    }
    ScenarioOutcome::Completed(session.finish())
}

/// One step, validated and dispatched in Java's exact order
/// (`Execution.run` + the per-kind handlers). Comments cite the mirrored
/// Java sequence points; do not reorder without re-reading `OracleEngine`.
fn run_step(
    session: &mut dyn ScenarioSession,
    limits: &Limits,
    raw: &Value,
    index: usize,
) -> Result<(), ScenarioFailure> {
    let step = u32::try_from(index).unwrap_or(u32::MAX);
    // Execution.run: object(steps.get(i), "steps[i]").
    let Value::Obj(members) = raw else {
        return Err(ProtocolError::new(
            "TYPE_MISMATCH",
            format!("steps[{index}] must be an object"),
        )
        .into());
    };
    // Execution.run: string(step, "kind"), then the kind switch.
    match string(members, "kind")?.as_str() {
        "bytes" => {
            // Execution.input: rejectUnknown, then base64, then the
            // state/limit/translation effects (session).
            reject_unknown(members, &["data_base64", "kind"], "bytes step")?;
            let data = base64_field(members, "data_base64")?;
            session.bytes(&data, step)
        }
        "action" => {
            // Execution.action: actionCount++ and the max_actions check
            // precede even the `action` field read.
            session.begin_action(step)?;
            match string(members, "action")?.as_str() {
                "send_text" => {
                    // sendText: rejectUnknown -> requireOpen -> text ->
                    // requirePayloadLimit -> frames.
                    reject_unknown(members, &["action", "kind", "text"], "send_text action")?;
                    session.require_open("send_text")?;
                    let text = string(members, "text")?;
                    require_payload_limit(text.len(), limits)?;
                    session.send_text(&text, step)
                }
                "send_binary" => {
                    // sendBinary: rejectUnknown -> requireOpen -> base64 ->
                    // requirePayloadLimit -> frames.
                    reject_unknown(
                        members,
                        &["action", "data_base64", "kind"],
                        "send_binary action",
                    )?;
                    session.require_open("send_binary")?;
                    let data = base64_field(members, "data_base64")?;
                    require_payload_limit(data.len(), limits)?;
                    session.send_binary(&data, step)
                }
                "send_ping" => {
                    // sendControl: rejectUnknown -> requireOpen -> base64 ->
                    // frame validity (session); no payload-limit check.
                    reject_unknown(
                        members,
                        &["action", "data_base64", "kind"],
                        "send_ping action",
                    )?;
                    session.require_open("send_ping")?;
                    let data = base64_field(members, "data_base64")?;
                    session.send_ping(&data, step)
                }
                "send_pong" => {
                    reject_unknown(
                        members,
                        &["action", "data_base64", "kind"],
                        "send_pong action",
                    )?;
                    session.require_open("send_pong")?;
                    let data = base64_field(members, "data_base64")?;
                    session.send_pong(&data, step)
                }
                "send_close" => {
                    // sendClose: rejectUnknown -> requireOpen -> code ->
                    // reason -> frame effects.
                    reject_unknown(
                        members,
                        &["action", "code", "kind", "reason"],
                        "send_close action",
                    )?;
                    session.require_open("send_close")?;
                    let code = integer(members, "code")?;
                    let reason = string(members, "reason")?;
                    session.send_close(code, &reason, step)
                }
                "send_fragment" => {
                    // sendFragment: rejectUnknown -> requireOpen -> opcode
                    // (full Opcode vocabulary first, then the text/binary
                    // restriction — two distinct INVALID_ENUM details) ->
                    // base64 -> requirePayloadLimit -> fin -> frames.
                    reject_unknown(
                        members,
                        &["action", "data_base64", "fin", "kind", "opcode"],
                        "send_fragment action",
                    )?;
                    session.require_open("send_fragment")?;
                    let opcode = fragment_opcode(members)?;
                    let data = base64_field(members, "data_base64")?;
                    require_payload_limit(data.len(), limits)?;
                    let fin = boolean(members, "fin")?;
                    session.send_fragment(opcode, &data, fin, step)
                }
                "eof" => {
                    // eof: rejectUnknown -> state effects (session).
                    reject_unknown(members, &["action", "kind"], "eof action")?;
                    session.eof(step)
                }
                _ => Err(ProtocolError::new("INVALID_ENUM", "action has unsupported value").into()),
            }
        }
        _ => Err(ProtocolError::new("INVALID_ENUM", "step kind has unsupported value").into()),
    }
}

/// Java `enumValue(step, "opcode", Opcode.class)` + the explicit
/// text/binary restriction: an opcode outside the full Java `Opcode`
/// vocabulary reports "opcode has unsupported value"; a valid non-data
/// opcode reports "send_fragment opcode must be text or binary".
fn fragment_opcode(
    members: &std::collections::BTreeMap<String, Value>,
) -> Result<DataOpcode, ProtocolError> {
    let opcode = string(members, "opcode")?;
    match opcode.as_str() {
        "text" => Ok(DataOpcode::Text),
        "binary" => Ok(DataOpcode::Binary),
        "closing" | "continuous" | "ping" | "pong" => Err(ProtocolError::new(
            "INVALID_ENUM",
            "send_fragment opcode must be text or binary",
        )),
        _ => Err(invalid_enum("opcode")),
    }
}

/// Java `Execution.requirePayloadLimit`: data-frame action payloads are
/// bounded by `max_buffered_bytes`. Sits in the driver because Java places
/// it BETWEEN field reads (before `fin` in `sendFragment`), so the order is
/// part of the validation contract, and the limit comes from the request.
fn require_payload_limit(size: usize, limits: &Limits) -> Result<(), ProtocolError> {
    if size as i64 > limits.max_buffered_bytes {
        return Err(ProtocolError::new(
            "BUFFER_LIMIT_EXCEEDED",
            "action payload exceeds max_buffered_bytes",
        ));
    }
    Ok(())
}

/// Truthful placeholder implementation used until lane A's `ws_core`
/// ConnectionCore API lands: session construction always fails with the
/// honest `CORE_NOT_WIRED` detail (before any step is examined, mirroring
/// Java's runtime-unavailable construction path).
#[derive(Clone, Copy, Debug, Default)]
pub struct UnwiredCore;

/// The honest unwired detail, kept stable so transcripts are byte-identical
/// across reruns.
pub const UNWIRED_DETAIL: &str = "ws_core ConnectionCore API not yet landed \
     (US-009 lane A); harness truthfully reports no behavior instead of \
     fabricating it";

impl CandidateCore for UnwiredCore {
    fn begin(&mut self, _request: &OracleRequest) -> Result<Box<dyn ScenarioSession>, String> {
        Err(UNWIRED_DETAIL.to_string())
    }
}

/// Returns the active core implementation.
///
/// MERGE-TIME WIRING POINT: the integrating parent replaces this body with a
/// `ws_core`-backed session factory once lane A's ConnectionCore API lands.
/// Until then the truthfully-labeled [`UnwiredCore`] answers, so this crate
/// builds and runs standalone on this branch.
pub fn active_core() -> impl CandidateCore {
    UnwiredCore
}

#[cfg(test)]
mod tests {
    use super::*;
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

    /// A scripted session that records the exact hook order the driver
    /// calls, so Java's validation order is pinned by tests.
    #[derive(Default)]
    struct ScriptedSession {
        calls: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
        open: bool,
        actions: i64,
        max_actions: i64,
        input_bytes: i64,
    }

    impl ScriptedSession {
        fn log(&self, call: impl Into<String>) {
            self.calls.borrow_mut().push(call.into());
        }
    }

    impl ScenarioSession for ScriptedSession {
        fn bytes(&mut self, data: &[u8], _step: u32) -> Result<(), ScenarioFailure> {
            self.log(format!("bytes({})", data.len()));
            self.input_bytes += data.len() as i64;
            Ok(())
        }
        fn begin_action(&mut self, _step: u32) -> Result<(), ScenarioFailure> {
            self.log("begin_action");
            self.actions += 1;
            if self.actions > self.max_actions {
                return Err(ScenarioFailure {
                    code: "ACTION_LIMIT_EXCEEDED".to_string(),
                    close_code: None,
                    detail: "action count exceeds max_actions".to_string(),
                });
            }
            Ok(())
        }
        fn require_open(&mut self, action: &str) -> Result<(), ScenarioFailure> {
            self.log(format!("require_open({action})"));
            if self.open {
                Ok(())
            } else {
                Err(ScenarioFailure {
                    code: "STATE_VIOLATION".to_string(),
                    close_code: None,
                    detail: format!("{action} requires OPEN state"),
                })
            }
        }
        fn send_text(&mut self, _text: &str, _step: u32) -> Result<(), ScenarioFailure> {
            self.log("send_text");
            Ok(())
        }
        fn send_binary(&mut self, _data: &[u8], _step: u32) -> Result<(), ScenarioFailure> {
            self.log("send_binary");
            Ok(())
        }
        fn send_ping(&mut self, _data: &[u8], _step: u32) -> Result<(), ScenarioFailure> {
            self.log("send_ping");
            Ok(())
        }
        fn send_pong(&mut self, _data: &[u8], _step: u32) -> Result<(), ScenarioFailure> {
            self.log("send_pong");
            Ok(())
        }
        fn send_close(
            &mut self,
            _code: i64,
            _reason: &str,
            _step: u32,
        ) -> Result<(), ScenarioFailure> {
            self.log("send_close");
            Ok(())
        }
        fn send_fragment(
            &mut self,
            _opcode: DataOpcode,
            _data: &[u8],
            _fin: bool,
            _step: u32,
        ) -> Result<(), ScenarioFailure> {
            self.log("send_fragment");
            Ok(())
        }
        fn eof(&mut self, _step: u32) -> Result<(), ScenarioFailure> {
            self.log("eof");
            Ok(())
        }
        fn snapshot(&self) -> CountsWithState {
            CountsWithState {
                counts: Counts {
                    actions: self.actions,
                    input_bytes: self.input_bytes,
                    ..Counts::default()
                },
                final_state: if self.open {
                    ConnectionState::Open
                } else {
                    ConnectionState::Closed
                },
            }
        }
        fn finish(self: Box<Self>) -> Observations {
            Observations {
                counts: self.snapshot(),
                ..Observations::default()
            }
        }
    }

    struct ScriptedCore {
        open: bool,
        max_actions: i64,
        calls: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
    }

    impl CandidateCore for ScriptedCore {
        fn begin(&mut self, _request: &OracleRequest) -> Result<Box<dyn ScenarioSession>, String> {
            Ok(Box::new(ScriptedSession {
                calls: self.calls.clone(),
                open: self.open,
                max_actions: self.max_actions,
                ..ScriptedSession::default()
            }))
        }
    }

    fn scripted(open: bool, max_actions: i64) -> ScriptedCore {
        ScriptedCore {
            open,
            max_actions,
            calls: std::rc::Rc::default(),
        }
    }

    fn request_with_steps(steps_json: &str) -> OracleRequest {
        let Value::Obj(mut map) = crate::json::parse(PUB_0000).unwrap() else {
            unreachable!()
        };
        map.insert(
            "steps".to_string(),
            crate::json::parse(steps_json).expect("steps fixture parses"),
        );
        let digest = crate::request::canonical_request_digest(&map);
        map.insert("request_digest".to_string(), Value::Str(digest));
        parse_request(&Value::Obj(map).canonical()).expect("envelope verifies")
    }

    fn failure_code(outcome: ScenarioOutcome) -> (String, Counts) {
        match outcome {
            ScenarioOutcome::Failed {
                failure, counts, ..
            } => (failure.code, counts),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn unwired_core_never_claims_behavior() {
        let request = parse_request(PUB_0000).unwrap();
        let outcome = drive_scenario(&request, &mut UnwiredCore);
        assert_eq!(
            outcome,
            ScenarioOutcome::NotWired {
                detail: UNWIRED_DETAIL.to_string()
            }
        );
    }

    /// A malformed step AFTER an executed step fails request-bound with the
    /// counts the session accumulated so far (Java's partial-execution
    /// contract).
    #[test]
    fn malformed_step_mid_scenario_retains_partial_counts() {
        let request = request_with_steps(concat!(
            "[{\"data_base64\":\"AQI=\",\"kind\":\"bytes\"},",
            "{\"bogus\":1,\"data_base64\":\"AQI=\",\"kind\":\"bytes\"}]"
        ));
        let mut core = scripted(true, 64);
        let (code, counts) = failure_code(drive_scenario(&request, &mut core));
        assert_eq!(code, "UNKNOWN_FIELD");
        assert_eq!(counts.input_bytes, 2, "step 0's effect is retained");
    }

    /// Non-canonical base64 rejects at execution time (Java
    /// `Execution.input` -> `OracleEngine.base64`) — the round-1 envelope
    /// narrowing is gone.
    #[test]
    fn non_canonical_base64_fails_at_execution_time() {
        let request = request_with_steps("[{\"data_base64\":\"Zg\",\"kind\":\"bytes\"}]");
        let mut core = scripted(true, 64);
        let (code, _) = failure_code(drive_scenario(&request, &mut core));
        assert_eq!(code, "INVALID_BASE64");
    }

    /// Java increments and checks the action counter BEFORE reading the
    /// `action` field, so an exhausted budget wins over a malformed action.
    #[test]
    fn action_limit_precedes_action_field_read() {
        let request = request_with_steps(concat!(
            "[{\"action\":\"eof\",\"kind\":\"action\"},",
            "{\"bogus\":true,\"kind\":\"action\"}]"
        ));
        let mut core = scripted(true, 1);
        let (code, counts) = failure_code(drive_scenario(&request, &mut core));
        assert_eq!(code, "ACTION_LIMIT_EXCEEDED");
        assert_eq!(counts.actions, 2, "the rejected action is counted");
    }

    /// Java's `requireOpen` fires before payload fields are read: a
    /// send_text with NO text in a non-open state reports STATE_VIOLATION,
    /// not MISSING_FIELD.
    #[test]
    fn require_open_precedes_payload_field_reads() {
        let request = request_with_steps("[{\"action\":\"send_text\",\"kind\":\"action\"}]");
        let mut core = scripted(false, 64);
        let (code, _) = failure_code(drive_scenario(&request, &mut core));
        assert_eq!(code, "STATE_VIOLATION");

        // In OPEN state the same step reaches the field read.
        let mut core = scripted(true, 64);
        let (code, _) = failure_code(drive_scenario(&request, &mut core));
        assert_eq!(code, "MISSING_FIELD");
    }

    /// sendFragment reads `opcode` before `data_base64` before `fin`
    /// (payload limit between), with Java's two distinct INVALID_ENUM
    /// details for unknown vs non-data opcodes.
    #[test]
    fn send_fragment_validation_order_and_opcode_vocabulary() {
        let bad_opcode = request_with_steps(concat!(
            "[{\"action\":\"send_fragment\",\"data_base64\":\"Zg\",",
            "\"kind\":\"action\",\"opcode\":\"warp\"}]"
        ));
        let mut core = scripted(true, 64);
        let outcome = drive_scenario(&bad_opcode, &mut core);
        let ScenarioOutcome::Failed { failure, .. } = outcome else {
            panic!("expected Failed");
        };
        assert_eq!(failure.code, "INVALID_ENUM");
        assert_eq!(failure.detail, "opcode has unsupported value");

        let control_opcode = request_with_steps(concat!(
            "[{\"action\":\"send_fragment\",\"data_base64\":\"Zg\",",
            "\"kind\":\"action\",\"opcode\":\"ping\"}]"
        ));
        let mut core = scripted(true, 64);
        let ScenarioOutcome::Failed { failure, .. } = drive_scenario(&control_opcode, &mut core)
        else {
            panic!("expected Failed");
        };
        assert_eq!(failure.code, "INVALID_ENUM");
        assert_eq!(
            failure.detail,
            "send_fragment opcode must be text or binary"
        );

        // Valid opcode, oversized payload, MISSING fin: the payload limit
        // fires before the fin read (Java reads fin last).
        let no_fin = request_with_steps(&format!(
            "[{{\"action\":\"send_fragment\",\"data_base64\":\"{}\",\
             \"kind\":\"action\",\"opcode\":\"text\"}}]",
            crate::base64::encode(&vec![0u8; 65_537])
        ));
        let mut core = scripted(true, 64);
        let ScenarioOutcome::Failed { failure, .. } = drive_scenario(&no_fin, &mut core) else {
            panic!("expected Failed");
        };
        assert_eq!(failure.code, "BUFFER_LIMIT_EXCEEDED");
    }

    /// Unknown step kinds reject INVALID_ENUM without touching the action
    /// counter (Java's kind switch precedes `action()`).
    #[test]
    fn unknown_kind_rejects_before_action_counting() {
        let request = request_with_steps("[{\"kind\":\"warp\"}]");
        let mut core = scripted(true, 64);
        let calls = core.calls.clone();
        let (code, counts) = failure_code(drive_scenario(&request, &mut core));
        assert_eq!(code, "INVALID_ENUM");
        assert_eq!(counts.actions, 0);
        assert!(calls.borrow().is_empty(), "no session hook was reached");
    }

    /// The full hook order for a healthy mixed scenario matches Java's
    /// execution sequence.
    #[test]
    fn driver_hook_order_matches_java_execution() {
        let request = request_with_steps(concat!(
            "[{\"data_base64\":\"AQI=\",\"kind\":\"bytes\"},",
            "{\"action\":\"send_text\",\"kind\":\"action\",\"text\":\"hi\"},",
            "{\"action\":\"eof\",\"kind\":\"action\"}]"
        ));
        let mut core = scripted(true, 64);
        let calls = core.calls.clone();
        let outcome = drive_scenario(&request, &mut core);
        assert!(matches!(outcome, ScenarioOutcome::Completed(_)));
        assert_eq!(
            *calls.borrow(),
            vec![
                "bytes(2)".to_string(),
                "begin_action".to_string(),
                "require_open(send_text)".to_string(),
                "send_text".to_string(),
                "begin_action".to_string(),
                "eof".to_string(),
            ]
        );
    }
}
