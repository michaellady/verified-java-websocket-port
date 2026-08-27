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
//!    The driver owns step SHAPE only: it reads every field in Java's exact
//!    order (`parse_action`) and ALWAYS delivers a constructible command to
//!    the session, so the core runs Java's interleaved gates itself (the
//!    action prelude, requireOpen, the payload limit — connection.rs
//!    `handle_command` re-runs exactly that sequence at command receipt).
//!    Only a step that can never become a core input (malformed or
//!    unrepresentable) is failed driver-side, with the [`ScenarioSession`]
//!    driver-gate hooks re-establishing Java's gate order around the parse
//!    failure. (Re-review round 1, session 01a04427: pre-delivery gates on
//!    the deliverable path would let the adapter synthesize protocol
//!    behavior the core owns.)
//! 2. [`CandidateCore`] — the constructor seam. `begin` mirrors
//!    `new Execution(...)`: construction failure (Java's
//!    `NoClassDefFoundError` path) precedes ALL step validation.
//!
//! ## This round: WIRED to the real `ws_core` ConnectionCore
//!
//! Both US-009 lanes are merged on this branch, so [`active_core`] now
//! answers with [`WiredCore`]: every scenario constructs a real
//! [`ws_core::connection::ConnectionCore`] via `new_in_state` (the corpus
//! `initial_state` seam), maps steps onto [`ws_core::connection::Input`]
//! values (`bytes` -> `TransportBytes`, `eof` -> `TransportEof`, send
//! actions -> `LocalCommand`), drains the core's typed event/write queues
//! after every input, and projects the drained events 1:1 into the
//! transcript vocabulary through [`crate::observe`]. Failure mapping is
//! faithful and honest:
//!
//! - an oracle-coded [`ws_core::error::TypedProtocolFailure`] becomes the
//!   failure envelope with its exact wire code and close code;
//! - the skeleton's [`ws_core::error::FailureCode::Unimplemented`] refusal
//!   (deliberately carrying NO oracle wire code) becomes the honest
//!   non-oracle `CORE_BEHAVIOR_UNIMPLEMENTED` envelope — shaped exactly
//!   like `CORE_NOT_WIRED` was: a truthful adapter-vocabulary code the
//!   evaluator can never score as Java behavior;
//! - non-fatal [`ws_core::error::FailureCode::Backpressure`] follows the
//!   core's documented contract (nothing consumed; drain and retry the
//!   identical input) — the session drains after every input, so a
//!   persistent refusal is a contract bug reported as the honest non-oracle
//!   `CORE_BACKPRESSURE_UNDRAINED`, never as a fabricated oracle code.
//!
//! [`UnwiredCore`] remains available (tests, and the historical
//! `CORE_NOT_WIRED` envelope shape it pins), but it is no longer the
//! default.

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
    /// Session construction itself failed (Java's runtime-unavailable
    /// `NoClassDefFoundError` path, which precedes all step validation).
    /// The response is the request-bound failure envelope with zero counts
    /// and `final_state == initial_state`.
    ConstructionFailed {
        /// The honest typed construction failure (`CORE_NOT_WIRED` for the
        /// unwired stub; adapter-vocabulary codes otherwise).
        failure: ScenarioFailure,
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

    /// Driver-gate mirror of Java's `Execution.action` prelude
    /// (`actionCount++` and the `max_actions` check, which fire BEFORE the
    /// `action` field is even read). Called ONLY for an action step that
    /// can never become a core input (a driver-level parse or
    /// representability failure): a deliverable command reaches the core's
    /// own identical prelude instead, so this hook never runs on the
    /// delivered path (re-review round 1).
    fn begin_action(&mut self, step: u32) -> Result<(), ScenarioFailure>;

    /// Driver-gate mirror of Java's `Execution.requireOpen`, which fires
    /// after the action's unknown-field rejection and BEFORE its payload
    /// fields are read (Java reads `text`, `data_base64`, `code`/`reason`,
    /// `opcode`/`fin` only after this check). Called ONLY for a step that
    /// can never become a core input and whose failed read sits past
    /// requireOpen; a deliverable command reaches the core's own identical
    /// state gate instead (re-review round 1).
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
    /// truthfully reports why it cannot. Construction precedes all step
    /// validation, exactly as Java's `NoClassDefFoundError` construction
    /// path precedes `Execution.run`.
    ///
    /// # Errors
    ///
    /// The honest typed construction failure, serialized into the
    /// request-bound failure envelope with zero counts and
    /// `final_state == initial_state`.
    fn begin(
        &mut self,
        request: &OracleRequest,
    ) -> Result<Box<dyn ScenarioSession>, ScenarioFailure>;
}

/// Drives one envelope-validated request through the core: constructs the
/// session, then walks the RAW steps, validating each at execution time in
/// `OracleEngine.Execution.run`'s exact order. The first failure ends the
/// scenario with the session's retained counts and state.
pub fn drive_scenario(request: &OracleRequest, core: &mut dyn CandidateCore) -> ScenarioOutcome {
    let mut session = match core.begin(request) {
        Ok(session) => session,
        Err(failure) => return ScenarioOutcome::ConstructionFailed { failure },
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
        "action" => match parse_action(members, limits) {
            // Every field Java reads parsed in Java's exact order: the
            // step is a real core input, and the session (the core) alone
            // runs Java's interleaved gates — `Execution.action`'s
            // actionCount++/max_actions prelude, requireOpen, and the
            // payload limit all re-run identically inside
            // connection.rs `handle_command` at command receipt. The
            // driver adds NO pre-delivery protocol check (re-review
            // round 1, session 01a04427).
            Ok(command) => deliver(session, command, step),
            // The step can never become a core input (a field is missing,
            // mistyped, or unrepresentable), so no core gate will ever see
            // it. Java still ran its gates BEFORE reaching the failed
            // read; the driver-gate hooks re-establish exactly that order
            // around the parse failure — input-shaping, not protocol
            // behavior (both hooks are pure reads of the core's live
            // counts and state).
            Err(refusal) => {
                session.begin_action(step)?;
                if let Some(action) = refusal.requires_open {
                    session.require_open(action)?;
                }
                Err(refusal.failure)
            }
        },
        _ => Err(ProtocolError::new("INVALID_ENUM", "step kind has unsupported value").into()),
    }
}

/// One fully parsed action step: every field Java reads, read in Java's
/// exact order with NO gates interleaved. The existence of this value
/// means the step is deliverable — the session receives it as a real core
/// input and the core runs Java's gate order itself.
enum ParsedAction {
    /// `send_text {text}`.
    SendText {
        /// The text to send.
        text: String,
    },
    /// `send_binary {data_base64}`.
    SendBinary {
        /// The decoded payload.
        data: Vec<u8>,
    },
    /// `send_ping {data_base64}`.
    SendPing {
        /// The decoded payload.
        data: Vec<u8>,
    },
    /// `send_pong {data_base64}`.
    SendPong {
        /// The decoded payload.
        data: Vec<u8>,
    },
    /// `send_close {code, reason}`.
    SendClose {
        /// The requested close code (representability against the core's
        /// vocabulary is the session's concern, not the driver's).
        code: i64,
        /// The close reason.
        reason: String,
    },
    /// `send_fragment {opcode, data_base64, fin}`.
    SendFragment {
        /// The declared data opcode.
        opcode: DataOpcode,
        /// The decoded payload.
        data: Vec<u8>,
        /// Whether this fragment ends the message.
        fin: bool,
    },
    /// `eof` (maps to transport EOF; participates in action accounting
    /// inside the core).
    Eof,
}

/// Why an action step can never become a core input. `requires_open`
/// records where the failed read sits relative to Java's `requireOpen`:
/// `Some(action)` when the failure is at or past a payload-field read
/// (which Java performs only after requireOpen), `None` when it precedes
/// the per-action state gate (the `action` field read, an unknown action
/// value, or rejectUnknown).
struct ActionRefusal {
    /// The parse failure Java would report once its gates have passed.
    failure: ScenarioFailure,
    /// The requireOpen position marker (see the type docs).
    requires_open: Option<&'static str>,
}

/// Refusal constructor for failures that precede Java's `requireOpen`.
fn before_open(error: ProtocolError) -> ActionRefusal {
    ActionRefusal {
        failure: error.into(),
        requires_open: None,
    }
}

/// Refusal constructor for failures at or past Java's payload-field reads
/// (requireOpen precedes them, so the driver must re-establish it).
fn after_open(action: &'static str) -> impl Fn(ProtocolError) -> ActionRefusal {
    move |error| ActionRefusal {
        failure: error.into(),
        requires_open: Some(action),
    }
}

/// Parses one action step by reading exactly the fields Java reads, in
/// Java's exact order (`Execution.action` + the per-action handlers),
/// WITHOUT running any gate: gates belong to the core for deliverable
/// commands and to the driver-gate hooks for refusals (see `run_step`).
fn parse_action(
    members: &std::collections::BTreeMap<String, Value>,
    limits: &Limits,
) -> Result<ParsedAction, ActionRefusal> {
    // Execution.action: string(step, "action") — after the prelude, which
    // for a deliverable command is the core's own.
    match string(members, "action").map_err(before_open)?.as_str() {
        "send_text" => {
            // sendText: rejectUnknown -> [requireOpen] -> text ->
            // [requirePayloadLimit] -> frames.
            reject_unknown(members, &["action", "kind", "text"], "send_text action")
                .map_err(before_open)?;
            let text = string(members, "text").map_err(after_open("send_text"))?;
            Ok(ParsedAction::SendText { text })
        }
        "send_binary" => {
            // sendBinary: rejectUnknown -> [requireOpen] -> base64 ->
            // [requirePayloadLimit] -> frames.
            reject_unknown(
                members,
                &["action", "data_base64", "kind"],
                "send_binary action",
            )
            .map_err(before_open)?;
            let data = base64_field(members, "data_base64").map_err(after_open("send_binary"))?;
            Ok(ParsedAction::SendBinary { data })
        }
        "send_ping" => {
            // sendControl: rejectUnknown -> [requireOpen] -> base64 ->
            // frame validity; no payload-limit check (Java applies none to
            // control frames).
            reject_unknown(
                members,
                &["action", "data_base64", "kind"],
                "send_ping action",
            )
            .map_err(before_open)?;
            let data = base64_field(members, "data_base64").map_err(after_open("send_ping"))?;
            Ok(ParsedAction::SendPing { data })
        }
        "send_pong" => {
            reject_unknown(
                members,
                &["action", "data_base64", "kind"],
                "send_pong action",
            )
            .map_err(before_open)?;
            let data = base64_field(members, "data_base64").map_err(after_open("send_pong"))?;
            Ok(ParsedAction::SendPong { data })
        }
        "send_close" => {
            // sendClose: rejectUnknown -> [requireOpen] -> code -> reason
            // -> frame effects.
            reject_unknown(
                members,
                &["action", "code", "kind", "reason"],
                "send_close action",
            )
            .map_err(before_open)?;
            let code = integer(members, "code").map_err(after_open("send_close"))?;
            let reason = string(members, "reason").map_err(after_open("send_close"))?;
            Ok(ParsedAction::SendClose { code, reason })
        }
        "send_fragment" => {
            // sendFragment: rejectUnknown -> [requireOpen] -> opcode (full
            // Opcode vocabulary first, then the text/binary restriction —
            // two distinct INVALID_ENUM details) -> base64 ->
            // [requirePayloadLimit] -> fin -> frames.
            reject_unknown(
                members,
                &["action", "data_base64", "fin", "kind", "opcode"],
                "send_fragment action",
            )
            .map_err(before_open)?;
            let opcode = fragment_opcode(members).map_err(after_open("send_fragment"))?;
            let data = base64_field(members, "data_base64").map_err(after_open("send_fragment"))?;
            // Java's `Execution.requirePayloadLimit` sits BETWEEN the data
            // and fin reads. A deliverable command meets the identical
            // limit at the identical post-requireOpen position inside the
            // core, so the driver defers it; only when `fin` cannot be
            // read does the limit become a DRIVER failure, keeping Java's
            // read order observable (BUFFER_LIMIT_EXCEEDED wins over the
            // fin error).
            let fin = match boolean(members, "fin") {
                Ok(fin) => fin,
                Err(fin_error) => {
                    let failure = if data.len() as i64 > limits.max_buffered_bytes {
                        ProtocolError::new(
                            "BUFFER_LIMIT_EXCEEDED",
                            "action payload exceeds max_buffered_bytes",
                        )
                    } else {
                        fin_error
                    };
                    return Err(after_open("send_fragment")(failure));
                }
            };
            Ok(ParsedAction::SendFragment { opcode, data, fin })
        }
        "eof" => {
            // eof: rejectUnknown -> state effects (core).
            reject_unknown(members, &["action", "kind"], "eof action").map_err(before_open)?;
            Ok(ParsedAction::Eof)
        }
        _ => Err(before_open(ProtocolError::new(
            "INVALID_ENUM",
            "action has unsupported value",
        ))),
    }
}

/// Hands one deliverable command to the session. From here every gate is
/// the core's own (see [`parse_action`]).
fn deliver(
    session: &mut dyn ScenarioSession,
    command: ParsedAction,
    step: u32,
) -> Result<(), ScenarioFailure> {
    match command {
        ParsedAction::SendText { text } => session.send_text(&text, step),
        ParsedAction::SendBinary { data } => session.send_binary(&data, step),
        ParsedAction::SendPing { data } => session.send_ping(&data, step),
        ParsedAction::SendPong { data } => session.send_pong(&data, step),
        ParsedAction::SendClose { code, reason } => session.send_close(code, &reason, step),
        ParsedAction::SendFragment { opcode, data, fin } => {
            session.send_fragment(opcode, &data, fin, step)
        }
        ParsedAction::Eof => session.eof(step),
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

/// Truthful placeholder implementation from the pre-merge round: session
/// construction always fails with the honest `CORE_NOT_WIRED` detail
/// (before any step is examined, mirroring Java's runtime-unavailable
/// construction path). Kept for tests and as the pinned historical envelope
/// shape; [`WiredCore`] is the active implementation.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnwiredCore;

/// The honest unwired detail, kept stable so transcripts are byte-identical
/// across reruns.
pub const UNWIRED_DETAIL: &str = "ws_core ConnectionCore API not yet landed \
     (US-009 lane A); harness truthfully reports no behavior instead of \
     fabricating it";

/// The non-oracle construction-failure code of the unwired stub.
pub const NOT_WIRED_CODE: &str = "CORE_NOT_WIRED";

impl CandidateCore for UnwiredCore {
    fn begin(
        &mut self,
        _request: &OracleRequest,
    ) -> Result<Box<dyn ScenarioSession>, ScenarioFailure> {
        Err(ScenarioFailure {
            code: NOT_WIRED_CODE.to_string(),
            close_code: None,
            detail: UNWIRED_DETAIL.to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// The wired implementation: the real ws_core ConnectionCore behind the
// ScenarioSession seam.
// ---------------------------------------------------------------------------

/// The honest non-oracle failure code for behavior the `ws_core` skeleton
/// deliberately refuses ([`ws_core::error::FailureCode::Unimplemented`],
/// which carries NO oracle wire code by design). Shaped exactly like
/// [`NOT_WIRED_CODE`] was: an adapter-vocabulary code the evaluator can
/// never mistake for Java behavior, so the protocol-stub gate keeps failing
/// until the owning stories (US-010..US-016) land.
pub const UNIMPLEMENTED_CODE: &str = "CORE_BEHAVIOR_UNIMPLEMENTED";

/// The stable detail carried with [`UNIMPLEMENTED_CODE`] envelopes, kept
/// constant so reruns are byte-identical.
pub const UNIMPLEMENTED_DETAIL: &str = "ws_core refused this input honestly: its protocol \
     behavior belongs to a later story (US-010/US-011 handshake, US-012..US-016 framing, \
     messages, control, close); the harness reports the non-oracle refusal instead of \
     fabricating Java behavior";

/// The honest non-oracle failure code for a bounded-queue refusal that
/// survives a full drain-and-retry. Per the core contract, backpressure is
/// non-fatal (nothing consumed; drain and retry the identical input) and a
/// correct owner drains eagerly — this session drains after EVERY input, so
/// this code is unreachable unless the per-input event bound outgrows the
/// configured queue capacity (a contract bug that must fail the corpus, not
/// wear an oracle code).
pub const BACKPRESSURE_CODE: &str = "CORE_BACKPRESSURE_UNDRAINED";

/// The active, wired candidate: constructs one real
/// [`ws_core::connection::ConnectionCore`] per scenario in the corpus
/// `initial_state` (the `new_in_state` oracle-harness seam) with the
/// scenario's role and limits.
#[derive(Clone, Copy, Debug, Default)]
pub struct WiredCore;

impl CandidateCore for WiredCore {
    fn begin(
        &mut self,
        request: &OracleRequest,
    ) -> Result<Box<dyn ScenarioSession>, ScenarioFailure> {
        let config = scenario_config(&request.limits).map_err(|error| ScenarioFailure {
            code: "CORE_CONFIG_REJECTED".to_string(),
            close_code: None,
            detail: format!(
                "ws_core rejected the envelope-validated configuration ({error}); \
                 unreachable for a corpus request (the oracle ceilings and the \
                 ws_core limit table coincide — see the boundary test) and \
                 reported truthfully rather than fabricated"
            ),
        })?;
        let core = ws_core::ConnectionCore::new_in_state(
            config,
            wired_role(request.role),
            wired_initial_state(request.initial_state),
        );
        Ok(Box::new(WiredSession {
            core,
            pending_action: false,
            initial: request.initial_state.connection_state(),
            events: Vec::new(),
            frames: Vec::new(),
            transitions: Vec::new(),
        }))
    }
}

/// Maps the corpus `limits` object onto the 13-field
/// [`ws_core::config::ConnectionConfigBuilder`]:
///
/// - `max_buffered_bytes` feeds THREE fields — `max_buffered_bytes` itself
///   plus `max_frame_payload_bytes` and `max_message_bytes` — mirroring the
///   oracle adapter, which hands the corpus value to Java-WebSocket as its
///   single maximum frame/message size ("Java-WebSocket receives
///   max_buffered_bytes as its maximum frame/message size",
///   java-oracle/README.md; `LimitField::MaxFramePayloadBytes` docs);
/// - `max_input_bytes` / `max_actions` / `max_frames` / `max_output_bytes`
///   map 1:1;
/// - the handshake caps keep their deterministic defaults (the behavior
///   corpora begin post-handshake and never exercise them; enforcement is
///   US-010/US-011);
/// - the queue capacities keep their port-side defaults (this session
///   drains both queues after every input, and the default capacity 64
///   covers the skeleton's 2-slot per-input bound with headroom);
/// - `mask_key_seed` keeps its deterministic default (quirk Q28: mask keys
///   are never observable, so any deterministic source scores identically).
fn scenario_config(
    limits: &Limits,
) -> Result<ws_core::ConnectionConfig, ws_core::config::ConfigError> {
    // Envelope validation already bounded every limit to the oracle
    // ceilings, all non-negative; a negative value cannot reach here, and 0
    // would fail the builder's own minimum check (fail closed).
    let unsigned = |value: i64| u64::try_from(value).unwrap_or(0);
    ws_core::ConnectionConfig::builder()
        .max_frame_payload_bytes(unsigned(limits.max_buffered_bytes))
        .max_message_bytes(unsigned(limits.max_buffered_bytes))
        .max_buffered_bytes(unsigned(limits.max_buffered_bytes))
        .max_input_bytes(unsigned(limits.max_input_bytes))
        .max_actions(unsigned(limits.max_actions))
        .max_frames(unsigned(limits.max_frames))
        .max_output_bytes(unsigned(limits.max_output_bytes))
        .build()
}

/// One live scenario against the real core. The session owns NO protocol
/// state: every count, state, limit, and protocol effect is read from (or
/// produced by) the [`ws_core::ConnectionCore`] it drives; the vectors below
/// only accumulate the core's drained observation events in transcript
/// vocabulary.
struct WiredSession {
    core: ws_core::ConnectionCore,
    /// Seam bookkeeping, NOT protocol state: Java increments `actionCount`
    /// inside `Execution.action` BEFORE the action's fields are read, so an
    /// action step whose command can NEVER reach the core (a malformed or
    /// unrepresentable step — the only path on which the driver-gate
    /// mirrors run, re-review round 1) is still counted in Java's failure
    /// envelope even though the core never saw an input. This flag records
    /// exactly that one counted-but-undeliverable action;
    /// [`WiredSession::snapshot`] adds it to the core's own counts as
    /// Java's partial-execution counts do. Every failure on this path is
    /// fatal, so the one-step gap can never accumulate. A DELIVERED
    /// command is counted by the core itself at receipt and never touches
    /// this flag.
    pending_action: bool,
    /// The scenario's declared initial state, kept as the projection
    /// fallback for [`ws_core::connection::ReadyState::NotYetConnected`]
    /// (unreachable by construction: this session is built via
    /// `new_in_state` in a corpus state and no post-handshake path
    /// re-enters `NotYetConnected`).
    initial: ConnectionState,
    events: Vec<crate::observe::SemanticEvent>,
    frames: Vec<crate::observe::FrameRecord>,
    transitions: Vec<crate::observe::Transition>,
}

impl WiredSession {
    /// Feeds one input to the core, honoring the documented backpressure
    /// contract: a non-fatal refusal consumed nothing, so drain both queues
    /// and retry the identical input once. The session drains after every
    /// input, so a second refusal means the per-input event bound exceeds
    /// the total queue capacity — reported as the honest non-oracle
    /// [`BACKPRESSURE_CODE`].
    fn submit(&mut self, input: ws_core::Input<'_>) -> Result<(), ScenarioFailure> {
        let mut result = self.core.handle(input.clone());
        if matches!(&result, Err(failure) if !failure.code.is_fatal()) {
            self.drain();
            result = self.core.handle(input);
        }
        self.drain();
        result.map_err(|failure| map_core_failure(&failure))
    }

    /// Routes one action command to the core. The core's own accounting is
    /// authoritative from here; clearing the pending flag is defensive
    /// symmetry for callers outside `drive_scenario` (the driver never
    /// sets it on the delivered path).
    fn command(&mut self, command: ws_core::LocalCommand) -> Result<(), ScenarioFailure> {
        self.pending_action = false;
        self.submit(ws_core::Input::Command(command))
    }

    /// Drains both bounded queues into the transcript projection. Transport
    /// writes are drained but not recorded: the transcript has no raw-wire
    /// stream — the observable form of every outbound frame is the
    /// `frames[]`/`events[]` projection the core emits alongside the write
    /// (the US-009 skeleton emits no writes at all; outbound framing is
    /// US-012+).
    fn drain(&mut self) {
        while self.core.next_write().is_some() {}
        while let Some(event) = self.core.next_event() {
            self.record(event);
        }
    }

    /// Projects one drained core event into the transcript vocabulary
    /// (mechanical 1:1 rendering; no protocol decisions).
    fn record(&mut self, event: ws_core::SemanticEvent) {
        use crate::observe::SemanticEventKind as Out;
        use ws_core::SemanticEventKind as In;
        let step = clamp_step(event.step);
        let kind = match event.kind {
            In::InputChunk { bytes } => Out::InputChunk {
                bytes: clamp_count(bytes),
            },
            In::Text { text } => Out::Text { text },
            In::Binary { data } => Out::Binary { data },
            In::Ping { data } => Out::Ping { data },
            In::Pong { data } => Out::Pong { data },
            In::Close(detail) => Out::Close(observed_close(&detail)),
            In::CloseInitiated(detail) => Out::CloseInitiated(observed_close(&detail)),
            In::Eof(detail) => Out::Eof(observed_close(&detail)),
            In::OutboundCause { cause, opcode } => Out::OutboundCause {
                cause: observed_outbound_cause(cause),
                opcode: observed_opcode(opcode),
            },
            In::FrameObserved(frame) => {
                self.frames.push(observed_frame(&frame));
                return;
            }
            In::Transition { from, to, cause } => {
                self.transitions.push(crate::observe::Transition {
                    from: self.observed_state(from),
                    to: self.observed_state(to),
                    cause: observed_transition_cause(cause),
                    step,
                });
                return;
            }
        };
        self.events
            .push(crate::observe::SemanticEvent { step, kind });
    }

    /// Projects the core's [`ws_core::ReadyState`] onto the corpus
    /// post-handshake vocabulary. `NotYetConnected` has no corpus
    /// projection and is unreachable here (see [`WiredSession::initial`]);
    /// the fallback reports where the scenario began rather than inventing
    /// vocabulary the corpus does not have.
    fn observed_state(&self, state: ws_core::ReadyState) -> ConnectionState {
        match state {
            ws_core::ReadyState::Open => ConnectionState::Open,
            ws_core::ReadyState::Closing => ConnectionState::Closing,
            ws_core::ReadyState::Closed => ConnectionState::Closed,
            ws_core::ReadyState::NotYetConnected => self.initial,
        }
    }
}

impl ScenarioSession for WiredSession {
    fn bytes(&mut self, data: &[u8], _step: u32) -> Result<(), ScenarioFailure> {
        self.submit(ws_core::Input::TransportBytes(data))
    }

    /// Java's `Execution.action` prelude (actionCount++/max_actions) for a
    /// step the core will NEVER see — `drive_scenario` calls this only on
    /// the driver-failure path of a malformed or unrepresentable step
    /// (re-review round 1: a deliverable command reaches the core's own
    /// identical prelude at command receipt instead). The comparison is a
    /// pure read of the core's live count and config, never adapter-held
    /// state, and [`WiredSession::pending_action`] carries the
    /// counted-but-undeliverable action into the failure counts exactly as
    /// Java's partial-execution counts do.
    fn begin_action(&mut self, _step: u32) -> Result<(), ScenarioFailure> {
        self.pending_action = true;
        let next = self.core.counts().actions.saturating_add(1);
        if next > self.core.config().max_actions() {
            return Err(map_core_failure(&ws_core::TypedProtocolFailure::protocol(
                ws_core::FailureCode::ActionLimitExceeded,
            )));
        }
        Ok(())
    }

    /// Java's `Execution.requireOpen` for a step the core will NEVER see:
    /// a pure read of the core's live state (quirk Q26 / derive.go
    /// requireOpen). A deliverable command is state-gated by the core
    /// itself (connection.rs `handle_command`); this mirror exists solely
    /// so a step whose payload field cannot be read (or represented) in a
    /// non-open state reports STATE_VIOLATION in Java's
    /// requireOpen-before-field-read order — input-shaping, not protocol
    /// behavior (re-review round 1).
    fn require_open(&mut self, _action: &str) -> Result<(), ScenarioFailure> {
        if self.core.state() != ws_core::ReadyState::Open {
            return Err(map_core_failure(&ws_core::TypedProtocolFailure::protocol(
                ws_core::FailureCode::StateViolation,
            )));
        }
        Ok(())
    }

    fn send_text(&mut self, text: &str, _step: u32) -> Result<(), ScenarioFailure> {
        self.command(ws_core::LocalCommand::SendText {
            text: text.to_string(),
        })
    }

    fn send_binary(&mut self, data: &[u8], _step: u32) -> Result<(), ScenarioFailure> {
        self.command(ws_core::LocalCommand::SendBinary {
            data: data.to_vec(),
        })
    }

    fn send_ping(&mut self, data: &[u8], _step: u32) -> Result<(), ScenarioFailure> {
        self.command(ws_core::LocalCommand::SendPing {
            data: data.to_vec(),
        })
    }

    fn send_pong(&mut self, data: &[u8], _step: u32) -> Result<(), ScenarioFailure> {
        self.command(ws_core::LocalCommand::SendPong {
            data: data.to_vec(),
        })
    }

    fn send_close(&mut self, code: i64, reason: &str, step: u32) -> Result<(), ScenarioFailure> {
        // The core's command vocabulary carries close codes as u16 (US-016
        // wires the Q13/Q14 close-code model). A corpus code outside u16
        // cannot be represented as a core input, so the step joins the
        // driver-failure path: the seam re-establishes Java's gate order
        // itself (the action prelude, then requireOpen — Java reads `code`
        // only after both) and then answers the same honest non-oracle
        // refusal the core gives every representable send_close this
        // round. US-016 must revisit this seam alongside the close
        // stories.
        let Ok(code) = u16::try_from(code) else {
            self.begin_action(step)?;
            self.require_open("send_close")?;
            return Err(ScenarioFailure {
                code: UNIMPLEMENTED_CODE.to_string(),
                close_code: None,
                detail: UNIMPLEMENTED_DETAIL.to_string(),
            });
        };
        self.command(ws_core::LocalCommand::SendClose {
            code,
            reason: reason.to_string(),
        })
    }

    fn send_fragment(
        &mut self,
        opcode: DataOpcode,
        data: &[u8],
        fin: bool,
        _step: u32,
    ) -> Result<(), ScenarioFailure> {
        self.command(ws_core::LocalCommand::SendFragment {
            opcode: wired_opcode(opcode),
            data: data.to_vec(),
            fin,
        })
    }

    fn eof(&mut self, _step: u32) -> Result<(), ScenarioFailure> {
        // `eof` participates in action accounting inside the core's
        // TransportEof path (derive.go actionStep), so the pending gap
        // closes exactly as for commands.
        self.pending_action = false;
        self.submit(ws_core::Input::TransportEof)
    }

    fn snapshot(&self) -> CountsWithState {
        let mut counts = observed_counts(&self.core.counts());
        if self.pending_action {
            // The counted-but-never-delivered action of a fatal mid-action
            // failure (see the field docs).
            counts.actions = counts.actions.saturating_add(1);
        }
        CountsWithState {
            counts,
            final_state: self.observed_state(self.core.state()),
        }
    }

    fn finish(self: Box<Self>) -> Observations {
        let counts = self.snapshot();
        let close = self.core.close_detail().map(observed_close);
        Observations {
            events: self.events,
            frames: self.frames,
            transitions: self.transitions,
            close,
            counts,
        }
    }
}

/// Maps one typed core failure onto the transcript failure vocabulary:
/// oracle-coded failures pass through verbatim (code + close code); the two
/// deliberately non-oracle codes become the honest adapter-vocabulary
/// envelopes ([`UNIMPLEMENTED_CODE`], [`BACKPRESSURE_CODE`]) that the
/// evaluator can never score as Java behavior.
fn map_core_failure(failure: &ws_core::TypedProtocolFailure) -> ScenarioFailure {
    if let Some(wire) = failure.code.wire_code() {
        return ScenarioFailure {
            code: wire.to_string(),
            close_code: failure.close_code.map(i64::from),
            detail: format!("ws_core reported {failure}"),
        };
    }
    match failure.code {
        ws_core::FailureCode::Unimplemented => ScenarioFailure {
            code: UNIMPLEMENTED_CODE.to_string(),
            close_code: None,
            detail: UNIMPLEMENTED_DETAIL.to_string(),
        },
        // Backpressure is the only other wireless code; reachable solely
        // through the exhausted retry in `WiredSession::submit`.
        _ => ScenarioFailure {
            code: BACKPRESSURE_CODE.to_string(),
            close_code: None,
            detail: "ws_core refused the input with backpressure even after a full \
                     drain-and-retry; the per-input event bound exceeds the configured \
                     queue capacity (core contract bug, reported honestly)"
                .to_string(),
        },
    }
}

fn wired_role(role: crate::request::Role) -> ws_core::Role {
    match role {
        crate::request::Role::Client => ws_core::Role::Client,
        crate::request::Role::Server => ws_core::Role::Server,
    }
}

fn wired_initial_state(state: crate::request::InitialState) -> ws_core::InitialState {
    match state {
        crate::request::InitialState::Open => ws_core::InitialState::Open,
        crate::request::InitialState::Closing => ws_core::InitialState::Closing,
        crate::request::InitialState::Closed => ws_core::InitialState::Closed,
    }
}

fn wired_opcode(opcode: DataOpcode) -> ws_core::connection::DataOpcode {
    match opcode {
        DataOpcode::Text => ws_core::connection::DataOpcode::Text,
        DataOpcode::Binary => ws_core::connection::DataOpcode::Binary,
    }
}

fn observed_close(detail: &ws_core::CloseDetail) -> crate::observe::CloseDetail {
    crate::observe::CloseDetail {
        code: i64::from(detail.code),
        reason: detail.reason.clone(),
        origin: match detail.origin {
            ws_core::close::CloseOrigin::Remote => crate::observe::CloseOrigin::Remote,
            ws_core::close::CloseOrigin::Local => crate::observe::CloseOrigin::Local,
            ws_core::close::CloseOrigin::Transport => crate::observe::CloseOrigin::Transport,
        },
        remote: detail.remote,
        handshake_complete: detail.handshake_complete,
    }
}

fn observed_opcode(opcode: ws_core::framing::Opcode) -> crate::observe::Opcode {
    match opcode {
        ws_core::framing::Opcode::Continuous => crate::observe::Opcode::Continuous,
        ws_core::framing::Opcode::Text => crate::observe::Opcode::Text,
        ws_core::framing::Opcode::Binary => crate::observe::Opcode::Binary,
        ws_core::framing::Opcode::Closing => crate::observe::Opcode::Closing,
        ws_core::framing::Opcode::Ping => crate::observe::Opcode::Ping,
        ws_core::framing::Opcode::Pong => crate::observe::Opcode::Pong,
    }
}

fn observed_outbound_cause(cause: ws_core::event::OutboundCause) -> crate::observe::OutboundCause {
    use ws_core::event::OutboundCause as In;
    match cause {
        In::SendText => crate::observe::OutboundCause::SendText,
        In::SendBinary => crate::observe::OutboundCause::SendBinary,
        In::SendPing => crate::observe::OutboundCause::SendPing,
        In::SendPong => crate::observe::OutboundCause::SendPong,
        In::SendClose => crate::observe::OutboundCause::SendClose,
        In::SendFragment => crate::observe::OutboundCause::SendFragment,
        In::EchoClose => crate::observe::OutboundCause::EchoClose,
    }
}

fn observed_transition_cause(
    cause: ws_core::event::TransitionCause,
) -> crate::observe::TransitionCause {
    match cause {
        ws_core::event::TransitionCause::SendClose => crate::observe::TransitionCause::SendClose,
        ws_core::event::TransitionCause::ReceiveClose => {
            crate::observe::TransitionCause::ReceiveClose
        }
        ws_core::event::TransitionCause::Eof => crate::observe::TransitionCause::Eof,
    }
}

fn observed_frame(frame: &ws_core::event::FrameRecord) -> crate::observe::FrameRecord {
    crate::observe::FrameRecord {
        direction: match frame.direction {
            ws_core::event::Direction::Inbound => crate::observe::Direction::Inbound,
            ws_core::event::Direction::Outbound => crate::observe::Direction::Outbound,
        },
        fin: frame.fin,
        masked: frame.masked,
        opcode: observed_opcode(frame.opcode),
        payload: frame.payload.clone(),
        rsv1: frame.rsv1,
        rsv2: frame.rsv2,
        rsv3: frame.rsv3,
        step: clamp_step(frame.step),
        wire_bytes: clamp_count(frame.wire_bytes),
    }
}

fn observed_counts(counts: &ws_core::Counts) -> Counts {
    Counts {
        actions: clamp_count(counts.actions),
        buffered_bytes: clamp_count(counts.buffered_bytes),
        consumed_bytes: clamp_count(counts.consumed_bytes),
        frames: clamp_count(counts.frames),
        input_bytes: clamp_count(counts.input_bytes),
        message_buffered_bytes: clamp_count(counts.message_buffered_bytes),
        wire_buffered_bytes: clamp_count(counts.wire_buffered_bytes),
    }
}

/// Core step indices are `u64`; the transcript vocabulary carries `u32`
/// (clamped like the driver's own index conversion — unreachable for any
/// corpus scenario, whose step count is bounded by the JSON container
/// limits).
fn clamp_step(step: u64) -> u32 {
    u32::try_from(step).unwrap_or(u32::MAX)
}

/// Core counters are `u64`; the transcript vocabulary carries `i64`. Every
/// counter is bounded by the oracle ceilings (≤ 4 MiB), so the clamp is
/// unreachable and exists only to keep the conversion checked.
fn clamp_count(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Returns the active core implementation: the wired [`WiredCore`] (both
/// US-009 lanes merged on this branch). [`UnwiredCore`] remains available
/// for tests and as the pinned pre-merge envelope shape.
pub fn active_core() -> impl CandidateCore {
    WiredCore
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
    /// calls, so the driver's contract is pinned by tests: deliverable
    /// commands arrive as send/eof hooks (which count actions at receipt,
    /// mirroring the core's own accounting), while the driver-gate hooks
    /// (`begin_action`, `require_open`) fire only for steps that can never
    /// be delivered. Deliberately permissive: sends succeed in any state,
    /// so a recorded send hook proves the driver did not pre-gate.
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

        /// The core-side action accounting every delivered command (and
        /// EOF) runs at receipt: count first, then the limit check.
        fn count_action(&mut self) -> Result<(), ScenarioFailure> {
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
    }

    impl ScenarioSession for ScriptedSession {
        fn bytes(&mut self, data: &[u8], _step: u32) -> Result<(), ScenarioFailure> {
            self.log(format!("bytes({})", data.len()));
            self.input_bytes += data.len() as i64;
            Ok(())
        }
        fn begin_action(&mut self, _step: u32) -> Result<(), ScenarioFailure> {
            self.log("begin_action");
            self.count_action()
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
            self.count_action()
        }
        fn send_binary(&mut self, _data: &[u8], _step: u32) -> Result<(), ScenarioFailure> {
            self.log("send_binary");
            self.count_action()
        }
        fn send_ping(&mut self, _data: &[u8], _step: u32) -> Result<(), ScenarioFailure> {
            self.log("send_ping");
            self.count_action()
        }
        fn send_pong(&mut self, _data: &[u8], _step: u32) -> Result<(), ScenarioFailure> {
            self.log("send_pong");
            self.count_action()
        }
        fn send_close(
            &mut self,
            _code: i64,
            _reason: &str,
            _step: u32,
        ) -> Result<(), ScenarioFailure> {
            self.log("send_close");
            self.count_action()
        }
        fn send_fragment(
            &mut self,
            _opcode: DataOpcode,
            _data: &[u8],
            _fin: bool,
            _step: u32,
        ) -> Result<(), ScenarioFailure> {
            self.log("send_fragment");
            self.count_action()
        }
        fn eof(&mut self, _step: u32) -> Result<(), ScenarioFailure> {
            self.log("eof");
            self.count_action()
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
        fn begin(
            &mut self,
            _request: &OracleRequest,
        ) -> Result<Box<dyn ScenarioSession>, ScenarioFailure> {
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
            ScenarioOutcome::ConstructionFailed {
                failure: ScenarioFailure {
                    code: NOT_WIRED_CODE.to_string(),
                    close_code: None,
                    detail: UNWIRED_DETAIL.to_string(),
                }
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

    /// The full hook order for a healthy mixed scenario: every deliverable
    /// step goes straight to its delivery hook — NO driver gate fires on
    /// the delivered path (Java's interleaved gates are the core's own
    /// there; re-review round 1).
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
                "send_text".to_string(),
                "eof".to_string(),
            ]
        );
    }

    /// The driver-gate hook order for an UNDELIVERABLE step re-establishes
    /// Java's sequence: the `Execution.action` prelude, then requireOpen
    /// (the failed read sits past it), then the parse failure — and no
    /// delivery hook ever fires.
    #[test]
    fn driver_gate_hooks_fire_only_for_undeliverable_steps() {
        let request = request_with_steps("[{\"action\":\"send_text\",\"kind\":\"action\"}]");
        let mut core = scripted(true, 64);
        let calls = core.calls.clone();
        let (code, counts) = failure_code(drive_scenario(&request, &mut core));
        assert_eq!(code, "MISSING_FIELD");
        assert_eq!(counts.actions, 1, "the prelude counted the action");
        assert_eq!(
            *calls.borrow(),
            vec![
                "begin_action".to_string(),
                "require_open(send_text)".to_string(),
            ]
        );
    }

    /// Re-review round 1: a constructible command is ALWAYS delivered —
    /// even in a non-open state the driver adds no pre-delivery gate; the
    /// state refusal is the session's (i.e. the core's) own behavior. The
    /// deliberately permissive scripted double accepts the delivered
    /// command, proving no driver gate intervened.
    #[test]
    fn driver_delivers_constructible_commands_without_pre_gating() {
        let request =
            request_with_steps("[{\"action\":\"send_text\",\"kind\":\"action\",\"text\":\"hi\"}]");
        let mut core = scripted(false, 64);
        let calls = core.calls.clone();
        let outcome = drive_scenario(&request, &mut core);
        assert!(
            matches!(outcome, ScenarioOutcome::Completed(_)),
            "the permissive scripted session accepted the delivered \
             command, got {outcome:?}"
        );
        assert_eq!(*calls.borrow(), vec!["send_text".to_string()]);
    }

    // -- WiredCore: the real ws_core ConnectionCore behind the seam --------

    /// A delegating wrapper around the real [`WiredSession`] that records
    /// which driver hooks fire, so tests can prove WHERE a failure
    /// originated: a hook trace of `["send_text"]` means the command was
    /// delivered and every gate that fired was the core's own; a trace
    /// containing `begin_action`/`require_open` means the driver supplied
    /// gate shaping.
    struct RecordingSession {
        inner: Box<dyn ScenarioSession>,
        calls: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
    }

    impl RecordingSession {
        fn log(&self, call: impl Into<String>) {
            self.calls.borrow_mut().push(call.into());
        }
    }

    impl ScenarioSession for RecordingSession {
        fn bytes(&mut self, data: &[u8], step: u32) -> Result<(), ScenarioFailure> {
            self.log(format!("bytes({})", data.len()));
            self.inner.bytes(data, step)
        }
        fn begin_action(&mut self, step: u32) -> Result<(), ScenarioFailure> {
            self.log("begin_action");
            self.inner.begin_action(step)
        }
        fn require_open(&mut self, action: &str) -> Result<(), ScenarioFailure> {
            self.log(format!("require_open({action})"));
            self.inner.require_open(action)
        }
        fn send_text(&mut self, text: &str, step: u32) -> Result<(), ScenarioFailure> {
            self.log("send_text");
            self.inner.send_text(text, step)
        }
        fn send_binary(&mut self, data: &[u8], step: u32) -> Result<(), ScenarioFailure> {
            self.log("send_binary");
            self.inner.send_binary(data, step)
        }
        fn send_ping(&mut self, data: &[u8], step: u32) -> Result<(), ScenarioFailure> {
            self.log("send_ping");
            self.inner.send_ping(data, step)
        }
        fn send_pong(&mut self, data: &[u8], step: u32) -> Result<(), ScenarioFailure> {
            self.log("send_pong");
            self.inner.send_pong(data, step)
        }
        fn send_close(
            &mut self,
            code: i64,
            reason: &str,
            step: u32,
        ) -> Result<(), ScenarioFailure> {
            self.log("send_close");
            self.inner.send_close(code, reason, step)
        }
        fn send_fragment(
            &mut self,
            opcode: DataOpcode,
            data: &[u8],
            fin: bool,
            step: u32,
        ) -> Result<(), ScenarioFailure> {
            self.log("send_fragment");
            self.inner.send_fragment(opcode, data, fin, step)
        }
        fn eof(&mut self, step: u32) -> Result<(), ScenarioFailure> {
            self.log("eof");
            self.inner.eof(step)
        }
        fn snapshot(&self) -> CountsWithState {
            self.inner.snapshot()
        }
        fn finish(self: Box<Self>) -> Observations {
            self.inner.finish()
        }
    }

    /// [`WiredCore`] with every session hook recorded (see
    /// [`RecordingSession`]).
    struct RecordingWiredCore {
        calls: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
    }

    impl CandidateCore for RecordingWiredCore {
        fn begin(
            &mut self,
            request: &OracleRequest,
        ) -> Result<Box<dyn ScenarioSession>, ScenarioFailure> {
            let inner = WiredCore.begin(request)?;
            Ok(Box::new(RecordingSession {
                inner,
                calls: self.calls.clone(),
            }))
        }
    }

    /// Rebuilds `PUB_0000` with envelope patches (e.g. `initial_state`,
    /// `limits`) plus a raw `steps` array, re-signing the digest.
    fn wired_request(patch: &[(&str, &str)], steps_json: &str) -> OracleRequest {
        let Value::Obj(mut map) = crate::json::parse(PUB_0000).unwrap() else {
            unreachable!()
        };
        for (key, value_json) in patch {
            map.insert(
                (*key).to_string(),
                crate::json::parse(value_json).expect("patch fixture parses"),
            );
        }
        map.insert(
            "steps".to_string(),
            crate::json::parse(steps_json).expect("steps fixture parses"),
        );
        let digest = crate::request::canonical_request_digest(&map);
        map.insert("request_digest".to_string(), Value::Str(digest));
        parse_request(&Value::Obj(map).canonical()).expect("envelope verifies")
    }

    fn wired_outcome(request: &OracleRequest) -> ScenarioOutcome {
        drive_scenario(request, &mut WiredCore)
    }

    /// The corpus limits map onto the 13-field builder exactly as the
    /// oracle adapter maps them onto Java-WebSocket: `max_buffered_bytes`
    /// feeds the frame/message/buffer trio, the four other corpus limits
    /// map 1:1, and the handshake/queue fields keep their deterministic
    /// defaults.
    #[test]
    fn wired_config_maps_corpus_limits_onto_the_thirteen_field_builder() {
        let request = parse_request(PUB_0000).unwrap();
        let config = scenario_config(&request.limits).expect("corpus limits build");
        assert_eq!(config.max_frame_payload_bytes(), 65_536);
        assert_eq!(config.max_message_bytes(), 65_536);
        assert_eq!(config.max_buffered_bytes(), 65_536);
        assert_eq!(config.max_input_bytes(), 65_536);
        assert_eq!(config.max_actions(), 64);
        assert_eq!(config.max_frames(), 64);
        assert_eq!(config.max_output_bytes(), 4_194_304);
        // Handshake caps: deterministic defaults (US-010/US-011 behavior;
        // the behavior corpora never exercise them).
        assert_eq!(config.max_handshake_bytes(), 4096);
        assert_eq!(config.max_header_count(), 32);
        assert_eq!(config.max_header_line_bytes(), 512);
        // Queue capacities: port-side defaults, drained after every input.
        assert_eq!(config.event_queue_capacity(), 64);
        assert_eq!(config.command_queue_capacity(), 64);
        assert_eq!(config.write_queue_capacity(), 64);
        assert_eq!(config.mask_key_seed(), 0);
    }

    /// Every envelope-legal limit extreme builds: the oracle hard ceilings
    /// and schema minima coincide with the ws_core limit table, so the
    /// `CORE_CONFIG_REJECTED` construction path is unreachable for a
    /// validated request.
    #[test]
    fn wired_config_accepts_the_full_envelope_legal_limit_range() {
        let minima = Limits {
            max_input_bytes: 1,
            max_buffered_bytes: 1,
            max_actions: 0,
            max_frames: 1,
            max_output_bytes: 512,
        };
        scenario_config(&minima).expect("schema minima build");
        let ceilings = Limits {
            max_input_bytes: crate::request::HARD_INPUT_BYTES,
            max_buffered_bytes: crate::request::HARD_BUFFERED_BYTES,
            max_actions: crate::request::HARD_ACTIONS,
            max_frames: crate::request::HARD_FRAMES,
            max_output_bytes: crate::request::HARD_OUTPUT_BYTES,
        };
        scenario_config(&ceilings).expect("oracle hard ceilings build");
    }

    /// GOLDEN (quirk Q20 / derive.go `eof`): an `eof` action in OPEN
    /// completes with the pinned 1006 transport close, the `eof` event, the
    /// open->closed transition, and `actions == 1` — real core, end to end.
    #[test]
    fn wired_eof_scenario_completes_with_java_q20_vocabulary() {
        let request = request_with_steps("[{\"action\":\"eof\",\"kind\":\"action\"}]");
        let ScenarioOutcome::Completed(observations) = wired_outcome(&request) else {
            panic!("eof scenario must complete");
        };
        let close = crate::observe::CloseDetail {
            code: 1006,
            reason: "transport EOF before close handshake completed".to_string(),
            origin: crate::observe::CloseOrigin::Transport,
            remote: false,
            handshake_complete: false,
        };
        assert_eq!(
            observations.events,
            vec![crate::observe::SemanticEvent {
                step: 0,
                kind: crate::observe::SemanticEventKind::Eof(close.clone()),
            }]
        );
        assert_eq!(
            observations.transitions,
            vec![crate::observe::Transition {
                from: ConnectionState::Open,
                to: ConnectionState::Closed,
                cause: crate::observe::TransitionCause::Eof,
                step: 0,
            }]
        );
        assert_eq!(observations.frames, vec![]);
        assert_eq!(observations.close, Some(close));
        assert_eq!(
            observations.counts,
            CountsWithState {
                counts: Counts {
                    actions: 1,
                    ..Counts::default()
                },
                final_state: ConnectionState::Closed,
            }
        );
    }

    /// Byte steps flow through the real core's bounded buffering: one
    /// `input_chunk` event per surviving chunk, with the derive.go counter
    /// semantics (whole surviving chunks consumed; leftover buffered).
    #[test]
    fn wired_bytes_project_input_chunks_and_real_counts() {
        let request = request_with_steps(concat!(
            "[{\"data_base64\":\"AQI=\",\"kind\":\"bytes\"},",
            "{\"data_base64\":\"AQI=\",\"kind\":\"bytes\"}]"
        ));
        let ScenarioOutcome::Completed(observations) = wired_outcome(&request) else {
            panic!("bytes scenario must complete");
        };
        let chunk = |step: u32| crate::observe::SemanticEvent {
            step,
            kind: crate::observe::SemanticEventKind::InputChunk { bytes: 2 },
        };
        assert_eq!(observations.events, vec![chunk(0), chunk(1)]);
        assert_eq!(
            observations.counts,
            CountsWithState {
                counts: Counts {
                    input_bytes: 4,
                    consumed_bytes: 4,
                    buffered_bytes: 4,
                    wire_buffered_bytes: 4,
                    ..Counts::default()
                },
                final_state: ConnectionState::Open,
            }
        );
    }

    /// Quirk Q26 (derive.go:292-294): nonzero bytes in CLOSED are a state
    /// violation, reported through the real core with zero counts.
    #[test]
    fn wired_bytes_in_closed_state_report_state_violation() {
        let request = wired_request(
            &[("initial_state", "\"closed\"")],
            "[{\"data_base64\":\"AQI=\",\"kind\":\"bytes\"}]",
        );
        let ScenarioOutcome::Failed {
            failure,
            counts,
            final_state,
        } = wired_outcome(&request)
        else {
            panic!("expected Failed");
        };
        assert_eq!(failure.code, "STATE_VIOLATION");
        assert_eq!(failure.close_code, None);
        assert_eq!(counts, Counts::default());
        assert_eq!(final_state, ConnectionState::Closed);
    }

    /// derive.go `eof`: transport EOF in CLOSED refuses as STATE_VIOLATION,
    /// with the rejected action still counted (actionStep counts first) —
    /// the corpus eof-in-closed shape, through the real core.
    #[test]
    fn wired_eof_in_closed_counts_the_rejected_action() {
        let request = wired_request(
            &[("initial_state", "\"closed\"")],
            "[{\"action\":\"eof\",\"kind\":\"action\"}]",
        );
        let ScenarioOutcome::Failed {
            failure,
            counts,
            final_state,
        } = wired_outcome(&request)
        else {
            panic!("expected Failed");
        };
        assert_eq!(failure.code, "STATE_VIOLATION");
        assert_eq!(counts.actions, 1, "the core counted the rejected action");
        assert_eq!(final_state, ConnectionState::Closed);
    }

    /// The action budget is enforced BEFORE the action field is read
    /// (Java's `actionCount++` precedes the field read), and the rejected
    /// action is included in the failure counts even though it never
    /// reached the core (the pending-action seam accounting).
    #[test]
    fn wired_action_limit_precedes_field_read_and_counts_the_rejection() {
        let request = wired_request(
            &[(
                "limits",
                concat!(
                    "{\"max_actions\":1,\"max_buffered_bytes\":65536,",
                    "\"max_frames\":64,\"max_input_bytes\":65536,",
                    "\"max_output_bytes\":4194304}"
                ),
            )],
            concat!(
                "[{\"action\":\"eof\",\"kind\":\"action\"},",
                "{\"bogus\":true,\"kind\":\"action\"}]"
            ),
        );
        let ScenarioOutcome::Failed {
            failure,
            counts,
            final_state,
        } = wired_outcome(&request)
        else {
            panic!("expected Failed");
        };
        assert_eq!(failure.code, "ACTION_LIMIT_EXCEEDED");
        assert_eq!(counts.actions, 2, "the rejected second action is counted");
        assert_eq!(final_state, ConnectionState::Closed, "the eof had executed");
    }

    /// The skeleton core's honest `Unimplemented` refusal (send paths)
    /// surfaces as the non-oracle `CORE_BEHAVIOR_UNIMPLEMENTED` envelope —
    /// never a fabricated oracle code — with the action counted by the core
    /// itself and the state retained.
    #[test]
    fn wired_unimplemented_send_maps_to_honest_non_oracle_code() {
        let request =
            request_with_steps("[{\"action\":\"send_text\",\"kind\":\"action\",\"text\":\"hi\"}]");
        let ScenarioOutcome::Failed {
            failure,
            counts,
            final_state,
        } = wired_outcome(&request)
        else {
            panic!("expected Failed");
        };
        assert_eq!(failure.code, UNIMPLEMENTED_CODE);
        assert_eq!(failure.close_code, None);
        assert_eq!(failure.detail, UNIMPLEMENTED_DETAIL);
        assert_eq!(counts.actions, 1, "the core counted the refused send");
        assert_eq!(final_state, ConnectionState::Open);
    }

    /// PUB_0000's own shape (send_close 999 while OPEN): the gates pass and
    /// the skeleton refuses the close behavior honestly (close semantics
    /// are US-016).
    #[test]
    fn wired_send_close_is_honestly_unimplemented_this_round() {
        let request = parse_request(PUB_0000).unwrap();
        let ScenarioOutcome::Failed {
            failure, counts, ..
        } = wired_outcome(&request)
        else {
            panic!("expected Failed");
        };
        assert_eq!(failure.code, UNIMPLEMENTED_CODE);
        assert_eq!(counts.actions, 1);
    }

    /// A send_close code outside the u16 command vocabulary cannot reach
    /// the core; the seam answers the SAME honest unimplemented refusal the
    /// core gives every send_close this round (revisited by US-016), with
    /// the action still counted via the pending seam accounting.
    #[test]
    fn wired_send_close_code_outside_u16_is_honestly_refused_and_counted() {
        let request = request_with_steps(concat!(
            "[{\"action\":\"send_close\",\"code\":70000,",
            "\"kind\":\"action\",\"reason\":\"x\"}]"
        ));
        let ScenarioOutcome::Failed {
            failure, counts, ..
        } = wired_outcome(&request)
        else {
            panic!("expected Failed");
        };
        assert_eq!(failure.code, UNIMPLEMENTED_CODE);
        assert_eq!(
            counts.actions, 1,
            "Java counts the action before the code read"
        );
    }

    /// Java's `requireOpen` precedes the payload field read: with the real
    /// core in OPEN, a send_text with no text reports MISSING_FIELD and the
    /// counted action survives into the failure counts (pending seam
    /// accounting: the command never reached the core).
    #[test]
    fn wired_missing_payload_field_still_counts_the_action() {
        let request = request_with_steps("[{\"action\":\"send_text\",\"kind\":\"action\"}]");
        let ScenarioOutcome::Failed {
            failure,
            counts,
            final_state,
        } = wired_outcome(&request)
        else {
            panic!("expected Failed");
        };
        assert_eq!(failure.code, "MISSING_FIELD");
        assert_eq!(counts.actions, 1, "actionCount++ precedes the field read");
        assert_eq!(final_state, ConnectionState::Open);
    }

    /// A malformed step after an executed step keeps the REAL core's
    /// partial counts (the oracle's partial-execution contract, now against
    /// ws_core instead of a scripted double).
    #[test]
    fn wired_malformed_step_mid_scenario_retains_real_core_counts() {
        let request = request_with_steps(concat!(
            "[{\"data_base64\":\"AQI=\",\"kind\":\"bytes\"},",
            "{\"bogus\":1,\"data_base64\":\"AQI=\",\"kind\":\"bytes\"}]"
        ));
        let ScenarioOutcome::Failed {
            failure, counts, ..
        } = wired_outcome(&request)
        else {
            panic!("expected Failed");
        };
        assert_eq!(failure.code, "UNKNOWN_FIELD");
        assert_eq!(counts.input_bytes, 2, "step 0's real effect is retained");
        assert_eq!(counts.wire_buffered_bytes, 2);
    }

    /// A fatal failure poisons the core: every subsequent input refuses
    /// with STATE_VIOLATION while the retained counts stay frozen
    /// (partial-execution semantics, exercised directly on the session).
    #[test]
    fn wired_poisoned_core_refuses_further_input_as_state_violation() {
        let request = request_with_steps("[]");
        let mut session = WiredCore
            .begin(&request)
            .expect("wired construction succeeds");
        let oversized = vec![0u8; 65_537];
        let failure = session
            .bytes(&oversized, 0)
            .expect_err("over max_input_bytes");
        assert_eq!(failure.code, "INPUT_LIMIT_EXCEEDED");
        let failure = session.bytes(&[1], 1).expect_err("poisoned core refuses");
        assert_eq!(failure.code, "STATE_VIOLATION");
        let snapshot = session.snapshot();
        assert_eq!(
            snapshot.counts.input_bytes, 0,
            "addBounded never partially updates"
        );
        assert_eq!(snapshot.final_state, ConnectionState::Open);
    }

    /// The typed-failure mapping: oracle-coded failures pass through with
    /// their close codes; the two deliberately wireless codes become the
    /// honest adapter vocabulary.
    #[test]
    fn wired_failure_mapping_is_faithful_and_honest() {
        let invalid = map_core_failure(&ws_core::TypedProtocolFailure::java_invalid_data(1002));
        assert_eq!(invalid.code, "JAVA_INVALID_DATA");
        assert_eq!(invalid.close_code, Some(1002));

        let state = map_core_failure(&ws_core::TypedProtocolFailure::protocol(
            ws_core::FailureCode::StateViolation,
        ));
        assert_eq!(state.code, "STATE_VIOLATION");
        assert_eq!(state.close_code, None);

        let unimplemented = map_core_failure(&ws_core::TypedProtocolFailure::protocol(
            ws_core::FailureCode::Unimplemented,
        ));
        assert_eq!(unimplemented.code, UNIMPLEMENTED_CODE);
        assert_eq!(unimplemented.close_code, None);

        let backpressure = map_core_failure(&ws_core::TypedProtocolFailure::protocol(
            ws_core::FailureCode::Backpressure(ws_core::error::QueueKind::Event),
        ));
        assert_eq!(backpressure.code, BACKPRESSURE_CODE);
        assert_eq!(backpressure.close_code, None);
    }

    /// Projection round-trip: every ws_core observation vocabulary entry
    /// projects onto the observe type with the IDENTICAL transcript wire
    /// string, so the two vocabularies cannot drift.
    #[test]
    fn wired_projection_round_trips_the_wire_vocabulary() {
        use ws_core::framing::Opcode as CoreOpcode;
        for opcode in [
            CoreOpcode::Continuous,
            CoreOpcode::Text,
            CoreOpcode::Binary,
            CoreOpcode::Closing,
            CoreOpcode::Ping,
            CoreOpcode::Pong,
        ] {
            assert_eq!(observed_opcode(opcode).wire(), opcode.wire_name());
        }
        use ws_core::event::OutboundCause as CoreCause;
        for cause in [
            CoreCause::SendText,
            CoreCause::SendBinary,
            CoreCause::SendPing,
            CoreCause::SendPong,
            CoreCause::SendClose,
            CoreCause::SendFragment,
            CoreCause::EchoClose,
        ] {
            assert_eq!(observed_outbound_cause(cause).wire(), cause.wire_name());
        }
        use ws_core::event::TransitionCause as CoreTransition;
        for cause in [
            CoreTransition::SendClose,
            CoreTransition::ReceiveClose,
            CoreTransition::Eof,
        ] {
            assert_eq!(observed_transition_cause(cause).wire(), cause.wire_name());
        }
        use ws_core::close::CloseOrigin as CoreOrigin;
        for origin in [CoreOrigin::Remote, CoreOrigin::Local, CoreOrigin::Transport] {
            let detail = ws_core::CloseDetail {
                code: 1000,
                reason: "r".to_string(),
                origin,
                remote: true,
                handshake_complete: true,
            };
            let projected = observed_close(&detail);
            assert_eq!(projected.origin.wire(), origin.wire_name());
            assert_eq!(projected.code, 1000);
            assert_eq!(projected.reason, "r");
            assert!(projected.remote);
            assert!(projected.handshake_complete);
        }
        // States: the corpus projection of each post-handshake ReadyState.
        let request = parse_request(PUB_0000).unwrap();
        let mut core = WiredCore;
        drop(core.begin(&request).expect("construction succeeds"));
        for (state, expected) in [
            (ws_core::ReadyState::Open, ConnectionState::Open),
            (ws_core::ReadyState::Closing, ConnectionState::Closing),
            (ws_core::ReadyState::Closed, ConnectionState::Closed),
        ] {
            assert_eq!(
                state.corpus_state().expect("post-handshake state projects"),
                expected.wire()
            );
        }
    }

    // -- Re-review round 1 (session 01a04427): core-produced gating --------

    fn recorded_outcome(
        request: &OracleRequest,
    ) -> (
        ScenarioOutcome,
        std::rc::Rc<std::cell::RefCell<Vec<String>>>,
    ) {
        let calls = std::rc::Rc::<std::cell::RefCell<Vec<String>>>::default();
        let mut core = RecordingWiredCore {
            calls: calls.clone(),
        };
        (drive_scenario(request, &mut core), calls)
    }

    /// `us005.pub.0068`'s exact shape (a constructible `send_text` while
    /// CLOSING), driven through the full driver against the real core: the
    /// command must REACH the core (the hook trace is exactly
    /// `["send_text"]` — no driver gate fires) and the STATE_VIOLATION plus
    /// the action count are the core's own (connection.rs `handle_command`:
    /// action prelude, then the Q26 state gate). Re-review round 1: this
    /// pass must be core-produced, never adapter-synthesized.
    #[test]
    fn wired_send_in_closing_is_core_produced_not_adapter_synthesized() {
        let request = wired_request(
            &[("initial_state", "\"closing\"")],
            "[{\"action\":\"send_text\",\"kind\":\"action\",\"text\":\"#_{\"}]",
        );
        let (outcome, calls) = recorded_outcome(&request);
        let ScenarioOutcome::Failed {
            failure,
            counts,
            final_state,
        } = outcome
        else {
            panic!("expected Failed, got {outcome:?}");
        };
        assert_eq!(failure.code, "STATE_VIOLATION");
        assert_eq!(failure.close_code, None);
        assert_eq!(
            counts.actions, 1,
            "the CORE counted the action at command receipt"
        );
        assert_eq!(final_state, ConnectionState::Closing);
        assert_eq!(
            *calls.borrow(),
            vec!["send_text".to_string()],
            "no driver gate fired: the command was delivered and the \
             refusal is the core's own"
        );
    }

    /// The same provenance for a constructible `send_close` (code within
    /// u16) while CLOSING: delivered, and state-gated by the core itself.
    #[test]
    fn wired_send_close_in_closing_is_core_gated() {
        let request = wired_request(
            &[("initial_state", "\"closing\"")],
            concat!(
                "[{\"action\":\"send_close\",\"code\":999,",
                "\"kind\":\"action\",\"reason\":\"bad\"}]"
            ),
        );
        let (outcome, calls) = recorded_outcome(&request);
        let ScenarioOutcome::Failed {
            failure,
            counts,
            final_state,
        } = outcome
        else {
            panic!("expected Failed, got {outcome:?}");
        };
        assert_eq!(failure.code, "STATE_VIOLATION");
        assert_eq!(counts.actions, 1, "core-counted at command receipt");
        assert_eq!(final_state, ConnectionState::Closing);
        assert_eq!(*calls.borrow(), vec!["send_close".to_string()]);
    }

    /// An oversized but fully constructible `send_text` is delivered too:
    /// the core's own post-requireOpen payload gate (connection.rs
    /// `handle_command`) produces BUFFER_LIMIT_EXCEEDED with the
    /// core-counted action — the driver no longer pre-checks the payload
    /// limit for deliverable commands.
    #[test]
    fn wired_oversized_constructible_send_is_gated_by_the_core_payload_gate() {
        let request = wired_request(
            &[],
            &format!(
                "[{{\"action\":\"send_text\",\"kind\":\"action\",\"text\":\"{}\"}}]",
                "a".repeat(65_537)
            ),
        );
        let (outcome, calls) = recorded_outcome(&request);
        let ScenarioOutcome::Failed {
            failure,
            counts,
            final_state,
        } = outcome
        else {
            panic!("expected Failed, got {outcome:?}");
        };
        assert_eq!(failure.code, "BUFFER_LIMIT_EXCEEDED");
        assert_eq!(counts.actions, 1, "core-counted at command receipt");
        assert_eq!(final_state, ConnectionState::Open);
        assert_eq!(*calls.borrow(), vec!["send_text".to_string()]);
    }

    /// Regression (driver-level shaping, malformed step in a non-open
    /// state): a `send_text` with NO `text` field while CLOSING can never
    /// become a core input, so the driver re-establishes Java's
    /// requireOpen-before-field-read order (OracleEngine.sendText:433-436:
    /// rejectUnknown -> requireOpen -> text) — STATE_VIOLATION with the
    /// prelude-counted action retained.
    #[test]
    fn wired_malformed_send_in_closing_keeps_java_require_open_order() {
        let request = wired_request(
            &[("initial_state", "\"closing\"")],
            "[{\"action\":\"send_text\",\"kind\":\"action\"}]",
        );
        let ScenarioOutcome::Failed {
            failure,
            counts,
            final_state,
        } = wired_outcome(&request)
        else {
            panic!("expected Failed");
        };
        assert_eq!(failure.code, "STATE_VIOLATION");
        assert_eq!(counts.actions, 1, "Java's prelude counted the action");
        assert_eq!(final_state, ConnectionState::Closing);
    }

    /// Regression: rejectUnknown precedes requireOpen
    /// (OracleEngine.sendText:433-434), so an unknown field on a send in
    /// CLOSING reports UNKNOWN_FIELD, never STATE_VIOLATION.
    #[test]
    fn wired_unknown_field_wins_over_state_gate_in_non_open_state() {
        let request = wired_request(
            &[("initial_state", "\"closing\"")],
            concat!(
                "[{\"action\":\"send_text\",\"bogus\":1,",
                "\"kind\":\"action\",\"text\":\"hi\"}]"
            ),
        );
        let ScenarioOutcome::Failed {
            failure, counts, ..
        } = wired_outcome(&request)
        else {
            panic!("expected Failed");
        };
        assert_eq!(failure.code, "UNKNOWN_FIELD");
        assert_eq!(counts.actions, 1, "Java's prelude counted the action");
    }

    /// Regression: a `send_close` code outside u16 (unrepresentable in the
    /// core's command vocabulary) in CLOSING — Java reads `code` only
    /// after requireOpen, so STATE_VIOLATION wins over the seam's honest
    /// unimplemented refusal.
    #[test]
    fn wired_send_close_code_outside_u16_in_closing_reports_state_violation() {
        let request = wired_request(
            &[("initial_state", "\"closing\"")],
            concat!(
                "[{\"action\":\"send_close\",\"code\":70000,",
                "\"kind\":\"action\",\"reason\":\"x\"}]"
            ),
        );
        let ScenarioOutcome::Failed {
            failure,
            counts,
            final_state,
        } = wired_outcome(&request)
        else {
            panic!("expected Failed");
        };
        assert_eq!(failure.code, "STATE_VIOLATION");
        assert_eq!(counts.actions, 1, "Java's prelude counted the action");
        assert_eq!(final_state, ConnectionState::Closing);
    }

    /// Regression: `send_fragment` with an oversized payload and an
    /// unreadable `fin` cannot reach the core; Java's payload limit sits
    /// before the fin read and requireOpen before both, so the driver
    /// reports BUFFER_LIMIT_EXCEEDED in OPEN and STATE_VIOLATION in
    /// CLOSING.
    #[test]
    fn wired_fragment_payload_limit_and_state_shaping_for_unreadable_fin() {
        let steps = format!(
            "[{{\"action\":\"send_fragment\",\"data_base64\":\"{}\",\
             \"kind\":\"action\",\"opcode\":\"text\"}}]",
            crate::base64::encode(&vec![0u8; 65_537])
        );
        let open = wired_request(&[], &steps);
        let ScenarioOutcome::Failed {
            failure, counts, ..
        } = wired_outcome(&open)
        else {
            panic!("expected Failed");
        };
        assert_eq!(failure.code, "BUFFER_LIMIT_EXCEEDED");
        assert_eq!(counts.actions, 1, "Java's prelude counted the action");

        let closing = wired_request(&[("initial_state", "\"closing\"")], &steps);
        let ScenarioOutcome::Failed {
            failure, counts, ..
        } = wired_outcome(&closing)
        else {
            panic!("expected Failed");
        };
        assert_eq!(failure.code, "STATE_VIOLATION");
        assert_eq!(counts.actions, 1, "Java's prelude counted the action");
    }
}
