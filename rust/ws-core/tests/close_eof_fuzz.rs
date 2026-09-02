//! US-021 AC2 dedicated fuzz target: **close / EOF**.
//!
//! ## Why this file exists
//!
//! The US-021 fuzz census recorded this family as
//! `SHARED_NO_DEDICATED_TARGET`, and its reason named the exact hole:
//!
//! > Close payloads ARE generated: `draw_close_payload` draws empty,
//! > one-byte, and hostile code/reason pairs across a 14-code table plus
//! > uniformly random u16 codes, with invalid-UTF-8 reasons. Transport EOF IS
//! > generated, but only inside `family_command_interleave` (one step in ten,
//! > over 5,000 cases) -- `byte_soup` and `frame_soup` never emit EOF at all.
//! > So close/EOF has no dedicated target and EOF in particular is exercised
//! > by exactly one family.
//!
//! Both halves of that are still true of `adversarial_fuzz.rs`. What this
//! target adds is not more volume but a different question. The shared
//! coverage asks "did the core survive?"; the close/EOF family's actual
//! contract is about WHICH close outcome governs -- a close code and reason
//! that survive a parse, an echo that carries the constructor payload rather
//! than the wire payload, an EOF whose reported code depends on whether a
//! close was already governing, and a terminal that happens exactly once and
//! then absorbs everything. None of that is observable from "no panic".
//!
//! ## The model
//!
//! Written from the documented sites, not from the implementation's control
//! flow:
//!
//! - `framing.rs` `parse_close_payload` (Q11/Q12/Q13): empty payload is code
//!   1000 with an empty reason; one byte is code 1002 with an empty reason;
//!   two or more bytes are a big-endian code plus a STRICTLY decoded UTF-8
//!   reason, where an invalid reason is Java's `NullPointerException` path
//!   (`JavaRuntimeRejection`, NOT a 1007); then the `close_code_rejection`
//!   chain.
//! - `close.rs` `close_code_rejection` (Q13): 1007 with an empty reason
//!   rejects as 1007; 1005 with a non-empty reason rejects as 1002; codes in
//!   1016..2999 reject as 1002; and 1006/1015/1005/1004 and anything outside
//!   1000..=4999 reject as 1002.
//! - `close.rs` `normalize_send_close_code` (Q14): a LOCAL send of 1015
//!   becomes 1005 BEFORE validation, so `send_close(1015, "")` is rejected as
//!   1005-with-empty-reason would be, not as 1015.
//! - `connection.rs` `process_close_frame` (Q19/Q10): a close frame received
//!   while OPEN records the remote detail, emits `close`, echoes a close
//!   frame carrying the CONSTRUCTOR payload `[0x03, 0xe8]` -- never the wire
//!   payload -- and moves to `closing`. Received while CLOSING it records,
//!   emits, and moves to `closed` with no echo.
//! - `connection.rs` `send_close`: the Q13 rejection returns WITHOUT a
//!   transition and WITHOUT recording a detail. That arm carries an owner
//!   decision and a corpus differential in its comment; the model mirrors it
//!   deliberately, and a model that "fixed" it would be asserting against a
//!   pinned observable.
//! - `connection.rs` `handle_eof` (Q20): from `closing` WITH a governing
//!   close, EOF echoes that close's code and reason; otherwise it reports
//!   1006 with the pinned reason. `remote` records whether the state was
//!   closing; `handshake_complete` echoes the prior detail's flag, which is
//!   FALSE when no detail exists and false after a local send_close.
//! - `connection.rs` `handle_command` / `handle_bytes`: `closed` refuses
//!   every non-empty chunk and every action; `closing` refuses every
//!   non-close frame and every send. Every failure except backpressure is
//!   fatal and poisons the core, after which every input is a
//!   `StateViolation` with no event and no write.
//!
//! ## Generator domain
//!
//! `draw_schedule` emits `Vec<Step>` over `{InboundFrame(FrameSpec), Eof,
//! Command(LocalCommand)}`, one frame per transport chunk so that the
//! chunk-atomicity of the translate stage cannot blur which step a rejection
//! belongs to. Role is `Server` in the modeled families so the outbound
//! bytes are unmasked and can be predicted exactly; the hostile family draws
//! both roles. Data frames are held to valid UTF-8 text and small binary --
//! message content is the message/UTF-8 family's subject, not this one.
//!
//! ## RED record (defects planted in shipped source, then removed)
//!
//! - **RED-D** -- the Q10 close echo in `process_close_frame` made to carry
//!   the WIRE payload instead of the constructor payload `[0x03, 0xe8]`.
//!   CAUGHT: `close_payload_parse_differential` failed at case 2 with exactly
//!   the message it exists for, and `close_eof_modeled_schedules` failed at
//!   case 6 on the outbound write differential. The shared coverage this
//!   family used to rest on -- `adversarial_fuzz.rs` -- passed all 14 of its
//!   tests under the same plant.
//! - **RED-E** -- `handle_eof`'s Q20 arm made to report 1006 unconditionally,
//!   dropping a governing close's code and reason. CAUGHT: the modeled and
//!   inertness families both failed at case 6 on the event sequence.
//!   `adversarial_fuzz.rs` passed all 14 again.
//! - **RED-F** -- the `closed`-state refusal of a non-empty chunk in
//!   `handle_bytes` deleted. **MISSED at first, and the miss was the test's
//!   fault, not the defect's.** Two things were wrong here and both are
//!   fixed below. (1) The inertness family compared only the close-vocabulary
//!   projection, which drops chunk records -- so a terminated core recording
//!   an `input_chunk` for a chunk it should have refused before recording
//!   anything was invisible; the comparison now includes every event KIND.
//!   (2) The baseline was clamped to `head_len` rather than `head_len - 1`,
//!   which silently pulled the first post-terminal step INTO the baseline and
//!   made the comparison vacuous for exactly the step that mattered. With
//!   both corrected the plant is CAUGHT: "input 3 after the terminal was not
//!   a typed StateViolation", because with the outer gate gone a malformed
//!   frame arriving at a closed core is rejected by the translate stage
//!   instead of absorbed by the state machine. Outside this file only
//!   `core_semantics.rs` caught it, with one fixed-example test.
//!
//! ## Claim grade
//!
//! Bounded. Fixed committed seeds, no coverage feedback, no corpus
//! evolution. Bounded evidence, never proof.

#![forbid(unsafe_code)]

use std::panic::{AssertUnwindSafe, catch_unwind};

use ws_core::close::{CloseDetail, CloseOrigin, close_code_rejection, normalize_send_close_code};
use ws_core::config::ConnectionConfig;
use ws_core::connection::{
    ConnectionCore, InitialState, Input, LocalCommand, ReadyState, Role, WIRE_PENDING_SLACK_BYTES,
};
use ws_core::error::{FailureCode, TypedProtocolFailure};
use ws_core::event::SemanticEventKind;

// ---------------------------------------------------------------------------
// Deterministic PRNG (SplitMix64) -- fixed committed seeds only.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> SplitMix64 {
        SplitMix64 { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        assert!(n > 0, "below(0) has no value to return");
        self.next_u64() % n
    }

    fn byte(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }

    fn chance(&mut self, one_in: u64) -> bool {
        self.below(one_in) == 0
    }
}

// ---------------------------------------------------------------------------
// Wire rendering, written independently of the shipped encoder.
// ---------------------------------------------------------------------------

fn xor_mask(payload: &mut [u8], key: [u8; 4]) {
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= key[index % 4];
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FrameSpec {
    fin: bool,
    opcode: u8,
    payload: Vec<u8>,
    mask: Option<[u8; 4]>,
}

impl FrameSpec {
    fn render(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.payload.len() + 14);
        let mut first = self.opcode & 0x0f;
        if self.fin {
            first |= 0x80;
        }
        out.push(first);
        let mask_bit = if self.mask.is_some() { 0x80u8 } else { 0 };
        let len = self.payload.len();
        if len <= 125 {
            out.push(mask_bit | (len as u8));
        } else if len <= 0xffff {
            out.push(mask_bit | 126);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            out.push(mask_bit | 127);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
        if let Some(key) = self.mask {
            out.extend_from_slice(&key);
            let start = out.len();
            out.extend_from_slice(&self.payload);
            xor_mask(&mut out[start..], key);
        } else {
            out.extend_from_slice(&self.payload);
        }
        out
    }
}

/// The unmasked wire encoding of one outbound server frame, so the model can
/// predict the exact bytes the core is expected to write.
fn server_wire(opcode: u8, payload: &[u8]) -> Vec<u8> {
    FrameSpec {
        fin: true,
        opcode,
        payload: payload.to_vec(),
        mask: None,
    }
    .render()
}

// ---------------------------------------------------------------------------
// The model.
// ---------------------------------------------------------------------------

/// Quirk Q10: the echoed close frame carries the CONSTRUCTOR payload.
const CLOSE_CONSTRUCTOR_PAYLOAD: [u8; 2] = [0x03, 0xe8];
/// The pinned Q20 EOF reason.
const EOF_DEFAULT_REASON: &str = "transport EOF before close handshake completed";

#[derive(Clone, Debug, PartialEq, Eq)]
enum Step {
    InboundFrame(FrameSpec),
    Eof,
    Command(LocalCommand),
}

/// The observable projection this family compares. Frame records are
/// deliberately absent: they are the transcript's `frames[]` stream, not its
/// `events[]` stream, and this family is about the close vocabulary.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ModelEvent {
    Text(Vec<u8>),
    Ping(Vec<u8>),
    Close(CloseDetail),
    CloseInitiated(CloseDetail),
    Eof(CloseDetail),
    Outbound(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Prediction {
    events: Vec<ModelEvent>,
    writes: Vec<Vec<u8>>,
    final_state: ReadyState,
    final_detail: Option<CloseDetail>,
    /// The step index of the first fatal refusal, if any.
    first_fatal: Option<usize>,
    terminal_transitions: usize,
}

/// `parse_close_payload`, restated (Q11/Q12/Q13). `Err(())` means the frame
/// is refused; the specific code is not modeled because the campaign compares
/// the OBSERVABLE close detail, and a refused frame has none.
fn model_parse_close(payload: &[u8]) -> Result<(u16, String), ()> {
    let (code, reason) = match payload.len() {
        0 => (1000u16, String::new()),
        1 => (1002u16, String::new()),
        _ => {
            let code = u16::from_be_bytes([payload[0], payload[1]]);
            let Ok(reason) = std::str::from_utf8(&payload[2..]) else {
                return Err(());
            };
            (code, reason.to_owned())
        }
    };
    if close_code_rejection(code, &reason).is_some() {
        return Err(());
    }
    Ok((code, reason))
}

/// Predict the whole schedule for a SERVER-role core started `Open`.
#[allow(clippy::too_many_lines)]
fn predict(schedule: &[Step], max_actions: u64) -> Prediction {
    let mut events = Vec::new();
    let mut writes: Vec<Vec<u8>> = Vec::new();
    let mut state = ReadyState::Open;
    let mut detail: Option<CloseDetail> = None;
    let mut actions = 0u64;
    let mut terminal = 0usize;

    for (index, step) in schedule.iter().enumerate() {
        macro_rules! fatal {
            () => {
                return Prediction {
                    events,
                    writes,
                    final_state: state,
                    final_detail: detail,
                    first_fatal: Some(index),
                    terminal_transitions: terminal,
                }
            };
        }
        match step {
            Step::InboundFrame(frame) => {
                // handle_bytes: closed refuses a non-empty chunk.
                if state == ReadyState::Closed {
                    fatal!();
                }
                // Translate stage, one frame per chunk.
                let control = frame.opcode >= 0x8;
                if control && (!frame.fin || frame.payload.len() > 125) {
                    fatal!();
                }
                let mut parsed_close = None;
                if frame.opcode == 0x8 {
                    match model_parse_close(&frame.payload) {
                        Ok(pair) => parsed_close = Some(pair),
                        Err(()) => fatal!(),
                    }
                }
                if frame.opcode == 0x1 && std::str::from_utf8(&frame.payload).is_err() {
                    fatal!();
                }
                // Process stage: closing refuses every non-close frame.
                if state == ReadyState::Closing && frame.opcode != 0x8 {
                    fatal!();
                }
                match frame.opcode {
                    0x8 => {
                        let (code, reason) = parsed_close.expect("close frames parse above");
                        let was_closing = state == ReadyState::Closing;
                        let next = CloseDetail {
                            code: i32::from(code),
                            reason,
                            origin: CloseOrigin::Remote,
                            remote: true,
                            handshake_complete: true,
                        };
                        detail = Some(next.clone());
                        events.push(ModelEvent::Close(next));
                        if was_closing {
                            state = ReadyState::Closed;
                            terminal += 1;
                        } else {
                            // Q19/Q10 echo-while-open.
                            writes.push(server_wire(0x8, &CLOSE_CONSTRUCTOR_PAYLOAD));
                            events.push(ModelEvent::Outbound("echo_close".to_owned()));
                            state = ReadyState::Closing;
                        }
                    }
                    0x9 => events.push(ModelEvent::Ping(frame.payload.clone())),
                    0x1 => events.push(ModelEvent::Text(frame.payload.clone())),
                    other => panic!("model domain excludes inbound opcode {other:#x}"),
                }
            }
            Step::Eof => {
                if state == ReadyState::Closed {
                    fatal!();
                }
                actions = actions.saturating_add(1);
                if actions > max_actions {
                    fatal!();
                }
                let (code, reason) = match (state, &detail) {
                    (ReadyState::Closing, Some(governing)) => {
                        (governing.code, governing.reason.clone())
                    }
                    _ => (1006, EOF_DEFAULT_REASON.to_owned()),
                };
                let handshake_complete = detail
                    .as_ref()
                    .is_some_and(|governing| governing.handshake_complete);
                let next = CloseDetail {
                    code,
                    reason,
                    origin: CloseOrigin::Transport,
                    remote: state == ReadyState::Closing,
                    handshake_complete,
                };
                detail = Some(next.clone());
                events.push(ModelEvent::Eof(next));
                state = ReadyState::Closed;
                terminal += 1;
            }
            Step::Command(command) => {
                actions = actions.saturating_add(1);
                if actions > max_actions {
                    fatal!();
                }
                if state != ReadyState::Open {
                    fatal!();
                }
                match command {
                    LocalCommand::SendPing { data } => {
                        writes.push(server_wire(0x9, data));
                        events.push(ModelEvent::Outbound("send_ping".to_owned()));
                    }
                    LocalCommand::SendClose { code, reason } => {
                        let normalized = normalize_send_close_code(*code);
                        if close_code_rejection(normalized, reason).is_some() {
                            // No transition, no detail: the pinned arm.
                            fatal!();
                        }
                        let mut payload = normalized.to_be_bytes().to_vec();
                        payload.extend_from_slice(reason.as_bytes());
                        writes.push(server_wire(0x8, &payload));
                        events.push(ModelEvent::Outbound("send_close".to_owned()));
                        let next = CloseDetail {
                            code: i32::from(normalized),
                            reason: reason.clone(),
                            origin: CloseOrigin::Local,
                            remote: false,
                            handshake_complete: false,
                        };
                        detail = Some(next.clone());
                        events.push(ModelEvent::CloseInitiated(next));
                        state = ReadyState::Closing;
                    }
                    other => panic!("model domain excludes command {other:?}"),
                }
            }
        }
    }

    Prediction {
        events,
        writes,
        final_state: state,
        final_detail: detail,
        first_fatal: None,
        terminal_transitions: terminal,
    }
}

// ---------------------------------------------------------------------------
// Driving the core.
// ---------------------------------------------------------------------------

fn target_config() -> ConnectionConfig {
    ConnectionConfig::builder()
        .event_queue_capacity(1024)
        .write_queue_capacity(1024)
        .build()
        .expect("target default config is valid")
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Outcome {
    events: Vec<ModelEvent>,
    /// Every drained event kind with chunk records dropped and frame records
    /// zeroed: the chunking-invariant projection.
    kinds: Vec<SemanticEventKind>,
    writes: Vec<Vec<u8>>,
    results: Vec<Result<(), TypedProtocolFailure>>,
    first_fatal: Option<usize>,
    final_state: ReadyState,
    final_detail: Option<CloseDetail>,
    terminal_transitions: usize,
}

fn drive(config: &ConnectionConfig, role: Role, steps: &[Step]) -> Outcome {
    let mut core = ConnectionCore::new_in_state(config.clone(), role, InitialState::Open);
    let mut events = Vec::new();
    let mut kinds = Vec::new();
    let mut writes = Vec::new();
    let mut results = Vec::new();
    let mut first_fatal = None;
    let mut terminal = 0usize;

    for (index, step) in steps.iter().enumerate() {
        let rendered;
        let result = match step {
            Step::InboundFrame(frame) => {
                rendered = frame.render();
                core.handle(Input::TransportBytes(&rendered))
            }
            Step::Eof => core.handle(Input::TransportEof),
            Step::Command(command) => core.handle(Input::Command(command.clone())),
        };
        let mut drained = 0usize;
        while let Some(event) = core.next_event() {
            drained += 1;
            assert!(
                drained <= config.event_queue_capacity(),
                "event queue exceeded its configured capacity"
            );
            match &event.kind {
                SemanticEventKind::Text { text } => {
                    events.push(ModelEvent::Text(text.as_bytes().to_vec()));
                }
                SemanticEventKind::Ping { data } => events.push(ModelEvent::Ping(data.clone())),
                SemanticEventKind::Close(detail) => {
                    events.push(ModelEvent::Close(detail.clone()));
                }
                SemanticEventKind::CloseInitiated(detail) => {
                    events.push(ModelEvent::CloseInitiated(detail.clone()));
                }
                SemanticEventKind::Eof(detail) => events.push(ModelEvent::Eof(detail.clone())),
                SemanticEventKind::OutboundCause { cause, .. } => {
                    events.push(ModelEvent::Outbound(cause.wire_name().to_owned()));
                }
                SemanticEventKind::Transition { to, .. } if *to == ReadyState::Closed => {
                    terminal += 1;
                }
                _ => {}
            }
            match &event.kind {
                SemanticEventKind::InputChunk { .. } => {}
                SemanticEventKind::FrameObserved(record) => {
                    let mut record = record.clone();
                    record.step = 0;
                    kinds.push(SemanticEventKind::FrameObserved(record));
                }
                other => kinds.push(other.clone()),
            }
        }
        let mut written = 0usize;
        while let Some(write) = core.next_write() {
            written += 1;
            assert!(
                written <= config.write_queue_capacity(),
                "write queue exceeded its configured capacity"
            );
            writes.push(write.bytes);
        }

        let counts = core.counts();
        assert_eq!(
            counts.buffered_bytes,
            counts.wire_buffered_bytes + counts.message_buffered_bytes,
            "buffered-byte decomposition identity"
        );
        assert!(
            counts.wire_buffered_bytes
                <= config.max_buffered_bytes() as u64 + WIRE_PENDING_SLACK_BYTES,
            "pending wire buffer exceeded max_buffered_bytes + the pinned wire slack"
        );
        assert!(
            terminal <= 1,
            "more than one terminal transition to Closed: {terminal}"
        );

        if let Err(failure) = &result
            && failure.code.is_fatal()
            && first_fatal.is_none()
        {
            first_fatal = Some(index);
        }
        results.push(result);
    }

    Outcome {
        events,
        kinds,
        writes,
        results,
        first_fatal,
        final_state: core.state(),
        final_detail: core.close_detail().cloned(),
        terminal_transitions: terminal,
    }
}

fn drive_checked(label: &str, config: &ConnectionConfig, role: Role, steps: &[Step]) -> Outcome {
    match catch_unwind(AssertUnwindSafe(|| drive(config, role, steps))) {
        Ok(outcome) => outcome,
        Err(payload) => {
            let detail = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("non-string panic payload");
            panic!("{label}: panic caught by the close/EOF oracle: {detail}");
        }
    }
}

// ---------------------------------------------------------------------------
// Generators.
// ---------------------------------------------------------------------------

/// A close payload spanning the whole documented decision surface: empty,
/// one-byte, the code table, uniformly random codes, ASCII reasons, valid
/// multi-byte reasons, and deliberately invalid UTF-8 reasons.
fn draw_close_payload(rng: &mut SplitMix64) -> Vec<u8> {
    match rng.below(12) {
        0 => Vec::new(),
        1 => vec![rng.byte()],
        _ => {
            // Boundary-heavy: every literal in the Q13 chain plus its
            // neighbours.
            const CODES: [u16; 20] = [
                999, 1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1011, 1014, 1015, 1016, 2998,
                2999, 3000, 4999, 5000, 65535, 0,
            ];
            let code = if rng.chance(4) {
                (rng.next_u64() & 0xffff) as u16
            } else {
                CODES[rng.below(CODES.len() as u64) as usize]
            };
            let mut payload = code.to_be_bytes().to_vec();
            let reason_len = rng.below(20) as usize;
            match rng.below(8) {
                0 => {} // empty reason: the 1007 and 1005 arms need it
                1 => {
                    // Deliberately invalid UTF-8.
                    payload.extend_from_slice(&[0xff, 0xfe]);
                    payload.extend((0..reason_len).map(|_| rng.byte()));
                }
                2 => {
                    // Valid multi-byte.
                    for _ in 0..reason_len {
                        payload.push(0xc2 | (rng.byte() & 0x01));
                        payload.push(0x80 | (rng.byte() & 0x3f));
                    }
                }
                _ => payload.extend((0..reason_len).map(|_| 0x20 + (rng.byte() % 0x5e))),
            }
            payload
        }
    }
}

fn draw_mask(rng: &mut SplitMix64) -> Option<[u8; 4]> {
    if rng.chance(2) {
        Some([rng.byte(), rng.byte(), rng.byte(), rng.byte()])
    } else {
        None
    }
}

fn draw_reason(rng: &mut SplitMix64) -> String {
    let len = rng.below(16) as usize;
    if len == 0 {
        return String::new();
    }
    (0..len)
        .map(|_| char::from(0x20 + (rng.byte() % 0x5e)))
        .collect()
}

/// One step of a close/EOF schedule, inside the modeled domain.
fn draw_step(rng: &mut SplitMix64) -> Step {
    match rng.below(10) {
        0..=3 => Step::InboundFrame(FrameSpec {
            fin: true,
            opcode: 0x8,
            payload: draw_close_payload(rng),
            mask: draw_mask(rng),
        }),
        4..=5 => Step::Eof,
        6 => {
            const CODES: [u16; 12] = [
                999, 1000, 1001, 1002, 1004, 1005, 1006, 1007, 1011, 1015, 1016, 3000,
            ];
            let code = if rng.chance(3) {
                (rng.next_u64() & 0xffff) as u16
            } else {
                CODES[rng.below(CODES.len() as u64) as usize]
            };
            Step::Command(LocalCommand::SendClose {
                code,
                reason: draw_reason(rng),
            })
        }
        7 => Step::Command(LocalCommand::SendPing {
            data: (0..rng.below(8)).map(|_| rng.byte()).collect(),
        }),
        8 => Step::InboundFrame(FrameSpec {
            fin: true,
            opcode: 0x9,
            payload: (0..rng.below(8)).map(|_| rng.byte()).collect(),
            mask: draw_mask(rng),
        }),
        _ => Step::InboundFrame(FrameSpec {
            fin: true,
            opcode: 0x1,
            payload: (0..rng.below(12))
                .map(|_| 0x41 + (rng.byte() % 26))
                .collect(),
            mask: draw_mask(rng),
        }),
    }
}

fn draw_schedule(rng: &mut SplitMix64) -> Vec<Step> {
    let len = 1 + rng.below(7) as usize;
    (0..len).map(|_| draw_step(rng)).collect()
}

// ---------------------------------------------------------------------------
// Family 1: the model differential.
// ---------------------------------------------------------------------------

/// Drawn close/EOF schedules, compared against the model event by event,
/// write by write, plus the final state and the final governing close detail.
#[test]
fn close_eof_modeled_schedules() {
    let config = target_config();
    let max_actions = config.max_actions();
    let mut rng = SplitMix64::new(0xc10e_0001);
    let mut reached_closed = 0usize;
    let mut echoed = 0usize;
    let mut eof_after_close = 0usize;
    let mut refused = 0usize;

    for case in 0..7_000u32 {
        let schedule = draw_schedule(&mut rng);
        let prediction = predict(&schedule, max_actions);
        let label = format!("close_eof_modeled_schedules case={case}");
        let outcome = drive_checked(&label, &config, Role::Server, &schedule);

        assert_eq!(
            outcome.events, prediction.events,
            "{label}: event sequence differs from the model\nschedule={schedule:#?}"
        );
        assert_eq!(
            outcome.writes, prediction.writes,
            "{label}: outbound write stream differs from the model\nschedule={schedule:#?}"
        );
        assert_eq!(
            outcome.first_fatal, prediction.first_fatal,
            "{label}: first fatal refusal differs from the model\nschedule={schedule:#?}"
        );
        assert_eq!(
            outcome.final_state, prediction.final_state,
            "{label}: final state differs from the model\nschedule={schedule:#?}"
        );
        assert_eq!(
            outcome.final_detail, prediction.final_detail,
            "{label}: final close detail differs from the model\nschedule={schedule:#?}"
        );
        assert_eq!(
            outcome.terminal_transitions, prediction.terminal_transitions,
            "{label}: terminal-transition count differs from the model"
        );

        if outcome.final_state == ReadyState::Closed {
            reached_closed += 1;
        }
        if outcome
            .events
            .iter()
            .any(|event| matches!(event, ModelEvent::Outbound(cause) if cause == "echo_close"))
        {
            echoed += 1;
        }
        if outcome
            .events
            .iter()
            .any(|event| matches!(event, ModelEvent::Eof(detail) if detail.code != 1006))
        {
            eof_after_close += 1;
        }
        if outcome.first_fatal.is_some() {
            refused += 1;
        }
    }

    assert!(
        reached_closed >= 2_000,
        "generator degenerated: only {reached_closed} schedules reached Closed"
    );
    assert!(
        echoed >= 1_000,
        "generator degenerated: only {echoed} schedules reached the Q19 echo-while-open arm"
    );
    assert!(
        eof_after_close >= 200,
        "generator degenerated: only {eof_after_close} schedules reached the Q20 arm where EOF \
         echoes a governing close's code instead of reporting 1006"
    );
    assert!(
        refused >= 1_000,
        "generator degenerated: only {refused} schedules were refused"
    );
}

// ---------------------------------------------------------------------------
// Family 2: the close-payload parse, at volume, in isolation.
// ---------------------------------------------------------------------------

/// One close frame, drawn payload, into an open core: the accept/reject
/// decision and the resulting `(code, reason)` must be exactly Q11/Q12/Q13.
///
/// Isolating it from the schedule is the point: in a schedule a parse
/// rejection and a state rejection both look like "the core refused", and a
/// model that conflated them would still pass family 1. Here the state is
/// fixed, so only the parse can decide.
#[test]
fn close_payload_parse_differential() {
    let config = target_config();
    let mut rng = SplitMix64::new(0xc10e_0002);
    let mut accepted = 0usize;
    let mut rejected_code = 0usize;
    let mut rejected_utf8 = 0usize;

    for case in 0..6_000u32 {
        let payload = draw_close_payload(&mut rng);
        let step = Step::InboundFrame(FrameSpec {
            fin: true,
            opcode: 0x8,
            payload: payload.clone(),
            mask: draw_mask(&mut rng),
        });
        let label = format!("close_payload_parse_differential case={case}");
        let outcome = drive_checked(&label, &config, Role::Server, &[step]);

        match model_parse_close(&payload) {
            Ok((code, reason)) => {
                accepted += 1;
                assert_eq!(
                    outcome.final_detail,
                    Some(CloseDetail {
                        code: i32::from(code),
                        reason: reason.clone(),
                        origin: CloseOrigin::Remote,
                        remote: true,
                        handshake_complete: true,
                    }),
                    "{label}: accepted close parsed to a different detail; payload={payload:?}"
                );
                assert_eq!(
                    outcome.final_state,
                    ReadyState::Closing,
                    "{label}: an accepted close while open must move to closing"
                );
                assert_eq!(
                    outcome.writes,
                    vec![server_wire(0x8, &CLOSE_CONSTRUCTOR_PAYLOAD)],
                    "{label}: the Q10 echo must carry the constructor payload, never the wire \
                     payload; payload={payload:?}"
                );
            }
            Err(()) => {
                assert!(
                    outcome.first_fatal == Some(0),
                    "{label}: the model rejects this payload and the core accepted it; \
                     payload={payload:?}"
                );
                assert!(
                    outcome.final_detail.is_none(),
                    "{label}: a refused close frame recorded a governing close detail"
                );
                assert!(
                    outcome.writes.is_empty(),
                    "{label}: a refused close frame emitted a write"
                );
                if payload.len() >= 2 && std::str::from_utf8(&payload[2..]).is_err() {
                    rejected_utf8 += 1;
                    assert_eq!(
                        outcome.results[0],
                        Err(TypedProtocolFailure::protocol(
                            FailureCode::JavaRuntimeRejection
                        )),
                        "{label}: Q12 says an invalid reason is the NullPointerException path, \
                         not a 1007"
                    );
                } else {
                    rejected_code += 1;
                }
            }
        }
    }

    assert!(
        accepted >= 500,
        "generator degenerated: only {accepted} payloads were wire-legal"
    );
    assert!(
        rejected_code >= 1_000,
        "generator degenerated: only {rejected_code} payloads were rejected by the code chain"
    );
    assert!(
        rejected_utf8 >= 200,
        "generator degenerated: only {rejected_utf8} payloads carried an invalid-UTF-8 reason"
    );
}

// ---------------------------------------------------------------------------
// Family 3: exactly-once terminal and post-terminal inertness.
// ---------------------------------------------------------------------------

/// Run a drawn schedule to termination, then keep pushing.
///
/// This is the family the census's own words called for: EOF was exercised by
/// exactly one other family, and never twice. Here every terminated core gets
/// a drawn TAIL of further inputs -- more EOFs, more bytes, more commands --
/// and the contract is absolute: no new event, no new write, no change to the
/// governing close detail or the state, and a typed refusal for every input.
#[test]
fn close_eof_terminal_is_exactly_once_and_post_terminal_is_inert() {
    let config = target_config();
    let max_actions = config.max_actions();
    let mut rng = SplitMix64::new(0xc10e_0003);
    let mut terminated = 0usize;
    let mut repeated_eof = 0usize;

    for case in 0..5_000u32 {
        // Draw a head that is LIKELY to terminate, then a tail that keeps
        // hammering a core that already has.
        let mut schedule = draw_schedule(&mut rng);
        schedule.push(Step::Eof);
        let head_len = schedule.len();
        let tail_len = 1 + rng.below(4) as usize;
        let mut tail_eofs = 0usize;
        for _ in 0..tail_len {
            let step = if rng.chance(2) {
                tail_eofs += 1;
                Step::Eof
            } else {
                draw_step(&mut rng)
            };
            schedule.push(step);
        }
        if tail_eofs > 0 {
            repeated_eof += 1;
        }

        let label = format!("close_eof_terminal_inertness case={case}");
        let outcome = drive_checked(&label, &config, Role::Server, &schedule);
        let prediction = predict(&schedule, max_actions);
        assert_eq!(
            outcome.events, prediction.events,
            "{label}: event sequence differs from the model\nschedule={schedule:#?}"
        );

        assert!(
            outcome.terminal_transitions <= 1,
            "{label}: {} terminal transitions",
            outcome.terminal_transitions
        );

        // Once the core has refused fatally or reached Closed, everything
        // after must be inert. Re-drive the head alone and compare the whole
        // observable surface against the full run.
        // The baseline is the schedule up to and including the step that
        // ENDED it -- the head's own EOF, or an earlier fatal. Clamping to
        // head_len - 1 matters: an earlier draft clamped to head_len, which
        // silently pulled the FIRST tail step into the baseline and made the
        // whole comparison vacuous for it. RED-F was missed until this was
        // corrected.
        let stop = outcome
            .first_fatal
            .map_or(head_len - 1, |index| index.min(head_len - 1));
        if stop < schedule.len() {
            terminated += 1;
            let head_only = drive_checked(&label, &config, Role::Server, &schedule[..=stop]);
            assert_eq!(
                head_only.events, outcome.events,
                "{label}: inputs after the terminal produced new events"
            );
            // Every event KIND, not just the close vocabulary. This is the
            // assertion that sees an input_chunk record emitted for a chunk
            // a terminated core should have refused before recording
            // anything -- RED-F below, which the close-vocabulary
            // comparison above cannot see because it projects chunk records
            // away.
            assert_eq!(
                head_only.kinds, outcome.kinds,
                "{label}: inputs after the terminal produced new events of some kind"
            );
            assert_eq!(
                head_only.writes, outcome.writes,
                "{label}: inputs after the terminal produced new writes"
            );
            assert_eq!(
                head_only.final_detail, outcome.final_detail,
                "{label}: inputs after the terminal changed the governing close detail"
            );
            assert_eq!(
                head_only.final_state, outcome.final_state,
                "{label}: inputs after the terminal changed the state"
            );
            for (index, result) in outcome.results.iter().enumerate().skip(stop + 1) {
                assert_eq!(
                    result,
                    &Err(TypedProtocolFailure::protocol(FailureCode::StateViolation)),
                    "{label}: input {index} after the terminal was not a typed StateViolation"
                );
            }
        }
    }

    assert!(
        terminated >= 3_000,
        "generator degenerated: only {terminated} schedules ran past their terminal"
    );
    assert!(
        repeated_eof >= 2_000,
        "generator degenerated: only {repeated_eof} schedules delivered a second EOF"
    );
}

// ---------------------------------------------------------------------------
// Family 4: hostile close/EOF soup, outside the modeled domain.
// ---------------------------------------------------------------------------

/// Malformed close frames, non-fin close frames, oversized close payloads,
/// close frames split across chunks, EOF everywhere, both roles. No model:
/// no panic, bounded output, determinism, and at most one terminal.
#[test]
fn close_eof_hostile_soup_no_panic_deterministic() {
    let config = target_config();
    let mut rng = SplitMix64::new(0xc10e_0004);
    let mut refused = 0usize;
    let mut survived = 0usize;

    for case in 0..5_000u32 {
        let len = 1 + rng.below(8) as usize;
        let mut steps = Vec::with_capacity(len);
        for _ in 0..len {
            let step = match rng.below(8) {
                0..=2 => Step::InboundFrame(FrameSpec {
                    fin: !rng.chance(4),
                    opcode: 0x8,
                    payload: if rng.chance(6) {
                        (0..126 + rng.below(60)).map(|_| rng.byte()).collect()
                    } else {
                        draw_close_payload(&mut rng)
                    },
                    mask: draw_mask(&mut rng),
                }),
                3..=4 => Step::Eof,
                5 => Step::Command(LocalCommand::SendClose {
                    code: (rng.next_u64() & 0xffff) as u16,
                    reason: draw_reason(&mut rng),
                }),
                6 => Step::Command(LocalCommand::SendPing {
                    data: (0..rng.below(200)).map(|_| rng.byte()).collect(),
                }),
                _ => Step::InboundFrame(FrameSpec {
                    fin: !rng.chance(3),
                    opcode: [0x0u8, 0x1, 0x2, 0x9, 0xa, 0xb][rng.below(6) as usize],
                    payload: (0..rng.below(40)).map(|_| rng.byte()).collect(),
                    mask: draw_mask(&mut rng),
                }),
            };
            steps.push(step);
        }
        let role = if case % 2 == 0 {
            Role::Server
        } else {
            Role::Client
        };
        let label = format!("close_eof_hostile case={case}");
        let first = drive_checked(&label, &config, role, &steps);
        let second = drive_checked(&label, &config, role, &steps);
        assert_eq!(
            first, second,
            "{label}: the same schedule produced two different observable traces"
        );
        assert!(
            first.terminal_transitions <= 1,
            "{label}: more than one terminal transition"
        );
        if first.first_fatal.is_some() {
            refused += 1;
        } else {
            survived += 1;
        }
    }

    assert!(
        refused >= 1_000,
        "generator degenerated: only {refused} hostile schedules were refused"
    );
    assert!(
        survived >= 200,
        "generator degenerated: only {survived} hostile schedules survived; a generator whose \
         every case dies at the first step explores nothing past it"
    );
}
