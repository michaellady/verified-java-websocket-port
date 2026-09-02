//! US-021 AC2 dedicated fuzz target: **fragment/control sequences**.
//!
//! ## Why this file exists
//!
//! The US-021 fuzz census recorded this family as
//! `SHARED_NO_DEDICATED_TARGET`, and the reason it gave was exact:
//!
//! > Fragment and control sequences ARE generated -- `draw_frame` in
//! > `adversarial_fuzz.rs` draws continuation/text/binary/close/ping/pong and
//! > reserved opcodes, clears FIN one time in five, sets RSV bits, and
//! > `draw_stream` concatenates one to ten such frames with optional garbage
//! > tails and truncations. But they are generated only INSIDE the
//! > frame-decode target: this family has no target of its own, no campaign
//! > bound of its own, and no separately captured artifact.
//!
//! That description of `adversarial_fuzz.rs` is still true, and it is worth
//! saying plainly what it means: those frames are drawn INDEPENDENTLY of one
//! another. `draw_stream` concatenates `draw_frame` results, so a fragment
//! sequence only ever appears there by accident, and the oracles applied to
//! it are no-panic, bounds, determinism, and rechunk invariance -- none of
//! which can observe whether reassembly produced the RIGHT message, because
//! none of them knows what the right message was.
//!
//! This target draws the SEQUENCE, not the frame. It builds a fragmentation
//! program (messages split across a drawn number of fragments, with control
//! frames interleaved at drawn positions), predicts the delivered
//! message/control sequence from a MODEL of the documented state machine,
//! and compares. That is a differential oracle the shared coverage could not
//! express.
//!
//! ## The model
//!
//! The model is written from the documented Java-faithful sites, not from
//! the implementation's control flow:
//!
//! - `framing.rs` `process_frame` data arm: a non-fin data frame during an
//!   open sequence is 1002; an unfragmented (fin) data frame during an open
//!   sequence is 1002; otherwise a non-fin data frame STARTS a sequence and
//!   a fin data frame delivers a message.
//! - `framing.rs` `process_frame_continuous`: a continuation with no open
//!   sequence is 1002; a non-fin continuation whose cumulative total would
//!   exceed `max_buffered_bytes` is `BufferLimitExceeded`; a fin
//!   continuation runs `check_buffer_limit` over the ASSEMBLED size against
//!   `max_message_bytes` (quirk Q23) and then delivers.
//! - `framing.rs` decode: a control frame with an extended-length marker
//!   (>= 126) is 1002 at the length site, a control payload over 125 is
//!   1002, and a non-fin control frame is 1002 after the payload.
//! - `connection.rs` `process_inbound`: ping and pong ONLY record their
//!   events (quirk Q18, no automatic pong) and NEITHER ARM TOUCHES THE
//!   FRAGMENT ACCUMULATOR. That last clause is the one this target exists
//!   to hold: control interleave must be transparent to reassembly.
//!
//! ## Generator domain (stated, because a shrinker below reduces inside it)
//!
//! `draw_program` emits `Vec<FrameSpec>` where each `FrameSpec` carries
//! `{fin, rsv, opcode, payload, masked, escape}`. The MODELED domain is
//! deliberately narrower than the wire: `rsv == 0`, opcodes drawn from
//! `{continuation, text, binary, ping, pong}` only, text payloads drawn as
//! VALID UTF-8, and payload lengths bounded well under the frame-size gate.
//! Close frames are excluded on purpose -- close and EOF are their own AC2
//! family with their own dedicated target
//! (`rust/ws-core/tests/close_eof_fuzz.rs`), and mixing them here would put
//! terminal transitions in the middle of a fragmentation program and make
//! the reassembly model answer a question it was not asked. The HOSTILE
//! family below leaves that domain on purpose and drops the model with it,
//! keeping only the oracles that survive: no panic, bounds, determinism,
//! rechunk invariance.
//!
//! ## RED record (defects planted in shipped source, then removed)
//!
//! - **RED-A** -- the ping arm in `connection.rs` `process_inbound` made to
//!   clear the fragment accumulator. CAUGHT: `interleave_is_transparent`
//!   failed at case 0 with "moving the control frames changed the
//!   reassembled data", and `modeled_programs` and the shrinker pins failed
//!   too. The shared coverage this family used to rely on --
//!   `adversarial_fuzz.rs` -- passed all 14 of its tests under the same
//!   plant. That is the empirical answer to "is the shared coverage enough".
//! - **RED-B** -- `CONTROL_PAYLOAD_LIMIT` moved from 125 to 126. **MISSED by
//!   the entire ws-core suite, this target included**, and the reason is
//!   worth recording rather than patching around: the check it mutates is
//!   UNREACHABLE. A control frame whose payload exceeds 125 bytes needs an
//!   extended-length marker, and `decode_frame_header` rejects
//!   `is_control() && marker >= 126` at the length site BEFORE the
//!   `payload_len > CONTROL_PAYLOAD_LIMIT` comparison it would otherwise
//!   reach; with a marker below 126 the length is at most 125, so the
//!   comparison can never be true. The constant is therefore dead at that
//!   site, the observable behavior is unchanged either way, and no test can
//!   distinguish the two values. `Violation::OversizedControlPayload` below
//!   is consequently exercising the MARKER path, not the limit path, and is
//!   named for what it draws rather than for what rejects it. Nothing was
//!   changed in shipped source over this: the behavior is correct, the
//!   redundancy is deliberate (the comment at the site says it mirrors
//!   Java's call sites), and a campaign that quietly deleted a Java-mirroring
//!   call site to make its own RED reading look better would be worth less
//!   than the reading.
//! - **RED-C** -- the `1002` rejection of an unfragmented data frame arriving
//!   during an open fragment sequence, deleted from `framing.rs`
//!   `process_frame`. CAUGHT: `modeled_programs` failed at case 2 and the
//!   shrinker normal forms failed with it. `adversarial_fuzz.rs` again
//!   passed all 14.
//!
//! ## Deletion attacks on this file's own oracles
//!
//! An oracle nobody removed is an oracle nobody measured.
//!
//! - Collapsing `predict`'s TWO STAGES back into one, on correct shipped
//!   source: `modeled_programs` FAILS. The two-stage split is load-bearing
//!   and is not decoration; a one-stage model would have to be weakened
//!   somewhere else to pass.
//! - Deleting the shrinker's PASS 1 (frame deletion): both shrinker tests
//!   fail.
//! - Deleting the shrinker's PASS 2 (payload truncation): both shrinker tests
//!   fail. Each pass is separately load-bearing, which is the point of
//!   pinning normal forms that need each.
//!
//! ## Claim grade
//!
//! Bounded. Fixed committed seeds, no coverage feedback, no corpus
//! evolution. A campaign that found nothing is evidence about the inputs it
//! drew and about nothing else. Two of the three plants above were caught;
//! the third was not, and the reason it was not is stated rather than
//! rounded off.

#![forbid(unsafe_code)]

use std::panic::{AssertUnwindSafe, catch_unwind};

use ws_core::config::ConnectionConfig;
use ws_core::connection::{
    ConnectionCore, InitialState, Input, ReadyState, Role, WIRE_PENDING_SLACK_BYTES,
};
use ws_core::error::TypedProtocolFailure;
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

/// One frame of a drawn program. `escape` forces a non-canonical length
/// encoding when set; the shipped decoder accepts non-minimal extended
/// lengths on data frames (Java does) and rejects them on control frames.
#[derive(Clone, Debug, PartialEq, Eq)]
struct FrameSpec {
    fin: bool,
    rsv: u8,
    opcode: u8,
    payload: Vec<u8>,
    mask: Option<[u8; 4]>,
    escape: Option<u8>,
}

impl FrameSpec {
    fn render(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.payload.len() + 14);
        let mut first = self.opcode & 0x0f;
        if self.fin {
            first |= 0x80;
        }
        first |= (self.rsv & 0x07) << 4;
        out.push(first);
        let mask_bit = if self.mask.is_some() { 0x80u8 } else { 0 };
        let len = self.payload.len() as u64;
        let escape = match self.escape {
            Some(marker) => marker,
            None if len <= 125 => 0,
            None if len <= 0xffff => 126,
            None => 127,
        };
        match escape {
            126 => {
                out.push(mask_bit | 126);
                out.extend_from_slice(&(len as u16).to_be_bytes());
            }
            127 => {
                out.push(mask_bit | 127);
                out.extend_from_slice(&len.to_be_bytes());
            }
            _ => out.push(mask_bit | (len as u8)),
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

fn render_program(program: &[FrameSpec]) -> Vec<u8> {
    let mut out = Vec::new();
    for frame in program {
        out.extend_from_slice(&frame.render());
    }
    out
}

// ---------------------------------------------------------------------------
// The model: the documented fragment/control state machine, restated.
// ---------------------------------------------------------------------------

/// What an observer should see. Deliberately NOT the core's event type: a
/// model that reuses the implementation's vocabulary tends to reuse its
/// bugs, so this is the transcript vocabulary reduced to what this family
/// is about.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ModelEvent {
    Text(Vec<u8>),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Prediction {
    events: Vec<ModelEvent>,
    /// Index of the first frame the documented rules refuse, if any.
    first_violation: Option<usize>,
}

/// Java's fixed control-payload limit (`translateSingleFramePayloadLength`).
const CONTROL_PAYLOAD_LIMIT: usize = 125;

/// Predict the observable outcome of a program delivered as ONE chunk,
/// inside the MODELED domain.
///
/// Callers outside that domain (rsv set, reserved opcodes, close frames,
/// invalid UTF-8 text) get no prediction: `predict` is only consulted by the
/// modeled families, and the hostile family does not call it.
///
/// ## The two stages, and why the model has to have both
///
/// `ConnectionCore::handle_bytes` runs the chunk in two passes, mirroring
/// derive.go's order (quirk Q25):
///
/// 1. TRANSLATE decodes **every** span in the chunk before any frame is
///    processed. This is where reserved bits, the control-frame fin check,
///    the control-payload limit, the extended-length control marker, the
///    frame-size gate, and close/UTF-8 translate-time semantics live.
/// 2. PROCESS then walks the decoded frames one at a time. This is where the
///    fragment-sequence rules and the buffer limits live.
///
/// The consequence is observable and is NOT a detail: a TRANSLATE-stage
/// rejection anywhere in the chunk means the chunk emits **nothing at all**,
/// including for the frames before it, because processing never started. A
/// PROCESS-stage rejection leaves the earlier frames' events in the queue.
/// The first draft of this model had one stage and predicted the earlier
/// events in both cases; the campaign refused it at case 16 (an oversized
/// ping seven frames in, whose whole chunk vanished). The model was wrong,
/// the core was right, and this is the corrected model.
///
/// It also means a chunk boundary IS observable when a translate-stage
/// rejection is in play -- moving the offending frame into a later chunk
/// preserves the earlier chunk's events. That is why the rechunk-invariance
/// family in this file runs over LEGAL programs only, and says so.
fn predict(program: &[FrameSpec], max_message: usize, max_buffered: usize) -> Prediction {
    // --- stage 1: translate every frame, before any of them is processed ---
    for (index, frame) in program.iter().enumerate() {
        let control = frame.opcode >= 0x8;
        // Header phase: the length marker is read before the payload.
        if control && frame.escape.is_some_and(|marker| marker >= 126) {
            return Prediction {
                events: Vec::new(),
                first_violation: Some(index),
            };
        }
        if control && frame.payload.len() > CONTROL_PAYLOAD_LIMIT {
            return Prediction {
                events: Vec::new(),
                first_violation: Some(index),
            };
        }
        // Post-payload phase: reserved bits, then the control fin check.
        if frame.rsv != 0 || (control && !frame.fin) {
            return Prediction {
                events: Vec::new(),
                first_violation: Some(index),
            };
        }
        assert!(
            matches!(frame.opcode, 0x0 | 0x1 | 0x2 | 0x9 | 0xa),
            "model domain excludes opcode {:#x}",
            frame.opcode
        );
    }

    // --- stage 2: process the decoded frames one at a time -----------------
    let mut events = Vec::new();
    let mut open: Option<u8> = None;
    let mut buffered: Vec<u8> = Vec::new();
    let mut buffered_count: u64 = 0;

    for (index, frame) in program.iter().enumerate() {
        if frame.opcode >= 0x8 {
            match frame.opcode {
                0x9 => events.push(ModelEvent::Ping(frame.payload.clone())),
                0xa => events.push(ModelEvent::Pong(frame.payload.clone())),
                other => panic!("model domain excludes control opcode {other:#x}"),
            }
            // Q18 / process_inbound: neither control arm touches the
            // accumulator. Falling through without touching `open` or
            // `buffered` IS that clause.
            continue;
        }

        if frame.opcode == 0x0 {
            let Some(message_opcode) = open else {
                return Prediction {
                    events,
                    first_violation: Some(index),
                };
            };
            if !frame.fin {
                let next = buffered_count.saturating_add(frame.payload.len() as u64);
                if next > max_buffered as u64 {
                    return Prediction {
                        events,
                        first_violation: Some(index),
                    };
                }
                buffered.extend_from_slice(&frame.payload);
                buffered_count = next;
                continue;
            }
            let assembled_size = buffered.len().saturating_add(frame.payload.len());
            if assembled_size > max_message {
                return Prediction {
                    events,
                    first_violation: Some(index),
                };
            }
            let mut assembled = std::mem::take(&mut buffered);
            assembled.extend_from_slice(&frame.payload);
            buffered_count = 0;
            open = None;
            events.push(if message_opcode == 0x1 {
                ModelEvent::Text(assembled)
            } else {
                ModelEvent::Binary(assembled)
            });
            continue;
        }

        // Unfragmented or starting data frame.
        if open.is_some() {
            return Prediction {
                events,
                first_violation: Some(index),
            };
        }
        if !frame.fin {
            if frame.payload.len() > max_message {
                return Prediction {
                    events,
                    first_violation: Some(index),
                };
            }
            open = Some(frame.opcode);
            buffered = frame.payload.clone();
            buffered_count = frame.payload.len() as u64;
            continue;
        }
        events.push(if frame.opcode == 0x1 {
            ModelEvent::Text(frame.payload.clone())
        } else {
            ModelEvent::Binary(frame.payload.clone())
        });
    }

    Prediction {
        events,
        first_violation: None,
    }
}

// ---------------------------------------------------------------------------
// Driving the core.
// ---------------------------------------------------------------------------

/// Corpus-default limits with generous queues: backpressure is a different
/// AC2 family with its own dedicated target, and an eagerly draining owner
/// must never meet it here.
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
    /// Every drained event kind, chunk events excluded -- the rechunk-safe
    /// projection.
    kinds: Vec<SemanticEventKind>,
    writes: Vec<Vec<u8>>,
    fatal: Option<TypedProtocolFailure>,
    final_state: ReadyState,
}

/// Feed `chunks` to a core and drain everything, checking the bounds oracles
/// after every input. Never panics for a modeled reason: a panic here is the
/// no-panic oracle firing.
fn drive(config: &ConnectionConfig, role: Role, chunks: &[Vec<u8>]) -> Outcome {
    let mut core = ConnectionCore::new_in_state(config.clone(), role, InitialState::Open);
    let mut events = Vec::new();
    let mut kinds = Vec::new();
    let mut writes = Vec::new();
    let mut fatal = None;
    let mut terminal_transitions = 0usize;

    for chunk in chunks {
        let result = core.handle(Input::TransportBytes(chunk));
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
                SemanticEventKind::Binary { data } => {
                    events.push(ModelEvent::Binary(data.clone()));
                }
                SemanticEventKind::Ping { data } => events.push(ModelEvent::Ping(data.clone())),
                SemanticEventKind::Pong { data } => events.push(ModelEvent::Pong(data.clone())),
                SemanticEventKind::Transition { to, .. } if *to == ReadyState::Closed => {
                    terminal_transitions += 1;
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
            counts.message_buffered_bytes
                <= (config.max_buffered_bytes() as u64).max(config.max_message_bytes() as u64),
            "fragment reassembly exceeded its cap"
        );
        assert!(
            terminal_transitions <= 1,
            "more than one terminal transition to Closed"
        );

        if let Err(failure) = result
            && failure.code.is_fatal()
        {
            if fatal.is_none() {
                fatal = Some(failure);
            }
            break;
        }
    }

    Outcome {
        events,
        kinds,
        writes,
        fatal,
        final_state: core.state(),
    }
}

fn drive_checked(
    label: &str,
    config: &ConnectionConfig,
    role: Role,
    chunks: &[Vec<u8>],
) -> Outcome {
    match catch_unwind(AssertUnwindSafe(|| drive(config, role, chunks))) {
        Ok(outcome) => outcome,
        Err(payload) => {
            let detail = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("non-string panic payload");
            panic!("{label}: panic caught by the fragment/control oracle: {detail}");
        }
    }
}

/// Split `bytes` into drawn chunks. Used by the rechunk-invariance oracle.
fn rechunk(rng: &mut SplitMix64, bytes: &[u8], strategy: u8) -> Vec<Vec<u8>> {
    match strategy {
        0 => vec![bytes.to_vec()],
        1 => bytes.chunks(1).map(<[u8]>::to_vec).collect(),
        _ => {
            let mut chunks = Vec::new();
            let mut offset = 0usize;
            while offset < bytes.len() {
                let remaining = bytes.len() - offset;
                let take = 1 + rng.below(remaining as u64) as usize;
                chunks.push(bytes[offset..offset + take].to_vec());
                offset += take;
            }
            if chunks.is_empty() {
                chunks.push(Vec::new());
            }
            chunks
        }
    }
}

// ---------------------------------------------------------------------------
// Generators.
// ---------------------------------------------------------------------------

/// Valid UTF-8 of a drawn length, so the modeled family never trips the
/// strict process-time 1007 gate -- that gate belongs to the message/UTF-8
/// family, which has its own target.
fn draw_valid_utf8(rng: &mut SplitMix64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 3);
    while out.len() < len {
        match rng.below(6) {
            0..=3 => out.push(0x20 + (rng.byte() % 0x5e)),
            4 => {
                out.push(0xc2 | (rng.byte() & 0x01));
                out.push(0x80 | (rng.byte() & 0x3f));
            }
            _ => {
                out.push(0xe1 + (rng.byte() % 0x0c));
                out.push(0x80 | (rng.byte() & 0x3f));
                out.push(0x80 | (rng.byte() & 0x3f));
            }
        }
    }
    // Truncating could split a scalar, so re-validate and trim back to the
    // last boundary instead.
    while !out.is_empty() && std::str::from_utf8(&out).is_err() {
        out.pop();
    }
    out
}

fn draw_mask(rng: &mut SplitMix64) -> Option<[u8; 4]> {
    if rng.chance(2) {
        Some([rng.byte(), rng.byte(), rng.byte(), rng.byte()])
    } else {
        None
    }
}

/// A data frame's payload, valid for its opcode.
fn draw_data_payload(rng: &mut SplitMix64, opcode: u8, len: usize) -> Vec<u8> {
    if opcode == 0x1 {
        draw_valid_utf8(rng, len)
    } else {
        (0..len).map(|_| rng.byte()).collect()
    }
}

/// One control frame inside the modeled domain: fin, canonical length,
/// payload at or under the limit, biased onto the 0/1/124/125 boundary.
fn draw_legal_control(rng: &mut SplitMix64) -> FrameSpec {
    let sites: [usize; 6] = [0, 1, 2, 24, 124, 125];
    let len = if rng.chance(2) {
        sites[rng.below(sites.len() as u64) as usize]
    } else {
        rng.below(40) as usize
    };
    FrameSpec {
        fin: true,
        rsv: 0,
        opcode: if rng.chance(2) { 0x9 } else { 0xa },
        payload: (0..len).map(|_| rng.byte()).collect(),
        mask: draw_mask(rng),
        escape: None,
    }
}

/// Split one message into a drawn number of fragments. This is the shape the
/// shared coverage could not produce: the fragments are drawn TOGETHER, from
/// one payload, so reassembly has a right answer.
fn fragment_message(
    rng: &mut SplitMix64,
    opcode: u8,
    payload: &[u8],
    parts: usize,
) -> Vec<FrameSpec> {
    let mut cuts: Vec<usize> = Vec::new();
    for _ in 1..parts {
        cuts.push(rng.below(payload.len() as u64 + 1) as usize);
    }
    cuts.sort_unstable();
    let mut bounds = vec![0usize];
    bounds.extend(cuts);
    bounds.push(payload.len());

    let mut frames = Vec::with_capacity(parts);
    for index in 0..parts {
        let slice = payload[bounds[index]..bounds[index + 1]].to_vec();
        let last = index + 1 == parts;
        frames.push(FrameSpec {
            fin: last,
            rsv: 0,
            opcode: if index == 0 { opcode } else { 0x0 },
            payload: slice,
            mask: draw_mask(rng),
            escape: if rng.chance(8) { Some(127) } else { None },
        });
    }
    frames
}

/// The violation menu. Each entry is a single frame that the documented
/// rules refuse in the state the program has reached, injected at a drawn
/// index so the events BEFORE it still have to match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Violation {
    OrphanContinuation,
    StartDuringOpenSequence,
    UnfragmentedDuringOpenSequence,
    NonFinControl,
    OversizedControlPayload,
    ControlWithExtendedLengthMarker,
}

const VIOLATIONS: [Violation; 6] = [
    Violation::OrphanContinuation,
    Violation::StartDuringOpenSequence,
    Violation::UnfragmentedDuringOpenSequence,
    Violation::NonFinControl,
    Violation::OversizedControlPayload,
    Violation::ControlWithExtendedLengthMarker,
];

fn violation_frame(rng: &mut SplitMix64, violation: Violation) -> FrameSpec {
    let mask = draw_mask(rng);
    match violation {
        Violation::OrphanContinuation => FrameSpec {
            fin: rng.chance(2),
            rsv: 0,
            opcode: 0x0,
            payload: (0..rng.below(8)).map(|_| rng.byte()).collect(),
            mask,
            escape: None,
        },
        Violation::StartDuringOpenSequence => FrameSpec {
            fin: false,
            rsv: 0,
            opcode: if rng.chance(2) { 0x1 } else { 0x2 },
            payload: Vec::new(),
            mask,
            escape: None,
        },
        Violation::UnfragmentedDuringOpenSequence => FrameSpec {
            fin: true,
            rsv: 0,
            opcode: 0x2,
            payload: (0..rng.below(8)).map(|_| rng.byte()).collect(),
            mask,
            escape: None,
        },
        Violation::NonFinControl => FrameSpec {
            fin: false,
            rsv: 0,
            opcode: if rng.chance(2) { 0x9 } else { 0xa },
            payload: (0..rng.below(8)).map(|_| rng.byte()).collect(),
            mask,
            escape: None,
        },
        Violation::OversizedControlPayload => FrameSpec {
            fin: true,
            rsv: 0,
            opcode: 0x9,
            payload: (0..126 + rng.below(40)).map(|_| rng.byte()).collect(),
            mask,
            escape: None,
        },
        Violation::ControlWithExtendedLengthMarker => FrameSpec {
            fin: true,
            rsv: 0,
            opcode: 0xa,
            payload: (0..rng.below(8)).map(|_| rng.byte()).collect(),
            mask,
            escape: Some(if rng.chance(2) { 126 } else { 127 }),
        },
    }
}

/// Draw a fragmentation program inside the modeled domain.
///
/// Shape: one to three messages, each unfragmented or split into two to six
/// fragments, with legal control frames interleaved at drawn positions --
/// including BETWEEN fragments, which is the transparency clause. With
/// probability one in three, one violation from the menu is injected at a
/// drawn index; the injected kinds that need an open sequence
/// (`StartDuringOpenSequence`, `UnfragmentedDuringOpenSequence`) are placed
/// only where one is open, and `OrphanContinuation` only where none is.
fn draw_program(rng: &mut SplitMix64) -> Vec<FrameSpec> {
    let mut program: Vec<FrameSpec> = Vec::new();
    let messages = 1 + rng.below(3) as usize;
    for _ in 0..messages {
        let opcode = if rng.chance(2) { 0x1 } else { 0x2 };
        let len = if rng.chance(3) {
            0
        } else {
            rng.below(180) as usize
        };
        let payload = draw_data_payload(rng, opcode, len);
        let parts = if rng.chance(3) {
            1
        } else {
            2 + rng.below(5) as usize
        };
        let fragments = fragment_message(rng, opcode, &payload, parts);
        for (index, frame) in fragments.into_iter().enumerate() {
            // A control frame BEFORE a continuation is the interesting
            // position: it is the one that proves the accumulator is
            // untouched.
            if index > 0 && rng.chance(2) {
                program.push(draw_legal_control(rng));
            }
            program.push(frame);
        }
        if rng.chance(3) {
            program.push(draw_legal_control(rng));
        }
    }

    if rng.chance(3) {
        let violation = VIOLATIONS[rng.below(VIOLATIONS.len() as u64) as usize];
        let frame = violation_frame(rng, violation);
        // Find the indices where this violation is actually a violation, by
        // asking the model rather than by re-deriving the state here.
        let mut candidates = Vec::new();
        for index in 0..=program.len() {
            let mut probe = program.clone();
            probe.insert(index, frame.clone());
            let prediction = predict(&probe, 65_536, 65_536);
            if prediction.first_violation == Some(index) {
                candidates.push(index);
            }
        }
        if !candidates.is_empty() {
            let at = candidates[rng.below(candidates.len() as u64) as usize];
            program.insert(at, frame);
        }
    }

    program
}

/// A hostile program: OUTSIDE the modeled domain on purpose. RSV bits,
/// reserved opcodes, control frames of every shape, deep fragment chains,
/// truncated tails. No model is predicted for these -- only the oracles that
/// survive leaving the domain.
fn draw_hostile_program(rng: &mut SplitMix64) -> Vec<u8> {
    let frames = 1 + rng.below(8) as usize;
    let mut bytes = Vec::new();
    for _ in 0..frames {
        let opcode: u8 = match rng.below(16) {
            0..=3 => 0x0,
            4..=5 => 0x1,
            6..=7 => 0x2,
            8..=10 => 0x9,
            11..=12 => 0xa,
            13 => 0x3 + (rng.byte() % 5),
            _ => 0xb + (rng.byte() % 5),
        };
        let len = if rng.chance(3) {
            [0usize, 1, 124, 125, 126, 127, 200][rng.below(7) as usize]
        } else {
            rng.below(120) as usize
        };
        let spec = FrameSpec {
            fin: !rng.chance(3),
            rsv: if rng.chance(4) { 1 << rng.below(3) } else { 0 },
            opcode,
            payload: (0..len).map(|_| rng.byte()).collect(),
            mask: draw_mask(rng),
            escape: if rng.chance(6) {
                Some(if rng.chance(2) { 126 } else { 127 })
            } else {
                None
            },
        };
        bytes.extend_from_slice(&spec.render());
    }
    if rng.chance(4) && !bytes.is_empty() {
        let keep = rng.below(bytes.len() as u64) as usize;
        bytes.truncate(keep);
    }
    bytes
}

// ---------------------------------------------------------------------------
// Family 1: the model differential.
// ---------------------------------------------------------------------------

/// Drawn fragmentation programs, driven whole, compared against the model.
///
/// This is the oracle the shared coverage in `adversarial_fuzz.rs` could not
/// state: it does not ask whether the core survived, it asks whether the core
/// delivered the RIGHT messages in the RIGHT order, and refused at exactly
/// the frame the documented rules refuse.
#[test]
fn fragment_control_modeled_programs() {
    let config = target_config();
    let mut rng = SplitMix64::new(0xfc70_0001);
    let mut with_violation = 0usize;
    let mut without_violation = 0usize;
    let mut interleaved_control = 0usize;
    let mut multi_fragment = 0usize;

    for case in 0..8_000u32 {
        let program = draw_program(&mut rng);
        let prediction = predict(
            &program,
            config.max_message_bytes(),
            config.max_buffered_bytes(),
        );
        let bytes = render_program(&program);
        let role = if case % 2 == 0 {
            Role::Server
        } else {
            Role::Client
        };
        let label = format!("fragment_control_modeled_programs case={case}");
        let outcome = drive_checked(&label, &config, role, &[bytes]);

        let shape: Vec<(bool, u8, usize, bool, Option<u8>)> = program
            .iter()
            .map(|frame| {
                (
                    frame.fin,
                    frame.opcode,
                    frame.payload.len(),
                    frame.mask.is_some(),
                    frame.escape,
                )
            })
            .collect();
        assert_eq!(
            outcome.events, prediction.events,
            "{label}: delivered sequence differs from the model\n\
             model_violation={:?} observed_fatal={:?}\n\
             shape (fin, opcode, payload_len, masked, escape) = {shape:?}",
            prediction.first_violation, outcome.fatal
        );
        assert_eq!(
            outcome.fatal.is_some(),
            prediction.first_violation.is_some(),
            "{label}: fatal-refusal disagreement (model says {:?})\nprogram={program:#?}",
            prediction.first_violation
        );

        if prediction.first_violation.is_some() {
            with_violation += 1;
        } else {
            without_violation += 1;
        }
        if program.iter().any(|frame| frame.opcode >= 0x8) {
            interleaved_control += 1;
        }
        if program.iter().any(|frame| frame.opcode == 0x0) {
            multi_fragment += 1;
        }
    }

    // Coverage floors: a generator that degenerated into one shape would
    // still pass every oracle above, so the campaign asserts it did not.
    assert!(
        with_violation >= 800,
        "generator degenerated: only {with_violation} programs carried a modeled violation"
    );
    assert!(
        without_violation >= 800,
        "generator degenerated: only {without_violation} programs were violation-free"
    );
    assert!(
        interleaved_control >= 2_000,
        "generator degenerated: only {interleaved_control} programs carried a control frame"
    );
    assert!(
        multi_fragment >= 2_000,
        "generator degenerated: only {multi_fragment} programs carried a continuation"
    );
}

// ---------------------------------------------------------------------------
// Family 2: control interleave is transparent to reassembly.
// ---------------------------------------------------------------------------

/// The same message, the same fragmentation, the control frames MOVED.
///
/// `process_inbound`'s ping/pong arms return before the accumulator is
/// touched, and the doc comment says so ("neither arm touches the fragment
/// accumulator"). A doc comment binds nothing. This does: the delivered data
/// events must be identical no matter where the control frames sit, and the
/// control events must be exactly the ones that were inserted.
#[test]
fn fragment_control_interleave_is_transparent_to_reassembly() {
    let config = target_config();
    let mut rng = SplitMix64::new(0xfc70_0002);
    let mut moved_positions = 0usize;

    for case in 0..4_000u32 {
        let opcode = if rng.chance(2) { 0x1 } else { 0x2 };
        let len = rng.below(200) as usize;
        let payload = draw_data_payload(&mut rng, opcode, len);
        let parts = 2 + rng.below(6) as usize;
        let fragments = fragment_message(&mut rng, opcode, &payload, parts);

        let controls: Vec<FrameSpec> = (0..1 + rng.below(3))
            .map(|_| draw_legal_control(&mut rng))
            .collect();

        // Two different legal placements of the SAME control frames.
        let place = |rng: &mut SplitMix64, fragments: &[FrameSpec]| -> Vec<FrameSpec> {
            let mut program = Vec::new();
            let mut pending: Vec<FrameSpec> = controls.clone();
            for (index, frame) in fragments.iter().enumerate() {
                // Controls may sit anywhere except before the opening
                // fragment, where they would be legal but would not test
                // interleave.
                while index > 0 && !pending.is_empty() && rng.chance(2) {
                    program.push(pending.remove(0));
                }
                program.push(frame.clone());
            }
            program.extend(pending);
            program
        };

        let first = place(&mut rng, &fragments);
        let second = place(&mut rng, &fragments);
        if first != second {
            moved_positions += 1;
        }

        let label = format!("fragment_control_interleave case={case}");
        let outcome_a = drive_checked(&label, &config, Role::Server, &[render_program(&first)]);
        let outcome_b = drive_checked(&label, &config, Role::Server, &[render_program(&second)]);

        let data_only = |events: &[ModelEvent]| -> Vec<ModelEvent> {
            events
                .iter()
                .filter(|event| matches!(event, ModelEvent::Text(_) | ModelEvent::Binary(_)))
                .cloned()
                .collect()
        };
        let control_only = |events: &[ModelEvent]| -> Vec<ModelEvent> {
            events
                .iter()
                .filter(|event| matches!(event, ModelEvent::Ping(_) | ModelEvent::Pong(_)))
                .cloned()
                .collect()
        };

        assert_eq!(
            data_only(&outcome_a.events),
            data_only(&outcome_b.events),
            "{label}: moving the control frames changed the reassembled data"
        );
        assert_eq!(
            control_only(&outcome_a.events),
            control_only(&outcome_b.events),
            "{label}: moving the control frames changed the control observations"
        );

        // And the delivered message is the payload that was fragmented --
        // the reassembly identity itself, not merely agreement between two
        // runs of the same implementation.
        let expected = if opcode == 0x1 {
            ModelEvent::Text(payload.clone())
        } else {
            ModelEvent::Binary(payload.clone())
        };
        assert_eq!(
            data_only(&outcome_a.events),
            vec![expected],
            "{label}: reassembly did not reproduce the fragmented payload"
        );
        assert!(
            outcome_a.fatal.is_none() && outcome_b.fatal.is_none(),
            "{label}: a legal interleaved fragmentation was refused"
        );
        assert_eq!(
            control_only(&outcome_a.events).len(),
            controls.len(),
            "{label}: an interleaved control frame was swallowed"
        );
    }

    assert!(
        moved_positions >= 1_500,
        "generator degenerated: only {moved_positions} cases actually moved a control frame"
    );
}

// ---------------------------------------------------------------------------
// Family 3: split invariance.
// ---------------------------------------------------------------------------

/// One payload, two different fragmentations, and three transport chunkings
/// of each. Every combination must deliver the same message.
///
/// Where the interleave family holds the fragmentation fixed and moves the
/// controls, this one holds the payload fixed and moves the FRAGMENT
/// boundaries -- and then moves the TRANSPORT boundaries underneath both,
/// which is a different axis again (a frame boundary is a protocol event; a
/// chunk boundary must not be one).
#[test]
fn fragment_split_and_rechunk_invariance() {
    let config = target_config();
    let mut rng = SplitMix64::new(0xfc70_0003);
    let mut distinct_splits = 0usize;

    for case in 0..3_000u32 {
        let opcode = if rng.chance(2) { 0x1 } else { 0x2 };
        let len = 1 + rng.below(220) as usize;
        let payload = draw_data_payload(&mut rng, opcode, len);
        let first_parts = 2 + rng.below(6) as usize;
        let first = fragment_message(&mut rng, opcode, &payload, first_parts);
        let second_parts = 2 + rng.below(6) as usize;
        let second = fragment_message(&mut rng, opcode, &payload, second_parts);
        if first.len() != second.len() {
            distinct_splits += 1;
        }

        let expected = if opcode == 0x1 {
            ModelEvent::Text(payload.clone())
        } else {
            ModelEvent::Binary(payload.clone())
        };

        for (which, program) in [("a", &first), ("b", &second)] {
            let bytes = render_program(program);
            let label = format!("fragment_split_and_rechunk case={case} split={which}");
            let mut baseline: Option<(Vec<SemanticEventKind>, Vec<Vec<u8>>, ReadyState)> = None;
            for strategy in 0..3u8 {
                let chunks = rechunk(&mut rng, &bytes, strategy);
                let outcome = drive_checked(&label, &config, Role::Server, &chunks);
                assert!(
                    outcome.fatal.is_none(),
                    "{label} strategy={strategy}: a legal fragmentation was refused"
                );
                assert_eq!(
                    outcome.events,
                    vec![expected.clone()],
                    "{label} strategy={strategy}: reassembly did not reproduce the payload"
                );
                match &baseline {
                    None => {
                        baseline = Some((outcome.kinds, outcome.writes, outcome.final_state));
                    }
                    Some((kinds, writes, state)) => {
                        assert_eq!(
                            &outcome.kinds, kinds,
                            "{label} strategy={strategy}: rechunking changed the event stream"
                        );
                        assert_eq!(
                            &outcome.writes, writes,
                            "{label} strategy={strategy}: rechunking changed the write stream"
                        );
                        assert_eq!(
                            outcome.final_state, *state,
                            "{label} strategy={strategy}: rechunking changed the final state"
                        );
                    }
                }
            }
        }
    }

    assert!(
        distinct_splits >= 1_000,
        "generator degenerated: only {distinct_splits} cases drew two different fragment counts"
    );
}

// ---------------------------------------------------------------------------
// Family 4: hostile soup, outside the modeled domain.
// ---------------------------------------------------------------------------

/// RSV bits, reserved opcodes, malformed control frames, truncated tails.
/// No model: only no-panic, the bounds oracles inside `drive`, and
/// determinism.
#[test]
fn fragment_control_hostile_soup_no_panic_deterministic() {
    let config = target_config();
    let mut rng = SplitMix64::new(0xfc70_0004);
    let mut refused = 0usize;
    let mut survived = 0usize;

    for case in 0..6_000u32 {
        let bytes = draw_hostile_program(&mut rng);
        let role = if case % 2 == 0 {
            Role::Server
        } else {
            Role::Client
        };
        let label = format!("fragment_control_hostile case={case}");
        let first = drive_checked(&label, &config, role, std::slice::from_ref(&bytes));
        let second = drive_checked(&label, &config, role, std::slice::from_ref(&bytes));
        assert_eq!(
            first, second,
            "{label}: the same bytes produced two different observable traces"
        );
        if first.fatal.is_some() {
            refused += 1;
        } else {
            survived += 1;
        }
    }

    assert!(
        refused >= 1_000,
        "generator degenerated: only {refused} hostile programs were refused"
    );
    assert!(
        survived >= 300,
        "generator degenerated: only {survived} hostile programs survived; a generator whose \
         every case dies at the first byte explores nothing past it"
    );
}

// ---------------------------------------------------------------------------
// The program-level shrinker.
// ---------------------------------------------------------------------------

/// Shrink a refused program to a 1-MINIMAL one.
///
/// **Generator domain.** `Vec<FrameSpec>` as produced by `draw_program`: a
/// sequence of frames, each `{fin, rsv, opcode, payload, mask, escape}`,
/// rendered by `FrameSpec::render`.
///
/// **Preserved property.** `still_fails` -- the rendered program is refused
/// by the core with a FATAL failure. Note what is deliberately NOT
/// preserved: the particular failure code. A shrinker that pinned the code
/// would refuse reductions that reach the same defect by a shorter route,
/// and this shrinker's job is to produce the shortest witness that anything
/// went fatally wrong.
///
/// **Reduction.** Two passes, applied to fixpoint:
///
/// 1. FRAME DELETION -- try removing each frame; keep the removal when the
///    program still fails. Strictly decreases the frame count.
/// 2. PAYLOAD TRUNCATION -- for each surviving frame, try emptying its
///    payload; keep it when the program still fails. Strictly decreases the
///    total payload length and never the frame count.
///
/// Pass 2 exists because pass 1 alone cannot reduce a witness whose LENGTH
/// is the property (an oversized control payload cannot lose its frame
/// without losing the failure), which is the same reason the handshake
/// shrinker in `handshake_fuzz.rs` needs its byte-simplification pass.
///
/// **Bound.** Each pass strictly decreases a non-negative measure (frame
/// count, then total payload bytes), so the fixpoint loop terminates; the
/// loop is additionally capped at `program.len() + 1` rounds, which is a
/// DOMAIN bound (there are that many frames to delete and no more), not a
/// liveness guard.
///
/// **1-minimality.** On return, no single frame can be deleted and no single
/// payload emptied without the program ceasing to fail. That is asserted,
/// not assumed.
fn shrink_program(config: &ConnectionConfig, role: Role, program: &[FrameSpec]) -> Vec<FrameSpec> {
    let still_fails = |candidate: &[FrameSpec]| -> bool {
        if candidate.is_empty() {
            return false;
        }
        let bytes = render_program(candidate);
        drive(config, role, &[bytes]).fatal.is_some()
    };
    assert!(
        still_fails(program),
        "shrink_program requires a program that already fails"
    );

    let mut current = program.to_vec();
    for _ in 0..=program.len() {
        let before = current.clone();

        let mut index = 0usize;
        while index < current.len() {
            let mut candidate = current.clone();
            candidate.remove(index);
            if still_fails(&candidate) {
                current = candidate;
            } else {
                index += 1;
            }
        }

        for index in 0..current.len() {
            if current[index].payload.is_empty() {
                continue;
            }
            let mut candidate = current.clone();
            candidate[index].payload = Vec::new();
            if still_fails(&candidate) {
                current = candidate;
            }
        }

        if current == before {
            break;
        }
    }
    current
}

/// The shrinker reaches 1-minimal witnesses, and the witnesses are smaller.
#[test]
fn fragment_control_shrinker_reaches_1_minimal_witnesses() {
    let config = target_config();
    let mut rng = SplitMix64::new(0xfc70_0005);
    let mut witnessed = 0usize;
    let mut original_frames = 0usize;
    let mut shrunk_frames = 0usize;

    for case in 0..200u32 {
        let program = draw_program(&mut rng);
        let bytes = render_program(&program);
        if drive(&config, Role::Server, &[bytes]).fatal.is_none() {
            continue;
        }
        witnessed += 1;
        let shrunk = shrink_program(&config, Role::Server, &program);
        original_frames += program.len();
        shrunk_frames += shrunk.len();

        assert!(
            !shrunk.is_empty(),
            "case={case}: the shrinker reduced a failing program to nothing"
        );
        assert!(
            shrunk.len() <= program.len(),
            "case={case}: the shrinker grew the program"
        );
        assert!(
            drive(&config, Role::Server, &[render_program(&shrunk)])
                .fatal
                .is_some(),
            "case={case}: the shrunk program no longer fails"
        );

        // 1-minimality, checked rather than claimed.
        for index in 0..shrunk.len() {
            let mut candidate = shrunk.clone();
            candidate.remove(index);
            let fails = !candidate.is_empty()
                && drive(&config, Role::Server, &[render_program(&candidate)])
                    .fatal
                    .is_some();
            assert!(
                !fails,
                "case={case}: frame {index} could still be deleted; the result is not 1-minimal"
            );
        }
        for index in 0..shrunk.len() {
            if shrunk[index].payload.is_empty() {
                continue;
            }
            let mut candidate = shrunk.clone();
            candidate[index].payload = Vec::new();
            assert!(
                drive(&config, Role::Server, &[render_program(&candidate)])
                    .fatal
                    .is_none(),
                "case={case}: frame {index}'s payload could still be emptied; not 1-minimal"
            );
        }
    }

    assert!(
        witnessed >= 30,
        "only {witnessed} refused programs were drawn; the shrinker was barely exercised"
    );
    assert!(
        shrunk_frames < original_frames,
        "the shrinker reduced nothing across {witnessed} witnesses \
         ({original_frames} frames in, {shrunk_frames} out)"
    );
}

/// Byte-pinned normal forms, so the shrinker cannot silently stop reducing.
///
/// Each case is a program that fails, together with the EXACT program the
/// shrinker must return. A shrinker that regressed to a no-op would still
/// satisfy every property in the campaign above (a no-op preserves the
/// failure and is trivially "not larger"); only pinned normal forms catch
/// that, which is why they are here.
///
/// The last case is the one that needs pass 2 and cannot be reached by
/// deletion alone: an oversized control payload's LENGTH is the property, so
/// the frame must stay and only its payload can shrink -- and it must shrink
/// only to the extent that keeps the failure, which for a 126-byte control
/// payload is not at all.
#[test]
fn fragment_control_shrinker_normal_forms_are_pinned() {
    let config = target_config();
    let ping = |len: usize, fin: bool| FrameSpec {
        fin,
        rsv: 0,
        opcode: 0x9,
        payload: vec![0x41; len],
        mask: None,
        escape: None,
    };
    let text = |fin: bool, len: usize| FrameSpec {
        fin,
        rsv: 0,
        opcode: 0x1,
        payload: vec![0x61; len],
        mask: None,
        escape: None,
    };
    let cont = |fin: bool, len: usize| FrameSpec {
        fin,
        rsv: 0,
        opcode: 0x0,
        payload: vec![0x62; len],
        mask: None,
        escape: None,
    };

    // 1. An orphan continuation buried behind legal traffic reduces to
    //    itself alone, with an emptied payload.
    let case1 = vec![text(true, 5), ping(3, true), cont(true, 4), text(true, 2)];
    assert_eq!(
        shrink_program(&config, Role::Server, &case1),
        vec![cont(true, 0)],
        "orphan-continuation normal form"
    );

    // 2. A non-fin control frame reduces to itself alone, emptied. The
    //    surrounding traffic is deliberately COMPLETE messages: an earlier
    //    draft wrapped the non-fin ping in an open fragment sequence, and the
    //    shrinker correctly found the shorter witness that sequence left
    //    behind (a bare orphan continuation) instead. The pin now isolates
    //    the frame it names.
    let case2 = vec![text(true, 4), ping(2, false), text(true, 3)];
    assert_eq!(
        shrink_program(&config, Role::Server, &case2),
        vec![ping(0, false)],
        "non-fin-control normal form"
    );

    // 3. An unfragmented data frame during an open sequence keeps the frame
    //    that OPENS the sequence: deleting it removes the violation, so the
    //    normal form has two frames and neither can go.
    let case3 = vec![text(false, 6), ping(1, true), text(true, 3)];
    assert_eq!(
        shrink_program(&config, Role::Server, &case3),
        vec![text(false, 0), text(true, 0)],
        "start-then-unfragmented normal form"
    );

    // 4. The pin that keeps pass 2 honest in the OTHER direction. A
    //    126-byte control payload breaches the fixed control limit: the
    //    frame cannot be deleted (nothing else here fails) and its payload
    //    cannot be emptied (a 0-byte ping is legal), so the normal form is
    //    the frame at its ORIGINAL length. A pass 2 that emptied payloads
    //    unconditionally -- the obvious wrong implementation -- would return
    //    a ping(0) here and would no longer fail, which the campaign's
    //    "the shrunk program no longer fails" assertion catches; a pass 2
    //    that emptied them and then reverted the whole shrink would return
    //    the three-frame input, which this pin catches.
    let case4 = vec![text(true, 3), ping(126, true), text(true, 3)];
    assert_eq!(
        shrink_program(&config, Role::Server, &case4),
        vec![ping(126, true)],
        "oversized-control normal form"
    );
}
