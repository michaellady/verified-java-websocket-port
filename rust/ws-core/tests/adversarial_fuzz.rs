//! E1 adversarial-evidence lane: the deterministic byte-fuzz campaign
//! driving `ConnectionCore` end to end (gap G5 of the US-010..016
//! AC-closure dossier; the 2026-08-27 owner amendment amends BEHAVIOR
//! clauses to Java-faithful but does NOT waive this evidence machinery).
//!
//! Zero new dependencies: a hand-rolled SplitMix64 PRNG from fixed
//! committed seeds generates every case, so each family is deterministic
//! and re-runnable byte for byte. All generators here are written
//! independently of the shipped encoder (raw header/byte construction, an
//! in-test XOR mask), so a shared-bug generator cannot mask a defect.
//!
//! ## Families (counts are fixed in each test)
//!
//! 1. `byte_soup` — random transport chunks, replayed twice (determinism).
//! 2. `frame_soup` — structured random frames (valid/invalid opcodes, FIN
//!    and RSV bits, both maskings, boundary lengths 0/1/125/126/127,
//!    noncanonical 16/64-bit escapes, close payloads with hostile
//!    code/reason pairs, invalid UTF-8 text), garbage tails, truncations.
//! 3. `rechunk_invariance` — one stream, three chunkings (whole,
//!    byte-at-a-time, seeded random splits): identical observable outcome.
//! 4. `command_interleave` — random local commands mixed with bytes/EOF.
//! 5. `config_boundary` — random configurations at limit minima/ceilings,
//!    plus out-of-range builder probes.
//! 6. `queue_pressure` — undersized event/write queues: refusals must be
//!    typed `Backpressure`, never a panic or a partial mutation.
//! 7. `seed_anchors` — every committed `fuzz-seeds/**/*.hex` corpus file
//!    replayed under three core setups and three chunkings.
//! 8. `declared_length_headers` — curated hostile length declarations
//!    (65536/65537, 2^63 high bit, `u64::MAX`, extended-length controls).
//!
//! ## Oracles (checked on every case)
//!
//! - **No panic**: every drive runs under `catch_unwind`; a core panic
//!   fails the case with its seed label.
//! - **Bounded allocation**: drained events/writes per input never exceed
//!   the configured queue capacities; `counts` respect
//!   `max_input_bytes`, `max_buffered_bytes` (+ the pinned Q24 wire slack),
//!   and the wire/message decomposition identity.
//! - **Determinism**: same seed + same chunking => byte-identical full
//!   trace (results, events, writes, counts, state, close detail).
//! - **Rechunking invariance**: same bytes under any chunking => identical
//!   normalized observables (non-chunk events, write stream, final state,
//!   close detail, fatal failure).
//! - **State-machine sanity**: at most one terminal transition to Closed
//!   (exactly-once terminal); after the first fatal failure the core is
//!   poisoned — every later input returns `StateViolation` and emits no
//!   event or write.

#![forbid(unsafe_code)]

use std::panic::{AssertUnwindSafe, catch_unwind};

use ws_core::close::CloseDetail;
use ws_core::config::{ConnectionConfig, LimitField};
use ws_core::connection::{
    ConnectionCore, DataOpcode, InitialState, Input, LocalCommand, ReadyState, Role,
    WIRE_PENDING_SLACK_BYTES,
};
use ws_core::error::{FailureCode, TypedProtocolFailure};
use ws_core::event::{Counts, SemanticEvent, SemanticEventKind};

// ---------------------------------------------------------------------------
// Deterministic PRNG (SplitMix64) — fixed committed seeds only.
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
        assert!(n > 0);
        self.next_u64() % n
    }

    fn byte(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }

    fn chance(&mut self, one_in: u64) -> bool {
        self.below(one_in) == 0
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.byte()).collect()
    }
}

// ---------------------------------------------------------------------------
// Trace capture and the per-step invariant oracles.
// ---------------------------------------------------------------------------

/// One owned fuzz input (the borrowed `Input` is rebuilt per call).
#[derive(Debug, Clone, PartialEq, Eq)]
enum FuzzStep {
    Bytes(Vec<u8>),
    Eof,
    Command(LocalCommand),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StepRecord {
    result: Result<(), TypedProtocolFailure>,
    events: Vec<SemanticEvent>,
    writes: Vec<Vec<u8>>,
}

/// The FULL observable state of a core between inputs: ready state, every
/// counter (which carries the buffered/pending byte state), and the close
/// detail. Captured before each input so a refused input can be proven to
/// have changed nothing — see the backpressure-atomicity oracle in `drive`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Observable {
    state: ReadyState,
    counts: Counts,
    close: Option<CloseDetail>,
}

impl Observable {
    fn capture(core: &ConnectionCore) -> Observable {
        Observable {
            state: core.state(),
            counts: core.counts(),
            close: core.close_detail().cloned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Trace {
    steps: Vec<StepRecord>,
    final_state: ReadyState,
    final_counts: Counts,
    close: Option<CloseDetail>,
}

/// Drive one core over `steps`, drain eagerly, and check every
/// state-machine/bounds oracle after every input. Panics carry `label`.
fn drive(
    config: &ConnectionConfig,
    role: Role,
    initial: InitialState,
    steps: &[FuzzStep],
) -> Trace {
    let mut core = ConnectionCore::new_in_state(config.clone(), role, initial);
    let mut records = Vec::with_capacity(steps.len());
    let mut poisoned = false;
    let mut terminal_transitions = 0usize;
    for step in steps {
        // Snapshot the whole observable surface BEFORE the input. The queues
        // are drained to empty at the end of every step, so occupancy here is
        // always zero; together with the drained-empty assertions below that
        // pins queue occupancy across a refusal too.
        let before = Observable::capture(&core);
        let result = match step {
            FuzzStep::Bytes(chunk) => core.handle(Input::TransportBytes(chunk)),
            FuzzStep::Eof => core.handle(Input::TransportEof),
            FuzzStep::Command(command) => core.handle(Input::Command(command.clone())),
        };
        let mut events = Vec::new();
        while let Some(event) = core.next_event() {
            events.push(event);
            assert!(
                events.len() <= config.event_queue_capacity(),
                "event queue exceeded its configured capacity"
            );
        }
        let mut writes = Vec::new();
        while let Some(write) = core.next_write() {
            writes.push(write.bytes);
            assert!(
                writes.len() <= config.write_queue_capacity(),
                "write queue exceeded its configured capacity"
            );
        }

        // Poisoned permanence: after the first fatal failure every input is
        // a StateViolation and nothing new is observable.
        if poisoned {
            assert_eq!(
                result,
                Err(TypedProtocolFailure::protocol(FailureCode::StateViolation)),
                "poisoned core must refuse with StateViolation"
            );
            assert!(events.is_empty(), "poisoned core emitted events");
            assert!(writes.is_empty(), "poisoned core emitted writes");
        }
        match &result {
            Err(failure) if failure.code.is_fatal() => poisoned = true,
            Err(_) => {
                // Backpressure ATOMICITY: the input was not consumed, so the
                // core must be byte-for-byte where it was before the call.
                // Emitting nothing is necessary but nowhere near sufficient —
                // a refusal that had already committed a counter, advanced the
                // state, recorded a close, or retained pending bytes would
                // satisfy the empty-queue checks while leaving the core in a
                // state no retry can reproduce. Every observable is compared.
                assert!(events.is_empty(), "backpressure refusal emitted events");
                assert!(writes.is_empty(), "backpressure refusal emitted writes");
                let after = Observable::capture(&core);
                assert_eq!(
                    after.state, before.state,
                    "backpressure refusal changed the ready state"
                );
                assert_eq!(
                    after.counts, before.counts,
                    "backpressure refusal mutated the counters (including buffered/pending bytes)"
                );
                assert_eq!(
                    after.close, before.close,
                    "backpressure refusal changed the close detail"
                );
            }
            Ok(()) => {}
        }

        // Bounded-allocation oracles over the counts snapshot.
        let counts = core.counts();
        assert_eq!(
            counts.buffered_bytes,
            counts.wire_buffered_bytes + counts.message_buffered_bytes,
            "buffered-byte decomposition identity"
        );
        assert!(
            counts.wire_buffered_bytes
                <= config.max_buffered_bytes() as u64 + WIRE_PENDING_SLACK_BYTES,
            "pending wire buffer exceeded max_buffered_bytes + Q24 slack"
        );
        assert!(
            counts.message_buffered_bytes
                <= (config.max_buffered_bytes() as u64).max(config.max_message_bytes() as u64),
            "fragment reassembly exceeded its cap"
        );
        assert!(
            counts.input_bytes <= config.max_input_bytes() as u64,
            "input_bytes exceeded max_input_bytes"
        );

        // Event-order oracle (US-013 AC5 "event-order"): every close-family
        // state transition is preceded, in the SAME step, by its own close
        // notification — all six transition sites in the core emit the
        // notification (close / close_initiated / eof) immediately before
        // the transition, and a chunk carrying several close frames pairs
        // them one-for-one in arrival order.
        let mut unpaired_notifications = 0usize;
        for event in &events {
            match &event.kind {
                SemanticEventKind::Close(_)
                | SemanticEventKind::CloseInitiated(_)
                | SemanticEventKind::Eof(_) => unpaired_notifications += 1,
                SemanticEventKind::Transition { cause, .. } => {
                    assert!(
                        unpaired_notifications > 0,
                        "transition ({cause:?}) emitted before its close notification"
                    );
                    unpaired_notifications -= 1;
                }
                _ => {}
            }
        }

        // Exactly-once terminal accounting.
        for event in &events {
            if let SemanticEventKind::Transition { to, .. } = &event.kind
                && *to == ReadyState::Closed
            {
                terminal_transitions += 1;
            }
        }
        assert!(
            terminal_transitions <= 1,
            "more than one terminal transition to Closed"
        );

        records.push(StepRecord {
            result,
            events,
            writes,
        });
    }
    if core.state() == ReadyState::Closed && initial != InitialState::Closed {
        assert_eq!(
            terminal_transitions, 1,
            "reached Closed without exactly one terminal transition"
        );
    }
    if terminal_transitions == 1 {
        assert_eq!(
            core.state(),
            ReadyState::Closed,
            "terminal transition recorded but the state is not Closed"
        );
    }
    Trace {
        steps: records,
        final_state: core.state(),
        final_counts: core.counts(),
        close: core.close_detail().cloned(),
    }
}

/// Run `drive` under `catch_unwind` so a core panic fails the campaign with
/// the case label (the no-panic oracle, attributably).
fn drive_checked(
    label: &str,
    config: &ConnectionConfig,
    role: Role,
    initial: InitialState,
    steps: &[FuzzStep],
) -> Trace {
    let result = catch_unwind(AssertUnwindSafe(|| drive(config, role, initial, steps)));
    match result {
        Ok(trace) => trace,
        Err(payload) => {
            let detail = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("non-string panic payload");
            panic!("{label}: panic caught by the fuzz oracle: {detail}");
        }
    }
}

/// The chunk-invariant projection of a trace: every non-chunk event kind
/// (frame-record steps zeroed), the concatenated write stream, the final
/// state, the close detail, and the first fatal failure.
fn normalized_observables(
    trace: &Trace,
) -> (
    Vec<SemanticEventKind>,
    Vec<u8>,
    ReadyState,
    Option<CloseDetail>,
    Option<TypedProtocolFailure>,
) {
    let mut kinds = Vec::new();
    let mut writes = Vec::new();
    let mut fatal = None;
    for step in &trace.steps {
        for event in &step.events {
            let mut kind = event.kind.clone();
            match &mut kind {
                SemanticEventKind::InputChunk { .. } => continue,
                SemanticEventKind::FrameObserved(record) => record.step = 0,
                _ => {}
            }
            kinds.push(kind);
        }
        for write in &step.writes {
            writes.extend_from_slice(write);
        }
        if fatal.is_none()
            && let Err(failure) = &step.result
            && failure.code.is_fatal()
        {
            fatal = Some(failure.clone());
        }
    }
    (kinds, writes, trace.final_state, trace.close.clone(), fatal)
}

// ---------------------------------------------------------------------------
// Independent generators (never call the shipped encoder).
// ---------------------------------------------------------------------------

/// The fuzz-default configuration: corpus-default limits with generous
/// bounded queues so an eagerly-draining owner never sees backpressure
/// (backpressure has its own dedicated family).
fn fuzz_config() -> ConnectionConfig {
    ConnectionConfig::builder()
        .event_queue_capacity(1024)
        .write_queue_capacity(1024)
        .build()
        .expect("fuzz default config is valid")
}

/// In-test masking (independent of `Draft6455::apply_mask`).
fn xor_mask(payload: &mut [u8], key: [u8; 4]) {
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= key[index % 4];
    }
}

/// Raw frame builder: canonical or deliberately noncanonical length
/// encodings, arbitrary FIN/RSV/opcode/mask combinations.
fn raw_frame(
    fin: bool,
    rsv: u8,
    opcode: u8,
    payload: &[u8],
    mask: Option<[u8; 4]>,
    force_escape: Option<u8>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    let mut first = opcode & 0x0f;
    if fin {
        first |= 0x80;
    }
    first |= (rsv & 0x07) << 4;
    out.push(first);
    let mask_bit = if mask.is_some() { 0x80u8 } else { 0 };
    let len = payload.len() as u64;
    let escape = match force_escape {
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
    if let Some(key) = mask {
        out.extend_from_slice(&key);
        let start = out.len();
        out.extend_from_slice(payload);
        xor_mask(&mut out[start..], key);
    } else {
        out.extend_from_slice(payload);
    }
    out
}

/// A biased payload length across the pinned boundary sites.
fn draw_len(rng: &mut SplitMix64, control: bool) -> usize {
    let sites: &[usize] = if control {
        &[0, 1, 2, 5, 25, 124, 125, 126, 127, 200]
    } else {
        &[0, 1, 2, 5, 50, 124, 125, 126, 127, 200, 300]
    };
    if rng.chance(2) {
        sites[rng.below(sites.len() as u64) as usize]
    } else {
        rng.below(160) as usize
    }
}

/// Random text payload: mostly ASCII, sometimes multi-byte UTF-8,
/// sometimes deliberately invalid sequences.
fn draw_text_payload(rng: &mut SplitMix64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 4);
    while out.len() < len {
        match rng.below(10) {
            0..=5 => out.push(rng.byte() & 0x7f),
            6 => {
                // Valid two-byte scalar.
                out.push(0xc2 | (rng.byte() & 0x1d));
                out.push(0x80 | (rng.byte() & 0x3f));
            }
            7 => {
                // Valid three-byte scalar (E1..EC lead: window-free).
                out.push(0xe1 + (rng.byte() % 0x0c));
                out.push(0x80 | (rng.byte() & 0x3f));
                out.push(0x80 | (rng.byte() & 0x3f));
            }
            8 => {
                // Hostile: overlong / surrogate / orphan continuation.
                match rng.below(4) {
                    0 => out.extend_from_slice(&[0xc0, 0xaf]),
                    1 => out.extend_from_slice(&[0xed, 0xa0, 0x80]),
                    2 => out.push(0x80 | (rng.byte() & 0x3f)),
                    _ => out.extend_from_slice(&[0xf4, 0x90, 0x80, 0x80]),
                }
            }
            _ => {
                // Dangling multi-byte tail (Q15 split coverage).
                out.push(0xe2);
                if rng.chance(2) {
                    out.push(0x82);
                }
            }
        }
    }
    out.truncate(len);
    out
}

/// Close payload generator: empty, one-byte, hostile code/reason pairs,
/// invalid-UTF-8 reasons.
fn draw_close_payload(rng: &mut SplitMix64) -> Vec<u8> {
    match rng.below(10) {
        0 => Vec::new(),
        1 => vec![rng.byte()],
        _ => {
            const CODES: [u16; 14] = [
                999, 1000, 1001, 1002, 1004, 1005, 1006, 1007, 1011, 1015, 1016, 2999, 4999, 5000,
            ];
            let code = if rng.chance(4) {
                (rng.next_u64() & 0xffff) as u16
            } else {
                CODES[rng.below(CODES.len() as u64) as usize]
            };
            let mut payload = code.to_be_bytes().to_vec();
            let reason_len = rng.below(24) as usize;
            if rng.chance(6) {
                payload.extend_from_slice(&draw_text_payload(rng, reason_len));
            } else {
                payload.extend((0..reason_len).map(|_| rng.byte() & 0x7f));
            }
            payload
        }
    }
}

/// One structured adversarial frame.
fn draw_frame(rng: &mut SplitMix64) -> Vec<u8> {
    let opcode: u8 = match rng.below(20) {
        0..=2 => 0x0,  // continuation
        3..=6 => 0x1,  // text
        7..=10 => 0x2, // binary
        11..=13 => 0x8,
        14..=15 => 0x9,
        16..=17 => 0xa,
        18 => 0x3 + (rng.byte() % 5), // reserved data opcodes 3..7
        _ => 0xb + (rng.byte() % 5),  // reserved control opcodes B..F
    };
    let control = opcode >= 0x8;
    let fin = !rng.chance(5);
    let rsv = if rng.chance(10) { 1 << rng.below(3) } else { 0 };
    let len = draw_len(rng, control);
    let payload = match opcode {
        0x1 => draw_text_payload(rng, len),
        0x8 => draw_close_payload(rng),
        _ => rng.bytes(len),
    };
    let mask = if rng.chance(2) {
        Some([rng.byte(), rng.byte(), rng.byte(), rng.byte()])
    } else {
        None
    };
    let force_escape = if payload.len() <= 125 && rng.chance(8) {
        Some(if rng.chance(2) { 126 } else { 127 })
    } else if payload.len() <= 0xffff && payload.len() > 125 && rng.chance(8) {
        Some(127)
    } else {
        None
    };
    raw_frame(fin, rsv, opcode, &payload, mask, force_escape)
}

/// A whole adversarial stream: several frames, an optional garbage tail,
/// an optional truncation.
fn draw_stream(rng: &mut SplitMix64) -> Vec<u8> {
    let frames = 1 + rng.below(10);
    let mut stream = Vec::new();
    for _ in 0..frames {
        stream.extend_from_slice(&draw_frame(rng));
    }
    if rng.chance(6) {
        let tail = rng.below(24) as usize;
        stream.extend(rng.bytes(tail));
    }
    if rng.chance(6) && !stream.is_empty() {
        let keep = stream.len() - (rng.below(stream.len().min(20) as u64) as usize);
        stream.truncate(keep);
    }
    stream
}

/// Split a stream into chunks per the given strategy.
fn chunk_stream(rng: &mut SplitMix64, stream: &[u8], strategy: u64) -> Vec<FuzzStep> {
    match strategy {
        0 => vec![FuzzStep::Bytes(stream.to_vec())],
        1 => stream
            .iter()
            .map(|byte| FuzzStep::Bytes(vec![*byte]))
            .collect(),
        _ => {
            let mut chunks = Vec::new();
            let mut at = 0usize;
            while at < stream.len() {
                let take = 1 + rng.below(64) as usize;
                let end = (at + take).min(stream.len());
                chunks.push(FuzzStep::Bytes(stream[at..end].to_vec()));
                at = end;
            }
            if rng.chance(8) {
                chunks.push(FuzzStep::Bytes(Vec::new()));
            }
            chunks
        }
    }
}

/// One random local command.
fn draw_command(rng: &mut SplitMix64) -> LocalCommand {
    match rng.below(6) {
        0 => LocalCommand::SendText {
            text: String::from_utf8(
                (0..rng.below(80))
                    .map(|_| rng.byte() & 0x7f)
                    .collect::<Vec<u8>>(),
            )
            .expect("ascii"),
        },
        1 => {
            let len = rng.below(160) as usize;
            LocalCommand::SendBinary {
                data: rng.bytes(len),
            }
        }
        2 => {
            let len = draw_len(rng, true);
            LocalCommand::SendPing {
                data: rng.bytes(len),
            }
        }
        3 => {
            let len = draw_len(rng, true);
            LocalCommand::SendPong {
                data: rng.bytes(len),
            }
        }
        4 => {
            const CODES: [u16; 8] = [1000, 1001, 1002, 1005, 1007, 1015, 3000, 4999];
            LocalCommand::SendClose {
                code: if rng.chance(3) {
                    (rng.next_u64() & 0xffff) as u16
                } else {
                    CODES[rng.below(CODES.len() as u64) as usize]
                },
                reason: String::from_utf8(
                    (0..rng.below(30))
                        .map(|_| rng.byte() & 0x7f)
                        .collect::<Vec<u8>>(),
                )
                .expect("ascii"),
            }
        }
        _ => LocalCommand::SendFragment {
            opcode: if rng.chance(2) {
                DataOpcode::Text
            } else {
                DataOpcode::Binary
            },
            data: (0..rng.below(60)).map(|_| rng.byte() & 0x7f).collect(),
            fin: rng.chance(2),
        },
    }
}

fn draw_role(rng: &mut SplitMix64) -> Role {
    if rng.chance(2) {
        Role::Client
    } else {
        Role::Server
    }
}

// ---------------------------------------------------------------------------
// Family 1: random byte soup + determinism replay. 10_000 cases, each
// driven twice (20_000 drives) for the determinism oracle.
// ---------------------------------------------------------------------------

#[test]
fn family_byte_soup_no_panic_bounded_deterministic() {
    let config = fuzz_config();
    let mut rng = SplitMix64::new(0xe1f0_0001);
    for case in 0..10_000u32 {
        let role = draw_role(&mut rng);
        let chunk_count = 1 + rng.below(8);
        let steps: Vec<FuzzStep> = (0..chunk_count)
            .map(|_| {
                let len = rng.below(300) as usize;
                FuzzStep::Bytes(rng.bytes(len))
            })
            .collect();
        let label = format!("byte_soup case {case}");
        let first = drive_checked(&label, &config, role, InitialState::Open, &steps);
        let second = drive_checked(&label, &config, role, InitialState::Open, &steps);
        assert_eq!(first, second, "{label}: determinism (identical full trace)");
    }
}

// ---------------------------------------------------------------------------
// Family 2: structured frame soup + determinism replay. 10_000 cases, each
// driven twice (20_000 drives) for the determinism oracle.
// ---------------------------------------------------------------------------

#[test]
fn family_frame_soup_no_panic_bounded_deterministic() {
    let config = fuzz_config();
    let mut rng = SplitMix64::new(0xe1f0_0002);
    for case in 0..10_000u32 {
        let role = draw_role(&mut rng);
        let stream = draw_stream(&mut rng);
        let strategy = rng.below(3);
        let mut chunk_rng = SplitMix64::new(0xc4c4_0000 + u64::from(case));
        let steps = chunk_stream(&mut chunk_rng, &stream, strategy);
        let label = format!("frame_soup case {case}");
        let first = drive_checked(&label, &config, role, InitialState::Open, &steps);
        let second = drive_checked(&label, &config, role, InitialState::Open, &steps);
        assert_eq!(first, second, "{label}: determinism (identical full trace)");
    }
}

// ---------------------------------------------------------------------------
// Family 3: rechunking invariance.
//
// The reference semantics batch TRANSLATION per read chunk exactly like the
// pinned Java runtime (`Draft_6455.translateFrame` decodes the whole
// buffered read and throws for the entire batch; derive.go `inputStep`
// translates every complete span before any frame is recorded). A
// translate-stage rejection in a LATER frame of the same chunk therefore
// legitimately discards the delivery of EARLIER frames in that chunk — a
// Java-faithful chunk-visible behavior, not a defect. The invariance oracle
// is accordingly split:
//
// - 3a (2_000 cases): single-frame streams — full normalized-observable
//   equality across chunkings regardless of outcome (no earlier span
//   exists to discard).
// - 3b (4_000 cases): multi-frame streams — full equality whenever the
//   whole-chunk drive is fatal-free; when it is fatal, every chunking must
//   also end in a fatal typed failure (fatality itself is chunk-invariant
//   because translate/process checks are span-local and cumulative).
// ---------------------------------------------------------------------------

#[test]
fn family_rechunk_invariance_single_frame() {
    let config = fuzz_config();
    let mut rng = SplitMix64::new(0xe1f0_0013);
    for case in 0..2_000u32 {
        let role = draw_role(&mut rng);
        let mut stream = draw_frame(&mut rng);
        if rng.chance(5) && !stream.is_empty() {
            let keep = stream.len() - (rng.below(stream.len().min(6) as u64) as usize);
            stream.truncate(keep);
        }
        stream.truncate(900); // keep byte-at-a-time affordable
        let label = format!("rechunk single case {case}");
        let mut projections = Vec::new();
        for strategy in 0..3u64 {
            let mut chunk_rng = SplitMix64::new(0xabcd_1000 + u64::from(case));
            let steps = chunk_stream(&mut chunk_rng, &stream, strategy);
            let trace = drive_checked(
                &format!("{label} strategy {strategy}"),
                &config,
                role,
                InitialState::Open,
                &steps,
            );
            projections.push(normalized_observables(&trace));
        }
        assert_eq!(
            projections[0], projections[1],
            "{label}: whole vs byte-at-a-time"
        );
        assert_eq!(
            projections[0], projections[2],
            "{label}: whole vs random splits"
        );
    }
}

#[test]
fn family_rechunk_invariance_multi_frame() {
    let config = fuzz_config();
    let mut rng = SplitMix64::new(0xe1f0_0003);
    for case in 0..4_000u32 {
        let role = draw_role(&mut rng);
        let mut stream = draw_stream(&mut rng);
        stream.truncate(900); // keep byte-at-a-time affordable
        let label = format!("rechunk case {case}");
        let mut projections = Vec::new();
        for strategy in 0..3u64 {
            let mut chunk_rng = SplitMix64::new(0xabcd_0000 + u64::from(case));
            let steps = chunk_stream(&mut chunk_rng, &stream, strategy);
            let trace = drive_checked(
                &format!("{label} strategy {strategy}"),
                &config,
                role,
                InitialState::Open,
                &steps,
            );
            projections.push(normalized_observables(&trace));
        }
        let whole_fatal = projections[0].4.is_some();
        if whole_fatal {
            for (strategy, projection) in projections.iter().enumerate() {
                assert!(
                    projection.4.is_some(),
                    "{label} strategy {strategy}: fatality must be chunk-invariant"
                );
            }
        } else {
            assert_eq!(
                projections[0], projections[1],
                "{label}: whole vs byte-at-a-time (fatal-free stream)"
            );
            assert_eq!(
                projections[0], projections[2],
                "{label}: whole vs random splits (fatal-free stream)"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Family 4: command/byte/EOF interleave + determinism. 5_000 cases, each
// driven twice (10_000 drives).
// ---------------------------------------------------------------------------

#[test]
fn family_command_interleave_no_panic_deterministic() {
    let config = fuzz_config();
    let mut rng = SplitMix64::new(0xe1f0_0004);
    for case in 0..5_000u32 {
        let role = draw_role(&mut rng);
        let step_count = 1 + rng.below(12);
        let steps: Vec<FuzzStep> = (0..step_count)
            .map(|_| match rng.below(10) {
                0..=3 => {
                    let mut sub = SplitMix64::new(rng.next_u64());
                    FuzzStep::Bytes(draw_frame(&mut sub))
                }
                4 => FuzzStep::Eof,
                _ => FuzzStep::Command(draw_command(&mut rng)),
            })
            .collect();
        let label = format!("command_interleave case {case}");
        let first = drive_checked(&label, &config, role, InitialState::Open, &steps);
        let second = drive_checked(&label, &config, role, InitialState::Open, &steps);
        assert_eq!(first, second, "{label}: determinism (identical full trace)");
    }
}

// ---------------------------------------------------------------------------
// Family 5: configuration boundary values. 2_000 driven cases plus
// out-of-range builder probes (ceiling+1, minimum-1, minimum) on every one
// of the 13 limit fields.
// ---------------------------------------------------------------------------

#[test]
fn family_config_boundaries() {
    // Builder probes: below-minimum and above-ceiling must reject with the
    // typed error, never panic and never build.
    for field in LimitField::ALL {
        let ceiling_probe = apply_field(ConnectionConfig::builder(), field, field.ceiling() + 1);
        assert!(
            ceiling_probe.build().is_err(),
            "{}: ceiling+1 must be rejected",
            field.name()
        );
        if field.minimum() > 0 {
            let floor_probe = apply_field(ConnectionConfig::builder(), field, field.minimum() - 1);
            assert!(
                floor_probe.build().is_err(),
                "{}: minimum-1 must be rejected",
                field.name()
            );
        }
        apply_field(ConnectionConfig::builder(), field, field.minimum())
            .build()
            .unwrap_or_else(|e| panic!("{}: minimum must build: {e:?}", field.name()));
    }

    let mut rng = SplitMix64::new(0xe1f0_0005);
    for case in 0..2_000u32 {
        let mut builder = ConnectionConfig::builder();
        for field in LimitField::ALL {
            let value = match rng.below(5) {
                0 => field.minimum(),
                1 => field.minimum().saturating_add(1).min(field.ceiling()),
                2 => field.default_value(),
                3 => field.ceiling(),
                _ => {
                    let span = field.ceiling() - field.minimum() + 1;
                    field.minimum() + rng.below(span.min(4096))
                }
            };
            builder = apply_field(builder, field, value);
        }
        let config = builder.build().expect("in-range values must always build");
        let role = draw_role(&mut rng);
        let mut steps = Vec::new();
        for _ in 0..(1 + rng.below(6)) {
            if rng.chance(3) {
                steps.push(FuzzStep::Command(draw_command(&mut rng)));
            } else {
                let mut sub = SplitMix64::new(rng.next_u64());
                steps.push(FuzzStep::Bytes(draw_frame(&mut sub)));
            }
        }
        let label = format!("config_boundary case {case}");
        drive_checked(&label, &config, role, InitialState::Open, &steps);
    }
}

fn apply_field(
    builder: ws_core::config::ConnectionConfigBuilder,
    field: LimitField,
    value: u64,
) -> ws_core::config::ConnectionConfigBuilder {
    match field {
        LimitField::MaxHandshakeBytes => builder.max_handshake_bytes(value),
        LimitField::MaxHeaderCount => builder.max_header_count(value),
        LimitField::MaxHeaderLineBytes => builder.max_header_line_bytes(value),
        LimitField::MaxFramePayloadBytes => builder.max_frame_payload_bytes(value),
        LimitField::MaxMessageBytes => builder.max_message_bytes(value),
        LimitField::MaxBufferedBytes => builder.max_buffered_bytes(value),
        LimitField::MaxInputBytes => builder.max_input_bytes(value),
        LimitField::MaxActions => builder.max_actions(value),
        LimitField::MaxFrames => builder.max_frames(value),
        LimitField::MaxOutputBytes => builder.max_output_bytes(value),
        LimitField::EventQueueCapacity => builder.event_queue_capacity(value),
        LimitField::CommandQueueCapacity => builder.command_queue_capacity(value),
        LimitField::WriteQueueCapacity => builder.write_queue_capacity(value),
    }
}

// ---------------------------------------------------------------------------
// Family 6: undersized queues — refusals are typed Backpressure.
// 1_000 cases.
// ---------------------------------------------------------------------------

#[test]
fn family_queue_pressure_typed_backpressure() {
    let config = ConnectionConfig::builder()
        .event_queue_capacity(4)
        .write_queue_capacity(1)
        .build()
        .expect("minimum queue config builds");
    let mut rng = SplitMix64::new(0xe1f0_0006);
    for case in 0..1_000u32 {
        let role = draw_role(&mut rng);
        let mut steps = Vec::new();
        for _ in 0..(1 + rng.below(8)) {
            if rng.chance(2) {
                let mut sub = SplitMix64::new(rng.next_u64());
                steps.push(FuzzStep::Bytes(draw_stream(&mut sub)));
            } else {
                steps.push(FuzzStep::Command(draw_command(&mut rng)));
            }
        }
        let label = format!("queue_pressure case {case}");
        // The drive itself asserts: backpressure refusals emit nothing and
        // never poison; queue drains never exceed the tiny capacities.
        drive_checked(&label, &config, role, InitialState::Open, &steps);
    }
}

// ---------------------------------------------------------------------------
// Family 7: committed seed-corpus anchors. Every fuzz-seeds/**/*.hex file
// (98 at the time of writing; the test asserts >= 90) x 3 core setups
// x 3 chunkings = 882 drives, with rechunk invariance per setup.
// ---------------------------------------------------------------------------

fn committed_hex_seeds() -> Vec<(String, Vec<u8>)> {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz-seeds");
    let mut files = Vec::new();
    let mut dirs: Vec<std::path::PathBuf> = std::fs::read_dir(&root)
        .expect("fuzz-seeds directory exists")
        .map(|entry| entry.expect("readable entry").path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    for dir in dirs {
        let mut entries: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
            .expect("readable seed dir")
            .map(|entry| entry.expect("readable entry").path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "hex"))
            .collect();
        entries.sort();
        for path in entries {
            let raw = std::fs::read_to_string(&path).expect("readable seed");
            let hex: String = raw.chars().filter(|c| !c.is_ascii_whitespace()).collect();
            assert!(
                hex.len().is_multiple_of(2),
                "seed {} must hold an even number of hex digits",
                path.display()
            );
            let bytes: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| {
                    u8::from_str_radix(&hex[i..i + 2], 16)
                        .unwrap_or_else(|e| panic!("seed {} must be hex: {e}", path.display()))
                })
                .collect();
            files.push((path.display().to_string(), bytes));
        }
    }
    files
}

#[test]
fn family_seed_corpus_anchors() {
    let config = fuzz_config();
    let seeds = committed_hex_seeds();
    assert!(
        seeds.len() >= 90,
        "expected the full committed hex corpus, found {}",
        seeds.len()
    );
    let setups = [
        (Role::Client, InitialState::Open),
        (Role::Server, InitialState::Open),
        (Role::Server, InitialState::Closing),
    ];
    for (name, bytes) in &seeds {
        for (setup, (role, initial)) in setups.into_iter().enumerate() {
            let mut projections = Vec::new();
            for strategy in 0..3u64 {
                let mut chunk_rng = SplitMix64::new(0x5eed_0000 + strategy);
                let steps = chunk_stream(&mut chunk_rng, bytes, strategy);
                let label = format!("seed {name} setup {setup} strategy {strategy}");
                let trace = drive_checked(&label, &config, role, initial, &steps);
                projections.push(normalized_observables(&trace));
            }
            // Same fatal-aware invariance split as family 3 (whole-chunk
            // translate batching is Java-faithful chunk-visible behavior).
            if projections[0].4.is_some() {
                for (strategy, projection) in projections.iter().enumerate() {
                    assert!(
                        projection.4.is_some(),
                        "seed {name} setup {setup} strategy {strategy}: fatality invariance"
                    );
                }
            } else {
                assert_eq!(
                    projections[0], projections[1],
                    "seed {name} setup {setup}: whole vs byte-at-a-time"
                );
                assert_eq!(
                    projections[0], projections[2],
                    "seed {name} setup {setup}: whole vs random splits"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Family 8: curated hostile length declarations (headers only — the
// declared payload never arrives): 9 declarations x 2 roles = 18 drives.
// ---------------------------------------------------------------------------

#[test]
fn family_declared_length_headers() {
    let config = fuzz_config();
    let mut declarations: Vec<Vec<u8>> = Vec::new();
    // Data frame, 16-bit escape: boundary declarations.
    for len in [126u16, 65_535] {
        let mut header = vec![0x82u8, 126];
        header.extend_from_slice(&len.to_be_bytes());
        declarations.push(header);
    }
    // Data frame, 64-bit escape: cap boundary, cap+1, high bit, all-ones.
    for len in [65_536u64, 65_537, 1 << 63, u64::MAX] {
        let mut header = vec![0x82u8, 127];
        header.extend_from_slice(&len.to_be_bytes());
        declarations.push(header);
    }
    // Control frames with extended-length markers (rejected pre-length).
    declarations.push(vec![0x89, 126, 0x00, 0x80]);
    declarations.push(vec![0x88, 127, 0, 0, 0, 0, 0, 0, 0, 200]);
    // Control frame declaring 126 via the 7-bit marker is impossible; the
    // 125-boundary declaration is legal and buffers.
    declarations.push(vec![0x89, 125]);
    for (index, header) in declarations.iter().enumerate() {
        for role in [Role::Client, Role::Server] {
            let label = format!("declared_length case {index} role {role:?}");
            let steps = [FuzzStep::Bytes(header.clone())];
            let trace = drive_checked(&label, &config, role, InitialState::Open, &steps);
            // Whatever the verdict, it must be a typed outcome: either the
            // header buffers (incomplete) or rejects through the failure
            // vocabulary — the drive's oracles already exclude panics and
            // unbounded buffering.
            if let Err(failure) = &trace.steps[0].result {
                assert!(
                    failure.code.wire_code().is_some()
                        || matches!(failure.code, FailureCode::Backpressure(_)),
                    "{label}: refusal must stay in the oracle vocabulary, got {failure:?}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Mutation-campaign survivor kill (RED-first against
// mprobe-mask-counter-stall): the documented client mask-key seam derives
// each key from mask_key_seed AND the advancing outbound masked-frame
// counter (connection.rs next_mask_key; quirk Q28 makes the keys
// transcript-invisible, so this port-side seam property is the ONLY seam
// that can observe a stalled counter). Two successive masked sends must
// carry distinct keys, and re-driving the same commands must reproduce the
// identical key sequence.
// ---------------------------------------------------------------------------

#[test]
fn mask_key_derivation_advances_per_outbound_frame() {
    let drive_keys = || {
        let config = ConnectionConfig::builder()
            .mask_key_seed(7)
            .build()
            .expect("valid config");
        let mut core = ConnectionCore::new_in_state(config, Role::Client, InitialState::Open);
        let mut keys = Vec::new();
        for _ in 0..4 {
            core.handle(Input::Command(LocalCommand::SendBinary {
                data: vec![0x11, 0x22, 0x33],
            }))
            .expect("send_binary in open succeeds");
            let wire = core.next_write().expect("one write per send").bytes;
            // header(2) + mask(4) + payload(3)
            assert_eq!(wire.len(), 9, "masked binary frame layout");
            keys.push([wire[2], wire[3], wire[4], wire[5]]);
            while core.next_event().is_some() {}
        }
        keys
    };
    let keys = drive_keys();
    for (i, pair) in keys.windows(2).enumerate() {
        assert_ne!(
            pair[0],
            pair[1],
            "successive masked frames {i}/{} must advance the key derivation counter",
            i + 1
        );
    }
    assert_eq!(keys, drive_keys(), "the key sequence is seed-deterministic");
}

// ---------------------------------------------------------------------------
// Mutation-campaign survivor kill (RED-first against
// m013-close-event-order-swap, the US-013 AC5 "event-order" defect class):
// on the close-ACK path (a remote close arriving while already closing) the
// core emits the `close` event BEFORE the terminal transition. No prior test
// and no public corpus case pinned that relative order, so a swap survived
// both judges. The per-step ordering oracle in `drive` generalizes this to
// every close-family transition on every fuzz family; this test pins the
// exact ack sequence by hand.
// ---------------------------------------------------------------------------

#[test]
fn close_ack_emits_the_close_event_before_the_terminal_transition() {
    let config = fuzz_config();
    let close_frame = raw_frame(true, 0, 0x8, &[0x03, 0xe8], None, None);
    let steps = [FuzzStep::Bytes(close_frame)];
    let trace = drive_checked(
        "close ack ordering",
        &config,
        Role::Server,
        InitialState::Closing,
        &steps,
    );
    let kinds: Vec<&SemanticEventKind> = trace.steps[0]
        .events
        .iter()
        .map(|event| &event.kind)
        .filter(|kind| {
            matches!(
                kind,
                SemanticEventKind::Close(_) | SemanticEventKind::Transition { .. }
            )
        })
        .collect();
    assert_eq!(
        kinds.len(),
        2,
        "the ack step emits exactly one close and one transition, got {kinds:?}"
    );
    assert!(
        matches!(kinds[0], SemanticEventKind::Close(_)),
        "the close event must come FIRST, got {:?}",
        kinds[0]
    );
    match kinds[1] {
        SemanticEventKind::Transition { from, to, .. } => {
            assert_eq!(*from, ReadyState::Closing, "ack transitions from closing");
            assert_eq!(*to, ReadyState::Closed, "ack transitions to closed");
        }
        other => panic!("the transition event must come SECOND, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Mutation-campaign survivor kills (each added RED-first against the named
// campaign-1 survivor, then verified green on the pristine core): the three
// genuine coverage gaps were all exact-boundary behaviors no prior test or
// corpus case pinned.
// ---------------------------------------------------------------------------

/// Kills m012-control-limit-off-by-one: a control payload of EXACTLY 125
/// bytes is legal and delivers; 126 requires the extended-length marker,
/// which a control frame rejects 1002 before the length is read.
#[test]
fn control_payload_exactly_125_delivers() {
    let config = fuzz_config();
    let payload: Vec<u8> = (0..125u8).collect();
    let frame = raw_frame(true, 0, 0x9, &payload, None, None);
    let trace = drive_checked(
        "control-125 boundary",
        &config,
        Role::Client,
        InitialState::Open,
        &[FuzzStep::Bytes(frame)],
    );
    assert_eq!(trace.steps[0].result, Ok(()), "125-byte ping is legal");
    assert!(
        trace.steps[0].events.iter().any(|event| matches!(
            &event.kind,
            SemanticEventKind::Ping { data } if *data == payload
        )),
        "the 125-byte ping payload must deliver byte-exactly"
    );
    // The over-boundary partner: a 126-byte control needs marker 126 and
    // rejects 1002 at the two-byte site.
    let oversize = raw_frame(true, 0, 0x9, &[0u8; 126], None, None);
    let trace = drive_checked(
        "control-126 boundary",
        &config,
        Role::Client,
        InitialState::Open,
        &[FuzzStep::Bytes(oversize)],
    );
    assert_eq!(
        trace.steps[0].result,
        Err(TypedProtocolFailure::java_invalid_data(1002)),
        "126-byte control rejects 1002"
    );
}

/// Kills m014-continuation-cap-off-by-one: non-fin continuation growth to
/// EXACTLY max_buffered_bytes is accepted; one byte more refuses with the
/// typed BufferLimitExceeded.
#[test]
fn fragment_accumulation_to_exactly_max_buffered_is_accepted() {
    let config = ConnectionConfig::builder()
        .max_buffered_bytes(256)
        .build()
        .expect("valid config");
    let start = raw_frame(false, 0, 0x2, &[0xaa; 200], None, None);
    let boundary = raw_frame(false, 0, 0x0, &[0xbb; 56], None, None);
    let fin = raw_frame(true, 0, 0x0, &[], None, None);
    let trace = drive_checked(
        "fragment exact-boundary",
        &config,
        Role::Server,
        InitialState::Open,
        &[
            FuzzStep::Bytes(start),
            FuzzStep::Bytes(boundary),
            FuzzStep::Bytes(fin),
        ],
    );
    assert_eq!(trace.steps[0].result, Ok(()), "start buffers");
    assert_eq!(
        trace.steps[1].result,
        Ok(()),
        "growth to exactly max_buffered_bytes (256) is accepted"
    );
    assert_eq!(trace.steps[2].result, Ok(()), "fin delivers");
    assert!(
        trace.steps[2].events.iter().any(|event| matches!(
            &event.kind,
            SemanticEventKind::Binary { data } if data.len() == 256
        )),
        "the assembled 256-byte message must deliver"
    );
    // Over-boundary partner: one more byte in the continuation refuses.
    let start = raw_frame(false, 0, 0x2, &[0xaa; 200], None, None);
    let over = raw_frame(false, 0, 0x0, &[0xbb; 57], None, None);
    let trace = drive_checked(
        "fragment over-boundary",
        &config,
        Role::Server,
        InitialState::Open,
        &[FuzzStep::Bytes(start), FuzzStep::Bytes(over)],
    );
    assert_eq!(
        trace.steps[1].result,
        Err(TypedProtocolFailure::protocol(
            FailureCode::BufferLimitExceeded
        )),
        "257 bytes of accumulation refuses with the adapter accounting code"
    );
}

/// Kills m013-send-payload-gate-off-by-one: a send payload of EXACTLY
/// max_buffered_bytes sends; one byte more refuses before any encoding.
#[test]
fn send_payload_at_exactly_max_buffered_sends() {
    let config = ConnectionConfig::builder()
        .max_buffered_bytes(64)
        .build()
        .expect("valid config");
    let trace = drive_checked(
        "send exact-boundary",
        &config,
        Role::Server,
        InitialState::Open,
        &[FuzzStep::Command(LocalCommand::SendBinary {
            data: vec![0x5a; 64],
        })],
    );
    assert_eq!(
        trace.steps[0].result,
        Ok(()),
        "64-byte send at the cap succeeds"
    );
    assert_eq!(trace.steps[0].writes.len(), 1, "one wire frame emitted");
    let trace = drive_checked(
        "send over-boundary",
        &config,
        Role::Server,
        InitialState::Open,
        &[FuzzStep::Command(LocalCommand::SendBinary {
            data: vec![0x5a; 65],
        })],
    );
    assert_eq!(
        trace.steps[0].result,
        Err(TypedProtocolFailure::protocol(
            FailureCode::BufferLimitExceeded
        )),
        "65-byte send over the cap refuses before encoding"
    );
    assert!(
        trace.steps[0].writes.is_empty(),
        "no wire output on refusal"
    );
}
