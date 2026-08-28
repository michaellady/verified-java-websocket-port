//! US-017 bounded schedule exploration with minimized-schedule retention.
//!
//! This suite is the story's systematic concurrency evidence at the driver
//! seam: it enumerates EVERY interleaving of five fixed actor programs
//! (two producers, transport read, transport write, adapter control) within
//! an explicit context-switch bound, executes each schedule twice against
//! the real `ws_driver` + `ws_core` pair, and asserts the driver-seam
//! invariants on every run. It is systematic concurrency testing under the
//! declared bounds of `assurance/concurrency/plan.json` — never proof.
//!
//! Retention: any failing schedule is deterministically SHRUNK to a
//! 1-minimal failing schedule and persisted as a `key=value` seed artifact.
//! Because the shipped driver passes every explored schedule, the retention
//! mechanism is demonstrated (and pinned as a regression) through a
//! deliberately faulty test-only boundary interpreter: each of the six
//! named seed mutations (adopted with attribution from codex-import
//! 6a7606a, `fuzz-seeds/us017/*.seed`) is injected at the public driver
//! boundary, the exploration finds a failing schedule, the minimizer
//! shrinks it, and the minimized schedule is compared byte-for-byte with
//! the committed artifact in `fuzz-seeds/us017/minimized/`.
//!
//! Determinism: no clock, no randomness, no threads. Schedule enumeration
//! is a pure function of the declared bounds; every schedule carries a
//! stable FNV-64 digest and replays to an identical trace.

#![forbid(unsafe_code)]

use std::collections::{BTreeSet, VecDeque};
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use ws_core::config::ConnectionConfig;
use ws_core::{CommandSender, InitialState, LocalCommand, ReadyState, Role};
use ws_driver::{
    AutoResponsePolicy, CommandDisposition, ConnectionDriver, DeferredReason, DriverInput,
    DriverOutput, InputDisposition, connection_driver_in_state_with_policy,
};

// ---------------------------------------------------------------------------
// Declared bounds (all within assurance/concurrency/plan.json `bounds`)
// ---------------------------------------------------------------------------

/// Actor programs in the exploration (plan bound: producer_tasks_max 3,
/// owner_tasks_per_connection 1 — here: 2 producers, 1 transport-read,
/// 1 transport-write, 1 adapter-control lane, all serialized through the
/// single owner's `poll`).
const PROGRAM_COUNT: usize = 5;
/// Preemptive context switches allowed beyond the `PROGRAM_COUNT - 1`
/// switches any complete interleaving needs (plan bound: preemption_bound 3).
const PREEMPTION_BUDGET: usize = 3;
/// Total context-switch bound: schedules are enumerated EXHAUSTIVELY within
/// this bound — no truncation.
const CONTEXT_SWITCH_BOUND: usize = (PROGRAM_COUNT - 1) + PREEMPTION_BUDGET;
/// Plan bound `schedule_count_max`: the exhaustive enumeration must fit.
const SCHEDULE_COUNT_MAX: usize = 100_000;
/// Plan bound `branch_count_max` for the enumeration search tree.
const BRANCH_COUNT_MAX: usize = 1_000_000;
/// Weak-fairness drain budget per run (owner progress, flush progress,
/// event drain — the three declared weak-fairness assumptions). A run that
/// cannot quiesce within this budget is a convergence failure.
const DRAIN_BUDGET: usize = 256;

/// Bounded-channel capacities for the explored connection (plan bounds:
/// command/write/event queue capacities <= 8). Small on purpose: queue-full
/// refusals and backpressure deferrals must be REACHED by the schedule
/// space, not just typed.
const COMMAND_QUEUE_CAPACITY: u64 = 2;
const WRITE_QUEUE_CAPACITY: u64 = 2;
/// 8, not the config floor 4: `ConnectionCore::byte_input_event_bound`
/// needs 1 + 3*spans + 2 = 6 free slots to admit even a one-frame chunk,
/// so a 4-slot queue (the config minimum) can never make byte-path
/// progress. 8 keeps backpressure reachable (any >=3 queued events defer
/// inbound; >=5 defer EOF) while every deferral resolves under drain.
const EVENT_QUEUE_CAPACITY: u64 = 8;

// Wire constants (server role: outbound unmasked, inbound masked).
const MASKED_PING: &[u8] = &[0x89, 0x80, 0x00, 0x00, 0x00, 0x00];
const MASKED_CLOSE_1000: &[u8] = &[0x88, 0x82, 0x00, 0x00, 0x00, 0x00, 0x03, 0xE8];
const FRAME_TEXT_A: &[u8] = &[0x81, 0x02, b'a', b'1'];
const FRAME_BINARY_A: &[u8] = &[0x82, 0x02, 0xB1, 0xB2];
const FRAME_PING_B: &[u8] = &[0x89, 0x01, 0x50];
/// Local close and the Q19 echo both emit the constructor payload (Q10).
const FRAME_CLOSE: &[u8] = &[0x88, 0x02, 0x03, 0xE8];

// ---------------------------------------------------------------------------
// Action alphabet and actor programs
// ---------------------------------------------------------------------------

/// One schedule step. The alphabet fixes tasks, commands, inbound actions,
/// flushes, and shutdowns (US-017 AC3): four bounded command kinds across
/// two producers, inbound control + close + EOF on the transport-read lane,
/// partial/complete flush progress on the transport-write lane, and the
/// owner-wake / adapter-shutdown control lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Action {
    EnqueueTextA,
    EnqueueBinaryA,
    EnqueuePingB,
    EnqueueCloseB,
    InboundPing,
    InboundClose,
    TransportEof,
    WritePartial,
    WriteAll,
    Wake,
    Shutdown,
}

impl Action {
    fn verb(self) -> &'static str {
        match self {
            Action::EnqueueTextA => "enqueue-text-a",
            Action::EnqueueBinaryA => "enqueue-binary-a",
            Action::EnqueuePingB => "enqueue-ping-b",
            Action::EnqueueCloseB => "enqueue-close-b",
            Action::InboundPing => "inbound-ping",
            Action::InboundClose => "inbound-close",
            Action::TransportEof => "transport-eof",
            Action::WritePartial => "write-partial",
            Action::WriteAll => "write-all",
            Action::Wake => "wake",
            Action::Shutdown => "shutdown",
        }
    }

    fn parse(verb: &str) -> Action {
        match verb {
            "enqueue-text-a" => Action::EnqueueTextA,
            "enqueue-binary-a" => Action::EnqueueBinaryA,
            "enqueue-ping-b" => Action::EnqueuePingB,
            "enqueue-close-b" => Action::EnqueueCloseB,
            "inbound-ping" => Action::InboundPing,
            "inbound-close" => Action::InboundClose,
            "transport-eof" => Action::TransportEof,
            "write-partial" => Action::WritePartial,
            "write-all" => Action::WriteAll,
            "wake" => Action::Wake,
            "shutdown" => Action::Shutdown,
            other => panic!("unknown schedule verb {other:?}"),
        }
    }
}

/// The five fixed actor programs whose interleavings are explored.
const PROGRAMS: [&[Action]; PROGRAM_COUNT] = [
    // Producer A: bounded data commands.
    &[Action::EnqueueTextA, Action::EnqueueBinaryA],
    // Producer B: bounded control + local-close commands.
    &[Action::EnqueuePingB, Action::EnqueueCloseB],
    // Transport read: inbound control, peer close, then EOF.
    &[
        Action::InboundPing,
        Action::InboundClose,
        Action::TransportEof,
    ],
    // Transport write: partial then complete flush progress.
    &[Action::WritePartial, Action::WriteAll, Action::WriteAll],
    // Adapter control: an owner turn, then shutdown.
    &[Action::Wake, Action::Shutdown],
];

// ---------------------------------------------------------------------------
// Exhaustive bounded enumeration
// ---------------------------------------------------------------------------

struct Exploration {
    schedules: Vec<Vec<Action>>,
    branches: usize,
}

fn enumerate_schedules() -> Exploration {
    fn visit(
        schedules: &mut Vec<Vec<Action>>,
        branches: &mut usize,
        positions: &mut [usize; PROGRAM_COUNT],
        schedule: &mut Vec<Action>,
        last_actor: Option<usize>,
        switches: usize,
    ) {
        if positions
            .iter()
            .enumerate()
            .all(|(actor, position)| *position == PROGRAMS[actor].len())
        {
            schedules.push(schedule.clone());
            return;
        }
        for actor in 0..PROGRAM_COUNT {
            if positions[actor] == PROGRAMS[actor].len() {
                continue;
            }
            let next_switches =
                switches + usize::from(last_actor.is_some_and(|last| last != actor));
            if next_switches > CONTEXT_SWITCH_BOUND {
                continue;
            }
            // Exact feasibility pruning: completing every OTHER unfinished
            // program costs at least one switch each, so a prefix that
            // cannot finish within the bound is never entered (branches
            // count real prefix nodes only).
            let unfinished_others = (0..PROGRAM_COUNT)
                .filter(|other| *other != actor && positions[*other] < PROGRAMS[*other].len())
                .count();
            if next_switches + unfinished_others > CONTEXT_SWITCH_BOUND {
                continue;
            }
            *branches += 1;
            assert!(
                *branches <= BRANCH_COUNT_MAX,
                "enumeration exceeded the declared branch bound"
            );
            let action = PROGRAMS[actor][positions[actor]];
            positions[actor] += 1;
            schedule.push(action);
            visit(
                schedules,
                branches,
                positions,
                schedule,
                Some(actor),
                next_switches,
            );
            schedule.pop();
            positions[actor] -= 1;
        }
    }

    let mut schedules = Vec::new();
    let mut branches = 0usize;
    visit(
        &mut schedules,
        &mut branches,
        &mut [0; PROGRAM_COUNT],
        &mut Vec::new(),
        None,
        0,
    );
    Exploration {
        schedules,
        branches,
    }
}

fn fnv64(bytes: impl IntoIterator<Item = u8>) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash = (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

fn schedule_digest(schedule: &[Action]) -> u64 {
    fnv64(schedule.iter().map(|action| *action as u8))
}

// ---------------------------------------------------------------------------
// Deterministic seed-schedule interpreter (the public driver boundary)
// ---------------------------------------------------------------------------

/// Named test-only boundary faults, one per adopted seed mutation
/// (codex-import 6a7606a vocabulary). They corrupt the ADAPTER side of the
/// public boundary, never the driver: the exploration must detect, shrink,
/// and retain each one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    /// `mutate-protocol-through-producer` (lock-sharing).
    ProducerProtocolMutation,
    /// `drop-first-accepted-command` (lost-command).
    DropFirstDisposition,
    /// `apply-second-command-before-front-write-drains` (queue-bypass).
    PrematureWriteProgress,
    /// `swap-committed-writes` (write-reorder).
    SwapCommittedWrites,
    /// `drop-terminal-after-shutdown` (close-race).
    DropTerminal,
    /// `repeat-terminal-on-wake` (duplicate-delivery).
    RepeatTerminal,
}

impl Fault {
    fn mutation(self) -> &'static str {
        match self {
            Fault::None => "none",
            Fault::ProducerProtocolMutation => "mutate-protocol-through-producer",
            Fault::DropFirstDisposition => "drop-first-accepted-command",
            Fault::PrematureWriteProgress => "apply-second-command-before-front-write-drains",
            Fault::SwapCommittedWrites => "swap-committed-writes",
            Fault::DropTerminal => "drop-terminal-after-shutdown",
            Fault::RepeatTerminal => "repeat-terminal-on-wake",
        }
    }

    fn parse(mutation: &str) -> Fault {
        match mutation {
            "mutate-protocol-through-producer" => Fault::ProducerProtocolMutation,
            "drop-first-accepted-command" => Fault::DropFirstDisposition,
            "apply-second-command-before-front-write-drains" => Fault::PrematureWriteProgress,
            "swap-committed-writes" => Fault::SwapCommittedWrites,
            "drop-terminal-after-shutdown" => Fault::DropTerminal,
            "repeat-terminal-on-wake" => Fault::RepeatTerminal,
            other => panic!("unknown fault mutation {other:?}"),
        }
    }
}

/// Driver-seam invariant violations the interpreter can observe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Violation {
    /// A producer-side step moved a protocol observable.
    SingleOwner,
    /// Accepted commands were not disposed exactly once each.
    LostOrDuplicatedCommand,
    /// A committed frame reached the wire out of owner FIFO order.
    WriteReorder,
    /// Wire bytes diverged from the committed frame content.
    WriteBypass,
    /// More accepted-but-undisposed commands than the bounded channel plus
    /// the single held slot can hold.
    QueueBound,
    /// A closed run did not deliver its terminal outcome under fair drain.
    Convergence,
    /// The terminal outcome was observed more than once.
    DuplicateTerminal,
    /// Outputs or dispositions kept moving after terminal quiescence.
    PostTerminalActivity,
    /// One run observed BOTH a surfaced fatal `Failure` output and a
    /// `Terminal` delivery: the two terminal dispositions must be
    /// exclusive, exactly as the real adapter (which stops at the first
    /// surfaced `Failure`) would experience them.
    TerminalAfterFailure,
    /// Two executions of the same schedule diverged.
    Nondeterminism,
}

impl Violation {
    fn property(self) -> &'static str {
        match self {
            Violation::SingleOwner => "single-owner",
            Violation::LostOrDuplicatedCommand => "accepted-eventual-exactly-once",
            Violation::WriteReorder => "fifo-owner-order",
            Violation::WriteBypass => "no-write-bypass",
            Violation::QueueBound => "queue-bounds",
            Violation::Convergence => "close-convergence",
            Violation::DuplicateTerminal => "terminal-exactly-once",
            Violation::PostTerminalActivity => "no-post-terminal",
            Violation::TerminalAfterFailure => "failure-halt-stops-driving",
            Violation::Nondeterminism => "deterministic-replay",
        }
    }

    fn counterexample(self) -> &'static str {
        match self {
            Violation::SingleOwner => "producer-protocol-mutation-visible",
            Violation::LostOrDuplicatedCommand => "accepted-not-equal-disposed",
            Violation::WriteReorder => "wire-order-swapped",
            Violation::WriteBypass => "second-wire-observed-before-first-completes",
            Violation::QueueBound => "in-flight-exceeds-bounded-capacity",
            Violation::Convergence => "no-terminal-after-fair-drain",
            Violation::DuplicateTerminal => "terminal-count-two",
            Violation::PostTerminalActivity => "movement-after-terminal",
            Violation::TerminalAfterFailure => "output-recorded-after-surfaced-failure",
            Violation::Nondeterminism => "replay-trace-divergence",
        }
    }
}

/// Identity of each producer command (payloads are distinct on purpose).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Tag {
    TextA,
    BinaryA,
    PingB,
    CloseB,
}

fn command_for(tag: Tag) -> LocalCommand {
    match tag {
        Tag::TextA => LocalCommand::SendText {
            text: "a1".to_owned(),
        },
        Tag::BinaryA => LocalCommand::SendBinary {
            data: vec![0xB1, 0xB2],
        },
        Tag::PingB => LocalCommand::SendPing { data: vec![0x50] },
        Tag::CloseB => LocalCommand::SendClose {
            code: 1000,
            reason: String::new(),
        },
    }
}

fn tag_of(command: &LocalCommand) -> Tag {
    match command {
        LocalCommand::SendText { .. } => Tag::TextA,
        LocalCommand::SendBinary { .. } => Tag::BinaryA,
        LocalCommand::SendPing { .. } => Tag::PingB,
        LocalCommand::SendClose { .. } => Tag::CloseB,
        other => panic!("unexpected command in exploration: {other:?}"),
    }
}

fn expected_frame(tag: Tag) -> &'static [u8] {
    match tag {
        Tag::TextA => FRAME_TEXT_A,
        Tag::BinaryA => FRAME_BINARY_A,
        Tag::PingB => FRAME_PING_B,
        Tag::CloseB => FRAME_CLOSE,
    }
}

/// The full owned output of one poll, retained verbatim in the trace:
/// semantic-event contents, typed failure values, and byte-exact write
/// suffixes all participate in replay equality and the trace digest.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TraceOutput {
    Idle,
    Write(Vec<u8>),
    Event(ws_core::SemanticEvent),
    Failure(ws_core::TypedProtocolFailure),
    Terminal,
}

/// One poll observation, complete: the input (kind + byte length), its full
/// typed disposition (including rejection details), the full command
/// disposition (command payloads and typed rejection failures included),
/// the full owned output, and the resulting lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TraceRecord {
    input_kind: u8,
    input_len: usize,
    input_disposition: InputDisposition,
    command: Option<CommandDisposition>,
    output: TraceOutput,
    state: ReadyState,
}

/// Deterministic, comparable outcome of one schedule execution.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct Outcome {
    trace: Vec<TraceRecord>,
    completed_writes: Vec<Vec<u8>>,
    accepted: u32,
    refused_full: u32,
    applied: u32,
    rejected: u32,
    events: u32,
    failures: u32,
    terminals: u32,
    deferred_output_pending: u32,
    deferred_command_turn: u32,
    deferred_backpressure: u32,
    rejected_inputs: u32,
    drain_polls: u32,
    closed: bool,
    /// The run stopped at its first surfaced fatal `Failure` output (the
    /// adapter-seam terminal disposition of a poisoned run).
    halted: bool,
    violations: Vec<Violation>,
}

impl Outcome {
    /// Digest over the FULL structured trace (every field of every record,
    /// via the deterministic Debug rendering) plus the committed wire log.
    fn digest(&self) -> u64 {
        let mut bytes: Vec<u8> = Vec::new();
        for record in &self.trace {
            bytes.extend_from_slice(format!("{record:?}\n").as_bytes());
        }
        for write in &self.completed_writes {
            bytes.extend_from_slice(write);
            bytes.push(0xFF);
        }
        fnv64(bytes)
    }

    fn record(&mut self, violation: Violation) {
        if !self.violations.contains(&violation) {
            self.violations.push(violation);
        }
    }
}

/// The write currently offered by the driver, as modeled by the boundary.
struct Offer {
    frame: Vec<u8>,
    accepted: usize,
}

struct Run {
    driver: ConnectionDriver,
    sender: CommandSender,
    outcome: Outcome,
    offer: Option<Offer>,
    pending_inbound: VecDeque<&'static [u8]>,
    /// FIFO frame expectations derived from observed dispositions/echoes.
    expected_frames: VecDeque<Vec<u8>>,
    accepted_tags: Vec<Tag>,
    disposed_tags: Vec<Tag>,
    shutdown_seen: bool,
    eof_seen: bool,
    /// Set when a `DriverOutput::Failure` surfaces: the modeled adapter
    /// stops driving the run at that instant, exactly like the real
    /// ws-testee io_loop (`StepOutput::Failure` ends the loop as
    /// `LoopOutcome::ProtocolFailure`). No further schedule actions,
    /// drain polls, or quiescence polls are issued.
    halted: bool,
    fault: Fault,
    fault_used: bool,
    swap_hold: Option<Vec<u8>>,
}

fn exploration_config(event_queue_capacity: u64) -> ConnectionConfig {
    ConnectionConfig::builder()
        .command_queue_capacity(COMMAND_QUEUE_CAPACITY)
        .write_queue_capacity(WRITE_QUEUE_CAPACITY)
        .event_queue_capacity(event_queue_capacity)
        .build()
        .expect("valid exploration config")
}

impl Run {
    fn new(fault: Fault, event_queue_capacity: u64) -> Run {
        // The exploration runs under the EXPLICIT
        // `AutoResponsePolicy::Disabled` configuration (US-015 AC1's
        // configurable policy): its invariants, boundary model, and
        // byte-pinned retained corpus (`fuzz-seeds/us017/minimized/`,
        // `fuzz-seeds/us017/regressions/`) are the US-017 driver-seam
        // properties, which are orthogonal to the automatic reply; the
        // default `PongInboundPing` behavior is pinned by the dedicated
        // deterministic suite in `tests/auto_response.rs` and the live
        // cross-peer loopback assertion in ws-testee.
        let (sender, driver) = connection_driver_in_state_with_policy(
            exploration_config(event_queue_capacity),
            Role::Server,
            InitialState::Open,
            AutoResponsePolicy::Disabled,
        );
        Run {
            driver,
            sender,
            outcome: Outcome::default(),
            offer: None,
            pending_inbound: VecDeque::new(),
            expected_frames: VecDeque::new(),
            accepted_tags: Vec::new(),
            disposed_tags: Vec::new(),
            shutdown_seen: false,
            eof_seen: false,
            halted: false,
            fault,
            fault_used: false,
            swap_hold: None,
        }
    }

    fn arm(&mut self, fault: Fault) -> bool {
        if self.fault == fault && !self.fault_used {
            self.fault_used = true;
            true
        } else {
            false
        }
    }

    /// One observed poll: dispositions, outputs, the FULL trace record, and
    /// the adapter-faithful halt at the first surfaced `Failure`.
    fn poll(&mut self, input: DriverInput<'_>) -> InputDisposition {
        let (input_kind, input_len) = match input {
            DriverInput::Wake => (0u8, 0usize),
            DriverInput::Inbound(bytes) => (1, bytes.len()),
            DriverInput::WriteProgress { bytes } => (2, bytes),
            DriverInput::TransportEof => (3, 0),
            DriverInput::Shutdown => (4, 0),
        };
        let (input_disposition, command, output, state) = {
            let result = self.driver.poll(input);
            let output = match result.output {
                DriverOutput::Idle => TraceOutput::Idle,
                DriverOutput::Write(suffix) => TraceOutput::Write(suffix.to_vec()),
                DriverOutput::Event(event) => TraceOutput::Event(event),
                DriverOutput::Failure(failure) => TraceOutput::Failure(failure),
                DriverOutput::Terminal(_) => TraceOutput::Terminal,
            };
            (result.input, result.command, output, result.state)
        };
        match &command {
            None => {}
            Some(CommandDisposition::Applied(command)) => {
                let tag = tag_of(command);
                if !self.arm(Fault::DropFirstDisposition) {
                    self.outcome.applied += 1;
                    self.disposed_tags.push(tag);
                    self.expected_frames.push_back(expected_frame(tag).to_vec());
                }
            }
            Some(CommandDisposition::Rejected { command, .. }) => {
                let tag = tag_of(command);
                if !self.arm(Fault::DropFirstDisposition) {
                    self.outcome.rejected += 1;
                    self.disposed_tags.push(tag);
                }
            }
        }
        match &output {
            TraceOutput::Idle => {}
            TraceOutput::Write(suffix) => {
                if let Some(offer) = &self.offer {
                    // The driver re-offers BYTE-EXACTLY the undrained
                    // suffix of the committed frame.
                    if suffix.as_slice() != &offer.frame[offer.accepted..] {
                        self.outcome.record(Violation::WriteBypass);
                    }
                } else {
                    self.offer = Some(Offer {
                        frame: suffix.clone(),
                        accepted: 0,
                    });
                }
            }
            TraceOutput::Event(_) => {
                self.outcome.events += 1;
            }
            TraceOutput::Failure(_) => {
                self.outcome.failures += 1;
                // Adapter-faithful stop: the real io_loop ends the
                // connection at the first surfaced Failure, so this run
                // stops driving here; Terminal-after-Failure is impossible
                // by construction and asserted in finish().
                self.halted = true;
            }
            TraceOutput::Terminal => {
                if self.arm(Fault::DropTerminal) {
                    // Swallowed: the adapter loses the one delivery.
                } else if self.arm(Fault::RepeatTerminal) {
                    self.outcome.terminals += 2;
                } else {
                    self.outcome.terminals += 1;
                }
                if self.outcome.terminals > 1 {
                    self.outcome.record(Violation::DuplicateTerminal);
                }
            }
        }
        match input_disposition {
            InputDisposition::Consumed { .. } => {}
            InputDisposition::Deferred(DeferredReason::OutputPending) => {
                self.outcome.deferred_output_pending += 1;
            }
            InputDisposition::Deferred(DeferredReason::CommandTurn) => {
                self.outcome.deferred_command_turn += 1;
            }
            InputDisposition::Deferred(DeferredReason::Backpressure) => {
                self.outcome.deferred_backpressure += 1;
            }
            InputDisposition::Rejected(_) => {
                self.outcome.rejected_inputs += 1;
            }
        }
        // The trace keeps the RAW observation (pre-fault-filtering): full
        // input disposition (rejection details included), full command
        // disposition (payloads and typed failures included), full owned
        // output, and the lifecycle state.
        self.outcome.trace.push(TraceRecord {
            input_kind,
            input_len,
            input_disposition,
            command,
            output,
            state,
        });
        input_disposition
    }

    /// Producer-side bounded enqueue with the single-owner check: the
    /// whole producer step must move no protocol observable.
    fn enqueue(&mut self, tag: Tag) {
        let counts_before = self.driver.counts();
        let state_before = self.driver.state();
        if self.fault == Fault::ProducerProtocolMutation && !self.fault_used && tag == Tag::TextA {
            // The seeded defect: a producer-context step drives protocol
            // input around the owner. Only counts as injected if the core
            // actually consumed it.
            let result = self.driver.poll(DriverInput::Inbound(MASKED_PING));
            if matches!(result.input, InputDisposition::Consumed { .. })
                && self.driver.counts() != counts_before
            {
                self.fault_used = true;
            }
        }
        match self.sender.try_send(command_for(tag)) {
            Ok(()) => {
                self.outcome.accepted += 1;
                self.accepted_tags.push(tag);
                let in_flight = self.accepted_tags.len() - self.disposed_tags.len();
                // Bounded channel + at most one owner-held command.
                if in_flight > (COMMAND_QUEUE_CAPACITY as usize) + 1 {
                    self.outcome.record(Violation::QueueBound);
                }
            }
            Err(refused) => {
                assert_eq!(
                    refused.command,
                    command_for(tag),
                    "a refused command returns to the producer intact"
                );
                self.outcome.refused_full += 1;
            }
        }
        if self.driver.counts() != counts_before || self.driver.state() != state_before {
            self.outcome.record(Violation::SingleOwner);
        }
    }

    /// Offer the front pending inbound chunk; consumed chunks update the
    /// echo expectation (Q19: close consumed while OPEN echoes one close).
    fn offer_inbound(&mut self) {
        let Some(front) = self.pending_inbound.front().copied() else {
            return;
        };
        let state_before = self.driver.state();
        let disposition = self.poll(DriverInput::Inbound(front));
        if matches!(disposition, InputDisposition::Consumed { .. }) {
            self.pending_inbound.pop_front();
            if front == MASKED_CLOSE_1000 && state_before == ReadyState::Open {
                self.expected_frames.push_back(FRAME_CLOSE.to_vec());
            }
        }
    }

    /// Accept `bytes` of the offered write; a completed frame is committed
    /// against the FIFO expectation.
    fn accept_write(&mut self, bytes: usize) {
        let Some(offer) = self.offer.as_mut() else {
            return;
        };
        let remaining = offer.frame.len() - offer.accepted;
        let bytes = bytes.min(remaining);
        if bytes == 0 {
            return;
        }
        offer.accepted += bytes;
        let completed = if offer.accepted == offer.frame.len() {
            self.offer.take().map(|offer| offer.frame)
        } else {
            None
        };
        // Report progress to the driver AFTER the model update: the result
        // may immediately offer the next frame.
        let _ = self.poll(DriverInput::WriteProgress { bytes });
        if let Some(frame) = completed {
            self.commit_frame(frame);
        }
    }

    fn commit_frame(&mut self, frame: Vec<u8>) {
        if self.fault == Fault::SwapCommittedWrites && self.swap_hold.is_none() && !self.fault_used
        {
            self.fault_used = true;
            self.swap_hold = Some(frame);
            return;
        }
        self.commit_frame_checked(frame);
        if let Some(held) = self.swap_hold.take() {
            self.commit_frame_checked(held);
        }
    }

    fn commit_frame_checked(&mut self, frame: Vec<u8>) {
        match self.expected_frames.front() {
            Some(front) if *front == frame => {
                self.expected_frames.pop_front();
            }
            Some(_) if self.expected_frames.contains(&frame) => {
                self.outcome.record(Violation::WriteReorder);
                self.expected_frames.retain(|expected| *expected != frame);
            }
            _ => {
                self.outcome.record(Violation::WriteBypass);
            }
        }
        self.outcome.completed_writes.push(frame);
    }

    fn exec(&mut self, action: Action) {
        if self.halted {
            // The adapter stopped at a surfaced Failure: the schedule
            // stops driving this run.
            return;
        }
        match action {
            Action::EnqueueTextA => self.enqueue(Tag::TextA),
            Action::EnqueueBinaryA => self.enqueue(Tag::BinaryA),
            Action::EnqueuePingB => self.enqueue(Tag::PingB),
            Action::EnqueueCloseB => self.enqueue(Tag::CloseB),
            Action::InboundPing => {
                self.pending_inbound.push_back(MASKED_PING);
                self.offer_inbound();
            }
            Action::InboundClose => {
                self.pending_inbound.push_back(MASKED_CLOSE_1000);
                self.offer_inbound();
            }
            Action::TransportEof => {
                self.eof_seen = true;
                let _ = self.poll(DriverInput::TransportEof);
            }
            Action::WritePartial => {
                if self.offer.is_some() {
                    self.accept_write(1);
                } else {
                    // Typed rejection polarity: progress without an offer.
                    let _ = self.poll(DriverInput::WriteProgress { bytes: 1 });
                }
            }
            Action::WriteAll => {
                if self.offer.is_none() {
                    let _ = self.poll(DriverInput::Wake);
                }
                if let Some(offer) = &self.offer {
                    let remaining = offer.frame.len() - offer.accepted;
                    if self.arm(Fault::PrematureWriteProgress) {
                        // The seeded defect: claim complete progress while
                        // the frame tail never reached the wire.
                        let frame = self
                            .offer
                            .take()
                            .map(|offer| {
                                let held_back = offer.frame.len() - 1;
                                offer.frame[..held_back].to_vec()
                            })
                            .expect("offer checked above");
                        let _ = self.poll(DriverInput::WriteProgress { bytes: remaining });
                        self.commit_frame(frame);
                    } else {
                        self.accept_write(remaining);
                    }
                }
            }
            Action::Wake => {
                let _ = self.poll(DriverInput::Wake);
            }
            Action::Shutdown => {
                self.shutdown_seen = true;
                // Undeliverable committed output is aborted with the
                // transport; the boundary drops its expectations with it.
                self.offer = None;
                self.expected_frames.clear();
                self.swap_hold = None;
                let _ = self.poll(DriverInput::Shutdown);
            }
        }
    }

    /// Weak-fairness drain: flush progress while writable, owner progress
    /// while work is pending, event drain while output is pending.
    /// Whether the last trace record moved anything (a disposition or a
    /// non-idle output).
    fn last_record_moved(&self) -> bool {
        self.outcome.trace.last().is_some_and(|record| {
            record.command.is_some() || !matches!(record.output, TraceOutput::Idle)
        })
    }

    fn fair_drain(&mut self) {
        for _ in 0..DRAIN_BUDGET {
            if self.halted {
                return;
            }
            self.outcome.drain_polls += 1;
            if self.driver.state() == ReadyState::Closed {
                self.pending_inbound.clear();
            }
            let before = (
                self.outcome.trace.len(),
                self.offer.as_ref().map(|offer| offer.accepted),
                self.pending_inbound.len(),
            );
            if let Some(offer) = &self.offer {
                let remaining = offer.frame.len() - offer.accepted;
                self.accept_write(remaining);
            } else if !self.pending_inbound.is_empty() {
                self.offer_inbound();
            } else {
                let _ = self.poll(DriverInput::Wake);
                if !self.last_record_moved()
                    && self.offer.is_none()
                    && self.pending_inbound.is_empty()
                {
                    break;
                }
            }
            let after = (
                self.outcome.trace.len(),
                self.offer.as_ref().map(|offer| offer.accepted),
                self.pending_inbound.len(),
            );
            if before == after {
                break;
            }
        }
    }

    fn finish(mut self) -> Outcome {
        self.fair_drain();
        let closed = self.driver.state() == ReadyState::Closed;
        self.outcome.closed = closed;
        self.outcome.halted = self.halted;
        // Disposition sanity that holds in EVERY end state: each command
        // instance disposed at most once, and only if accepted.
        let mut accepted_sorted = self.accepted_tags.clone();
        accepted_sorted.sort_unstable();
        let mut disposed_sorted = self.disposed_tags.clone();
        disposed_sorted.sort_unstable();
        let subset = disposed_sorted
            .iter()
            .fold(
                (true, accepted_sorted.as_slice()),
                |(ok, rest), tag| match rest.iter().position(|accepted| accepted == tag) {
                    Some(index) => (ok, &rest[index + 1..]),
                    None => (false, rest),
                },
            )
            .0;
        if !subset {
            self.outcome.record(Violation::LostOrDuplicatedCommand);
        }
        if self.halted {
            // The run stopped at its first surfaced fatal `Failure`,
            // exactly as the real adapter does: that Failure IS the
            // adapter-seam terminal (oracle partial-execution semantics —
            // a poisoned core retains its final state). The two terminal
            // dispositions are ORDERED, not merely exclusive. Owner decision
            // us017-post-terminal-owner-decision-2026-08-28
            // (`post-terminal-inbound`) makes a converged connection REFUSE
            // work that is still pushed at it, so a clean `Terminal` may
            // legitimately PRECEDE a later refusal.
            //
            // NAMING/STRENGTH CORRECTION (review
            // 01a04866-df4b-7521-8abe-d8bad09edf38): this property was called
            // `failure-halt-exclusivity` and looked only for a `Terminal`
            // recorded after the first `Failure`. Because `exec` and
            // `fair_drain` STOP DRIVING at the first surfaced failure, no
            // record of ANY kind can follow it, so that condition was
            // mechanically unreachable — a name promising more than the test
            // delivered, which is the same failure class this story has spent
            // four rounds digging out. The property is renamed
            // `failure-halt-stops-driving` and now asserts what the halt model
            // actually claims and what IS checkable: after the first surfaced
            // failure the interpreter records no command disposition and no
            // non-Idle output at all. A `Terminal` after a `Failure` is one
            // instance of that, no longer the whole of it.
            let first_failure = self
                .outcome
                .trace
                .iter()
                .position(|record| matches!(record.output, TraceOutput::Failure(_)));
            if let Some(index) = first_failure
                && self.outcome.trace[index + 1..].iter().any(|record| {
                    record.command.is_some() || !matches!(record.output, TraceOutput::Idle)
                })
            {
                self.outcome.record(Violation::TerminalAfterFailure);
            }
            // Commands still queued at the halt belong to the embedding
            // adapter's teardown; only the at-most-once subset invariant
            // above applies. No further polls are issued.
            return self.outcome;
        }
        // Non-halted run: no Failure ever surfaced (a Failure halts by
        // construction), so a transport that ended must converge to the
        // clean terminal under the weak-fairness drain.
        if (self.eof_seen || self.shutdown_seen) && !closed {
            self.outcome.record(Violation::Convergence);
        }
        if closed {
            if self.outcome.terminals == 0 {
                self.outcome.record(Violation::Convergence);
            }
            // Clean terminal reached: EVERY accepted command must have
            // been disposed exactly once (applied, typed rejection, or
            // terminal rejection) — nothing lost, nothing duplicated.
            if accepted_sorted != disposed_sorted {
                self.outcome.record(Violation::LostOrDuplicatedCommand);
            }
            // Quiescence: nothing keeps moving after the terminal.
            for _ in 0..2 {
                let _ = self.poll(DriverInput::Wake);
                if self.last_record_moved() {
                    self.outcome.record(Violation::PostTerminalActivity);
                }
            }
            // A converged run holds no committed-but-undrained frame unless
            // shutdown aborted the transport.
            if !self.shutdown_seen && (!self.expected_frames.is_empty() || self.offer.is_some()) {
                self.outcome.record(Violation::WriteBypass);
            }
        }
        self.outcome
    }
}

fn execute_with_capacity(schedule: &[Action], fault: Fault, event_queue_capacity: u64) -> Outcome {
    let mut run = Run::new(fault, event_queue_capacity);
    for action in schedule {
        run.exec(*action);
    }
    run.finish()
}

fn execute(schedule: &[Action], fault: Fault) -> Outcome {
    execute_with_capacity(schedule, fault, EVENT_QUEUE_CAPACITY)
}

/// Execute twice; any trace divergence is itself a violation.
fn execute_deterministic(schedule: &[Action], fault: Fault) -> Outcome {
    let mut first = execute(schedule, fault);
    let second = execute(schedule, fault);
    if first != second {
        first.record(Violation::Nondeterminism);
    }
    first
}

// ---------------------------------------------------------------------------
// Minimization (deterministic greedy shrink to a 1-minimal schedule)
// ---------------------------------------------------------------------------

fn violates(schedule: &[Action], fault: Fault, target: Violation) -> bool {
    execute_deterministic(schedule, fault)
        .violations
        .contains(&target)
}

/// Shrink a failing schedule to a 1-minimal failing schedule: repeatedly
/// drop single actions while the target violation persists, to fixpoint.
fn minimize(schedule: &[Action], fault: Fault, target: Violation) -> Vec<Action> {
    let mut current = schedule.to_vec();
    loop {
        let mut reduced = false;
        let mut index = 0;
        while index < current.len() {
            let mut candidate = current.clone();
            candidate.remove(index);
            if violates(&candidate, fault, target) {
                current = candidate;
                reduced = true;
            } else {
                index += 1;
            }
        }
        if !reduced {
            break;
        }
    }
    current
}

fn render_schedule(schedule: &[Action]) -> String {
    schedule
        .iter()
        .map(|action| action.verb())
        .collect::<Vec<_>>()
        .join(",")
}

fn render_seed(
    id: &str,
    fault: Fault,
    target: Violation,
    schedule: &[Action],
    event_queue_capacity: u64,
) -> String {
    let mut body = String::new();
    let _ = writeln!(body, "id={id}");
    let _ = writeln!(body, "property={}", target.property());
    let _ = writeln!(body, "mutation={}", fault.mutation());
    let _ = writeln!(body, "event_queue_capacity={event_queue_capacity}");
    let _ = writeln!(body, "schedule={}", render_schedule(schedule));
    let _ = writeln!(body, "counterexample={}", target.counterexample());
    body
}

/// Serializes writer/reader access to the minimized corpus so the
/// sanctioned `US017_RETAIN=1` regeneration and the pinned replay cannot
/// race inside one test binary.
static MINIMIZED_CORPUS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn corpus_guard() -> std::sync::MutexGuard<'static, ()> {
    MINIMIZED_CORPUS_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn minimized_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz-seeds/us017/minimized")
}

/// Retention for REAL failures: persist the minimized reproduction beside
/// the committed minimized corpus and fail with the artifact path.
fn retain_and_fail(schedule: &[Action], target: Violation, outcome: &Outcome) -> ! {
    let minimized = minimize(schedule, Fault::None, target);
    let body = render_seed(
        "retained-real-failure",
        Fault::None,
        target,
        &minimized,
        EVENT_QUEUE_CAPACITY,
    );
    let dir = minimized_dir();
    fs::create_dir_all(&dir).expect("create retention directory");
    let path = dir.join(format!("retained-{}.seed", target.property()));
    fs::write(&path, &body).expect("persist minimized failing schedule");
    panic!(
        "US-017 exploration found a real failing schedule.\n\
         violation: {target:?}\nfull schedule: {}\nminimized (retained at {}):\n{}\noutcome: {outcome:?}",
        render_schedule(schedule),
        path.display(),
        body,
    );
}

// ---------------------------------------------------------------------------
// The exploration itself
// ---------------------------------------------------------------------------

#[test]
fn bounded_exploration_is_exhaustive_and_every_schedule_upholds_the_invariants() {
    let exploration = enumerate_schedules();
    // Enumeration is itself deterministic.
    let replay = enumerate_schedules();
    assert_eq!(exploration.schedules, replay.schedules);
    assert_eq!(exploration.branches, replay.branches);

    let schedule_count = exploration.schedules.len();
    assert!(
        schedule_count <= SCHEDULE_COUNT_MAX,
        "exhaustive enumeration ({schedule_count}) must fit the declared schedule bound"
    );
    let digests = exploration
        .schedules
        .iter()
        .map(|schedule| schedule_digest(schedule))
        .collect::<BTreeSet<_>>();
    assert_eq!(digests.len(), schedule_count, "schedules are distinct");

    let mut distinct_outcomes = BTreeSet::new();
    let mut totals = Outcome::default();
    let mut max_drain = 0u32;
    let mut closed_terminal_runs = 0usize;
    let mut failure_halted_runs = 0usize;
    // Clean terminals observed in runs that LATER halted, refusing work
    // pushed at an already-converged connection (owner decision
    // post-terminal-inbound).
    let mut halted_terminals = 0usize;
    for schedule in &exploration.schedules {
        let outcome = execute_deterministic(schedule, Fault::None);
        if let Some(violation) = outcome.violations.first().copied() {
            retain_and_fail(schedule, violation, &outcome);
        }
        // Every full schedule reaches EXACTLY ONE of the two typed
        // terminal dispositions, mirroring the real adapter: the clean
        // Terminal from the absorbing Closed state, or the halt at the
        // first surfaced fatal Failure (the poisoned core's final state
        // per the oracle's partial-execution semantics). Since the
        // post-terminal ruling these are ORDERED rather than mutually
        // exclusive: a schedule may converge cleanly, take its one Terminal,
        // and then have further work pushed at the converged connection,
        // which the core refuses. The ordering property (no Terminal AFTER a
        // Failure) is asserted in `finish` against the trace itself.
        if outcome.halted {
            assert_eq!(outcome.failures, 1, "the halt is the first failure");
            assert!(
                outcome.terminals <= 1,
                "at most one terminal, and only before the failure"
            );
            halted_terminals += usize::try_from(outcome.terminals).expect("small count");
            failure_halted_runs += 1;
        } else {
            assert!(outcome.closed, "a non-halted full schedule converges");
            assert_eq!(outcome.failures, 0, "any surfaced failure halts");
            assert_eq!(outcome.terminals, 1, "terminal delivered exactly once");
            closed_terminal_runs += 1;
        }
        distinct_outcomes.insert(outcome.digest());
        totals.accepted += outcome.accepted;
        totals.refused_full += outcome.refused_full;
        totals.applied += outcome.applied;
        totals.rejected += outcome.rejected;
        totals.events += outcome.events;
        totals.failures += outcome.failures;
        totals.terminals += outcome.terminals;
        totals.deferred_output_pending += outcome.deferred_output_pending;
        totals.deferred_command_turn += outcome.deferred_command_turn;
        totals.deferred_backpressure += outcome.deferred_backpressure;
        totals.rejected_inputs += outcome.rejected_inputs;
        max_drain = max_drain.max(outcome.drain_polls);
    }

    // Coverage honesty: the schedule space actually REACHED the bounded
    // refusal, every deferral reason, and the typed input rejection.
    assert!(totals.refused_full > 0, "queue-full refusals were explored");
    assert!(totals.deferred_output_pending > 0);
    assert!(totals.deferred_command_turn > 0);
    assert!(
        totals.deferred_backpressure > 0,
        "backpressure was explored"
    );
    assert!(totals.rejected_inputs > 0, "typed input rejection explored");
    assert_eq!(
        totals.terminals as usize,
        closed_terminal_runs + halted_terminals,
        "exactly one terminal per Closed run, plus the clean terminals of runs that \
         later halted refusing post-convergence work"
    );
    assert_eq!(
        totals.failures as usize, failure_halted_runs,
        "exactly one surfaced failure per halted run and none elsewhere"
    );
    assert_eq!(closed_terminal_runs + failure_halted_runs, schedule_count);
    assert!(closed_terminal_runs > 0, "clean convergence explored");
    assert!(
        failure_halted_runs > 0,
        "the failure-halt disposition was explored"
    );

    println!(
        "US017_EXPLORATION programs={PROGRAM_COUNT} actions_total={} context_switch_bound={CONTEXT_SWITCH_BOUND} \
         preemption_budget={PREEMPTION_BUDGET} schedules={schedule_count} branches={} truncated=false \
         executions={} distinct_trace_digests={} closed_terminal_runs={closed_terminal_runs} \
         failure_halted_runs={failure_halted_runs} accepted={} refused_full={} applied={} rejected={} \
         events={} failures={} deferred_output_pending={} deferred_command_turn={} \
         deferred_backpressure={} rejected_inputs={} max_drain_polls={max_drain}",
        PROGRAMS.iter().map(|program| program.len()).sum::<usize>(),
        exploration.branches,
        schedule_count * 2,
        distinct_outcomes.len(),
        totals.accepted,
        totals.refused_full,
        totals.applied,
        totals.rejected,
        totals.events,
        totals.failures,
        totals.deferred_output_pending,
        totals.deferred_command_turn,
        totals.deferred_backpressure,
        totals.rejected_inputs,
    );
}

// ---------------------------------------------------------------------------
// Retention demonstration: the six named boundary faults are found by the
// exploration, shrunk to 1-minimal schedules, and pinned as artifacts.
// ---------------------------------------------------------------------------

const NAMED_FAULTS: [(&str, Fault, Violation); 6] = [
    (
        "lock-sharing",
        Fault::ProducerProtocolMutation,
        Violation::SingleOwner,
    ),
    (
        "lost-command",
        Fault::DropFirstDisposition,
        Violation::LostOrDuplicatedCommand,
    ),
    (
        "queue-bypass",
        Fault::PrematureWriteProgress,
        Violation::WriteBypass,
    ),
    (
        "write-reorder",
        Fault::SwapCommittedWrites,
        Violation::WriteReorder,
    ),
    ("close-race", Fault::DropTerminal, Violation::Convergence),
    (
        "duplicate-delivery",
        Fault::RepeatTerminal,
        Violation::DuplicateTerminal,
    ),
];

/// Find the first schedule (in deterministic enumeration order) on which a
/// fault manifests as its target violation.
fn first_failing_schedule(
    exploration: &Exploration,
    fault: Fault,
    target: Violation,
) -> Option<(usize, Vec<Action>)> {
    exploration
        .schedules
        .iter()
        .enumerate()
        .find(|(_, schedule)| violates(schedule, fault, target))
        .map(|(index, schedule)| (index, schedule.clone()))
}

#[test]
fn retention_minimizes_every_named_fault_and_pins_the_artifacts() {
    let _guard = corpus_guard();
    let regenerate = std::env::var("US017_RETAIN").as_deref() == Ok("1");
    let exploration = enumerate_schedules();
    for (name, fault, target) in NAMED_FAULTS {
        // 1. The exploration DETECTS the fault (harness polarity).
        let (index, failing) = first_failing_schedule(&exploration, fault, target)
            .unwrap_or_else(|| panic!("fault {name} was not detected by the exploration"));

        // 2. Deterministic shrink to a 1-minimal failing schedule.
        let minimized = minimize(&failing, fault, target);
        assert!(minimized.len() <= failing.len());
        assert!(
            violates(&minimized, fault, target),
            "{name}: minimized schedule still fails under the fault"
        );
        for drop_index in 0..minimized.len() {
            let mut candidate = minimized.clone();
            candidate.remove(drop_index);
            assert!(
                !violates(&candidate, fault, target),
                "{name}: minimized schedule is 1-minimal"
            );
        }

        // 3. Fault localization: the same minimized schedule passes clean.
        let clean = execute_deterministic(&minimized, Fault::None);
        assert!(
            clean.violations.is_empty(),
            "{name}: minimized schedule passes without the fault: {clean:?}"
        );

        // 4. The faulty run injected the fault exactly once.
        let faulty = execute_deterministic(&minimized, fault);
        assert!(
            faulty.violations.contains(&target),
            "{name}: counterexample observed"
        );

        // 5. Retention: the minimized schedule is a committed artifact.
        let body = render_seed(
            &format!("minimized-{name}"),
            fault,
            target,
            &minimized,
            EVENT_QUEUE_CAPACITY,
        );
        let path = minimized_dir().join(format!("{name}.seed"));
        if regenerate {
            fs::create_dir_all(minimized_dir()).expect("create minimized dir");
            fs::write(&path, &body).expect("write minimized artifact");
        }
        let committed = fs::read_to_string(&path).unwrap_or_else(|err| {
            panic!(
                "{name}: committed minimized artifact missing at {} ({err}); \
                 run US017_RETAIN=1 to regenerate deliberately",
                path.display()
            )
        });
        assert_eq!(
            committed,
            body,
            "{name}: committed minimized artifact matches the freshly minimized schedule \
             (found at exploration index {index}, {} -> {} actions)",
            failing.len(),
            minimized.len(),
        );
        println!(
            "US017_RETENTION fault={name} found_index={index} full_len={} minimized_len={} schedule={}",
            failing.len(),
            minimized.len(),
            render_schedule(&minimized),
        );
    }
}

/// Fixed real defects found by this exploration: their minimized
/// reproductions are committed under `fuzz-seeds/us017/regressions/` and
/// must pass on the shipped driver forever.
///
/// `eof-backpressure-livelock.seed` is the exploration's first real find
/// (minimized 12 -> 3 actions): the driver latched `eof_applied` even when
/// the core refused the EOF with non-fatal event-queue backpressure, so
/// the EOF was lost, the close never converged, and no terminal was ever
/// delivered.
#[test]
fn fixed_defect_regressions_replay_clean_on_the_shipped_driver() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz-seeds/us017/regressions");
    let mut names = fs::read_dir(&dir)
        .expect("regressions corpus present")
        .map(|entry| {
            entry
                .expect("read dir entry")
                .file_name()
                .into_string()
                .expect("utf8 name")
        })
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(names, ["eof-backpressure-livelock.seed"]);
    for name in names {
        let body = fs::read_to_string(dir.join(&name)).expect("read regression seed");
        let mut fields = std::collections::BTreeMap::new();
        for line in body.lines().filter(|line| !line.trim().is_empty()) {
            let (key, value) = line.split_once('=').expect("key=value seed line");
            fields.insert(key.trim().to_owned(), value.trim().to_owned());
        }
        assert_eq!(fields["mutation"], "none", "{name}: a real-defect pin");
        let capacity: u64 = fields["event_queue_capacity"]
            .parse()
            .expect("numeric capacity");
        let schedule = fields["schedule"]
            .split(',')
            .map(|verb| Action::parse(verb.trim()))
            .collect::<Vec<_>>();
        // The reproduction runs under the exact configuration that exposed
        // the defect (a smaller event queue than the exploration default).
        let outcome = execute_with_capacity(&schedule, Fault::None, capacity);
        let replay = execute_with_capacity(&schedule, Fault::None, capacity);
        assert_eq!(outcome, replay, "{name}: deterministic replay");
        assert!(
            outcome.violations.is_empty(),
            "{name}: fixed defect must stay fixed: {outcome:?}"
        );
        assert!(outcome.closed, "{name}: the run converges to Closed");
        assert_eq!(outcome.terminals, 1, "{name}: terminal delivered once");
    }
}

/// The committed minimized artifacts replay as regressions on their own:
/// parse from disk, fail under the named fault, pass clean.
#[test]
fn committed_minimized_schedules_replay_as_regressions() {
    let _guard = corpus_guard();
    let dir = minimized_dir();
    let mut names = fs::read_dir(&dir)
        .unwrap_or_else(|err| {
            panic!(
                "minimized corpus missing at {} ({err}); run US017_RETAIN=1 to regenerate",
                dir.display()
            )
        })
        .map(|entry| {
            entry
                .expect("read dir entry")
                .file_name()
                .into_string()
                .expect("utf8 name")
        })
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(
        names,
        [
            "close-race.seed",
            "duplicate-delivery.seed",
            "lock-sharing.seed",
            "lost-command.seed",
            "queue-bypass.seed",
            "write-reorder.seed",
        ],
        "exactly the six named minimized artifacts are retained"
    );
    for name in names {
        let body = fs::read_to_string(dir.join(&name)).expect("read minimized seed");
        let mut fields = std::collections::BTreeMap::new();
        for line in body.lines().filter(|line| !line.trim().is_empty()) {
            let (key, value) = line.split_once('=').expect("key=value seed line");
            fields.insert(key.trim().to_owned(), value.trim().to_owned());
        }
        let fault = Fault::parse(&fields["mutation"]);
        let capacity: u64 = fields["event_queue_capacity"]
            .parse()
            .expect("numeric capacity");
        let schedule = fields["schedule"]
            .split(',')
            .map(|verb| Action::parse(verb.trim()))
            .collect::<Vec<_>>();
        let target = *NAMED_FAULTS
            .iter()
            .find(|(_, named_fault, _)| *named_fault == fault)
            .map(|(_, _, target)| target)
            .expect("named fault");
        assert_eq!(fields["property"], target.property(), "{name}");
        assert_eq!(fields["counterexample"], target.counterexample(), "{name}");
        assert!(
            execute_with_capacity(&schedule, fault, capacity)
                .violations
                .contains(&target),
            "{name}: retained schedule reproduces its counterexample"
        );
        let clean = execute_with_capacity(&schedule, Fault::None, capacity);
        let clean_replay = execute_with_capacity(&schedule, Fault::None, capacity);
        assert_eq!(clean, clean_replay, "{name}: deterministic replay");
        assert!(
            clean.violations.is_empty(),
            "{name}: retained schedule passes on the real driver: {clean:?}"
        );
    }
}
