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
use ws_core::connection::CommandRefusalReason;
use ws_core::{CommandSender, InitialState, LocalCommand, ReadyState, Role};
use ws_driver::{
    AutoResponsePolicy, CommandDisposition, ConnectionDriver, DeferredReason, DriverInput,
    DriverOutput, DroppedWrites, InputDisposition, connection_driver_in_state_with_policy,
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

/// The action budget for the MAIN sweep. 1024 is the `ConnectionConfig`
/// default and is far above the 12-action alphabet, so no schedule can
/// reach `ActionLimitExceeded` there: the main sweep's classification is
/// exactly what it would be with the budget left unset.
const MAX_ACTIONS_UNREACHED: u64 = 1024;
/// Action budgets for the FATAL-TERMINATION sweep (US-017 story review
/// round 2, session 01a0464f). A budget of N makes action N+1 fail FATALLY
/// with `ActionLimitExceeded`, which is the reachable way to end a run
/// fatally while committed writes are still outstanding. Budget 0 fails the
/// very first action (nothing can be committed first); 1..=3 let a schedule
/// commit writes and THEN hit the wall, which is the interleaving class the
/// suppressed-report defect lives in.
const FATAL_SWEEP_ACTION_BUDGETS: [u64; 4] = [0, 1, 2, 3];

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

/// One scenario's five fixed actor programs.
type ProgramSet = [&'static [Action]; PROGRAM_COUNT];

/// Scenario A — ABNORMAL TEARDOWN. The adapter stops serving the transport
/// (`Shutdown`) AND the read side independently reaches EOF, so the
/// connection is terminated TWICE. This models a real but exceptional
/// shape: the embedding application tearing down, or the write side
/// failing, while the peer is also closing.
///
/// This was the ONLY scenario explored until owner decision
/// `us017-exploration-program-set-owner-decision-2026-08-28.json`
/// (sha 86793909). Because every schedule ran both terminations, and
/// because the driver silently COALESCED multiple pending EOF
/// notifications until 8a7e3a4, its "clean convergence" runs were an
/// artifact of that defect rather than evidence of clean convergence. With
/// the coalescing fixed, every schedule in this scenario correctly halts on
/// the second scored termination — which is right, and is why a second
/// scenario is required to cover the normal lifecycle at all.
///
/// RECORD models: the exceptional path: the embedding application tearing
/// down, or the write side failing, while the peer is also closing. The
/// adapter Shutdowns AND the read side reaches EOF, so the connection is
/// terminated twice.
/// RECORD why_explored: the original and, until owner decision
/// us017-exploration-program-set-owner-decision-2026-08-28 (sha 86793909),
/// the ONLY program set. With the driver's EOF coalescing fixed, every
/// schedule here halts on the second scored termination, which is correct
/// and is why a second scenario is required to cover the normal lifecycle
/// at all.
const SCENARIO_ABNORMAL_TEARDOWN: ProgramSet = [
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

/// Scenario B — CLEAN FINISH. The connection is terminated exactly ONCE.
///
/// REAL-ADAPTER JUSTIFICATION (owner requirement 1: this must be a shape a
/// real adapter produces, not a shape reverse-engineered to make a gate
/// green). This is the ordinary WebSocket close lifecycle: the application
/// sends a message and initiates close, the peer's close frame arrives, the
/// committed frames flush, and the read side reaches EOF exactly once. A
/// healthy adapter never calls `Shutdown` on this path — `Shutdown` means
/// "the adapter can provide no further transport service" and belongs to
/// abnormal teardown (scenario A). The `ws-testee` io_loop drives exactly
/// this shape: it reads until EOF and lets the connection converge, calling
/// shutdown only when it is itself being torn down.
///
/// The point is not that this scenario is easier. It is that the previous
/// program set modelled ONLY the abnormal double-termination path, so the
/// normal lifecycle every real deployment spends its life in was never
/// actually explored — its apparent coverage came from two terminations
/// being silently merged into one.
///
/// RECORD models: the ordinary WebSocket close lifecycle: the application
/// sends a message and initiates close, the peer's close frame arrives, the
/// committed frames flush, and the read side reaches EOF exactly ONCE. A
/// healthy adapter never calls Shutdown on this path - Shutdown means the
/// adapter can provide no further transport service and belongs to abnormal
/// teardown. The ws-testee io_loop drives exactly this shape.
/// RECORD why_explored: owner decision
/// us017-exploration-program-set-owner-decision-2026-08-28 (sha 86793909).
/// The previous single-scenario set modelled ONLY the abnormal
/// double-termination path, so the normal lifecycle every real deployment
/// spends its life in was never actually explored - its apparent coverage
/// came from two terminations being silently merged into one by the
/// driver's EOF coalescing defect. Its clean route is NARROW: 49 of its
/// 1260 schedules reach a clean terminal and they carry 18 distinct
/// semantic traces, which is why scenario clean-finish-inbound-ping exists
/// beside it rather than instead of it.
const SCENARIO_CLEAN_FINISH: ProgramSet = [
    // Producer A: one bounded data command.
    &[Action::EnqueueTextA],
    // Producer B: the local close that opens the closing handshake.
    &[Action::EnqueueCloseB],
    // Transport read: the peer's close, then the read side ending ONCE.
    &[Action::InboundClose, Action::TransportEof],
    // Transport write: flush the committed frames to completion.
    &[Action::WriteAll, Action::WriteAll],
    // Adapter control: owner turns only; no shutdown on a healthy close.
    &[Action::Wake],
];

/// Scenario C — CLEAN FINISH WITH AN INBOUND PING IN FLIGHT. The same
/// single-termination lifecycle as scenario B, at scenario A's richness.
///
/// REAL-ADAPTER JUSTIFICATION (owner requirement 1, the same one scenario B
/// is held to). Every action here is one a real deployment produces on the
/// ordinary path: the application sends a message and initiates close; the
/// peer sends a keepalive ping BEFORE its close frame, which is the common
/// case a server sees because peers ping on an idle timer that does not
/// know a close is coming; the committed frames flush; the read side ends
/// exactly ONCE; and the adapter takes TWO owner turns, because an adapter
/// polls repeatedly rather than exactly once. No `Shutdown`, for the reason
/// scenario B gives: a healthy adapter never calls it on this path.
///
/// WHY IT EXISTS, measured rather than asserted (this branch, the
/// post-failure landing review's finding 1). Scenario B reaches a clean
/// terminal in 49 of its 1,260 schedules, and those 49 runs carry only 18
/// DISTINCT semantic trace digests, so the four properties that hold only
/// on the clean route — convergence, the exactly-once reconciliation, the
/// post-terminal quiescence, and the no-write-bypass check — were being
/// exercised against eighteen behaviours. A clean finish requires both
/// producer enqueues to land before the peer's close, and with seven
/// actions across five programs almost every interleaving loses that race.
/// Lengthening the READ program instead of the producer programs is what
/// buys clean breadth: an inbound ping ahead of the close gives the
/// producers somewhere to be scheduled that is not a state violation.
/// Measured on this scenario alone: 1,127 clean-terminal runs carrying 385
/// distinct digests, against scenario B's 49 and 18.
///
/// IT DOES NOT REPLACE SCENARIO B. B's clean digests are not a subset of
/// C's — B flushes a text and a close with no ping on the wire — so B is
/// kept and C is APPENDED, which also leaves every schedule index in
/// scenarios A and B unchanged and so leaves the pinned retention seeds'
/// `found_index` ordinals untouched.
///
/// RECORD models: the ordinary WebSocket close lifecycle with a keepalive
/// ping still in flight: the application sends a message and initiates
/// close, the peer's ping arrives ahead of its close frame because peers
/// ping on an idle timer that does not know a close is coming, the
/// committed frames flush, and the read side reaches EOF exactly ONCE. Two
/// owner turns, because an adapter polls repeatedly. No Shutdown, for the
/// reason scenario clean-finish gives.
/// RECORD why_explored: the post-failure landing review's finding 1
/// (drafts/self-review/post-failure-landing-review.md). Scenario
/// clean-finish reaches a clean terminal in 49 of its 1260 schedules and
/// those 49 runs carry only 18 distinct semantic traces, so the four
/// properties that hold ONLY on the clean route were exercised against
/// eighteen behaviours in a single scenario. Lengthening the READ program
/// rather than the producer programs is what buys clean breadth, because it
/// gives the producers somewhere to be scheduled that is not a state
/// violation. Measured on this scenario alone: 1127 clean-terminal runs
/// carrying 385 distinct traces.
const SCENARIO_CLEAN_FINISH_INBOUND_PING: ProgramSet = [
    // Producer A: one bounded data command.
    &[Action::EnqueueTextA],
    // Producer B: the local close that opens the closing handshake.
    &[Action::EnqueueCloseB],
    // Transport read: the peer's keepalive ping, its close, then the read
    // side ending ONCE.
    &[
        Action::InboundPing,
        Action::InboundClose,
        Action::TransportEof,
    ],
    // Transport write: flush the committed frames to completion.
    &[Action::WriteAll, Action::WriteAll],
    // Adapter control: two owner turns; no shutdown on a healthy close.
    &[Action::Wake, Action::Wake],
];

/// Every scenario explored, each an independent bounded enumeration.
///
/// ORDER IS LOAD-BEARING. The explored space is the concatenation of the
/// per-scenario enumerations, so a schedule's index is its position in this
/// order. The pinned retention artifacts carry `found_index=` ordinals
/// against that indexing; appending a scenario preserves them, inserting or
/// reordering one does not.
const SCENARIOS: [(&str, ProgramSet); 3] = [
    ("abnormal-teardown", SCENARIO_ABNORMAL_TEARDOWN),
    ("clean-finish", SCENARIO_CLEAN_FINISH),
    (
        "clean-finish-inbound-ping",
        SCENARIO_CLEAN_FINISH_INBOUND_PING,
    ),
];

// ---------------------------------------------------------------------------
// Exhaustive bounded enumeration
// ---------------------------------------------------------------------------

struct Exploration {
    schedules: Vec<Vec<Action>>,
    branches: usize,
    /// `(scenario name, how many schedules that scenario contributed)`, in
    /// the order the scenarios are concatenated. This is what lets the sweep
    /// say WHERE its clean terminals are instead of only how many there are —
    /// the distinction the post-failure landing review's finding 1 turned on.
    spans: Vec<(&'static str, usize)>,
}

fn enumerate_schedules() -> Exploration {
    fn visit(
        programs: &ProgramSet,
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
            .all(|(actor, position)| *position == programs[actor].len())
        {
            schedules.push(schedule.clone());
            return;
        }
        for actor in 0..PROGRAM_COUNT {
            if positions[actor] == programs[actor].len() {
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
                .filter(|other| *other != actor && positions[*other] < programs[*other].len())
                .count();
            if next_switches + unfinished_others > CONTEXT_SWITCH_BOUND {
                continue;
            }
            *branches += 1;
            assert!(
                *branches <= BRANCH_COUNT_MAX,
                "enumeration exceeded the declared branch bound"
            );
            let action = programs[actor][positions[actor]];
            positions[actor] += 1;
            schedule.push(action);
            visit(
                programs,
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
    let mut spans = Vec::new();
    // Each scenario is its own bounded enumeration; the explored space is
    // their union, concatenated in SCENARIOS order.
    for (name, programs) in &SCENARIOS {
        let before = schedules.len();
        visit(
            programs,
            &mut schedules,
            &mut branches,
            &mut [0; PROGRAM_COUNT],
            &mut Vec::new(),
            None,
            0,
        );
        spans.push((*name, schedules.len() - before));
    }
    Exploration {
        schedules,
        branches,
        spans,
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
    /// `drop-writes-dropped-report` (silent-write-drop): the adapter
    /// swallows the typed dropped-write disposition, which is exactly the
    /// US-017 story-review BLOCKING-2 behavior (committed pending writes
    /// abandoned on shutdown with nothing reported).
    DropWritesDroppedReport,
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
            Fault::DropWritesDroppedReport => "drop-writes-dropped-report",
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
            "drop-writes-dropped-report" => Fault::DropWritesDroppedReport,
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
    /// The interpreter kept driving past the first surfaced fatal
    /// `Failure`, so the trace carries a record after it.
    ///
    /// SCOPE, stated exactly, because the previous two phrasings both
    /// promised more than they delivered. This is a property of the
    /// INTERPRETER's halt model, NOT of the driver. The halt is enforced
    /// here (`poll` sets `halted`; `exec` and `fair_drain` return on it),
    /// so a correct interpreter can never record anything after the
    /// failure — and the driver is never asked whether it would have.
    /// See the reachability note in `finish` for what is and is not
    /// verified, and for the measurement behind that distinction.
    ///
    /// THE PROPERTY NAME WAS THE THIRD THING THAT OVERPROMISED, and it is
    /// now fixed: `property()` reads
    /// `interpreter-halts-at-first-surfaced-failure`, not
    /// `failure-halt-stops-driving`. The old name named a DRIVER guarantee
    /// while the check is a property of this interpreter, which is the
    /// same conflation the two predicate rounds documented in `finish`
    /// made — expressed in the one place a reader looks first (owner
    /// decision `us017-post-failure-owner-decisions-2026-08-28.json`,
    /// sequencing note; investigation finding C4).
    ///
    /// C5 CAVEAT — WHAT "FAILURE" MEANS HERE, AND WHY IT NOW MEANS MORE
    /// THAN IT DID. The halt keys on `DriverOutput::Failure`, which is NOT
    /// the same predicate as "a fatal happened". A fatal reaches the owner
    /// by two routes, and the COMMAND route used to surface only a
    /// `CommandDisposition::Rejected` with no `Failure` output at all
    /// (`ws_driver::ConnectionDriver::finish_poll` was called with
    /// `failure = None`), while `ws_core::ConnectionCore::handle` poisoned
    /// the core all the same. Neither halt model halted on it and the
    /// poisoned connection could still deliver a clean `Terminal`. That
    /// asymmetry was ruled a defect
    /// (`c5-fatal-command-rejection-surfaces-failure`) and fixed at the
    /// source in `finish_poll`, so a fatal now surfaces a `Failure`
    /// whichever way it arrived. Two consequences for this suite, stated
    /// rather than left to be rediscovered: schedules whose fatal arrives
    /// as a command rejection now HALT where they previously ran on, which
    /// moves runs from the `closed_terminal_runs` column into
    /// `failure_halted_runs` while their sum is unchanged; and the
    /// `failure`-vs-`fatal` gap the accounting note at the bottom of
    /// `finish` warns about is narrowed by the fix but is NOT claimed
    /// closed — only measurement, not this comment, can say that.
    TerminalAfterFailure,
    /// Committed writes the ended transport abandoned were not reported
    /// back to the adapter with the typed dropped-write disposition, or the
    /// report did not account for exactly what was abandoned (US-017 AC2
    /// adapter shutdown; story review BLOCKING-2).
    UnreportedWriteDrop,
    /// A committed write was offered to a transport that had already been
    /// shut down.
    WriteAfterShutdown,
    /// A send after the sole owner was dropped did not yield the typed
    /// receiver-drop refusal (US-017 AC2 receiver-drop; story review
    /// BLOCKING-1).
    ReceiverDropUnreported,
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
            Violation::TerminalAfterFailure => "interpreter-halts-at-first-surfaced-failure",
            Violation::UnreportedWriteDrop => "shutdown-write-drop-reported",
            Violation::WriteAfterShutdown => "no-write-after-shutdown",
            Violation::ReceiverDropUnreported => "receiver-drop-typed",
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
            Violation::UnreportedWriteDrop => "committed-writes-abandoned-unreported",
            Violation::WriteAfterShutdown => "write-offered-after-shutdown",
            Violation::ReceiverDropUnreported => "send-accepted-after-owner-drop",
            Violation::Nondeterminism => "replay-trace-divergence",
        }
    }
}

/// The invariant property ids this exploration checks, in the order the
/// acceptance record (`assurance/concurrency/results.json` `invariants`)
/// lists them.
///
/// WHY THIS EXISTS. Review 01a0487b round 2 BLOCKING: the whole `invariants`
/// array was unmodeled by both validators, so its ten `PASS` outcomes were
/// decoration a reader trusted and nothing could contradict. Measured before
/// this: the array could be rewritten wholesale and both halves still exited
/// 0. The exploration now PRINTS the array it actually checked, so the
/// document's copy is re-derived from the run like every counter.
///
/// `violation_index` looks a variant up in THIS array and panics if it is
/// absent, and `Outcome::record` calls it on every recorded violation — so a
/// new `Violation` variant that can actually fire cannot stay undeclared.
const CHECKED_INVARIANTS: [Violation; 13] = [
    Violation::SingleOwner,
    Violation::QueueBound,
    Violation::LostOrDuplicatedCommand,
    Violation::WriteReorder,
    Violation::WriteBypass,
    Violation::Convergence,
    Violation::DuplicateTerminal,
    Violation::PostTerminalActivity,
    Violation::TerminalAfterFailure,
    Violation::Nondeterminism,
    // The three US-017 AC2 dispositions (claude/us017-ac2, landed 7262a29)
    // the acceptance record lists after the original ten. They are checked
    // by the same per-schedule accounting as the rest, so printing them
    // from the observed set is derived, not declared.
    Violation::UnreportedWriteDrop,
    Violation::WriteAfterShutdown,
    Violation::ReceiverDropUnreported,
];

/// The namespace the acceptance record prefixes every property id with.
const INVARIANT_NAMESPACE: &str = "concurrency.";

/// The three weak-fairness assumptions `fair_drain` implements, in the order
/// the acceptance record lists them. They gate ONLY the final drain; no
/// fairness is assumed during the schedule itself.
const WEAK_FAIRNESS: [&str; 3] = [
    "WEAK_OWNER_PROGRESS_WHEN_WORK_PENDING",
    "WEAK_FLUSH_PROGRESS_WHEN_WRITABLE",
    "WEAK_EVENT_DRAIN_WHEN_OUTPUT_PENDING",
];

/// The producer-admission fairness stance this exploration takes, matching
/// the preregistered plan's `PRODUCER_ADMISSION_FAIRNESS_ABSENT` entry.
///
/// "absent" is a structural property of the enumeration, not a label:
/// `enumerate_schedules` advances `positions[actor]` on every visit, so a
/// producer step is CONSUMED whether or not the command was admitted. A
/// queue-full refusal is therefore final for that step and no producer is
/// ever guaranteed admission ahead of another.
/// `producer_admission_is_absent_by_construction` asserts it against a real
/// schedule rather than trusting this string.
const PRODUCER_ADMISSION_FAIRNESS: &str = "absent";

/// Position of `violation` in [`CHECKED_INVARIANTS`].
fn violation_index(violation: Violation) -> usize {
    CHECKED_INVARIANTS
        .iter()
        .position(|candidate| *candidate == violation)
        .unwrap_or_else(|| {
            panic!(
                "{violation:?} is a checked invariant violation but is not declared in \
                 CHECKED_INVARIANTS, so the exploration would print an invariant list that \
                 omits it and the acceptance record would claim coverage it does not have"
            )
        })
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
    WritesDropped(DroppedWrites),
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
    /// Typed dropped-write dispositions surfaced (US-017 AC2).
    write_drop_reports: u32,
    /// Committed frames and undelivered bytes those reports accounted for.
    dropped_frames: usize,
    dropped_bytes: usize,
    /// Whether a report said the abandoned front write was already partly
    /// on the wire.
    dropped_partial_front: bool,
    /// Typed receiver-drop refusals observed by the end-of-run probe
    /// (US-017 AC2; exactly one per non-halted run).
    receiver_drop_refusals: u32,
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
        // Panics if the variant is not declared in CHECKED_INVARIANTS, so a
        // violation the exploration can actually observe cannot be missing
        // from the invariant list it prints.
        let _ = violation_index(violation);
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
    /// What the BOUNDARY independently computed the ended transport still
    /// owed at the shutdown instant: committed frames not fully on the
    /// wire, their undelivered bytes, and whether the front one was
    /// already partly written. The driver's typed report must match it
    /// exactly — that equality is the US-017 AC2 no-leak check.
    owed_frames: usize,
    owed_bytes: usize,
    owed_partial_front: bool,
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

fn exploration_config(event_queue_capacity: u64, max_actions: u64) -> ConnectionConfig {
    ConnectionConfig::builder()
        .command_queue_capacity(COMMAND_QUEUE_CAPACITY)
        .write_queue_capacity(WRITE_QUEUE_CAPACITY)
        .event_queue_capacity(event_queue_capacity)
        .max_actions(max_actions)
        .build()
        .expect("valid exploration config")
}

impl Run {
    fn new(fault: Fault, event_queue_capacity: u64, max_actions: u64) -> Run {
        // The exploration runs under the EXPLICIT
        // `AutoResponsePolicy::Disabled` configuration (US-015 AC1's
        // configurable policy): its invariants, boundary model, and
        // byte-pinned retained corpus (`fuzz-seeds/us017/minimized/`,
        // `fuzz-seeds/us017/regressions/`) are the US-017 driver-seam
        // properties, which are orthogonal to the automatic reply; the
        // default `PongInboundPing` behavior is pinned by the dedicated
        // deterministic suite in `tests/auto_response.rs` and the live
        // cross-peer loopback assertion in ws-testee.
        //
        // DISCLOSED CONSEQUENCE (pre-landing review finding 1, session
        // 01a04960): this sweep therefore cannot reach ANY interaction
        // between the automatic reply and shutdown, and the reviewer found
        // two that were reachable under the default policy — a post-shutdown
        // Ping delivery committing a pong (a real defect, now fixed by the
        // `!shutdown_latched` gate in `ConnectionDriver::next_output`), and a
        // report legitimately carrying TWO committed frames. Both are pinned
        // by `driver_contract.rs::a_ping_delivered_after_shutdown_injects_no_pong_and_emits_no_second_report`
        // and `..::a_shutdown_report_accounts_for_every_committed_frame_not_just_the_offered_one`,
        // which is where the default policy meets shutdown. Do not read the
        // one-report/one-frame counters below as properties of the default
        // policy; they are properties of THIS sweep's configuration.
        let (sender, driver) = connection_driver_in_state_with_policy(
            exploration_config(event_queue_capacity, max_actions),
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
            owed_frames: 0,
            owed_bytes: 0,
            owed_partial_front: false,
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
                DriverOutput::Failure { failure, .. } => TraceOutput::Failure(failure),
                DriverOutput::WritesDropped(dropped) => TraceOutput::WritesDropped(dropped),
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
                if self.shutdown_seen {
                    // US-017 AC2: a transport that has ended can deliver
                    // nothing, so no committed write may be offered to it.
                    self.outcome.record(Violation::WriteAfterShutdown);
                }
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
                // stops driving here.
                //
                // Note the consequence, spelled out because two rounds of
                // this suite asserted around it without stating it: because
                // the halt latches HERE, before the trace record is pushed,
                // the failure is always the FINAL record. Nothing after it
                // can be observed, so `finish` can only check that the halt
                // held — never what the driver would have done next. See the
                // reachability note in `finish`.
                self.halted = true;
            }
            TraceOutput::WritesDropped(dropped) => {
                if self.arm(Fault::DropWritesDroppedReport) {
                    // The seeded defect: the adapter never learns that
                    // committed writes were abandoned — the exact
                    // BLOCKING-2 behavior, now caught by the accounting
                    // check in `finish`.
                } else {
                    self.outcome.write_drop_reports += 1;
                    self.outcome.dropped_frames += dropped.frames;
                    self.outcome.dropped_bytes += dropped.bytes;
                    self.outcome.dropped_partial_front |= dropped.partial_front;
                }
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
                // US-017 AC2: before dropping its expectations, the
                // boundary computes what the ended transport still OWES —
                // the committed frames that never fully reached the wire
                // and their undelivered bytes — so the driver's typed
                // report can be checked against an independent count
                // instead of being taken on trust.
                let already_on_wire = self.offer.as_ref().map_or(0, |offer| offer.accepted);
                let owed_bytes = self
                    .expected_frames
                    .iter()
                    .map(Vec::len)
                    .sum::<usize>()
                    .saturating_sub(already_on_wire);
                self.owed_frames += self.expected_frames.len();
                self.owed_bytes += owed_bytes;
                self.owed_partial_front |= already_on_wire > 0;
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
            // REACHABILITY CORRECTION, THIRD PASS — and this time measured
            // rather than reasoned about.
            //
            // Round one called this `failure-halt-exclusivity` and looked for
            // a `Terminal` after the first `Failure`. Round two renamed it
            // `failure-halt-stops-driving` and broadened the predicate to
            // "no command disposition and no non-Idle output at all",
            // claiming that made it checkable. It did not. `poll` sets
            // `halted` BEFORE pushing the failure record, and both `exec`
            // and `fair_drain` return on `halted`, so the failure record is
            // always the LAST record in the trace and `trace[index + 1..]`
            // is always EMPTY. `any()` over an empty slice is `false`, so
            // the violation could not be recorded by any run.
            //
            // MEASURED, not asserted: over the full bounded exploration —
            // 81180 schedules, 80072 of them carrying a failure record — the
            // post-failure suffix length was 0 in every single run
            // (`max_post_failure_suffix=0`, `runs_with_nonempty_suffix=0`).
            // The broadened predicate was exactly as unreachable as the
            // narrow one it replaced.
            //
            // WHAT IS CHECKED NOW: the halt model itself, which is the only
            // thing this trace can witness. If the interpreter ever stops
            // halting, the failure stops being the final record and this
            // fires. That is reachable — removing the `halted` guards makes
            // 77984 of the 80072 halted runs record post-failure output.
            //
            // WHAT IS NOT CHECKED, stated so no one reads more into it: this
            // says NOTHING about the driver. The driver is never polled past
            // a surfaced failure here, so whether IT would stay quiet is
            // untested by this suite. Probing past the halt shows it does
            // not — it goes on to deliver the pending EOF transition and a
            // `Terminal`.
            //
            // THE OWNER RULING THAT NOTE ASKED FOR HAS ARRIVED, and it
            // resolved into two different answers, so read them separately
            // rather than as one verdict
            // (`us017-post-failure-owner-decisions-2026-08-28.json`):
            //
            //   * The continuation itself is NOT a defect. It is ordered
            //     delivery of work committed BEFORE the failure — the EOF
            //     transition and `Terminal` seen past the halt were earned
            //     by inputs the core had already accepted. On a PURE
            //     protocol violation (RSV1 on TEXT, reserved opcode 0x3)
            //     the driver composes nothing at all and stays in `Open`,
            //     which is the measurement that separates "finishes a
            //     shutdown it had already begun" from "shuts down because
            //     of the failure". The contract is now written down in
            //     `ws_driver`'s module docs instead of being inferred here.
            //   * What WAS a defect is C5, folded into
            //     `Violation::TerminalAfterFailure`'s doc comment above: a
            //     fatal arriving as a command rejection surfaced no
            //     `Failure` output, so this halt model never saw it. Fixed
            //     in `finish_poll`; the halt now covers both arrival paths.
            let first_failure = self
                .outcome
                .trace
                .iter()
                .position(|record| matches!(record.output, TraceOutput::Failure(_)));
            if let Some(index) = first_failure
                && index + 1 != self.outcome.trace.len()
            {
                self.outcome.record(Violation::TerminalAfterFailure);
            }
            // Commands still queued at the halt belong to the embedding
            // adapter's teardown; only the at-most-once subset invariant
            // above applies. No further polls are issued.
            //
            // The dropped-write accounting, however, DOES apply here
            // (US-017 story review round 2, session 01a0464f). Exempting
            // halted runs is exactly what let a pending report be
            // suppressed by the fatal Failure that ends the run: the
            // adapter stops at that Failure, so anything not surfaced
            // before it is lost for good. What the ended transport owed is
            // owed on both routes.
            self.check_write_drop_accounting();
            return self.probe_receiver_drop();
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
        self.check_write_drop_accounting();
        self.probe_receiver_drop()
    }

    /// US-017 AC2 (story review BLOCKING-2, and BLOCKING-1 of round 2):
    /// whatever the ended transport owed must have come back as the typed
    /// dropped-write disposition, accounted EXACTLY — frames, undelivered
    /// bytes, and whether the front frame was already partly on the wire.
    /// Silent abandonment shows up here as a mismatch, on the clean route
    /// and on the fatal-halt route alike.
    fn check_write_drop_accounting(&mut self) {
        if self.owed_frames != self.outcome.dropped_frames
            || self.owed_bytes != self.outcome.dropped_bytes
            || self.owed_partial_front != self.outcome.dropped_partial_front
        {
            self.outcome.record(Violation::UnreportedWriteDrop);
        }
        // The report is a single disposition, not a stream: nothing is
        // reported when nothing was owed, and one report otherwise. The
        // report may carry MORE THAN ONE frame — the plural arm is reachable
        // under the default automatic-response policy and pinned in
        // `driver_contract.rs` — so only the report COUNT is bounded here,
        // never the frame count (pre-landing review finding 1).
        if self.outcome.write_drop_reports > 1
            || (self.owed_frames == 0 && self.outcome.write_drop_reports != 0)
        {
            self.outcome.record(Violation::UnreportedWriteDrop);
        }
    }

    /// US-017 AC2 (story review BLOCKING-1): drop the sole owner from the
    /// state THIS schedule reached, then probe the producer seam. Once the
    /// owner is gone a send can never be applied, so it must refuse with
    /// the typed receiver-drop reason and hand the command back — never
    /// report accepted.
    ///
    /// WHAT THIS IS AND IS NOT (pre-landing review finding 3, session
    /// 01a04960). It is a deterministic post-run EPILOGUE, executed once per
    /// schedule, so it exercises the typed refusal from every END STATE the
    /// 79,920 schedules reach — that is why the counter equals the schedule
    /// count exactly. It is NOT receiver-drop RACE exploration: the drop and
    /// the send are sequenced on one thread here, and no interleaving of the
    /// two is explored. The racing evidence is the native-thread test
    /// `ws-core/tests/concurrency_boundary.rs::a_producer_racing_the_owner_drop_never_blocks_and_never_reports_a_stale_accept`,
    /// which requires a typed post-drop observation rather than merely
    /// tolerating one.
    fn probe_receiver_drop(self) -> Outcome {
        let Run {
            driver,
            sender,
            mut outcome,
            ..
        } = self;
        drop(driver);
        let probe = command_for(Tag::TextA);
        match sender.try_send(probe.clone()) {
            Ok(()) => outcome.record(Violation::ReceiverDropUnreported),
            Err(refused) => {
                if refused.reason == CommandRefusalReason::ReceiverDropped
                    && refused.command == probe
                {
                    outcome.receiver_drop_refusals += 1;
                } else {
                    outcome.record(Violation::ReceiverDropUnreported);
                }
            }
        }
        if outcome.receiver_drop_refusals != 1 {
            outcome.record(Violation::ReceiverDropUnreported);
        }
        outcome
    }
}

fn execute_with_limits(
    schedule: &[Action],
    fault: Fault,
    event_queue_capacity: u64,
    max_actions: u64,
) -> Outcome {
    let mut run = Run::new(fault, event_queue_capacity, max_actions);
    for action in schedule {
        run.exec(*action);
    }
    run.finish()
}

fn execute_with_capacity(schedule: &[Action], fault: Fault, event_queue_capacity: u64) -> Outcome {
    execute_with_limits(schedule, fault, event_queue_capacity, MAX_ACTIONS_UNREACHED)
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
    render_seed_with_limits(
        id,
        fault,
        target,
        schedule,
        event_queue_capacity,
        MAX_ACTIONS_UNREACHED,
    )
}

/// `max_actions` is written ONLY when it is not the default, so every seed
/// pinned before the fatal-termination sweep existed stays byte-identical.
fn render_seed_with_limits(
    id: &str,
    fault: Fault,
    target: Violation,
    schedule: &[Action],
    event_queue_capacity: u64,
    max_actions: u64,
) -> String {
    let mut body = String::new();
    let _ = writeln!(body, "id={id}");
    let _ = writeln!(body, "property={}", target.property());
    let _ = writeln!(body, "mutation={}", fault.mutation());
    let _ = writeln!(body, "event_queue_capacity={event_queue_capacity}");
    if max_actions != MAX_ACTIONS_UNREACHED {
        let _ = writeln!(body, "max_actions={max_actions}");
    }
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
    // Every invariant violation any schedule observed. The outcome the
    // printed invariant list carries is DERIVED from this set rather than
    // written as a literal PASS; `retain_and_fail` below means a non-empty
    // set never reaches the print, which is exactly what makes reaching the
    // print evidence that the set is empty.
    let mut observed_violations: BTreeSet<Violation> = BTreeSet::new();
    let mut partial_front_drops = 0usize;
    let mut max_dropped_frames = 0usize;
    // CLEAN-PATH BREADTH, the measurement the post-failure landing review's
    // finding 1 asked for and this sweep did not have.
    //
    // `closed_terminal_runs` counts RUNS, and a run count is not a coverage
    // reading: at the landing, 49 clean-terminal runs carried only 18
    // distinct semantic traces, so the four properties that hold only on the
    // clean route were being exercised against eighteen behaviours while the
    // record printed forty-nine. The distinct-digest count is the honest
    // reading and it is printed beside the run count so neither can be read
    // without the other. `clean_terminal_scenarios` says in how many
    // scenarios a clean terminal is reached at all — 1 was the whole of
    // finding 1's "confined to one scenario".
    let mut clean_terminal_digests: BTreeSet<u64> = BTreeSet::new();
    let mut clean_terminal_scenarios: BTreeSet<&'static str> = BTreeSet::new();
    // Which scenario each schedule index belongs to, from the enumeration's
    // own spans rather than from a second guess at the shapes.
    let mut scenario_of: Vec<&'static str> = Vec::with_capacity(schedule_count);
    for (name, count) in &exploration.spans {
        scenario_of.extend(std::iter::repeat_n(*name, *count));
    }
    assert_eq!(
        scenario_of.len(),
        schedule_count,
        "the enumeration's spans must account for every schedule"
    );
    for (index, schedule) in exploration.schedules.iter().enumerate() {
        let outcome = execute_deterministic(schedule, Fault::None);
        observed_violations.extend(outcome.violations.iter().copied());
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
            clean_terminal_digests.insert(outcome.digest());
            clean_terminal_scenarios.insert(scenario_of[index]);
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
        totals.write_drop_reports += outcome.write_drop_reports;
        totals.dropped_frames += outcome.dropped_frames;
        totals.dropped_bytes += outcome.dropped_bytes;
        totals.receiver_drop_refusals += outcome.receiver_drop_refusals;
        if outcome.dropped_partial_front {
            partial_front_drops += 1;
        }
        max_dropped_frames = max_dropped_frames.max(outcome.dropped_frames);
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
    // CLEAN-PATH BREADTH FLOOR (post-failure landing review, finding 1).
    //
    // These are the only assertions in this sweep that speak about how much
    // of the clean route is covered rather than about whether it holds, and
    // they exist because the landed record could say "49 clean-terminal
    // runs" while the honest reading was eighteen behaviours in one
    // scenario, and nothing disagreed.
    //
    // The floors are deliberately BELOW what the tree measures (1,176 runs,
    // 403 digests, 2 scenarios) so ordinary drift does not trip them; they
    // catch the collapse, which is the failure mode that actually happened.
    // A clean route reachable in only ONE scenario is exactly the shape
    // finding 1 named, so two is the floor.
    assert!(
        clean_terminal_digests.len() >= 2,
        "the clean-terminal route must be more than one behaviour: {} runs \
         carrying {} distinct traces",
        closed_terminal_runs,
        clean_terminal_digests.len()
    );
    assert!(
        clean_terminal_digests.len() >= 100,
        "clean-terminal BREADTH floor: {} clean-terminal runs carry only {} \
         distinct semantic traces, so the properties that hold only on the \
         clean route (convergence, exactly-once reconciliation, \
         post-terminal quiescence, no write bypass) are exercised against \
         that many behaviours, not against the run count",
        closed_terminal_runs,
        clean_terminal_digests.len()
    );
    assert!(
        clean_terminal_scenarios.len() >= 2,
        "the clean-terminal route must be reached in more than one scenario, \
         or a single scenario's shape decides the whole clean-path claim; \
         reached in {:?}",
        clean_terminal_scenarios
    );
    // The breadth reading cannot exceed the run count that produced it.
    assert!(
        clean_terminal_digests.len() <= closed_terminal_runs,
        "more distinct clean traces than clean runs is impossible"
    );
    // US-017 AC2 story-review coverage: BOTH new dispositions are reached
    // by the exhaustive sweep, not just by the unit fixtures.
    assert_eq!(
        totals.receiver_drop_refusals as usize, schedule_count,
        "every explored schedule ends with the typed receiver-drop refusal, \
         from whatever state it reached"
    );
    assert!(
        totals.write_drop_reports > 0,
        "shutdown with committed pending writes was explored, and reported"
    );
    assert!(
        totals.dropped_bytes > 0,
        "the reported drops account for real undelivered bytes"
    );
    assert!(
        partial_front_drops > 0,
        "the partially-written front frame (a truncated frame on the peer's \
         wire) was explored"
    );
    assert!(
        totals.write_drop_reports as usize <= schedule_count,
        "at most one dropped-write disposition per schedule"
    );

    // The invariant list and the fairness stance the record carries, derived
    // from what this run actually checked. Review 01a0487b round 2 BLOCKING:
    // both were unmodeled decoration until they were printed here.
    for (index, violation) in CHECKED_INVARIANTS.iter().enumerate() {
        assert_eq!(
            violation_index(*violation),
            index,
            "CHECKED_INVARIANTS must list each violation exactly once"
        );
    }
    let invariants = CHECKED_INVARIANTS
        .iter()
        .map(|violation| {
            let outcome = if observed_violations.contains(violation) {
                "FAIL"
            } else {
                "PASS"
            };
            format!("{INVARIANT_NAMESPACE}{}:{outcome}", violation.property())
        })
        .collect::<Vec<_>>()
        .join(",");
    let weak_fairness = WEAK_FAIRNESS.join(",");

    let measured = format!(
        "US017_EXPLORATION scenarios={} programs_per_scenario={PROGRAM_COUNT} actions_total={} context_switch_bound={CONTEXT_SWITCH_BOUND} \
         preemption_budget={PREEMPTION_BUDGET} command_queue_capacity={COMMAND_QUEUE_CAPACITY} \
         write_queue_capacity={WRITE_QUEUE_CAPACITY} event_queue_capacity={EVENT_QUEUE_CAPACITY} \
         drain_budget_polls={DRAIN_BUDGET} schedules={schedule_count} branches={} truncated=false \
         executions={} distinct_trace_digests={} closed_terminal_runs={closed_terminal_runs} \
         clean_terminal_digests={} clean_terminal_scenarios={} halted_terminals={halted_terminals} \
         failure_halted_runs={failure_halted_runs} accepted={} refused_full={} applied={} rejected={} \
         events={} failures={} deferred_output_pending={} deferred_command_turn={} \
         deferred_backpressure={} rejected_inputs={} write_drop_reports={} dropped_frames={} \
         dropped_bytes={} partial_front_drops={partial_front_drops} \
         max_dropped_frames={max_dropped_frames} receiver_drop_refusals={} \
         max_drain_polls={max_drain} \
         invariants={invariants} weak_fairness={weak_fairness} \
         producer_admission_fairness={PRODUCER_ADMISSION_FAIRNESS}",
        SCENARIOS.len(),
        SCENARIOS
            .iter()
            .map(|(_, programs)| programs.iter().map(|program| program.len()).sum::<usize>())
            .sum::<usize>(),
        exploration.branches,
        schedule_count * 2,
        distinct_outcomes.len(),
        clean_terminal_digests.len(),
        clean_terminal_scenarios.len(),
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
        totals.write_drop_reports,
        totals.dropped_frames,
        totals.dropped_bytes,
        totals.receiver_drop_refusals,
    );
    println!("{measured}");
    assert_committed_results_cite_this_run(&measured);
}

// ---------------------------------------------------------------------------
// Fatal-termination sweep (US-017 story review round 2, session 01a0464f)
// ---------------------------------------------------------------------------

/// The SAME exhaustive schedule space, re-run under tightened action
/// budgets so runs end FATALLY (`ActionLimitExceeded`) while committed
/// writes are still outstanding.
///
/// The main sweep cannot reach this: its action budget is the config
/// default, far above the 12-action alphabet, so no schedule there ever
/// terminates fatally with a pending dropped-write report. That gap is
/// precisely where the round-2 finding lived — "a pending `WritesDropped`
/// disposition is suppressed by a fatal `Failure`, after which the adapter
/// halts, leaving a reachable committed write silently unreported".
///
/// The invariant asserted is the same one the clean route uses, with the
/// same INDEPENDENT boundary-side count of what the ended transport owed:
/// a report must have surfaced, before the halting Failure, accounting for
/// exactly the frames and undelivered bytes that were abandoned.
#[test]
fn fatal_termination_sweep_reports_every_abandoned_committed_write() {
    let exploration = enumerate_schedules();
    let schedule_count = exploration.schedules.len();
    let mut total_fatal_path_drops = 0usize;
    let mut total_fatal_path_bytes = 0usize;
    let mut per_budget = Vec::new();
    let mut lines = Vec::new();

    for budget in FATAL_SWEEP_ACTION_BUDGETS {
        let mut halted_runs = 0usize;
        let mut closed_runs = 0usize;
        let mut fatal_path_drops = 0usize;
        let mut fatal_path_bytes = 0usize;
        let mut clean_path_drops = 0usize;
        let mut receiver_drop_refusals = 0u32;

        for schedule in &exploration.schedules {
            let first = execute_with_limits(schedule, Fault::None, EVENT_QUEUE_CAPACITY, budget);
            let second = execute_with_limits(schedule, Fault::None, EVENT_QUEUE_CAPACITY, budget);
            let mut outcome = first;
            if outcome != second {
                outcome.record(Violation::Nondeterminism);
            }
            assert!(
                outcome.violations.is_empty(),
                "budget {budget}: schedule {} violated {:?}\noutcome: {outcome:?}",
                render_schedule(schedule),
                outcome.violations,
            );
            // Terminal-disposition ORDERING holds under the tightened budget
            // exactly as it does in the main sweep — and it is ordering, not
            // exclusivity. Since owner decision
            // us017-post-terminal-owner-decision-2026-08-28
            // (`post-terminal-inbound`) a converged connection REFUSES work
            // still pushed at it instead of absorbing it, so a schedule may
            // take its one clean Terminal and only then reach a fatal. This
            // arm previously demanded `terminals == 0` and read `left: 1`
            // against the merged tree. The no-Terminal-AFTER-a-Failure
            // property is asserted where it can actually be seen, in
            // `finish`, against the trace itself.
            if outcome.halted {
                assert_eq!(outcome.failures, 1, "the halt is the first failure");
                assert!(
                    outcome.terminals <= 1,
                    "at most one terminal, and only before the failure"
                );
                halted_runs += 1;
                if outcome.write_drop_reports > 0 {
                    // THE ROUND-2 CLASS: committed writes were abandoned and
                    // reported, and the run then ended at a fatal Failure the
                    // adapter halts on. Pre-fix, the report never surfaced.
                    fatal_path_drops += 1;
                    fatal_path_bytes += outcome.dropped_bytes;
                }
            } else {
                assert!(outcome.closed, "a non-halted full schedule converges");
                assert_eq!(outcome.failures, 0, "any surfaced failure halts");
                assert_eq!(outcome.terminals, 1, "terminal delivered exactly once");
                closed_runs += 1;
                if outcome.write_drop_reports > 0 {
                    clean_path_drops += 1;
                }
            }
            receiver_drop_refusals += outcome.receiver_drop_refusals;
        }

        assert_eq!(
            halted_runs + closed_runs,
            schedule_count,
            "budget {budget}: every schedule reaches exactly one disposition"
        );
        assert_eq!(
            receiver_drop_refusals as usize, schedule_count,
            "budget {budget}: the receiver-drop disposition holds under fatal termination too"
        );
        let line = format!(
            "US017_FATAL_SWEEP budget={budget} schedules={schedule_count} halted_runs={halted_runs} \
             closed_terminal_runs={closed_runs} fatal_path_drop_runs={fatal_path_drops} \
             fatal_path_dropped_bytes={fatal_path_bytes} clean_path_drop_runs={clean_path_drops}"
        );
        println!("{line}");
        lines.push(line);
        per_budget.push((budget, fatal_path_drops));
        total_fatal_path_drops += fatal_path_drops;
        total_fatal_path_bytes += fatal_path_bytes;
    }

    // Coverage honesty: the sweep must actually REACH the class the finding
    // names, or it proves nothing about it.
    assert!(
        total_fatal_path_drops > 0,
        "the fatal-termination drop class must be exercised: {per_budget:?}"
    );
    assert!(total_fatal_path_bytes > 0);
    let total = format!(
        "US017_FATAL_SWEEP_TOTAL budgets={:?} fatal_path_drop_runs={total_fatal_path_drops} \
         fatal_path_dropped_bytes={total_fatal_path_bytes} per_budget={per_budget:?}",
        FATAL_SWEEP_ACTION_BUDGETS,
    );
    println!("{total}");
    lines.push(total);
    // The committed record cites THIS sweep, line for line, or the sweep
    // fails: the same binding the exploration line carries, so the
    // fatal-termination magnitudes stop being transcribed numbers.
    assert_committed_results_cite_this_sweep(&lines);
}

/// The `producer_admission_fairness=absent` token the exploration prints is a
/// MEASURED property of the enumeration, not a label someone typed.
///
/// WHY THIS EXISTS. Review 01a0487b round 2 BLOCKING, the reviewer's own
/// example: `execution.producer_admission_fairness_claimed` could be flipped
/// from `false` to `true` and both validators still exited 0, because neither
/// modeled the field. It is now re-derived from this run — which only means
/// something if the run's own stance is checked rather than asserted.
///
/// Absence of admission fairness is exactly this: a producer step is CONSUMED
/// whether or not the command was admitted, so a queue-full refusal is final
/// for that step. If the interpreter retried refused sends (the fairness this
/// document declines to claim), the producers would dispose MORE steps than
/// their programs contain.
#[test]
fn producer_admission_is_absent_by_construction() {
    // All four producer steps run back to back, before any owner poll can
    // drain the command queue, so the bounded channel (capacity 2) must
    // refuse some of them.
    let schedule = [
        Action::EnqueueTextA,
        Action::EnqueueBinaryA,
        Action::EnqueuePingB,
        Action::EnqueueCloseB,
        Action::InboundPing,
        Action::InboundClose,
        Action::TransportEof,
        Action::WritePartial,
        Action::WriteAll,
        Action::WriteAll,
        Action::Wake,
        Action::Shutdown,
    ];
    let producer_steps = schedule
        .iter()
        .filter(|action| {
            matches!(
                action,
                Action::EnqueueTextA
                    | Action::EnqueueBinaryA
                    | Action::EnqueuePingB
                    | Action::EnqueueCloseB
            )
        })
        .count() as u32;

    let outcome = execute_deterministic(&schedule, Fault::None);
    assert!(
        outcome.refused_full > 0,
        "this schedule must actually reach a queue-full refusal or it proves nothing about \
         what happens to a refused producer step"
    );
    assert_eq!(
        outcome.accepted + outcome.refused_full,
        producer_steps,
        "each producer step is admitted or refused EXACTLY ONCE ({} accepted + {} refused vs \
         {producer_steps} steps). A larger total would mean a refused send was re-offered, \
         which is the admission fairness assurance/concurrency/plan.json declares absent \
         (PRODUCER_ADMISSION_FAIRNESS_ABSENT) and the results record must not claim.",
        outcome.accepted,
        outcome.refused_full,
    );
    assert_eq!(
        PRODUCER_ADMISSION_FAIRNESS, "absent",
        "the printed stance must be the one this test just measured"
    );
}

// ---------------------------------------------------------------------------
// Binding the committed acceptance evidence to this run
// ---------------------------------------------------------------------------

/// The acceptance-evidence document this exploration produces.
const RESULTS_DOCUMENT: &str = "assurance/concurrency/results.json";

/// Repository-relative path resolved against this crate's manifest directory,
/// so the check works from any working directory cargo is invoked from.
fn repository_path(relative: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

/// The key whose single string value binds this document to a run.
const STDOUT_LINE_KEY: &str = "\"stdout_line\"";

/// Read the one `stdout_line` string out of the committed results document.
///
/// This is deliberately NOT a JSON parser — the workspace carries zero
/// non-path dependencies and hand-rolling one would be a second, unverified
/// parser in the tree.
///
/// THE RULE THAT MAKES IT COMPOSE. Review 01a0487b BLOCKING 1 broke the
/// previous version: it searched for the exact bytes `"stdout_line": "`, so a
/// document could carry an ignored top-level decoy in that exact form for this
/// reader plus a nested `"stdout_line" : "<forgery>"` — legal JSON whitespace —
/// for the structural Go reader. Both halves passed while the counters were
/// forged. Reproduced and measured: both exits 0.
///
/// The fix is that this reader keys on the BARE key token and requires it to
/// occur EXACTLY ONCE ANYWHERE in the document, under any legal whitespace.
/// There is therefore exactly one such string in the file and every reader
/// must land on it. internal/formalplan/concurrencyresults.go runs this same
/// algorithm and asserts its result equals its own structural parse, so the
/// two halves are checked to be reading identical bytes rather than assumed to.
///
/// Every way the assumption could quietly stop holding — key missing, key
/// duplicated, a separator that is not a colon, a value that is not a string,
/// an escape inside the value — panics with what it saw instead of returning
/// something plausible.
fn committed_stdout_line(document: &str) -> String {
    let occurrences = document.matches(STDOUT_LINE_KEY).count();
    assert_eq!(
        occurrences, 1,
        "{RESULTS_DOCUMENT} must carry exactly one {STDOUT_LINE_KEY} key anywhere in the document for this \
         binding to be unambiguous, found {occurrences}. More than one means two readers could land on \
         different values (review 01a0487b BLOCKING 1); zero means the document cites no run."
    );
    let after_key = document
        .find(STDOUT_LINE_KEY)
        .expect("occurrence count is 1")
        + STDOUT_LINE_KEY.len();
    let rest = &document[after_key..];
    let colon = rest
        .find(|c: char| !c.is_whitespace())
        .expect("the document ends after the stdout_line key");
    assert_eq!(
        rest[colon..].chars().next(),
        Some(':'),
        "{RESULTS_DOCUMENT} stdout_line key is not followed by a colon"
    );
    let after_colon = &rest[colon + 1..];
    let quote = after_colon
        .find(|c: char| !c.is_whitespace())
        .expect("the document ends after the stdout_line colon");
    assert_eq!(
        after_colon[quote..].chars().next(),
        Some('"'),
        "{RESULTS_DOCUMENT} stdout_line value is not a string literal"
    );
    let value_start = &after_colon[quote + 1..];
    let end = value_start
        .find('"')
        .expect("the stdout_line literal is unterminated");
    let value = &value_start[..end];
    assert!(
        !value.contains('\\'),
        "{RESULTS_DOCUMENT} stdout_line contains a JSON escape ({value:?}); this reader does not unescape, \
         so the comparison below would be against the wrong bytes"
    );
    value.to_string()
}

/// Fail if the committed acceptance evidence does not cite THIS run.
///
/// WHY. `assurance/concurrency/results.json` is the sole evidence node bound
/// to US-017. Before this check nothing connected its twenty-two counters to
/// an execution: the numbers were transcribed by hand from a printed line, and
/// a measured corruption confirmed the consequence — with explored_schedules
/// rewritten from 79920 to 11 and accepted_commands from 221353 to 999999,
/// `make -C rust gates` exited 0 and `go test ./...` exited 0 once the
/// evidence-DAG byte pin was regenerated.
///
/// WHAT IT PROVES. Only that the recorded line is a line this exploration
/// really emits. It says nothing about whether the document's counter FIELDS
/// agree with that line — that half is `ValidateConcurrencyResults` in
/// internal/formalplan/concurrencyresults.go, which re-derives every field
/// from the same string. Neither half alone is a binding.
fn assert_committed_results_cite_this_run(measured: &str) {
    let path = repository_path(RESULTS_DOCUMENT);
    let document = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("{RESULTS_DOCUMENT} is the acceptance evidence this run produces and must be readable at {path:?}: {error}")
    });
    let committed = committed_stdout_line(&document);
    assert_eq!(
        committed, measured,
        "\n{RESULTS_DOCUMENT} cites a run that is not this one.\n  \
         committed: {committed}\n  \
         measured:  {measured}\n\
         The committed acceptance evidence is stale. Refresh it deliberately: copy the measured line into \
         execution.executed_run.stdout_line, bring every counter field into agreement with it (the Go validator \
         internal/formalplan/concurrencyresults.go re-derives them and will name any that disagree), update \
         target.source.git_blob, target.harness.git_blob and preregistered_plan.sha256 to the current tree, and \
         record what moved and why in revision_note. Do NOT edit this assertion.\n"
    );
}

/// The bare key under which the record cites the fatal-termination sweep's
/// printed lines. Distinct from STDOUT_LINE_KEY on purpose: neither key is a
/// substring of the other, so each reader's exactly-once rule stays exact.
const SWEEP_STDOUT_LINES_KEY: &str = "\"sweep_stdout_lines\"";

/// Read the one `sweep_stdout_lines` string array out of the committed
/// results document, by the same bare-key, exactly-once, no-escape rules as
/// `committed_stdout_line`; internal/formalplan/concurrencyresults.go runs the
/// same algorithm on the raw bytes and checks it against its structural parse.
fn committed_sweep_lines(document: &str) -> Vec<String> {
    let occurrences = document.matches(SWEEP_STDOUT_LINES_KEY).count();
    assert_eq!(
        occurrences, 1,
        "{RESULTS_DOCUMENT} must carry exactly one {SWEEP_STDOUT_LINES_KEY} key anywhere in the document \
         for this binding to be unambiguous, found {occurrences}; zero means the record cites no sweep."
    );
    let after_key = document
        .find(SWEEP_STDOUT_LINES_KEY)
        .expect("occurrence count is 1")
        + SWEEP_STDOUT_LINES_KEY.len();
    let mut rest = document[after_key..].trim_start();
    assert!(
        rest.starts_with(':'),
        "{RESULTS_DOCUMENT} sweep_stdout_lines key is not followed by a colon"
    );
    rest = rest[1..].trim_start();
    assert!(
        rest.starts_with('['),
        "{RESULTS_DOCUMENT} sweep_stdout_lines value is not an array"
    );
    rest = rest[1..].trim_start();
    let mut lines = Vec::new();
    while !rest.starts_with(']') {
        assert!(
            rest.starts_with('"'),
            "{RESULTS_DOCUMENT} sweep_stdout_lines element {} is not a string literal",
            lines.len()
        );
        let body = &rest[1..];
        let end = body
            .find('"')
            .expect("a sweep_stdout_lines literal is unterminated");
        let value = &body[..end];
        assert!(
            !value.contains('\\'),
            "{RESULTS_DOCUMENT} sweep_stdout_lines element contains a JSON escape ({value:?}); this reader \
             does not unescape, so the comparison would be against the wrong bytes"
        );
        lines.push(value.to_string());
        rest = body[end + 1..].trim_start();
        if rest.starts_with(',') {
            rest = rest[1..].trim_start();
            continue;
        }
        assert!(
            rest.starts_with(']'),
            "{RESULTS_DOCUMENT} sweep_stdout_lines element is followed by neither a comma nor the closing bracket"
        );
    }
    lines
}

/// Fail if the committed acceptance evidence does not cite THIS fatal-termination
/// sweep. Same contract as `assert_committed_results_cite_this_run`: this half
/// proves the recorded lines are lines this sweep really emits, and the Go half
/// re-derives every per-budget map and total from them.
fn assert_committed_results_cite_this_sweep(measured: &[String]) {
    let path = repository_path(RESULTS_DOCUMENT);
    let document = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("{RESULTS_DOCUMENT} is the acceptance evidence this sweep produces and must be readable at {path:?}: {error}")
    });
    let committed = committed_sweep_lines(&document);
    assert_eq!(
        committed, measured,
        "\n{RESULTS_DOCUMENT} cites a fatal-termination sweep that is not this one.\n  \
         committed: {committed:#?}\n  \
         measured:  {measured:#?}\n\
         The committed acceptance evidence is stale. Refresh it deliberately: copy the measured lines into \
         execution.fatal_termination_sweep.executed_run.sweep_stdout_lines, bring the per-budget maps and totals \
         into agreement with them (internal/formalplan/concurrencyresults.go re-derives them and will name any that \
         disagree), update target.harness.git_blob to the current tree, and record what moved and why in \
         revision_note. Do NOT edit this assertion.\n"
    );
}

// ---------------------------------------------------------------------------
// Retention demonstration: the six named boundary faults are found by the
// exploration, shrunk to 1-minimal schedules, and pinned as artifacts.
// ---------------------------------------------------------------------------

const NAMED_FAULTS: [(&str, Fault, Violation); 7] = [
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
    // US-017 story review BLOCKING-2: the reported defect itself, seeded
    // as a boundary fault so the new accounting check is shown to kill it.
    (
        "silent-write-drop",
        Fault::DropWritesDroppedReport,
        Violation::UnreportedWriteDrop,
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

/// PAIRED POSITIVE CONTROL for the
/// `interpreter-halts-at-first-surfaced-failure` check.
///
/// The check in `finish` records `TerminalAfterFailure` when the first
/// surfaced `Failure` is not the final trace record. Two earlier versions of
/// that check scanned `trace[first_failure + 1..]` — a slice the halt keeps
/// EMPTY in all 81180 explored schedules — so neither could fail, and the
/// invariant was upheld vacuously by every run.
///
/// This control is what makes the current check meaningful: it proves the
/// check DISTINGUISHES a halted run from an unhalted one, rather than being
/// satisfied by the absence of anything to look at. Without it, "no records
/// after the failure" is indistinguishable from "no records were ever going
/// to be there".
#[test]
fn failure_halt_check_distinguishes_a_halt_from_a_missing_one() {
    let schedule: Vec<Action> = ["inbound-ping", "transport-eof", "wake", "shutdown"]
        .iter()
        .map(|verb| Action::parse(verb))
        .collect();

    // NEGATIVE ARM — the real interpreter halts, so the failure is last and
    // no violation is recorded.
    let mut run = Run::new(Fault::None, EVENT_QUEUE_CAPACITY, MAX_ACTIONS_UNREACHED);
    for action in &schedule {
        run.exec(*action);
    }
    run.fair_drain();
    assert!(
        run.halted,
        "precondition: this schedule must reach a surfaced failure"
    );
    let failure_index = run
        .outcome
        .trace
        .iter()
        .position(|record| matches!(record.output, TraceOutput::Failure(_)))
        .expect("precondition: a failure record exists");
    assert_eq!(
        failure_index + 1,
        run.outcome.trace.len(),
        "precondition: the halt leaves the failure as the final trace record"
    );
    let halted_outcome = run.finish();
    assert!(
        !halted_outcome
            .violations
            .contains(&Violation::TerminalAfterFailure),
        "a properly halted run records no violation: {halted_outcome:?}"
    );

    // POSITIVE ARM — the identical schedule with the halt suppressed, which
    // is what an interpreter that FAILED to stop driving would produce.
    let mut run = Run::new(Fault::None, EVENT_QUEUE_CAPACITY, MAX_ACTIONS_UNREACHED);
    for action in &schedule {
        run.exec(*action);
    }
    run.fair_drain();
    assert!(run.halted, "precondition: the same schedule halts");
    let failure_index = run
        .outcome
        .trace
        .iter()
        .position(|record| matches!(record.output, TraceOutput::Failure(_)))
        .expect("precondition: a failure record exists");
    run.halted = false;
    for _ in 0..2 {
        let _ = run.poll(DriverInput::Wake);
        // `poll` re-latches the halt if it surfaces another failure; the
        // control deliberately keeps driving anyway.
        run.halted = false;
    }
    // The driver did not merely get polled — it was still doing WORK past the
    // point the adapter model stops looking. This is the observation the old
    // check could never make, and it is contingent, not structural: it fails
    // if the driver really does go quiet after a surfaced failure.
    assert!(
        run.outcome.trace[failure_index + 1..]
            .iter()
            .any(|record| record.command.is_some() || !matches!(record.output, TraceOutput::Idle)),
        "control precondition: polling past the halt must surface real work, \
         otherwise this arm proves nothing: {:?}",
        &run.outcome.trace[failure_index + 1..]
    );
    run.halted = true;
    let unhalted_outcome = run.finish();
    assert!(
        unhalted_outcome
            .violations
            .contains(&Violation::TerminalAfterFailure),
        "the check MUST fire once a record follows the surfaced failure — if it \
         does not, `interpreter-halts-at-first-surfaced-failure` is vacuous again: \
         {unhalted_outcome:?}"
    );
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
        //
        // The retained body carries `found_index` — the exploration ordinal at
        // which this fault first failed. Reviews 01a0487b rounds 2, 3 and 4
        // each named the six `retention.minimized_artifacts[*].found_index`
        // values in assurance/concurrency/results.json as the record's last
        // unbound leaves: the exploration only PRINTED the ordinal, so the
        // document could carry any number and nothing contradicted it. Written
        // here, the ordinal is inside the artifact whose sha256 the document
        // pins and whose bytes this test re-derives from a real minimization
        // run, so a wrong ordinal in the document now disagrees with the seed
        // and a doctored seed disagrees with its digest.
        let mut body = render_seed(
            &format!("minimized-{name}"),
            fault,
            target,
            &minimized,
            EVENT_QUEUE_CAPACITY,
        );
        let _ = writeln!(body, "found_index={index}");
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
///
/// SCOPE (pre-landing review finding 5, session 01a04960): these are PINS,
/// not polarity controls. `mutation=none` is asserted below precisely
/// because a real defect must stay fixed against the SHIPPED driver — which
/// means a pin can only ever show that the current driver is clean, never
/// that a pre-fix one was not. The executable polarity evidence lives in the
/// seeds that declare a real, parsed, executed mutation:
/// `minimized/silent-write-drop.seed` for round 1 and
/// `controls/fatal-halt-write-drop-accounting.seed` for round 2 (see
/// `round_two_fatal_halt_accounting_control_replays_both_polarities`).
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
    assert_eq!(
        names,
        [
            "eof-backpressure-livelock.seed",
            "fatal-halt-suppressed-write-drop.seed"
        ]
    );
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
        let max_actions: u64 = fields
            .get("max_actions")
            .map_or(MAX_ACTIONS_UNREACHED, |value| {
                value.parse().expect("numeric action budget")
            });
        let schedule = fields["schedule"]
            .split(',')
            .map(|verb| Action::parse(verb.trim()))
            .collect::<Vec<_>>();
        // The reproduction runs under the exact configuration that exposed
        // the defect (a smaller event queue, or a tightened action budget,
        // than the exploration default).
        let outcome = execute_with_limits(&schedule, Fault::None, capacity, max_actions);
        let replay = execute_with_limits(&schedule, Fault::None, capacity, max_actions);
        assert_eq!(outcome, replay, "{name}: deterministic replay");
        assert!(
            outcome.violations.is_empty(),
            "{name}: fixed defect must stay fixed: {outcome:?}"
        );
        // Both typed terminal dispositions are legitimate end states for a
        // pinned reproduction: a clean convergence, or the adapter-faithful
        // halt at a fatal Failure — which is the very route the
        // fatal-halt-suppressed-write-drop defect lived on.
        if outcome.halted {
            assert_eq!(outcome.failures, 1, "{name}: the halt is the first failure");
            assert_eq!(outcome.terminals, 0, "{name}: no terminal after a halt");
            assert!(
                outcome.write_drop_reports > 0,
                "{name}: the abandoned committed write is reported before the halting failure"
            );
        } else {
            assert!(outcome.closed, "{name}: the run converges to Closed");
            assert_eq!(outcome.terminals, 1, "{name}: terminal delivered once");
        }
    }
}

/// The ROUND-2 polarity control, committed and rerunnable (pre-landing
/// review finding 5, session 01a04960).
///
/// `regressions/fatal-halt-suppressed-write-drop.seed` is a real-defect PIN:
/// `mutation=none`, so it only replays the fixed driver and can never
/// demonstrate the pre-fix polarity. The reviewer's objection was that the
/// round-2 evidence was therefore prose. This control closes that: it
/// executes a REAL test-only mutation (`drop-writes-dropped-report`) on the
/// FATAL-HALT route, which is precisely where the round-2 defect hid,
/// because exempting halted runs from the owed-vs-reported equality was the
/// hiding place. Both polarities are read from one committed artifact:
///
/// * faulted — the adapter swallows the typed report, the run still halts at
///   its fatal `Failure`, and `UnreportedWriteDrop` fires. If the halted-run
///   accounting check in `finish()` were removed (or re-exempted), this
///   assertion fails and the control goes red.
/// * clean — the same schedule and budget on the shipped driver surfaces
///   exactly one report, BEFORE the halting failure, with zero violations.
#[test]
fn round_two_fatal_halt_accounting_control_replays_both_polarities() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz-seeds/us017/controls/fatal-halt-write-drop-accounting.seed");
    let body = fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "round-2 polarity control missing at {} ({err})",
            path.display()
        )
    });
    let mut fields = std::collections::BTreeMap::new();
    for line in body.lines().filter(|line| !line.trim().is_empty()) {
        let (key, value) = line.split_once('=').expect("key=value seed line");
        fields.insert(key.trim().to_owned(), value.trim().to_owned());
    }
    let fault = Fault::parse(&fields["mutation"]);
    assert_ne!(
        fault,
        Fault::None,
        "a POLARITY control declares a mutation that is actually executed"
    );
    let capacity: u64 = fields["event_queue_capacity"]
        .parse()
        .expect("numeric capacity");
    let max_actions: u64 = fields["max_actions"]
        .parse()
        .expect("numeric action budget");
    assert!(
        max_actions < MAX_ACTIONS_UNREACHED,
        "the control's budget must be tight enough to terminate FATALLY"
    );
    let schedule = fields["schedule"]
        .split(',')
        .map(|verb| Action::parse(verb.trim()))
        .collect::<Vec<_>>();
    let target = Violation::UnreportedWriteDrop;
    assert_eq!(fields["property"], target.property());
    assert_eq!(fields["counterexample"], target.counterexample());

    // Faulted polarity: the report is swallowed on the fatal route and the
    // boundary's independent owed count catches it.
    let faulted = execute_with_limits(&schedule, fault, capacity, max_actions);
    let faulted_replay = execute_with_limits(&schedule, fault, capacity, max_actions);
    assert_eq!(faulted, faulted_replay, "deterministic faulted replay");
    assert!(
        faulted.halted,
        "the control must reach the FATAL-HALT route, not the clean terminal: {faulted:?}"
    );
    assert!(
        faulted.violations.contains(&target),
        "suppressing the report on a halted run must be caught: {faulted:?}"
    );

    // Clean polarity: the shipped driver surfaces the report strictly before
    // the halting failure.
    let clean = execute_with_limits(&schedule, Fault::None, capacity, max_actions);
    let clean_replay = execute_with_limits(&schedule, Fault::None, capacity, max_actions);
    assert_eq!(clean, clean_replay, "deterministic clean replay");
    assert!(
        clean.violations.is_empty(),
        "the shipped driver passes the control clean: {clean:?}"
    );
    assert!(clean.halted, "same fatal route without the fault");
    assert_eq!(clean.failures, 1, "exactly one surfaced failure");
    assert_eq!(clean.terminals, 0, "no terminal after a halt");
    assert_eq!(
        clean.write_drop_reports, 1,
        "the abandoned committed write is reported before the halting failure"
    );
    assert!(
        clean.dropped_frames > 0 && clean.dropped_bytes > 0,
        "{clean:?}"
    );
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
            "silent-write-drop.seed",
            "write-reorder.seed",
        ],
        "exactly the seven named minimized artifacts are retained"
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

// ---------------------------------------------------------------------------
// Review 01a0487b BLOCKING 1: the split-read fabrication
// ---------------------------------------------------------------------------

/// Build the exact document the reviewer described: an ignored top-level
/// `"stdout_line": "<real>"` in the spelling the OLD raw reader searched for,
/// plus the real nested field written `"stdout_line" : "<forgery>"` with legal
/// JSON whitespace before the colon.
///
/// Against the old reader this document was invisible — it found the decoy,
/// compared it to the measurement, and passed, while the Go half validated
/// forged counters against the nested forgery. Both exits were 0. Keying on
/// the bare token and requiring it exactly once anywhere in the document is
/// what makes the decoy fatal instead of useful.
#[test]
#[should_panic(expected = "must carry exactly one")]
fn split_read_fabrication_is_refused() {
    let document = concat!(
        "{\n",
        "  \"schema_version\": \"1.0.0\",\n",
        "  \"stdout_line\": \"US017_EXPLORATION accepted=221353\",\n",
        "  \"execution\": {\n",
        "    \"executed_run\": {\n",
        "      \"stdout_line\" : \"US017_EXPLORATION accepted=999999\"\n",
        "    }\n",
        "  }\n",
        "}\n"
    );
    let _ = committed_stdout_line(document);
}

/// The reader must be defeated only by a real forgery, never by valid JSON
/// formatting — the mistake the first version made.
#[test]
fn stdout_line_reader_tolerates_legal_whitespace() {
    for spelling in [
        "{\"stdout_line\": \"US017_EXPLORATION x=1\"}",
        "{\"stdout_line\" : \"US017_EXPLORATION x=1\"}",
        "{\"stdout_line\"\n\t:\n\t\"US017_EXPLORATION x=1\"}",
        "{\"stdout_line\":\"US017_EXPLORATION x=1\"}",
    ] {
        assert_eq!(
            committed_stdout_line(spelling),
            "US017_EXPLORATION x=1",
            "legal JSON spelling {spelling:?} must read the same value"
        );
    }
}

/// A document that cites no run at all must fail loudly rather than compare
/// against an empty string.
#[test]
#[should_panic(expected = "must carry exactly one")]
fn a_document_citing_no_run_is_refused() {
    let _ = committed_stdout_line("{\"schedules\": 79920}");
}
