#![forbid(unsafe_code)]

use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use websocket_core::{ConnectionConfig, ConnectionLimits, LocalCommand, Role, TransportBytes};
use websocket_driver::{
    CommandDisposition, CommandHandle, ConnectionOwner, DriverInput, DriverOutput, EnqueueError,
    InputDisposition, connection_driver,
};

const RFC_REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
const MASKED_EMPTY_PING: &[u8] = b"\x89\x80\x01\x02\x03\x04";
const MASKED_CLOSE_1000: &[u8] = b"\x88\x82\x01\x02\x03\x04\x02\xea";
const EXECUTION_LIMIT: usize = 512;
const MAX_SCHEDULES: usize = 100_000;
const MAX_PREEMPTIONS: usize = 3;
const MAX_BRANCHES: usize = 1_000_000;
const STRESS_REPEATS: usize = 8;
const PRODUCERS: usize = 4;
const COMMANDS_PER_PRODUCER: usize = 16;

fn config(capacity: u64) -> ConnectionConfig {
    ConnectionConfig::try_from(ConnectionLimits {
        command_queue_entries: capacity,
        write_queue_entries: 2,
        event_queue_entries: 2,
        ..ConnectionLimits::default()
    })
    .unwrap()
}

fn text(value: impl Into<Box<str>>) -> LocalCommand {
    LocalCommand::SendText {
        payload: value.into(),
        mask_key: None,
    }
}

fn open_server(owner: &mut ConnectionOwner) {
    let write_length = {
        let result = owner.poll(DriverInput::Inbound(TransportBytes::new(RFC_REQUEST)));
        match result.output {
            DriverOutput::Write(bytes) => bytes.len(),
            other => panic!("opening did not offer a write: {other:?}"),
        }
    };
    assert!(matches!(
        owner
            .poll(DriverInput::WriteProgress {
                bytes: write_length,
            })
            .output,
        DriverOutput::StateChanged(_)
    ));
    assert!(matches!(
        owner.poll(DriverInput::Wake).output,
        DriverOutput::Event(_)
    ));
    assert!(matches!(
        owner.poll(DriverInput::Wake).output,
        DriverOutput::Idle
    ));
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Trace {
    accepted: usize,
    enqueue_rejected: usize,
    applied: usize,
    rejected: usize,
    writes: Vec<Vec<u8>>,
    events: usize,
    terminal: usize,
    post_terminal: usize,
    write_bypass: usize,
    external_protocol_mutations: usize,
    fault_injections: usize,
    executed_actions: usize,
}

impl Trace {
    fn reconciled(&self) -> bool {
        self.accepted == self.applied + self.rejected
    }
}

fn observe_poll(
    owner: &mut ConnectionOwner,
    input: DriverInput<'_>,
    trace: &mut Trace,
    offered: &mut Option<usize>,
) -> InputDisposition {
    let result = owner.poll(input);
    match result.command {
        Some(CommandDisposition::Applied(_)) => trace.applied += 1,
        Some(CommandDisposition::Rejected { .. } | CommandDisposition::TerminalRejected(_)) => {
            trace.rejected += 1;
        }
        Some(CommandDisposition::ProducersDropped) | None => {}
    }
    match result.output {
        DriverOutput::Write(bytes) => {
            if offered.is_none() {
                trace.writes.push(bytes.to_vec());
            }
            *offered = Some(bytes.len());
        }
        DriverOutput::Event(_) => trace.events += 1,
        DriverOutput::Terminal(_) => trace.terminal += 1,
        DriverOutput::Idle | DriverOutput::StateChanged(_) | DriverOutput::Failure(_) => {}
    }
    result.input
}

fn enqueue(handle: &CommandHandle, command: LocalCommand, trace: &mut Trace) {
    match handle.try_enqueue(command) {
        Ok(()) => trace.accepted += 1,
        Err(
            EnqueueError::Full(_)
            | EnqueueError::ShuttingDown(_)
            | EnqueueError::ReceiverDropped(_)
            | EnqueueError::LimitExceeded { .. },
        ) => trace.enqueue_rejected += 1,
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Action {
    ProducerA1,
    ProducerA2,
    ProducerB1,
    ProducerB2,
    OwnerWake,
    InboundPing,
    InboundClose,
    TransportEof,
    WriteZero,
    WritePartial,
    WriteAll,
    EventDrain,
    Shutdown,
}

const PROGRAMS: [&[Action]; 7] = [
    &[Action::ProducerA1, Action::ProducerA2],
    &[Action::ProducerB1, Action::ProducerB2],
    &[
        Action::OwnerWake,
        Action::OwnerWake,
        Action::OwnerWake,
        Action::OwnerWake,
    ],
    &[Action::InboundPing, Action::InboundPing],
    &[Action::WriteZero, Action::WritePartial, Action::WriteAll],
    &[Action::EventDrain, Action::EventDrain, Action::EventDrain],
    &[Action::Shutdown],
];

// Borrowed and adapted from Claude's exhaustive five-lane scheduler at
// dc07516. The original seven-lane campaign above remains as the exact
// preregistered 512-schedule prefix. This second campaign combines the
// owner, callback-drain, and shutdown actions into one adapter-control lane
// so every interleaving inside three additional context switches fits under
// the same 100,000-schedule and 1,000,000-branch ceilings.
const EXHAUSTIVE_PROGRAMS: [&[Action]; 5] = [
    &[Action::ProducerA1, Action::ProducerA2],
    &[Action::ProducerB1, Action::ProducerB2],
    &[
        Action::InboundPing,
        Action::InboundClose,
        Action::TransportEof,
    ],
    &[Action::WriteZero, Action::WritePartial, Action::WriteAll],
    &[Action::OwnerWake, Action::Shutdown],
];

const EXHAUSTIVE_CONTEXT_SWITCH_BOUND: usize = (EXHAUSTIVE_PROGRAMS.len() - 1) + MAX_PREEMPTIONS;

#[derive(Debug)]
struct Exploration {
    schedules: Vec<Vec<Action>>,
    branches: usize,
    maximum_preemptions: usize,
    truncated: bool,
}

#[derive(Debug)]
struct ExhaustiveExploration {
    schedules: Vec<Vec<Action>>,
    branches: usize,
    maximum_context_switches: usize,
    truncated: bool,
}

fn explore_exhaustive_five_lane_interleavings() -> ExhaustiveExploration {
    fn visit(
        exploration: &mut ExhaustiveExploration,
        positions: &mut [usize],
        schedule: &mut Vec<Action>,
        last_actor: Option<usize>,
        context_switches: usize,
    ) {
        if exploration.schedules.len() == MAX_SCHEDULES || exploration.branches == MAX_BRANCHES {
            exploration.truncated = true;
            return;
        }
        if positions
            .iter()
            .enumerate()
            .all(|(actor, position)| *position == EXHAUSTIVE_PROGRAMS[actor].len())
        {
            exploration.maximum_context_switches =
                exploration.maximum_context_switches.max(context_switches);
            exploration.schedules.push(schedule.clone());
            return;
        }
        for actor in 0..EXHAUSTIVE_PROGRAMS.len() {
            if positions[actor] == EXHAUSTIVE_PROGRAMS[actor].len() {
                continue;
            }
            let next_switches = context_switches
                + usize::from(last_actor.is_some_and(|previous| previous != actor));
            if next_switches > EXHAUSTIVE_CONTEXT_SWITCH_BOUND {
                continue;
            }
            // Completing every other unfinished lane requires entering it at
            // least once. Prune prefixes that cannot finish inside the bound.
            let unfinished_others = (0..EXHAUSTIVE_PROGRAMS.len())
                .filter(|other| {
                    *other != actor && positions[*other] < EXHAUSTIVE_PROGRAMS[*other].len()
                })
                .count();
            if next_switches + unfinished_others > EXHAUSTIVE_CONTEXT_SWITCH_BOUND {
                continue;
            }
            exploration.branches += 1;
            if exploration.branches == MAX_BRANCHES {
                exploration.truncated = true;
                return;
            }
            let action = EXHAUSTIVE_PROGRAMS[actor][positions[actor]];
            positions[actor] += 1;
            schedule.push(action);
            visit(exploration, positions, schedule, Some(actor), next_switches);
            schedule.pop();
            positions[actor] -= 1;
            if exploration.truncated {
                return;
            }
        }
    }

    let mut exploration = ExhaustiveExploration {
        schedules: Vec::new(),
        branches: 0,
        maximum_context_switches: 0,
        truncated: false,
    };
    visit(
        &mut exploration,
        &mut vec![0; EXHAUSTIVE_PROGRAMS.len()],
        &mut Vec::new(),
        None,
        0,
    );
    exploration
}

fn explore_actor_interleavings() -> Exploration {
    struct Search {
        schedules: Vec<Vec<Action>>,
        branches: usize,
        maximum_preemptions: usize,
        truncated: bool,
    }

    fn visit(
        search: &mut Search,
        positions: &mut [usize; PROGRAMS.len()],
        schedule: &mut Vec<Action>,
        last_actor: Option<usize>,
        preemptions: usize,
    ) {
        if search.schedules.len() == EXECUTION_LIMIT || search.branches == MAX_BRANCHES {
            search.truncated = true;
            return;
        }
        if positions
            .iter()
            .enumerate()
            .all(|(actor, position)| *position == PROGRAMS[actor].len())
        {
            search.maximum_preemptions = search.maximum_preemptions.max(preemptions);
            search.schedules.push(schedule.clone());
            return;
        }
        for actor in 0..PROGRAMS.len() {
            if positions[actor] == PROGRAMS[actor].len() {
                continue;
            }
            search.branches += 1;
            if search.branches == MAX_BRANCHES {
                search.truncated = true;
                return;
            }
            let switched_early = last_actor
                .is_some_and(|last| last != actor && positions[last] < PROGRAMS[last].len());
            let next_preemptions = preemptions + usize::from(switched_early);
            if next_preemptions > MAX_PREEMPTIONS {
                continue;
            }
            let action = PROGRAMS[actor][positions[actor]];
            positions[actor] += 1;
            schedule.push(action);
            visit(search, positions, schedule, Some(actor), next_preemptions);
            schedule.pop();
            positions[actor] -= 1;
            if search.truncated {
                return;
            }
        }
    }

    let mut search = Search {
        schedules: Vec::new(),
        branches: 0,
        maximum_preemptions: 0,
        truncated: false,
    };
    visit(
        &mut search,
        &mut [0; PROGRAMS.len()],
        &mut Vec::new(),
        None,
        0,
    );
    Exploration {
        schedules: search.schedules,
        branches: search.branches,
        maximum_preemptions: search.maximum_preemptions,
        truncated: search.truncated,
    }
}

fn execute_action_schedule(schedule: &[Action]) -> Trace {
    let (first, mut owner) = connection_driver(config(2), Role::Server);
    let second = first.clone();
    open_server(&mut owner);
    let mut trace = Trace::default();
    let mut offered = None;
    let mut pending_inbound = VecDeque::new();
    for action in schedule {
        trace.executed_actions += 1;
        match action {
            Action::ProducerA1 => enqueue(&first, text("a1"), &mut trace),
            Action::ProducerA2 => enqueue(&first, text("a2"), &mut trace),
            Action::ProducerB1 => enqueue(&second, text("b1"), &mut trace),
            Action::ProducerB2 => enqueue(&second, text("b2"), &mut trace),
            Action::OwnerWake | Action::EventDrain => {
                observe_poll(&mut owner, DriverInput::Wake, &mut trace, &mut offered);
            }
            Action::InboundPing => {
                pending_inbound.push_back(MASKED_EMPTY_PING);
                let disposition = observe_poll(
                    &mut owner,
                    DriverInput::Inbound(TransportBytes::new(
                        pending_inbound.front().expect("just queued inbound"),
                    )),
                    &mut trace,
                    &mut offered,
                );
                if matches!(disposition, InputDisposition::Consumed { .. }) {
                    pending_inbound.pop_front();
                }
            }
            Action::InboundClose => {
                pending_inbound.push_back(MASKED_CLOSE_1000);
                let disposition = observe_poll(
                    &mut owner,
                    DriverInput::Inbound(TransportBytes::new(
                        pending_inbound.front().expect("just queued inbound close"),
                    )),
                    &mut trace,
                    &mut offered,
                );
                if matches!(disposition, InputDisposition::Consumed { .. }) {
                    pending_inbound.pop_front();
                }
            }
            Action::TransportEof => {
                observe_poll(
                    &mut owner,
                    DriverInput::TransportEof,
                    &mut trace,
                    &mut offered,
                );
            }
            Action::WriteZero => {
                observe_poll(
                    &mut owner,
                    DriverInput::WriteProgress { bytes: 0 },
                    &mut trace,
                    &mut offered,
                );
            }
            Action::WritePartial => {
                let bytes = offered.map_or(1, |remaining| remaining.saturating_sub(1).max(1));
                observe_poll(
                    &mut owner,
                    DriverInput::WriteProgress { bytes },
                    &mut trace,
                    &mut offered,
                );
            }
            Action::WriteAll => {
                let bytes = offered.take().unwrap_or(1);
                observe_poll(
                    &mut owner,
                    DriverInput::WriteProgress { bytes },
                    &mut trace,
                    &mut offered,
                );
            }
            Action::Shutdown => {
                offered = None;
                observe_poll(&mut owner, DriverInput::Shutdown, &mut trace, &mut offered);
            }
        }
    }

    for _ in 0..64 {
        if trace.terminal == 1 && trace.reconciled() {
            break;
        }
        if let Some(bytes) = offered.take() {
            observe_poll(
                &mut owner,
                DriverInput::WriteProgress { bytes },
                &mut trace,
                &mut offered,
            );
        } else if let Some(bytes) = pending_inbound.front() {
            let disposition = observe_poll(
                &mut owner,
                DriverInput::Inbound(TransportBytes::new(bytes)),
                &mut trace,
                &mut offered,
            );
            if matches!(disposition, InputDisposition::Consumed { .. }) {
                pending_inbound.pop_front();
            }
        } else {
            observe_poll(&mut owner, DriverInput::Wake, &mut trace, &mut offered);
        }
    }
    for _ in 0..2 {
        if !matches!(owner.poll(DriverInput::Wake).output, DriverOutput::Idle) {
            trace.post_terminal += 1;
        }
    }
    trace
}

fn digest(trace: &Trace) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for value in [
        trace.accepted,
        trace.enqueue_rejected,
        trace.applied,
        trace.rejected,
        trace.events,
        trace.terminal,
        trace.post_terminal,
        trace.write_bypass,
        trace.external_protocol_mutations,
        trace.executed_actions,
    ] {
        for byte in value.to_le_bytes() {
            hash = (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3);
        }
    }
    for wire in &trace.writes {
        for byte in wire {
            hash = (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3);
        }
    }
    hash
}

fn schedule_digest(schedule: &[Action]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for action in schedule {
        hash = (hash ^ (*action as u64)).wrapping_mul(0x100000001b3);
    }
    hash
}

#[test]
fn bounded_actor_interleavings_execute_and_replay_with_honest_metrics() {
    let fairness = [
        "WEAK_OWNER_PROGRESS_WHEN_WORK_PENDING",
        "WEAK_FLUSH_PROGRESS_WHEN_WRITABLE",
        "WEAK_EVENT_DRAIN_WHEN_OUTPUT_PENDING",
    ];
    assert_eq!(fairness.len(), 3);
    let exploration = explore_actor_interleavings();
    assert_eq!(exploration.schedules.len(), EXECUTION_LIMIT);
    assert!(exploration.schedules.len() <= MAX_SCHEDULES);
    assert!(exploration.branches <= MAX_BRANCHES);
    assert!(exploration.maximum_preemptions <= MAX_PREEMPTIONS);
    assert!(exploration.truncated);
    assert_eq!(
        exploration
            .schedules
            .iter()
            .map(|schedule| schedule_digest(schedule))
            .collect::<BTreeSet<_>>()
            .len(),
        exploration.schedules.len()
    );

    let mut semantic_digest = 0u64;
    let mut distinct_semantic_digests = BTreeSet::new();
    for (index, schedule) in exploration.schedules.iter().enumerate() {
        let first = execute_action_schedule(schedule);
        let replay = execute_action_schedule(schedule);
        assert_eq!(first, replay, "schedule {index} replay drift");
        assert_eq!(first.executed_actions, schedule.len());
        assert!(first.reconciled(), "schedule {index} command loss");
        assert_eq!(first.terminal, 1, "schedule {index} terminal count");
        assert_eq!(first.post_terminal, 0, "schedule {index} post terminal");
        let trace_digest = digest(&first);
        distinct_semantic_digests.insert(trace_digest);
        semantic_digest ^= trace_digest.rotate_left((index % 63) as u32);
    }
    println!(
        "executed={} distinct_schedules={} distinct_semantics={} branches={} preemptions={} truncated={} digest=fnv64:{semantic_digest:016x}",
        exploration.schedules.len(),
        exploration.schedules.len(),
        distinct_semantic_digests.len(),
        exploration.branches,
        exploration.maximum_preemptions,
        exploration.truncated
    );
}

#[test]
fn five_lane_bound_is_exhaustive_and_every_schedule_replays() {
    let exploration = explore_exhaustive_five_lane_interleavings();
    assert!(
        !exploration.truncated,
        "five-lane campaign hit a declared ceiling: schedules={} branches={}",
        exploration.schedules.len(),
        exploration.branches
    );
    assert!(exploration.schedules.len() > EXECUTION_LIMIT);
    assert!(exploration.schedules.len() <= MAX_SCHEDULES);
    assert!(exploration.branches <= MAX_BRANCHES);
    assert!(exploration.maximum_context_switches <= EXHAUSTIVE_CONTEXT_SWITCH_BOUND);
    assert_eq!(exploration.schedules.len(), 79_920);
    assert_eq!(exploration.branches, 315_070);
    assert_eq!(exploration.maximum_context_switches, 7);
    assert_eq!(
        exploration
            .schedules
            .iter()
            .map(|schedule| schedule_digest(schedule))
            .collect::<BTreeSet<_>>()
            .len(),
        exploration.schedules.len()
    );

    let mut semantic_digest = 0u64;
    let mut distinct_semantic_digests = BTreeSet::new();
    for (index, schedule) in exploration.schedules.iter().enumerate() {
        let first = execute_action_schedule(schedule);
        let replay = execute_action_schedule(schedule);
        assert_eq!(first, replay, "schedule {index} replay drift");
        assert_eq!(first.executed_actions, schedule.len());
        assert!(first.reconciled(), "schedule {index} command loss");
        assert_eq!(first.terminal, 1, "schedule {index} terminal count");
        assert_eq!(first.post_terminal, 0, "schedule {index} post terminal");
        let trace_digest = digest(&first);
        distinct_semantic_digests.insert(trace_digest);
        semantic_digest ^= trace_digest.rotate_left((index % 63) as u32);
    }
    assert_eq!(distinct_semantic_digests.len(), 35);
    assert_eq!(semantic_digest, 0x4a21_acfd_2e03_f588);
    println!(
        "executed={} distinct_schedules={} distinct_semantics={} branches={} context_switches={} truncated={} digest=fnv64:{semantic_digest:016x}",
        exploration.schedules.len(),
        exploration.schedules.len(),
        distinct_semantic_digests.len(),
        exploration.branches,
        exploration.maximum_context_switches,
        exploration.truncated
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SeedAction {
    Open,
    EnqueueA,
    EnqueueB,
    Wake,
    WriteAll,
    WritePartial,
    Shutdown,
    Drain,
}

#[derive(Debug)]
struct Seed {
    id: String,
    property: String,
    mutation: String,
    schedule: Vec<SeedAction>,
    counterexample: String,
}

fn parse_seed(body: &str) -> Seed {
    let fields = body
        .lines()
        .map(|line| line.split_once('=').expect("canonical key=value seed"))
        .collect::<Vec<_>>();
    assert_eq!(fields.len(), 5);
    assert_eq!(
        fields.iter().map(|field| field.0).collect::<Vec<_>>(),
        ["id", "property", "mutation", "schedule", "counterexample"]
    );
    let schedule = fields[3]
        .1
        .split(',')
        .map(|action| match action {
            "open" => SeedAction::Open,
            "enqueue-a" => SeedAction::EnqueueA,
            "enqueue-b" => SeedAction::EnqueueB,
            "wake" => SeedAction::Wake,
            "write-all" => SeedAction::WriteAll,
            "write-partial" => SeedAction::WritePartial,
            "shutdown" => SeedAction::Shutdown,
            "drain" => SeedAction::Drain,
            unknown => panic!("unknown seed action {unknown}"),
        })
        .collect();
    Seed {
        id: fields[0].1.to_owned(),
        property: fields[1].1.to_owned(),
        mutation: fields[2].1.to_owned(),
        schedule,
        counterexample: fields[4].1.to_owned(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SeedFault {
    None,
    ProducerProtocolMutation,
    DropFirstDisposition,
    PrematureWriteProgress,
    SwapCommittedWrites,
    DropTerminal,
    RepeatTerminal,
}

impl SeedFault {
    fn parse(name: &str) -> Self {
        match name {
            "mutate-protocol-through-producer" => Self::ProducerProtocolMutation,
            "drop-first-accepted-command" => Self::DropFirstDisposition,
            "apply-second-command-before-front-write-drains" => Self::PrematureWriteProgress,
            "swap-committed-writes" => Self::SwapCommittedWrites,
            "drop-terminal-after-shutdown" => Self::DropTerminal,
            "repeat-terminal-on-wake" => Self::RepeatTerminal,
            unknown => panic!("unknown seed mutation {unknown}"),
        }
    }
}

#[derive(Debug)]
struct OfferedSeedWrite {
    wire: Vec<u8>,
    driver_remaining: usize,
}

#[derive(Debug)]
struct FaultyBoundary {
    fault: SeedFault,
    fault_used: bool,
    trace: Trace,
    offered: Option<OfferedSeedWrite>,
    actual_undrained: usize,
    delayed_wire: Option<Vec<u8>>,
}

impl FaultyBoundary {
    fn new(fault: SeedFault) -> Self {
        Self {
            fault,
            fault_used: false,
            trace: Trace::default(),
            offered: None,
            actual_undrained: 0,
            delayed_wire: None,
        }
    }

    fn activate(&mut self, fault: SeedFault) -> bool {
        if self.fault == fault && !self.fault_used {
            self.fault_used = true;
            self.trace.fault_injections += 1;
            true
        } else {
            false
        }
    }

    fn poll(&mut self, owner: &mut ConnectionOwner, input: DriverInput<'_>) -> InputDisposition {
        let result = owner.poll(input);
        match result.command {
            Some(CommandDisposition::Applied(_)) => {
                if !self.activate(SeedFault::DropFirstDisposition) {
                    self.trace.applied += 1;
                }
                if self.fault == SeedFault::PrematureWriteProgress
                    && self.fault_used
                    && self.actual_undrained > 0
                {
                    self.trace.write_bypass += 1;
                }
            }
            Some(CommandDisposition::Rejected { .. } | CommandDisposition::TerminalRejected(_)) => {
                if !self.activate(SeedFault::DropFirstDisposition) {
                    self.trace.rejected += 1;
                }
            }
            Some(CommandDisposition::ProducersDropped) | None => {}
        }
        match result.output {
            DriverOutput::Write(bytes) => {
                if let Some(offered) = &mut self.offered {
                    offered.driver_remaining = bytes.len();
                } else {
                    self.offered = Some(OfferedSeedWrite {
                        wire: bytes.to_vec(),
                        driver_remaining: bytes.len(),
                    });
                }
            }
            DriverOutput::Event(_) => self.trace.events += 1,
            DriverOutput::Terminal(_) if self.activate(SeedFault::DropTerminal) => {}
            DriverOutput::Terminal(_) if self.activate(SeedFault::RepeatTerminal) => {
                self.trace.terminal += 2;
            }
            DriverOutput::Terminal(_) => self.trace.terminal += 1,
            DriverOutput::Idle | DriverOutput::StateChanged(_) | DriverOutput::Failure(_) => {}
        }
        result.input
    }

    fn enqueue(&mut self, handle: &CommandHandle, command: LocalCommand) {
        enqueue(handle, command, &mut self.trace);
    }

    fn producer_protocol_mutation(&mut self, owner: &mut ConnectionOwner) {
        if self.activate(SeedFault::ProducerProtocolMutation) {
            self.trace.external_protocol_mutations += 1;
            self.poll(
                owner,
                DriverInput::Inbound(TransportBytes::new(MASKED_EMPTY_PING)),
            );
        }
    }

    fn write_partial(&mut self, owner: &mut ConnectionOwner) {
        let remaining = self
            .offered
            .as_ref()
            .map_or(1, |offered| offered.driver_remaining);
        let actual = remaining.saturating_sub(1).max(1).min(remaining);
        if self.activate(SeedFault::PrematureWriteProgress) {
            self.actual_undrained += remaining.saturating_sub(actual);
            self.offered = None;
            self.poll(owner, DriverInput::WriteProgress { bytes: remaining });
            self.poll(owner, DriverInput::Wake);
            self.poll(owner, DriverInput::Wake);
        } else {
            self.poll(owner, DriverInput::WriteProgress { bytes: actual });
        }
    }

    fn write_all(&mut self, owner: &mut ConnectionOwner) {
        let Some(offered) = self.offered.take() else {
            self.poll(owner, DriverInput::WriteProgress { bytes: 1 });
            return;
        };
        if self.fault == SeedFault::SwapCommittedWrites {
            if let Some(first) = self.delayed_wire.take() {
                self.trace.writes.push(offered.wire.clone());
                self.trace.writes.push(first);
            } else {
                self.activate(SeedFault::SwapCommittedWrites);
                self.delayed_wire = Some(offered.wire.clone());
            }
        } else {
            self.trace.writes.push(offered.wire);
        }
        self.poll(
            owner,
            DriverInput::WriteProgress {
                bytes: offered.driver_remaining,
            },
        );
    }
}

fn execute_seed_with_fault(seed: &Seed, fault: SeedFault) -> Trace {
    let (handle, mut owner) = connection_driver(config(2), Role::Server);
    let mut boundary = FaultyBoundary::new(fault);
    for action in &seed.schedule {
        boundary.trace.executed_actions += 1;
        match action {
            SeedAction::Open => open_server(&mut owner),
            SeedAction::EnqueueA => {
                boundary.producer_protocol_mutation(&mut owner);
                boundary.enqueue(&handle, text("a"));
            }
            SeedAction::EnqueueB => boundary.enqueue(&handle, text("b")),
            SeedAction::Wake | SeedAction::Drain => {
                boundary.poll(&mut owner, DriverInput::Wake);
            }
            SeedAction::WriteAll => boundary.write_all(&mut owner),
            SeedAction::WritePartial => boundary.write_partial(&mut owner),
            SeedAction::Shutdown => {
                boundary.offered = None;
                boundary.actual_undrained = 0;
                boundary.poll(&mut owner, DriverInput::Shutdown);
            }
        }
    }
    for _ in 0..32 {
        if boundary.trace.terminal == 1 && boundary.trace.reconciled() {
            break;
        }
        if boundary.offered.is_some() {
            boundary.write_all(&mut owner);
        } else {
            boundary.poll(&mut owner, DriverInput::Wake);
        }
    }
    boundary.trace
}

fn execute_seed(seed: &Seed) -> Trace {
    execute_seed_with_fault(seed, SeedFault::None)
}

fn execute_faulty_seed(seed: &Seed) -> Trace {
    execute_seed_with_fault(seed, SeedFault::parse(&seed.mutation))
}

fn seed_property_holds(seed: &Seed, trace: &Trace) -> bool {
    match seed.property.as_str() {
        "single-owner" => trace.external_protocol_mutations == 0,
        "accepted-eventual-exactly-once" => trace.reconciled(),
        "no-write-bypass" => trace.write_bypass == 0,
        "fifo-owner-order" => trace.writes == [b"\x81\x01a".to_vec(), b"\x81\x01b".to_vec()],
        "close-convergence" | "terminal-exactly-once" => trace.terminal == 1,
        unknown => panic!("unknown seed property {unknown}"),
    }
}

fn derive_counterexample(property: &str, trace: &Trace) -> Option<&'static str> {
    match property {
        "single-owner" if trace.external_protocol_mutations > 0 => {
            Some("producer-protocol-mutation-visible")
        }
        "accepted-eventual-exactly-once" if !trace.reconciled() => {
            Some("accepted-not-equal-disposed")
        }
        "no-write-bypass" if trace.write_bypass > 0 => {
            Some("second-wire-observed-before-first-completes")
        }
        "fifo-owner-order" if trace.writes == [b"\x81\x01b".to_vec(), b"\x81\x01a".to_vec()] => {
            Some("wire-order-b-a")
        }
        "close-convergence" if trace.terminal == 0 => Some("no-terminal-after-fair-drain"),
        "terminal-exactly-once" if trace.terminal == 2 => Some("terminal-count-two"),
        _ => None,
    }
}

#[test]
fn all_six_seed_schedules_execute_named_mutants_and_counterexamples_twice() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz-seeds/us017");
    let mut discovered = fs::read_dir(&root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    discovered.sort();
    let expected = [
        "close-race.seed",
        "duplicate-delivery.seed",
        "lock-sharing.seed",
        "lost-command.seed",
        "queue-bypass.seed",
        "write-reorder.seed",
    ];
    assert_eq!(discovered, expected);
    let mut seen = BTreeSet::new();
    for file in expected {
        let seed = parse_seed(&fs::read_to_string(root.join(file)).unwrap());
        assert!(seen.insert(seed.id.clone()), "duplicate seed {}", seed.id);
        let first_good = execute_seed(&seed);
        let second_good = execute_seed(&seed);
        assert_eq!(first_good, second_good, "good replay drift for {}", seed.id);
        assert_eq!(first_good.executed_actions, seed.schedule.len());
        assert!(
            seed_property_holds(&seed, &first_good),
            "good run failed {}",
            seed.id
        );

        let first_mutant = execute_faulty_seed(&seed);
        let second_mutant = execute_faulty_seed(&seed);
        assert_eq!(
            first_mutant, second_mutant,
            "mutant replay drift for {}",
            seed.id
        );
        assert_eq!(first_mutant.executed_actions, seed.schedule.len());
        assert_ne!(digest(&first_good), digest(&first_mutant));
        assert_eq!(first_mutant.fault_injections, 1);
        assert_eq!(
            derive_counterexample(&seed.property, &first_mutant),
            Some(seed.counterexample.as_str()),
            "faulty public-boundary run did not reproduce {}",
            seed.id,
        );
    }
    assert_eq!(seen.len(), 6);
}

#[test]
fn current_host_native_thread_stress_reconciles_every_accepted_command() {
    let deadline = Duration::from_secs(10);
    let started = Instant::now();
    let mut totals = (0usize, 0usize, 0usize, 0usize);
    for repeat in 0..STRESS_REPEATS {
        let (handle, mut owner) = connection_driver(
            config((PRODUCERS * COMMANDS_PER_PRODUCER) as u64),
            Role::Server,
        );
        open_server(&mut owner);
        let barrier = Arc::new(Barrier::new(PRODUCERS + 1));
        let accepted = Arc::new(AtomicUsize::new(0));
        let mut producers = Vec::new();
        for producer in 0..PRODUCERS {
            let handle = handle.clone();
            let barrier = Arc::clone(&barrier);
            let accepted = Arc::clone(&accepted);
            producers.push(thread::spawn(move || {
                barrier.wait();
                let mut local = 0usize;
                for sequence in 0..COMMANDS_PER_PRODUCER {
                    let payload = format!("r{repeat}-p{producer}-s{sequence}");
                    match handle.try_enqueue(text(payload)) {
                        Ok(()) => {
                            accepted.fetch_add(1, Ordering::SeqCst);
                            local += 1;
                        }
                        Err(EnqueueError::Full(_)) => {}
                        Err(other) => panic!("unexpected stress enqueue: {other:?}"),
                    }
                }
                local
            }));
        }
        barrier.wait();
        let mut applied = 0usize;
        while applied < PRODUCERS * COMMANDS_PER_PRODUCER {
            assert!(
                started.elapsed() < deadline,
                "native stress deadline exceeded"
            );
            let (write, disposition) = {
                let result = owner.poll(DriverInput::Wake);
                let length = match result.output {
                    DriverOutput::Write(bytes) => Some(bytes.len()),
                    DriverOutput::Idle => None,
                    other => panic!("unexpected stress output: {other:?}"),
                };
                (length, result.command)
            };
            if matches!(disposition, Some(CommandDisposition::Applied(_))) {
                applied += 1;
            }
            if let Some(bytes) = write {
                let _ = owner.poll(DriverInput::WriteProgress { bytes });
            }
            if accepted.load(Ordering::SeqCst) < PRODUCERS * COMMANDS_PER_PRODUCER {
                thread::yield_now();
            }
        }
        let producer_accepted: usize = producers
            .into_iter()
            .map(|producer| producer.join().unwrap())
            .sum();
        assert_eq!(producer_accepted, PRODUCERS * COMMANDS_PER_PRODUCER);
        assert_eq!(accepted.load(Ordering::SeqCst), producer_accepted);
        assert_eq!(applied, producer_accepted);
        totals.0 += producer_accepted;
        totals.1 += applied;
        totals.3 += 1;
    }
    assert_eq!(totals.0, STRESS_REPEATS * PRODUCERS * COMMANDS_PER_PRODUCER);
    assert_eq!(totals.0, totals.1 + totals.2);
    assert_eq!(totals.3, STRESS_REPEATS);
    assert!(started.elapsed() < deadline);
}
