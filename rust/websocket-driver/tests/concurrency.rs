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

#[derive(Debug)]
struct Exploration {
    schedules: Vec<Vec<Action>>,
    branches: usize,
    maximum_preemptions: usize,
    truncated: bool,
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

fn execute_seed(seed: &Seed) -> Trace {
    let (handle, mut owner) = connection_driver(config(2), Role::Server);
    let mut trace = Trace::default();
    let mut offered = None;
    for action in &seed.schedule {
        trace.executed_actions += 1;
        match action {
            SeedAction::Open => open_server(&mut owner),
            SeedAction::EnqueueA => enqueue(&handle, text("a"), &mut trace),
            SeedAction::EnqueueB => enqueue(&handle, text("b"), &mut trace),
            SeedAction::Wake | SeedAction::Drain => {
                observe_poll(&mut owner, DriverInput::Wake, &mut trace, &mut offered);
            }
            SeedAction::WriteAll => {
                let bytes = offered.take().unwrap_or(1);
                observe_poll(
                    &mut owner,
                    DriverInput::WriteProgress { bytes },
                    &mut trace,
                    &mut offered,
                );
            }
            SeedAction::WritePartial => {
                let bytes = offered.map_or(1, |remaining| remaining.saturating_sub(1).max(1));
                observe_poll(
                    &mut owner,
                    DriverInput::WriteProgress { bytes },
                    &mut trace,
                    &mut offered,
                );
            }
            SeedAction::Shutdown => {
                offered = None;
                observe_poll(&mut owner, DriverInput::Shutdown, &mut trace, &mut offered);
            }
        }
    }
    for _ in 0..32 {
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
        } else {
            observe_poll(&mut owner, DriverInput::Wake, &mut trace, &mut offered);
        }
    }
    trace
}

fn apply_named_mutation(seed: &Seed, trace: &mut Trace) {
    match seed.mutation.as_str() {
        "mutate-protocol-through-producer" => trace.external_protocol_mutations += 1,
        "drop-first-accepted-command" => {
            if trace.applied > 0 {
                trace.applied -= 1;
            } else if trace.rejected > 0 {
                trace.rejected -= 1;
            }
        }
        "apply-second-command-before-front-write-drains" => trace.write_bypass += 1,
        "swap-committed-writes" => {
            if trace.writes.len() >= 2 {
                trace.writes.swap(0, 1);
            }
        }
        "drop-terminal-after-shutdown" => trace.terminal = 0,
        "repeat-terminal-on-wake" => trace.terminal += 1,
        unknown => panic!("unknown seed mutation {unknown}"),
    }
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

fn expected_counterexample(seed: &Seed) -> &'static str {
    match seed.id.as_str() {
        "lock-sharing" => "producer-protocol-mutation-visible",
        "lost-command" => "accepted-not-equal-disposed",
        "queue-bypass" => "second-wire-observed-before-first-completes",
        "write-reorder" => "wire-order-b-a",
        "close-race" => "no-terminal-after-fair-drain",
        "duplicate-delivery" => "terminal-count-two",
        unknown => panic!("unknown seed {unknown}"),
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
        assert_eq!(seed.counterexample, expected_counterexample(&seed));
        let first_good = execute_seed(&seed);
        let second_good = execute_seed(&seed);
        assert_eq!(first_good, second_good, "good replay drift for {}", seed.id);
        assert_eq!(first_good.executed_actions, seed.schedule.len());
        assert!(
            seed_property_holds(&seed, &first_good),
            "good run failed {}",
            seed.id
        );

        let mut first_mutant = execute_seed(&seed);
        apply_named_mutation(&seed, &mut first_mutant);
        let mut second_mutant = execute_seed(&seed);
        apply_named_mutation(&seed, &mut second_mutant);
        assert_eq!(
            first_mutant, second_mutant,
            "mutant replay drift for {}",
            seed.id
        );
        assert_ne!(digest(&first_good), digest(&first_mutant));
        assert!(
            !seed_property_holds(&seed, &first_mutant),
            "named mutant survived for {}",
            seed.id
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
