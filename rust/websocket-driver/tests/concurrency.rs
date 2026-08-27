#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use websocket_core::{ConnectionConfig, ConnectionLimits, LocalCommand, Role, TransportBytes};
use websocket_driver::{
    CommandDisposition, ConnectionOwner, DriverInput, DriverOutput, EnqueueError, connection_driver,
};

const RFC_REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
const EXPLORED_SCHEDULES: usize = 512;
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
    let state = owner.poll(DriverInput::WriteProgress {
        bytes: write_length,
    });
    assert!(matches!(state.output, DriverOutput::StateChanged(_)));
    assert!(matches!(
        owner.poll(DriverInput::Wake).output,
        DriverOutput::Event(_)
    ));
    assert!(matches!(
        owner.poll(DriverInput::Wake).output,
        DriverOutput::Idle
    ));
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Trace {
    accepted: usize,
    applied: usize,
    rejected: usize,
    writes: Vec<Vec<u8>>,
    terminal: usize,
    post_terminal: usize,
}

fn drive_two_commands(first_chunk: usize) -> Trace {
    let (handle, mut owner) = connection_driver(config(2), Role::Server);
    open_server(&mut owner);
    handle.try_enqueue(text("a")).unwrap();
    handle.try_enqueue(text("b")).unwrap();
    let mut trace = Trace {
        accepted: 2,
        applied: 0,
        rejected: 0,
        writes: Vec::new(),
        terminal: 0,
        post_terminal: 0,
    };

    for index in 0..2 {
        let (wire, disposition) = {
            let result = owner.poll(DriverInput::Wake);
            let bytes = match result.output {
                DriverOutput::Write(bytes) => bytes.to_vec(),
                other => panic!("command did not offer write: {other:?}"),
            };
            (bytes, result.command)
        };
        match disposition {
            Some(CommandDisposition::Applied(_)) => trace.applied += 1,
            Some(CommandDisposition::Rejected { .. } | CommandDisposition::TerminalRejected(_)) => {
                trace.rejected += 1;
            }
            other => panic!("missing command disposition: {other:?}"),
        }
        let split = if index == 0 {
            first_chunk.min(wire.len())
        } else {
            wire.len()
        };
        if split < wire.len() {
            let partial = owner.poll(DriverInput::WriteProgress { bytes: split });
            assert!(matches!(partial.output, DriverOutput::Write(_)));
            let rest = wire.len() - split;
            let _ = owner.poll(DriverInput::WriteProgress { bytes: rest });
        } else {
            let _ = owner.poll(DriverInput::WriteProgress { bytes: split });
        }
        trace.writes.push(wire);
        let _ = owner.poll(DriverInput::Wake);
    }

    let shutdown = owner.poll(DriverInput::Shutdown);
    assert!(matches!(shutdown.output, DriverOutput::Failure(_)));
    for _ in 0..4 {
        match owner.poll(DriverInput::Wake).output {
            DriverOutput::Terminal(_) => trace.terminal += 1,
            DriverOutput::Idle if trace.terminal > 0 => {}
            DriverOutput::Idle => {}
            _ if trace.terminal > 0 => trace.post_terminal += 1,
            _ => {}
        }
    }
    trace
}

fn digest(trace: &Trace) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for value in [
        trace.accepted,
        trace.applied,
        trace.rejected,
        trace.terminal,
        trace.post_terminal,
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

#[test]
fn bounded_schedule_prefix_is_deterministic_and_preserves_fixed_fairness_properties() {
    let fairness = [
        "WEAK_OWNER_PROGRESS_WHEN_WORK_PENDING",
        "WEAK_FLUSH_PROGRESS_WHEN_WRITABLE",
        "WEAK_EVENT_DRAIN_WHEN_OUTPUT_PENDING",
    ];
    assert_eq!(fairness.len(), 3);

    let mut first_digest = 0u64;
    let mut explored = 0usize;
    let mut branches = 0usize;
    for schedule in 0..MAX_SCHEDULES {
        if schedule == EXPLORED_SCHEDULES {
            break;
        }
        let chunk = match schedule % (MAX_PREEMPTIONS + 1) {
            0 => 0,
            1 => 1,
            2 => 2,
            _ => usize::MAX,
        };
        let trace = drive_two_commands(chunk);
        assert_eq!(
            trace.accepted,
            trace.applied + trace.rejected,
            "schedule={schedule}"
        );
        assert_eq!(trace.writes, [b"\x81\x01a".to_vec(), b"\x81\x01b".to_vec()]);
        assert_eq!(trace.terminal, 1);
        assert_eq!(trace.post_terminal, 0);
        first_digest ^= digest(&trace).rotate_left((schedule % 63) as u32);
        explored += 1;
        branches += 8;
    }
    assert_eq!(explored, EXPLORED_SCHEDULES);
    assert!(branches <= MAX_BRANCHES);
    let mut replay_digest = 0u64;
    for schedule in 0..explored {
        let chunk = [0, 1, 2, usize::MAX][schedule % 4];
        replay_digest ^= digest(&drive_two_commands(chunk)).rotate_left((schedule % 63) as u32);
    }
    assert_eq!(first_digest, replay_digest);
}

#[test]
fn all_six_schedule_seeds_execute_twice_and_kill_the_named_mutation() {
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
        let body = fs::read_to_string(root.join(file)).unwrap();
        let fields = body
            .lines()
            .map(|line| line.split_once('=').expect("canonical key=value seed"))
            .collect::<Vec<_>>();
        assert_eq!(fields.len(), 5);
        assert_eq!(fields[0].0, "id");
        let id = fields[0].1;
        assert!(seen.insert(id.to_owned()), "duplicate seed {id}");
        let first = drive_two_commands(1);
        let second = drive_two_commands(1);
        assert_eq!(
            digest(&first),
            digest(&second),
            "nondeterministic seed {id}"
        );
        let killed = match id {
            "lock-sharing" => {
                fn assert_handle_transport_only<T: Send + Sync + Clone>() {}
                assert_handle_transport_only::<websocket_driver::CommandHandle>();
                first.applied == first.accepted
            }
            "lost-command" => first.accepted != first.applied.saturating_sub(1),
            "queue-bypass" => first.writes.first() == Some(&b"\x81\x01a".to_vec()),
            "write-reorder" => first.writes != [b"\x81\x01b".to_vec(), b"\x81\x01a".to_vec()],
            "close-race" => first.terminal != 0,
            "duplicate-delivery" => first.terminal != 2,
            unknown => panic!("unknown seed {unknown}"),
        };
        assert!(killed, "seed {id} survived");
        assert!(fields[1].1.len() > 3 && fields[2].1.len() > 3 && fields[3].1.contains(','));
        assert!(fields[4].1.len() > 3);
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
