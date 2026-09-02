//! Serialization-discipline evidence for `surface.concurrency.command-order`.
//!
//! ASSURANCE LABEL: this file is `BOUNDED_TEST_EVIDENCE` plus compiler-checked
//! type-level facts. Per `docs/us006-formal-concurrency-design.md` it projects
//! no higher than `BoundedCheckPassed` for the bounded runtime cases and
//! carries no proof claim whatsoever. It is NOT a proof, NOT exhaustive
//! interleaving exploration, and NOT native-thread race-detector evidence.
//! It does not discharge `surface.concurrency.command-order`, whose catalog
//! `required_strength` is `PRODUCTION_REFINEMENT`.
//!
//! What it does add that nothing else in the tree currently pins: the
//! *mechanism* by which `Concurrent commands have one serialized owner order`
//! is enforced is the Rust type system, not runtime logic. `ConnectionOwner`
//! owns the `mpsc::Receiver` and every mutable protocol field; `Receiver` is
//! `!Sync`, so the owner cannot be shared by reference across threads, and
//! `poll` takes `&mut self`, so no two callers can ever be inside an owner
//! transition at once. Producers share only the `Send + Sync + Clone`
//! `CommandHandle`, which reaches the owner exclusively through one bounded
//! FIFO `mpsc::sync_channel`.
//!
//! Those are compiler-enforced facts today, but nothing in the repository
//! asserts them, so an edit that added an `Arc<Mutex<..>>` sharing path, made
//! the owner cloneable, or replaced the FIFO channel would silently delete the
//! obligation's actual enforcement mechanism while every existing test kept
//! passing. The static assertions below fail the build if that happens.

#![forbid(unsafe_code)]

use std::marker::PhantomData;
use std::sync::mpsc;
use std::thread;

use websocket_core::{
    ConnectionConfig, ConnectionLimits, ConnectionState, LocalCommand, Role, SemanticEvent,
    TransportBytes,
};
use websocket_driver::{
    CommandDisposition, CommandHandle, ConnectionOwner, DriverInput, DriverOutput,
    connection_driver,
};

const RFC_REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";

// --- Type-level probes -----------------------------------------------------
//
// Stable-Rust negative trait assertion. An inherent associated const shadows a
// trait associated const of the same name, so `Probe::<T>::SYNC` resolves to
// the inherent `true` when `T: Sync`, and otherwise falls back to the blanket
// trait `false`. No dependencies (the workspace pins
// `allowed_dev_dependencies = []` in `rust/dependency-policy.toml`) and no
// `unsafe`.

struct Probe<T: ?Sized>(PhantomData<T>);

trait SyncFallback {
    const SYNC: bool = false;
}
impl<T: ?Sized> SyncFallback for Probe<T> {}
impl<T: ?Sized + Sync> Probe<T> {
    const SYNC: bool = true;
}

trait CloneFallback {
    const CLONE: bool = false;
}
impl<T: ?Sized> CloneFallback for Probe<T> {}
impl<T: Clone> Probe<T> {
    const CLONE: bool = true;
}

const fn assert_send<T: Send>() {}

/// The owner is movable between threads but can never be *shared* between
/// them: `mpsc::Receiver` is `!Sync`, and that is what makes "one serialized
/// owner order" a compiler-enforced property rather than a convention.
#[test]
fn owner_is_send_but_never_shareable_and_never_cloneable() {
    assert_send::<ConnectionOwner>();

    assert!(
        !Probe::<ConnectionOwner>::SYNC,
        "ConnectionOwner became Sync: it can now be shared by reference across \
         threads, so `poll` is no longer the single serialization point for \
         surface.concurrency.command-order"
    );
    assert!(
        !Probe::<ConnectionOwner>::CLONE,
        "ConnectionOwner became Clone: a second owner can now apply commands \
         against a divergent protocol core, so there is no single owner order"
    );

    // Control: the probe reports true for a type that really is Sync/Clone,
    // so a passing assertion above cannot be an artifact of a broken probe.
    assert!(Probe::<u8>::SYNC);
    assert!(Probe::<u8>::CLONE);
}

/// Producers may be cloned and moved across threads, but they carry no owner
/// state: the handle is the only thing they share.
#[test]
fn producer_handle_is_shareable_cloneable_and_the_sole_producer_path() {
    assert_send::<CommandHandle>();
    assert!(Probe::<CommandHandle>::SYNC);
    assert!(Probe::<CommandHandle>::CLONE);

    // The command queue is a bounded FIFO channel. If this type changes, the
    // FIFO premise of the obligation changes with it.
    assert_send::<mpsc::SyncSender<u8>>();
}

// --- Bounded runtime cases -------------------------------------------------

fn config(command_queue_entries: u64) -> ConnectionConfig {
    ConnectionConfig::try_from(ConnectionLimits {
        command_queue_entries,
        ..ConnectionLimits::default()
    })
    .unwrap()
}

fn text(payload: &str) -> LocalCommand {
    LocalCommand::SendText {
        payload: payload.into(),
        mask_key: None,
    }
}

fn open_server(owner: &mut ConnectionOwner) {
    let opening = owner.poll(DriverInput::Inbound(TransportBytes::new(RFC_REQUEST)));
    let opening_len = match opening.output {
        DriverOutput::Write(bytes) => bytes.len(),
        other => panic!("expected opening write, got {other:?}"),
    };
    assert!(matches!(
        owner
            .poll(DriverInput::WriteProgress { bytes: opening_len })
            .output,
        DriverOutput::StateChanged(ConnectionState::Open)
    ));
    assert!(matches!(
        owner.poll(DriverInput::Wake).output,
        DriverOutput::Event(SemanticEvent::ServerHandshakeOpened { .. })
    ));
    assert!(matches!(
        owner.poll(DriverInput::Wake).output,
        DriverOutput::Idle
    ));
}

fn applied_payload(disposition: &CommandDisposition) -> Option<String> {
    match disposition {
        CommandDisposition::Applied(LocalCommand::SendText { payload, .. }) => {
            Some(payload.to_string())
        }
        _ => None,
    }
}

/// Drains the owner until `wanted` applied commands have been observed or the
/// bounded turn budget is exhausted. Returns the applied payloads in the exact
/// order the single owner applied them.
/// Each applied command emits a transport write that must be acknowledged with
/// `WriteProgress` before the owner will take its next command, so this is a
/// real pump rather than a bare `Wake` loop.
fn drain_applied(owner: &mut ConnectionOwner, wanted: usize, max_turns: usize) -> Vec<String> {
    let mut applied = Vec::new();
    let mut pending_write: Option<usize> = None;
    for _ in 0..max_turns {
        let input = match pending_write.take() {
            Some(bytes) => DriverInput::WriteProgress { bytes },
            None => DriverInput::Wake,
        };
        let result = owner.poll(input);
        if let Some(command) = result.command.as_ref().and_then(applied_payload) {
            applied.push(command);
        }
        if let DriverOutput::Write(bytes) = result.output {
            pending_write = Some(bytes.len());
        }
        if applied.len() == wanted && pending_write.is_none() {
            break;
        }
    }
    applied
}

/// Commands enqueued through *different cloned handles* still reach the owner
/// in one total order, and that order is the enqueue order. Cloning a producer
/// does not create a second ordering domain.
#[test]
fn cloned_producers_share_one_fifo_owner_order() {
    let (handle, mut owner) = connection_driver(config(8), Role::Server);
    open_server(&mut owner);

    let producers: Vec<CommandHandle> = (0..4).map(|_| handle.clone()).collect();
    let expected: Vec<String> = (0..8).map(|index| format!("m{index}")).collect();

    // Round-robin across the clones so the enqueue order deliberately does not
    // match any single producer's order.
    for (index, payload) in expected.iter().enumerate() {
        producers[index % producers.len()]
            .try_enqueue(text(payload))
            .expect("bounded queue admits the enqueue");
    }

    let applied = drain_applied(&mut owner, expected.len(), 256);
    assert_eq!(
        applied, expected,
        "the single owner must apply commands in exact enqueue order regardless \
         of which cloned producer handle submitted them"
    );
}

/// The genuinely concurrent case. Real OS threads race to enqueue; the owner
/// then drains. This asserts the *serialization* half of the obligation that a
/// deterministic test cannot: whatever interleaving the OS picks, every
/// accepted command is applied exactly once, none is duplicated or lost, and
/// each producer's own commands stay in its submission order.
///
/// This is bounded stress on one host, not a race detector and not exhaustive
/// interleaving exploration. `evidence/runtime/manifest.json` records that
/// Miri, sanitizers, and ThreadSanitizer are all `UNAVAILABLE` on the pinned
/// toolchain, so no race-freedom claim is made or implied here.
#[test]
fn concurrent_producers_yield_one_total_order_preserving_per_producer_order() {
    const PRODUCERS: usize = 4;
    const PER_PRODUCER: usize = 6;
    const TOTAL: usize = PRODUCERS * PER_PRODUCER;

    let (handle, mut owner) = connection_driver(config(TOTAL as u64), Role::Server);
    open_server(&mut owner);

    thread::scope(|scope| {
        for producer in 0..PRODUCERS {
            let producer_handle = handle.clone();
            scope.spawn(move || {
                for sequence in 0..PER_PRODUCER {
                    let payload = format!("p{producer}-s{sequence}");
                    // The queue is sized for every command, and admission stays
                    // open, so a rejection here is a real defect rather than
                    // expected backpressure.
                    producer_handle
                        .try_enqueue(text(&payload))
                        .expect("queue sized for the full concurrent batch");
                }
            });
        }
    });

    let applied = drain_applied(&mut owner, TOTAL, 1024);

    assert_eq!(
        applied.len(),
        TOTAL,
        "every accepted command must be applied exactly once by the single owner"
    );

    let mut sorted = applied.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        TOTAL,
        "the owner must not duplicate or drop an accepted command"
    );

    // Per-producer order is the observable consequence of FIFO admission into
    // one queue drained by one owner.
    for producer in 0..PRODUCERS {
        let prefix = format!("p{producer}-");
        let observed: Vec<&String> = applied
            .iter()
            .filter(|payload| payload.starts_with(&prefix))
            .collect();
        let expected: Vec<String> = (0..PER_PRODUCER)
            .map(|sequence| format!("p{producer}-s{sequence}"))
            .collect();
        let expected_refs: Vec<&String> = expected.iter().collect();
        assert_eq!(
            observed, expected_refs,
            "producer {producer} commands were reordered by the owner"
        );
    }
}

/// Mutation canary for `owner-command-order-reversed`.
///
/// `ConnectionOwner::next_disposition` is the single point where the owner's
/// serialized command order becomes publicly observable. On the steady-state
/// path only one disposition is ever queued at a time, so `pop_front` and
/// `pop_back` are indistinguishable there — which is precisely why the US-017
/// bounded-schedule and native-stress suite in
/// `rust/websocket-driver/tests/concurrency.rs` passes unchanged under that
/// mutation (measured; see the US-008 memo).
///
/// The terminal path is where the owner queues *several* dispositions at once:
/// `prepare_terminal` moves the held command and every still-queued command
/// into the disposition deque in FIFO order. Asserting that order here makes
/// this ordering evidence sensitive to the ordering mutation, rather than
/// relying on an unrelated terminal-rejection test to catch it by accident.
#[test]
fn terminal_rejected_commands_preserve_owner_order() {
    let (handle, mut owner) = connection_driver(config(4), Role::Server);
    open_server(&mut owner);

    for payload in ["first", "second", "third", "fourth"] {
        handle
            .try_enqueue(text(payload))
            .expect("bounded queue admits the enqueue");
    }

    // Shutdown closes admission and moves every accepted-but-unapplied command
    // into the disposition queue at once, in owner order.
    owner.poll(DriverInput::Shutdown);

    let mut rejected = Vec::new();
    for _ in 0..256 {
        let result = owner.poll(DriverInput::Wake);
        if let Some(CommandDisposition::TerminalRejected(LocalCommand::SendText {
            payload, ..
        })) = result.command
        {
            rejected.push(payload.to_string());
        }
        if rejected.len() == 4 {
            break;
        }
    }

    assert_eq!(
        rejected,
        vec![
            "first".to_string(),
            "second".to_string(),
            "third".to_string(),
            "fourth".to_string()
        ],
        "the owner must report terminal rejections in its one serialized command \
         order; a reversed disposition drain is a command-order defect"
    );
}

/// Direct canary anchor for the ordering mutation described in the US-008
/// memo. The owner reports command dispositions from one FIFO queue; reversing
/// that drain (`pop_front` -> `pop_back` in `ConnectionOwner::next_disposition`)
/// must be observable at the public boundary.
#[test]
fn owner_disposition_drain_is_first_in_first_out() {
    let (handle, mut owner) = connection_driver(config(4), Role::Server);
    open_server(&mut owner);

    for payload in ["alpha", "beta", "gamma", "delta"] {
        handle
            .try_enqueue(text(payload))
            .expect("bounded queue admits the enqueue");
    }

    let applied = drain_applied(&mut owner, 4, 256);
    assert_eq!(
        applied,
        vec![
            "alpha".to_string(),
            "beta".to_string(),
            "gamma".to_string(),
            "delta".to_string()
        ],
        "owner disposition drain must be FIFO"
    );
}
