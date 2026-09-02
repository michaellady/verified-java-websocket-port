//! US-017 native-thread concurrency evidence: bounded multi-producer
//! enqueueing against the single owner, explicit backpressure, exactly-once
//! disposition, and exactly-once terminal delivery under racing producers.
//!
//! These are systematic native-thread stress checks, NOT proof and NOT a
//! bounded-schedule exploration (the seed-schedule properties live in
//! `driver_contract.rs`); no story acceptance is claimed by this suite
//! (borrow batch C lands the adapted implementation slice only).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use ws_core::config::ConnectionConfig;
use ws_core::{InitialState, LocalCommand, ReadyState, Role};
use ws_driver::{CommandDisposition, DriverInput, DriverOutput, connection_driver_in_state};

const PRODUCERS: usize = 4;
const COMMANDS_PER_PRODUCER: usize = 50;
const TOTAL: usize = PRODUCERS * COMMANDS_PER_PRODUCER;
/// Generous owner-poll deadline: the run is a contract violation if it does
/// not converge far inside this.
///
/// This is a DURATION and not a poll count on purpose. It used to be
/// `POLL_BUDGET: u64 = 2_000_000` owner polls, and a count of how many times
/// a fast machine can go round a loop is a host-speed measurement dressed as
/// a bound: on a loaded host the producer threads had not finished enqueueing
/// when the owner exhausted the count, and
/// `racing_producers_never_lose_or_duplicate_commands` failed
/// `applied.len() == TOTAL` with `left: 179 right: 200` and no defect
/// anywhere. What these loops guard against is spinning FOREVER, and a
/// generous wall clock says exactly that without saying anything about how
/// fast this machine is. Same class as
/// `drafts/self-review/findings/F004-race-test-spin-bound-sized-to-a-host.md`
/// and F002 before it; the poll counter is kept, but only to REPORT in the
/// failure message, never to decide.
const POLL_DEADLINE: Duration = Duration::from_secs(60);

fn stress_config() -> ConnectionConfig {
    ConnectionConfig::builder()
        .max_actions(1024)
        .max_frames(1024)
        .build()
        .expect("valid stress config")
}

/// Multi-producer stress: every accepted command is applied exactly once,
/// writes drain completely, and the owner terminates cleanly.
#[test]
fn racing_producers_never_lose_or_duplicate_commands() {
    let (sender, mut driver) =
        connection_driver_in_state(stress_config(), Role::Server, InitialState::Open);
    let enqueued = Arc::new(AtomicU64::new(0));
    let mut producers = Vec::new();
    for producer in 0..PRODUCERS {
        let sender = sender.clone();
        let enqueued = Arc::clone(&enqueued);
        producers.push(thread::spawn(move || {
            for index in 0..COMMANDS_PER_PRODUCER {
                let mut command = LocalCommand::SendText {
                    text: format!("p{producer}m{index}"),
                };
                // Bounded nonblocking sends: refusals hand the command back
                // and the producer retries after yielding — never blocks,
                // never drops.
                loop {
                    match sender.try_send(command) {
                        Ok(()) => break,
                        Err(refused) => {
                            command = refused.command;
                            thread::yield_now();
                        }
                    }
                }
                enqueued.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }

    let mut applied: Vec<String> = Vec::new();
    let mut wire_bytes = 0usize;
    let mut polls = 0u64;
    let started = Instant::now();
    while applied.len() < TOTAL && started.elapsed() < POLL_DEADLINE {
        polls += 1;
        let result = driver.poll(DriverInput::Wake);
        if let Some(CommandDisposition::Applied(LocalCommand::SendText { text })) = result.command {
            applied.push(text);
        } else if let Some(other) = result.command {
            panic!("unexpected disposition under legal load: {other:?}");
        }
        if let DriverOutput::Write(suffix) = result.output {
            let len = suffix.len();
            wire_bytes += len;
            let progress = driver.poll(DriverInput::WriteProgress { bytes: len });
            if let Some(CommandDisposition::Applied(LocalCommand::SendText { text })) =
                progress.command
            {
                applied.push(text);
            }
        }
    }
    for producer in producers {
        producer.join().expect("producer thread");
    }
    assert_eq!(enqueued.load(Ordering::SeqCst) as usize, TOTAL);
    assert_eq!(
        applied.len(),
        TOTAL,
        "no accepted command lost (polls={polls})"
    );
    let mut unique = applied.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), TOTAL, "no command applied twice");
    // Every payload is 6 bytes ("pXmYY" is 4..6): recompute the exact
    // expected wire total from the applied set (server frames: 2-byte
    // header + payload).
    let expected_wire: usize = applied.iter().map(|text| 2 + text.len()).sum();
    // The final write may still be in flight when the loop exits; drain it.
    loop {
        let result = driver.poll(DriverInput::Wake);
        match result.output {
            DriverOutput::Write(suffix) => {
                let len = suffix.len();
                wire_bytes += len;
                let _ = driver.poll(DriverInput::WriteProgress { bytes: len });
            }
            DriverOutput::Event(_) => {}
            _ => break,
        }
    }
    assert_eq!(wire_bytes, expected_wire, "committed writes all drained");
    assert_eq!(driver.counts().frames, TOTAL as u64);
}

/// Racing producers across a shutdown: the terminal outcome delivers
/// exactly once, and every command that was accepted into the channel is
/// disposed exactly once (applied, rejected, or terminal-rejected).
#[test]
fn terminal_is_exactly_once_under_racing_producers() {
    let (sender, mut driver) =
        connection_driver_in_state(stress_config(), Role::Server, InitialState::Open);
    let accepted = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicU64::new(0));
    let mut producers = Vec::new();
    for _ in 0..PRODUCERS {
        let sender = sender.clone();
        let accepted = Arc::clone(&accepted);
        let stop = Arc::clone(&stop);
        producers.push(thread::spawn(move || {
            let mut index = 0u64;
            while stop.load(Ordering::SeqCst) == 0 {
                index += 1;
                if sender
                    .try_send(LocalCommand::SendText {
                        text: format!("m{index}"),
                    })
                    .is_ok()
                {
                    accepted.fetch_add(1, Ordering::SeqCst);
                }
                thread::yield_now();
            }
        }));
    }

    // Let some traffic flow, then shut down while producers keep racing.
    let mut disposed = 0u64;
    let mut terminals = 0u64;
    let mut polls = 0u64;
    let started = Instant::now();
    while disposed < 20 && started.elapsed() < POLL_DEADLINE {
        polls += 1;
        let result = driver.poll(DriverInput::Wake);
        if result.command.is_some() {
            disposed += 1;
        }
        if let DriverOutput::Write(suffix) = result.output {
            let len = suffix.len();
            let progress = driver.poll(DriverInput::WriteProgress { bytes: len });
            if progress.command.is_some() {
                disposed += 1;
            }
        }
    }
    let shutdown_result = driver.poll(DriverInput::Shutdown);
    if shutdown_result.command.is_some() {
        disposed += 1;
    }
    if matches!(shutdown_result.output, DriverOutput::Terminal(_)) {
        terminals += 1;
    }
    drop(shutdown_result);
    // Drain to quiescence while producers still race, then stop them and
    // drain the tail.
    let mut drained_idle_passes = 0;
    while drained_idle_passes < 3 && started.elapsed() < POLL_DEADLINE {
        polls += 1;
        let result = driver.poll(DriverInput::Wake);
        if result.command.is_some() {
            disposed += 1;
        }
        let state = result.state;
        match result.output {
            DriverOutput::Terminal(_) => terminals += 1,
            DriverOutput::Idle if state == ReadyState::Closed => {
                drained_idle_passes += 1;
            }
            _ => {}
        }
    }
    stop.store(1, Ordering::SeqCst);
    for producer in producers {
        producer.join().expect("producer thread");
    }
    // Post-join tail: every remaining queued command must surface as
    // TerminalRejected; the terminal never repeats.
    loop {
        let result = driver.poll(DriverInput::Wake);
        let mut moved = false;
        if result.command.is_some() {
            disposed += 1;
            moved = true;
        }
        if matches!(result.output, DriverOutput::Terminal(_)) {
            terminals += 1;
            moved = true;
        }
        if !moved {
            break;
        }
    }
    // `polls` decides nothing — the loops above are bounded by POLL_DEADLINE —
    // but reporting how far the owner actually got is what tells a reader
    // whether a failure is a real disposition bug or a starved run.
    assert_eq!(
        terminals, 1,
        "terminal delivered exactly once (polls={polls})"
    );
    assert_eq!(
        disposed,
        accepted.load(Ordering::SeqCst),
        "every accepted command disposed exactly once (polls={polls})"
    );
    assert_eq!(driver.state(), ReadyState::Closed);
}
