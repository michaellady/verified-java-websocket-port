//! Positive control for the shapes that HISTORY does not supply.
//!
//! F004 supplies shape B1 (an in-loop `assert!` on a count) and F005 supplies
//! shape A (a count conjunct in the loop header). Shape B2 — a loop that
//! silently breaks out after N machine operations, so that everything asserted
//! afterwards is asserted about a truncated run — has not yet cost this
//! program a red gate, and is here so the rule is not merely a restatement of
//! the two texts it was derived from.

use std::time::{Duration, Instant};

const POLL_BUDGET: u64 = 2_000_000;
const ATTEMPT_CAP: usize = 4096;

/// SHAPE B2: the break is silent, so `applied` is short and the assertion
/// afterwards blames the system under test for the host being busy.
fn truncating_drain(step: impl Fn() -> Option<String>) -> Vec<String> {
    let mut applied = Vec::new();
    let mut polls = 0u64;
    loop {
        polls += 1;
        if let Some(text) = step() {
            applied.push(text);
        }
        if polls >= POLL_BUDGET {
            break;
        }
    }
    applied
}

/// SHAPE B1 via `panic!` rather than `assert!`.
fn spin_until_published(try_once: impl Fn() -> bool) {
    let mut attempts = 0usize;
    loop {
        if try_once() {
            return;
        }
        attempts += 1;
        if attempts > ATTEMPT_CAP {
            panic!("the owner never published (attempts={attempts})");
        }
    }
}

/// SHAPE A on an atomic counter read with `.load`.
fn atomic_header(step: impl Fn() -> bool) -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    let polls = AtomicU64::new(0);
    let mut done = false;
    while !done && polls.load(Ordering::SeqCst) < POLL_BUDGET {
        polls.fetch_add(1, Ordering::SeqCst);
        done = step();
    }
    polls.load(Ordering::SeqCst)
}

/// THE ESCAPE HATCH, exercised. This one is waived and must NOT be reported
/// as a violation; the gate counts it instead.
fn waived_guard(step: impl Fn() -> bool) -> usize {
    let mut ticks = 0usize;
    let started = Instant::now();
    loop {
        ticks += 1;
        if step() {
            return ticks;
        }
        // FIXTURE-COUNT-GUARD-ALLOWED: this fixture's subject IS the counter itself, so the bound is the property under test, not a liveness guard
        assert!(ticks < 32, "the subject overflowed its own domain");
        if started.elapsed() > Duration::from_secs(30) {
            return ticks;
        }
    }
}

/// A waiver marker with no real justification must NOT silence the gate.
fn unjustified_waiver(step: impl Fn() -> bool) -> usize {
    let mut ticks = 0usize;
    loop {
        ticks += 1;
        if step() {
            return ticks;
        }
        // FIXTURE-COUNT-GUARD-ALLOWED: ok
        assert!(ticks < 64, "spun too long");
    }
}
