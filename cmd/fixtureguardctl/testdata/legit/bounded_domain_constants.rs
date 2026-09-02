//! Negative control for fixtureguardctl: legitimate bounded-domain constants
//! and goal counters that MUST NOT be reported.
//!
//! Every construct below is drawn from a real shape in this repository's Rust
//! test tree (rust/ws-core/tests, rust/ws-driver/tests). If the detector ever
//! starts reporting one of these, the rule has drifted into the noisy
//! direction and the gate becomes something people route around.

use std::time::{Duration, Instant};

const MAX_FRAMES: usize = 1024;
const TOTAL: usize = 200;
const POLL_DEADLINE: Duration = Duration::from_secs(60);

/// A config value that happens to be a count. Never a loop guard.
fn config_budgets() -> (usize, usize) {
    (MAX_FRAMES, 1024)
}

/// A `for` over an exact domain: 247 cases is what there are, not a budget.
fn every_case() -> usize {
    let mut seen = 0usize;
    for case in 0..247 {
        seen += case % 2;
    }
    seen
}

/// A `while` bounded by a DYNAMIC quantity: `bytes.len()` is not a constant.
fn walk(bytes: &[u8]) -> usize {
    let mut i = 0usize;
    let mut nonzero = 0usize;
    while i < bytes.len() {
        if bytes[i] != 0 {
            nonzero += 1;
        }
        i += 1;
    }
    nonzero
}

/// A GOAL counter: the loop's purpose is to reach 20 dispositions, and it is
/// incremented only when progress actually happens. The liveness guard beside
/// it is the wall clock, which is the correct shape.
fn drain_until_twenty(step: impl Fn() -> bool) -> u64 {
    let mut disposed = 0u64;
    let mut polls = 0u64;
    let started = Instant::now();
    while disposed < 20 && started.elapsed() < POLL_DEADLINE {
        polls += 1;
        if step() {
            disposed += 1;
        }
    }
    assert_eq!(disposed, 20, "drained (polls={polls})");
    polls
}

/// A goal counter incremented inside a `match` arm, beside a wall clock.
fn drain_to_quiescence(step: impl Fn() -> u8) -> u64 {
    let mut drained_idle_passes = 0;
    let mut polls = 0u64;
    let started = Instant::now();
    while drained_idle_passes < 3 && started.elapsed() < POLL_DEADLINE {
        polls += 1;
        match step() {
            0 => drained_idle_passes += 1,
            _ => {}
        }
    }
    polls
}

/// An assertion ABOUT THE SYSTEM UNDER TEST, placed after the loop. Bounded
/// capacity is a property of the queue, not a statement about this host.
fn bounded_capacity(send: impl Fn() -> bool) -> usize {
    let mut accepted = 0usize;
    let started = Instant::now();
    loop {
        if send() {
            accepted += 1;
        }
        if started.elapsed() >= Duration::from_secs(30) {
            break;
        }
        if accepted >= 8 {
            break;
        }
    }
    assert!(accepted <= 8, "bounded capacity held: {accepted}");
    accepted
}

/// The CORRECT shape of a stress loop: a wall-clock deadline decides, and the
/// operation count only reports.
fn stress(step: impl Fn() -> Option<String>) -> Vec<String> {
    let mut applied: Vec<String> = Vec::new();
    let mut polls = 0u64;
    let started = Instant::now();
    while applied.len() < TOTAL && started.elapsed() < POLL_DEADLINE {
        polls += 1;
        if let Some(text) = step() {
            applied.push(text);
        }
    }
    assert_eq!(applied.len(), TOTAL, "no accepted command lost (polls={polls})");
    applied
}

/// A comment that QUOTES the defect must not be mistaken for the defect:
/// the old guard read `while applied.len() < TOTAL && polls < POLL_BUDGET`
/// and the old assertion read `assert!(refusals_before_the_drop < 4096, ..)`.
/// Neither of those is code here.
fn quoted_in_prose() -> &'static str {
    "while polls < POLL_BUDGET { polls += 1; }"
}
