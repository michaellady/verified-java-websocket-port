// Polarity control for SHAPE C: a fixture-supplied production budget, and the
// two roles the same field serves. Hand-written, but every shape here is one
// `rust/ws-testee/tests/loopback.rs` actually carried before this branch.
//
// The production side this stands in for:
//     rust/ws-testee/src/io_loop.rs   `while report.polls < bounds.max_polls`
//     the outcome when that bound IS reached: `LoopOutcome::BudgetExhausted`
//
// Declared line numbers are load-bearing; do not reflow this file.

use std::time::Duration;

/// LIVENESS, and the sharpest instance the tree had: a count racing a
/// wall-clock stall limit written three lines above it. MUST FIRE (line 19).
fn a_stalled_peer_trips_the_write_deadline() {
    let bounds = IoBounds {
        read_timeout: Duration::from_millis(2),
        write_stall_limit: Duration::from_millis(300),
        max_polls: 50_000,
        ..IoBounds::default()
    };
    drive(&bounds);
    assert_eq!(outcome(), LoopOutcome::WriteStalled);
}

/// SUBJECT: the run is supposed to end by spending the budget, and the test
/// says so. MUST STAY SILENT — this is a test OF the mechanism, and the number
/// is what it measures.
fn budget_exhaustion_is_reported_honestly() {
    let starved = IoBounds {
        max_polls: 1,
        ..IoBounds::default()
    };
    drive(&starved);
    assert_eq!(outcome(), LoopOutcome::BudgetExhausted);
}

/// A forwarder: it hands its own parameter straight to the budget field.
fn prompt_bounds(max_polls: u64) -> IoBounds {
    IoBounds {
        read_timeout: Duration::from_millis(1),
        max_polls,
        ..IoBounds::default()
    }
}

/// The same forwarder with the parameter RENAMED. Keying on the assignment
/// rather than on the name is what stops this from dodging the rule.
fn renamed_bounds(turns: u64) -> IoBounds {
    IoBounds {
        read_timeout: Duration::from_millis(1),
        max_polls: turns,
        ..IoBounds::default()
    }
}

/// The remedy: the fixture states a DURATION and the count is arithmetic on
/// the one cost a waiting poll pays. Nothing here is a chosen magnitude.
fn derived_bounds(deadline: Duration) -> IoBounds {
    IoBounds {
        read_timeout: Duration::from_millis(1),
        max_polls: polls_for(deadline, Duration::from_millis(1)),
        ..IoBounds::default()
    }
}

/// LIVENESS through a forwarder. MUST FIRE (line 69).
fn a_server_closes_once_its_echo_has_drained() {
    drive(&prompt_bounds(2_000));
    assert!(saw_eof());
}

/// LIVENESS through the RENAMED forwarder. MUST FIRE (line 75).
fn a_client_waits_for_its_peer() {
    drive(&renamed_bounds(250));
    assert!(!saw_eof());
}

/// The remedy in use: a duration, not a count. MUST STAY SILENT.
fn a_server_stamps_a_live_date() {
    drive(&derived_bounds(Duration::from_secs(20)));
    assert!(saw_eof());
}

/// A justified waiver: COUNTED, not reported (line 89).
fn a_deliberately_tiny_budget_for_a_slow_path() {
    // FIXTURE-COUNT-GUARD-ALLOWED: pinned while the wall-clock form lands
    let bounds = IoBounds {
        max_polls: 8,
        ..IoBounds::default()
    };
    drive(&bounds);
    assert!(saw_eof());
}

/// An UNJUSTIFIED marker must not silence anything (line 100).
fn an_unjustified_marker_is_not_a_waiver() {
    // FIXTURE-COUNT-GUARD-ALLOWED: ok
    let bounds = IoBounds {
        max_polls: 9,
        ..IoBounds::default()
    };
    drive(&bounds);
    assert!(saw_eof());
}

/// Prose that QUOTES the defect must not be read as code: `max_polls: 12_345`
/// in a doc comment is documentation. MUST STAY SILENT.
fn prose_is_not_a_supply_site() {
    let text = "max_polls: 6_789";
    drive(&IoBounds::default());
    assert!(!text.is_empty());
}
