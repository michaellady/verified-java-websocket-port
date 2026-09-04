//! Residue probes for the fuzzingserver-mode agent's own checks.
//!
//! `valid_agent_name` is the seam that stops an agent name from forging a
//! query parameter in the suite's request target, and every entry point in
//! `agent.rs` calls it. The round-4 US-019 sweep never swept Rust, and
//! sweeping it found that the function's THREE conjuncts and the per-entry
//! guards that consume them all survived neutralisation.
//!
//! Nothing here opens a socket: every assertion is either a pure call to
//! `valid_agent_name` or a call that must be REFUSED before any connect is
//! attempted, so the file cannot block.

use std::net::SocketAddr;

use ws_testee::{
    AgentFixture, IoBounds, SetupOutcome, autobahn_config, case_target, fetch_case_count,
    reports_target, run_case, run_cases, update_reports, valid_agent_name,
};

/// A loopback port nothing can be listening on. Every fixture below is refused
/// on its agent name BEFORE this address is used, so no connect is attempted;
/// if a guard were gone the connect would be refused instead, which is a
/// DIFFERENT outcome and that difference is what these tests read.
fn refused_address() -> SocketAddr {
    "127.0.0.1:1".parse().expect("literal loopback address")
}

fn fixture<'a>(agent: &'a str) -> AgentFixture<'a> {
    AgentFixture {
        address: refused_address(),
        host: "localhost",
        agent,
        config: autobahn_config(),
        bounds: IoBounds::default(),
    }
}

// ---------------------------------------------------------------------------
// agent.rs:73-76 — the three conjuncts of valid_agent_name.
// ---------------------------------------------------------------------------

#[test]
fn an_empty_agent_name_is_refused() {
    // agent.rs:73 — `!agent.is_empty()`. Dropping this conjunct makes the
    // empty name VALID, because `"".bytes().all(..)` is vacuously true. An
    // empty agent name would file the run's results under no agent at all.
    assert!(!valid_agent_name(""));
    assert!(valid_agent_name("a"), "a one-byte name must still be valid");
}

#[test]
fn an_agent_name_carrying_a_target_forging_byte_is_refused() {
    // agent.rs:74 — the `agent.bytes().all(..)` conjunct. Each byte below
    // would change what `/runCase?case=N&agent=NAME` addresses.
    for forged in [
        "an agent",
        "a&agent",
        "a?agent",
        "a#agent",
        "a=agent",
        "a/agent",
        "a%agent",
        "a\nagent",
        "a\tagent",
        "a\u{7f}agent",
        "café",
    ] {
        assert!(
            !valid_agent_name(forged),
            "{forged:?} can forge a request target and must be refused"
        );
    }
}

#[test]
fn the_permitted_agent_alphabet_is_both_halves_of_the_byte_predicate() {
    // agent.rs:75 — the two disjuncts of the per-byte predicate. Each half is
    // asserted on its own: without the alphanumeric half a plain name is
    // rejected, and without the punctuation half every one of these
    // separators is.
    assert!(
        valid_agent_name("rustwstestee19"),
        "alphanumerics must be permitted"
    );
    assert!(
        valid_agent_name("ABCabc0123456789"),
        "the whole alphanumeric range"
    );
    for permitted in ["a-b", "a_b", "a.b", "a+b", "a:b", "-", "_", ".", "+", ":"] {
        assert!(
            valid_agent_name(permitted),
            "{permitted:?} is in the documented alphabet and must be permitted"
        );
    }
}

#[test]
fn the_request_targets_carry_the_agent_name_verbatim() {
    // The reason the alphabet is constrained at all: both targets
    // interpolate the name into a query string.
    assert_eq!(case_target("an-agent", 7), "/runCase?case=7&agent=an-agent");
    assert!(reports_target("an-agent").contains("an-agent"));
}

// ---------------------------------------------------------------------------
// agent.rs:192 / 250 / 265 — every entry point checks the name for itself.
// ---------------------------------------------------------------------------

#[test]
fn every_agent_entry_point_refuses_a_forgeable_name_before_connecting() {
    // agent.rs:250 (run_case), agent.rs:265 (update_reports) and
    // agent.rs:192 (run_one, reached here through fetch_case_count, which
    // has no guard of its own). Each is asserted through the entry point
    // that reaches ONLY it, so no guard can answer for another.
    //
    // The discriminating observable is InvalidAgentName versus
    // SocketFailed: with a guard gone the call proceeds to connect to a
    // refused port and reports the socket failure instead.
    let bad = fixture("a&agent");
    assert_eq!(run_case(&bad, 1), Err(SetupOutcome::InvalidAgentName));
    assert_eq!(update_reports(&bad), Err(SetupOutcome::InvalidAgentName));
    assert_eq!(
        fetch_case_count(&bad).err(),
        Some(SetupOutcome::InvalidAgentName),
        "fetch_case_count carries no guard of its own, so this reads run_one's"
    );
    assert_eq!(
        run_cases(&bad, 4, Some((1, 2)), &mut |_| {}).err(),
        Some(SetupOutcome::InvalidAgentName)
    );

    // And the same calls with a USABLE name must get past the name check to
    // the connect, or the assertions above would hold for a guard that
    // refused everything.
    let good = fixture("a-usable-agent");
    assert!(matches!(
        run_case(&good, 1),
        Err(SetupOutcome::SocketFailed(_))
    ));
    assert!(matches!(
        update_reports(&good),
        Err(SetupOutcome::SocketFailed(_))
    ));
    assert!(matches!(
        fetch_case_count(&good),
        Err(SetupOutcome::SocketFailed(_))
    ));
}

// ---------------------------------------------------------------------------
// agent.rs:323 — the case-range boundary.
// ---------------------------------------------------------------------------

#[test]
fn a_usable_case_range_is_not_refused_as_empty() {
    // agent.rs:323's two disjuncts. The refusing direction is already
    // pinned elsewhere; this is the ACCEPTING direction, which is what
    // separates a boundary check from one that refuses every range. A
    // range the check accepts reaches the connect and fails there.
    let good = fixture("a-usable-agent");
    assert!(
        matches!(
            run_cases(&good, 4, Some((1, 2)), &mut |_| {}),
            Err(SetupOutcome::SocketFailed(_))
        ),
        "range 1..=2 is usable and must get past the boundary check"
    );
    assert_eq!(
        run_cases(&good, 4, Some((0, 2)), &mut |_| {}).err(),
        Some(SetupOutcome::EmptyCaseRange),
        "a 0 lower bound addresses no case the suite numbers"
    );
    assert_eq!(
        run_cases(&good, 4, Some((3, 2)), &mut |_| {}).err(),
        Some(SetupOutcome::EmptyCaseRange),
        "an inverted range selects nothing"
    );
}
