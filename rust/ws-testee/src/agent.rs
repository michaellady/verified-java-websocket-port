//! The Autobahn **fuzzingserver-mode** client agent (US-019 AC3).
//!
//! Autobahn's two modes test opposite roles. `wstest --mode fuzzingclient`
//! connects OUT to a testee server — that is the E5/E5b lane, wired through
//! [`crate::server::run_server_sessions`]. `wstest --mode fuzzingserver`
//! inverts it: the suite LISTENS and the testee is a WebSocket **client**
//! that must speak the suite's own small agent protocol over three request
//! targets:
//!
//! | target | purpose |
//! |---|---|
//! | `/getCaseCount` | the suite sends one text message: how many cases the config SELECTED |
//! | `/runCase?case=N&agent=NAME` | one case; the testee echoes every delivered message |
//! | `/updateReports?agent=NAME` | the suite flushes its reports for `NAME` |
//!
//! The E5 lane disclosed that `ws-testee` lacked this agent; this module is
//! that missing half. It is pure ADAPTER routing, exactly like
//! [`crate::client`] and [`crate::server`]: every protocol decision —
//! handshake, framing, limits, control frames, close — stays in `ws_core`
//! behind `ws_driver`. The agent only chooses request targets, re-sends
//! delivered payloads through the bounded [`CommandSender`], and counts.
//!
//! ## Conformance is judged by the suite, never by this agent
//!
//! A large share of the selected cases deliberately provoke a protocol
//! failure (in fuzzingclient mode 123 of 247 ended in a typed
//! `ProtocolFailure`, which was the CORRECT outcome). So a case ending in
//! [`crate::LoopOutcome::ProtocolFailure`] is **not** an agent error and
//! must not be scored as one here. The agent's own success is purely
//! operational — every selected case was driven to a terminal transport
//! outcome and the reports were flushed. The verdict comes from wstest's
//! report, read separately.

use std::net::{SocketAddr, TcpStream};

use ws_core::{ConnectionConfig, Role};
use ws_driver::connection_driver;

use crate::io_loop::{
    ConnectionReport, EchoPolicy, EventPolicy, IoBounds, LoopOutcome, ObserveOnly,
    drive_connection_from, drive_until_open, empty_report,
};
use crate::{SetupOutcome, loopback_only};

/// One fuzzingserver-mode agent run's parameters.
#[derive(Debug, Clone)]
pub struct AgentFixture<'a> {
    /// The suite's listening address, reached over loopback (the Autobahn
    /// container publishes its port to `127.0.0.1`; the US-018 loopback-only
    /// contract binds this adapter too).
    pub address: SocketAddr,
    /// Host header value for the upgrade request.
    pub host: &'a str,
    /// The agent name the suite files results under. Constrained by
    /// [`valid_agent_name`] so it cannot forge query parameters.
    pub agent: &'a str,
    /// Connection configuration (protocol limits live in the core).
    pub config: ConnectionConfig,
    /// Bounded I/O parameters.
    pub bounds: IoBounds,
}

/// Whether an agent name may be placed in a request target verbatim.
///
/// The name is interpolated into the query string, so a name carrying `&`,
/// `?`, `#`, `=`, `/`, `%`, whitespace, or any non-visible-ASCII byte could
/// forge a different case selection or report scope. Such names are REFUSED
/// at the construction seam rather than silently sanitized — a silently
/// rewritten agent name would make the suite's report file disagree with the
/// name this run recorded in its evidence.
#[must_use]
pub fn valid_agent_name(agent: &str) -> bool {
    !agent.is_empty()
        && agent.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+' | b':')
        })
}

/// The suite's case-count request target.
pub const CASE_COUNT_TARGET: &str = "/getCaseCount";

/// Builds the `/runCase` target for a 1-based case index.
///
/// # Panics
///
/// Never: [`valid_agent_name`] is checked by every entry point before this
/// is reached.
#[must_use]
pub fn case_target(agent: &str, case: u32) -> String {
    format!("/runCase?case={case}&agent={agent}")
}

/// Builds the `/updateReports` target.
#[must_use]
pub fn reports_target(agent: &str) -> String {
    format!("/updateReports?agent={agent}")
}

/// What one `/getCaseCount` connection produced.
#[derive(Debug, Clone)]
pub struct CaseCountOutcome {
    /// The selected-case count the suite reported, when it sent a parseable
    /// one. `None` means the suite sent nothing usable — NEVER coerced to
    /// zero, because a zero-case sweep would "succeed" having tested
    /// nothing.
    pub count: Option<u32>,
    /// The connection's own report (outcome, texts, close).
    pub report: ConnectionReport,
}

/// One case's operational result.
#[derive(Debug, Clone)]
pub struct CaseOutcome {
    /// The 1-based case index as addressed in the request target.
    pub case: u32,
    /// The connection's report; `outcome` may legitimately be a typed
    /// `ProtocolFailure` for cases that provoke one.
    pub report: ConnectionReport,
}

/// A whole fuzzingserver-mode sweep's operational accounting.
#[derive(Debug, Clone)]
pub struct AgentSweep {
    /// The selected-case count the SUITE reported (read, never assumed).
    pub case_count: u32,
    /// Per-case outcomes, in the order they were addressed.
    pub cases: Vec<CaseOutcome>,
    /// Whether the `/updateReports` connection reached a terminal outcome.
    pub reports_updated: bool,
}

impl AgentSweep {
    /// Cases that reached a terminal transport outcome.
    #[must_use]
    pub fn terminal(&self) -> usize {
        self.cases
            .iter()
            .filter(|case| case.report.outcome == LoopOutcome::Terminal)
            .count()
    }

    /// Cases that ended in a typed protocol failure. Expected and correct
    /// for the cases that provoke one; reported, never judged, here.
    #[must_use]
    pub fn protocol_failures(&self) -> usize {
        self.cases
            .iter()
            .filter(|case| matches!(case.report.outcome, LoopOutcome::ProtocolFailure(_)))
            .count()
    }

    /// Cases that ended in an outcome neither terminal nor a typed protocol
    /// failure — the only class that indicates the HARNESS, not the peer,
    /// went wrong (socket error, write stall, exhausted poll budget).
    #[must_use]
    pub fn harness_faults(&self) -> usize {
        self.cases.len() - self.terminal() - self.protocol_failures()
    }
}

/// Ceiling-tier `ws_core` limits for the Autobahn fixture, shared by BOTH
/// modes so the server-role and client-role runs are configured identically.
///
/// Adapter WIRING only: the suite's selected families (1-7, 10) carry up to
/// 64 KiB messages and 51-fragment auto-fragmentation, which exceed the
/// corpus-tier per-connection defaults (64 frames / 64 KiB input). Every
/// value stays within the documented builder ceilings; what happens when a
/// limit trips is untouched core behavior.
#[must_use]
pub fn autobahn_config() -> ConnectionConfig {
    ConnectionConfig::builder()
        .max_frame_payload_bytes(1_048_576)
        .max_message_bytes(1_048_576)
        .max_buffered_bytes(1_048_576)
        .max_input_bytes(1_048_576)
        .max_frames(4096)
        .max_actions(1024)
        .event_queue_capacity(16_384)
        .command_queue_capacity(4096)
        .write_queue_capacity(4096)
        .build()
        .expect("ceiling-tier limits are valid by construction")
}

/// Runs ONE client connection against `target` to its terminal outcome.
fn run_one(
    fixture: &AgentFixture<'_>,
    target: &str,
    policy: &mut dyn EventPolicy,
) -> Result<ConnectionReport, SetupOutcome> {
    loopback_only(&fixture.address)?;
    if !valid_agent_name(fixture.agent) {
        return Err(SetupOutcome::InvalidAgentName);
    }
    let mut stream = TcpStream::connect(fixture.address)
        .map_err(|error| SetupOutcome::SocketFailed(format!("{:?}", error.kind())))?;
    let (sender, mut driver) = connection_driver(fixture.config.clone(), Role::Client);
    let mut report = empty_report();
    if let Err(failure) = driver.begin_client_handshake(target, fixture.host) {
        report.outcome = LoopOutcome::ProtocolFailure(failure);
        return Ok(report);
    }
    let handshake = drive_until_open(&mut driver, &mut stream, &fixture.bounds, &mut report);
    if !handshake.opened {
        return Ok(report);
    }
    drive_connection_from(
        &mut driver,
        &sender,
        &mut stream,
        &fixture.bounds,
        policy,
        &mut report,
        handshake.carryover,
    );
    Ok(report)
}

/// Asks the suite how many cases its config SELECTED.
///
/// # Errors
///
/// [`SetupOutcome`] when the address is non-loopback, the agent name is
/// unusable, or the connect fails.
pub fn fetch_case_count(fixture: &AgentFixture<'_>) -> Result<CaseCountOutcome, SetupOutcome> {
    let mut policy = ObserveOnly;
    let report = run_one(fixture, CASE_COUNT_TARGET, &mut policy)?;
    // A count of zero is NOT a usable count. The suite always selects at
    // least one case, so `"0"` means the suite refused, answered from an
    // empty configuration, or was not the suite at all. Accepting it would
    // let a sweep "succeed" having run nothing, which is exactly the
    // outcome the `Option` here exists to prevent — an explicit zero is no
    // better evidence than a missing or unparseable answer.
    let count = report
        .texts
        .first()
        .and_then(|text| text.trim().parse::<u32>().ok())
        .filter(|count| *count > 0);
    Ok(CaseCountOutcome { count, report })
}

/// Runs ONE case by its 1-based index, echoing every delivered message.
///
/// # Errors
///
/// [`SetupOutcome`] when the address is non-loopback, the agent name is
/// unusable, or the connect fails.
pub fn run_case(fixture: &AgentFixture<'_>, case: u32) -> Result<ConnectionReport, SetupOutcome> {
    if !valid_agent_name(fixture.agent) {
        return Err(SetupOutcome::InvalidAgentName);
    }
    let target = case_target(fixture.agent, case);
    let mut policy = EchoPolicy;
    run_one(fixture, &target, &mut policy)
}

/// Asks the suite to flush its reports for this agent.
///
/// # Errors
///
/// [`SetupOutcome`] when the address is non-loopback, the agent name is
/// unusable, or the connect fails.
pub fn update_reports(fixture: &AgentFixture<'_>) -> Result<ConnectionReport, SetupOutcome> {
    if !valid_agent_name(fixture.agent) {
        return Err(SetupOutcome::InvalidAgentName);
    }
    let target = reports_target(fixture.agent);
    let mut policy = ObserveOnly;
    run_one(fixture, &target, &mut policy)
}

/// Runs a whole fuzzingserver-mode sweep: read the suite's selected-case
/// count, run each case in `range` (all of them when `None`), then flush the
/// reports.
///
/// `range` is an inclusive pair of 1-based indices addressing the SAME
/// numbering the full sweep uses, so a rerun of a subset cannot renumber the
/// cases it re-executes.
///
/// # Errors
///
/// [`SetupOutcome`] from the first connection that could not be set up, or
/// [`SetupOutcome::NoCaseCount`] when the suite reported no usable count.
pub fn run_agent_sweep(
    fixture: &AgentFixture<'_>,
    range: Option<(u32, u32)>,
) -> Result<AgentSweep, SetupOutcome> {
    let counted = fetch_case_count(fixture)?;
    let Some(case_count) = counted.count else {
        return Err(SetupOutcome::NoCaseCount);
    };
    let cases = run_cases(fixture, case_count, range, &mut |_| {})?;
    let reports = update_reports(fixture)?;
    Ok(AgentSweep {
        case_count,
        cases,
        reports_updated: reports.outcome == LoopOutcome::Terminal,
    })
}

/// Runs the cases in `range` (all `1..=case_count` when `None`) against an
/// ALREADY-READ suite case count, reporting each as it completes.
///
/// Split out of [`run_agent_sweep`] so a caller that wants to observe the
/// `/getCaseCount` connection itself — the one place a suite-side refusal
/// shows up — can read that report before committing to a sweep, without
/// spending a second count connection.
///
/// # Errors
///
/// [`SetupOutcome`] from the first connection that could not be set up.
pub fn run_cases(
    fixture: &AgentFixture<'_>,
    case_count: u32,
    range: Option<(u32, u32)>,
    on_case: &mut dyn FnMut(&CaseOutcome),
) -> Result<Vec<CaseOutcome>, SetupOutcome> {
    let (first, last) = range.unwrap_or((1, case_count));
    // An empty or inverted range would leave the loop below untouched and
    // return an EMPTY, "successful" sweep. A sweep that executed no case is
    // not evidence, so refuse it at the boundary rather than reporting it.
    if first == 0 || last < first {
        return Err(SetupOutcome::EmptyCaseRange);
    }
    let mut cases = Vec::new();
    for case in first..=last {
        let report = run_case(fixture, case)?;
        let outcome = CaseOutcome { case, report };
        on_case(&outcome);
        cases.push(outcome);
    }
    Ok(cases)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_are_built_exactly_as_the_suite_expects() {
        assert_eq!(CASE_COUNT_TARGET, "/getCaseCount");
        assert_eq!(case_target("rust", 1), "/runCase?case=1&agent=rust");
        assert_eq!(case_target("rust", 247), "/runCase?case=247&agent=rust");
        assert_eq!(reports_target("rust"), "/updateReports?agent=rust");
    }

    #[test]
    fn agent_name_policy_refuses_query_forging_bytes() {
        assert!(valid_agent_name("ws-core.1.6.0+us019"));
        assert!(!valid_agent_name(""));
        assert!(!valid_agent_name("a&case=9"));
        assert!(!valid_agent_name("a b"));
        assert!(!valid_agent_name("a/b"));
    }

    #[test]
    fn autobahn_config_matches_the_ceiling_tier_limits_both_modes_share() {
        let config = autobahn_config();
        assert_eq!(config.max_frame_payload_bytes(), 1_048_576);
        assert_eq!(config.max_message_bytes(), 1_048_576);
        assert_eq!(config.max_frames(), 4096);
    }
}
