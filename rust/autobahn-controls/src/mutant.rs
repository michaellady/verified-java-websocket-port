//! The PLANTED PROTOCOL MUTANTS (US-019 AC4).
//!
//! Every mutant here runs the REAL protocol: `ws_core` behind `ws_driver`,
//! driven by the shipped `ws_testee` bounded I/O loop, with the shipped
//! [`crate::autobahn_config`] limits. Nothing is re-implemented, and no
//! protocol decision is made in this module — that is deliberate. A mutant
//! built on its own protocol code would discriminate on the re-implementation
//! rather than on its deviation, and the calibration would prove nothing.
//!
//! Each mutant therefore differs from the shipped adapters at exactly ONE
//! seam:
//!
//! | mutant | seam | deviation |
//! |---|---|---|
//! | [`Mutant::NoEcho`] | adapter echo policy | never re-sends a delivered message |
//! | [`Mutant::OpcodeSwap`] | adapter echo policy | re-sends text as binary and binary as text |
//! | [`Mutant::PayloadTruncate`] | adapter echo policy | drops the final byte of every non-empty echo |
//! | [`Mutant::PongSuppressed`] | driver auto-response policy | never answers an inbound ping |
//!
//! The first three are message-level ADAPTER policy — the same layer the
//! shipped [`ws_testee::EchoPolicy`] occupies, which runs outside the core
//! and may only enqueue commands. The fourth replaces the shipped-Java
//! listener default [`AutoResponsePolicy::PongInboundPing`] with
//! [`AutoResponsePolicy::Disabled`] and leaves the echo policy alone, so the
//! two axes (echo, ping reply) are discriminated independently.
//!
//! ## Both roles, one deviation
//!
//! The server path ([`run_mutant_server_sessions`]) is the fuzzingclient-mode
//! testee and the agent path ([`run_mutant_cases`]) is the fuzzingserver-mode
//! testee. Both build their policy from the SAME [`MutantPolicy`], so a
//! control cannot carry one deviation in one mode and a different one in the
//! other.
//!
//! ## Conformance is judged by the suite, never here
//!
//! A case that ends in a typed [`ws_testee::LoopOutcome::ProtocolFailure`] is
//! frequently the CORRECT outcome (a large share of the selected cases
//! deliberately provoke one), so nothing in this module scores conformance.
//! These functions report what happened operationally; the verdict is
//! wstest's report.

use std::net::{SocketAddr, TcpListener, TcpStream};

use ws_core::{CommandSender, ConnectionConfig, LocalCommand, Role, SemanticEvent};
use ws_driver::{AutoResponsePolicy, connection_driver_with_policy};
use ws_testee::io_loop::{
    ConnectionReport, EchoPolicy, EventPolicy, IoBounds, LoopOutcome, ObserveOnly,
    drive_connection_from, drive_until_open, empty_report,
};
use ws_testee::{
    CASE_COUNT_TARGET, CaseCountOutcome, CaseOutcome, SetupOutcome, case_target, loopback_only,
    reports_target, valid_agent_name,
};

/// Which planted protocol deviation a control carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mutant {
    /// The echo obligation is removed.
    NoEcho,
    /// The echo comes back on the wrong opcode.
    OpcodeSwap,
    /// The echoed payload is short by one byte.
    PayloadTruncate,
    /// Inbound pings are never answered.
    PongSuppressed,
}

impl Mutant {
    /// Every shipped mutant, in `manifest.json` order.
    pub const ALL: [Mutant; 4] = [
        Mutant::NoEcho,
        Mutant::OpcodeSwap,
        Mutant::PayloadTruncate,
        Mutant::PongSuppressed,
    ];

    /// Stable manifest identifier.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Mutant::NoEcho => "us019-mutant-no-echo",
            Mutant::OpcodeSwap => "us019-mutant-opcode-swap",
            Mutant::PayloadTruncate => "us019-mutant-payload-truncate",
            Mutant::PongSuppressed => "us019-mutant-pong-suppressed",
        }
    }

    /// The binary that carries this mutant. Identical to [`Mutant::id`] by
    /// construction, and asserted against `Cargo.toml` and `manifest.json`
    /// by the manifest test, so a rename cannot silently point the
    /// calibration at the wrong artifact.
    #[must_use]
    pub fn binary(self) -> &'static str {
        self.id()
    }

    /// One-sentence statement of the single planted deviation.
    #[must_use]
    pub fn deviation(self) -> &'static str {
        match self {
            Mutant::NoEcho => "delivered messages are never re-sent",
            Mutant::OpcodeSwap => "text is echoed as binary and binary as text",
            Mutant::PayloadTruncate => {
                "the final byte of every non-empty echoed payload is dropped"
            }
            Mutant::PongSuppressed => "inbound pings are never answered",
        }
    }

    /// The driver's automatic ping-reply policy for this mutant.
    ///
    /// Only [`Mutant::PongSuppressed`] deviates here; every other mutant
    /// carries the shipped-Java listener default, so its ping/pong behavior
    /// is indistinguishable from the real port's.
    #[must_use]
    pub fn auto_response(self) -> AutoResponsePolicy {
        match self {
            Mutant::NoEcho | Mutant::OpcodeSwap | Mutant::PayloadTruncate => {
                AutoResponsePolicy::PongInboundPing
            }
            Mutant::PongSuppressed => AutoResponsePolicy::Disabled,
        }
    }
}

/// The adapter-side message policy carrying the planted deviation.
///
/// Occupies exactly the seam [`ws_testee::EchoPolicy`] occupies: it runs
/// OUTSIDE the core over drained semantic events and may only enqueue
/// commands through the bounded sender. It never touches protocol state, so
/// no mutant here can deviate anywhere except in what it chooses to send.
#[derive(Debug, Clone, Copy)]
pub struct MutantPolicy {
    mutant: Mutant,
}

impl MutantPolicy {
    /// Builds the policy for one planted deviation.
    #[must_use]
    pub fn new(mutant: Mutant) -> MutantPolicy {
        MutantPolicy { mutant }
    }

    /// Which deviation this policy carries.
    #[must_use]
    pub fn mutant(&self) -> Mutant {
        self.mutant
    }
}

impl EventPolicy for MutantPolicy {
    fn on_event(&mut self, event: &SemanticEvent, sender: &CommandSender) {
        use ws_core::SemanticEventKind as Kind;
        match self.mutant {
            // DEVIATION: the echo obligation is removed. Delegating to the
            // shipped observer keeps the "no message policy" case honest —
            // the mutant does not merely forget to echo, it installs the
            // pure-observer policy in the echo policy's place.
            Mutant::NoEcho => ObserveOnly.on_event(event, sender),
            // DEVIATION: the payload survives, the opcode does not. A binary
            // payload that is not valid UTF-8 is lossily transcoded on the
            // way into the text frame; that is a disclosed consequence of
            // the swap (a text frame cannot carry arbitrary bytes), not a
            // second deviation.
            Mutant::OpcodeSwap => match &event.kind {
                Kind::Text { text } => {
                    let _ = sender.try_send(LocalCommand::SendBinary {
                        data: text.clone().into_bytes(),
                    });
                }
                Kind::Binary { data } => {
                    let _ = sender.try_send(LocalCommand::SendText {
                        text: String::from_utf8_lossy(data).into_owned(),
                    });
                }
                _ => {}
            },
            // DEVIATION: the opcode survives, the last byte does not. An
            // empty payload has no final byte and is echoed unchanged. A
            // text payload whose last byte was part of a multi-byte
            // character is lossily re-encoded; that is a disclosed
            // consequence of dropping the byte, not a second deviation.
            Mutant::PayloadTruncate => match &event.kind {
                Kind::Text { text } => {
                    let bytes = text.as_bytes();
                    let kept = &bytes[..bytes.len().saturating_sub(1)];
                    let _ = sender.try_send(LocalCommand::SendText {
                        text: String::from_utf8_lossy(kept).into_owned(),
                    });
                }
                Kind::Binary { data } => {
                    let kept = &data[..data.len().saturating_sub(1)];
                    let _ = sender.try_send(LocalCommand::SendBinary {
                        data: kept.to_vec(),
                    });
                }
                _ => {}
            },
            // NO deviation at this seam: this mutant runs the shipped echo
            // policy verbatim. Its single deviation lives one layer down, in
            // the driver's auto-response policy (see
            // [`Mutant::auto_response`]).
            Mutant::PongSuppressed => EchoPolicy.on_event(event, sender),
        }
    }
}

/// One mutant server run's parameters (fuzzingclient mode: the suite dials
/// in, the mutant is the testee SERVER).
#[derive(Debug, Clone)]
pub struct MutantServerFixture {
    /// The planted deviation.
    pub mutant: Mutant,
    /// Connection configuration (protocol limits live in the core).
    pub config: ConnectionConfig,
    /// Bounded I/O parameters.
    pub bounds: IoBounds,
}

/// One mutant agent run's parameters (fuzzingserver mode: the suite listens,
/// the mutant is the testee CLIENT agent).
#[derive(Debug, Clone)]
pub struct MutantAgentFixture<'a> {
    /// The planted deviation.
    pub mutant: Mutant,
    /// The suite's listening address, reached over loopback.
    pub address: SocketAddr,
    /// Host header value for the upgrade request.
    pub host: &'a str,
    /// The agent name the suite files results under. Constrained by
    /// [`ws_testee::valid_agent_name`] so it cannot forge query parameters.
    pub agent: &'a str,
    /// Connection configuration (protocol limits live in the core).
    pub config: ConnectionConfig,
    /// Bounded I/O parameters.
    pub bounds: IoBounds,
}

/// Serves `sessions` mutant connections in sequence on ONE bound listener.
///
/// The listener stays bound between sessions with no accept gap: the fuzzer
/// opens one fresh connection per case, strictly sequentially.
///
/// # Errors
///
/// The first [`SetupOutcome`] (accept failure / non-loopback peer) ends the
/// run early; sessions already served have been reported.
pub fn run_mutant_server_sessions(
    listener: &TcpListener,
    fixture: &MutantServerFixture,
    sessions: u64,
    on_report: &mut dyn FnMut(u64, &ConnectionReport),
) -> Result<(), SetupOutcome> {
    for index in 1..=sessions {
        let report = run_mutant_server_once(listener, fixture)?;
        on_report(index, &report);
    }
    Ok(())
}

/// Accepts and runs ONE loopback connection with the planted deviation in
/// force.
///
/// # Errors
///
/// [`SetupOutcome::SocketFailed`] when the accept fails, or
/// [`SetupOutcome::NonLoopback`] for a non-loopback peer; every post-setup
/// condition is reported inside the [`ConnectionReport`].
pub fn run_mutant_server_once(
    listener: &TcpListener,
    fixture: &MutantServerFixture,
) -> Result<ConnectionReport, SetupOutcome> {
    let (mut stream, peer) = listener
        .accept()
        .map_err(|error| SetupOutcome::SocketFailed(format!("{:?}", error.kind())))?;
    if !peer.ip().is_loopback() {
        return Err(SetupOutcome::NonLoopback);
    }
    let (sender, mut driver) = connection_driver_with_policy(
        fixture.config.clone(),
        Role::Server,
        fixture.mutant.auto_response(),
    );
    let mut report = empty_report();
    let handshake = drive_until_open(&mut driver, &mut stream, &fixture.bounds, &mut report);
    if !handshake.opened {
        return Ok(report);
    }
    let mut policy = MutantPolicy::new(fixture.mutant);
    drive_connection_from(
        &mut driver,
        &sender,
        &mut stream,
        &fixture.bounds,
        Role::Server,
        &mut policy,
        &mut report,
        handshake.carryover,
    );
    Ok(report)
}

/// Runs ONE agent connection against `target` to its terminal outcome.
fn run_one(
    fixture: &MutantAgentFixture<'_>,
    target: &str,
    policy: &mut dyn EventPolicy,
) -> Result<ConnectionReport, SetupOutcome> {
    let mut stream = TcpStream::connect(fixture.address)
        .map_err(|error| SetupOutcome::SocketFailed(format!("{:?}", error.kind())))?;
    let (sender, mut driver) = connection_driver_with_policy(
        fixture.config.clone(),
        Role::Client,
        fixture.mutant.auto_response(),
    );
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
        Role::Client,
        policy,
        &mut report,
        handshake.carryover,
    );
    Ok(report)
}

/// Refuses a fixture that cannot address the suite safely, BEFORE any
/// connect: a non-loopback target, or an agent name that could forge a query
/// parameter in the request target.
fn check_addressing(fixture: &MutantAgentFixture<'_>) -> Result<(), SetupOutcome> {
    loopback_only(&fixture.address)?;
    if valid_agent_name(fixture.agent) {
        Ok(())
    } else {
        Err(SetupOutcome::InvalidAgentName)
    }
}

/// Asks the suite how many cases its config SELECTED.
///
/// The count is read, never assumed, and an unparseable answer stays `None`
/// rather than becoming zero — a sweep that tested nothing must not look
/// like a completed run.
///
/// # Errors
///
/// [`SetupOutcome`] when the address is non-loopback, the agent name is
/// unusable, or the connect fails.
pub fn mutant_fetch_case_count(
    fixture: &MutantAgentFixture<'_>,
) -> Result<CaseCountOutcome, SetupOutcome> {
    check_addressing(fixture)?;
    // The count connection carries no message policy: a mutant that
    // deviated here would corrupt the case count itself and make the sweep
    // unattributable to the planted deviation.
    let mut policy = ObserveOnly;
    let report = run_one(fixture, CASE_COUNT_TARGET, &mut policy)?;
    let count = report
        .texts
        .first()
        .and_then(|text| text.trim().parse::<u32>().ok());
    Ok(CaseCountOutcome { count, report })
}

/// Runs ONE case by its 1-based index with the planted deviation in force.
///
/// # Errors
///
/// [`SetupOutcome`] when the address is non-loopback, the agent name is
/// unusable, or the connect fails.
pub fn run_mutant_case(
    fixture: &MutantAgentFixture<'_>,
    case: u32,
) -> Result<ConnectionReport, SetupOutcome> {
    check_addressing(fixture)?;
    let target = case_target(fixture.agent, case);
    let mut policy = MutantPolicy::new(fixture.mutant);
    run_one(fixture, &target, &mut policy)
}

/// Asks the suite to flush its reports for this agent.
///
/// # Errors
///
/// [`SetupOutcome`] when the address is non-loopback, the agent name is
/// unusable, or the connect fails.
pub fn mutant_update_reports(
    fixture: &MutantAgentFixture<'_>,
) -> Result<ConnectionReport, SetupOutcome> {
    check_addressing(fixture)?;
    let mut policy = ObserveOnly;
    run_one(fixture, &reports_target(fixture.agent), &mut policy)
}

/// Runs cases `1..=selected` with the planted deviation in force, reporting
/// each as it completes.
///
/// # Errors
///
/// [`SetupOutcome`] from the first connection that could not be set up.
pub fn run_mutant_cases(
    fixture: &MutantAgentFixture<'_>,
    selected: u32,
    on_case: &mut dyn FnMut(&CaseOutcome),
) -> Result<Vec<CaseOutcome>, SetupOutcome> {
    let mut cases = Vec::new();
    for case in 1..=selected {
        let report = run_mutant_case(fixture, case)?;
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
    fn exactly_one_mutant_deviates_in_the_drivers_auto_response_policy() {
        let suppressed: Vec<Mutant> = Mutant::ALL
            .into_iter()
            .filter(|mutant| mutant.auto_response() == AutoResponsePolicy::Disabled)
            .collect();
        assert_eq!(suppressed, vec![Mutant::PongSuppressed]);
    }

    #[test]
    fn every_mutant_has_a_distinct_id_that_is_also_its_binary_name() {
        let mut ids: Vec<&str> = Mutant::ALL.iter().map(|mutant| mutant.id()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), Mutant::ALL.len(), "ids must be distinct");
        for mutant in Mutant::ALL {
            assert_eq!(mutant.binary(), mutant.id());
            assert!(!mutant.deviation().is_empty());
        }
    }

    #[test]
    fn the_policy_reports_the_deviation_it_carries() {
        for mutant in Mutant::ALL {
            assert_eq!(MutantPolicy::new(mutant).mutant(), mutant);
        }
    }
}
