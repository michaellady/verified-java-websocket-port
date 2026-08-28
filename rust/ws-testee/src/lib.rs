//! # ws-testee: thin blocking loopback TCP adapters for `ws_core` (US-018)
//!
//! The adapters own ONLY socket connect/accept, partial read/write with
//! progress reporting, bounded I/O buffers, explicit timeout/EOF handling,
//! and report routing. Every protocol decision — handshake, framing,
//! limits, control, close — stays in [`ws_core::ConnectionCore`], driven
//! through the single-owner [`ws_driver::ConnectionDriver`]. Loopback only:
//! these are verification fixtures and cutover-rehearsal adapters, never a
//! general networking API (no TLS, proxy, reconnect, async runtime,
//! extension, or compression).
//!
//! ## Borrow attribution (owner strategy: borrow with attribution)
//!
//! Adapted from the Codex-plane US-018 `websocket-testee` (codex-import
//! f1d023d): the crate split (client/server fixtures + one bounded blocking
//! io loop + a tiny CLI), the loopback-only refusal, the normalized setup /
//! socket-error vocabulary, and the single-connection-per-invocation
//! discipline are their design. **Adaptation to this plane:** the loop
//! drives `ws_driver`'s poll contract (their driver API differs), the echo
//! policy is expressed as adapter-side command routing through the
//! incumbent `ws_core::CommandSender`, and every close/EOF observable is
//! the Java-faithful `ws_core` vocabulary (their RFC-strict close/EOF
//! failure classes are not adopted — see the US-016 batch-C corrections).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod agent;
pub mod client;
pub mod io_loop;
pub mod server;

pub use agent::{
    AgentFixture, AgentSweep, CASE_COUNT_TARGET, CaseCountOutcome, CaseOutcome, autobahn_config,
    case_target, fetch_case_count, reports_target, run_agent_sweep, run_case, run_cases,
    update_reports, valid_agent_name,
};
pub use client::{ClientFixture, run_client_once};
pub use io_loop::{ConnectionReport, EchoPolicy, HandshakeOutcome, IoBounds, LoopOutcome};
pub use server::{ServerFixture, run_server_once, run_server_sessions};

use std::net::SocketAddr;

/// Why an adapter refused to start (normalized, deterministic vocabulary).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupOutcome {
    /// The requested address is not a loopback address (the adapters are
    /// loopback-only by contract).
    NonLoopback,
    /// The socket could not be bound/connected (normalized kind name).
    SocketFailed(String),
    /// The Autobahn agent name could not be placed in a request target
    /// safely (see [`agent::valid_agent_name`]).
    InvalidAgentName,
    /// The Autobahn suite reported no parseable selected-case count on
    /// `/getCaseCount`. Never coerced to zero: a zero-case sweep would
    /// report success having executed nothing.
    NoCaseCount,
    /// The requested case range selects no cases at all (an empty or
    /// inverted range). A sweep that runs zero cases cannot evidence
    /// anything, so it is refused rather than reported as a success.
    EmptyCaseRange,
}

/// Guard: the adapters serve loopback addresses only (US-018 AC2/AC5).
///
/// # Errors
///
/// [`SetupOutcome::NonLoopback`] for any non-loopback address.
pub fn loopback_only(address: &SocketAddr) -> Result<(), SetupOutcome> {
    if address.ip().is_loopback() {
        Ok(())
    } else {
        Err(SetupOutcome::NonLoopback)
    }
}
