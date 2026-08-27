//! The single `ws_core` coupling seam (MERGE-TIME WIRING POINT).
//!
//! Everything the harness knows about the Rust ConnectionCore lives in this
//! module, so lane A's real API (built in parallel on another branch) can be
//! connected in one place without touching the protocol machinery. The
//! [`CandidateCore`] trait is shaped on the US-009 ConnectionCore contract
//! draft (§1.4/§1.5): the driver constructs a core via the
//! `new_in_state(config, role, initial_state)` seam, maps validated steps to
//! `Input::TransportBytes` / `Input::Command` / `Input::TransportEof`, drains
//! `next_write` / `next_event` eagerly, and snapshots `state()` / `counts()` /
//! `close_detail()` — all of which project onto [`crate::observe`] types.
//!
//! ## This round: truthfully unwired
//!
//! The `ws_core` crate on this branch is still the committed UNIMPLEMENTED
//! scaffold (no ConnectionCore API exists to call), so the active
//! implementation is [`UnwiredCore`]: it answers every scenario with a typed
//! `CORE_NOT_WIRED` failure (zero counts, `final_state == initial_state`),
//! mirroring how the US-005 candidate-stub declares inertness — but honestly
//! labeled as awaiting the core's API landing. **No behavior is fabricated.**
//! The wiring commit that replaces [`active_core`]'s body with a real
//! `ws_core`-backed driver happens at merge time by the integrating parent,
//! against lane A's landed API.

use crate::observe::{ConnectionState, Counts, Observations};
use crate::request::OracleRequest;

/// One scenario-scoped typed failure, mirroring the oracle's stable error
/// vocabulary (`JAVA_INVALID_DATA` + close code, `STATE_VIOLATION`, the
/// limit codes, …) plus the harness's own truthful `CORE_NOT_WIRED`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioFailure {
    /// Stable typed code (`^[A-Z0-9_]+$`).
    pub code: String,
    /// Close code, present exactly when the oracle vocabulary carries one.
    pub close_code: Option<i64>,
    /// Bounded human-readable detail.
    pub detail: String,
}

/// The outcome of driving one validated scenario through the core.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScenarioOutcome {
    /// Every step executed; the full observation surface is reported.
    Completed(Observations),
    /// A typed failure ended the scenario; counts and final state are
    /// retained (the oracle's partial-execution contract).
    Failed {
        /// The typed failure that ended the scenario.
        failure: ScenarioFailure,
        /// Counters at the failure point.
        counts: Counts,
        /// Connection state at the failure point.
        final_state: ConnectionState,
    },
    /// The core API is not wired yet; the harness must report this
    /// truthfully instead of fabricating behavior.
    NotWired {
        /// Honest explanation serialized into the failure detail.
        detail: String,
    },
}

/// The narrow surface the harness needs from a Rust oracle candidate.
pub trait CandidateCore {
    /// Drives one validated scenario and reports its observable outcome.
    fn run_scenario(&mut self, request: &OracleRequest) -> ScenarioOutcome;
}

/// Truthful placeholder implementation used until lane A's `ws_core`
/// ConnectionCore API lands: every scenario is `CORE_NOT_WIRED`.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnwiredCore;

/// The honest unwired detail, kept stable so transcripts are byte-identical
/// across reruns.
pub const UNWIRED_DETAIL: &str = "ws_core ConnectionCore API not yet landed \
     (US-009 lane A); harness truthfully reports no behavior instead of \
     fabricating it";

impl CandidateCore for UnwiredCore {
    fn run_scenario(&mut self, _request: &OracleRequest) -> ScenarioOutcome {
        ScenarioOutcome::NotWired {
            detail: UNWIRED_DETAIL.to_string(),
        }
    }
}

/// Returns the active core implementation.
///
/// MERGE-TIME WIRING POINT: the integrating parent replaces this body with a
/// `ws_core`-backed driver once lane A's ConnectionCore API lands. Until
/// then the truthfully-labeled [`UnwiredCore`] answers, so this crate builds
/// and runs standalone on this branch.
pub fn active_core() -> impl CandidateCore {
    UnwiredCore
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::parse_request;

    const PUB_0000: &str = concat!(
        "{\"initial_state\":\"open\",\"limits\":{\"max_actions\":64,",
        "\"max_buffered_bytes\":65536,\"max_frames\":64,\"max_input_bytes\":65536,",
        "\"max_output_bytes\":4194304},\"protocol\":\"java-websocket-oracle\",",
        "\"request_digest\":\"sha256:332b88dac25b405b3d9ce3b6a82b4ec8821296a9a4",
        "92aa70a26ce867d817e0c9\",\"request_id\":\"us005.pub.0000\",",
        "\"role\":\"client\",\"steps\":[{\"action\":\"send_close\",\"code\":999,",
        "\"kind\":\"action\",\"reason\":\"bad\"}],\"version\":\"1.0.0\"}"
    );

    #[test]
    fn unwired_core_never_claims_behavior() {
        let request = parse_request(PUB_0000).unwrap();
        let outcome = UnwiredCore.run_scenario(&request);
        assert_eq!(
            outcome,
            ScenarioOutcome::NotWired {
                detail: UNWIRED_DETAIL.to_string()
            }
        );
    }
}
