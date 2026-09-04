//! # autobahn-controls: US-019 AC4 discrimination instruments
//!
//! Verification instruments for the US-019 AC4 Autobahn calibration — an
//! empty/stub Rust **negative control** that implements NO WebSocket
//! behavior, and four **planted protocol mutants** with documented
//! deliberate deviations. Pointing the pinned Autobahn suite at these
//! artifacts must produce FAILURES where the same suite produces passes
//! against the real port; that contrast is what makes the case manifest's
//! pass claim mean something. **These are not port crates and no story
//! acceptance, production, or publication claim is made by them.**
//!
//! ## What each control is
//!
//! - [`inert`] — the negative control. Raw [`std::net::TcpStream`] only: it
//!   accepts (or opens) the connection, reads whatever arrives, writes
//!   nothing, and closes without ever completing an opening handshake. It
//!   does not use `ws_core` for protocol at all, because there is no
//!   protocol to speak. EVERY selected case must fail against it.
//! - [`mutant`] — four planted mutants that run the REAL `ws_core` protocol
//!   through the REAL `ws_driver`, over the REAL `ws_testee` bounded I/O
//!   loop, with the same [`autobahn_config`] limits the shipped adapters
//!   use. Each differs from the shipped adapters in exactly ONE documented
//!   way, so a scoring difference is attributable to the planted deviation
//!   and not to harness drift.
//!
//! Every control serves BOTH Autobahn roles through the shared [`cli`]:
//! `serve` is the fuzzingclient-mode SERVER and `client` is the
//! fuzzingserver-mode CLIENT agent, so one artifact is scorable in either
//! direction.
//!
//! ## Dependency stance
//!
//! Like `ws-core` and `candidate-stub`, this crate is dependency-free by
//! design: the only edges are the in-workspace path crates it is calibrated
//! against (`ws-core`, `ws-driver`, `ws-testee`). The mutants MUST reuse the
//! shipped protocol and the shipped I/O loop — a re-implementation would
//! make the deviation unattributable — and the negative control needs no
//! protocol code at all. Adding a non-path dependency would break the
//! US-009 AC1 zero-dependency audit surface.
//!
//! ## Honesty stance
//!
//! `manifest.json` states, per control, the single deviation and what
//! Autobahn must SHOW. Those statements are expectations, not observations:
//! nothing here claims a measured case result, and the in-crate loopback
//! tests are unit-scale discrimination proofs that do not substitute for the
//! live suite run they exist to calibrate.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod cli;
pub mod inert;
pub mod mutant;

pub use inert::{InertBounds, InertSession};
pub use mutant::{Mutant, MutantAgentFixture, MutantPolicy, MutantServerFixture};

/// The ceiling-tier `ws_core` limits the shipped Autobahn adapters use,
/// re-exported so every control is configured IDENTICALLY to the real port.
///
/// A control that differed in its limits would discriminate on the limits
/// rather than on its planted deviation, which is exactly the confound this
/// calibration exists to rule out.
pub use ws_testee::autobahn_config;

/// Stable manifest identifier of the empty/stub negative control.
pub const NEGATIVE_CONTROL_ID: &str = "us019-negative-control";

/// Binary name of the empty/stub negative control.
pub const NEGATIVE_CONTROL_BINARY: &str = "us019-negative-control";
