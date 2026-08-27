//! # ws-core: the deterministic Sans-I/O WebSocket `ConnectionCore` contract
//!
//! US-009 of the verified Java-WebSocket -> Rust port: one deep,
//! deterministic Sans-I/O interface so that networking, runtime, proof, and
//! oracle adapters cannot duplicate protocol state. The library namespace is
//! `ws_core` — the canonical namespace fixed by the owner crate-naming
//! decision (us009_crate_naming = ws_core); the migration map's `ws_core::`
//! semantic ids resolve against this crate.
//!
//! ## The contract (US-009 AC2-AC4)
//!
//! [`connection::ConnectionCore`] accepts an immutable
//! [`config::ConnectionConfig`], a [`connection::Role`], transport bytes, and
//! [`connection::LocalCommand`]s, and returns ordered
//! [`connection::TransportWrite`]s, [`event::SemanticEvent`]s,
//! [`connection::ReadyState`], and [`error::TypedProtocolFailure`]s —
//! without opening sockets, reading clocks, or invoking callbacks (enforced
//! by construction and by the `sans_io_contract` source-scan test).
//! Configuration carries explicit handshake / frame / message /
//! buffered-byte / event / command-queue / write-queue limits with checked
//! conversions and deterministic defaults. One mutable owner plus the
//! bounded [`connection::CommandQueue`] channel are the only concurrency
//! boundary; the core is deterministic under arbitrary byte chunking and
//! surfaces backpressure as typed outputs rather than allocating
//! unboundedly.
//!
//! ## What this story does NOT claim
//!
//! No handshake, framing, message, control, or close-sequence behavior:
//! those are US-010..US-016. The skeleton refuses their inputs with the
//! non-oracle [`error::FailureCode::Unimplemented`] code, so a corpus
//! evaluation of this crate must fail (the protocol-stub gate of the design
//! draft; `empty_rust_target_fails` discipline). The observable vocabulary
//! is the java-oracle transcript vocabulary; where the skeleton does encode
//! behavior (state gates, limits, transport EOF), it mirrors the pinned
//! Java runtime through `internal/corpora/derive.go` exactly, with quirk-id
//! citations at every site.
//!
//! ## Fidelity stance
//!
//! JAVA_FAITHFUL_PLUS_SAFE (owner decision us009_normativity): mirror
//! shipped Java-WebSocket 1.6.0 observable behavior exactly — including its
//! RFC divergences — but refuse shipped unsafety: bounded memory, checked
//! arithmetic, exactly-once terminal delivery. Each such divergence is a
//! documented port-side strengthening, recorded in the behavior-delta
//! ledger once its baseline observations exist.
//!
//! ## Safety policy
//!
//! `#![forbid(unsafe_code)]` for every first-party crate (PRD quality
//! gate); this crate is dependency-free by design (guarded by
//! `scaffold_smoke`), so no dependency unsafe exists to inventory.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod close;
pub mod config;
pub mod connection;
pub mod control;
pub mod error;
pub mod event;
pub mod fragment;
pub mod framing;
pub mod handshake;
pub mod message;
mod queue;

pub use close::CloseDetail;
pub use config::{ConnectionConfig, ConnectionConfigBuilder};
pub use connection::{
    CommandQueue, CommandSender, ConnectionCore, ConnectionState, InitialState, Input,
    LocalCommand, ReadyState, Role, TransportWrite,
};
pub use error::{FailureCode, TypedProtocolFailure};
pub use event::{Counts, SemanticEvent, SemanticEventKind};

// NOTE: the toolchain-pin guard lives in tests/scaffold_smoke.rs (an
// integration test) so the library source itself stays free of filesystem
// access — the sans_io_contract scan covers everything under src/.
