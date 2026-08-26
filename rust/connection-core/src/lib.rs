//! # connection-core (UNIMPLEMENTED scaffold)
//!
//! Placeholder for the deterministic Sans-I/O WebSocket `ConnectionCore`
//! described by US-009 of the verified-java-websocket-port PRD. This crate is
//! **enabling work only**: it establishes the pinned, gated, safe-Rust
//! workspace so US-009 can start the moment its dependencies unblock. It
//! contains **no protocol behavior** and claims **no story acceptance**.
//!
//! ## Intended shape (informative, not implemented)
//!
//! The eventual core accepts an immutable configuration, a role, transport
//! bytes, and local commands, and returns ordered transport writes, semantic
//! events, connection state, and typed protocol failures -- without opening
//! sockets, reading clocks, or invoking callbacks. None of that exists yet.
//! Every module below is an empty, documented placeholder pending
//! US-009..US-016.
//!
//! ## Safety policy
//!
//! `#![forbid(unsafe_code)]` is non-negotiable for every first-party crate in
//! this workspace (PRD quality gate). Dependency unsafe, when dependencies
//! ever exist, is enumerated and reviewed separately; today this crate is
//! dependency-free by design.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod close;
pub mod connection;
pub mod control;
pub mod framing;
pub mod handshake;

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    /// The workspace toolchain pin must stay exactly on the intake-qualified
    /// compiler (evidence/intake/toolchain-pins.json). This guards against a
    /// silent channel float breaking the reproducibility assumption baked
    /// into the quality gates.
    #[test]
    fn toolchain_pin_matches_intake_qualified_compiler() {
        let pin_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../rust-toolchain.toml");
        let pin = fs::read_to_string(&pin_path)
            .expect("rust-toolchain.toml must exist at the workspace root");
        assert!(
            pin.contains("channel = \"1.95.0\""),
            "workspace toolchain must stay pinned to 1.95.0 per \
             evidence/intake/toolchain-pins.json; found:\n{pin}"
        );
    }
}
