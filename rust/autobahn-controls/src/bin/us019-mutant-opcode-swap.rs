//! US-019 AC4 planted mutant: the echo comes back on the wrong opcode.
//!
//! Real `ws_core` protocol, real opening handshake, real close lifecycle —
//! but text messages are re-sent as BINARY and binary messages as TEXT.
//! Exactly one deviation from the shipped `ws-testee` adapters; see
//! `manifest.json`.
//!
//! ```text
//! us019-mutant-opcode-swap serve  <loopback-addr> <sessions>
//! us019-mutant-opcode-swap client <loopback-addr> <host> <agent>
//! ```

#![forbid(unsafe_code)]

use std::env;
use std::process::exit;

use autobahn_controls::mutant::Mutant;

fn main() {
    let arguments: Vec<String> = env::args().collect();
    exit(autobahn_controls::cli::run_mutant(
        Mutant::OpcodeSwap,
        &arguments,
    ));
}
