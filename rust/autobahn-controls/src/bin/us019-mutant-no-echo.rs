//! US-019 AC4 planted mutant: the echo obligation is removed.
//!
//! Real `ws_core` protocol, real opening handshake, real close lifecycle —
//! but delivered text and binary messages are never re-sent. Exactly one
//! deviation from the shipped `ws-testee` adapters; see `manifest.json`.
//!
//! ```text
//! us019-mutant-no-echo serve  <loopback-addr> <sessions>
//! us019-mutant-no-echo client <loopback-addr> <host> <agent>
//! ```

#![forbid(unsafe_code)]

use std::env;
use std::process::exit;

use autobahn_controls::mutant::Mutant;

fn main() {
    let arguments: Vec<String> = env::args().collect();
    exit(autobahn_controls::cli::run_mutant(
        Mutant::NoEcho,
        &arguments,
    ));
}
