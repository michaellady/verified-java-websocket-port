//! US-019 AC4 planted mutant: the echoed payload is short by one byte.
//!
//! Real `ws_core` protocol, real opening handshake, real close lifecycle —
//! but the final byte of every non-empty echoed payload is dropped (empty
//! payloads are echoed unchanged). Exactly one deviation from the shipped
//! `ws-testee` adapters; see `manifest.json`.
//!
//! ```text
//! us019-mutant-payload-truncate serve  <loopback-addr> <sessions>
//! us019-mutant-payload-truncate client <loopback-addr> <host> <agent>
//! ```

#![forbid(unsafe_code)]

use std::env;
use std::process::exit;

use autobahn_controls::mutant::Mutant;

fn main() {
    let arguments: Vec<String> = env::args().collect();
    exit(autobahn_controls::cli::run_mutant(
        Mutant::PayloadTruncate,
        &arguments,
    ));
}
