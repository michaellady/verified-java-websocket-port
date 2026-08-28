//! US-019 AC4 planted mutant: inbound pings are never answered.
//!
//! Real `ws_core` protocol and the shipped echo policy, unmodified — but the
//! driver is built with `ws_driver::AutoResponsePolicy::Disabled` in place of
//! the shipped-Java listener default, so no pong is ever composed. Exactly
//! one deviation from the shipped `ws-testee` adapters; see `manifest.json`.
//!
//! ```text
//! us019-mutant-pong-suppressed serve  <loopback-addr> <sessions>
//! us019-mutant-pong-suppressed client <loopback-addr> <host> <agent>
//! ```

#![forbid(unsafe_code)]

use std::env;
use std::process::exit;

use autobahn_controls::mutant::Mutant;

fn main() {
    let arguments: Vec<String> = env::args().collect();
    exit(autobahn_controls::cli::run_mutant(
        Mutant::PongSuppressed,
        &arguments,
    ));
}
