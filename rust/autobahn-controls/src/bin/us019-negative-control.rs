//! US-019 AC4 empty/stub NEGATIVE CONTROL.
//!
//! Implements no WebSocket behavior at all — no handshake, no framing, no
//! reply of any kind — in either Autobahn role. Every selected case must FAIL
//! against it; a passing case means the suite wiring is wrong, not the
//! control. Calibration instrument only: no story acceptance is claimed by
//! this binary.
//!
//! ```text
//! us019-negative-control serve  <loopback-addr> <sessions>
//! us019-negative-control client <loopback-addr> <host> <agent>
//! ```

#![forbid(unsafe_code)]

use std::env;
use std::process::exit;

fn main() {
    let arguments: Vec<String> = env::args().collect();
    exit(autobahn_controls::cli::run_negative_control(&arguments));
}
