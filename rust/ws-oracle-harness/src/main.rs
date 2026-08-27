//! `ws-oracle-harness` binary: the JSONL oracle-candidate for `ws_core`.
//!
//! Pipeline (identical to the java-oracle pipeline):
//! `corporactl oracle-requests --tier … | ws-oracle-harness |
//! corporactl evaluate --tier … --transcript -`.
//!
//! Standard output carries protocol records only; bounded fatal diagnostics
//! go to standard error, mirroring `OracleMain`.

// The bin target is its own crate root, so the PRD's safe-Rust gate must be
// declared here independently of src/lib.rs.
#![forbid(unsafe_code)]

use std::io::Write;

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.iter().any(|a| a == "--identify") {
        println!("{}", ws_oracle_harness::identify());
        return;
    }
    if !arguments.is_empty() {
        diagnostic("ws-oracle-harness accepts only --identify");
        std::process::exit(64);
    }
    // Fail closed if the harness cannot report an honest runtime identity —
    // never fabricate one (mirrors the oracle's startup runtime pinning).
    let runtime = match ws_oracle_harness::response::RuntimeIdentity::from_current_exe() {
        Ok(runtime) => runtime,
        Err(detail) => {
            diagnostic(&format!("ws-oracle-harness startup denied: {detail}"));
            std::process::exit(78);
        }
    };
    let mut core = ws_oracle_harness::core_adapter::active_core();
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    if let Err(error) =
        ws_oracle_harness::run_lines(stdin.lock(), stdout.lock(), &mut core, &runtime)
    {
        diagnostic(&format!("ws-oracle-harness I/O failure: {error}"));
        std::process::exit(74);
    }
}

/// Bounded stderr diagnostic (mirrors `OracleMain.diagnostic`): one line,
/// newlines stripped, clipped to 512 bytes.
fn diagnostic(message: &str) {
    let cleaned: String = message
        .chars()
        .map(|c| if c == '\r' || c == '\n' { ' ' } else { c })
        .collect();
    let mut end = cleaned.len().min(512);
    while !cleaned.is_char_boundary(end) {
        end -= 1;
    }
    let mut stderr = std::io::stderr();
    let _ = writeln!(stderr, "{}", &cleaned[..end]);
    let _ = stderr.flush();
}
