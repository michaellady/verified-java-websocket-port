//! Sans-I/O contract guards (US-009 AC2, mechanical layer).
//!
//! The `ConnectionCore` contract forbids sockets, clocks, callbacks, threads,
//! filesystem access, and process spawning inside the core crate. The compiler
//! cannot express "no I/O" directly, so this test is the mechanical tripwire
//! from the US-009 design draft (section 6, AC2 step 2): it scans every
//! library source file for the std facilities that would smuggle I/O or time
//! into the core. It is a tripwire, not a proof: it strips `//` comments
//! crudely and matches substrings, which is exactly enough to force any
//! attempt to use these modules through a loud, reviewed change to this test.

use std::fs;
use std::path::{Path, PathBuf};

/// std modules that must never appear in the core library source.
/// `std::net` (sockets), `std::time` (clocks), `std::thread` (threads),
/// `std::fs` / `std::io` (file and stream I/O), `std::process` (subprocesses).
const FORBIDDEN: [&str; 6] = [
    "std::net",
    "std::time",
    "std::thread",
    "std::fs",
    "std::io",
    "std::process",
];

fn src_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("src directory must be readable") {
        let path = entry.expect("directory entry must be readable").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Strip the portion of a line at and after the first `//`. This removes
/// line comments and doc comments; it is deliberately crude (a string
/// literal containing `//` would also be truncated) because the scan only
/// needs to fail loudly on real code, not parse Rust.
fn without_line_comment(line: &str) -> &str {
    match line.find("//") {
        Some(idx) => &line[..idx],
        None => line,
    }
}

#[test]
fn core_source_never_names_io_time_thread_fs_process() {
    let mut sources = Vec::new();
    rust_sources(&src_dir(), &mut sources);
    assert!(
        !sources.is_empty(),
        "expected at least one .rs file under src/"
    );
    let mut violations = Vec::new();
    for path in &sources {
        let text = fs::read_to_string(path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        for (lineno, line) in text.lines().enumerate() {
            let code = without_line_comment(line);
            for pattern in FORBIDDEN {
                if code.contains(pattern) {
                    violations.push(format!(
                        "{}:{}: forbidden `{pattern}` in: {line}",
                        path.display(),
                        lineno + 1
                    ));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "US-009 AC2 sans-I/O contract violated (no sockets, no clocks, no \
         threads, no fs, no process, no stream I/O in the core):\n{}",
        violations.join("\n")
    );
}
