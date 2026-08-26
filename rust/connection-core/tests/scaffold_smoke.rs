//! Scaffold smoke tests.
//!
//! These tests make only infrastructure claims: the crate compiles and links,
//! the mandatory safety/documentation attributes are literally present in the
//! library source, and the crate is dependency-free as designed. They claim
//! nothing about WebSocket behavior -- there is none to claim.

// Linking this integration test against the library is itself the
// "crate compiles" assertion.
use connection_core as _;

use std::fs;
use std::path::{Path, PathBuf};

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

/// The PRD quality gate requires `#![forbid(unsafe_code)]` on every
/// first-party crate. Assert the attribute is literally present in the
/// library source so it cannot be dropped without a test failure.
#[test]
fn lib_source_forbids_unsafe_code() {
    let lib_rs = read(&manifest_dir().join("src/lib.rs"));
    assert!(
        lib_rs.contains("#![forbid(unsafe_code)]"),
        "src/lib.rs must contain #![forbid(unsafe_code)] (PRD quality gate)"
    );
}

/// The scaffold also denies missing docs so every future public item of the
/// US-009 contract arrives documented.
#[test]
fn lib_source_denies_missing_docs() {
    let lib_rs = read(&manifest_dir().join("src/lib.rs"));
    assert!(
        lib_rs.contains("#![deny(missing_docs)]"),
        "src/lib.rs must contain #![deny(missing_docs)]"
    );
}

/// Design stance: the Sans-I/O core is dependency-free. Guard the stance by
/// asserting every dependency table in Cargo.toml is empty, so adding a
/// dependency forces a deliberate, reviewed change to this test.
#[test]
fn crate_is_dependency_free() {
    let cargo_toml = read(&manifest_dir().join("Cargo.toml"));
    let mut in_dependency_table = false;
    for raw_line in cargo_toml.lines() {
        let line = raw_line.trim();
        if line.starts_with('[') {
            in_dependency_table = line.ends_with("dependencies]");
            continue;
        }
        if in_dependency_table && !line.is_empty() && !line.starts_with('#') {
            panic!(
                "connection-core must stay dependency-free \
                 (see docs/rust-workspace.md); found dependency line: {line}"
            );
        }
    }
}
