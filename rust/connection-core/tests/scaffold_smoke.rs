//! Workspace policy smoke tests.
//!
//! These tests exercise the checked source and dependency policy boundaries.

#![forbid(unsafe_code)]

// Linking this integration test against the library is itself the
// "crate compiles" assertion.
use websocket_core as _;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

#[test]
fn toolchain_pin_matches_intake_qualified_compiler() {
    let pin = read(&manifest_dir().join("../rust-toolchain.toml"));
    assert!(
        pin.contains("channel = \"1.95.0\""),
        "workspace toolchain must stay pinned to 1.95.0; found:\n{pin}"
    );
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

#[test]
fn workspace_and_package_both_enforce_the_unsafe_policy() {
    let workspace = read(&manifest_dir().join("../Cargo.toml"));
    let package = read(&manifest_dir().join("Cargo.toml"));
    assert!(workspace.contains("[workspace.lints.rust]\nunsafe_code = \"forbid\""));
    assert!(package.contains("[lints]\nworkspace = true"));
}

#[test]
fn lockfile_and_inventory_allow_only_the_exact_first_party_driver_edge() {
    let workspace = manifest_dir().join("..");
    let lock = read(&workspace.join("Cargo.lock"));
    let inventory = read(&workspace.join("dependency-inventory.toml"));
    let policy = read(&workspace.join("dependency-policy.toml"));

    assert!(lock.contains("name = \"websocket-core\""));
    assert!(lock.contains("name = \"websocket-driver\""));
    assert!(!lock.contains("source = "));
    assert!(!lock.contains("checksum = "));
    assert_eq!(
        lock.matches("dependencies = [\"websocket-core\"]").count(),
        1
    );
    assert!(inventory.contains("status = \"FIRST_PARTY_LOCAL_PATH_ONLY\""));
    assert!(inventory.contains(
        "direct_dependencies = [\"websocket-driver:websocket-core:path:../connection-core\"]"
    ));
    assert!(inventory.contains("transitive_packages = []"));
    assert!(inventory.contains("unsafe_allowances = []"));
    assert!(policy.contains("policy = \"DEPENDENCY_FREE_SAFE_RUST\""));
    assert!(policy.contains(
        "allowed_direct_dependencies = [\"websocket-driver:websocket-core:path:../connection-core\"]"
    ));
    assert!(policy.contains("first_party_unsafe_allowed = false"));
    assert!(policy.contains("rust_toolchain = \"1.95.0\""));
}

#[test]
fn production_source_has_no_ambient_or_callback_surfaces() {
    fn collect_rs(dir: &Path, files: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect_rs(&path, files);
            } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
                files.push(path);
            }
        }
    }

    let mut files = Vec::new();
    collect_rs(&manifest_dir().join("src"), &mut files);
    let forbidden = [
        "std::net",
        "std::fs",
        "std::time",
        "std::process",
        "std::thread",
        "thread::spawn",
        "TcpStream",
        "UdpSocket",
        "SystemTime",
        "Instant::now",
        "Command::new",
        "dyn Fn",
        "impl Fn",
        "extern \"C\" fn",
    ];
    for file in files {
        let source = read(&file);
        let production = source.split("#[cfg(test)]").next().unwrap_or(&source);
        for token in forbidden {
            assert!(
                !production.contains(token),
                "production source {} contains forbidden surface {token}",
                file.display()
            );
        }
    }
}

#[test]
fn us006_proof_paths_host_the_exact_us012_production_symbols() {
    let root = manifest_dir().join("src/frame");
    assert!(root.join("mask.rs").is_file());
    assert!(root.join("decode.rs").is_file());
    let mask = read(&root.join("mask.rs"));
    let decode = read(&root.join("decode.rs"));
    assert!(mask.contains("pub fn apply_mask_in_place"));
    assert!(decode.contains("pub struct FrameHeaderDecoder"));
    assert!(decode.contains("pub fn decode_header"));
}

#[test]
fn package_and_repository_license_are_exactly_bound() {
    let package = read(&manifest_dir().join("Cargo.toml"));
    assert!(package.contains("license.workspace = true"));
    let workspace = read(&manifest_dir().join("../Cargo.toml"));
    assert!(workspace.contains("license = \"Apache-2.0\""));

    let license = manifest_dir().join("../../LICENSE");
    let output = Command::new("shasum")
        .args(["-a", "256"])
        .arg(&license)
        .output()
        .expect("the macOS qualification host must provide shasum");
    assert!(output.status.success());
    let digest = String::from_utf8(output.stdout).expect("shasum output is UTF-8");
    assert!(
        digest.starts_with("c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4 "),
        "LICENSE digest must remain bound to the architecture receipt"
    );
}
