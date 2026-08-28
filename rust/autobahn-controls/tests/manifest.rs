//! The machine-readable control manifest must describe exactly the controls
//! this crate actually ships.
//!
//! `manifest.json` is what the Autobahn case-manifest calibration reads to
//! know which binary carries which planted deviation. A manifest that names a
//! binary the crate does not build — or omits one it does — would silently
//! calibrate against the wrong artifact, so the correspondence is asserted
//! mechanically here rather than maintained by hand.

use autobahn_controls::{NEGATIVE_CONTROL_BINARY, NEGATIVE_CONTROL_ID, mutant::Mutant};

const MANIFEST: &str = include_str!("../manifest.json");
const CARGO_TOML: &str = include_str!("../Cargo.toml");

#[test]
fn the_manifest_names_every_control_this_crate_ships() {
    for id in std::iter::once(NEGATIVE_CONTROL_ID).chain(Mutant::ALL.iter().map(|m| m.id())) {
        assert!(
            MANIFEST.contains(&format!("\"id\": \"{id}\"")),
            "manifest.json has no entry for control {id}"
        );
    }
    for binary in
        std::iter::once(NEGATIVE_CONTROL_BINARY).chain(Mutant::ALL.iter().map(|m| m.binary()))
    {
        assert!(
            MANIFEST.contains(&format!("\"binary\": \"{binary}\"")),
            "manifest.json has no binary entry for {binary}"
        );
        assert!(
            CARGO_TOML.contains(&format!("name = \"{binary}\"")),
            "Cargo.toml declares no [[bin]] named {binary}"
        );
    }
}

#[test]
fn every_manifest_entry_states_a_deviation_and_an_expected_discrimination() {
    // Honesty guard: an entry that does not say what it deviates in, or what
    // Autobahn must show, is not usable as calibration evidence.
    let entries = MANIFEST.matches("\"id\": \"").count();
    assert_eq!(
        entries,
        Mutant::ALL.len() + 1,
        "manifest.json must describe exactly the shipped controls"
    );
    assert_eq!(MANIFEST.matches("\"deviation\": \"").count(), entries);
    assert_eq!(
        MANIFEST.matches("\"expected_discrimination\": \"").count(),
        entries
    );
    assert_eq!(
        MANIFEST.matches("\"kind\": \"mutant\"").count(),
        Mutant::ALL.len()
    );
    assert_eq!(
        MANIFEST.matches("\"kind\": \"negative-control\"").count(),
        1
    );
}

#[test]
fn the_manifest_claims_no_measured_case_counts() {
    // US-019 AC4 asks for a conservative, honest expectation. No numeric case
    // count has been measured against these controls yet, so the manifest
    // must not carry one — a fabricated count would be read as evidence.
    for forbidden in ["measured_", "cases_failed", "case_count"] {
        assert!(
            !MANIFEST.contains(forbidden),
            "manifest.json must not claim an unmeasured result ({forbidden})"
        );
    }
}

#[test]
fn each_mutant_documents_exactly_one_deviation_seam() {
    for mutant in Mutant::ALL {
        assert!(!mutant.id().is_empty());
        assert!(!mutant.deviation().is_empty());
        assert!(
            mutant.binary().starts_with("us019-mutant-"),
            "{} does not follow the mutant binary naming",
            mutant.binary()
        );
    }
    assert_eq!(NEGATIVE_CONTROL_BINARY, "us019-negative-control");
}
