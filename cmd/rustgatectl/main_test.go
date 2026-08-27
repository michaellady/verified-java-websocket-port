// Polarity tests for the US-009 AC1 rust workspace gate mechanics.
//
// Every mechanical scan the gate runner performs must be proven in BOTH
// directions here: a conforming input passes and a deliberately broken input
// fails. The live good/bad scaffold canaries (rust/gates/canaries/) prove the
// same polarity end-to-end through real cargo invocations; these tests prove
// the pure decision logic without a toolchain.
package main

import (
	"os"
	"path/filepath"
	"testing"
)

// --- forbid(unsafe_code) scan ----------------------------------------------

func TestHasForbidUnsafeDetectsRealAttributeOnly(t *testing.T) {
	cases := []struct {
		name   string
		source string
		want   bool
	}{
		{"attribute-present", "//! doc\n#![forbid(unsafe_code)]\npub fn f() {}\n", true},
		{"attribute-with-leading-whitespace", "  #![forbid(unsafe_code)]\n", true},
		{"doc-comment-mention-only", "//! carries #![forbid(unsafe_code)] per the PRD\npub fn f() {}\n", false},
		{"line-comment-mention-only", "// #![forbid(unsafe_code)]\npub fn f() {}\n", false},
		{"absent", "pub fn f() {}\n", false},
		{"empty", "", false},
		{"deny-is-not-forbid", "#![deny(unsafe_code)]\n", false},
	}
	for _, tc := range cases {
		if got := hasForbidUnsafe(tc.source); got != tc.want {
			t.Errorf("%s: hasForbidUnsafe = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestScanRootsForForbidPolarity(t *testing.T) {
	dir := t.TempDir()
	goodRoot := filepath.Join(dir, "good.rs")
	badRoot := filepath.Join(dir, "bad.rs")
	writeFile(t, goodRoot, "#![forbid(unsafe_code)]\npub fn ok() {}\n")
	writeFile(t, badRoot, "//! no attribute here\npub fn nope() {}\n")

	if violations := scanRootsForForbid([]string{goodRoot}); len(violations) != 0 {
		t.Fatalf("conforming root reported violations: %v", violations)
	}
	violations := scanRootsForForbid([]string{goodRoot, badRoot})
	if len(violations) != 1 {
		t.Fatalf("want exactly 1 violation for the bad root, got %v", violations)
	}
	missing := filepath.Join(dir, "missing.rs")
	if violations := scanRootsForForbid([]string{missing}); len(violations) != 1 {
		t.Fatalf("unreadable root must be a violation, got %v", violations)
	}
}

// --- dependency-unsafe inventory -------------------------------------------

func TestCompareDependencyInventoryPolarity(t *testing.T) {
	none := []externalDependency{}
	empty := []inventoryEntry{}
	if violations := compareDependencyInventory(none, empty); len(violations) != 0 {
		t.Fatalf("zero externals + empty inventory must pass, got %v", violations)
	}

	externals := []externalDependency{{Name: "smallvec", Version: "1.13.2", Source: "registry+https://github.com/rust-lang/crates.io-index"}}
	if violations := compareDependencyInventory(externals, empty); len(violations) == 0 {
		t.Fatal("external dependency without an inventory entry must fail")
	}

	covered := []inventoryEntry{{Name: "smallvec", Version: "1.13.2", UnsafeUsage: "uses unsafe for inline storage; reviewed"}}
	if violations := compareDependencyInventory(externals, covered); len(violations) != 0 {
		t.Fatalf("covered external must pass, got %v", violations)
	}

	blank := []inventoryEntry{{Name: "smallvec", Version: "1.13.2", UnsafeUsage: "   "}}
	if violations := compareDependencyInventory(externals, blank); len(violations) == 0 {
		t.Fatal("inventory entry with a blank unsafe_usage statement must fail")
	}

	stale := []inventoryEntry{{Name: "gone-crate", Version: "0.1.0", UnsafeUsage: "stated"}}
	if violations := compareDependencyInventory(none, stale); len(violations) == 0 {
		t.Fatal("stale inventory entry with no matching dependency must fail")
	}
}

// --- MSRV declaration consistency ------------------------------------------

func TestParseToolchainChannel(t *testing.T) {
	pin := "# comment\n[toolchain]\nchannel = \"1.95.0\"\ncomponents = [\"rustfmt\", \"clippy\"]\n"
	got, err := parseToolchainChannel(pin)
	if err != nil || got != "1.95.0" {
		t.Fatalf("parseToolchainChannel = %q, %v; want 1.95.0, nil", got, err)
	}
	if _, err := parseToolchainChannel("[toolchain]\ncomponents = []\n"); err == nil {
		t.Fatal("missing channel must be an error")
	}
}

func TestParseWorkspacePackageKey(t *testing.T) {
	manifest := "[workspace]\nmembers = [\"a\"]\n\n[workspace.package]\nversion = \"0.0.0\"\nrust-version = \"1.95.0\"\nlicense = \"Apache-2.0\"\n"
	if got, err := parseWorkspacePackageKey(manifest, "rust-version"); err != nil || got != "1.95.0" {
		t.Fatalf("rust-version = %q, %v; want 1.95.0, nil", got, err)
	}
	if got, err := parseWorkspacePackageKey(manifest, "license"); err != nil || got != "Apache-2.0" {
		t.Fatalf("license = %q, %v; want Apache-2.0, nil", got, err)
	}
	// A rust-version outside [workspace.package] must not satisfy the lookup.
	elsewhere := "[package]\nrust-version = \"1.95.0\"\n"
	if _, err := parseWorkspacePackageKey(elsewhere, "rust-version"); err == nil {
		t.Fatal("rust-version outside [workspace.package] must be an error")
	}
}

func TestMemberInheritsWorkspaceKeyPolarity(t *testing.T) {
	inherits := "[package]\nname = \"x\"\nrust-version.workspace = true\nlicense.workspace = true\n"
	if !memberInheritsWorkspaceKey(inherits, "rust-version", "1.95.0") {
		t.Fatal("dotted workspace inheritance must satisfy the check")
	}
	inline := "[package]\nrust-version = { workspace = true }\n"
	if !memberInheritsWorkspaceKey(inline, "rust-version", "1.95.0") {
		t.Fatal("inline-table workspace inheritance must satisfy the check")
	}
	explicitMatch := "[package]\nrust-version = \"1.95.0\"\n"
	if !memberInheritsWorkspaceKey(explicitMatch, "rust-version", "1.95.0") {
		t.Fatal("explicit value equal to the workspace value must satisfy the check")
	}
	explicitDrift := "[package]\nrust-version = \"1.80.0\"\n"
	if memberInheritsWorkspaceKey(explicitDrift, "rust-version", "1.95.0") {
		t.Fatal("explicit drifted value must fail the check")
	}
	absent := "[package]\nname = \"x\"\n"
	if memberInheritsWorkspaceKey(absent, "rust-version", "1.95.0") {
		t.Fatal("absent declaration must fail the check")
	}
}

func TestParseInstalledToolchainVersions(t *testing.T) {
	listing := "stable-aarch64-apple-darwin (active, default)\n1.95.0-aarch64-apple-darwin\n"
	versioned, symbolic := parseInstalledToolchains(listing)
	if len(versioned) != 1 || versioned[0].name != "1.95.0-aarch64-apple-darwin" || versioned[0].version != "1.95.0" {
		t.Fatalf("versioned toolchains = %+v", versioned)
	}
	if len(symbolic) != 1 || symbolic[0] != "stable-aarch64-apple-darwin" {
		t.Fatalf("symbolic toolchains = %v", symbolic)
	}
}

func TestVersionOlderThan(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"1.94.0", "1.95.0", true},
		{"1.95.0", "1.95.0", false},
		{"1.100.0", "1.95.0", false},
		{"0.9.9", "1.95.0", true},
	}
	for _, tc := range cases {
		if got := versionOlderThan(tc.a, tc.b); got != tc.want {
			t.Errorf("versionOlderThan(%s, %s) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// --- license policy ---------------------------------------------------------

func TestLicenseFileLooksApache2Polarity(t *testing.T) {
	apache := "                                 Apache License\n                           Version 2.0, January 2004\n"
	if !licenseFileLooksApache2(apache) {
		t.Fatal("real Apache-2.0 header must pass")
	}
	mit := "MIT License\n\nPermission is hereby granted...\n"
	if licenseFileLooksApache2(mit) {
		t.Fatal("MIT text must fail the Apache-2.0 check")
	}
	if licenseFileLooksApache2("") {
		t.Fatal("empty license text must fail")
	}
}

// --- canary polarity contract ----------------------------------------------

func TestEvaluateCanaryPolarity(t *testing.T) {
	good := canaryResult{name: "good-scaffold", scanExit: 0, clippyExit: 0, testExit: 0}
	bad := canaryResult{name: "bad-scaffold", scanExit: 1, clippyExit: 101, testExit: exitNotRun}
	if violations := evaluateCanaryPolarity(good, bad); len(violations) != 0 {
		t.Fatalf("correct polarity must pass, got %v", violations)
	}

	brokenGood := good
	brokenGood.testExit = 101
	if violations := evaluateCanaryPolarity(brokenGood, bad); len(violations) == 0 {
		t.Fatal("good canary failing a gate must fail the polarity check")
	}

	sneakyBadScan := bad
	sneakyBadScan.scanExit = 0
	if violations := evaluateCanaryPolarity(good, sneakyBadScan); len(violations) == 0 {
		t.Fatal("bad canary passing the forbid scan must fail the polarity check")
	}

	sneakyBadClippy := bad
	sneakyBadClippy.clippyExit = 0
	if violations := evaluateCanaryPolarity(good, sneakyBadClippy); len(violations) == 0 {
		t.Fatal("bad canary passing clippy must fail the polarity check")
	}
}

// --- helpers ----------------------------------------------------------------

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
