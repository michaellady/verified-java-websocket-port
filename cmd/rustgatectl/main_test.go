// Polarity tests for the US-009 AC1 rust workspace gate mechanics.
//
// Every mechanical scan the gate runner performs must be proven in BOTH
// directions here: a conforming input passes and a deliberately broken input
// fails. The live good/bad scaffold canaries (rust/gates/canaries/) prove the
// same polarity end-to-end through real cargo invocations; these tests prove
// the pure decision logic without a toolchain.
package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
		// Round-1 review blockers: comment/scope-aware scan. The attribute
		// only counts at crate-root position, never inside a comment, a
		// string/raw-string literal, or a nested module.
		{"attribute-in-block-comment", "/*\n#![forbid(unsafe_code)]\n*/\npub fn f() {}\n", false},
		{"attribute-in-nested-block-comment", "/* outer /* inner */\n#![forbid(unsafe_code)]\n*/\npub fn f() {}\n", false},
		{"attribute-in-raw-string", "pub const DOC: &str = r#\"\n#![forbid(unsafe_code)]\n\"#;\n", false},
		{"attribute-in-plain-string", "pub const DOC: &str = \"\n#![forbid(unsafe_code)]\n\";\n", false},
		{"attribute-inside-mod", "mod inner {\n    #![forbid(unsafe_code)]\n}\npub fn f() {}\n", false},
		{"attribute-after-item", "pub fn f() {}\n#![forbid(unsafe_code)]\n", false},
		// Conforming placements that must keep passing.
		{"attribute-after-doc-comments", "//! docs\n//! more docs\n#![forbid(unsafe_code)]\npub fn f() {}\n", true},
		{"attribute-after-block-comment", "/* license\nheader */\n#![forbid(unsafe_code)]\npub fn f() {}\n", true},
		{"attribute-after-other-inner-attribute", "#![deny(missing_docs)]\n#![forbid(unsafe_code)]\npub fn f() {}\n", true},
		{"attribute-with-inner-spacing", "#![ forbid ( unsafe_code ) ]\npub fn f() {}\n", true},
		{"doc-attr-string-decoy-only", "#![doc = \"#![forbid(unsafe_code)]\"]\npub fn f() {}\n", false},
		{"doc-attr-string-decoy-then-real", "#![doc = \"#![forbid(unsafe_code)]\"]\n#![forbid(unsafe_code)]\npub fn f() {}\n", true},
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

	const registry = "registry+https://github.com/rust-lang/crates.io-index"
	externals := []externalDependency{{Name: "smallvec", Version: "1.13.2", Source: registry}}
	if violations := compareDependencyInventory(externals, empty); len(violations) == 0 {
		t.Fatal("external dependency without an inventory entry must fail")
	}

	covered := []inventoryEntry{{Name: "smallvec", Version: "1.13.2", Source: registry, UnsafeUsage: "uses unsafe for inline storage; reviewed"}}
	if violations := compareDependencyInventory(externals, covered); len(violations) != 0 {
		t.Fatalf("covered external (name+version+source all matching) must pass, got %v", violations)
	}

	blank := []inventoryEntry{{Name: "smallvec", Version: "1.13.2", Source: registry, UnsafeUsage: "   "}}
	if violations := compareDependencyInventory(externals, blank); len(violations) == 0 {
		t.Fatal("inventory entry with a blank unsafe_usage statement must fail")
	}

	stale := []inventoryEntry{{Name: "gone-crate", Version: "0.1.0", Source: registry, UnsafeUsage: "stated"}}
	if violations := compareDependencyInventory(none, stale); len(violations) == 0 {
		t.Fatal("stale inventory entry with no matching dependency must fail")
	}
}

// Round-1 review blocker: the inventory must bind the reviewed SOURCE, not
// just name@version. A dependency swapped to a different source (the
// source-swap bypass) demands a renewed reviewed entry, and an entry that
// omits its source cannot cover anything.
func TestCompareDependencyInventoryRequiresSource(t *testing.T) {
	const registry = "registry+https://github.com/rust-lang/crates.io-index"
	externals := []externalDependency{{Name: "smallvec", Version: "1.13.2", Source: registry}}

	unsourced := []inventoryEntry{{Name: "smallvec", Version: "1.13.2", UnsafeUsage: "reviewed"}}
	if violations := compareDependencyInventory(externals, unsourced); len(violations) == 0 {
		t.Fatal("inventory entry without a source must fail — the reviewed source is part of the reviewed identity")
	}

	swapped := []inventoryEntry{{Name: "smallvec", Version: "1.13.2", Source: "git+https://github.com/attacker/smallvec", UnsafeUsage: "reviewed"}}
	violations := compareDependencyInventory(externals, swapped)
	if len(violations) == 0 {
		t.Fatal("source-swap bypass: same name@version from a different source must FAIL until a renewed reviewed entry lands")
	}
	joined := strings.Join(violations, "\n")
	if !strings.Contains(joined, registry) {
		t.Fatalf("source-swap violation must name the actual dependency source, got %v", violations)
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

// Round-1 review blocker: the member checks must be section-aware. A key
// under [package.metadata.*] (or any non-[package] section) is a decoy and
// must NOT satisfy the MSRV/license member requirement.
func TestMemberInheritsWorkspaceKeyIsSectionAware(t *testing.T) {
	metadataValueDecoy := "[package]\nname = \"x\"\n\n[package.metadata.gate-dodge]\nrust-version = \"1.95.0\"\n"
	if memberInheritsWorkspaceKey(metadataValueDecoy, "rust-version", "1.95.0") {
		t.Fatal("explicit value under [package.metadata.*] must NOT satisfy the check")
	}
	metadataInheritDecoy := "[package]\nname = \"x\"\n\n[package.metadata.gate-dodge]\nrust-version.workspace = true\n"
	if memberInheritsWorkspaceKey(metadataInheritDecoy, "rust-version", "1.95.0") {
		t.Fatal("workspace-inheritance marker under [package.metadata.*] must NOT satisfy the check")
	}
	metadataLicenseDecoy := "[package]\nname = \"x\"\n\n[package.metadata.gate-dodge]\nlicense = \"Apache-2.0\"\n"
	if memberInheritsWorkspaceKey(metadataLicenseDecoy, "license", "Apache-2.0") {
		t.Fatal("license under [package.metadata.*] must NOT satisfy the check")
	}
	otherSectionDecoy := "[package]\nname = \"x\"\n\n[dependencies]\nrust-version = \"1.95.0\"\n"
	if memberInheritsWorkspaceKey(otherSectionDecoy, "rust-version", "1.95.0") {
		t.Fatal("key under [dependencies] must NOT satisfy the check")
	}
	keyBeforeAnySection := "rust-version = \"1.95.0\"\n[package]\nname = \"x\"\n"
	if memberInheritsWorkspaceKey(keyBeforeAnySection, "rust-version", "1.95.0") {
		t.Fatal("top-level key outside any [package] section must NOT satisfy the check")
	}
	// The real placements must keep passing, including with trailing comments
	// and spaced section headers.
	underPackage := "[ package ]\nname = \"x\"\nrust-version.workspace = true # inherited\n"
	if !memberInheritsWorkspaceKey(underPackage, "rust-version", "1.95.0") {
		t.Fatal("inheritance marker under [package] with a trailing comment must satisfy the check")
	}
	afterMetadata := "[package.metadata.gate-dodge]\nrust-version = \"1.80.0\"\n\n[package]\nname = \"x\"\nrust-version = \"1.95.0\"\n"
	if !memberInheritsWorkspaceKey(afterMetadata, "rust-version", "1.95.0") {
		t.Fatal("matching value under a [package] section that FOLLOWS a metadata section must satisfy the check")
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

// TestLicenseIdentityIsReDerivedNotPatternMatched is ROUND 3 ATTACK A3.
//
// The predicate this replaces was Contains("Apache License") &&
// Contains("Version 2.0"). The first case below is the LICENSE that defeated
// it: a proprietary, all-rights-reserved notice that says in so many words
// that the software is NOT under Apache-2.0, and carries both substrings.
func TestLicenseIdentityIsReDerivedNotPatternMatched(t *testing.T) {
	proprietary := "                        PROPRIETARY SOFTWARE LICENSE\n" +
		"                              All Rights Reserved\n\n" +
		"   This software is NOT distributed under the Apache License,\n" +
		"   Version 2.0, or under any other open-source licence.\n"
	if licenseIdentityProblem(proprietary) == "" {
		t.Fatal("A3: a proprietary licence carrying the strings \"Apache License\" and \"Version 2.0\" must NOT be accepted as Apache-2.0")
	}
	if licenseIdentityProblem("MIT License\n\nPermission is hereby granted...\n") == "" {
		t.Fatal("MIT text must fail the Apache-2.0 identity check")
	}
	if licenseIdentityProblem("") == "" {
		t.Fatal("empty license text must fail")
	}
	// A truncated Apache-2.0 -- header present, clauses gone -- must fail,
	// and the diagnostic must name the clause it stopped at.
	truncated := "                                 Apache License\n                           Version 2.0, January 2004\n"
	problem := licenseIdentityProblem(truncated)
	if problem == "" {
		t.Fatal("a truncated Apache-2.0 must fail")
	}
	if !strings.Contains(problem, "TERMS AND CONDITIONS") {
		t.Fatalf("the diagnostic must name the first missing clause, got %q", problem)
	}
	// The committed LICENSE is the canonical text and must pass.
	data, err := os.ReadFile(filepath.Join(repoRootForTest(t), "LICENSE"))
	if err != nil {
		t.Fatalf("read LICENSE: %v", err)
	}
	if problem := licenseIdentityProblem(string(data)); problem != "" {
		t.Fatalf("the committed LICENSE must be recognised as canonical Apache-2.0: %s", problem)
	}
}

// repoRootForTest walks up from the test's working directory to the
// repository root (the directory holding go.mod).
func repoRootForTest(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not find the repository root")
	return ""
}

// TestUnsafeTokenLine is ROUND 3 ATTACKS A1 AND A2: the scan that finds
// `unsafe` in a crate root the attribute requirement does not cover.
func TestUnsafeTokenLine(t *testing.T) {
	cases := []struct {
		name   string
		source string
		want   int
		found  bool
	}{
		{"A1 unsafe in a test crate root", "#[test]\nfn t() {\n    let x = 1u32;\n    let _ = unsafe { std::ptr::read(&x) };\n}\n", 4, true},
		{"A2 unsafe in a build script", "fn main() {\n    let _ = unsafe { std::ptr::read(&0u32) };\n}\n", 2, true},
		{"the forbid attribute is not an unsafe token", "#![forbid(unsafe_code)]\nfn a() {}\n", 0, false},
		{"unsafe_op_in_unsafe_fn is not an unsafe token", "#![allow(unsafe_op_in_unsafe_fn)]\n", 0, false},
		{"unsafe inside a line comment", "// this is unsafe\nfn a() {}\n", 0, false},
		{"unsafe inside a doc comment", "//! talks about unsafe code\nfn a() {}\n", 0, false},
		{"unsafe inside a block comment", "/* unsafe\n   still unsafe */\nfn a() {}\n", 0, false},
		{"unsafe inside a string literal", "fn a() { let s = \"unsafe\"; let _ = s; }\n", 0, false},
		{"unsafe inside a raw string literal", "fn a() { let s = r#\"unsafe\"#; let _ = s; }\n", 0, false},
		{"unsafe after a skipped comment keeps the line count", "// one\n/* two\n   three */\nunsafe fn f() {}\n", 4, true},
	}
	for _, tc := range cases {
		line, ok := unsafeTokenLine(tc.source)
		if ok != tc.found || line != tc.want {
			t.Errorf("%s: unsafeTokenLine = (%d, %v), want (%d, %v)", tc.name, line, ok, tc.want, tc.found)
		}
	}
}

// TestExternalDependenciesAreNonMembersNotNonPathDeps is ROUND 3 ATTACK A7.
//
// A crate vendored under third_party/ and reached by a path dependency from
// OUTSIDE the workspace directory has a NULL cargo `source`. Under the old
// definition it was neither a member nor external, so the inventory gate, the
// audit gate and the forbid scan all reported a clean tree while its unsafe
// code was compiled into ws-core.
func TestExternalDependenciesAreNonMembersNotNonPathDeps(t *testing.T) {
	registry := "registry+https://github.com/rust-lang/crates.io-index"
	meta := &cargoMetadata{
		WorkspaceMembers: []string{"member 0.0.0 (path+file:///repo/rust/ws-core)"},
		Packages: []cargoPackage{
			{ID: "member 0.0.0 (path+file:///repo/rust/ws-core)", Name: "ws-core", Version: "0.0.0", ManifestPath: "/repo/rust/ws-core/Cargo.toml"},
			{ID: "vendored 0.0.0 (path+file:///repo/third_party/attackdep)", Name: "attackdep", Version: "0.0.0", ManifestPath: "/repo/third_party/attackdep/Cargo.toml"},
			{ID: "reg 1.0.0", Name: "someregistrycrate", Version: "1.0.0", Source: &registry, ManifestPath: "/home/u/.cargo/registry/someregistrycrate/Cargo.toml"},
		},
	}
	got := meta.externalDependencies()
	if len(got) != 2 {
		t.Fatalf("want 2 external dependencies (the vendored path dep and the registry dep), got %d: %+v", len(got), got)
	}
	if got[0].Name != "attackdep" {
		t.Fatalf("A7: the vendored path dependency must be external, got %+v", got)
	}
	if !strings.HasPrefix(got[0].Source, "path:") {
		t.Fatalf("a path dependency's source must be reported as its resolved directory, not the empty string; got %q", got[0].Source)
	}
	if got[1].Source != registry {
		t.Fatalf("a registry dependency must keep its cargo source, got %q", got[1].Source)
	}
	// The polarity: a workspace with only members has no external dependency.
	onlyMembers := &cargoMetadata{
		WorkspaceMembers: []string{"member 0.0.0 (path+file:///repo/rust/ws-core)"},
		Packages:         []cargoPackage{{ID: "member 0.0.0 (path+file:///repo/rust/ws-core)", Name: "ws-core", ManifestPath: "/repo/rust/ws-core/Cargo.toml"}},
	}
	if n := len(onlyMembers.externalDependencies()); n != 0 {
		t.Fatalf("a members-only workspace must report 0 external dependencies, got %d", n)
	}
}

// TestClippyLintNames is the extraction the canary polarity now rests on.
func TestClippyLintNames(t *testing.T) {
	withLints := "error: this if-then-else expression returns a bool literal\n" +
		"   = note: `-D clippy::needless-bool` implied by `-D warnings`\n" +
		"error: equality checks against true are unnecessary\n" +
		"   = note: `-D clippy::bool-comparison` implied by `-D warnings`\n"
	got := clippyLintNames(withLints)
	if len(got) != 2 || got[0] != "bool_comparison" || got[1] != "needless_bool" {
		t.Fatalf("want the two lint names sorted, got %v", got)
	}
	// clippy names the same lint both ways in one run; the count must be of
	// LINTS, not of spellings.
	bothSpellings := "`-D clippy::needless-bool` implied by `-D warnings`\n" +
		"to override `-D warnings` add `#[allow(clippy::needless_bool)]`\n"
	if got := clippyLintNames(bothSpellings); len(got) != 1 || got[0] != "needless_bool" {
		t.Fatalf("the hyphen and underscore spellings are one lint, got %v", got)
	}
	// A6: a crate that does not compile fails clippy with no lint at all.
	compileError := "error[E0425]: cannot find function `attack_a6_no_such_function` in this scope\n" +
		" --> src/lib.rs:23:5\nerror: could not compile `bad-scaffold` (lib) due to 1 previous error\n"
	if got := clippyLintNames(compileError); len(got) != 0 {
		t.Fatalf("A6: a pure compile error names no clippy lint, got %v", got)
	}
}

// --- canary polarity contract ----------------------------------------------

func TestEvaluateCanaryPolarity(t *testing.T) {
	good := canaryResult{name: "good-scaffold", scanExit: 0, clippyExit: 0, testExit: 0, checkExit: exitNotRun}
	bad := canaryResult{name: "bad-scaffold", scanExit: 1, clippyExit: 101, testExit: exitNotRun, checkExit: 0, clippyLints: 2}
	if violations := evaluateCanaryPolarity(good, bad); len(violations) != 0 {
		t.Fatalf("correct polarity must pass, got %v", violations)
	}

	// ROUND 3 ATTACK A6: the bad canary's clippy refusal must be a LINT.
	// Replacing its `if flag == true` with a call to an undefined function
	// left clippy at exit 101 with no clippy lint named, and the gate printed
	// the same "exits 1/101" census as a run where the lint really fired.
	compileErrorNotLint := bad
	compileErrorNotLint.checkExit = 101
	compileErrorNotLint.clippyLints = 0
	violations := evaluateCanaryPolarity(good, compileErrorNotLint)
	if len(violations) != 2 {
		t.Fatalf("A6: a bad canary that fails to compile and names no lint must produce both findings, got %v", violations)
	}
	// Each half must fire on its own, so neither can be deleted behind the
	// other.
	onlyNoLint := bad
	onlyNoLint.clippyLints = 0
	if v := evaluateCanaryPolarity(good, onlyNoLint); len(v) != 1 {
		t.Fatalf("A6: a compiling bad canary whose clippy named no lint must produce exactly one finding, got %v", v)
	}
	onlyBroken := bad
	onlyBroken.checkExit = 101
	if v := evaluateCanaryPolarity(good, onlyBroken); len(v) != 1 {
		t.Fatalf("A6: a bad canary that does not compile must produce exactly one finding even when clippy named a lint, got %v", v)
	}
	// A cargo check that never ran is not a detection either.
	neverRan := bad
	neverRan.checkExit = exitNoProcessState
	if v := evaluateCanaryPolarity(good, neverRan); len(v) == 0 {
		t.Fatal("A6: a cargo check that never produced a process state must be its own violation")
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

// --- exit-code reporting shape ----------------------------------------------

// Round-1 review blocker: the exit code must be READ from the process state
// of every completed command — success and failure alike — and printed
// verbatim; a command that never produced a ProcessState must say so
// explicitly instead of inventing a numeric code.
func TestExecStepExitReportingShape(t *testing.T) {
	dir := t.TempDir()

	var buf bytes.Buffer
	r := &gateRunner{stdout: &buf}
	exit, _ := r.execStep("shape", "success", dir, false, "sh", "-c", "exit 0")
	if exit != 0 {
		t.Fatalf("sh -c 'exit 0' reported exit %d", exit)
	}
	if !strings.Contains(buf.String(), "exit=0") {
		t.Fatalf("success line must carry the verbatim exit code, got %q", buf.String())
	}

	buf.Reset()
	exit, _ = r.execStep("shape", "failure", dir, false, "sh", "-c", "exit 7")
	if exit != 7 {
		t.Fatalf("sh -c 'exit 7' reported exit %d, want 7", exit)
	}
	if !strings.Contains(buf.String(), "exit=7") {
		t.Fatalf("failure line must carry the verbatim exit code, got %q", buf.String())
	}

	buf.Reset()
	exit, _ = r.execStep("shape", "never-started", dir, false, "/nonexistent-rustgatectl-test-binary")
	if exit == 0 {
		t.Fatal("a command that never started must not report success")
	}
	if !strings.Contains(buf.String(), "exit=none") || !strings.Contains(buf.String(), "process_state=absent") {
		t.Fatalf("a command with no ProcessState must say so explicitly (exit=none process_state=absent), got %q", buf.String())
	}
}

func TestCompletedExitReadsProcessState(t *testing.T) {
	cmd := exec.Command("sh", "-c", "exit 0")
	runErr := cmd.Run()
	exit, field := completedExit(cmd.ProcessState, runErr)
	if exit != 0 || field != "exit=0" {
		t.Fatalf("success: completedExit = (%d, %q), want (0, \"exit=0\")", exit, field)
	}

	cmd = exec.Command("sh", "-c", "exit 42")
	runErr = cmd.Run()
	exit, field = completedExit(cmd.ProcessState, runErr)
	if exit != 42 || field != "exit=42" {
		t.Fatalf("failure: completedExit = (%d, %q), want (42, \"exit=42\")", exit, field)
	}

	cmd = exec.Command("/nonexistent-rustgatectl-test-binary")
	runErr = cmd.Run()
	exit, field = completedExit(cmd.ProcessState, runErr)
	if exit != exitNoProcessState {
		t.Fatalf("no ProcessState: exit = %d, want sentinel %d", exit, exitNoProcessState)
	}
	if !strings.Contains(field, "exit=none") || !strings.Contains(field, "process_state=absent") {
		t.Fatalf("no ProcessState: field = %q must state the absence explicitly", field)
	}
}

// --- MSRV build hard requirement ---------------------------------------------

// Round-1 review blocker: build-under-MSRV is a hard requirement. An absent
// MSRV toolchain FAILS the msrv gate; it is never recorded as a passing
// pending note. Only the below-MSRV differential may remain pending.
func TestBuildUnderMSRVOutcomeHardRequirement(t *testing.T) {
	buildRan := false
	pass, detail := buildUnderMSRVOutcome("", "1.95.0", func(string) int { buildRan = true; return 0 })
	if pass {
		t.Fatal("absent MSRV toolchain must FAIL the msrv gate, not pass pending")
	}
	if buildRan {
		t.Fatal("no build may be attempted without the MSRV toolchain")
	}
	if !strings.Contains(detail, "hard requirement") {
		t.Fatalf("failure detail must state the hard requirement, got %q", detail)
	}

	var usedToolchain string
	pass, detail = buildUnderMSRVOutcome("1.95.0-aarch64-apple-darwin", "1.95.0", func(tc string) int { usedToolchain = tc; return 0 })
	if !pass {
		t.Fatalf("clean build under the MSRV toolchain must pass, got %q", detail)
	}
	if usedToolchain != "1.95.0-aarch64-apple-darwin" {
		t.Fatalf("build must run under the MSRV toolchain, ran under %q", usedToolchain)
	}

	pass, detail = buildUnderMSRVOutcome("1.95.0-aarch64-apple-darwin", "1.95.0", func(string) int { return 101 })
	if pass {
		t.Fatal("failing build under the MSRV toolchain must fail the gate")
	}
	if !strings.Contains(detail, "101") {
		t.Fatalf("build failure detail must carry the verbatim exit, got %q", detail)
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
