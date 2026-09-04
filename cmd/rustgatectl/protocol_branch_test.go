// Polarity and adversarial tests for the US-018 AC1 protocol-state branch rule
// (F016). Every mechanical decision is proven in BOTH directions: each seeded
// evasion produces a finding, and each legitimate adapter use of a core
// protocol type produces none.
//
// The attack list is the one run against this gate after it was built. The
// entries that got through are recorded in
// drafts/self-review/f016-protocol-branch-gate.md and named in the ceiling
// section rather than being left to be discovered.
package main

import (
	"strings"
	"testing"
)

// coreFixture is a miniature ws-core: two protocol enums plus the declared
// event seam, so the derivation path is exercised rather than stubbed.
func coreFixture() map[string]string {
	return map[string]string{
		"ws-core/src/connection.rs": "" +
			"/// Role, mirroring org.java_websocket.enums.Role.\n" +
			"#[derive(Debug, Clone, Copy, PartialEq, Eq)]\n" +
			"pub enum Role { Client, Server }\n" +
			"#[derive(Debug, Clone, Copy, PartialEq, Eq)]\n" +
			"pub enum ReadyState { NotYetConnected, Open, Closing, Closed }\n" +
			"pub type ConnectionState = ReadyState;\n",
		"ws-core/src/event.rs": "" +
			"pub enum SemanticEventKind { Text { text: String }, Binary { data: Vec<u8> } }\n",
		"ws-core/src/lib.rs": "" +
			"pub use connection::{ReadyState, Role};\npub use event::SemanticEventKind;\n",
	}
}

func adapterWith(body string) map[string]string {
	return map[string]string{
		"ws-testee/src/io_loop.rs": "use ws_core::{ReadyState, Role};\n" + body,
	}
}

// scanFixture runs the protocol-state half over a fixture pair with the
// shipped allowances suppressed: these tests assert what the DETECTOR sees, and
// the allowance reconciliation has its own tests below.
func scanFixture(t *testing.T, adapter map[string]string) []protocolBranchSite {
	t.Helper()
	governed := deriveGovernedEnums(coreFixture())
	if len(governed) == 0 {
		t.Fatal("fixture core must derive at least one governed enum")
	}
	var sites []protocolBranchSite
	for _, path := range sortedSourcePaths(adapter) {
		found, _ := findProtocolBranchSites(path, adapter[path], governed)
		sites = append(sites, found...)
	}
	return sites
}

func mustBranch(t *testing.T, name, body string) {
	t.Helper()
	if sites := scanFixture(t, adapterWith(body)); len(sites) == 0 {
		t.Errorf("%s: seeded protocol branch was NOT detected\n---\n%s", name, body)
	}
}

func mustNotBranch(t *testing.T, name, body string) {
	t.Helper()
	if sites := scanFixture(t, adapterWith(body)); len(sites) != 0 {
		t.Errorf("%s: legitimate use was flagged as a branch: %+v\n---\n%s", name, sites, body)
	}
}

// --- the seam contract ------------------------------------------------------

func TestDerivationExcludesTheDeclaredEventSeam(t *testing.T) {
	names := map[string]bool{}
	for _, enum := range deriveGovernedEnums(coreFixture()) {
		names[enum.Name] = true
	}
	for _, want := range []string{"Role", "ReadyState", "ConnectionState"} {
		if !names[want] {
			t.Errorf("governed set must contain %q derived from ws-core", want)
		}
	}
	if names["SemanticEventKind"] {
		t.Error("the declared event seam must not be governed: matching a drained event " +
			"kind is the adapter's declared job")
	}
}

func TestSeamDeclarationGoesStaleWhenItsEnumDisappears(t *testing.T) {
	core := coreFixture()
	delete(core, "ws-core/src/event.rs")
	if !hasFindingKind(checkSeamDeclarations(core), "STALE_PROTOCOL_SEAM") {
		t.Fatal("a seam declaration naming an enum that no longer exists must fail")
	}
}

func TestEmptyVocabularyFailsClosed(t *testing.T) {
	findings, _, _ := scanProtocolBranches(adapterWith(""), map[string]string{
		"ws-core/src/lib.rs": "pub struct NotAnEnum;\n",
	})
	if !hasFindingKind(findings, "PROTOCOL_VOCABULARY_EMPTY") {
		t.Fatal("deriving no protocol enums must FAIL, not pass vacuously: a silent " +
			"detector is indistinguishable from a clean tree")
	}
}

// --- the F016 probe and its variants ---------------------------------------

// Rule 1 (a governed VARIANT in a decision position) is tested through a
// scrutinee whose type is NOT annotated -- `driver.state()` rather than a
// `s: ReadyState` parameter -- so rule 2 cannot silently stand in for it. The
// first version of these fixtures used typed parameters, and disabling rule 1's
// bare-variant resolution killed no test at all.
func TestSeededProtocolBranchesAreDetected(t *testing.T) {
	for name, body := range map[string]string{
		// The exact probe from the F016 finding.
		"f016-probe": "fn p(state: ReadyState, role: Role) -> u8 {\n" +
			"    match (role, state) {\n" +
			"        (Role::Server, ReadyState::Closing) => 8,\n" +
			"        (Role::Client, ReadyState::Open) => 1,\n" +
			"        (_, ReadyState::Closed) => 0,\n        _ => 2,\n    }\n}\n",
		"equality":      "fn p(d: &D) -> bool { d.role() == Role::Server }\n",
		"inequality":    "fn p(d: &D) -> bool { d.state() != ReadyState::Open }\n",
		"reversed-oper": "fn p(d: &D) -> bool { Role::Server == d.role() }\n",
		"matches-macro": "fn p(d: &D) -> bool { matches!(d.state(), ReadyState::Closing) }\n",
		"if-let":        "fn p(d: &D) { if let ReadyState::Open = d.state() { g(); } }\n",
		"while-let":     "fn p(d: &D) { while let ReadyState::Open = d.state() { g(); } }\n",
		"match-guard": "fn p(d: &D) -> u8 " +
			"{ match d.state() { x if x == ReadyState::Open => 1, _ => 0 } }\n",
		"or-pattern": "fn p(d: &D) -> u8 " +
			"{ match d.state() { ReadyState::Open | ReadyState::Closing => 1, _ => 0 } }\n",
		"nested-in-impl": "struct A;\nimpl A {\n" +
			"    fn p(&self, d: &D) -> u8 { match d.state() { ReadyState::Open => 1, _ => 0 } }\n}\n",
		// The type alias is governed exactly like the enum it aliases.
		"type-alias-of-state": "use ws_core::ConnectionState;\n" +
			"fn p(d: &D) -> u8 { match d.state() { ConnectionState::Open => 1, _ => 0 } }\n",
		// Reached without importing the enum at all.
		"fully-qualified": "fn p(d: &D) -> u8 " +
			"{ match d.state() { ws_core::ReadyState::Open => 1, _ => 0 } }\n",
		// Renamed on import: the vocabulary follows the rename.
		"as-alias": "use ws_core::ReadyState as RS;\n" +
			"fn p(d: &D) -> u8 { match d.state() { RS::Open => 1, _ => 0 } }\n",
		// Variants imported unqualified, so no `Enum::` prefix is ever written.
		"bare-variant-import": "use ws_core::ReadyState::{Closing, Open};\n" +
			"fn p(d: &D) -> u8 { match d.state() { Open => 1, Closing => 2, _ => 0 } }\n",
		"glob-variant-import": "use ws_core::ReadyState::*;\n" +
			"fn p(d: &D) -> u8 { match d.state() { Open => 1, _ => 0 } }\n",
		"bare-variant-equality": "use ws_core::ReadyState::Closing;\n" +
			"fn p(d: &D) -> bool { d.state() == Closing }\n",
		// Renamed variant import: `Open as O`.
		"renamed-variant-import": "use ws_core::ReadyState::Open as O;\n" +
			"fn p(d: &D) -> u8 { match d.state() { O => 1, _ => 0 } }\n",
		// No variant is spelled at all: rule 2 only.
		"numeric-cast": "fn p(s: ReadyState) -> bool { if s as u8 == 2 { true } else { false } }\n",
		"grouped-cast": "fn p(s: ReadyState) -> bool { if (s as u8) == 2 { true } else { false } }\n",
		"projection-scrutinee": "fn p(r: Role) -> u8 " +
			"{ match r.wire_name() { \"server\" => 1, _ => 0 } }\n",
		// A governed-typed FIELD reached through a struct still decides.
		"field-projection": "struct R { role: Role }\n" +
			"fn p(rep: &R) -> bool { if rep.role.is_server() { true } else { false } }\n",
		// An attribute that is NOT the bare `#[cfg(test)]` stays scanned.
		"cfg-any-test-feature": "#[cfg(any(test, feature = \"x\"))]\n" +
			"fn p(d: &D) -> u8 { match d.state() { ReadyState::Open => 1, _ => 0 } }\n",
	} {
		mustBranch(t, name, body)
	}
}

// --- the separation the design constraint requires --------------------------

func TestLegitimateAdapterUseOfProtocolTypesIsNotFlagged(t *testing.T) {
	for name, body := range map[string]string{
		"pass-through":     "fn p() { let d = connection_driver(config(), Role::Client); let _ = d; }\n",
		"argument-in-call": "fn p(r: Role) { start(r, 3); }\n",
		"store-in-struct":  "struct R { role: Role }\nfn p(r: Role) -> R { R { role: r } }\n",
		"initializer":      "fn p() { let r = Role::Server; let _ = r; }\n",
		"return-value":     "fn p() -> Role { Role::Server }\n",
		"print-it":         "fn p(r: Role) { println!(\"{r:?}\"); }\n",
		"print-projection": "fn p(r: Role) -> String { format!(\"{}\", r.wire_name()) }\n",
		"array-of-states": "fn p() { for s in [ReadyState::Open, ReadyState::Closed] " +
			"{ record(s); } }\n",
		// A condition that merely PASSES protocol state to a predicate consumes
		// that predicate's answer; it does not decide from the state itself.
		"predicate-call-site": "fn p(r: Role, s: ReadyState) { if decided(r, s) { go(); } }\n",
		// Comments and strings naming variants are documentation, not code.
		"comment-mention": "// match s { ReadyState::Open => 1 }\nfn p() {}\n",
		"string-mention":  "fn p() -> &'static str { \"ReadyState::Open => 1\" }\n",
		// The declared event seam: matching a drained event kind is the job.
		"event-seam-match": "use ws_core::SemanticEventKind;\n" +
			"fn p(k: &SemanticEventKind) { match k { SemanticEventKind::Text { text } => " +
			"echo(text), _ => {} } }\n",
		// Not compiled into the shipped adapter at all.
		"cfg-test-module": "#[cfg(test)]\nmod tests {\n    use super::*;\n" +
			"    #[test]\n    fn t() { assert!(matches!(ReadyState::Open, ReadyState::Open)); }\n}\n",
	} {
		mustNotBranch(t, name, body)
	}
}

// --- allowance reconciliation ----------------------------------------------

func TestAllowanceMatchesOnFingerprintNotOnName(t *testing.T) {
	if len(protocolBranchAllowance) == 0 {
		t.Skip("no allowances declared")
	}
	entry := protocolBranchAllowance[0]
	site := protocolBranchSite{Path: entry.Path, Enclosing: entry.Enclosing,
		Fingerprint: entry.Fingerprint}
	if allowanceIndexFor(site) < 0 {
		t.Fatal("an allowance must match its own declared fingerprint")
	}
	site.Fingerprint = strings.Repeat("be", 32)
	if allowanceIndexFor(site) >= 0 {
		t.Error("an allowance must NOT reach a site whose fingerprint it does not declare: " +
			"an edited decision has to lose its ruling, not inherit it")
	}
	site.Fingerprint = entry.Fingerprint
	site.Path = "ws-testee/src/somewhere_else.rs"
	if allowanceIndexFor(site) >= 0 {
		t.Error("an allowance must not reach a different file")
	}
}

func TestEveryDeclaredAllowanceIsPinned(t *testing.T) {
	for _, entry := range protocolBranchAllowance {
		if len(entry.Fingerprint) != 64 {
			t.Errorf("allowance for %s fn %s is not pinned to a 64-hex fingerprint; an "+
				"unpinned allowance would cover any future edit of that function",
				entry.Path, entry.Enclosing)
		}
		if strings.TrimSpace(entry.Reason) == "" {
			t.Errorf("allowance for %s fn %s carries no ruling", entry.Path, entry.Enclosing)
		}
	}
}

func TestAllowanceWhoseSiteIsGoneFailsStale(t *testing.T) {
	findings := checkProtocolBranchAllowances(nil)
	if !hasFindingKind(findings, "STALE_PROTOCOL_BRANCH_ALLOWANCE") {
		t.Fatal("an allowance matching no site this run must fail: a stale allowance is a " +
			"lie about coverage")
	}
}

func TestUndeclaredSiteIsReported(t *testing.T) {
	site := protocolBranchSite{Path: "ws-testee/src/new.rs", Enclosing: "leak",
		Rule: "variant-in-pattern", Evidence: "Role::Server",
		Fingerprint: strings.Repeat("ab", 32)}
	if !hasFindingKind(checkProtocolBranchAllowances([]protocolBranchSite{site}),
		"ADAPTER_PROTOCOL_BRANCH") {
		t.Fatal("a branch with no declared allowance must be reported")
	}
}

// --- fingerprint properties -------------------------------------------------

func TestFingerprintSurvivesLayoutButNotDecisionChanges(t *testing.T) {
	governed := deriveGovernedEnums(coreFixture())
	fingerprintOf := func(body string) string {
		sites, _ := findProtocolBranchSites("a.rs",
			"use ws_core::{ReadyState, Role};\n"+body, governed)
		if len(sites) == 0 {
			t.Fatalf("no site found in:\n%s", body)
		}
		return sites[0].Fingerprint
	}
	base := fingerprintOf("fn p(r: Role) -> bool { r == Role::Server }\n")

	// Reformatting and doc edits must NOT invalidate an owner ruling.
	reformatted := fingerprintOf("/// A brand new doc comment.\nfn p(r: Role) -> bool {\n" +
		"    r\n        == Role::Server\n}\n")
	if reformatted != base {
		t.Error("a rustfmt pass or a doc edit must not move the fingerprint")
	}

	// Any change to what is DECIDED must invalidate it.
	for name, body := range map[string]string{
		"variant swapped":  "fn p(r: Role) -> bool { r == Role::Client }\n",
		"operator flipped": "fn p(r: Role) -> bool { r != Role::Server }\n",
		"arm added": "fn p(r: Role) -> bool " +
			"{ if r == Role::Server { true } else { r == Role::Client } }\n",
		"operand renamed": "fn p(role: Role) -> bool { role == Role::Server }\n",
	} {
		if fingerprintOf(body) == base {
			t.Errorf("%s: the fingerprint must move when the decision changes", name)
		}
	}
}

// A line-number pin drifts under an unrelated edit above it; a fingerprint pin
// does not. This is the property the plane-correspondence drift cost this
// project, and it is the reason the allowance is not keyed on file:line.
func TestFingerprintIsStableUnderUnrelatedEditsAbove(t *testing.T) {
	governed := deriveGovernedEnums(coreFixture())
	decision := "fn p(r: Role) -> bool { r == Role::Server }\n"
	scan := func(source string) protocolBranchSite {
		sites, _ := findProtocolBranchSites("a.rs", source, governed)
		if len(sites) != 1 {
			t.Fatalf("want exactly one site, got %d", len(sites))
		}
		return sites[0]
	}
	before := scan("use ws_core::{ReadyState, Role};\n" + decision)
	after := scan("use ws_core::{ReadyState, Role};\n" +
		"fn unrelated() {\n    let _ = 1;\n    let _ = 2;\n}\n" + decision)
	if before.Line == after.Line {
		t.Fatal("the fixture must actually move the line, or it proves nothing")
	}
	if before.Fingerprint != after.Fingerprint {
		t.Error("an unrelated edit above the decision must not invalidate its ruling")
	}
}

// A17. A verbatim copy of a ruled function into a nested module of the same
// file normalizes to the same fingerprint under the same name. Against an
// earlier draft of this gate this got a second protocol branch past at exit 0:
// the allowance matched, and nothing counted how many functions it matched.
func TestCopyOfARuledFunctionCannotInheritItsAllowance(t *testing.T) {
	if len(protocolBranchAllowance) == 0 {
		t.Skip("no allowances declared")
	}
	entry := protocolBranchAllowance[0]
	base := protocolBranchSite{Path: entry.Path, Enclosing: entry.Enclosing,
		Fingerprint: entry.Fingerprint, instance: 100}
	if hasFindingKind(checkProtocolBranchAllowances([]protocolBranchSite{base}),
		"DUPLICATE_PROTOCOL_BRANCH_ALLOWANCE") {
		t.Fatal("one ruled instance must not be reported as a duplicate")
	}
	copied := base
	copied.instance = 900 // a different function, identical text
	findings := checkProtocolBranchAllowances([]protocolBranchSite{base, copied})
	if !hasFindingKind(findings, "DUPLICATE_PROTOCOL_BRANCH_ALLOWANCE") {
		t.Fatal("a copy of a ruled decision must not inherit the ruling")
	}
}

// Two evidence rows from the SAME function (`role == Role::Server && state ==
// ReadyState::Closing` reports both operands) are one instance, not two.
func TestTwoEvidenceRowsFromOneFunctionAreOneInstance(t *testing.T) {
	if len(protocolBranchAllowance) == 0 {
		t.Skip("no allowances declared")
	}
	entry := protocolBranchAllowance[0]
	row := protocolBranchSite{Path: entry.Path, Enclosing: entry.Enclosing,
		Fingerprint: entry.Fingerprint, instance: 42}
	other := row
	other.Evidence = "ReadyState::Closing"
	if hasFindingKind(checkProtocolBranchAllowances([]protocolBranchSite{row, other}),
		"DUPLICATE_PROTOCOL_BRANCH_ALLOWANCE") {
		t.Fatal("two operands of one decision are one instance")
	}
}

// A02/A08/A09. Comparison without the comparison OPERATOR. Against an earlier
// draft `d.state().eq(&ReadyState::Closing)` got a protocol branch into shipped
// adapter code at exit 0: the variant sat in a call argument, which every other
// rule treats as a value position.
func TestComparisonWithoutAnOperatorIsStillABranch(t *testing.T) {
	for name, body := range map[string]string{
		"eq-method":       "fn p(d: &D) -> bool { d.state().eq(&ReadyState::Closing) }\n",
		"ne-method":       "fn p(d: &D) -> bool { d.role().ne(&Role::Server) }\n",
		"partial-eq-path": "fn p(d: &D) -> bool { PartialEq::eq(&d.state(), &ReadyState::Open) }\n",
		"membership": "fn p(d: &D) -> bool " +
			"{ [ReadyState::Closing, ReadyState::Closed].contains(&d.state()) }\n",
	} {
		mustBranch(t, name, body)
	}
}

// A13. A branch written inside a `macro_rules!` body has no enclosing `fn`.
// Before the fallback every such site hashed the EMPTY token span -- the
// sha256 of "" -- so two different hidden branches were indistinguishable and
// the fingerprint described nothing.
func TestBranchInAMacroBodyIsAttributedAndFingerprinted(t *testing.T) {
	governed := deriveGovernedEnums(coreFixture())
	source := "use ws_core::{ReadyState, Role};\n" +
		"macro_rules! decide {\n    ($s:expr) => { match $s { ReadyState::Closing => 8u8, _ => 0 } };\n}\n"
	sites, _ := findProtocolBranchSites("a.rs", source, governed)
	if len(sites) == 0 {
		t.Fatal("a branch inside a macro body must still be detected")
	}
	emptyHash := fingerprintTokens(nil, tokenSpan{0, 0})
	for _, site := range sites {
		if site.Fingerprint == emptyHash {
			t.Error("a site with no enclosing fn must not hash the empty span")
		}
		if site.Enclosing != "macro_rules!decide" {
			t.Errorf("want the macro named as the enclosing item, got %q", site.Enclosing)
		}
	}
}

// A variant used inside a condition without being an operand, a pattern, or a
// call argument -- indexing a table by protocol state still decides from it.
func TestVariantUsedInAConditionWithoutAnOperatorIsABranch(t *testing.T) {
	for name, body := range map[string]string{
		"index-by-state":  "fn p(t: &[bool]) -> bool { if t[ReadyState::Open as usize] { true } else { false } }\n",
		"index-by-role":   "fn p(t: &[bool]) { while t[Role::Server as usize] { g(); } }\n",
		"scrutinee-index": "fn p(t: &[u8]) -> u8 { match t[Role::Client as usize] { 0 => 1, _ => 0 } }\n",
	} {
		mustBranch(t, name, body)
	}
}

// A site with no enclosing `fn` and no enclosing `macro_rules!` must still get
// a fingerprint that describes something. Before the fallback it hashed the
// EMPTY span, so every such site shared one constant.
func TestSiteWithNoEnclosingItemStillFingerprints(t *testing.T) {
	governed := deriveGovernedEnums(coreFixture())
	sites, _ := findProtocolBranchSites("a.rs",
		"use ws_core::{ReadyState, Role};\n"+
			"const READY: bool = matches!(ReadyState::Open, ReadyState::Open);\n", governed)
	if len(sites) == 0 {
		t.Fatal("a branch in a const initializer must still be detected")
	}
	empty := fingerprintTokens(nil, tokenSpan{0, 0})
	for _, site := range sites {
		if site.Fingerprint == empty {
			t.Errorf("site %+v hashed the empty span", site)
		}
	}
}

// --- disclosed ceilings -----------------------------------------------------
//
// These are the attacks that got a protocol branch past this gate and are NOT
// closed. They are pinned as tests so the disclosure in
// drafts/self-review/f016-protocol-branch-gate.md cannot silently drift from
// what the detector actually does: if a later change closes one of these, this
// test fails and the disclosure has to be rewritten rather than left stale.
//
// Each shares one root cause: this is a token-level scan with NO type
// inference. It knows a value is protocol state only when a governed variant is
// spelled out, or when a binding was annotated with a governed type IN THE SAME
// FILE. Break either link and the value becomes opaque.
func TestDisclosedCeilings(t *testing.T) {
	for name, body := range map[string]string{
		// A10. The cast leaves the condition; the condition sees only an integer.
		"two-step-numeric-cast": "fn p(s: ReadyState) -> u8 " +
			"{ let n = s as u8; if n == 2 { 8 } else { 0 } }\n",
		// A11. The projection leaves the condition; the condition sees a &str.
		"two-step-projection": "fn p(r: Role) -> u8 " +
			"{ let name = r.wire_name(); if name == \"server\" { 8 } else { 0 } }\n",
		// A12. The binding is named only INSIDE a string literal, and string
		// contents are collapsed to one token so a `=>` in a string cannot
		// invent match arms.
		"debug-format-capture": "fn p(state: ReadyState) -> u8 " +
			"{ if format!(\"{state:?}\") == \"Closing\" { 8 } else { 0 } }\n",
		// The `isCall` guard: a METHOD whose name collides with a governed
		// binding is not assumed to return protocol state. Detecting it would
		// need the method's return type, which a token scan does not have.
		// A METHOD whose name collides with a governed FIELD declared in the
		// same file is not assumed to return protocol state. Deciding that
		// would need the method's return type, which a token scan does not
		// have -- and assuming it would flag `driver.state()` in the shipped
		// adapter purely because some struct there has a `state:` field.
		"method-name-collides-with-governed-field": "struct R { state: ReadyState }\n" +
			"fn p(d: &D) -> bool { if d.state().is_open() { true } else { false } }\n",
	} {
		if sites := scanFixture(t, adapterWith(body)); len(sites) != 0 {
			t.Errorf("%s: this ceiling is now CLOSED (%d sites). That is an improvement, "+
				"but the disclosure in drafts/self-review/f016-protocol-branch-gate.md "+
				"now overstates the limitation and must be updated.", name, len(sites))
		}
	}
}

// The gate scans rust/ws-testee/src only. A protocol branch moved into
// ws-driver or ws-core is outside what "adapter-side" means and outside what
// this gate reads; nothing here would see it.
func TestDisclosedCeilingScopeIsTheAdapterCrateOnly(t *testing.T) {
	governed := deriveGovernedEnums(coreFixture())
	sites, _ := findProtocolBranchSites("ws-driver/src/lib.rs",
		"use ws_core::{ReadyState, Role};\n"+
			"pub fn policy(r: Role, s: ReadyState) -> u8 "+
			"{ match (r, s) { (Role::Server, ReadyState::Closing) => 8, _ => 0 } }\n", governed)
	if len(sites) == 0 {
		t.Fatal("the RULE itself must fire on this shape; only the gate's file SCOPE " +
			"excludes it, and that distinction is what the disclosure rests on")
	}
}
