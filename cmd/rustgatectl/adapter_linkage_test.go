// Polarity tests for the US-018 adapter-linkage architecture gate.
//
// AC3: "A linkage test proves the adapters call the exact shipped
// core/driver symbols and a seeded adapter-side parser or protocol branch
// fails the architecture gate." Every mechanical decision is proven in BOTH
// directions: the conforming adapter shape passes with zero findings, and
// each seeded hostile fixture receives its exact typed finding.
//
// Typed-finding vocabulary and the role-scoped gate design are adopted with
// attribution from the Codex-plane US-018 rustgate extension (codex-import
// b7146dd/9cd886c): ADAPTER_LINKAGE_MISSING, ADAPTER_PROTOCOL_SURFACE,
// ADAPTER_PROTOCOL_BRANCH, ADAPTER_DEPENDENCY_NOT_ALLOWED. The scan itself
// is reimplemented on this plane's comment/string-aware tokenizer so doc
// comments naming core types (which the shipped adapter legitimately has)
// never trip the gate.
package main

import (
	"strings"
	"testing"
)

// cleanAdapterSources mirrors the shipped rust/ws-testee/src shape: doc
// comments may NAME core types, production code calls only the shipped
// driver seams.
func cleanAdapterSources() map[string]string {
	return map[string]string{
		"src/lib.rs": "//! Protocol truth stays in [`ws_core::ConnectionCore`].\n" +
			"#![forbid(unsafe_code)]\npub mod client;\n",
		"src/client.rs": "use ws_driver::connection_driver;\n" +
			"pub fn run() {\n" +
			"    let (sender, mut driver) = connection_driver(config(), Role::Client);\n" +
			"    driver.begin_client_handshake(\"/chat\", \"localhost\").unwrap();\n" +
			"    let result = driver.poll(DriverInput::Wake);\n" +
			"    let _ = (sender, result);\n}\n",
	}
}

func TestScanAdapterSourcesCleanShapePasses(t *testing.T) {
	findings := scanAdapterSources(cleanAdapterSources())
	if len(findings) != 0 {
		t.Fatalf("clean adapter shape must produce zero findings, got %v", findings)
	}
}

func TestScanAdapterSourcesSeededParserBranchFails(t *testing.T) {
	sources := cleanAdapterSources()
	// The canonical seeded canary from the AC: a byte-index plus
	// opcode-bitmask branch in adapter production code.
	sources["src/io_loop.rs"] = "pub fn peek(bytes: &[u8]) -> u8 {\n" +
		"    let opcode = bytes[0] & 0x0f;\n" +
		"    if opcode == 0x8 { return 1; }\n    opcode\n}\n"
	findings := scanAdapterSources(sources)
	if !hasFindingKind(findings, "ADAPTER_PROTOCOL_BRANCH") {
		t.Fatalf("seeded opcode-bitmask branch must fail with ADAPTER_PROTOCOL_BRANCH, got %v", findings)
	}
}

func TestScanAdapterSourcesSeededWireLiteralFails(t *testing.T) {
	for name, snippet := range map[string]string{
		"sec-websocket-header": "pub fn h() -> &'static str { \"Sec-WebSocket-Key\" }\n",
		"http-status-line":     "pub fn h() -> &'static str { \"HTTP/1.1 101\" }\n",
		"payload-len-mask":     "pub fn l(b: u8) -> u8 { b & 0x7f }\n",
	} {
		sources := cleanAdapterSources()
		sources["src/seeded.rs"] = snippet
		findings := scanAdapterSources(sources)
		if !hasFindingKind(findings, "ADAPTER_PROTOCOL_BRANCH") {
			t.Errorf("%s: seeded wire literal/branch must fail with ADAPTER_PROTOCOL_BRANCH, got %v", name, findings)
		}
	}
}

func TestScanAdapterSourcesSeededProtocolSurfaceFails(t *testing.T) {
	for name, snippet := range map[string]string{
		"core-construction": "pub fn c() { let core = ws_core::ConnectionCore::new(config(), Role::Client); let _ = core; }\n",
		"frame-header":      "use ws_core::framing::FrameHeader;\npub fn f(h: FrameHeader) { let _ = h; }\n",
		"masking-helper":    "pub fn m(p: &mut [u8]) { ws_core::framing::Draft6455::apply_mask(p, [0; 4]); }\n",
		"handshake-module":  "use ws_core::handshake::HandshakeLimits;\npub fn f(l: HandshakeLimits) { let _ = l; }\n",
	} {
		sources := cleanAdapterSources()
		sources["src/seeded.rs"] = snippet
		findings := scanAdapterSources(sources)
		if !hasFindingKind(findings, "ADAPTER_PROTOCOL_SURFACE") {
			t.Errorf("%s: seeded protocol surface must fail with ADAPTER_PROTOCOL_SURFACE, got %v", name, findings)
		}
	}
}

func TestScanAdapterSourcesCommentAndStringMentionsDoNotTrip(t *testing.T) {
	sources := cleanAdapterSources()
	sources["src/docs.rs"] = "//! `ConnectionCore` owns framing; `FrameHeader` and\n" +
		"//! `Sec-WebSocket-Accept` never appear in adapter code.\n" +
		"/* apply_mask and bytes[0] & 0x0f belong to the core. */\n" +
		"pub fn nothing() {}\n"
	findings := scanAdapterSources(sources)
	if len(findings) != 0 {
		t.Fatalf("comment mentions must not trip the scan, got %v", findings)
	}
}

func TestScanAdapterSourcesMissingLinkageFails(t *testing.T) {
	// An adapter tree that never constructs the shipped driver or polls it
	// cannot prove it drives the exact shipped seams.
	sources := map[string]string{
		"src/lib.rs":    "#![forbid(unsafe_code)]\npub mod client;\n",
		"src/client.rs": "pub fn run() { /* hand-rolled socket loop, no driver */ }\n",
	}
	findings := scanAdapterSources(sources)
	if !hasFindingKind(findings, "ADAPTER_LINKAGE_MISSING") {
		t.Fatalf("adapter without connection_driver/poll linkage must fail, got %v", findings)
	}
}

func TestScanAdapterSourcesPollAloneIsNotEnough(t *testing.T) {
	sources := map[string]string{
		"src/lib.rs": "pub fn run(d: &mut ws_driver::ConnectionDriver) { let _ = d.poll(ws_driver::DriverInput::Wake); }\n",
	}
	findings := scanAdapterSources(sources)
	if !hasFindingKind(findings, "ADAPTER_LINKAGE_MISSING") {
		t.Fatalf("poll without connection_driver construction must still fail, got %v", findings)
	}
}

// --- dependency-edge checks -------------------------------------------------

func adapterEdgePackages(testeeDeps, driverDeps []cargoDependency) []cargoPackage {
	return []cargoPackage{
		{ID: "ws-core-id", Name: "ws-core"},
		{ID: "ws-driver-id", Name: "ws-driver", Dependencies: driverDeps},
		{ID: "ws-testee-id", Name: "ws-testee", Dependencies: testeeDeps},
	}
}

func pathDep(name string) cargoDependency {
	path := "/x/" + name
	return cargoDependency{Name: name, Path: &path}
}

func TestCheckAdapterEdgesExactShapePasses(t *testing.T) {
	pkgs := adapterEdgePackages(
		[]cargoDependency{pathDep("ws-core"), pathDep("ws-driver")},
		[]cargoDependency{pathDep("ws-core")},
	)
	findings := checkAdapterEdges(pkgs)
	if len(findings) != 0 {
		t.Fatalf("exact local path edges must pass, got %v", findings)
	}
}

func TestCheckAdapterEdgesMissingDriverEdgeFails(t *testing.T) {
	pkgs := adapterEdgePackages(
		[]cargoDependency{pathDep("ws-core")},
		[]cargoDependency{pathDep("ws-core")},
	)
	findings := checkAdapterEdges(pkgs)
	if !hasFindingKind(findings, "ADAPTER_LINKAGE_MISSING") {
		t.Fatalf("missing ws-driver edge must fail with ADAPTER_LINKAGE_MISSING, got %v", findings)
	}
}

func TestCheckAdapterEdgesExternalDependencyFails(t *testing.T) {
	external := cargoDependency{Name: "tokio"} // no Path: registry dep
	pkgs := adapterEdgePackages(
		[]cargoDependency{pathDep("ws-core"), pathDep("ws-driver"), external},
		[]cargoDependency{pathDep("ws-core")},
	)
	findings := checkAdapterEdges(pkgs)
	if !hasFindingKind(findings, "ADAPTER_DEPENDENCY_NOT_ALLOWED") {
		t.Fatalf("external adapter dependency must fail, got %v", findings)
	}
}

func TestCheckAdapterEdgesMissingPackageFails(t *testing.T) {
	pkgs := []cargoPackage{{ID: "ws-core-id", Name: "ws-core"}}
	findings := checkAdapterEdges(pkgs)
	if !hasFindingKind(findings, "ADAPTER_LINKAGE_MISSING") {
		t.Fatalf("absent adapter package must fail closed, got %v", findings)
	}
}

// --- helpers ----------------------------------------------------------------

func hasFindingKind(findings []adapterFinding, kind string) bool {
	for _, f := range findings {
		if f.Kind == kind {
			return true
		}
	}
	return false
}

func TestStripRustCommentsKeepsCodeAndStrings(t *testing.T) {
	// Comments are documentation and never trip the scan; string literals
	// are runtime behavior (a wire literal in a string IS the canary) and
	// must survive. A `//` inside a string is not a comment start.
	source := "//! doc ConnectionCore\n/* block FrameHeader */\n" +
		"let s = \"Sec-WebSocket\"; let u = \"http://x\"; let r = r#\"HTTP/1.1\"#;\n" +
		"let opcode = bytes[0] & 0x0f;\n"
	stripped := stripRustComments(source)
	for _, gone := range []string{"ConnectionCore", "FrameHeader"} {
		if strings.Contains(stripped, gone) {
			t.Errorf("comment content %q must be stripped", gone)
		}
	}
	for _, kept := range []string{"Sec-WebSocket", "HTTP/1.1", "& 0x0f", "http://x"} {
		if !strings.Contains(stripped, kept) {
			t.Errorf("code/string content %q must survive the strip; got %q", kept, stripped)
		}
	}
}
