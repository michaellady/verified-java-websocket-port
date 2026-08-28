package linkage

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// cargoWorkspaceMembers parses the workspace member list from rust/Cargo.toml
// independently of the resolver, so the scan-scope assertion cannot be
// satisfied by the implementation quoting itself.
func cargoWorkspaceMembers(t *testing.T, root string) []string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(root, "rust", "Cargo.toml"))
	if err != nil {
		t.Fatalf("read rust/Cargo.toml: %v", err)
	}
	match := regexp.MustCompile(`(?m)^members\s*=\s*\[([^\]]*)\]`).FindSubmatch(content)
	if match == nil {
		t.Fatal("rust/Cargo.toml has no workspace members list")
	}
	names := regexp.MustCompile(`"([^"]+)"`).FindAllSubmatch(match[1], -1)
	if len(names) == 0 {
		t.Fatal("workspace members list is empty")
	}
	members := make([]string, 0, len(names))
	for _, name := range names {
		members = append(members, string(name[1]))
	}
	return members
}

// TestReviewRound2CorrectionsHold pins the three blocking corrections from
// review session 01a04566-bccd-7851-8582-3379eca41bd5:
//
//  1. sym.allocation.check-alloc must bind the actual pre-allocation guard —
//     the header-time declared-length gate in Draft6455::decode_frame_header
//     — and must NOT conflate it with the reassembly-time cumulative gate
//     check_buffer_limit (the frozen target distinguishes checkAlloc from
//     checkBufferLimit).
//  2. sym.connection.open must bind ConnectionCore::finish_handshake_open,
//     the declaration that actually sets ReadyState::Open.
//  3. The capability-exclusion scan must cover the src tree of every
//     workspace member listed in rust/Cargo.toml, so its workspace-wide
//     absence claim and the drift gate genuinely cover their stated scope.
func TestReviewRound2CorrectionsHold(t *testing.T) {
	root := repoRoot(t)

	checkAlloc, exists := proofTargetSymbolBindings["sym.allocation.check-alloc"]
	if !exists {
		t.Fatal("sym.allocation.check-alloc has no binding")
	}
	boundDecode := false
	for _, symbol := range checkAlloc.Symbols {
		if symbol == "ws_core::framing::Draft6455::check_buffer_limit" {
			t.Fatal("sym.allocation.check-alloc conflates checkAlloc with the reassembly gate check_buffer_limit")
		}
		if symbol == "ws_core::framing::Draft6455::decode_frame_header" {
			boundDecode = true
		}
	}
	if !boundDecode {
		t.Fatal("sym.allocation.check-alloc does not bind the pre-allocation guard Draft6455::decode_frame_header")
	}

	open, exists := proofTargetSymbolBindings["sym.connection.open"]
	if !exists {
		t.Fatal("sym.connection.open has no binding")
	}
	boundFinish := false
	for _, symbol := range open.Symbols {
		if symbol == "ws_core::connection::ConnectionCore::finish_handshake_open" {
			boundFinish = true
		}
	}
	if !boundFinish {
		t.Fatal("sym.connection.open does not bind ConnectionCore::finish_handshake_open (the ReadyState::Open transition site)")
	}
	resolved, err := resolveSymbol(root, "ws_core::connection::ConnectionCore::finish_handshake_open")
	if err != nil {
		t.Fatalf("finish_handshake_open does not resolve against the tree: %v", err)
	}
	if resolved.File != "rust/ws-core/src/connection.rs" {
		t.Fatalf("finish_handshake_open resolved in unexpected file %s", resolved.File)
	}

	scanned, err := workspaceSourceDirs(root)
	if err != nil {
		t.Fatalf("workspace source dirs: %v", err)
	}
	scannedSet := map[string]bool{}
	for _, dir := range scanned {
		scannedSet[dir] = true
	}
	members := cargoWorkspaceMembers(t, root)
	if len(members) < 5 {
		t.Fatalf("expected at least 5 workspace members, got %v", members)
	}
	for _, member := range members {
		expected := "rust/" + member + "/src"
		if !scannedSet[expected] {
			t.Fatalf("exclusion scan omits workspace member source dir %s (scans %v)", expected, scanned)
		}
	}
}

// ac2TypedSymbols are the three US-017 AC2 typed behaviours the pre-landing
// review's round-2 mapping.go finding named as missing from the exact
// linkage, each with the exact declaration text a deletion would remove.
var ac2TypedSymbols = []struct {
	rustPath string
	file     string
	declared string
	deleted  string
}{
	{
		rustPath: "ws_driver::DroppedWrites",
		file:     "rust/ws-driver/src/lib.rs",
		declared: "pub struct DroppedWrites {",
		deleted:  "pub struct SomethingElseEntirely {",
	},
	{
		rustPath: "ws_driver::DriverOutput::WritesDropped",
		file:     "rust/ws-driver/src/lib.rs",
		declared: "\n    WritesDropped(DroppedWrites),",
		deleted:  "\n    SomethingElseEntirely(DroppedWrites),",
	},
	{
		rustPath: "ws_core::connection::CommandRefusalReason::ReceiverDropped",
		file:     "rust/ws-core/src/connection.rs",
		declared: "\n    ReceiverDropped,",
		deleted:  "\n    SomethingElseEntirely,",
	},
}

// TestTheAC2TypedSymbolsAreBoundToUS017 pins the binding itself: the three
// symbols must be US-017 story symbols and must be in the resolver catalog,
// so removing an EDGE (rather than a declaration) is caught too.
func TestTheAC2TypedSymbolsAreBoundToUS017(t *testing.T) {
	bound := map[string]bool{}
	for _, symbol := range storySymbols["US-017"] {
		bound[symbol] = true
	}
	for _, symbol := range ac2TypedSymbols {
		if !bound[symbol.rustPath] {
			t.Fatalf("US-017 does not bind AC2 typed symbol %s; sanctioned regeneration could accept its removal", symbol.rustPath)
		}
		if _, known := symbolCatalog[symbol.rustPath]; !known {
			t.Fatalf("AC2 typed symbol %s has no catalog specification", symbol.rustPath)
		}
	}
}

// TestDeletingAnAC2TypedSymbolFailsTheLinkageGate is the DELETION-SENSITIVE
// polarity: a green gate with the symbols present proves nothing, so each
// declaration is actually removed from an isolated copy of the derivation
// inputs and both the drift gate (Verify) and the SANCTIONED regeneration
// path (WriteArtifacts) must refuse. Before the round-2 mapping.go fix the
// three symbols were absent from the exact linkage entirely, so deleting any
// of them left every linkage check green.
func TestDeletingAnAC2TypedSymbolFailsTheLinkageGate(t *testing.T) {
	root := repoRoot(t)
	isolated := t.TempDir()
	for _, relative := range derivationInputPaths(t, root) {
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatalf("read %s: %v", relative, err)
		}
		target := filepath.Join(isolated, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(target, content, 0o644); err != nil {
			t.Fatalf("write %s: %v", relative, err)
		}
	}
	if err := WriteArtifacts(isolated); err != nil {
		t.Fatalf("write artifacts into the isolated copy: %v", err)
	}
	if findings := Verify(isolated); len(findings) != 0 {
		t.Fatalf("the isolated copy must verify clean before any deletion, got %v", findings)
	}

	for _, symbol := range ac2TypedSymbols {
		target := filepath.Join(isolated, filepath.FromSlash(symbol.file))
		pristine, err := os.ReadFile(target)
		if err != nil {
			t.Fatalf("read %s: %v", symbol.file, err)
		}
		if !strings.Contains(string(pristine), symbol.declared) {
			t.Fatalf("%s no longer declares %q as written; the polarity probe is stale",
				symbol.file, symbol.declared)
		}
		mutated := strings.Replace(string(pristine), symbol.declared, symbol.deleted, 1)
		if err := os.WriteFile(target, []byte(mutated), 0o644); err != nil {
			t.Fatalf("delete %s: %v", symbol.rustPath, err)
		}

		findings := Verify(isolated)
		refused := false
		for _, finding := range findings {
			if strings.HasPrefix(finding, "LINKAGE_DERIVATION_FAILED") && strings.Contains(finding, symbol.rustPath) {
				refused = true
			}
		}
		if !refused {
			t.Fatalf("deleting %s left the gate reporting %v; the linkage does not discriminate on it",
				symbol.rustPath, findings)
		}
		// The sanctioned regeneration path must refuse the same deletion,
		// otherwise LINKAGE_REGENERATE=1 would launder the removal into a
		// freshly "verified" artifact.
		if err := WriteArtifacts(isolated); err == nil {
			t.Fatalf("sanctioned regeneration accepted the removal of %s", symbol.rustPath)
		} else if !strings.Contains(err.Error(), symbol.rustPath) {
			t.Fatalf("regeneration refused %s with an unrelated error: %v", symbol.rustPath, err)
		}

		if err := os.WriteFile(target, pristine, 0o644); err != nil {
			t.Fatalf("restore %s: %v", symbol.file, err)
		}
		if findings := Verify(isolated); len(findings) != 0 {
			t.Fatalf("restoring %s must return the copy to clean, got %v", symbol.rustPath, findings)
		}
	}
}
