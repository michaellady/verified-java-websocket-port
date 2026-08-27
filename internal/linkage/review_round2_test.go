package linkage

import (
	"os"
	"path/filepath"
	"regexp"
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
