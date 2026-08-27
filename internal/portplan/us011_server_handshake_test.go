package portplan

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestUS011UsesConcreteEvidenceWithoutPromotingCutover(t *testing.T) {
	root := t.TempDir()
	server := filepath.Join(root, "rust/connection-core/src/handshake/server.rs")
	if err := os.MkdirAll(filepath.Dir(server), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(server, []byte("source-bound only"), 0o600); err != nil {
		t.Fatal(err)
	}
	request := DeriveRequest{Root: root, ToolchainRoot: root}

	compatibility := buildCompatibilitySurface(request)
	for _, item := range compatibility.Items {
		if item.SurfaceID == "surface.handshake.server-response" &&
			!slices.Equal(item.EvidenceObligationIDs, []string{"evidence.us-011-server-handshake"}) {
			t.Fatalf("US-011 compatibility evidence = %v", item.EvidenceObligationIDs)
		}
	}
	cutover := buildCutoverContract(request)
	for _, obligation := range cutover.Obligations {
		if obligation.ID == "cutover.surface-handshake-server-response" &&
			(obligation.Status != "DECLARED" || len(obligation.EvidenceIDs) != 0) {
			t.Fatalf("source existence promoted cutover: %+v", obligation)
		}
	}
	if got := evidenceObligationIDs("US-011"); !slices.Equal(got, []string{"evidence.us-011-server-handshake"}) {
		t.Fatalf("US-011 evidence IDs = %v", got)
	}
}

func TestUS011ReconcilesStaleServerBuilderNamesWithoutAliases(t *testing.T) {
	want := map[string]string{
		"org.java_websocket.handshake.ServerHandshake":        "websocket_core::ServerRequestDescriptor",
		"org.java_websocket.handshake.ServerHandshakeBuilder": "websocket_core::ServerRequestDescriptor",
		"org.java_websocket.handshake.HandshakeImpl1Server":   "websocket_core::ServerRequestDescriptor",
	}
	for javaID, rustID := range want {
		if got := us011SourceBoundRustIdentities[javaID]; got != rustID {
			t.Fatalf("%s reconciles to %q, want %q", javaID, got, rustID)
		}
	}
	for _, stale := range []string{
		"ws_core::handshake::server::ServerHandshake",
		"ws_core::handshake::server::ServerHandshakeBuilder",
		"ws_core::handshake::server::HandshakeImpl1Server",
	} {
		if slices.Contains([]string{
			us011SourceBoundRustIdentities["org.java_websocket.handshake.ServerHandshake"],
			us011SourceBoundRustIdentities["org.java_websocket.handshake.ServerHandshakeBuilder"],
			us011SourceBoundRustIdentities["org.java_websocket.handshake.HandshakeImpl1Server"],
		}, stale) {
			t.Fatalf("fabricated compatibility identity survived: %s", stale)
		}
	}
}
