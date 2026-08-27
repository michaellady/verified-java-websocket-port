package portplan

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestUS010UsesOnlyConcreteEvidenceAndCutoverCannotPromoteFromSourceExistence(t *testing.T) {
	root := t.TempDir()
	client := filepath.Join(root, "rust/connection-core/src/handshake/client.rs")
	if err := os.MkdirAll(filepath.Dir(client), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(client, []byte("present but not cutover evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	request := DeriveRequest{Root: root, ToolchainRoot: root}

	compatibility := buildCompatibilitySurface(request)
	for _, item := range compatibility.Items {
		if item.SurfaceID != "surface.handshake.client-request" {
			continue
		}
		if !slices.Equal(item.EvidenceObligationIDs, []string{"evidence.us-010-client-handshake"}) {
			t.Fatalf("US-010 compatibility evidence = %v", item.EvidenceObligationIDs)
		}
	}
	cutover := buildCutoverContract(request)
	for _, obligation := range cutover.Obligations {
		if obligation.ID != "cutover.surface-handshake-client-request" {
			continue
		}
		if obligation.Status != "DECLARED" || len(obligation.EvidenceIDs) != 0 {
			t.Fatalf("source existence promoted cutover: %+v", obligation)
		}
	}
	if got := evidenceObligationIDs("US-010"); !slices.Equal(got, []string{"evidence.us-010-client-handshake"}) {
		t.Fatalf("US-010 evidence IDs = %v", got)
	}
}
