package portplan

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestUS012UsesConcreteEvidenceWithoutPromotingCutover(t *testing.T) {
	wantSurfaces := map[string]bool{
		"surface.framing.frame-octets":  false,
		"surface.framing.masking":       false,
		"surface.errors.protocol-fault": false,
		"surface.limits.allocation":     false,
	}
	wantEvidence := []string{"evidence.us-012-frame-codec"}
	for _, item := range buildCompatibilitySurface(DeriveRequest{}).Items {
		if _, wanted := wantSurfaces[item.SurfaceID]; !wanted {
			continue
		}
		if !slices.Equal(item.EvidenceObligationIDs, wantEvidence) {
			t.Errorf("%s evidence = %v, want %v", item.SurfaceID, item.EvidenceObligationIDs, wantEvidence)
		}
		wantSurfaces[item.SurfaceID] = true
	}
	for surface, found := range wantSurfaces {
		if !found {
			t.Errorf("US-012 compatibility surface missing: %s", surface)
		}
	}

	for _, obligation := range buildCutoverContract(DeriveRequest{}).Obligations {
		if _, wanted := wantSurfaces[obligation.SurfaceID]; !wanted {
			continue
		}
		if obligation.Status != "DECLARED" || len(obligation.EvidenceIDs) != 0 {
			t.Errorf("US-012 evidence promoted cutover: %+v", obligation)
		}
	}
	if got := evidenceObligationIDs("US-012"); !slices.Equal(got, wantEvidence) {
		t.Fatalf("US-012 evidence IDs = %v, want %v", got, wantEvidence)
	}
}

func TestUS012DeclaresShippedFrameModuleAndSourceBoundIdentities(t *testing.T) {
	var framing *PortSlice
	for index := range PortSlices {
		if PortSlices[index].ID == "slice.framing" {
			framing = &PortSlices[index]
			break
		}
	}
	if framing == nil || framing.RustModule != "websocket_core::frame" {
		t.Fatalf("slice.framing = %+v, want shipped websocket_core::frame module", framing)
	}

	want := map[string]string{
		"org.java_websocket.drafts.Draft_6455$TranslatedPayloadMetaData": "websocket_core::frame::decode::FrameHeader",
		"org.java_websocket.enums.Opcode":                                "websocket_core::frame::Opcode",
		"org.java_websocket.exceptions.IncompleteException":              "websocket_core::frame::decode::FrameHeaderDecode",
		"org.java_websocket.exceptions.InvalidFrameException":            "websocket_core::FrameFailure",
		"org.java_websocket.exceptions.LimitExceededException":           "websocket_core::FailureKind",
		"org.java_websocket.exceptions.NotSendableException":             "websocket_core::FrameFailure",
		"org.java_websocket.framing.ControlFrame":                        "websocket_core::frame::Frame",
		"org.java_websocket.framing.DataFrame":                           "websocket_core::frame::Frame",
		"org.java_websocket.framing.Framedata":                           "websocket_core::frame::Frame",
		"org.java_websocket.framing.FramedataImpl1":                      "websocket_core::frame::Frame",
		"org.java_websocket.util.ByteBufferUtils":                        "websocket_core::frame::Frame",
	}
	if len(us012SourceBoundRustIdentities) != len(want) {
		t.Fatalf("US-012 source-bound identity count = %d, want %d", len(us012SourceBoundRustIdentities), len(want))
	}
	for javaID, rustID := range want {
		if got := us012SourceBoundRustIdentities[javaID]; got != rustID {
			t.Errorf("%s maps to %q, want %q", javaID, got, rustID)
		}
	}
}

func TestUS012MigrationOverlayIsNarrowAndResolverUnverified(t *testing.T) {
	root := t.TempDir()
	codec := filepath.Join(root, "rust/connection-core/src/frame/mod.rs")
	if err := os.MkdirAll(filepath.Dir(codec), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(codec, []byte("source-bound only"), 0o600); err != nil {
		t.Fatal(err)
	}

	declarations := make([]OracleDeclaration, 0, len(us012SourceBoundRustIdentities))
	for javaID := range us012SourceBoundRustIdentities {
		declarations = append(declarations, OracleDeclaration{
			Kind:            "CLASS",
			OwnerBinaryName: javaID,
			Descriptor:      "L" + javaID + ";",
			File:            "source.java",
			Line:            1,
			InStudySurface:  true,
		})
	}
	migration, err := buildMigrationMap(OracleOutput{Declarations: declarations}, DeriveRequest{
		Root: root, ToolchainRoot: root, SourceCommit: "source",
	}, map[string]bool{"source.java": true})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range migration.Rows {
		if row.RustSemanticID != us012SourceBoundRustIdentities[row.JavaSemanticID] {
			t.Errorf("%s derived %q, want %q", row.JavaSemanticID, row.RustSemanticID, us012SourceBoundRustIdentities[row.JavaSemanticID])
		}
		if row.RustIdentityVerified {
			t.Errorf("source-bound identity fabricated resolver verification: %s", row.JavaSemanticID)
		}
	}

	for _, shared := range []string{
		"org.java_websocket.WebSocketImpl",
		"org.java_websocket.drafts.Draft",
		"org.java_websocket.drafts.Draft_6455",
		"org.java_websocket.exceptions.InvalidDataException",
	} {
		if _, overlaid := us012SourceBoundRustIdentities[shared]; overlaid {
			t.Errorf("US-012 row-wide overlay includes shared type %s", shared)
		}
	}
}
