package portplan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Round 2, item 2: cardinality is derived and restated exactly.
// ---------------------------------------------------------------------------

// TestBindingAndSeamCardinality freezes the true cardinality: one dossier seam per
// (type, slice) binding, plus exactly one byte-channel context seam.
func TestBindingAndSeamCardinality(t *testing.T) {
	migration := loadMigration(t, repoRoot)
	dossier := loadDossier(t, repoRoot)
	bindings := 0
	for _, row := range migration.Rows {
		bindings += len(row.PortSlices)
	}
	if bindings != 90 {
		t.Fatalf("migration map holds %d (type,slice) bindings, the frozen count is 90", bindings)
	}
	if len(dossier.Seams) != bindings+1 {
		t.Fatalf("dossier holds %d seams for %d bindings; must be bindings+1 (the byte-channel"+
			" context seam), i.e. %d total", len(dossier.Seams), bindings, bindings+1)
	}
	contextSeams := 0
	for _, seam := range dossier.Seams {
		if seam.SurfaceID == "seam.adapter.byte-channel-context" {
			contextSeams++
		}
	}
	if contextSeams != 1 {
		t.Fatalf("exactly one byte-channel context seam expected, found %d", contextSeams)
	}
}

func TestManifestStatesTheDerivedCardinality(t *testing.T) {
	var manifest IntakeManifest
	loadDocument(t, repoRoot, ManifestDocument, &manifest)
	joined := strings.Join(manifest.HonestyNotes, " | ")
	if !strings.Contains(joined, "90 (type,slice) bindings") ||
		!strings.Contains(joined, "91 seams") {
		t.Fatalf("the manifest must state the true cardinality (90 bindings, 91 seams total"+
			" including the byte-channel context seam); notes: %q", joined)
	}
}

// The new binding relationships are load-bearing: dropping any of them must fail verification.
func TestValidatorFailsWhenAdapterStoryLosesListenerBinding(t *testing.T) {
	report := mutate(t, MigrationMapDocument, func(document map[string]any) {
		dropBinding(document["rows"].([]any),
			"org.java_websocket.WebSocketListener", "slice.tcp-adapter")
	})
	requireFinding(t, report, FindingStoryCoverageGap)
}

func TestValidatorFailsWhenHandshakeLosesAdapterCallbacks(t *testing.T) {
	report := mutate(t, MigrationMapDocument, func(document map[string]any) {
		dropBinding(document["rows"].([]any),
			"org.java_websocket.WebSocketAdapter", "slice.client-handshake")
	})
	requireFinding(t, report, FindingStoryCoverageGap)
}

func TestValidatorFailsWhenFragmentationLosesDraftContinuousFrame(t *testing.T) {
	report := mutate(t, MigrationMapDocument, func(document map[string]any) {
		dropBinding(document["rows"].([]any),
			"org.java_websocket.drafts.Draft", "slice.fragmentation")
	})
	requireFinding(t, report, FindingStoryCoverageGap)
}

func TestValidatorFailsWhenHandshakeLosesInvalidDataRejection(t *testing.T) {
	report := mutate(t, MigrationMapDocument, func(document map[string]any) {
		dropBinding(document["rows"].([]any),
			"org.java_websocket.exceptions.InvalidDataException", "slice.server-handshake")
	})
	requireFinding(t, report, FindingStoryCoverageGap)
}

func TestValidatorFailsWhenFragmentationLosesSendFragmentedFrame(t *testing.T) {
	report := mutate(t, MigrationMapDocument, func(document map[string]any) {
		dropBinding(document["rows"].([]any),
			"org.java_websocket.WebSocket", "slice.fragmentation")
	})
	requireFinding(t, report, FindingStoryCoverageGap)
}

// ---------------------------------------------------------------------------
// Round 2, item 3: the javac re-run is enforced, so a declaration-level tamper
// of the committed oracle fails closed even when every file hash still matches.
// ---------------------------------------------------------------------------

func TestDeriveFailsOnDeclarationLevelOracleTamper(t *testing.T) {
	content, err := os.ReadFile(filepath.Join(repoRoot, EvidenceDirectory, OracleEvidenceDocument))
	if err != nil {
		t.Fatalf("read oracle: %v", err)
	}
	var doctored map[string]any
	if err := json.Unmarshal(content, &doctored); err != nil {
		t.Fatalf("unmarshal oracle: %v", err)
	}
	declarations := doctored["declarations"].([]any)
	first := declarations[0].(map[string]any)
	first["descriptor"] = "(Ljava/lang/String;)V" // wrong descriptor; file hashes untouched
	tampered, err := json.MarshalIndent(doctored, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	oraclePath := filepath.Join(t.TempDir(), "declaration-tampered-oracle.json")
	if err := os.WriteFile(oraclePath, tampered, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	request := reproductionRequest(t.TempDir())
	request.OraclePath = oraclePath
	err = Derive(request)
	if err == nil || !strings.Contains(err.Error(), "ORACLE_REPRODUCTION_MISMATCH") {
		t.Fatalf("a declaration-level tamper must fail closed with ORACLE_REPRODUCTION_MISMATCH,"+
			" got %v", err)
	}
}

func TestOracleReproductionFailsTypedWhenJavacUnavailable(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // no javac, no make anywhere on PATH
	err := VerifyOracleReproduction(repoRoot,
		filepath.Join(repoRoot, EvidenceDirectory, OracleEvidenceDocument))
	if err == nil || !strings.Contains(err.Error(), "JAVAC_UNAVAILABLE") {
		t.Fatalf("missing javac must fail typed with JAVAC_UNAVAILABLE, never skip, got %v", err)
	}
}

func TestPinnedJavacIdentityRequiresOneExactDistribution(t *testing.T) {
	for _, test := range []struct {
		output, distribution string
	}{
		{"java.vendor = Homebrew\njava.vendor.version = Homebrew\njavac 17.0.19\n", pinnedHomebrewJavac},
		{"java.vendor = Eclipse Adoptium\njava.vendor.version = Temurin-17.0.19+10\njavac 17.0.19\n", pinnedTemurinJavac},
	} {
		if distribution, err := pinnedJavacDistribution([]byte(test.output)); err != nil || distribution != test.distribution {
			t.Fatalf("distribution=%q want=%q err=%v", distribution, test.distribution, err)
		}
	}
	for _, mutation := range [][]byte{
		[]byte("java.vendor = Eclipse Adoptium\njava.vendor.version = Homebrew\njavac 17.0.19\n"),
		[]byte("java.vendor = Eclipse Adoptium\njava.vendor.version = Temurin-17.0.19+10\njavac 17.0.18\n"),
		[]byte("java.vendor = Eclipse Adoptium\njavac 17.0.19\n"),
	} {
		if _, err := pinnedJavacDistribution(mutation); err == nil || !strings.Contains(err.Error(), "JAVAC_UNAVAILABLE") {
			t.Fatalf("unpinned javac identity accepted: %q err=%v", mutation, err)
		}
	}
}

func TestOracleSemanticParityAllowsOnlyPinnedVendorDifference(t *testing.T) {
	canonical := []byte(`{"jdk_vendor":"Homebrew","declarations":[{"semantic_key":"A"}]}`)
	alternate := []byte(`{"declarations":[{"semantic_key":"A"}],"jdk_vendor":"Eclipse Adoptium"}`)
	if err := verifyOracleSemanticParity(canonical, alternate); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range [][]byte{
		[]byte(`{"jdk_vendor":"Eclipse Adoptium","declarations":[{"semantic_key":"B"}]}`),
		[]byte(`{"jdk_vendor":"Homebrew","declarations":[{"semantic_key":"A"}]}`),
	} {
		if err := verifyOracleSemanticParity(canonical, mutation); err == nil || !strings.Contains(err.Error(), "ORACLE_REPRODUCTION_MISMATCH") {
			t.Fatalf("oracle semantic or provenance mutation accepted: %s err=%v", mutation, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Round 2, item 4: both WebSocketImpl queues are inventoried; inQueue's NIO
// ownership is stated explicitly in the manifest AND the dossier.
// ---------------------------------------------------------------------------

func TestBothWebSocketImplQueuesAreInventoried(t *testing.T) {
	var manifest IntakeManifest
	loadDocument(t, repoRoot, ManifestDocument, &manifest)
	var concurrency *SurfaceSection
	for index := range manifest.Sections {
		if manifest.Sections[index].ID == "concurrency" {
			concurrency = &manifest.Sections[index]
		}
	}
	if concurrency == nil {
		t.Fatal("no concurrency section")
	}
	joined := strings.Join(concurrency.Items, " | ")
	for _, needle := range []string{"outQueue", "inQueue", "EXCLUDED_JAVA_NIO_TOPOLOGY"} {
		if !strings.Contains(joined, needle) {
			t.Fatalf("manifest concurrency section must name %s; got %q", needle, joined)
		}
	}

	dossier := loadDossier(t, repoRoot)
	queues := strings.Join(dossier.Queues, " | ")
	for _, needle := range []string{"outQueue", "inQueue"} {
		if !strings.Contains(queues, needle) {
			t.Fatalf("dossier queues category must name %s; got %q", needle, queues)
		}
	}
	if !strings.Contains(queues, "excluded NIO server topology") {
		t.Fatalf("dossier must state inQueue's excluded ownership explicitly; got %q", queues)
	}
}
