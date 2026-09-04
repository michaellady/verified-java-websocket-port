package portplan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// B1: slice-crossing types must carry multi-slice bindings with per-slice
// touched behavior; NotSendableException belongs to framing.
// ---------------------------------------------------------------------------

func rowsByName(t *testing.T) map[string]MigrationRow {
	t.Helper()
	migration := loadMigration(t, repoRoot)
	rows := map[string]MigrationRow{}
	for _, row := range migration.Rows {
		rows[row.JavaBinaryName] = row
	}
	return rows
}

func requireBindings(t *testing.T, rows map[string]MigrationRow, name string, want ...string) {
	t.Helper()
	row, present := rows[name]
	if !present {
		t.Fatalf("no migration row for %s", name)
	}
	bound := map[string]bool{}
	for _, binding := range row.PortSlices {
		bound[binding.PortSliceID] = true
	}
	for _, slice := range want {
		if !bound[slice] {
			t.Fatalf("%s must bind %s; bound=%v", name, slice, keysOf(bound))
		}
	}
	if len(row.PortSlices) != len(want) {
		t.Fatalf("%s binds %d slices, want exactly %d (%v)",
			name, len(row.PortSlices), len(want), keysOf(bound))
	}
}

func keysOf(set map[string]bool) []string {
	var keys []string
	for key := range set {
		keys = append(keys, key)
	}
	return keys
}

func TestWebSocketImplBindsEveryBehavioralSlice(t *testing.T) {
	requireBindings(t, rowsByName(t), "org.java_websocket.WebSocketImpl",
		"slice.connection-core", "slice.client-handshake", "slice.server-handshake",
		"slice.framing", "slice.messages", "slice.fragmentation", "slice.ping-pong",
		"slice.close-eof", "slice.concurrency", "slice.tcp-adapter")
}

func TestDraft6455BindsItsSevenBehavioralSlices(t *testing.T) {
	requireBindings(t, rowsByName(t), "org.java_websocket.drafts.Draft_6455",
		"slice.framing", "slice.client-handshake", "slice.server-handshake",
		"slice.messages", "slice.fragmentation", "slice.ping-pong", "slice.close-eof")
}

func TestRemainingCrossingTypesCarryMultiSliceBindings(t *testing.T) {
	rows := rowsByName(t)
	requireBindings(t, rows, "org.java_websocket.drafts.Draft",
		"slice.connection-core", "slice.client-handshake", "slice.server-handshake",
		"slice.framing", "slice.fragmentation", "slice.messages", "slice.ping-pong",
		"slice.close-eof")
	requireBindings(t, rows, "org.java_websocket.WebSocket",
		"slice.connection-core", "slice.messages", "slice.fragmentation", "slice.ping-pong",
		"slice.close-eof")
	requireBindings(t, rows, "org.java_websocket.WebSocketAdapter",
		"slice.connection-core", "slice.client-handshake", "slice.server-handshake",
		"slice.ping-pong")
	requireBindings(t, rows, "org.java_websocket.WebSocketListener",
		"slice.connection-core", "slice.client-handshake", "slice.server-handshake",
		"slice.messages", "slice.ping-pong", "slice.close-eof", "slice.tcp-adapter")
	requireBindings(t, rows, "org.java_websocket.exceptions.InvalidDataException",
		"slice.framing", "slice.messages", "slice.fragmentation", "slice.close-eof",
		"slice.client-handshake", "slice.server-handshake")
	requireBindings(t, rows, "org.java_websocket.exceptions.LimitExceededException",
		"slice.framing", "slice.fragmentation")
	requireBindings(t, rows, "org.java_websocket.enums.CloseHandshakeType",
		"slice.connection-core", "slice.close-eof")
	requireBindings(t, rows, "org.java_websocket.enums.HandshakeState",
		"slice.client-handshake", "slice.server-handshake")
}

func TestNotSendableExceptionBindsToFramingNotConcurrency(t *testing.T) {
	rows := rowsByName(t)
	row := rows["org.java_websocket.exceptions.NotSendableException"]
	if len(row.PortSlices) != 1 || row.PortSlices[0].PortSliceID != "slice.framing" {
		t.Fatalf("NotSendableException is raised only from Draft_6455.createFrames and must"+
			" bind slice.framing alone, got %+v", row.PortSlices)
	}
	if row.PortSlices[0].ChildStoryID != "US-012" {
		t.Fatalf("framing is owned by US-012, got %s", row.PortSlices[0].ChildStoryID)
	}
}

func TestEveryBindingCarriesBehaviorStoryAndEvidence(t *testing.T) {
	migration := loadMigration(t, repoRoot)
	for _, row := range migration.Rows {
		if len(row.PortSlices) == 0 {
			t.Fatalf("%s has no slice binding", row.JavaBinaryName)
		}
		for _, binding := range row.PortSlices {
			slice, known := sliceByID(binding.PortSliceID)
			if !known {
				t.Fatalf("%s binds unknown slice %s", row.JavaBinaryName, binding.PortSliceID)
			}
			if slice.ChildStoryID != binding.ChildStoryID {
				t.Fatalf("%s binding %s names story %s, slice owner is %s",
					row.JavaBinaryName, binding.PortSliceID, binding.ChildStoryID,
					slice.ChildStoryID)
			}
			if strings.TrimSpace(binding.TouchedBehavior) == "" {
				t.Fatalf("%s binding %s has no touched behavior",
					row.JavaBinaryName, binding.PortSliceID)
			}
			if len(binding.EvidenceIDs) == 0 {
				t.Fatalf("%s binding %s carries no evidence obligation",
					row.JavaBinaryName, binding.PortSliceID)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// B2: story touched surface must be derived from the bindings, and the
// validator must fail when a story's behavioral surface has no covering
// binding — even when the dossier still claims resolution.
// ---------------------------------------------------------------------------

func dropBinding(rows []any, binaryName, sliceID string) {
	for _, entry := range rows {
		row := entry.(map[string]any)
		if row["java_binary_name"].(string) != binaryName {
			continue
		}
		bindings := row["port_slices"].([]any)
		kept := make([]any, 0, len(bindings))
		for _, candidate := range bindings {
			if candidate.(map[string]any)["port_slice_id"].(string) != sliceID {
				kept = append(kept, candidate)
			}
		}
		row["port_slices"] = kept
	}
}

func TestValidatorFailsWhenFragmentationLosesDraft6455(t *testing.T) {
	report := mutate(t, MigrationMapDocument, func(document map[string]any) {
		dropBinding(document["rows"].([]any),
			"org.java_websocket.drafts.Draft_6455", "slice.fragmentation")
	})
	requireFinding(t, report, FindingStoryCoverageGap)
}

func TestValidatorFailsWhenConcurrencyLosesWebSocketImpl(t *testing.T) {
	report := mutate(t, MigrationMapDocument, func(document map[string]any) {
		dropBinding(document["rows"].([]any),
			"org.java_websocket.WebSocketImpl", "slice.concurrency")
	})
	requireFinding(t, report, FindingStoryCoverageGap)
}

func TestValidatorFailsWhenPingPongLosesDraft6455(t *testing.T) {
	report := mutate(t, MigrationMapDocument, func(document map[string]any) {
		dropBinding(document["rows"].([]any),
			"org.java_websocket.drafts.Draft_6455", "slice.ping-pong")
	})
	requireFinding(t, report, FindingStoryCoverageGap)
}

func TestAdapterStorySeamsIncludeTheByteChannelFiles(t *testing.T) {
	dossier := loadDossier(t, repoRoot)
	touched := map[string]bool{}
	for _, seam := range dossier.Seams {
		if seam.ChildStoryID != "US-018" {
			continue
		}
		for _, file := range seam.TouchedFiles {
			touched[file] = true
		}
	}
	for _, file := range []string{
		"org/java_websocket/WrappedByteChannel.java",
		"org/java_websocket/AbstractWrappedByteChannel.java",
	} {
		if !touched[file] {
			t.Fatalf("US-018 touched surface must include %s", file)
		}
	}
}

func TestValidatorFailsWhenAdapterLosesByteChannelFiles(t *testing.T) {
	report := mutate(t, SeamDossierDocument, func(document map[string]any) {
		seams := document["seams"].([]any)
		kept := make([]any, 0, len(seams))
		for _, entry := range seams {
			seam := entry.(map[string]any)
			files := seam["touched_files"].([]any)
			filtered := make([]any, 0, len(files))
			for _, file := range files {
				if !strings.Contains(file.(string), "WrappedByteChannel") {
					filtered = append(filtered, file)
				}
			}
			if len(filtered) == 0 {
				continue // drop the byte-channel context seam entirely
			}
			seam["touched_files"] = filtered
			kept = append(kept, seam)
		}
		document["seams"] = kept
		// Keep every story's seam list pointing only at surviving seams.
		surviving := map[string]bool{}
		for _, entry := range kept {
			surviving[entry.(map[string]any)["surface_id"].(string)] = true
		}
		for _, entry := range document["implementation_stories"].([]any) {
			story := entry.(map[string]any)
			ids := story["seam_ids"].([]any)
			keptIDs := make([]any, 0, len(ids))
			for _, id := range ids {
				if surviving[id.(string)] {
					keptIDs = append(keptIDs, id)
				}
			}
			story["seam_ids"] = keptIDs
		}
	})
	requireFinding(t, report, FindingStoryCoverageGap)
}

// ---------------------------------------------------------------------------
// B3: evidence-to-source correspondence must be real and non-skippable.
// ---------------------------------------------------------------------------

func TestDeriveFailsWhenOracleDisagreesWithTree(t *testing.T) {
	production := filepath.Join(repoRoot, quarantineTree, "src/main/java")
	if _, err := os.Stat(production); err != nil {
		if _, ensureErr := EnsureQuarantinedSource(repoRoot); ensureErr != nil {
			t.Fatalf("cannot materialize the pinned source: %v", ensureErr)
		}
	}
	content, err := os.ReadFile(filepath.Join(repoRoot, EvidenceDirectory, OracleEvidenceDocument))
	if err != nil {
		t.Fatalf("read oracle: %v", err)
	}
	var doctored map[string]any
	if err := json.Unmarshal(content, &doctored); err != nil {
		t.Fatalf("unmarshal oracle: %v", err)
	}
	files := doctored["files"].([]any)
	files[0].(map[string]any)["sha256"] =
		"sha256:0000000000000000000000000000000000000000000000000000000000000000"
	tampered, err := json.Marshal(doctored)
	if err != nil {
		t.Fatalf("marshal oracle: %v", err)
	}
	oraclePath := filepath.Join(t.TempDir(), "tampered-oracle.json")
	if err := os.WriteFile(oraclePath, tampered, 0o644); err != nil {
		t.Fatalf("write oracle: %v", err)
	}

	request := reproductionRequest(t.TempDir())
	request.OraclePath = oraclePath
	err = Derive(request)
	if err == nil || !strings.Contains(err.Error(), "ORACLE_TREE_MISMATCH") {
		t.Fatalf("Derive must fail closed with ORACLE_TREE_MISMATCH, got %v", err)
	}
}

func TestEnsureQuarantinedSourceRejectsACorruptArchive(t *testing.T) {
	root := t.TempDir()
	quarantine := filepath.Join(root, QuarantineDirectory)
	if err := os.MkdirAll(quarantine, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	corrupt := filepath.Join(quarantine, SourceArchiveFileName)
	if err := os.WriteFile(corrupt, []byte("not the pinned archive"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := EnsureQuarantinedSource(root)
	if err == nil || !strings.Contains(err.Error(), "QUARANTINE_ARCHIVE_DIGEST_MISMATCH") {
		t.Fatalf("corrupt archive must fail closed, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// B4: the SLF4J compile input is bound by identity, not existence.
// ---------------------------------------------------------------------------

func TestSLF4JDigestMatchesTheUS002Qualification(t *testing.T) {
	qualification, err := os.ReadFile(filepath.Join(repoRoot, "internal/lab/autobahn_endpoint.go"))
	if err != nil {
		t.Fatalf("read qualification source: %v", err)
	}
	if !strings.Contains(string(qualification), SLF4JAPIJarSHA256) {
		t.Fatalf("pinned SLF4J digest %s is not the US-002 qualified digest", SLF4JAPIJarSHA256)
	}
	makefile, err := os.ReadFile(filepath.Join(repoRoot, "java-semantic-oracle/Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	bareHex := strings.TrimPrefix(SLF4JAPIJarSHA256, "sha256:")
	if !strings.Contains(string(makefile), bareHex) {
		t.Fatal("the oracle Makefile must verify the SLF4J jar digest before javac runs")
	}
	if !strings.Contains(string(makefile), "shasum") {
		t.Fatal("the Makefile digest gate must actually compute a digest")
	}
}

func TestManifestRecordsTheSLF4JPromotedInput(t *testing.T) {
	var manifest IntakeManifest
	loadDocument(t, repoRoot, ManifestDocument, &manifest)
	if len(manifest.PromotedInputs) == 0 {
		t.Fatal("the manifest must record the SLF4J binding as a promoted input")
	}
	var slf4j *PromotedInput
	for index := range manifest.PromotedInputs {
		if manifest.PromotedInputs[index].ArtifactID == "slf4j-api-2.0.13" {
			slf4j = &manifest.PromotedInputs[index]
		}
	}
	if slf4j == nil {
		t.Fatal("no slf4j-api-2.0.13 promoted input")
	}
	if slf4j.SHA256 != SLF4JAPIJarSHA256 {
		t.Fatalf("promoted input digest %s != qualified digest %s", slf4j.SHA256, SLF4JAPIJarSHA256)
	}
	if slf4j.QualifiedBy != "US-002" {
		t.Fatalf("the binding must cite the qualifying story, got %q", slf4j.QualifiedBy)
	}
}

func TestValidatorRejectsAnUnboundPromotedInput(t *testing.T) {
	report := mutate(t, ManifestDocument, func(document map[string]any) {
		inputs := document["promoted_inputs"].([]any)
		inputs[0].(map[string]any)["sha256"] =
			"sha256:1111111111111111111111111111111111111111111111111111111111111111"
	})
	requireFinding(t, report, FindingPromotedInputUnbound)
}

// ---------------------------------------------------------------------------
// I1: the manifest's runtime inventory must match the authoritative
// test manifest exactly.
// ---------------------------------------------------------------------------

func TestRuntimeInventorySectionMatchesTheAuthoritativeTestManifest(t *testing.T) {
	content, err := os.ReadFile(filepath.Join(repoRoot, "evidence/java/test-manifest.json"))
	if err != nil {
		t.Fatalf("read test manifest: %v", err)
	}
	var authoritative struct {
		NonTests []struct {
			Kind          string `json:"kind"`
			Executable    bool   `json:"executable"`
			CountedAsTest bool   `json:"counted_as_test"`
		} `json:"non_tests"`
	}
	if err := json.Unmarshal(content, &authoritative); err != nil {
		t.Fatalf("unmarshal test manifest: %v", err)
	}
	utilities, features := 0, 0
	for _, entry := range authoritative.NonTests {
		switch entry.Kind {
		case "autobahn-utility":
			utilities++
		case "feature-file":
			features++
		}
	}
	if utilities != 3 || features != 1 {
		t.Fatalf("authoritative counts changed: %d utilities, %d feature files", utilities, features)
	}

	var manifest IntakeManifest
	loadDocument(t, repoRoot, ManifestDocument, &manifest)
	var runtime *SurfaceSection
	for index := range manifest.Sections {
		if manifest.Sections[index].ID == "runtime-test-inventory" {
			runtime = &manifest.Sections[index]
		}
	}
	if runtime == nil {
		t.Fatal("no runtime-test-inventory section")
	}
	joined := strings.Join(runtime.Items, " | ")
	if !strings.Contains(joined, "3 Autobahn utility classes") ||
		!strings.Contains(joined, "1 feature file") {
		t.Fatalf("runtime inventory must state 3 utility classes + 1 feature file, got %q", joined)
	}
	if strings.Contains(joined, "4 Autobahn utility classes") {
		t.Fatalf("stale I1 wording survives: %q", joined)
	}
}

// ---------------------------------------------------------------------------
// I2: seam categories are explicit and role-consistent, not package-name
// heuristics.
// ---------------------------------------------------------------------------

func TestSeamCategoriesAreExplicitAndRoleConsistent(t *testing.T) {
	dossier := loadDossier(t, repoRoot)
	migration := loadMigration(t, repoRoot)
	rowByID := map[string]MigrationRow{}
	for _, row := range migration.Rows {
		rowByID[row.ID] = row
	}
	want := map[string]string{
		"org.java_websocket.WebSocketImpl":                        "internal_boundaries",
		"org.java_websocket.WebSocket":                            "public_boundaries",
		"org.java_websocket.WebSocketListener":                    "callbacks",
		"org.java_websocket.WebSocketAdapter":                     "callbacks",
		"org.java_websocket.util.NamedThreadFactory":              "threads",
		"org.java_websocket.util.ByteBufferUtils":                 "buffers",
		"org.java_websocket.exceptions.LimitExceededException":    "limits",
		"org.java_websocket.exceptions.NotSendableException":      "frames",
		"org.java_websocket.exceptions.InvalidHandshakeException": "handshakes",
		"org.java_websocket.exceptions.WrappedIOException":        "adapter_seams",
		"org.java_websocket.enums.HandshakeState":                 "handshakes",
	}
	seen := map[string]bool{}
	for _, seam := range dossier.Seams {
		row, present := rowByID[seam.SemanticID]
		if !present {
			continue
		}
		expected, checked := want[row.JavaBinaryName]
		if !checked {
			continue
		}
		seen[row.JavaBinaryName] = true
		if seam.Category != expected {
			t.Fatalf("%s seam category = %s, want %s", row.JavaBinaryName, seam.Category, expected)
		}
	}
	for name := range want {
		if !seen[name] {
			t.Fatalf("no seam observed for %s", name)
		}
	}
}

func TestEveryStudyTypeHasAnExplicitCategory(t *testing.T) {
	migration := loadMigration(t, repoRoot)
	for _, row := range migration.Rows {
		if _, present := TypeCategories[row.JavaBinaryName]; !present {
			t.Fatalf("%s has no explicit seam category; heuristics are not allowed",
				row.JavaBinaryName)
		}
	}
}

// reproductionRequest is the canonical DeriveRequest against the pinned inputs.
func reproductionRequest(root string) DeriveRequest {
	return DeriveRequest{
		Root:                 root,
		ProductionSourceRoot: filepath.Join(repoRoot, quarantineTree, "src/main/java"),
		TestSourceRoot:       filepath.Join(repoRoot, quarantineTree, "src/test/java"),
		OraclePath:           filepath.Join(repoRoot, EvidenceDirectory, OracleEvidenceDocument),
		OracleToolPath:       filepath.Join(repoRoot, "java-semantic-oracle/src/main/java/SemanticIdOracle.java"),
		TestManifestPath:     filepath.Join(repoRoot, "evidence/java/test-manifest.json"),
		ToolchainRoot:        repoRoot,
		SourceArtifactID:     "java-websocket-source-archive",
		SourceSHA256:         "sha256:f44e7647b4aee40819b51947cf0bb5f35a48293a202b77704c3c79e98ed13cb4",
		SourceVersion:        "1.6.0",
		SourceCommit:         "da3cf2a777aed862f2f5b5cf060cae7969958667",
		RFC6455SHA256:        "sha256:765775326aee0ecca9b04bde3fd1f52932d498e33e34e428bd61b8a24da0fa3b",
	}
}
