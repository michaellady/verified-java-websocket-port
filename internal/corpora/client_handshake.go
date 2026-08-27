package corpora

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// ClientHandshakeProjection binds the US-010 Rust tests to frozen and
// additive public evidence without changing the immutable US-005 corpus.
type ClientHandshakeProjection struct {
	Schema          string                      `json:"$schema"`
	SchemaVersion   string                      `json:"schema_version"`
	CorpusID        string                      `json:"corpus_id"`
	FrozenSource    ClientHandshakeFrozenSource `json:"frozen_source"`
	FrozenCases     []ClientHandshakeCase       `json:"frozen_cases"`
	AdditiveVectors []string                    `json:"additive_vectors"`
	Properties      ClientHandshakeProperties   `json:"properties"`
	FuzzSeeds       []ClientHandshakeFuzzSeed   `json:"fuzz_seeds"`
	Nonclaims       []string                    `json:"nonclaims"`
	Assurance       ClientHandshakeAssurance    `json:"assurance"`
}

// ClientHandshakeFrozenSource identifies the immutable input corpus.
type ClientHandshakeFrozenSource struct {
	CorpusID        string   `json:"corpus_id"`
	Artifact        string   `json:"artifact"`
	SHA256          string   `json:"sha256"`
	SelectedCaseIDs []string `json:"selected_case_ids"`
}

// ClientHandshakeCase is one exact frozen response projection.
type ClientHandshakeCase struct {
	CaseID    string `json:"case_id"`
	ClientKey string `json:"client_key"`
	NonceHex  string `json:"nonce_hex"`
	Expected  string `json:"expected"`
}

// ClientHandshakeProperties records deterministic property execution counts.
type ClientHandshakeProperties struct {
	ValidCasesSplitAtEveryByte int      `json:"valid_cases_split_at_every_byte"`
	SplitPointExecutions       int      `json:"split_point_executions"`
	DeterministicProperties    []string `json:"deterministic_properties"`
	ExecutionID                string   `json:"execution_id"`
}

// ClientHandshakeFuzzSeed binds an inert seed to its expected typed result.
type ClientHandshakeFuzzSeed struct {
	Path     string          `json:"path"`
	SHA256   string          `json:"sha256"`
	Expected string          `json:"expected"`
	Config   HandshakeConfig `json:"config"`
}

// ClientHandshakeAssurance prevents the projection from implying deployment.
type ClientHandshakeAssurance struct {
	Assurance                string `json:"assurance"`
	IndependentReviewClaimed bool   `json:"independent_review_claimed"`
	AutobahnExecutions       int    `json:"autobahn_executions"`
	Production               bool   `json:"production"`
	Publication              bool   `json:"publication"`
}

// LoadAndVerifyClientHandshakeProjection checks all referenced immutable
// bytes, source case identities, nonces, and assurance bounds.
func LoadAndVerifyClientHandshakeProjection(root string) (ClientHandshakeProjection, error) {
	raw, err := readUS010Artifact(root, "corpora/handshake/client.json")
	if err != nil {
		return ClientHandshakeProjection{}, err
	}
	var projection ClientHandshakeProjection
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&projection); err != nil {
		return ClientHandshakeProjection{}, fmt.Errorf("decode client projection: %w", err)
	}
	if projection.SchemaVersion != "1.0.0" || projection.CorpusID != "us010-client-handshake" {
		return ClientHandshakeProjection{}, fmt.Errorf("unexpected client projection identity")
	}
	if len(projection.FrozenCases) != 10 || len(projection.FuzzSeeds) != 11 {
		return ClientHandshakeProjection{}, fmt.Errorf("projection requires 10 frozen cases and 11 fuzz seeds")
	}
	if err := verifyClientPropertyClaims(projection.Properties); err != nil {
		return ClientHandshakeProjection{}, err
	}
	if projection.Assurance.Assurance != "OWNER_ATTESTED_NOT_INDEPENDENT" ||
		projection.Assurance.IndependentReviewClaimed || projection.Assurance.AutobahnExecutions != 0 ||
		projection.Assurance.Production || projection.Assurance.Publication {
		return ClientHandshakeProjection{}, fmt.Errorf("client projection overstates assurance")
	}

	source, err := readUS010Artifact(root, projection.FrozenSource.Artifact)
	if err != nil {
		return ClientHandshakeProjection{}, err
	}
	if DigestSHA256(source) != projection.FrozenSource.SHA256 {
		return ClientHandshakeProjection{}, fmt.Errorf("frozen source digest mismatch")
	}
	sourceCases, err := serverResponseCases(source)
	if err != nil {
		return ClientHandshakeProjection{}, err
	}
	if err := verifyFrozenClientProjection(projection, sourceCases); err != nil {
		return ClientHandshakeProjection{}, err
	}
	if err := verifyClientFuzzProjection(root, projection.FuzzSeeds); err != nil {
		return ClientHandshakeProjection{}, err
	}
	return projection, nil
}

type frozenClientExpectation struct {
	projected string
	verdict   string
	reject    string
}

var frozenClientExpectations = map[string]frozenClientExpectation{
	"us005.hs.0006": {"Open", "accept", ""},
	"us005.hs.0007": {"Open", "accept", ""},
	"us005.hs.0008": {"Open", "accept", ""},
	"us005.hs.0035": {"StatusNotSwitchingProtocols(200)", "reject", "HS_STATUS_NOT_101"},
	"us005.hs.0036": {"StatusNotSwitchingProtocols(404)", "reject", "HS_STATUS_NOT_101"},
	"us005.hs.0037": {"StatusNotSwitchingProtocols(301)", "reject", "HS_STATUS_NOT_101"},
	"us005.hs.0038": {"MissingAccept", "reject", "HS_MISSING_ACCEPT"},
	"us005.hs.0039": {"AcceptMismatch", "reject", "HS_ACCEPT_MISMATCH"},
	"us005.hs.0040": {"AcceptMismatch", "reject", "HS_ACCEPT_MISMATCH"},
	"us005.hs.0041": {"MissingUpgrade", "reject", "HS_MISSING_UPGRADE"},
}

var defaultClientHandshakeConfig = HandshakeConfig{
	MaxHandshakeBytes:  4096,
	MaxHeaderCount:     32,
	MaxHeaderLineBytes: 512,
}

func verifyFrozenClientProjection(projection ClientHandshakeProjection, sourceCases map[string]HandshakeCase) error {
	seen := make(map[string]bool, len(projection.FrozenCases))
	for _, projected := range projection.FrozenCases {
		expectation, allowed := frozenClientExpectations[projected.CaseID]
		if !allowed || seen[projected.CaseID] || projected.Expected != expectation.projected {
			return fmt.Errorf("case %s is outside the exact frozen projection allowlist", projected.CaseID)
		}
		seen[projected.CaseID] = true
		sourceCase, ok := sourceCases[projected.CaseID]
		if !ok || sourceCase.Direction != "server_response" ||
			sourceCase.Context.ClientKey != projected.ClientKey ||
			sourceCase.Config != defaultClientHandshakeConfig ||
			sourceCase.Expected.Verdict != expectation.verdict ||
			sourceCase.Expected.RejectCode != expectation.reject {
			return fmt.Errorf("case %s does not match its exact frozen source verdict/config", projected.CaseID)
		}
		raw, err := base64.StdEncoding.DecodeString(sourceCase.RawBase64)
		if err != nil {
			return fmt.Errorf("case %s raw bytes are invalid: %w", projected.CaseID, err)
		}
		derived, err := DeriveHandshake(sourceCase.Direction, raw, sourceCase.Config, sourceCase.Context)
		if err != nil || derived.Verdict != sourceCase.Expected.Verdict ||
			derived.RejectCode != sourceCase.Expected.RejectCode ||
			derived.SecWebSocketAccept != sourceCase.Expected.SecWebSocketAccept ||
			!stringSlicesEqual(derived.Basis, sourceCase.Expected.Basis) {
			return fmt.Errorf("case %s no longer matches the executable reference evaluator", projected.CaseID)
		}
		nonce, err := hex.DecodeString(projected.NonceHex)
		if err != nil || len(nonce) != 16 || base64.StdEncoding.EncodeToString(nonce) != projected.ClientKey {
			return fmt.Errorf("case %s nonce does not derive its client key", projected.CaseID)
		}
	}
	if len(seen) != len(frozenClientExpectations) ||
		len(projection.FrozenSource.SelectedCaseIDs) != len(frozenClientExpectations) {
		return fmt.Errorf("frozen client projection inventory is incomplete")
	}
	for _, id := range projection.FrozenSource.SelectedCaseIDs {
		if !seen[id] {
			return fmt.Errorf("selected case %s is not projected", id)
		}
	}
	return nil
}

var exactClientProperties = []string{
	"three fixed frozen responses open at every byte split",
	"one fixed response with Upgrade second in the Connection comma list opens at every byte split",
	"one fixed wrong Sec-WebSocket-Accept literal rejects",
	"one fixed one-byte suffix after the terminal CRLF rejects",
}

func verifyClientPropertyClaims(properties ClientHandshakeProperties) error {
	if properties.ValidCasesSplitAtEveryByte != 4 || properties.SplitPointExecutions != 548 ||
		properties.ExecutionID != "us010-client-handshake-deterministic-v1" ||
		!stringSlicesEqual(properties.DeterministicProperties, exactClientProperties) {
		return fmt.Errorf("deterministic property claims exceed the exact executed allowlist")
	}
	return nil
}

type fuzzSeedExpectation struct {
	digest   string
	expected string
	config   HandshakeConfig
}

var exactClientFuzzSeeds = map[string]fuzzSeedExpectation{
	"rust/connection-core/fuzz-seeds/us010/bare-lf.hex":           {"sha256:7284b34e944c6ab24909c20c9be93350a224d9aca0243aeeef02e04fa0b5a757", "BareLineEnding", defaultClientHandshakeConfig},
	"rust/connection-core/fuzz-seeds/us010/count-limit.hex":       {"sha256:8413f43a8f7de94de9cc3e1522c941a5fe1c99ef0cae1e2164e5f39716cb3142", "HandshakeHeaderCount(6>5)", HandshakeConfig{512, 5, 512}},
	"rust/connection-core/fuzz-seeds/us010/duplicate-casing.hex":  {"sha256:261296e4015a0099d2131750b0415e73ebfeb974a058aa9d956a502c2b669aca", "DuplicateHeader", defaultClientHandshakeConfig},
	"rust/connection-core/fuzz-seeds/us010/extension.hex":         {"sha256:b7399b8d47aba688df1b6058c8608c1ddc97602c1e2446f343e254cfd8bf0d7a", "UnexpectedExtension", defaultClientHandshakeConfig},
	"rust/connection-core/fuzz-seeds/us010/incomplete-crlf.hex":   {"sha256:96a0fd211bd5d6c322e4bec75e5b20ffd58618c56033d54f8d49938e91614d26", "UnexpectedEof", defaultClientHandshakeConfig},
	"rust/connection-core/fuzz-seeds/us010/invalid-token.hex":     {"sha256:f1cdba4f3049a64766cb60d81073e2ce5c4591d48f57dcdff9cdbd8a50477b21", "InvalidHeaderName", defaultClientHandshakeConfig},
	"rust/connection-core/fuzz-seeds/us010/line-limit.hex":        {"sha256:a2d42824d614e2071ab3354ec1a573b4abbacc4828fba3ca5e63064870eac799", "HandshakeHeaderLineBytes(65>64)", HandshakeConfig{512, 32, 64}},
	"rust/connection-core/fuzz-seeds/us010/obs-fold.hex":          {"sha256:fcb49e919ceceecbe70d0ddaed9a0228d6c6421d7df87b44ddf93810c6e400e4", "ObsoleteLineFolding", defaultClientHandshakeConfig},
	"rust/connection-core/fuzz-seeds/us010/subprotocol.hex":       {"sha256:a96e8d9ca40d008e20fca5504eb430b12f91f7b08571bbe99a20fc1e68d0573f", "UnexpectedSubprotocol", defaultClientHandshakeConfig},
	"rust/connection-core/fuzz-seeds/us010/total-limit.hex":       {"sha256:e3468fb515e57fe97987e89202bc98585323174433b3cccf433ed105319cdbec", "HandshakeBytes(257>256)", HandshakeConfig{256, 32, 256}},
	"rust/connection-core/fuzz-seeds/us010/valid-plus-suffix.hex": {"sha256:655cdef213936180818ba004399acc2f8f01a83b9d86799e0fd36a27e7c31eb6", "TrailingData(1)", defaultClientHandshakeConfig},
}

func verifyClientFuzzProjection(root string, seeds []ClientHandshakeFuzzSeed) error {
	if len(seeds) != len(exactClientFuzzSeeds) {
		return fmt.Errorf("fuzz seed inventory is incomplete")
	}
	testSource, err := readUS010Artifact(root, "rust/connection-core/tests/client_handshake.rs")
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(seeds))
	for _, seed := range seeds {
		expected, allowed := exactClientFuzzSeeds[seed.Path]
		if !allowed || seen[seed.Path] || seed.SHA256 != expected.digest ||
			seed.Expected != expected.expected || seed.Config != expected.config {
			return fmt.Errorf("fuzz seed %q is outside the exact verdict/config allowlist", seed.Path)
		}
		seen[seed.Path] = true
		seedBytes, err := readUS010Artifact(root, seed.Path)
		if err != nil {
			return err
		}
		if DigestSHA256(seedBytes) != seed.SHA256 {
			return fmt.Errorf("seed digest mismatch: %s", seed.Path)
		}
		compact := strings.TrimSuffix(string(seedBytes), "\n")
		decoded, err := hex.DecodeString(compact)
		if err != nil || len(decoded) == 0 || string(seedBytes) != strings.ToLower(compact)+"\n" {
			return fmt.Errorf("seed is not canonical lowercase hex: %s", seed.Path)
		}
		include := "include_str!(\"../fuzz-seeds/us010/" + filepath.Base(seed.Path) + "\")"
		if !bytes.Contains(testSource, []byte(include)) {
			return fmt.Errorf("seed is absent from the executable Rust harness: %s", seed.Path)
		}
	}
	return nil
}

func stringSlicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func serverResponseCases(raw []byte) (map[string]HandshakeCase, error) {
	cases := make(map[string]HandshakeCase)
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		var item HandshakeCase
		if err := json.Unmarshal(scanner.Bytes(), &item); err != nil {
			return nil, err
		}
		if item.Direction == "server_response" {
			cases[item.CaseID] = item
		}
	}
	return cases, scanner.Err()
}

type evidenceArtifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type clientHandshakeEvidence struct {
	EvidenceID string `json:"evidence_id"`
	StoryID    string `json:"story_id"`
	Source     struct {
		Commit              string             `json:"commit"`
		Tree                string             `json:"tree"`
		ImplementationFiles []evidenceArtifact `json:"implementation_files"`
	} `json:"source"`
	Toolchain struct {
		RustcArtifactID string `json:"rustc_artifact_id"`
		RustcSHA256     string `json:"rustc_sha256"`
		CargoSHA256     string `json:"cargo_sha256"`
		ValidationTime  string `json:"validation_time"`
		RustAnalyzer    struct {
			HistoricalUS009ReceiptPreserved bool   `json:"historical_us009_receipt_preserved"`
			PinnedArtifactID                string `json:"pinned_artifact_id"`
			PinnedSHA256                    string `json:"pinned_sha256"`
			FreshUS010Resolution            string `json:"fresh_us010_resolution"`
			ProxyIsNotAcceptedAsResolver    bool   `json:"proxy_is_not_accepted_as_resolver"`
		} `json:"rust_analyzer"`
	} `json:"toolchain"`
	Tests struct {
		Debug struct {
			Command string `json:"command"`
			Passed  int    `json:"passed"`
			Failed  int    `json:"failed"`
		} `json:"debug"`
		Release struct {
			Command string `json:"command"`
			Passed  int    `json:"passed"`
			Failed  int    `json:"failed"`
		} `json:"release"`
		ClientHandshakeTests int `json:"client_handshake_tests_per_profile"`
		SplitPointExecutions int `json:"split_point_executions_per_profile"`
		FuzzSeedsReplayed    int `json:"fuzz_seeds_replayed_per_profile"`
		FrozenResponseCases  int `json:"frozen_server_response_cases"`
	} `json:"tests"`
	Corpus struct {
		ProjectionPath   string `json:"projection_path"`
		ProjectionSHA256 string `json:"projection_sha256"`
		FuzzSeedCount    int    `json:"fuzz_seed_count"`
	} `json:"corpus"`
	Symbols struct {
		MigrationMapPath       string `json:"migration_map_path"`
		MigrationMapSHA256     string `json:"migration_map_sha256"`
		NewResolverVerified    int    `json:"new_resolver_verified_identities"`
		JavaShapedAliasesAdded int    `json:"java_shaped_aliases_added"`
		Bindings               []struct {
			RustSemanticID string `json:"rust_semantic_id"`
			Source         string `json:"source"`
			Status         string `json:"status"`
		} `json:"bindings"`
	} `json:"symbols"`
	Compatibility struct {
		SurfaceID                  string   `json:"surface_id"`
		CutoverObligationID        string   `json:"cutover_obligation_id"`
		EvidenceIDs                []string `json:"evidence_ids"`
		JavaObservationMode        string   `json:"java_observation_mode"`
		JavaMappingPath            string   `json:"java_mapping_path"`
		JavaMappingSHA256          string   `json:"java_mapping_sha256"`
		CompatibilitySurfaceSHA256 string   `json:"compatibility_surface_sha256"`
		CutoverContractSHA256      string   `json:"cutover_contract_sha256"`
	} `json:"compatibility"`
	DeltaLedger struct {
		Path               string `json:"path"`
		SHA256             string `json:"sha256"`
		RecordsAdded       int    `json:"records_added"`
		AutobahnExecutions int    `json:"autobahn_executions"`
	} `json:"delta_ledger"`
	EvidenceDAGClaim  string                   `json:"evidence_dag_claim"`
	EvidenceDAGPath   string                   `json:"evidence_dag_path"`
	EvidenceDAGSHA256 string                   `json:"evidence_dag_sha256"`
	Assurance         ClientHandshakeAssurance `json:"assurance"`
}

// VerifyClientHandshakeEvidence closes every file, symbol, cutover, and DAG
// reference without treating a missing resolver or an unexecuted oracle as a pass.
func VerifyClientHandshakeEvidence(root string) error {
	raw, err := readUS010Artifact(root, "evidence/us010-client-handshake.json")
	if err != nil {
		return err
	}
	var evidence clientHandshakeEvidence
	if err := json.Unmarshal(raw, &evidence); err != nil {
		return err
	}
	if evidence.EvidenceID != "evidence.us-010-client-handshake" || evidence.StoryID != "US-010" {
		return fmt.Errorf("invalid US-010 evidence identity or source binding")
	}
	if err := verifyUS010GitSourceBinding(root, evidence.Source.Commit, evidence.Source.Tree, evidence.Source.ImplementationFiles); err != nil {
		return err
	}
	for _, artifact := range evidence.Source.ImplementationFiles {
		if err := verifyEvidenceArtifact(root, artifact); err != nil {
			return err
		}
	}
	if evidence.Toolchain.RustcArtifactID != "rustc-1.95.0-aarch64-apple-darwin" ||
		evidence.Toolchain.RustcSHA256 != "sha256:b829b733131d4e1673eeebd1f34d06ae1e9ff4977b051313cf42e2a9e79ecf1c" ||
		evidence.Toolchain.CargoSHA256 != "sha256:c512bff73c86143b557463f021d0c3d5b0490d97d65040ba59ea2b3427784758" ||
		evidence.Toolchain.ValidationTime == "" ||
		!evidence.Toolchain.RustAnalyzer.HistoricalUS009ReceiptPreserved ||
		evidence.Toolchain.RustAnalyzer.PinnedArtifactID != "rust-analyzer-2026-08-17.4-aarch64-apple-darwin" ||
		evidence.Toolchain.RustAnalyzer.PinnedSHA256 != "sha256:5142e0d6d0a48bc8ba0638125eaa68296defba7d32628362175eff967d12e145" ||
		evidence.Toolchain.RustAnalyzer.FreshUS010Resolution != "NOT_PERFORMED_EXACT_PIN_NOT_LOCALLY_AVAILABLE" ||
		!evidence.Toolchain.RustAnalyzer.ProxyIsNotAcceptedAsResolver {
		return fmt.Errorf("US-010 toolchain binding is incomplete or overstated")
	}
	if evidence.Tests.Debug.Command != "make -C rust test" ||
		evidence.Tests.Release.Command != "make -C rust test-release" ||
		evidence.Tests.Debug.Passed != 36 || evidence.Tests.Debug.Failed != 0 ||
		evidence.Tests.Release.Passed != 36 || evidence.Tests.Release.Failed != 0 ||
		evidence.Tests.ClientHandshakeTests != 14 || evidence.Tests.SplitPointExecutions != 548 ||
		evidence.Tests.FuzzSeedsReplayed != 11 || evidence.Tests.FrozenResponseCases != 10 {
		return fmt.Errorf("US-010 test counts do not match the committed harness")
	}
	if err := verifyEvidenceArtifact(root, evidenceArtifact{evidence.Corpus.ProjectionPath, evidence.Corpus.ProjectionSHA256}); err != nil {
		return err
	}
	if evidence.Corpus.FuzzSeedCount != 11 || evidence.Symbols.NewResolverVerified != 0 || evidence.Symbols.JavaShapedAliasesAdded != 0 {
		return fmt.Errorf("US-010 corpus or resolver claims are inconsistent")
	}
	if err := verifyEvidenceArtifact(root, evidenceArtifact{evidence.Symbols.MigrationMapPath, evidence.Symbols.MigrationMapSHA256}); err != nil {
		return err
	}
	if err := verifyUS010MigrationBindings(root, evidence.Symbols.Bindings); err != nil {
		return err
	}
	for _, artifact := range []evidenceArtifact{
		{evidence.Compatibility.JavaMappingPath, evidence.Compatibility.JavaMappingSHA256},
		{"evidence/intake/compatibility-surface.json", evidence.Compatibility.CompatibilitySurfaceSHA256},
		{"evidence/intake/cutover-contract.json", evidence.Compatibility.CutoverContractSHA256},
		{evidence.DeltaLedger.Path, evidence.DeltaLedger.SHA256},
	} {
		if err := verifyEvidenceArtifact(root, artifact); err != nil {
			return err
		}
	}
	if evidence.Compatibility.SurfaceID != "surface.handshake.client-request" ||
		evidence.Compatibility.CutoverObligationID != "cutover.surface-handshake-client-request" ||
		!stringSlicesEqual(evidence.Compatibility.EvidenceIDs, []string{"evidence.us-010-client-handshake"}) ||
		evidence.Compatibility.JavaObservationMode != "SOURCE_DERIVED_NO_LIVE_COMMITTED_CORPUS_EXECUTION" ||
		evidence.DeltaLedger.RecordsAdded != 0 || evidence.DeltaLedger.AutobahnExecutions != 0 {
		return fmt.Errorf("US-010 compatibility or delta nonclaims are inconsistent")
	}
	if err := verifyEvidenceArtifact(root, evidenceArtifact{evidence.EvidenceDAGPath, evidence.EvidenceDAGSHA256}); err != nil {
		return err
	}
	if err := verifyUS010DAGAndCutover(root, evidence.EvidenceDAGPath, evidence.EvidenceDAGClaim); err != nil {
		return err
	}
	if evidence.Assurance.Assurance != "OWNER_ATTESTED_NOT_INDEPENDENT" ||
		evidence.Assurance.IndependentReviewClaimed || evidence.Assurance.Production || evidence.Assurance.Publication {
		return fmt.Errorf("US-010 evidence overstates assurance")
	}
	return nil
}

func verifyEvidenceArtifact(root string, artifact evidenceArtifact) error {
	raw, err := readUS010Artifact(root, artifact.Path)
	if err != nil {
		return err
	}
	if DigestSHA256(raw) != artifact.SHA256 {
		return fmt.Errorf("evidence artifact digest mismatch: %s", artifact.Path)
	}
	return nil
}

func verifyUS010MigrationBindings(root string, bindings []struct {
	RustSemanticID string `json:"rust_semantic_id"`
	Source         string `json:"source"`
	Status         string `json:"status"`
}) error {
	expected := map[string]bool{
		"websocket_core::ConnectionCore":          false,
		"websocket_core::ClientRequestDescriptor": false,
		"websocket_core::LocalCommand":            false,
		"websocket_core::HandshakeFailure":        false,
		"websocket_core::SemanticEvent":           false,
	}
	for _, binding := range bindings {
		if _, ok := expected[binding.RustSemanticID]; !ok || expected[binding.RustSemanticID] {
			return fmt.Errorf("unexpected or duplicate US-010 binding %s", binding.RustSemanticID)
		}
		expected[binding.RustSemanticID] = true
		path, lineText, found := strings.Cut(binding.Source, ":")
		lineNumber, lineErr := strconv.Atoi(lineText)
		if !found || lineErr != nil || lineNumber < 1 {
			return fmt.Errorf("binding lacks source line: %s", binding.RustSemanticID)
		}
		source, err := readUS010Artifact(root, path)
		if err != nil {
			return err
		}
		name := strings.TrimPrefix(binding.RustSemanticID, "websocket_core::")
		lines := bytes.Split(source, []byte("\n"))
		if lineNumber > len(lines) || !bytes.Contains(lines[lineNumber-1], []byte(name)) {
			return fmt.Errorf("binding symbol absent from exact source line: %s", binding.RustSemanticID)
		}
		if name == "ConnectionCore" && binding.Status != "RESOLVER_VERIFIED_BY_IMMUTABLE_US009_RECEIPT" {
			return fmt.Errorf("ConnectionCore lost its historical resolver status")
		}
		if name != "ConnectionCore" && binding.Status != "SOURCE_BOUND_RESOLVER_UNAVAILABLE" {
			return fmt.Errorf("new US-010 symbol overstates resolver status: %s", binding.RustSemanticID)
		}
	}
	for id, present := range expected {
		if !present {
			return fmt.Errorf("missing US-010 symbol binding %s", id)
		}
	}
	return nil
}

func verifyUS010DAGAndCutover(root, dagPath, claim string) error {
	var dag struct {
		Nodes []struct {
			ID string `json:"id"`
		} `json:"nodes"`
		Edges []struct {
			From string `json:"from"`
			To   string `json:"to"`
			Kind string `json:"kind"`
		} `json:"edges"`
	}
	if dagPath != "assurance/us010-evidence-dag.json" {
		return fmt.Errorf("US-010 evidence DAG path is not the additive story DAG")
	}
	raw, err := readUS010Artifact(root, dagPath)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &dag); err != nil {
		return err
	}
	nodeFound := false
	edgeFound := false
	for _, node := range dag.Nodes {
		nodeFound = nodeFound || node.ID == claim
	}
	for _, edge := range dag.Edges {
		edgeFound = edgeFound || edge.From == claim && edge.To == "evidence-us010-client-handshake" && edge.Kind == "supports"
	}
	if !nodeFound || !edgeFound {
		return fmt.Errorf("US-010 evidence DAG claim is not closed")
	}
	var cutover struct {
		Obligations []struct {
			ID          string   `json:"id"`
			Status      string   `json:"status"`
			EvidenceIDs []string `json:"evidence_ids"`
		} `json:"obligations"`
	}
	raw, err = readUS010Artifact(root, "evidence/intake/cutover-contract.json")
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &cutover); err != nil {
		return err
	}
	for _, obligation := range cutover.Obligations {
		if obligation.ID == "cutover.surface-handshake-client-request" {
			if obligation.Status != "DECLARED" || len(obligation.EvidenceIDs) != 0 {
				return fmt.Errorf("US-010 cutover obligation must remain declared without promoted evidence")
			}
			return nil
		}
	}
	return fmt.Errorf("US-010 cutover obligation is absent")
}

func verifyUS010GitSourceBinding(root, commit, tree string, artifacts []evidenceArtifact) error {
	if len(commit) != 40 || len(tree) != 40 {
		return fmt.Errorf("source commit/tree are not full object IDs")
	}
	if _, err := hex.DecodeString(commit + tree); err != nil {
		return fmt.Errorf("source commit/tree are not hexadecimal: %w", err)
	}
	if err := runGitObjectCheck(root, commit+"^{commit}"); err != nil {
		return fmt.Errorf("US-010 source commit is not a local git commit: %w", err)
	}
	if err := runGitObjectCheck(root, tree+"^{tree}"); err != nil {
		return fmt.Errorf("US-010 source tree is not a local git tree: %w", err)
	}
	command := exec.Command("git", "-C", root, "rev-parse", commit+"^{tree}")
	actualTree, err := command.Output()
	if err != nil || strings.TrimSpace(string(actualTree)) != tree {
		return fmt.Errorf("US-010 source tree does not belong to its source commit")
	}
	for _, artifact := range artifacts {
		if _, err := readUS010Artifact(root, artifact.Path); err != nil {
			return err
		}
		command := exec.Command("git", "-C", root, "show", commit+":"+artifact.Path)
		committed, err := command.Output()
		if err != nil || DigestSHA256(committed) != artifact.SHA256 {
			return fmt.Errorf("US-010 artifact is not bound to the source commit: %s", artifact.Path)
		}
	}
	return nil
}

func runGitObjectCheck(root, object string) error {
	return exec.Command("git", "-C", root, "cat-file", "-e", object).Run()
}
