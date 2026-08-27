package corpora

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	CasePermutationProperties  []string `json:"case_permutation_properties"`
	FixedSeed                  string   `json:"fixed_seed"`
}

// ClientHandshakeFuzzSeed binds an inert seed to its expected typed result.
type ClientHandshakeFuzzSeed struct {
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
	Expected string `json:"expected"`
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
	path := filepath.Join(root, "corpora/handshake/client.json")
	raw, err := os.ReadFile(path)
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
	if projection.Properties.ValidCasesSplitAtEveryByte != 4 || projection.Properties.SplitPointExecutions != 548 {
		return ClientHandshakeProjection{}, fmt.Errorf("property execution counts do not match committed tests")
	}
	if projection.Assurance.Assurance != "OWNER_ATTESTED_NOT_INDEPENDENT" ||
		projection.Assurance.IndependentReviewClaimed || projection.Assurance.AutobahnExecutions != 0 ||
		projection.Assurance.Production || projection.Assurance.Publication {
		return ClientHandshakeProjection{}, fmt.Errorf("client projection overstates assurance")
	}

	sourcePath := filepath.Join(root, projection.FrozenSource.Artifact)
	source, err := os.ReadFile(sourcePath)
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
	seen := make(map[string]bool, len(projection.FrozenCases))
	for _, projected := range projection.FrozenCases {
		if seen[projected.CaseID] {
			return ClientHandshakeProjection{}, fmt.Errorf("duplicate projected case %s", projected.CaseID)
		}
		seen[projected.CaseID] = true
		sourceCase, ok := sourceCases[projected.CaseID]
		if !ok || sourceCase.Context.ClientKey != projected.ClientKey {
			return ClientHandshakeProjection{}, fmt.Errorf("case %s does not match frozen source", projected.CaseID)
		}
		nonce, err := hex.DecodeString(projected.NonceHex)
		if err != nil || len(nonce) != 16 || base64.StdEncoding.EncodeToString(nonce) != projected.ClientKey {
			return ClientHandshakeProjection{}, fmt.Errorf("case %s nonce does not derive its client key", projected.CaseID)
		}
	}
	if len(seen) != len(projection.FrozenSource.SelectedCaseIDs) {
		return ClientHandshakeProjection{}, fmt.Errorf("selected case inventory length mismatch")
	}
	for _, id := range projection.FrozenSource.SelectedCaseIDs {
		if !seen[id] {
			return ClientHandshakeProjection{}, fmt.Errorf("selected case %s is not projected", id)
		}
	}

	seedSeen := make(map[string]bool, len(projection.FuzzSeeds))
	for _, seed := range projection.FuzzSeeds {
		if seedSeen[seed.Path] || !strings.HasPrefix(seed.Path, "rust/connection-core/fuzz-seeds/us010/") || filepath.Clean(seed.Path) != seed.Path {
			return ClientHandshakeProjection{}, fmt.Errorf("invalid or duplicate seed path %q", seed.Path)
		}
		seedSeen[seed.Path] = true
		seedBytes, err := os.ReadFile(filepath.Join(root, seed.Path))
		if err != nil {
			return ClientHandshakeProjection{}, err
		}
		if DigestSHA256(seedBytes) != seed.SHA256 {
			return ClientHandshakeProjection{}, fmt.Errorf("seed digest mismatch: %s", seed.Path)
		}
		compact := strings.Map(func(r rune) rune {
			if r == '\n' || r == '\r' || r == '\t' || r == ' ' {
				return -1
			}
			return r
		}, string(seedBytes))
		if _, err := hex.DecodeString(compact); err != nil {
			return ClientHandshakeProjection{}, fmt.Errorf("seed is not canonical hex: %s", seed.Path)
		}
	}
	return projection, nil
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
	Tests struct {
		Debug struct {
			Passed int `json:"passed"`
			Failed int `json:"failed"`
		} `json:"debug"`
		Release struct {
			Passed int `json:"passed"`
			Failed int `json:"failed"`
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
		SurfaceID                  string `json:"surface_id"`
		CutoverObligationID        string `json:"cutover_obligation_id"`
		JavaMappingPath            string `json:"java_mapping_path"`
		JavaMappingSHA256          string `json:"java_mapping_sha256"`
		CompatibilitySurfaceSHA256 string `json:"compatibility_surface_sha256"`
		CutoverContractSHA256      string `json:"cutover_contract_sha256"`
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
	raw, err := os.ReadFile(filepath.Join(root, "evidence/us010-client-handshake.json"))
	if err != nil {
		return err
	}
	var evidence clientHandshakeEvidence
	if err := json.Unmarshal(raw, &evidence); err != nil {
		return err
	}
	if evidence.EvidenceID != "evidence.us-010-client-handshake" || evidence.StoryID != "US-010" ||
		len(evidence.Source.Commit) != 40 || len(evidence.Source.Tree) != 40 {
		return fmt.Errorf("invalid US-010 evidence identity or source binding")
	}
	if _, err := hex.DecodeString(evidence.Source.Commit + evidence.Source.Tree); err != nil {
		return fmt.Errorf("source commit/tree are not hexadecimal: %w", err)
	}
	for _, artifact := range evidence.Source.ImplementationFiles {
		if err := verifyEvidenceArtifact(root, artifact); err != nil {
			return err
		}
	}
	if evidence.Tests.Debug.Passed != 35 || evidence.Tests.Debug.Failed != 0 ||
		evidence.Tests.Release.Passed != 35 || evidence.Tests.Release.Failed != 0 ||
		evidence.Tests.ClientHandshakeTests != 13 || evidence.Tests.SplitPointExecutions != 548 ||
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
	if artifact.Path == "" || filepath.Clean(artifact.Path) != artifact.Path || filepath.IsAbs(artifact.Path) {
		return fmt.Errorf("invalid evidence artifact path %q", artifact.Path)
	}
	raw, err := os.ReadFile(filepath.Join(root, artifact.Path))
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
		path, _, found := strings.Cut(binding.Source, ":")
		if !found {
			return fmt.Errorf("binding lacks source line: %s", binding.RustSemanticID)
		}
		source, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			return err
		}
		name := strings.TrimPrefix(binding.RustSemanticID, "websocket_core::")
		if !bytes.Contains(source, []byte(name)) {
			return fmt.Errorf("binding symbol absent from source: %s", binding.RustSemanticID)
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
	raw, err := os.ReadFile(filepath.Join(root, dagPath))
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
	raw, err = os.ReadFile(filepath.Join(root, "evidence/intake/cutover-contract.json"))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &cutover); err != nil {
		return err
	}
	for _, obligation := range cutover.Obligations {
		if obligation.ID == "cutover.surface-handshake-client-request" {
			if obligation.Status != "SATISFIED" || len(obligation.EvidenceIDs) != 3 {
				return fmt.Errorf("US-010 cutover obligation is not exactly satisfied")
			}
			return nil
		}
	}
	return fmt.Errorf("US-010 cutover obligation is absent")
}
