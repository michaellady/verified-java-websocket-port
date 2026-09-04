package assurance

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"sort"
	"testing"

	vendorprotocol "github.com/michaellady/verified-java-to-rust/foundation/protocol"
)

func TestUS004RegenerateCanonicalLifecycle(t *testing.T) {
	if os.Getenv("US004_REGENERATE") != "1" {
		t.Skip("set US004_REGENERATE=1 to rewrite canonical assurance artifacts")
	}
	root := repoRoot(t)
	regenerateCanonicalAssurance(t, root)
	first := readGeneratedAssuranceArtifacts(t, root)
	regenerateCanonicalAssurance(t, root)
	second := readGeneratedAssuranceArtifacts(t, root)
	for path, before := range first {
		if !bytes.Equal(before, second[path]) {
			t.Fatalf("canonical regeneration is not byte-idempotent for %s", path)
		}
	}
}

func regenerateCanonicalAssurance(t *testing.T, root string) {
	t.Helper()
	bundle := readLifecycleBundle(t, root, lifecyclePathDefault)
	reconcileSecurityValidationTopology(t, &bundle)
	writeJSONFile(t, filepath.Join(root, evidenceDAGPath), expectedEvidenceDAG(bundle))
	writeJSONFile(t, filepath.Join(root, publicContractPath), expectedPublicContract(bundle))

	digests := make(map[string]string, len(expectedRetainedArtifacts)+len(expectedEvidenceNodes))
	for _, artifact := range expectedRetainedArtifacts {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(artifact.Path)))
		if err != nil {
			t.Fatalf("read retained artifact %s: %v", artifact.Path, err)
		}
		digests[artifact.Path] = vendorprotocol.DigestBytes(data)
	}
	for index := range bundle.Nodes {
		for _, expected := range expectedEvidenceNodes {
			if bundle.Nodes[index].ID != expected.ID {
				continue
			}
			binding := retainedDigest{Path: expected.Path, SHA256: digests[expected.Path]}
			encoded, err := vendorprotocol.CanonicalJSON(binding)
			if err != nil {
				t.Fatalf("canonical binding %s: %v", expected.Path, err)
			}
			bundle.Nodes[index].ContentBase64 = base64.StdEncoding.EncodeToString(encoded)
			bundle.Nodes[index].Digest = vendorprotocol.DigestBytes(encoded)
			digests[bundle.Nodes[index].ID] = digests[expected.Path]
		}
	}
	candidate, err := snapshotBindingDigest(bundle, digests)
	if err != nil {
		t.Fatalf("snapshot binding digest: %v", err)
	}
	bundle.Snapshot.CandidateDigest = candidate
	bundle.Authorization.SnapshotDigest = candidate
	for index := range bundle.Attestations {
		bundle.Attestations[index].SnapshotDigest = candidate
	}
	writeJSONFile(t, filepath.Join(root, lifecyclePathDefault), bundle)
	checkpoint := buildChildCheckpointFixture(t, bundle, childPolicy())
	writeJSONFile(t, filepath.Join(root, checkpointPath), checkpoint)
}

func reconcileSecurityValidationTopology(t *testing.T, bundle *vendorprotocol.Bundle) {
	t.Helper()
	const nodeID = "evidence-security-validation"
	foundNode := false
	for index := range bundle.Nodes {
		if bundle.Nodes[index].ID != nodeID {
			continue
		}
		foundNode = true
		bundle.Nodes[index].Kind = "evidence"
		bundle.Nodes[index].Classification = "PUBLIC_DERIVED"
		bundle.Nodes[index].Stale = false
		bundle.Nodes[index].Contradictory = false
		bundle.Nodes[index].Migrated = false
		bundle.Nodes[index].MigrationLossless = false
	}
	if !foundNode {
		bundle.Nodes = append(bundle.Nodes, vendorprotocol.Node{
			ID:             nodeID,
			Kind:           "evidence",
			Classification: "PUBLIC_DERIVED",
		})
	}

	foundEdge := false
	for _, edge := range bundle.Edges {
		if edge.From == bundle.RootNodeID && edge.To == nodeID && edge.Kind == "supports" {
			foundEdge = true
		}
	}
	if !foundEdge {
		bundle.Edges = append(bundle.Edges, vendorprotocol.Edge{From: bundle.RootNodeID, To: nodeID, Kind: "supports"})
	}

	foundStage := false
	for index := range bundle.Stages {
		if bundle.Stages[index].ID != "verify" {
			continue
		}
		foundStage = true
		foundInput := false
		for _, input := range bundle.Stages[index].Inputs {
			if input == nodeID {
				foundInput = true
			}
		}
		if !foundInput {
			bundle.Stages[index].Inputs = append(bundle.Stages[index].Inputs, nodeID)
		}
		sort.Strings(bundle.Stages[index].Inputs)
	}
	if !foundStage {
		t.Fatal("canonical lifecycle is missing the verify stage")
	}
}

func readGeneratedAssuranceArtifacts(t *testing.T, root string) map[string][]byte {
	t.Helper()
	paths := []string{evidenceDAGPath, lifecyclePathDefault, publicContractPath, checkpointPath}
	artifacts := make(map[string][]byte, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			t.Fatalf("read generated artifact %s: %v", path, err)
		}
		artifacts[path] = data
	}
	return artifacts
}
