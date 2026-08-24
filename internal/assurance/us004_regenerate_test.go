package assurance

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	vendorprotocol "github.com/michaellady/verified-java-to-rust/foundation/protocol"
)

func TestUS004RegenerateCanonicalLifecycle(t *testing.T) {
	if os.Getenv("US004_REGENERATE") != "1" {
		t.Skip("set US004_REGENERATE=1 to rewrite canonical lifecycle bindings")
	}
	root := repoRoot(t)
	bundle := readLifecycleBundle(t, root, lifecyclePathDefault)
	digests := make(map[string]string, len(expectedRetainedArtifacts)+len(expectedEvidenceNodes))
	for _, artifact := range expectedRetainedArtifacts {
		data := mustReadRepoFile(t, artifact.Path)
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
}
