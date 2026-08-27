package corpora

import "testing"

func TestCommittedClientHandshakeProjectionReconciles(t *testing.T) {
	projection, err := LoadAndVerifyClientHandshakeProjection(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(projection.AdditiveVectors) != 18 || len(projection.Nonclaims) != 6 {
		t.Fatalf("unexpected additive/nonclaim inventory: %d/%d", len(projection.AdditiveVectors), len(projection.Nonclaims))
	}
}

func TestCommittedClientHandshakeEvidenceClosesExactArtifacts(t *testing.T) {
	if err := VerifyClientHandshakeEvidence(repoRoot(t)); err != nil {
		t.Fatal(err)
	}
}
