package projection_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/projection"
)

var inputPaths = []string{
	"contracts/laboratory-template.json",
	"assurance/candidate-manifest.json",
	"assurance/candidate-claims.json",
	"assurance/formal/obligation-catalog.json",
	"assurance/reviews/human.json",
	"assurance/reviews/codex.json",
	"assurance/reviews/reality.json",
	"evidence/cutover.json",
	"security/release-firewall.json",
	"schemas/us027-receipt-1.0.0.schema.json",
	"schemas/us027-independent-replay-1.0.0.schema.json",
	"schemas/us027-public-snapshot-1.0.0.schema.json",
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func fixtureRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	source := repositoryRoot(t)
	for _, name := range inputPaths {
		raw, err := os.ReadFile(filepath.Join(source, filepath.FromSlash(name)))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		target := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestCaptureVerifyBindsRelaxedProjection(t *testing.T) {
	root := fixtureRoot(t)
	summary, err := projection.Capture(root)
	if err != nil {
		t.Fatal(err)
	}
	if summary.MechanicsStatus != projection.MechanicsPass || summary.AcceptanceState != projection.AcceptanceBlocked {
		t.Fatalf("unexpected ceilings: %+v", summary)
	}
	if summary.ChildStoryCount != 26 || summary.ChildMechanicsPassed != 26 || summary.StrongChildAccepted != 0 {
		t.Fatalf("unexpected child ledger: %+v", summary)
	}
	if summary.FormalObligations != 24 || summary.FormalBlocked != 24 || summary.FormalStrongAccepted != 0 {
		t.Fatalf("unexpected obligation ledger: %+v", summary)
	}
	if _, err := projection.Verify(root); err != nil {
		t.Fatal(err)
	}
}

func TestCaptureIsByteIdenticalAndPartialSetFails(t *testing.T) {
	root := fixtureRoot(t)
	if _, err := projection.Capture(root); err != nil {
		t.Fatal(err)
	}
	before := make(map[string]string)
	for _, name := range projection.ArtifactPaths() {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		before[name] = string(raw)
	}
	if _, err := projection.Capture(root); err != nil {
		t.Fatal(err)
	}
	for _, name := range projection.ArtifactPaths() {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil || string(raw) != before[name] {
			t.Fatalf("recapture drift for %s: %v", name, err)
		}
	}
	if err := os.Remove(filepath.Join(root, "public", "README.md")); err != nil {
		t.Fatal(err)
	}
	if _, err := projection.Capture(root); err == nil {
		t.Fatal("partial bundle accepted")
	}
}

func TestVerifyRejectsInputAndPublicDrift(t *testing.T) {
	root := fixtureRoot(t)
	if _, err := projection.Capture(root); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "public", "README.md"), []byte("drift\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := projection.Verify(root); err == nil {
		t.Fatal("public drift accepted")
	}
}
