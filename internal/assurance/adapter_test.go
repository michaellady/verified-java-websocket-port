package assurance

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	vendorprotocol "github.com/michaellady/verified-java-to-rust/foundation/protocol"
)

func TestVerifyCanonicalLifecycle(t *testing.T) {
	root := repoRoot(t)
	verdict, err := Verify(context.Background(), Request{
		RootPath:      root,
		LifecyclePath: "assurance/lifecycle.json",
		Mode:          ModeVerify,
	})
	if err != nil {
		t.Fatalf("verify canonical lifecycle: %v", err)
	}
	if verdict.State != "BLOCKED" {
		t.Fatalf("state = %q, want BLOCKED", verdict.State)
	}
	if len(verdict.Findings) != 0 {
		t.Fatalf("canonical lifecycle produced findings: %+v", verdict.Findings)
	}
	if verdict.Assurance != assuranceCeiling {
		t.Fatalf("assurance = %q, want %q", verdict.Assurance, assuranceCeiling)
	}
	if verdict.IndependentReviewClaimed {
		t.Fatal("canonical lifecycle must not claim independent review")
	}
	if verdict.SnapshotRoot == "" || verdict.PublicEvidenceRoot == "" {
		t.Fatalf("roots missing from verdict: %+v", verdict)
	}
}

func TestVerifyRejectsVendoredManifestDrift(t *testing.T) {
	root := copiedAssuranceRoot(t)
	target := filepath.Join(root, "third_party", "verified-java-to-rust-foundation", "protocol", "canonical.go")
	if err := os.WriteFile(target, []byte("drift"), 0o600); err != nil {
		t.Fatalf("drift vendored file: %v", err)
	}
	verdict, err := Verify(context.Background(), Request{
		RootPath:      root,
		LifecyclePath: "assurance/lifecycle.json",
		Mode:          ModeVerify,
	})
	if err != nil {
		t.Fatalf("verify vendored drift: %v", err)
	}
	assertFinding(t, verdict.Findings, "VENDORED_FILE_DIGEST_MISMATCH", vendorprotocol.Block)
}

func TestReplayFixturesProduceStableFindings(t *testing.T) {
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "assurance", "replay", "fixtures", "cases.json"))
	if err != nil {
		t.Fatalf("read replay cases: %v", err)
	}
	var catalog replayCaseCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		t.Fatalf("decode replay cases: %v", err)
	}
	for _, fixture := range catalog.Cases {
		t.Run(fixture.ID, func(t *testing.T) {
			verdict, err := Replay(context.Background(), Request{
				RootPath:      root,
				LifecyclePath: fixture.LifecyclePath,
				Mode:          ModeReplay,
			})
			if err != nil {
				t.Fatalf("replay fixture %s: %v", fixture.ID, err)
			}
			for _, expected := range fixture.ExpectedFindings {
				assertFinding(t, verdict.Findings, expected.Code, vendorprotocol.Disposition(expected.Disposition))
			}
		})
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return root
}

func copiedAssuranceRoot(t *testing.T) string {
	t.Helper()
	source := repoRoot(t)
	destination := t.TempDir()
	for _, relative := range []string{
		"assurance",
		"third_party",
	} {
		if err := copyDir(filepath.Join(source, relative), filepath.Join(destination, relative)); err != nil {
			t.Fatalf("copy %s: %v", relative, err)
		}
	}
	return destination
}

func copyDir(source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600)
	})
}

func assertFinding(t *testing.T, findings []vendorprotocol.Finding, code string, disposition vendorprotocol.Disposition) {
	t.Helper()
	for _, finding := range findings {
		if finding.Code == code && finding.Disposition == disposition {
			return
		}
	}
	t.Fatalf("missing finding %s/%s in %+v", code, disposition, findings)
}

type replayCaseCatalog struct {
	Cases []replayCase `json:"cases"`
}

type replayCase struct {
	ID               string                  `json:"id"`
	LifecyclePath    string                  `json:"lifecycle_path"`
	ExpectedFindings []replayCaseExpectation `json:"expected_findings"`
}

type replayCaseExpectation struct {
	Code        string `json:"code"`
	Disposition string `json:"disposition"`
}
