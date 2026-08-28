package cutover

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var canonicalInputPaths = []string{
	"evidence/intake/cutover-contract.json",
	"assurance/candidate-manifest.json",
	"evidence/refinement-replay.json",
	"evidence/performance.json",
	"java-oracle/pom.xml",
}

func fixtureRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, relative := range canonicalInputPaths {
		source := filepath.Join(repositoryRootForTests(t), filepath.FromSlash(relative))
		content, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func repositoryRootForTests(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func TestCaptureAndVerifyCanonicalFixtureMechanics(t *testing.T) {
	root := fixtureRoot(t)
	captured, err := Capture(root)
	if err != nil {
		t.Fatal(err)
	}
	if captured.MechanicsStatus != MechanicsPass || captured.CutoverAcceptance != CutoverBlocked {
		t.Fatalf("capture = %+v", captured)
	}
	if captured.ShadowComparisons != 32 || captured.RustSelections != 2 || captured.FailedAttempts != 1 {
		t.Fatalf("fixture counts = %+v", captured)
	}
	if captured.RollbackActions != 3 || captured.SoakTicks != 32 || captured.ReconciledEffects != 15 || captured.DuplicateEffectsSuppressed != 1 {
		t.Fatalf("rehearsal accounting = %+v", captured)
	}
	verified, err := Verify(root)
	if err != nil {
		t.Fatal(err)
	}
	if verified != captured {
		t.Fatalf("verify summary = %+v, capture = %+v", verified, captured)
	}

	want := []string{
		"cutover/contract.json", "cutover/shadow.json", "cutover/canary.json",
		"cutover/rollback.json", "cutover/soak.json", "evidence/cutover.json",
	}
	for _, relative := range want {
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatal(err)
		}
		if len(content) == 0 || content[len(content)-1] != '\n' || !json.Valid(content) {
			t.Fatalf("artifact %s is not canonical newline-terminated JSON", relative)
		}
	}
}

func TestVerifyRejectsAuthorityAndArtifactDrift(t *testing.T) {
	root := fixtureRoot(t)
	if _, err := Capture(root); err != nil {
		t.Fatal(err)
	}

	shadowPath := filepath.Join(root, "cutover", "shadow.json")
	shadow, err := os.ReadFile(shadowPath)
	if err != nil {
		t.Fatal(err)
	}
	shadow = []byte(strings.Replace(string(shadow), "SHADOW_VERIFIED_FIXTURE", "CUTOVER_READY", 1))
	if err := os.WriteFile(shadowPath, shadow, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(root); failureCode(err) != FailureCutoverReadyForbidden {
		t.Fatalf("forged readiness error = %v", err)
	}

	root = fixtureRoot(t)
	intakePath := filepath.Join(root, "evidence", "intake", "cutover-contract.json")
	if err := os.WriteFile(intakePath, []byte(`{"authority":"assurance/developer-tools/cutover-contract.json"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Capture(root); failureCode(err) != FailureInputDigestMismatch {
		t.Fatalf("noncanonical authority error = %v", err)
	}
}

func TestVerifyReturnsTypedPhaseInvariantFailures(t *testing.T) {
	mutations := []struct {
		old, new string
		want     FailureCode
	}{
		{"CANARY_VERIFIED_FIXTURE", "CUTOVER_BLOCKED", FailureStateSkipOrReorder},
		{"SYNTHETIC_FIXTURE_NOT_A_MEASUREMENT", "MEASURED", FailureResourceFixturePromoted},
		{`"preserved": true`, `"preserved": false`, FailureFailedAttemptNotRetained},
	}
	for _, mutation := range mutations {
		root := fixtureRoot(t)
		if _, err := Capture(root); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "cutover", "canary.json")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		changed := strings.Replace(string(raw), mutation.old, mutation.new, 1)
		if changed == string(raw) {
			t.Fatalf("mutation source %q absent", mutation.old)
		}
		if err := os.WriteFile(path, []byte(changed), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(root); failureCode(err) != mutation.want {
			t.Fatalf("mutation %q error = %v, want %s", mutation.old, err, mutation.want)
		}
	}
}

func TestCaptureRejectsSymlinkAndStrandedLock(t *testing.T) {
	root := fixtureRoot(t)
	if err := os.Mkdir(filepath.Join(root, "cutover"), 0o755); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(filepath.Join(outside, "contract.json"), filepath.Join(root, "cutover", "contract.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := Capture(root); failureCode(err) != FailureInputSymlinkOrNonregular {
		t.Fatalf("symlink error = %v", err)
	}

	root = fixtureRoot(t)
	if err := os.Mkdir(filepath.Join(root, "cutover"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "cutover", ".capture.lock"), []byte("retained"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Capture(root); failureCode(err) != FailureCaptureLocked {
		t.Fatalf("stranded lock error = %v", err)
	}
}

func TestVerifyRejectsMissingAndUnknownArtifacts(t *testing.T) {
	root := fixtureRoot(t)
	if _, err := Capture(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "cutover", "soak.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(root); failureCode(err) != FailureInputAbsent {
		t.Fatalf("missing artifact error = %v", err)
	}

	root = fixtureRoot(t)
	if _, err := Capture(root); err != nil {
		t.Fatal(err)
	}
	contractPath := filepath.Join(root, "cutover", "contract.json")
	content, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatal(err)
	}
	content = append(content[:len(content)-2], []byte(`,"unknown":true}\n`)...)
	if err := os.WriteFile(contractPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(root); failureCode(err) != FailureArtifactDrift {
		t.Fatalf("unknown field error = %v", err)
	}
}

func failureCode(err error) FailureCode {
	var failure *Failure
	if errors.As(err, &failure) {
		return failure.Code
	}
	return ""
}

func TestFixtureRootContainsOnlyExpectedInputs(t *testing.T) {
	root := fixtureRoot(t)
	count := 0
	if err := filepath.WalkDir(root, func(_ string, entry fs.DirEntry, err error) error {
		if err == nil && !entry.IsDir() {
			count++
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if count != len(canonicalInputPaths) {
		t.Fatalf("fixture input count = %d", count)
	}
}
