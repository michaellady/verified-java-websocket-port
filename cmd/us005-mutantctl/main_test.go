package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func fixture(t *testing.T) (pristine, overlay, out string) {
	t.Helper()
	base := t.TempDir()
	pristine = filepath.Join(base, "pristine")
	overlay = filepath.Join(base, "us005-jm-example")
	out = filepath.Join(base, "staged")
	writeFile(t, filepath.Join(pristine, "OracleMain.java"), "class OracleMain {}\n")
	writeFile(t, filepath.Join(pristine, "OracleEngine.java"), "class OracleEngine {}\n")
	writeFile(t, filepath.Join(overlay, "OracleEngine.java"),
		"class OracleEngine { /* MUTANT us005-jm-example */ }\n")
	return pristine, overlay, out
}

func TestStageAppliesOverlayAndKeepsPristineUntouched(t *testing.T) {
	pristine, overlay, out := fixture(t)
	pristineBefore, err := os.ReadFile(filepath.Join(pristine, "OracleEngine.java"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := stage(pristine, overlay, out)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	staged, err := os.ReadFile(filepath.Join(out, "src", "OracleEngine.java"))
	if err != nil {
		t.Fatalf("staged overlay missing: %v", err)
	}
	if string(staged) != "class OracleEngine { /* MUTANT us005-jm-example */ }\n" {
		t.Fatalf("staged OracleEngine.java is not the overlay content: %q", staged)
	}
	untouched, err := os.ReadFile(filepath.Join(out, "src", "OracleMain.java"))
	if err != nil || string(untouched) != "class OracleMain {}\n" {
		t.Fatalf("non-overlaid pristine source not staged verbatim: %v %q", err, untouched)
	}
	pristineAfter, err := os.ReadFile(filepath.Join(pristine, "OracleEngine.java"))
	if err != nil || string(pristineAfter) != string(pristineBefore) {
		t.Fatalf("pristine tree was modified by staging")
	}
	if manifest.MutantID != "us005-jm-example" {
		t.Fatalf("manifest mutant id %q", manifest.MutantID)
	}
	if len(manifest.Overlaid) != 1 || manifest.Overlaid[0].File != "OracleEngine.java" {
		t.Fatalf("manifest overlaid records: %+v", manifest.Overlaid)
	}
	record := manifest.Overlaid[0]
	if record.PristineSHA256 == "" || record.MutantSHA256 == "" ||
		record.PristineSHA256 == record.MutantSHA256 {
		t.Fatalf("manifest must record distinct pristine and mutant digests: %+v", record)
	}
}

func TestStageWritesManifestFile(t *testing.T) {
	pristine, overlay, out := fixture(t)
	if _, err := stage(pristine, overlay, out); err != nil {
		t.Fatalf("stage: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(out, "staged-manifest.json"))
	if err != nil {
		t.Fatalf("staged-manifest.json missing: %v", err)
	}
	var parsed StageManifest
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("staged-manifest.json is not valid JSON: %v", err)
	}
	if parsed.MutantID != "us005-jm-example" {
		t.Fatalf("persisted manifest mutant id %q", parsed.MutantID)
	}
}

func TestStageRejectsOverlayForUnknownFile(t *testing.T) {
	pristine, overlay, out := fixture(t)
	writeFile(t, filepath.Join(overlay, "Invented.java"), "class Invented {}\n")
	if _, err := stage(pristine, overlay, out); err == nil {
		t.Fatalf("overlay naming a file absent from the pristine tree must fail")
	}
}

func TestStageRejectsIdenticalOverlay(t *testing.T) {
	pristine, overlay, out := fixture(t)
	writeFile(t, filepath.Join(overlay, "OracleEngine.java"), "class OracleEngine {}\n")
	if _, err := stage(pristine, overlay, out); err == nil {
		t.Fatalf("an overlay byte-identical to pristine is not a mutant and must fail")
	}
}

func TestStageRejectsEmptyOverlayDir(t *testing.T) {
	pristine, _, out := fixture(t)
	empty := filepath.Join(t.TempDir(), "us005-jm-empty")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := stage(pristine, empty, out); err == nil {
		t.Fatalf("an overlay directory with no .java files must fail")
	}
}
