package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
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

// fakeTool writes a trivial executable stand-in for javac/jar that records
// its own invocation, so build tests can prove the toolchain is (or is not)
// reached without depending on a JDK.
func fakeTool(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path,
		[]byte("#!/bin/sh\ntouch \"$0.invoked\"\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func toolInvoked(path string) bool {
	_, err := os.Stat(path + ".invoked")
	return err == nil
}

// stagedFixture stages a valid mutant tree and fabricates a runtime jar file
// (build only checks its existence before the compile step).
func stagedFixture(t *testing.T) (staged, runtimeJar string) {
	t.Helper()
	pristine, overlay, out := fixture(t)
	if _, err := stage(pristine, overlay, out); err != nil {
		t.Fatalf("stage: %v", err)
	}
	runtimeJar = filepath.Join(t.TempDir(), "Java-WebSocket-1.6.0.jar")
	if err := os.WriteFile(runtimeJar, []byte("pinned-jar-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	return out, runtimeJar
}

func TestStageRefusesExistingOutputTree(t *testing.T) {
	pristine, overlay, out := fixture(t)
	if _, err := stage(pristine, overlay, out); err != nil {
		t.Fatalf("first stage: %v", err)
	}
	if _, err := stage(pristine, overlay, out); err == nil {
		t.Fatalf("staging into an existing output tree must fail closed, not reuse it")
	}
}

func TestStageRefusesPrepopulatedOutputPath(t *testing.T) {
	pristine, overlay, out := fixture(t)
	writeFile(t, filepath.Join(out, "stale.txt"), "stale\n")
	if _, err := stage(pristine, overlay, out); err == nil {
		t.Fatalf("staging into a pre-populated output path must fail closed")
	}
}

func TestStageRefusesSymlinkedOutputDestination(t *testing.T) {
	pristine, overlay, _ := fixture(t)
	elsewhere := t.TempDir()
	out := filepath.Join(t.TempDir(), "staged-link")
	if err := os.Symlink(elsewhere, out); err != nil {
		t.Fatal(err)
	}
	if _, err := stage(pristine, overlay, out); err == nil {
		t.Fatalf("staging into a symlinked destination must fail closed")
	}
	entries, err := os.ReadDir(elsewhere)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("stage wrote through the symlink into %s: %v", elsewhere, entries)
	}
}

func TestBuildRefusesMissingStagedManifest(t *testing.T) {
	staged, runtimeJar := stagedFixture(t)
	if err := os.Remove(filepath.Join(staged, "staged-manifest.json")); err != nil {
		t.Fatal(err)
	}
	tools := t.TempDir()
	javac, jar := fakeTool(t, tools, "javac"), fakeTool(t, tools, "jar")
	if err := build(staged, runtimeJar, javac, jar, io.Discard, io.Discard); err == nil {
		t.Fatalf("build without staged-manifest.json must fail closed")
	}
	if toolInvoked(javac) || toolInvoked(jar) {
		t.Fatalf("build must not invoke the toolchain on an unverified tree")
	}
}

func TestBuildRefusesModifiedStagedSource(t *testing.T) {
	staged, runtimeJar := stagedFixture(t)
	writeFile(t, filepath.Join(staged, "src", "OracleEngine.java"),
		"class OracleEngine { /* tampered after staging */ }\n")
	tools := t.TempDir()
	javac, jar := fakeTool(t, tools, "javac"), fakeTool(t, tools, "jar")
	err := build(staged, runtimeJar, javac, jar, io.Discard, io.Discard)
	if err == nil {
		t.Fatalf("a staged source modified after staging must fail the build")
	}
	if !strings.Contains(err.Error(), "STAGED_DIGEST_MISMATCH") {
		t.Fatalf("expected STAGED_DIGEST_MISMATCH, got: %v", err)
	}
	if toolInvoked(javac) || toolInvoked(jar) {
		t.Fatalf("build must not compile a tree that fails digest verification")
	}
}

func TestBuildRefusesExtraStagedFile(t *testing.T) {
	staged, runtimeJar := stagedFixture(t)
	writeFile(t, filepath.Join(staged, "src", "Smuggled.java"), "class Smuggled {}\n")
	tools := t.TempDir()
	javac, jar := fakeTool(t, tools, "javac"), fakeTool(t, tools, "jar")
	err := build(staged, runtimeJar, javac, jar, io.Discard, io.Discard)
	if err == nil {
		t.Fatalf("a source absent from staged-manifest.json must fail the build")
	}
	if !strings.Contains(err.Error(), "STAGED_EXTRA_FILE") {
		t.Fatalf("expected STAGED_EXTRA_FILE, got: %v", err)
	}
	if toolInvoked(javac) || toolInvoked(jar) {
		t.Fatalf("build must not compile unmanifested sources")
	}
}

func TestBuildRefusesMissingStagedFile(t *testing.T) {
	staged, runtimeJar := stagedFixture(t)
	if err := os.Remove(filepath.Join(staged, "src", "OracleMain.java")); err != nil {
		t.Fatal(err)
	}
	tools := t.TempDir()
	javac, jar := fakeTool(t, tools, "javac"), fakeTool(t, tools, "jar")
	err := build(staged, runtimeJar, javac, jar, io.Discard, io.Discard)
	if err == nil {
		t.Fatalf("a manifest entry missing from src/ must fail the build")
	}
	if !strings.Contains(err.Error(), "STAGED_MISSING_FILE") {
		t.Fatalf("expected STAGED_MISSING_FILE, got: %v", err)
	}
	if toolInvoked(javac) || toolInvoked(jar) {
		t.Fatalf("build must not compile an incomplete staged tree")
	}
}

func TestBuildCompilesFromCleanClassesDirAndDropsStaleJar(t *testing.T) {
	staged, runtimeJar := stagedFixture(t)
	stale := filepath.Join(staged, "classes", "Stale.class")
	writeFile(t, stale, "stale bytecode")
	staleJar := filepath.Join(staged, "java-oracle-mutant.jar")
	writeFile(t, staleJar, "stale jar")
	tools := t.TempDir()
	javac, jar := fakeTool(t, tools, "javac"), fakeTool(t, tools, "jar")
	if err := build(staged, runtimeJar, javac, jar, io.Discard, io.Discard); err != nil {
		t.Fatalf("build on a verified staged tree: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("pre-existing class files must not survive into the packaging dir")
	}
	if _, err := os.Stat(staleJar); !os.IsNotExist(err) {
		t.Fatalf("a stale mutant jar must be removed before packaging")
	}
	if !toolInvoked(javac) || !toolInvoked(jar) {
		t.Fatalf("a verified build must reach javac and jar")
	}
}

func TestRunStageCLIStagesAndPrintsManifest(t *testing.T) {
	pristine, overlay, out := fixture(t)
	var stdout, stderr strings.Builder
	code := run([]string{"stage", "--pristine", pristine, "--overlay", overlay,
		"--out", out}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("stage CLI exit %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "us005-jm-example") {
		t.Fatalf("stage CLI must print the manifest, got: %s", stdout.String())
	}
}

func TestRunStageCLIFailsClosedOnExistingOut(t *testing.T) {
	pristine, overlay, out := fixture(t)
	var stdout, stderr strings.Builder
	if code := run([]string{"stage", "--pristine", pristine, "--overlay", overlay,
		"--out", out}, &stdout, &stderr); code != 0 {
		t.Fatalf("first stage CLI exit %d, stderr: %s", code, stderr.String())
	}
	stderr.Reset()
	if code := run([]string{"stage", "--pristine", pristine, "--overlay", overlay,
		"--out", out}, &stdout, &stderr); code != 1 {
		t.Fatalf("stage CLI into an existing tree must exit 1, got %d", code)
	}
	if stderr.Len() == 0 {
		t.Fatalf("stage CLI failure must explain itself on stderr")
	}
}

func TestRunBuildCLIFailsClosedOnTamperedTree(t *testing.T) {
	staged, runtimeJar := stagedFixture(t)
	writeFile(t, filepath.Join(staged, "src", "OracleEngine.java"),
		"class OracleEngine { /* tampered */ }\n")
	tools := t.TempDir()
	javac, jar := fakeTool(t, tools, "javac"), fakeTool(t, tools, "jar")
	var stdout, stderr strings.Builder
	code := run([]string{"build", "--staged", staged,
		"--java-websocket-jar", runtimeJar, "--javac", javac, "--jar", jar},
		&stdout, &stderr)
	if code != 1 {
		t.Fatalf("build CLI on a tampered tree must exit 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "STAGED_DIGEST_MISMATCH") {
		t.Fatalf("build CLI stderr must name the mismatch, got: %s", stderr.String())
	}
}

func TestRunBuildCLIBuildsVerifiedTree(t *testing.T) {
	staged, runtimeJar := stagedFixture(t)
	tools := t.TempDir()
	javac, jar := fakeTool(t, tools, "javac"), fakeTool(t, tools, "jar")
	var stdout, stderr strings.Builder
	code := run([]string{"build", "--staged", staged,
		"--java-websocket-jar", runtimeJar, "--javac", javac, "--jar", jar},
		&stdout, &stderr)
	if code != 0 {
		t.Fatalf("build CLI exit %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "built") {
		t.Fatalf("build CLI must report the built jar, got: %s", stdout.String())
	}
}

func TestRunUsageErrors(t *testing.T) {
	var stdout, stderr strings.Builder
	for _, arguments := range [][]string{nil, {"frobnicate"}, {"stage"}, {"build"}} {
		if code := run(arguments, &stdout, &stderr); code != 2 {
			t.Fatalf("run(%v) must exit 2 with usage, got %d", arguments, code)
		}
	}
}
