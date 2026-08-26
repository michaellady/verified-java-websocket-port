package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func repoSchemas(t *testing.T) string {
	t.Helper()
	absolute, err := filepath.Abs("../../schemas")
	if err != nil {
		t.Fatal(err)
	}
	return absolute
}

func runCLI(t *testing.T, arguments ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(arguments, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestGenerateVerifyCalibrateEndToEnd(t *testing.T) {
	root := t.TempDir()
	protectedRoot := t.TempDir()

	code, _, stderr := runCLI(t, "generate",
		"--root", root, "--protected-root", protectedRoot)
	if code != 0 {
		t.Fatalf("generate exit %d: %s", code, stderr)
	}
	for _, path := range []string{
		"corpora/public/manifest.json", "corpora/handshake/manifest.json",
		"corpora/hidden/manifest.json", "corpora/sealed/manifest.json"} {
		if _, err := os.Stat(filepath.Join(root, path)); err != nil {
			t.Fatalf("generate did not write %s", path)
		}
	}

	code, stdout, stderr := runCLI(t, "verify",
		"--root", root, "--protected-root", protectedRoot,
		"--schemas", repoSchemas(t))
	if code != 0 {
		t.Fatalf("verify exit %d: %s / %s", code, stdout, stderr)
	}
	var verifyResult map[string]any
	if err := json.Unmarshal([]byte(stdout), &verifyResult); err != nil {
		t.Fatalf("verify output not JSON: %v", err)
	}
	if verifyResult["ok"] != true {
		t.Fatalf("verify not ok: %s", stdout)
	}

	code, stdout, stderr = runCLI(t, "calibrate",
		"--root", root, "--protected-root", protectedRoot,
		"--schemas", repoSchemas(t))
	if code != 0 {
		t.Fatalf("calibrate exit %d: %s / %s", code, stdout, stderr)
	}
	if _, err := os.Stat(filepath.Join(root, "evidence/corpus-calibration.json")); err != nil {
		t.Fatal("calibrate did not write the evidence document")
	}
	if !strings.Contains(stdout, "OFFLINE_CALIBRATED_PENDING_LIVE_EXECUTION") {
		t.Fatalf("calibrate status not reported: %s", stdout)
	}

	// A second generate run must be byte-identical (rerun reconciliation).
	before, err := os.ReadFile(filepath.Join(root, "corpora/public/scenarios.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	code, _, stderr = runCLI(t, "generate",
		"--root", root, "--protected-root", protectedRoot)
	if code != 0 {
		t.Fatalf("regenerate exit %d: %s", code, stderr)
	}
	after, err := os.ReadFile(filepath.Join(root, "corpora/public/scenarios.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("regeneration must be byte-identical")
	}
}

func TestOracleRequestsEmitsJSONL(t *testing.T) {
	root := t.TempDir()
	protectedRoot := t.TempDir()
	if code, _, stderr := runCLI(t, "generate",
		"--root", root, "--protected-root", protectedRoot); code != 0 {
		t.Fatalf("generate failed: %s", stderr)
	}
	code, stdout, stderr := runCLI(t, "oracle-requests",
		"--root", root, "--protected-root", protectedRoot, "--tier", "public")
	if code != 0 {
		t.Fatalf("oracle-requests exit %d: %s", code, stderr)
	}
	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	if len(lines) < 40 {
		t.Fatalf("too few request lines: %d", len(lines))
	}
	var request map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &request); err != nil {
		t.Fatalf("request line not JSON: %v", err)
	}
	if request["protocol"] != "java-websocket-oracle" || request["request_digest"] == nil {
		t.Fatalf("request line malformed: %s", lines[0])
	}
}

func TestEvaluateFailsClosedOnEmptyTranscript(t *testing.T) {
	root := t.TempDir()
	protectedRoot := t.TempDir()
	if code, _, stderr := runCLI(t, "generate",
		"--root", root, "--protected-root", protectedRoot); code != 0 {
		t.Fatalf("generate failed: %s", stderr)
	}
	transcript := filepath.Join(t.TempDir(), "empty.jsonl")
	if err := os.WriteFile(transcript, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := runCLI(t, "evaluate",
		"--root", root, "--protected-root", protectedRoot,
		"--tier", "public", "--transcript", transcript)
	if code == 0 {
		t.Fatal("empty transcript must not reconcile")
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("evaluate output not JSON: %v", err)
	}
	if int(report["missing"].(float64)) == 0 {
		t.Fatalf("missing count not reported: %s", stdout)
	}
}

func TestUsageOnUnknownCommand(t *testing.T) {
	code, _, stderr := runCLI(t, "warp")
	if code != 2 || !strings.Contains(stderr, "usage") {
		t.Fatalf("unknown command: code=%d stderr=%s", code, stderr)
	}
}
