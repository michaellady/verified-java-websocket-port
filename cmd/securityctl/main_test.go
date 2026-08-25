package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestVerifyExactJSONAndNonzeroSemantics(t *testing.T) {
	root := filepath.Join("..", "..")
	var stdout, stderr bytes.Buffer
	if exit := run([]string{"verify", "--root", root}, &stdout, &stderr); exit != 1 {
		t.Fatalf("exit=%d stderr=%s stdout=%s", exit, stderr.String(), stdout.String())
	}
	var good map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &good); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if good["state"] != "BLOCKED_SANDBOX_ENFORCEMENT_UNAVAILABLE" {
		t.Fatalf("state=%v", good["state"])
	}
	stdout.Reset()
	stderr.Reset()
	if exit := run([]string{"verify", "--root", root, "--fixture", "good-benign-ingest"}, &stdout, &stderr); exit != 0 {
		t.Fatalf("good fixture exit=%d", exit)
	}
	stdout.Reset()
	stderr.Reset()
	if exit := run([]string{"verify", "--root", root, "--fixture", "credential-leak"}, &stdout, &stderr); exit != 1 {
		t.Fatalf("bad exit=%d", exit)
	}
	var bad map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &bad); err != nil {
		t.Fatalf("invalid bad JSON: %v", err)
	}
	findings := bad["findings"].([]any)
	if findings[0].(map[string]any)["code"] != "CREDENTIAL_DISCLOSURE" {
		t.Fatalf("findings=%#v", findings)
	}
}

func TestRootFlagIsRequired(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if exit := run([]string{"verify"}, &stdout, &stderr); exit != 2 {
		t.Fatalf("exit=%d", exit)
	}
}
