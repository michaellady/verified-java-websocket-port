package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/securitygate"
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

func TestOnlyExplicitSuccessStatesExitZero(t *testing.T) {
	for _, state := range []string{"", "BLOCKED", "BLOCKED_SANDBOX_ENFORCEMENT_UNAVAILABLE", "UNKNOWN"} {
		if verdictSucceeded(securitygate.Verdict{State: state}) {
			t.Fatalf("state %q was accepted", state)
		}
	}
	for _, state := range []string{"PASS_INGESTION_COMPONENT", "PASS_SYNTHETIC_NON_CLAIM", "PASS_PROJECTION_COMPONENT"} {
		if !verdictSucceeded(securitygate.Verdict{State: state}) {
			t.Fatalf("state %q was rejected", state)
		}
		if verdictSucceeded(securitygate.Verdict{State: state, Findings: []securitygate.Finding{{Code: "INVALID_SECURITY_POLICY"}}}) {
			t.Fatalf("state %q accepted a finding", state)
		}
	}
}
