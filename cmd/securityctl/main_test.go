package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
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
	if good["state"] != "PROVEN_LIVE_RLIMIT_ENVELOPE_ATTEMPT_0123" {
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
	for _, state := range []string{"", "BLOCKED", "BLOCKED_SANDBOX_ENFORCEMENT_UNAVAILABLE", "PROVEN_LIVE_RLIMIT_ENVELOPE_ATTEMPT_0123", "UNKNOWN"} {
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

func TestProjectUsesCandidateRootAndRejectsOperationSpecificRootFlagMisuse(t *testing.T) {
	content := []byte("inert public bytes")
	digest := intake.DigestBytes(content)
	objectID := "blob." + strings.TrimPrefix(digest, "sha256:")
	provenance := "scope:SYNTHETIC_NON_CLAIM/company:open-source-projects/project:verified-java-websocket-port"
	manifest := map[string]any{
		"schema_version": "1.0.0", "classification": "QUARANTINED",
		"directories": []map[string]any{{"path": "public", "collision_key": "public", "classification": "PUBLIC", "provenance": provenance}},
		"files": []map[string]any{{
			"path": "public/readme.txt", "collision_key": "public/readme.txt", "object_id": objectID,
			"digest": digest, "byte_size": len(content), "media_kind": "REGULAR", "classification": "PUBLIC",
			"provenance": provenance + "/source:" + digest,
		}},
		"hostile_executables": []any{},
	}
	manifestBytes, err := intake.CanonicalJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	store := t.TempDir()
	rootDigest, err := intake.PromoteDirectory(store, []intake.Object{
		{ID: "candidate-manifest", Digest: intake.DigestBytes(manifestBytes), Bytes: manifestBytes},
		{ID: objectID, Digest: digest, Bytes: content},
	})
	if err != nil {
		t.Fatal(err)
	}

	root := filepath.Join("..", "..")
	var stdout, stderr bytes.Buffer
	if exit := run([]string{"project", "--root", root, "--candidate-root", rootDigest, "--store", store}, &stdout, &stderr); exit != 1 {
		t.Fatalf("project exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	var verdict securitygate.Verdict
	if err := json.Unmarshal(stdout.Bytes(), &verdict); err != nil {
		t.Fatalf("project JSON: %v", err)
	}
	if len(verdict.Findings) != 1 || verdict.Findings[0].Code != "PROTECTED_CLASSIFIER_UNAVAILABLE" || verdict.ProjectionRoot == "" {
		t.Fatalf("project verdict=%#v", verdict)
	}
	stdout.Reset()
	stderr.Reset()
	if exit := run([]string{"project", "--root", root, "--candidate-root", rootDigest, "--store", store, "--fixture", "credential-leak"}, &stdout, &stderr); exit != 1 {
		t.Fatalf("unbound credential fixture exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	verdict = securitygate.Verdict{}
	if err := json.Unmarshal(stdout.Bytes(), &verdict); err != nil {
		t.Fatalf("unbound credential fixture JSON: %v", err)
	}
	if len(verdict.Findings) != 1 || verdict.Findings[0].Code != "INVALID_SECURITY_POLICY" || verdict.ProjectionRoot != "" {
		t.Fatalf("unbound credential fixture verdict=%#v", verdict)
	}

	misuse := [][]string{
		{"project", "--root", root, "--accepted-root", rootDigest, "--store", store},
		{"project", "--root", root, "--accepted-root", rootDigest, "--candidate-root", rootDigest, "--store", store},
		{"ingest", "--root", root, "--candidate-root", rootDigest, "--store", store},
		{"verify", "--root", root, "--accepted-root", rootDigest},
	}
	for _, args := range misuse {
		stdout.Reset()
		stderr.Reset()
		if exit := run(args, &stdout, &stderr); exit != 2 {
			t.Fatalf("args=%v exit=%d stdout=%s stderr=%s", args, exit, stdout.String(), stderr.String())
		}
	}
}
