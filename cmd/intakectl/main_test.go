package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

func TestSignOwnerActionsAcceptsInjectedEnvironmentKeyWithoutDisclosure(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secret := hex.EncodeToString(privateKey)
	const secretEnvironment = "TEST_OWNER_ED25519_PRIVATE_KEY"
	t.Setenv(secretEnvironment, secret)

	now := time.Date(2026, 8, 24, 13, 0, 0, 0, time.UTC)
	requestPath := writeJSONTestFile(t, "request.json", validOwnerRequest(now), 0o600)
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"sign-owner-actions", "--request", requestPath,
		"--private-key-env", secretEnvironment,
	}, &stdout, &stderr, now)
	if code != 0 {
		t.Fatalf("sign command returned %d: %s", code, stderr.String())
	}
	if _, exists := os.LookupEnv(secretEnvironment); exists {
		t.Fatal("sign command left injected secret in the process environment")
	}
	if strings.Contains(stdout.String(), secret) || strings.Contains(stderr.String(), secret) {
		t.Fatal("sign command disclosed injected private key material")
	}
	var actions []intake.Action
	if err := intake.DecodeStrict(stdout.Bytes(), &actions); err != nil {
		t.Fatal(err)
	}
	if len(actions) != 4 {
		t.Fatalf("got %d owner actions, want 4", len(actions))
	}
}

func TestSignOwnerActionsRejectsAmbiguousKeySourcesBeforeReadingEither(t *testing.T) {
	now := time.Date(2026, 8, 24, 13, 0, 0, 0, time.UTC)
	requestPath := writeJSONTestFile(t, "request.json", validOwnerRequest(now), 0o600)
	keyPath := filepath.Join(t.TempDir(), "missing-private-key")
	const secretEnvironment = "TEST_OWNER_AMBIGUOUS_PRIVATE_KEY"
	t.Setenv(secretEnvironment, "do-not-read-this-value")
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"sign-owner-actions", "--request", requestPath,
		"--private-key-file", keyPath, "--private-key-env", secretEnvironment,
	}, &stdout, &stderr, now)
	if code != 2 || !strings.Contains(stderr.String(), "exactly one private-key source") {
		t.Fatalf("ambiguous sources returned %d, stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if value := os.Getenv(secretEnvironment); value != "do-not-read-this-value" {
		t.Fatal("rejected ambiguous command inspected or mutated the environment secret")
	}
}

func TestPromoteOwnerInputsRejectsUnknownAuthorityFieldWithoutStateMutation(t *testing.T) {
	root := t.TempDir()
	authorityPath := filepath.Join(root, "authority.json")
	if err := os.WriteFile(authorityPath, []byte(`{"schema_version":"1.0.0","unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	actionsPath := filepath.Join(root, "actions.json")
	manifestPath := filepath.Join(root, "materialization.json")
	if err := os.WriteFile(actionsPath, []byte("[]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	evidenceDirectory := filepath.Join(root, "evidence")
	materializationRoot := filepath.Join(root, "materialized")
	ledgerDirectory := filepath.Join(root, "nonce-ledger")
	promotionStore := filepath.Join(root, "promotion-store")
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"promote-owner-inputs",
		"--evidence-dir", evidenceDirectory,
		"--authority-file", authorityPath,
		"--signed-actions-file", actionsPath,
		"--materialization-manifest", manifestPath,
		"--materialization-root", materializationRoot,
		"--nonce-ledger", ledgerDirectory,
		"--promotion-store", promotionStore,
	}, &stdout, &stderr, time.Date(2026, 8, 24, 13, 0, 0, 0, time.UTC))
	if code != 1 || !strings.Contains(stderr.String(), "unknown field") {
		t.Fatalf("unknown authority field returned %d, stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	for _, path := range []string{ledgerDirectory, promotionStore} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("rejected authority mutated protected state at %s: %v", path, err)
		}
	}
}

func TestPromoteOwnerInputsRequiresOwnerOnlyAuthorityFile(t *testing.T) {
	root := t.TempDir()
	authorityPath := filepath.Join(root, "authority.json")
	if err := os.WriteFile(authorityPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"promote-owner-inputs",
		"--evidence-dir", filepath.Join(root, "evidence"),
		"--authority-file", authorityPath,
		"--signed-actions-file", filepath.Join(root, "actions.json"),
		"--materialization-manifest", filepath.Join(root, "materialization.json"),
		"--materialization-root", filepath.Join(root, "materialized"),
		"--nonce-ledger", filepath.Join(root, "nonce-ledger"),
		"--promotion-store", filepath.Join(root, "promotion-store"),
	}, &stdout, &stderr, time.Date(2026, 8, 24, 13, 0, 0, 0, time.UTC))
	if code != 1 || !strings.Contains(stderr.String(), "cannot read protected authority file") {
		t.Fatalf("unsafe authority mode returned %d, stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestPromoteOwnerInputsRejectsUnknownMaterializationFieldWithoutNonceState(t *testing.T) {
	root := t.TempDir()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authority := intake.OwnerAuthorityDocument{
		SchemaVersion: "1.0.0", AuthorityMode: intake.SingleOwnerAuthorityMode,
		OwnerActorID: intake.RequiredOwnerActor,
		Identity: intake.Identity{
			ActorID: intake.RequiredOwnerActor, AuthorityMode: intake.SingleOwnerAuthorityMode,
			AllowedRoles: append([]string(nil), intake.SingleOwnerActionRoles...),
			KeyID:        "owner-test-key", PublicKey: hex.EncodeToString(publicKey),
		},
		Snapshot: intake.Snapshot{
			RoleDigest:       intake.DigestBytes([]byte("roles")),
			RevocationDigest: intake.DigestBytes([]byte("revocations")),
		},
	}
	authorityPath := writeJSONTestFile(t, "authority.json", authority, 0o600)
	actionsPath := writeJSONTestFile(t, "actions.json", []intake.Action{}, 0o600)
	manifestPath := filepath.Join(root, "materialization.json")
	if err := os.WriteFile(manifestPath, []byte(`{"schema_version":"1.0.0","unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ledgerDirectory := filepath.Join(root, "nonce-ledger")
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"promote-owner-inputs",
		"--evidence-dir", filepath.Join(root, "evidence"),
		"--authority-file", authorityPath,
		"--signed-actions-file", actionsPath,
		"--materialization-manifest", manifestPath,
		"--materialization-root", filepath.Join(root, "materialized"),
		"--nonce-ledger", ledgerDirectory,
		"--promotion-store", filepath.Join(root, "promotion-store"),
	}, &stdout, &stderr, time.Date(2026, 8, 24, 13, 0, 0, 0, time.UTC))
	if code != 1 || !strings.Contains(stderr.String(), "unknown field") {
		t.Fatalf("unknown manifest field returned %d, stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if _, err := os.Lstat(ledgerDirectory); !os.IsNotExist(err) {
		t.Fatalf("strict manifest rejection mutated nonce state: %v", err)
	}
}

func validOwnerRequest(now time.Time) intake.OwnerActionRequest {
	return intake.OwnerActionRequest{
		ActorID: intake.RequiredOwnerActor, KeyID: "owner-test-key",
		ArtifactDigest: intake.DigestBytes([]byte("candidate")),
		PolicyVersion:  intake.BasePolicyVersion, PolicyDigest: intake.BasePolicyDigest,
		PolicyAmendmentVersion: intake.SingleOwnerAmendmentVersion,
		PolicyAmendmentDigest:  intake.SingleOwnerAmendmentDigest,
		IssuedAt:               now, ExpiresAt: now.Add(time.Hour),
		RoleSnapshotDigest:          intake.DigestBytes([]byte("roles")),
		RevocationSnapshotDigest:    intake.DigestBytes([]byte("revocations")),
		VulnerabilitySnapshotDigest: intake.DigestBytes([]byte("vulnerabilities")),
		Nonces: []string{
			"owner-cli-test-nonce-000001", "owner-cli-test-nonce-000002",
			"owner-cli-test-nonce-000003", "owner-cli-test-nonce-000004",
		},
		RiskRationale: "test-only quarantined laboratory acceptance",
	}
}

func writeJSONTestFile(t *testing.T, name string, value any, mode os.FileMode) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, append(data, '\n'), mode); err != nil {
		t.Fatal(err)
	}
	return path
}
