package intake

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRetainedEvidenceFailsClosedOnRealBlockers(t *testing.T) {
	t.Parallel()
	report, err := VerifyEvidenceDir(filepath.Join("..", "..", "evidence", "intake"), time.Date(2026, 8, 24, 13, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if report.EvidenceRoot != "sha256:1e226796e8bcc248b10e763211ed8eff92a93caf71adec06d07862be0a0a20a7" {
		t.Fatalf("unexpected evidence root %s", report.EvidenceRoot)
	}
	assertFindingCodes(t, report.Blockers, "OWNER_RISK_DISPOSITION_REQUIRED", "MISSING_PROMOTION_REQUIREMENT")
}

func TestEvidenceMutationsDenyBeforePromotion(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		old  string
		new  string
		code string
	}{
		{"tenant", `"company": "open-source-projects"`, `"company": "other-company"`, "CROSS_COMPANY_REFERENCE"},
		{"classification", `"default_classification": "QUARANTINED"`, `"default_classification": ""`, "UNCLASSIFIED_OBJECT"},
		{"digest", "f44e7647b4aee40819b51947cf0bb5f35a48293a202b77704c3c79e98ed13cb4", "a44e7647b4aee40819b51947cf0bb5f35a48293a202b77704c3c79e98ed13cb4", "ARTIFACT_DRIFT"},
		{"url", "https://github.com/TooTallNate/Java-WebSocket/archive/da3cf2a777aed862f2f5b5cf060cae7969958667.tar.gz", "https://github.com/TooTallNate/Java-WebSocket/archive/v1.6.0.tar.gz", "MUTABLE_SOURCE_REFERENCE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := copyEvidence(t)
			path := filepath.Join(directory, "source-pins.json")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			mutated := strings.Replace(string(data), tc.old, tc.new, 1)
			if mutated == string(data) {
				t.Fatal("test mutation did not apply")
			}
			if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err = VerifyEvidenceDir(directory, time.Date(2026, 8, 24, 13, 0, 0, 0, time.UTC))
			assertCode(t, err, tc.code)
		})
	}
}

func TestSandboxAndLinuxDeferralMutationsDeny(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		file string
		edit func(string) string
		code string
	}{
		{"secrets", "toolchain-pins.json", func(data string) string {
			return strings.Replace(data, `"secrets": "none"`, `"secrets": "available"`, 1)
		}, "FORBIDDEN_SANDBOX_ACCESS"},
		{"forbidden-access", "toolchain-pins.json", func(data string) string {
			return strings.Replace(data, `"forbidden_access": ["protected-held-out", "canonical-evidence", "release-signing", "production-credentials", "cross-company-data"]`, `"forbidden_access": []`, 1)
		}, "FORBIDDEN_SANDBOX_ACCESS"},
		{"linux-deferral", "source-pins.json", func(data string) string {
			start := strings.Index(data, `"deferred_platform_inputs": [`)
			if start < 0 {
				return data
			}
			return data[:start] + `"deferred_platform_inputs": []` + "\n}"
		}, "MISSING_PROMOTION_REQUIREMENT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := copyEvidence(t)
			path := filepath.Join(directory, tc.file)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			mutated := tc.edit(string(data))
			if mutated == string(data) {
				t.Fatal("test mutation did not apply")
			}
			if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err = VerifyEvidenceDir(directory, time.Date(2026, 8, 24, 13, 0, 0, 0, time.UTC))
			assertCode(t, err, tc.code)
		})
	}
}

func TestRequiredActionTraceRejectsMissingReorderedOrMutatedRecords(t *testing.T) {
	now := time.Date(2026, 8, 24, 13, 0, 0, 0, time.UTC)
	for _, testCase := range []struct {
		name   string
		mutate func(*promotionDocument)
	}{
		{"missing", func(document *promotionDocument) { document.RequiredActions = document.RequiredActions[:3] }},
		{"reordered", func(document *promotionDocument) {
			document.RequiredActions[0], document.RequiredActions[1] = document.RequiredActions[1], document.RequiredActions[0]
		}},
		{"role", func(document *promotionDocument) { document.RequiredActions[0].Role = "release-attestor" }},
		{"sandbox", func(document *promotionDocument) {
			document.RequiredActions[0].RequestedSandboxAccess = []string{"quarantined-source"}
		}},
		{"publication", func(document *promotionDocument) { document.RequiredActions[0].PublicationRequested = true }},
		{"status", func(document *promotionDocument) {
			document.RequiredActions[0].Status = "OWNER_SIGNED_AND_PROTECTED_VERIFIED"
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			directory := copyEvidence(t)
			path := filepath.Join(directory, "promotion-receipts.json")
			var document promotionDocument
			readStrictTestFile(t, path, &document)
			testCase.mutate(&document)
			writeJSONTestFile(t, path, document)
			_, err := VerifyEvidenceDir(directory, now)
			assertCode(t, err, "ACTION_SCOPE_MISMATCH")
		})
	}
}

func TestAuthorizeRejectsAuthoritativeRoleConflictAndRevocation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	action := validAction(now)
	action.Signature = hex.EncodeToString(ed25519.Sign(privateKey, CanonicalAction(action)))
	identity := Identity{ActorID: action.ActorID, AuthorityMode: SingleOwnerAuthorityMode, AllowedRoles: []string{"release-attestor"}, KeyID: action.KeyID, PublicKey: hex.EncodeToString(publicKey)}
	err = Authorize(action, map[string]Identity{action.ActorID: identity}, Snapshot{RoleDigest: action.RoleSnapshotDigest, RevocationDigest: action.RevocationSnapshotDigest}, NewMemoryLedger(), now)
	assertCode(t, err, "ROLE_CONFLICT")

	identity.AllowedRoles = []string{action.Role}
	identity.Revoked = true
	err = Authorize(action, map[string]Identity{action.ActorID: identity}, Snapshot{RoleDigest: action.RoleSnapshotDigest, RevocationDigest: action.RevocationSnapshotDigest}, NewMemoryLedger(), now)
	assertCode(t, err, "REVOKED_AUTHORIZATION")
}

func copyEvidence(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	source := filepath.Join("..", "..", "evidence", "intake")
	for _, name := range evidenceFiles {
		data, err := os.ReadFile(filepath.Join(source, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return directory
}

func readStrictTestFile(t *testing.T, path string, target any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := DecodeStrict(data, target); err != nil {
		t.Fatal(err)
	}
}

func writeJSONTestFile(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertFindingCodes(t *testing.T, findings []Finding, codes ...string) {
	t.Helper()
	if len(findings) != len(codes) {
		t.Fatalf("got %d findings, want %d: %+v", len(findings), len(codes), findings)
	}
	for index, code := range codes {
		if findings[index].Code != code {
			t.Fatalf("finding %d is %s, want %s", index, findings[index].Code, code)
		}
	}
}
