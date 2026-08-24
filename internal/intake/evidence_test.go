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
	if report.EvidenceRoot != "sha256:6c4110581091c4cd9baca73fbdf1f7d5048af158ce6d28445259a0da07f032e8" {
		t.Fatalf("unexpected evidence root %s", report.EvidenceRoot)
	}
	assertFindingCodes(t, report.Blockers, "VULNERABILITY_STATE_BLOCKED", "MISSING_PROMOTION_REQUIREMENT")
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

func TestAuthorizeRejectsAuthoritativeRoleConflictAndRevocation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	action := validAction(now)
	action.Signature = hex.EncodeToString(ed25519.Sign(privateKey, CanonicalAction(action)))
	identity := Identity{ActorID: action.ActorID, Role: "release-attestor", KeyID: action.KeyID, PublicKey: hex.EncodeToString(publicKey)}
	err = Authorize(action, map[string]Identity{action.ActorID: identity}, Snapshot{RoleDigest: action.RoleSnapshotDigest, RevocationDigest: action.RevocationSnapshotDigest}, NewMemoryLedger(), now)
	assertCode(t, err, "ROLE_CONFLICT")

	identity.Role = action.Role
	identity.Revoked = true
	err = Authorize(action, map[string]Identity{action.ActorID: identity}, Snapshot{RoleDigest: action.RoleSnapshotDigest, RevocationDigest: action.RevocationSnapshotDigest}, NewMemoryLedger(), now)
	assertCode(t, err, "REVOKED_AUTHORIZATION")
}

func TestOnlyProtectedCallerCanClearPromotionGate(t *testing.T) {
	t.Parallel()
	directory := copyEvidence(t)
	now := time.Date(2026, 8, 24, 13, 0, 0, 0, time.UTC)

	var vulnerabilities vulnerabilityDocument
	readStrictTestFile(t, filepath.Join(directory, "vulnerability-snapshot.json"), &vulnerabilities)
	vulnerabilities.Decision = "CLEAR"
	vulnerabilities.DecisionReason = "test-only authoritative risk disposition"
	writeJSONTestFile(t, filepath.Join(directory, "vulnerability-snapshot.json"), vulnerabilities)

	var promotions promotionDocument
	readStrictTestFile(t, filepath.Join(directory, "promotion-receipts.json"), &promotions)
	promotions.Status = "PROMOTED"
	promotions.AcceptedObjectCount = len(expectedArtifacts)
	promotions.BlockingFindings = nil
	for index := range promotions.CandidatePayload.Files {
		name := promotions.CandidatePayload.Files[index].Path
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		promotions.CandidatePayload.Files[index].SHA256 = DigestBytes(data)
	}
	records := make([]string, 0, len(promotions.CandidatePayload.Files))
	for _, file := range promotions.CandidatePayload.Files {
		records = append(records, file.Path+"="+file.SHA256)
	}
	promotions.CandidatePayload.RootDigest = DigestBytes([]byte(strings.Join(records, "\n") + "\n"))

	type signer struct {
		actor, role, keyID string
		public             ed25519.PublicKey
		private            ed25519.PrivateKey
		snapshot           Snapshot
	}
	signers := map[string]*signer{}
	for _, identity := range []struct{ actor, role string }{{"github:steward", "method-schema-steward"}, {"github:implementer", "port-implementer"}, {"github:attestor", "release-attestor"}} {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signers[identity.role] = &signer{
			actor: identity.actor, role: identity.role, keyID: "test:" + identity.role,
			public: publicKey, private: privateKey,
			snapshot: Snapshot{RoleDigest: DigestBytes([]byte("roles:" + identity.actor)), RevocationDigest: DigestBytes([]byte("revocations:" + identity.actor))},
		}
	}
	stages := []struct {
		stage, action, role string
		sandbox             []string
	}{
		{"acquisition", "acquire", "method-schema-steward", nil},
		{"quarantine", "quarantine", "port-implementer", nil},
		{"qualification", "qualify", "port-implementer", []string{"quarantined-source"}},
		{"independent-promotion", "promote", "release-attestor", nil},
	}
	for index, stage := range stages {
		signer := signers[stage.role]
		action := Action{
			ObjectID: "java-websocket-us001-inputs-v1", ObjectKind: "artifact-set", Stage: stage.stage, Action: stage.action,
			ActorID: signer.actor, Role: signer.role, KeyID: signer.keyID, Company: RequiredCompany, Project: RequiredProject, LaboratoryID: RequiredLaboratory,
			ArtifactDigest: promotions.CandidatePayload.RootDigest, PolicyVersion: promotions.PolicyVersion, PolicyDigest: promotions.PolicyDigest,
			RequestedSandboxAccess: stage.sandbox, Publication: PublicationIntent{Requested: false, Classification: "QUARANTINED"},
			IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Nonce: "nonce-authorized-stage-000" + string(rune('0'+index)),
			RoleSnapshotDigest: signer.snapshot.RoleDigest, RevocationSnapshotDigest: signer.snapshot.RevocationDigest,
		}
		action.Signature = hex.EncodeToString(ed25519.Sign(signer.private, CanonicalAction(action)))
		promotions.SignedActions = append(promotions.SignedActions, action)
	}
	writeJSONTestFile(t, filepath.Join(directory, "promotion-receipts.json"), promotions)

	report, err := VerifyEvidenceDir(directory, now)
	if err != nil {
		t.Fatal(err)
	}
	assertFindingCodes(t, report.Blockers, "PROTECTED_CALLER_REQUIRED")
	authority := TrustedAuthority{Identities: map[string]Identity{}, Snapshots: map[string]Snapshot{}, Ledger: NewMemoryLedger()}
	for _, signer := range signers {
		authority.Identities[signer.actor] = Identity{ActorID: signer.actor, Role: signer.role, KeyID: signer.keyID, PublicKey: hex.EncodeToString(signer.public)}
		authority.Snapshots[signer.actor] = signer.snapshot
	}
	report, err = VerifyAuthorizedEvidenceDir(directory, now, authority)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Blockers) != 0 {
		t.Fatalf("authorized evidence remains blocked: %+v", report.Blockers)
	}
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
