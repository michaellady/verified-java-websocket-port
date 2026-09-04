package securitygate

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestExecutablePromotionSubjectBindsControlledCanaryQualificationOnly(t *testing.T) {
	binaryDigest := intake.DigestBytes([]byte("exact-securityctl-bytes"))
	subject, err := ExecutablePromotionSubject(repoRoot(t), binaryDigest)
	if err != nil {
		t.Fatal(err)
	}
	if subject.ArtifactDigest != binaryDigest || subject.Kind != "CONTROLLED_CANARY_EXECUTABLE_PROMOTION" ||
		subject.Operation != "CONTROLLED_CANARY" || subject.Company != intake.RequiredCompany ||
		subject.Project != intake.RequiredProject || subject.LaboratoryID != intake.RequiredLaboratory {
		t.Fatalf("subject is not bound to the exact executable and tenant: %#v", subject)
	}
	if !equalStrings(subject.SubjectRoles, []string{"SANDBOX_SUPERVISOR", "SECURITYCTL"}) ||
		subject.Scope != "QUARANTINED_LABORATORY_QUALIFICATION_ONLY" || subject.HistoricalKeyID != executablePromotionKeyID {
		t.Fatalf("subject widened the controlled-canary role/scope binding: %#v", subject)
	}
	if subject.ProductionUseAuthorized || subject.PublicationAuthorized || subject.IndependentReviewClaimed {
		t.Fatalf("subject widened the owner-only assurance ceiling: %#v", subject)
	}
	if !equalDigestBindings(subject.EvidenceBindings, []intake.ScopedDigestBinding{
		{Name: "security-evidence", Digest: currentSecurityEvidenceDigest(t)},
		{Name: "us001-accepted-root", Digest: retainedUS001AcceptedRoot},
		{Name: "us001-public-evidence", Digest: retainedUS001PublicEvidenceRoot},
	}) {
		t.Fatalf("subject evidence bindings = %#v", subject.EvidenceBindings)
	}
	policyBytes, err := os.ReadFile(filepath.Join(repoRoot(t), "security/sandbox-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if subject.PolicyDigest != intake.DigestBytes(policyBytes) {
		t.Fatalf("policy digest = %q", subject.PolicyDigest)
	}

	requirements := ExecutablePromotionOwnerRequirements()
	if len(requirements.Statements) != 2 ||
		requirements.Statements[0] != (intake.ScopedStatementRequirement{Stage: "qualification", Action: "authorize-controlled-canary", SignerRole: "port-implementer"}) ||
		requirements.Statements[1] != (intake.ScopedStatementRequirement{Stage: intake.PromotionStageID, Action: "promote-controlled-canary-executable", SignerRole: "release-attestor"}) {
		t.Fatalf("required action sequence = %#v", requirements.Statements)
	}
}

func TestExecutablePromotionRecordRejectsEverySubjectMutation(t *testing.T) {
	record := testExecutablePromotionRecord(t)
	tests := []struct {
		name   string
		mutate func(*ExecutablePromotionRecord)
	}{
		{"schema-version", func(r *ExecutablePromotionRecord) { r.Subject.SchemaVersion = "2.0.0" }},
		{"kind", func(r *ExecutablePromotionRecord) { r.Subject.Kind = "CANDIDATE_PROMOTION" }},
		{"binary", func(r *ExecutablePromotionRecord) {
			r.Subject.ArtifactDigest = intake.DigestBytes([]byte("other-binary"))
		}},
		{"roles-order", func(r *ExecutablePromotionRecord) {
			r.Subject.SubjectRoles = []string{"SECURITYCTL", "SANDBOX_SUPERVISOR"}
		}},
		{"roles-extra", func(r *ExecutablePromotionRecord) {
			r.Subject.SubjectRoles = append(r.Subject.SubjectRoles, "MAVEN_CORE")
		}},
		{"operation", func(r *ExecutablePromotionRecord) { r.Subject.Operation = "MAVEN_TEST" }},
		{"company", func(r *ExecutablePromotionRecord) { r.Subject.Company = "other-company" }},
		{"project", func(r *ExecutablePromotionRecord) { r.Subject.Project = "other-project" }},
		{"laboratory", func(r *ExecutablePromotionRecord) { r.Subject.LaboratoryID = "other-lab" }},
		{"policy", func(r *ExecutablePromotionRecord) {
			r.Subject.PolicyDigest = intake.DigestBytes([]byte("other-policy"))
		}},
		{"security-evidence", func(r *ExecutablePromotionRecord) {
			r.Subject.EvidenceBindings[0].Digest = intake.DigestBytes([]byte("other-evidence"))
		}},
		{"evidence-name", func(r *ExecutablePromotionRecord) { r.Subject.EvidenceBindings[0].Name = "candidate-evidence" }},
		{"evidence-order", func(r *ExecutablePromotionRecord) {
			r.Subject.EvidenceBindings[0], r.Subject.EvidenceBindings[1] = r.Subject.EvidenceBindings[1], r.Subject.EvidenceBindings[0]
		}},
		{"evidence-extra", func(r *ExecutablePromotionRecord) {
			r.Subject.EvidenceBindings = append(r.Subject.EvidenceBindings, intake.ScopedDigestBinding{Name: "candidate", Digest: intake.DigestBytes([]byte("candidate"))})
		}},
		{"accepted-root", func(r *ExecutablePromotionRecord) {
			r.Subject.EvidenceBindings[1].Digest = intake.DigestBytes([]byte("other-accepted"))
		}},
		{"public-evidence", func(r *ExecutablePromotionRecord) {
			r.Subject.EvidenceBindings[2].Digest = intake.DigestBytes([]byte("other-public"))
		}},
		{"scope", func(r *ExecutablePromotionRecord) { r.Subject.Scope = "PRODUCTION" }},
		{"retained-key-id", func(r *ExecutablePromotionRecord) { r.Subject.HistoricalKeyID = "candidate-key" }},
		{"production", func(r *ExecutablePromotionRecord) { r.Subject.ProductionUseAuthorized = true }},
		{"publication", func(r *ExecutablePromotionRecord) { r.Subject.PublicationAuthorized = true }},
		{"independence", func(r *ExecutablePromotionRecord) { r.Subject.IndependentReviewClaimed = true }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := cloneExecutablePromotionRecord(t, record)
			test.mutate(&mutated)
			if err := ValidateExecutablePromotionRecord(repoRoot(t), record.Subject.ArtifactDigest, mutated, testPromotionNow()); err == nil || !strings.Contains(err.Error(), "EXECUTABLE_PROMOTION_MISMATCH") {
				t.Fatalf("mutation err=%v", err)
			}
		})
	}
}

func TestExecutablePromotionRecordRequiresDistinctQualificationAndPromotion(t *testing.T) {
	base := testExecutablePromotionRecord(t)
	tests := []struct {
		name   string
		mutate func(*ExecutablePromotionRecord)
	}{
		{"missing", func(r *ExecutablePromotionRecord) { r.Statements = r.Statements[:1] }},
		{"extra", func(r *ExecutablePromotionRecord) { r.Statements = append(r.Statements, r.Statements[1]) }},
		{"same-nonce", func(r *ExecutablePromotionRecord) { r.Statements[1].Nonce = r.Statements[0].Nonce }},
		{"wrong-qualification-stage", func(r *ExecutablePromotionRecord) { r.Statements[0].Stage = intake.PromotionStageID }},
		{"wrong-qualification-role", func(r *ExecutablePromotionRecord) { r.Statements[0].Role = "release-attestor" }},
		{"wrong-promotion-action", func(r *ExecutablePromotionRecord) { r.Statements[1].Action = "publish" }},
		{"wrong-promotion-role", func(r *ExecutablePromotionRecord) { r.Statements[1].Role = "port-implementer" }},
		{"wrong-signer", func(r *ExecutablePromotionRecord) { r.Statements[1].ActorID = "candidate:attacker" }},
		{"wrong-key", func(r *ExecutablePromotionRecord) { r.Statements[1].KeyID = "candidate-key" }},
		{"expired", func(r *ExecutablePromotionRecord) { r.Statements[1].ExpiresAt = testPromotionNow().Add(-time.Minute) }},
		{"future", func(r *ExecutablePromotionRecord) { r.Statements[1].IssuedAt = testPromotionNow().Add(6 * time.Minute) }},
		{"missing-snapshot", func(r *ExecutablePromotionRecord) { r.Statements[1].RoleSnapshotDigest = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := cloneExecutablePromotionRecord(t, base)
			test.mutate(&mutated)
			if err := ValidateExecutablePromotionRecord(repoRoot(t), base.Subject.ArtifactDigest, mutated, testPromotionNow()); err == nil {
				t.Fatal("malformed action sequence was accepted")
			}
		})
	}
}

func TestExecutablePromotionHardSelfAuthorityRequiresProtectedCaller(t *testing.T) {
	record := testExecutablePromotionRecord(t)
	attackerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x7a}, ed25519.SeedSize))
	for index := range record.Statements {
		signed, err := intake.SignScopedOwnerStatement(record.Statements[index], attackerKey)
		if err != nil {
			t.Fatal(err)
		}
		record.Statements[index] = signed
	}
	ledger := intake.FileLedger{Directory: filepath.Join(t.TempDir(), "candidate-ledger")}
	authority := intake.TrustedAuthority{
		AuthorityMode: intake.SingleOwnerAuthorityMode,
		OwnerActorID:  intake.RequiredOwnerActor,
		Identities: map[string]intake.Identity{intake.RequiredOwnerActor: {
			ActorID: intake.RequiredOwnerActor, AuthorityMode: intake.SingleOwnerAuthorityMode,
			AllowedRoles: []string{"port-implementer", "release-attestor"}, KeyID: executablePromotionKeyID,
			PublicKey: hex.EncodeToString(attackerKey.Public().(ed25519.PublicKey)),
		}},
		Snapshots: map[string]intake.Snapshot{intake.RequiredOwnerActor: {
			RoleDigest: record.Statements[0].RoleSnapshotDigest, RevocationDigest: record.Statements[0].RevocationSnapshotDigest,
		}},
		Ledger: ledger,
	}
	recordBytes, err := intake.CanonicalJSON(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := PreflightExecutablePromotionCandidate(repoRoot(t), record.Subject.ArtifactDigest, recordBytes, authority, testPromotionNow()); err == nil {
		t.Fatal("candidate-supplied authority was mistaken for a protected launch proof")
	} else if finding, ok := err.(*PromotionFinding); !ok || finding.Code != "PROTECTED_CALLER_REQUIRED" || finding.Disposition != "BLOCK" {
		t.Fatalf("hard self-authority err=%T %v", err, err)
	}

	// The protected-caller rejection happens before nonce consumption. The
	// attacker authority is internally self-consistent, which is precisely why
	// repository-local verification cannot be the root of trust.
	if _, err := intake.VerifyScopedOwnerStatements(record.Subject, record.Statements, authority, ExecutablePromotionOwnerRequirements(), testPromotionNow()); err != nil {
		t.Fatalf("protected boundary consumed or altered the supplied nonce batch: %v", err)
	}
}

func TestExecutablePromotionSuppliedAuthorityEnvelopeFailsClosed(t *testing.T) {
	record := testExecutablePromotionRecord(t)
	recordBytes, err := intake.CanonicalJSON(record)
	if err != nil {
		t.Fatal(err)
	}
	authority := intake.TrustedAuthority{AuthorityMode: intake.SingleOwnerAuthorityMode, OwnerActorID: intake.RequiredOwnerActor}
	if err := PreflightExecutablePromotionCandidate(repoRoot(t), record.Subject.ArtifactDigest, recordBytes, authority, testPromotionNow()); err == nil || !strings.Contains(err.Error(), "PROTECTED_CALLER_REQUIRED") {
		t.Fatalf("missing protected authority state err=%v", err)
	}
	if !record.Subject.PublicationAuthorized && !record.Subject.ProductionUseAuthorized && !record.Subject.IndependentReviewClaimed {
		return
	}
	t.Fatal("test fixture widened forbidden claims")
}

func TestExecutablePromotionCandidatePreflightNeverAuthorizes(t *testing.T) {
	record := testExecutablePromotionRecord(t)
	authority := intake.TrustedAuthority{}
	tests := []struct {
		name string
		data []byte
		code string
	}{
		{"absent", nil, "UNPROMOTED_EXECUTABLE"},
		{"unknown-field", []byte(`{"schema_version":"1.0.0","candidate_authority":true}`), "EXECUTABLE_PROMOTION_MISMATCH"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := PreflightExecutablePromotionCandidate(repoRoot(t), record.Subject.ArtifactDigest, test.data, authority, testPromotionNow())
			finding, ok := err.(*PromotionFinding)
			if !ok || finding.Code != test.code || finding.Disposition != "QUARANTINE" {
				t.Fatalf("preflight err=%T %v", err, err)
			}
		})
	}
	if _, err := ExecutablePromotionSubject(repoRoot(t), "candidate-digest"); err == nil || !strings.Contains(err.Error(), "EXECUTABLE_PROMOTION_MISMATCH") {
		t.Fatalf("non-digest executable identity err=%v", err)
	}
}

func TestExecutablePromotionSchemaIsClosed(t *testing.T) {
	schemaPath := filepath.Join(repoRoot(t), executablePromotionSchemaPath)
	schemaBytes, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	var schemaResource any
	if err := json.Unmarshal(schemaBytes, &schemaResource); err != nil {
		t.Fatal(err)
	}
	if err := compiler.AddResource(executablePromotionSchemaPath, schemaResource); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(executablePromotionSchemaPath)
	if err != nil {
		t.Fatal(err)
	}
	record := testExecutablePromotionRecord(t)
	recordBytes, err := intake.CanonicalJSON(record)
	if err != nil {
		t.Fatal(err)
	}
	var value any
	if err := json.Unmarshal(recordBytes, &value); err != nil || schema.Validate(value) != nil {
		t.Fatalf("canonical record does not satisfy schema: unmarshal=%v schema=%v", err, schema.Validate(value))
	}
	var object map[string]any
	if err := json.Unmarshal(recordBytes, &object); err != nil {
		t.Fatal(err)
	}
	object["public_key_ed25519_hex"] = strings.Repeat("0", ed25519.PublicKeySize*2)
	if err := schema.Validate(object); err == nil {
		t.Fatal("schema accepted a candidate-included trust root")
	}
	unknown, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeExecutablePromotionRecord(unknown); err == nil {
		t.Fatal("strict decoder accepted a candidate-included trust root")
	}
}

func testExecutablePromotionRecord(t *testing.T) ExecutablePromotionRecord {
	t.Helper()
	subject, err := ExecutablePromotionSubject(repoRoot(t), intake.DigestBytes([]byte("exact-securityctl-bytes")))
	if err != nil {
		t.Fatal(err)
	}
	subjectDigest, err := intake.ScopedOwnerSubjectDigest(subject)
	if err != nil {
		t.Fatal(err)
	}
	now := testPromotionNow()
	statements := make([]intake.ScopedOwnerStatement, 2)
	for index, requirement := range ExecutablePromotionOwnerRequirements().Statements {
		statements[index] = intake.ScopedOwnerStatement{
			SchemaVersion: "1.0.0", SubjectDigest: subjectDigest, Stage: requirement.Stage, Action: requirement.Action,
			ActorID: intake.RequiredOwnerActor, Role: requirement.SignerRole, KeyID: executablePromotionKeyID,
			AuthorityMode: intake.SingleOwnerAuthorityMode, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
			Nonce:              "nonce-us007-executable-promotion-000" + string(rune('1'+index)),
			RoleSnapshotDigest: intake.DigestBytes([]byte("roles-current")), RevocationSnapshotDigest: intake.DigestBytes([]byte("revocations-current")),
			Signature: strings.Repeat("0", ed25519.SignatureSize*2),
		}
	}
	return ExecutablePromotionRecord{SchemaVersion: "1.0.0", Subject: subject, Statements: statements}
}

func cloneExecutablePromotionRecord(t *testing.T, record ExecutablePromotionRecord) ExecutablePromotionRecord {
	t.Helper()
	data, err := intake.CanonicalJSON(record)
	if err != nil {
		t.Fatal(err)
	}
	cloned, err := DecodeExecutablePromotionRecord(data)
	if err != nil {
		t.Fatal(err)
	}
	return cloned
}

func currentSecurityEvidenceDigest(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "evidence/security-validation.json"))
	if err != nil {
		t.Fatal(err)
	}
	return intake.DigestBytes(data)
}

func equalDigestBindings(left, right []intake.ScopedDigestBinding) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func testPromotionNow() time.Time { return time.Date(2026, 8, 25, 5, 0, 0, 0, time.UTC) }
