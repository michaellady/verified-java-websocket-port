package securitygate

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestClassifiedPublicProjectionGoldenRoundTrip(t *testing.T) {
	projection := testClassifiedPublicProjection()
	raw := encodeTestClassifiedPublicProjection(t, projection)
	got, err := DecodeProtectedPublicProjection(raw)
	if err != nil {
		t.Fatal(err)
	}
	projection.Classifier.OutputDigest = got.Classifier.OutputDigest
	if !reflect.DeepEqual(got, projection) {
		t.Fatalf("decoded projection drifted:\n got: %#v\nwant: %#v", got, projection)
	}

	schemaBytes, err := os.ReadFile(filepath.Join(repoRoot(t), "schemas", "sbx-public-projection-1.0.0.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schemaResource any
	if err := json.Unmarshal(schemaBytes, &schemaResource); err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("sbx-public-projection", schemaResource); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("sbx-public-projection")
	if err != nil {
		t.Fatal(err)
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(value); err != nil {
		t.Fatalf("classified public projection schema: %v", err)
	}

	object := value.(map[string]any)
	object["descriptor_observations"] = []any{}
	if err := schema.Validate(value); err == nil {
		t.Fatal("schema accepted protected raw descriptor observations")
	}
}

func TestClassifiedPublicProjectionRejectsStructuralAndDigestDrift(t *testing.T) {
	valid := encodeTestClassifiedPublicProjection(t, testClassifiedPublicProjection())
	unknownTop := bytes.Replace(valid, []byte(`{"schema":"1.0.0",`), []byte(`{"schema":"1.0.0","company":"enterprise-vibe-code",`), 1)
	unknownNested := bytes.Replace(valid, []byte(`"digests":{`), []byte(`"digests":{"input_root":"/protected",`), 1)
	duplicateTop := bytes.Replace(valid, []byte(`{"schema":"1.0.0",`), []byte(`{"schema":"1.0.0","schema":"1.0.0",`), 1)
	duplicateNested := bytes.Replace(valid, []byte(`"digests":{`), []byte(`"digests":{"policy_digest":"`+digestOf("duplicate")+`",`), 1)
	missing := bytes.Replace(valid, []byte(`"classification":"PUBLIC_DERIVED",`), nil, 1)
	trailing := append(append([]byte(nil), valid...), []byte(` {}`)...)

	for name, raw := range map[string][]byte{
		"unknown-top":      unknownTop,
		"unknown-nested":   unknownNested,
		"duplicate-top":    duplicateTop,
		"duplicate-nested": duplicateNested,
		"missing":          missing,
		"trailing":         trailing,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeProtectedPublicProjection(raw); err == nil {
				t.Fatal("invalid classified projection accepted")
			}
		})
	}

	outputDrift := bytes.Replace(valid, []byte(digestOf("policy")), []byte(digestOf("different-policy")), 1)
	if _, err := DecodeProtectedPublicProjection(outputDrift); err == nil || !strings.Contains(err.Error(), "PUBLIC_PROJECTION_DIGEST_DRIFT") {
		t.Fatalf("output digest drift err=%v", err)
	}
}

func TestClassifiedPublicProjectionRejectsSemanticDriftAfterRedigest(t *testing.T) {
	tests := []struct {
		name string
		edit func(*ProtectedPublicProjection)
	}{
		{"classification", func(value *ProtectedPublicProjection) { value.Classification = "PUBLIC" }},
		{"attempt-shape", func(value *ProtectedPublicProjection) { value.AttemptID = "us007-sbx-output-live-next" }},
		{"attempt-prefix", func(value *ProtectedPublicProjection) { value.AttemptID = "other-sbx-output-live-0019" }},
		{"stale-attempt", func(value *ProtectedPublicProjection) { value.AttemptID = "us007-sbx-output-live-0012" }},
		{"target-commit", func(value *ProtectedPublicProjection) { value.TargetCommit = strings.ToUpper(value.TargetCommit) }},
		{"fixed-plan", func(value *ProtectedPublicProjection) { value.Digests.FixedPlanDigest = digestOf("other-plan") }},
		{"profile", func(value *ProtectedPublicProjection) { value.Digests.ProfileDigest = digestOf("other-profile") }},
		{"policy-digest-uppercase", func(value *ProtectedPublicProjection) {
			value.Digests.PolicyDigest = strings.ToUpper(value.Digests.PolicyDigest)
		}},
		{"template", func(value *ProtectedPublicProjection) { value.Digests.TemplateDigest = digestOf("other-template") }},
		{"rule", func(value *ProtectedPublicProjection) { value.Classifier.RuleDigest = digestOf("other-rules") }},
		{"envelope", func(value *ProtectedPublicProjection) { value.ResourceEnvelope.PIDs++ }},
		{"descriptor-count", func(value *ProtectedPublicProjection) {
			value.DescriptorSummaries = value.DescriptorSummaries[:len(value.DescriptorSummaries)-1]
		}},
		{"descriptor-order", func(value *ProtectedPublicProjection) {
			value.DescriptorSummaries[0], value.DescriptorSummaries[1] = value.DescriptorSummaries[1], value.DescriptorSummaries[0]
		}},
		{"descriptor-not-accepted", func(value *ProtectedPublicProjection) { value.DescriptorSummaries[0].Accepted = false }},
		{"descriptor-digest-uppercase", func(value *ProtectedPublicProjection) {
			value.DescriptorSummaries[0].RawReceiptDigest = strings.ToUpper(value.DescriptorSummaries[0].RawReceiptDigest)
		}},
		{"artifact-empty", func(value *ProtectedPublicProjection) { value.BenignArtifact.Bytes = 0 }},
		{"sandbox-present", func(value *ProtectedPublicProjection) { value.Cleanup.SandboxAbsent = false }},
		{"independence-overclaim", func(value *ProtectedPublicProjection) { value.IndependentReviewClaimed = true }},
		{"assurance-overclaim", func(value *ProtectedPublicProjection) { value.Assurance = "INDEPENDENTLY_REVIEWED" }},
		{"autobahn-rerun", func(value *ProtectedPublicProjection) { value.AutobahnReruns = 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			projection := testClassifiedPublicProjection()
			projection.DescriptorSummaries = append([]ClassifiedDescriptorSummary(nil), projection.DescriptorSummaries...)
			test.edit(&projection)
			if _, err := DecodeProtectedPublicProjection(encodeTestClassifiedPublicProjection(t, projection)); err == nil {
				t.Fatal("semantically drifted classified projection accepted after self-redigest")
			}
		})
	}
}

func TestCandidateProjectionStillRequiresExternalProtectedClassifier(t *testing.T) {
	store, root := acceptedProjectionFixture(t, "public/readme.txt", []byte("inert public bytes"), "PUBLIC", true)
	verdict, err := Project(t.Context(), Request{RootPath: repoRoot(t), Operation: OperationProject, CandidateRoot: root, StorePath: store})
	if err != nil {
		t.Fatal(err)
	}
	if len(verdict.Findings) != 1 || verdict.Findings[0].Code != "PROTECTED_CLASSIFIER_UNAVAILABLE" {
		t.Fatalf("candidate-only projection did not fail closed: %#v", verdict)
	}
}

func testClassifiedPublicProjection() ProtectedPublicProjection {
	plan := protectedFixedPlan()
	summaries := make([]ClassifiedDescriptorSummary, 0, len(plan))
	for _, id := range plan {
		summaries = append(summaries, ClassifiedDescriptorSummary{DescriptorID: id, Accepted: true, RawReceiptDigest: digestOf("receipt-" + id)})
	}
	return ProtectedPublicProjection{
		Schema:         "1.0.0",
		Classification: "PUBLIC_DERIVED",
		Project:        "verified-java-websocket-port",
		Story:          "US-007",
		AttemptID:      "us007-sbx-output-live-0019",
		TargetCommit:   "0123456789abcdef0123456789abcdef01234567",
		TargetTree:     "89abcdef0123456789abcdef0123456789abcdef",
		Digests: ClassifiedProjectionDigests{
			FixedPlanDigest:            protectedFixedPlanDigest(),
			ProfileDigest:              classifiedPublicProjectionProfileDigest(),
			PolicyDigest:               digestOf("policy"),
			RuntimeDigest:              digestOf("runtime"),
			TemplateDigest:             classifiedPublicProjectionTemplateDigest,
			SupervisorDigest:           digestOf("supervisor"),
			AuthorizationClosureDigest: digestOf("authorization-closure"),
		},
		ResourceEnvelope:    exactProtectedEnvelope(),
		DescriptorSummaries: summaries,
		BenignArtifact:      ClassifiedArtifact{Digest: digestOf("artifact"), Bytes: 8},
		Cleanup:             ClassifiedCleanup{RemoveDigest: digestOf("remove"), AbsenceDigest: digestOf("absence"), SandboxAbsent: true},
		Classifier:          ClassifiedClassifier{RuleDigest: classifiedPublicProjectionRuleDigest, InputDigest: digestOf("input"), ActionDigest: digestOf("action")},
		Assurance:           AssuranceOwnerOnly,
	}
}

func encodeTestClassifiedPublicProjection(t *testing.T, projection ProtectedPublicProjection) []byte {
	t.Helper()
	projection.Classifier.OutputDigest = ""
	canonical, err := intake.CanonicalJSON(projection)
	if err != nil {
		t.Fatal(err)
	}
	projection.Classifier.OutputDigest = intake.DigestBytes(canonical)
	raw, err := intake.CanonicalJSON(projection)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
