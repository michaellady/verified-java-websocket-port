package lab

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

func TestUS019PreparationInterfaceExists(t *testing.T) {
	_, err := PrepareRustAutobahn(context.Background(), RustAutobahnPreparationConfig{})
	if err == nil {
		t.Fatal("empty preparation configuration must fail closed")
	}
}

func TestUS019ManifestAndPlansAreCurrent(t *testing.T) {
	root := us019RepositoryRoot(t)
	if err := VerifyRustAutobahnStaticFiles(root); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRustAutobahnArchitectureFiles(root); err != nil {
		t.Fatal(err)
	}
}

func TestUS019StaticFilesRejectManifestAndPlanOverclaims(t *testing.T) {
	root := t.TempDir()
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, relative := range []string{rustAutobahnManifestRelative, rustAutobahnClientPlanRelative, rustAutobahnServerPlanRelative} {
		copyUS019TestFile(t, filepath.Join(us019RepositoryRoot(t), relative), filepath.Join(root, relative))
	}
	tests := []struct {
		name   string
		path   string
		mutate func(map[string]any)
	}{
		{"manifest count", rustAutobahnManifestRelative, func(value map[string]any) { value["selected_count"] = float64(246) }},
		{"plan authorization", rustAutobahnClientPlanRelative, func(value map[string]any) { value["execution_authorized"] = true }},
		{"plan conformance status", rustAutobahnServerPlanRelative, func(value map[string]any) { value["status"] = "PASS_CONFORMANCE" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(root, test.path)
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var value map[string]any
			if err := json.Unmarshal(original, &value); err != nil {
				t.Fatal(err)
			}
			test.mutate(value)
			mutated, err := intake.CanonicalJSON(value)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, append(mutated, '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := VerifyRustAutobahnStaticFiles(root); findingCode(err) != "AUTOBAHN_MANIFEST_DRIFT" {
				t.Fatalf("finding=%v", err)
			}
			if err := os.WriteFile(path, original, 0o600); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUS019SyntheticReconciliationControlsAndHistoryFirewall(t *testing.T) {
	root := us019RepositoryRoot(t)
	manifestBytes, err := os.ReadFile(filepath.Join(root, rustAutobahnManifestRelative))
	if err != nil {
		t.Fatal(err)
	}
	var manifest RustAutobahnCaseManifest
	if err := intake.DecodeStrict(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	manifestDigest := intake.DigestBytes(manifestBytes)
	planBytes, err := os.ReadFile(filepath.Join(root, rustAutobahnClientPlanRelative))
	if err != nil {
		t.Fatal(err)
	}
	challenge := strings.Repeat("a", 64)
	fixture, err := deriveRustAutobahnFixture(manifest, "client", intake.DigestBytes(planBytes), manifestDigest, challenge)
	if err != nil {
		t.Fatal(err)
	}
	if fixture.FixtureObserved != 247 || fixture.FixtureOK != 247 || fixture.LiveExecution || fixture.SuiteInvoked || fixture.Disposition != "SYNTHETIC_RECONCILED" {
		t.Fatalf("fixture=%+v", fixture)
	}
	baseline, err := os.ReadFile(filepath.Join(root, rustAutobahnBaselineRelative))
	if err != nil {
		t.Fatal(err)
	}
	controls, err := deriveRustAutobahnControls(manifest, manifestDigest, intake.DigestBytes(planBytes), challenge, baseline)
	if err != nil {
		t.Fatal(err)
	}
	if controls.Repetitions != 2 || len(controls.FixtureMutants) != 8 || len(controls.LineageMutants) != 4 || controls.ReferenceMutants.Total < 12 || controls.ReferenceMutants.Surviving != 0 || controls.ReferenceMutants.IdentitySurviving != 1 {
		t.Fatalf("controls=%+v", controls)
	}
	history, err := validateRustAutobahnHistory(baseline)
	if err != nil {
		t.Fatal(err)
	}
	if history.ClientAttempts != 2 || history.ServerAttempts != 2 || history.ClientExecuted || history.ServerExecuted || history.FurtherRerunsAuthorized || history.Disposition != "NO_FURTHER_RERUNS_AUTHORIZED" {
		t.Fatalf("history=%+v", history)
	}
}

func TestUS019ProcessContractDiscriminatesStubAndTranscriptMutants(t *testing.T) {
	challenge := strings.Repeat("b", 64)
	good := []byte(rustAutobahnContractLine(challenge))
	if err := validateRustAutobahnContractOutcome(good, nil, 0, challenge, false); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name           string
		stdout, stderr []byte
		exit           int
		exceeded       bool
	}{
		{"empty-stub", nil, nil, 0, false},
		{"cached-challenge", []byte(rustAutobahnContractLine(strings.Repeat("a", 64))), nil, 0, false},
		{"extra-output", append(append([]byte(nil), good...), 'x'), nil, 0, false},
		{"stderr", good, []byte("diagnostic"), 0, false},
		{"nonzero", good, nil, 1, false},
		{"output-limit", good, nil, 0, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateRustAutobahnContractOutcome(test.stdout, test.stderr, test.exit, challenge, test.exceeded); findingCode(err) != "RUST_TESTEE_NOT_EXERCISED" {
				t.Fatalf("finding=%v", err)
			}
		})
	}
}

func TestUS019ReceiptRejectsAnyLiveOrPassOverclaim(t *testing.T) {
	root := us019RepositoryRoot(t)
	for _, mutate := range []func(*RustAutobahnPreparationReceipt){
		func(value *RustAutobahnPreparationReceipt) { value.Status = "PASS_CONFORMANCE" },
		func(value *RustAutobahnPreparationReceipt) { value.LiveConformanceStatus = "PASS" },
		func(value *RustAutobahnPreparationReceipt) { value.StrictPassClaimed = true },
		func(value *RustAutobahnPreparationReceipt) { value.IndependentReviewClaimed = true },
	} {
		value := RustAutobahnPreparationReceipt{Schema: "../" + rustAutobahnSchemaRelative, SchemaVersion: "1.0.0", EvidenceID: "evidence.us-019-autobahn-rust-readiness", StoryID: "US-019", Status: RustAutobahnStatus, LiveConformanceStatus: RustAutobahnLiveStatus, Assurance: "OWNER_ATTESTED_NOT_INDEPENDENT"}
		mutate(&value)
		if err := validateRustAutobahnReceipt(root, value); findingCode(err) != "AUTOBAHN_CONFORMANCE_OVERCLAIM" {
			t.Fatalf("finding=%v", err)
		}
	}
}

func TestUS019CommittedEvidenceVerifiesAndSchemaClosesObjects(t *testing.T) {
	root := us019RepositoryRoot(t)
	evidence, err := os.ReadFile(filepath.Join(root, rustAutobahnEvidenceRelative))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRustAutobahnPreparation(root, evidence); err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(evidence, &value); err != nil {
		t.Fatal(err)
	}
	value["status"] = "PASS_CONFORMANCE"
	mutated, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRustAutobahnPreparation(root, mutated); findingCode(err) != "AUTOBAHN_CONFORMANCE_OVERCLAIM" {
		t.Fatalf("finding=%v", err)
	}
	schema, err := os.ReadFile(filepath.Join(root, rustAutobahnSchemaRelative))
	if err != nil {
		t.Fatal(err)
	}
	var document any
	if err := json.Unmarshal(schema, &document); err != nil {
		t.Fatal(err)
	}
	assertUS019SchemaObjectsClosed(t, document, "$", false)
}

func assertUS019SchemaObjectsClosed(t *testing.T, value any, path string, underProperties bool) {
	t.Helper()
	switch typed := value.(type) {
	case map[string]any:
		if kind, _ := typed["type"].(string); kind == "object" {
			if typed["additionalProperties"] != false {
				t.Fatalf("schema object %s is not closed", path)
			}
		}
		for key, child := range typed {
			assertUS019SchemaObjectsClosed(t, child, path+"."+key, key == "properties")
		}
	case []any:
		for index, child := range typed {
			assertUS019SchemaObjectsClosed(t, child, path+fmt.Sprintf("[%d]", index), underProperties)
		}
	}
}

func us019RepositoryRoot(t *testing.T) string {
	t.Helper()
	working, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs(filepath.Join(working, "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func copyUS019TestFile(t *testing.T, source, destination string) {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
