package lab

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

func TestUS019ImmutableTesteeCopySurvivesHostileSourceSwap(t *testing.T) {
	directory := t.TempDir()
	directory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(directory, "websocket-testee")
	validated := []byte("validated-testee-bytes")
	if err := os.WriteFile(source, validated, 0o500); err != nil {
		t.Fatal(err)
	}
	staged, cleanup, err := stageRustAutobahnTestee(validated)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	swap := filepath.Join(directory, "hostile-swap")
	if err := os.WriteFile(swap, []byte("hostile-swapped-testee"), 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(swap, source); err != nil {
		t.Fatal(err)
	}
	stagedBytes, err := readBoundedRegular(staged, rustAutobahnMaximumExecutable)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stagedBytes, validated) {
		t.Fatalf("staged bytes changed after source swap: %q", stagedBytes)
	}
	stagedInfo, err := os.Lstat(staged)
	if err != nil {
		t.Fatal(err)
	}
	sourceInfo, err := os.Lstat(source)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(stagedInfo, sourceInfo) || stagedInfo.Mode().Perm() != 0o500 {
		t.Fatalf("staged identity/mode is unsafe: same=%v mode=%o", os.SameFile(stagedInfo, sourceInfo), stagedInfo.Mode().Perm())
	}
	stagedDirectoryInfo, err := os.Lstat(filepath.Dir(staged))
	if err != nil {
		t.Fatal(err)
	}
	if stagedDirectoryInfo.Mode().Perm() != 0o500 {
		t.Fatalf("staged directory is not sealed: mode=%o", stagedDirectoryInfo.Mode().Perm())
	}
}

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

func TestUS019StaticFilesRejectCoherentUnknownCaseInventory(t *testing.T) {
	root := t.TempDir()
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, relative := range []string{rustAutobahnManifestRelative, rustAutobahnClientPlanRelative, rustAutobahnServerPlanRelative} {
		copyUS019TestFile(t, filepath.Join(us019RepositoryRoot(t), relative), filepath.Join(root, relative))
	}
	manifestPath := filepath.Join(root, rustAutobahnManifestRelative)
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest RustAutobahnCaseManifest
	if err := intake.DecodeStrict(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.SelectedCaseIDs[len(manifest.SelectedCaseIDs)-1] = "1.999"
	sort.Strings(manifest.SelectedCaseIDs)
	manifest.SelectedCaseIDsDigest = digestStringSlice(manifest.SelectedCaseIDs)
	manifestBytes, err = canonicalDocument(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	manifestDigest := intake.DigestBytes(manifestBytes)
	for _, item := range []struct {
		path, mode, role string
	}{
		{rustAutobahnClientPlanRelative, "fuzzing-server", "client"},
		{rustAutobahnServerPlanRelative, "fuzzing-client", "server"},
	} {
		planBytes, err := canonicalDocument(buildRustAutobahnPlan(manifest, manifestDigest, item.mode, item.role))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, item.path), planBytes, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := VerifyRustAutobahnStaticFiles(root); findingCode(err) != "AUTOBAHN_MANIFEST_DRIFT" {
		t.Fatalf("coherent unknown case inventory accepted: %v", err)
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

func TestUS019ReceiptRejectsHistoricalSourceIdentitySubstitution(t *testing.T) {
	root := us019RepositoryRoot(t)
	evidence, err := os.ReadFile(filepath.Join(root, rustAutobahnEvidenceRelative))
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(evidence, &value); err != nil {
		t.Fatal(err)
	}
	value["testee"].(map[string]any)["source_tree_digest"] = "sha256:" + strings.Repeat("0", 64)
	mutated, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRustAutobahnPreparation(root, mutated); findingCode(err) != "AUTOBAHN_TESTEE_LINKAGE_MISSING" {
		t.Fatalf("historical source substitution finding=%v", err)
	}
}

func TestUS019ReceiptRejectsStaticBinaryReverificationOverclaim(t *testing.T) {
	root := us019RepositoryRoot(t)
	evidence, err := os.ReadFile(filepath.Join(root, rustAutobahnEvidenceRelative))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"boolean claim", func(value map[string]any) {
			value["testee"].(map[string]any)["binary_reverified_by_static_verifier"] = true
		}},
		{"nonclaim removed", func(value map[string]any) {
			nonclaims := value["nonclaims"].([]any)
			value["nonclaims"] = nonclaims[:len(nonclaims)-1]
		}},
		{"nonclaim inverted", func(value map[string]any) {
			nonclaims := value["nonclaims"].([]any)
			nonclaims[len(nonclaims)-1] = "static verifier reverified the testee binary"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var value map[string]any
			if err := json.Unmarshal(evidence, &value); err != nil {
				t.Fatal(err)
			}
			test.mutate(value)
			mutated, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyRustAutobahnPreparation(root, mutated); findingCode(err) != "AUTOBAHN_CONFORMANCE_OVERCLAIM" {
				t.Fatalf("binary reverification overclaim finding=%v", err)
			}
		})
	}
	var legacy map[string]any
	if err := json.Unmarshal(evidence, &legacy); err != nil {
		t.Fatal(err)
	}
	legacy["testee"].(map[string]any)["digest"] = strings.Repeat("0", 71)
	mutated, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRustAutobahnPreparation(root, mutated); findingCode(err) != "INVALID_RUST_AUTOBAHN_EVIDENCE" {
		t.Fatalf("legacy binary-identity field finding=%v", err)
	}
}

func TestUS019ReceiptRejectsMalformedPreparationHost(t *testing.T) {
	root := us019RepositoryRoot(t)
	evidence, err := os.ReadFile(filepath.Join(root, rustAutobahnEvidenceRelative))
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(evidence, &value); err != nil {
		t.Fatal(err)
	}
	value["testee"].(map[string]any)["host"] = "../../untrusted"
	mutated, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRustAutobahnPreparation(root, mutated); findingCode(err) != "RUST_TESTEE_NOT_EXERCISED" {
		t.Fatalf("malformed preparation host finding=%v", err)
	}
}

func TestUS019ReceiptRejectsPreparationGateOverclaims(t *testing.T) {
	root := us019RepositoryRoot(t)
	evidence, err := os.ReadFile(filepath.Join(root, rustAutobahnEvidenceRelative))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"pass", func(gates map[string]any) { gates["focused_go"] = "PASS" }},
		{"failure", func(gates map[string]any) { gates["focused_go"] = "FAIL" }},
		{"missing", func(gates map[string]any) { delete(gates, "focused_go") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var value map[string]any
			if err := json.Unmarshal(evidence, &value); err != nil {
				t.Fatal(err)
			}
			test.mutate(value["gates"].(map[string]any))
			mutated, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyRustAutobahnPreparation(root, mutated); findingCode(err) != "AUTOBAHN_CONFORMANCE_OVERCLAIM" {
				t.Fatalf("gate overclaim finding=%v", err)
			}
		})
	}
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
