package cutover

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestSchemasAreClosedAndReceiptsFormExactDigestChain(t *testing.T) {
	repositoryRoot := repositoryRootForTests(t)
	for _, name := range []string{
		"cutover-rehearsal-contract-1.0.0.schema.json",
		"cutover-phase-receipt-1.0.0.schema.json",
		"cutover-evidence-1.0.0.schema.json",
	} {
		raw, err := os.ReadFile(filepath.Join(repositoryRoot, "schemas", name))
		if err != nil {
			t.Fatal(err)
		}
		var schema map[string]any
		if err := json.Unmarshal(raw, &schema); err != nil {
			t.Fatal(err)
		}
		if schema["additionalProperties"] != false {
			t.Fatalf("schema %s is not closed", name)
		}
	}

	root := fixtureRoot(t)
	if _, err := Capture(root); err != nil {
		t.Fatal(err)
	}
	predecessorPath := "cutover/contract.json"
	predecessorRaw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(predecessorPath)))
	if err != nil {
		t.Fatal(err)
	}
	predecessorDigest := digest(predecessorRaw)
	for _, phase := range []string{"shadow", "canary", "rollback", "soak"} {
		path := "cutover/" + phase + ".json"
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		var receipt phaseReceipt
		if err := json.Unmarshal(raw, &receipt); err != nil {
			t.Fatal(err)
		}
		if receipt.PredecessorPath != predecessorPath || receipt.PredecessorSHA256 != predecessorDigest {
			t.Fatalf("%s predecessor = %s/%s, want %s/%s", phase, receipt.PredecessorPath, receipt.PredecessorSHA256, predecessorPath, predecessorDigest)
		}
		if receipt.CutoverReadyReached || receipt.CutoverAcceptance != CutoverBlocked {
			t.Fatalf("%s promoted cutover readiness", phase)
		}
		predecessorPath, predecessorDigest = path, digest(raw)
	}
	for artifactPath, schemaName := range map[string]string{
		"cutover/contract.json": "cutover-rehearsal-contract-1.0.0.schema.json",
		"cutover/shadow.json":   "cutover-phase-receipt-1.0.0.schema.json",
		"cutover/canary.json":   "cutover-phase-receipt-1.0.0.schema.json",
		"cutover/rollback.json": "cutover-phase-receipt-1.0.0.schema.json",
		"cutover/soak.json":     "cutover-phase-receipt-1.0.0.schema.json",
		"evidence/cutover.json": "cutover-evidence-1.0.0.schema.json",
	} {
		validateArtifactSchema(t, repositoryRoot, root, artifactPath, schemaName)
	}
}

func validateArtifactSchema(t *testing.T, repositoryRoot, artifactRoot, artifactPath, schemaName string) {
	t.Helper()
	schemaRaw, err := os.ReadFile(filepath.Join(repositoryRoot, "schemas", schemaName))
	if err != nil {
		t.Fatal(err)
	}
	schemaValue, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaRaw))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	url := "https://verified-java-websocket-port.invalid/" + schemaName
	if err := compiler.AddResource(url, schemaValue); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(url)
	if err != nil {
		t.Fatal(err)
	}
	artifactRaw, err := os.ReadFile(filepath.Join(artifactRoot, filepath.FromSlash(artifactPath)))
	if err != nil {
		t.Fatal(err)
	}
	artifactValue, err := jsonschema.UnmarshalJSON(bytes.NewReader(artifactRaw))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(artifactValue); err != nil {
		t.Fatalf("%s schema failure: %v", artifactPath, err)
	}
}

func TestCaptureIsIdempotentAndByteIdentical(t *testing.T) {
	root := fixtureRoot(t)
	first, err := Capture(root)
	if err != nil {
		t.Fatal(err)
	}
	before := map[string][]byte{}
	for _, path := range []string{
		"cutover/contract.json", "cutover/shadow.json", "cutover/canary.json",
		"cutover/rollback.json", "cutover/soak.json", "evidence/cutover.json",
	} {
		before[path], err = os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
	}
	second, err := Capture(root)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("second summary = %+v, first = %+v", second, first)
	}
	for path, want := range before {
		got, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("second capture changed %s", path)
		}
	}
}

func TestCanonicalFixtureHasExactClosedTracesAndAbort(t *testing.T) {
	root := fixtureRoot(t)
	if _, err := Capture(root); err != nil {
		t.Fatal(err)
	}
	canaryRaw, err := os.ReadFile(filepath.Join(root, "cutover", "canary.json"))
	if err != nil {
		t.Fatal(err)
	}
	var canary phaseReceipt
	if err := json.Unmarshal(canaryRaw, &canary); err != nil {
		t.Fatal(err)
	}
	if len(canary.Runs) != 2 || len(canary.Runs[0].SelectedRequestIDs) != 2 || len(canary.Runs[1].SelectedRequestIDs) != 2 {
		t.Fatalf("canary run cardinality = %+v", canary.Runs)
	}
	if len(canary.Runs[1].RustAttemptedRequestIDs) != 1 || len(canary.Runs[1].FailedAttempts) != 1 || !canary.Runs[1].FailedAttempts[0].Preserved {
		t.Fatalf("mismatch abort was not retained: %+v", canary.Runs[1])
	}
	abortedRequest := canary.Runs[1].FailedAttempts[0].RequestID
	afterAbort := false
	for _, effect := range canary.Runs[1].CommittedFixtureEffects {
		if effect.IdempotencyKey == "us026-idempotency-02" && abortedRequest == "request-02" {
			afterAbort = true
		}
		if afterAbort && effect.Route != "java-fallback" {
			t.Fatalf("post-abort effect %s retained route %s", effect.IdempotencyKey, effect.Route)
		}
	}
	if !afterAbort {
		t.Fatalf("abort request %s was not reconciled", abortedRequest)
	}
	if !equalStrings(canary.Runs[0].States, nominalTrace) || !equalStrings(canary.Runs[1].States, mismatchTrace) {
		t.Fatalf("closed traces drifted: %+v / %+v", canary.Runs[0].States, canary.Runs[1].States)
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
