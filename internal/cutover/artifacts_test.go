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

func TestSeededMismatchIsOneConsistentUnequalSemanticResult(t *testing.T) {
	root := fixtureRoot(t)
	if _, err := Capture(root); err != nil {
		t.Fatal(err)
	}
	var unequal []comparison
	for _, phase := range []string{"shadow", "canary"} {
		raw, err := os.ReadFile(filepath.Join(root, "cutover", phase+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var receipt phaseReceipt
		if err := json.Unmarshal(raw, &receipt); err != nil {
			t.Fatal(err)
		}
		var phaseUnequal []comparison
		for _, observed := range receipt.Runs[1].Comparisons {
			if !observed.Equal || observed.JavaSemanticSHA256 != observed.RustSemanticSHA256 {
				phaseUnequal = append(phaseUnequal, observed)
			}
		}
		if len(phaseUnequal) != 1 {
			t.Fatalf("%s mismatch comparison count = %d", phase, len(phaseUnequal))
		}
		unequal = append(unequal, phaseUnequal[0])
	}
	if unequal[0] != unequal[1] {
		t.Fatalf("shadow/canary mismatch differs: %+v / %+v", unequal[0], unequal[1])
	}
	canaryRaw, err := os.ReadFile(filepath.Join(root, "cutover", "canary.json"))
	if err != nil {
		t.Fatal(err)
	}
	var canary phaseReceipt
	if err := json.Unmarshal(canaryRaw, &canary); err != nil {
		t.Fatal(err)
	}
	attempt := canary.Runs[1].FailedAttempts[0]
	if attempt.RequestID != unequal[0].RequestID || attempt.ExpectedSemantic != unequal[0].JavaSemanticSHA256 || attempt.ObservedSemantic != unequal[0].RustSemanticSHA256 {
		t.Fatalf("failed attempt is not the compared mismatch: %+v / %+v", attempt, unequal[0])
	}
}

func TestFallbackBindsDeclaredJavaIntakeSource(t *testing.T) {
	root := fixtureRoot(t)
	if _, err := Capture(root); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "cutover", "contract.json"))
	if err != nil {
		t.Fatal(err)
	}
	var contract map[string]any
	if err := json.Unmarshal(raw, &contract); err != nil {
		t.Fatal(err)
	}
	fallback := contract["java_fallback"].(map[string]any)
	if fallback["source_intake_path"] != "evidence/intake/java-intake-manifest.json" ||
		fallback["source_root"] != "src/main/java" ||
		fallback["source_identity_sha256"] != "sha256:f44e7647b4aee40819b51947cf0bb5f35a48293a202b77704c3c79e98ed13cb4" ||
		fallback["source_intake_sha256"] != "sha256:fa21240329e3eea761743adcb7a0bb30ae966c307b7da4df49891385a9439b71" {
		t.Fatalf("fallback source binding = %+v", fallback)
	}
	for _, binding := range contract["authoritative_inputs"].([]any) {
		input := binding.(map[string]any)
		if input["path"] == "evidence/intake/java-intake-manifest.json" {
			root = fixtureRoot(t)
			manifestPath := filepath.Join(root, "evidence", "intake", "java-intake-manifest.json")
			manifest, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Fatal(err)
			}
			manifest = bytes.Replace(manifest, []byte("sha256:f44e7647b4aee40819b51947cf0bb5f35a48293a202b77704c3c79e98ed13cb4"), []byte("sha256:0000000000000000000000000000000000000000000000000000000000000001"), 1)
			if err := os.WriteFile(manifestPath, manifest, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Capture(root); failureCode(err) != FailureInputDigestMismatch {
				t.Fatalf("mutated Java source declaration error = %v", err)
			}
			return
		}
	}
	t.Fatal("Java intake manifest is not an authoritative input")
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
