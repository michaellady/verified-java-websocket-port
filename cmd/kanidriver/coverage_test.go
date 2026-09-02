package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestBuildCoverageProjectionUsesExactCatalogDenominator(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	projection, err := buildCoverageProjection(root, "evidence/formal/kani-a2b00ef/summary.json", coverageSchemaVersion, "")
	if err != nil {
		t.Fatal(err)
	}
	if projection.Status != "BLOCKED" || projection.ClaimScope != "SUPPLEMENTAL_RUST_FORMAL_COVERAGE_ONLY" {
		t.Fatalf("projection posture = %#v", projection)
	}
	if projection.Counts.Required != 24 || projection.Counts.RustSatisfied != 18 ||
		projection.Counts.MutationSatisfied != 18 || projection.Counts.JavaSatisfied != 0 ||
		projection.Counts.RefinementSatisfied != 0 || projection.Counts.AggregateSatisfied != 0 ||
		projection.Counts.AggregateBlocked != 24 {
		t.Fatalf("coverage counts = %#v", projection.Counts)
	}
	if len(projection.Coverage) != 24 {
		t.Fatalf("coverage denominator = %d, want 24", len(projection.Coverage))
	}
	covered := map[string]bool{}
	mutationCovered := map[string]bool{}
	for _, row := range projection.Coverage {
		if row.JavaStatus != "BLOCKED" || row.RefinementStatus != "BLOCKED" || row.AggregateStatus != "BLOCKED" {
			t.Fatalf("aggregate posture inflated for %s: %#v", row.ObligationID, row)
		}
		if row.RustStatus == "SATISFIED" {
			covered[row.ObligationID] = true
			if row.MutationStatus != "SATISFIED" {
				t.Errorf("current proved obligation lacks mutation sensitivity: %#v", row)
			}
		}
		if row.MutationStatus == "SATISFIED" {
			mutationCovered[row.ObligationID] = true
		}
	}
	for _, obligationID := range []string{
		"obligation.checked-header-arithmetic",
		"obligation.control-fin-and-length",
		"obligation.length-canonical-16",
		"obligation.length-canonical-64-high-bit-zero",
		"obligation.length-canonical-7",
		"obligation.mask-equation",
		"obligation.mask-involution",
		"obligation.preallocation-cap",
		"obligation.role-masking",
		"surface.close.status-code",
		"surface.close.terminal-state",
		"surface.control.ping-pong",
		"surface.framing.frame-octets",
		"surface.framing.masking",
		"surface.fragmentation.continuation",
		"surface.limits.allocation",
		"surface.messages.binary",
		"surface.messages.text-utf8",
	} {
		if !covered[obligationID] {
			t.Errorf("missing verified production-symbol coverage for %s", obligationID)
		}
	}
	if covered["surface.websocket-open"] {
		t.Fatal("unproved WebSocket-open obligation was marked satisfied")
	}
	for _, obligationID := range []string{
		"obligation.checked-header-arithmetic",
		"obligation.control-fin-and-length",
		"obligation.length-canonical-16",
		"obligation.length-canonical-64-high-bit-zero",
		"obligation.length-canonical-7",
		"obligation.mask-equation",
		"obligation.mask-involution",
		"obligation.preallocation-cap",
		"obligation.role-masking",
		"surface.close.status-code",
		"surface.close.terminal-state",
		"surface.control.ping-pong",
		"surface.framing.frame-octets",
		"surface.framing.masking",
		"surface.fragmentation.continuation",
		"surface.limits.allocation",
		"surface.messages.binary",
		"surface.messages.text-utf8",
	} {
		if !mutationCovered[obligationID] {
			t.Errorf("missing verified mutation coverage for %s", obligationID)
		}
	}
	if projection.Limitations[2] != "6 obligations have no retained shipped-symbol Kani harness; 6 have no obligation-specific killed exact source mutation." {
		t.Fatalf("coverage limitation does not reconcile current counts: %q", projection.Limitations[2])
	}
}

func TestValidateCoverageProjectionRejectsCountAndClaimInflation(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	projection, err := buildCoverageProjection(root, "evidence/formal/kani-a2b00ef/summary.json", coverageSchemaVersion, "")
	if err != nil {
		t.Fatal(err)
	}
	projection.Counts.RustSatisfied++
	if err := validateCoverageProjection(root, projection); err == nil {
		t.Fatal("inflated Rust coverage count was accepted")
	}

	projection, err = buildCoverageProjection(root, "evidence/formal/kani-a2b00ef/summary.json", coverageSchemaVersion, "")
	if err != nil {
		t.Fatal(err)
	}
	projection.Coverage[len(projection.Coverage)-1].AggregateStatus = "SATISFIED"
	if err := validateCoverageProjection(root, projection); err == nil {
		t.Fatal("inflated aggregate coverage was accepted")
	}
}

func TestVerifyRetainedCoverageProjection(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	projection, err := verifyCoverage(root, "evidence/formal/kani-coverage-a2b00ef.json")
	if err != nil {
		t.Fatal(err)
	}
	if projection.Counts.Required != 24 || projection.Counts.RustSatisfied != 18 ||
		projection.Counts.MutationSatisfied != 18 || projection.Counts.AggregateSatisfied != 0 {
		t.Fatalf("retained coverage posture drifted: %#v", projection.Counts)
	}
}

func TestVerifyHistoricalCoverageProjections(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		path     string
		rust     int
		mutation int
	}{
		{path: "evidence/formal/kani-coverage-0cf36a9.json", rust: 11, mutation: 9},
		{path: "evidence/formal/kani-coverage-17e92c5.json", rust: 11, mutation: 11},
		{path: "evidence/formal/kani-coverage-467a224.json", rust: 14, mutation: 14},
		{path: "evidence/formal/kani-coverage-e624399.json", rust: 16, mutation: 16},
		{path: "evidence/formal/kani-coverage-2531f12.json", rust: 17, mutation: 17},
	} {
		projection, err := verifyCoverage(root, test.path)
		if err != nil {
			t.Fatalf("verify historical projection %s: %v", test.path, err)
		}
		if projection.Counts.RustSatisfied != test.rust || projection.Counts.MutationSatisfied != test.mutation {
			t.Errorf("historical projection %s drifted: %#v", test.path, projection.Counts)
		}
	}
}

func TestCoverageSchemaCompilesAndAcceptsGeneratedProjection(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	schemaBody, err := os.ReadFile(filepath.Join(root, "schemas", "kani-formal-coverage-1.0.0.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schemaValue any
	if err := json.Unmarshal(schemaBody, &schemaValue); err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	if err := compiler.AddResource("schema", schemaValue); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("schema")
	if err != nil {
		t.Fatal(err)
	}
	projection, err := buildCoverageProjection(root, "evidence/formal/kani-a2b00ef/summary.json", coverageSchemaVersion, "")
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(document); err != nil {
		t.Fatal(err)
	}
}

// Schema 1.0.0 pinned java_status to a const and java_satisfied to 0, so no input
// could ever raise Java coverage. 1.1.0 makes the axis an enumeration. 1.0.0 and
// everything validated under it stay untouched.
func TestJavaAxisIsRepresentableUnderOneOneZeroAndImpossibleUnderOneZeroZero(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	projection, err := buildCoverageProjection(root, "evidence/formal/kani-a2b00ef/summary.json", coverageSchemaVersionV11, "")
	if err != nil {
		t.Fatal(err)
	}
	if projection.SchemaVersion != coverageSchemaVersionV11 || projection.Schema != coverageSchemaReferenceV11 {
		t.Fatalf("projection did not adopt 1.1.0 identity: %s %s", projection.SchemaVersion, projection.Schema)
	}
	if projection.Counts.JavaSatisfied != 0 {
		t.Fatalf("no Java receipt was cited, so the axis must stay 0, got %d", projection.Counts.JavaSatisfied)
	}

	body, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatal(err)
	}
	// Raise the Java axis the way a real Java receipt would.
	counts := document["counts"].(map[string]any)
	counts["java_satisfied"] = 1
	rows := document["coverage"].([]any)
	rows[0].(map[string]any)["java_status"] = "SATISFIED"
	raised, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}

	if err := validateCoverageSchema(root, coverageSchemaPathV11, raised); err != nil {
		t.Errorf("schema 1.1.0 must admit nonzero Java coverage: %v", err)
	}
	if err := validateCoverageSchema(root, coverageSchemaPath, raised); err == nil {
		t.Error("schema 1.0.0 must remain unable to represent Java coverage")
	}
}

// Retained 1.0.0 projections must keep validating under the untouched 1.0.0 path.
func TestRetainedProjectionsStillValidateUnderOneZeroZero(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"0cf36a9", "17e92c5", "467a224", "e624399", "2531f12", "a2b00ef", "30ee613"} {
		path := filepath.Join("evidence", "formal", "kani-coverage-"+id+".json")
		value, verifyErr := verifyCoverage(root, path)
		if verifyErr != nil {
			t.Errorf("retained projection %s no longer verifies: %v", id, verifyErr)
			continue
		}
		if value.SchemaVersion != coverageSchemaVersion || value.Counts.JavaSatisfied != 0 || value.Status != coverageStatus {
			t.Errorf("retained projection %s drifted: %+v", id, value.Counts)
		}
	}
}

// A Java result is credited only when it targets the symbol the catalog binds for
// that obligation. A self-declared obligation label is not evidence.
func TestDeriveJavaCoverageRequiresTheBoundSymbol(t *testing.T) {
	bindings := map[string]string{"o.one": "com.example.A.m()V", "o.two": "com.example.B.n()V"}
	catalogSet := map[string]bool{"o.one": true, "o.two": true}
	base := func(results ...javaFormalResult) javaFormalReceipt {
		return javaFormalReceipt{SchemaVersion: javaFormalSchemaVersion, EvidenceKind: javaFormalEvidenceKind, Results: results}
	}

	covered, err := deriveJavaCoverage(bindings, catalogSet, base(
		javaFormalResult{ObligationID: "o.one", ProductionSymbol: "com.example.A.m()V", Status: "SATISFIED"},
	))
	if err != nil || len(covered) != 1 || !covered["o.one"] {
		t.Fatalf("a matching Java result must raise the axis: %v %v", covered, err)
	}

	if _, err := deriveJavaCoverage(bindings, catalogSet, base(
		javaFormalResult{ObligationID: "o.one", ProductionSymbol: "com.example.WRONG.m()V", Status: "SATISFIED"},
	)); err == nil {
		t.Error("a Java result on an unbound symbol must be rejected, not credited")
	}

	if _, err := deriveJavaCoverage(bindings, catalogSet, base(
		javaFormalResult{ObligationID: "o.absent", ProductionSymbol: "com.example.A.m()V", Status: "SATISFIED"},
	)); err == nil {
		t.Error("a Java result outside the catalog must be rejected")
	}

	covered, err = deriveJavaCoverage(bindings, catalogSet, base(
		javaFormalResult{ObligationID: "o.one", ProductionSymbol: "com.example.A.m()V", Status: "BLOCKED"},
	))
	if err != nil || len(covered) != 0 {
		t.Fatalf("a blocked Java result must not be credited: %v %v", covered, err)
	}

	if _, err := deriveJavaCoverage(bindings, catalogSet, javaFormalReceipt{SchemaVersion: "9.9.9", EvidenceKind: javaFormalEvidenceKind}); err == nil {
		t.Error("a Java receipt with foreign identity must be rejected")
	}
}

// The catalog's bindings must actually be readable; cmd/kanidriver previously
// unmarshalled only obligation_id and never loaded them at all.
func TestCatalogBindingsAreLoaded(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(coverageCatalogPath)))
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := decodeCoverageCatalog(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.JavaBindings) != coverageRequiredCount {
		t.Fatalf("expected %d Java bindings, got %d", coverageRequiredCount, len(catalog.JavaBindings))
	}
	for _, obligationID := range catalog.ObligationIDs {
		if catalog.JavaBindings[obligationID] == "" {
			t.Errorf("obligation %s has no Java production symbol", obligationID)
		}
	}
}
