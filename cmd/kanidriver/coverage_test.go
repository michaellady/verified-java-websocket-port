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
	projection, err := buildCoverageProjection(root, "evidence/formal/kani-0cf36a9/summary.json")
	if err != nil {
		t.Fatal(err)
	}
	if projection.Status != "BLOCKED" || projection.ClaimScope != "SUPPLEMENTAL_RUST_FORMAL_COVERAGE_ONLY" {
		t.Fatalf("projection posture = %#v", projection)
	}
	if projection.Counts.Required != 24 || projection.Counts.RustSatisfied != 11 ||
		projection.Counts.MutationSatisfied != 9 || projection.Counts.JavaSatisfied != 0 ||
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
		"surface.messages.text-utf8",
	} {
		if !covered[obligationID] {
			t.Errorf("missing verified production-symbol coverage for %s", obligationID)
		}
	}
	if covered["surface.websocket-open"] {
		t.Fatal("unproved WebSocket-open obligation was marked satisfied")
	}
	for _, obligationID := range []string{"obligation.length-canonical-7", "obligation.mask-involution"} {
		if mutationCovered[obligationID] {
			t.Errorf("%s was credited with mutation coverage it does not have", obligationID)
		}
	}
	for _, obligationID := range []string{
		"obligation.checked-header-arithmetic",
		"obligation.control-fin-and-length",
		"obligation.length-canonical-16",
		"obligation.length-canonical-64-high-bit-zero",
		"obligation.mask-equation",
		"obligation.preallocation-cap",
		"obligation.role-masking",
		"surface.close.status-code",
		"surface.messages.text-utf8",
	} {
		if !mutationCovered[obligationID] {
			t.Errorf("missing verified mutation coverage for %s", obligationID)
		}
	}
}

func TestValidateCoverageProjectionRejectsCountAndClaimInflation(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	projection, err := buildCoverageProjection(root, "evidence/formal/kani-0cf36a9/summary.json")
	if err != nil {
		t.Fatal(err)
	}
	projection.Counts.RustSatisfied++
	if err := validateCoverageProjection(root, projection); err == nil {
		t.Fatal("inflated Rust coverage count was accepted")
	}

	projection, err = buildCoverageProjection(root, "evidence/formal/kani-0cf36a9/summary.json")
	if err != nil {
		t.Fatal(err)
	}
	projection.Coverage[len(projection.Coverage)-1].AggregateStatus = "SATISFIED"
	if err := validateCoverageProjection(root, projection); err == nil {
		t.Fatal("inflated aggregate coverage was accepted")
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
	projection, err := buildCoverageProjection(root, "evidence/formal/kani-0cf36a9/summary.json")
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
