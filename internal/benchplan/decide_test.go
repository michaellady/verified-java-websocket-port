package benchplan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadFixture(t *testing.T, name string) SampleSet {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var set SampleSet
	if err := json.Unmarshal(content, &set); err != nil {
		t.Fatal(err)
	}
	if set.ProvenanceLabel != LabelSynthetic {
		t.Fatalf("fixture %s must be labeled %s, got %q", name, LabelSynthetic, set.ProvenanceLabel)
	}
	return set
}

func TestDecideValidSyntheticFixtureDecides(t *testing.T) {
	// Closed form: mean=-0.02, sd=0.05 → exponentiated upper bound
	// exp(-0.02 + 2.045230*0.05/sqrt(30)) ≈ 0.99867 ≤ 1.0 for cpu_time.
	set := loadFixture(t, "synthetic-valid.json")
	decision := DecideEndpoint(set)
	if decision.Outcome != OutcomeThresholdMet {
		t.Fatalf("valid fixture: outcome %s (%v), want %s", decision.Outcome, decision.Reasons, OutcomeThresholdMet)
	}
	if decision.ProvenanceLabel != LabelSynthetic {
		t.Fatalf("decision must echo the synthetic provenance label, got %q", decision.ProvenanceLabel)
	}
	if decision.Analysis == nil {
		t.Fatal("valid decision must carry the analysis")
	}
}

func TestDecideValidFixtureWithAgreeingSummaryDecides(t *testing.T) {
	set := loadFixture(t, "synthetic-valid.json")
	base := DecideEndpoint(set)
	if base.Analysis == nil {
		t.Fatal("baseline analysis missing")
	}
	set.DeclaredSummary = &DeclaredSummary{
		Mean:       base.Analysis.Mean,
		SampleSD:   base.Analysis.SampleSD,
		CILowerExp: base.Analysis.CILowerExp,
		CIUpperExp: base.Analysis.CIUpperExp,
	}
	decision := DecideEndpoint(set)
	if decision.Outcome != OutcomeThresholdMet {
		t.Fatalf("agreeing summary: outcome %s (%v)", decision.Outcome, decision.Reasons)
	}
}

func TestDecideUnderpoweredFixtureIsInconclusive(t *testing.T) {
	set := loadFixture(t, "synthetic-underpowered.json")
	decision := DecideEndpoint(set)
	if decision.Outcome != OutcomeInconclusive {
		t.Fatalf("underpowered fixture: outcome %s (%v), want %s", decision.Outcome, decision.Reasons, OutcomeInconclusive)
	}
	if !reasonsContain(decision.Reasons, "underpowered") {
		t.Fatalf("expected an underpowered reason, got %v", decision.Reasons)
	}
}

func TestDecideNonfiniteFixtureIsInconclusive(t *testing.T) {
	set := loadFixture(t, "synthetic-nonfinite.json")
	decision := DecideEndpoint(set)
	if decision.Outcome != OutcomeInconclusive {
		t.Fatalf("nonfinite fixture: outcome %s (%v), want %s", decision.Outcome, decision.Reasons, OutcomeInconclusive)
	}
}

func TestDecideReorderedFixtureIsBlocked(t *testing.T) {
	set := loadFixture(t, "synthetic-reordered.json")
	decision := DecideEndpoint(set)
	if decision.Outcome != OutcomeBlocked {
		t.Fatalf("reordered fixture: outcome %s (%v), want %s", decision.Outcome, decision.Reasons, OutcomeBlocked)
	}
	if !reasonsContain(decision.Reasons, "order") {
		t.Fatalf("expected an order reason, got %v", decision.Reasons)
	}
}

func TestDecideMissingPairFixtureIsBlocked(t *testing.T) {
	set := loadFixture(t, "synthetic-missing-pair.json")
	decision := DecideEndpoint(set)
	if decision.Outcome != OutcomeBlocked {
		t.Fatalf("missing-pair fixture: outcome %s (%v), want %s", decision.Outcome, decision.Reasons, OutcomeBlocked)
	}
}

func TestDecideExtraPairIsBlocked(t *testing.T) {
	set := loadFixture(t, "synthetic-valid.json")
	set.MeasuredPairs = append(set.MeasuredPairs, Pair{Java: 100, Rust: 98})
	decision := DecideEndpoint(set)
	if decision.Outcome != OutcomeBlocked {
		t.Fatalf("extra pair: outcome %s (%v), want %s", decision.Outcome, decision.Reasons, OutcomeBlocked)
	}
}

func TestDecideWrongWarmupCountIsBlocked(t *testing.T) {
	set := loadFixture(t, "synthetic-valid.json")
	set.WarmupPairs = set.WarmupPairs[:4]
	decision := DecideEndpoint(set)
	if decision.Outcome != OutcomeBlocked {
		t.Fatalf("warmup count: outcome %s (%v), want %s", decision.Outcome, decision.Reasons, OutcomeBlocked)
	}
}

func TestDecidePostHocMutatedSummaryIsInconclusive(t *testing.T) {
	set := loadFixture(t, "synthetic-valid.json")
	base := DecideEndpoint(set)
	if base.Analysis == nil {
		t.Fatal("baseline analysis missing")
	}
	// A post-hoc "improved" summary that disagrees with the raw pairs.
	set.DeclaredSummary = &DeclaredSummary{
		Mean:       base.Analysis.Mean - 0.05,
		SampleSD:   base.Analysis.SampleSD,
		CILowerExp: base.Analysis.CILowerExp,
		CIUpperExp: base.Analysis.CIUpperExp - 0.1,
	}
	decision := DecideEndpoint(set)
	if decision.Outcome != OutcomeInconclusive {
		t.Fatalf("mutated summary: outcome %s (%v), want %s", decision.Outcome, decision.Reasons, OutcomeInconclusive)
	}
	if !reasonsContain(decision.Reasons, "disagreement") {
		t.Fatalf("expected a raw-versus-summary disagreement reason, got %v", decision.Reasons)
	}
}

func TestDecideMeasuredWithoutBindingsIsBlocked(t *testing.T) {
	set := loadFixture(t, "synthetic-valid.json")
	set.ProvenanceLabel = LabelMeasured
	decision := DecideEndpoint(set)
	if decision.Outcome != OutcomeBlocked {
		t.Fatalf("unbound MEASURED set: outcome %s (%v), want %s", decision.Outcome, decision.Reasons, OutcomeBlocked)
	}
	if !reasonsContain(decision.Reasons, "binding") {
		t.Fatalf("expected a bindings reason, got %v", decision.Reasons)
	}
}

func TestDecideMeasuredWithZeroDigestsIsBlocked(t *testing.T) {
	set := loadFixture(t, "synthetic-valid.json")
	set.ProvenanceLabel = LabelMeasured
	set.Bindings = map[string]string{}
	for _, name := range RequiredSampleBindings {
		set.Bindings[name] = "sha256:" + strings.Repeat("0", 64)
	}
	decision := DecideEndpoint(set)
	if decision.Outcome != OutcomeBlocked {
		t.Fatalf("zero-digest MEASURED set: outcome %s (%v), want %s", decision.Outcome, decision.Reasons, OutcomeBlocked)
	}
}

func TestDecideUnknownLabelWorkloadMetricAreBlocked(t *testing.T) {
	set := loadFixture(t, "synthetic-valid.json")
	set.ProvenanceLabel = "TOTALLY_REAL_MEASUREMENT"
	if decision := DecideEndpoint(set); decision.Outcome != OutcomeBlocked {
		t.Fatalf("unknown label: outcome %s, want %s", decision.Outcome, OutcomeBlocked)
	}
	set = loadFixture(t, "synthetic-valid.json")
	set.WorkloadID = "wl-99-not-preregistered"
	if decision := DecideEndpoint(set); decision.Outcome != OutcomeBlocked {
		t.Fatalf("unknown workload: outcome %s, want %s", decision.Outcome, OutcomeBlocked)
	}
	set = loadFixture(t, "synthetic-valid.json")
	set.Metric = "vibes"
	if decision := DecideEndpoint(set); decision.Outcome != OutcomeBlocked {
		t.Fatalf("unknown metric: outcome %s, want %s", decision.Outcome, OutcomeBlocked)
	}
}

func TestThresholdTableIsTheFrozenPRDTable(t *testing.T) {
	expected := map[string]Threshold{
		"peak_rss":         {BoundUpper, 0.8},
		"steady_rss":       {BoundUpper, 0.8},
		"cpu_time":         {BoundUpper, 1.0},
		"startup_to_ready": {BoundUpper, 1.0},
		"latency_p50":      {BoundUpper, 1.0},
		"latency_p95":      {BoundUpper, 1.0},
		"latency_p99":      {BoundUpper, 1.0},
		"allocated_bytes":  {BoundUpper, 1.0},
		"allocation_count": {BoundUpper, 1.0},
		"throughput":       {BoundLower, 1.0},
	}
	if len(MetricThresholds) != len(expected) {
		t.Fatalf("threshold table has %d entries, frozen plan requires %d", len(MetricThresholds), len(expected))
	}
	for metric, want := range expected {
		got, present := MetricThresholds[metric]
		if !present || got != want {
			t.Errorf("metric %s: got %+v, frozen plan requires %+v", metric, got, want)
		}
	}
	if len(MetricNames) != len(expected) {
		t.Fatalf("MetricNames has %d entries, want %d", len(MetricNames), len(expected))
	}
	for _, name := range MetricNames {
		if _, present := expected[name]; !present {
			t.Errorf("MetricNames contains unknown metric %s", name)
		}
	}
}

func reasonsContain(reasons []string, fragment string) bool {
	for _, reason := range reasons {
		if strings.Contains(strings.ToLower(reason), strings.ToLower(fragment)) {
			return true
		}
	}
	return false
}
