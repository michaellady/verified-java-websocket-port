package benchplan

import (
	"crypto/sha256"
	"encoding/hex"
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

// syntheticDigest builds an obviously-synthetic but well-formed digest
// for binding-verification tests (the hash of a labeled test string,
// never of any real artifact).
func syntheticDigest(name string) string {
	sum := sha256.Sum256([]byte("synthetic-binding-not-a-real-artifact|" + name))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func syntheticClosure() BoundIdentities {
	closure := BoundIdentities{}
	for _, name := range RequiredSampleBindings {
		closure[name] = syntheticDigest(name)
	}
	return closure
}

// measuredSet builds a MEASURED-labeled set from the valid fixture with
// a complete matching binding closure and clean run-validity
// observations. It exists only to exercise the verification code paths;
// every digest is synthetic and labeled as such.
func measuredSet(t *testing.T) (SampleSet, BoundIdentities) {
	t.Helper()
	set := loadFixture(t, "synthetic-valid.json")
	set.ProvenanceLabel = LabelMeasured
	set.Bindings = map[string]string{}
	closure := syntheticClosure()
	for name, digest := range closure {
		set.Bindings[name] = digest
	}
	observations := cleanObservations()
	set.RunValidity = &observations
	return set, closure
}

func TestDecideValidSyntheticFixtureDecides(t *testing.T) {
	set := loadFixture(t, "synthetic-valid.json")
	decision := DecideEndpoint(set, nil)
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
	base := DecideEndpoint(set, nil)
	if base.Analysis == nil {
		t.Fatal("baseline analysis missing")
	}
	set.DeclaredSummary = &DeclaredSummary{
		Mean:       base.Analysis.Mean,
		SampleSD:   base.Analysis.SampleSD,
		CILowerExp: base.Analysis.CILowerExp,
		CIUpperExp: base.Analysis.CIUpperExp,
	}
	decision := DecideEndpoint(set, nil)
	if decision.Outcome != OutcomeThresholdMet {
		t.Fatalf("agreeing summary: outcome %s (%v)", decision.Outcome, decision.Reasons)
	}
}

func TestDecideUnderpoweredFixtureIsInconclusive(t *testing.T) {
	set := loadFixture(t, "synthetic-underpowered.json")
	decision := DecideEndpoint(set, nil)
	if decision.Outcome != OutcomeInconclusive {
		t.Fatalf("underpowered fixture: outcome %s (%v), want %s", decision.Outcome, decision.Reasons, OutcomeInconclusive)
	}
	if !reasonsContain(decision.Reasons, "underpowered") {
		t.Fatalf("expected an underpowered reason, got %v", decision.Reasons)
	}
}

func TestDecideNonfiniteFixtureIsInconclusive(t *testing.T) {
	set := loadFixture(t, "synthetic-nonfinite.json")
	decision := DecideEndpoint(set, nil)
	if decision.Outcome != OutcomeInconclusive {
		t.Fatalf("nonfinite fixture: outcome %s (%v), want %s", decision.Outcome, decision.Reasons, OutcomeInconclusive)
	}
}

func TestDecideReorderedFixtureIsBlocked(t *testing.T) {
	set := loadFixture(t, "synthetic-reordered.json")
	decision := DecideEndpoint(set, nil)
	if decision.Outcome != OutcomeBlocked {
		t.Fatalf("reordered fixture: outcome %s (%v), want %s", decision.Outcome, decision.Reasons, OutcomeBlocked)
	}
	if !reasonsContain(decision.Reasons, "order") {
		t.Fatalf("expected an order reason, got %v", decision.Reasons)
	}
}

func TestDecideMissingPairFixtureIsBlocked(t *testing.T) {
	set := loadFixture(t, "synthetic-missing-pair.json")
	decision := DecideEndpoint(set, nil)
	if decision.Outcome != OutcomeBlocked {
		t.Fatalf("missing-pair fixture: outcome %s (%v), want %s", decision.Outcome, decision.Reasons, OutcomeBlocked)
	}
}

func TestDecideExtraPairIsBlocked(t *testing.T) {
	set := loadFixture(t, "synthetic-valid.json")
	set.MeasuredPairs = append(set.MeasuredPairs, Pair{Java: 100, Rust: 98})
	decision := DecideEndpoint(set, nil)
	if decision.Outcome != OutcomeBlocked {
		t.Fatalf("extra pair: outcome %s (%v), want %s", decision.Outcome, decision.Reasons, OutcomeBlocked)
	}
}

func TestDecideWrongWarmupCountIsBlocked(t *testing.T) {
	set := loadFixture(t, "synthetic-valid.json")
	set.WarmupPairs = set.WarmupPairs[:4]
	decision := DecideEndpoint(set, nil)
	if decision.Outcome != OutcomeBlocked {
		t.Fatalf("warmup count: outcome %s (%v), want %s", decision.Outcome, decision.Reasons, OutcomeBlocked)
	}
}

func TestDecidePostHocMutatedSummaryIsInconclusive(t *testing.T) {
	set := loadFixture(t, "synthetic-valid.json")
	base := DecideEndpoint(set, nil)
	if base.Analysis == nil {
		t.Fatal("baseline analysis missing")
	}
	set.DeclaredSummary = &DeclaredSummary{
		Mean:       base.Analysis.Mean - 0.05,
		SampleSD:   base.Analysis.SampleSD,
		CILowerExp: base.Analysis.CILowerExp,
		CIUpperExp: base.Analysis.CIUpperExp - 0.1,
	}
	decision := DecideEndpoint(set, nil)
	if decision.Outcome != OutcomeInconclusive {
		t.Fatalf("mutated summary: outcome %s (%v), want %s", decision.Outcome, decision.Reasons, OutcomeInconclusive)
	}
	if !reasonsContain(decision.Reasons, "disagreement") {
		t.Fatalf("expected a raw-versus-summary disagreement reason, got %v", decision.Reasons)
	}
}

// Review fix B3: sample sets must be self-distinguishing by environment
// role.
func TestDecideMissingOrUnknownEnvironmentRoleIsBlocked(t *testing.T) {
	set := loadFixture(t, "synthetic-valid.json")
	set.EnvironmentRole = ""
	decision := DecideEndpoint(set, nil)
	if decision.Outcome != OutcomeBlocked || !codesContain(decision.Codes, CodeEnvironmentRoleInvalid) {
		t.Fatalf("empty role: outcome %s codes %v, want BLOCKED with %s", decision.Outcome, decision.Codes, CodeEnvironmentRoleInvalid)
	}
	set = loadFixture(t, "synthetic-valid.json")
	set.EnvironmentRole = "docker-sbx"
	decision = DecideEndpoint(set, nil)
	if decision.Outcome != OutcomeBlocked || !codesContain(decision.Codes, CodeEnvironmentRoleInvalid) {
		t.Fatalf("unknown role: outcome %s codes %v, want BLOCKED with %s", decision.Outcome, decision.Codes, CodeEnvironmentRoleInvalid)
	}
	set = loadFixture(t, "synthetic-valid.json")
	set.EnvironmentRole = EnvironmentRoleConfirmation
	if decision := DecideEndpoint(set, nil); decision.Outcome != OutcomeThresholdMet {
		t.Fatalf("confirmation role must be accepted, got %s (%v)", decision.Outcome, decision.Reasons)
	}
}

// Review fix B2: identity verification is EQUALITY against the bound
// closure, not presence/format.
func TestDecideMeasuredWithMatchingClosureDecides(t *testing.T) {
	set, closure := measuredSet(t)
	decision := DecideEndpoint(set, closure)
	if decision.Outcome != OutcomeThresholdMet {
		t.Fatalf("matching closure: outcome %s (%v), want %s", decision.Outcome, decision.Reasons, OutcomeThresholdMet)
	}
	if decision.ProvenanceLabel != LabelMeasured {
		t.Fatalf("decision must echo the provenance label, got %q", decision.ProvenanceLabel)
	}
}

func TestDecideMeasuredEachDigestMutationIsBindingMismatch(t *testing.T) {
	for _, name := range RequiredSampleBindings {
		set, closure := measuredSet(t)
		// Flip one hex character of this sample digest: still perfectly
		// well-formed, but no longer EQUAL to the bound identity.
		digest := set.Bindings[name]
		last := digest[len(digest)-1]
		flip := "0"
		if last == '0' {
			flip = "1"
		}
		set.Bindings[name] = digest[:len(digest)-1] + flip
		decision := DecideEndpoint(set, closure)
		if decision.Outcome != OutcomeBlocked {
			t.Errorf("%s mutated: outcome %s (%v), want %s", name, decision.Outcome, decision.Reasons, OutcomeBlocked)
			continue
		}
		if !codesContain(decision.Codes, CodeBindingMismatch) {
			t.Errorf("%s mutated: codes %v must contain %s", name, decision.Codes, CodeBindingMismatch)
		}
		if !reasonsContain(decision.Reasons, name) {
			t.Errorf("%s mutated: reasons %v must name the mismatched field", name, decision.Reasons)
		}
	}
}

func TestDecideMeasuredBoundSideMutationIsBindingMismatch(t *testing.T) {
	set, closure := measuredSet(t)
	closure["analyzer_digest"] = syntheticDigest("a-different-analyzer")
	decision := DecideEndpoint(set, closure)
	if decision.Outcome != OutcomeBlocked || !codesContain(decision.Codes, CodeBindingMismatch) {
		t.Fatalf("bound-side mutation: outcome %s codes %v, want BLOCKED with %s", decision.Outcome, decision.Codes, CodeBindingMismatch)
	}
}

func TestDecideMeasuredWithoutClosureIsBlocked(t *testing.T) {
	set, _ := measuredSet(t)
	decision := DecideEndpoint(set, nil)
	if decision.Outcome != OutcomeBlocked || !codesContain(decision.Codes, CodeBindingMissing) {
		t.Fatalf("nil closure: outcome %s codes %v, want BLOCKED with %s", decision.Outcome, decision.Codes, CodeBindingMissing)
	}
}

func TestDecideMeasuredWithoutBindingsIsBlocked(t *testing.T) {
	set := loadFixture(t, "synthetic-valid.json")
	set.ProvenanceLabel = LabelMeasured
	decision := DecideEndpoint(set, syntheticClosure())
	if decision.Outcome != OutcomeBlocked || !codesContain(decision.Codes, CodeBindingMissing) {
		t.Fatalf("unbound MEASURED set: outcome %s codes %v, want BLOCKED with %s", decision.Outcome, decision.Codes, CodeBindingMissing)
	}
}

func TestDecideMeasuredWithZeroDigestsIsBlocked(t *testing.T) {
	set, closure := measuredSet(t)
	zero := "sha256:" + strings.Repeat("0", 64)
	for _, name := range RequiredSampleBindings {
		set.Bindings[name] = zero
	}
	decision := DecideEndpoint(set, closure)
	if decision.Outcome != OutcomeBlocked || !codesContain(decision.Codes, CodeBindingMissing) {
		t.Fatalf("zero-digest MEASURED set: outcome %s codes %v, want BLOCKED with %s", decision.Outcome, decision.Codes, CodeBindingMissing)
	}
}

// Review fix B4: run-validity observations are mandatory for MEASURED
// and enforced fail-closed.
func TestDecideMeasuredWithoutRunValidityIsBlocked(t *testing.T) {
	set, closure := measuredSet(t)
	set.RunValidity = nil
	decision := DecideEndpoint(set, closure)
	if decision.Outcome != OutcomeBlocked || !codesContain(decision.Codes, CodeRunValidityMissing) {
		t.Fatalf("missing observations: outcome %s codes %v, want BLOCKED with %s", decision.Outcome, decision.Codes, CodeRunValidityMissing)
	}
}

func TestDecideRunValidityViolationFixtureIsInconclusive(t *testing.T) {
	set := loadFixture(t, "synthetic-run-validity-violation.json")
	if set.RunValidity == nil {
		t.Fatal("fixture must carry run-validity observations")
	}
	decision := DecideEndpoint(set, nil)
	if decision.Outcome != OutcomeInconclusive {
		t.Fatalf("violation fixture: outcome %s (%v), want %s", decision.Outcome, decision.Reasons, OutcomeInconclusive)
	}
	if !codesContain(decision.Codes, CodeRunValidityViolation) {
		t.Fatalf("codes %v must contain %s", decision.Codes, CodeRunValidityViolation)
	}
	// The fixture violates both the thermal rule and the drift envelope.
	if !reasonsContain(decision.Reasons, "thermal") || !reasonsContain(decision.Reasons, "drifted") {
		t.Fatalf("reasons must name thermal and drift violations, got %v", decision.Reasons)
	}
}

func TestDecideMeasuredMalformedRunValidityIsBlocked(t *testing.T) {
	set, closure := measuredSet(t)
	set.RunValidity.ReferenceDrift.SubsequentStatistics = set.RunValidity.ReferenceDrift.SubsequentStatistics[:3]
	decision := DecideEndpoint(set, closure)
	if decision.Outcome != OutcomeBlocked || !codesContain(decision.Codes, CodeRunValidityMissing) {
		t.Fatalf("malformed observations: outcome %s codes %v, want BLOCKED with %s", decision.Outcome, decision.Codes, CodeRunValidityMissing)
	}
}

func TestDecideUnknownLabelWorkloadMetricAreBlocked(t *testing.T) {
	set := loadFixture(t, "synthetic-valid.json")
	set.ProvenanceLabel = "TOTALLY_REAL_MEASUREMENT"
	if decision := DecideEndpoint(set, nil); decision.Outcome != OutcomeBlocked {
		t.Fatalf("unknown label: outcome %s, want %s", decision.Outcome, OutcomeBlocked)
	}
	set = loadFixture(t, "synthetic-valid.json")
	set.WorkloadID = "wl-99-not-preregistered"
	if decision := DecideEndpoint(set, nil); decision.Outcome != OutcomeBlocked {
		t.Fatalf("unknown workload: outcome %s, want %s", decision.Outcome, OutcomeBlocked)
	}
	set = loadFixture(t, "synthetic-valid.json")
	set.Metric = "vibes"
	if decision := DecideEndpoint(set, nil); decision.Outcome != OutcomeBlocked {
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

func codesContain(codes []string, code string) bool {
	for _, candidate := range codes {
		if candidate == code {
			return true
		}
	}
	return false
}
