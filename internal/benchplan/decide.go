package benchplan

import (
	"fmt"
	"math"
	"regexp"
	"strings"
)

// Provenance labels for raw sample sets.
const (
	// LabelSynthetic marks a fixture used only to validate the engine.
	LabelSynthetic = "SYNTHETIC_FIXTURE_NOT_A_MEASUREMENT"
	// LabelMeasured marks a real measured sample set. None exists yet;
	// a MEASURED set without complete, non-sentinel bindings is BLOCKED.
	LabelMeasured = "MEASURED"
)

// Outcome of a per-endpoint decision.
type Outcome string

const (
	// OutcomeThresholdMet: complete predeclared paired evidence met the
	// frozen CI threshold.
	OutcomeThresholdMet Outcome = "THRESHOLD_MET"
	// OutcomeThresholdNotMet: complete predeclared paired evidence did
	// not meet the frozen CI threshold.
	OutcomeThresholdNotMet Outcome = "THRESHOLD_NOT_MET"
	// OutcomeInconclusive: evidence exists but cannot decide (nonfinite
	// values, underpowered SD, raw-versus-summary disagreement).
	OutcomeInconclusive Outcome = "INCONCLUSIVE"
	// OutcomeBlocked: the sample set violates the preregistration
	// (wrong order, missing/extra pairs, unbound measurement).
	OutcomeBlocked Outcome = "BLOCKED"
)

// ThresholdBound names which exponentiated CI bound a threshold
// constrains.
type ThresholdBound string

const (
	// BoundUpper: the exponentiated upper 95% bound must be <= Value.
	BoundUpper ThresholdBound = "upper"
	// BoundLower: the exponentiated lower 95% bound must be >= Value.
	BoundLower ThresholdBound = "lower"
)

// Threshold is one frozen per-metric CI threshold.
type Threshold struct {
	Bound ThresholdBound
	Value float64
}

// MetricThresholds is the frozen threshold table (PRD US-008,
// acceptance criterion 5). Ratios are Rust/Java.
var MetricThresholds = map[string]Threshold{
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

// MetricNames returns the frozen metric endpoint names in a stable order.
var MetricNames = []string{
	"peak_rss", "steady_rss", "cpu_time", "startup_to_ready",
	"latency_p50", "latency_p95", "latency_p99",
	"allocated_bytes", "allocation_count", "throughput",
}

// RequiredSampleBindings is the frozen list of digests a canonical
// MEASURED raw-pair record must bind (PRD: plan, workload, order,
// environments, tools, Java/Rust source/executable/adapter digests, and
// the independently rebuilt analyzer).
var RequiredSampleBindings = []string{
	"plan_digest",
	"primary_environment_digest",
	"confirmation_environment_digest",
	"java_source_digest",
	"rust_source_digest",
	"java_executable_digest",
	"rust_executable_digest",
	"adapter_digest",
	"tool_identity_digest",
	"analyzer_digest",
}

// DeclaredSummary is a producer-declared summary that must agree with
// the raw recomputation or the endpoint is INCONCLUSIVE.
type DeclaredSummary struct {
	Mean       float64 `json:"mean"`
	SampleSD   float64 `json:"sample_sd"`
	CILowerExp float64 `json:"ci_lower_exp"`
	CIUpperExp float64 `json:"ci_upper_exp"`
}

// SampleSet is one canonical raw-pair record for one workload x metric
// endpoint.
type SampleSet struct {
	Schema          string            `json:"schema"`
	ProvenanceLabel string            `json:"provenance_label"`
	WorkloadID      string            `json:"workload_id"`
	Metric          string            `json:"metric"`
	Order           []string          `json:"order"`
	WarmupPairs     []Pair            `json:"warmup_pairs"`
	MeasuredPairs   []Pair            `json:"measured_pairs"`
	Bindings        map[string]string `json:"bindings,omitempty"`
	DeclaredSummary *DeclaredSummary  `json:"declared_summary,omitempty"`
}

// Decision is the fail-closed outcome for one endpoint.
type Decision struct {
	Outcome         Outcome
	Reasons         []string
	ProvenanceLabel string
	Analysis        *PairedAnalysis
}

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var zeroDigest = "sha256:" + strings.Repeat("0", 64)

// summaryTolerance is the maximum absolute disagreement between a
// declared summary field and its raw recomputation.
const summaryTolerance = 1e-9

// DecideEndpoint applies the preregistered fail-closed decision rule:
// only complete predeclared paired evidence can decide; every other
// case is INCONCLUSIVE or BLOCKED.
func DecideEndpoint(set SampleSet) Decision {
	decision := Decision{ProvenanceLabel: set.ProvenanceLabel}
	blocked := func(format string, args ...any) Decision {
		decision.Outcome = OutcomeBlocked
		decision.Reasons = append(decision.Reasons, fmt.Sprintf(format, args...))
		return decision
	}
	inconclusive := func(format string, args ...any) Decision {
		decision.Outcome = OutcomeInconclusive
		decision.Reasons = append(decision.Reasons, fmt.Sprintf(format, args...))
		return decision
	}

	switch set.ProvenanceLabel {
	case LabelSynthetic:
		// Engine-validation fixture; no bindings required, and any
		// outcome it produces is itself synthetic.
	case LabelMeasured:
		var missing []string
		for _, name := range RequiredSampleBindings {
			digest, present := set.Bindings[name]
			if !present || !digestPattern.MatchString(digest) || digest == zeroDigest {
				missing = append(missing, name)
			}
		}
		if len(missing) > 0 {
			return blocked("MEASURED sample set lacks valid canonical bindings: %s (no measured sample may exist before the attested plan freeze and host binding)", strings.Join(missing, ", "))
		}
	default:
		return blocked("unknown provenance label %q (must be %s or %s)", set.ProvenanceLabel, LabelSynthetic, LabelMeasured)
	}

	if !isKnownWorkload(set.WorkloadID) {
		return blocked("workload %q is not preregistered", set.WorkloadID)
	}
	threshold, known := MetricThresholds[set.Metric]
	if !known {
		return blocked("metric %q is not a preregistered endpoint", set.Metric)
	}

	expectedOrder, err := PairOrder(set.WorkloadID)
	if err != nil {
		return blocked("pair order derivation failed: %v", err)
	}
	if len(set.Order) != TotalPairs {
		return blocked("order length %d violates the preregistration (must be exactly %d)", len(set.Order), TotalPairs)
	}
	for i, entry := range set.Order {
		if entry != expectedOrder[i] {
			return blocked("pair %d order %q disagrees with the SHA-256-derived order %q (reordering is forbidden)", i, entry, expectedOrder[i])
		}
	}
	if len(set.WarmupPairs) != WarmupPairs {
		return blocked("warmup pair count %d violates the preregistration (must be exactly %d)", len(set.WarmupPairs), WarmupPairs)
	}
	if len(set.MeasuredPairs) != MeasuredPairs {
		return blocked("measured pair count %d violates the preregistration (must be exactly %d; missing and extra pairs are forbidden)", len(set.MeasuredPairs), MeasuredPairs)
	}

	analysis, err := AnalyzePairs(set.MeasuredPairs)
	if err != nil {
		return inconclusive("analysis fail-closed: %v", err)
	}
	decision.Analysis = &analysis

	if analysis.SampleSD > MaxLogRatioSD {
		return inconclusive("underpowered: sample log-ratio SD %.6f exceeds the frozen maximum %.2f", analysis.SampleSD, MaxLogRatioSD)
	}

	if set.DeclaredSummary != nil {
		disagreements := summaryDisagreements(*set.DeclaredSummary, analysis)
		if len(disagreements) > 0 {
			return inconclusive("raw-versus-summary disagreement (altered summaries are blocking): %s", strings.Join(disagreements, "; "))
		}
	}

	switch threshold.Bound {
	case BoundUpper:
		if analysis.CIUpperExp <= threshold.Value {
			decision.Outcome = OutcomeThresholdMet
		} else {
			decision.Outcome = OutcomeThresholdNotMet
		}
		decision.Reasons = append(decision.Reasons, fmt.Sprintf("exponentiated upper bound %.6f vs threshold <= %.2f", analysis.CIUpperExp, threshold.Value))
	case BoundLower:
		if analysis.CILowerExp >= threshold.Value {
			decision.Outcome = OutcomeThresholdMet
		} else {
			decision.Outcome = OutcomeThresholdNotMet
		}
		decision.Reasons = append(decision.Reasons, fmt.Sprintf("exponentiated lower bound %.6f vs threshold >= %.2f", analysis.CILowerExp, threshold.Value))
	default:
		return blocked("threshold bound %q is not preregistered", threshold.Bound)
	}
	return decision
}

func summaryDisagreements(declared DeclaredSummary, analysis PairedAnalysis) []string {
	var disagreements []string
	check := func(name string, declaredValue, recomputed float64) {
		if math.IsNaN(declaredValue) || math.IsInf(declaredValue, 0) || math.Abs(declaredValue-recomputed) > summaryTolerance {
			disagreements = append(disagreements, fmt.Sprintf("%s declared %.12f, recomputed %.12f", name, declaredValue, recomputed))
		}
	}
	check("mean", declared.Mean, analysis.Mean)
	check("sample_sd", declared.SampleSD, analysis.SampleSD)
	check("ci_lower_exp", declared.CILowerExp, analysis.CILowerExp)
	check("ci_upper_exp", declared.CIUpperExp, analysis.CIUpperExp)
	return disagreements
}
