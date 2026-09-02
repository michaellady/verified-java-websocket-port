package benchplan

import (
	"fmt"
	"math"
	"strings"
)

// Frozen reference-drift procedure (review fix B4). The plan document
// pins the same values; verification fails on any disagreement.
const (
	// ReferenceDriftEnvelopePercent is the PRD's 5% reference-drift
	// envelope.
	ReferenceDriftEnvelopePercent = 5
	// ReferenceWorkloadID is the frozen reference workload whose
	// dedicated reference runs probe environment drift.
	ReferenceWorkloadID = "wl-02-small-text-echo"
	// ReferenceRunsTotal: one baseline run before pair 0 plus one run
	// after every 5 completed pairs (after pairs 4, 9, 14, 19, 24, 29,
	// and 34).
	ReferenceRunsTotal = 8
	// ReferenceSubsequentRuns is ReferenceRunsTotal minus the baseline.
	ReferenceSubsequentRuns = ReferenceRunsTotal - 1
)

// CheckReferenceDrift applies the frozen drift rule: every subsequent
// reference statistic s_i must satisfy |s_i - baseline| <= 0.05 *
// baseline (the product form is the frozen comparison, chosen over the
// ratio form so the exact 5% boundary is not misclassified by floating-
// point rounding). It is fail-closed: a wrong count or a nonfinite/
// nonpositive statistic is an error (the observation set is malformed),
// and each out-of-envelope statistic is returned as a violation.
func CheckReferenceDrift(baseline float64, subsequent []float64) ([]string, error) {
	if !isFinitePositive(baseline) {
		return nil, fmt.Errorf("reference drift: baseline statistic %g is not finite and strictly positive", baseline)
	}
	if len(subsequent) != ReferenceSubsequentRuns {
		return nil, fmt.Errorf("reference drift: %d subsequent statistics, the frozen schedule requires exactly %d", len(subsequent), ReferenceSubsequentRuns)
	}
	envelope := float64(ReferenceDriftEnvelopePercent) / 100 * baseline
	var violations []string
	for i, statistic := range subsequent {
		if !isFinitePositive(statistic) {
			return nil, fmt.Errorf("reference drift: subsequent statistic %d (%g) is not finite and strictly positive", i, statistic)
		}
		if math.Abs(statistic-baseline) > envelope {
			violations = append(violations, fmt.Sprintf(
				"reference run %d drifted %.4f%% from baseline (envelope %d%%)", i+1, math.Abs(statistic/baseline-1)*100, ReferenceDriftEnvelopePercent))
		}
	}
	return violations, nil
}

// ReferenceDriftObservations is the recorded reference-run statistics
// for one workload run sequence.
type ReferenceDriftObservations struct {
	BaselineStatistic    float64   `json:"baseline_statistic"`
	SubsequentStatistics []float64 `json:"subsequent_statistics"`
}

// RunValidityObservations records the fail-closed run-validity facts
// the PRD requires for every measured run sequence: background CPU,
// thermal, power, identity, invalid-sample, and reference-drift
// observations.
type RunValidityObservations struct {
	BackgroundCPUPercentMaxObserved float64                    `json:"background_cpu_percent_max_observed"`
	ThermalThrottleEvents           int                        `json:"thermal_throttle_events"`
	PowerStateAnomalies             int                        `json:"power_state_anomalies"`
	IdentityChecksPassed            bool                       `json:"identity_checks_passed"`
	InvalidSamples                  int                        `json:"invalid_samples"`
	ReferenceDrift                  ReferenceDriftObservations `json:"reference_drift"`

	// ObservedCPUClock is the per-run observed CPU clock required by the
	// owner-bound host CPU-frequency policy
	// DOCUMENT_DEFAULTS_RECORD_OBSERVED (decision record
	// us009-us008-owner-decisions-2026-08-27.json,
	// us008_cpu_frequency_policy). It is a pointer so that ABSENCE is
	// distinguishable from a zero-valued record: a MEASURED sample that
	// omits it is BLOCKED, never defaulted.
	//
	// RECORD-ONLY by construction. The bound policy documents the host's
	// default scaling behavior and records the observed clock; it
	// declares NO threshold. EnforceRunValidity therefore validates only
	// that the readings are well formed and never derives a violation
	// from their values — adding a clock threshold would be an
	// unattested addition to a frozen preregistration.
	ObservedCPUClock *ObservedCPUClock `json:"observed_cpu_clock,omitempty"`
}

// ObservedCPUClock is one run sequence's recorded CPU-clock evidence:
// the identity of the reader that produced it and the readings
// themselves. An unattributed reading is not evidence, so Source is
// mandatory and non-empty.
type ObservedCPUClock struct {
	Source     string    `json:"source"`
	SamplesMHz []float64 `json:"samples_mhz"`
}

// validate reports whether the recorded clock evidence is well formed.
// It applies no threshold: see the ObservedCPUClock field comment.
func (o *ObservedCPUClock) validate() error {
	if strings.TrimSpace(o.Source) == "" {
		return fmt.Errorf("run validity: observed CPU clock record has an empty source (an unattributed clock reading is not evidence)")
	}
	if len(o.SamplesMHz) == 0 {
		return fmt.Errorf("run validity: observed CPU clock record from %q carries no readings (the bound CPU-frequency policy requires the observed clock recorded per run)", o.Source)
	}
	for i, mhz := range o.SamplesMHz {
		if math.IsNaN(mhz) || math.IsInf(mhz, 0) || mhz <= 0 {
			return fmt.Errorf("run validity: observed CPU clock reading %d from %q is %g, not a finite positive MHz value", i, o.Source, mhz)
		}
	}
	return nil
}

// EnforceRunValidity applies the frozen fail-closed validity rules to a
// recorded observation set. Malformed observations are an error;
// rule violations are returned as violations (the endpoint becomes
// INCONCLUSIVE, never patched or resampled around).
func EnforceRunValidity(observations RunValidityObservations) ([]string, error) {
	if math.IsNaN(observations.BackgroundCPUPercentMaxObserved) || math.IsInf(observations.BackgroundCPUPercentMaxObserved, 0) || observations.BackgroundCPUPercentMaxObserved < 0 {
		return nil, fmt.Errorf("run validity: background CPU observation %g is not a finite non-negative percentage", observations.BackgroundCPUPercentMaxObserved)
	}
	if observations.ThermalThrottleEvents < 0 || observations.PowerStateAnomalies < 0 || observations.InvalidSamples < 0 {
		return nil, fmt.Errorf("run validity: negative event counts (%d thermal, %d power, %d invalid)",
			observations.ThermalThrottleEvents, observations.PowerStateAnomalies, observations.InvalidSamples)
	}
	// Malformed clock evidence is an error (BLOCKED), never a violation:
	// the bound policy is record-only, so a badly formed record means the
	// required observation is absent, not that a rule was broken.
	if observations.ObservedCPUClock != nil {
		if err := observations.ObservedCPUClock.validate(); err != nil {
			return nil, err
		}
	}
	var violations []string
	if observations.BackgroundCPUPercentMaxObserved > 2 {
		violations = append(violations, fmt.Sprintf("background CPU %.4f%% exceeds the 2%% budget", observations.BackgroundCPUPercentMaxObserved))
	}
	if observations.ThermalThrottleEvents > 0 {
		violations = append(violations, fmt.Sprintf("%d thermal throttle event(s) (fail-closed: must be zero)", observations.ThermalThrottleEvents))
	}
	if observations.PowerStateAnomalies > 0 {
		violations = append(violations, fmt.Sprintf("%d power-state anomaly(ies) (fail-closed: must be zero)", observations.PowerStateAnomalies))
	}
	if !observations.IdentityChecksPassed {
		violations = append(violations, "host/tool identity checks did not pass (fail-closed)")
	}
	if observations.InvalidSamples > 0 {
		violations = append(violations, fmt.Sprintf("%d INVALID sample(s): replacement is forbidden, the run sequence cannot decide", observations.InvalidSamples))
	}
	driftViolations, err := CheckReferenceDrift(observations.ReferenceDrift.BaselineStatistic, observations.ReferenceDrift.SubsequentStatistics)
	if err != nil {
		return nil, err
	}
	violations = append(violations, driftViolations...)
	return violations, nil
}
