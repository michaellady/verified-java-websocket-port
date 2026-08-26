package benchplan

import (
	"math"
	"strings"
	"testing"
)

func cleanDrift() ReferenceDriftObservations {
	return ReferenceDriftObservations{
		BaselineStatistic:    100,
		SubsequentStatistics: []float64{100, 101, 99, 104.9, 95.1, 100, 102},
	}
}

func cleanObservations() RunValidityObservations {
	return RunValidityObservations{
		BackgroundCPUPercentMaxObserved: 1.5,
		ThermalThrottleEvents:           0,
		PowerStateAnomalies:             0,
		IdentityChecksPassed:            true,
		InvalidSamples:                  0,
		ReferenceDrift:                  cleanDrift(),
	}
}

func TestCheckReferenceDriftAcceptsWithinEnvelope(t *testing.T) {
	drift := cleanDrift()
	violations, err := CheckReferenceDrift(drift.BaselineStatistic, drift.SubsequentStatistics)
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 0 {
		t.Fatalf("statistics within 5%% must not violate, got %v", violations)
	}
}

func TestCheckReferenceDriftFlagsOutOfEnvelope(t *testing.T) {
	subsequent := []float64{100, 106, 100, 100, 93, 100, 100} // +6% and -7%
	violations, err := CheckReferenceDrift(100, subsequent)
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 2 {
		t.Fatalf("expected exactly 2 drift violations, got %v", violations)
	}
	// The 5% boundary is inclusive: exactly 5.0% does not violate.
	violations, err = CheckReferenceDrift(100, []float64{105, 95, 100, 100, 100, 100, 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 0 {
		t.Fatalf("exactly 5%% drift is within the envelope, got %v", violations)
	}
}

func TestCheckReferenceDriftIsFailClosedOnMalformedInput(t *testing.T) {
	good := cleanDrift().SubsequentStatistics
	if _, err := CheckReferenceDrift(0, good); err == nil {
		t.Error("expected error for zero baseline")
	}
	if _, err := CheckReferenceDrift(math.NaN(), good); err == nil {
		t.Error("expected error for NaN baseline")
	}
	if _, err := CheckReferenceDrift(100, good[:6]); err == nil {
		t.Error("expected error for 6 subsequent statistics (schedule requires 7)")
	}
	if _, err := CheckReferenceDrift(100, append(append([]float64{}, good...), 100)); err == nil {
		t.Error("expected error for 8 subsequent statistics")
	}
	bad := append([]float64{}, good...)
	bad[3] = -1
	if _, err := CheckReferenceDrift(100, bad); err == nil {
		t.Error("expected error for negative subsequent statistic")
	}
}

func TestEnforceRunValidityCleanObservationsPass(t *testing.T) {
	violations, err := EnforceRunValidity(cleanObservations())
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 0 {
		t.Fatalf("clean observations must not violate, got %v", violations)
	}
}

func TestEnforceRunValidityFlagsEachViolation(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*RunValidityObservations)
		fragment string
	}{
		{"background cpu", func(o *RunValidityObservations) { o.BackgroundCPUPercentMaxObserved = 2.5 }, "2% budget"},
		{"thermal", func(o *RunValidityObservations) { o.ThermalThrottleEvents = 1 }, "thermal"},
		{"power", func(o *RunValidityObservations) { o.PowerStateAnomalies = 2 }, "power-state"},
		{"identity", func(o *RunValidityObservations) { o.IdentityChecksPassed = false }, "identity"},
		{"invalid samples", func(o *RunValidityObservations) { o.InvalidSamples = 1 }, "INVALID sample"},
		{"drift", func(o *RunValidityObservations) { o.ReferenceDrift.SubsequentStatistics[0] = 120 }, "drifted"},
	}
	for _, testCase := range cases {
		observations := cleanObservations()
		observations.ReferenceDrift.SubsequentStatistics = append([]float64{}, cleanDrift().SubsequentStatistics...)
		testCase.mutate(&observations)
		violations, err := EnforceRunValidity(observations)
		if err != nil {
			t.Fatalf("%s: %v", testCase.name, err)
		}
		if len(violations) == 0 {
			t.Errorf("%s: expected a violation", testCase.name)
			continue
		}
		found := false
		for _, violation := range violations {
			if strings.Contains(violation, testCase.fragment) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no violation mentions %q: %v", testCase.name, testCase.fragment, violations)
		}
	}
}

func TestEnforceRunValidityIsFailClosedOnMalformedObservations(t *testing.T) {
	observations := cleanObservations()
	observations.BackgroundCPUPercentMaxObserved = math.NaN()
	if _, err := EnforceRunValidity(observations); err == nil {
		t.Error("expected error for NaN background CPU")
	}
	observations = cleanObservations()
	observations.ThermalThrottleEvents = -1
	if _, err := EnforceRunValidity(observations); err == nil {
		t.Error("expected error for negative thermal count")
	}
	observations = cleanObservations()
	observations.ReferenceDrift.SubsequentStatistics = observations.ReferenceDrift.SubsequentStatistics[:5]
	if _, err := EnforceRunValidity(observations); err == nil {
		t.Error("expected error for short drift schedule")
	}
}

func TestFrozenDriftConstants(t *testing.T) {
	if ReferenceDriftEnvelopePercent != 5 {
		t.Errorf("drift envelope %d, PRD requires 5", ReferenceDriftEnvelopePercent)
	}
	if ReferenceWorkloadID != "wl-02-small-text-echo" {
		t.Errorf("reference workload %s, frozen plan requires wl-02-small-text-echo", ReferenceWorkloadID)
	}
	if ReferenceRunsTotal != 8 || ReferenceSubsequentRuns != 7 {
		t.Errorf("reference schedule %d/%d, frozen plan requires 8 total / 7 subsequent", ReferenceRunsTotal, ReferenceSubsequentRuns)
	}
}
