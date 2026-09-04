package benchplan

import (
	"math"
	"testing"
)

// publishedT80 is the literature one-sided 80% quantile for 29 degrees
// of freedom (standard tables publish 0.854).
const publishedT80 = 0.854

func TestMinimumDetectableLogEffectMatchesTableComputation(t *testing.T) {
	// Expected value computed from published table constants only:
	// (t_{0.975,29} + t_{0.80,29}) * sd / sqrt(30).
	expected := (publishedT29 + publishedT80) * MaxLogRatioSD / math.Sqrt(30)
	got, err := MinimumDetectableLogEffect(PowerAlpha, PowerMinimum, MaxLogRatioSD, MeasuredPairs)
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(got-expected) > 2e-5 {
		t.Fatalf("minimum detectable effect %.6f, table computation %.6f", got, expected)
	}
	// Sanity: with the frozen model the minimum detectable log effect
	// is ~0.0529 — below both named alternatives.
	if got < 0.05 || got > 0.056 {
		t.Fatalf("minimum detectable effect %.6f outside the expected ~0.0529 window", got)
	}
}

func TestVerifyPowerModelHoldsAtFrozenSD(t *testing.T) {
	failures, err := VerifyPowerModel(MaxLogRatioSD)
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) != 0 {
		t.Fatalf("frozen power model must hold at sd=%.2f, got failures: %v", MaxLogRatioSD, failures)
	}
}

func TestVerifyPowerModelFailsWhenSDTooLarge(t *testing.T) {
	// At sd=0.20 the minimum detectable effect (~0.1059) exceeds
	// ln(1.1)=0.0953, so the non-regression alternative is no longer
	// detectable and the model must report a failure.
	failures, err := VerifyPowerModel(0.20)
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) == 0 {
		t.Fatal("expected the non-regression alternative to be undetectable at sd=0.20")
	}
}

func TestNamedAlternativesAreTheFrozenExpressions(t *testing.T) {
	if math.Abs(MemoryAlternativeLogRatio-math.Log(0.8)) > 1e-15 {
		t.Errorf("memory alternative %.15f, want ln(0.8)", MemoryAlternativeLogRatio)
	}
	if math.Abs(NonRegressionAlternativeLogRatio-math.Log(1.1)) > 1e-15 {
		t.Errorf("non-regression alternative %.15f, want ln(1.1)", NonRegressionAlternativeLogRatio)
	}
}

func TestFrozenPowerConstants(t *testing.T) {
	if PowerAlpha != 0.025 {
		t.Errorf("alpha %v, frozen plan requires 0.025", PowerAlpha)
	}
	if PowerMinimum != 0.8 {
		t.Errorf("power minimum %v, frozen plan requires 0.8", PowerMinimum)
	}
	if MaxLogRatioSD != 0.10 {
		t.Errorf("max log-ratio SD %v, frozen plan requires 0.10", MaxLogRatioSD)
	}
	if MeasuredPairs != 30 || WarmupPairs != 5 || DegreesOfFreedom != 29 {
		t.Errorf("sample structure %d/%d/%d, frozen plan requires 30 measured, 5 warmup, 29 df", MeasuredPairs, WarmupPairs, DegreesOfFreedom)
	}
}

func TestMinimumDetectableLogEffectRejectsInvalidInput(t *testing.T) {
	cases := []struct {
		alpha, power, sd float64
		n                int
	}{
		{0, 0.8, 0.1, 30},
		{0.6, 0.8, 0.1, 30},
		{0.025, 0.4, 0.1, 30},
		{0.025, 1.0, 0.1, 30},
		{0.025, 0.8, 0, 30},
		{0.025, 0.8, -0.1, 30},
		{0.025, 0.8, math.NaN(), 30},
		{0.025, 0.8, 0.1, 1},
	}
	for _, c := range cases {
		if _, err := MinimumDetectableLogEffect(c.alpha, c.power, c.sd, c.n); err == nil {
			t.Errorf("expected error for alpha=%g power=%g sd=%g n=%d", c.alpha, c.power, c.sd, c.n)
		}
	}
}
