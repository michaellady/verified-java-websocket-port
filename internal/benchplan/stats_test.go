package benchplan

import (
	"math"
	"testing"
)

// publishedT29 is the literature value of t_{0.975,29}, used so the
// closed-form expectations below do not depend on the engine's own
// quantile computation.
const publishedT29 = 2.045230

// closedFormPairs builds 30 SYNTHETIC pairs whose log ratios are
// exactly mean + sd*z_i where the z_i are +/- sqrt(29/30) (15 each), so
// the sample mean is exactly `mean` and the sample SD exactly `sd` by
// construction (closed form, not a measurement).
func closedFormPairs(mean, sd float64) []Pair {
	a := math.Sqrt(29.0 / 30.0)
	pairs := make([]Pair, MeasuredPairs)
	for i := 0; i < MeasuredPairs; i++ {
		z := a
		if i%2 == 1 {
			z = -a
		}
		java := 100.0 + float64(i)
		pairs[i] = Pair{Java: java, Rust: java * math.Exp(mean+sd*z)}
	}
	return pairs
}

func TestAnalyzePairsMatchesClosedForm(t *testing.T) {
	const mean, sd = 0.05, 0.08
	analysis, err := AnalyzePairs(closedFormPairs(mean, sd))
	if err != nil {
		t.Fatal(err)
	}
	if len(analysis.LogRatios) != MeasuredPairs {
		t.Fatalf("expected %d log ratios, got %d", MeasuredPairs, len(analysis.LogRatios))
	}
	if math.Abs(analysis.Mean-mean) > 1e-12 {
		t.Errorf("mean %.15f, closed form %.15f", analysis.Mean, mean)
	}
	if math.Abs(analysis.SampleSD-sd) > 1e-12 {
		t.Errorf("sample SD %.15f, closed form %.15f", analysis.SampleSD, sd)
	}
	// CI computed with the published table t value, independent of the
	// engine's quantile function.
	halfWidth := publishedT29 * sd / math.Sqrt(30)
	if math.Abs(analysis.CILowerLog-(mean-halfWidth)) > 1e-6 {
		t.Errorf("CI lower log %.9f, closed form %.9f", analysis.CILowerLog, mean-halfWidth)
	}
	if math.Abs(analysis.CIUpperLog-(mean+halfWidth)) > 1e-6 {
		t.Errorf("CI upper log %.9f, closed form %.9f", analysis.CIUpperLog, mean+halfWidth)
	}
	if math.Abs(analysis.CILowerExp-math.Exp(mean-halfWidth)) > 1e-6 {
		t.Errorf("CI lower exp %.9f, closed form %.9f", analysis.CILowerExp, math.Exp(mean-halfWidth))
	}
	if math.Abs(analysis.CIUpperExp-math.Exp(mean+halfWidth)) > 1e-6 {
		t.Errorf("CI upper exp %.9f, closed form %.9f", analysis.CIUpperExp, math.Exp(mean+halfWidth))
	}
	if math.Abs(analysis.TCritical-publishedT29) > 2e-6 {
		t.Errorf("t critical %.8f, published %.6f", analysis.TCritical, publishedT29)
	}
}

func TestAnalyzePairsIsFailClosedOnCount(t *testing.T) {
	pairs := closedFormPairs(0.05, 0.08)
	if _, err := AnalyzePairs(pairs[:29]); err == nil {
		t.Error("expected error for 29 pairs (missing pair)")
	}
	if _, err := AnalyzePairs(append(pairs, Pair{Java: 1, Rust: 1})); err == nil {
		t.Error("expected error for 31 pairs (extra pair)")
	}
	if _, err := AnalyzePairs(nil); err == nil {
		t.Error("expected error for zero pairs")
	}
}

func TestAnalyzePairsIsFailClosedOnValues(t *testing.T) {
	for _, bad := range []Pair{
		{Java: 0, Rust: 1},
		{Java: 1, Rust: 0},
		{Java: -5, Rust: 1},
		{Java: 1, Rust: -5},
		{Java: math.NaN(), Rust: 1},
		{Java: 1, Rust: math.NaN()},
		{Java: math.Inf(1), Rust: 1},
		{Java: 1, Rust: math.Inf(1)},
	} {
		pairs := closedFormPairs(0.05, 0.08)
		pairs[13] = bad
		if _, err := AnalyzePairs(pairs); err == nil {
			t.Errorf("expected error for pair %+v", bad)
		}
	}
}
