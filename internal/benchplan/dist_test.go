package benchplan

import (
	"math"
	"testing"
)

// Published Student-t upper-quantile table values (standard statistical
// tables, e.g. NIST/SEMATECH e-Handbook). These anchor the engine to
// literature, independently of its own implementation.
var publishedTQuantiles = []struct {
	p         float64
	df        int
	value     float64
	tolerance float64
}{
	// The frozen critical value of the preregistration: two-sided 95%
	// with 29 degrees of freedom.
	{0.975, 29, 2.045230, 2e-6},
	{0.995, 29, 2.7564, 1e-4},
	{0.95, 29, 1.6991, 1e-4},
	{0.90, 29, 1.3114, 1e-4},
	// One-sided 80% quantile used by the power model (tables publish
	// 0.854 at 3 decimal places for df=29).
	{0.80, 29, 0.854, 5e-4},
	// Classic table rows as cross-anchors.
	{0.975, 1, 12.706205, 1e-5},
	{0.975, 2, 4.302653, 1e-5},
	{0.975, 5, 2.570582, 1e-5},
	{0.975, 10, 2.228139, 1e-5},
	{0.975, 30, 2.042272, 1e-5},
}

func TestStudentTQuantileMatchesPublishedTables(t *testing.T) {
	for _, anchor := range publishedTQuantiles {
		got, err := StudentTQuantile(anchor.p, anchor.df)
		if err != nil {
			t.Fatal(err)
		}
		if math.Abs(got-anchor.value) > anchor.tolerance {
			t.Errorf("t quantile p=%g df=%d: got %.8f, published %.6f (tolerance %g)", anchor.p, anchor.df, got, anchor.value, anchor.tolerance)
		}
	}
}

func TestStudentTCDFAtPublishedCriticalValues(t *testing.T) {
	// The CDF evaluated at a published quantile must return its
	// probability.
	for _, anchor := range publishedTQuantiles {
		cdf, err := StudentTCDF(anchor.value, anchor.df)
		if err != nil {
			t.Fatal(err)
		}
		if math.Abs(cdf-anchor.p) > 1e-4 {
			t.Errorf("t cdf at %.6f df=%d: got %.8f, want %.4f", anchor.value, anchor.df, cdf, anchor.p)
		}
	}
}

// TestStudentTCDFAgainstSimpsonIntegration cross-checks the
// incomplete-beta CDF against a numerically integrated t density — a
// structurally independent algorithm.
func TestStudentTCDFAgainstSimpsonIntegration(t *testing.T) {
	for _, df := range []int{1, 5, 29} {
		for _, tv := range []float64{0.3, 0.854, 1.5, 2.045230, 3.0} {
			got, err := StudentTCDF(tv, df)
			if err != nil {
				t.Fatal(err)
			}
			want := 0.5 + simpsonTDensity(0, tv, df, 20000)
			if math.Abs(got-want) > 1e-9 {
				t.Errorf("cdf(t=%g, df=%d): incomplete beta %.12f vs Simpson %.12f", tv, df, got, want)
			}
		}
	}
}

func TestStudentTSymmetryAndRoundTrip(t *testing.T) {
	for _, p := range []float64{0.025, 0.2, 0.5, 0.8, 0.975} {
		q, err := StudentTQuantile(p, 29)
		if err != nil {
			t.Fatal(err)
		}
		mirror, err := StudentTQuantile(1-p, 29)
		if err != nil {
			t.Fatal(err)
		}
		if math.Abs(q+mirror) > 1e-10 {
			t.Errorf("quantile symmetry broken at p=%g: %g vs %g", p, q, mirror)
		}
		back, err := StudentTCDF(q, 29)
		if err != nil {
			t.Fatal(err)
		}
		if math.Abs(back-p) > 1e-10 {
			t.Errorf("round trip p=%g: cdf(quantile)=%g", p, back)
		}
	}
}

func TestStudentTRejectsInvalidInput(t *testing.T) {
	if _, err := StudentTQuantile(0, 29); err == nil {
		t.Error("expected error for p=0")
	}
	if _, err := StudentTQuantile(1, 29); err == nil {
		t.Error("expected error for p=1")
	}
	if _, err := StudentTQuantile(0.975, 0); err == nil {
		t.Error("expected error for df=0")
	}
	if _, err := StudentTCDF(math.NaN(), 29); err == nil {
		t.Error("expected error for NaN t")
	}
	if _, err := StudentTCDF(math.Inf(1), 29); err == nil {
		t.Error("expected error for infinite t")
	}
}

// simpsonTDensity integrates the Student-t density on [lo, hi] with
// Simpson's rule using n intervals (n even).
func simpsonTDensity(lo, hi float64, df, n int) float64 {
	nu := float64(df)
	logNorm := logGamma((nu+1)/2) - logGamma(nu/2) - 0.5*math.Log(nu*math.Pi)
	density := func(x float64) float64 {
		return math.Exp(logNorm - (nu+1)/2*math.Log(1+x*x/nu))
	}
	h := (hi - lo) / float64(n)
	sum := density(lo) + density(hi)
	for i := 1; i < n; i++ {
		x := lo + float64(i)*h
		if i%2 == 1 {
			sum += 4 * density(x)
		} else {
			sum += 2 * density(x)
		}
	}
	return sum * h / 3
}
