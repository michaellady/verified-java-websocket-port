package benchplan

import (
	"fmt"
	"math"
)

// Student-t distribution support for the frozen statistics plan.
//
// The CDF is computed through the regularized incomplete beta function
// (continued-fraction evaluation, Lentz's method) and the quantile by
// bisection on the CDF. The test suite verifies both against published
// t-table values (including t_{0.975,29} = 2.0452, the frozen 95%
// two-sided critical value with 29 degrees of freedom) and against an
// independent Simpson-rule integration of the t density, so the engine
// is anchored to literature, not to itself.

// logGamma returns the natural log of the Gamma function (Lanczos).
func logGamma(x float64) float64 {
	lg, _ := math.Lgamma(x)
	return lg
}

// regularizedIncompleteBeta computes I_x(a, b) for 0 <= x <= 1, a, b > 0.
func regularizedIncompleteBeta(a, b, x float64) (float64, error) {
	if a <= 0 || b <= 0 {
		return 0, fmt.Errorf("regularized incomplete beta: nonpositive shape (a=%g b=%g)", a, b)
	}
	if x < 0 || x > 1 {
		return 0, fmt.Errorf("regularized incomplete beta: x=%g outside [0,1]", x)
	}
	if x == 0 {
		return 0, nil
	}
	if x == 1 {
		return 1, nil
	}
	logPrefix := logGamma(a+b) - logGamma(a) - logGamma(b) + a*math.Log(x) + b*math.Log(1-x)
	prefix := math.Exp(logPrefix)
	if x < (a+1)/(a+b+2) {
		cf, err := betaContinuedFraction(a, b, x)
		if err != nil {
			return 0, err
		}
		return prefix * cf / a, nil
	}
	cf, err := betaContinuedFraction(b, a, 1-x)
	if err != nil {
		return 0, err
	}
	return 1 - prefix*cf/b, nil
}

// betaContinuedFraction evaluates the continued fraction for the
// incomplete beta function by the modified Lentz method.
func betaContinuedFraction(a, b, x float64) (float64, error) {
	const (
		maxIterations = 500
		epsilon       = 3e-16
		tiny          = 1e-300
	)
	qab := a + b
	qap := a + 1
	qam := a - 1
	c := 1.0
	d := 1 - qab*x/qap
	if math.Abs(d) < tiny {
		d = tiny
	}
	d = 1 / d
	h := d
	for m := 1; m <= maxIterations; m++ {
		fm := float64(m)
		aa := fm * (b - fm) * x / ((qam + 2*fm) * (a + 2*fm))
		d = 1 + aa*d
		if math.Abs(d) < tiny {
			d = tiny
		}
		c = 1 + aa/c
		if math.Abs(c) < tiny {
			c = tiny
		}
		d = 1 / d
		h *= d * c
		aa = -(a + fm) * (qab + fm) * x / ((a + 2*fm) * (qap + 2*fm))
		d = 1 + aa*d
		if math.Abs(d) < tiny {
			d = tiny
		}
		c = 1 + aa/c
		if math.Abs(c) < tiny {
			c = tiny
		}
		d = 1 / d
		delta := d * c
		h *= delta
		if math.Abs(delta-1) < epsilon {
			return h, nil
		}
	}
	return 0, fmt.Errorf("beta continued fraction did not converge (a=%g b=%g x=%g)", a, b, x)
}

// StudentTCDF returns P(T <= t) for a Student-t variable with df degrees
// of freedom.
func StudentTCDF(t float64, df int) (float64, error) {
	if df < 1 {
		return 0, fmt.Errorf("student t cdf: degrees of freedom must be >= 1 (got %d)", df)
	}
	if math.IsNaN(t) || math.IsInf(t, 0) {
		return 0, fmt.Errorf("student t cdf: nonfinite t=%g", t)
	}
	nu := float64(df)
	x := nu / (nu + t*t)
	ib, err := regularizedIncompleteBeta(nu/2, 0.5, x)
	if err != nil {
		return 0, err
	}
	if t >= 0 {
		return 1 - ib/2, nil
	}
	return ib / 2, nil
}

// StudentTQuantile returns the p-quantile of the Student-t distribution
// with df degrees of freedom, found by bisection on the CDF.
func StudentTQuantile(p float64, df int) (float64, error) {
	if df < 1 {
		return 0, fmt.Errorf("student t quantile: degrees of freedom must be >= 1 (got %d)", df)
	}
	if p <= 0 || p >= 1 {
		return 0, fmt.Errorf("student t quantile: p=%g outside (0,1)", p)
	}
	if p == 0.5 {
		return 0, nil
	}
	// The quantile is symmetric: solve for p > 0.5 and negate if needed.
	target := p
	negate := false
	if p < 0.5 {
		target = 1 - p
		negate = true
	}
	lo, hi := 0.0, 2.0
	for {
		cdf, err := StudentTCDF(hi, df)
		if err != nil {
			return 0, err
		}
		if cdf >= target {
			break
		}
		hi *= 2
		if hi > 1e9 {
			return 0, fmt.Errorf("student t quantile: bracket expansion failed (p=%g df=%d)", p, df)
		}
	}
	for i := 0; i < 200; i++ {
		mid := (lo + hi) / 2
		cdf, err := StudentTCDF(mid, df)
		if err != nil {
			return 0, err
		}
		if cdf < target {
			lo = mid
		} else {
			hi = mid
		}
		if hi-lo < 1e-13 {
			break
		}
	}
	q := (lo + hi) / 2
	if negate {
		q = -q
	}
	return q, nil
}
