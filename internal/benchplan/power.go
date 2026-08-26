package benchplan

import (
	"fmt"
	"math"
)

// Frozen one-sample log-ratio power model (PRD US-008, acceptance
// criterion 4). These constants ARE the preregistration; the plan
// document and its schema pin the same values, and verification fails
// on any disagreement.
const (
	// PowerAlpha is the one-sided significance level (matches the
	// 0.025-per-tail structure of the two-sided 95% interval).
	PowerAlpha = 0.025
	// PowerMinimum is the minimum acceptable power against every named
	// alternative.
	PowerMinimum = 0.8
	// MaxLogRatioSD is the preregistered maximum log-ratio sample
	// standard deviation. An observed sample SD above this bound means
	// the run is underpowered relative to the frozen model and the
	// endpoint is INCONCLUSIVE.
	MaxLogRatioSD = 0.10
)

// Named alternative effect sizes (natural-log ratios), preregistered by
// the driver (PREREGISTERED_BY_DRIVER; the PRD names the alternative
// classes — memory and non-regression — but not the sizes).
var (
	// MemoryAlternativeLogRatio is ln(0.8): the memory alternative that
	// Rust peak/steady RSS is at most 80% of Java's, matching the 0.8
	// CI threshold on the RSS endpoints.
	MemoryAlternativeLogRatio = math.Log(0.8)
	// NonRegressionAlternativeLogRatio is ln(1.1): a 10% regression on
	// any non-memory endpoint must be detectable so a true regression
	// cannot hide inside an underpowered interval.
	NonRegressionAlternativeLogRatio = math.Log(1.1)
)

// MinimumDetectableLogEffect returns the smallest absolute true mean
// log-ratio detectable with the frozen model:
//
//	(t_{1-alpha, n-1} + t_{power, n-1}) * sd / sqrt(n)
//
// using the standard noncentral-t power approximation for a one-sample
// t test.
func MinimumDetectableLogEffect(alpha, power, sd float64, n int) (float64, error) {
	if n < 2 {
		return 0, fmt.Errorf("power model: n must be >= 2 (got %d)", n)
	}
	if sd <= 0 || math.IsNaN(sd) || math.IsInf(sd, 0) {
		return 0, fmt.Errorf("power model: sd must be finite and positive (got %g)", sd)
	}
	if alpha <= 0 || alpha >= 0.5 {
		return 0, fmt.Errorf("power model: alpha=%g outside (0, 0.5)", alpha)
	}
	if power <= 0.5 || power >= 1 {
		return 0, fmt.Errorf("power model: power=%g outside (0.5, 1)", power)
	}
	df := n - 1
	tAlpha, err := StudentTQuantile(1-alpha, df)
	if err != nil {
		return 0, err
	}
	tPower, err := StudentTQuantile(power, df)
	if err != nil {
		return 0, err
	}
	return (tAlpha + tPower) * sd / math.Sqrt(float64(n)), nil
}

// VerifyPowerModel checks that both named alternatives are detectable
// under the frozen model at the given log-ratio SD: their absolute
// effect sizes must be at least the minimum detectable effect at
// alpha=PowerAlpha, power=PowerMinimum, n=MeasuredPairs. It returns the
// failures (empty means the model holds).
func VerifyPowerModel(sd float64) ([]string, error) {
	minimumEffect, err := MinimumDetectableLogEffect(PowerAlpha, PowerMinimum, sd, MeasuredPairs)
	if err != nil {
		return nil, err
	}
	var failures []string
	named := []struct {
		name   string
		effect float64
	}{
		{"memory alternative ln(0.8)", MemoryAlternativeLogRatio},
		{"non-regression alternative ln(1.1)", NonRegressionAlternativeLogRatio},
	}
	for _, alternative := range named {
		if math.Abs(alternative.effect) < minimumEffect {
			failures = append(failures, fmt.Sprintf(
				"%s (|effect|=%.6f) is below the minimum detectable effect %.6f at sd=%.4f, alpha=%.4f, power=%.2f, n=%d",
				alternative.name, math.Abs(alternative.effect), minimumEffect, sd, PowerAlpha, PowerMinimum, MeasuredPairs))
		}
	}
	return failures, nil
}
