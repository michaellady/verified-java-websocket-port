package benchplan

import (
	"fmt"
	"math"
)

// Frozen statistics plan constants (PRD US-008, acceptance criterion 4).
const (
	// DegreesOfFreedom for the two-sided 95% Student-t interval.
	DegreesOfFreedom = MeasuredPairs - 1 // 29
	// ConfidenceLevel of the two-sided interval.
	ConfidenceLevel = 0.95
	// TCriticalProbability is the upper-tail quantile probability for the
	// two-sided 95% interval: 1 - (1-0.95)/2.
	TCriticalProbability = 0.975
)

// Pair is one raw benchmark pair: the Java sample value and the Rust
// sample value for the same metric under the same workload.
type Pair struct {
	Java float64 `json:"java"`
	Rust float64 `json:"rust"`
}

// PairedAnalysis is the preregistered per-endpoint analysis output: all
// 30 paired natural-log Rust/Java ratios, their arithmetic mean and
// sample standard deviation, the two-sided 95% Student-t interval with
// 29 degrees of freedom, and the exponentiated bounds.
type PairedAnalysis struct {
	LogRatios  []float64
	Mean       float64
	SampleSD   float64
	TCritical  float64
	CILowerLog float64
	CIUpperLog float64
	CILowerExp float64
	CIUpperExp float64
}

// AnalyzePairs runs the frozen paired natural-log ratio analysis. It is
// fail-closed: anything other than exactly 30 finite, strictly positive
// pairs is an error, never a silently adjusted computation.
func AnalyzePairs(pairs []Pair) (PairedAnalysis, error) {
	var analysis PairedAnalysis
	if len(pairs) != MeasuredPairs {
		return analysis, fmt.Errorf("paired analysis requires exactly %d measured pairs, got %d", MeasuredPairs, len(pairs))
	}
	logRatios := make([]float64, MeasuredPairs)
	for i, pair := range pairs {
		if !isFinitePositive(pair.Java) || !isFinitePositive(pair.Rust) {
			return analysis, fmt.Errorf("pair %d is not finite and strictly positive (java=%g rust=%g)", i, pair.Java, pair.Rust)
		}
		ratio := math.Log(pair.Rust / pair.Java)
		if math.IsNaN(ratio) || math.IsInf(ratio, 0) {
			return analysis, fmt.Errorf("pair %d produced a nonfinite log ratio", i)
		}
		logRatios[i] = ratio
	}
	sum := 0.0
	for _, r := range logRatios {
		sum += r
	}
	mean := sum / float64(MeasuredPairs)
	sumSquares := 0.0
	for _, r := range logRatios {
		d := r - mean
		sumSquares += d * d
	}
	sampleSD := math.Sqrt(sumSquares / float64(DegreesOfFreedom))
	tCritical, err := StudentTQuantile(TCriticalProbability, DegreesOfFreedom)
	if err != nil {
		return analysis, err
	}
	halfWidth := tCritical * sampleSD / math.Sqrt(float64(MeasuredPairs))
	analysis = PairedAnalysis{
		LogRatios:  logRatios,
		Mean:       mean,
		SampleSD:   sampleSD,
		TCritical:  tCritical,
		CILowerLog: mean - halfWidth,
		CIUpperLog: mean + halfWidth,
		CILowerExp: math.Exp(mean - halfWidth),
		CIUpperExp: math.Exp(mean + halfWidth),
	}
	return analysis, nil
}

func isFinitePositive(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v > 0
}
