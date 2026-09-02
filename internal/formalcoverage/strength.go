package formalcoverage

import "fmt"

// The evidence-strength lattice, weakest first. It is a TOTAL order over a
// CLOSED vocabulary, and a value outside it is an error rather than a pass.
// That is deliberate: the cheapest way to make a coverage number move is to
// invent a strength label nobody ranked, and an unranked label that compared
// as "not less than required" would silently discharge every obligation.
var strengthRank = map[string]int{
	"NONE":                 0,
	"DECLARATION_SCAN":     1,
	"EXECUTED_OBSERVATION": 2,
	"EXECUTED_OBSERVATION_WITH_MUTATION_SENSITIVITY": 3,
	"BOUNDED_MODEL":         4,
	"PROVED_MODEL":          5,
	"PRODUCTION_REFINEMENT": 6,
}

// StrengthRank returns the rank of one label, or an error for an unranked one.
func StrengthRank(label string) (int, error) {
	rank, ok := strengthRank[label]
	if !ok {
		return 0, fmt.Errorf("formalcoverage: %q is not in the closed evidence-strength vocabulary; "+
			"an unranked strength cannot be compared against a required one and must not be assumed to satisfy it", label)
	}
	return rank, nil
}

// MeetsRequired reports whether observed is at least as strong as required.
// Both labels must be in the vocabulary; neither is defaulted.
func MeetsRequired(observed, required string) (bool, error) {
	observedRank, err := StrengthRank(observed)
	if err != nil {
		return false, err
	}
	requiredRank, err := StrengthRank(required)
	if err != nil {
		return false, err
	}
	return observedRank >= requiredRank, nil
}
