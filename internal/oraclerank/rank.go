// Package oraclerank makes the US-020 AC2 adjudication order executable.
//
// AC2 (docs/prd-pack/07c-child-prd-us020-us027.md) reads:
//
//	RFC 6455 is rank one, in-scope Autobahn is rank two, independent neutral
//	expectations are rank three, Java observation is rank four, and Rust
//	observation is rank five; agreement between Java and Rust cannot override
//	a higher oracle.
//
// Before this package that sentence had no mechanism anywhere in the tree: a
// search for a rank, an oracle hierarchy or an adjudication order returned one
// hit, a prose string inside internal/deltaledger/definitions_gap_closure.go.
// There was no type, no field and no check, so nothing stopped a rank-four
// observation agreeing with a rank-five observation on something a higher
// oracle forbids and that agreement being read as parity.
//
// This file is the ordering. adjudicate.go is the override rule. binding.go
// records, per rank, whether the rank is bound to content or only declared,
// and probes empirically whether a rank is distinguishable from the rank below
// it at all. census.go builds propositions from committed evidence.
package oraclerank

import "fmt"

// Rank is a position in the AC2 adjudication order. LOWER NUMBER OUTRANKS.
// The numbering is AC2's own, kept literal so a reader can check it against
// the acceptance criterion without a translation table.
type Rank uint8

const (
	// RankRFC6455 is AC2 rank one: the normative protocol text.
	RankRFC6455 Rank = 1
	// RankAutobahnInScope is AC2 rank two: the in-scope Autobahn suite.
	RankAutobahnInScope Rank = 2
	// RankNeutralExpectation is AC2 rank three: independent neutral
	// expectations.
	RankNeutralExpectation Rank = 3
	// RankJavaObservation is AC2 rank four: observation of the pinned Java.
	RankJavaObservation Rank = 4
	// RankRustObservation is AC2 rank five: observation of the Rust port.
	RankRustObservation Rank = 5
)

// lowestRank and highestRank bound the closed set. A rank outside them is an
// error at every entry point; this package never silently normalizes one.
const (
	lowestRank  = RankRFC6455
	highestRank = RankRustObservation
)

// Ranks returns the closed rank set in adjudication order, strongest first.
func Ranks() []Rank {
	return []Rank{
		RankRFC6455,
		RankAutobahnInScope,
		RankNeutralExpectation,
		RankJavaObservation,
		RankRustObservation,
	}
}

// Valid reports whether r is one of the five AC2 ranks.
func (r Rank) Valid() bool { return r >= lowestRank && r <= highestRank }

// Outranks reports whether r governs over other. AC2's order is total and
// strict: a rank does not outrank itself.
func (r Rank) Outranks(other Rank) bool { return r < other }

// Subordinate reports whether r is governed by other. Spelled out separately
// because the override rule reads more honestly in that direction.
func (r Rank) Subordinate(other Rank) bool { return other < r }

// String names the rank the way AC2 names it.
func (r Rank) String() string {
	switch r {
	case RankRFC6455:
		return "rank1-rfc6455"
	case RankAutobahnInScope:
		return "rank2-autobahn-in-scope"
	case RankNeutralExpectation:
		return "rank3-neutral-expectation"
	case RankJavaObservation:
		return "rank4-java-observation"
	case RankRustObservation:
		return "rank5-rust-observation"
	default:
		return fmt.Sprintf("rank-invalid(%d)", uint8(r))
	}
}

// ObservationRanks is the pair AC2's final clause is about. Their agreement is
// the reading this package exists to refuse when a higher oracle dissents.
func ObservationRanks() (java, rust Rank) {
	return RankJavaObservation, RankRustObservation
}
