package normcollide

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// LandingRecordPath is the prose record that states this audit's bounds in
// English, for a human reader, at drafts/self-review/.
//
// It exists in a different regime from DocumentPath and that asymmetry is a
// defect this check closes. `normcollidectl write` REGENERATES the committed
// document from a fresh harness run, and `Verify` plus
// TestCommittedAuditMatchesAFreshRun refuse a stale one. Nothing regenerates
// the prose, and until this file nothing read it. So the document could move
// while the record that states its meaning stood still — and it did:
//
//	a973211  handshake bounds  26 distinct / 27 sharing / largest 11
//	d90308a  handshake bounds  29 distinct / 23 sharing / largest 10
//
// `d90308a` added `reject_stage` and a client-side `sec_websocket_accept` to the
// projection, which split classes apart, and `verify` agreed with the new
// document, so every gate stayed green. The landing record — last touched by
// `70f104f`, which is an ANCESTOR of `d90308a` — went on stating 26/27/11 as a
// present-tense measurement. Nothing in the tree could say so, because the
// prose was pinned to nothing.
//
// The record's own §1 claims the surface table "cannot go stale silently"
// because PartitionCensus refuses an unclassified shape. For the handshake row
// that claim is false and this is why: ClassifyHandshakeKeys returns
// handshake.judged for ANY key set containing java_observable, so adding a key
// to the reject shape cannot make the partition check fire. The shape stayed
// classified; the key COUNT column rotted.
const LandingRecordPath = "drafts/self-review/normalization-collision-audit.md"

// A BoundClaim ties one sentence the landing record states to the field of the
// committed document it must agree with.
//
// The pattern is matched against the record FLATTENED to one line, so a
// sentence the author wrapped across a line break still matches. Match on the
// flattened text, report the line the match began on.
type BoundClaim struct {
	// Field names the document field, as it appears in audit.json, so a
	// failure message points at the thing to re-read rather than at prose.
	Field string
	// Pattern must capture exactly one decimal group: the number claimed.
	Pattern *regexp.Regexp
	// Want reads the measured value out of the committed document.
	Want func(*Document) int
}

// A BoundMismatch is one disagreement between the record and the document.
// Found is boundClaimAbsent when the claim sentence could not be located at
// all, which is a FAILURE and not a pass: see RecordBoundClaims.
type BoundMismatch struct {
	Field string
	Found int
	Want  int
	Line  int
	Text  string
}

// boundClaimAbsent marks a claim whose sentence was not found in the record.
const boundClaimAbsent = -1

func (m BoundMismatch) String() string {
	if m.Found == boundClaimAbsent {
		return fmt.Sprintf("%s: the record no longer states this bound where this check "+
			"reads it (want %d). A record that stopped stating its bound is not a record "+
			"that agrees with it", m.Field, m.Want)
	}
	return fmt.Sprintf("%s: record line %d says %d, the committed document measures %d\n      %s",
		m.Field, m.Line, m.Found, m.Want, m.Text)
}

// RecordBoundClaims is the set of bounds the landing record must state.
//
// FAIL-CLOSED on absence, deliberately. If a missing sentence were a pass, the
// check would be defeated by deleting the sentence — which is the cheapest
// possible way to make a stale number stop being stale, and the exact move this
// project keeps filing as a defect. So a claim this list names and the record
// does not carry is a mismatch with Found == boundClaimAbsent.
//
// Every bound here is a CEILING and the record must never state its denominator
// without it: 74 public rows carry 73 distinct scored observations, and 49
// handshake cases carry 29 (23 sharing, largest class 10).
//
// The structural counts at the end are pinned for the same reason as the
// numbers. `d90308a` and `da6e119` decided three of the first pass's five open
// candidates, so a record still headed "Undecided candidates (5)" is not merely
// out of date: it presents as open three questions the tree has answered, which
// overstates what is unknown exactly as a stale bound understates what is
// known.
func RecordBoundClaims() []BoundClaim {
	return []BoundClaim{
		{
			Field:   "public_rows_whose_projection_erases_every_observation_stream",
			Pattern: regexp.MustCompile(`(\d+) of the 74 rows are error rows`),
			Want:    func(d *Document) int { return d.Bounds.PublicBlindRows },
		},
		{
			Field:   "public_distinct_scored_observations",
			Pattern: regexp.MustCompile(`The 74 rows carry only (\d+) distinct scored observations`),
			Want:    func(d *Document) int { return d.Bounds.PublicDistinct },
		},
		{
			Field:   "public_distinct_scored_observations (ceiling sentence)",
			Pattern: regexp.MustCompile(`ceiling is (\d+) distinguishable answers`),
			Want:    func(d *Document) int { return d.Bounds.PublicDistinct },
		},
		{
			Field:   "handshake_distinct_scored_observations",
			Pattern: regexp.MustCompile(`49 handshake cases produce only (\d+) distinct scored observations`),
			Want:    func(d *Document) int { return d.Bounds.HandshakeDistinct },
		},
		{
			Field:   "handshake_cases_sharing_an_observation",
			Pattern: regexp.MustCompile(`(\d+) of the 49 cases share their observation`),
			Want:    func(d *Document) int { return d.Bounds.HandshakeShared },
		},
		{
			Field:   "handshake_largest_equivalence_class",
			Pattern: regexp.MustCompile(`largest equivalence class holds (\d+) cases`),
			Want:    func(d *Document) int { return d.Bounds.HandshakeLargest },
		},
		{
			Field:   "handshake_distinct_scored_observations (ceiling sentence)",
			Pattern: regexp.MustCompile(`certifies at most (\d+) distinguishable answers`),
			Want:    func(d *Document) int { return d.Bounds.HandshakeDistinct },
		},
		{
			Field:   "probes[] (confirmed collisions)",
			Pattern: regexp.MustCompile(`Confirmed collisions \((\d+)\)`),
			Want:    func(d *Document) int { return len(d.Probes) },
		},
		{
			Field:   "refutations[]",
			Pattern: regexp.MustCompile(`carries (\d+) refutation probes`),
			Want:    func(d *Document) int { return len(d.Refutations) },
		},
		{
			Field:   "decided_candidates[]",
			Pattern: regexp.MustCompile(`Decided candidates \((\d+)\)`),
			Want:    func(d *Document) int { return len(d.DecidedCandidates) },
		},
		{
			Field:   "undecided_candidates[]",
			Pattern: regexp.MustCompile(`Undecided candidates \((\d+)\)`),
			Want:    func(d *Document) int { return len(d.Candidates) },
		},
	}
}

// flattenRecord renders the record as one line for matching, and returns a map
// from each byte offset in that line back to the 1-based source line number.
//
// Markdown emphasis and code spans are stripped, because a bound stated as
// `**26 distinct**` and one stated as `26 distinct` are the same claim and a
// check that could be defeated by adding two asterisks would be measuring
// typography.
func flattenRecord(raw string) (string, []int) {
	var flat strings.Builder
	var lineOf []int
	line := 1
	lastWasSpace := true
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch c {
		case '\n':
			line++
			c = ' '
		case '*', '`', '_':
			continue
		}
		if c == ' ' || c == '\t' {
			if lastWasSpace {
				continue
			}
			lastWasSpace = true
			flat.WriteByte(' ')
			lineOf = append(lineOf, line)
			continue
		}
		lastWasSpace = false
		flat.WriteByte(c)
		lineOf = append(lineOf, line)
	}
	return flat.String(), lineOf
}

// CheckRecordBounds reads the prose landing record and the committed document
// and returns every disagreement between them. An empty slice means the record
// states each bound in RecordBoundClaims and states it as measured.
//
// The document is the authority and the record is checked against it, never the
// other way round: the document is recomputed from a real harness run and
// refused when stale, so if the two disagree it is the prose that is wrong.
func CheckRecordBounds(root string) ([]BoundMismatch, error) {
	rawDocument, err := os.ReadFile(filepath.Join(root, DocumentPath))
	if err != nil {
		return nil, err
	}
	var document Document
	if err := json.Unmarshal(rawDocument, &document); err != nil {
		return nil, fmt.Errorf("%s: %w", DocumentPath, err)
	}
	rawRecord, err := os.ReadFile(filepath.Join(root, LandingRecordPath))
	if err != nil {
		return nil, err
	}
	flat, lineOf := flattenRecord(string(rawRecord))

	var mismatches []BoundMismatch
	for _, claim := range RecordBoundClaims() {
		want := claim.Want(&document)
		location := claim.Pattern.FindStringSubmatchIndex(flat)
		if location == nil {
			mismatches = append(mismatches, BoundMismatch{
				Field: claim.Field, Found: boundClaimAbsent, Want: want})
			continue
		}
		found, err := strconv.Atoi(flat[location[2]:location[3]])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", claim.Field, err)
		}
		if found == want {
			continue
		}
		mismatches = append(mismatches, BoundMismatch{
			Field: claim.Field, Found: found, Want: want,
			Line: lineOf[location[0]],
			Text: strings.TrimSpace(flat[location[0]:location[1]]),
		})
	}
	return mismatches, nil
}
