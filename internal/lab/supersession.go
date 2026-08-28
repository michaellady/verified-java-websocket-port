package lab

// SUPERSESSION IN THE RECORD VOCABULARY, WHERE THE READINESS GATE CAN SEE IT.
//
// THE DEFECT (round-2 finding 6). internal/deltaledger made supersession
// machine-visible — a structured Supersedes list, a canonical SUPERSEDES token
// inside each correcting record's hashed rationale, a committed sidecar, and
// AuthoritativeSequences. But the ONE consumer that decides release readiness,
// VerifyBaselineEvidence in this package, had no supersession input at all and
// validated every record identically. A withdrawn record therefore remained
// authoritative to the only consumer whose opinion is load-bearing, which is
// precisely the failure the supersede mechanism was built to prevent. A
// supersede mechanism invisible to the gate that matters is not a mechanism.
//
// THE OWNER RULING, protected/governance-mirroring-and-record-schema-owner-decision-2026-08-28.json
// (sha256 e6837006a722b71f6b7137b82be31f4a9e8d802f0ef4c0614dbd4016f27c361f,
// decided 2026-08-28T20:05:00Z): BUMP THE RECORD SCHEMA TO 1.1.0 AND TEACH THE
// READINESS GATE ABOUT SUPERSESSION, with the binding constraint that the bump
// must not disturb the frozen prefix.
//
// WHERE THE BUMP LANDS, AND WHY IT LANDS THERE. A record's digest preimage is
// {schema_version, sequence, previous_digest, delta}. Bumping the PER-RECORD
// schema_version would change every record digest and rewrite the hash chain
// from sequence 1, breaking the frozen prefix the same ruling protects. So
// 1.1.0 is the LEDGER DOCUMENT schema: the document gains a first-class
// `supersessions` array, every record stays at record schema_version 1.0.0, and
// sequence 35 keeps digesting to 3fcd461c… under VerifyFrozenPrefix.
//
// The links are PARSED FROM THE HASHED RATIONALES here rather than trusted from
// the document, so the declared array is checked against the evidence instead of
// being believed.

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// SUPERSESSION IS PARSED, NOT SEARCHED FOR (round-3 finding 4).
//
// THE DEFECT. The parser used to be a bare `FindAllStringSubmatch` over the
// whole rationale, so the canonical token was recognised ANYWHERE in the text.
// A record could quote one — in a disclaimer, in a "an earlier draft wrongly
// asserted '...'" note, inside quotation marks — and the quotation became a
// real withdrawal. Regeneration then wrote the matching declaration into the
// ledger document and the sidecar, so the rationale and the declaration agreed
// with each other while the structured `Definition.Supersedes` list, which is
// the actual claim, said nothing at all. Reproduced before this fix: a
// disclaimed, explicitly-quoted token planted in the class record's rationale
// withdrew sequence 44 (the reserved-bit ready-state record), the sidecar grew
// from three links to four, and `deltaledgerctl --check` exited 0.
//
// THE PARSE. internal/deltaledger emits the tokens as an ANCHORED PREFIX RUN:
// zero or more canonical tokens at offset 0, each terminated by `;`, separated
// and followed by exactly one space. So that is what is parsed — a prefix run,
// consumed token by token from position 0 — rather than searched for. Three
// things follow, and all three are the point:
//
//   - POSITION. A token that is not in the prefix run is not a claim. Prose,
//     quotations and disclaimers all live after the run by construction.
//   - FORM. Each token must match the canonical grammar in full, including the
//     `reason=...;` terminator, not merely contain a recognisable substring.
//   - NO STRAY MARKERS. After the run, the remainder must not contain the
//     marker at all. A record that wants to TALK about supersession has to do
//     so without writing the canonical marker, which is a small price for the
//     marker meaning exactly one thing. This is what turns a quoted token from
//     a silent withdrawal into a loud refusal.
//
// And separately, in internal/deltaledger, VerifySupersessionsMatchDefinitions
// requires the links parsed back out of the chain to equal the links the
// structured `Definition.Supersedes` lists claim, so generation is bound to the
// structured claim rather than to whatever the prose happened to say.

// SupersedesMarker is the literal that may appear ONLY as the opening of a
// canonical token in the anchored prefix run.
const SupersedesMarker = "SUPERSEDES ledger-sequence="

// SupersedesPattern is the canonical token, ANCHORED at the start of the string
// it is applied to. It is exported because internal/deltaledger emits the form
// it parses, and one pattern shared beats two that can drift.
var SupersedesPattern = regexp.MustCompile(
	`^SUPERSEDES ledger-sequence=([0-9]+) delta=(delta-[0-9a-f]{64}) ` +
		`subject=(semantic:[a-z0-9][a-z0-9._-]*:provisional-v[0-9]+) reason=([^;]+);`)

// parseSupersedesPrefix consumes the anchored prefix run of canonical tokens
// and returns them together with the remaining rationale. A canonical marker
// found anywhere in the remainder is an error: the marker is reserved.
func parseSupersedesPrefix(sequence uint64, rationale string) ([][]string, error) {
	var tokens [][]string
	rest := rationale
	for {
		match := SupersedesPattern.FindStringSubmatch(rest)
		if match == nil {
			break
		}
		tokens = append(tokens, match)
		rest = rest[len(match[0]):]
		if !strings.HasPrefix(rest, " ") {
			return nil, fmt.Errorf("record %d: the canonical supersession token at the head of the rationale is not "+
				"followed by the single separating space the generator emits; the token run is parsed positionally, "+
				"so a token that does not sit in it is not a claim", sequence)
		}
		rest = rest[1:]
	}
	if index := strings.Index(rest, SupersedesMarker); index >= 0 {
		return nil, fmt.Errorf("record %d: %q appears in the rationale OUTSIDE the anchored token run at its head, "+
			"at offset %d of the remainder. The marker is reserved: it declares a withdrawal and nothing else, so a "+
			"quoted, disclaimed or merely discussed token is refused rather than silently turned into one. "+
			"Context: %q", sequence, SupersedesMarker, index, excerpt(rest, index))
	}
	return tokens, nil
}

// excerpt renders a short window around an offset for a failure message.
func excerpt(text string, index int) string {
	start := index - 40
	if start < 0 {
		start = 0
	}
	end := index + 120
	if end > len(text) {
		end = len(text)
	}
	return text[start:end]
}

// SupersessionLink is one parsed link, as read back off the committed chain.
type SupersessionLink struct {
	SupersededSequence  uint64 `json:"superseded_sequence"`
	SupersededDeltaID   string `json:"superseded_delta_id"`
	SupersededSubject   string `json:"superseded_subject_ref"`
	SupersedingSequence uint64 `json:"superseding_sequence"`
	SupersedingDeltaID  string `json:"superseding_delta_id"`
	SupersedingSubject  string `json:"superseding_subject_ref"`
}

// ReadSupersessionLinks parses every supersession link out of the record chain.
// It reads the RECORDS, not any sidecar and not any declaration, so it reports
// what the committed hashed evidence itself says.
func ReadSupersessionLinks(records []BehaviorLedgerRecord) ([]SupersessionLink, error) {
	bySequence := map[uint64]BehaviorLedgerRecord{}
	for _, record := range records {
		bySequence[record.Sequence] = record
	}
	var links []SupersessionLink
	supersededBy := map[uint64]uint64{}
	for _, record := range records {
		tokens, err := parseSupersedesPrefix(record.Sequence, record.Delta.Rationale)
		if err != nil {
			return nil, err
		}
		for _, match := range tokens {
			sequence, err := strconv.ParseUint(match[1], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("record %d: unparsable superseded sequence %q", record.Sequence, match[1])
			}
			target, exists := bySequence[sequence]
			if !exists {
				return nil, fmt.Errorf("record %d supersedes sequence %d, which is not in the chain",
					record.Sequence, sequence)
			}
			if target.Delta.DeltaID != match[2] {
				return nil, fmt.Errorf("record %d supersedes sequence %d naming delta %s, but sequence %d is %s",
					record.Sequence, sequence, match[2], sequence, target.Delta.DeltaID)
			}
			if target.Delta.SubjectRef != match[3] {
				return nil, fmt.Errorf("record %d supersedes sequence %d naming subject %s, but sequence %d is %s",
					record.Sequence, sequence, match[3], sequence, target.Delta.SubjectRef)
			}
			if sequence >= record.Sequence {
				return nil, fmt.Errorf("record %d supersedes sequence %d, which is not earlier in the chain",
					record.Sequence, sequence)
			}
			if previous, already := supersededBy[sequence]; already {
				return nil, fmt.Errorf("sequence %d is superseded by both record %d and record %d; a record may be "+
					"superseded at most once, otherwise authoritative state is ambiguous", sequence, previous, record.Sequence)
			}
			supersededBy[sequence] = record.Sequence
			links = append(links, SupersessionLink{
				SupersededSequence:  sequence,
				SupersededDeltaID:   target.Delta.DeltaID,
				SupersededSubject:   target.Delta.SubjectRef,
				SupersedingSequence: record.Sequence,
				SupersedingDeltaID:  record.Delta.DeltaID,
				SupersedingSubject:  record.Delta.SubjectRef,
			})
		}
	}
	sort.Slice(links, func(i, j int) bool { return links[i].SupersededSequence < links[j].SupersededSequence })
	return links, nil
}

// SupersededSequences is the set of sequences the chain records as withdrawn.
func SupersededSequences(records []BehaviorLedgerRecord) (map[uint64]bool, error) {
	links, err := ReadSupersessionLinks(records)
	if err != nil {
		return nil, err
	}
	superseded := map[uint64]bool{}
	for _, link := range links {
		superseded[link.SupersededSequence] = true
	}
	return superseded, nil
}

// AuthoritativeRecords returns the records that are still the authoritative
// statement of their subject. A superseded record stays byte-identical in the
// chain with its digest intact — that is the point of SUPERSEDE, DO NOT
// REWRITE — but it no longer speaks for its subject, so no consumer may accept
// it as coverage for anything.
func AuthoritativeRecords(records []BehaviorLedgerRecord) ([]BehaviorLedgerRecord, error) {
	superseded, err := SupersededSequences(records)
	if err != nil {
		return nil, err
	}
	authoritative := make([]BehaviorLedgerRecord, 0, len(records))
	for _, record := range records {
		if !superseded[record.Sequence] {
			authoritative = append(authoritative, record)
		}
	}
	return authoritative, nil
}

// SupersessionLinksEqual reports whether a DECLARED supersession array equals
// the one the record chain carries. It is exact and order-sensitive: both sides
// are sorted by superseded sequence, so a difference is a real difference.
func SupersessionLinksEqual(left, right []SupersessionLink) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
