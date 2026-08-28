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
)

// SupersedesPattern parses the canonical supersession link out of a rationale.
// The token is emitted at the head of a superseding record's rationale by
// internal/deltaledger, so it is inside the hashed digest preimage and cannot be
// edited away without changing the record digest.
var SupersedesPattern = regexp.MustCompile(
	`SUPERSEDES ledger-sequence=([0-9]+) delta=(delta-[0-9a-f]{64}) subject=(semantic:[a-z0-9][a-z0-9._-]*:provisional-v[0-9]+)`)

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
		for _, match := range SupersedesPattern.FindAllStringSubmatch(record.Delta.Rationale, -1) {
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
