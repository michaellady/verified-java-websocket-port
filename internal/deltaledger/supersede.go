package deltaledger

// SUPERSESSION AS A MACHINE-VISIBLE LEDGER OPERATION.
//
// THE DEFECT (review BLOCKING 8). "Supersede" was prose. Sequences 14-16 stated
// a wrong RFC basis and sequences 45-47 corrected it, but neither the
// Definition type nor the frozen 1.0.0 ledger record carried a supersedes link
// or an authoritative-state field. All six records read `disposition:
// unresolved`, every consumer treated them identically, and a reader had to
// know to go looking in later rationale text to discover that half of them were
// withdrawn in substance.
//
// THE CONSTRAINT. schemas/behavior-delta-ledger-1.0.0.schema.json is FROZEN and
// its `delta` object has `additionalProperties: false`. A new record field is
// not available, and the owner ruling at
// protected/ledger-frozen-prefix-owner-decision-2026-08-28.json is SUPERSEDE,
// DO NOT REWRITE, so the superseded records must stay byte-identical.
//
// THE FIX, within those constraints, in three parts:
//
//  1. Definition carries a structured `Supersedes` list.
//  2. buildDeltasFrom emits a CANONICAL, MACHINE-PARSABLE token at the head of
//     the record's rationale — the one free-text field the frozen schema does
//     carry — of the exact form
//     `SUPERSEDES ledger-sequence=<N> delta=<delta-id>;`
//     so the link is inside the hashed digest preimage and cannot be edited
//     away without changing the record digest.
//  3. deltaledgerctl emits evidence/java/ledger-supersessions.json, a committed
//     first-class artifact that states, as DATA rather than as prose, which
//     sequences are superseded, by which, and under whose authority. A consumer
//     that wants authoritative-only records reads that file; it no longer has
//     to grep rationales.
//
// WHAT THIS DOES NOT FIX, disclosed rather than glossed: internal/lab's
// readiness gate consumes the frozen record vocabulary and still sees six
// `unresolved` records. Teaching the readiness gate to exclude superseded
// records would require a 1.1.0 record schema and an owner ruling on the
// vocabulary, which is out of scope for a correction branch and is escalated
// rather than decided here.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/michaellady/verified-java-websocket-port/internal/lab"
)

// SupersessionsRelativePath is the committed machine-readable supersession map.
const SupersessionsRelativePath = "evidence/java/ledger-supersessions.json"

// Supersession is one record's structured claim to correct an earlier record.
type Supersession struct {
	// Sequence is the superseded record's 1-based ledger sequence.
	Sequence int
	// DeltaID is the superseded record's delta identity, so the link is
	// pinned to content and not merely to a position.
	DeltaID string
	// Subject is the superseded record's subject WITHOUT the "semantic:"
	// prefix and ":provisional-v1" suffix, matching Definition.Subject.
	Subject string
	// Reason is the one-line statement of what the superseded record got
	// wrong. It is part of the hashed preimage.
	Reason string
	// Authority is the owner decision that permits supersede-not-rewrite.
	Authority string
}

// supersedesToken renders the canonical machine-parsable link. It is kept
// terse because the frozen record schema bounds a rationale at 4096 bytes: the
// authority citation is carried once in the record's prose and in the sidecar's
// `authority` field rather than repeated inside every token.
func (s Supersession) supersedesToken() string {
	return "SUPERSEDES ledger-sequence=" + strconv.Itoa(s.Sequence) + " delta=" + s.DeltaID +
		" subject=semantic:" + s.Subject + ":provisional-v1 reason=" + s.Reason + ";"
}

// supersedesPattern parses the canonical link back out of a rationale.
var supersedesPattern = regexp.MustCompile(
	`SUPERSEDES ledger-sequence=([0-9]+) delta=(delta-[0-9a-f]{64}) subject=(semantic:[a-z0-9][a-z0-9._-]*:provisional-v[0-9]+)`)

// supersededSubjects is the set of Definition.Subject values that some later
// definition supersedes. A superseded record is still in the chain, still
// digests, and still reads `unresolved` — but it is no longer the authoritative
// statement of its subject, so the censuses do not accept it as coverage.
func supersededSubjects(definitions []Definition) map[string]bool {
	superseded := map[string]bool{}
	for _, definition := range definitions {
		for _, one := range definition.Supersedes {
			superseded[one.Subject] = true
		}
	}
	return superseded
}

// supersedesPrefix is emitted ahead of every superseding record's rationale.
func supersedesPrefix(definition Definition) string {
	if len(definition.Supersedes) == 0 {
		return ""
	}
	parts := make([]string, 0, len(definition.Supersedes))
	for _, one := range definition.Supersedes {
		parts = append(parts, one.supersedesToken())
	}
	return strings.Join(parts, " ") + " "
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

// SupersessionsDocument is the committed sidecar.
type SupersessionsDocument struct {
	Schema        string             `json:"$schema"`
	SchemaVersion string             `json:"schema_version"`
	EvidenceKind  string             `json:"evidence_kind"`
	Statement     string             `json:"statement"`
	Authority     string             `json:"authority"`
	Links         []SupersessionLink `json:"links"`
}

// SupersessionsStatement is the committed statement field, held here so the
// artifact and the code that validates it cannot drift.
const SupersessionsStatement = "Machine-readable supersession map for evidence/java/behavior-delta-ledger.json. " +
	"A superseded record remains byte-identical in the hash chain with its digest intact, under the owner ruling " +
	"SUPERSEDE-DO-NOT-REWRITE; this file states which records are no longer the authoritative statement of their " +
	"subject, so a consumer does not have to discover it by reading later rationale prose. The frozen 1.0.0 record " +
	"vocabulary has no authoritative-state field, so both the superseded and the superseding record still carry " +
	"disposition 'unresolved'; internal/lab.VerifyBaselineEvidence does not yet consume this map, which is disclosed " +
	"rather than implied."

// SupersessionsAuthority names the owner ruling.
const SupersessionsAuthority = "protected/ledger-frozen-prefix-owner-decision-2026-08-28.json " +
	"(workspace orchestrator protected store, sha256 " +
	"bb3cd0da7f4aed014290dab3dc35b2ec87f41d3d7e7a8c7449816159e9d837c7, decided 2026-08-28T12:54:30Z): " +
	"SUPERSEDE, DO NOT REWRITE."

// ReadSupersessionLinks parses every supersession link out of the record chain.
// It reads the RECORDS, not the definitions, so it reports what the committed
// hashed evidence actually says.
func ReadSupersessionLinks(records []lab.BehaviorLedgerRecord) ([]SupersessionLink, error) {
	bySequence := map[uint64]lab.BehaviorLedgerRecord{}
	byDelta := map[string]lab.BehaviorLedgerRecord{}
	for _, record := range records {
		bySequence[record.Sequence] = record
		byDelta[record.Delta.DeltaID] = record
	}
	var links []SupersessionLink
	supersededBy := map[uint64]uint64{}
	for _, record := range records {
		for _, match := range supersedesPattern.FindAllStringSubmatch(record.Delta.Rationale, -1) {
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
	for superseded, superseding := range supersededBy {
		if _, chained := supersededBy[superseding]; chained && superseding == superseded {
			return nil, fmt.Errorf("sequence %d supersedes itself", superseded)
		}
	}
	sort.Slice(links, func(i, j int) bool { return links[i].SupersededSequence < links[j].SupersededSequence })
	return links, nil
}

// AuthoritativeSequences returns the sequences that are still the authoritative
// statement of their subject: everything the chain does not record as
// superseded.
func AuthoritativeSequences(records []lab.BehaviorLedgerRecord) ([]uint64, error) {
	links, err := ReadSupersessionLinks(records)
	if err != nil {
		return nil, err
	}
	superseded := map[uint64]bool{}
	for _, link := range links {
		superseded[link.SupersededSequence] = true
	}
	var authoritative []uint64
	for _, record := range records {
		if !superseded[record.Sequence] {
			authoritative = append(authoritative, record.Sequence)
		}
	}
	return authoritative, nil
}

// BuildSupersessionsDocument renders the committed sidecar from the chain.
func BuildSupersessionsDocument(records []lab.BehaviorLedgerRecord) (SupersessionsDocument, error) {
	links, err := ReadSupersessionLinks(records)
	if err != nil {
		return SupersessionsDocument{}, err
	}
	if links == nil {
		links = []SupersessionLink{}
	}
	return SupersessionsDocument{
		Schema:        "../../schemas/ledger-supersessions-1.0.0.schema.json",
		SchemaVersion: "1.0.0",
		EvidenceKind:  "ledger-supersessions",
		Statement:     SupersessionsStatement,
		Authority:     SupersessionsAuthority,
		Links:         links,
	}, nil
}

// EncodeSupersessions renders the sidecar exactly as it is committed.
func EncodeSupersessions(document SupersessionsDocument) ([]byte, error) {
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

// ReadSupersessions decodes the committed sidecar.
func ReadSupersessions(root string) (SupersessionsDocument, error) {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(SupersessionsRelativePath)))
	if err != nil {
		return SupersessionsDocument{}, err
	}
	var document SupersessionsDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		return SupersessionsDocument{}, fmt.Errorf("decode %s: %w", SupersessionsRelativePath, err)
	}
	return document, nil
}

// VerifySupersessions requires the committed sidecar to equal the map the
// committed record chain itself carries, so the sidecar cannot become a
// separate story from the hashed evidence.
func VerifySupersessions(root string, records []lab.BehaviorLedgerRecord) error {
	built, err := BuildSupersessionsDocument(records)
	if err != nil {
		return err
	}
	committed, err := ReadSupersessions(root)
	if err != nil {
		return err
	}
	expected, err := EncodeSupersessions(built)
	if err != nil {
		return err
	}
	actual, err := EncodeSupersessions(committed)
	if err != nil {
		return err
	}
	if string(expected) != string(actual) {
		return fmt.Errorf("%s does not equal the supersession map carried by the committed record chain "+
			"(%d link(s) in the chain)", SupersessionsRelativePath, len(built.Links))
	}
	if len(built.Links) == 0 {
		return fmt.Errorf("%s records no supersession links at all; this branch appends superseding corrections for "+
			"sequences 14-16, so an empty map means the machine-visible link has been lost", SupersessionsRelativePath)
	}
	return nil
}
