package divergencesweep

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
	"github.com/michaellady/verified-java-websocket-port/internal/lab"
)

// ProposalDir is where this sweep writes DRAFT ledger records. The committed
// behavior-delta ledger is append-only with a frozen prefix and is edited by a
// different track; nothing in this package writes to it.
const ProposalDir = "drafts/ledger-proposals"

// PendingDigest stands where a real ledger record carries previous_digest and
// record_digest. Those two are functions of the append POSITION, which a draft
// cannot know, so the draft says so instead of carrying plausible hex.
const PendingDigest = "PENDING_APPEND_POSITION"

// ProposalDefinition is the digest preimage set for a proposed record. It is
// the shape internal/deltaledger.Definition takes, restated here so a draft can
// be produced without touching the ledger's own definition list. The digests
// in the emitted record are computed from exactly these strings, so appending
// the same definition to internal/deltaledger reproduces the same delta_id.
type ProposalDefinition struct {
	Subject         string
	RFCRefs         []string
	RFCExpectation  string
	RFCValue        string
	JavaRef         string
	JavaObservation string
	JavaValue       string
	AutobahnRefs    []string
	AutobahnResult  string
	AutobahnValue   string
	Rationale       string
}

// Proposal is one drafted record with the sweep measurement behind it.
type Proposal struct {
	// Number orders the draft files: divergence-sweep-<Number>.json.
	Number int
	// ClassID is the sweep class this record would carry.
	ClassID string
	// Definition is the preimage set.
	Definition ProposalDefinition
	// Disposition is the ledger disposition the record would carry.
	Disposition string
}

// ProposalDocument is what a draft file holds.
type ProposalDocument struct {
	SchemaVersion   string            `json:"schema_version"`
	EntityType      string            `json:"entity_type"`
	Note            string            `json:"note"`
	SweepClassID    string            `json:"sweep_class_id"`
	Recommendation  string            `json:"sweep_recommendation"`
	MeasuredExtent  MeasuredExtent    `json:"measured_extent"`
	DigestPreimages map[string]string `json:"digest_preimages"`
	Record          ProposedRecord    `json:"proposed_record"`
}

// MeasuredExtent is the class's recomputed case set, so the draft cannot drift
// from the reports it rests on.
type MeasuredExtent struct {
	SweepDocument string              `json:"sweep_document"`
	RunID         string              `json:"run_id"`
	SubjectCommit string              `json:"subject_commit"`
	CaseCounts    map[string]int      `json:"case_counts_by_subject_role"`
	Cases         map[string][]string `json:"cases_by_subject_role"`
}

// ProposedRecord mirrors a committed ledger record's field shape exactly, with
// the two position-dependent digests marked pending.
type ProposedRecord struct {
	SchemaVersion  string            `json:"schema_version"`
	Sequence       string            `json:"sequence"`
	PreviousDigest string            `json:"previous_digest"`
	Delta          lab.BehaviorDelta `json:"delta"`
	RecordDigest   string            `json:"record_digest"`
}

// BuildProposals renders every drafted record from the sweep. The rationale of
// each record quotes the measured counts, so the delta identity is a function
// of the report bytes: a run in which the divergence moved produces a
// different delta_id and the committed draft stops matching.
func BuildProposals(document *Document) ([]ProposalDocument, error) {
	byClass := map[string]ClassDoc{}
	for _, class := range document.Classes {
		byClass[class.ID] = class
	}
	proposals := proposalSpecs(document)
	out := make([]ProposalDocument, 0, len(proposals))
	for _, proposal := range proposals {
		class, ok := byClass[proposal.ClassID]
		if !ok {
			return nil, fmt.Errorf("proposal %d names class %s, which the sweep does not produce",
				proposal.Number, proposal.ClassID)
		}
		if class.ProposedLedgerSubjectRef != "semantic:"+proposal.Definition.Subject+":provisional-v1" {
			return nil, fmt.Errorf("proposal %d subject %q does not match class %s's proposed subject_ref %q",
				proposal.Number, proposal.Definition.Subject, class.ID, class.ProposedLedgerSubjectRef)
		}
		delta, err := buildDelta(proposal)
		if err != nil {
			return nil, fmt.Errorf("proposal %d (%s): %w", proposal.Number, proposal.ClassID, err)
		}
		out = append(out, ProposalDocument{
			SchemaVersion:  "1.0.0",
			EntityType:     "BehaviorDeltaLedgerRecordProposal",
			Note:           "A DRAFT, not a ledger record. evidence/java/behavior-delta-ledger.json is append-only with a frozen prefix and is edited by another track; this file exists so the owner can append the record without retyping it. previous_digest and record_digest are functions of the append position and are therefore marked " + PendingDigest + ". Everything else, including delta_id, is computed here from the digest preimages below by the same construction internal/deltaledger uses, so appending this definition reproduces this delta_id exactly.",
			SweepClassID:   proposal.ClassID,
			Recommendation: class.Recommendation,
			MeasuredExtent: MeasuredExtent{
				SweepDocument: DocumentPath,
				RunID:         document.RecomputedFrom.RunID,
				SubjectCommit: document.RecomputedFrom.SubjectCommit,
				CaseCounts:    class.CaseCounts,
				Cases:         class.Cases,
			},
			DigestPreimages: map[string]string{
				"rfc_expectation_digest":  proposal.Definition.RFCExpectation,
				"rfc_value_digest":        proposal.Definition.RFCValue,
				"java_observation_digest": proposal.Definition.JavaObservation,
				"java_value_digest":       proposal.Definition.JavaValue,
				"autobahn_result_digest":  proposal.Definition.AutobahnResult,
				"autobahn_value_digest":   proposal.Definition.AutobahnValue,
			},
			Record: ProposedRecord{
				SchemaVersion:  "1.0.0",
				Sequence:       "PENDING_APPEND_POSITION (the next free sequence at append time)",
				PreviousDigest: PendingDigest,
				Delta:          delta,
				RecordDigest:   PendingDigest,
			},
		})
	}
	return out, nil
}

func buildDelta(proposal Proposal) (lab.BehaviorDelta, error) {
	definition := proposal.Definition
	rfcRefs := append([]string(nil), definition.RFCRefs...)
	sort.Strings(rfcRefs)
	autobahnRefs := append([]string(nil), definition.AutobahnRefs...)
	sort.Strings(autobahnRefs)
	disagreement := lab.ObservedDisagreement{
		SubjectRef:            "semantic:" + definition.Subject + ":provisional-v1",
		RFCRefs:               rfcRefs,
		RFCExpectationDigest:  intake.DigestBytes([]byte(definition.RFCExpectation)),
		RFCValueDigest:        intake.DigestBytes([]byte(definition.RFCValue)),
		JavaRef:               "java-v1.6.0:" + definition.JavaRef,
		JavaObservationDigest: intake.DigestBytes([]byte(definition.JavaObservation)),
		JavaValueDigest:       intake.DigestBytes([]byte(definition.JavaValue)),
		AutobahnRefs:          autobahnRefs,
		AutobahnResultDigest:  intake.DigestBytes([]byte(definition.AutobahnResult)),
		AutobahnValueDigest:   intake.DigestBytes([]byte(definition.AutobahnValue)),
	}
	digest, err := disagreement.Digest()
	if err != nil {
		return lab.BehaviorDelta{}, err
	}
	identity, err := lab.BehaviorDeltaID(digest)
	if err != nil {
		return lab.BehaviorDelta{}, err
	}
	delta := lab.BehaviorDelta{
		SchemaVersion:         "1.0.0",
		DeltaID:               identity,
		SubjectRef:            disagreement.SubjectRef,
		RFCRefs:               rfcRefs,
		RFCExpectationDigest:  disagreement.RFCExpectationDigest,
		RFCValueDigest:        disagreement.RFCValueDigest,
		JavaRef:               disagreement.JavaRef,
		JavaObservationDigest: disagreement.JavaObservationDigest,
		JavaValueDigest:       disagreement.JavaValueDigest,
		AutobahnRefs:          autobahnRefs,
		AutobahnResultDigest:  disagreement.AutobahnResultDigest,
		AutobahnValueDigest:   disagreement.AutobahnValueDigest,
		DisagreementDigest:    digest,
		NormativeAuthority:    "rfc6455",
		Disposition:           proposal.Disposition,
		Rationale:             definition.Rationale,
	}
	if err := delta.Validate(); err != nil {
		return lab.BehaviorDelta{}, err
	}
	return delta, nil
}

// MarshalProposal renders one draft in the committed form.
func MarshalProposal(proposal ProposalDocument) ([]byte, error) {
	encoded, err := json.MarshalIndent(proposal, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

// ProposalPath is where draft n lives.
func ProposalPath(root string, number int) string {
	return filepath.Join(root, ProposalDir, fmt.Sprintf("divergence-sweep-%d.json", number))
}

// WriteProposals emits every draft.
func WriteProposals(root string, document *Document) ([]string, error) {
	proposals, err := BuildProposals(document)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(root, ProposalDir), 0o755); err != nil {
		return nil, err
	}
	var written []string
	for index, proposal := range proposals {
		encoded, err := MarshalProposal(proposal)
		if err != nil {
			return nil, err
		}
		path := ProposalPath(root, index+1)
		if err := os.WriteFile(path, encoded, 0o644); err != nil {
			return nil, err
		}
		written = append(written, path)
	}
	return written, nil
}

// VerifyProposals refuses a committed draft that disagrees with the sweep.
func VerifyProposals(root string, document *Document) error {
	proposals, err := BuildProposals(document)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(filepath.Join(root, ProposalDir))
	if err != nil {
		return fmt.Errorf("ledger proposal drafts: %w", err)
	}
	committedCount := 0
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "divergence-sweep-") && strings.HasSuffix(entry.Name(), ".json") {
			committedCount++
		}
	}
	if committedCount != len(proposals) {
		return fmt.Errorf("%s holds %d divergence-sweep drafts, the sweep produces %d",
			ProposalDir, committedCount, len(proposals))
	}
	for index, proposal := range proposals {
		encoded, err := MarshalProposal(proposal)
		if err != nil {
			return err
		}
		path := ProposalPath(root, index+1)
		committed, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("ledger proposal draft: %w", err)
		}
		if string(committed) != string(encoded) {
			return fmt.Errorf("%s disagrees with the sweep it is drafted from: %s",
				path, firstDifference(committed, encoded))
		}
	}
	return nil
}
