package deltaledger

// THE DRAFT-TO-RECORD BINDING.
//
// Seven records were drafted under drafts/ledger-proposals/ and held unappended
// because the 1.1.0 disposition vocabulary could not express them. They are
// appended now (sequences 50-56). This file is what stops "appended" from
// meaning "a record with a similar name exists".
//
// WHAT IT BINDS, AND WHY THAT SHAPE. Each draft carries the SIX DIGEST
// PREIMAGES its record is built from, in full, as plain strings: the RFC
// expectation and value, the Java observation and value, and the Autobahn
// result and value. This check recomputes the disagreement digest and the delta
// identity FROM THOSE STRINGS, by the same construction internal/lab uses, and
// then requires (a) the draft's own declared delta_id to equal that
// recomputation, so a draft cannot claim an identity its preimages do not
// produce, and (b) a record in the committed chain to carry exactly that
// identity, subject reference, Java reference and reference sets.
//
// It deliberately does NOT check that a record with the drafted SUBJECT exists,
// which is the check that would have been easy to write and worthless: a
// subject reference is a name, and this program keeps rediscovering that a name
// standing in for content is not evidence. Reword one byte of one preimage —
// in the draft or in the Go definition — and the digest moves and this fails.
//
// WHAT IT DELIBERATELY DOES NOT BIND is the rationale and the disposition. The
// drafts' rationales end in a RECOMMENDATION, and one of them (DIV-01) says in
// as many words that the record "stays unresolved", which is not the
// adjudication that was made. The drafts' `disposition` fields are all the
// pre-vocabulary placeholder "unresolved" for the same reason. Those two fields
// are outside the disagreement-digest preimage — the drafts say so themselves —
// so the appended record states the adjudication and the draft keeps its
// proposal. Binding them would force a rewrite of files another package
// byte-verifies against the sweep that produced them.

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

// ProposalDraftPaths are the committed drafts appended at this landing. They
// are listed rather than globbed: drafts/ledger-proposals/ also holds
// java-formal-binding-corroborations.json, which is a corroboration receipt and
// not a record proposal, and a glob would silently demand a record for it.
func ProposalDraftPaths() []string {
	return []string{
		"drafts/ledger-proposals/server-close-parity.json",
		"drafts/ledger-proposals/divergence-sweep-1.json",
		"drafts/ledger-proposals/divergence-sweep-2.json",
		"drafts/ledger-proposals/divergence-sweep-3.json",
		"drafts/ledger-proposals/divergence-sweep-4.json",
		"drafts/ledger-proposals/divergence-sweep-5.json",
		"drafts/ledger-proposals/divergence-sweep-6.json",
	}
}

// proposalDraft is the union of the two committed draft shapes. The six sweep
// drafts carry their preimages under `digest_preimages` (whose keys are named
// for the digests they produce, not for themselves); the server-close-parity
// draft carries them under `proposed_definition` in the field names of
// deltaledger.Definition. Only one of the two is present in any file.
type proposalDraft struct {
	DigestPreimages *struct {
		RFCExpectation  string `json:"rfc_expectation_digest"`
		RFCValue        string `json:"rfc_value_digest"`
		JavaObservation string `json:"java_observation_digest"`
		JavaValue       string `json:"java_value_digest"`
		AutobahnResult  string `json:"autobahn_result_digest"`
		AutobahnValue   string `json:"autobahn_value_digest"`
	} `json:"digest_preimages"`
	ProposedDefinition *struct {
		RFCExpectation  string `json:"RFCExpectation"`
		RFCValue        string `json:"RFCValue"`
		JavaObservation string `json:"JavaObservation"`
		JavaValue       string `json:"JavaValue"`
		AutobahnResult  string `json:"AutobahnResult"`
		AutobahnValue   string `json:"AutobahnValue"`
	} `json:"proposed_definition"`
	ProposedRecord struct {
		Delta struct {
			DeltaID            string   `json:"delta_id"`
			SubjectRef         string   `json:"subject_ref"`
			RFCRefs            []string `json:"rfc_refs"`
			JavaRef            string   `json:"java_ref"`
			AutobahnRefs       []string `json:"autobahn_refs"`
			DisagreementDigest string   `json:"disagreement_digest"`
		} `json:"delta"`
	} `json:"proposed_record"`
}

// ReadProposalDraft decodes one committed draft and rebuilds the disagreement
// it proposes from the draft's OWN preimage strings.
func ReadProposalDraft(root, relative string) (lab.ObservedDisagreement, string, error) {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil {
		return lab.ObservedDisagreement{}, "", err
	}
	var draft proposalDraft
	if err := json.Unmarshal(raw, &draft); err != nil {
		return lab.ObservedDisagreement{}, "", fmt.Errorf("%s: %w", relative, err)
	}
	var rfcExpectation, rfcValue, javaObservation, javaValue, autobahnResult, autobahnValue string
	switch {
	case draft.DigestPreimages != nil:
		p := draft.DigestPreimages
		rfcExpectation, rfcValue = p.RFCExpectation, p.RFCValue
		javaObservation, javaValue = p.JavaObservation, p.JavaValue
		autobahnResult, autobahnValue = p.AutobahnResult, p.AutobahnValue
	case draft.ProposedDefinition != nil:
		p := draft.ProposedDefinition
		rfcExpectation, rfcValue = p.RFCExpectation, p.RFCValue
		javaObservation, javaValue = p.JavaObservation, p.JavaValue
		autobahnResult, autobahnValue = p.AutobahnResult, p.AutobahnValue
	default:
		return lab.ObservedDisagreement{}, "", fmt.Errorf(
			"%s carries neither a digest_preimages block nor a proposed_definition block, so nothing in it can be "+
				"recomputed; a draft this check cannot rebuild is not evidence that its record is the drafted one",
			relative)
	}
	// An empty Autobahn preimage is the honest NON-EXECUTION marker, exactly as
	// on the definition side, not an empty string hashed.
	if autobahnResult == "" {
		autobahnResult = AutobahnResultMarker
	}
	if autobahnValue == "" {
		autobahnValue = AutobahnValueMarker
	}
	delta := draft.ProposedRecord.Delta
	rfcRefs := append([]string(nil), delta.RFCRefs...)
	sort.Strings(rfcRefs)
	autobahnRefs := append([]string(nil), delta.AutobahnRefs...)
	sort.Strings(autobahnRefs)
	disagreement := lab.ObservedDisagreement{
		SubjectRef:            delta.SubjectRef,
		RFCRefs:               rfcRefs,
		RFCExpectationDigest:  intake.DigestBytes([]byte(rfcExpectation)),
		RFCValueDigest:        intake.DigestBytes([]byte(rfcValue)),
		JavaRef:               delta.JavaRef,
		JavaObservationDigest: intake.DigestBytes([]byte(javaObservation)),
		JavaValueDigest:       intake.DigestBytes([]byte(javaValue)),
		AutobahnRefs:          autobahnRefs,
		AutobahnResultDigest:  intake.DigestBytes([]byte(autobahnResult)),
		AutobahnValueDigest:   intake.DigestBytes([]byte(autobahnValue)),
	}
	return disagreement, delta.DeltaID, nil
}

// VerifyProposalDraftsAreLedgered requires every held draft to have become a
// record whose identity the draft's own preimages reproduce.
func VerifyProposalDraftsAreLedgered(root string, records []lab.BehaviorLedgerRecord) error {
	byDelta := map[string]lab.BehaviorDelta{}
	for _, record := range records {
		byDelta[record.Delta.DeltaID] = record.Delta
	}
	var problems []string
	for _, relative := range ProposalDraftPaths() {
		disagreement, declared, err := ReadProposalDraft(root, relative)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		digest, err := disagreement.Digest()
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", relative, err))
			continue
		}
		identity, err := lab.BehaviorDeltaID(digest)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", relative, err))
			continue
		}
		if declared != identity {
			problems = append(problems, fmt.Sprintf(
				"%s declares delta_id %s, but the disagreement rebuilt from its own six digest preimages is %s. The "+
					"draft's identity must be a FUNCTION of the evidence it carries, never a value typed beside it",
				relative, declared, identity))
			continue
		}
		delta, exists := byDelta[identity]
		if !exists {
			problems = append(problems, fmt.Sprintf(
				"%s proposes %s (subject %s), which no record in the committed chain carries. The draft was held "+
					"because the disposition vocabulary could not express it; with the vocabulary in place it must be "+
					"appended, not left held",
				relative, identity, disagreement.SubjectRef))
			continue
		}
		if delta.DisagreementDigest != digest {
			problems = append(problems, fmt.Sprintf(
				"%s: record %s binds disagreement %s but the draft's preimages produce %s",
				relative, identity, delta.DisagreementDigest, digest))
		}
		if delta.SubjectRef != disagreement.SubjectRef || delta.JavaRef != disagreement.JavaRef {
			problems = append(problems, fmt.Sprintf(
				"%s: record %s binds subject %s / java %s, the draft proposes %s / %s",
				relative, identity, delta.SubjectRef, delta.JavaRef, disagreement.SubjectRef, disagreement.JavaRef))
		}
		if !stringsEqual(delta.RFCRefs, disagreement.RFCRefs) || !stringsEqual(delta.AutobahnRefs, disagreement.AutobahnRefs) {
			problems = append(problems, fmt.Sprintf(
				"%s: record %s binds reference sets the draft does not propose", relative, identity))
		}
		// A landed draft must carry an ADJUDICATION, which is the whole reason
		// it was held. A record that came from a held draft and still says
		// nothing in the vocabulary would mean the vocabulary was added and
		// then not used.
		if delta.MismatchClass == "" {
			problems = append(problems, fmt.Sprintf(
				"%s: record %s carries no mismatch_class. These seven drafts were held BECAUSE the vocabulary could "+
					"not express them; appending one without an attribution reproduces the defect",
				relative, identity))
		}
	}
	sort.Strings(problems)
	if len(problems) != 0 {
		return fmt.Errorf("held ledger-proposal drafts (%d problem(s)):\n  %s",
			len(problems), strings.Join(problems, "\n  "))
	}
	return nil
}

func stringsEqual(left, right []string) bool {
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
