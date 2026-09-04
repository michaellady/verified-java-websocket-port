package deltaledger

// THE DRAFT-TO-RECORD BINDING.
//
// Seven records were drafted under drafts/ledger-proposals/ and held unappended
// because the 1.1.0 disposition vocabulary could not express them. They are
// appended now (sequences 50-56). This file is what stops "appended" from
// meaning "a record with a similar name exists".
//
// THE POPULATION IS DERIVED, NOT LISTED, AND THAT IS A 2026-09-04 CORRECTION.
// It used to be a hardcoded list of seven paths, and the list was the whole
// weakness: drafts/ledger-proposals/ holds ELEVEN .json files, and the four the
// list did not name were not checked by anything. Three of them are genuinely
// not record proposals -- and this file's own reader says so, refusing them for
// carrying nothing it can recompute. The fourth,
// legacy-13-bare-lf-server-basis-correction.json, is a record proposal of
// exactly the shape read here: it rebuilds from its own six preimages, its
// declared delta_id EQUALS the identity those preimages produce, and no record
// among the fifty-nine in the committed chain carries it. The gate printed
// "held proposal drafts" verified at exit 0 for as long as the list decided the
// population, because a rule cannot refuse a file it was never handed.
//
// So the population now comes from the DIRECTORY, by shape and by declared
// kind, and every file in it is named in the census whether it is in the
// population or out of it. A file leaves the population only by being
// classified out loud.
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

// ProposalDraftsDir is the directory the population is derived FROM. Nothing
// downstream of it may narrow it silently.
const ProposalDraftsDir = "drafts/ledger-proposals"

// The two spellings a file uses to declare itself a proposal of a ledger
// RECORD. The six sweep drafts say entity_type; the two hand-written drafts say
// draft_kind. Both are checked because both are in the tree.
const (
	recordProposalDraftKind  = "behavior-delta-ledger-record-proposal"
	recordProposalEntityType = "BehaviorDeltaLedgerRecordProposal"
)

// declaredNonProposalKinds are the kinds a file may carry to be OUT of the
// population, each with the reason that is true of it. A kind is not a keyword
// a file may invent: a file declaring none of these and none of the record
// proposal spellings is UNCLASSIFIED and fails, because the alternative is that
// deleting two fields from a draft removes it from a gate in silence.
var declaredNonProposalKinds = map[string]string{
	"ledger-record-description-correction": "proposes a correction to the DESCRIPTION of a record already in the " +
		"chain, not a new record; it has no delta of its own to be ledgered",
	"divergence-closure-record": "records the closure of a sweep class and asks for a pending draft to be " +
		"WITHDRAWN; it proposes no record",
	"CORROBORATION_ONLY_NO_NEW_RECORDS": "a corroboration receipt whose own ledger_write_policy says it writes " +
		"no records, so demanding one for it would be demanding a record it declines to propose",
}

// DraftClassification is one file in drafts/ledger-proposals/ and the reason it
// is in the population or out of it. Every file gets one, so the census is the
// directory rather than a subset of it.
type DraftClassification struct {
	// Relative is the repository-relative slash path.
	Relative string
	// DeclaredKinds are the kind strings the file itself carries, verbatim.
	DeclaredKinds []string
	// RecordProposal is whether the file is in the population.
	RecordProposal bool
	// DeclaredDeltaID is the delta_id the file types beside its evidence. It is
	// recorded here for the census only; the rule NEVER trusts it -- it is
	// checked against the identity rebuilt from the file's own preimages.
	DeclaredDeltaID string
	// Why states, for a file out of the population, what it is instead.
	Why string
	// Problem is set when the file can be neither read nor classified.
	Problem string
}

// DraftCensus is the derivation over the whole directory.
type DraftCensus struct {
	Files []DraftClassification
}

// Proposals are the classified record proposals, in path order.
func (c DraftCensus) Proposals() []string {
	var paths []string
	for _, file := range c.Files {
		if file.RecordProposal {
			paths = append(paths, file.Relative)
		}
	}
	return paths
}

// ClassifyProposalDrafts derives the held-draft population from the directory.
//
// TWO SIGNALS, TAKEN AS A UNION, AND NEITHER ONE ALONE CAN REMOVE A FILE. A file
// is a record proposal if it carries a proposed_record.delta.delta_id (the
// STRUCTURE of a record proposal) OR declares one of the record-proposal kinds
// (the file's own WORD for itself). Escaping the population therefore takes
// gutting both, and a file that has been gutted matches no declared
// non-proposal kind either, so it fails as unclassified instead of vanishing.
// That is the whole point: the previous population was a list, and a list is a
// third party's word about a file, which the file can outlive.
func ClassifyProposalDrafts(root string) (DraftCensus, error) {
	dir := filepath.Join(root, filepath.FromSlash(ProposalDraftsDir))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return DraftCensus{}, fmt.Errorf("derive the held-draft population from %s: %w", ProposalDraftsDir, err)
	}
	var census DraftCensus
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		relative := ProposalDraftsDir + "/" + entry.Name()
		classified := DraftClassification{Relative: relative}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			classified.Problem = fmt.Sprintf("%s cannot be read (%v), so it is absent from this census rather "+
				"than clean", relative, err)
			census.Files = append(census.Files, classified)
			continue
		}
		var draft proposalDraft
		if err := json.Unmarshal(raw, &draft); err != nil {
			classified.Problem = fmt.Sprintf("%s does not parse as JSON (%v). A tracked draft the population "+
				"derivation cannot read is a SILENT subtraction from it", relative, err)
			census.Files = append(census.Files, classified)
			continue
		}
		for _, kind := range []string{draft.DraftKind, draft.EntityType, draft.ProposalKind} {
			if kind != "" {
				classified.DeclaredKinds = append(classified.DeclaredKinds, kind)
			}
		}
		classified.DeclaredDeltaID = draft.ProposedRecord.Delta.DeltaID
		for _, kind := range classified.DeclaredKinds {
			if kind == recordProposalDraftKind || kind == recordProposalEntityType {
				classified.RecordProposal = true
			}
		}
		if classified.DeclaredDeltaID != "" {
			classified.RecordProposal = true
		}
		if !classified.RecordProposal {
			for _, kind := range classified.DeclaredKinds {
				if why, declared := declaredNonProposalKinds[kind]; declared {
					classified.Why = kind + ": " + why
					break
				}
			}
			if classified.Why == "" {
				classified.Problem = fmt.Sprintf(
					"%s proposes no record and declares no kind this rule classifies (kinds carried: %s). A file in "+
						"%s is either a record proposal or something this rule NAMES; being neither is how a draft "+
						"leaves a gate without anyone deciding that it should",
					relative, kindList(classified.DeclaredKinds), ProposalDraftsDir)
			}
		}
		census.Files = append(census.Files, classified)
	}
	sort.Slice(census.Files, func(i, j int) bool { return census.Files[i].Relative < census.Files[j].Relative })
	return census, nil
}

func kindList(kinds []string) string {
	if len(kinds) == 0 {
		return "none"
	}
	return strings.Join(kinds, ", ")
}

// ProposalDraftPaths derives the record proposals held under
// drafts/ledger-proposals/. It reads the directory; it is not a list.
func ProposalDraftPaths(root string) ([]string, error) {
	census, err := ClassifyProposalDrafts(root)
	if err != nil {
		return nil, err
	}
	return census.Proposals(), nil
}

// HeldDraftExemption is a DECLARED, per-draft acknowledgement of a TRUE finding
// that cannot be fixed from inside this rule: one record proposal has NOT
// become a record, and appending it is an owner decision rather than a repair.
// It is not an explanation and it is not a coverage claim -- the draft really is
// unledgered.
//
// IT EXCUSES EXACTLY ONE HALF OF ONE CHECK. The draft is still read, still
// rebuilt from its own six preimages, and its declared delta_id must still
// EQUAL that recomputation; only the demand that the committed chain carry the
// identity is waived. An exemption that also waived the recomputation would
// excuse the draft from being evidence at all.
//
// AND IT IS RE-CHECKED THREE WAYS, because an exemption nothing re-checks is a
// bypass wearing an exemption's name. It fails as STALE_EXEMPTION when the
// chain DOES carry the identity (the owner appended it and the acknowledgement
// outlived the finding), when the derivation no longer classifies the named
// path as a record proposal (the file was deleted, renamed or gutted), and when
// the pinned delta_id no longer equals the one the draft declares (the draft was
// edited under the exemption). The pin is the same device cmd/pinconsumerctl
// uses for allowedPin: an exemption cannot survive an edit to the thing it
// excuses.
type HeldDraftExemption struct {
	// Relative is the draft this exemption is about.
	Relative string
	// DeclaredDeltaID is pinned, so editing the draft's identity invalidates
	// the exemption instead of silently widening it.
	DeclaredDeltaID string
	// Owner is the action that would let this entry be deleted.
	Owner string
}

// heldDraftExemptions is the complete set of record proposals this rule does not
// require to be in the chain. Adding an entry is a decision someone has to
// defend in review; it is not a place to park a red gate.
var heldDraftExemptions = []HeldDraftExemption{
	{
		Relative:        "drafts/ledger-proposals/legacy-13-bare-lf-server-basis-correction.json",
		DeclaredDeltaID: "delta-3905e4669f52383df8aa4bc2965d64f320f6e2f4fdb6b609904dba627112a906",
		Owner: "OA-held-draft-legacy-13, RULED 2026-09-04: derive the population and carry this draft as a " +
			"declared exemption with a staleness check; do NOT append to the ledger to make the gate green. " +
			"The draft's own why_this_is_a_draft_and_not_an_append says the remedy is a superseding record in " +
			"the shape of sequences 45-47 and that appending it is an owner decision. Appending it moves the " +
			"chain head, the sequence after the frozen prefix and the unledgered_disagreements recomputation, " +
			"which an agent may not do. DELETE THIS ENTRY when the superseding record is appended.",
	},
}

// HeldDraftExemptions exposes the declared exemptions for the census the gate
// prints, so an exemption is visible where the result is read rather than only
// in this file.
func HeldDraftExemptions() []HeldDraftExemption {
	return append([]HeldDraftExemption(nil), heldDraftExemptions...)
}

// proposalDraft is the union of the two committed draft shapes. The six sweep
// drafts carry their preimages under `digest_preimages` (whose keys are named
// for the digests they produce, not for themselves); the server-close-parity
// draft carries them under `proposed_definition` in the field names of
// deltaledger.Definition. Only one of the two is present in any file.
type proposalDraft struct {
	// The three spellings a file uses to say what it IS. They are read for the
	// population derivation, never for the identity: a draft's kind decides
	// whether the rule reads it, and nothing else.
	DraftKind       string `json:"draft_kind"`
	EntityType      string `json:"entity_type"`
	ProposalKind    string `json:"proposal_kind"`
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
	census, err := ClassifyProposalDrafts(root)
	if err != nil {
		return err
	}
	var problems []string
	for _, file := range census.Files {
		if file.Problem != "" {
			problems = append(problems, file.Problem)
		}
	}
	// AN EMPTY SCAN IS NOT A PASS. The population is now derived, and a derived
	// population can be emptied -- by a moved directory, a changed suffix, a
	// checkout without the drafts -- in which case every loop below runs zero
	// times and this rule reports nothing wrong. The old hardcoded list could
	// not do that, and replacing it must not buy silence at the cost of a
	// number. cmd/fixtureguardctl already refuses a scan that matched no files
	// for the same reason.
	proposals := census.Proposals()
	if len(proposals) == 0 {
		problems = append(problems, fmt.Sprintf(
			"the population derived from %s/ contains no record proposal at all (%d .json file(s) classified). A "+
				"rule whose population is empty verifies nothing and must not report that as agreement",
			ProposalDraftsDir, len(census.Files)))
	}
	// The exemptions, matched as they are used, so an entry that matches nothing
	// can be named afterwards rather than dying quietly.
	classified := map[string]DraftClassification{}
	for _, file := range census.Files {
		classified[file.Relative] = file
	}
	acknowledged := map[int]bool{}
	for _, relative := range proposals {
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
			// The ONE half a declared exemption may excuse, and only for the
			// exact draft and the exact identity it pins.
			if index := heldDraftExemptionFor(relative, declared); index >= 0 {
				acknowledged[index] = true
				continue
			}
			problems = append(problems, fmt.Sprintf(
				"%s proposes %s (subject %s), which no record in the committed chain carries. The draft was held "+
					"because the disposition vocabulary could not express it; with the vocabulary in place it must be "+
					"appended, not left held",
				relative, identity, disagreement.SubjectRef))
			continue
		}
		// AN EXEMPTION THAT IS NO LONGER NEEDED IS A BYPASS. The chain carries
		// this identity, so the draft passes on its own and the acknowledgement
		// has outlived the finding it acknowledged. Left in place it would
		// silently excuse whatever next lands at that path.
		if index := heldDraftExemptionFor(relative, declared); index >= 0 {
			acknowledged[index] = true
			problems = append(problems, fmt.Sprintf(
				"STALE_EXEMPTION %s: the exemption excuses this draft for having no record in the committed chain, "+
					"and record %s carries it. The acknowledgement outlived the finding and must be deleted",
				relative, identity))
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
	// The other two staleness arms: an exemption whose draft the derivation no
	// longer classifies as a record proposal, and one whose pinned identity no
	// longer equals the identity the draft declares. Both mean the entry is
	// excusing something other than what it was written about.
	for index, exemption := range heldDraftExemptions {
		if acknowledged[index] {
			continue
		}
		file, present := classified[exemption.Relative]
		switch {
		case !present:
			problems = append(problems, fmt.Sprintf(
				"STALE_EXEMPTION %s: the exemption names a file the derivation over %s/ does not see at all. An "+
					"exemption outliving its subject would exempt whatever next takes that path",
				exemption.Relative, ProposalDraftsDir))
		case !file.RecordProposal:
			problems = append(problems, fmt.Sprintf(
				"STALE_EXEMPTION %s: the exemption excuses a record proposal and the derivation no longer classifies "+
					"this file as one (kinds carried: %s). Either the file changed shape or the exemption is about "+
					"something that no longer exists",
				exemption.Relative, kindList(file.DeclaredKinds)))
		case file.DeclaredDeltaID != exemption.DeclaredDeltaID:
			problems = append(problems, fmt.Sprintf(
				"STALE_EXEMPTION %s: the exemption pins delta_id %s and the draft now declares %s. The draft was "+
					"edited under its own exemption, which is the one thing a pinned acknowledgement exists to catch",
				exemption.Relative, exemption.DeclaredDeltaID, file.DeclaredDeltaID))
		default:
			problems = append(problems, fmt.Sprintf(
				"STALE_EXEMPTION %s: the exemption was never reached on this run, so nothing it claims was tested. "+
					"An acknowledgement that matches no finding must be deleted",
				exemption.Relative))
		}
	}
	sort.Strings(problems)
	if len(problems) != 0 {
		return fmt.Errorf("held ledger-proposal drafts (%d problem(s), %d record proposal(s) derived from %s/ of %d "+
			"file(s), %d declared exemption(s)):\n  %s",
			len(problems), len(proposals), ProposalDraftsDir, len(census.Files), len(heldDraftExemptions),
			strings.Join(problems, "\n  "))
	}
	return nil
}

// heldDraftExemptionFor returns the index of the exemption covering this draft
// at this declared identity, or -1. Both must match: an exemption is about one
// file AND one identity, so a draft whose identity moved is unexcused.
func heldDraftExemptionFor(relative, declaredDeltaID string) int {
	for index, exemption := range heldDraftExemptions {
		if exemption.Relative == relative && exemption.DeclaredDeltaID == declaredDeltaID {
			return index
		}
	}
	return -1
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
