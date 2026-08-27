package deltaledger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
	"github.com/michaellady/verified-java-websocket-port/internal/lab"
)

// LedgerRelativePath is the repository-relative committed ledger artifact.
const LedgerRelativePath = "evidence/java/behavior-delta-ledger.json"

// LedgerFile mirrors the committed evidence document field-for-field (and in
// field order), so regenerating it is deterministic.
type LedgerFile struct {
	Schema                  string                     `json:"$schema"`
	SchemaVersion           string                     `json:"schema_version"`
	EvidenceKind            string                     `json:"evidence_kind"`
	AcceptedRootDigest      string                     `json:"accepted_root_digest"`
	Status                  string                     `json:"status"`
	NormativeAuthority      string                     `json:"normative_authority"`
	Head                    string                     `json:"head"`
	Records                 []lab.BehaviorLedgerRecord `json:"records"`
	AppendImplementation    string                     `json:"append_implementation"`
	UnledgeredDisagreements int                        `json:"unledgered_disagreements"`
	Production              bool                       `json:"production"`
	Publication             bool                       `json:"publication"`
}

// BuildDeltas materializes every recorded divergence definition into a
// validated behavior delta, deriving the disagreement digest and delta
// identity through the canonical internal/lab implementation.
func BuildDeltas() ([]lab.BehaviorDelta, error) {
	definitions := Definitions()
	deltas := make([]lab.BehaviorDelta, 0, len(definitions))
	for index, definition := range definitions {
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
			AutobahnResultDigest:  intake.DigestBytes([]byte(AutobahnResultMarker)),
			AutobahnValueDigest:   intake.DigestBytes([]byte(AutobahnValueMarker)),
		}
		digest, err := disagreement.Digest()
		if err != nil {
			return nil, fmt.Errorf("definition %d (%s): %w", index, definition.Subject, err)
		}
		identity, err := lab.BehaviorDeltaID(digest)
		if err != nil {
			return nil, fmt.Errorf("definition %d (%s): %w", index, definition.Subject, err)
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
			Disposition:           "unresolved",
			Rationale:             definition.Rationale,
		}
		if err := delta.Validate(); err != nil {
			return nil, fmt.Errorf("definition %d (%s): %w", index, definition.Subject, err)
		}
		deltas = append(deltas, delta)
	}
	return deltas, nil
}

// BuildLedger appends every delta through the canonical hash-chained CAS
// implementation (in a private scratch directory) and returns the verified
// record chain and its head.
func BuildLedger() ([]lab.BehaviorLedgerRecord, string, error) {
	deltas, err := BuildDeltas()
	if err != nil {
		return nil, "", err
	}
	scratch, err := os.MkdirTemp("", "deltaledger-")
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = os.RemoveAll(scratch) }()
	directory := filepath.Join(scratch, "ledger")
	head := lab.GenesisLedgerHead
	for _, delta := range deltas {
		head, err = lab.AppendBehaviorDelta(directory, head, delta)
		if err != nil {
			return nil, "", fmt.Errorf("append %s: %w", delta.SubjectRef, err)
		}
	}
	records, verifiedHead, err := lab.ReadBehaviorLedger(directory)
	if err != nil {
		return nil, "", err
	}
	if verifiedHead != head {
		return nil, "", fmt.Errorf("verified head %s does not equal append head %s", verifiedHead, head)
	}
	return records, verifiedHead, nil
}

// BuildLedgerFile regenerates the committed evidence document, preserving the
// envelope of the existing committed file (accepted root and status: the
// ledger's aggregate READY gate additionally requires the Autobahn baseline to
// be PASS — see internal/lab.VerifyBaselineEvidence — and that baseline is
// BLOCKED with no further reruns authorized, so populating records does not
// flip the status).
func BuildLedgerFile(existing LedgerFile) (LedgerFile, error) {
	records, head, err := BuildLedger()
	if err != nil {
		return LedgerFile{}, err
	}
	built := existing
	built.Head = head
	built.Records = records
	built.UnledgeredDisagreements = 0
	return built, nil
}

// ReadCommittedLedger decodes the committed evidence document at root.
func ReadCommittedLedger(root string) (LedgerFile, error) {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(LedgerRelativePath)))
	if err != nil {
		return LedgerFile{}, err
	}
	var file LedgerFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return LedgerFile{}, err
	}
	return file, nil
}
