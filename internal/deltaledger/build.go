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

// LedgerRelativePath is the repository-relative committed ledger artifact, and
// LedgerSchemaRelativePath is its contract.
//
// THE 1.1.0 BUMP, and exactly where it lands. The owner ruled BUMP THE RECORD
// SCHEMA TO 1.1.0 AND TEACH THE READINESS GATE ABOUT SUPERSESSION, with the
// binding constraint that the bump must not disturb the frozen prefix. A
// record's digest preimage is {schema_version, sequence, previous_digest,
// delta}, so bumping the PER-RECORD version would change every record digest
// and rewrite the chain from sequence 1. The bump is therefore at the LEDGER
// DOCUMENT level: the document gains a first-class `supersessions` array,
// records stay at record schema_version 1.0.0, and VerifyFrozenPrefix still
// finds sequence 35 at 3fcd461c….
//
// THE 1.2.0 BUMP lands the same way and for the same reason. It adds the
// DISPOSITION VOCABULARY — three terms on `disposition`, the optional
// per-record `mismatch_class`, and the computed document-level
// `records_without_mismatch_class` — because US-020 AC3 requires every mismatch
// to be recorded as a Java quirk, a Rust defect or underspecified behavior and
// the 1.1.0 vocabulary could express neither that nor the adoption-versus-
// correction question. `mismatch_class` is OPTIONAL rather than defaulted so
// that the forty-nine records sealed before it existed serialize to the same
// preimage bytes they always did; the record schema_version stays 1.0.0.
const (
	LedgerRelativePath       = "evidence/java/behavior-delta-ledger.json"
	LedgerSchemaRelativePath = "schemas/behavior-delta-ledger-1.2.0.schema.json"
	LedgerSchemaPointer      = "../../schemas/behavior-delta-ledger-1.2.0.schema.json"
	LedgerSchemaVersion      = "1.2.0"
)

// LedgerFile mirrors the committed evidence document field-for-field (and in
// field order), so regenerating it is deterministic.
type LedgerFile struct {
	Schema               string                     `json:"$schema"`
	SchemaVersion        string                     `json:"schema_version"`
	EvidenceKind         string                     `json:"evidence_kind"`
	AcceptedRootDigest   string                     `json:"accepted_root_digest"`
	Status               string                     `json:"status"`
	NormativeAuthority   string                     `json:"normative_authority"`
	Head                 string                     `json:"head"`
	Records              []lab.BehaviorLedgerRecord `json:"records"`
	AppendImplementation string                     `json:"append_implementation"`
	// Supersessions is the 1.1.0 addition: the links the record chain's own
	// hashed rationales carry, declared as data. internal/lab re-derives them
	// and refuses a document that declares anything else.
	Supersessions           []SupersessionLink `json:"supersessions"`
	UnledgeredDisagreements int                `json:"unledgered_disagreements"`
	// RecordsWithoutMismatchClass is the 1.2.0 addition: how many records carry
	// no US-020 AC3 mismatch class. Like unledgered_disagreements it is
	// COMPUTED, never assigned a literal, and the requirement on it is a
	// RECOMPUTATION rather than a constant — see adjudication.go for why a
	// `const: 0` here would have been the same fake gate all over again.
	RecordsWithoutMismatchClass int  `json:"records_without_mismatch_class"`
	Production                  bool `json:"production"`
	Publication                 bool `json:"publication"`
}

// BuildDeltas materializes every recorded divergence definition into a
// validated behavior delta, deriving the disagreement digest and delta
// identity through the canonical internal/lab implementation.
func BuildDeltas() ([]lab.BehaviorDelta, error) {
	return buildDeltasFrom(Definitions())
}

// buildDeltasFrom materializes an explicit definition list.
func buildDeltasFrom(definitions []Definition) ([]lab.BehaviorDelta, error) {
	deltas := make([]lab.BehaviorDelta, 0, len(definitions))
	for index, definition := range definitions {
		rfcRefs := append([]string(nil), definition.RFCRefs...)
		sort.Strings(rfcRefs)
		autobahnRefs := append([]string(nil), definition.AutobahnRefs...)
		sort.Strings(autobahnRefs)
		// Records whose Autobahn refs are executed observations carry their
		// own preimages; every other record keeps the honest non-execution
		// markers (see Definition.AutobahnResult).
		autobahnResult := AutobahnResultMarker
		if definition.AutobahnResult != "" {
			autobahnResult = definition.AutobahnResult
		}
		autobahnValue := AutobahnValueMarker
		if definition.AutobahnValue != "" {
			autobahnValue = definition.AutobahnValue
		}
		disagreement := lab.ObservedDisagreement{
			SubjectRef:            "semantic:" + definition.Subject + ":provisional-v1",
			RFCRefs:               rfcRefs,
			RFCExpectationDigest:  intake.DigestBytes([]byte(definition.RFCExpectation)),
			RFCValueDigest:        intake.DigestBytes([]byte(definition.RFCValue)),
			JavaRef:               "java-v1.6.0:" + definition.JavaRef,
			JavaObservationDigest: intake.DigestBytes([]byte(definition.JavaObservation)),
			JavaValueDigest:       intake.DigestBytes([]byte(definition.JavaValue)),
			AutobahnRefs:          autobahnRefs,
			AutobahnResultDigest:  intake.DigestBytes([]byte(autobahnResult)),
			AutobahnValueDigest:   intake.DigestBytes([]byte(autobahnValue)),
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
			// The disposition was a HARDCODED "unresolved" here until the
			// 1.2.0 vocabulary existed, which is precisely why all
			// forty-nine committed records read "unresolved": no definition
			// could say anything else. It now comes from the definition, and
			// the empty definition field still means "unresolved" so that
			// every definition written before this change reproduces its
			// sealed record byte-for-byte.
			Disposition: dispositionOf(definition),
			// The supersession link is emitted at the HEAD of the rationale
			// so it is inside a hashed digest preimage and a reader meets it
			// first, rather than having to find it in later prose.
			Rationale: supersedesPrefix(definition) + definition.Rationale,
			// MismatchClass is LAST and empty on every pre-vocabulary
			// definition, so `omitempty` drops it from the canonical JSON and
			// those records' digests do not move.
			MismatchClass: definition.MismatchClass,
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
	return buildLedgerFrom(Definitions())
}

// buildLedgerFrom is BuildLedger over an explicit definition list.
func buildLedgerFrom(definitions []Definition) ([]lab.BehaviorLedgerRecord, string, error) {
	deltas, err := buildDeltasFrom(definitions)
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
//
// unledgered_disagreements is COMPUTED, not assigned. It counts the
// observations in the committed evidence/java/observed-disagreements.json
// whose disagreement digest has no record in the chain. It was previously the
// literal 0 with a schema that admitted nothing else — a gate that could not
// fail, and did not, through the whole period when gap G3c and the
// reserved-bit ready-state proposition were genuinely unledgered. See
// observations.go for the full account.
//
// The zero REQUIREMENT deliberately does not live here: this function reports
// the count honestly whatever it is, and internal/lab.VerifyBaselineEvidence
// refuses readiness when it is nonzero.
func BuildLedgerFile(root string, existing LedgerFile) (LedgerFile, error) {
	return BuildLedgerFileFrom(root, existing, Definitions())
}

// BuildLedgerFileFrom is BuildLedgerFile over an EXPLICIT definition list, and
// it is the single production assignment of unledgered_disagreements.
//
// The seam exists so the polarity proof can exercise THIS function rather than
// hand-constructing a degraded document beside it. Review BLOCKING 2 reproduced
// the previous arrangement's failure: reverting the assignment below to the
// literal 0 left the entire deltaledger suite green and `deltaledgerctl
// --check` passing, because the polarity test set the field itself. The tests
// in observations_test.go now call this function with a truncated definition
// list and with a degraded evidence root, so reverting the assignment fails
// them.
func BuildLedgerFileFrom(root string, existing LedgerFile, definitions []Definition) (LedgerFile, error) {
	records, head, err := buildLedgerFrom(definitions)
	if err != nil {
		return LedgerFile{}, err
	}
	unledgeredSubjects, unledgeredDemands, err := UnledgeredDisagreements(root, records, definitions)
	if err != nil {
		return LedgerFile{}, err
	}
	links, err := ReadSupersessionLinks(records)
	if err != nil {
		return LedgerFile{}, err
	}
	if links == nil {
		links = []SupersessionLink{}
	}
	built := existing
	// The 1.1.0 envelope is asserted here rather than inherited from the
	// committed file, so a hand-edited document cannot keep the gate reading it
	// as the older contract.
	built.Schema = LedgerSchemaPointer
	built.SchemaVersion = LedgerSchemaVersion
	built.Head = head
	built.Records = records
	built.Supersessions = links
	built.UnledgeredDisagreements = len(unledgeredSubjects) + len(unledgeredDemands)
	built.RecordsWithoutMismatchClass = CountRecordsWithoutMismatchClass(records)
	return built, nil
}

// dispositionOf is the definition-to-record disposition, with the empty
// definition field meaning the frozen vocabulary's "unresolved".
//
// THE DEFAULT IS NOT A CONVENIENCE. Every definition written before the 1.2.0
// vocabulary leaves the field empty, and each of those definitions must keep
// reproducing the exact record digest it was sealed with; "unresolved" is the
// token those records carry, so it is the only value the empty field can mean.
func dispositionOf(definition Definition) string {
	if definition.Disposition == "" {
		return lab.DispositionUnresolved
	}
	return definition.Disposition
}

// UnledgeredDisagreements is the whole measurement, in its two arms.
//
//   - THE DIGEST ARM (unledgeredSubjects) compares the committed
//     observed-disagreement set against the record chain by exact disagreement
//     digest. It reports a record that was DELETED or DRIFTED away from an
//     observation that outlived it.
//
//   - THE EVIDENCE ARM (unledgeredDemands) sweeps the committed evidence
//     artifacts for divergences and reports the ones no record is about. It
//     reports a divergence that was NEWLY OBSERVED and never written down —
//     the G3c failure this plane actually suffered, and the failure the digest
//     arm alone is structurally incapable of seeing, because an observation
//     built from the definitions can only exist where a definition already did.
//
// Both arms are needed. Neither subsumes the other, and the sum is the number
// the ledger publishes and internal/lab.VerifyBaselineEvidence refuses on.
func UnledgeredDisagreements(root string, records []lab.BehaviorLedgerRecord, definitions []Definition) (
	unledgeredSubjects []string, unledgeredDemands []EvidenceDemand, err error) {
	observations, err := ReadObservations(root)
	if err != nil {
		return nil, nil, err
	}
	unledgeredSubjects, err = UnledgeredSubjects(records, observations.Observed)
	if err != nil {
		return nil, nil, err
	}
	unledgeredDemands, err = UnledgeredEvidenceDemands(root, definitions)
	if err != nil {
		return nil, nil, err
	}
	return unledgeredSubjects, unledgeredDemands, nil
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
