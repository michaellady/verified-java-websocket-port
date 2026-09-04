package lab

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

const GenesisLedgerHead = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

var (
	provisionalSubjectPattern = regexp.MustCompile(`^semantic:[a-z0-9][a-z0-9._-]{0,127}:provisional-v[0-9]+$`)
	rfcReferencePattern       = regexp.MustCompile(`^rfc6455#section-[0-9]+(?:\.[0-9]+)*$`)
	javaReferencePattern      = regexp.MustCompile(`^java-v1\.6\.0:[A-Za-z0-9][A-Za-z0-9._:-]{0,191}$`)
	autobahnReferencePattern  = regexp.MustCompile(`^autobahn-v25\.10\.1:([1-7]|9|10|12|13)\.[0-9]+(?:\.[0-9]+)*$`)
)

type BehaviorDelta struct {
	SchemaVersion         string   `json:"schema_version"`
	DeltaID               string   `json:"delta_id"`
	SubjectRef            string   `json:"subject_ref"`
	RFCRefs               []string `json:"rfc_refs"`
	RFCExpectationDigest  string   `json:"rfc_expectation_digest"`
	RFCValueDigest        string   `json:"rfc_value_digest"`
	JavaRef               string   `json:"java_ref"`
	JavaObservationDigest string   `json:"java_observation_digest"`
	JavaValueDigest       string   `json:"java_value_digest"`
	AutobahnRefs          []string `json:"autobahn_refs"`
	AutobahnResultDigest  string   `json:"autobahn_result_digest"`
	AutobahnValueDigest   string   `json:"autobahn_value_digest"`
	DisagreementDigest    string   `json:"disagreement_digest"`
	NormativeAuthority    string   `json:"normative_authority"`
	Disposition           string   `json:"disposition"`
	Rationale             string   `json:"rationale"`
	// MismatchClass is the US-020 AC3 ATTRIBUTION axis: where the mismatch
	// this record binds ORIGINATES. It is OPTIONAL and it is declared LAST, and
	// both facts are load-bearing.
	//
	// The record digest preimage is the whole delta, canonicalized by
	// intake.CanonicalJSON, which is json.Marshal plus a compaction. A field
	// that is present serializes; a field with `omitempty` that is empty
	// serializes to nothing at all. So every record appended before this field
	// existed produces byte-identical preimage bytes with the field in the
	// struct, and the frozen prefix through sequence 35 keeps its digest. A
	// REQUIRED field, or a field with a non-empty default, would have rewritten
	// the chain from sequence 1 — which is exactly what the owner ruling that
	// pins the per-record schema_version at 1.0.0 forbids.
	MismatchClass string `json:"mismatch_class,omitempty"`
}

// THE DISPOSITION VOCABULARY, in its two independent axes.
//
// `disposition` answers WHAT THE PROGRAM DOES about the mismatch, and
// `mismatch_class` answers WHERE THE MISMATCH ORIGINATES. They are separate
// fields because they vary independently: a divergence rooted in the RFC's
// silence can be one the port keeps deliberately (client request field order)
// or one the port still owes an answer for (the 101 response's Server/Date
// fields), and a divergence rooted in a Java quirk can be one the port adopts
// (the role-gated transport close) or one nobody has ruled on yet (the stall on
// an invalid-UTF-8 close reason). A single enum would need their cross product
// and would force a record to misstate one axis in order to state the other.
//
// The `disposition` terms are not invented here. `unresolved` and `rfc-governs`
// are the frozen 1.0.0 vocabulary, unchanged in meaning and still carried by
// every record appended before this vocabulary existed. The three added terms
// are the inherited foundation schema's own adoption/correction axis
// (assurance/schema/behavior-delta-ledger.schema.json: PRESERVE,
// INTENTIONALLY_CORRECT, UNRESOLVED) in this ledger's spelling, and they agree
// term-for-term with the divergence sweep's recommendation vocabulary
// (FIX_IN_PORT, LEDGER_INTENTIONAL_CORRECTION).
const (
	// DispositionUnresolved: no adjudication has been made. The mismatch
	// stands and the decision is owed. Unchanged from the 1.0.0 vocabulary.
	DispositionUnresolved = "unresolved"
	// DispositionRFCGoverns: the RFC's requirement governs and the port
	// follows the RFC rather than Java. Unchanged from the 1.0.0 vocabulary.
	DispositionRFCGoverns = "rfc-governs"
	// DispositionAdoptJava: the port reproduces shipped Java, including where
	// Java departs from the RFC. The foundation schema's PRESERVE.
	DispositionAdoptJava = "adopt-java"
	// DispositionFixInPort: the remedy is a change in the Rust port, which is
	// short of its equivalence target. The sweep's FIX_IN_PORT.
	DispositionFixInPort = "fix-in-port"
	// DispositionIntentionalCorrection: the port deliberately differs from
	// shipped Java and keeps the difference, disclosed rather than removed.
	// The foundation schema's INTENTIONALLY_CORRECT.
	DispositionIntentionalCorrection = "intentional-correction"
)

// The `mismatch_class` terms are US-020 AC3's three, verbatim in meaning:
// "Java quirk, Rust defect, or underspecified behavior". Each names one of the
// three places a mismatch can originate, and exactly one of them is true of any
// given record:
//
//   - MismatchJavaQuirk: RFC 6455 determines the observable and the pinned Java
//     runtime is on the other side of it.
//   - MismatchRustDefect: Java and the RFC agree, or Java is the equivalence
//     target on a point the RFC leaves open, and the PORT fails to reproduce it.
//   - MismatchUnderspecified: RFC 6455 does not determine the observable at
//     all, and Java and the port each chose differently.
const (
	MismatchJavaQuirk      = "java-quirk"
	MismatchRustDefect     = "rust-defect"
	MismatchUnderspecified = "underspecified-behavior"
)

// Dispositions and MismatchClasses are the closed vocabularies, exported so a
// consumer cannot drift a private copy away from the one Validate enforces.
func Dispositions() []string {
	return []string{DispositionUnresolved, DispositionRFCGoverns, DispositionAdoptJava,
		DispositionFixInPort, DispositionIntentionalCorrection}
}

func MismatchClasses() []string {
	return []string{MismatchJavaQuirk, MismatchRustDefect, MismatchUnderspecified}
}

func inVocabulary(value string, vocabulary []string) bool {
	for _, term := range vocabulary {
		if value == term {
			return true
		}
	}
	return false
}

func (d BehaviorDelta) Validate() error {
	if d.SchemaVersion != "1.0.0" || !idPattern.MatchString(d.DeltaID) || !provisionalSubjectPattern.MatchString(d.SubjectRef) || !javaReferencePattern.MatchString(d.JavaRef) || !isDigest(d.DisagreementDigest) {
		return finding("INVALID_BEHAVIOR_DELTA", "$", "delta identity, subject, Java reference, or disagreement digest is invalid")
	}
	if d.NormativeAuthority != "rfc6455" {
		return finding("INVALID_ORACLE_AUTHORITY", "$.normative_authority", "RFC 6455 must remain normative over Java and Autobahn observations")
	}
	if !inVocabulary(d.Disposition, Dispositions()) {
		return finding("INVALID_BEHAVIOR_DELTA", "$.disposition", "disposition is outside the stable provisional vocabulary")
	}
	// The EMPTY mismatch class is admitted, and only the empty one: it is what
	// every record appended before this axis existed carries, and admitting it
	// is what leaves those records' digest preimages byte-identical. Whether an
	// EMPTY class is ACCEPTABLE on a given record is a ledger-level question
	// about that record's position and rationale, not a delta-level one, and it
	// is answered by deltaledger.VerifyAdjudication.
	if d.MismatchClass != "" && !inVocabulary(d.MismatchClass, MismatchClasses()) {
		return finding("INVALID_BEHAVIOR_DELTA", "$.mismatch_class", "mismatch class is outside the US-020 AC3 vocabulary")
	}
	if d.Rationale == "" || len(d.Rationale) > 4096 || strings.ContainsRune(d.Rationale, 0) {
		return finding("INVALID_BEHAVIOR_DELTA", "$.rationale", "bounded rationale is required")
	}
	if err := validateReferences(d.RFCRefs, "$.rfc_refs", rfcReferencePattern); err != nil {
		return err
	}
	if err := validateReferences(d.AutobahnRefs, "$.autobahn_refs", autobahnReferencePattern); err != nil {
		return err
	}
	derived, err := (ObservedDisagreement{
		SubjectRef: d.SubjectRef, RFCRefs: d.RFCRefs, RFCExpectationDigest: d.RFCExpectationDigest, RFCValueDigest: d.RFCValueDigest,
		JavaRef: d.JavaRef, JavaObservationDigest: d.JavaObservationDigest, JavaValueDigest: d.JavaValueDigest,
		AutobahnRefs: d.AutobahnRefs, AutobahnResultDigest: d.AutobahnResultDigest, AutobahnValueDigest: d.AutobahnValueDigest,
	}).Digest()
	if err != nil {
		return err
	}
	if derived != d.DisagreementDigest {
		return finding("BEHAVIOR_DELTA_BINDING_MISMATCH", "$.disagreement_digest", "digest does not bind the stable subject and oracle references")
	}
	identity, err := BehaviorDeltaID(derived)
	if err != nil {
		return err
	}
	if d.DeltaID != identity {
		return finding("BEHAVIOR_DELTA_IDENTITY_MISMATCH", "$.delta_id", "delta identity must derive from the exact bound disagreement")
	}
	return nil
}

func BehaviorDeltaID(disagreementDigest string) (string, error) {
	if !isDigest(disagreementDigest) {
		return "", finding("INVALID_DIGEST", "$.disagreement_digest", "disagreement digest must be exact SHA-256")
	}
	return "delta-" + disagreementDigest[7:], nil
}

func validateReferences(values []string, path string, pattern *regexp.Regexp) error {
	if len(values) == 0 || len(values) > 128 || !sort.StringsAreSorted(values) {
		return finding("INVALID_REFERENCE", path, "references must be a nonempty sorted bounded set")
	}
	for index, value := range values {
		if !pattern.MatchString(value) || index > 0 && values[index-1] == value {
			return finding("INVALID_REFERENCE", fmt.Sprintf("%s[%d]", path, index), "reference is invalid or duplicated")
		}
	}
	return nil
}

type BehaviorLedgerRecord struct {
	SchemaVersion  string        `json:"schema_version"`
	Sequence       uint64        `json:"sequence"`
	PreviousDigest string        `json:"previous_digest"`
	Delta          BehaviorDelta `json:"delta"`
	RecordDigest   string        `json:"record_digest"`
}

type unsignedBehaviorLedgerRecord struct {
	SchemaVersion  string        `json:"schema_version"`
	Sequence       uint64        `json:"sequence"`
	PreviousDigest string        `json:"previous_digest"`
	Delta          BehaviorDelta `json:"delta"`
}

func recordDigest(record BehaviorLedgerRecord) (string, error) {
	unsigned := unsignedBehaviorLedgerRecord{record.SchemaVersion, record.Sequence, record.PreviousDigest, record.Delta}
	bytes, err := intake.CanonicalJSON(unsigned)
	if err != nil {
		return "", err
	}
	return intake.DigestBytes(bytes), nil
}

func (r BehaviorLedgerRecord) Validate() error {
	if r.SchemaVersion != "1.0.0" || r.Sequence == 0 || !isDigest(r.PreviousDigest) || !isDigest(r.RecordDigest) {
		return finding("INVALID_BEHAVIOR_LEDGER", "$", "record envelope is invalid")
	}
	if err := r.Delta.Validate(); err != nil {
		return err
	}
	digest, err := recordDigest(r)
	if err != nil || digest != r.RecordDigest {
		return finding("BEHAVIOR_LEDGER_HASH_MISMATCH", "$.record_digest", "record digest does not bind its canonical content")
	}
	return nil
}

// ReadBehaviorLedger verifies every committed record and requires exactly one
// unbroken genesis-to-head chain. It rejects forks, gaps, links, and extras.
func ReadBehaviorLedger(directory string) ([]BehaviorLedgerRecord, string, error) {
	clean, err := cleanAbsoluteDirectory(directory, "$.ledger_directory")
	if err != nil {
		return nil, "", err
	}
	info, err := os.Lstat(clean)
	if errors.Is(err, os.ErrNotExist) {
		return nil, GenesisLedgerHead, nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, "", finding("UNSAFE_LEDGER_DIRECTORY", clean, "ledger directory must be a private real directory")
	}
	entries, err := os.ReadDir(clean)
	if err != nil {
		return nil, "", finding("INVALID_BEHAVIOR_LEDGER", clean, err.Error())
	}
	if len(entries) > 100000 {
		return nil, "", finding("INPUT_TOO_LARGE", clean, "ledger contains too many filesystem members")
	}
	records := make([]BehaviorLedgerRecord, 0, len(entries))
	for _, entry := range entries {
		if entry.Name() == ".append.lock" {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".delta") || len(entry.Name()) != 64+len(".delta") {
			return nil, "", finding("INVALID_BEHAVIOR_LEDGER", filepath.Join(clean, entry.Name()), "unrecognized ledger member")
		}
		digest := "sha256:" + strings.TrimSuffix(entry.Name(), ".delta")
		if !isDigest(digest) {
			return nil, "", finding("INVALID_BEHAVIOR_LEDGER", filepath.Join(clean, entry.Name()), "ledger filename is not a record digest")
		}
		data, err := readBoundedRegular(filepath.Join(clean, entry.Name()), maxManifestBytes)
		if err != nil {
			return nil, "", err
		}
		info, err := os.Lstat(filepath.Join(clean, entry.Name()))
		if err != nil || info.Mode().Perm()&0o077 != 0 {
			return nil, "", finding("UNSAFE_FILE", filepath.Join(clean, entry.Name()), "ledger records must not be accessible to group or other users")
		}
		var record BehaviorLedgerRecord
		if err := intake.DecodeStrict(data, &record); err != nil {
			return nil, "", err
		}
		if err := record.Validate(); err != nil || record.RecordDigest != digest {
			if err != nil {
				return nil, "", err
			}
			return nil, "", finding("BEHAVIOR_LEDGER_HASH_MISMATCH", filepath.Join(clean, entry.Name()), "filename does not match record digest")
		}
		records = append(records, record)
	}
	if len(records) == 0 {
		return nil, GenesisLedgerHead, nil
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Sequence < records[j].Sequence })
	previous := GenesisLedgerHead
	seenDelta := make(map[string]struct{}, len(records))
	for index, record := range records {
		if record.Sequence != uint64(index+1) || record.PreviousDigest != previous {
			return nil, "", finding("BEHAVIOR_LEDGER_CHAIN_BROKEN", "$.records", "record sequence has a gap, fork, or invalid predecessor")
		}
		if _, duplicate := seenDelta[record.Delta.DeltaID]; duplicate {
			return nil, "", finding("DUPLICATE_ENTRY", "$.delta.delta_id", "delta ID may only be appended once")
		}
		seenDelta[record.Delta.DeltaID] = struct{}{}
		previous = record.RecordDigest
	}
	return records, previous, nil
}

// AppendBehaviorDelta performs a compare-and-swap append. A stale expected
// head or contending writer fails without consuming or rewriting any record.
func AppendBehaviorDelta(directory, expectedHead string, delta BehaviorDelta) (string, error) {
	clean, err := cleanAbsoluteDirectory(directory, "$.ledger_directory")
	if err != nil {
		return "", err
	}
	if err := delta.Validate(); err != nil {
		return "", err
	}
	if !isDigest(expectedHead) {
		return "", finding("INVALID_DIGEST", "$.expected_head", "expected ledger head must be a SHA-256 digest")
	}
	if err := os.MkdirAll(clean, 0o700); err != nil {
		return "", finding("LEDGER_APPEND_FAILED", clean, err.Error())
	}
	info, err := os.Lstat(clean)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return "", finding("UNSAFE_LEDGER_DIRECTORY", clean, "ledger directory must be private")
	}
	lockPath := filepath.Join(clean, ".append.lock")
	lock, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", finding("LEDGER_CAS_CONFLICT", "$.expected_head", "ledger is being appended concurrently")
	}
	defer func() {
		_ = lock.Close()
		_ = os.Remove(lockPath)
		_ = syncDir(clean)
	}()
	records, head, err := ReadBehaviorLedger(clean)
	if err != nil {
		return "", err
	}
	if head != expectedHead {
		return "", finding("LEDGER_CAS_CONFLICT", "$.expected_head", "expected head is stale")
	}
	for _, record := range records {
		if record.Delta.DeltaID == delta.DeltaID {
			return "", finding("DUPLICATE_ENTRY", "$.delta_id", "delta ID was already appended")
		}
	}
	record := BehaviorLedgerRecord{SchemaVersion: "1.0.0", Sequence: uint64(len(records) + 1), PreviousDigest: head, Delta: delta}
	record.RecordDigest, err = recordDigest(record)
	if err != nil {
		return "", err
	}
	data, err := intake.CanonicalJSON(record)
	if err != nil {
		return "", err
	}
	temporary, err := os.CreateTemp(clean, ".delta-*.tmp")
	if err != nil {
		return "", finding("LEDGER_APPEND_FAILED", clean, err.Error())
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return "", finding("LEDGER_APPEND_FAILED", temporaryPath, err.Error())
	}
	if _, err := temporary.Write(data); err != nil {
		return "", finding("LEDGER_APPEND_FAILED", temporaryPath, err.Error())
	}
	if err := temporary.Sync(); err != nil {
		return "", finding("LEDGER_APPEND_FAILED", temporaryPath, err.Error())
	}
	if err := temporary.Close(); err != nil {
		return "", finding("LEDGER_APPEND_FAILED", temporaryPath, err.Error())
	}
	final := filepath.Join(clean, record.RecordDigest[7:]+".delta")
	if err := renameExclusive(temporaryPath, final); err != nil {
		return "", finding("LEDGER_APPEND_FAILED", final, err.Error())
	}
	committed = true
	return record.RecordDigest, nil
}

type ObservedDisagreement struct {
	SubjectRef            string   `json:"subject_ref"`
	RFCRefs               []string `json:"rfc_refs"`
	RFCExpectationDigest  string   `json:"rfc_expectation_digest"`
	RFCValueDigest        string   `json:"rfc_value_digest"`
	JavaRef               string   `json:"java_ref"`
	JavaObservationDigest string   `json:"java_observation_digest"`
	JavaValueDigest       string   `json:"java_value_digest"`
	AutobahnRefs          []string `json:"autobahn_refs"`
	AutobahnResultDigest  string   `json:"autobahn_result_digest"`
	AutobahnValueDigest   string   `json:"autobahn_value_digest"`
}

func (d ObservedDisagreement) Digest() (string, error) {
	if !provisionalSubjectPattern.MatchString(d.SubjectRef) || !javaReferencePattern.MatchString(d.JavaRef) {
		return "", finding("INVALID_REFERENCE", "$", "subject or Java observation reference is invalid")
	}
	if err := validateReferences(d.RFCRefs, "$.rfc_refs", rfcReferencePattern); err != nil {
		return "", err
	}
	if err := validateReferences(d.AutobahnRefs, "$.autobahn_refs", autobahnReferencePattern); err != nil {
		return "", err
	}
	for path, digest := range map[string]string{
		"$.rfc_expectation_digest": d.RFCExpectationDigest, "$.rfc_value_digest": d.RFCValueDigest,
		"$.java_observation_digest": d.JavaObservationDigest, "$.java_value_digest": d.JavaValueDigest,
		"$.autobahn_result_digest": d.AutobahnResultDigest, "$.autobahn_value_digest": d.AutobahnValueDigest,
	} {
		if !isDigest(digest) {
			return "", finding("INVALID_DISAGREEMENT_EVIDENCE", path, "every oracle reference must bind exact content and normalized value digests")
		}
	}
	if d.JavaValueDigest == d.RFCValueDigest && d.AutobahnValueDigest == d.RFCValueDigest {
		return "", finding("NO_BEHAVIOR_DISAGREEMENT", "$.rfc_value_digest", "at least one observed Java or Autobahn value must differ from the RFC expectation")
	}
	bytes, err := intake.CanonicalJSON(d)
	if err != nil {
		return "", err
	}
	return intake.DigestBytes(bytes), nil
}

func DetectUnledgeredDisagreements(records []BehaviorLedgerRecord, observed []ObservedDisagreement) error {
	if _, err := validateRecordChain(records); err != nil {
		return err
	}
	ledgered := make(map[string]struct{}, len(records))
	for _, record := range records {
		if err := record.Validate(); err != nil {
			return err
		}
		ledgered[record.Delta.DisagreementDigest] = struct{}{}
	}
	for index, disagreement := range observed {
		digest, err := disagreement.Digest()
		if err != nil {
			return err
		}
		if _, exists := ledgered[digest]; !exists {
			return finding("UNLEDGERED_BEHAVIOR_DISAGREEMENT", fmt.Sprintf("$.observed[%d]", index), "Java/RFC/Autobahn disagreement has no immutable ledger entry")
		}
	}
	return nil
}

func validateRecordChain(records []BehaviorLedgerRecord) (string, error) {
	previous := GenesisLedgerHead
	seenDelta := make(map[string]struct{}, len(records))
	for index, record := range records {
		if err := record.Validate(); err != nil {
			return "", err
		}
		if record.Sequence != uint64(index+1) || record.PreviousDigest != previous {
			return "", finding("BEHAVIOR_LEDGER_CHAIN_BROKEN", "$.records", "record sequence has a gap, fork, or invalid predecessor")
		}
		if _, duplicate := seenDelta[record.Delta.DeltaID]; duplicate {
			return "", finding("DUPLICATE_ENTRY", "$.delta.delta_id", "delta ID may only appear once")
		}
		seenDelta[record.Delta.DeltaID] = struct{}{}
		previous = record.RecordDigest
	}
	return previous, nil
}
