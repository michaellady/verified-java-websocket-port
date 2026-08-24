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
	SchemaVersion      string   `json:"schema_version"`
	DeltaID            string   `json:"delta_id"`
	SubjectRef         string   `json:"subject_ref"`
	RFCRefs            []string `json:"rfc_refs"`
	JavaRef            string   `json:"java_ref"`
	AutobahnRefs       []string `json:"autobahn_refs"`
	DisagreementDigest string   `json:"disagreement_digest"`
	NormativeAuthority string   `json:"normative_authority"`
	Disposition        string   `json:"disposition"`
	Rationale          string   `json:"rationale"`
}

func (d BehaviorDelta) Validate() error {
	if d.SchemaVersion != "1.0.0" || !idPattern.MatchString(d.DeltaID) || !provisionalSubjectPattern.MatchString(d.SubjectRef) || !javaReferencePattern.MatchString(d.JavaRef) || !isDigest(d.DisagreementDigest) {
		return finding("INVALID_BEHAVIOR_DELTA", "$", "delta identity, subject, Java reference, or disagreement digest is invalid")
	}
	if d.NormativeAuthority != "rfc6455" {
		return finding("INVALID_ORACLE_AUTHORITY", "$.normative_authority", "RFC 6455 must remain normative over Java and Autobahn observations")
	}
	if d.Disposition != "unresolved" && d.Disposition != "rfc-governs" {
		return finding("INVALID_BEHAVIOR_DELTA", "$.disposition", "disposition is outside the stable provisional vocabulary")
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
	derived, err := (ObservedDisagreement{SubjectRef: d.SubjectRef, RFCRefs: d.RFCRefs, JavaRef: d.JavaRef, AutobahnRefs: d.AutobahnRefs}).Digest()
	if err != nil {
		return err
	}
	if derived != d.DisagreementDigest {
		return finding("BEHAVIOR_DELTA_BINDING_MISMATCH", "$.disagreement_digest", "digest does not bind the stable subject and oracle references")
	}
	return nil
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
	SubjectRef   string   `json:"subject_ref"`
	RFCRefs      []string `json:"rfc_refs"`
	JavaRef      string   `json:"java_ref"`
	AutobahnRefs []string `json:"autobahn_refs"`
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
