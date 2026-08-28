package benchplan

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"reflect"
)

const RawLedgerEntrySchema = "vjwp-benchmark-raw-ledger-entry/1.0.0"

const (
	RecordBindingClosure = "BINDING_CLOSURE"
	RecordEndpoint       = "ENDPOINT"
	RecordSupport        = "WORKLOAD_SUPPORT"
	SupportSchema        = "vjwp-benchmark-workload-support/1.0.0"
	maxRawLedgerBytes    = 64 << 20
	maxRawPayloadBytes   = 4 << 20
)

var completeLedgerRecords = 1 + len(WorkloadIDs)*len(MetricNames) + len(WorkloadIDs)

type WorkloadBinding struct {
	WorkloadID       string `json:"workload_id"`
	DefinitionDigest string `json:"definition_digest"`
	PairOrderDigest  string `json:"pair_order_digest"`
}

type BindingClosure struct {
	PlanDigest                    string            `json:"plan_digest"`
	PrimaryEnvironmentDigest      string            `json:"primary_environment_digest"`
	PrimaryHostDigest             string            `json:"primary_host_digest"`
	ConfirmationEnvironmentDigest string            `json:"confirmation_environment_digest"`
	ConfirmationHostDigest        string            `json:"confirmation_host_digest"`
	JavaSourceDigest              string            `json:"java_source_digest"`
	JavaExecutableDigest          string            `json:"java_executable_digest"`
	JavaDependencyLockDigest      string            `json:"java_dependency_lock_digest"`
	RustSourceDigest              string            `json:"rust_source_digest"`
	RustExecutableDigest          string            `json:"rust_executable_digest"`
	RustDependencyLockDigest      string            `json:"rust_dependency_lock_digest"`
	AdapterDigest                 string            `json:"adapter_digest"`
	MeasurementToolManifestDigest string            `json:"measurement_tool_manifest_digest"`
	AnalyzerDigest                string            `json:"analyzer_digest"`
	Workloads                     []WorkloadBinding `json:"workloads"`
	SBXInsideMeasurementBoundary  bool              `json:"sbx_inside_measurement_boundary"`
}

// VerifiedClosureFacts are independently opened and verified repository,
// environment, host, source, executable, dependency-lock, adapter, tool, and
// analyzer bytes. Raw-ledger bytes are never an input to this seam.
type VerifiedClosureFacts struct {
	Plan                    []byte
	PrimaryEnvironment      []byte
	PrimaryHost             []byte
	ConfirmationEnvironment []byte
	ConfirmationHost        []byte
	JavaSource              []byte
	JavaExecutable          []byte
	JavaDependencyLock      []byte
	RustSource              []byte
	RustExecutable          []byte
	RustDependencyLock      []byte
	Adapter                 []byte
	MeasurementToolManifest []byte
	Analyzer                []byte
	WorkloadDefinitions     [6][]byte
}

// DeriveExpectedBindingClosure hashes the independently verified fact set and
// derives the frozen six workload pair-order identities. The returned closure
// is the bound-side value every ledger must match exactly.
func DeriveExpectedBindingClosure(facts VerifiedClosureFacts) (BindingClosure, error) {
	values := [][]byte{
		facts.Plan, facts.PrimaryEnvironment, facts.PrimaryHost,
		facts.ConfirmationEnvironment, facts.ConfirmationHost,
		facts.JavaSource, facts.JavaExecutable, facts.JavaDependencyLock,
		facts.RustSource, facts.RustExecutable, facts.RustDependencyLock,
		facts.Adapter, facts.MeasurementToolManifest, facts.Analyzer,
	}
	for i, value := range values {
		if len(value) == 0 {
			return BindingClosure{}, fmt.Errorf("verified closure fact %d is empty", i)
		}
	}
	closure := BindingClosure{
		PlanDigest:                    digestBytes(facts.Plan),
		PrimaryEnvironmentDigest:      digestBytes(facts.PrimaryEnvironment),
		PrimaryHostDigest:             digestBytes(facts.PrimaryHost),
		ConfirmationEnvironmentDigest: digestBytes(facts.ConfirmationEnvironment),
		ConfirmationHostDigest:        digestBytes(facts.ConfirmationHost),
		JavaSourceDigest:              digestBytes(facts.JavaSource),
		JavaExecutableDigest:          digestBytes(facts.JavaExecutable),
		JavaDependencyLockDigest:      digestBytes(facts.JavaDependencyLock),
		RustSourceDigest:              digestBytes(facts.RustSource),
		RustExecutableDigest:          digestBytes(facts.RustExecutable),
		RustDependencyLockDigest:      digestBytes(facts.RustDependencyLock),
		AdapterDigest:                 digestBytes(facts.Adapter),
		MeasurementToolManifestDigest: digestBytes(facts.MeasurementToolManifest),
		AnalyzerDigest:                digestBytes(facts.Analyzer),
		SBXInsideMeasurementBoundary:  false,
	}
	for i, workloadID := range WorkloadIDs {
		if len(facts.WorkloadDefinitions[i]) == 0 {
			return BindingClosure{}, fmt.Errorf("verified workload definition %d is empty", i)
		}
		order, err := PairOrder(workloadID)
		if err != nil {
			return BindingClosure{}, err
		}
		closure.Workloads = append(closure.Workloads, WorkloadBinding{
			WorkloadID:       workloadID,
			DefinitionDigest: digestBytes(facts.WorkloadDefinitions[i]),
			PairOrderDigest:  pairOrderDigest(order),
		})
	}
	return closure, validateBindingClosure(closure)
}

type GCEvent struct {
	TimestampSeconds float64 `json:"timestamp_seconds"`
	DurationSeconds  float64 `json:"duration_seconds"`
}

type SupportPosition struct {
	PairIndex      int       `json:"pair_index"`
	Order          string    `json:"order"`
	ExcludedWarmup bool      `json:"excluded_warmup"`
	JavaFDCount    int       `json:"java_fd_count"`
	RustFDCount    int       `json:"rust_fd_count"`
	JavaGCEvents   []GCEvent `json:"java_gc_events"`
}

type WorkloadSupport struct {
	Schema                string            `json:"schema"`
	EnvironmentRole       string            `json:"environment_role"`
	WorkloadID            string            `json:"workload_id"`
	CollectorOutputDigest string            `json:"collector_output_digest"`
	Positions             []SupportPosition `json:"positions"`
}

type RawLedgerEntry struct {
	Schema               string          `json:"schema"`
	EnvironmentRole      string          `json:"environment_role"`
	Sequence             uint64          `json:"sequence"`
	PreviousEntryDigest  string          `json:"previous_entry_digest"`
	PayloadDigest        string          `json:"payload_digest"`
	BindingClosureDigest string          `json:"binding_closure_digest"`
	RecordType           string          `json:"record_type"`
	Payload              json.RawMessage `json:"payload"`
}

type RawLedgerReceipt struct {
	State                string         `json:"state"`
	EnvironmentRole      string         `json:"environment_role"`
	Bytes                int64          `json:"bytes"`
	FileSHA256           string         `json:"file_sha256"`
	RecordCount          int            `json:"record_count"`
	TerminalEntryDigest  string         `json:"terminal_entry_digest"`
	BindingClosureDigest string         `json:"binding_closure_digest"`
	BundleOutcome        Outcome        `json:"bundle_outcome,omitempty"`
	Closure              BindingClosure `json:"-"`
}

func digestBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return fmt.Sprintf("sha256:%x", sum)
}

func pairOrderDigest(order []string) string {
	raw, _ := json.Marshal(order)
	return digestBytes(append([]byte("vjwp-us025-pair-order-v1\x00"), raw...))
}

func closureBindings(closure BindingClosure) BoundIdentities {
	return BoundIdentities{
		"plan_digest":                     closure.PlanDigest,
		"primary_environment_digest":      closure.PrimaryEnvironmentDigest,
		"confirmation_environment_digest": closure.ConfirmationEnvironmentDigest,
		"java_source_digest":              closure.JavaSourceDigest,
		"rust_source_digest":              closure.RustSourceDigest,
		"java_executable_digest":          closure.JavaExecutableDigest,
		"rust_executable_digest":          closure.RustExecutableDigest,
		"adapter_digest":                  closure.AdapterDigest,
		"tool_identity_digest":            closure.MeasurementToolManifestDigest,
		"analyzer_digest":                 closure.AnalyzerDigest,
	}
}

func validateBindingClosure(closure BindingClosure) error {
	digests := map[string]string{
		"plan_digest":                      closure.PlanDigest,
		"primary_environment_digest":       closure.PrimaryEnvironmentDigest,
		"primary_host_digest":              closure.PrimaryHostDigest,
		"confirmation_environment_digest":  closure.ConfirmationEnvironmentDigest,
		"confirmation_host_digest":         closure.ConfirmationHostDigest,
		"java_source_digest":               closure.JavaSourceDigest,
		"java_executable_digest":           closure.JavaExecutableDigest,
		"java_dependency_lock_digest":      closure.JavaDependencyLockDigest,
		"rust_source_digest":               closure.RustSourceDigest,
		"rust_executable_digest":           closure.RustExecutableDigest,
		"rust_dependency_lock_digest":      closure.RustDependencyLockDigest,
		"adapter_digest":                   closure.AdapterDigest,
		"measurement_tool_manifest_digest": closure.MeasurementToolManifestDigest,
		"analyzer_digest":                  closure.AnalyzerDigest,
	}
	for name, value := range digests {
		if !validDigest(value) {
			return fmt.Errorf("binding closure %s is not a nonzero SHA-256 digest", name)
		}
	}
	if closure.SBXInsideMeasurementBoundary {
		return errors.New("binding closure must state sbx_inside_measurement_boundary=false")
	}
	if len(closure.Workloads) != len(WorkloadIDs) {
		return fmt.Errorf("binding closure has %d workload bindings, want %d", len(closure.Workloads), len(WorkloadIDs))
	}
	for i, binding := range closure.Workloads {
		if binding.WorkloadID != WorkloadIDs[i] {
			return fmt.Errorf("binding closure workload %d is %q, want %q", i, binding.WorkloadID, WorkloadIDs[i])
		}
		if !validDigest(binding.DefinitionDigest) {
			return fmt.Errorf("workload %s definition digest is invalid", binding.WorkloadID)
		}
		order, err := PairOrder(binding.WorkloadID)
		if err != nil {
			return err
		}
		if binding.PairOrderDigest != pairOrderDigest(order) {
			return fmt.Errorf("workload %s pair-order digest mismatch", binding.WorkloadID)
		}
	}
	return nil
}

func validateSupport(support WorkloadSupport, role, workloadID string) error {
	if support.Schema != SupportSchema || support.EnvironmentRole != role || support.WorkloadID != workloadID {
		return fmt.Errorf("support identity %q/%q/%q does not match %q/%q", support.Schema, support.EnvironmentRole, support.WorkloadID, role, workloadID)
	}
	if !validDigest(support.CollectorOutputDigest) {
		return errors.New("support collector_output_digest is invalid")
	}
	if len(support.Positions) != TotalPairs {
		return fmt.Errorf("support position count %d, want %d", len(support.Positions), TotalPairs)
	}
	order, err := PairOrder(workloadID)
	if err != nil {
		return err
	}
	for i, position := range support.Positions {
		if position.PairIndex != i || position.Order != order[i] || position.ExcludedWarmup != (i < WarmupPairs) {
			return fmt.Errorf("support position %d identity/order/warmup mismatch", i)
		}
		if position.JavaFDCount <= 0 || position.RustFDCount <= 0 {
			return fmt.Errorf("support position %d FD counts must be positive", i)
		}
		if position.JavaGCEvents == nil {
			return fmt.Errorf("support position %d must carry an observed GC-event list", i)
		}
		for j, event := range position.JavaGCEvents {
			if math.IsNaN(event.TimestampSeconds) || math.IsInf(event.TimestampSeconds, 0) || event.TimestampSeconds < 0 || !isFinitePositive(event.DurationSeconds) {
				return fmt.Errorf("support position %d GC event %d is nonfinite, negative, or nonpositive", i, j)
			}
		}
	}
	return nil
}

func decodeStrictJSON(raw []byte, target any) error {
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("trailing JSON content")
	}
	return nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var visit func() error
	visit = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("object key is not a string")
				}
				if seen[key] {
					return fmt.Errorf("duplicate JSON field %q", key)
				}
				seen[key] = true
				if err := visit(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := visit(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return errors.New("unexpected JSON delimiter")
		}
	}
	if err := visit(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON content")
		}
		return err
	}
	return nil
}

func validatePayloadForPosition(payload []byte, role, recordType string, position int, expectedClosure *BindingClosure) (BindingClosure, error) {
	wantType := RecordBindingClosure
	if position > 0 && position <= len(WorkloadIDs)*len(MetricNames) {
		wantType = RecordEndpoint
	} else if position > len(WorkloadIDs)*len(MetricNames) && position < completeLedgerRecords {
		wantType = RecordSupport
	} else if position >= completeLedgerRecords {
		return BindingClosure{}, errors.New("ledger is already complete; extra post-completion entry is forbidden")
	}
	if recordType != wantType {
		return BindingClosure{}, fmt.Errorf("record %d type %q, want %q", position, recordType, wantType)
	}
	switch recordType {
	case RecordBindingClosure:
		var closure BindingClosure
		if err := decodeStrictJSON(payload, &closure); err != nil {
			return closure, fmt.Errorf("binding closure decode: %w", err)
		}
		if err := validateBindingClosure(closure); err != nil {
			return closure, err
		}
		if expectedClosure != nil && !reflect.DeepEqual(closure, *expectedClosure) {
			return closure, errors.New("binding closure disagrees with the independently bound closure")
		}
		return closure, nil
	case RecordEndpoint:
		var sample SampleSet
		if err := decodeStrictJSON(payload, &sample); err != nil {
			return BindingClosure{}, fmt.Errorf("endpoint decode: %w", err)
		}
		endpointIndex := position - 1
		workloadID := WorkloadIDs[endpointIndex/len(MetricNames)]
		metric := MetricNames[endpointIndex%len(MetricNames)]
		if sample.Schema != "vjwp-benchmark-raw-sample/1.0.0" || sample.ProvenanceLabel != LabelMeasured || sample.EnvironmentRole != role || sample.WorkloadID != workloadID || sample.Metric != metric {
			return BindingClosure{}, fmt.Errorf("endpoint %d identity/order disagrees with %s/%s/%s", position, role, workloadID, metric)
		}
		if expectedClosure == nil {
			return BindingClosure{}, errors.New("endpoint cannot be validated without the preceding binding closure")
		}
		endpointDecision := DecideEndpoint(sample, closureBindings(*expectedClosure))
		if endpointDecision.Outcome == OutcomeBlocked || endpointDecision.Analysis == nil {
			return BindingClosure{}, fmt.Errorf("endpoint %d fails the frozen validator: %s %v", position, endpointDecision.Outcome, endpointDecision.Reasons)
		}
	case RecordSupport:
		var support WorkloadSupport
		if err := decodeStrictJSON(payload, &support); err != nil {
			return BindingClosure{}, fmt.Errorf("support decode: %w", err)
		}
		workloadID := WorkloadIDs[position-1-len(WorkloadIDs)*len(MetricNames)]
		if err := validateSupport(support, role, workloadID); err != nil {
			return BindingClosure{}, err
		}
	}
	return BindingClosure{}, nil
}

func verifyRawLedgerBytes(content []byte, role string, expectedClosure BindingClosure) (RawLedgerReceipt, error) {
	var receipt RawLedgerReceipt
	if role != EnvironmentRolePrimary && role != EnvironmentRoleConfirmation {
		return receipt, fmt.Errorf("environment role %q is invalid", role)
	}
	if len(content) == 0 {
		return receipt, errors.New("empty raw ledger is PRESENT_INVALID, not ABSENT")
	}
	if len(content) > maxRawLedgerBytes {
		return receipt, errors.New("raw ledger exceeds byte bound")
	}
	if content[len(content)-1] != '\n' {
		return receipt, errors.New("raw ledger has a truncated final line")
	}
	lines := bytes.Split(content[:len(content)-1], []byte{'\n'})
	if len(lines) > completeLedgerRecords {
		return receipt, errors.New("raw ledger contains an extra post-completion entry")
	}
	bundle := EvidenceBundle{Schema: EvidenceBundleSchema, ProvenanceLabel: LabelMeasured, EnvironmentRole: role}
	rawRecords := map[string][]byte{}
	previousDigest := zeroDigest
	closureDigest := ""
	var closure BindingClosure
	for i, line := range lines {
		if len(line) == 0 || len(line) > maxRawPayloadBytes {
			return receipt, fmt.Errorf("ledger line %d is empty or exceeds its byte bound", i)
		}
		var entry RawLedgerEntry
		if err := decodeStrictJSON(line, &entry); err != nil {
			return receipt, fmt.Errorf("ledger line %d strict decode: %w", i, err)
		}
		if entry.Schema != RawLedgerEntrySchema || entry.EnvironmentRole != role || entry.Sequence != uint64(i) {
			return receipt, fmt.Errorf("ledger line %d schema/role/sequence mismatch", i)
		}
		if entry.PreviousEntryDigest != previousDigest {
			return receipt, fmt.Errorf("ledger line %d previous-entry digest mismatch", i)
		}
		if entry.PayloadDigest != digestBytes(entry.Payload) {
			return receipt, fmt.Errorf("ledger line %d payload digest mismatch", i)
		}
		boundClosure := &expectedClosure
		if i > 0 {
			boundClosure = &closure
		}
		parsedClosure, err := validatePayloadForPosition(entry.Payload, role, entry.RecordType, i, boundClosure)
		if err != nil {
			return receipt, fmt.Errorf("ledger line %d: %w", i, err)
		}
		if i == 0 {
			closure = parsedClosure
			closureDigest = entry.PayloadDigest
		}
		if entry.BindingClosureDigest != closureDigest {
			return receipt, fmt.Errorf("ledger line %d binding-closure digest mismatch", i)
		}
		if entry.RecordType == RecordEndpoint {
			var sample SampleSet
			if err := decodeStrictJSON(entry.Payload, &sample); err != nil {
				return receipt, err
			}
			rawCopy := append([]byte(nil), entry.Payload...)
			rawRecords[entry.PayloadDigest] = rawCopy
			bundle.Endpoints = append(bundle.Endpoints, EvidenceEndpoint{WorkloadID: sample.WorkloadID, Metric: sample.Metric, RawRecordDigest: entry.PayloadDigest})
		}
		previousDigest = digestBytes(line)
	}
	receipt = RawLedgerReceipt{
		State:                RawPresentPartial,
		EnvironmentRole:      role,
		Bytes:                int64(len(content)),
		FileSHA256:           digestBytes(content),
		RecordCount:          len(lines),
		TerminalEntryDigest:  previousDigest,
		BindingClosureDigest: closureDigest,
		Closure:              closure,
	}
	if len(lines) == completeLedgerRecords {
		decision := DecideEvidenceBundle(bundle, rawRecords, closureBindings(closure))
		if decision.Outcome == OutcomeBlocked {
			return receipt, fmt.Errorf("complete ledger endpoint bundle is blocked: %v", decision.Reasons)
		}
		receipt.State = RawPresentComplete
		receipt.BundleOutcome = decision.Outcome
	}
	return receipt, nil
}

type rawLedgerWriter func(*os.File, []byte) (int, error)

type secureLedgerRepository struct {
	repository *os.Root
	raw        *os.Root
}

func rejectSymlinkedPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	clean := filepath.Clean(absolute)
	info, err := os.Lstat(clean)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("repository root is a symlink: %s", clean)
	}
	canonical, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return "", err
	}
	return canonical, nil
}

func openSecureLedgerRepository(repositoryRoot string, createRaw bool) (*secureLedgerRepository, error) {
	clean, err := rejectSymlinkedPath(repositoryRoot)
	if err != nil {
		return nil, err
	}
	pathInfo, err := os.Lstat(clean)
	if err != nil || !pathInfo.IsDir() {
		return nil, fmt.Errorf("repository root is not a directory: %w", err)
	}
	repository, err := os.OpenRoot(clean)
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*secureLedgerRepository, error) {
		_ = repository.Close()
		return nil, cause
	}
	heldInfo, err := repository.Stat(".")
	if err != nil || !os.SameFile(pathInfo, heldInfo) {
		return fail(errors.New("repository root changed while being opened"))
	}
	benchmarksInfo, err := repository.Lstat("benchmarks")
	if err != nil || !benchmarksInfo.IsDir() || benchmarksInfo.Mode()&os.ModeSymlink != 0 {
		return fail(errors.New("benchmarks must be a regular directory beneath the held repository root"))
	}
	rawInfo, err := repository.Lstat("benchmarks/raw")
	if errors.Is(err, os.ErrNotExist) && createRaw {
		if err := repository.Mkdir("benchmarks/raw", 0o700); err != nil {
			return fail(err)
		}
		if err := syncRootDirectory(repository, "benchmarks"); err != nil {
			return fail(err)
		}
		rawInfo, err = repository.Lstat("benchmarks/raw")
	}
	if errors.Is(err, os.ErrNotExist) {
		return &secureLedgerRepository{repository: repository}, nil
	}
	if err != nil || !rawInfo.IsDir() || rawInfo.Mode()&os.ModeSymlink != 0 {
		return fail(errors.New("benchmarks/raw must be a regular non-symlink directory"))
	}
	raw, err := repository.OpenRoot("benchmarks/raw")
	if err != nil {
		return fail(err)
	}
	heldRawInfo, err := raw.Stat(".")
	if err != nil || !os.SameFile(rawInfo, heldRawInfo) {
		_ = raw.Close()
		return fail(errors.New("benchmarks/raw changed while being opened"))
	}
	return &secureLedgerRepository{repository: repository, raw: raw}, nil
}

func (repository *secureLedgerRepository) close() {
	if repository.raw != nil {
		_ = repository.raw.Close()
	}
	_ = repository.repository.Close()
}

func syncRootDirectory(root *os.Root, name string) error {
	directory, err := root.Open(name)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func readHeldRepositoryFile(root *os.Root, name string, limit int64) ([]byte, error) {
	file, err := openHeldRegular(root, name, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() <= 0 || info.Size() > limit {
		return nil, fmt.Errorf("repository fact %s is empty or exceeds its byte bound", name)
	}
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(content)) != info.Size() {
		return nil, fmt.Errorf("repository fact %s changed while held", name)
	}
	return content, nil
}

func secureTreeFact(root *os.Root, directory string) ([]byte, error) {
	var fact bytes.Buffer
	err := fs.WalkDir(root.FS(), directory, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == directory {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("repository fact tree contains symlink %s", name)
		}
		if entry.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("repository fact tree contains nonregular file %s", name)
		}
		content, err := readHeldRepositoryFile(root, name, 16<<20)
		if err != nil {
			return err
		}
		fmt.Fprintf(&fact, "%s\x00%s\x00%d\n", name, digestBytes(content), len(content))
		return nil
	})
	if err != nil {
		return nil, err
	}
	if fact.Len() == 0 {
		return nil, fmt.Errorf("repository fact tree %s is empty", directory)
	}
	return fact.Bytes(), nil
}

func boundToolFact(primary, confirmation environmentDocument, name string) ([]byte, string, error) {
	left, leftPresent := primary.ToolIdentities[name]
	right, rightPresent := confirmation.ToolIdentities[name]
	if !leftPresent || !rightPresent || left.Status != "BOUND" || right.Status != "BOUND" || len(left.Value) == 0 || !bytes.Equal(left.Value, right.Value) {
		return nil, "", fmt.Errorf("bound tool fact %s is absent or differs between hosts", name)
	}
	var digestValue string
	if json.Unmarshal(left.Value, &digestValue) == nil && validDigest(digestValue) {
		return append([]byte(nil), left.Value...), digestValue, nil
	}
	return append([]byte(nil), left.Value...), digestBytes(left.Value), nil
}

// DeriveRepositoryExpectedBindingClosure derives the bound-side closure from
// the verified repository and both BOUND environment documents. The current
// unbound tree fails before any raw or payload operation.
func DeriveRepositoryExpectedBindingClosure(repositoryRoot string) (BindingClosure, error) {
	report, err := Verify(repositoryRoot)
	if err != nil {
		return BindingClosure{}, err
	}
	if !report.FullyBound() {
		return BindingClosure{}, errors.New("both verified environment documents must be BOUND before expected-closure derivation")
	}
	repository, err := openSecureLedgerRepository(repositoryRoot, false)
	if err != nil {
		return BindingClosure{}, err
	}
	defer repository.close()
	plan, err := readHeldRepositoryFile(repository.repository, "benchmarks/plan/workloads.json", 4<<20)
	if err != nil {
		return BindingClosure{}, err
	}
	primaryRaw, err := readHeldRepositoryFile(repository.repository, "benchmarks/environments/primary-macos.json", 4<<20)
	if err != nil {
		return BindingClosure{}, err
	}
	confirmationRaw, err := readHeldRepositoryFile(repository.repository, "benchmarks/environments/confirmation.json", 4<<20)
	if err != nil {
		return BindingClosure{}, err
	}
	var primary, confirmation environmentDocument
	if err := json.Unmarshal(primaryRaw, &primary); err != nil {
		return BindingClosure{}, err
	}
	if err := json.Unmarshal(confirmationRaw, &confirmation); err != nil {
		return BindingClosure{}, err
	}
	primaryHost, err := json.Marshal(primary.HostIdentity)
	if err != nil {
		return BindingClosure{}, err
	}
	confirmationHost, err := json.Marshal(confirmation.HostIdentity)
	if err != nil {
		return BindingClosure{}, err
	}
	javaSource, err := secureTreeFact(repository.repository, "java-oracle/src/main/java")
	if err != nil {
		return BindingClosure{}, err
	}
	rustCoreSource, err := secureTreeFact(repository.repository, "rust/connection-core/src")
	if err != nil {
		return BindingClosure{}, err
	}
	rustDriverSource, err := secureTreeFact(repository.repository, "rust/websocket-driver/src")
	if err != nil {
		return BindingClosure{}, err
	}
	rustTesteeSource, err := secureTreeFact(repository.repository, "rust/websocket-testee/src")
	if err != nil {
		return BindingClosure{}, err
	}
	rustSource := bytes.Join([][]byte{rustCoreSource, rustDriverSource, rustTesteeSource}, []byte{0})
	adapter, err := secureTreeFact(repository.repository, "cmd/benchrunner")
	if err != nil {
		return BindingClosure{}, err
	}
	javaLock, err := readHeldRepositoryFile(repository.repository, "java-oracle/pom.xml", 4<<20)
	if err != nil {
		return BindingClosure{}, err
	}
	rustLock, err := readHeldRepositoryFile(repository.repository, "rust/Cargo.lock", 16<<20)
	if err != nil {
		return BindingClosure{}, err
	}
	javaExecutableFact, javaExecutableDigest, err := boundToolFact(primary, confirmation, "java_executable_digest")
	if err != nil {
		return BindingClosure{}, err
	}
	rustExecutableFact, rustExecutableDigest, err := boundToolFact(primary, confirmation, "rust_executable_digest")
	if err != nil {
		return BindingClosure{}, err
	}
	adapterFact, adapterDigest, err := boundToolFact(primary, confirmation, "load_driver")
	if err != nil {
		return BindingClosure{}, err
	}
	toolFact, toolDigest, err := boundToolFact(primary, confirmation, "measurement_tools")
	if err != nil {
		return BindingClosure{}, err
	}
	analyzerFact, analyzerDigest, err := boundToolFact(primary, confirmation, "analyzer")
	if err != nil {
		return BindingClosure{}, err
	}
	var planWorkloads struct {
		Workloads []json.RawMessage `json:"workloads"`
	}
	if err := json.Unmarshal(plan, &planWorkloads); err != nil {
		return BindingClosure{}, err
	}
	if len(planWorkloads.Workloads) != len(WorkloadIDs) {
		return BindingClosure{}, errors.New("verified plan workload denominator drift")
	}
	facts := VerifiedClosureFacts{
		Plan: plan, PrimaryEnvironment: primaryRaw, PrimaryHost: primaryHost,
		ConfirmationEnvironment: confirmationRaw, ConfirmationHost: confirmationHost,
		JavaSource: javaSource, JavaExecutable: javaExecutableFact, JavaDependencyLock: javaLock,
		RustSource: rustSource, RustExecutable: rustExecutableFact, RustDependencyLock: rustLock,
		Adapter: append(adapter, adapterFact...), MeasurementToolManifest: toolFact, Analyzer: analyzerFact,
	}
	for i := range planWorkloads.Workloads {
		facts.WorkloadDefinitions[i] = planWorkloads.Workloads[i]
	}
	closure, err := DeriveExpectedBindingClosure(facts)
	if err != nil {
		return BindingClosure{}, err
	}
	closure.JavaExecutableDigest = javaExecutableDigest
	closure.RustExecutableDigest = rustExecutableDigest
	closure.AdapterDigest = adapterDigest
	closure.MeasurementToolManifestDigest = toolDigest
	closure.AnalyzerDigest = analyzerDigest
	return closure, validateBindingClosure(closure)
}

func ledgerFilename(role string) (string, error) {
	switch role {
	case EnvironmentRolePrimary:
		return "primary.jsonl", nil
	case EnvironmentRoleConfirmation:
		return "confirmation.jsonl", nil
	default:
		return "", fmt.Errorf("environment role %q is invalid", role)
	}
}

func openHeldRegular(root *os.Root, name string, flags int, perm os.FileMode) (*os.File, error) {
	before, lstatErr := root.Lstat(name)
	if lstatErr == nil && before.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s must not be a symlink", name)
	}
	file, err := root.OpenFile(name, flags, perm)
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("%s is not a held regular file", name)
	}
	if lstatErr == nil && !os.SameFile(before, after) {
		_ = file.Close()
		return nil, fmt.Errorf("%s changed while being opened", name)
	}
	if lstatErr != nil && !errors.Is(lstatErr, os.ErrNotExist) {
		_ = file.Close()
		return nil, lstatErr
	}
	return file, nil
}

func verifyHeldRawLedger(file *os.File, role string, expected BindingClosure) (RawLedgerReceipt, error) {
	var receipt RawLedgerReceipt
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() {
		return receipt, errors.New("raw ledger is not a regular held file")
	}
	if before.Size() <= 0 || before.Size() > maxRawLedgerBytes {
		return receipt, errors.New("raw ledger is empty or exceeds its byte bound")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return receipt, err
	}
	content, err := io.ReadAll(io.LimitReader(file, maxRawLedgerBytes+1))
	if err != nil {
		return receipt, err
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || int64(len(content)) != after.Size() {
		return receipt, errors.New("raw ledger changed while held and being read")
	}
	return verifyRawLedgerBytes(content, role, expected)
}

// VerifyRawLedger securely opens and verifies one role's ledger beneath a
// held repository/raw root against an independently derived expected closure.
func VerifyRawLedger(repositoryRoot, role string, expected BindingClosure) (RawLedgerReceipt, error) {
	if err := validateBindingClosure(expected); err != nil {
		return RawLedgerReceipt{}, fmt.Errorf("expected closure: %w", err)
	}
	filename, err := ledgerFilename(role)
	if err != nil {
		return RawLedgerReceipt{}, err
	}
	repository, err := openSecureLedgerRepository(repositoryRoot, false)
	if err != nil {
		return RawLedgerReceipt{}, err
	}
	defer repository.close()
	if repository.raw == nil {
		return RawLedgerReceipt{}, os.ErrNotExist
	}
	file, err := openHeldRegular(repository.raw, filename, os.O_RDONLY, 0)
	if err != nil {
		return RawLedgerReceipt{}, err
	}
	defer file.Close()
	return verifyHeldRawLedger(file, role, expected)
}

// AppendBoundRawLedger serializes one canonical entry under an adjacent
// exclusive lock. The first record must equal the independently expected
// closure; every later verification retains that same binding.
func AppendBoundRawLedger(repositoryRoot, role string, expected BindingClosure, recordType string, payload []byte) (RawLedgerReceipt, error) {
	return appendBoundRawLedger(repositoryRoot, role, expected, recordType, payload, func(file *os.File, line []byte) (int, error) {
		return file.Write(line)
	})
}

func appendBoundRawLedger(repositoryRoot, role string, expected BindingClosure, recordType string, payload []byte, write rawLedgerWriter) (receipt RawLedgerReceipt, resultErr error) {
	if role != EnvironmentRolePrimary && role != EnvironmentRoleConfirmation {
		return receipt, fmt.Errorf("environment role %q is invalid", role)
	}
	if err := validateBindingClosure(expected); err != nil {
		return receipt, fmt.Errorf("expected closure: %w", err)
	}
	if len(payload) == 0 || len(payload) > maxRawPayloadBytes {
		return receipt, errors.New("raw payload is empty or exceeds its byte bound")
	}
	// Reject a forged or non-closure first payload before clean-tree directory
	// creation. Existing-ledger position is resolved only after lock ownership.
	var prospective BindingClosure
	if recordType == RecordBindingClosure {
		var err error
		prospective, err = validatePayloadForPosition(payload, role, recordType, 0, &expected)
		if err != nil {
			return receipt, err
		}
		_ = prospective
	}
	filename, err := ledgerFilename(role)
	if err != nil {
		return receipt, err
	}
	repository, err := openSecureLedgerRepository(repositoryRoot, true)
	if err != nil {
		return receipt, err
	}
	defer repository.close()
	lockName := filename + ".lock"
	lock, err := repository.raw.OpenFile(lockName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return receipt, fmt.Errorf("raw ledger lock acquisition failed: %w", err)
	}
	if err := lock.Close(); err != nil {
		return receipt, err
	}
	preserveLock := false
	defer func() {
		if !preserveLock {
			if removeErr := repository.raw.Remove(lockName); resultErr == nil && removeErr != nil {
				resultErr = removeErr
			}
			if resultErr == nil {
				resultErr = syncRootDirectory(repository.raw, ".")
			}
		}
	}()

	position := 0
	previousDigest := zeroDigest
	closureDigest := ""
	currentClosure := &expected
	_, statErr := repository.raw.Lstat(filename)
	existing := statErr == nil
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return receipt, statErr
	}
	flags := os.O_RDWR | os.O_APPEND
	if !existing {
		flags |= os.O_CREATE | os.O_EXCL
	}
	file, err := openHeldRegular(repository.raw, filename, flags, 0o600)
	if err != nil {
		return receipt, err
	}
	defer func() {
		if closeErr := file.Close(); resultErr == nil && closeErr != nil {
			resultErr = closeErr
		}
	}()
	if !existing {
		if err := syncRootDirectory(repository.raw, "."); err != nil {
			return receipt, err
		}
	}
	if existing {
		current, err := verifyHeldRawLedger(file, role, expected)
		if err != nil {
			return receipt, err
		}
		position = current.RecordCount
		previousDigest = current.TerminalEntryDigest
		closureDigest = current.BindingClosureDigest
	}
	parsedClosure, err := validatePayloadForPosition(payload, role, recordType, position, currentClosure)
	if err != nil {
		return receipt, err
	}
	payloadDigest := digestBytes(payload)
	if position == 0 {
		closureDigest = payloadDigest
		_ = parsedClosure
	}
	entry := RawLedgerEntry{
		Schema:               RawLedgerEntrySchema,
		EnvironmentRole:      role,
		Sequence:             uint64(position),
		PreviousEntryDigest:  previousDigest,
		PayloadDigest:        payloadDigest,
		BindingClosureDigest: closureDigest,
		RecordType:           recordType,
		Payload:              append(json.RawMessage(nil), payload...),
	}
	encoded, err := json.Marshal(entry)
	if err != nil {
		return receipt, err
	}
	encoded = append(encoded, '\n')
	preserveLock = true
	written, writeErr := write(file, encoded)
	if writeErr == nil && written != len(encoded) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	if writeErr != nil {
		return receipt, writeErr
	}
	receipt, err = verifyHeldRawLedger(file, role, expected)
	if err != nil {
		return receipt, err
	}
	preserveLock = false
	return receipt, nil
}
