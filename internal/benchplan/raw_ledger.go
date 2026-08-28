package benchplan

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// VerifyRawLedger verifies an exact newline-terminated hash chain. Valid
// prefixes remain PRESENT_PARTIAL evidence; malformed, shortened, reordered,
// replaced, or post-completion data returns an error and is never repaired.
func VerifyRawLedger(path, role string, expectedClosure *BindingClosure) (RawLedgerReceipt, error) {
	var receipt RawLedgerReceipt
	if role != EnvironmentRolePrimary && role != EnvironmentRoleConfirmation {
		return receipt, fmt.Errorf("environment role %q is invalid", role)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return receipt, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return receipt, errors.New("raw ledger must be a regular non-symlink file")
	}
	if info.Size() <= 0 {
		return receipt, errors.New("empty raw ledger is PRESENT_INVALID, not ABSENT")
	}
	if info.Size() > maxRawLedgerBytes {
		return receipt, errors.New("raw ledger exceeds byte bound")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return receipt, err
	}
	if int64(len(content)) != info.Size() {
		return receipt, errors.New("raw ledger changed while being read")
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
		boundClosure := expectedClosure
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

// AppendRawLedger serializes one canonical entry under an adjacent exclusive
// lock. It never truncates or repairs evidence and fsyncs every successful
// append before releasing ownership.
func AppendRawLedger(path, role, recordType string, payload []byte) (RawLedgerReceipt, error) {
	return appendRawLedger(path, role, recordType, payload, func(file *os.File, line []byte) (int, error) {
		return file.Write(line)
	})
}

func appendRawLedger(path, role, recordType string, payload []byte, write rawLedgerWriter) (receipt RawLedgerReceipt, resultErr error) {
	if role != EnvironmentRolePrimary && role != EnvironmentRoleConfirmation {
		return receipt, fmt.Errorf("environment role %q is invalid", role)
	}
	if len(payload) == 0 || len(payload) > maxRawPayloadBytes {
		return receipt, errors.New("raw payload is empty or exceeds its byte bound")
	}
	lockPath := path + ".lock"
	lock, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return receipt, fmt.Errorf("raw ledger lock acquisition failed: %w", err)
	}
	if err := lock.Close(); err != nil {
		return receipt, err
	}
	preserveLock := false
	defer func() {
		if !preserveLock {
			if removeErr := os.Remove(lockPath); resultErr == nil && removeErr != nil {
				resultErr = removeErr
			}
		}
	}()

	position := 0
	previousDigest := zeroDigest
	closureDigest := ""
	var currentClosure *BindingClosure
	_, statErr := os.Lstat(path)
	existing := statErr == nil
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return receipt, statErr
	}
	if existing {
		current, err := VerifyRawLedger(path, role, nil)
		if err != nil {
			return receipt, err
		}
		position = current.RecordCount
		previousDigest = current.TerminalEntryDigest
		closureDigest = current.BindingClosureDigest
		currentClosure = &current.Closure
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
	flags := os.O_WRONLY | os.O_APPEND
	if !existing {
		flags |= os.O_CREATE | os.O_EXCL
	}
	file, err := os.OpenFile(filepath.Clean(path), flags, 0o600)
	if err != nil {
		return receipt, err
	}
	preserveLock = true
	written, writeErr := write(file, encoded)
	if writeErr == nil && written != len(encoded) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil {
		return receipt, writeErr
	}
	if closeErr != nil {
		return receipt, closeErr
	}
	receipt, err = VerifyRawLedger(path, role, nil)
	if err != nil {
		return receipt, err
	}
	preserveLock = false
	return receipt, nil
}
