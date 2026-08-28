package benchplan

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
)

func syntheticLedgerClosure(t *testing.T) BindingClosure {
	t.Helper()
	old := syntheticClosure()
	closure := BindingClosure{
		PlanDigest:                    old["plan_digest"],
		PrimaryEnvironmentDigest:      old["primary_environment_digest"],
		PrimaryHostDigest:             syntheticDigest("primary_host_digest"),
		ConfirmationEnvironmentDigest: old["confirmation_environment_digest"],
		ConfirmationHostDigest:        syntheticDigest("confirmation_host_digest"),
		JavaSourceDigest:              old["java_source_digest"],
		JavaExecutableDigest:          old["java_executable_digest"],
		JavaDependencyLockDigest:      syntheticDigest("java_dependency_lock_digest"),
		RustSourceDigest:              old["rust_source_digest"],
		RustExecutableDigest:          old["rust_executable_digest"],
		RustDependencyLockDigest:      syntheticDigest("rust_dependency_lock_digest"),
		AdapterDigest:                 old["adapter_digest"],
		MeasurementToolManifestDigest: old["tool_identity_digest"],
		AnalyzerDigest:                old["analyzer_digest"],
		SBXInsideMeasurementBoundary:  false,
	}
	for _, workloadID := range WorkloadIDs {
		order, err := PairOrder(workloadID)
		if err != nil {
			t.Fatal(err)
		}
		closure.Workloads = append(closure.Workloads, WorkloadBinding{
			WorkloadID:       workloadID,
			DefinitionDigest: syntheticDigest(workloadID + "|definition"),
			PairOrderDigest:  pairOrderDigest(order),
		})
	}
	return closure
}

func TestRawLedgerWriterIsExclusiveAndVerifierRetainsPartial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "primary.jsonl")
	payload, err := json.Marshal(syntheticLedgerClosure(t))
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errors := make(chan error, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			_, appendErr := AppendRawLedger(path, EnvironmentRolePrimary, RecordBindingClosure, payload)
			errors <- appendErr
		}()
	}
	close(start)
	workers.Wait()
	close(errors)
	succeeded := 0
	for appendErr := range errors {
		if appendErr == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("successful writers = %d, want exactly one", succeeded)
	}
	if _, err := os.Lstat(path + ".lock"); !os.IsNotExist(err) {
		t.Fatalf("clean writer left adjacent lock: %v", err)
	}
	receipt, err := VerifyRawLedger(path, EnvironmentRolePrimary, nil)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.State != RawPresentPartial || receipt.RecordCount != 1 || receipt.TerminalEntryDigest == "" || receipt.FileSHA256 == "" {
		t.Fatalf("partial receipt = %+v", receipt)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	root := copyBenchmarkTree(t)
	if err := os.WriteFile(filepath.Join(root, "entry.json"), bytes.TrimSuffix(content, []byte{'\n'}), 0o600); err != nil {
		t.Fatal(err)
	}
	failures, err := validateAgainstSchema(root, "entry.json", "benchmark-raw-ledger-entry-1.0.0.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) != 0 {
		t.Fatalf("raw-ledger entry schema failures: %v", failures)
	}
}

func appendClosure(t *testing.T, path, role string, closure BindingClosure) RawLedgerReceipt {
	t.Helper()
	payload, err := json.Marshal(closure)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := AppendRawLedger(path, role, RecordBindingClosure, payload)
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func supportPayload(t *testing.T, role, workloadID string) []byte {
	t.Helper()
	order, err := PairOrder(workloadID)
	if err != nil {
		t.Fatal(err)
	}
	support := WorkloadSupport{
		Schema:                SupportSchema,
		EnvironmentRole:       role,
		WorkloadID:            workloadID,
		CollectorOutputDigest: syntheticDigest(role + "|" + workloadID + "|collector-output"),
	}
	for i := range TotalPairs {
		support.Positions = append(support.Positions, SupportPosition{
			PairIndex:      i,
			Order:          order[i],
			ExcludedWarmup: i < WarmupPairs,
			JavaFDCount:    10 + i,
			RustFDCount:    8 + i,
			JavaGCEvents:   []GCEvent{},
		})
	}
	payload, err := json.Marshal(support)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func appendCompletePrimaryLedger(t *testing.T, path string, mutate func(int, *SampleSet)) RawLedgerReceipt {
	t.Helper()
	appendClosure(t, path, EnvironmentRolePrimary, syntheticLedgerClosure(t))
	bundle, records, _ := completeSyntheticBundle(t)
	for i, endpoint := range bundle.Endpoints {
		payload := records[endpoint.RawRecordDigest]
		if mutate != nil {
			var sample SampleSet
			if err := json.Unmarshal(payload, &sample); err != nil {
				t.Fatal(err)
			}
			mutate(i, &sample)
			var err error
			payload, err = json.Marshal(sample)
			if err != nil {
				t.Fatal(err)
			}
		}
		if _, err := AppendRawLedger(path, EnvironmentRolePrimary, RecordEndpoint, payload); err != nil {
			t.Fatalf("append endpoint %d: %v", i, err)
		}
	}
	var receipt RawLedgerReceipt
	for _, workloadID := range WorkloadIDs {
		var err error
		receipt, err = AppendRawLedger(path, EnvironmentRolePrimary, RecordSupport, supportPayload(t, EnvironmentRolePrimary, workloadID))
		if err != nil {
			t.Fatalf("append support %s: %v", workloadID, err)
		}
	}
	return receipt
}

func TestCompleteRawLedgerDelegatesToFrozenBundleDecision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "primary.jsonl")
	receipt := appendCompletePrimaryLedger(t, path, nil)
	if receipt.State != RawPresentComplete || receipt.RecordCount != completeLedgerRecords || receipt.BundleOutcome != OutcomeThresholdMet {
		t.Fatalf("complete receipt = %+v", receipt)
	}

	regressed := filepath.Join(t.TempDir(), "primary.jsonl")
	receipt = appendCompletePrimaryLedger(t, regressed, func(index int, sample *SampleSet) {
		if index != 0 {
			return
		}
		for i := range sample.WarmupPairs {
			sample.WarmupPairs[i] = Pair{Java: 1, Rust: 2}
		}
		for i := range sample.MeasuredPairs {
			sample.MeasuredPairs[i] = Pair{Java: 1, Rust: 2}
		}
	})
	if receipt.BundleOutcome != OutcomeThresholdNotMet {
		t.Fatalf("one endpoint regression was masked: %+v", receipt)
	}
}

func TestRawLedgerRejectsChainAndCardinalityTampering(t *testing.T) {
	validPath := filepath.Join(t.TempDir(), "primary.jsonl")
	appendCompletePrimaryLedger(t, validPath, nil)
	valid, err := os.ReadFile(validPath)
	if err != nil {
		t.Fatal(err)
	}
	baseLines := bytes.Split(bytes.TrimSuffix(valid, []byte{'\n'}), []byte{'\n'})
	tests := []struct {
		name   string
		mutate func([][]byte) [][]byte
	}{
		{"missing", func(lines [][]byte) [][]byte { return append(lines[:2], lines[3:]...) }},
		{"duplicate", func(lines [][]byte) [][]byte { return append(lines[:2], append([][]byte{lines[1]}, lines[2:]...)...) }},
		{"reordered", func(lines [][]byte) [][]byte { lines[1], lines[2] = lines[2], lines[1]; return lines }},
		{"changed historical prefix", func(lines [][]byte) [][]byte {
			lines[0] = bytes.Replace(lines[0], []byte(EnvironmentRolePrimary), []byte("primarz"), 1)
			return lines
		}},
		{"broken previous digest", func(lines [][]byte) [][]byte {
			lines[1] = bytes.Replace(lines[1], []byte(`"previous_entry_digest":"sha256:`), []byte(`"previous_entry_digest":"sha257:`), 1)
			return lines
		}},
		{"truncated final line", func(lines [][]byte) [][]byte {
			lines[len(lines)-1] = lines[len(lines)-1][:len(lines[len(lines)-1])-1]
			return lines
		}},
		{"extra post completion", func(lines [][]byte) [][]byte { return append(lines, lines[len(lines)-1]) }},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			lines := make([][]byte, len(baseLines))
			for i := range baseLines {
				lines[i] = append([]byte(nil), baseLines[i]...)
			}
			content := bytes.Join(testCase.mutate(lines), []byte{'\n'})
			if testCase.name != "truncated final line" {
				content = append(content, '\n')
			}
			path := filepath.Join(t.TempDir(), "primary.jsonl")
			if err := os.WriteFile(path, content, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyRawLedger(path, EnvironmentRolePrimary, nil); err == nil {
				t.Fatal("tampered ledger verified")
			}
		})
	}
}

func TestBindingClosureRejectsEveryInvalidOrChangedIdentity(t *testing.T) {
	base := syntheticLedgerClosure(t)
	value := reflect.ValueOf(&base).Elem()
	typeOf := value.Type()
	for i := range value.NumField() {
		field := value.Field(i)
		if field.Kind() != reflect.String {
			continue
		}
		name := typeOf.Field(i).Name
		t.Run(name+" missing", func(t *testing.T) {
			closure := base
			reflect.ValueOf(&closure).Elem().Field(i).SetString("")
			if err := validateBindingClosure(closure); err == nil {
				t.Fatal("missing identity accepted")
			}
		})
		t.Run(name+" zero", func(t *testing.T) {
			closure := base
			reflect.ValueOf(&closure).Elem().Field(i).SetString(zeroDigest)
			if err := validateBindingClosure(closure); err == nil {
				t.Fatal("zero identity accepted")
			}
		})
		t.Run(name+" malformed", func(t *testing.T) {
			closure := base
			reflect.ValueOf(&closure).Elem().Field(i).SetString("sha256:nope")
			if err := validateBindingClosure(closure); err == nil {
				t.Fatal("malformed identity accepted")
			}
		})
	}
	changed := base
	changed.AnalyzerDigest = syntheticDigest("changed analyzer")
	path := filepath.Join(t.TempDir(), "primary.jsonl")
	appendClosure(t, path, EnvironmentRolePrimary, changed)
	if _, err := VerifyRawLedger(path, EnvironmentRolePrimary, &base); err == nil {
		t.Fatal("valid-but-changed raw closure agreed with the independently bound side")
	}
	changed = base
	changed.Workloads[0].DefinitionDigest = syntheticDigest("changed workload")
	if err := validateBindingClosure(changed); err != nil {
		t.Fatalf("a changed valid workload digest is structurally valid and must be caught against bound side: %v", err)
	}
	changed = base
	changed.Workloads[0].PairOrderDigest = syntheticDigest("wrong pair order")
	if err := validateBindingClosure(changed); err == nil {
		t.Fatal("wrong pair-order digest accepted")
	}
}

func TestRawLedgerRejectsInvalidEndpointAndSupportValues(t *testing.T) {
	closure := syntheticLedgerClosure(t)
	bundle, records, _ := completeSyntheticBundle(t)
	first := records[bundle.Endpoints[0].RawRecordDigest]
	var sample SampleSet
	if err := json.Unmarshal(first, &sample); err != nil {
		t.Fatal(err)
	}
	for _, testCase := range []struct {
		name   string
		mutate func(*SampleSet)
	}{
		{"four warmups", func(set *SampleSet) { set.WarmupPairs = set.WarmupPairs[:4] }},
		{"six warmups", func(set *SampleSet) { set.WarmupPairs = append(set.WarmupPairs, Pair{Java: 1, Rust: 1}) }},
		{"29 measured", func(set *SampleSet) { set.MeasuredPairs = set.MeasuredPairs[:29] }},
		{"31 measured", func(set *SampleSet) { set.MeasuredPairs = append(set.MeasuredPairs, Pair{Java: 1, Rust: 1}) }},
		{"zero", func(set *SampleSet) { set.MeasuredPairs[0].Java = 0 }},
		{"negative", func(set *SampleSet) { set.MeasuredPairs[0].Rust = -1 }},
		{"reordered", func(set *SampleSet) { set.Order[0], set.Order[1] = set.Order[1], set.Order[0] }},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			candidate := sample
			candidate.Order = append([]string(nil), sample.Order...)
			candidate.WarmupPairs = append([]Pair(nil), sample.WarmupPairs...)
			candidate.MeasuredPairs = append([]Pair(nil), sample.MeasuredPairs...)
			testCase.mutate(&candidate)
			payload, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "primary.jsonl")
			appendClosure(t, path, EnvironmentRolePrimary, closure)
			if _, err := AppendRawLedger(path, EnvironmentRolePrimary, RecordEndpoint, payload); err == nil {
				t.Fatal("invalid endpoint appended")
			}
		})
	}
	if _, err := json.Marshal(Pair{Java: math.NaN(), Rust: 1}); err == nil {
		t.Fatal("encoding/json unexpectedly encoded NaN")
	}
	path := filepath.Join(t.TempDir(), "primary.jsonl")
	appendClosure(t, path, EnvironmentRolePrimary, closure)
	if _, err := AppendRawLedger(path, EnvironmentRolePrimary, RecordEndpoint, []byte(`{"java":NaN}`)); err == nil {
		t.Fatal("non-JSON nonfinite token appended")
	}

	partial := filepath.Join(t.TempDir(), "primary.jsonl")
	appendClosure(t, partial, EnvironmentRolePrimary, closure)
	for _, endpoint := range bundle.Endpoints {
		if _, err := AppendRawLedger(partial, EnvironmentRolePrimary, RecordEndpoint, records[endpoint.RawRecordDigest]); err != nil {
			t.Fatal(err)
		}
	}
	valid := supportPayload(t, EnvironmentRolePrimary, WorkloadIDs[0])
	var support WorkloadSupport
	if err := json.Unmarshal(valid, &support); err != nil {
		t.Fatal(err)
	}
	for _, testCase := range []struct {
		name   string
		mutate func(*WorkloadSupport)
	}{
		{"missing position", func(value *WorkloadSupport) { value.Positions = value.Positions[1:] }},
		{"reordered position", func(value *WorkloadSupport) {
			value.Positions[0], value.Positions[1] = value.Positions[1], value.Positions[0]
		}},
		{"zero fd", func(value *WorkloadSupport) { value.Positions[0].JavaFDCount = 0 }},
		{"missing gc list", func(value *WorkloadSupport) { value.Positions[0].JavaGCEvents = nil }},
		{"negative gc time", func(value *WorkloadSupport) {
			value.Positions[0].JavaGCEvents = []GCEvent{{TimestampSeconds: -1, DurationSeconds: 1}}
		}},
		{"zero gc duration", func(value *WorkloadSupport) {
			value.Positions[0].JavaGCEvents = []GCEvent{{TimestampSeconds: 0, DurationSeconds: 0}}
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			candidate := support
			candidate.Positions = append([]SupportPosition(nil), support.Positions...)
			candidate.Positions[0].JavaGCEvents = append([]GCEvent(nil), support.Positions[0].JavaGCEvents...)
			testCase.mutate(&candidate)
			payload, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := validatePayloadForPosition(payload, EnvironmentRolePrimary, RecordSupport, 61, nil); err == nil {
				t.Fatal("invalid support accepted")
			}
		})
	}
}

func TestWriterFailureStrandsLockAndPartialTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "primary.jsonl")
	payload, err := json.Marshal(syntheticLedgerClosure(t))
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected writer failure")
	_, err = appendRawLedger(path, EnvironmentRolePrimary, RecordBindingClosure, payload, func(file *os.File, line []byte) (int, error) {
		written, writeErr := file.Write(line[:len(line)/2])
		if writeErr != nil {
			return written, writeErr
		}
		return written, injected
	})
	if !errors.Is(err, injected) {
		t.Fatalf("append error = %v", err)
	}
	if _, err := os.Lstat(path + ".lock"); err != nil {
		t.Fatalf("failed writer did not strand lock: %v", err)
	}
	if _, err := VerifyRawLedger(path, EnvironmentRolePrimary, nil); err == nil {
		t.Fatal("partial tail verified")
	}
	if _, err := AppendRawLedger(path, EnvironmentRolePrimary, RecordBindingClosure, payload); err == nil {
		t.Fatal("stranded lock did not block subsequent append")
	}

	panicPath := filepath.Join(t.TempDir(), "primary.jsonl")
	func() {
		defer func() { _ = recover() }()
		_, _ = appendRawLedger(panicPath, EnvironmentRolePrimary, RecordBindingClosure, payload, func(_ *os.File, _ []byte) (int, error) {
			panic("injected writer panic")
		})
	}()
	if _, err := os.Lstat(panicPath + ".lock"); err != nil {
		t.Fatalf("panicked writer did not strand lock: %v", err)
	}
}

func TestStrictLedgerDecodeRejectsDuplicateUnknownTrailingAndNonfiniteJSON(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte(`{"schema":"a","schema":"b"}`),
		[]byte(`{"unknown":true}`),
		[]byte(`{} {}`),
		[]byte(`{"value":NaN}`),
		[]byte(`{"value":Infinity}`),
		[]byte(`{"value":-Infinity}`),
	} {
		var entry RawLedgerEntry
		if err := decodeStrictJSON(raw, &entry); err == nil {
			t.Fatalf("hostile JSON decoded: %s", raw)
		}
	}
}
