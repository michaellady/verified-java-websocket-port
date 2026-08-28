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
	fact := func(name string) []byte { return []byte("synthetic-binding-not-a-real-artifact|" + name) }
	facts := VerifiedClosureFacts{
		Plan:                    fact("plan_digest"),
		PrimaryEnvironment:      fact("primary_environment_digest"),
		PrimaryHost:             fact("primary_host_digest"),
		ConfirmationEnvironment: fact("confirmation_environment_digest"),
		ConfirmationHost:        fact("confirmation_host_digest"),
		JavaSource:              fact("java_source_digest"),
		JavaExecutable:          fact("java_executable_digest"),
		JavaDependencyLock:      fact("java_dependency_lock_digest"),
		RustSource:              fact("rust_source_digest"),
		RustExecutable:          fact("rust_executable_digest"),
		RustDependencyLock:      fact("rust_dependency_lock_digest"),
		Adapter:                 fact("adapter_digest"),
		MeasurementToolManifest: fact("tool_identity_digest"),
		Analyzer:                fact("analyzer_digest"),
	}
	for i, workloadID := range WorkloadIDs {
		facts.WorkloadDefinitions[i] = fact(workloadID + "|definition")
	}
	closure, err := DeriveExpectedBindingClosure(facts)
	if err != nil {
		t.Fatal(err)
	}
	return closure
}

func newLedgerRepository(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "benchmarks"), 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

func ledgerPath(root, role string) string {
	name := "primary.jsonl"
	if role == EnvironmentRoleConfirmation {
		name = "confirmation.jsonl"
	}
	return filepath.Join(root, "benchmarks", "raw", name)
}

func TestRawLedgerWriterIsExclusiveAndVerifierRetainsPartial(t *testing.T) {
	root := newLedgerRepository(t)
	expected := syntheticLedgerClosure(t)
	payload, err := json.Marshal(expected)
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
			_, appendErr := AppendBoundRawLedger(root, EnvironmentRolePrimary, expected, RecordBindingClosure, payload)
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
	if _, err := os.Lstat(ledgerPath(root, EnvironmentRolePrimary) + ".lock"); !os.IsNotExist(err) {
		t.Fatalf("clean writer left adjacent lock: %v", err)
	}
	receipt, err := VerifyRawLedger(root, EnvironmentRolePrimary, expected)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.State != RawPresentPartial || receipt.RecordCount != 1 || receipt.TerminalEntryDigest == "" || receipt.FileSHA256 == "" {
		t.Fatalf("partial receipt = %+v", receipt)
	}
	content, err := os.ReadFile(ledgerPath(root, EnvironmentRolePrimary))
	if err != nil {
		t.Fatal(err)
	}
	schemaRoot := copyBenchmarkTree(t)
	if err := os.WriteFile(filepath.Join(schemaRoot, "entry.json"), bytes.TrimSuffix(content, []byte{'\n'}), 0o600); err != nil {
		t.Fatal(err)
	}
	failures, err := validateAgainstSchema(schemaRoot, "entry.json", "benchmark-raw-ledger-entry-1.0.0.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) != 0 {
		t.Fatalf("raw-ledger entry schema failures: %v", failures)
	}
}

func appendClosure(t *testing.T, root, role string, closure BindingClosure) RawLedgerReceipt {
	t.Helper()
	payload, err := json.Marshal(closure)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := AppendBoundRawLedger(root, role, closure, RecordBindingClosure, payload)
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

func appendCompletePrimaryLedger(t *testing.T, root string, mutate func(int, *SampleSet)) RawLedgerReceipt {
	t.Helper()
	expected := syntheticLedgerClosure(t)
	appendClosure(t, root, EnvironmentRolePrimary, expected)
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
		if _, err := AppendBoundRawLedger(root, EnvironmentRolePrimary, expected, RecordEndpoint, payload); err != nil {
			t.Fatalf("append endpoint %d: %v", i, err)
		}
	}
	var receipt RawLedgerReceipt
	for _, workloadID := range WorkloadIDs {
		var err error
		receipt, err = AppendBoundRawLedger(root, EnvironmentRolePrimary, expected, RecordSupport, supportPayload(t, EnvironmentRolePrimary, workloadID))
		if err != nil {
			t.Fatalf("append support %s: %v", workloadID, err)
		}
	}
	return receipt
}

func TestCompleteRawLedgerDelegatesToFrozenBundleDecision(t *testing.T) {
	root := newLedgerRepository(t)
	receipt := appendCompletePrimaryLedger(t, root, nil)
	if receipt.State != RawPresentComplete || receipt.RecordCount != completeLedgerRecords || receipt.BundleOutcome != OutcomeThresholdMet {
		t.Fatalf("complete receipt = %+v", receipt)
	}

	regressed := newLedgerRepository(t)
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
	validRoot := newLedgerRepository(t)
	appendCompletePrimaryLedger(t, validRoot, nil)
	valid, err := os.ReadFile(ledgerPath(validRoot, EnvironmentRolePrimary))
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
			root := newLedgerRepository(t)
			if err := os.Mkdir(filepath.Join(root, "benchmarks", "raw"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(ledgerPath(root, EnvironmentRolePrimary), content, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyRawLedger(root, EnvironmentRolePrimary, syntheticLedgerClosure(t)); err == nil {
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
	root := newLedgerRepository(t)
	appendClosure(t, root, EnvironmentRolePrimary, changed)
	if _, err := VerifyRawLedger(root, EnvironmentRolePrimary, base); err == nil {
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
			root := newLedgerRepository(t)
			appendClosure(t, root, EnvironmentRolePrimary, closure)
			if _, err := AppendBoundRawLedger(root, EnvironmentRolePrimary, closure, RecordEndpoint, payload); err == nil {
				t.Fatal("invalid endpoint appended")
			}
		})
	}
	if _, err := json.Marshal(Pair{Java: math.NaN(), Rust: 1}); err == nil {
		t.Fatal("encoding/json unexpectedly encoded NaN")
	}
	root := newLedgerRepository(t)
	appendClosure(t, root, EnvironmentRolePrimary, closure)
	if _, err := AppendBoundRawLedger(root, EnvironmentRolePrimary, closure, RecordEndpoint, []byte(`{"java":NaN}`)); err == nil {
		t.Fatal("non-JSON nonfinite token appended")
	}

	partial := newLedgerRepository(t)
	appendClosure(t, partial, EnvironmentRolePrimary, closure)
	for _, endpoint := range bundle.Endpoints {
		if _, err := AppendBoundRawLedger(partial, EnvironmentRolePrimary, closure, RecordEndpoint, records[endpoint.RawRecordDigest]); err != nil {
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
	root := newLedgerRepository(t)
	expected := syntheticLedgerClosure(t)
	payload, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected writer failure")
	_, err = appendBoundRawLedger(root, EnvironmentRolePrimary, expected, RecordBindingClosure, payload, func(file *os.File, line []byte) (int, error) {
		written, writeErr := file.Write(line[:len(line)/2])
		if writeErr != nil {
			return written, writeErr
		}
		return written, injected
	})
	if !errors.Is(err, injected) {
		t.Fatalf("append error = %v", err)
	}
	if _, err := os.Lstat(ledgerPath(root, EnvironmentRolePrimary) + ".lock"); err != nil {
		t.Fatalf("failed writer did not strand lock: %v", err)
	}
	if _, err := VerifyRawLedger(root, EnvironmentRolePrimary, expected); err == nil {
		t.Fatal("partial tail verified")
	}
	if _, err := AppendBoundRawLedger(root, EnvironmentRolePrimary, expected, RecordBindingClosure, payload); err == nil {
		t.Fatal("stranded lock did not block subsequent append")
	}

	panicRoot := newLedgerRepository(t)
	func() {
		defer func() { _ = recover() }()
		_, _ = appendBoundRawLedger(panicRoot, EnvironmentRolePrimary, expected, RecordBindingClosure, payload, func(_ *os.File, _ []byte) (int, error) {
			panic("injected writer panic")
		})
	}()
	if _, err := os.Lstat(ledgerPath(panicRoot, EnvironmentRolePrimary) + ".lock"); err != nil {
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

func TestBoundRawLedgerRejectsSelfAttestedClosureAndSymlinkEscapes(t *testing.T) {
	repositoryRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(repositoryRoot, "benchmarks"), 0o755); err != nil {
		t.Fatal(err)
	}
	expected := syntheticLedgerClosure(t)
	forged := expected
	forged.AnalyzerDigest = syntheticDigest("self-attested replacement")
	forgedPayload, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AppendBoundRawLedger(repositoryRoot, EnvironmentRolePrimary, expected, RecordBindingClosure, forgedPayload); err == nil {
		t.Fatal("self-attested first closure appended")
	}
	if _, err := os.Lstat(filepath.Join(repositoryRoot, "benchmarks", "raw")); !os.IsNotExist(err) {
		t.Fatalf("rejected first closure created raw directory: %v", err)
	}

	repositoryLink := filepath.Join(t.TempDir(), "repository-link")
	if err := os.Symlink(repositoryRoot, repositoryLink); err != nil {
		t.Fatal(err)
	}
	expectedPayload, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AppendBoundRawLedger(repositoryLink, EnvironmentRolePrimary, expected, RecordBindingClosure, expectedPayload); err == nil {
		t.Fatal("symlinked repository root accepted")
	}

	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(repositoryRoot, "benchmarks", "raw")); err != nil {
		t.Fatal(err)
	}
	if _, err := AppendBoundRawLedger(repositoryRoot, EnvironmentRolePrimary, expected, RecordBindingClosure, expectedPayload); err == nil {
		t.Fatal("symlinked raw directory accepted")
	}
	if _, err := os.Lstat(filepath.Join(outside, "primary.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("out-of-root raw file created: %v", err)
	}
}

func TestBoundRawLedgerCreatesCleanRawTreeAndRejectsFinalSymlink(t *testing.T) {
	repositoryRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(repositoryRoot, "benchmarks"), 0o755); err != nil {
		t.Fatal(err)
	}
	expected := syntheticLedgerClosure(t)
	payload, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := AppendBoundRawLedger(repositoryRoot, EnvironmentRolePrimary, expected, RecordBindingClosure, payload)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.State != RawPresentPartial {
		t.Fatalf("clean-tree first append = %+v", receipt)
	}
	rawInfo, err := os.Lstat(filepath.Join(repositoryRoot, "benchmarks", "raw"))
	if err != nil || !rawInfo.IsDir() || rawInfo.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("secure raw directory missing: %v %+v", err, rawInfo)
	}

	confirmationTarget := filepath.Join(t.TempDir(), "outside.jsonl")
	if err := os.WriteFile(confirmationTarget, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(confirmationTarget, filepath.Join(repositoryRoot, "benchmarks", "raw", "confirmation.jsonl")); err != nil {
		t.Fatal(err)
	}
	if _, err := AppendBoundRawLedger(repositoryRoot, EnvironmentRoleConfirmation, expected, RecordBindingClosure, payload); err == nil {
		t.Fatal("symlinked final ledger accepted")
	}
	outsideBytes, err := os.ReadFile(confirmationTarget)
	if err != nil || string(outsideBytes) != "outside" {
		t.Fatalf("outside target changed: %q, %v", outsideBytes, err)
	}
}

func TestRepositoryClosureRejectsVerifiedFactReplacement(t *testing.T) {
	repositoryRoot := copyBenchmarkTree(t)
	bindAllPendingFields(t, repositoryRoot)
	setBindingStatuses(t, repositoryRoot, "BOUND")

	primaryPath := filepath.Join(repositoryRoot, "benchmarks", "environments", "primary-macos.json")
	_, err := deriveRepositoryExpectedBindingClosure(repositoryRoot, true, func() error {
		originalPath := primaryPath + ".verified"
		if err := os.Rename(primaryPath, originalPath); err != nil {
			return err
		}
		return os.WriteFile(primaryPath, []byte(`{"replacement":"not-the-verified-fact"}`), 0o600)
	})
	if err == nil {
		t.Fatal("closure derived after a verified repository fact was replaced")
	}
	if _, statErr := os.Lstat(filepath.Join(repositoryRoot, "benchmarks", "raw")); !os.IsNotExist(statErr) {
		t.Fatalf("rejected derivation created a raw evidence path: %v", statErr)
	}
}

func TestNewSiblingLedgerMustMatchExistingClosure(t *testing.T) {
	repositoryRoot := newLedgerRepository(t)
	primaryClosure := syntheticLedgerClosure(t)
	primaryPayload, err := json.Marshal(primaryClosure)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AppendBoundRawLedger(repositoryRoot, EnvironmentRolePrimary, primaryClosure, RecordBindingClosure, primaryPayload); err != nil {
		t.Fatal(err)
	}

	confirmationClosure := primaryClosure
	confirmationClosure.AnalyzerDigest = syntheticDigest("sequential repository replacement")
	confirmationPayload, err := json.Marshal(confirmationClosure)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AppendBoundRawLedger(repositoryRoot, EnvironmentRoleConfirmation, confirmationClosure, RecordBindingClosure, confirmationPayload); err == nil {
		t.Fatal("confirmation ledger accepted a closure different from the existing primary ledger")
	}
	if _, err := os.Lstat(ledgerPath(repositoryRoot, EnvironmentRoleConfirmation)); !os.IsNotExist(err) {
		t.Fatalf("closure mismatch created confirmation ledger: %v", err)
	}
	if _, err := VerifyRawLedger(repositoryRoot, EnvironmentRolePrimary, primaryClosure); err != nil {
		t.Fatalf("sibling mismatch damaged the incumbent primary ledger: %v", err)
	}
}
