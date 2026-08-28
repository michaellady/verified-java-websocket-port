package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type retainedSummary struct {
	SchemaVersion string `json:"schema_version"`
	Kind          string `json:"kind"`
	Subject       struct {
		Commit        string `json:"commit"`
		Tree          string `json:"tree"`
		ObjectFormat  string `json:"object_format"`
		CleanCheckout bool   `json:"clean_checkout"`
	} `json:"subject"`
	Execution struct {
		Environment    string `json:"environment"`
		SandboxName    string `json:"sandbox_name"`
		ToolSHA256     string `json:"tool_sha256"`
		ModelSHA256    string `json:"model_sha256"`
		ConfigSHA256   string `json:"config_sha256"`
		ManifestSHA256 string `json:"manifest_sha256"`
		Seed           int64  `json:"seed"`
		Fingerprint    int    `json:"fingerprint_index"`
		Workers        int    `json:"workers"`
		TimeoutSeconds int    `json:"process_timeout_seconds"`
	} `json:"execution"`
	CanonicalResult struct {
		Status                 string `json:"status"`
		StatesGenerated        int    `json:"states_generated"`
		DistinctStates         int    `json:"distinct_states"`
		StatesLeftOnQueue      int    `json:"states_left_on_queue"`
		GraphDepth             int    `json:"graph_depth"`
		TemporalDistinctStates int    `json:"temporal_distinct_states"`
	} `json:"canonical_result"`
	MutationResult struct {
		ConfiguredChecks             int `json:"configured_checks"`
		MutantsExecuted              int `json:"mutants_executed"`
		MutantsKilledByExpectedCheck int `json:"mutants_killed_by_expected_check"`
		Survivors                    int `json:"survivors"`
		Indeterminate                int `json:"indeterminate"`
	} `json:"mutation_result"`
	Replay struct {
		RepeatCount              int    `json:"repeat_count"`
		SemanticallyIdentical    bool   `json:"semantically_identical"`
		SemanticProjectionSHA256 string `json:"semantic_projection_sha256"`
		Receipts                 []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"receipts"`
	} `json:"replay"`
	ClaimScope             string   `json:"claim_scope"`
	ProductionRustProved   bool     `json:"production_rust_proved"`
	IndependentReviewClaim bool     `json:"independent_review_claimed"`
	Provenance             []string `json:"provenance"`
	Limitations            []string `json:"limitations"`
}

type semanticReceipt struct {
	DriverSHA256   string         `json:"driver_sha256"`
	ToolSHA256     string         `json:"tool_sha256"`
	JavaSHA256     string         `json:"java_sha256"`
	Runtime        runtimeInfo    `json:"runtime"`
	Checker        checkerInfo    `json:"checker"`
	ManifestSHA256 string         `json:"manifest_sha256"`
	Models         []artifact     `json:"models"`
	Results        []semanticStep `json:"results"`
	Status         string         `json:"status"`
	ClaimScope     string         `json:"claim_scope"`
}

type semanticStep struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	ExitCode int    `json:"exit_code"`
	Verdict  string `json:"verdict"`
	Check    string `json:"check"`
}

func TestRetainedCurrentHeadEvidenceReconciles(t *testing.T) {
	root := repositoryRoot(t)
	summaryPath := filepath.Join(root, "evidence", "formal", "tlc-4dc9582", "summary.json")
	var summary retainedSummary
	decodeFileStrict(t, summaryPath, &summary)

	for path, wanted := range map[string]string{
		filepath.Join(root, "assurance", "formal", "connection-model.tla"): summary.Execution.ModelSHA256,
		filepath.Join(root, "assurance", "formal", "connection-model.cfg"): summary.Execution.ConfigSHA256,
		filepath.Join(root, "assurance", "formal", "model-mutations.json"): summary.Execution.ManifestSHA256,
	} {
		actual, err := digestFile(path)
		if err != nil || actual != wanted {
			t.Fatalf("digest %s=%s err=%v, want %s", path, actual, err, wanted)
		}
	}
	if summary.ClaimScope != "PROVED_MODEL_ONLY" || summary.ProductionRustProved || summary.IndependentReviewClaim ||
		summary.MutationResult.ConfiguredChecks != 10 || summary.MutationResult.MutantsExecuted != 10 ||
		summary.MutationResult.MutantsKilledByExpectedCheck != 10 || summary.MutationResult.Survivors != 0 ||
		summary.MutationResult.Indeterminate != 0 || summary.Replay.RepeatCount != 2 ||
		!summary.Replay.SemanticallyIdentical || len(summary.Replay.Receipts) != 2 {
		t.Fatalf("retained evidence posture drifted: %#v", summary)
	}

	var baseline []byte
	for _, retained := range summary.Replay.Receipts {
		receiptPath := filepath.Join(root, filepath.FromSlash(retained.Path))
		actual, err := digestFile(receiptPath)
		if err != nil || actual != retained.SHA256 {
			t.Fatalf("receipt digest %s=%s err=%v, want %s", receiptPath, actual, err, retained.SHA256)
		}
		var record receipt
		decodeFileStrict(t, receiptPath, &record)
		if record.Status != "PASS" || record.ClaimScope != "PROVED_MODEL_ONLY" || record.Tool.SHA256 != summary.Execution.ToolSHA256 ||
			record.Manifest.SHA256 != summary.Execution.ManifestSHA256 || len(record.Results) != 12 {
			t.Fatalf("receipt identity drifted: %#v", record)
		}
		for _, observed := range record.Results {
			if filepath.Base(observed.Log.Path) != observed.Log.Path {
				t.Fatalf("unsafe retained log path %q", observed.Log.Path)
			}
			logPath := filepath.Join(filepath.Dir(receiptPath), observed.Log.Path)
			logDigest, digestErr := digestFile(logPath)
			if digestErr != nil || logDigest != observed.Log.SHA256 {
				t.Fatalf("log digest %s=%s err=%v, want %s", logPath, logDigest, digestErr, observed.Log.SHA256)
			}
		}
		canonicalLog, err := os.ReadFile(filepath.Join(filepath.Dir(receiptPath), "tlc.ConnectionModel.out"))
		if err != nil || !strings.Contains(string(canonicalLog), "2424 states generated, 685 distinct states found, 0 states left on queue.") ||
			!strings.Contains(string(canonicalLog), "The depth of the complete state graph search is 17.") ||
			!strings.Contains(string(canonicalLog), "Model checking completed. No error has been found.") {
			t.Fatalf("canonical TLC result is incomplete: %v", err)
		}

		projection := semanticReceipt{
			DriverSHA256: record.Driver.SHA256, ToolSHA256: record.Tool.SHA256, JavaSHA256: record.Java.SHA256,
			Runtime: record.Runtime, Checker: record.Checker, ManifestSHA256: record.Manifest.SHA256,
			Models: record.Models, Status: record.Status, ClaimScope: record.ClaimScope,
		}
		for _, observed := range record.Results {
			projection.Results = append(projection.Results, semanticStep{
				ID: observed.ID, Kind: observed.Kind, ExitCode: observed.ExitCode, Verdict: observed.Verdict, Check: observed.Check,
			})
		}
		body, err := json.Marshal(projection)
		if err != nil {
			t.Fatal(err)
		}
		var canonical any
		if err := json.Unmarshal(body, &canonical); err != nil {
			t.Fatal(err)
		}
		body, err = json.Marshal(canonical)
		if err != nil {
			t.Fatal(err)
		}
		if baseline == nil {
			baseline = body
		} else if string(body) != string(baseline) {
			t.Fatal("retained semantic replay projections differ")
		}
	}
	if actual := digestBytes(baseline); actual != summary.Replay.SemanticProjectionSHA256 {
		t.Fatalf("semantic projection digest=%s, want %s", actual, summary.Replay.SemanticProjectionSHA256)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(directory, "..", ".."))
}

func decodeFileStrict(t *testing.T, path string, target any) {
	t.Helper()
	handle, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = handle.Close() }()
	decoder := json.NewDecoder(handle)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		t.Fatalf("%s has trailing JSON: %v", path, err)
	}
}
