//go:build diffregress

// This file carries the live re-run of OUR arm. It is build-tagged because it
// needs a built ws-oracle-harness binary, which the default `go test ./...`
// must not require. Run it with:
//
//	CARGO_TARGET_DIR=<scratch> cargo build --release --bin ws-oracle-harness \
//	  --manifest-path rust/Cargo.toml
//	WS_ORACLE_HARNESS=<scratch>/release/ws-oracle-harness \
//	  go test -tags diffregress ./internal/diffregress/
//
// The Java arm is NEVER re-derived here. It is the committed recording of the
// real pinned oracle and is treated as the fixed authority; this test only
// re-runs the Rust side and asserts it still agrees.
package diffregress

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestRerunRustArmAgreesWithRecordedJava rebuilds nothing and predicts nothing:
// it executes the real harness binary over the committed probe requests, reads
// the process exit status, and compares the fresh output against the committed
// real-Java arm.
func TestRerunRustArmAgreesWithRecordedJava(t *testing.T) {
	binary := os.Getenv("WS_ORACLE_HARNESS")
	if binary == "" {
		t.Fatal("WS_ORACLE_HARNESS must name the ws-oracle-harness binary; this gate is never skipped once its tag is selected")
	}
	if _, err := os.Stat(binary); err != nil {
		t.Fatalf("WS_ORACLE_HARNESS: %v", err)
	}

	requests, err := os.ReadFile(evidencePath(t, ProbesFile))
	if err != nil {
		t.Fatal(err)
	}
	// The committed requests must still be exactly what the catalog emits,
	// otherwise this re-run would score a different question than the one the
	// Java arm answered.
	generated, err := RequestsJSONL()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(requests, generated) {
		t.Fatal("committed probes.jsonl is not the catalog's output; regenerate before re-running")
	}

	var stdout, stderr bytes.Buffer
	command := exec.Command(binary)
	command.Stdin = bytes.NewReader(requests)
	command.Stdout = &stdout
	command.Stderr = &stderr
	runErr := command.Run()
	exitCode := command.ProcessState.ExitCode()
	if runErr != nil || exitCode != 0 {
		t.Fatalf("ws-oracle-harness exit %d (err %v), stderr: %s", exitCode, runErr, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("ws-oracle-harness wrote %d bytes to stderr: %s", stderr.Len(), stderr.String())
	}

	fresh := filepath.Join(t.TempDir(), "rust-rerun.jsonl")
	if err := os.WriteFile(fresh, stdout.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	summary, err := CompareTranscripts(evidencePath(t, JavaArmFile), fresh)
	if err != nil {
		t.Fatalf("compare fresh Rust arm against recorded Java arm: %v", err)
	}
	if summary.Total != len(Catalog()) {
		t.Fatalf("re-run produced %d responses, catalog has %d probes", summary.Total, len(Catalog()))
	}
	if summary.Divergent != 0 {
		t.Fatalf("fresh Rust arm diverges from the real Java oracle on %d probe(s): %v",
			summary.Divergent, summary.DivergentIDs)
	}
	for _, comparison := range summary.Comparisons {
		for _, path := range comparison.DiffPaths {
			if path != DetailField {
				t.Fatalf("%s: unexpected differing path %q", comparison.RequestID, path)
			}
		}
	}

	// The fresh run must also reproduce the committed Rust arm exactly, modulo
	// the runtime identity object (which names the binary that answered).
	committed, _, err := LoadTranscript(evidencePath(t, RustArmFile))
	if err != nil {
		t.Fatal(err)
	}
	freshByID, _, err := LoadTranscript(fresh)
	if err != nil {
		t.Fatal(err)
	}
	for id, committedResponse := range committed {
		got, ok := freshByID[id]
		if !ok {
			t.Fatalf("%s missing from the fresh run", id)
		}
		if comparison := CompareResponses(committedResponse, got); comparison.Verdict != Identical {
			t.Fatalf("%s: fresh Rust arm differs from the committed Rust arm at %v",
				id, comparison.DiffPaths)
		}
	}
}
