package diffregress

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/corpora"
)

// TestCommittedArmsAgree is the standing differential assertion over the
// committed regression set: our recorded Rust arm must agree behaviorally with
// the recorded real-Java arm on every corpus-invisible probe. This runs in the
// default `go test ./...` because both arms are committed; the live re-run of
// our arm lives in rerun_test.go behind the `diffregress` build tag.
func TestCommittedArmsAgree(t *testing.T) {
	summary, err := CompareTranscripts(
		evidencePath(t, JavaArmFile),
		evidencePath(t, RustArmFile),
	)
	if err != nil {
		t.Fatalf("compare committed arms: %v", err)
	}
	if summary.Total != len(Catalog()) {
		t.Fatalf("compared %d probes, catalog has %d", summary.Total, len(Catalog()))
	}
	if summary.Divergent != 0 {
		t.Fatalf("behavioral divergence against the real Java oracle on %d probe(s): %v",
			summary.Divergent, summary.DivergentIDs)
	}
	for _, comparison := range summary.Comparisons {
		for _, path := range comparison.DiffPaths {
			if path != DetailField {
				t.Fatalf("%s: unexpected differing path %q (only %s may differ)",
					comparison.RequestID, path, DetailField)
			}
		}
	}
}

// TestEveryProbeHasBothArms proves the set is complete: no probe may be
// committed without a recorded result from each side.
func TestEveryProbeHasBothArms(t *testing.T) {
	java, _, err := LoadTranscript(evidencePath(t, JavaArmFile))
	if err != nil {
		t.Fatal(err)
	}
	rust, _, err := LoadTranscript(evidencePath(t, RustArmFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, probe := range Catalog() {
		if _, ok := java[probe.ID]; !ok {
			t.Fatalf("%s has no recorded Java arm", probe.ID)
		}
		if _, ok := rust[probe.ID]; !ok {
			t.Fatalf("%s has no recorded Rust arm", probe.ID)
		}
	}
}

// TestArmsAnswerTheCommittedRequests proves each arm answered the exact probe
// it claims to: every response must echo the request_digest the catalog binds.
// Without this a transcript recorded against edited requests could be committed
// alongside unedited requests.
func TestArmsAnswerTheCommittedRequests(t *testing.T) {
	for _, file := range []string{JavaArmFile, RustArmFile} {
		responses, _, err := LoadTranscript(evidencePath(t, file))
		if err != nil {
			t.Fatal(err)
		}
		for _, probe := range Catalog() {
			request, err := RequestObject(probe)
			if err != nil {
				t.Fatal(err)
			}
			want, _ := request["request_digest"].(string)
			got, _ := responses[probe.ID]["request_digest"].(string)
			if got != want {
				t.Fatalf("%s in %s echoes request_digest %s, catalog binds %s",
					probe.ID, file, got, want)
			}
		}
	}
}

// TestManifestMatchesTheCommittedArtifacts proves the manifest is not stale:
// its recorded digests must match the files beside it, and its per-probe
// verdicts must match a fresh comparison of the two arms.
func TestManifestMatchesTheCommittedArtifacts(t *testing.T) {
	raw, err := os.ReadFile(evidencePath(t, ManifestFile))
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	for name, want := range manifest.Artifacts {
		data, err := os.ReadFile(filepath.Join(repoRoot(t), EvidenceDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if got := corpora.DigestSHA256(data); got != want {
			t.Fatalf("%s digest %s, manifest records %s", name, got, want)
		}
	}
	if manifest.Counts["probes"] != len(Catalog()) {
		t.Fatalf("manifest records %d probes, catalog has %d",
			manifest.Counts["probes"], len(Catalog()))
	}
	if manifest.Counts["behaviorally_divergent"] != 0 {
		t.Fatalf("manifest records %d behavioral divergences",
			manifest.Counts["behaviorally_divergent"])
	}
	java, _, err := LoadTranscript(evidencePath(t, JavaArmFile))
	if err != nil {
		t.Fatal(err)
	}
	rust, _, err := LoadTranscript(evidencePath(t, RustArmFile))
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]ProbeRecord{}
	for _, record := range manifest.Probes {
		byID[record.RequestID] = record
	}
	for _, probe := range Catalog() {
		record, ok := byID[probe.ID]
		if !ok {
			t.Fatalf("manifest has no record for %s", probe.ID)
		}
		if record.Origin != probe.Origin || record.Class != probe.Class {
			t.Fatalf("%s: manifest records class=%s origin=%s, catalog says class=%s origin=%s",
				probe.ID, record.Class, record.Origin, probe.Class, probe.Origin)
		}
		fresh := CompareResponses(java[probe.ID], rust[probe.ID])
		if fresh.Verdict != record.Verdict {
			t.Fatalf("%s: manifest verdict %s, fresh comparison %s",
				probe.ID, record.Verdict, fresh.Verdict)
		}
		if !record.Agree {
			t.Fatalf("%s: manifest records non-agreement", probe.ID)
		}
	}
}

// TestManifestJavaArmMatchesTheRecordedTranscript proves the manifest's
// Java-side values were projected from the recorded Java transcript and not
// copied from the Rust arm. If a future editor "fixed" a Java value by hand to
// match Rust, this fails.
func TestManifestJavaArmMatchesTheRecordedTranscript(t *testing.T) {
	raw, err := os.ReadFile(evidencePath(t, ManifestFile))
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	java, _, err := LoadTranscript(evidencePath(t, JavaArmFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range manifest.Probes {
		want := armView(java[record.RequestID])
		if record.Java.Outcome != want.Outcome {
			t.Fatalf("%s: manifest java outcome %q, transcript %q",
				record.RequestID, record.Java.Outcome, want.Outcome)
		}
		if !sameJSONScalar(record.Java.ConsumedBytes, want.ConsumedBytes) {
			t.Fatalf("%s: manifest java consumed_bytes %v, transcript %v",
				record.RequestID, record.Java.ConsumedBytes, want.ConsumedBytes)
		}
		if !sameJSONScalar(record.Java.InputBytes, want.InputBytes) {
			t.Fatalf("%s: manifest java input_bytes %v, transcript %v",
				record.RequestID, record.Java.InputBytes, want.InputBytes)
		}
		if !sameJSONScalar(record.Java.FinalState, want.FinalState) {
			t.Fatalf("%s: manifest java final_state %v, transcript %v",
				record.RequestID, record.Java.FinalState, want.FinalState)
		}
	}
}

// sameJSONScalar compares values that may arrive as json.Number (from the
// transcript loader) or float64/string (from encoding/json on the manifest).
func sameJSONScalar(a, b any) bool {
	return scalarText(a) == scalarText(b)
}

func scalarText(v any) string {
	switch typed := v.(type) {
	case nil:
		return "null"
	case json.Number:
		return typed.String()
	case float64:
		return json.Number(trimFloat(typed)).String()
	case string:
		return typed
	default:
		data, _ := json.Marshal(typed)
		return string(data)
	}
}

func trimFloat(f float64) string {
	data, _ := json.Marshal(f)
	return string(data)
}
