package diffregress

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func decode(t *testing.T, line string) map[string]any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader([]byte(line)))
	decoder.UseNumber()
	var object map[string]any
	if err := decoder.Decode(&object); err != nil {
		t.Fatal(err)
	}
	return object
}

// TestComparatorExcludesOnlyRuntime proves the one documented exclusion really
// is the only one: identical responses that differ solely in `runtime` compare
// identical.
func TestComparatorExcludesOnlyRuntime(t *testing.T) {
	java := decode(t, `{"request_id":"x","outcome":"ok","runtime":{"artifact":"java-oracle"}}`)
	rust := decode(t, `{"request_id":"x","outcome":"ok","runtime":{"artifact":"ws-oracle-harness"}}`)
	if got := CompareResponses(java, rust); got.Verdict != Identical {
		t.Fatalf("verdict %s, want %s (paths %v)", got.Verdict, Identical, got.DiffPaths)
	}
}

// TestComparatorDetectsPlantedDivergences is the negative control the whole
// regression set rests on: if the comparator could not see a divergence, the
// "0 divergences" headline would be worthless. Each planted mutation must be
// caught and named.
func TestComparatorDetectsPlantedDivergences(t *testing.T) {
	base := `{"request_id":"x","outcome":"error","final_state":"open",
	  "error":{"code":"JAVA_INVALID_DATA","close_code":1002,"detail":"a"},
	  "counts":{"consumed_bytes":17,"input_bytes":25,"frames":0},
	  "events":[{"type":"input_chunk","bytes":25}],
	  "runtime":{"artifact":"java-oracle"}}`
	for _, planted := range []struct {
		name string
		line string
		path string
	}{
		{"consumed_bytes", `"consumed_bytes":17`, "counts.consumed_bytes"},
		{"input_bytes", `"input_bytes":25`, "counts.input_bytes"},
		{"outcome", `"outcome":"error"`, "outcome"},
		{"final_state", `"final_state":"open"`, "final_state"},
		{"error_code", `"code":"JAVA_INVALID_DATA"`, "error.code"},
		{"close_code", `"close_code":1002`, "error.close_code"},
		{"event_bytes", `"bytes":25`, "events[0].bytes"},
	} {
		t.Run(planted.name, func(t *testing.T) {
			mutated := bytes.Replace([]byte(base), []byte(planted.line), []byte(mutate(planted.line)), 1)
			if bytes.Equal(mutated, []byte(base)) {
				t.Fatalf("planted mutation %q did not apply", planted.line)
			}
			got := CompareResponses(decode(t, base), decode(t, string(mutated)))
			if got.Verdict != Divergent {
				t.Fatalf("verdict %s, want %s", got.Verdict, Divergent)
			}
			if len(got.DiffPaths) != 1 || got.DiffPaths[0] != planted.path {
				t.Fatalf("diff paths %v, want [%s]", got.DiffPaths, planted.path)
			}
		})
	}
}

// mutate flips a JSON member's value to a different one of the same shape.
func mutate(member string) string {
	switch {
	case bytes.HasSuffix([]byte(member), []byte(`"error"`)):
		return `"outcome":"ok"`
	case bytes.Contains([]byte(member), []byte(`"open"`)):
		return `"final_state":"closed"`
	case bytes.Contains([]byte(member), []byte(`"JAVA_INVALID_DATA"`)):
		return `"code":"STATE_VIOLATION"`
	case bytes.Contains([]byte(member), []byte(`consumed_bytes`)):
		return `"consumed_bytes":25`
	case bytes.Contains([]byte(member), []byte(`input_bytes`)):
		return `"input_bytes":17`
	case bytes.Contains([]byte(member), []byte(`close_code`)):
		return `"close_code":1009`
	default:
		return `"bytes":24`
	}
}

// TestDetailOnlyIsClassifiedNotHidden proves error.detail divergence is
// surfaced with its path rather than silently dropped.
func TestDetailOnlyIsClassifiedNotHidden(t *testing.T) {
	java := decode(t, `{"request_id":"x","outcome":"error","error":{"code":"E","detail":"java wording"}}`)
	rust := decode(t, `{"request_id":"x","outcome":"error","error":{"code":"E","detail":"rust wording"}}`)
	got := CompareResponses(java, rust)
	if got.Verdict != DetailOnly {
		t.Fatalf("verdict %s, want %s", got.Verdict, DetailOnly)
	}
	if len(got.DiffPaths) != 1 || got.DiffPaths[0] != DetailField {
		t.Fatalf("diff paths %v, want [%s]", got.DiffPaths, DetailField)
	}
}

// TestDetailPlusBehavioralIsDivergent proves a behavioral divergence cannot
// hide behind a simultaneous detail divergence.
func TestDetailPlusBehavioralIsDivergent(t *testing.T) {
	java := decode(t, `{"request_id":"x","outcome":"error","error":{"code":"E","detail":"a"},"counts":{"consumed_bytes":9}}`)
	rust := decode(t, `{"request_id":"x","outcome":"error","error":{"code":"E","detail":"b"},"counts":{"consumed_bytes":0}}`)
	if got := CompareResponses(java, rust); got.Verdict != Divergent {
		t.Fatalf("verdict %s, want %s (paths %v)", got.Verdict, Divergent, got.DiffPaths)
	}
}

// TestMissingFieldIsADivergence proves a dropped member cannot pass as a match.
func TestMissingFieldIsADivergence(t *testing.T) {
	java := decode(t, `{"request_id":"x","outcome":"ok","final_state":"open"}`)
	rust := decode(t, `{"request_id":"x","outcome":"ok"}`)
	got := CompareResponses(java, rust)
	if got.Verdict != Divergent {
		t.Fatalf("verdict %s, want %s", got.Verdict, Divergent)
	}
	if len(got.DiffPaths) != 1 || got.DiffPaths[0] != "final_state" {
		t.Fatalf("diff paths %v, want [final_state]", got.DiffPaths)
	}
}

// TestArrayLengthDivergenceIsCaught proves a truncated event list is caught
// rather than compared element-wise up to the shorter length.
func TestArrayLengthDivergenceIsCaught(t *testing.T) {
	java := decode(t, `{"request_id":"x","events":[{"a":1},{"a":2}]}`)
	rust := decode(t, `{"request_id":"x","events":[{"a":1}]}`)
	got := CompareResponses(java, rust)
	if got.Verdict != Divergent {
		t.Fatalf("verdict %s, want %s", got.Verdict, Divergent)
	}
	if len(got.DiffPaths) != 1 || got.DiffPaths[0] != "events.length" {
		t.Fatalf("diff paths %v, want [events.length]", got.DiffPaths)
	}
}

// TestNumbersCompareExactly proves integer counters are compared by literal
// text, so no float64 rounding can make unequal counts look equal.
func TestNumbersCompareExactly(t *testing.T) {
	java := decode(t, `{"request_id":"x","counts":{"n":9007199254740993}}`)
	rust := decode(t, `{"request_id":"x","counts":{"n":9007199254740992}}`)
	if got := CompareResponses(java, rust); got.Verdict != Divergent {
		t.Fatalf("verdict %s, want %s", got.Verdict, Divergent)
	}
}

// TestCompareTranscriptsRejectsShortRun proves a truncated run cannot be
// reported as agreement.
func TestCompareTranscriptsRejectsShortRun(t *testing.T) {
	dir := t.TempDir()
	full := filepath.Join(dir, "java.jsonl")
	short := filepath.Join(dir, "rust.jsonl")
	if err := os.WriteFile(full, []byte(`{"request_id":"a","outcome":"ok"}`+"\n"+`{"request_id":"b","outcome":"ok"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(short, []byte(`{"request_id":"a","outcome":"ok"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := CompareTranscripts(full, short); err == nil {
		t.Fatal("a short Rust transcript compared clean; it must be a hard error")
	}
}

// TestLoadTranscriptRejectsDuplicateIDs proves a duplicated request_id cannot
// mask a missing one while keeping the line count right.
func TestLoadTranscriptRejectsDuplicateIDs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "t.jsonl")
	if err := os.WriteFile(path, []byte(`{"request_id":"a"}`+"\n"+`{"request_id":"a"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadTranscript(path); err == nil {
		t.Fatal("duplicate request_id accepted")
	}
}
