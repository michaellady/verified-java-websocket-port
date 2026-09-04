package rfcneutral

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const repoRoot = "../.."

// TestDerivationIgnoresRecordedExpectation is the structural independence
// proof the adjudication register cites.
//
// The register says rank three's public-tier opinions are no longer read from
// the corpus's REFERENCE_MODEL_DERIVED expectation. A doc comment saying so is
// worth nothing. This test rewrites every line of the committed corpus so that
// its expected block CONTRADICTS what the derivation returns -- an expectation
// of "closed" wherever the derivation says open, "open" wherever it says closed
// -- and additionally strips expectation_status, expectation_basis and family,
// then re-derives. Every decision must be byte-identical.
//
// RED evidence: adding an Expected field to the Scenario struct and consulting
// it anywhere in decide() makes this test fail. See the deletion attacks
// recorded in drafts/self-review/oracle-rank3-independence.md.
func TestDerivationIgnoresRecordedExpectation(t *testing.T) {
	pristine, err := Derive(repoRoot)
	if err != nil {
		t.Fatalf("derive from the committed corpus: %v", err)
	}
	if len(pristine) == 0 {
		t.Fatal("the committed corpus produced no decisions")
	}

	byID := make(map[string]Decision, len(pristine))
	for _, d := range pristine {
		byID[d.ScenarioID] = d
	}

	raw := readRawCorpus(t)
	if len(raw) != len(pristine) {
		t.Fatalf("read %d raw lines and %d decisions", len(raw), len(pristine))
	}

	poisoned := make([]Scenario, 0, len(raw))
	rewritten := 0
	for i, doc := range raw {
		id, _ := doc["scenario_id"].(string)
		d, ok := byID[id]
		if !ok {
			t.Fatalf("line %d: scenario %q has no decision", i+1, id)
		}
		contra := "closed"
		if !d.Abstains && d.Verdict == VerdictClosed {
			contra = "open"
		}
		doc["expected"] = map[string]any{
			"final_state": contra,
			"outcome":     "error",
			"error":       map[string]any{"code": "POISONED", "close_code": 4999},
			"counts":      map[string]any{"frames": 999},
		}
		doc["expectation_status"] = "POISONED_BY_A_TEST"
		doc["expectation_basis"] = []any{"not.a.real.basis"}
		doc["family"] = "poisoned"
		rewritten++

		encoded, err := json.Marshal(doc)
		if err != nil {
			t.Fatalf("line %d: re-encode: %v", i+1, err)
		}
		var s Scenario
		if err := json.Unmarshal(encoded, &s); err != nil {
			t.Fatalf("line %d: decode poisoned line: %v", i+1, err)
		}
		poisoned = append(poisoned, s)
	}
	if rewritten != len(raw) {
		t.Fatalf("rewrote %d of %d lines", rewritten, len(raw))
	}

	got, err := DeriveScenarios(poisoned)
	if err != nil {
		t.Fatalf("derive from the poisoned corpus: %v", err)
	}
	if !reflect.DeepEqual(pristine, got) {
		for i := range got {
			if !reflect.DeepEqual(pristine[i], got[i]) {
				t.Fatalf("scenario %s changed when its recorded expectation was contradicted:\n pristine %+v\n poisoned %+v",
					pristine[i].ScenarioID, pristine[i], got[i])
			}
		}
		t.Fatal("decisions differ but no single scenario differs; slice lengths?")
	}
}

// TestScenarioStructCarriesNoExpectation is the same claim at the type level.
// The independence above holds because the struct cannot see the expectation;
// this fails the moment a field is added that could.
func TestScenarioStructCarriesNoExpectation(t *testing.T) {
	forbidden := map[string]bool{
		"expected": true, "expectation_status": true, "expectation_basis": true,
		"family": true, "seed_index": true, "tier": true,
	}
	ty := reflect.TypeOf(Scenario{})
	for i := 0; i < ty.NumField(); i++ {
		tag := ty.Field(i).Tag.Get("json")
		if forbidden[tag] {
			t.Fatalf("Scenario.%s decodes %q; rank three must not be able to see a reference-model-derived expectation or a corpus label",
				ty.Field(i).Name, tag)
		}
	}
	if ty.NumField() != 5 {
		t.Fatalf("Scenario has %d fields; it is meant to carry exactly scenario_id, role, initial_state, limits and steps", ty.NumField())
	}
}

// TestDerivationReadsNoJavaArtifact asserts the package imports nothing that
// carries a Java observation or a reference-model derivation.
func TestDerivationReadsNoJavaArtifact(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	banned := []string{"internal/corpora", "java-oracle", "internal/deltaledger", "internal/divergencesweep"}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".go" {
			continue
		}
		data, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for _, b := range banned {
			// The package doc names internal/corpora in prose to say what
			// it is NOT; an import would appear inside a quoted path.
			if containsQuotedImport(string(data), b) {
				t.Fatalf("%s imports %q; rank three's derivation must not read a Java-shaped model", e.Name(), b)
			}
		}
	}
}

func containsQuotedImport(src, path string) bool {
	needle := `"github.com/michaellady/verified-java-websocket-port/` + path + `"`
	for i := 0; i+len(needle) <= len(src); i++ {
		if src[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func readRawCorpus(t *testing.T) []map[string]any {
	t.Helper()
	f, err := os.Open(filepath.Join(repoRoot, filepath.FromSlash(PublicCorpusPath)))
	if err != nil {
		t.Fatalf("open corpus: %v", err)
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<26)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal(sc.Bytes(), &doc); err != nil {
			t.Fatalf("decode corpus line: %v", err)
		}
		out = append(out, doc)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan corpus: %v", err)
	}
	return out
}
