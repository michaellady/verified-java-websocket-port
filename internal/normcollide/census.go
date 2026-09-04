package normcollide

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// PublicArmPath is the committed real-Java arm of the 74-scenario public
// corpus: the transcript the 74/74 headline is computed over.
const PublicArmPath = "evidence/ac5-class-completeness/java-arm-public.jsonl"

// HandshakeCasesPath is the committed 49-case handshake corpus.
const HandshakeCasesPath = "corpora/handshake/cases.jsonl"

// Census measures how coarse a scored transcript actually is: how many rows
// it has, and how many DISTINCT scored rows those collapse to once the
// identity fields are removed.
//
// This is the number that bounds a headline. A corpus of N cases whose rows
// collapse to D distinct observations cannot distinguish more than D
// behaviours, whatever N says.
type Census struct {
	// Source is the file measured.
	Source string `json:"source"`
	// Rows is the row count.
	Rows int `json:"rows"`
	// DistinctScoredRows is how many distinct observations those rows carry
	// once identity fields are stripped.
	DistinctScoredRows int `json:"distinct_scored_rows"`
	// RowsSharingAnObservation is how many rows are in a class of size > 1:
	// rows the observation cannot tell apart from some other row.
	RowsSharingAnObservation int `json:"rows_sharing_an_observation_with_another_row"`
	// LargestClass is the size of the biggest equivalence class.
	LargestClass int `json:"largest_equivalence_class"`
	// KeySets partitions the rows by their exact top-level key set, which is
	// how the Projections() table is checked against reality.
	KeySets []KeySetCount `json:"key_sets"`
}

// KeySetCount is one observed response shape and how many rows have it.
type KeySetCount struct {
	// Keys is the sorted top-level key set.
	Keys []string `json:"keys"`
	// Rows is how many rows carry exactly these keys.
	Rows int `json:"rows"`
	// Projection is the Projections() entry this shape belongs to.
	Projection string `json:"projection"`
}

// MeasureTranscript reads a JSONL transcript and censuses it. The equivalence
// classes are computed on the canonical JSON of each row with the identity
// fields removed — the same three fields Decide strips, for the same reason.
func MeasureTranscript(path string, classify func(keys []string) string) (Census, error) {
	census := Census{Source: path}
	raw, err := os.ReadFile(path)
	if err != nil {
		return census, err
	}
	identity := map[string]bool{}
	for _, field := range IdentityFields() {
		identity[field] = true
	}
	classes := map[string]int{}
	keySets := map[string]int{}
	keySetKeys := map[string][]string{}
	for i, line := range bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var object map[string]any
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.UseNumber()
		if err := decoder.Decode(&object); err != nil {
			return census, fmt.Errorf("%s line %d: %w", path, i+1, err)
		}
		census.Rows++
		stripped := map[string]any{}
		var keys []string
		for key, value := range object {
			keys = append(keys, key)
			if identity[key] {
				continue
			}
			stripped[key] = value
		}
		sort.Strings(keys)
		signature, err := json.Marshal(stripped)
		if err != nil {
			return census, err
		}
		classes[string(signature)]++
		joined := fmt.Sprint(keys)
		keySets[joined]++
		keySetKeys[joined] = keys
	}
	census.DistinctScoredRows = len(classes)
	for _, size := range classes {
		if size > 1 {
			census.RowsSharingAnObservation += size
		}
		if size > census.LargestClass {
			census.LargestClass = size
		}
	}
	var joinedNames []string
	for joined := range keySets {
		joinedNames = append(joinedNames, joined)
	}
	sort.Strings(joinedNames)
	for _, joined := range joinedNames {
		census.KeySets = append(census.KeySets, KeySetCount{
			Keys:       keySetKeys[joined],
			Rows:       keySets[joined],
			Projection: classify(keySetKeys[joined]),
		})
	}
	return census, nil
}

// ClassifyBehaviourKeys maps an observed behaviour-response key set onto a
// Projections() entry. An unrecognised shape returns the empty string, which
// fails the partition check rather than being silently filed somewhere.
func ClassifyBehaviourKeys(keys []string) string {
	has := map[string]bool{}
	for _, key := range keys {
		has[key] = true
	}
	switch {
	case has["events"] && has["frames"] && has["transitions"]:
		return "behaviour.ok"
	case has["counts"] && has["final_state"] && has["error"]:
		return "behaviour.failure"
	case has["error"] && has["request_digest"] && !has["counts"] && !has["runtime"]:
		return "behaviour.output_limit"
	case has["error"] && !has["request_digest"]:
		return "behaviour.envelope_error"
	default:
		return ""
	}
}

// ClassifyHandshakeKeys maps an observed handshake key set onto its
// projection.
func ClassifyHandshakeKeys(keys []string) string {
	for _, key := range keys {
		if key == "java_observable" {
			return "handshake.judged"
		}
	}
	return ""
}

// MeasureHandshake censuses the handshake surface. It cannot read a committed
// Java handshake transcript because none is committed at a path this package
// may read, so it drives the harness over the 49 committed CASES and censuses
// the answers. That makes it a measurement of OUR arm's observations, which is
// the right object anyway: the question is how many distinct observations the
// exam's 49 cases can produce, not who produced them.
func MeasureHandshake(root string, runner Runner) (Census, error) {
	census := Census{Source: HandshakeCasesPath}
	raw, err := os.ReadFile(filepath.Join(root, HandshakeCasesPath))
	if err != nil {
		return census, err
	}
	var lines []string
	for i, line := range bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var c struct {
			CaseID    string `json:"case_id"`
			Direction string `json:"direction"`
			RawBase64 string `json:"raw_base64"`
			Context   struct {
				ClientKey string `json:"client_key"`
			} `json:"context"`
		}
		if err := json.Unmarshal(line, &c); err != nil {
			return census, fmt.Errorf("%s line %d: %w", HandshakeCasesPath, i+1, err)
		}
		decoded, err := decodeBase64(c.RawBase64)
		if err != nil {
			return census, fmt.Errorf("%s line %d: %w", HandshakeCasesPath, i+1, err)
		}
		// client_key is carried through: a server_response case judged
		// without its recorded key answers a different question.
		seed := Seed{ID: c.CaseID, Direction: c.Direction, RawHandshake: decoded,
			ClientKey: c.Context.ClientKey}
		rendered, err := seed.Line()
		if err != nil {
			return census, err
		}
		lines = append(lines, rendered)
	}
	answers, err := runner.Run(lines)
	if err != nil {
		return census, err
	}
	temp, err := os.CreateTemp("", "normcollide-handshake-*.jsonl")
	if err != nil {
		return census, err
	}
	defer os.Remove(temp.Name())
	for _, answer := range answers {
		if _, err := temp.WriteString(answer + "\n"); err != nil {
			return census, err
		}
	}
	if err := temp.Close(); err != nil {
		return census, err
	}
	measured, err := MeasureTranscript(temp.Name(), ClassifyHandshakeKeys)
	if err != nil {
		return census, err
	}
	measured.Source = HandshakeCasesPath + " (driven through the harness)"
	return measured, nil
}
