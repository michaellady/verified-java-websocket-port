package diffregress

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// RuntimeField is the one response member excluded from every comparison: it
// carries the responder's own identity (which artifact answered), so Java and
// Rust necessarily differ there and nowhere else may they differ silently.
const RuntimeField = "runtime"

// DetailField is the free-text diagnostic the adapter protocol documents as
// non-semantic and the corpus evaluator never compares. A divergence confined
// to this one path is reported as DetailOnly rather than hidden: it is still
// surfaced, just classified.
const DetailField = "error.detail"

// Verdict classifies one request_id's Java-vs-Rust comparison.
type Verdict string

const (
	// Identical means every compared field matched, runtime excluded.
	Identical Verdict = "identical"
	// DetailOnly means the ONLY differing path was error.detail.
	DetailOnly Verdict = "identical_except_error_detail"
	// Divergent means at least one behavioral field differed.
	Divergent Verdict = "behaviorally_divergent"
)

// Comparison is the per-request result.
type Comparison struct {
	RequestID string   `json:"request_id"`
	Verdict   Verdict  `json:"verdict"`
	DiffPaths []string `json:"diff_paths,omitempty"`
}

// Summary aggregates a whole-transcript comparison.
type Summary struct {
	Total                      int          `json:"total"`
	Identical                  int          `json:"identical_excluding_runtime"`
	DetailOnly                 int          `json:"identical_except_error_detail"`
	Divergent                  int          `json:"behaviorally_divergent"`
	DetailOnlyIDs              []string     `json:"error_detail_wording_case_ids,omitempty"`
	DivergentIDs               []string     `json:"behaviorally_divergent_case_ids,omitempty"`
	Comparisons                []Comparison `json:"comparisons"`
	ComparedFieldsNote         string       `json:"compared_fields_note"`
	ExcludedFromComparisonNote string       `json:"excluded_from_comparison_note"`
}

// LoadTranscript reads a JSONL transcript into request_id -> response object,
// preserving the file order. Numbers are decoded as json.Number so integer
// counters compare exactly rather than through float64.
func LoadTranscript(path string) (map[string]map[string]any, []string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	byID := make(map[string]map[string]any)
	var order []string
	for i, line := range bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.UseNumber()
		var object map[string]any
		if err := decoder.Decode(&object); err != nil {
			return nil, nil, fmt.Errorf("%s line %d: %w", path, i+1, err)
		}
		id, _ := object["request_id"].(string)
		if id == "" {
			return nil, nil, fmt.Errorf("%s line %d: response has no request_id", path, i+1)
		}
		if _, seen := byID[id]; seen {
			return nil, nil, fmt.Errorf("%s line %d: duplicate request_id %s", path, i+1, id)
		}
		byID[id] = object
		order = append(order, id)
	}
	return byID, order, nil
}

// CompareResponses compares two oracle responses for the same request_id,
// excluding only the runtime identity object, and returns every differing
// path. Absence and presence are distinguished: a field present on one side and
// missing on the other is a difference, so a dropped field cannot pass as a
// match.
func CompareResponses(java, rust map[string]any) Comparison {
	id, _ := java["request_id"].(string)
	var paths []string
	diffWalk("", stripRuntime(java), stripRuntime(rust), &paths)
	sort.Strings(paths)
	verdict := Identical
	switch {
	case len(paths) == 0:
		verdict = Identical
	case len(paths) == 1 && paths[0] == DetailField:
		verdict = DetailOnly
	default:
		verdict = Divergent
	}
	return Comparison{RequestID: id, Verdict: verdict, DiffPaths: paths}
}

func stripRuntime(object map[string]any) map[string]any {
	out := make(map[string]any, len(object))
	for k, v := range object {
		if k == RuntimeField {
			continue
		}
		out[k] = v
	}
	return out
}

// diffWalk records the dotted path of every scalar disagreement between two
// decoded JSON values.
func diffWalk(path string, a, b any, paths *[]string) {
	switch left := a.(type) {
	case map[string]any:
		right, ok := b.(map[string]any)
		if !ok {
			*paths = append(*paths, orRoot(path))
			return
		}
		keys := make(map[string]struct{}, len(left)+len(right))
		for k := range left {
			keys[k] = struct{}{}
		}
		for k := range right {
			keys[k] = struct{}{}
		}
		names := make([]string, 0, len(keys))
		for k := range keys {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			lv, lok := left[k]
			rv, rok := right[k]
			child := join(path, k)
			if lok != rok {
				*paths = append(*paths, child)
				continue
			}
			diffWalk(child, lv, rv, paths)
		}
	case []any:
		right, ok := b.([]any)
		if !ok {
			*paths = append(*paths, orRoot(path))
			return
		}
		if len(left) != len(right) {
			*paths = append(*paths, orRoot(path)+".length")
			return
		}
		for i := range left {
			diffWalk(fmt.Sprintf("%s[%d]", path, i), left[i], right[i], paths)
		}
	default:
		if !scalarEqual(a, b) {
			*paths = append(*paths, orRoot(path))
		}
	}
}

// scalarEqual compares decoded JSON scalars. json.Number is compared by its
// literal text, which is exact for the integer counters this protocol carries.
func scalarEqual(a, b any) bool {
	an, aok := a.(json.Number)
	bn, bok := b.(json.Number)
	if aok || bok {
		if !aok || !bok {
			return false
		}
		return an.String() == bn.String()
	}
	return a == b
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func orRoot(path string) string {
	if path == "" {
		return "<root>"
	}
	return path
}

// CompareTranscripts compares two transcripts request-for-request. A request_id
// present in one transcript and absent from the other is a hard error rather
// than a skipped row, so a short run can never look like agreement.
func CompareTranscripts(javaPath, rustPath string) (*Summary, error) {
	java, javaOrder, err := LoadTranscript(javaPath)
	if err != nil {
		return nil, err
	}
	rust, _, err := LoadTranscript(rustPath)
	if err != nil {
		return nil, err
	}
	if len(java) != len(rust) {
		return nil, fmt.Errorf("transcript length mismatch: java=%d rust=%d", len(java), len(rust))
	}
	summary := &Summary{
		Total: len(javaOrder),
		ComparedFieldsNote: "every field of the response envelope is compared recursively, " +
			"including outcome, error (code/close_code/detail), counts, final_state, close, " +
			"events, frames, transitions, initial_state, role, protocol, version, request_id " +
			"and request_digest; presence/absence differences are reported, not ignored",
		ExcludedFromComparisonNote: "only the top-level runtime identity object is excluded " +
			"(it names which artifact answered, so it necessarily differs); error.detail is " +
			"COMPARED and reported, but a divergence confined to it alone is classified " +
			"identical_except_error_detail rather than behavioral",
	}
	for _, id := range javaOrder {
		rustResponse, ok := rust[id]
		if !ok {
			return nil, fmt.Errorf("request_id %s present in java transcript, absent from rust transcript", id)
		}
		comparison := CompareResponses(java[id], rustResponse)
		summary.Comparisons = append(summary.Comparisons, comparison)
		switch comparison.Verdict {
		case Identical:
			summary.Identical++
		case DetailOnly:
			summary.DetailOnly++
			summary.DetailOnlyIDs = append(summary.DetailOnlyIDs, id)
		case Divergent:
			summary.Divergent++
			summary.DivergentIDs = append(summary.DivergentIDs, id)
		}
	}
	return summary, nil
}

// String renders a one-line human summary.
func (s *Summary) String() string {
	return fmt.Sprintf("total=%d identical=%d detail_only=%d divergent=%d [%s]",
		s.Total, s.Identical, s.DetailOnly, s.Divergent, strings.Join(s.DivergentIDs, ","))
}
