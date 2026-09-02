package formalplan

// THE MEASURING INSTRUMENT FOR THIS DOCUMENT'S INERTNESS.
//
// The lane that produced concurrencyresults.go exists to find evidence
// artifacts that cannot fail. Its own headline number — "N of this document's
// 162 JSON leaves produce no finding when corrupted" — was for two rounds a
// figure typed into a commit message and a receipt from an ad-hoc run that
// left no reproducible instrument behind. It was wrong twice, in two different
// directions, and both wrong versions reached the project owner.
//
// So the enumeration lives here now, runs in `go test ./...`, and pins its
// result. If a check is weakened, a leaf that was CHECKED becomes INERT and
// this test fails naming it; if a check is strengthened without updating the
// receipt, it fails the other way. The number in the receipt, in results.json
// and in this file's doc comments cannot drift from the measurement again
// without a test going red.
//
// THE SUBSTITUTION STRATEGY, AND WHY IT IS NOT ONE SENTINEL. Review 01a0487b
// round 3 BLOCKING 1: the round-2 enumeration replaced each leaf with a single
// obviously-wrong sentinel and called the leaf CHECKED if that produced a
// finding. That measures whether a leaf is looked at, not whether it is
// pinned. Measured against the round-2 tree: native_stress.suite replaced by
// the unrelated but existing path `go.mod` passed both validators at exit 0,
// and so did either regression reference rewritten to `<same file>::test` —
// because path existence and strings.Contains accept any resolvable string.
// Those three leaves were counted CHECKED and were not.
//
// A leaf is CHECKED here only if EVERY candidate in crLeafCandidates is
// refused. The candidates are shaped like the value they replace — a path
// becomes a different real path, a digest becomes a different real-looking
// digest, a verdict token becomes a different verdict token that already
// appears in this document, a sentence with a number in it keeps the sentence
// and moves the number, prose is swapped with other prose from the same
// document — so INERT means "a plausible wrong value is accepted", not "an
// obviously malformed value is accepted".
//
// HOW MANY CANDIDATES, AND WHY THE ANSWER IS NOT A RANGE. Review 01a0487b
// round 4 BLOCKING 3: the round-3 receipt said "162 of 162 leaves attacked,
// 2 to 6 candidates each". That was a fourth number typed rather than read.
// The measured shape is 1 to 6, and the 1 is not a weakness — it is the only
// honest count for a boolean. A boolean has exactly one other value, so the
// single flip IS the exhaustive enumeration of wrong values for that leaf;
// adding a second candidate would mean substituting a non-boolean, which is a
// type error and not a plausible wrong reading. So the true statement is
// "1 candidate for each of the six booleans, because flipping a boolean is
// exhaustive; 2 to 6 for every other leaf", and
// TestConcurrencyResultsCandidateBatteryIsMeasured derives all three of those
// numbers from the battery rather than trusting this comment.
//
// DELETION IS A SEPARATE AXIS. Review 01a0487b round 3 BLOCKING 2: substitution
// cannot see the omission gap, because an absent key decodes to the zero value
// and the zero value is often exactly the value that agrees with everything.
// TestConcurrencyResultsEveryModeledKeyIsRequired measures that axis.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Walking the document
// ---------------------------------------------------------------------------

// crLeafPath addresses one position in the document. Object steps are keys,
// array steps are indices; the printed form is the dotted/bracketed notation
// used in the receipt and in results.json's own prose.
type crLeafPath []any

func (p crLeafPath) String() string {
	var out strings.Builder
	for _, step := range p {
		switch value := step.(type) {
		case string:
			if out.Len() > 0 {
				out.WriteByte('.')
			}
			out.WriteString(value)
		case int:
			fmt.Fprintf(&out, "[%d]", value)
		}
	}
	return out.String()
}

func (p crLeafPath) clone() crLeafPath {
	out := make(crLeafPath, len(p))
	copy(out, p)
	return out
}

type crLeaf struct {
	Path  crLeafPath
	Value any
}

// crWalkLeaves returns every scalar leaf of the document in document order.
func crWalkLeaves(node any, at crLeafPath, out *[]crLeaf) {
	switch value := node.(type) {
	case map[string]any:
		for _, key := range crOrderedKeys(value) {
			crWalkLeaves(value[key], append(at.clone(), key), out)
		}
	case []any:
		for index, element := range value {
			crWalkLeaves(element, append(at.clone(), index), out)
		}
	default:
		*out = append(*out, crLeaf{Path: at.clone(), Value: node})
	}
}

// crOrderedKeys keeps the enumeration deterministic. encoding/json decodes
// objects into maps, which have no order, so the printed leaf list would
// otherwise shuffle between runs and make the pinned set unreviewable.
func crOrderedKeys(object map[string]any) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// crAssign writes value at path, and crDelete removes the key or array
// element at path. Both operate on the decoded document in place.
func crAssign(document map[string]any, path crLeafPath, value any) {
	container := crContainerAt(document, path)
	switch parent := container.(type) {
	case map[string]any:
		parent[path[len(path)-1].(string)] = value
	case []any:
		parent[path[len(path)-1].(int)] = value
	}
}

func crDelete(document map[string]any, path crLeafPath) {
	last := path[len(path)-1]
	if len(path) == 1 {
		if key, ok := last.(string); ok {
			delete(document, key)
		}
		return
	}
	grand := crContainerAt(document, path[:len(path)-1])
	container := crContainerAt(document, path)
	switch parent := container.(type) {
	case map[string]any:
		delete(parent, last.(string))
	case []any:
		index := last.(int)
		shortened := append(append([]any{}, parent[:index]...), parent[index+1:]...)
		switch owner := grand.(type) {
		case map[string]any:
			owner[path[len(path)-2].(string)] = shortened
		case []any:
			owner[path[len(path)-2].(int)] = shortened
		}
	}
}

// crContainerAt returns the container that directly holds path's last step.
func crContainerAt(document map[string]any, path crLeafPath) any {
	var current any = document
	for _, step := range path[:len(path)-1] {
		switch node := current.(type) {
		case map[string]any:
			current = node[step.(string)]
		case []any:
			current = node[step.(int)]
		}
	}
	return current
}

// ---------------------------------------------------------------------------
// The candidate battery
// ---------------------------------------------------------------------------

var (
	crRefPattern        = regexp.MustCompile(`^([A-Za-z0-9_./-]+)::(.+)$`)
	crSHA256Pattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	crBlobPattern       = regexp.MustCompile(`^[0-9a-f]{40}$`)
	crStampPattern      = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)
	crTokenPattern      = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	crFirstNumPattern   = regexp.MustCompile(`\d+`)
	crUnrelatedRealPath = "go.mod"
)

// crLeafCandidates is the battery. Every candidate is a value the same reader
// would find plausible in that position and that is NOT what the run produced.
func crLeafCandidates(root string, value any, otherStrings []string, otherTokens []string) []any {
	switch typed := value.(type) {
	case bool:
		// EXHAUSTIVE, not thin. A boolean has one other value; this is every
		// wrong value the leaf can hold. See the header note on round 4
		// BLOCKING 3 — the receipt's "2 to 6 candidates each" was false here
		// and the honest reading is "1, and 1 is all there is".
		return []any{!typed}
	case float64:
		candidates := []any{typed + 1}
		if crSentinelOnly() {
			return candidates
		}
		if typed != 0 {
			candidates = append(candidates, float64(0))
		}
		return append(candidates, typed*2+7)
	case nil:
		return []any{"MUTATED"}
	case string:
		return crStringCandidates(root, typed, otherStrings, otherTokens)
	}
	return nil
}

// crSentinelOnly reproduces the round-2 substitution strategy exactly — one
// wrong value per leaf — so the two readings can be compared on the same tree
// and the difference attributed to the strategy rather than to the tree.
func crSentinelOnly() bool { return os.Getenv("CR_LEAF_ENUM_STRATEGY") == "sentinel" }

func crStringCandidates(root, value string, otherStrings, otherTokens []string) []any {
	seen := map[string]struct{}{value: {}}
	var candidates []any
	add := func(candidate string) {
		if _, done := seen[candidate]; done || candidate == "" {
			return
		}
		seen[candidate] = struct{}{}
		candidates = append(candidates, candidate)
	}

	// 1. The round-2 sentinel, kept so this enumeration is a strict superset
	//    of the one it replaces.
	add("MUTATED")
	if crSentinelOnly() {
		return candidates
	}

	// 2. A reference `<file>::<test>` keeps its file and names something the
	//    file trivially contains. This is review 01a0487b round 3's example:
	//    strings.Contains accepts it, so it must not be accepted any more.
	if match := crRefPattern.FindStringSubmatch(value); match != nil {
		add(match[1] + "::test")
		add(match[1] + "::" + strings.ToLower(match[1][strings.LastIndexByte(match[1], '/')+1:]))
	}

	// 3. A sentence that OPENS with a repository-relative path that resolves:
	//    swap the path for a different one that also resolves and leave the
	//    sentence intact. The reviewer's `native_stress.suite` -> `go.mod`.
	if fields := strings.Fields(value); len(fields) > 0 {
		head := strings.TrimSuffix(fields[0], ":")
		if head != crUnrelatedRealPath && crResolves(root, head) {
			add(strings.Replace(value, head, crUnrelatedRealPath, 1))
			add(crUnrelatedRealPath)
		}
	}

	// 4. Digests and blob ids: a different value of the same shape.
	if crSHA256Pattern.MatchString(value) || crBlobPattern.MatchString(value) {
		add(crFlipLastHex(value))
	}

	// 5. Timestamps: a different real timestamp.
	if crStampPattern.MatchString(value) {
		add("20" + strconv.Itoa(30) + value[4:])
	}

	// 6. A bare verdict/scope token: a different token this document already
	//    uses somewhere, so the substitution reads as legitimate vocabulary.
	if crTokenPattern.MatchString(value) {
		for _, token := range otherTokens {
			if token != value {
				add(token)
				break
			}
		}
	}

	// 7. Prose carrying a number: keep the sentence, move the number. This is
	//    the shape of every "the record says 79920 but the run said 11" edit.
	if location := crFirstNumPattern.FindStringIndex(value); location != nil {
		digits := value[location[0]:location[1]]
		if parsed, err := strconv.Atoi(digits); err == nil {
			add(value[:location[0]] + strconv.Itoa(parsed+1) + value[location[1]:])
		}
	}

	// 8. Neighbour swap: real prose from elsewhere in this same document. A
	//    wrong sentence that is indistinguishable from a right one to any
	//    non-empty or membership check.
	for _, other := range otherStrings {
		if other != value && len(other) > 24 {
			add(other)
			break
		}
	}

	// 9. Truncation: the claim softened rather than replaced.
	if len(value) > 24 {
		add(value[:len(value)/2])
	}
	return candidates
}

func crResolves(root, rel string) bool {
	if root == "" || rel == "" || strings.HasPrefix(rel, "/") {
		return false
	}
	_, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel)))
	return err == nil
}

func crFlipLastHex(value string) string {
	last := value[len(value)-1]
	replacement := byte('a')
	if last == 'a' {
		replacement = 'b'
	}
	return value[:len(value)-1] + string(replacement)
}

// ---------------------------------------------------------------------------
// Running the enumeration
// ---------------------------------------------------------------------------

// crBlocking reports whether the validator refused the document. Advisories
// are not refusals: an advisory is what the validator emits when it declines
// to check something, which is the opposite of a finding.
func crBlocking(findings []ModelFinding) []ModelFinding {
	var out []ModelFinding
	for _, finding := range findings {
		if finding.Severity != SeverityAdvisory {
			out = append(out, finding)
		}
	}
	return out
}

type crEnumOutcome struct {
	Path      string
	Inert     bool
	Accepted  string // the first candidate that was accepted, printed for the receipt
	Candidate int    // how many candidates were tried
}

func crRunEnumeration(t *testing.T, root, resultsPath string) []crEnumOutcome {
	t.Helper()
	raw, err := os.ReadFile(resultsPath)
	if err != nil {
		t.Fatalf("read results: %v", err)
	}
	var pristine map[string]any
	if err := json.Unmarshal(raw, &pristine); err != nil {
		t.Fatalf("decode results: %v", err)
	}

	var leaves []crLeaf
	crWalkLeaves(pristine, nil, &leaves)

	// The pools the battery draws its plausible-wrong values from.
	var otherStrings, otherTokens []string
	for _, leaf := range leaves {
		if text, ok := leaf.Value.(string); ok {
			otherStrings = append(otherStrings, text)
			if crTokenPattern.MatchString(text) {
				otherTokens = append(otherTokens, text)
			}
		}
	}

	dir := t.TempDir()
	scratch := filepath.Join(dir, "results.json")
	validate := func(document map[string]any) []ModelFinding {
		encoded, err := json.MarshalIndent(document, "", "  ")
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if err := os.WriteFile(scratch, encoded, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		return crBlocking(ValidateConcurrencyResults(ConcurrencyResultsInputs{ResultsPath: scratch, Root: root}))
	}

	// Control: the reformatting this harness performs must itself be inert,
	// or every reading below would be measuring the harness.
	if findings := validate(pristine); len(findings) != 0 {
		t.Fatalf("the pristine document does not validate through the harness: %v", crTestCodes(findings))
	}

	outcomes := make([]crEnumOutcome, 0, len(leaves))
	for _, leaf := range leaves {
		candidates := crLeafCandidates(root, leaf.Value, otherStrings, otherTokens)
		outcome := crEnumOutcome{Path: leaf.Path.String(), Candidate: len(candidates)}
		for _, candidate := range candidates {
			document := crReload(t, raw)
			crAssign(document, leaf.Path, candidate)
			if len(validate(document)) == 0 {
				outcome.Inert = true
				outcome.Accepted = crPrintable(candidate)
				break
			}
		}
		outcomes = append(outcomes, outcome)
	}
	return outcomes
}

func crReload(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("decode results: %v", err)
	}
	return document
}

func crPrintable(value any) string {
	text := fmt.Sprintf("%v", value)
	if len(text) > 70 {
		return text[:70] + "..."
	}
	return text
}

// ---------------------------------------------------------------------------
// The pinned readings
// ---------------------------------------------------------------------------

// crExpectedLeafCount is the document's leaf cardinality. It is pinned so the
// denominator of every "N of 327" statement is itself a measurement. It was
// 162 until the landing union merged claude/us017-ac2's record into this one.
const crExpectedLeafCount = 327

// crInertLeaves is the residual set: leaves that still accept a plausible
// wrong value. Transcribed from CR_LEAF_ENUM=print, not chosen.
//
// WHAT IS LEFT, AND WHY EACH ONE IS LEFT. Four classes, and none of them is
// "we ran out of ideas":
//
//   - Defect narrative (description, fix, found_by, note, finding_verbatim,
//     ac_reading, reproduction_read, reproduction): 51 leaves across the ten
//     defects the landed record rolls. How a defect was found, what it was,
//     what the reviewer wrote and how it was fixed is prose about history. It
//     carries no number, verdict, identity or scope claim that anything in
//     this tree can contradict. The claim ceiling inside a defect record — its
//     RED evidence, its regression coverage, its shrink, its reproduction's
//     seed — is bound; the story around it is not.
//   - Seven RED readings — defects 3, 4, 5, 6, 8, 9 and the sweep's
//     harness_polarity_read — each accept ONE candidate: a number moved inside
//     the runtime output they quote (frames=1 becoming frames=2 in a label the
//     failing test printed; "budget 1:" becoming "budget 2:" in the violation
//     the pre-fix sweep printed). The quoted ASSERTION text is resolved into
//     the body of a test the defect names, the polarity read must name a
//     control test the harness declares, and the quotation must be whole, so
//     "MUTATED", a neighbour's reading and a truncation are refused; the
//     values the pre-fix run printed exist nowhere in the committed tree to
//     compare against.
//   - Prose that accepts one candidate — a number moved inside a citation
//     token (AC2, round-2, io_loop.rs:228, US-017, a commit id, a session id)
//     or a truncation that keeps every load-bearing clause: adapter_model,
//     the two run citations' binding and executed_against sentences, the
//     sweep's why, limitations 7, 9, 10 and 11, sha256_provenance,
//     recorded_at_provenance, retention.demonstration, added_by,
//     pinned_artifacts_unchanged_by_review_round and
//     real_defect_regressions[1]. Their shape and their load-bearing clauses
//     are checked (phrases from both halves, re-derived numbers where the
//     sentence quotes a counter, the seed's own fields where it names a seed);
//     the token values are attested, not derived.
//   - native_stress.rustc and revision_note, as in every round before this
//     one: a compiler version string and the session prose.
//
// THE SIX found_index ORDINALS ARE GONE FROM THIS LIST, after being named in
// it for three rounds. They were the class the reviewer kept re-flagging: the
// retention run PRINTED each ordinal (US017_RETENTION found_index=) but the
// pinned seed did not carry it, so the document could quote any number and
// nothing disagreed. The retention test in
// rust/ws-driver/tests/schedule_exploration.rs now writes `found_index=` into
// the seed body it re-derives and byte-compares, and the Go validator compares
// the document's ordinal to the seed's — so the ordinals are pinned by exactly
// the digest that already pinned the schedule beside them. Measured after the
// fix: substituting another artifact's real ordinal, an adjacent ordinal, or a
// plausible small integer each produces RESULTS_SEED_CONTENT_CONTRADICTED.
//
// THE FATAL-TERMINATION SWEEP'S MAGNITUDES ARE GONE FROM THIS LIST TOO. At the
// 2026-09-02 landing union the document carried the sweep block claude/us017-ac2
// added — two totals and, after the union, five per-budget maps — and the
// first enumeration of the merged document read every one of those numbers as
// INERT: fatal_path_drop_runs_total moved from 56189 to 56190 and nothing
// disagreed, exactly the transcription the record's own limitation admitted.
// The harness now cites the five US017_FATAL_SWEEP lines it prints
// (execution.fatal_termination_sweep.executed_run.sweep_stdout_lines, compared
// element-for-element by assert_committed_results_cite_this_sweep) and
// crValidateSweepRun re-derives the block from them.
var crInertLeaves = []string{
	"adapter_model",
	"defects_found_and_fixed[0].description",
	"defects_found_and_fixed[0].fix",
	"defects_found_and_fixed[0].found_by",
	"defects_found_and_fixed[1].description",
	"defects_found_and_fixed[1].fix",
	"defects_found_and_fixed[1].found_by",
	"defects_found_and_fixed[1].note",
	"defects_found_and_fixed[2].description",
	"defects_found_and_fixed[2].finding_verbatim",
	"defects_found_and_fixed[2].fix",
	"defects_found_and_fixed[2].found_by",
	"defects_found_and_fixed[3].description",
	"defects_found_and_fixed[3].finding_verbatim",
	"defects_found_and_fixed[3].fix",
	"defects_found_and_fixed[3].found_by",
	"defects_found_and_fixed[3].red_evidence",
	"defects_found_and_fixed[4].ac_reading",
	"defects_found_and_fixed[4].description",
	"defects_found_and_fixed[4].finding_verbatim",
	"defects_found_and_fixed[4].fix",
	"defects_found_and_fixed[4].found_by",
	"defects_found_and_fixed[4].red_evidence",
	"defects_found_and_fixed[5].description",
	"defects_found_and_fixed[5].finding_verbatim",
	"defects_found_and_fixed[5].fix",
	"defects_found_and_fixed[5].found_by",
	"defects_found_and_fixed[5].red_evidence",
	"defects_found_and_fixed[5].reproduction_read",
	"defects_found_and_fixed[6].description",
	"defects_found_and_fixed[6].finding_verbatim",
	"defects_found_and_fixed[6].fix",
	"defects_found_and_fixed[6].found_by",
	"defects_found_and_fixed[6].red_evidence",
	"defects_found_and_fixed[7].description",
	"defects_found_and_fixed[7].finding_verbatim",
	"defects_found_and_fixed[7].fix",
	"defects_found_and_fixed[7].found_by",
	"defects_found_and_fixed[7].note",
	"defects_found_and_fixed[7].reproduction_read",
	"defects_found_and_fixed[8].description",
	"defects_found_and_fixed[8].finding_verbatim",
	"defects_found_and_fixed[8].fix",
	"defects_found_and_fixed[8].found_by",
	"defects_found_and_fixed[8].note",
	"defects_found_and_fixed[8].red_evidence",
	"defects_found_and_fixed[8].reproduction_read",
	"defects_found_and_fixed[9].ac_reading",
	"defects_found_and_fixed[9].description",
	"defects_found_and_fixed[9].finding_verbatim",
	"defects_found_and_fixed[9].fix",
	"defects_found_and_fixed[9].found_by",
	"defects_found_and_fixed[9].red_evidence",
	"defects_found_and_fixed[9].reproduction",
	"execution.executed_run.binding",
	"execution.executed_run.executed_against",
	"execution.fatal_termination_sweep.executed_run.executed_against",
	"execution.fatal_termination_sweep.harness_polarity_read",
	"execution.fatal_termination_sweep.why",
	"limitations[7]",
	"limitations[9]",
	"limitations[10]",
	"limitations[11]",
	"native_stress.rustc",
	"preregistered_plan.sha256_provenance",
	"recorded_at_provenance",
	"retention.demonstration",
	"retention.minimized_artifacts[6].added_by",
	"retention.pinned_artifacts_unchanged_by_review_round",
	"retention.real_defect_regressions[1]",
	"revision_note",
}

// TestConcurrencyResultsLeafInertnessIsPinned is the measurement of record.
//
// The residual set below is not a target; it is what the enumeration printed,
// transcribed. Every entry is a leaf whose value can be replaced with a
// plausible wrong one and neither validator says anything. They are named
// individually so the receipt cannot round them off.
func TestConcurrencyResultsLeafInertnessIsPinned(t *testing.T) {
	outcomes := crRunEnumeration(t, crTestRoot, crTestResultsPath)
	if len(outcomes) != crExpectedLeafCount {
		t.Fatalf("the document has %d leaves, the pinned reading covers %d", len(outcomes), crExpectedLeafCount)
	}
	measured := map[string]string{}
	for _, outcome := range outcomes {
		if outcome.Inert {
			measured[outcome.Path] = outcome.Accepted
		}
	}
	expected := map[string]struct{}{}
	for _, path := range crInertLeaves {
		expected[path] = struct{}{}
	}
	for path, accepted := range measured {
		if _, listed := expected[path]; !listed {
			t.Errorf("leaf %s is INERT and is not in the pinned residual list (accepted %q): a check was weakened, or the list is stale", path, accepted)
		}
	}
	for path := range expected {
		if _, still := measured[path]; !still {
			t.Errorf("leaf %s is pinned as INERT but is now CHECKED: the residual list understates the binding and must shrink", path)
		}
	}
	if t.Failed() {
		t.Fatalf("measured %d inert of %d leaves, pinned %d", len(measured), len(outcomes), len(crInertLeaves))
	}
}

// The three numbers the receipt is allowed to state about the battery's size.
// They are asserted, not described, so a receipt sentence can be checked
// against them: see TestConcurrencyResultsCandidateBatteryIsMeasured.
const (
	crBooleanLeafCandidates    = 1 // exhaustive: a boolean has one other value
	crMinNonBooleanCandidates  = 2
	crMaxCandidatesForAnyLeaf  = 6
	crExpectedBooleanLeafCount = 6
)

// TestConcurrencyResultsCandidateBatteryIsMeasured is review 01a0487b round 4
// BLOCKING 3.
//
// The round-3 receipt claimed "162 of 162 leaves attacked, 2 to 6 candidates
// each". It was the lane's fourth transcribed figure — after 108, after the
// 35 undercount — and it was wrong in the lane whose whole purpose is catching
// exactly that. Every boolean leaf gets ONE candidate, so the real span is
// 1 to 6.
//
// The correction is not a better sentence, it is a measurement: this test
// derives the span from the battery itself and refuses the three numbers if
// they drift. It also asserts WHY the 1 is not a gap — for a boolean the
// single flip is the complete enumeration of wrong values, so a leaf with one
// candidate is exhaustively attacked and a leaf with six is not.
func TestConcurrencyResultsCandidateBatteryIsMeasured(t *testing.T) {
	raw, err := os.ReadFile(crTestResultsPath)
	if err != nil {
		t.Fatalf("read results: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("decode results: %v", err)
	}
	var leaves []crLeaf
	crWalkLeaves(document, nil, &leaves)

	var otherStrings, otherTokens []string
	for _, leaf := range leaves {
		if text, ok := leaf.Value.(string); ok {
			otherStrings = append(otherStrings, text)
			if crTokenPattern.MatchString(text) {
				otherTokens = append(otherTokens, text)
			}
		}
	}

	histogram := map[int]int{}
	booleans, minimumNonBoolean, maximum := 0, 0, 0
	for _, leaf := range leaves {
		candidates := crLeafCandidates(crTestRoot, leaf.Value, otherStrings, otherTokens)
		if len(candidates) == 0 {
			t.Fatalf("leaf %s gets no candidate at all, so it is not attacked", leaf.Path)
		}
		histogram[len(candidates)]++
		if len(candidates) > maximum {
			maximum = len(candidates)
		}
		value, isBoolean := leaf.Value.(bool)
		if isBoolean {
			booleans++
			if len(candidates) != crBooleanLeafCandidates {
				t.Errorf("boolean leaf %s gets %d candidates, not %d", leaf.Path, len(candidates), crBooleanLeafCandidates)
				continue
			}
			// Exhaustive: the one candidate is the only other value.
			if flipped, ok := candidates[0].(bool); !ok || flipped != !value {
				t.Errorf("boolean leaf %s is attacked with %v, which is not its negation, so the single "+
					"candidate is not the exhaustive one", leaf.Path, candidates[0])
			}
			continue
		}
		if len(candidates) < crMinNonBooleanCandidates {
			t.Errorf("non-boolean leaf %s gets only %d candidate(s); the receipt's lower bound for a "+
				"non-boolean leaf is %d", leaf.Path, len(candidates), crMinNonBooleanCandidates)
		}
		if minimumNonBoolean == 0 || len(candidates) < minimumNonBoolean {
			minimumNonBoolean = len(candidates)
		}
	}

	if booleans != crExpectedBooleanLeafCount {
		t.Errorf("the document has %d boolean leaves, the pinned reading covers %d", booleans, crExpectedBooleanLeafCount)
	}
	if minimumNonBoolean != crMinNonBooleanCandidates {
		t.Errorf("the smallest non-boolean battery is %d, the receipt says %d", minimumNonBoolean, crMinNonBooleanCandidates)
	}
	if maximum != crMaxCandidatesForAnyLeaf {
		t.Errorf("the largest battery is %d, the receipt says %d", maximum, crMaxCandidatesForAnyLeaf)
	}
	if t.Failed() {
		sizes := make([]int, 0, len(histogram))
		for size := range histogram {
			sizes = append(sizes, size)
		}
		sort.Ints(sizes)
		for _, size := range sizes {
			t.Logf("candidates=%d -> %d leaves", size, histogram[size])
		}
	}
}

// ---------------------------------------------------------------------------
// The omission axis
// ---------------------------------------------------------------------------

// crWalkKeys returns every removable position in the document: every object
// key at every depth, container or scalar, and every array element. This is a
// strict superset of the leaf set, because deleting `execution.counters`
// wholesale is an attack the leaf walk cannot express.
func crWalkKeys(node any, at crLeafPath, out *[]crLeafPath) {
	switch value := node.(type) {
	case map[string]any:
		for _, key := range crOrderedKeys(value) {
			path := append(at.clone(), key)
			*out = append(*out, path)
			crWalkKeys(value[key], path, out)
		}
	case []any:
		for index, element := range value {
			path := append(at.clone(), index)
			*out = append(*out, path)
			crWalkKeys(element, path, out)
		}
	}
}

func crRunOmission(t *testing.T, root, resultsPath string) (accepted []string, total int) {
	t.Helper()
	raw, err := os.ReadFile(resultsPath)
	if err != nil {
		t.Fatalf("read results: %v", err)
	}
	var pristine map[string]any
	if err := json.Unmarshal(raw, &pristine); err != nil {
		t.Fatalf("decode results: %v", err)
	}
	var positions []crLeafPath
	crWalkKeys(pristine, nil, &positions)

	dir := t.TempDir()
	scratch := filepath.Join(dir, "results.json")
	for _, path := range positions {
		document := crReload(t, raw)
		crDelete(document, path)
		encoded, err := json.MarshalIndent(document, "", "  ")
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if err := os.WriteFile(scratch, encoded, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		findings := crBlocking(ValidateConcurrencyResults(ConcurrencyResultsInputs{ResultsPath: scratch, Root: root}))
		if len(findings) == 0 {
			accepted = append(accepted, path.String())
		}
	}
	return accepted, len(positions)
}

// TestConcurrencyResultsEveryModeledKeyIsRequired is review 01a0487b round 3
// BLOCKING 2, and it is the sharpest finding this document has taken.
//
// DisallowUnknownFields guards one direction only: a field nothing models
// cannot be ADDED. It says nothing about DELETING a modeled one, because an
// absent key decodes to the zero value — and for a claim-ceiling boolean the
// zero value is `false`, which is exactly the value that agrees with the plan,
// with the cited run and with every other check. A forger does not have to
// write a false value; removing the field is enough.
//
// Measured against the committed binding BEFORE this check existed, each
// deletion applied to the real tree, the evidence DAG refrozen through its own
// LINKAGE_REGENERATE=1 flow and BOTH validators run: deleting `truncated`,
// `producer_admission_fairness_claimed`, `independent_review_claimed`,
// `production` or `publication` each gave `go test ./... -count=1` exit 0 and
// `cargo test -p ws-driver --release --test schedule_exploration` exit 0.
//
// The five the reviewer named are a sample. This test asserts the whole class:
// no position in the document may be removed without a finding.
func TestConcurrencyResultsEveryModeledKeyIsRequired(t *testing.T) {
	accepted, total := crRunOmission(t, crTestRoot, crTestResultsPath)
	if total < crExpectedLeafCount {
		t.Fatalf("the omission walk covered %d positions, fewer than the %d leaves", total, crExpectedLeafCount)
	}
	if len(accepted) != 0 {
		for _, path := range accepted {
			t.Errorf("deleting %s produces no finding: its absence decodes to a zero value that agrees with everything", path)
		}
		t.Fatalf("%d of %d removable positions are omission holes", len(accepted), total)
	}
}

// CR_LEAF_ENUM=print dumps the full per-leaf reading. This is how the numbers
// quoted in the receipt and in results.json's revision_note are produced.
func TestConcurrencyResultsLeafEnumerationReport(t *testing.T) {
	if os.Getenv("CR_LEAF_ENUM") != "print" {
		t.Skip("set CR_LEAF_ENUM=print to dump the per-leaf enumeration")
	}
	outcomes := crRunEnumeration(t, crTestRoot, crTestResultsPath)
	inert := 0
	histogram := map[int]int{}
	for _, outcome := range outcomes {
		state := "CHECKED"
		if outcome.Inert {
			state = "INERT"
			inert++
		}
		histogram[outcome.Candidate]++
		fmt.Printf("%-7s %-72s candidates=%d accepted=%q\n", state, outcome.Path, outcome.Candidate, outcome.Accepted)
	}
	// The battery's own size, printed with the reading. Round 4 BLOCKING 3 was
	// a receipt sentence about this histogram that nobody had ever printed.
	sizes := make([]int, 0, len(histogram))
	for size := range histogram {
		sizes = append(sizes, size)
	}
	sort.Ints(sizes)
	for _, size := range sizes {
		fmt.Printf("LEAF_BATTERY candidates=%d leaves=%d\n", size, histogram[size])
	}
	fmt.Printf("LEAF_ENUMERATION leaves=%d checked=%d inert=%d\n", len(outcomes), len(outcomes)-inert, inert)
}
