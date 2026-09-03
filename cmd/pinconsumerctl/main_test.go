package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	output, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Skipf("not in a git checkout: %v", err)
	}
	return strings.TrimSpace(string(output))
}

// splitPinFields must recognise a digest with or without the sha256: prefix,
// and must only treat a string as a path when git actually tracks it -- an
// arbitrary string that looks path-shaped is not a pin.
func TestSplitPinFieldsRecognisesDigestsAndOnlyTrackedPaths(t *testing.T) {
	tracked := map[string]bool{"internal/lab/sandbox.go": true}

	paths, digests := splitPinFields(map[string]any{
		"path":       "internal/lab/sandbox.go",
		"digest":     "sha256:acb7ecd0b2cf917673342506ad25a43cbce83ab87b2ea4832cdfefd23f7374cf",
		"bare":       "aef61f2b265b27559b809900083308a1eedf308d459d7cfdd3600889ae4cad6e",
		"not_a_path": "internal/lab/does-not-exist.go",
		"bytes":      float64(30704),
	}, tracked)

	if len(paths) != 1 || paths[0] != "internal/lab/sandbox.go" {
		t.Errorf("tracked path not identified uniquely: %v", paths)
	}
	if len(digests) != 2 {
		t.Errorf("both prefixed and bare digests must be read, got %v", digests)
	}
}

// A "./"-prefixed path is the same path. Missing this made the index blind to a
// whole spelling of every pin.
func TestSplitPinFieldsNormalisesDotSlash(t *testing.T) {
	paths, _ := splitPinFields(map[string]any{
		"path":   "./internal/lab/sandbox.go",
		"digest": "sha256:acb7ecd0b2cf917673342506ad25a43cbce83ab87b2ea4832cdfefd23f7374cf",
	}, map[string]bool{"internal/lab/sandbox.go": true})

	if len(paths) != 1 || paths[0] != "internal/lab/sandbox.go" {
		t.Errorf("./-prefixed path not normalised: %v", paths)
	}
}

// walk must reach objects nested inside arrays inside objects, and must name
// them with a pointer a reader can navigate to. A detector that reports a
// finding without a locatable pointer is not much better than none.
func TestWalkReachesNestedObjectsAndNamesThem(t *testing.T) {
	var document any
	if err := json.Unmarshal([]byte(`{"a":{"b":[{"c":1},{"d":2}]}}`), &document); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var pointers []string
	walk(document, "$", func(_ map[string]any, pointer string) {
		pointers = append(pointers, pointer)
	})

	want := map[string]bool{"$": true, "$.a": true, "$.a.b[0]": true, "$.a.b[1]": true}
	if len(pointers) != len(want) {
		t.Fatalf("expected %d objects, got %v", len(want), pointers)
	}
	for _, pointer := range pointers {
		if !want[pointer] {
			t.Errorf("unexpected pointer %q", pointer)
		}
	}
}

// The load-bearing negative: when SOME digest in the object matches the named
// file, the object is not dangling. Without this the detector would report every
// pin in the tree.
func TestADigestThatMatchesIsNotReportedAsDangling(t *testing.T) {
	root := repoRoot(t)
	target := filepath.Join(root, "go.mod")
	if _, err := os.Stat(target); err != nil {
		t.Skipf("go.mod not present: %v", err)
	}
	actual, ok := fileDigest(root, "go.mod")
	if !ok {
		t.Fatal("could not digest go.mod")
	}

	paths, digests := splitPinFields(map[string]any{
		"path":   "go.mod",
		"digest": "sha256:" + actual,
	}, map[string]bool{"go.mod": true})

	if len(paths) != 1 || len(digests) != 1 {
		t.Fatalf("fixture shape wrong: paths=%v digests=%v", paths, digests)
	}
	if digests[0] != actual {
		t.Errorf("a matching digest must compare equal to the file's own: %s vs %s",
			digests[0], actual)
	}
}

// F014, pinned as a regression fixture. evidence/java/test-manifest.json declares
// material_execution_path_changed_after_run:false while two of its four pinned
// sources have drifted. If someone re-pins those digests without recording a
// rationale, or the drift widens, this test must be the thing that says so.
//
// It asserts the DRIFT, deliberately -- the finding is filed and undecided, and
// the owner decision is recorded in
// drafts/self-review/findings/F014-a-code-binding-verified-against-a-copy-of-itself.md.
// When that decision lands, this test changes with it.
func TestF014ExecutionCodeBindingDriftIsStillPresentAndStillUnbound(t *testing.T) {
	root := repoRoot(t)
	content, err := os.ReadFile(filepath.Join(root, "evidence/java/test-manifest.json"))
	if err != nil {
		t.Skipf("manifest absent: %v", err)
	}
	var document struct {
		AuthoritativeRun struct {
			ExecutionCodeBinding struct {
				MaterialExecutionPathChanged bool `json:"material_execution_path_changed_after_run"`
				Sources                      []struct {
					Path   string `json:"path"`
					Digest string `json:"digest"`
					Bytes  int    `json:"bytes"`
				} `json:"sources"`
			} `json:"execution_code_binding"`
		} `json:"authoritative_run"`
	}
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	binding := document.AuthoritativeRun.ExecutionCodeBinding

	if binding.MaterialExecutionPathChanged {
		t.Fatal("the manifest now admits drift; F014's owner decision has landed" +
			" and this fixture must be rewritten to match it")
	}

	drifted := 0
	for _, source := range binding.Sources {
		actual, ok := fileDigest(root, source.Path)
		if !ok {
			t.Errorf("pinned source %s is not readable", source.Path)
			continue
		}
		declared := strings.TrimPrefix(source.Digest, "sha256:")
		if declared == actual {
			continue
		}
		drifted++
		onDisk, err := os.ReadFile(filepath.Join(root, source.Path))
		if err == nil && len(onDisk) == source.Bytes {
			t.Errorf("%s: digest differs but byte count matches the pin --"+
				" that is a different defect from F014 and needs its own reading",
				source.Path)
		}
	}

	if drifted != 2 {
		t.Errorf("F014 measured exactly 2 of 4 sources drifted; now %d."+
			" Either the drift changed or someone re-pinned: read"+
			" F014 before touching this number", drifted)
	}
}

// scratchRepo builds a throwaway git checkout so analyseDangling can be driven
// against known content. Without this, every check inside analyseDangling is
// unexercised -- two deletion attacks (the single-path guard and the self-pin
// skip) survived the helper-only suite, which is why this exists.
func scratchRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		full := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	for _, argv := range [][]string{
		{"init", "-q"},
		{"config", "user.email", "t@example.com"},
		{"config", "user.name", "t"},
		{"add", "-A"},
		{"-c", "commit.gpgsign=false", "commit", "-q", "-m", "scratch"},
	} {
		command := exec.Command("git", append([]string{"-C", root}, argv...)...)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", argv, err, output)
		}
	}
	return root
}

func TestAnalyseDanglingReportsAStalePinAndItsPointer(t *testing.T) {
	root := scratchRepo(t, map[string]string{
		"subject.txt": "the real content\n",
		"consumer.json": `{"pins":[{"path":"subject.txt",` +
			`"digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}]}`,
	})

	census, err := analyseDangling(root)
	if err != nil {
		t.Fatalf("analyse: %v", err)
	}
	if len(census.candidates) != 1 {
		t.Fatalf("expected exactly one candidate, got %d: %+v",
			len(census.candidates), census.candidates)
	}
	candidate := census.candidates[0]
	if candidate.namedPath != "subject.txt" || candidate.pointer != "$.pins[0]" {
		t.Errorf("candidate does not locate the pin: %+v", candidate)
	}
	if candidate.actual == candidate.declared {
		t.Errorf("a stale pin must report differing digests: %+v", candidate)
	}
}

// The single-path guard: an object naming TWO tracked files cannot be attributed
// to either, so it must not be reported. Attack A4 survived without this.
func TestAnalyseDanglingSkipsObjectsNamingMoreThanOnePath(t *testing.T) {
	root := scratchRepo(t, map[string]string{
		"one.txt": "one\n",
		"two.txt": "two\n",
		"consumer.json": `{"ambiguous":{"a":"one.txt","b":"two.txt",` +
			`"digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}}`,
	})

	census, err := analyseDangling(root)
	if err != nil {
		t.Fatalf("analyse: %v", err)
	}
	if len(census.candidates) != 0 {
		t.Errorf("an object naming two paths must not be attributed to either: %+v",
			census.candidates)
	}
}

// The self-pin skip: a document carrying its own digest is a different check
// (self-reference), not a dangling consumer pin. Attack A5 survived without this.
func TestAnalyseDanglingSkipsADocumentPinningItself(t *testing.T) {
	root := scratchRepo(t, map[string]string{
		"selfref.json": `{"self":{"path":"selfref.json",` +
			`"digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}}`,
	})

	census, err := analyseDangling(root)
	if err != nil {
		t.Fatalf("analyse: %v", err)
	}
	for _, candidate := range census.candidates {
		if candidate.artifact == candidate.namedPath {
			t.Errorf("a document pinning its own digest must be skipped: %+v", candidate)
		}
	}
}

// The matching-digest exit: a pin that is CORRECT must stay silent, or the
// detector reports the whole tree. Attack A3's anchor.
func TestAnalyseDanglingStaysSilentOnACorrectPin(t *testing.T) {
	content := "the real content\n"
	root := scratchRepo(t, map[string]string{"subject.txt": content})
	digest, ok := fileDigest(root, "subject.txt")
	if !ok {
		t.Fatal("could not digest the scratch subject")
	}
	consumer := `{"pins":[{"path":"subject.txt","digest":"sha256:` + digest + `"}]}`
	if err := os.WriteFile(filepath.Join(root, "consumer.json"), []byte(consumer), 0o644); err != nil {
		t.Fatalf("write consumer: %v", err)
	}
	for _, argv := range [][]string{{"add", "-A"},
		{"-c", "commit.gpgsign=false", "commit", "-q", "-m", "add consumer"}} {
		command := exec.Command("git", append([]string{"-C", root}, argv...)...)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", argv, err, output)
		}
	}

	census, err := analyseDangling(root)
	if err != nil {
		t.Fatalf("analyse: %v", err)
	}
	if len(census.candidates) != 0 {
		t.Errorf("a correct pin must not be reported: %+v", census.candidates)
	}
	if census.artifacts != 1 {
		t.Errorf("the one JSON artifact should have been counted, got %d", census.artifacts)
	}
}

// Unparsable JSON must be COUNTED, not silently dropped: a detector that skips
// what it cannot read while printing a clean census is claiming coverage it
// does not have.
func TestAnalyseDanglingCountsUnparsableArtifacts(t *testing.T) {
	root := scratchRepo(t, map[string]string{"broken.json": "{not json"})

	census, err := analyseDangling(root)
	if err != nil {
		t.Fatalf("analyse: %v", err)
	}
	if census.unparsable != 1 {
		t.Errorf("unparsable artifact not counted: %+v", census)
	}
	if census.artifacts != 0 {
		t.Errorf("an unparsable file must not count as an analysed artifact: %+v", census)
	}
}

// The blind spot a survivor-closure agent found in this tool, pinned so it
// cannot come back: `consumers` matched only the file's CURRENT digest, so an
// artifact holding a STALE pin of that file matched nothing and the command
// printed "nothing in the tree pins this file's current content". True on the
// axis it measured, and the opposite of the truth on the axis the caller is
// asking about -- "who must I update if I change this?" -- in precisely the case
// where the answer matters most.
func TestConsumersFindsAPinThatHasALREADYDrifted(t *testing.T) {
	root := scratchRepo(t, map[string]string{
		"subject.txt": "the CURRENT content\n",
		"consumer.json": `{"pins":[{"path":"subject.txt",` +
			`"digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}]}`,
	})

	report, err := analyseConsumers(root, []string{"subject.txt"})
	if err != nil {
		t.Fatalf("analyse: %v", err)
	}
	if len(report) != 1 {
		t.Fatalf("expected one target, got %d", len(report))
	}
	target := report[0]

	if len(target.current) != 0 {
		t.Errorf("no artifact holds the current digest: %+v", target.current)
	}
	if len(target.stale) != 1 {
		t.Fatalf("the stale pin must be reported, got %+v", target.stale)
	}
	if target.stale[0].artifact != "consumer.json" || target.stale[0].pointer != "$.pins[0]" {
		t.Errorf("stale pin not located: %+v", target.stale[0])
	}
}

// A correct pin belongs in `current`, never in `stale` -- otherwise every pin in
// the tree gets reported and the distinction is worthless.
func TestConsumersSeparatesCurrentPinsFromStaleOnes(t *testing.T) {
	root := scratchRepo(t, map[string]string{"subject.txt": "content\n"})
	digest, ok := fileDigest(root, "subject.txt")
	if !ok {
		t.Fatal("digest")
	}
	consumer := `{"pins":[{"path":"subject.txt","digest":"sha256:` + digest + `"}]}`
	if err := os.WriteFile(filepath.Join(root, "consumer.json"), []byte(consumer), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	for _, argv := range [][]string{{"add", "-A"},
		{"-c", "commit.gpgsign=false", "commit", "-q", "-m", "c"}} {
		if output, err := exec.Command("git", append([]string{"-C", root}, argv...)...).
			CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", argv, err, output)
		}
	}

	report, err := analyseConsumers(root, []string{"subject.txt"})
	if err != nil {
		t.Fatalf("analyse: %v", err)
	}
	if len(report[0].current) != 1 {
		t.Errorf("the matching pin must be reported as current: %+v", report[0].current)
	}
	if len(report[0].stale) != 0 {
		t.Errorf("a correct pin is not stale: %+v", report[0].stale)
	}
}

// A digest can pin a FIELD INSIDE the named file rather than the file itself.
// `assurance/concurrency/plan.json` carries `ledger_path` beside `observed_head`,
// and `observed_head` is the behaviour-delta ledger's own `head` value, not the
// ledger file's sha256. Read as a file-digest pin it looks permanently stale
// while being permanently correct -- a systematic false positive, and one this
// tool reported on real data before this test existed.
func TestAFieldPinThatIsCurrentIsNotReportedAsStale(t *testing.T) {
	// subject.json's own `head` field is what the consumer pins.
	subject := `{"head":"sha256:1111111111111111111111111111111111111111111111111111111111111111",` +
		`"records":[]}`
	root := scratchRepo(t, map[string]string{
		"subject.json": subject,
		"consumer.json": `{"binding":{"ledger_path":"subject.json",` +
			`"observed_head":"sha256:1111111111111111111111111111111111111111111111111111111111111111"}}`,
	})

	report, err := analyseConsumers(root, []string{"subject.json"})
	if err != nil {
		t.Fatalf("analyse: %v", err)
	}
	if len(report[0].stale) != 0 {
		t.Errorf("a CURRENT field pin must not be reported as stale: %+v", report[0].stale)
	}

	census, err := analyseDangling(root)
	if err != nil {
		t.Fatalf("dangling: %v", err)
	}
	for _, candidate := range census.candidates {
		if candidate.namedPath == "subject.json" {
			t.Errorf("dangling must not report a current field pin: %+v", candidate)
		}
	}
}

// The other direction: a field pin that has genuinely gone stale MUST still be
// reported, or the exemption above becomes a hole.
func TestAFieldPinThatHasDriftedIsStillReported(t *testing.T) {
	subject := `{"head":"sha256:2222222222222222222222222222222222222222222222222222222222222222",` +
		`"records":[]}`
	root := scratchRepo(t, map[string]string{
		"subject.json": subject,
		"consumer.json": `{"binding":{"ledger_path":"subject.json",` +
			`"observed_head":"sha256:1111111111111111111111111111111111111111111111111111111111111111"}}`,
	})

	report, err := analyseConsumers(root, []string{"subject.json"})
	if err != nil {
		t.Fatalf("analyse: %v", err)
	}
	if len(report[0].stale) != 1 {
		t.Fatalf("a DRIFTED field pin must still be reported: %+v", report[0].stale)
	}
}

// ---------------------------------------------------------------------------
// Explanation rules. Each rule SUBTRACTS from the candidate count, so each is
// tested twice: that it fires on the shape it is for, and that it stays silent
// -- leaving the pin a candidate -- when the recomputation does not match. A
// rule that fired on a key NAME would pass the first test and fail the second.
// ---------------------------------------------------------------------------

// R1: internal/fuzzpin.TreeDigest envelopes a one-file list as
// "relpath\x00filedigest\n". 25 of the census's 85 rows were this.
func TestTreeEnvelopeDigestIsExplainedNotReportedAsDangling(t *testing.T) {
	content := "channel = \"1.95.0\"\n"
	sum := sha256.Sum256([]byte(content))
	envelope := sha256.Sum256([]byte("toolchain.toml\x00" + hex.EncodeToString(sum[:]) + "\n"))
	root := scratchRepo(t, map[string]string{
		"toolchain.toml": content,
		"manifest.json": `{"toolchain":{"pin_file":"toolchain.toml","pin_digest":"sha256:` +
			hex.EncodeToString(envelope[:]) + `"}}`,
	})

	census, err := analyseDangling(root)
	if err != nil {
		t.Fatalf("analyse: %v", err)
	}
	if len(census.candidates) != 0 {
		t.Errorf("a verified tree envelope must not be a candidate: %+v", census.candidates)
	}
	if len(census.explained) != 1 ||
		!strings.HasPrefix(census.explained[0].explanation, "tree-envelope:") {
		t.Fatalf("expected one tree-envelope explanation, got %+v", census.explained)
	}
}

// The property that makes R1 safe to subtract: the envelope is recomputed from
// the file's CURRENT bytes, so editing the file makes the pin dangle again. A
// rule keyed on the name `pin_digest` would stay quiet here and hide real drift.
func TestTreeEnvelopeExplanationStopsApplyingWhenTheFileDrifts(t *testing.T) {
	original := "channel = \"1.95.0\"\n"
	sum := sha256.Sum256([]byte(original))
	envelope := sha256.Sum256([]byte("toolchain.toml\x00" + hex.EncodeToString(sum[:]) + "\n"))
	root := scratchRepo(t, map[string]string{
		"toolchain.toml": original,
		"manifest.json": `{"toolchain":{"pin_file":"toolchain.toml","pin_digest":"sha256:` +
			hex.EncodeToString(envelope[:]) + `"}}`,
	})

	if err := os.WriteFile(filepath.Join(root, "toolchain.toml"),
		[]byte("channel = \"1.96.0\"\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	census, err := analyseDangling(root)
	if err != nil {
		t.Fatalf("analyse: %v", err)
	}
	if len(census.candidates) != 1 {
		t.Fatalf("a drifted toolchain pin MUST be reported: %d candidates, %d explained",
			len(census.candidates), len(census.explained))
	}
}

// R2: internal/fuzzpin.digestLines over a sibling array -- why two runs of one
// fuzz campaign share an outcome_digest and neither equals its own log.
func TestSiblingLineArrayDigestIsExplained(t *testing.T) {
	hasher := sha256.New()
	for _, line := range []string{"test a ... ok", "test b ... ok"} {
		hasher.Write([]byte(line + "\n"))
	}
	root := scratchRepo(t, map[string]string{
		"run1.log": "wall time differs between runs\n",
		"result.json": `{"runs":[{"log_path":"run1.log","outcome_lines":["test a ... ok",` +
			`"test b ... ok"],"outcome_digest":"sha256:` + hex.EncodeToString(hasher.Sum(nil)) + `"}]}`,
	})

	census, err := analyseDangling(root)
	if err != nil {
		t.Fatalf("analyse: %v", err)
	}
	if len(census.candidates) != 0 {
		t.Errorf("a digest of the object's own lines is not a pin of the log: %+v", census.candidates)
	}
	if len(census.explained) != 1 ||
		!strings.HasPrefix(census.explained[0].explanation, "sibling-lines:") {
		t.Errorf("expected one sibling-lines explanation, got %+v", census.explained)
	}
}

// R3: `field` names where the digest was read from, and the claim is VERIFIED by
// resolving it. An object claiming a field it does not match explains nothing --
// the lying fixture's digest is absent from the source too, so the field-inside
// rule cannot rescue it either.
func TestFieldProvenanceIsExplainedOnlyWhenTheFieldActuallyMatches(t *testing.T) {
	digest := "sha256:" + strings.Repeat("ab", 32)
	absent := "sha256:" + strings.Repeat("ba", 32)
	root := scratchRepo(t, map[string]string{
		"corpus.json": `{"generator":{"secret_seed_commitment":"` + digest + `"}}`,
		"honest.json": `{"credential":{"declared":"` + digest + `","source":"corpus.json",` +
			`"field":"generator.secret_seed_commitment"}}`,
		"lying.json": `{"credential":{"declared":"` + absent + `","source":"corpus.json",` +
			`"field":"generator.absent_field"}}`,
	})

	census, err := analyseDangling(root)
	if err != nil {
		t.Fatalf("analyse: %v", err)
	}
	var explainedFrom, candidateFrom []string
	for _, row := range census.explained {
		explainedFrom = append(explainedFrom, row.artifact)
	}
	for _, row := range census.candidates {
		candidateFrom = append(candidateFrom, row.artifact)
	}
	if len(explainedFrom) != 1 || explainedFrom[0] != "honest.json" {
		t.Errorf("only the verifiable field claim may be explained, got %v", explainedFrom)
	}
	if len(candidateFrom) != 1 || candidateFrom[0] != "lying.json" {
		t.Errorf("an unverifiable field claim must stay a candidate, got %v", candidateFrom)
	}
}

// R5: a json_set operation carries the value it WRITES. A seeded defect's
// deliberately wrong digest is a payload, not a pin that drifted.
func TestMutationOperandIsExplained(t *testing.T) {
	root := scratchRepo(t, map[string]string{
		"target.json": `{"nodes":[{"digest":"sha256:` + strings.Repeat("00", 32) + `"}]}`,
		"mutation.json": `{"operations":[{"kind":"json_set","target":"target.json",` +
			`"pointer":"/nodes/0/digest","value":"sha256:` + strings.Repeat("cc", 32) + `"}]}`,
	})

	census, err := analyseDangling(root)
	if err != nil {
		t.Fatalf("analyse: %v", err)
	}
	if len(census.candidates) != 0 {
		t.Errorf("a mutation operand is not a pin: %+v", census.candidates)
	}
	if len(census.explained) != 1 ||
		!strings.HasPrefix(census.explained[0].explanation, "mutation-operand:") {
		t.Errorf("expected a mutation-operand explanation, got %+v", census.explained)
	}
}

// The rule that stops an explanation covering for its neighbour: an object with
// one provable digest AND one unexplained digest stays a candidate.
func TestAnUnexplainedDigestIsNotCoveredByAnExplainedNeighbour(t *testing.T) {
	recordDigest := "sha256:" + strings.Repeat("cd", 32)
	root := scratchRepo(t, map[string]string{
		"ledger.json": `{"records":[{"record_digest":"` + recordDigest + `"}]}`,
		"receipt.json": `{"pin":{"ledger_path":"ledger.json","ledger_head":"` + recordDigest +
			`","file_sha256":"sha256:` + strings.Repeat("ef", 32) + `"}}`,
	})

	census, err := analyseDangling(root)
	if err != nil {
		t.Fatalf("analyse: %v", err)
	}
	if len(census.candidates) != 1 {
		t.Errorf("an object with one unprovable digest must stay a candidate: candidates=%+v explained=%+v",
			census.candidates, census.explained)
	}
}

// The point of the whole exercise: the real tree's adjudicated TRUE dangling
// pins must still be reported after the precision rules land. If one is ever
// swallowed, the tool has started hiding drift.
func TestAdjudicatedTrueDanglingPinsAreStillReported(t *testing.T) {
	root := repoRoot(t)
	census, err := analyseDangling(root)
	if err != nil {
		t.Fatalf("analyse: %v", err)
	}
	reported := map[string]bool{}
	for _, candidate := range census.candidates {
		reported[candidate.artifact+" "+candidate.pointer] = true
	}
	for _, required := range []string{
		"assurance/formal/obligation-catalog.json $.denominator_basis[1]",
		"assurance/formal/obligation-catalog.json $.denominator_basis[3]",
		"assurance/formal/obligation-catalog.json $.denominator_basis[4]",
		"drafts/ledger-proposals/java-formal-binding-corroborations.json $.evidence_basis.projection",
		"drafts/ledger-proposals/java-formal-binding-corroborations.json $.evidence_basis.receipt",
		"evidence/governance/decisions/e3-formal-receipt.json $.artifacts.results_documents[0]",
		"evidence/governance/decisions/e3-formal-receipt.json $.artifacts.results_documents[1]",
		"evidence/java/test-manifest.json $.authoritative_run.execution_code_binding.sources[0]",
		"evidence/java/test-manifest.json $.authoritative_run.execution_code_binding.sources[2]",
	} {
		if !reported[required] {
			t.Errorf("adjudicated TRUE dangling pin no longer reported: %s", required)
		}
	}
}
