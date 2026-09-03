package main

import (
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
