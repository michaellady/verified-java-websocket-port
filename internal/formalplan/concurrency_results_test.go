package formalplan

// Polarity coverage for the US-017 results-binding gate (pre-landing review
// round 2, results.json finding). A green run with correct digests proves
// nothing on its own: the finding is that a STALE binding was undetectable,
// so each way of going stale is produced here and the refusal is read.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const crTestRoot = "../.."

// crBindingCount is the number of file-naming bindings the committed artifact
// declares: two target blobs, the preregistered plan, two minimized
// reproductions, and seven pinned minimized artifacts. Pinned so the
// enumeration below cannot silently empty out and leave the polarity loops
// iterating over nothing; change it only when the artifact really does gain or
// lose a binding, and add the coverage in the same edit.
const crBindingCount = 12

// crBinding is one file-naming binding the results gate checks: the label
// ValidateConcurrencyResults prints for it, the repository file it names, the
// exact digest text recorded for it in the artifact, and the typed code a
// staleness must raise.
type crBinding struct {
	field                   string
	path                    string
	recorded                string
	code                    string
	isMinimizedReproduction bool
}

// crEnumerateBindings derives the bindings FROM THE DOCUMENT rather than from
// a hand-maintained list. That is the point: the round-3 finding was that the
// polarity suite covered the bindings its author happened to think of (the two
// target blobs, the plan, one retention seed) while the artifact claimed every
// binding was covered from both sides. Driving the polarity loops off this
// enumeration means a binding cannot be added to results.json without its
// polarity cases coming with it.
func crEnumerateBindings(t *testing.T, root string) []crBinding {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(ConcurrencyResultsDocumentPath)))
	if err != nil {
		t.Fatalf("read results artifact: %v", err)
	}
	var results crResults
	if err := json.Unmarshal(raw, &results); err != nil {
		t.Fatalf("parse results artifact: %v", err)
	}
	bindings := []crBinding{
		{field: "target.source", path: results.Target.Source.Path,
			recorded: results.Target.Source.GitBlob, code: "RESULTS_TARGET_BLOB_STALE"},
		{field: "target.harness", path: results.Target.Harness.Path,
			recorded: results.Target.Harness.GitBlob, code: "RESULTS_TARGET_BLOB_STALE"},
		{field: "preregistered_plan", path: results.PreregisteredPlan.Path,
			recorded: results.PreregisteredPlan.SHA256, code: "RESULTS_ARTIFACT_DIGEST_STALE"},
	}
	for index, defect := range results.DefectsFound {
		reference := defect.MinimizedReproduction
		if reference.Path == "" && reference.SHA256 == "" {
			continue
		}
		bindings = append(bindings, crBinding{
			field: fmt.Sprintf("defects_found_and_fixed[%d] (%s).minimized_reproduction",
				index, defect.DefectID),
			path:                    reference.Path,
			recorded:                reference.SHA256,
			code:                    "RESULTS_ARTIFACT_DIGEST_STALE",
			isMinimizedReproduction: true,
		})
	}
	for index, artifact := range results.Retention.MinimizedArtifacts {
		bindings = append(bindings, crBinding{
			field:    fmt.Sprintf("retention.minimized_artifacts[%d] (%s)", index, artifact.Seed),
			path:     minimizedSeedDir + "/" + artifact.Seed + ".seed",
			recorded: artifact.SHA256,
			code:     "RESULTS_ARTIFACT_DIGEST_STALE",
		})
	}
	if len(bindings) != crBindingCount {
		t.Fatalf("the artifact declares %d file-naming bindings, but crBindingCount pins %d; "+
			"a binding was added or removed without its polarity coverage",
			len(bindings), crBindingCount)
	}
	for _, binding := range bindings {
		if binding.path == "" || binding.recorded == "" {
			t.Fatalf("binding %s is half-recorded (path %q, digest %q); "+
				"the committed artifact must not ship one", binding.field, binding.path, binding.recorded)
		}
	}
	return bindings
}

// crTestIsolate copies every file the results binding reads into a temp tree,
// so a deliberate staleness never touches the repository. The file list is the
// binding enumeration itself, so it cannot drift from what the gate reads.
func crTestIsolate(t *testing.T) string {
	t.Helper()
	isolated := t.TempDir()
	copyIn := func(relative string) {
		content, err := os.ReadFile(filepath.Join(crTestRoot, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatalf("read %s: %v", relative, err)
		}
		target := filepath.Join(isolated, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", relative, err)
		}
		if err := os.WriteFile(target, content, 0o644); err != nil {
			t.Fatalf("write %s: %v", relative, err)
		}
	}
	copyIn(ConcurrencyResultsDocumentPath)
	for _, binding := range crEnumerateBindings(t, crTestRoot) {
		copyIn(binding.path)
	}
	if findings := ValidateConcurrencyResults(isolated); len(findings) != 0 {
		t.Fatalf("the isolated copy must validate clean before any mutation, got %v", findings)
	}
	return isolated
}

func crTestOverwrite(t *testing.T, root, relative, before, after string) {
	t.Helper()
	target := filepath.Join(root, filepath.FromSlash(relative))
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read %s: %v", relative, err)
	}
	if !strings.Contains(string(content), before) {
		t.Fatalf("%s no longer contains %q; the polarity probe is stale", relative, before)
	}
	mutated := strings.Replace(string(content), before, after, 1)
	if err := os.WriteFile(target, []byte(mutated), 0o644); err != nil {
		t.Fatalf("write %s: %v", relative, err)
	}
}

// crTestOverwriteUnique is crTestOverwrite with an anchor-uniqueness demand.
// A polarity probe that silently hits the first of several matches would
// mutate a binding other than the one under test and could read the "right"
// refusal for the wrong reason, so an ambiguous anchor is a test failure.
func crTestOverwriteUnique(t *testing.T, root, relative, before, after string) {
	t.Helper()
	target := filepath.Join(root, filepath.FromSlash(relative))
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read %s: %v", relative, err)
	}
	if occurrences := strings.Count(string(content), before); occurrences != 1 {
		t.Fatalf("%s contains %q %d times, want exactly 1: the polarity probe cannot "+
			"name a unique binding", relative, before, occurrences)
	}
	mutated := strings.Replace(string(content), before, after, 1)
	if err := os.WriteFile(target, []byte(mutated), 0o644); err != nil {
		t.Fatalf("write %s: %v", relative, err)
	}
}

// crTestAppend edits a NAMED file so the recorded digest goes stale from the
// other side, the way the real defect arrived: a fix round rewrote the file
// and the artifact kept the previous revision's digest.
func crTestAppend(t *testing.T, root, relative, suffix string) {
	t.Helper()
	target := filepath.Join(root, filepath.FromSlash(relative))
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read %s: %v", relative, err)
	}
	if err := os.WriteFile(target, append(content, []byte(suffix)...), 0o644); err != nil {
		t.Fatalf("write %s: %v", relative, err)
	}
}

// crFlipDigest returns a well-formed digest of the same shape that is
// guaranteed to differ from the one recorded, so the mutated artifact stays
// parseable and only the RECORDED side has gone stale.
func crFlipDigest(t *testing.T, recorded string) string {
	t.Helper()
	if recorded == "" {
		t.Fatalf("cannot flip an empty digest")
	}
	runes := []rune(recorded)
	if runes[len(runes)-1] == '0' {
		runes[len(runes)-1] = '1'
	} else {
		runes[len(runes)-1] = '0'
	}
	return string(runes)
}

func crTestRequireFinding(t *testing.T, root, code, needle string) {
	t.Helper()
	findings := ValidateConcurrencyResults(root)
	for _, finding := range findings {
		if finding.Code == code && strings.Contains(finding.Detail, needle) {
			if finding.Severity != SeverityBlocking {
				t.Fatalf("%s must be blocking, got %q", code, finding.Severity)
			}
			return
		}
	}
	t.Fatalf("expected a blocking %s mentioning %q, got %v", code, needle, findings)
}

// TestCommittedConcurrencyResultsBindTheCommittedTree is the gate: the PASS
// artifact's recorded blobs and digests must describe the tree it ships with.
func TestCommittedConcurrencyResultsBindTheCommittedTree(t *testing.T) {
	if findings := ValidateConcurrencyResults(crTestRoot); len(findings) != 0 {
		t.Fatalf("the committed results artifact does not describe the committed tree: %v", findings)
	}
}

// TestGitBlobIDMatchesGitsOwnObjectIds pins the hash construction itself
// against object ids git produces, so the comparison cannot be vacuous
// because the id was computed a different way than the artifact records it.
func TestGitBlobIDMatchesGitsOwnObjectIds(t *testing.T) {
	for _, vector := range []struct {
		content string
		blob    string
	}{
		// `printf '' | git hash-object --stdin`
		{"", "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"},
		// `printf 'hello\n' | git hash-object --stdin`
		{"hello\n", "ce013625030ba8dba906f756967f9e9ca394464a"},
		// `printf 'what is up, doc?' | git hash-object --stdin`
		{"what is up, doc?", "bd9dbf5aae1a3862dd1526723246b20206e5fc37"},
	} {
		if got := GitBlobID([]byte(vector.content)); got != vector.blob {
			t.Fatalf("GitBlobID(%q) = %s, want git's %s", vector.content, got, vector.blob)
		}
	}
}

// TestAStaleResultsTargetBindingIsRefused is the deletion-equivalent polarity
// for a digest: an artifact whose target names a tree OTHER than the one it
// claims to describe must fail, whichever side went stale. Both directions
// are exercised — the recorded id edited, and the named file edited — because
// the real defect arrived the second way: the driver source was rewritten by
// a fix round and the artifact kept the previous revision's blob id.
func TestAStaleResultsTargetBindingIsRefused(t *testing.T) {
	t.Run("recorded source blob names another revision", func(t *testing.T) {
		isolated := crTestIsolate(t)
		crTestOverwrite(t, isolated, ConcurrencyResultsDocumentPath,
			`"git_blob": "`, `"git_blob": "2dab10459db8a34b44a9d031b3670010f9667fdb`)
		crTestRequireFinding(t, isolated, "RESULTS_TARGET_BLOB_STALE", "target.source")
	})

	t.Run("named driver source changed under the recorded blob", func(t *testing.T) {
		isolated := crTestIsolate(t)
		crTestOverwrite(t, isolated, "rust/ws-driver/src/lib.rs",
			"#![forbid(unsafe_code)]", "#![forbid(unsafe_code)] // a later fix round")
		crTestRequireFinding(t, isolated, "RESULTS_TARGET_BLOB_STALE", "target.source")
	})

	t.Run("named exploration harness changed under the recorded blob", func(t *testing.T) {
		isolated := crTestIsolate(t)
		target := filepath.Join(isolated, filepath.FromSlash("rust/ws-driver/tests/schedule_exploration.rs"))
		content, err := os.ReadFile(target)
		if err != nil {
			t.Fatalf("read harness: %v", err)
		}
		if err := os.WriteFile(target, append(content, []byte("\n// harness edited\n")...), 0o644); err != nil {
			t.Fatalf("write harness: %v", err)
		}
		crTestRequireFinding(t, isolated, "RESULTS_TARGET_BLOB_STALE", "target.harness")
	})

	t.Run("preregistered plan digest goes stale", func(t *testing.T) {
		isolated := crTestIsolate(t)
		crTestOverwrite(t, isolated, "assurance/concurrency/plan.json",
			`"schema_version"`, `"schema_version_edited"`)
		crTestRequireFinding(t, isolated, "RESULTS_ARTIFACT_DIGEST_STALE", "preregistered_plan")
	})

	t.Run("a pinned minimized artifact is edited", func(t *testing.T) {
		isolated := crTestIsolate(t)
		target := filepath.Join(isolated, filepath.FromSlash(minimizedSeedDir+"/silent-write-drop.seed"))
		content, err := os.ReadFile(target)
		if err != nil {
			t.Fatalf("read seed: %v", err)
		}
		if err := os.WriteFile(target, append(content, '\n'), 0o644); err != nil {
			t.Fatalf("write seed: %v", err)
		}
		crTestRequireFinding(t, isolated, "RESULTS_ARTIFACT_DIGEST_STALE", "silent-write-drop")
	})

	t.Run("a named file is gone entirely", func(t *testing.T) {
		isolated := crTestIsolate(t)
		if err := os.Remove(filepath.Join(isolated,
			filepath.FromSlash("rust/ws-driver/tests/schedule_exploration.rs"))); err != nil {
			t.Fatalf("remove harness: %v", err)
		}
		crTestRequireFinding(t, isolated, "RESULTS_TARGET_PATH_MISSING", "target.harness")
	})

	// The empty-path arm is a separate branch from the unreadable-file arm and
	// prints a different reason; requiring that reason keeps it discriminating
	// (deleting the arm still refuses, but as "not in the tree").
	t.Run("a named path is emptied", func(t *testing.T) {
		isolated := crTestIsolate(t)
		crTestOverwriteUnique(t, isolated, ConcurrencyResultsDocumentPath,
			`"path": "rust/ws-driver/tests/schedule_exploration.rs"`, `"path": ""`)
		crTestRequireFinding(t, isolated, "RESULTS_TARGET_PATH_MISSING", "names no path")
	})
}

// TestEveryResultsBindingIsRefusedFromBothSides is the round-3 correction.
// results.json claims its polarity test "makes each one stale in turn, from
// BOTH sides"; before this test that was true of the two target blobs and one
// retention seed only, and deleting the whole minimized-reproduction
// validation loop left `go test ./...` green (proven by execution: 29 packages
// ok, 0 failures, with the loop removed). The coverage is now driven off the
// artifact's own binding enumeration, so the claim is enforced rather than
// asserted: every binding the document declares is made stale from the
// recorded side and from the named-file side, and the typed refusal is read
// each time.
func TestEveryResultsBindingIsRefusedFromBothSides(t *testing.T) {
	for _, binding := range crEnumerateBindings(t, crTestRoot) {
		t.Run(binding.field+" -- recorded id edited", func(t *testing.T) {
			isolated := crTestIsolate(t)
			crTestOverwriteUnique(t, isolated, ConcurrencyResultsDocumentPath,
				`"`+binding.recorded+`"`, `"`+crFlipDigest(t, binding.recorded)+`"`)
			crTestRequireFinding(t, isolated, binding.code, binding.field)
		})
		t.Run(binding.field+" -- named file edited", func(t *testing.T) {
			isolated := crTestIsolate(t)
			crTestAppend(t, isolated, binding.path, "\n")
			crTestRequireFinding(t, isolated, binding.code, binding.field)
		})
	}
}

// TestAHalfMinimizedReproductionBindingIsRefused covers the other branch the
// round-3 finding named: a defect that records a path with no digest, or a
// digest with no path, binds nothing while looking bound. Both halves are
// discriminating for the TYPED refusal specifically — with the refusal at
// concurrency_results.go deleted a path-without-digest degrades into
// RESULTS_ARTIFACT_DIGEST_STALE and a digest-without-path into
// RESULTS_TARGET_PATH_MISSING, so requiring the incomplete-binding code is
// what makes the deletion fail.
func TestAHalfMinimizedReproductionBindingIsRefused(t *testing.T) {
	covered := 0
	for _, binding := range crEnumerateBindings(t, crTestRoot) {
		if !binding.isMinimizedReproduction {
			continue
		}
		covered++
		t.Run(binding.field+" -- a path with no sha256", func(t *testing.T) {
			isolated := crTestIsolate(t)
			crTestOverwriteUnique(t, isolated, ConcurrencyResultsDocumentPath,
				`"sha256": "`+binding.recorded+`"`, `"sha256": ""`)
			crTestRequireFinding(t, isolated, "RESULTS_ARTIFACT_BINDING_INCOMPLETE", binding.field)
		})
		t.Run(binding.field+" -- a sha256 with no path", func(t *testing.T) {
			isolated := crTestIsolate(t)
			crTestOverwriteUnique(t, isolated, ConcurrencyResultsDocumentPath,
				`"path": "`+binding.path+`"`, `"path": ""`)
			crTestRequireFinding(t, isolated, "RESULTS_ARTIFACT_BINDING_INCOMPLETE", binding.field)
		})
	}
	if covered != 2 {
		t.Fatalf("expected both recorded minimized_reproduction bindings, covered %d", covered)
	}
}

// TestAnUnusableResultsDocumentIsRefused closes the three intake arms found
// uncovered by this round's own adversarial pass. Each is discriminating by
// its typed code or reason: with the size bound deleted the padded document
// parses clean and yields NO finding, and with the parse check deleted the
// zero-valued document yields RESULTS_TARGET_PATH_MISSING instead.
func TestAnUnusableResultsDocumentIsRefused(t *testing.T) {
	t.Run("the artifact is absent", func(t *testing.T) {
		isolated := crTestIsolate(t)
		if err := os.Remove(filepath.Join(isolated,
			filepath.FromSlash(ConcurrencyResultsDocumentPath))); err != nil {
			t.Fatalf("remove results artifact: %v", err)
		}
		// The detail is the os error, which names the file; matching the
		// basename rather than the platform's phrasing keeps this portable.
		crTestRequireFinding(t, isolated, "RESULTS_FILE_UNREADABLE", "results.json")
	})

	t.Run("the artifact exceeds the bounded size", func(t *testing.T) {
		isolated := crTestIsolate(t)
		crTestAppend(t, isolated, ConcurrencyResultsDocumentPath,
			strings.Repeat(" ", 1<<20))
		crTestRequireFinding(t, isolated, "RESULTS_FILE_UNREADABLE", "exceeds the bounded size")
	})

	t.Run("the artifact is not parseable", func(t *testing.T) {
		isolated := crTestIsolate(t)
		crTestOverwriteUnique(t, isolated, ConcurrencyResultsDocumentPath,
			`"defects_found_and_fixed": [`, `"defects_found_and_fixed": [[[`)
		crTestRequireFinding(t, isolated, "RESULTS_FILE_UNREADABLE", "invalid character")
	})
}

// TestAnAbsentMinimizedReproductionStaysLegitimate pins the third arm of the
// same loop from the other direction: most recorded defects (harness-side and
// test-side findings, and the ones whose repro is a unit pin rather than a
// schedule) carry no minimized_reproduction at all, and that must NOT be
// refused. Without this the "absent is legitimate" continue could be tightened
// into a refusal and only the whole-tree gate would notice.
func TestAnAbsentMinimizedReproductionStaysLegitimate(t *testing.T) {
	isolated := crTestIsolate(t)
	raw, err := os.ReadFile(filepath.Join(isolated, filepath.FromSlash(ConcurrencyResultsDocumentPath)))
	if err != nil {
		t.Fatalf("read isolated results artifact: %v", err)
	}
	var results crResults
	if err := json.Unmarshal(raw, &results); err != nil {
		t.Fatalf("parse isolated results artifact: %v", err)
	}
	absent := 0
	for _, defect := range results.DefectsFound {
		if defect.MinimizedReproduction.Path == "" && defect.MinimizedReproduction.SHA256 == "" {
			absent++
		}
	}
	if absent == 0 {
		t.Fatalf("no defect records an absent minimized_reproduction; this test is vacuous")
	}
	if findings := ValidateConcurrencyResults(isolated); len(findings) != 0 {
		t.Fatalf("%d defects legitimately record no minimized_reproduction, but the gate "+
			"refused the unmutated artifact: %v", absent, findings)
	}
}
