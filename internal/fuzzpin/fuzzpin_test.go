package fuzzpin

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// repoRoot resolves the checkout root from this package's directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return root
}

type fixtureExpectation struct {
	ExitCode int      `json:"exit_code"`
	State    string   `json:"state"`
	Findings []string `json:"findings"`
}

type fixtureCase struct {
	ID           string             `json:"id"`
	ManifestPath string             `json:"manifest_path"`
	Rationale    string             `json:"rationale"`
	Expected     fixtureExpectation `json:"expected"`
}

type fixtureCatalog struct {
	SchemaVersion string        `json:"schema_version"`
	Story         string        `json:"story"`
	Note          string        `json:"note"`
	Cases         []fixtureCase `json:"cases"`
}

func loadCatalog(t *testing.T, path string) fixtureCatalog {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read catalog: %v", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var catalog fixtureCatalog
	if err := decoder.Decode(&catalog); err != nil {
		t.Fatalf("decode catalog: %v", err)
	}
	return catalog
}

// TestPolarityFixtures drives every committed fixture manifest through the real
// Check and requires its exact state and set of typed BLOCK codes. It is the
// same evidence `fuzzpinctl -replay-fixtures` produces, wired into `go test`
// so no release path can run one without the other.
func TestPolarityFixtures(t *testing.T) {
	root := repoRoot(t)
	catalog := loadCatalog(t, filepath.Join(root, "assurance", "fuzz", "fixtures", "cases.json"))
	if len(catalog.Cases) == 0 {
		t.Fatal("empty polarity catalog proves nothing")
	}
	greens := 0
	for _, testCase := range catalog.Cases {
		manifest, err := LoadManifest(filepath.Join(root, testCase.ManifestPath))
		if err != nil {
			t.Fatalf("%s: load: %v", testCase.ID, err)
		}
		verdict := Check(root, manifest)
		var codes []string
		seen := map[string]bool{}
		for _, finding := range verdict.Findings {
			if finding.Disposition != Block || seen[finding.Code] {
				continue
			}
			seen[finding.Code] = true
			codes = append(codes, finding.Code)
		}
		sort.Strings(codes)
		want := append([]string(nil), testCase.Expected.Findings...)
		sort.Strings(want)
		if verdict.State != testCase.Expected.State {
			t.Errorf("%s: state %q, want %q", testCase.ID, verdict.State, testCase.Expected.State)
		}
		if strings.Join(codes, ",") != strings.Join(want, ",") {
			t.Errorf("%s: findings %v, want %v", testCase.ID, codes, want)
		}
		if verdict.State == "OK" {
			greens++
		}
	}
	// A checker that blocked unconditionally would satisfy every red case. The
	// suite is only evidence because exactly one case is green.
	if greens != 1 {
		t.Errorf("polarity suite has %d green cases, want exactly 1", greens)
	}
}

// TestEveryAC2FamilyIsMappedByTheRealManifest guards the census itself: AC2
// names seven target families and the shipped manifest must carry a record for
// every one of them, whatever that record says.
func TestEveryAC2FamilyIsMappedByTheRealManifest(t *testing.T) {
	root := repoRoot(t)
	manifest, err := LoadManifest(filepath.Join(root, "assurance", "fuzz", "manifest.json"))
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	mapped := map[string]bool{}
	for _, target := range manifest.Targets {
		mapped[target.AC2Family] = true
	}
	for _, family := range AC2Families {
		if !mapped[family] {
			t.Errorf("AC2 family %q has no record in the shipped manifest", family)
		}
	}
}

// TestShippedManifestMakesNoMetClaim pins the honest state: US-021 AC2 and AC3
// are NOT met in this checkout, and the manifest may not say otherwise. If a
// later change closes the gaps, this test is the place the claim is re-argued
// -- deliberately, not by drift.
func TestShippedManifestMakesNoMetClaim(t *testing.T) {
	root := repoRoot(t)
	manifest, err := LoadManifest(filepath.Join(root, "assurance", "fuzz", "manifest.json"))
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	if manifest.Claim.AC2Met || manifest.Claim.AC3Met {
		t.Errorf("manifest claims ac2_met=%t ac3_met=%t; three AC2 families have no target and the "+
			"coverage-guided engine is not installed", manifest.Claim.AC2Met, manifest.Claim.AC3Met)
	}
	if manifest.Claim.ClaimGrade != "bounded" {
		t.Errorf("claim_grade %q; a deterministic bounded campaign is bounded evidence, never proof",
			manifest.Claim.ClaimGrade)
	}
	verdict := Check(root, manifest)
	if verdict.State != "BLOCKED" {
		t.Errorf("shipped manifest checks %q; the honest state is BLOCKED", verdict.State)
	}
}

// TestUnavailableEngineNeverSkips is the AC3 rule in one assertion: an engine
// whose probe cannot run BLOCKS, and it blocks whether the targets on it are
// recorded honestly or not. There is no input to this function that produces a
// skip.
func TestUnavailableEngineNeverSkips(t *testing.T) {
	root := repoRoot(t)
	probe := ProbeEngine(root, Engine{
		ID:           "absent-engine",
		Kind:         EngineCoverageGuided,
		ProbeCommand: []string{"this-command-does-not-exist-anywhere"},
	})
	if probe.Available {
		t.Fatal("a probe that cannot run reported available")
	}
	if probe.Exit != exitNoProcessState {
		t.Errorf("exit %d, want the no-process-state sentinel %d", probe.Exit, exitNoProcessState)
	}
	if !strings.Contains(probe.ExitText, "process_state=absent") {
		t.Errorf("exit text %q does not state the absent process state", probe.ExitText)
	}

	// An engine with no probe command at all is unavailable: availability that
	// cannot be decided is not availability.
	none := ProbeEngine(root, Engine{ID: "no-probe", Kind: EngineCoverageGuided})
	if none.Available {
		t.Error("an engine with no probe command reported available")
	}
}

// TestTreeDigestRefusesAMissingCorpus: a missing corpus is not an empty corpus.
// Returning a digest over zero files would let a deleted corpus verify.
func TestTreeDigestRefusesAMissingCorpus(t *testing.T) {
	root := repoRoot(t)
	if _, _, err := TreeDigest(root, []string{"assurance/fuzz/no-such-corpus"}); err == nil {
		t.Fatal("TreeDigest accepted a corpus root that does not exist")
	}
	digest, count, err := TreeDigest(root, []string{"assurance/fuzz/fixtures/corpus"})
	if err != nil {
		t.Fatalf("TreeDigest: %v", err)
	}
	if count != 2 || !strings.HasPrefix(digest, "sha256:") {
		t.Errorf("digest=%s count=%d", digest, count)
	}
}

// TestNormalizeOutcomeDropsHostTiming: wall time is a property of the machine,
// not of the campaign, so two runs of the same deterministic campaign must
// normalize identically however long each took.
func TestNormalizeOutcomeDropsHostTiming(t *testing.T) {
	fast := "test family_x ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.85s\n"
	slow := "test family_x ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 41.20s\n"
	if digestLines(normalizeOutcome(fast)) != digestLines(normalizeOutcome(slow)) {
		t.Error("host timing changed the normalized outcome digest")
	}
	failed := "test family_x ... FAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.85s\n"
	if digestLines(normalizeOutcome(fast)) == digestLines(normalizeOutcome(failed)) {
		t.Error("a failing run normalized to the same digest as a passing one")
	}
}
