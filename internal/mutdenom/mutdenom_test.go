package mutdenom

import (
	"os"
	"path/filepath"
	"testing"
)

// repoRoot resolves the repository root from this package's directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return root
}

// TestTheNineDispositionsArePartitioned is the arithmetic the whole denominator
// rests on: every one of the nine AC1 classes is either ineligible-with-gates or
// eligible, and every eligible class is either a kill or MISSED. A tenth
// category, or a class that fell out of both tables, would let a mutant be
// counted in the denominator and in no numerator -- silently.
func TestTheNineDispositionsArePartitioned(t *testing.T) {
	if len(Dispositions) != 9 {
		t.Fatalf("AC1 names nine dispositions; the model carries %d", len(Dispositions))
	}
	seen := map[string]bool{}
	for _, disposition := range Dispositions {
		if seen[disposition] {
			t.Fatalf("duplicate disposition %q", disposition)
		}
		seen[disposition] = true

		ineligible := IneligibleDispositions[disposition]
		missed := MissedDispositions[disposition]
		killed := disposition == DispKilled
		switch {
		case ineligible:
			if missed || killed {
				t.Errorf("%q is ineligible and also counted as missed=%t killed=%t",
					disposition, missed, killed)
			}
		case killed:
			if missed {
				t.Errorf("%q is both the kill and a miss", disposition)
			}
		case !missed:
			t.Errorf("%q is eligible, is not the kill, and is not MISSED: it would sit in "+
				"the denominator contributing to no numerator", disposition)
		}
	}
	for disposition := range IneligibleDispositions {
		if !seen[disposition] {
			t.Errorf("ineligible table names %q, which is not one of the nine", disposition)
		}
	}
	for disposition := range MissedDispositions {
		if !seen[disposition] {
			t.Errorf("missed table names %q, which is not one of the nine", disposition)
		}
	}
}

// TestNoSkipDisposition: the model has BLOCK and NOTE and nothing else. US-021's
// precedent and this repository's ledger gate both refuse rather than skip, and
// a skip disposition is the one addition that would undo every other rule here.
func TestNoSkipDisposition(t *testing.T) {
	for _, forbidden := range []string{"SKIP", "SKIPPED", "IGNORE", "WAIVED", "N/A"} {
		if Block == forbidden || Note == forbidden {
			t.Fatalf("a %q disposition exists", forbidden)
		}
	}
	if StatusSkippedForbidden != "SKIPPED" {
		t.Fatalf("the forbidden status must be named so it can be refused by name, got %q",
			StatusSkippedForbidden)
	}
}

// TestShippedDenominatorIsBlockedForNamedReasons pins the real artifact's
// verdict. It is expected to be BLOCKED: no mutation engine is installed and no
// campaign has run. If this ever goes green without a campaign, something has
// been weakened.
func TestShippedDenominatorIsBlockedForNamedReasons(t *testing.T) {
	root := repoRoot(t)
	manifest, err := LoadManifest(filepath.Join(root, "assurance/mutation/denominator.json"))
	if err != nil {
		t.Fatalf("load shipped denominator: %v", err)
	}
	verdict := Check(root, manifest)
	if verdict.State != "BLOCKED" {
		t.Fatalf("shipped denominator state = %q, want BLOCKED: no PIT run and no "+
			"cargo-mutants run exists in this repository", verdict.State)
	}
	required := []string{
		FindingEngineUnavailable,
		FindingDependencyGraphNotPromoted,
		FindingPopulationNotEnumerated,
		FindingScoreNotComputable,
		FindingSignatureAbsent,
		FindingArmNotRun,
		FindingArmSeparationShared,
		FindingReconciliationLegNotRun,
		FindingAC5LegNotPassed,
	}
	present := map[string]bool{}
	for _, finding := range verdict.Findings {
		present[finding.Code] = true
	}
	for _, code := range required {
		if !present[code] {
			t.Errorf("shipped denominator no longer raises %s", code)
		}
	}
	if manifest.Claim.AC1Met || manifest.Claim.AC2Met || manifest.Claim.AC3Met ||
		manifest.Claim.AC4Met || manifest.Claim.AC5Met {
		t.Errorf("shipped denominator claims an AC met while BLOCKED")
	}
}

// TestSharedSeparationValueIsFoundOnRealData: the hidden and sealed corpus
// manifests really do record one secret-seed commitment between them. The AC4
// rule is proven against the repository, not only against a fixture.
func TestSharedSeparationValueIsFoundOnRealData(t *testing.T) {
	root := repoRoot(t)
	hidden, err := LookupJSONField(
		filepath.Join(root, "corpora/hidden/manifest.json"), "generator.secret_seed_commitment")
	if err != nil {
		t.Fatalf("hidden witness: %v", err)
	}
	sealed, err := LookupJSONField(
		filepath.Join(root, "corpora/sealed/manifest.json"), "generator.secret_seed_commitment")
	if err != nil {
		t.Fatalf("sealed witness: %v", err)
	}
	if hidden != sealed {
		t.Skipf("the two tiers no longer share a seed commitment (hidden=%s sealed=%s); "+
			"this test recorded that they did", hidden, sealed)
	}
	manifest, err := LoadManifest(filepath.Join(root, "assurance/mutation/denominator.json"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	verdict := Check(root, manifest)
	for _, finding := range verdict.Findings {
		if finding.Code == FindingArmSeparationShared {
			return
		}
	}
	t.Fatalf("hidden and sealed share the credential witness %q and the checker did not "+
		"raise %s", hidden, FindingArmSeparationShared)
}

// TestPayloadDigestCoversTheDocument: the signed payload must move when any
// field but the signature's own two moves. Otherwise a signature would cover a
// summary rather than the denominator.
func TestPayloadDigestCoversTheDocument(t *testing.T) {
	root := repoRoot(t)
	manifest, err := LoadManifest(filepath.Join(root, "assurance/mutation/denominator.json"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	base, err := PayloadDigest(manifest)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if base != manifest.Signature.PayloadDigest {
		t.Fatalf("shipped payload digest %s does not match recomputed %s",
			manifest.Signature.PayloadDigest, base)
	}

	// The two signature fields the digest deliberately excludes.
	for _, mutate := range []func(*Manifest){
		func(m *Manifest) { m.Signature.Signature = "deadbeef" },
		func(m *Manifest) { m.Signature.PayloadDigest = "sha256:0" },
	} {
		clone := *manifest
		mutate(&clone)
		digest, err := PayloadDigest(&clone)
		if err != nil {
			t.Fatalf("digest: %v", err)
		}
		if digest != base {
			t.Errorf("the payload digest moved when a field it excludes changed")
		}
	}

	// Everything else must move it.
	mutations := map[string]func(*Manifest){
		"score":       func(m *Manifest) { m.Score.KilledTotal = 12345 },
		"claim":       func(m *Manifest) { m.Claim.AC1Met = true },
		"surface":     func(m *Manifest) { m.Surfaces[0].Digest = "sha256:0" },
		"population":  func(m *Manifest) { m.Populations[0].DeclaredTotal = 7 },
		"arm":         func(m *Manifest) { m.Arms[0].BudgetMonotonic = true },
		"ac5":         func(m *Manifest) { m.AC5Legs[0].Status = "PASSED" },
		"key_id":      func(m *Manifest) { m.Signature.KeyID = "someone-elses-key" },
		"public_key":  func(m *Manifest) { m.Signature.PublicKeyHex = "aa" },
		"engine":      func(m *Manifest) { m.Engines[0].ProbeCommand = []string{"true"} },
		"integrity":   func(m *Manifest) { m.TestIntegrity.TestSurfaceDigestAfter = "sha256:0" },
		"reviews":     func(m *Manifest) { m.Reviews = append(m.Reviews, Review{ID: "x"}) },
		"schema_vers": func(m *Manifest) { m.SchemaVersion = "9.9.9" },
	}
	for name, mutate := range mutations {
		clone := *manifest
		clone.Surfaces = append([]Surface(nil), manifest.Surfaces...)
		clone.Populations = append([]Population(nil), manifest.Populations...)
		clone.Arms = append([]Arm(nil), manifest.Arms...)
		clone.AC5Legs = append([]AC5Leg(nil), manifest.AC5Legs...)
		clone.Engines = append([]Engine(nil), manifest.Engines...)
		clone.Reviews = append([]Review(nil), manifest.Reviews...)
		mutate(&clone)
		digest, err := PayloadDigest(&clone)
		if err != nil {
			t.Fatalf("digest: %v", err)
		}
		if digest == base {
			t.Errorf("changing %s left the payload digest unmoved: a signature over it "+
				"would not cover that field", name)
		}
	}
}

// TestProbeReadsRealExitCodes: availability is decided by running the command
// and reading its ProcessState, never by an assertion in the manifest.
func TestProbeReadsRealExitCodes(t *testing.T) {
	root := repoRoot(t)
	cases := []struct {
		name      string
		command   []string
		available bool
	}{
		{"absent-binary", []string{"definitely-not-a-real-binary-xyz"}, false},
		{"no-probe-declared", nil, false},
		{"real-success", []string{"cargo", "--version"}, true},
		{"real-failure", []string{"cargo", "definitely-not-a-subcommand"}, false},
	}
	for _, testCase := range cases {
		probe := ProbeEngine(root, Engine{
			ID: testCase.name, ProbeCommand: testCase.command, ProbeDir: "rust",
		})
		if probe.Available != testCase.available {
			t.Errorf("%s: available=%t want %t (%s)",
				testCase.name, probe.Available, testCase.available, probe.ExitText)
		}
		if len(testCase.command) == 0 && probe.Exit != exitNoProcessState {
			t.Errorf("%s: a command that never ran must not be given an invented exit code, got %d",
				testCase.name, probe.Exit)
		}
	}
}

// TestFixtureSuiteHasExactlyOneGreenCase: a polarity suite with no green case
// would pass under a checker that blocked everything, and a suite that is mostly
// green is not a polarity suite.
func TestFixtureSuiteHasExactlyOneGreenCase(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "assurance/mutation/fixtures/cases.json"))
	if err != nil {
		t.Fatalf("read catalog: %v", err)
	}
	greens := 0
	total := 0
	for _, line := range splitJSONObjects(string(raw)) {
		if line == "" {
			continue
		}
		total++
		if line == "OK" {
			greens++
		}
	}
	if total < 20 {
		t.Fatalf("polarity suite has only %d cases", total)
	}
	if greens != 1 {
		t.Fatalf("polarity suite has %d green cases, want exactly 1", greens)
	}
}

// splitJSONObjects pulls each case's expected state out of the catalog without
// decoding the whole thing, so this test stays independent of the runner's own
// structs.
func splitJSONObjects(raw string) []string {
	var states []string
	const marker = "\"state\": \""
	for index := 0; ; {
		next := indexFrom(raw, marker, index)
		if next < 0 {
			return states
		}
		start := next + len(marker)
		end := start
		for end < len(raw) && raw[end] != '"' {
			end++
		}
		states = append(states, raw[start:end])
		index = end
	}
}

func indexFrom(haystack, needle string, from int) int {
	if from >= len(haystack) {
		return -1
	}
	found := -1
	for i := from; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			found = i
			break
		}
	}
	return found
}
