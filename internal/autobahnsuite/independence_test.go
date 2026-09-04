package autobahnsuite

// Review 01a04961 finding 7, narrowed: the manifest is now held to sources
// outside the runs it constrains. Every negative case below was run against
// the committed manifest BEFORE the check existed and observed to pass; the
// readings are recorded in drafts/self-review/us019-native-run-round-2.md.

import (
	"path/filepath"
	"testing"
)

func nativeConfigs(t *testing.T, root string) []*SuiteConfig {
	t.Helper()
	base := filepath.Join(root, "evidence", "autobahn", "native-x86_64-provenance", "config")
	var configs []*SuiteConfig
	for _, name := range []string{
		"fuzzingclient-rust.json",
		"fuzzingclient-java.json",
		"fuzzingserver-derived.json",
	} {
		path := filepath.Join(base, name)
		mustExist(t, path)
		config, err := ReadSuiteConfig(path)
		if err != nil {
			t.Fatalf("ReadSuiteConfig %s: %v", name, err)
		}
		configs = append(configs, config)
	}
	return configs
}

// TestTheCommittedManifestSatisfiesEveryIndependentConstraint is the positive
// reading: the manifest the branch ships is consistent with the frozen family
// policy, the pinned selected-case count, the suite's own identity grammar,
// and the configurations the four legs were launched with.
func TestTheCommittedManifestSatisfiesEveryIndependentConstraint(t *testing.T) {
	root := repoRoot(t)
	manifest, err := BuildManifest(devSources(root))
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	for _, problem := range VerifyManifestIndependence(manifest, nativeConfigs(t, root)) {
		t.Errorf("the manifest is not consistent with an independent source: %s", problem)
	}
}

// TestASnapshotCannotInventOrDropCases is the polarity. Each mutation is
// something the manifest's own build path CANNOT catch, because the manifest
// is expanded from the runs: if the runs say it, the manifest records it.
func TestASnapshotCannotInventOrDropCases(t *testing.T) {
	root := repoRoot(t)
	configs := nativeConfigs(t, root)

	build := func(t *testing.T) *Manifest {
		t.Helper()
		manifest, err := BuildManifest(devSources(root))
		if err != nil {
			t.Fatalf("BuildManifest: %v", err)
		}
		return manifest
	}

	for _, testCase := range []struct {
		name   string
		mutate func(t *testing.T, manifest *Manifest)
	}{
		{
			name: "a case is dropped",
			mutate: func(t *testing.T, manifest *Manifest) {
				manifest.Cases = manifest.Cases[1:]
			},
		},
		{
			name: "a case is duplicated to keep the count",
			mutate: func(t *testing.T, manifest *Manifest) {
				manifest.Cases = append(manifest.Cases[1:], manifest.Cases[1])
			},
		},
		{
			name: "a case from an EXCLUDED family is admitted",
			mutate: func(t *testing.T, manifest *Manifest) {
				manifest.Cases[0].CaseID = "12.1.1"
			},
		},
		{
			name: "a whole selected family disappears",
			mutate: func(t *testing.T, manifest *Manifest) {
				kept := manifest.Cases[:0]
				for _, entry := range manifest.Cases {
					if len(entry.CaseID) > 2 && entry.CaseID[:2] == "10" {
						continue
					}
					kept = append(kept, entry)
				}
				manifest.Cases = kept
			},
		},
		{
			name: "the manifest narrows its own declared selection",
			mutate: func(t *testing.T, manifest *Manifest) {
				manifest.SelectedFamilies = manifest.SelectedFamilies[:4]
			},
		},
		{
			name: "an exclusion is quietly dropped from the declaration",
			mutate: func(t *testing.T, manifest *Manifest) {
				manifest.NonselectedCategories = manifest.NonselectedCategories[:1]
			},
		},
		{
			name: "an identity that is not a case identity at all",
			mutate: func(t *testing.T, manifest *Manifest) {
				manifest.Cases[0].CaseID = "1.1.1-rerun"
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			manifest := build(t)
			testCase.mutate(t, manifest)
			if problems := VerifyManifestIndependence(manifest, configs); len(problems) == 0 {
				t.Error("a manifest a snapshot could have produced satisfied every independent " +
					"constraint")
			}
		})
	}
}

// TestTheResidualOfFinding7IsMeasuredNotClaimed is the honest half of this
// round, and it FAILS THE DAY THE GAP CLOSES, which is the point.
//
// Review 01a04961 finding 7 says the manifest is snapshot-derived. The checks
// above narrow that considerably: a dropped case, a duplicate, an excluded
// family, a vanished family, a narrowed declaration and a malformed identity
// are all refused now. ONE attack survives all of them — a real case
// identity swapped for a FABRICATED one of the same shape, in the same
// selected family, keeping the count at exactly 247. Every constraint this
// tree can currently apply is satisfied by that manifest, because none of
// them knows which identities the suite actually defines.
//
// This test asserts the gap rather than describing it, so the finding cannot
// be reported as closed while it is open, and so the day someone binds the
// manifest to internal/lab.ParsePinnedAutobahnRegistryArchive — the pinned
// suite's own Python case definitions, which is the source outside the run
// that finding 7 asks for — this test goes red and must be deleted with the
// gap it records.
//
// WHAT CLOSES IT, exactly: materialise the pinned Autobahn source archive
// (digest internal/lab.PinnedAutobahnSourceArchiveDigest) into the
// quarantine, parse it with the existing registry parser, and require every
// manifest identity to appear in the resulting selection. In this
// environment the GitHub archive URL answers 403 through the agent proxy, so
// the archive is not obtainable here; that is an environment item, recorded
// with this test rather than left implicit.
func TestTheResidualOfFinding7IsMeasuredNotClaimed(t *testing.T) {
	root := repoRoot(t)
	manifest, err := BuildManifest(devSources(root))
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	fabricated := false
	for index := range manifest.Cases {
		if manifest.Cases[index].CaseID == "7.9.6" {
			manifest.Cases[index].CaseID = "7.9.997"
			fabricated = true
			break
		}
	}
	if !fabricated {
		t.Fatal("case 7.9.6 not present; this probe is stale")
	}
	problems := VerifyManifestIndependence(manifest, nativeConfigs(t, root))
	if len(problems) != 0 {
		t.Errorf("a fabricated case identity is now REFUSED (%v). Finding 7's residual is "+
			"closed, this test records a gap that no longer exists, and it should be deleted "+
			"along with the paragraph about it in the round record", problems)
	}
}

// TestTheSuiteConfigurationIsPartOfTheBinding proves the configuration arm is
// load-bearing rather than decorative: a config that selects a different set
// of families describes a different suite selection than the manifest holds,
// and supplying no config at all is reported rather than silently accepted.
func TestTheSuiteConfigurationIsPartOfTheBinding(t *testing.T) {
	root := repoRoot(t)
	manifest, err := BuildManifest(devSources(root))
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	if problems := VerifyManifestIndependence(manifest, nil); len(problems) == 0 {
		t.Error("a manifest bound to NO suite configuration produced no problem; a check that " +
			"applies only when its input is supplied is a check nobody arms")
	}
	configs := nativeConfigs(t, root)
	for _, mutate := range []func(*SuiteConfig){
		func(config *SuiteConfig) { config.Cases = append(config.Cases, "9.*") },
		func(config *SuiteConfig) { config.Cases = config.Cases[:3] },
		func(config *SuiteConfig) { config.Excluded = nil },
	} {
		forged := &SuiteConfig{
			Path:     configs[0].Path,
			Cases:    append([]string(nil), configs[0].Cases...),
			Excluded: append([]string(nil), configs[0].Excluded...),
		}
		mutate(forged)
		if problems := VerifyManifestIndependence(manifest, []*SuiteConfig{forged}); len(problems) == 0 {
			t.Errorf("a suite config selecting %v / excluding %v produced no problem",
				forged.Cases, forged.Excluded)
		}
	}
}
