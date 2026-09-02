// fuzzpinctl verifies the US-021 AC3 fuzz-target pinning record and executes
// the pinned campaigns.
//
// Verbs:
//
//	-check                   verify a manifest against the tree. Exit 0 only
//	                         when no BLOCK finding stands.
//	-campaign                additionally EXECUTE each PINNED target's replay
//	                         command twice under its declared wall-clock
//	                         deadline, capture artifacts, and require a
//	                         byte-identical normalized outcome. A replay command
//	                         nobody ran is a string.
//	-replay-fixtures FILE    run the digest-frozen polarity fixtures through the
//	                         REAL checker and require each case's exact exit
//	                         code, state, and typed finding codes.
//
// Honesty contract, inherited from cmd/rustgatectl: every completed external
// command's exit code is read from its ProcessState and printed verbatim; a
// command that never produced a ProcessState is reported as
// `exit=none process_state=absent`, never as an invented number.
//
// AC3's rule "unavailable tooling blocks instead of skipping" is mechanical
// here: an engine whose probe command does not exit 0 raises
// FUZZ_ENGINE_UNAVAILABLE (BLOCK), and any target that claims a campaign on
// that engine additionally raises UNAVAILABLE_REPRESENTED_AS_SKIP (BLOCK).
// There is no skip disposition in this tool.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/michaellady/verified-java-websocket-port/internal/fuzzpin"
)

func main() {
	root := flag.String("root", ".", "repository root")
	manifestPath := flag.String("manifest", "assurance/fuzz/manifest.json", "target manifest, relative to root")
	check := flag.Bool("check", false, "verify the manifest against the tree")
	campaign := flag.Bool("campaign", false, "execute each PINNED target's replay command and require reproduction")
	runs := flag.Int("runs", 2, "replay executions per target (minimum 2 to prove reproduction)")
	replayFixtures := flag.String("replay-fixtures", "", "polarity fixture catalog, relative to root")
	campaignFixtures := flag.String("campaign-fixtures", "", "campaign-runner polarity catalog, relative to root")
	emitDigest := flag.String("emit-digest", "", "print CANONICAL_PATH_SHA256_V1 over these comma-separated paths and exit")
	jsonOut := flag.String("json", "", "write the machine-readable result to this path, relative to root")
	flag.Parse()

	absRoot, err := filepath.Abs(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fuzzpinctl: %v\n", err)
		os.Exit(2)
	}

	if *emitDigest != "" {
		paths := strings.Split(*emitDigest, ",")
		digest, count, err := fuzzpin.TreeDigest(absRoot, paths)
		if err != nil {
			fmt.Fprintf(os.Stderr, "fuzzpinctl: %v\n", err)
			os.Exit(2)
		}
		fmt.Printf("digest=%s files=%d paths=%s\n", digest, count, *emitDigest)
		return
	}

	if *replayFixtures != "" {
		os.Exit(runFixtures(absRoot, filepath.Join(absRoot, *replayFixtures)))
	}

	if *campaignFixtures != "" {
		os.Exit(runCampaignFixtures(absRoot, filepath.Join(absRoot, *campaignFixtures)))
	}

	if !*check && !*campaign {
		fmt.Fprintln(os.Stderr, "fuzzpinctl: one of -check, -campaign, -replay-fixtures, -campaign-fixtures, -emit-digest is required")
		os.Exit(2)
	}

	manifest, err := fuzzpin.LoadManifest(filepath.Join(absRoot, *manifestPath))
	if err != nil {
		fmt.Fprintf(os.Stderr, "fuzzpinctl: manifest: %v\n", err)
		os.Exit(2)
	}

	verdict := fuzzpin.Check(absRoot, manifest)
	report := struct {
		Manifest  string                    `json:"manifest"`
		Verdict   fuzzpin.Verdict           `json:"verdict"`
		Campaigns []fuzzpin.CampaignResult  `json:"campaigns,omitempty"`
	}{Manifest: *manifestPath, Verdict: verdict}

	for _, probe := range verdict.EngineAvailability {
		fmt.Printf("gate=fuzzpin step=engine-probe engine=%s command=%q %s available=%t\n",
			probe.Engine, probe.Command, probe.ExitText, probe.Available)
	}

	campaignFailed := false
	if *campaign {
		if *runs < 2 {
			fmt.Fprintln(os.Stderr, "fuzzpinctl: -runs must be at least 2 to prove reproduction")
			os.Exit(2)
		}
		for _, target := range manifest.Targets {
			if target.Status != fuzzpin.StatusPinned && target.Status != fuzzpin.StatusSharedNoDedicatedTarget {
				fmt.Printf("gate=fuzzpin step=campaign target=%s status=%s not_executed=%q\n",
					target.ID, target.Status,
					"no runnable target exists for this family; recorded, never skipped")
				continue
			}
			result := fuzzpin.RunCampaign(absRoot, target, *runs)
			report.Campaigns = append(report.Campaigns, result)
			for _, record := range result.Runs {
				fmt.Printf("gate=fuzzpin step=campaign target=%s run=%d %s deadline_hit=%t wall=%.3fs outcome=%s log=%s\n",
					target.ID, record.Run, record.ExitText, record.DeadlineHit,
					record.WallSeconds, record.OutcomeDigest, record.LogPath)
			}
			if !result.Reproduced {
				campaignFailed = true
				fmt.Printf("gate=fuzzpin step=campaign target=%s REPRODUCTION_FAILED detail=%q\n",
					target.ID, result.Failure)
			} else {
				fmt.Printf("gate=fuzzpin step=campaign target=%s REPRODUCED runs=%d digest=%s\n",
					target.ID, len(result.Runs), result.Runs[0].OutcomeDigest)
			}
		}
	}

	for _, finding := range verdict.Findings {
		fmt.Printf("gate=fuzzpin finding=%s disposition=%s target=%s detail=%q\n",
			finding.Code, finding.Disposition, finding.Target, finding.Detail)
	}

	if *jsonOut != "" {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "fuzzpinctl: %v\n", err)
			os.Exit(2)
		}
		out := filepath.Join(absRoot, *jsonOut)
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "fuzzpinctl: %v\n", err)
			os.Exit(2)
		}
		if err := os.WriteFile(out, append(data, '\n'), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "fuzzpinctl: %v\n", err)
			os.Exit(2)
		}
	}

	blocking := 0
	for _, finding := range verdict.Findings {
		if finding.Disposition == fuzzpin.Block {
			blocking++
		}
	}
	fmt.Printf("gate=fuzzpin state=%s blocking_findings=%d campaigns_executed=%d\n",
		verdict.State, blocking, len(report.Campaigns))

	if verdict.State != "OK" || campaignFailed {
		os.Exit(1)
	}
}

// fixtureCase is one polarity case: a manifest that must produce exactly this
// verdict through the REAL checker.
type fixtureCase struct {
	ID           string `json:"id"`
	ManifestPath string `json:"manifest_path"`
	Rationale    string `json:"rationale"`
	Expected     struct {
		ExitCode int      `json:"exit_code"`
		State    string   `json:"state"`
		Findings []string `json:"findings"`
	} `json:"expected"`
}

type fixtureCatalog struct {
	SchemaVersion string        `json:"schema_version"`
	Story         string        `json:"story"`
	Note          string        `json:"note"`
	Cases         []fixtureCase `json:"cases"`
}

// runFixtures drives every fixture manifest through the real checker and
// requires the exact exit code, state, and set of typed finding codes. This is
// the polarity proof: a checker that cannot fail is not a check.
func runFixtures(root, catalogPath string) int {
	raw, err := os.ReadFile(catalogPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fuzzpinctl: fixtures: %v\n", err)
		return 2
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var catalog fixtureCatalog
	if err := decoder.Decode(&catalog); err != nil {
		fmt.Fprintf(os.Stderr, "fuzzpinctl: fixtures: %v\n", err)
		return 2
	}
	if len(catalog.Cases) == 0 {
		fmt.Fprintln(os.Stderr, "fuzzpinctl: fixtures: catalog is empty; an empty polarity suite proves nothing")
		return 2
	}

	failures := 0
	for _, testCase := range catalog.Cases {
		manifest, err := fuzzpin.LoadManifest(filepath.Join(root, testCase.ManifestPath))
		var state string
		var codes []string
		exit := 0
		if err != nil {
			state = "BLOCKED"
			codes = []string{fuzzpin.FindingManifestSchemaInvalid}
			exit = 1
		} else {
			verdict := fuzzpin.Check(root, manifest)
			state = verdict.State
			seen := map[string]bool{}
			for _, finding := range verdict.Findings {
				if finding.Disposition != fuzzpin.Block {
					continue
				}
				if !seen[finding.Code] {
					seen[finding.Code] = true
					codes = append(codes, finding.Code)
				}
			}
			sort.Strings(codes)
			if state != "OK" {
				exit = 1
			}
		}
		want := append([]string(nil), testCase.Expected.Findings...)
		sort.Strings(want)
		ok := exit == testCase.Expected.ExitCode &&
			state == testCase.Expected.State &&
			strings.Join(codes, ",") == strings.Join(want, ",")
		status := "PASS"
		if !ok {
			status = "FAIL"
			failures++
		}
		fmt.Printf("gate=fuzzpin-fixtures case=%s %s exit=%d want_exit=%d state=%s want_state=%s findings=[%s] want_findings=[%s]\n",
			testCase.ID, status, exit, testCase.Expected.ExitCode, state, testCase.Expected.State,
			strings.Join(codes, " "), strings.Join(want, " "))
	}
	fmt.Printf("gate=fuzzpin-fixtures cases=%d failures=%d\n", len(catalog.Cases), failures)
	if failures > 0 {
		return 1
	}
	return 0
}
