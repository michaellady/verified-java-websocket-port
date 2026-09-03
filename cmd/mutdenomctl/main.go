// mutdenomctl verifies the US-022 normalized mutation denominator.
//
// Verbs:
//
//	-check                     verify the denominator against the tree. Exit 0
//	                           only when no BLOCK finding stands.
//	-replay-fixtures FILE      run the polarity fixtures through the REAL checker
//	                           and require each case's exact exit code, state,
//	                           and typed BLOCK codes.
//	-emit-digest PATHS         print CANONICAL_PATH_SHA256_V1 over comma-separated
//	                           paths.
//	-emit-payload-digest       print MUTDENOM_PAYLOAD_SHA256_V1 over the manifest.
//	-normalize-e1              print the nine-class normalization of the on-disk
//	                           mutants/e1-ws-core-manifest.json verdict vocabulary.
//
// Honesty contract, inherited from cmd/rustgatectl and cmd/fuzzpinctl: every
// completed external command's exit code is read from its ProcessState and
// printed verbatim; a command that never produced a ProcessState is reported as
// `exit=none process_state=absent`, never as an invented number.
//
// This tool is EXPECTED to exit 1 on the current tree. Neither PIT nor
// cargo-mutants is installed, no campaign has ever run, and no denominator
// exists. A green reading here would be the defect.
//
// It is deliberately NOT wired into `make -C rust gates`. It exits 1 by design
// on the current tree, so wiring it in would turn every sibling branch red for a
// gap none of them introduced. The owner should wire it at the point US-022 is
// scheduled to close -- at which point its exit code becomes the story's answer.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/michaellady/verified-java-websocket-port/internal/mutdenom"
)

func main() {
	root := flag.String("root", ".", "repository root")
	manifestPath := flag.String("manifest", "assurance/mutation/denominator.json", "denominator manifest, relative to root")
	check := flag.Bool("check", false, "verify the denominator against the tree")
	replayFixtures := flag.String("replay-fixtures", "", "polarity fixture catalog, relative to root")
	emitDigest := flag.String("emit-digest", "", "print CANONICAL_PATH_SHA256_V1 over these comma-separated paths and exit")
	emitPayload := flag.Bool("emit-payload-digest", false, "print MUTDENOM_PAYLOAD_SHA256_V1 over the manifest and exit")
	normalizeE1 := flag.Bool("normalize-e1", false, "print the nine-class normalization of mutants/e1-ws-core-manifest.json")
	jsonOut := flag.String("json", "", "write the machine-readable result to this path, relative to root")
	flag.Parse()

	absRoot, err := filepath.Abs(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mutdenomctl: %v\n", err)
		os.Exit(2)
	}

	if *emitDigest != "" {
		paths := strings.Split(*emitDigest, ",")
		digest, count, err := mutdenom.TreeDigest(absRoot, paths)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mutdenomctl: %v\n", err)
			os.Exit(2)
		}
		fmt.Printf("digest=%s files=%d paths=%s\n", digest, count, *emitDigest)
		return
	}

	if *normalizeE1 {
		os.Exit(normalizeE1Manifest(absRoot))
	}

	if *replayFixtures != "" {
		os.Exit(runFixtures(absRoot, filepath.Join(absRoot, *replayFixtures)))
	}

	if *emitPayload {
		manifest, err := mutdenom.LoadManifest(filepath.Join(absRoot, *manifestPath))
		if err != nil {
			fmt.Fprintf(os.Stderr, "mutdenomctl: manifest: %v\n", err)
			os.Exit(2)
		}
		digest, err := mutdenom.PayloadDigest(manifest)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mutdenomctl: %v\n", err)
			os.Exit(2)
		}
		fmt.Printf("payload_digest=%s scheme=%s\n", digest, mutdenom.PayloadDigestScheme)
		return
	}

	if !*check {
		fmt.Fprintln(os.Stderr, "mutdenomctl: one of -check, -replay-fixtures, -emit-digest, -emit-payload-digest, -normalize-e1 is required")
		os.Exit(2)
	}

	manifest, err := mutdenom.LoadManifest(filepath.Join(absRoot, *manifestPath))
	if err != nil {
		fmt.Fprintf(os.Stderr, "mutdenomctl: manifest: %v\n", err)
		os.Exit(2)
	}

	verdict := mutdenom.Check(absRoot, manifest)

	for _, probe := range verdict.EngineAvailability {
		fmt.Printf("gate=mutdenom step=engine-probe engine=%s command=%q %s available=%t\n",
			probe.Engine, probe.Command, probe.ExitText, probe.Available)
	}
	for _, finding := range verdict.Findings {
		fmt.Printf("gate=mutdenom finding=%s disposition=%s target=%s detail=%q\n",
			finding.Code, finding.Disposition, finding.Target, finding.Detail)
	}

	if *jsonOut != "" {
		report := struct {
			Manifest string           `json:"manifest"`
			Verdict  mutdenom.Verdict `json:"verdict"`
		}{Manifest: *manifestPath, Verdict: verdict}
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "mutdenomctl: %v\n", err)
			os.Exit(2)
		}
		out := filepath.Join(absRoot, *jsonOut)
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "mutdenomctl: %v\n", err)
			os.Exit(2)
		}
		if err := os.WriteFile(out, append(data, '\n'), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "mutdenomctl: %v\n", err)
			os.Exit(2)
		}
	}

	blocking := mutdenom.BlockingCount(verdict)
	fmt.Printf("gate=mutdenom state=%s blocking_findings=%d\n", verdict.State, blocking)
	if verdict.State != "OK" {
		os.Exit(1)
	}
}

// normalizeE1Manifest reads the on-disk curated campaign manifest and prints how
// each of its five verdicts maps into the nine AC1 classes. The mapping is
// printed rather than hidden inside the checker so the normalization can be
// argued with. BUILD_FAILED is the interesting one: it is a tool_failure, not a
// technically_unviable mutant, because "the harness could not build it" is a
// statement about the run and not about the mutant.
func normalizeE1Manifest(root string) int {
	path := filepath.Join(root, "mutants/e1-ws-core-manifest.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mutdenomctl: %v\n", err)
		return 2
	}
	var doc struct {
		Mutants []struct {
			ID                 string `json:"id"`
			Verdict            string `json:"verdict"`
			EquivalentAnalysis string `json:"equivalent_analysis"`
		} `json:"mutants"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		fmt.Fprintf(os.Stderr, "mutdenomctl: %v\n", err)
		return 2
	}
	tally := map[string]int{}
	for _, mutant := range doc.Mutants {
		disposition, ok := NormalizeCuratedVerdict(mutant.Verdict)
		if !ok {
			fmt.Printf("gate=mutdenom step=normalize id=%s verdict=%s disposition=UNMAPPED\n",
				mutant.ID, mutant.Verdict)
			tally["UNMAPPED"]++
			continue
		}
		evidence := "absent"
		if strings.TrimSpace(mutant.EquivalentAnalysis) != "" {
			evidence = "present"
		}
		fmt.Printf("gate=mutdenom step=normalize id=%s verdict=%s disposition=%s evidence=%s review=absent\n",
			mutant.ID, mutant.Verdict, disposition, evidence)
		tally[disposition]++
	}
	classes := make([]string, 0, len(tally))
	for class := range tally {
		classes = append(classes, class)
	}
	sort.Strings(classes)
	parts := make([]string, 0, len(classes))
	for _, class := range classes {
		parts = append(parts, fmt.Sprintf("%s=%d", class, tally[class]))
	}
	fmt.Printf("gate=mutdenom step=normalize total=%d %s\n", len(doc.Mutants), strings.Join(parts, " "))
	return 0
}

// NormalizeCuratedVerdict maps cmd/mutctl's five-verdict vocabulary into the
// nine AC1 disposition classes. Exported so the mapping is testable and so
// nobody has to guess it from the checker's behaviour.
func NormalizeCuratedVerdict(verdict string) (string, bool) {
	switch verdict {
	case "KILLED_BY_TESTS", "KILLED_BY_CORPUS":
		return mutdenom.DispKilled, true
	case "SURVIVOR":
		return mutdenom.DispSurvived, true
	case "EQUIVALENT_DOCUMENTED":
		return mutdenom.DispEquivalent, true
	case "BUILD_FAILED":
		// A mutant the harness could not build is a statement about the RUN, not
		// about the mutant. Filing it as technically_unviable would move it out
		// of the eligible set on the strength of a build error, which is exactly
		// the reclassification AC2's evidence-and-review gate exists to stop.
		return mutdenom.DispToolFailure, true
	default:
		return "", false
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
// the polarity proof: a checker that cannot fail is not a check, and a checker
// that only ever fails proves nothing either.
func runFixtures(root, catalogPath string) int {
	raw, err := os.ReadFile(catalogPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mutdenomctl: fixtures: %v\n", err)
		return 2
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var catalog fixtureCatalog
	if err := decoder.Decode(&catalog); err != nil {
		fmt.Fprintf(os.Stderr, "mutdenomctl: fixtures: %v\n", err)
		return 2
	}
	if len(catalog.Cases) == 0 {
		fmt.Fprintln(os.Stderr, "mutdenomctl: fixtures: catalog is empty; an empty polarity suite proves nothing")
		return 2
	}

	greens := 0
	failures := 0
	for _, testCase := range catalog.Cases {
		if testCase.Expected.State == "OK" {
			greens++
		}
		manifest, err := mutdenom.LoadManifest(filepath.Join(root, testCase.ManifestPath))
		var state string
		var codes []string
		exit := 0
		if err != nil {
			state = "BLOCKED"
			codes = []string{mutdenom.FindingManifestSchemaInvalid}
			exit = 1
		} else {
			verdict := mutdenom.Check(root, manifest)
			state = verdict.State
			seen := map[string]bool{}
			for _, finding := range verdict.Findings {
				if finding.Disposition != mutdenom.Block {
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
		fmt.Printf("gate=mutdenom-fixtures case=%s %s exit=%d want_exit=%d state=%s want_state=%s findings=[%s] want_findings=[%s]\n",
			testCase.ID, status, exit, testCase.Expected.ExitCode, state, testCase.Expected.State,
			strings.Join(codes, " "), strings.Join(want, " "))
	}
	fmt.Printf("gate=mutdenom-fixtures cases=%d green_cases=%d failures=%d\n",
		len(catalog.Cases), greens, failures)
	if greens == 0 {
		// A suite with no green case would pass under a checker that blocked
		// unconditionally. That is not a polarity suite.
		fmt.Fprintln(os.Stderr, "mutdenomctl: fixtures: no case expects OK; a suite with no green case cannot distinguish a real checker from one that blocks everything")
		return 2
	}
	if failures > 0 {
		return 1
	}
	return 0
}
