package main

// Campaign-runner polarity. The manifest checker's fixtures prove that the
// STATIC pins can fail; these prove that the EXECUTED campaign can fail. A
// runner that reports REPRODUCED no matter what the process did is not
// evidence either, so each case drives the real runner over a synthetic
// replay command and requires the exact outcome: exit code read from the real
// process state, deadline kills recorded as kills, and a command whose output
// differs between runs refused as a non-reproduction.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/michaellady/verified-java-websocket-port/internal/fuzzpin"
)

type campaignFixtureCase struct {
	ID           string `json:"id"`
	ManifestPath string `json:"manifest_path"`
	TargetID     string `json:"target_id"`
	Rationale    string `json:"rationale"`
	Expected     struct {
		Reproduced      bool   `json:"reproduced"`
		FailureContains string `json:"failure_contains"`
		FirstRunExit    int    `json:"first_run_exit"`
		DeadlineHit     bool   `json:"deadline_hit"`
	} `json:"expected"`
}

type campaignFixtureCatalog struct {
	SchemaVersion string                `json:"schema_version"`
	Story         string                `json:"story"`
	Note          string                `json:"note"`
	Cases         []campaignFixtureCase `json:"cases"`
}

func runCampaignFixtures(root, catalogPath string) int {
	raw, err := os.ReadFile(catalogPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fuzzpinctl: campaign fixtures: %v\n", err)
		return 2
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var catalog campaignFixtureCatalog
	if err := decoder.Decode(&catalog); err != nil {
		fmt.Fprintf(os.Stderr, "fuzzpinctl: campaign fixtures: %v\n", err)
		return 2
	}
	if len(catalog.Cases) == 0 {
		fmt.Fprintln(os.Stderr, "fuzzpinctl: campaign fixtures: empty catalog proves nothing")
		return 2
	}

	failures := 0
	for _, testCase := range catalog.Cases {
		manifest, err := fuzzpin.LoadManifest(filepath.Join(root, testCase.ManifestPath))
		if err != nil {
			fmt.Printf("gate=fuzzpin-campaign-fixtures case=%s FAIL manifest_error=%q\n", testCase.ID, err)
			failures++
			continue
		}
		var target *fuzzpin.Target
		for index := range manifest.Targets {
			if manifest.Targets[index].ID == testCase.TargetID {
				target = &manifest.Targets[index]
				break
			}
		}
		if target == nil {
			fmt.Printf("gate=fuzzpin-campaign-fixtures case=%s FAIL target_absent=%q\n", testCase.ID, testCase.TargetID)
			failures++
			continue
		}
		result := fuzzpin.RunCampaign(root, *target, 2)
		firstExit := 0
		deadlineHit := false
		if len(result.Runs) > 0 {
			firstExit = result.Runs[0].Exit
			deadlineHit = result.Runs[0].DeadlineHit
		}
		ok := result.Reproduced == testCase.Expected.Reproduced &&
			firstExit == testCase.Expected.FirstRunExit &&
			deadlineHit == testCase.Expected.DeadlineHit &&
			strings.Contains(result.Failure, testCase.Expected.FailureContains)
		status := "PASS"
		if !ok {
			status = "FAIL"
			failures++
		}
		fmt.Printf("gate=fuzzpin-campaign-fixtures case=%s %s reproduced=%t want=%t first_exit=%d want=%d deadline_hit=%t want=%t failure=%q want_contains=%q\n",
			testCase.ID, status, result.Reproduced, testCase.Expected.Reproduced,
			firstExit, testCase.Expected.FirstRunExit, deadlineHit, testCase.Expected.DeadlineHit,
			result.Failure, testCase.Expected.FailureContains)
	}
	fmt.Printf("gate=fuzzpin-campaign-fixtures cases=%d failures=%d\n", len(catalog.Cases), failures)
	if failures > 0 {
		return 1
	}
	return 0
}
