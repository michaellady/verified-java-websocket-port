package mutation

import (
	"reflect"
	"testing"
)

func TestUS022MutationAndProtectedAcceptance(t *testing.T) {
	root := repositoryRoot(t)
	plan, _ := loadPlan(t, root)
	denominator := loadDenominator(t, root)
	java := loadEvidence(t, root, artifactPaths[2])
	rust := loadEvidence(t, root, artifactPaths[3])
	receipt := loadReceipt(t, root)

	for name, claims := range map[string]struct {
		story       string
		status      string
		assurance   string
		independent bool
		signing     bool
		production  bool
		publication bool
	}{
		"plan":        {plan.StoryID, plan.Status, plan.Assurance, plan.IndependentReviewClaimed, plan.Signing, plan.Production, plan.Publication},
		"denominator": {denominator.StoryID, denominator.Status, denominator.Assurance, denominator.IndependentReviewClaimed, denominator.Signing, denominator.Production, denominator.Publication},
		"java":        {java.StoryID, java.Status, java.Assurance, java.IndependentReviewClaimed, java.Signing, java.Production, java.Publication},
		"rust":        {rust.StoryID, rust.Status, rust.Assurance, rust.IndependentReviewClaimed, rust.Signing, rust.Production, rust.Publication},
		"protected":   {receipt.StoryID, receipt.Status, receipt.Assurance, receipt.IndependentReviewClaimed, receipt.Signing, receipt.Production, receipt.Publication},
	} {
		if claims.story != "US-022" || claims.status != PassOwner || claims.assurance != AssuranceOwner {
			t.Fatalf("%s claim boundary drifted: story=%q status=%q assurance=%q", name, claims.story, claims.status, claims.assurance)
		}
		if claims.independent || claims.signing || claims.production || claims.publication {
			t.Fatalf("%s made a forbidden independence/signing/production/publication claim", name)
		}
	}

	if len(denominator.Rows) != 8 {
		t.Fatalf("denominator rows=%d, want 8", len(denominator.Rows))
	}
	runtimeRows := map[string]int{}
	for _, row := range denominator.Rows {
		runtimeRows[row.Runtime]++
		if row.Disposition != "KILLED" {
			t.Fatalf("%s/%s disposition=%q, want KILLED", row.Runtime, row.MutantID, row.Disposition)
		}
	}
	if !reflect.DeepEqual(runtimeRows, map[string]int{"java": 4, "rust": 4}) {
		t.Fatalf("runtime denominator=%v, want java=4 rust=4", runtimeRows)
	}
	wantCounts := DenominatorCounts{Killed: 8}
	if denominator.Counts != wantCounts || denominator.Full != 8 || denominator.Excluded != 0 || denominator.Eligible != 8 || denominator.Missed != 0 || denominator.ScoreBasisPoints != 10000 {
		t.Fatalf("denominator summary does not represent 8/8 killed with zero exclusions or misses: %+v", denominator)
	}

	wantEngines := map[string][]ExternalEngine{
		"plan": {{ID: "cargo-mutants", Status: Unavailable}, {ID: "pit", Status: Unavailable}},
		"java": {{ID: "maven", Status: Unavailable}, {ID: "pit", Status: Unavailable}},
		"rust": {{ID: "cargo-mutants", Status: Unavailable}},
	}
	for name, got := range map[string][]ExternalEngine{"plan": plan.ExternalEngines, "java": java.ExternalEngines, "rust": rust.ExternalEngines} {
		if !reflect.DeepEqual(got, wantEngines[name]) {
			t.Fatalf("%s unavailable-engine projection=%v, want %v", name, got, wantEngines[name])
		}
	}

	planned := map[string]Mutant{}
	for _, mutant := range plan.Mutants {
		planned[mutant.Runtime+"/"+mutant.MutantID] = mutant
	}
	for _, evidence := range []RuntimeEvidence{java, rust} {
		if len(evidence.Results) != 4 {
			t.Fatalf("%s results=%d, want 4", evidence.Runtime, len(evidence.Results))
		}
		if !evidence.NoRepositoryDrift {
			t.Fatalf("%s did not reconcile repository state", evidence.Runtime)
		}
		sourceDigest, testDigest, err := closureDigests(root, evidence.Runtime, plan.RepositoryAnchor)
		if err != nil {
			t.Fatalf("derive %s closure digests: %v", evidence.Runtime, err)
		}
		if evidence.SourceClosureSHA256 != sourceDigest || evidence.TestClosureSHA256 != testDigest {
			t.Fatalf("%s source/test closure digest did not reconcile", evidence.Runtime)
		}
		testManifest, err := readArtifact(root, "evidence/java/test-manifest.json")
		if err != nil {
			t.Fatal(err)
		}
		if evidence.TestManifestSHA256 != digest(testManifest) {
			t.Fatalf("%s test-manifest digest did not reconcile", evidence.Runtime)
		}
		if len(evidence.Before) != 2 || len(evidence.After) != 2 {
			t.Fatalf("%s baseline observations: before=%d after=%d, want two each", evidence.Runtime, len(evidence.Before), len(evidence.After))
		}
		for index := range evidence.Before {
			before, after := evidence.Before[index], evidence.After[index]
			if before.Repeat != uint64(index+1) || after.Repeat != uint64(index+1) || before.Phase != "before" || after.Phase != "after" {
				t.Fatalf("%s baseline ordering drifted at observation %d", evidence.Runtime, index+1)
			}
			if !reflect.DeepEqual(before.Process.Argv, after.Process.Argv) {
				t.Fatalf("%s baseline command changed at observation %d", evidence.Runtime, index+1)
			}
			for phase, baseline := range map[string]Baseline{"before": before, "after": after} {
				if baseline.Process.ExitCode != 0 || baseline.Process.TerminationReason != "EXITED" || baseline.TestsPassed == 0 || baseline.TestsFailed != 0 || baseline.TestsSkipped != 0 || baseline.TestsFiltered != 0 {
					t.Fatalf("%s %s baseline %d did not pass completely: %+v", evidence.Runtime, phase, index+1, baseline)
				}
			}
			if before.TestsPassed != after.TestsPassed {
				t.Fatalf("%s passing-test count changed from %d to %d", evidence.Runtime, before.TestsPassed, after.TestsPassed)
			}
		}

		for _, result := range evidence.Results {
			mutant, ok := planned[evidence.Runtime+"/"+result.MutantID]
			if !ok {
				t.Fatalf("%s result %q is absent from the planted plan", evidence.Runtime, result.MutantID)
			}
			if result.Engine != "IN_TREE_PLANTED" || result.Disposition != "KILLED" || len(result.Observations) != 2 {
				t.Fatalf("%s/%s is not a two-observation planted kill", evidence.Runtime, result.MutantID)
			}
			for index, observation := range result.Observations {
				if observation.Repeat != uint64(index+1) || observation.Build.ExitCode != 0 || observation.Build.TerminationReason != "EXITED" {
					t.Fatalf("%s/%s observation %d was not a successful build", evidence.Runtime, result.MutantID, index+1)
				}
				if observation.Test.ExitCode == 0 || observation.Test.TerminationReason != "EXITED" || !observation.Killed || len(observation.FailedTestIDs) == 0 {
					t.Fatalf("%s/%s observation %d was not killed by a failing selected test", evidence.Runtime, result.MutantID, index+1)
				}
				if !receiptCommandMatches(mutant, observation.Build.Argv, true) || !receiptCommandMatches(mutant, observation.Test.Argv, false) || !reflect.DeepEqual(observation.FailedTestIDs, mutant.ExpectedKillingTestIDs) {
					t.Fatalf("%s/%s observation %d command or killing-test selection drifted", evidence.Runtime, result.MutantID, index+1)
				}
			}
		}
	}

	wantSubjects := []Subject{
		{ID: "pinned_java", Status: "PASS_RETAINED_RECONCILED"},
		{ID: "rust_candidate", Status: "NOT_EXECUTED_NO_PUBLIC_RECEIPT"},
		{ID: "empty_rust", Status: "NOT_EXECUTED_NO_PUBLIC_RECEIPT"},
		{ID: "planted_java", Status: "NOT_EXECUTED_NO_PUBLIC_RECEIPT"},
		{ID: "planted_rust", Status: "NOT_EXECUTED_NO_PUBLIC_RECEIPT"},
	}
	if !reflect.DeepEqual(receipt.Subjects, wantSubjects) {
		t.Fatalf("protected subject projection drifted: %v", receipt.Subjects)
	}
	if len(receipt.Tiers) != 2 || receipt.Tiers[0].Tier != "hidden" || receipt.Tiers[1].Tier != "sealed" {
		t.Fatalf("protected tiers must be the exact hidden/sealed public projections")
	}
	for _, tier := range receipt.Tiers {
		if tier.Expected == 0 || tier.Expected != tier.Selected || tier.Expected != tier.Executed || tier.Expected != tier.Passed || tier.Failed != 0 || tier.Skipped != 0 || tier.Filtered != 0 || tier.TimedOut != 0 {
			t.Fatalf("%s public projection counts do not reconcile", tier.Tier)
		}
	}
	if receipt.Leaks != (LeakCounts{}) {
		t.Fatalf("protected public projection reports nonzero leak counters: %+v", receipt.Leaks)
	}
	receiptRaw, err := readArtifact(root, artifactPaths[4])
	if err != nil {
		t.Fatal(err)
	}
	if err := rejectProtectedMaterial(receiptRaw); err != nil {
		t.Fatalf("protected public projection contains protected data: %v", err)
	}

	if err := Verify(root); err != nil {
		t.Fatalf("verify committed US-022 repository evidence: %v", err)
	}
}
