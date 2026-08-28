package mutation

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

type externalOutcomeReport struct {
	CargoMutantsVersion string            `json:"cargo_mutants_version"`
	Caught              int               `json:"caught"`
	Missed              int               `json:"missed"`
	Timeout             int               `json:"timeout"`
	TotalMutants        int               `json:"total_mutants"`
	Unviable            int               `json:"unviable"`
	Outcomes            []externalOutcome `json:"outcomes"`
}

type externalOutcome struct {
	Scenario json.RawMessage `json:"scenario"`
	Summary  string          `json:"summary"`
}

type externalScenario struct {
	Mutant struct {
		Name string `json:"name"`
	} `json:"Mutant"`
}

type externalReceiptDigest struct {
	Path          string `json:"path"`
	SHA256        string `json:"sha256"`
	ContentSHA256 string `json:"content_sha256"`
}

type externalManifestReceipts struct {
	RawReceipts []externalReceiptDigest `json:"raw_receipts"`
	RawReceipt  externalReceiptDigest   `json:"raw_receipt"`
}

type externalAdjudication struct {
	SubjectCommit string `json:"subject_commit"`
	ClosureCommit string `json:"closure_commit"`
	Items         []struct {
		Mutant      string `json:"mutant"`
		Disposition string `json:"disposition"`
		Reason      string `json:"reason"`
	} `json:"items"`
}

func loadExternalReport(t *testing.T, root, relative string) (externalOutcomeReport, map[string]string) {
	t.Helper()
	raw := readExternalReceipt(t, filepath.Join(root, relative))
	var report externalOutcomeReport
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("decode %s: %v", relative, err)
	}
	if report.CargoMutantsVersion != "27.1.0" {
		t.Fatalf("%s cargo-mutants version=%q", relative, report.CargoMutantsVersion)
	}
	if report.Caught+report.Missed+report.Timeout+report.Unviable != report.TotalMutants {
		t.Fatalf("%s counts do not sum to total: %+v", relative, report)
	}
	mutants := make(map[string]string, report.TotalMutants)
	baselines := 0
	for _, outcome := range report.Outcomes {
		var baseline string
		if json.Unmarshal(outcome.Scenario, &baseline) == nil {
			if baseline != "Baseline" || outcome.Summary != "Success" {
				t.Fatalf("%s invalid baseline outcome: %s/%s", relative, baseline, outcome.Summary)
			}
			baselines++
			continue
		}
		var scenario externalScenario
		if err := json.Unmarshal(outcome.Scenario, &scenario); err != nil || scenario.Mutant.Name == "" {
			t.Fatalf("%s invalid mutant scenario: %s", relative, outcome.Scenario)
		}
		if prior, exists := mutants[scenario.Mutant.Name]; exists {
			t.Fatalf("%s duplicate mutant %q (%s and %s)", relative, scenario.Mutant.Name, prior, outcome.Summary)
		}
		mutants[scenario.Mutant.Name] = outcome.Summary
	}
	if baselines != 1 || len(mutants) != report.TotalMutants {
		t.Fatalf("%s baseline=%d mutants=%d total=%d", relative, baselines, len(mutants), report.TotalMutants)
	}
	return report, mutants
}

func readExternalReceipt(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(path, ".gz") {
		return raw
	}
	reader, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	contents, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	return contents
}

func verifyExternalManifestDigests(t *testing.T, root, directory string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, directory, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest externalManifestReceipts
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	receipts := append([]externalReceiptDigest(nil), manifest.RawReceipts...)
	if manifest.RawReceipt.Path != "" {
		receipts = append(receipts, manifest.RawReceipt)
	}
	if len(receipts) == 0 {
		t.Fatalf("%s manifest has no raw receipts", directory)
	}
	for _, receipt := range receipts {
		if filepath.Base(receipt.Path) != receipt.Path || receipt.SHA256 == "" || receipt.ContentSHA256 == "" {
			t.Fatalf("%s unsafe or incomplete receipt: %+v", directory, receipt)
		}
		contents, err := os.ReadFile(filepath.Join(root, directory, receipt.Path))
		if err != nil {
			t.Fatal(err)
		}
		want := receipt.SHA256
		if !strings.HasPrefix(want, "sha256:") {
			want = "sha256:" + want
		}
		if got := digest(contents); got != want {
			t.Fatalf("%s/%s digest=%s want=%s", directory, receipt.Path, got, want)
		}
		contentWant := receipt.ContentSHA256
		if !strings.HasPrefix(contentWant, "sha256:") {
			contentWant = "sha256:" + contentWant
		}
		if got := digest(readExternalReceipt(t, filepath.Join(root, directory, receipt.Path))); got != contentWant {
			t.Fatalf("%s/%s content digest=%s want=%s", directory, receipt.Path, got, contentWant)
		}
	}
}

func addExternalCounts(total *externalOutcomeReport, report externalOutcomeReport) {
	total.Caught += report.Caught
	total.Missed += report.Missed
	total.Timeout += report.Timeout
	total.TotalMutants += report.TotalMutants
	total.Unviable += report.Unviable
}

func TestExternalCargoMutantsCampaignsReconcile(t *testing.T) {
	root := repositoryRoot(t)
	for _, directory := range []string{
		"evidence/mutation/external-30bbcad",
		"evidence/mutation/external-38428a5",
		"evidence/mutation/external-ac15da8",
	} {
		verifyExternalManifestDigests(t, root, directory)
	}

	var discovery externalOutcomeReport
	discoveryMutants := map[string]string{}
	for _, name := range []string{"a", "b", "c", "d"} {
		report, mutants := loadExternalReport(t, root, "evidence/mutation/external-30bbcad/outcomes-"+name+".json.gz")
		addExternalCounts(&discovery, report)
		for mutant, status := range mutants {
			if _, exists := discoveryMutants[mutant]; exists {
				t.Fatalf("discovery partitions overlap on %q", mutant)
			}
			discoveryMutants[mutant] = status
		}
	}
	wantDiscovery := externalOutcomeReport{Caught: 756, Missed: 81, Timeout: 45, TotalMutants: 1005, Unviable: 123}
	if discovery.Caught != wantDiscovery.Caught || discovery.Missed != wantDiscovery.Missed || discovery.Timeout != wantDiscovery.Timeout || discovery.TotalMutants != wantDiscovery.TotalMutants || discovery.Unviable != wantDiscovery.Unviable {
		t.Fatalf("discovery counts=%+v want=%+v", discovery, wantDiscovery)
	}
	replay, replayMutants := loadExternalReport(t, root, "evidence/mutation/external-30bbcad/outcomes-timeout-replay.json.gz")
	if replay.TotalMutants != 45 || replay.Caught != 11 || replay.Missed != 33 || replay.Timeout != 1 || replay.Unviable != 0 {
		t.Fatalf("timeout replay counts drifted: %+v", replay)
	}
	for mutant, status := range replayMutants {
		if discoveryMutants[mutant] != "Timeout" {
			t.Fatalf("replay mutant %q was not an original timeout", mutant)
		}
		discoveryMutants[mutant] = status
	}
	resolved := map[string]int{}
	for _, status := range discoveryMutants {
		resolved[status]++
	}
	if !reflect.DeepEqual(resolved, map[string]int{"CaughtMutant": 767, "MissedMutant": 114, "Timeout": 1, "Unviable": 123}) {
		t.Fatalf("resolved discovery counts=%v", resolved)
	}

	var full externalOutcomeReport
	fullMutants := map[string]string{}
	for _, shard := range []string{"0", "1", "2", "3"} {
		report, mutants := loadExternalReport(t, root, "evidence/mutation/external-38428a5/outcomes-shard-"+shard+".json.gz")
		addExternalCounts(&full, report)
		for mutant, status := range mutants {
			if _, exists := fullMutants[mutant]; exists {
				t.Fatalf("full shards overlap on %q", mutant)
			}
			fullMutants[mutant] = status
		}
	}
	wantFull := externalOutcomeReport{Caught: 786, Missed: 32, TotalMutants: 938, Unviable: 120}
	if full.Caught != wantFull.Caught || full.Missed != wantFull.Missed || full.Timeout != 0 || full.TotalMutants != wantFull.TotalMutants || full.Unviable != wantFull.Unviable {
		t.Fatalf("full counts=%+v want=%+v", full, wantFull)
	}

	adjudicationRaw, err := os.ReadFile(filepath.Join(root, "evidence/mutation/external-38428a5/adjudication.json"))
	if err != nil {
		t.Fatal(err)
	}
	var adjudication externalAdjudication
	if err := json.Unmarshal(adjudicationRaw, &adjudication); err != nil {
		t.Fatal(err)
	}
	if adjudication.SubjectCommit != "38428a502259f73a688eff2266c925ccf6bb5ea5" || adjudication.ClosureCommit != "ac15da85bffbbd5efae2969b6be35edd5833fa85" {
		t.Fatalf("adjudication anchors drifted: %+v", adjudication)
	}
	dispositions := map[string]int{}
	adjudicated := map[string]bool{}
	live := []string{}
	for _, item := range adjudication.Items {
		if item.Reason == "" || fullMutants[item.Mutant] != "MissedMutant" || adjudicated[item.Mutant] {
			t.Fatalf("invalid adjudication item: %+v", item)
		}
		adjudicated[item.Mutant] = true
		dispositions[item.Disposition]++
		if item.Disposition == "LIVE_CLOSED_TARGETED" {
			live = append(live, item.Mutant)
		}
	}
	wantDispositions := map[string]int{
		"ALLOCATION_SHAPE_ONLY":      8,
		"EQUIVALENT_ALGEBRAIC":       3,
		"EQUIVALENT_CONTROL_FLOW":    3,
		"INVARIANT_EQUIVALENT":       2,
		"LIVE_CLOSED_TARGETED":       8,
		"REDUNDANT_GUARD_EQUIVALENT": 3,
		"UNREACHABLE_BRANCH":         5,
	}
	if len(adjudicated) != 32 || !reflect.DeepEqual(dispositions, wantDispositions) {
		t.Fatalf("adjudication coverage=%d dispositions=%v", len(adjudicated), dispositions)
	}

	targeted, targetedMutants := loadExternalReport(t, root, "evidence/mutation/external-ac15da8/outcomes-targeted.json.gz")
	if targeted.TotalMutants != 9 || targeted.Caught != 9 || targeted.Missed != 0 || targeted.Timeout != 0 || targeted.Unviable != 0 {
		t.Fatalf("targeted closure counts drifted: %+v", targeted)
	}
	sort.Strings(live)
	for _, mutant := range live {
		if targetedMutants[mutant] != "CaughtMutant" {
			t.Fatalf("live mutant was not caught by targeted closure: %s", mutant)
		}
	}

	changedSource, err := exec.Command("git", "-C", root, "diff", "--name-only", adjudication.SubjectCommit, adjudication.ClosureCommit, "--", "rust/connection-core/src").Output()
	if err != nil {
		t.Fatal(err)
	}
	if string(changedSource) != "rust/connection-core/src/handshake/http.rs\n" {
		t.Fatalf("unexpected production-source files changed during closure: %s", changedSource)
	}
	const httpPath = "rust/connection-core/src/handshake/http.rs"
	before, err := exec.Command("git", "-C", root, "show", adjudication.SubjectCommit+":"+httpPath).Output()
	if err != nil {
		t.Fatal(err)
	}
	after, err := exec.Command("git", "-C", root, "show", adjudication.ClosureCommit+":"+httpPath).Output()
	if err != nil {
		t.Fatal(err)
	}
	const testMarker = "\n#[cfg(test)]\n"
	beforeMarker, afterMarker := bytes.Index(before, []byte(testMarker)), bytes.Index(after, []byte(testMarker))
	if beforeMarker < 0 || afterMarker < 0 || !bytes.Equal(before[:beforeMarker], after[:afterMarker]) {
		t.Fatal("production HTTP parser logic changed during the targeted test closure")
	}
}
