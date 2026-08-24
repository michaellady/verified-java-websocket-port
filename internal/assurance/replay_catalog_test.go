package assurance

import (
	"context"
	"encoding/json"
	"os/exec"
	"testing"

	vendorprotocol "github.com/michaellady/verified-java-to-rust/foundation/protocol"
)

func TestReplayCatalogCasesExerciseVerifyReplayAndCLI(t *testing.T) {
	t.Parallel()

	catalog := loadReplayCaseCatalog(t)
	binary := assurectlBinaryForUS004(t)
	for _, fixture := range catalog.Cases {
		fixture := fixture
		t.Run(fixture.ID, func(t *testing.T) {
			root, lifecyclePath := realizeReplayCaseRoot(t, fixture)

			verifyVerdict, err := Verify(context.Background(), Request{
				RootPath:      root,
				LifecyclePath: lifecyclePath,
				Mode:          ModeVerify,
			})
			if err != nil {
				t.Fatalf("verify %s: %v", fixture.ID, err)
			}
			assertReplayCaseExpectations(t, verifyVerdict.Findings, fixture.VerifyFindings, fixture.ExactFindings)

			replayVerdict, err := Replay(context.Background(), Request{
				RootPath:      root,
				LifecyclePath: lifecyclePath,
				Mode:          ModeReplay,
			})
			if err != nil {
				t.Fatalf("replay %s: %v", fixture.ID, err)
			}
			assertReplayCaseExpectations(t, replayVerdict.Findings, fixture.ReplayFindings, fixture.ExactFindings)

			assertCLIExitAndFindings(t, binary, "verify", root, lifecyclePath, fixture.VerifyFindings, fixture.CLI.VerifyExitCode, fixture.ExactFindings)
			assertCLIExitAndFindings(t, binary, "replay", root, lifecyclePath, fixture.ReplayFindings, fixture.CLI.ReplayExitCode, fixture.ExactFindings)
		})
	}
}

func TestReplayCatalogDispositionCoverageMatchesRegistry(t *testing.T) {
	t.Parallel()

	catalog := loadReplayCaseCatalog(t)
	assertReplayDispositionCoverage(t, catalog)
}

func assertCLIExitAndFindings(t *testing.T, binary, subcommand, root, lifecyclePath string, expected []replayCaseExpectation, exitCode int, exact bool) {
	t.Helper()
	command := exec.Command(binary, subcommand, "--root", root, "--lifecycle", lifecyclePath)
	output, err := command.CombinedOutput()
	if exitError, ok := err.(*exec.ExitError); ok {
		if exitError.ExitCode() != exitCode {
			t.Fatalf("%s exit = %d, want %d\n%s", subcommand, exitError.ExitCode(), exitCode, output)
		}
	} else if err != nil {
		t.Fatalf("%s exec: %v\n%s", subcommand, err, output)
	} else if exitCode != 0 {
		t.Fatalf("%s exit = 0, want %d\n%s", subcommand, exitCode, output)
	}

	var verdict Verdict
	if decodeErr := json.Unmarshal(output, &verdict); decodeErr != nil {
		t.Fatalf("%s output decode: %v\n%s", subcommand, decodeErr, output)
	}
	assertReplayCaseExpectations(t, verdict.Findings, expected, exact)
}

func assertReplayCaseExpectations(t *testing.T, findings []vendorprotocol.Finding, expected []replayCaseExpectation, exact bool) {
	t.Helper()

	for _, item := range expected {
		wantCount := item.Count
		if wantCount == 0 {
			wantCount = 1
		}
		gotCount := 0
		for _, finding := range findings {
			if finding.Code == item.Code && finding.Disposition == vendorprotocol.Disposition(item.Disposition) {
				gotCount++
			}
		}
		if gotCount != wantCount {
			t.Fatalf("finding %s/%s count = %d, want %d in %+v", item.Code, item.Disposition, gotCount, wantCount, findings)
		}
	}
	if !exact {
		return
	}
	total := 0
	for _, item := range expected {
		if item.Count == 0 {
			total++
			continue
		}
		total += item.Count
	}
	if len(findings) != total {
		t.Fatalf("finding count = %d, want %d exact findings: %+v", len(findings), total, findings)
	}
}
