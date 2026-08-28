package mutation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	working, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(working, "..", ".."))
}

func loadPlan(t *testing.T, root string) (Plan, string) {
	t.Helper()
	raw, err := readArtifact(root, artifactPaths[0])
	if err != nil {
		t.Fatal(err)
	}
	var plan Plan
	if err := decodeStrict(raw, &plan); err != nil {
		t.Fatal(err)
	}
	return plan, digest(raw)
}

func loadEvidence(t *testing.T, root, relative string) RuntimeEvidence {
	t.Helper()
	_, evidence, err := loadRuntime(root, relative)
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func loadDenominator(t *testing.T, root string) Denominator {
	t.Helper()
	raw, err := readArtifact(root, artifactPaths[1])
	if err != nil {
		t.Fatal(err)
	}
	var denominator Denominator
	if err := decodeStrict(raw, &denominator); err != nil {
		t.Fatal(err)
	}
	return denominator
}

func loadReceipt(t *testing.T, root string) ProtectedReceipt {
	t.Helper()
	raw, err := readArtifact(root, artifactPaths[4])
	if err != nil {
		t.Fatal(err)
	}
	var receipt ProtectedReceipt
	if err := decodeStrict(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func TestVerifyCommittedUS022Evidence(t *testing.T) {
	if err := Verify(repositoryRoot(t)); err != nil {
		t.Fatal(err)
	}
}

func TestStrictParserRejectsMissingDuplicateUnknownAndTrailingFields(t *testing.T) {
	required := []string{"required"}
	for name, raw := range map[string][]byte{
		"missing":   []byte(`{}`),
		"duplicate": []byte(`{"required":false,"required":true}`),
		"unknown":   []byte(`{"required":true,"other":false}`),
	} {
		t.Run(name, func(t *testing.T) {
			if err := exactObjectKeys(raw, required); err == nil {
				t.Fatal("hostile shape was accepted")
			}
		})
	}
	var destination struct {
		Required bool `json:"required"`
	}
	if err := decodeStrict([]byte(`{"required":true} {}`), &destination); err == nil {
		t.Fatal("trailing JSON was accepted")
	}
}

func TestDenominatorRejectsReorderOmissionAndRecomputedManipulation(t *testing.T) {
	root := repositoryRoot(t)
	plan, planDigest := loadPlan(t, root)
	java := loadEvidence(t, root, artifactPaths[2])
	rust := loadEvidence(t, root, artifactPaths[3])
	base := loadDenominator(t, root)

	t.Run("reordered", func(t *testing.T) {
		value := base
		value.Rows = append([]DenominatorRow(nil), base.Rows...)
		value.Rows[0], value.Rows[1] = value.Rows[1], value.Rows[0]
		if err := verifyDenominator(plan, planDigest, java, rust, value); err == nil {
			t.Fatal("reordered denominator was accepted")
		}
	})
	t.Run("omitted and recomputed", func(t *testing.T) {
		value := base
		value.Rows = append([]DenominatorRow(nil), base.Rows[1:]...)
		value.Counts.Killed--
		value.Full--
		value.Eligible--
		if err := verifyDenominator(plan, planDigest, java, rust, value); err == nil {
			t.Fatal("recomputed omission was accepted")
		}
	})
}

func TestPlanRejectsUnavailableToolOverclaimAndSourceGitDrift(t *testing.T) {
	root := repositoryRoot(t)
	base, _ := loadPlan(t, root)
	t.Run("unavailable tool", func(t *testing.T) {
		value := base
		value.ExternalEngines = append([]ExternalEngine(nil), base.ExternalEngines...)
		value.ExternalEngines[0].Status = "PASS"
		value.ExternalEngines[0].ResultCount = 1
		if err := verifyPlan(root, &value); err == nil || !strings.Contains(err.Error(), "UNAVAILABLE_TOOL_OVERCLAIM") {
			t.Fatalf("overclaim result=%v", err)
		}
	})
	t.Run("source drift", func(t *testing.T) {
		value := base
		value.Mutants = append([]Mutant(nil), base.Mutants...)
		value.Mutants[0].ProductionFileSHA256 = "sha256:" + strings.Repeat("0", 64)
		if err := verifyPlan(root, &value); err == nil {
			t.Fatal("source drift was accepted")
		}
	})
	t.Run("git drift", func(t *testing.T) {
		value := base
		value.Inputs = append([]Artifact(nil), base.Inputs...)
		value.Inputs[0].Git.Blob = strings.Repeat("0", 40)
		if err := verifyPlan(root, &value); err == nil {
			t.Fatal("Git drift was accepted")
		}
	})
}

func TestRuntimeRejectsTestManifestAndControlTampering(t *testing.T) {
	root := repositoryRoot(t)
	plan, planDigest := loadPlan(t, root)
	base := loadEvidence(t, root, artifactPaths[2])
	t.Run("test manifest", func(t *testing.T) {
		value := base
		value.TestManifestSHA256 = "sha256:" + strings.Repeat("0", 64)
		if err := verifyRuntimeEvidence(root, plan, planDigest, value, "java"); err == nil || !strings.Contains(err.Error(), "TEST_MANIFEST_DRIFT") {
			t.Fatalf("manifest drift result=%v", err)
		}
	})
	t.Run("control digest", func(t *testing.T) {
		value := base
		value.Results = append([]MutationResult(nil), base.Results...)
		value.Results[0].ResultFileSHA256 = "sha256:" + strings.Repeat("0", 64)
		if err := verifyRuntimeEvidence(root, plan, planDigest, value, "java"); err == nil || !strings.Contains(err.Error(), "CONTROL_TAMPERING") {
			t.Fatalf("control drift result=%v", err)
		}
	})
	t.Run("single attempt relabeled killed", func(t *testing.T) {
		value := base
		value.Results = append([]MutationResult(nil), base.Results...)
		value.Results[0].Observations = value.Results[0].Observations[:1]
		if err := verifyRuntimeEvidence(root, plan, planDigest, value, "java"); err == nil {
			t.Fatal("single-attempt kill was accepted")
		}
	})
}

func TestProtectedProjectionRejectsPathLeakAndStrongerClaims(t *testing.T) {
	root := repositoryRoot(t)
	base := loadReceipt(t, root)
	t.Run("candidate overclaim", func(t *testing.T) {
		value := base
		value.Subjects = append([]Subject(nil), base.Subjects...)
		value.Subjects[1].Status = "PASS_RETAINED_RECONCILED"
		if err := verifyProtected(root, value); err == nil || !strings.Contains(err.Error(), "PROTECTED_OVERCLAIM") {
			t.Fatalf("subject overclaim result=%v", err)
		}
	})
	t.Run("assurance overclaim", func(t *testing.T) {
		value := base
		value.IndependentReviewClaimed = true
		if err := verifyProtected(root, value); err == nil {
			t.Fatal("independence overclaim was accepted")
		}
	})
	t.Run("protected path leak", func(t *testing.T) {
		raw, err := json.Marshal(map[string]any{"protected_path": "sealed/case.json"})
		if err != nil {
			t.Fatal(err)
		}
		if err := rejectProtectedMaterial(raw); err == nil {
			t.Fatal("protected path was accepted")
		}
	})
	t.Run("secret in ordinary value", func(t *testing.T) {
		if err := rejectProtectedMaterial([]byte(`{"status":"token=hostile"}`)); err == nil {
			t.Fatal("secret-bearing ordinary value was accepted")
		}
	})
}

func TestRepositoryArtifactsRejectSymlinkFIFOAndRedirectedParent(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "safe"), 0o700); err != nil {
		t.Fatal(err)
	}
	regular := filepath.Join(root, "safe", "regular.json")
	if err := os.WriteFile(regular, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(regular, filepath.Join(root, "safe", "link.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := readArtifact(root, "safe/link.json"); err == nil {
		t.Fatal("symlink artifact was accepted")
	}
	fifo := filepath.Join(root, "safe", "fifo.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readArtifact(root, "safe/fifo.json"); err == nil {
		t.Fatal("FIFO artifact was accepted")
	}
	redirect := filepath.Join(root, "redirect")
	if err := os.Symlink(filepath.Join(root, "safe"), redirect); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(root, "redirect/output.json", []byte("{}\n")); err == nil {
		t.Fatal("atomic write traversed a redirected parent")
	}
}

func TestCanonicalConfigRejectsAncestorAliasOverlap(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	repository := filepath.Join(real, "repo")
	scratch := filepath.Join(repository, "scratch")
	if err := os.MkdirAll(scratch, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(real, "tool")
	if err := os.WriteFile(executable, []byte("tool"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := Config{RepositoryRoot: filepath.Join(alias, "repo"), ScratchRoot: scratch, JavaExecutable: executable, MavenExecutable: executable, MavenRepository: real, CargoExecutable: executable, RustcExecutable: executable}
	if _, err := normalizeConfig(cfg); err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("canonical alias overlap result=%v", err)
	}
}

func TestPlanCommandRejectsArbitraryExecutable(t *testing.T) {
	root := repositoryRoot(t)
	plan, _ := loadPlan(t, root)
	mutant := plan.Mutants[0]
	mutant.BuildArgv = []string{"/bin/sh", "-c", "anything"}
	if err := verifyCommandTemplate(mutant); err == nil {
		t.Fatal("arbitrary command was accepted")
	}
	raw, err := readArtifact(root, artifactPaths[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCurrentGitFile(root, artifactPaths[0], append(raw, '\n')); err == nil {
		t.Fatal("plan bytes outside the immutable current Git object were accepted")
	}
}

func TestDifferentialManifestRejectsPermissiveDependencyRows(t *testing.T) {
	keys := []string{"$schema", "schema_version", "story_id", "evidence_id", "status", "assurance", "independent_review_claimed", "signing", "production", "publication", "repository_anchor", "parity_scope", "coverage", "controls", "scenarios", "reproducers", "inputs", "processes", "ledger", "counts", "nonclaims"}
	for name, row := range map[string]map[string]any{
		"unknown": {"kind": "java-runtime-jar", "path": "/tmp/x", "sha256": "sha256:" + strings.Repeat("0", 64), "bytes": 1, "extra": true},
		"missing": {"kind": "java-runtime-jar", "path": "/tmp/x", "sha256": "sha256:" + strings.Repeat("0", 64)},
	} {
		t.Run(name, func(t *testing.T) {
			top := map[string]any{}
			for _, key := range keys {
				top[key] = nil
			}
			top["inputs"] = []any{row}
			raw, err := json.Marshal(top)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeDifferentialInputs(raw); err == nil {
				t.Fatal("permissive dependency row was accepted")
			}
		})
	}
}

func TestNestedShapeRejectsOmittedProcessField(t *testing.T) {
	raw, err := readArtifact(repositoryRoot(t), artifactPaths[2])
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	before := value["before"].([]any)
	process := before[0].(map[string]any)["process"].(map[string]any)
	delete(process, "stdout_bytes")
	hostile, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyRuntimeJSONShape(hostile); err == nil {
		t.Fatal("nested required-field omission was accepted")
	}
}

func TestRunProcessClassifiesSignalAsToolFailure(t *testing.T) {
	receipt, _, _, err := runProcess(t.Context(), t.TempDir(), []string{"/bin/sh", "-c", "kill -TERM $$"}, 5000)
	if err == nil || receipt.TerminationReason != "SIGNALLED" || receipt.ExitCode != -1 {
		t.Fatalf("signal result=%+v err=%v", receipt, err)
	}
}

func TestClosureRejectsPreexistingWorkingTreeDrift(t *testing.T) {
	root := repositoryRoot(t)
	plan, _ := loadPlan(t, root)
	path := "rust/connection-core/src/lib.rs"
	raw, err := readArtifact(root, path)
	if err != nil {
		t.Fatal(err)
	}
	hostile := append(append([]byte(nil), raw...), '\n')
	if err := verifyBytesAgainstGit(root, path, plan.RepositoryAnchor.Commit, hostile); err == nil {
		t.Fatal("preexisting closure drift was accepted")
	}
}
