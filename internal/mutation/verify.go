package mutation

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var artifactPaths = []string{
	"mutation/plan.json",
	"mutation/denominator.json",
	"evidence/mutation/java.json",
	"evidence/mutation/rust.json",
	"evidence/protected/receipt.json",
}

var schemaPaths = []string{
	"schemas/us022-mutation-plan-1.0.0.schema.json",
	"schemas/us022-mutation-denominator-1.0.0.schema.json",
	"schemas/us022-mutation-java-1.0.0.schema.json",
	"schemas/us022-mutation-rust-1.0.0.schema.json",
	"schemas/us022-protected-receipt-1.0.0.schema.json",
}

var exactInputs = []string{
	"corpora/hidden/manifest.json",
	"corpora/sealed/manifest.json",
	"evidence/corpus-calibration.json",
	"evidence/fuzz/manifest.json",
	"evidence/intake/surface-inventory.json",
	"evidence/java/test-inventory.json",
	"evidence/java/test-manifest.json",
	"evidence/property/manifest.json",
	"evidence/us020-current-head-qualification.json",
}

var publicID = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*$`)
var testIDGrammar = regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`)
var sha256Grammar = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func validDigest(value string) bool { return sha256Grammar.MatchString(value) }

func allowedBehavior(value string) bool {
	return value == "close-terminal" || value == "fragment-sequencing" || value == "frame-admission" || value == "strict-text"
}

func verifyCommandTemplate(mutant Mutant) error {
	if mutant.Runtime == "java" {
		build := []string{"{make}", "build", "JAVA_WEBSOCKET_JAR={runtime_jar}", "RUNTIME_SUPPORT_CP={support_jar}", "BUILD_DIR=build", "JAVAC={javac}", "JAVA={java}", "JAR={jar}"}
		test := append([]string(nil), build...)
		test[1] = "test"
		if !equalStrings(mutant.BuildArgv, build) || !equalStrings(mutant.TestArgv, test) {
			return errors.New("Java command must use the closed placeholder vocabulary")
		}
		return nil
	}
	targets := map[string]string{
		"close-payload-limit-disabled":      "close_eof",
		"control-length-admission-disabled": "frame_codec",
		"continuation-admission-relabeled":  "fragmentation",
		"unexpected-continuation-accepted":  "messages",
	}
	target, ok := targets[mutant.MutantID]
	if !ok {
		return errors.New("unknown Rust planted control")
	}
	build := []string{"{cargo}", "test", "--offline", "--locked", "-p", "websocket-core", "--no-run"}
	test := []string{"{cargo}", "test", "--offline", "--locked", "-p", "websocket-core", "--test", target}
	if !equalStrings(mutant.BuildArgv, build) || !equalStrings(mutant.TestArgv, test) {
		return errors.New("Rust command must use the closed placeholder vocabulary")
	}
	return nil
}

func receiptCommandMatches(mutant Mutant, argv []string, build bool) bool {
	if mutant.Runtime == "rust" {
		if len(argv) < 1 || !pinnedCargoPath(argv[0]) {
			return false
		}
		want := append([]string(nil), mutant.BuildArgv...)
		if !build {
			want = append([]string(nil), mutant.TestArgv...)
		}
		want[0] = argv[0]
		return equalStrings(argv, want)
	}
	if len(argv) != 8 || argv[0] != "/usr/bin/make" {
		return false
	}
	verb := "test"
	if build {
		verb = "build"
	}
	if argv[1] != verb || argv[2] != "JAVA_WEBSOCKET_JAR=../deps/Java-WebSocket-1.6.0.jar" || argv[3] != "RUNTIME_SUPPORT_CP=../deps/slf4j-api-2.0.13.jar" || argv[4] != "BUILD_DIR=build" {
		return false
	}
	javac := strings.TrimPrefix(argv[5], "JAVAC=")
	java := strings.TrimPrefix(argv[6], "JAVA=")
	jar := strings.TrimPrefix(argv[7], "JAR=")
	if javac == argv[5] || java == argv[6] || jar == argv[7] || filepath.Base(javac) != "javac" || filepath.Base(java) != "java" || filepath.Base(jar) != "jar" {
		return false
	}
	home := filepath.Dir(filepath.Dir(java))
	return filepath.IsAbs(home) && filepath.Clean(home) == home && javac == filepath.Join(home, "bin", "javac") && jar == filepath.Join(home, "bin", "jar")
}

func pinnedCargoPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && filepath.Base(path) == "cargo" && strings.Contains(filepath.ToSlash(path), "/toolchains/1.95.0-") && strings.HasSuffix(filepath.ToSlash(path), "/bin/cargo")
}

func baselineCommand(runtime string, argv []string) bool {
	if runtime == "rust" {
		return len(argv) == 7 && pinnedCargoPath(argv[0]) && equalStrings(argv[1:], []string{"test", "--offline", "--locked", "-p", "websocket-core", "--all-targets"})
	}
	return receiptCommandMatches(Mutant{Runtime: "java"}, argv, false)
}

func verifyProcessReceipt(receipt ProcessReceipt, timeout uint64, success bool) error {
	if receipt.WorkingDirectory != "PRIVATE_SCRATCH" || receipt.TimeoutMS != timeout || len(receipt.Argv) == 0 || receipt.DurationMS > receipt.TimeoutMS || receipt.StdoutBytes > outputLimit || receipt.StderrBytes > outputLimit || !validDigest(receipt.StdoutSHA256) || !validDigest(receipt.StderrSHA256) {
		return errors.New("invalid process receipt fields")
	}
	if receipt.TerminationReason != "EXITED" || (success && receipt.ExitCode != 0) || (!success && receipt.ExitCode <= 0) {
		return errors.New("invalid process result")
	}
	return nil
}

// Verify validates all committed public US-022 artifacts without executing a
// command or consulting protected storage.
func Verify(repositoryRoot string) error {
	root, err := canonicalRoot(repositoryRoot)
	if err != nil {
		return err
	}
	if err := verifySchemas(root); err != nil {
		return err
	}
	planRaw, err := readArtifact(root, artifactPaths[0])
	if err != nil {
		return err
	}
	if err := exactObjectKeys(planRaw, []string{"$schema", "schema_version", "story_id", "status", "assurance", "independent_review_claimed", "signing", "production", "publication", "repository_anchor", "inputs", "external_engines", "mutants", "minimum_per_runtime", "ideal_per_runtime", "inventory_gap", "nonclaims"}); err != nil {
		return finding("INVALID_PLAN", artifactPaths[0], err)
	}
	if err := verifyPlanJSONShape(planRaw); err != nil {
		return finding("INVALID_PLAN", artifactPaths[0], err)
	}
	if err := verifyCurrentGitFile(root, artifactPaths[0], planRaw); err != nil {
		return finding("PLAN_GIT_DRIFT", artifactPaths[0], err)
	}
	var plan Plan
	if err := decodeStrict(planRaw, &plan); err != nil {
		return finding("INVALID_PLAN", artifactPaths[0], err)
	}
	if err := verifyPlan(root, &plan); err != nil {
		return err
	}

	javaRaw, java, err := loadRuntime(root, artifactPaths[2])
	if err != nil {
		return err
	}
	rustRaw, rust, err := loadRuntime(root, artifactPaths[3])
	if err != nil {
		return err
	}
	planDigest := digest(planRaw)
	if err := verifyRuntimeEvidence(root, plan, planDigest, java, "java"); err != nil {
		return err
	}
	if err := verifyRuntimeEvidence(root, plan, planDigest, rust, "rust"); err != nil {
		return err
	}

	denominatorRaw, err := readArtifact(root, artifactPaths[1])
	if err != nil {
		return err
	}
	if err := exactObjectKeys(denominatorRaw, []string{"$schema", "schema_version", "story_id", "status", "assurance", "independent_review_claimed", "signing", "production", "publication", "plan_sha256", "rows", "counts", "full", "excluded", "eligible", "missed", "score_basis_points"}); err != nil {
		return finding("INVALID_DENOMINATOR", artifactPaths[1], err)
	}
	if err := verifyDenominatorJSONShape(denominatorRaw); err != nil {
		return finding("INVALID_DENOMINATOR", artifactPaths[1], err)
	}
	var denominator Denominator
	if err := decodeStrict(denominatorRaw, &denominator); err != nil {
		return finding("INVALID_DENOMINATOR", artifactPaths[1], err)
	}
	if err := verifyDenominator(plan, planDigest, java, rust, denominator); err != nil {
		return err
	}

	receiptRaw, err := readArtifact(root, artifactPaths[4])
	if err != nil {
		return err
	}
	if err := exactObjectKeys(receiptRaw, []string{"$schema", "schema_version", "story_id", "status", "assurance", "independent_review_claimed", "signing", "production", "publication", "policy_sha256", "evaluator_sha256", "tiers", "subjects", "isolation", "budgets", "leaks", "calibration_sha256", "projection_sha256"}); err != nil {
		return finding("INVALID_PROTECTED_RECEIPT", artifactPaths[4], err)
	}
	if err := verifyProtectedJSONShape(receiptRaw); err != nil {
		return finding("INVALID_PROTECTED_RECEIPT", artifactPaths[4], err)
	}
	var receipt ProtectedReceipt
	if err := decodeStrict(receiptRaw, &receipt); err != nil {
		return finding("INVALID_PROTECTED_RECEIPT", artifactPaths[4], err)
	}
	if err := verifyProtected(root, receipt); err != nil {
		return err
	}
	for index, raw := range [][]byte{planRaw, denominatorRaw, javaRaw, rustRaw, receiptRaw} {
		if err := rejectProtectedMaterial(raw); err != nil {
			return finding("PROTECTED_DATA_LEAK", artifactPaths[index], err)
		}
	}
	return nil
}

func finding(code, path string, cause any) error {
	return fmt.Errorf("%s at %s: %v", code, path, cause)
}

func readArtifact(root, relative string) ([]byte, error) {
	path, err := repositoryPath(root, relative, false)
	if err != nil {
		return nil, finding("UNSAFE_PATH", relative, err)
	}
	return readBounded(path)
}

func commonClaims(story, status, assurance string, independent, signing, production, publication bool) error {
	if story != "US-022" || status != PassOwner || assurance != AssuranceOwner {
		return errors.New("story/status/assurance overclaim")
	}
	if independent || signing || production || publication {
		return errors.New("independence/signing/production/publication overclaim")
	}
	return nil
}

func verifyPlan(root string, plan *Plan) error {
	if plan.Schema != "../schemas/us022-mutation-plan-1.0.0.schema.json" || plan.SchemaVersion != "1.0.0" {
		return finding("INVALID_PLAN", "schema", "unexpected schema identity")
	}
	if err := commonClaims(plan.StoryID, plan.Status, plan.Assurance, plan.IndependentReviewClaimed, plan.Signing, plan.Production, plan.Publication); err != nil {
		return finding("PLAN_OVERCLAIM", "claims", err)
	}
	if plan.RepositoryAnchor.Commit == "" || plan.RepositoryAnchor.Tree == "" || plan.RepositoryAnchor.Blob != "" {
		return finding("INVALID_PLAN", "repository_anchor", "commit and tree are required; blob is forbidden")
	}
	if err := verifyCommitTree(root, plan.RepositoryAnchor); err != nil {
		return finding("GIT_ANCHOR_DRIFT", "repository_anchor", err)
	}
	wantGap := "Java rows exercise the shipped java-oracle adapter seam rather than the full upstream 62-class surface because Maven and PIT are unavailable; this is not an upstream mutation-completeness claim."
	wantNonclaims := []string{"NO_CARGO_MUTANTS", "NO_HIDDEN_OR_SEALED_CANDIDATE_EXECUTION", "NO_INDEPENDENT_REVIEW", "NO_PIT", "NO_UPSTREAM_JAVA_MUTATION_COMPLETENESS"}
	if plan.MinimumPerRuntime != 4 || plan.IdealPerRuntime != 4 || plan.InventoryGap != wantGap || !equalStrings(plan.Nonclaims, wantNonclaims) {
		return finding("INVALID_PLAN", "inventory", "minimum, ideal, explicit gap, and nonclaims are required")
	}
	if len(plan.Inputs) != len(exactInputs) {
		return finding("INPUT_INVENTORY_DRIFT", "inputs", "wrong input count")
	}
	for index, expected := range exactInputs {
		if plan.Inputs[index].Path != expected {
			return finding("INPUT_INVENTORY_DRIFT", "inputs", "inputs must be sorted and exact")
		}
		if err := verifyArtifact(root, plan.Inputs[index], plan.RepositoryAnchor); err != nil {
			return finding("INPUT_GIT_DRIFT", expected, err)
		}
	}
	if len(plan.ExternalEngines) != 2 || plan.ExternalEngines[0] != (ExternalEngine{ID: "cargo-mutants", Status: Unavailable, ResultCount: 0}) || plan.ExternalEngines[1] != (ExternalEngine{ID: "pit", Status: Unavailable, ResultCount: 0}) {
		return finding("UNAVAILABLE_TOOL_OVERCLAIM", "external_engines", "PIT and cargo-mutants must remain unavailable with zero results")
	}
	counts := map[string]uint64{}
	seen := map[string]bool{}
	resultDigests := map[string]bool{}
	for index := range plan.Mutants {
		mutant := &plan.Mutants[index]
		key := mutant.Runtime + "/" + mutant.MutantID
		if seen[key] {
			return finding("MUTANT_INVENTORY_DRIFT", key, "mutants must be unique")
		}
		seen[key] = true
		if mutant.Runtime != "java" && mutant.Runtime != "rust" {
			return finding("INVALID_MUTANT", key, "unknown runtime")
		}
		if mutant.Engine != "IN_TREE_PLANTED" || mutant.TimeoutMS != 120000 || !allowedBehavior(mutant.Behavior) || !publicID.MatchString(mutant.MutantID) || len(mutant.ExpectedKillingTestIDs) == 0 {
			return finding("INVALID_MUTANT", key, "incomplete planted-mutant contract")
		}
		if !safeRelative(mutant.ProductionPath) || protectedComponent(mutant.ProductionPath) {
			return finding("INVALID_MUTANT_PATH", key, mutant.ProductionPath)
		}
		if mutant.Runtime == "java" && !strings.HasPrefix(mutant.ProductionPath, "java-oracle/src/main/java/") {
			return finding("INVALID_MUTANT_PATH", key, "Java owner-relaxed surface must be java-oracle production")
		}
		if mutant.Runtime == "rust" && !strings.HasPrefix(mutant.ProductionPath, "rust/connection-core/src/") {
			return finding("INVALID_MUTANT_PATH", key, "Rust surface must be connection-core production")
		}
		if err := verifyCommandTemplate(*mutant); err != nil {
			return finding("INVALID_MUTANT_COMMAND", key, err)
		}
		for _, testID := range mutant.ExpectedKillingTestIDs {
			if !testIDGrammar.MatchString(testID) {
				return finding("INVALID_MUTANT", key, "invalid killing-test ID")
			}
		}
		if err := verifyMutant(root, plan.RepositoryAnchor, *mutant, resultDigests); err != nil {
			return finding("INVALID_MUTANT", key, err)
		}
		counts[mutant.Runtime]++
	}
	for _, runtime := range []string{"java", "rust"} {
		if counts[runtime] < plan.MinimumPerRuntime || counts[runtime] == 0 {
			return finding("MUTANT_INVENTORY_DRIFT", runtime, "runtime denominator below declared minimum")
		}
	}
	return nil
}

func verifyMutant(root string, anchor GitAnchor, mutant Mutant, resultDigests map[string]bool) error {
	raw, err := readArtifact(root, mutant.ProductionPath)
	if err != nil {
		return err
	}
	if digest(raw) != mutant.ProductionFileSHA256 {
		return errors.New("production digest drift")
	}
	blob, err := git(root, "rev-parse", anchor.Commit+":"+mutant.ProductionPath)
	if err != nil {
		return err
	}
	committed, err := gitBytes(root, "show", anchor.Commit+":"+mutant.ProductionPath)
	if err != nil || !bytes.Equal(committed, raw) {
		return errors.New("production working tree does not equal anchored Git blob")
	}
	if strings.TrimSpace(blob) == "" {
		return errors.New("missing production blob")
	}
	match, err := base64.StdEncoding.Strict().DecodeString(mutant.UniqueMatchBase64)
	if err != nil || len(match) == 0 || digest(match) != mutant.UniqueMatchSHA256 {
		return errors.New("invalid unique match")
	}
	replacement, err := base64.StdEncoding.Strict().DecodeString(mutant.ReplacementBase64)
	if err != nil || len(replacement) == 0 || digest(replacement) != mutant.ReplacementSHA256 || bytes.Equal(match, replacement) {
		return errors.New("invalid replacement")
	}
	if bytes.Count(raw, match) != 1 {
		return errors.New("match is not unique")
	}
	mutated := bytes.Replace(raw, match, replacement, 1)
	result := digest(mutated)
	if resultDigests[result] {
		return errors.New("duplicate mutated result")
	}
	resultDigests[result] = true
	return nil
}

func loadRuntime(root, relative string) ([]byte, RuntimeEvidence, error) {
	raw, err := readArtifact(root, relative)
	if err != nil {
		return nil, RuntimeEvidence{}, err
	}
	if err := exactObjectKeys(raw, []string{"$schema", "schema_version", "story_id", "runtime", "status", "assurance", "independent_review_claimed", "signing", "production", "publication", "plan_sha256", "source_closure_sha256", "test_closure_sha256", "test_manifest_sha256", "before", "after", "results", "external_engines", "no_repository_drift", "nonclaims"}); err != nil {
		return nil, RuntimeEvidence{}, finding("INVALID_RUNTIME_EVIDENCE", relative, err)
	}
	if err := verifyRuntimeJSONShape(raw); err != nil {
		return nil, RuntimeEvidence{}, finding("INVALID_RUNTIME_EVIDENCE", relative, err)
	}
	var evidence RuntimeEvidence
	if err := decodeStrict(raw, &evidence); err != nil {
		return nil, RuntimeEvidence{}, finding("INVALID_RUNTIME_EVIDENCE", relative, err)
	}
	return raw, evidence, nil
}

func rawObject(raw []byte, keys []string) (map[string]json.RawMessage, error) {
	if err := exactObjectKeys(raw, keys); err != nil {
		return nil, err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, err
	}
	return object, nil
}

func rawObjects(raw json.RawMessage, keys []string) ([]map[string]json.RawMessage, error) {
	var rows []json.RawMessage
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, errors.New("required array has wrong type")
	}
	result := make([]map[string]json.RawMessage, 0, len(rows))
	for _, row := range rows {
		object, err := rawObject(row, keys)
		if err != nil {
			return nil, err
		}
		result = append(result, object)
	}
	return result, nil
}

func verifyPlanJSONShape(raw []byte) error {
	top, err := rawObject(raw, []string{"$schema", "schema_version", "story_id", "status", "assurance", "independent_review_claimed", "signing", "production", "publication", "repository_anchor", "inputs", "external_engines", "mutants", "minimum_per_runtime", "ideal_per_runtime", "inventory_gap", "nonclaims"})
	if err != nil {
		return err
	}
	if _, err := rawObject(top["repository_anchor"], []string{"commit", "tree"}); err != nil {
		return err
	}
	inputs, err := rawObjects(top["inputs"], []string{"path", "bytes", "sha256", "git"})
	if err != nil {
		return err
	}
	for _, input := range inputs {
		if _, err := rawObject(input["git"], []string{"commit", "tree", "blob"}); err != nil {
			return err
		}
	}
	if _, err := rawObjects(top["external_engines"], []string{"id", "status", "result_count"}); err != nil {
		return err
	}
	_, err = rawObjects(top["mutants"], []string{"runtime", "mutant_id", "behavior", "engine", "production_path", "production_file_sha256", "unique_match_base64", "unique_match_sha256", "replacement_base64", "replacement_sha256", "build_argv", "test_argv", "timeout_ms", "expected_killing_test_ids"})
	return err
}

func verifyDenominatorJSONShape(raw []byte) error {
	top, err := rawObject(raw, []string{"$schema", "schema_version", "story_id", "status", "assurance", "independent_review_claimed", "signing", "production", "publication", "plan_sha256", "rows", "counts", "full", "excluded", "eligible", "missed", "score_basis_points"})
	if err != nil {
		return err
	}
	if _, err := rawObjects(top["rows"], []string{"runtime", "mutant_id", "disposition"}); err != nil {
		return err
	}
	_, err = rawObject(top["counts"], dispositions)
	return err
}

func verifyRuntimeJSONShape(raw []byte) error {
	top, err := rawObject(raw, []string{"$schema", "schema_version", "story_id", "runtime", "status", "assurance", "independent_review_claimed", "signing", "production", "publication", "plan_sha256", "source_closure_sha256", "test_closure_sha256", "test_manifest_sha256", "before", "after", "results", "external_engines", "no_repository_drift", "nonclaims"})
	if err != nil {
		return err
	}
	processKeys := []string{"argv", "working_directory_class", "timeout_ms", "duration_ms", "exit_code", "termination_reason", "stdout_bytes", "stdout_sha256", "stderr_bytes", "stderr_sha256"}
	for _, phase := range []string{"before", "after"} {
		rows, err := rawObjects(top[phase], []string{"repeat", "phase", "process", "tests_passed", "tests_failed", "tests_skipped", "tests_filtered"})
		if err != nil {
			return err
		}
		for _, row := range rows {
			if _, err := rawObject(row["process"], processKeys); err != nil {
				return err
			}
		}
	}
	results, err := rawObjects(top["results"], []string{"mutant_id", "engine", "disposition", "result_file_sha256", "observations"})
	if err != nil {
		return err
	}
	for _, result := range results {
		observations, err := rawObjects(result["observations"], []string{"repeat", "build", "test", "failed_test_ids", "killed"})
		if err != nil {
			return err
		}
		for _, observation := range observations {
			for _, name := range []string{"build", "test"} {
				if _, err := rawObject(observation[name], processKeys); err != nil {
					return err
				}
			}
		}
	}
	_, err = rawObjects(top["external_engines"], []string{"id", "status", "result_count"})
	return err
}

func verifyProtectedJSONShape(raw []byte) error {
	top, err := rawObject(raw, []string{"$schema", "schema_version", "story_id", "status", "assurance", "independent_review_claimed", "signing", "production", "publication", "policy_sha256", "evaluator_sha256", "tiers", "subjects", "isolation", "budgets", "leaks", "calibration_sha256", "projection_sha256"})
	if err != nil {
		return err
	}
	if _, err := rawObjects(top["tiers"], []string{"tier", "manifest_sha256", "corpus_id", "expected", "selected", "executed", "passed", "failed", "skipped", "filtered", "timed_out", "commitment_root", "transcript_sha256", "report_sha256", "custodian_policy_sha256"}); err != nil {
		return err
	}
	if _, err := rawObjects(top["subjects"], []string{"id", "status"}); err != nil {
		return err
	}
	if _, err := rawObject(top["isolation"], []string{"identity", "workspace", "filesystem", "cache", "network", "protected_store", "signing_key_separation"}); err != nil {
		return err
	}
	if _, err := rawObject(top["budgets"], []string{"query_spent", "diagnostic_spent"}); err != nil {
		return err
	}
	_, err = rawObject(top["leaks"], []string{"case_ids", "case_bodies", "expected_outputs", "actual_outputs", "diagnostics", "salts", "keys", "tokens", "credentials", "protected_paths", "timestamps", "prose"})
	return err
}

func verifyRuntimeEvidence(root string, plan Plan, planDigest string, evidence RuntimeEvidence, runtime string) error {
	expectedSchema := "../../schemas/us022-mutation-" + runtime + "-1.0.0.schema.json"
	if evidence.Schema != expectedSchema || evidence.SchemaVersion != "1.0.0" || evidence.Runtime != runtime || evidence.PlanSHA256 != planDigest {
		return finding("RUNTIME_EVIDENCE_DRIFT", runtime, "schema, runtime, or plan digest mismatch")
	}
	if err := commonClaims(evidence.StoryID, evidence.Status, evidence.Assurance, evidence.IndependentReviewClaimed, evidence.Signing, evidence.Production, evidence.Publication); err != nil {
		return finding("RUNTIME_OVERCLAIM", runtime, err)
	}
	wantNonclaims := []string{"NO_PROTECTED_EXECUTION", "NO_INDEPENDENT_REVIEW", "FINITE_PLANTED_INVENTORY_ONLY"}
	if !evidence.NoRepositoryDrift || !equalStrings(evidence.Nonclaims, wantNonclaims) || len(evidence.Before) != 2 || len(evidence.After) != 2 || !validDigest(evidence.PlanSHA256) || !validDigest(evidence.SourceClosureSHA256) || !validDigest(evidence.TestClosureSHA256) || !validDigest(evidence.TestManifestSHA256) {
		return finding("BASELINE_RECONCILIATION_FAILED", runtime, "two before/after baselines and explicit nonclaims required")
	}
	for _, phase := range []struct {
		name string
		rows []Baseline
	}{{"before", evidence.Before}, {"after", evidence.After}} {
		for index, row := range phase.rows {
			if row.Repeat != uint64(index+1) || row.Phase != phase.name || row.Process.ExitCode != 0 || row.Process.TerminationReason != "EXITED" || row.TestsFailed != 0 || row.TestsSkipped != 0 || row.TestsFiltered != 0 || row.TestsPassed == 0 {
				return finding("BASELINE_RECONCILIATION_FAILED", runtime, phase.name)
			}
			if err := verifyProcessReceipt(row.Process, 300000, true); err != nil || !baselineCommand(runtime, row.Process.Argv) {
				return finding("BASELINE_RECONCILIATION_FAILED", runtime, err)
			}
		}
	}
	if runtime == "java" {
		if len(evidence.ExternalEngines) != 2 || evidence.ExternalEngines[0].ID != "maven" || evidence.ExternalEngines[0].Status != Unavailable || evidence.ExternalEngines[0].ResultCount != 0 || evidence.ExternalEngines[1] != (ExternalEngine{ID: "pit", Status: Unavailable, ResultCount: 0}) {
			return finding("UNAVAILABLE_TOOL_OVERCLAIM", runtime, "Maven/PIT nonclaim mismatch")
		}
	} else if len(evidence.ExternalEngines) != 1 || evidence.ExternalEngines[0] != (ExternalEngine{ID: "cargo-mutants", Status: Unavailable, ResultCount: 0}) {
		return finding("UNAVAILABLE_TOOL_OVERCLAIM", runtime, "cargo-mutants nonclaim mismatch")
	}
	source, tests, err := closureDigests(root, runtime, plan.RepositoryAnchor)
	if err != nil || source != evidence.SourceClosureSHA256 || tests != evidence.TestClosureSHA256 {
		return finding("SOURCE_TEST_CLOSURE_DRIFT", runtime, err)
	}
	manifestRaw, err := readArtifact(root, "evidence/java/test-manifest.json")
	if err != nil || digest(manifestRaw) != evidence.TestManifestSHA256 {
		return finding("TEST_MANIFEST_DRIFT", runtime, err)
	}
	expected := map[string]Mutant{}
	var expectedOrder []string
	for _, mutant := range plan.Mutants {
		if mutant.Runtime == runtime {
			expected[mutant.MutantID] = mutant
			expectedOrder = append(expectedOrder, mutant.MutantID)
		}
	}
	if len(evidence.Results) != len(expected) {
		return finding("MUTATION_RESULT_DRIFT", runtime, "wrong result count")
	}
	for index, result := range evidence.Results {
		mutant, ok := expected[result.MutantID]
		if !ok || result.MutantID != expectedOrder[index] || result.Engine != "IN_TREE_PLANTED" || result.Disposition != "KILLED" || len(result.Observations) != 2 {
			return finding("MUTATION_RESULT_DRIFT", runtime, result.MutantID)
		}
		raw, err := readArtifact(root, mutant.ProductionPath)
		if err != nil {
			return err
		}
		match, _ := base64.StdEncoding.Strict().DecodeString(mutant.UniqueMatchBase64)
		replacement, _ := base64.StdEncoding.Strict().DecodeString(mutant.ReplacementBase64)
		if result.ResultFileSHA256 != digest(bytes.Replace(raw, match, replacement, 1)) {
			return finding("CONTROL_TAMPERING", result.MutantID, "mutated result digest mismatch")
		}
		for index, observation := range result.Observations {
			if observation.Repeat != uint64(index+1) || observation.Build.ExitCode != 0 || observation.Build.TerminationReason != "EXITED" || observation.Test.ExitCode == 0 || observation.Test.TerminationReason != "EXITED" || !observation.Killed {
				return finding("FALSE_KILL", result.MutantID, "compile failures, single attempts, and passing tests are not kills")
			}
			if err := verifyProcessReceipt(observation.Build, mutant.TimeoutMS, true); err != nil {
				return finding("INVALID_PROCESS_RECEIPT", result.MutantID, err)
			}
			if err := verifyProcessReceipt(observation.Test, mutant.TimeoutMS, false); err != nil {
				return finding("INVALID_PROCESS_RECEIPT", result.MutantID, err)
			}
			if !receiptCommandMatches(mutant, observation.Build.Argv, true) || !receiptCommandMatches(mutant, observation.Test.Argv, false) {
				return finding("COMMAND_DRIFT", result.MutantID, "argv mismatch")
			}
			if !equalStrings(observation.FailedTestIDs, mutant.ExpectedKillingTestIDs) {
				return finding("FALSE_KILL", result.MutantID, "failed-test IDs do not reconcile")
			}
		}
	}
	return nil
}

func verifyDenominator(plan Plan, planDigest string, java, rust RuntimeEvidence, denominator Denominator) error {
	if denominator.Schema != "../schemas/us022-mutation-denominator-1.0.0.schema.json" || denominator.SchemaVersion != "1.0.0" || denominator.PlanSHA256 != planDigest {
		return finding("DENOMINATOR_DRIFT", "identity", "schema or plan mismatch")
	}
	if err := commonClaims(denominator.StoryID, denominator.Status, denominator.Assurance, denominator.IndependentReviewClaimed, denominator.Signing, denominator.Production, denominator.Publication); err != nil {
		return finding("DENOMINATOR_OVERCLAIM", "claims", err)
	}
	results := map[string]string{}
	for _, evidence := range []RuntimeEvidence{java, rust} {
		for _, result := range evidence.Results {
			results[evidence.Runtime+"/"+result.MutantID] = result.Disposition
		}
	}
	if len(denominator.Rows) != len(plan.Mutants) || len(results) != len(plan.Mutants) {
		return finding("DENOMINATOR_DRIFT", "rows", "not one row per plan mutant")
	}
	counts := map[string]uint64{}
	for index, mutant := range plan.Mutants {
		row := denominator.Rows[index]
		if row.Runtime != mutant.Runtime || row.MutantID != mutant.MutantID || row.Disposition != results[row.Runtime+"/"+row.MutantID] {
			return finding("DENOMINATOR_DRIFT", "rows", "extra, omitted, reordered, or relabeled row")
		}
		counts[row.Disposition]++
	}
	exact := []uint64{denominator.Counts.Killed, denominator.Counts.Survived, denominator.Counts.NotExecuted, denominator.Counts.Uncovered, denominator.Counts.Timeout, denominator.Counts.ToolFailure, denominator.Counts.Flaky, denominator.Counts.Equivalent, denominator.Counts.TechnicallyUnviable}
	for index, disposition := range dispositions {
		if exact[index] != counts[disposition] {
			return finding("DENOMINATOR_MATH", "counts", disposition)
		}
	}
	full := uint64(len(denominator.Rows))
	excluded := counts["EQUIVALENT"] + counts["TECHNICALLY_UNVIABLE"]
	eligible := full - excluded
	missed := counts["SURVIVED"] + counts["NOT_EXECUTED"] + counts["UNCOVERED"] + counts["TIMEOUT"] + counts["TOOL_FAILURE"] + counts["FLAKY"]
	if eligible == 0 || denominator.Full != full || denominator.Excluded != excluded || denominator.Eligible != eligible || denominator.Missed != missed || denominator.ScoreBasisPoints != 10000*counts["KILLED"]/eligible || counts["KILLED"] != eligible || missed != 0 || excluded != 0 {
		return finding("DENOMINATOR_MATH", "summary", "owner-relaxed gate not met")
	}
	return nil
}

type publicManifest struct {
	CorpusID string `json:"corpus_id"`
	Tier     string `json:"tier"`
	Counts   struct {
		Expected, Selected, Executed, Passed, Failed, Skipped, Filtered, TimedOut uint64 `json:"-"`
	} `json:"-"`
	Commitments struct {
		ScenarioCommitmentRoot string `json:"scenario_commitment_root"`
	} `json:"commitments"`
	Custodian struct {
		PolicyDigest string `json:"policy_digest"`
	} `json:"custodian"`
	ExecutionEvidence struct {
		TranscriptSHA256 string `json:"transcript_sha256"`
		ReportSHA256     string `json:"report_sha256"`
	} `json:"execution_evidence"`
}

func loadPublicProjection(root, relative string) (publicManifest, []byte, error) {
	raw, err := readArtifact(root, relative)
	if err != nil {
		return publicManifest{}, nil, err
	}
	if err := rejectDuplicateKeys(raw); err != nil {
		return publicManifest{}, nil, err
	}
	var envelope struct {
		CorpusID string `json:"corpus_id"`
		Tier     string `json:"tier"`
		Counts   struct {
			Expected uint64 `json:"expected"`
			Selected uint64 `json:"selected"`
			Executed uint64 `json:"executed"`
			Passed   uint64 `json:"passed"`
			Failed   uint64 `json:"failed"`
			Skipped  uint64 `json:"skipped"`
			Filtered uint64 `json:"filtered"`
			TimedOut uint64 `json:"timed_out"`
		} `json:"counts"`
		Commitments struct {
			ScenarioCommitmentRoot string `json:"scenario_commitment_root"`
		} `json:"commitments"`
		Custodian struct {
			PolicyDigest string `json:"policy_digest"`
		} `json:"custodian"`
		ExecutionEvidence struct {
			TranscriptSHA256 string `json:"transcript_sha256"`
			ReportSHA256     string `json:"report_sha256"`
		} `json:"execution_evidence"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return publicManifest{}, nil, err
	}
	result := publicManifest{CorpusID: envelope.CorpusID, Tier: envelope.Tier, Commitments: envelope.Commitments, Custodian: envelope.Custodian, ExecutionEvidence: envelope.ExecutionEvidence}
	result.Counts.Expected, result.Counts.Selected, result.Counts.Executed, result.Counts.Passed = envelope.Counts.Expected, envelope.Counts.Selected, envelope.Counts.Executed, envelope.Counts.Passed
	result.Counts.Failed, result.Counts.Skipped, result.Counts.Filtered, result.Counts.TimedOut = envelope.Counts.Failed, envelope.Counts.Skipped, envelope.Counts.Filtered, envelope.Counts.TimedOut
	return result, raw, nil
}

func verifyProtected(root string, receipt ProtectedReceipt) error {
	if receipt.Schema != "../../schemas/us022-protected-receipt-1.0.0.schema.json" || receipt.SchemaVersion != "1.0.0" {
		return finding("PROTECTED_RECEIPT_DRIFT", "schema", "unexpected schema")
	}
	if err := commonClaims(receipt.StoryID, receipt.Status, receipt.Assurance, receipt.IndependentReviewClaimed, receipt.Signing, receipt.Production, receipt.Publication); err != nil {
		return finding("PROTECTED_OVERCLAIM", "claims", err)
	}
	if len(receipt.Tiers) != 2 || receipt.Tiers[0].Tier != "hidden" || receipt.Tiers[1].Tier != "sealed" {
		return finding("PROTECTED_RECEIPT_DRIFT", "tiers", "exact hidden/sealed rows required")
	}
	projectionParts := make([]string, 0, 2)
	for index, relative := range []string{"corpora/hidden/manifest.json", "corpora/sealed/manifest.json"} {
		manifest, raw, err := loadPublicProjection(root, relative)
		if err != nil {
			return finding("PROTECTED_RECEIPT_DRIFT", relative, err)
		}
		tier := receipt.Tiers[index]
		if tier.ManifestSHA256 != digest(raw) || tier.CorpusID != manifest.CorpusID || tier.Tier != manifest.Tier || tier.Expected != manifest.Counts.Expected || tier.Selected != manifest.Counts.Selected || tier.Executed != manifest.Counts.Executed || tier.Passed != manifest.Counts.Passed || tier.Failed != manifest.Counts.Failed || tier.Skipped != manifest.Counts.Skipped || tier.Filtered != manifest.Counts.Filtered || tier.TimedOut != manifest.Counts.TimedOut || tier.CommitmentRoot != manifest.Commitments.ScenarioCommitmentRoot || tier.TranscriptSHA256 != manifest.ExecutionEvidence.TranscriptSHA256 || tier.ReportSHA256 != manifest.ExecutionEvidence.ReportSHA256 || tier.CustodianPolicySHA256 != manifest.Custodian.PolicyDigest {
			return finding("PROTECTED_RECEIPT_DRIFT", relative, "public projection mismatch")
		}
		projectionParts = append(projectionParts, digest(raw))
	}
	calibration, err := readArtifact(root, "evidence/corpus-calibration.json")
	if err != nil || receipt.CalibrationSHA256 != digest(calibration) || receipt.ProjectionSHA256 != digest([]byte(strings.Join(projectionParts, "\n")+"\n")) {
		return finding("PROTECTED_RECEIPT_DRIFT", "projection", err)
	}
	if receipt.PolicySHA256 != receipt.Tiers[0].CustodianPolicySHA256 || receipt.PolicySHA256 != receipt.Tiers[1].CustodianPolicySHA256 || receipt.EvaluatorSHA256 != receipt.Tiers[0].ReportSHA256 || receipt.EvaluatorSHA256 != receipt.Tiers[1].ReportSHA256 {
		return finding("PROTECTED_RECEIPT_DRIFT", "policy", "policy/evaluator identity mismatch")
	}
	expectedSubjects := []Subject{{"pinned_java", "PASS_RETAINED_RECONCILED"}, {"rust_candidate", "NOT_EXECUTED_NO_PUBLIC_RECEIPT"}, {"empty_rust", "NOT_EXECUTED_NO_PUBLIC_RECEIPT"}, {"planted_java", "NOT_EXECUTED_NO_PUBLIC_RECEIPT"}, {"planted_rust", "NOT_EXECUTED_NO_PUBLIC_RECEIPT"}}
	if len(receipt.Subjects) != len(expectedSubjects) {
		return finding("PROTECTED_OVERCLAIM", "subjects", "wrong subject count")
	}
	for index := range expectedSubjects {
		if receipt.Subjects[index] != expectedSubjects[index] {
			return finding("PROTECTED_OVERCLAIM", "subjects", "current candidate/control claim is forbidden")
		}
	}
	expectedIsolation := Isolation{"DISTINCT_RETAINED", "ISOLATED_RETAINED", "ISOLATED_RETAINED", "ISOLATED_RETAINED", "NOT_CLAIMED", "CUSTODIAN_RETAINED", "UNAVAILABLE_NOT_USED"}
	if receipt.Isolation != expectedIsolation || receipt.Budgets.QuerySpent != 8 || receipt.Budgets.DiagnosticSpent != 0 || receipt.Leaks != (LeakCounts{}) {
		return finding("PROTECTED_OVERCLAIM", "controls", "isolation, budget, or leak counters mismatch")
	}
	return nil
}

func verifySchemas(root string) error {
	expected := map[string]string{
		"schemas/us022-mutation-denominator-1.0.0.schema.json": "sha256:d053519571df560c9cd874f1491533b309e72ceccf74b401c17e9c392bf26d8d",
		"schemas/us022-mutation-java-1.0.0.schema.json":        "sha256:e44fd3480daaea6fd1260038dab0ce240967abadce961dac50fd3ba252143ddc",
		"schemas/us022-mutation-plan-1.0.0.schema.json":        "sha256:bab07b06e098337ef8894fdc13c38fe47127deb97fa2b76759466c16964ef971",
		"schemas/us022-mutation-rust-1.0.0.schema.json":        "sha256:97b8743df0faa67e71b7e7362b840854f701f718e77a1c69a20083bdd0423e7c",
		"schemas/us022-protected-receipt-1.0.0.schema.json":    "sha256:5981f8f1e41ad4de2606d9933a5d0e0dee84939af99978d5fb5b9f94fdcb9805",
	}
	for _, relative := range schemaPaths {
		raw, err := readArtifact(root, relative)
		if err != nil {
			return finding("SCHEMA_DRIFT", relative, err)
		}
		if err := rejectDuplicateKeys(raw); err != nil {
			return finding("SCHEMA_DRIFT", relative, err)
		}
		if digest(raw) != expected[relative] {
			return finding("SCHEMA_DRIFT", relative, "digest differs from the closed schema set")
		}
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			return finding("SCHEMA_DRIFT", relative, err)
		}
		object, ok := value.(map[string]any)
		if !ok || object["$id"] != filepath.Base(relative) {
			return finding("SCHEMA_DRIFT", relative, "schema identity mismatch")
		}
		if err := verifyLocalSchemaReferences(value); err != nil {
			return finding("UNSAFE_SCHEMA_REFERENCE", relative, err)
		}
	}
	return nil
}

func verifyLocalSchemaReferences(value any) error {
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			if key == "$ref" {
				ref, ok := nested.(string)
				if !ok || !strings.HasPrefix(ref, "#/") || strings.Contains(ref, "..") {
					return errors.New("only local fragment references are permitted")
				}
			}
			if err := verifyLocalSchemaReferences(nested); err != nil {
				return err
			}
		}
	case []any:
		for _, nested := range typed {
			if err := verifyLocalSchemaReferences(nested); err != nil {
				return err
			}
		}
	}
	return nil
}

func verifyArtifact(root string, artifact Artifact, repository GitAnchor) error {
	if !safeRelative(artifact.Path) || (protectedComponent(artifact.Path) && artifact.Path != "corpora/hidden/manifest.json" && artifact.Path != "corpora/sealed/manifest.json") {
		return errors.New("unsafe artifact path")
	}
	if artifact.Git.Commit != repository.Commit || artifact.Git.Tree != repository.Tree || artifact.Git.Blob == "" {
		return errors.New("artifact Git anchor mismatch")
	}
	raw, err := readArtifact(root, artifact.Path)
	if err != nil {
		return err
	}
	if uint64(len(raw)) != artifact.Bytes || digest(raw) != artifact.SHA256 {
		return errors.New("artifact byte identity mismatch")
	}
	blob, err := git(root, "rev-parse", repository.Commit+":"+artifact.Path)
	if err != nil || strings.TrimSpace(blob) != artifact.Git.Blob {
		return errors.New("artifact blob mismatch")
	}
	committed, err := gitBytes(root, "show", repository.Commit+":"+artifact.Path)
	if err != nil || !bytes.Equal(committed, raw) {
		return errors.New("artifact differs from immutable Git object")
	}
	return nil
}

func verifyCommitTree(root string, anchor GitAnchor) error {
	tree, err := git(root, "rev-parse", anchor.Commit+"^{tree}")
	if err != nil {
		return err
	}
	if strings.TrimSpace(tree) != anchor.Tree {
		return errors.New("tree mismatch")
	}
	_, err = git(root, "cat-file", "-e", anchor.Commit+"^{commit}")
	return err
}

func git(root string, arguments ...string) (string, error) {
	command := exec.Command("git", append([]string{"-C", root}, arguments...)...)
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	output, err := command.Output()
	return string(output), err
}

func gitBytes(root string, arguments ...string) ([]byte, error) {
	command := exec.Command("git", append([]string{"-C", root}, arguments...)...)
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	return command.Output()
}

func closureDigests(root, runtime string, anchor GitAnchor) (string, string, error) {
	var sourcePrefixes, testPrefixes []string
	if runtime == "java" {
		sourcePrefixes = []string{"java-oracle/src/main/"}
		testPrefixes = []string{"java-oracle/src/test/", "java-oracle/Makefile", "java-oracle/pom.xml"}
	} else {
		sourcePrefixes = []string{"rust/connection-core/src/", "rust/websocket-driver/src/", "rust/websocket-testee/src/"}
		testPrefixes = []string{"rust/connection-core/tests/", "rust/websocket-driver/tests/", "rust/websocket-testee/tests/", "rust/Cargo.toml", "rust/Cargo.lock", "rust/rust-toolchain.toml"}
	}
	tracked, err := git(root, "ls-files")
	if err != nil {
		return "", "", err
	}
	collect := func(prefixes []string) (string, error) {
		var entries []string
		for _, path := range lines([]byte(tracked)) {
			for _, prefix := range prefixes {
				if path == prefix || strings.HasPrefix(path, prefix) {
					raw, err := readArtifact(root, path)
					if err != nil {
						return "", err
					}
					if err := verifyBytesAgainstGit(root, path, anchor.Commit, raw); err != nil {
						return "", err
					}
					entries = append(entries, path+"\x00"+digest(raw))
					break
				}
			}
		}
		sort.Strings(entries)
		return digest([]byte(strings.Join(entries, "\n") + "\n")), nil
	}
	source, err := collect(sourcePrefixes)
	if err != nil {
		return "", "", err
	}
	tests, err := collect(testPrefixes)
	return source, tests, err
}

func rejectProtectedMaterial(raw []byte) error {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	forbidden := map[string]bool{"case_body": true, "expected_output": true, "actual_output": true, "raw_diagnostic": true, "salt": true, "private_key": true, "token": true, "credential": true, "protected_path": true, "signature": true, "timestamp": true}
	var walk func(any) error
	walk = func(value any) error {
		switch typed := value.(type) {
		case map[string]any:
			for key, nested := range typed {
				if forbidden[strings.ToLower(key)] && nested != float64(0) {
					return fmt.Errorf("forbidden key %q", key)
				}
				if err := walk(nested); err != nil {
					return err
				}
			}
		case []any:
			for _, nested := range typed {
				if err := walk(nested); err != nil {
					return err
				}
			}
		case string:
			lower := strings.ToLower(typed)
			allowedManifest := typed == "corpora/hidden/manifest.json" || typed == "corpora/sealed/manifest.json"
			if (!allowedManifest && (strings.Contains(lower, "/hidden/") || strings.Contains(lower, "/sealed/"))) || strings.Contains(lower, "private_key") || strings.Contains(lower, "private key") || strings.Contains(lower, "secret=") || strings.Contains(lower, "token=") || strings.Contains(lower, "credential=") || strings.Contains(lower, "-----begin") {
				return errors.New("forbidden protected or secret-bearing string")
			}
		}
		return nil
	}
	return walk(value)
}

func verifyBytesAgainstGit(root, relative, commit string, raw []byte) error {
	committed, err := gitBytes(root, "show", commit+":"+relative)
	if err != nil {
		return err
	}
	if !bytes.Equal(committed, raw) {
		return errors.New("working tree bytes differ from immutable Git object")
	}
	return nil
}

func verifyCurrentGitFile(root, relative string, raw []byte) error {
	head, err := git(root, "rev-parse", "HEAD^{commit}")
	if err != nil {
		return err
	}
	return verifyBytesAgainstGit(root, relative, strings.TrimSpace(head), raw)
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func parsePositive(value string) (uint64, error) { return strconv.ParseUint(value, 10, 64) }
