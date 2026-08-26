package formalplan

// US-006 lane C: backend qualification + formal preflight tests.
//
// TDD-first: these tests were written before backend.go and drive the
// formal-preflight validator, the us006-* fixture catalog (digest-frozen,
// distinct trees, exercised through the REAL CLI in both formal-preflight and
// formal-replay modes with exit codes read), and the deep rule vocabulary
// (one distinct typed finding code per failure family — no catch-all code).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const us006CatalogPath = "assurance/replay/fixtures/us006-cases.json"

// --- catalog data model -----------------------------------------------------

type us006Catalog struct {
	SchemaVersion string      `json:"schema_version"`
	Story         string      `json:"story"`
	Lane          string      `json:"lane"`
	Note          string      `json:"note"`
	DigestScheme  string      `json:"digest_scheme"`
	Cases         []us006Case `json:"cases"`
}

type us006Case struct {
	ID                   string             `json:"id"`
	MutationManifestPath string             `json:"mutation_manifest_path"`
	RealizedTreeSHA256   string             `json:"realized_tree_sha256"`
	Expected             us006Expectations  `json:"expected"`
}

type us006Expectations struct {
	ExitCode                          int                    `json:"exit_code"`
	State                             string                 `json:"state"`
	Findings                          []us006FindingExpect   `json:"findings"`
	ObligationsEvaluated              int                    `json:"obligations_evaluated"`
	ObligationsPassed                 int                    `json:"obligations_passed"`
	ProductionLinkedObligationsPassed int                    `json:"production_linked_obligations_passed"`
}

type us006FindingExpect struct {
	Code        string `json:"code"`
	Disposition string `json:"disposition"`
	Count       int    `json:"count"`
}

type us006Manifest struct {
	Operations []us006Operation `json:"operations"`
}

type us006Operation struct {
	Kind    string `json:"kind"`
	Path    string `json:"path,omitempty"`
	Source  string `json:"source,omitempty"`
	Target  string `json:"target,omitempty"`
	Pointer string `json:"pointer,omitempty"`
	Value   any    `json:"value,omitempty"`
}

// --- shared helpers ---------------------------------------------------------

func us006RepoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return root
}

func us006ReadRepoFile(t *testing.T, relative string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(us006RepoRoot(t), filepath.FromSlash(relative)))
	if err != nil {
		t.Fatalf("read repo file %s: %v", relative, err)
	}
	return data
}

func us006WriteFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", path, err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func us006LoadCatalog(t *testing.T) us006Catalog {
	t.Helper()
	var catalog us006Catalog
	if err := json.Unmarshal(us006ReadRepoFile(t, us006CatalogPath), &catalog); err != nil {
		t.Fatalf("decode %s: %v", us006CatalogPath, err)
	}
	if len(catalog.Cases) == 0 {
		t.Fatalf("catalog %s has no cases", us006CatalogPath)
	}
	return catalog
}

func us006ApplyManifest(t *testing.T, root, manifestPath string, depth int) {
	t.Helper()
	if depth > 4 {
		t.Fatalf("manifest include depth exceeded at %s", manifestPath)
	}
	var manifest us006Manifest
	if err := json.Unmarshal(us006ReadRepoFile(t, manifestPath), &manifest); err != nil {
		t.Fatalf("decode manifest %s: %v", manifestPath, err)
	}
	for _, operation := range manifest.Operations {
		switch operation.Kind {
		case "include":
			us006ApplyManifest(t, root, operation.Path, depth+1)
		case "copy_file":
			data := us006ReadRepoFile(t, operation.Source)
			us006WriteFile(t, filepath.Join(root, filepath.FromSlash(operation.Target)), data)
		case "json_set":
			target := filepath.Join(root, filepath.FromSlash(operation.Target))
			raw, err := os.ReadFile(target)
			if err != nil {
				t.Fatalf("json_set read %s: %v", operation.Target, err)
			}
			var document any
			if err := json.Unmarshal(raw, &document); err != nil {
				t.Fatalf("json_set decode %s: %v", operation.Target, err)
			}
			updated, err := us006SetPointer(document, operation.Pointer, operation.Value)
			if err != nil {
				t.Fatalf("json_set %s%s: %v", operation.Target, operation.Pointer, err)
			}
			encoded, err := json.MarshalIndent(updated, "", "  ")
			if err != nil {
				t.Fatalf("json_set encode %s: %v", operation.Target, err)
			}
			us006WriteFile(t, target, append(encoded, '\n'))
		case "raw_append":
			target := filepath.Join(root, filepath.FromSlash(operation.Target))
			data, err := os.ReadFile(target)
			if err != nil {
				t.Fatalf("raw_append read %s: %v", operation.Target, err)
			}
			suffix, ok := operation.Value.(string)
			if !ok {
				t.Fatalf("raw_append %s requires a string value", operation.Target)
			}
			us006WriteFile(t, target, append(data, []byte(suffix)...))
		case "remove_file":
			target := filepath.Join(root, filepath.FromSlash(operation.Target))
			if err := os.Remove(target); err != nil {
				t.Fatalf("remove_file %s: %v", operation.Target, err)
			}
		default:
			t.Fatalf("unsupported operation kind %q in %s", operation.Kind, manifestPath)
		}
	}
}

func us006SetPointer(document any, pointer string, value any) (any, error) {
	if pointer == "" {
		return value, nil
	}
	if !strings.HasPrefix(pointer, "/") {
		return nil, fmt.Errorf("pointer %q must start with /", pointer)
	}
	tokens := strings.Split(pointer[1:], "/")
	for index, token := range tokens {
		token = strings.ReplaceAll(token, "~1", "/")
		tokens[index] = strings.ReplaceAll(token, "~0", "~")
	}
	return us006SetPointerRecursive(document, tokens, value)
}

func us006SetPointerRecursive(current any, tokens []string, value any) (any, error) {
	if len(tokens) == 0 {
		return value, nil
	}
	switch container := current.(type) {
	case map[string]any:
		key := tokens[0]
		if len(tokens) == 1 {
			container[key] = value
			return container, nil
		}
		child, ok := container[key]
		if !ok {
			return nil, fmt.Errorf("missing key %q", key)
		}
		updated, err := us006SetPointerRecursive(child, tokens[1:], value)
		if err != nil {
			return nil, err
		}
		container[key] = updated
		return container, nil
	case []any:
		index, err := strconv.Atoi(tokens[0])
		if err != nil || index < 0 || index >= len(container) {
			return nil, fmt.Errorf("bad array index %q", tokens[0])
		}
		if len(tokens) == 1 {
			container[index] = value
			return container, nil
		}
		updated, err := us006SetPointerRecursive(container[index], tokens[1:], value)
		if err != nil {
			return nil, err
		}
		container[index] = updated
		return container, nil
	default:
		return nil, fmt.Errorf("cannot descend into %T", current)
	}
}

func us006RealizeCase(t *testing.T, fixture us006Case) string {
	t.Helper()
	root := t.TempDir()
	us006ApplyManifest(t, root, fixture.MutationManifestPath, 0)
	return root
}

// CANONICAL_PATH_SHA256_V1: sha256 over "path\x00sha256(bytes)\n" lines in
// sorted relative-path order.
func us006CanonicalTreeDigest(t *testing.T, root string) string {
	t.Helper()
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		relative, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		paths = append(paths, filepath.ToSlash(relative))
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	sort.Strings(paths)
	accumulator := sha256.New()
	for _, relative := range paths {
		data, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if readErr != nil {
			t.Fatalf("read %s: %v", relative, readErr)
		}
		fileDigest := sha256.Sum256(data)
		fmt.Fprintf(accumulator, "%s\x00%s\n", relative, hex.EncodeToString(fileDigest[:]))
	}
	return "sha256:" + hex.EncodeToString(accumulator.Sum(nil))
}

func us006BuildCLI(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "assurectl")
	command := exec.Command("go", "build", "-o", binary, "./cmd/assurectl")
	command.Dir = us006RepoRoot(t)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build assurectl: %v\n%s", err, output)
	}
	return binary
}

func us006RunCLI(t *testing.T, binary, verb, root string) (int, []byte) {
	t.Helper()
	command := exec.Command(binary, verb, "--root", root)
	output, err := command.Output()
	if err == nil {
		return 0, output
	}
	if exitError, ok := err.(*exec.ExitError); ok {
		return exitError.ExitCode(), output
	}
	t.Fatalf("run %s: %v", verb, err)
	return -1, nil
}

func us006AssertFindings(t *testing.T, findings []map[string]any, expected []us006FindingExpect) {
	t.Helper()
	total := 0
	for _, item := range expected {
		want := item.Count
		if want == 0 {
			want = 1
		}
		total += want
		got := 0
		for _, finding := range findings {
			if finding["code"] == item.Code && finding["disposition"] == item.Disposition {
				got++
			}
		}
		if got != want {
			t.Fatalf("finding %s/%s count = %d, want %d in %v", item.Code, item.Disposition, got, want, findings)
		}
	}
	if len(findings) != total {
		t.Fatalf("finding count = %d, want exactly %d: %v", len(findings), total, findings)
	}
}

func hasFindingCode(verdict PreflightVerdict, code string) bool {
	for _, finding := range verdict.Findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}

// --- unit-rule harness ------------------------------------------------------

// us006UnitRoot builds a minimal real-content root: the lane C document and
// schema plus the acceptance sources the deep rules read. Lane A/B documents
// are absent by construction, so every evaluation carries exactly two
// FORMAL_DOCUMENT_ABSENT findings for them; unit assertions filter on codes.
func us006UnitRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, relative := range []string{
		BackendQualificationDocumentPath,
		BackendQualificationSchemaPath,
		"security/sbx-template.json",
		"security/sandbox-policy.json",
		"evidence/corpus-calibration.json",
		"rust/connection-core/src/connection.rs",
	} {
		us006WriteFile(t, filepath.Join(root, filepath.FromSlash(relative)), us006ReadRepoFile(t, relative))
	}
	return root
}

func us006MutateDocument(t *testing.T, root, pointer string, value any) {
	t.Helper()
	target := filepath.Join(root, filepath.FromSlash(BackendQualificationDocumentPath))
	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read document: %v", err)
	}
	var document any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("decode document: %v", err)
	}
	updated, err := us006SetPointer(document, pointer, value)
	if err != nil {
		t.Fatalf("mutate %s: %v", pointer, err)
	}
	encoded, err := json.MarshalIndent(updated, "", "  ")
	if err != nil {
		t.Fatalf("encode document: %v", err)
	}
	us006WriteFile(t, target, append(encoded, '\n'))
}

// --- tests ------------------------------------------------------------------

// The real repository document must be clean under every deep rule: the only
// permitted findings on the real tree are the absences of the lane A/B
// documents (they land on other branches).
func TestFormalPreflightRealDocumentDeepRulesClean(t *testing.T) {
	t.Parallel()
	verdict, err := FormalPreflight(PreflightRequest{RootPath: us006RepoRoot(t)})
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	for _, finding := range verdict.Findings {
		if finding.Code == "FORMAL_DOCUMENT_ABSENT" &&
			(strings.Contains(finding.Path, ProofTargetsDocumentPath) || strings.Contains(finding.Path, ConcurrencyPlanDocumentPath)) {
			continue
		}
		t.Fatalf("unexpected finding on real tree: %+v", finding)
	}
	if len(verdict.Documents) != 3 {
		t.Fatalf("documents = %d, want 3", len(verdict.Documents))
	}
	if !verdict.Documents[0].Present || !verdict.Documents[0].SchemaPresent {
		t.Fatalf("backend qualification document/schema must be present: %+v", verdict.Documents[0])
	}
	if verdict.ObligationsEvaluated != 7 {
		t.Fatalf("obligations evaluated = %d, want 7", verdict.ObligationsEvaluated)
	}
	if verdict.ObligationsPassed != 0 || verdict.ProductionLinkedObligationsPassed != 0 {
		t.Fatalf("nothing has executed: passed=%d production=%d, want 0/0",
			verdict.ObligationsPassed, verdict.ProductionLinkedObligationsPassed)
	}
	if verdict.Assurance != "OWNER_ATTESTED_NOT_INDEPENDENT" || verdict.IndependentReviewClaimed {
		t.Fatalf("assurance framing wrong: %+v", verdict)
	}
}

func TestFormalPreflightDeepRuleFindings(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		pointer string
		value   any
		code    string
	}{
		{"probe-not-executed", "/backends/0/availability_probe/executed", false, "BACKEND_PROBE_NOT_EXECUTED"},
		{"probe-output-missing", "/backends/0/availability_probe/commands", []any{}, "PROBE_OUTPUT_MISSING"},
		{"probe-truncated-without-digest", "/backends/1/availability_probe/commands/0/stdout_sha256", "", "PROBE_OUTPUT_MISSING"},
		{"selected-without-execution", "/backends/0/selected", true, "BACKEND_SELECTED_WITHOUT_EXECUTION"},
		{"placeholder-receipt", "/backends/0/sbx_execution/receipt",
			map[string]any{"path": "evidence/security-validation.json", "sha256": "sha256:" + strings.Repeat("a", 64)},
			"PLACEHOLDER_EXECUTION_RECEIPT"},
		{"unavailable-as-success", "/backends/0/obligations/0/outcome", "BoundedCheckPassed", "UNAVAILABLE_BACKEND_CLAIM"},
		{"unavailable-as-skip", "/backends/0/obligations/0/outcome", "skipped", "UNAVAILABLE_REPRESENTED_AS_SKIP"},
		{"inflated-finite-claim", "/backends/3/obligations/0/outcome", "ProofEstablished", "INFLATED_BACKEND_CLAIM"},
		{"inflated-loom-proof", "/backends/1/obligations/0/outcome", "ProofEstablished", "INFLATED_BACKEND_CLAIM"},
		{"stale-attempt-binding", "/sandbox_profile/accepted_attempt_id", "us007-sbx-output-live-0123", "STALE_SBX_ATTEMPT_BINDING"},
		{"profile-digest-mismatch", "/sandbox_profile/template_manifest_digest", "sha256:" + strings.Repeat("a", 64), "SBX_PROFILE_DIGEST_MISMATCH"},
		{"missing-canary-pair", "/backends/2/canaries/known_bad", nil, "MISSING_CANARY_PAIR"},
		{"canary-outside-vocabulary", "/backends/2/canaries/known_bad/mutant_id", "invented-mutant", "MISSING_CANARY_PAIR"},
		{"canary-claim-without-execution", "/backends/2/canaries/known_bad/status", "DETECTED", "CANARY_CLAIM_WITHOUT_EXECUTION"},
		{"zero-obligations", "/backends/0/obligations", []any{}, "ZERO_BACKEND_OBLIGATIONS"},
	}
	for _, item := range cases {
		item := item
		t.Run(item.name, func(t *testing.T) {
			t.Parallel()
			root := us006UnitRoot(t)
			us006MutateDocument(t, root, item.pointer, item.value)
			verdict, err := FormalPreflight(PreflightRequest{RootPath: root})
			if err != nil {
				t.Fatalf("preflight: %v", err)
			}
			if !hasFindingCode(verdict, item.code) {
				t.Fatalf("missing finding %s in %+v", item.code, verdict.Findings)
			}
			if verdict.State != "BLOCKED" {
				t.Fatalf("state = %s, want BLOCKED", verdict.State)
			}
		})
	}
}

func TestFormalPreflightExecutedBackendRules(t *testing.T) {
	t.Parallel()
	executedExecution := func() map[string]any {
		return map[string]any{
			"status":           "EXECUTED",
			"reason":           "unit fixture",
			"required_profile": "sandbox_profile (this document)",
			"receipt": map[string]any{
				"path":   "seeded/receipt.json",
				"sha256": "sha256:" + strings.Repeat("a", 64),
			},
			"evidence_run": map[string]any{
				"source_revision":              "rev",
				"specification_revision":       "rev",
				"java_revision":                "rev",
				"rust_revision":                "rev",
				"java_semantic_ids":            []any{"java-id"},
				"rust_semantic_ids":            []any{"rust-id"},
				"command":                      "./tool run",
				"working_directory":            ".",
				"tool_hashes":                  []any{"sha256:" + strings.Repeat("b", 64)},
				"container_hashes":             []any{"sha256:" + strings.Repeat("c", 64)},
				"environment":                  []any{"LANG=C"},
				"seed":                         "0",
				"hardware":                     "fixture",
				"assumptions":                  []any{"fixture"},
				"bounds":                       map[string]any{"states": "412"},
				"unsupported_constructs":       []any{"none"},
				"trusted_base":                 []any{"fixture"},
				"exit_count":                   float64(2),
				"obligation_count":             float64(2),
				"raw_log_ids":                  []any{"log-1"},
				"artifact_ids":                 []any{"artifact-1"},
				"normalized_diff_id":           "diff-1",
				"counterexample_or_corpus_ids": []any{"cx-1"},
				"replay_command":               "./tool run",
			},
		}
	}
	prepareExecuted := func(t *testing.T) string {
		root := us006UnitRoot(t)
		receipt := []byte("{\"kind\":\"seeded-unit-receipt\"}\n")
		receiptDigest := sha256.Sum256(receipt)
		us006WriteFile(t, filepath.Join(root, "seeded", "receipt.json"), receipt)
		execution := executedExecution()
		execution["receipt"].(map[string]any)["sha256"] = "sha256:" + hex.EncodeToString(receiptDigest[:])
		us006MutateDocument(t, root, "/backends/2/sbx_execution", execution)
		us006MutateDocument(t, root, "/backends/2/selected", true)
		us006MutateDocument(t, root, "/backends/2/selection_state", "SELECTED_EXECUTED")
		us006MutateDocument(t, root, "/backends/2/canaries/known_good/status", "PASSED")
		us006MutateDocument(t, root, "/backends/2/canaries/known_bad/status", "DETECTED")
		us006MutateDocument(t, root, "/backends/2/canaries/known_bad/counterexample_digest", "sha256:"+strings.Repeat("d", 64))
		us006MutateDocument(t, root, "/backends/2/obligations/0/outcome", "ProofEstablished")
		us006MutateDocument(t, root, "/backends/2/obligations/0/production_code_ids",
			[]any{"rust/connection-core/src/connection.rs#connection_state_machine"})
		return root
	}

	t.Run("clean-executed-backend-passes-production-linked-obligation", func(t *testing.T) {
		t.Parallel()
		root := prepareExecuted(t)
		verdict, err := FormalPreflight(PreflightRequest{RootPath: root})
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		for _, finding := range verdict.Findings {
			if finding.Code != "FORMAL_DOCUMENT_ABSENT" {
				t.Fatalf("unexpected finding: %+v", finding)
			}
		}
		if verdict.ObligationsPassed != 1 || verdict.ProductionLinkedObligationsPassed != 1 {
			t.Fatalf("passed=%d production=%d, want 1/1", verdict.ObligationsPassed, verdict.ProductionLinkedObligationsPassed)
		}
	})
	// Re-review round 1 BLOCKING-3: an obligation counts as passed ONLY when
	// its outcome is a genuine lattice pass AND the execution record satisfies
	// the foundation EvidenceRun completeness predicate AND every canary in the
	// backend's pair is healthy (known-good PASSED, known-bad DETECTED with a
	// digested counterexample). Incomplete evidence or a failed/unexecuted
	// canary excludes the pass with the typed finding, never counts it.
	t.Run("evidence-run-incomplete", func(t *testing.T) {
		t.Parallel()
		root := prepareExecuted(t)
		us006MutateDocument(t, root, "/backends/2/sbx_execution/evidence_run/seed", "")
		verdict, err := FormalPreflight(PreflightRequest{RootPath: root})
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		if !hasFindingCode(verdict, "EVIDENCE_RUN_INCOMPLETE") {
			t.Fatalf("missing EVIDENCE_RUN_INCOMPLETE: %+v", verdict.Findings)
		}
		if verdict.ObligationsPassed != 0 || verdict.ProductionLinkedObligationsPassed != 0 {
			t.Fatalf("incomplete EvidenceRun must not count passes: passed=%d production=%d, want 0/0",
				verdict.ObligationsPassed, verdict.ProductionLinkedObligationsPassed)
		}
	})
	t.Run("receipt-digest-mismatch-is-incomplete", func(t *testing.T) {
		t.Parallel()
		root := prepareExecuted(t)
		us006MutateDocument(t, root, "/backends/2/sbx_execution/receipt/sha256", "sha256:"+strings.Repeat("e", 64))
		verdict, err := FormalPreflight(PreflightRequest{RootPath: root})
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		if !hasFindingCode(verdict, "EVIDENCE_RUN_INCOMPLETE") {
			t.Fatalf("missing EVIDENCE_RUN_INCOMPLETE for receipt mismatch: %+v", verdict.Findings)
		}
		if verdict.ObligationsPassed != 0 || verdict.ProductionLinkedObligationsPassed != 0 {
			t.Fatalf("unverifiable receipt must not count passes: passed=%d production=%d, want 0/0",
				verdict.ObligationsPassed, verdict.ProductionLinkedObligationsPassed)
		}
	})
	t.Run("known-bad-canary-survived", func(t *testing.T) {
		t.Parallel()
		root := prepareExecuted(t)
		us006MutateDocument(t, root, "/backends/2/canaries/known_bad/status", "SURVIVED")
		verdict, err := FormalPreflight(PreflightRequest{RootPath: root})
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		if !hasFindingCode(verdict, "KNOWN_BAD_CANARY_SURVIVED") {
			t.Fatalf("missing KNOWN_BAD_CANARY_SURVIVED: %+v", verdict.Findings)
		}
		if verdict.ObligationsPassed != 0 || verdict.ProductionLinkedObligationsPassed != 0 {
			t.Fatalf("surviving known-bad canary must not count passes: passed=%d production=%d, want 0/0",
				verdict.ObligationsPassed, verdict.ProductionLinkedObligationsPassed)
		}
	})
	t.Run("known-bad-canary-not-executed-excludes-pass", func(t *testing.T) {
		t.Parallel()
		root := prepareExecuted(t)
		us006MutateDocument(t, root, "/backends/2/canaries/known_bad/status", "NOT_EXECUTED")
		verdict, err := FormalPreflight(PreflightRequest{RootPath: root})
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		if !hasFindingCode(verdict, "KNOWN_BAD_CANARY_SURVIVED") {
			t.Fatalf("missing KNOWN_BAD_CANARY_SURVIVED for unexecuted canary on executed backend: %+v", verdict.Findings)
		}
		if verdict.ObligationsPassed != 0 || verdict.ProductionLinkedObligationsPassed != 0 {
			t.Fatalf("unexecuted known-bad canary must not count passes: passed=%d production=%d, want 0/0",
				verdict.ObligationsPassed, verdict.ProductionLinkedObligationsPassed)
		}
	})
	t.Run("good-canary-not-confirmed", func(t *testing.T) {
		t.Parallel()
		root := prepareExecuted(t)
		us006MutateDocument(t, root, "/backends/2/canaries/known_good/status", "NOT_EXECUTED")
		verdict, err := FormalPreflight(PreflightRequest{RootPath: root})
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		if !hasFindingCode(verdict, "CANARY_NOT_CONFIRMED") {
			t.Fatalf("missing CANARY_NOT_CONFIRMED: %+v", verdict.Findings)
		}
		if verdict.ObligationsPassed != 0 || verdict.ProductionLinkedObligationsPassed != 0 {
			t.Fatalf("unconfirmed known-good canary must not count passes: passed=%d production=%d, want 0/0",
				verdict.ObligationsPassed, verdict.ProductionLinkedObligationsPassed)
		}
	})
}

func TestFormalPreflightDocumentAndSourcePresence(t *testing.T) {
	t.Parallel()
	t.Run("backend-document-absent", func(t *testing.T) {
		t.Parallel()
		root := us006UnitRoot(t)
		if err := os.Remove(filepath.Join(root, filepath.FromSlash(BackendQualificationDocumentPath))); err != nil {
			t.Fatalf("remove: %v", err)
		}
		verdict, err := FormalPreflight(PreflightRequest{RootPath: root})
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		count := 0
		for _, finding := range verdict.Findings {
			if finding.Code == "FORMAL_DOCUMENT_ABSENT" {
				count++
			}
		}
		if count != 3 {
			t.Fatalf("FORMAL_DOCUMENT_ABSENT count = %d, want 3: %+v", count, verdict.Findings)
		}
	})
	t.Run("schema-absent", func(t *testing.T) {
		t.Parallel()
		root := us006UnitRoot(t)
		if err := os.Remove(filepath.Join(root, filepath.FromSlash(BackendQualificationSchemaPath))); err != nil {
			t.Fatalf("remove: %v", err)
		}
		verdict, err := FormalPreflight(PreflightRequest{RootPath: root})
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		if !hasFindingCode(verdict, "FORMAL_SCHEMA_ABSENT") {
			t.Fatalf("missing FORMAL_SCHEMA_ABSENT: %+v", verdict.Findings)
		}
	})
	t.Run("document-invalid-json", func(t *testing.T) {
		t.Parallel()
		root := us006UnitRoot(t)
		target := filepath.Join(root, filepath.FromSlash(BackendQualificationDocumentPath))
		data, err := os.ReadFile(target)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		us006WriteFile(t, target, append(data, []byte("]")...))
		verdict, preflightErr := FormalPreflight(PreflightRequest{RootPath: root})
		if preflightErr != nil {
			t.Fatalf("preflight: %v", preflightErr)
		}
		if !hasFindingCode(verdict, "FORMAL_DOCUMENT_INVALID") {
			t.Fatalf("missing FORMAL_DOCUMENT_INVALID: %+v", verdict.Findings)
		}
	})
	t.Run("schema-validation-failed", func(t *testing.T) {
		t.Parallel()
		root := us006UnitRoot(t)
		us006MutateDocument(t, root, "/backends/0/selection_state", "TOTALLY_SELECTED")
		verdict, err := FormalPreflight(PreflightRequest{RootPath: root})
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		if !hasFindingCode(verdict, "FORMAL_SCHEMA_VALIDATION_FAILED") {
			t.Fatalf("missing FORMAL_SCHEMA_VALIDATION_FAILED: %+v", verdict.Findings)
		}
	})
	// Re-review round 1 BLOCKING-2: the pinned sandbox_policy_digest must be
	// reconciled against the ACTUAL bytes of security/sandbox-policy.json.
	// Stale-pin case: the file's bytes drift while the document pin and the
	// sbx-template pin still agree with each other, so the string-equality
	// comparison (SBX_PROFILE_DIGEST_MISMATCH) stays silent and only a real
	// re-hash of the file catches the divergence.
	t.Run("profile-bytes-stale", func(t *testing.T) {
		t.Parallel()
		root := us006UnitRoot(t)
		policyPath := filepath.Join(root, "security", "sandbox-policy.json")
		data, err := os.ReadFile(policyPath)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		us006WriteFile(t, policyPath, append(data, '\n'))
		verdict, err := FormalPreflight(PreflightRequest{RootPath: root})
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		if !hasFindingCode(verdict, "PROFILE_DIGEST_MISMATCH") {
			t.Fatalf("missing PROFILE_DIGEST_MISMATCH: %+v", verdict.Findings)
		}
		if hasFindingCode(verdict, "SBX_PROFILE_DIGEST_MISMATCH") {
			t.Fatalf("pin-vs-source comparison must stay silent here (both pins agree); only the byte re-hash catches drift: %+v", verdict.Findings)
		}
		if verdict.State != "BLOCKED" {
			t.Fatalf("state = %s, want BLOCKED", verdict.State)
		}
	})
	t.Run("profile-artifact-missing", func(t *testing.T) {
		t.Parallel()
		root := us006UnitRoot(t)
		if err := os.Remove(filepath.Join(root, "security", "sandbox-policy.json")); err != nil {
			t.Fatalf("remove: %v", err)
		}
		verdict, err := FormalPreflight(PreflightRequest{RootPath: root})
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		if !hasFindingCode(verdict, "PROFILE_ARTIFACT_UNREADABLE") {
			t.Fatalf("missing PROFILE_ARTIFACT_UNREADABLE: %+v", verdict.Findings)
		}
		if verdict.State != "BLOCKED" {
			t.Fatalf("state = %s, want BLOCKED", verdict.State)
		}
	})
	t.Run("sbx-profile-source-absent", func(t *testing.T) {
		t.Parallel()
		root := us006UnitRoot(t)
		if err := os.Remove(filepath.Join(root, "security", "sbx-template.json")); err != nil {
			t.Fatalf("remove: %v", err)
		}
		verdict, err := FormalPreflight(PreflightRequest{RootPath: root})
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		if !hasFindingCode(verdict, "SBX_PROFILE_SOURCE_ABSENT") {
			t.Fatalf("missing SBX_PROFILE_SOURCE_ABSENT: %+v", verdict.Findings)
		}
	})
	t.Run("acceptance-evidence-absent", func(t *testing.T) {
		t.Parallel()
		root := us006UnitRoot(t)
		if err := os.Remove(filepath.Join(root, "evidence", "corpus-calibration.json")); err != nil {
			t.Fatalf("remove: %v", err)
		}
		verdict, err := FormalPreflight(PreflightRequest{RootPath: root})
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		if !hasFindingCode(verdict, "ACCEPTANCE_EVIDENCE_ABSENT") {
			t.Fatalf("missing ACCEPTANCE_EVIDENCE_ABSENT: %+v", verdict.Findings)
		}
	})
	t.Run("foundation-contract-mismatch", func(t *testing.T) {
		t.Parallel()
		root := us006UnitRoot(t)
		us006MutateDocument(t, root, "/foundation_binding/outcome_lattice/BoundedCheckPassed", float64(9))
		verdict, err := FormalPreflight(PreflightRequest{RootPath: root})
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		if !hasFindingCode(verdict, "FOUNDATION_CONTRACT_MISMATCH") {
			t.Fatalf("missing FOUNDATION_CONTRACT_MISMATCH: %+v", verdict.Findings)
		}
	})
}

// The digest-frozen fixture catalog: every case realizes to its frozen tree
// digest, all trees are pairwise distinct, and every case runs through the
// REAL CLI in both formal-preflight and formal-replay modes with byte-identical
// verdicts and the exact expected exit code, findings, and counters.
func TestUS006FixtureCatalogThroughRealCLI(t *testing.T) {
	catalog := us006LoadCatalog(t)
	binary := us006BuildCLI(t)

	regenerate := os.Getenv("US006_REGENERATE") == "1"
	digests := make(map[string]string, len(catalog.Cases))

	for index := range catalog.Cases {
		fixture := catalog.Cases[index]
		root := us006RealizeCase(t, fixture)
		digest := us006CanonicalTreeDigest(t, root)
		digests[fixture.ID] = digest
		if regenerate {
			catalog.Cases[index].RealizedTreeSHA256 = digest
		} else if digest != fixture.RealizedTreeSHA256 {
			t.Fatalf("case %s realized digest %s != frozen %s (run US006_REGENERATE=1 to refreeze deliberately)",
				fixture.ID, digest, fixture.RealizedTreeSHA256)
		}

		preflightExit, preflightOut := us006RunCLI(t, binary, "formal-preflight", root)
		replayExit, replayOut := us006RunCLI(t, binary, "formal-replay", root)
		if preflightExit != fixture.Expected.ExitCode {
			t.Fatalf("case %s: formal-preflight exit = %d, want %d\n%s", fixture.ID, preflightExit, fixture.Expected.ExitCode, preflightOut)
		}
		if replayExit != fixture.Expected.ExitCode {
			t.Fatalf("case %s: formal-replay exit = %d, want %d\n%s", fixture.ID, replayExit, fixture.Expected.ExitCode, replayOut)
		}
		if string(preflightOut) != string(replayOut) {
			t.Fatalf("case %s: preflight and replay verdicts differ:\n%s\n%s", fixture.ID, preflightOut, replayOut)
		}

		var verdict map[string]any
		if err := json.Unmarshal(preflightOut, &verdict); err != nil {
			t.Fatalf("case %s: decode verdict: %v\n%s", fixture.ID, err, preflightOut)
		}
		if verdict["state"] != fixture.Expected.State {
			t.Fatalf("case %s: state = %v, want %s", fixture.ID, verdict["state"], fixture.Expected.State)
		}
		rawFindings, _ := verdict["findings"].([]any)
		findings := make([]map[string]any, 0, len(rawFindings))
		for _, item := range rawFindings {
			entry, ok := item.(map[string]any)
			if !ok {
				t.Fatalf("case %s: malformed finding %v", fixture.ID, item)
			}
			findings = append(findings, entry)
		}
		us006AssertFindings(t, findings, fixture.Expected.Findings)
		if int(verdict["obligations_evaluated"].(float64)) != fixture.Expected.ObligationsEvaluated {
			t.Fatalf("case %s: obligations_evaluated = %v, want %d", fixture.ID, verdict["obligations_evaluated"], fixture.Expected.ObligationsEvaluated)
		}
		if int(verdict["obligations_passed"].(float64)) != fixture.Expected.ObligationsPassed {
			t.Fatalf("case %s: obligations_passed = %v, want %d", fixture.ID, verdict["obligations_passed"], fixture.Expected.ObligationsPassed)
		}
		if int(verdict["production_linked_obligations_passed"].(float64)) != fixture.Expected.ProductionLinkedObligationsPassed {
			t.Fatalf("case %s: production_linked_obligations_passed = %v, want %d",
				fixture.ID, verdict["production_linked_obligations_passed"], fixture.Expected.ProductionLinkedObligationsPassed)
		}
	}

	seen := make(map[string]string, len(digests))
	for id, digest := range digests {
		if other, duplicate := seen[digest]; duplicate {
			t.Fatalf("cases %s and %s realize identical trees (%s) — duplicate-content fixtures are forbidden", id, other, digest)
		}
		seen[digest] = id
	}

	if regenerate {
		encoded, err := json.MarshalIndent(catalog, "", "  ")
		if err != nil {
			t.Fatalf("encode catalog: %v", err)
		}
		us006WriteFile(t, filepath.Join(us006RepoRoot(t), filepath.FromSlash(us006CatalogPath)), append(encoded, '\n'))
	}
}

// The good-path fixture must contain a genuinely passing production-linked
// obligation (nonzero pass counters through the real CLI), unlike a good path
// in which nothing ever passes.
func TestUS006GoodPathPassesProductionLinkedObligation(t *testing.T) {
	catalog := us006LoadCatalog(t)
	goodCases := 0
	for _, fixture := range catalog.Cases {
		if fixture.Expected.ExitCode == 0 {
			goodCases++
			if fixture.Expected.ObligationsPassed == 0 || fixture.Expected.ProductionLinkedObligationsPassed == 0 {
				t.Fatalf("good case %s passes nothing: %+v", fixture.ID, fixture.Expected)
			}
		}
	}
	if goodCases == 0 {
		t.Fatalf("catalog has no good-path case")
	}
}

func TestFormalCLIDeterministicAndModeIdentical(t *testing.T) {
	binary := us006BuildCLI(t)
	root := us006UnitRoot(t)
	exitOne, outputOne := us006RunCLI(t, binary, "formal-preflight", root)
	exitTwo, outputTwo := us006RunCLI(t, binary, "formal-preflight", root)
	exitReplay, outputReplay := us006RunCLI(t, binary, "formal-replay", root)
	if exitOne != exitTwo || exitOne != exitReplay {
		t.Fatalf("exit codes differ: %d %d %d", exitOne, exitTwo, exitReplay)
	}
	if string(outputOne) != string(outputTwo) {
		t.Fatalf("repeated preflight runs differ:\n%s\n%s", outputOne, outputTwo)
	}
	if string(outputOne) != string(outputReplay) {
		t.Fatalf("preflight and replay verdicts differ:\n%s\n%s", outputOne, outputReplay)
	}
}

// The CLI cannot be coaxed into claiming an execution: the formal verbs accept
// only --root and reject anything else with usage exit 2.
func TestFormalCLIRejectsUnknownFlags(t *testing.T) {
	binary := us006BuildCLI(t)
	for _, arguments := range [][]string{
		{"formal-preflight", "--backend", "kani"},
		{"formal-preflight", "--receipt", "x.json"},
		{"formal-replay", "--executed", "true"},
	} {
		command := exec.Command(binary, arguments...)
		output, err := command.CombinedOutput()
		exitError, ok := err.(*exec.ExitError)
		if !ok || exitError.ExitCode() != 2 {
			t.Fatalf("%v: expected usage exit 2, got err=%v output=%s", arguments, err, output)
		}
	}
}
