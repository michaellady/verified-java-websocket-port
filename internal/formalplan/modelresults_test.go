package formalplan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// --- structural validation of the two new model artifacts -------------------

// The US-012 frame model and the US-016 close model are held to the SAME
// structural contract as the incumbent US-006 connection model: module
// header, staging note, model-check status, cfg coverage of every declared
// constant, genuine state predicates under INVARIANT, a falsification note
// on every checked property, and a resolvable quarantined-Java citation on
// every action. A clean tree must produce no blocking finding.
func TestShippedModelArtifactsValidateClean(t *testing.T) {
	root := us006RepoRoot(t)
	javaRoot := filepath.Join(root, ".quarantine",
		"Java-WebSocket-da3cf2a777aed862f2f5b5cf060cae7969958667",
		"src", "main", "java", "org", "java_websocket")
	for _, model := range []struct {
		module string
		tla    string
		cfg    string
	}{
		{FrameModelModuleName, FrameModelTLAPath, FrameModelCfgPath},
		{CloseModelModuleName, CloseModelTLAPath, CloseModelCfgPath},
	} {
		t.Run(model.module, func(t *testing.T) {
			findings := ValidateTLAModel(model.module,
				filepath.Join(root, filepath.FromSlash(model.tla)),
				filepath.Join(root, filepath.FromSlash(model.cfg)),
				javaRoot)
			for _, finding := range findings {
				t.Errorf("%s: %s %s: %s", finding.Severity, finding.Code, finding.Path, finding.Detail)
			}
		})
	}
}

// The module-parameterised validator must still reject a mismatched module
// name, so generalising it did not weaken the incumbent header check.
func TestValidateTLAModelRejectsWrongModuleName(t *testing.T) {
	root := us006RepoRoot(t)
	findings := ValidateTLAModel(CloseModelModuleName,
		filepath.Join(root, filepath.FromSlash(FrameModelTLAPath)),
		filepath.Join(root, filepath.FromSlash(FrameModelCfgPath)),
		"")
	if !mrHasCode(findings, "MODEL_HEADER_MISSING") {
		t.Fatalf("expected MODEL_HEADER_MISSING, got %+v", findings)
	}
	if !mrHasCode(findings, "MODEL_STAGING_NOTE_MISSING") {
		t.Fatalf("expected MODEL_STAGING_NOTE_MISSING, got %+v", findings)
	}
}

// --- results-document validation -------------------------------------------

func TestShippedModelResultsValidateClean(t *testing.T) {
	root := us006RepoRoot(t)
	for _, binding := range ModelResultsBindings() {
		t.Run(binding.Module, func(t *testing.T) {
			findings := ValidateModelResults(root, binding)
			for _, finding := range findings {
				t.Errorf("%s: %s %s: %s", finding.Severity, finding.Code, finding.Path, finding.Detail)
			}
		})
	}
}

// A tree that ships a model artifact but no executed results document must
// BLOCK: an unexecuted model may not be presented as a formal run.
func TestModelResultsAbsenceBlocks(t *testing.T) {
	root := mrStageTree(t, ModelResultsBindings()[0])
	if err := os.Remove(filepath.Join(root,
		filepath.FromSlash(ModelResultsBindings()[0].ResultsPath))); err != nil {
		t.Fatalf("remove results: %v", err)
	}
	findings := ValidateModelResults(root, ModelResultsBindings()[0])
	if !mrHasCode(findings, "MODEL_RESULTS_ABSENT") {
		t.Fatalf("expected MODEL_RESULTS_ABSENT, got %+v", findings)
	}
}

func TestModelResultsDeepRuleFindings(t *testing.T) {
	binding := ModelResultsBindings()[0]
	cases := []struct {
		name    string
		pointer string
		value   any
		code    string
	}{
		{
			name:    "digest mismatch on the model artifact blocks",
			pointer: "/model/tla_sha256",
			value:   "sha256:" + strings.Repeat("0", 64),
			code:    "MODEL_RESULTS_DIGEST_MISMATCH",
		},
		{
			name:    "an assurance overclaim blocks",
			pointer: "/assurance",
			value:   "INDEPENDENTLY_VERIFIED",
			code:    "MODEL_RESULTS_ASSURANCE_OVERCLAIM",
		},
		{
			name:    "a claim ceiling above proved-model blocks",
			pointer: "/claim_ceiling",
			value:   "proved-production/refinement",
			code:    "MODEL_RESULTS_CEILING_OVERCLAIM",
		},
		{
			name:    "an undigested checker binary blocks",
			pointer: "/backend/tool/sha256",
			value:   "eabd140a",
			code:    "MODEL_RESULTS_TOOL_UNDIGESTED",
		},
		{
			name:    "a nonzero TLC exit with no recorded violation blocks",
			pointer: "/execution/tlc/exit_code",
			value:   float64(13),
			code:    "MODEL_RESULTS_EXIT_INCONSISTENT",
		},
		{
			name:    "states left on the queue is not a complete run",
			pointer: "/state_space/states_left_on_queue",
			value:   float64(7),
			code:    "MODEL_RESULTS_STATE_SPACE_INCOHERENT",
		},
		{
			name:    "more distinct states than generated states is incoherent",
			pointer: "/state_space/distinct_states",
			value:   float64(1 << 30),
			code:    "MODEL_RESULTS_STATE_SPACE_INCOHERENT",
		},
		{
			name:    "an outcome above Held without a recorded violation blocks",
			pointer: "/invariants/0/outcome",
			value:   "Violated",
			code:    "MODEL_RESULTS_VIOLATION_UNRECORDED",
		},
		{
			name:    "an invariant with no falsification note blocks",
			pointer: "/invariants/0/falsified_by",
			value:   "",
			code:    "MODEL_RESULTS_FALSIFICATION_MISSING",
		},
		{
			name:    "a receipt digest that does not match the bytes blocks",
			pointer: "/execution/receipts/0/sha256",
			value:   "sha256:" + strings.Repeat("1", 64),
			code:    "MODEL_RESULTS_RECEIPT_UNVERIFIED",
		},
		{
			name:    "a bound that disagrees with the cfg blocks",
			pointer: "/bounds/0/value",
			value:   float64(999),
			code:    "MODEL_RESULTS_BOUND_MISMATCH",
		},
		{
			name:    "an unexecuted sbx record may not claim an executed run",
			pointer: "/execution/sbx_status",
			value:   "NOT_EXECUTED",
			code:    "MODEL_RESULTS_EXECUTION_UNSUBSTANTIATED",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			root := mrStageTree(t, binding)
			mrMutateJSON(t, filepath.Join(root, filepath.FromSlash(binding.ResultsPath)),
				testCase.pointer, testCase.value)
			findings := ValidateModelResults(root, binding)
			if !mrHasCode(findings, testCase.code) {
				t.Fatalf("expected %s, got %+v", testCase.code, findings)
			}
		})
	}
}

// Dropping a checked invariant from the results document must block: the
// results must account for EVERY check the shipped cfg runs, so a quietly
// removed obligation cannot pass as a clean run.
func TestModelResultsCheckSetMustMatchTheCfg(t *testing.T) {
	binding := ModelResultsBindings()[0]
	root := mrStageTree(t, binding)
	path := filepath.Join(root, filepath.FromSlash(binding.ResultsPath))
	var document map[string]any
	mrReadJSON(t, path, &document)
	list, _ := document["invariants"].([]any)
	if len(list) < 2 {
		t.Fatalf("fixture needs at least two invariants, got %d", len(list))
	}
	document["invariants"] = list[1:]
	mrWriteJSON(t, path, document)
	findings := ValidateModelResults(root, binding)
	if !mrHasCode(findings, "MODEL_RESULTS_CHECK_SET_MISMATCH") {
		t.Fatalf("expected MODEL_RESULTS_CHECK_SET_MISMATCH, got %+v", findings)
	}
}

// The preflight must fail closed on a model artifact whose results document
// is missing: shipping a model without its executed record is exactly the
// gap this work closes.
func TestFormalPreflightBindsModelResults(t *testing.T) {
	verdict, err := FormalPreflight(PreflightRequest{RootPath: us006RepoRoot(t)})
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	seen := map[string]bool{}
	for _, document := range verdict.Documents {
		seen[document.Path] = true
	}
	for _, binding := range ModelResultsBindings() {
		if !seen[binding.ResultsPath] {
			t.Fatalf("preflight verdict does not report %s; documents=%+v",
				binding.ResultsPath, verdict.Documents)
		}
	}
}

// --- helpers ---------------------------------------------------------------

func mrHasCode(findings []ModelFinding, code string) bool {
	for _, finding := range findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}

// mrStageTree copies the real inputs one binding's validation reads into a
// scratch tree, so a mutation case exercises the rule without touching the
// repository.
func mrStageTree(t *testing.T, binding ModelResultsBinding) string {
	t.Helper()
	root := us006RepoRoot(t)
	staged := t.TempDir()
	paths := []string{binding.TLAPath, binding.CfgPath, binding.ResultsPath, binding.SchemaPath}
	var results modelResultsDocument
	mrReadJSON(t, filepath.Join(root, filepath.FromSlash(binding.ResultsPath)), &results)
	for _, receipt := range results.Execution.Receipts {
		paths = append(paths, receipt.Path)
	}
	for _, relative := range paths {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatalf("read %s: %v", relative, err)
		}
		target := filepath.Join(staged, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", target, err)
		}
		if err := os.WriteFile(target, data, 0o644); err != nil {
			t.Fatalf("write %s: %v", target, err)
		}
	}
	return staged
}

func mrReadJSON(t *testing.T, path string, target any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

func mrWriteJSON(t *testing.T, path string, document any) {
	t.Helper()
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatalf("encode %s: %v", path, err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// mrMutateJSON applies a JSON-pointer-shaped mutation (object keys and
// array indices) to the document at path.
func mrMutateJSON(t *testing.T, path, pointer string, value any) {
	t.Helper()
	var document any
	mrReadJSON(t, path, &document)
	tokens := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
	current := document
	for index, token := range tokens {
		last := index == len(tokens)-1
		switch container := current.(type) {
		case map[string]any:
			if last {
				container[token] = value
				break
			}
			current = container[token]
		case []any:
			position := 0
			for _, digit := range token {
				position = position*10 + int(digit-'0')
			}
			if position >= len(container) {
				t.Fatalf("pointer %s index out of range", pointer)
			}
			if last {
				container[position] = value
				break
			}
			current = container[position]
		default:
			t.Fatalf("pointer %s does not resolve in %s", pointer, path)
		}
	}
	mrWriteJSON(t, path, document)
}

// mrDigest is the digest form the results documents record.
func mrDigest(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// The digests the shipped results documents record must be the digests of
// the shipped bytes; this test reads both sides rather than trusting the
// validator alone.
func TestShippedModelResultsDigestsAreReal(t *testing.T) {
	root := us006RepoRoot(t)
	for _, binding := range ModelResultsBindings() {
		var results modelResultsDocument
		mrReadJSON(t, filepath.Join(root, filepath.FromSlash(binding.ResultsPath)), &results)
		if got := mrDigest(t, filepath.Join(root, filepath.FromSlash(binding.TLAPath))); got != results.Model.TLASHA256 {
			t.Errorf("%s tla digest: document %s, bytes %s", binding.Module, results.Model.TLASHA256, got)
		}
		if got := mrDigest(t, filepath.Join(root, filepath.FromSlash(binding.CfgPath))); got != results.Model.CfgSHA256 {
			t.Errorf("%s cfg digest: document %s, bytes %s", binding.Module, results.Model.CfgSHA256, got)
		}
		names := make([]string, 0, len(results.Invariants))
		for _, entry := range results.Invariants {
			names = append(names, entry.Name)
		}
		sort.Strings(names)
		if len(names) == 0 {
			t.Errorf("%s records no invariants", binding.Module)
		}
	}
}
