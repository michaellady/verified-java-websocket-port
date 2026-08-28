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

// --- receipt CONTENT binding (review round 2, BLOCKING-1) -------------------
//
// Hashing a receipt proves only that the bytes did not change since someone
// wrote down their digest. It does not prove the bytes SAY what the results
// document claims. These cases fabricate content while keeping every digest
// internally consistent — exactly the attack the digest-only contract let
// through — and require the validator to reject each one.

// mrRewriteReceipt replaces a receipt's bytes AND re-points the results
// document at the new digest and length, so the digest rules pass cleanly and
// only content binding can catch the fabrication.
func mrRewriteReceipt(t *testing.T, root string, binding ModelResultsBinding,
	receiptPath string, transform func(string) string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(receiptPath))
	original, err := os.ReadFile(full)
	if err != nil {
		t.Fatalf("read receipt %s: %v", receiptPath, err)
	}
	rewritten := []byte(transform(string(original)))
	if string(rewritten) == string(original) {
		t.Fatalf("transform for %s changed nothing; the case would not test anything", receiptPath)
	}
	if err := os.WriteFile(full, rewritten, 0o644); err != nil {
		t.Fatalf("write receipt %s: %v", receiptPath, err)
	}
	sum := sha256.Sum256(rewritten)
	digest := "sha256:" + hex.EncodeToString(sum[:])

	resultsPath := filepath.Join(root, filepath.FromSlash(binding.ResultsPath))
	var document map[string]any
	mrReadJSON(t, resultsPath, &document)
	execution, _ := document["execution"].(map[string]any)
	receipts, _ := execution["receipts"].([]any)
	found := false
	for _, entry := range receipts {
		receipt, _ := entry.(map[string]any)
		if receipt["path"] == receiptPath {
			receipt["sha256"] = digest
			receipt["bytes"] = float64(len(rewritten))
			found = true
		}
	}
	if !found {
		t.Fatalf("receipt %s is not listed in %s", receiptPath, binding.ResultsPath)
	}
	mrWriteJSON(t, resultsPath, document)
}

func TestModelResultsReceiptContentIsBound(t *testing.T) {
	binding := ModelResultsBindings()[0]
	var results modelResultsDocument
	mrReadJSON(t, filepath.Join(us006RepoRoot(t), filepath.FromSlash(binding.ResultsPath)), &results)

	cases := []struct {
		name        string
		receiptPath string
		transform   func(string) string
		code        string
	}{
		{
			name:        "state counts that disagree with the TLC receipt block",
			receiptPath: results.Execution.TLC.ReceiptPath,
			transform: func(text string) string {
				return strings.ReplaceAll(text, "states generated", "states generated ")
			},
			code: "MODEL_RESULTS_RECEIPT_CONTENT_MISMATCH",
		},
		{
			name:        "a checker banner the receipt never printed blocks",
			receiptPath: results.Execution.TLC.ReceiptPath,
			transform: func(text string) string {
				return strings.ReplaceAll(text, "TLC2 Version", "TLC2 Fabricated")
			},
			code: "MODEL_RESULTS_RECEIPT_CONTENT_MISMATCH",
		},
		{
			name:        "a SANY receipt that never processed this module blocks",
			receiptPath: results.Execution.SANY.ReceiptPath,
			transform: func(text string) string {
				return strings.ReplaceAll(text, "Semantic processing of module", "Skipped module")
			},
			code: "MODEL_RESULTS_RECEIPT_CONTENT_MISMATCH",
		},
		{
			name:        "a TLC receipt reporting a violation under an empty violations list blocks",
			receiptPath: results.Execution.TLC.ReceiptPath,
			transform: func(text string) string {
				return strings.ReplaceAll(text,
					"Model checking completed. No error has been found.",
					"Error: Invariant TypeInvariant is violated.")
			},
			code: "MODEL_RESULTS_RECEIPT_CONTENT_MISMATCH",
		},
		{
			name:        "an exit code absent from the driver log blocks",
			receiptPath: results.Execution.DriverLog,
			transform: func(text string) string {
				return strings.ReplaceAll(text, "RESULT step=tlc.FrameModel exit=0",
					"RESULT step=tlc.FrameModel exit=7")
			},
			code: "MODEL_RESULTS_RECEIPT_CONTENT_MISMATCH",
		},
		{
			name:        "a seeded-defect outcome the driver log contradicts blocks",
			receiptPath: results.Execution.DriverLog,
			transform: func(text string) string {
				return strings.ReplaceAll(text, "outcome=Killed", "outcome=Survived")
			},
			code: "MODEL_RESULTS_RECEIPT_CONTENT_MISMATCH",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if testCase.receiptPath == "" {
				t.Fatalf("case has no receipt path; the results document must name one")
			}
			root := mrStageTree(t, binding)
			mrRewriteReceipt(t, root, binding, testCase.receiptPath, testCase.transform)
			findings := ValidateModelResults(root, binding)
			if !mrHasCode(findings, testCase.code) {
				t.Fatalf("expected %s, got %+v", testCase.code, findings)
			}
		})
	}
}

// --- contradictory-receipt binding (review round 3, BLOCKING 1) -------------
//
// The round-2 binder inspected violation text only when the clean banner was
// ABSENT, so a receipt carrying BOTH a clean completion and a violation
// passed. Every case below feeds the binder self-contradictory bytes with a
// consistent digest and length, and requires rejection. This is the same
// defect class as the two vacuous invariants: a check that passes on input
// it should have refused.
func TestModelResultsRejectsContradictoryReceipts(t *testing.T) {
	frame := ModelResultsBindings()[0]
	close := ModelResultsBindings()[1]
	var frameResults, closeResults modelResultsDocument
	mrReadJSON(t, filepath.Join(us006RepoRoot(t), filepath.FromSlash(frame.ResultsPath)), &frameResults)
	mrReadJSON(t, filepath.Join(us006RepoRoot(t), filepath.FromSlash(close.ResultsPath)), &closeResults)

	cases := []struct {
		name        string
		binding     ModelResultsBinding
		receiptPath string
		transform   func(string) string
	}{
		{
			name:        "a TLC receipt carrying BOTH a clean verdict and a violation blocks",
			binding:     frame,
			receiptPath: frameResults.Execution.TLC.ReceiptPath,
			transform: func(text string) string {
				return text + "\nError: Invariant MaskRoundTrip is violated.\n"
			},
		},
		{
			name:        "a TLC receipt carrying both a clean verdict and an ACTION property violation blocks",
			binding:     frame,
			receiptPath: frameResults.Execution.TLC.ReceiptPath,
			transform: func(text string) string {
				return text + "\nError: Action property FrameBudgetMonotone is violated.\n"
			},
		},
		{
			name:        "a killed mutant receipt that ALSO reports clean completion blocks",
			binding:     frame,
			receiptPath: frameResults.SeededDefects[0].ReceiptPath,
			transform: func(text string) string {
				return text + "\nModel checking completed. No error has been found.\n"
			},
		},
		{
			name:        "a mutant receipt naming a SECOND, different violated check blocks",
			binding:     frame,
			receiptPath: frameResults.SeededDefects[0].ReceiptPath,
			transform: func(text string) string {
				return text + "\nError: Invariant ConsumedSiteIsDeclared is violated.\n"
			},
		},
		{
			name:        "state counts must bind to TLC's FINAL summary, not an earlier progress line",
			binding:     close,
			receiptPath: closeResults.Execution.TLC.ReceiptPath,
			transform: func(text string) string {
				// Leave the Progress line intact and corrupt only the final
				// summary. A binder reading the leftmost match never notices.
				return strings.Replace(text, "\n348 states generated,", "\n999 states generated,", 1)
			},
		},
		{
			name:        "a driver log carrying two contradictory RESULT lines for one step blocks",
			binding:     frame,
			receiptPath: frameResults.Execution.DriverLog,
			transform: func(text string) string {
				// The contradictory line goes FIRST, so a last-wins map keeps
				// the honest line and never notices the contradiction.
				return "RESULT step=tlc.FrameModel exit=99 verdict=clean check=NONE\n" + text
			},
		},
		{
			name:        "a SANY receipt reporting a parse error alongside the module line blocks",
			binding:     frame,
			receiptPath: frameResults.Execution.SANY.ReceiptPath,
			transform: func(text string) string {
				return text + "\n***Parse Error***\n"
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if testCase.receiptPath == "" {
				t.Fatal("case has no receipt path")
			}
			root := mrStageTree(t, testCase.binding)
			mrRewriteReceipt(t, root, testCase.binding, testCase.receiptPath, testCase.transform)
			findings := ValidateModelResults(root, testCase.binding)
			if !mrHasCode(findings, "MODEL_RESULTS_RECEIPT_CONTENT_MISMATCH") {
				t.Fatalf("expected MODEL_RESULTS_RECEIPT_CONTENT_MISMATCH, got %+v", findings)
			}
		})
	}
}

// --- violation NAME binding (review round 4, BLOCKING 1) --------------------
//
// A non-clean receipt was accepted whenever the record listed any violation
// at all: the names TLC reported were never compared with the names the
// record claims. Same shape as the five defects before it — something was
// checked to EXIST, never to be the RIGHT something.
//
// mrMakeViolatingFixture builds a coherent non-clean fixture: the TLC receipt
// reports exactly receiptNames as violated, the record claims exactly
// recordNames, and the surrounding consistency rules (exit codes in the
// document and in the driver log, the invariant outcomes backing each
// violation entry) are all satisfied, so only the name comparison can fire.
func mrMakeViolatingFixture(t *testing.T, binding ModelResultsBinding,
	receiptNames, recordNames []string) string {
	t.Helper()
	root := mrStageTree(t, binding)
	var results modelResultsDocument
	mrReadJSON(t, filepath.Join(us006RepoRoot(t), filepath.FromSlash(binding.ResultsPath)), &results)

	// The receipt: drop the clean verdict, report the requested violations.
	mrRewriteReceipt(t, root, binding, results.Execution.TLC.ReceiptPath, func(text string) string {
		var lines []string
		for _, name := range receiptNames {
			lines = append(lines, "Error: Invariant "+name+" is violated.")
		}
		replacement := strings.Join(lines, "\n")
		if replacement == "" {
			replacement = "Error: TLC stopped without a clean verdict."
		}
		return strings.Replace(text, mrCleanVerdict, replacement, 1)
	})
	// The driver log: the checker exited non-zero on a violation.
	mrRewriteReceipt(t, root, binding, results.Execution.DriverLog, func(text string) string {
		return strings.Replace(text,
			"RESULT step=tlc."+binding.Module+" exit=0 verdict=clean check=NONE",
			"RESULT step=tlc."+binding.Module+" exit=12 verdict=violated check="+recordNames[0], 1)
	})

	resultsPath := filepath.Join(root, filepath.FromSlash(binding.ResultsPath))
	var document map[string]any
	mrReadJSON(t, resultsPath, &document)
	execution, _ := document["execution"].(map[string]any)
	tlc, _ := execution["tlc"].(map[string]any)
	tlc["exit_code"] = float64(12)
	var violations []any
	claimed := map[string]bool{}
	for _, name := range recordNames {
		claimed[name] = true
		violations = append(violations, map[string]any{
			"check":          name,
			"kind":           "invariant",
			"counterexample": "fabricated fixture counterexample",
			"receipt_path":   results.Execution.TLC.ReceiptPath,
		})
	}
	document["violations"] = violations
	// Every violation entry needs a matching Violated outcome, so the
	// document-internal rules stay satisfied.
	invariants, _ := document["invariants"].([]any)
	for _, entry := range invariants {
		item, _ := entry.(map[string]any)
		if name, _ := item["name"].(string); claimed[name] {
			item["outcome"] = "Violated"
		}
	}
	mrWriteJSON(t, resultsPath, document)
	return root
}

func TestModelResultsBindsViolationNames(t *testing.T) {
	binding := ModelResultsBindings()[0]
	cases := []struct {
		name         string
		receiptNames []string
		recordNames  []string
	}{
		{
			name:         "a receipt naming a DIFFERENT check than the record blocks",
			receiptNames: []string{"ConsumedSiteIsDeclared"},
			recordNames:  []string{"MaskRoundTrip"},
		},
		{
			name:         "a receipt naming an EXTRA check the record omits blocks",
			receiptNames: []string{"MaskRoundTrip", "ConsumedSiteIsDeclared"},
			recordNames:  []string{"MaskRoundTrip"},
		},
		{
			name:         "a record claiming a violation the receipt never names blocks",
			receiptNames: nil,
			recordNames:  []string{"MaskRoundTrip"},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			root := mrMakeViolatingFixture(t, binding, testCase.receiptNames, testCase.recordNames)
			findings := ValidateModelResults(root, binding)
			if !mrHasCode(findings, "MODEL_RESULTS_RECEIPT_CONTENT_MISMATCH") {
				t.Fatalf("expected MODEL_RESULTS_RECEIPT_CONTENT_MISMATCH, got %+v", findings)
			}
		})
	}

	// The control: names that agree on both sides must NOT trip the name
	// comparison. Without this, a rule that rejects everything would pass the
	// three cases above and prove nothing.
	t.Run("matching names do not trip the name comparison", func(t *testing.T) {
		root := mrMakeViolatingFixture(t, binding,
			[]string{"MaskRoundTrip"}, []string{"MaskRoundTrip"})
		for _, finding := range ValidateModelResults(root, binding) {
			if finding.Code == "MODEL_RESULTS_RECEIPT_CONTENT_MISMATCH" &&
				strings.Contains(finding.Detail, "violated check") {
				t.Fatalf("agreeing names must not be reported as a mismatch: %s", finding.Detail)
			}
		}
	})
}

// The seventh-shape sweep: a receipt is checked to EXIST and to be
// well-formed, but is it the RIGHT model's receipt? Citing another model's
// TLC output must block.
func TestModelResultsBindsReceiptToItsOwnModule(t *testing.T) {
	frame := ModelResultsBindings()[0]
	root := mrStageTree(t, frame)
	var results modelResultsDocument
	mrReadJSON(t, filepath.Join(root, filepath.FromSlash(frame.ResultsPath)), &results)
	mrRewriteReceipt(t, root, frame, results.Execution.TLC.ReceiptPath, func(text string) string {
		return strings.ReplaceAll(text, "module FrameModel", "module CloseModel")
	})
	findings := ValidateModelResults(root, frame)
	if !mrHasCode(findings, "MODEL_RESULTS_RECEIPT_CONTENT_MISMATCH") {
		t.Fatalf("expected MODEL_RESULTS_RECEIPT_CONTENT_MISMATCH, got %+v", findings)
	}
}

// Same shape again, one artifact over: the driver log carries DIGEST lines
// for the models it actually staged. A log from a different run must not be
// accepted just because its RESULT lines happen to line up.
func TestModelResultsBindsDriverLogToTheStagedModel(t *testing.T) {
	binding := ModelResultsBindings()[0]
	root := mrStageTree(t, binding)
	var results modelResultsDocument
	mrReadJSON(t, filepath.Join(root, filepath.FromSlash(binding.ResultsPath)), &results)
	mrRewriteReceipt(t, root, binding, results.Execution.DriverLog, func(text string) string {
		return strings.Replace(text, results.Model.TLASHA256,
			"sha256:"+strings.Repeat("c", 64), 1)
	})
	findings := ValidateModelResults(root, binding)
	if !mrHasCode(findings, "MODEL_RESULTS_RECEIPT_CONTENT_MISMATCH") {
		t.Fatalf("expected MODEL_RESULTS_RECEIPT_CONTENT_MISMATCH, got %+v", findings)
	}
}

// A seeded defect whose own mutant receipt does not name the check it claims
// to have killed must block.
func TestModelResultsMutantReceiptNamesItsCheck(t *testing.T) {
	binding := ModelResultsBindings()[1]
	var results modelResultsDocument
	mrReadJSON(t, filepath.Join(us006RepoRoot(t), filepath.FromSlash(binding.ResultsPath)), &results)
	if len(results.SeededDefects) == 0 {
		t.Fatal("fixture needs at least one seeded defect")
	}
	defect := results.SeededDefects[0]
	root := mrStageTree(t, binding)
	mrRewriteReceipt(t, root, binding, defect.ReceiptPath, func(text string) string {
		return strings.ReplaceAll(text, defect.ViolatedCheck, "SomeOtherCheck")
	})
	findings := ValidateModelResults(root, binding)
	if !mrHasCode(findings, "MODEL_RESULTS_RECEIPT_CONTENT_MISMATCH") {
		t.Fatalf("expected MODEL_RESULTS_RECEIPT_CONTENT_MISMATCH, got %+v", findings)
	}
}

// Every checked invariant and property must have an EXECUTED seeded defect.
// Round 2 established that an unexecuted falsification note is an assertion,
// not evidence: two of them were vacuous.
func TestEveryCheckHasAnExecutedSeededDefect(t *testing.T) {
	root := us006RepoRoot(t)
	for _, binding := range ModelResultsBindings() {
		t.Run(binding.Module, func(t *testing.T) {
			var results modelResultsDocument
			mrReadJSON(t, filepath.Join(root, filepath.FromSlash(binding.ResultsPath)), &results)
			covered := map[string]bool{}
			for _, defect := range results.SeededDefects {
				covered[defect.ViolatedCheck] = true
			}
			for _, entry := range append(append([]modelResultsCheck{}, results.Invariants...),
				results.Properties...) {
				if !covered[entry.Name] {
					t.Errorf("%s has no executed seeded defect; its non-vacuity is asserted, not shown",
						entry.Name)
				}
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
