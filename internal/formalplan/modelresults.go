// Package formalplan — model-results validation.
//
// This file owns the executed-record contract for the shipped TLA+ model
// artifacts: US-012 AC5's frame model and US-016 AC4's close model. The
// incumbent US-006 validators (targets.go, concurrency.go, model.go) check
// that a model artifact is well formed; nothing checked that a shipped model
// had actually been RUN. That was the audit gap these documents close, so
// the rules here are deliberately fail-closed:
//
//   - a model artifact present in the tree REQUIRES its results document
//     (MODEL_RESULTS_ABSENT); a model that ships without an executed record
//     may not be presented as a formal run;
//   - every number in the record is bound to bytes: the model and cfg
//     digests are re-hashed from the tree, and every receipt is re-hashed
//     against the file it names;
//   - the recorded check set must be exactly the cfg's INVARIANT/PROPERTY
//     set and the recorded bounds exactly the cfg's CONSTANT assignments, so
//     an obligation cannot be dropped quietly;
//   - a clean verdict requires a zero checker exit AND no Violated outcome
//     AND an empty violations list; any Violated outcome must carry a
//     recorded counterexample, because a violation is a finding to report,
//     never to suppress;
//   - the claim ceiling may not rise above proved-model and the assurance
//     may not claim independent review.
//
// The rules reuse the incumbent ModelFinding type and severities; there is
// no parallel validation stack.
package formalplan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	vendorprotocol "github.com/michaellady/verified-java-to-rust/foundation/protocol"

	"github.com/michaellady/verified-java-websocket-port/internal/portplan"
)

const (
	// FrameModelTLAPath and friends are the US-012 AC5 model artifact, its
	// TLC configuration, and its executed results record.
	FrameModelTLAPath     = "assurance/formal/frame-model.tla"
	FrameModelCfgPath     = "assurance/formal/frame-model.cfg"
	FrameModelResultsPath = "assurance/formal/frame-results.json"

	// CloseModelTLAPath and friends are the US-016 AC4 equivalents.
	CloseModelTLAPath     = "assurance/formal/close-model.tla"
	CloseModelCfgPath     = "assurance/formal/close-model.cfg"
	CloseModelResultsPath = "assurance/formal/close-model-results.json"

	ModelResultsSchemaPath = "schemas/formal-model-results-1.0.0.schema.json"

	// modelResultsCeiling is the highest claim any abstract model check may
	// carry. Raising it requires a reviewed composition/refinement link,
	// which no artifact in this tree has.
	modelResultsCeiling = "proved-model"
)

// ModelResultsBinding ties one model artifact to its TLC configuration and
// its executed results record.
type ModelResultsBinding struct {
	Story       string
	Module      string
	TLAPath     string
	CfgPath     string
	ResultsPath string
	SchemaPath  string
}

// ModelResultsBindings returns every model artifact that must carry an
// executed results record. The US-006 connection model is deliberately NOT
// in this set: its executed record lives in
// assurance/concurrency/plan.json#model_check.executed_run and is validated
// by lane B, and duplicating it here would create two authorities for one
// run.
func ModelResultsBindings() []ModelResultsBinding {
	return []ModelResultsBinding{
		{
			Story:       "US-012",
			Module:      FrameModelModuleName,
			TLAPath:     FrameModelTLAPath,
			CfgPath:     FrameModelCfgPath,
			ResultsPath: FrameModelResultsPath,
			SchemaPath:  ModelResultsSchemaPath,
		},
		{
			Story:       "US-016",
			Module:      CloseModelModuleName,
			TLAPath:     CloseModelTLAPath,
			CfgPath:     CloseModelCfgPath,
			ResultsPath: CloseModelResultsPath,
			SchemaPath:  ModelResultsSchemaPath,
		},
	}
}

type modelResultsDocument struct {
	SchemaRef                string                 `json:"$schema"`
	SchemaVersion            string                 `json:"schema_version"`
	Kind                     string                 `json:"kind"`
	Story                    string                 `json:"story"`
	AcceptanceCriterion      string                 `json:"acceptance_criterion"`
	Model                    modelResultsModel      `json:"model"`
	Assurance                string                 `json:"assurance"`
	IndependentReviewClaimed bool                   `json:"independent_review_claimed"`
	ClaimCeiling             string                 `json:"claim_ceiling"`
	Backend                  modelResultsBackend    `json:"backend"`
	Execution                modelResultsExecution  `json:"execution"`
	Bounds                   []modelResultsBound    `json:"bounds"`
	Invariants               []modelResultsCheck    `json:"invariants"`
	Properties               []modelResultsCheck    `json:"properties"`
	StateSpace               modelResultsStateSpace `json:"state_space"`
	SeededDefects            []modelResultsDefect   `json:"seeded_defects"`
	Violations               []modelResultsViol     `json:"violations"`
	Findings                 []modelResultsFinding  `json:"findings"`
	HonestyNotes             []string               `json:"honesty_notes"`
	Production               bool                   `json:"production"`
	Publication              bool                   `json:"publication"`
}

type modelResultsModel struct {
	Module    string `json:"module"`
	TLAPath   string `json:"tla_path"`
	CfgPath   string `json:"cfg_path"`
	TLASHA256 string `json:"tla_sha256"`
	CfgSHA256 string `json:"cfg_sha256"`
	StagedAs  string `json:"staged_as"`
}

type modelResultsBackend struct {
	BackendID string           `json:"backend_id"`
	Tool      modelResultsTool `json:"tool"`
	JVM       string           `json:"jvm"`
}

type modelResultsTool struct {
	Artifact      string `json:"artifact"`
	PinnedRelease string `json:"pinned_release"`
	SourceURL     string `json:"source_url"`
	SHA256        string `json:"sha256"`
	Bytes         int    `json:"bytes"`
	SANYBanner    string `json:"sany_banner"`
	TLCBanner     string `json:"tlc_banner"`
}

type modelResultsExecution struct {
	SbxStatus       string                `json:"sbx_status"`
	AttemptID       string                `json:"attempt_id"`
	Authorization   string                `json:"authorization"`
	Sandbox         string                `json:"sandbox"`
	SANY            modelResultsStep      `json:"sany"`
	TLC             modelResultsStep      `json:"tlc"`
	Receipts        []modelResultsReceipt `json:"receipts"`
	Window          string                `json:"window"`
	RuntimeObserved string                `json:"runtime_observed"`
}

type modelResultsStep struct {
	Argv     string `json:"argv"`
	ExitCode int    `json:"exit_code"`
	Observed string `json:"observed"`
}

type modelResultsReceipt struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

type modelResultsBound struct {
	Constant  string `json:"constant"`
	Value     int    `json:"value"`
	Rationale string `json:"rationale"`
}

type modelResultsCheck struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Statement   string `json:"statement"`
	FalsifiedBy string `json:"falsified_by"`
	Outcome     string `json:"outcome"`
}

type modelResultsStateSpace struct {
	StatesGenerated   int    `json:"states_generated"`
	DistinctStates    int    `json:"distinct_states"`
	StatesLeftOnQueue int    `json:"states_left_on_queue"`
	Depth             int    `json:"depth"`
	Source            string `json:"source"`
}

type modelResultsDefect struct {
	DefectID      string `json:"defect_id"`
	Mutation      string `json:"mutation"`
	Outcome       string `json:"outcome"`
	ExitCode      int    `json:"exit_code"`
	ViolatedCheck string `json:"violated_check"`
	ReceiptPath   string `json:"receipt_path"`
}

type modelResultsViol struct {
	Check          string `json:"check"`
	Kind           string `json:"kind"`
	Counterexample string `json:"counterexample"`
	ReceiptPath    string `json:"receipt_path"`
}

type modelResultsFinding struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Statement   string `json:"statement"`
	Disposition string `json:"disposition"`
}

// ValidateModelResults applies the executed-record contract for one model
// binding against the tree rooted at root. Every finding is blocking: a
// results record that cannot be substantiated is not a pass.
func ValidateModelResults(root string, binding ModelResultsBinding) []ModelFinding {
	absolute := func(relative string) string {
		return filepath.Join(root, filepath.FromSlash(relative))
	}
	finding := func(code, detail string) ModelFinding {
		return mpFinding(code, binding.ResultsPath, detail)
	}

	resultsData, err := os.ReadFile(absolute(binding.ResultsPath))
	if err != nil {
		return []ModelFinding{finding("MODEL_RESULTS_ABSENT",
			"model artifact "+binding.TLAPath+" ships without its executed results record: "+err.Error())}
	}

	var findings []ModelFinding

	var rawDocument any
	if err := vendorprotocol.DecodeStrict(resultsData, &rawDocument); err != nil {
		return append(findings, finding("MODEL_RESULTS_INVALID",
			"results record is not strict canonical JSON: "+err.Error()))
	}
	schemaData, schemaErr := os.ReadFile(absolute(binding.SchemaPath))
	if schemaErr != nil {
		findings = append(findings, finding("MODEL_RESULTS_SCHEMA_ABSENT",
			"schema "+binding.SchemaPath+" is absent; the results record cannot be schema-validated"))
	} else if err := validateAgainstSchema(binding.SchemaPath, schemaData, rawDocument); err != nil {
		findings = append(findings, finding("MODEL_RESULTS_SCHEMA_VALIDATION_FAILED",
			"schema validation failed: "+compactError(err)))
	}

	var document modelResultsDocument
	if err := vendorprotocol.DecodeStrict(resultsData, &document); err != nil {
		return append(findings, finding("MODEL_RESULTS_INVALID",
			"results record does not decode into the model-results shape: "+err.Error()))
	}

	// --- identity ----------------------------------------------------------
	if document.Story != binding.Story {
		findings = append(findings, finding("MODEL_RESULTS_BINDING_MISMATCH",
			"results record claims story "+document.Story+", expected "+binding.Story))
	}
	if document.Model.Module != binding.Module {
		findings = append(findings, finding("MODEL_RESULTS_BINDING_MISMATCH",
			"results record names module "+document.Model.Module+", expected "+binding.Module))
	}
	if document.Model.TLAPath != binding.TLAPath || document.Model.CfgPath != binding.CfgPath {
		findings = append(findings, finding("MODEL_RESULTS_BINDING_MISMATCH",
			"results record names artifacts "+document.Model.TLAPath+" / "+document.Model.CfgPath+
				", expected "+binding.TLAPath+" / "+binding.CfgPath))
	}
	if want := binding.Module + ".tla"; document.Model.StagedAs != want {
		findings = append(findings, finding("MODEL_RESULTS_BINDING_MISMATCH",
			"results record stages the model as "+document.Model.StagedAs+", expected "+want))
	}

	// --- artifacts bound to bytes ------------------------------------------
	for _, pair := range []struct {
		path     string
		recorded string
	}{
		{binding.TLAPath, document.Model.TLASHA256},
		{binding.CfgPath, document.Model.CfgSHA256},
	} {
		actual, digestErr := modelResultsDigestFile(absolute(pair.path))
		if digestErr != nil {
			findings = append(findings, finding("MODEL_RESULTS_DIGEST_MISMATCH",
				"cannot re-hash "+pair.path+": "+digestErr.Error()))
			continue
		}
		if actual != pair.recorded {
			findings = append(findings, finding("MODEL_RESULTS_DIGEST_MISMATCH",
				pair.path+": record says "+pair.recorded+", bytes hash to "+actual))
		}
	}

	// --- assurance ceilings -------------------------------------------------
	if document.Assurance != preflightAssurance || document.IndependentReviewClaimed {
		findings = append(findings, finding("MODEL_RESULTS_ASSURANCE_OVERCLAIM",
			"a model check run by its own author is "+preflightAssurance+
				" with independent_review_claimed false; record says "+document.Assurance+
				" / "+strconv.FormatBool(document.IndependentReviewClaimed)))
	}
	if document.ClaimCeiling != modelResultsCeiling {
		findings = append(findings, finding("MODEL_RESULTS_CEILING_OVERCLAIM",
			"an abstract model check is capped at "+modelResultsCeiling+
				" without a reviewed composition/refinement link; record claims "+document.ClaimCeiling))
	}
	if document.Production || document.Publication {
		findings = append(findings, finding("MODEL_RESULTS_ASSURANCE_OVERCLAIM",
			"model-check records are never production or publication artifacts"))
	}

	// --- checker identity ---------------------------------------------------
	if !isFullSha256Digest(document.Backend.Tool.SHA256) {
		findings = append(findings, finding("MODEL_RESULTS_TOOL_UNDIGESTED",
			"the checker binary must be pinned by a full sha256 digest recorded at fetch; got "+
				strconv.Quote(document.Backend.Tool.SHA256)))
	}

	// --- execution substantiation -------------------------------------------
	executed := document.Execution.SbxStatus == "EXECUTED_IN_SBX" ||
		document.Execution.SbxStatus == "EXECUTED_ON_HOST_SBX_PENDING"
	if !executed {
		findings = append(findings, finding("MODEL_RESULTS_EXECUTION_UNSUBSTANTIATED",
			"sbx_status "+document.Execution.SbxStatus+
				" cannot carry state counts, outcomes, or receipts; an unexecuted model has no results"))
	}
	if executed && (document.Execution.AttemptID == "" || document.Execution.Authorization == "") {
		findings = append(findings, finding("MODEL_RESULTS_EXECUTION_UNSUBSTANTIATED",
			"an executed record must cite its attempt id and its owner authorization"))
	}
	if len(document.Execution.Receipts) == 0 {
		findings = append(findings, finding("MODEL_RESULTS_RECEIPT_UNVERIFIED",
			"an executed record must carry at least one verbatim checker-output receipt"))
	}
	for _, receipt := range document.Execution.Receipts {
		actual, digestErr := modelResultsDigestFile(absolute(receipt.Path))
		if digestErr != nil {
			findings = append(findings, finding("MODEL_RESULTS_RECEIPT_UNVERIFIED",
				"receipt "+receipt.Path+" is not readable in this tree: "+digestErr.Error()))
			continue
		}
		if actual != receipt.SHA256 {
			findings = append(findings, finding("MODEL_RESULTS_RECEIPT_UNVERIFIED",
				"receipt "+receipt.Path+": record says "+receipt.SHA256+", bytes hash to "+actual))
		}
		if info, statErr := os.Stat(absolute(receipt.Path)); statErr == nil && int(info.Size()) != receipt.Bytes {
			findings = append(findings, finding("MODEL_RESULTS_RECEIPT_UNVERIFIED",
				fmt.Sprintf("receipt %s: record says %d bytes, file is %d bytes",
					receipt.Path, receipt.Bytes, info.Size())))
		}
	}

	// --- the cfg is the authority on what was checked -----------------------
	cfgText, cfgFailure := mpReadText(absolute(binding.CfgPath))
	if cfgFailure != nil {
		findings = append(findings, *cfgFailure)
		return modelResultsSorted(findings)
	}
	cfg, cfgFindings := mpParseCfg(cfgText)
	findings = append(findings, cfgFindings...)

	findings = append(findings,
		modelResultsCheckSet(binding, "invariant", cfg.Invariants, document.Invariants)...)
	findings = append(findings,
		modelResultsCheckSet(binding, "property", cfg.Properties, document.Properties)...)

	recordedBounds := map[string]int{}
	for _, bound := range document.Bounds {
		recordedBounds[bound.Constant] = bound.Value
	}
	var boundNames []string
	for name := range cfg.Constants {
		boundNames = append(boundNames, name)
	}
	sort.Strings(boundNames)
	for _, name := range boundNames {
		want, convErr := strconv.Atoi(cfg.Constants[name])
		if convErr != nil {
			continue
		}
		got, present := recordedBounds[name]
		if !present {
			findings = append(findings, finding("MODEL_RESULTS_BOUND_MISMATCH",
				"cfg assigns constant "+name+" but the results record states no bound for it"))
			continue
		}
		if got != want {
			findings = append(findings, finding("MODEL_RESULTS_BOUND_MISMATCH",
				fmt.Sprintf("constant %s: cfg assigns %d, results record states %d", name, want, got)))
		}
	}
	for _, bound := range document.Bounds {
		if _, declared := cfg.Constants[bound.Constant]; !declared {
			findings = append(findings, finding("MODEL_RESULTS_BOUND_MISMATCH",
				"results record states a bound for "+bound.Constant+" which the cfg does not assign"))
		}
	}

	// --- outcomes, violations, and the checker's own exit -------------------
	violated := map[string]bool{}
	for _, entry := range append(append([]modelResultsCheck{}, document.Invariants...),
		document.Properties...) {
		if entry.FalsifiedBy == "" {
			findings = append(findings, finding("MODEL_RESULTS_FALSIFICATION_MISSING",
				entry.Name+" carries no falsification note; an unfalsifiable check establishes nothing"))
		}
		switch entry.Outcome {
		case "Violated":
			violated[entry.Name] = true
		case "NotChecked":
			findings = append(findings, finding("MODEL_RESULTS_CHECK_SET_MISMATCH",
				entry.Name+" is listed in the shipped cfg but recorded NotChecked; the cfg is what ran"))
		}
	}
	recordedViolations := map[string]bool{}
	for _, violation := range document.Violations {
		recordedViolations[violation.Check] = true
		if !violated[violation.Check] {
			findings = append(findings, finding("MODEL_RESULTS_VIOLATION_UNRECORDED",
				"violation of "+violation.Check+" has no matching Violated outcome"))
		}
	}
	var violatedNames []string
	for name := range violated {
		violatedNames = append(violatedNames, name)
	}
	sort.Strings(violatedNames)
	for _, name := range violatedNames {
		if !recordedViolations[name] {
			findings = append(findings, finding("MODEL_RESULTS_VIOLATION_UNRECORDED",
				name+" is recorded Violated with no counterexample entry; a violation is reported, never suppressed"))
		}
	}

	clean := len(violated) == 0 && len(document.Violations) == 0
	if clean && document.Execution.TLC.ExitCode != 0 {
		findings = append(findings, finding("MODEL_RESULTS_EXIT_INCONSISTENT",
			fmt.Sprintf("TLC exited %d but no violation is recorded; a nonzero checker exit is a finding",
				document.Execution.TLC.ExitCode)))
	}
	if !clean && document.Execution.TLC.ExitCode == 0 {
		findings = append(findings, finding("MODEL_RESULTS_EXIT_INCONSISTENT",
			"violations are recorded but TLC exited 0; the recorded exit does not match the recorded outcome"))
	}
	if document.Execution.SANY.ExitCode != 0 {
		findings = append(findings, finding("MODEL_RESULTS_EXIT_INCONSISTENT",
			fmt.Sprintf("SANY exited %d; a model that does not parse and level-check has no results",
				document.Execution.SANY.ExitCode)))
	}

	// --- state space --------------------------------------------------------
	space := document.StateSpace
	if space.DistinctStates > space.StatesGenerated {
		findings = append(findings, finding("MODEL_RESULTS_STATE_SPACE_INCOHERENT",
			fmt.Sprintf("distinct states %d exceed generated states %d",
				space.DistinctStates, space.StatesGenerated)))
	}
	if clean && space.StatesLeftOnQueue != 0 {
		findings = append(findings, finding("MODEL_RESULTS_STATE_SPACE_INCOHERENT",
			fmt.Sprintf("%d states left on the queue is not an exhausted state space",
				space.StatesLeftOnQueue)))
	}
	if space.Depth > space.DistinctStates {
		findings = append(findings, finding("MODEL_RESULTS_STATE_SPACE_INCOHERENT",
			fmt.Sprintf("search depth %d exceeds the distinct-state count %d", space.Depth,
				space.DistinctStates)))
	}

	// --- seeded defects: the non-vacuity evidence ---------------------------
	// A check that no mutation can falsify establishes nothing, so every
	// recorded mutation must have been RUN (its receipt digest-bound above),
	// must name a check the cfg actually runs, and — when it was killed —
	// must carry the nonzero checker exit that killed it. A SURVIVING
	// mutation is a finding about the checks and must be disclosed as one;
	// silently listing a survivor is exactly the failure mode this rule
	// exists to prevent.
	checkNames := map[string]bool{}
	for _, entry := range append(append([]modelResultsCheck{}, document.Invariants...),
		document.Properties...) {
		checkNames[entry.Name] = true
	}
	receiptPaths := map[string]bool{}
	for _, receipt := range document.Execution.Receipts {
		receiptPaths[receipt.Path] = true
	}
	findingIDs := map[string]bool{}
	for _, entry := range document.Findings {
		findingIDs[entry.ID] = true
	}
	for _, defect := range document.SeededDefects {
		if !receiptPaths[defect.ReceiptPath] {
			findings = append(findings, finding("MODEL_RESULTS_DEFECT_UNSUBSTANTIATED",
				"seeded defect "+defect.DefectID+" cites receipt "+defect.ReceiptPath+
					" which is not digest-bound in execution.receipts"))
		}
		switch defect.Outcome {
		case "Killed":
			if defect.ExitCode == 0 {
				findings = append(findings, finding("MODEL_RESULTS_DEFECT_UNSUBSTANTIATED",
					"seeded defect "+defect.DefectID+" is recorded Killed with checker exit 0"))
			}
			if !checkNames[defect.ViolatedCheck] {
				findings = append(findings, finding("MODEL_RESULTS_DEFECT_UNSUBSTANTIATED",
					"seeded defect "+defect.DefectID+" names violated check "+
						strconv.Quote(defect.ViolatedCheck)+" which this cfg does not check"))
			}
		case "Survived":
			if defect.ExitCode != 0 {
				findings = append(findings, finding("MODEL_RESULTS_DEFECT_UNSUBSTANTIATED",
					"seeded defect "+defect.DefectID+" is recorded Survived with a nonzero checker exit"))
			}
			if !findingIDs[defect.DefectID] {
				findings = append(findings, finding("MODEL_RESULTS_DEFECT_SURVIVOR_UNDISCLOSED",
					"seeded defect "+defect.DefectID+
						" survived: a mutation the checks cannot kill is a finding and must appear in findings under the same id"))
			}
		}
	}

	// --- honest disclosure --------------------------------------------------
	if document.Execution.SbxStatus == "EXECUTED_ON_HOST_SBX_PENDING" {
		disclosed := false
		for _, note := range document.HonestyNotes {
			if strings.Contains(note, "host") {
				disclosed = true
			}
		}
		if !disclosed {
			findings = append(findings, finding("MODEL_RESULTS_DISCLOSURE_MISSING",
				"a host-side run must disclose that the sandbox leg is pending in honesty_notes"))
		}
	}
	for _, entry := range document.Findings {
		if entry.Disposition == "FIX_REQUIRED" {
			findings = append(findings, finding("MODEL_RESULTS_OPEN_FIX_REQUIRED",
				"finding "+entry.ID+" is marked FIX_REQUIRED and is still open in this record"))
		}
	}

	return modelResultsSorted(findings)
}

// modelResultsCheckSet compares the cfg's checked names with the record's,
// in both directions.
func modelResultsCheckSet(binding ModelResultsBinding, kind string, cfgNames []string,
	recorded []modelResultsCheck) []ModelFinding {
	var findings []ModelFinding
	inRecord := map[string]bool{}
	for _, entry := range recorded {
		inRecord[entry.Name] = true
		if entry.Kind != kind {
			findings = append(findings, mpFinding("MODEL_RESULTS_CHECK_SET_MISMATCH",
				binding.ResultsPath, entry.Name+" is recorded as a "+entry.Kind+
					" but the cfg lists it under "+strings.ToUpper(kind)))
		}
	}
	inCfg := map[string]bool{}
	for _, name := range cfgNames {
		inCfg[name] = true
		if !inRecord[name] {
			findings = append(findings, mpFinding("MODEL_RESULTS_CHECK_SET_MISMATCH",
				binding.ResultsPath, "cfg checks "+kind+" "+name+
					" but the results record does not account for it"))
		}
	}
	var extra []string
	for _, entry := range recorded {
		if !inCfg[entry.Name] {
			extra = append(extra, entry.Name)
		}
	}
	sort.Strings(extra)
	for _, name := range extra {
		findings = append(findings, mpFinding("MODEL_RESULTS_CHECK_SET_MISMATCH",
			binding.ResultsPath, "results record accounts for "+kind+" "+name+
				" which the shipped cfg does not check"))
	}
	return findings
}

// modelResultsJavaRoot resolves the quarantined org/java_websocket package
// root so the model artifacts' \* JAVA: citations resolve against real
// bytes; an empty answer downgrades citation checking to format-only, which
// the model validator reports as an advisory rather than passing silently.
func modelResultsJavaRoot(root string) string {
	treePath, err := portplan.EnsureQuarantinedSource(root)
	if err != nil {
		return ""
	}
	return filepath.Join(treePath, "src", "main", "java", "org", "java_websocket")
}

func modelResultsDigestFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func modelResultsSorted(findings []ModelFinding) []ModelFinding {
	sort.SliceStable(findings, func(left, right int) bool {
		if findings[left].Code != findings[right].Code {
			return findings[left].Code < findings[right].Code
		}
		return findings[left].Detail < findings[right].Detail
	})
	return findings
}

// evaluateModelResults wires the model-results contract into the formal
// preflight. It runs for every binding whose MODEL ARTIFACT is present in
// the tree: presence of the model is what creates the obligation to have
// run it. Trees that do not ship the artifact (the US-006 replay fixtures,
// which predate these models and carry their own frozen digests) are
// unaffected, and trees that do ship it fail closed when the executed
// record is missing or unsubstantiated.
func evaluateModelResults(evaluation *formalEvaluation, verdict *PreflightVerdict) {
	for _, binding := range ModelResultsBindings() {
		if _, present := evaluation.readFile(binding.TLAPath); !present {
			continue
		}
		_, resultsPresent := evaluation.readFile(binding.ResultsPath)
		_, schemaPresent := evaluation.readFile(binding.SchemaPath)
		verdict.Documents = append(verdict.Documents, PreflightDocumentStatus{
			Path:          binding.ResultsPath,
			SchemaPath:    binding.SchemaPath,
			Present:       resultsPresent,
			SchemaPresent: schemaPresent,
		})
		for _, finding := range ValidateModelResults(evaluation.root, binding) {
			disposition := vendorprotocol.Block
			if finding.Severity == SeverityAdvisory {
				disposition = vendorprotocol.DegradeNonAssurance
			}
			evaluation.add(finding.Code, disposition, binding.ResultsPath, "",
				trimRootPrefix(evaluation.root, finding.Detail))
		}
		for _, finding := range ValidateTLAModel(binding.Module,
			filepath.Join(evaluation.root, filepath.FromSlash(binding.TLAPath)),
			filepath.Join(evaluation.root, filepath.FromSlash(binding.CfgPath)),
			modelResultsJavaRoot(evaluation.root)) {
			disposition := vendorprotocol.Block
			if finding.Severity == SeverityAdvisory {
				disposition = vendorprotocol.DegradeNonAssurance
			}
			evaluation.add(finding.Code, disposition, binding.TLAPath,
				trimRootPrefix(evaluation.root, finding.Path),
				trimRootPrefix(evaluation.root, finding.Detail))
		}
	}
}
