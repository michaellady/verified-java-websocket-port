package javabind

import (
	"encoding/json"
	"fmt"
	"strings"
)

// VariantBaseline is the run variant name for an unmutated execution.
const VariantBaseline = "BASELINE"

// Run is one executed scenario: the exact request line offered to the adapter
// and the exact response line it produced.
type Run struct {
	RunID            string `json:"run_id"`
	Variant          string `json:"variant"`
	ScenarioID       string `json:"scenario_id"`
	RequestCanonical string `json:"request_canonical"`
	RequestDigest    string `json:"request_digest"`
	ResponseLine     string `json:"response_line"`
	ResponseDigest   string `json:"response_digest"`
}

// SourceConstruct is one resolved declaration in the pinned Java source.
type SourceConstruct struct {
	ObligationID           string   `json:"obligation_id"`
	ChainMember            string   `json:"chain_member"`
	IsChainRoot            bool     `json:"is_chain_root"`
	SourceFile             string   `json:"source_file"`
	FileSHA256             string   `json:"file_sha256"`
	Start                  int      `json:"start"`
	End                    int      `json:"end"`
	SpanSHA256             string   `json:"span_sha256"`
	StructureFingerprint   string   `json:"structure_fingerprint"`
	DeclaredParameterTypes []string `json:"declared_parameter_types"`
	DeclaredReturnType     string   `json:"declared_return_type"`
	HasBody                bool     `json:"has_body"`
	CatalogDescriptor      string   `json:"catalog_descriptor"`
	DescriptorAgreement    string   `json:"descriptor_agreement"`
}

// MutationApplication records where a mutation actually landed, and the identity
// of the two repackaged runtime archives it produced: the control, built by
// recompiling the unmutated file, and the mutant, built by recompiling the
// spliced file. Both are compiled and repackaged identically, so the only
// difference between them is the recorded edit.
type MutationApplication struct {
	MutationID        string `json:"mutation_id"`
	ObligationID      string `json:"obligation_id"`
	ChainMember       string `json:"chain_member"`
	SourceFile        string `json:"source_file"`
	AbsoluteOffset    int    `json:"absolute_offset"`
	Length            int    `json:"length"`
	RemovedSHA256     string `json:"removed_sha256"`
	ReplacementSHA256 string `json:"replacement_sha256"`
	MutatedFileSHA256 string `json:"mutated_file_sha256"`
	ControlRuntime    string `json:"control_runtime_sha256"`
	MutantRuntime     string `json:"mutant_runtime_sha256"`
}

// Toolchain records the executing environment without pretending it is portable.
type Toolchain struct {
	OS                    string   `json:"os"`
	Arch                  string   `json:"arch"`
	JavaVersion           string   `json:"java_version"`
	AdapterSourceDigests  []string `json:"adapter_source_digests"`
	AdapterJarSHA256      string   `json:"adapter_jar_sha256"`
	MutantDriverSHA256    string   `json:"mutant_driver_source_sha256"`
	MutantDriverJarSHA256 string   `json:"mutant_driver_jar_sha256"`
	RuntimeSupportSHA256  []string `json:"runtime_support_sha256"`
}

// Assurance is the fixed labelling every artifact here carries.
type Assurance struct {
	Assurance              string `json:"assurance"`
	IndependentReviewClaim bool   `json:"independent_review_claimed"`
	Production             bool   `json:"production"`
	Publication            bool   `json:"publication"`
	Signing                bool   `json:"signing"`
}

// DefaultAssurance is the only labelling this package emits.
func DefaultAssurance() Assurance {
	return Assurance{Assurance: "OWNER_ATTESTED_NOT_INDEPENDENT"}
}

// Receipt is the retained, self-contained evidence produced by the executed lane.
type Receipt struct {
	SchemaVersion    string                `json:"schema_version"`
	ReceiptID        string                `json:"receipt_id"`
	GeneratedAt      string                `json:"generated_at"`
	Assurance        Assurance             `json:"assurance"`
	Spec             ArtifactIdentity      `json:"spec"`
	Catalog          ArtifactIdentity      `json:"catalog"`
	PinnedSource     PinnedSource          `json:"pinned_source"`
	PinnedRuntime    PinnedRuntime         `json:"pinned_runtime"`
	Toolchain        Toolchain             `json:"toolchain"`
	SourceConstructs []SourceConstruct     `json:"source_constructs"`
	Mutations        []MutationApplication `json:"mutation_applications"`
	Runs             []Run                 `json:"runs"`
}

// DecodeReceipt parses and structurally validates a receipt.
func DecodeReceipt(data []byte) (Receipt, error) {
	var receipt Receipt
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return Receipt{}, fmt.Errorf("javabind: decode receipt: %w", err)
	}
	if receipt.SchemaVersion != "1.0.0" || receipt.ReceiptID != "java-formal-bindings" {
		return Receipt{}, fmt.Errorf("javabind: receipt identity is wrong")
	}
	if receipt.Assurance.Assurance != "OWNER_ATTESTED_NOT_INDEPENDENT" || receipt.Assurance.IndependentReviewClaim ||
		receipt.Assurance.Production || receipt.Assurance.Publication || receipt.Assurance.Signing {
		return Receipt{}, fmt.Errorf("javabind: receipt assurance labelling is not OWNER_ATTESTED_NOT_INDEPENDENT")
	}
	return receipt, nil
}

// Run finds one retained run by scenario and variant.
func (r Receipt) Run(scenarioID, variant string) (Run, bool) {
	for _, run := range r.Runs {
		if run.ScenarioID == scenarioID && run.Variant == variant {
			return run, true
		}
	}
	return Run{}, false
}

// Construct finds one retained construct.
func (r Receipt) Construct(obligationID, member string) (SourceConstruct, bool) {
	for _, construct := range r.SourceConstructs {
		if construct.ObligationID == obligationID && construct.ChainMember == member {
			return construct, true
		}
	}
	return SourceConstruct{}, false
}

// MutationApplication finds one retained mutation application.
func (r Receipt) MutationApplication(mutationID string) (MutationApplication, bool) {
	for _, mutation := range r.Mutations {
		if mutation.MutationID == mutationID {
			return mutation, true
		}
	}
	return MutationApplication{}, false
}

// VerifyDigests recomputes every digest a receipt asserts about its own retained
// bytes. It is the first line of defence against a receipt that was edited to
// make a check pass.
func (r Receipt) VerifyDigests(spec Spec) error {
	for _, run := range r.Runs {
		if got := Digest([]byte(run.ResponseLine)); got != run.ResponseDigest {
			return fmt.Errorf("javabind: run %q response digest is %s but the receipt records %s", run.RunID, got, run.ResponseDigest)
		}
		scenario, ok := spec.Scenario(run.ScenarioID)
		if !ok {
			return fmt.Errorf("javabind: run %q references scenario %q, which the spec does not declare", run.RunID, run.ScenarioID)
		}
		line, digest, err := EncodeRequest(scenario)
		if err != nil {
			return err
		}
		if string(line) != run.RequestCanonical {
			return fmt.Errorf("javabind: run %q retained request bytes do not re-encode from the spec scenario", run.RunID)
		}
		if digest != run.RequestDigest {
			return fmt.Errorf("javabind: run %q request digest does not recompute", run.RunID)
		}
		var response map[string]any
		if err := json.Unmarshal([]byte(run.ResponseLine), &response); err != nil {
			return fmt.Errorf("javabind: run %q response is not JSON: %w", run.RunID, err)
		}
		if got, _ := response["request_digest"].(string); got != run.RequestDigest {
			return fmt.Errorf("javabind: run %q response does not echo the request digest", run.RunID)
		}
		if got, _ := response["request_id"].(string); got != run.ScenarioID {
			return fmt.Errorf("javabind: run %q response does not echo the scenario id", run.RunID)
		}
		runtimeBlock, _ := response["runtime"].(map[string]any)
		if runtimeBlock == nil {
			return fmt.Errorf("javabind: run %q response does not bind a runtime", run.RunID)
		}
		if got, _ := runtimeBlock["artifact"].(string); got != r.PinnedRuntime.Artifact {
			return fmt.Errorf("javabind: run %q response binds artifact %q, not the pinned %q", run.RunID, got, r.PinnedRuntime.Artifact)
		}
		expected, err := r.expectedRuntimeFor(run)
		if err != nil {
			return err
		}
		if got, _ := runtimeBlock["sha256"].(string); got != expected {
			return fmt.Errorf("javabind: run %q response binds runtime %q, not the expected %q", run.RunID, got, expected)
		}
	}
	return nil
}

// expectedRuntimeFor says which archive a run must have loaded. A baseline must
// have loaded the pinned JAR; a control must have loaded the archive built from
// the unmutated source; a mutant must have loaded the archive built from the
// spliced source. Every one of those three digests is computed on the Go side.
func (r Receipt) expectedRuntimeFor(run Run) (string, error) {
	switch {
	case run.Variant == VariantBaseline:
		return r.PinnedRuntime.SHA256, nil
	case strings.HasPrefix(run.Variant, "CONTROL:"):
		application, ok := r.MutationApplication(strings.TrimPrefix(run.Variant, "CONTROL:"))
		if !ok {
			return "", fmt.Errorf("javabind: run %q names a mutation the receipt does not record", run.RunID)
		}
		return application.ControlRuntime, nil
	case strings.HasPrefix(run.Variant, "MUTANT:"):
		application, ok := r.MutationApplication(strings.TrimPrefix(run.Variant, "MUTANT:"))
		if !ok {
			return "", fmt.Errorf("javabind: run %q names a mutation the receipt does not record", run.RunID)
		}
		return application.MutantRuntime, nil
	}
	return "", fmt.Errorf("javabind: run %q has unknown variant %q", run.RunID, run.Variant)
}
