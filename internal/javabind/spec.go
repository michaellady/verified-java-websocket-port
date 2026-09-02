package javabind

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// CatalogDenominator is the size of the immutable semantic-obligation catalog.
// It is a constant of the programme, not of this package: partial coverage is
// reported as a fraction of it and is never renormalised.
const CatalogDenominator = 24

// ObservedStrength is the honest label for every Java-side binding this package
// produces. The catalog requires PRODUCTION_REFINEMENT, which is strictly
// stronger and which this package does not reach.
const ObservedStrength = "EXECUTED_OBSERVATION_WITH_MUTATION_SENSITIVITY"

// RequiredStrength is what the immutable catalog demands of every obligation.
const RequiredStrength = "PRODUCTION_REFINEMENT"

// ArtifactIdentity pins one file by content.
type ArtifactIdentity struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	GitBlob string `json:"git_blob,omitempty"`
}

// PinnedSource identifies the quarantined Java-WebSocket source tree.
type PinnedSource struct {
	ArchiveSHA256  string `json:"archive_sha256"`
	TreeDirectory  string `json:"tree_directory"`
	SourceRevision string `json:"source_revision"`
	SourceRoot     string `json:"source_root"`
}

// PinnedRuntime identifies the executed JAR.
type PinnedRuntime struct {
	Artifact string `json:"artifact"`
	SHA256   string `json:"sha256"`
}

// Step is one ordered element of an oracle scenario, in the adapter's own wire
// vocabulary.
type Step struct {
	Kind       string  `json:"kind"`
	DataBase64 string  `json:"data_base64,omitempty"`
	Action     string  `json:"action,omitempty"`
	Text       string  `json:"text,omitempty"`
	Opcode     string  `json:"opcode,omitempty"`
	Fin        *bool   `json:"fin,omitempty"`
	Code       *int    `json:"code,omitempty"`
	Reason     *string `json:"reason,omitempty"`
}

// Limits are the adapter limits a scenario declares.
type Limits struct {
	MaxInputBytes    int `json:"max_input_bytes"`
	MaxBufferedBytes int `json:"max_buffered_bytes"`
	MaxActions       int `json:"max_actions"`
	MaxFrames        int `json:"max_frames"`
	MaxOutputBytes   int `json:"max_output_bytes"`
}

// Scenario is one executable observation of the pinned runtime.
type Scenario struct {
	ScenarioID   string `json:"scenario_id"`
	Purpose      string `json:"purpose"`
	Role         string `json:"role"`
	InitialState string `json:"initial_state"`
	Steps        []Step `json:"steps"`
	Limits       Limits `json:"limits"`
}

// Predicate is one member of the closed predicate vocabulary. Nothing outside
// this vocabulary can be asserted, so a predicate cannot smuggle in prose.
type Predicate struct {
	Kind      string `json:"kind"`
	Direction string `json:"direction,omitempty"`
	EventType string `json:"event_type,omitempty"`
	Field     string `json:"field,omitempty"`
	Index     *int   `json:"index,omitempty"`
	String    string `json:"string,omitempty"`
	Number    *int   `json:"number,omitempty"`
}

// Witness pairs one scenario with one predicate over its retained response.
type Witness struct {
	ScenarioID string    `json:"scenario_id"`
	Predicate  Predicate `json:"predicate"`
}

// Clause is one conjunct of an obligation statement, written down once so the
// counting rule is mechanical rather than a judgement call at read time.
//
// Every clause carries its own mutation canary. A clause whose witnesses hold
// but which has no canary inside the bound chain is NOT satisfied: without a
// canary there is nothing tying the observation to the bound construct, and the
// clause would otherwise be discharged by behaviour implemented somewhere else
// entirely. Omitting the canary is how an honestly partial binding is spelled.
type Clause struct {
	ClauseID  string    `json:"clause_id"`
	Statement string    `json:"statement"`
	Witnesses []Witness `json:"witnesses"`
	Mutation  *Mutation `json:"mutation,omitempty"`
	NoCanary  string    `json:"no_canary_reason,omitempty"`
}

// Mutation is one exact, digest-anchored edit inside a bound declaration.
type Mutation struct {
	MutationID     string `json:"mutation_id"`
	ChainMember    string `json:"chain_member"`
	RelativeOffset int    `json:"relative_offset"`
	Length         int    `json:"length"`
	RemovedSHA256  string `json:"removed_sha256"`
	Replacement    string `json:"replacement"`
	ScenarioID     string `json:"scenario_id"`
	Expectation    string `json:"expectation"`
}

// Binding is one obligation's Java side.
type Binding struct {
	ObligationID   string   `json:"obligation_id"`
	CatalogSymbol  string   `json:"catalog_symbol"`
	SourceFile     string   `json:"source_file"`
	DeclaringType  string   `json:"declaring_type"`
	Chain          []string `json:"chain"`
	ChainRationale string   `json:"chain_rationale,omitempty"`
	Clauses        []Clause `json:"clauses"`
}

// Mutations returns every clause canary the binding declares, in clause order.
func (b Binding) Mutations() []Mutation {
	out := []Mutation{}
	for _, clause := range b.Clauses {
		if clause.Mutation != nil {
			out = append(out, *clause.Mutation)
		}
	}
	return out
}

// Unbound records, with a typed reason, an obligation this round does not bind.
type Unbound struct {
	ObligationID string `json:"obligation_id"`
	ReasonCode   string `json:"reason_code"`
	Detail       string `json:"detail"`
}

// UnboundReasonCodes is the closed vocabulary of reasons an obligation stays
// unbound. Anything outside it fails validation.
var UnboundReasonCodes = map[string]bool{
	"CATALOG_SYMBOL_SCOPE_MISMATCH":                true,
	"CATALOG_SYMBOL_NOT_ON_EXECUTED_PATH":          true,
	"INTERFACE_DECLARATION_NO_IMPLEMENTATION_SITE": true,
	"JAVA_CONSTRUCT_DOES_NOT_IMPLEMENT_CLAUSE":     true,
	"NOT_OBSERVABLE_THROUGH_ADAPTER":               true,
	"NOT_ATTEMPTED_THIS_ROUND":                     true,
}

// Spec is the complete, reviewable binding specification.
type Spec struct {
	SchemaVersion string           `json:"schema_version"`
	SpecID        string           `json:"spec_id"`
	Catalog       ArtifactIdentity `json:"catalog"`
	PinnedSource  PinnedSource     `json:"pinned_source"`
	PinnedRuntime PinnedRuntime    `json:"pinned_runtime"`
	Scenarios     []Scenario       `json:"scenarios"`
	Bindings      []Binding        `json:"bindings"`
	Unbound       []Unbound        `json:"unbound"`
}

// DecodeSpec parses and validates a specification document.
func DecodeSpec(data []byte) (Spec, error) {
	var spec Spec
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&spec); err != nil {
		return Spec{}, fmt.Errorf("javabind: decode spec: %w", err)
	}
	return spec, spec.Validate()
}

// Scenario returns the named scenario.
func (s Spec) Scenario(id string) (Scenario, bool) {
	for _, scenario := range s.Scenarios {
		if scenario.ScenarioID == id {
			return scenario, true
		}
	}
	return Scenario{}, false
}

// Validate enforces the structural rules the counting depends on.
func (s Spec) Validate() error {
	if s.SchemaVersion != "1.0.0" || s.SpecID != "java-formal-binding-spec" {
		return fmt.Errorf("javabind: spec identity is wrong")
	}
	if !isDigest(s.Catalog.SHA256) || s.Catalog.Path == "" {
		return fmt.Errorf("javabind: spec does not pin the catalog by content")
	}
	if !isDigest(s.PinnedSource.ArchiveSHA256) || s.PinnedSource.TreeDirectory == "" || s.PinnedSource.SourceRoot == "" {
		return fmt.Errorf("javabind: spec does not pin the Java source tree")
	}
	if !isDigest(s.PinnedRuntime.SHA256) || s.PinnedRuntime.Artifact == "" {
		return fmt.Errorf("javabind: spec does not pin the Java runtime")
	}
	seenScenario := map[string]bool{}
	for _, scenario := range s.Scenarios {
		if scenario.ScenarioID == "" || seenScenario[scenario.ScenarioID] {
			return fmt.Errorf("javabind: scenario id %q is empty or duplicated", scenario.ScenarioID)
		}
		seenScenario[scenario.ScenarioID] = true
		if scenario.Role != "client" && scenario.Role != "server" {
			return fmt.Errorf("javabind: scenario %q has role %q", scenario.ScenarioID, scenario.Role)
		}
		if len(scenario.Steps) == 0 {
			return fmt.Errorf("javabind: scenario %q has no steps", scenario.ScenarioID)
		}
	}
	seenObligation := map[string]bool{}
	seenMutation := map[string]bool{}
	for _, binding := range s.Bindings {
		if binding.ObligationID == "" || seenObligation[binding.ObligationID] {
			return fmt.Errorf("javabind: binding obligation %q is empty or duplicated", binding.ObligationID)
		}
		seenObligation[binding.ObligationID] = true
		if len(binding.Chain) == 0 {
			return fmt.Errorf("javabind: binding %q declares no chain", binding.ObligationID)
		}
		if len(binding.Clauses) == 0 {
			return fmt.Errorf("javabind: binding %q declares no clauses", binding.ObligationID)
		}
		seenClause := map[string]bool{}
		for _, clause := range binding.Clauses {
			if clause.ClauseID == "" || clause.Statement == "" || len(clause.Witnesses) == 0 {
				return fmt.Errorf("javabind: binding %q has an incomplete clause", binding.ObligationID)
			}
			if seenClause[clause.ClauseID] {
				return fmt.Errorf("javabind: binding %q repeats clause id %q", binding.ObligationID, clause.ClauseID)
			}
			seenClause[clause.ClauseID] = true
			clauseScenarios := map[string]bool{}
			for _, witness := range clause.Witnesses {
				if !seenScenario[witness.ScenarioID] {
					return fmt.Errorf("javabind: clause %q references unknown scenario %q", clause.ClauseID, witness.ScenarioID)
				}
				clauseScenarios[witness.ScenarioID] = true
				if err := witness.Predicate.Validate(); err != nil {
					return fmt.Errorf("javabind: clause %q: %w", clause.ClauseID, err)
				}
			}
			if clause.Mutation == nil {
				if clause.NoCanary == "" {
					return fmt.Errorf("javabind: clause %q declares no canary and gives no reason", clause.ClauseID)
				}
				continue
			}
			if clause.NoCanary != "" {
				return fmt.Errorf("javabind: clause %q declares both a canary and a no-canary reason", clause.ClauseID)
			}
			mutation := *clause.Mutation
			if mutation.MutationID == "" || seenMutation[mutation.MutationID] {
				return fmt.Errorf("javabind: clause %q has an empty or duplicated mutation id", clause.ClauseID)
			}
			seenMutation[mutation.MutationID] = true
			if !containsString(binding.Chain, mutation.ChainMember) {
				return fmt.Errorf("javabind: mutation %q edits %q, which is not in the bound chain", mutation.MutationID, mutation.ChainMember)
			}
			if mutation.Length <= 0 || mutation.RelativeOffset < 0 || !isDigest(mutation.RemovedSHA256) {
				return fmt.Errorf("javabind: mutation %q is not anchored by offset, length and digest", mutation.MutationID)
			}
			if !clauseScenarios[mutation.ScenarioID] {
				return fmt.Errorf("javabind: mutation %q runs scenario %q, which clause %q does not witness", mutation.MutationID, mutation.ScenarioID, clause.ClauseID)
			}
		}
	}
	for _, unbound := range s.Unbound {
		if seenObligation[unbound.ObligationID] {
			return fmt.Errorf("javabind: obligation %q is both bound and unbound", unbound.ObligationID)
		}
		if !UnboundReasonCodes[unbound.ReasonCode] {
			return fmt.Errorf("javabind: unbound obligation %q has reason code %q outside the closed vocabulary", unbound.ObligationID, unbound.ReasonCode)
		}
		if unbound.Detail == "" {
			return fmt.Errorf("javabind: unbound obligation %q has no detail", unbound.ObligationID)
		}
		seenObligation[unbound.ObligationID] = true
	}
	return nil
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func isDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, r := range value[7:] {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}

// SortedObligationIDs returns every obligation the spec mentions, bound or not.
func (s Spec) SortedObligationIDs() []string {
	ids := make([]string, 0, len(s.Bindings)+len(s.Unbound))
	for _, binding := range s.Bindings {
		ids = append(ids, binding.ObligationID)
	}
	for _, unbound := range s.Unbound {
		ids = append(ids, unbound.ObligationID)
	}
	sort.Strings(ids)
	return ids
}
