package javabind

import (
	"fmt"
	"sort"
)

// Binding states. Only CONNECTED counts toward the headline numerator.
const (
	StateConnected    = "CONNECTED"
	StatePartial      = "PARTIAL"
	StateDisconnected = "DISCONNECTED"
)

// WitnessResult is one evaluated predicate over one retained response.
type WitnessResult struct {
	ScenarioID string `json:"scenario_id"`
	Predicate  string `json:"predicate"`
	Satisfied  bool   `json:"satisfied"`
	Observed   string `json:"observed"`
}

// ClauseResult is one clause's verdict. A clause is satisfied only when every
// witness holds AND its own canary, inside the bound chain, flips one of them.
type ClauseResult struct {
	ClauseID          string          `json:"clause_id"`
	Statement         string          `json:"statement"`
	Satisfied         bool            `json:"satisfied"`
	WitnessesHold     bool            `json:"witnesses_hold"`
	Witnesses         []WitnessResult `json:"witnesses"`
	Mutation          *MutationResult `json:"mutation,omitempty"`
	NoCanaryReason    string          `json:"no_canary_reason,omitempty"`
	UnsatisfiedReason string          `json:"unsatisfied_reason,omitempty"`
}

// MutationResult records whether the obligation's canary flipped a predicate
// that held on the baseline, and names the one that flipped.
type MutationResult struct {
	MutationID       string `json:"mutation_id"`
	ScenarioID       string `json:"scenario_id"`
	ChainMember      string `json:"chain_member"`
	Applied          bool   `json:"applied"`
	ControlAgrees    bool   `json:"control_agrees_with_baseline"`
	Killed           bool   `json:"killed"`
	FlippedClauseID  string `json:"flipped_clause_id"`
	FlippedPredicate string `json:"flipped_predicate"`
	BaselineObserved string `json:"baseline_observed"`
	MutantObserved   string `json:"mutant_observed"`
	Detail           string `json:"detail,omitempty"`
}

// ObligationCoverage is one row of the projection, over the fixed denominator.
type ObligationCoverage struct {
	ObligationID        string         `json:"obligation_id"`
	CatalogStatement    string         `json:"catalog_statement"`
	CatalogSymbol       string         `json:"catalog_symbol"`
	BindingState        string         `json:"binding_state"`
	ReasonCode          string         `json:"reason_code,omitempty"`
	ReasonDetail        string         `json:"reason_detail,omitempty"`
	SourceFile          string         `json:"source_file,omitempty"`
	Chain               []string       `json:"chain,omitempty"`
	SpanSHA256          string         `json:"span_sha256,omitempty"`
	DescriptorAgreement string         `json:"descriptor_agreement,omitempty"`
	ObservedStrength    string         `json:"observed_strength,omitempty"`
	RequiredStrength    string         `json:"required_strength"`
	MeetsRequired       bool           `json:"meets_required_strength"`
	ClausesDeclared     int            `json:"clauses_declared,omitempty"`
	ClausesSatisfied    int            `json:"clauses_satisfied,omitempty"`
	CanariesKilled      int            `json:"canaries_killed,omitempty"`
	Clauses             []ClauseResult `json:"clauses,omitempty"`
}

// Counts are the derived numerators. Every one of them is recomputed from the
// receipt; none is transcribed.
type Counts struct {
	Denominator                    int `json:"denominator"`
	JavaBindingsConnected          int `json:"java_bindings_connected"`
	JavaBindingsPartial            int `json:"java_bindings_partial"`
	JavaBindingsDisconnected       int `json:"java_bindings_disconnected"`
	JavaMutationSensitive          int `json:"java_mutation_sensitive"`
	JavaBindingsAtRequiredStrength int `json:"java_bindings_at_required_strength"`
	Refinement                     int `json:"refinement"`
	Aggregate                      int `json:"aggregate"`
	// Clause-level denominators are reported separately so a binding with several
	// clauses can never read as several obligations, and so a partially witnessed
	// obligation is visible as the fraction it is.
	ClausesDeclared  int `json:"clauses_declared"`
	ClausesSatisfied int `json:"clauses_satisfied"`
	CanariesDeclared int `json:"canaries_declared"`
	CanariesKilled   int `json:"canaries_killed"`
}

// Projection is the derived coverage artifact.
type Projection struct {
	SchemaVersion    string               `json:"schema_version"`
	ProjectionID     string               `json:"projection_id"`
	CatalogID        string               `json:"catalog_id"`
	Assurance        Assurance            `json:"assurance"`
	ObservedStrength string               `json:"observed_strength"`
	RequiredStrength string               `json:"required_strength"`
	Claim            ProjectionClaim      `json:"claim"`
	Spec             ArtifactIdentity     `json:"spec"`
	Catalog          ArtifactIdentity     `json:"catalog"`
	Receipt          ArtifactIdentity     `json:"receipt"`
	PinnedSource     PinnedSource         `json:"pinned_source"`
	PinnedRuntime    PinnedRuntime        `json:"pinned_runtime"`
	Counts           Counts               `json:"counts"`
	Obligations      []ObligationCoverage `json:"obligations"`
}

// ProjectionClaim states the ceiling inside the artifact itself, so a reader who
// quotes only the JSON still gets the qualification.
type ProjectionClaim struct {
	Statement string   `json:"statement"`
	NotClaims []string `json:"not_claims"`
}

// DefaultClaim is the fixed claim text. It is deliberately not configurable.
func DefaultClaim() ProjectionClaim {
	return ProjectionClaim{
		Statement: "For each CONNECTED obligation: the immutable catalog's declared Java production symbol resolves " +
			"to exactly one declaration in the digest-pinned Java-WebSocket 1.6.0 source; every declared clause of " +
			"the obligation is witnessed by predicates over byte-exact responses of the pinned runtime executed out " +
			"of process; and each clause carries its own exact digest-anchored edit inside the bound declaration's " +
			"byte span which, delivered through a repackaged runtime archive whose recompiled-but-unmutated control " +
			"reproduces the baseline observation, flips a predicate of that clause which held on the baseline.",
		NotClaims: []string{
			"This is not a proof of the Java library; no prover or model checker is applied to Java-WebSocket 1.6.0.",
			"This is not 'formally verified'; that phrase is reserved here for named Kani-proved properties quoted with their bounds together with the refinement check.",
			"This does not establish Java-to-model, model-to-Rust or Java-to-Rust refinement; refinement remains 0/24.",
			"This does not move aggregate obligation coverage, which remains 0/24.",
			"Executed observations are finite scenario sets with declared bounds; they say nothing about inputs outside those sets.",
			"This is owner-executed on a single host and is not independent.",
			"A satisfied binding reports what the pinned Java did; it does not adjudicate that behaviour as correct. RFC 6455 remains normative.",
		},
	}
}

// Derive recomputes the whole projection from the spec, the receipt and the
// immutable catalog. It is the only place counts are produced.
func Derive(spec Spec, receipt Receipt, catalog Catalog, specIdentity, catalogIdentity, receiptIdentity ArtifactIdentity) (Projection, error) {
	if err := receipt.VerifyDigests(spec); err != nil {
		return Projection{}, err
	}
	if receipt.Catalog.SHA256 != spec.Catalog.SHA256 {
		return Projection{}, fmt.Errorf("javabind: receipt and spec pin different catalogs")
	}
	if catalogIdentity.SHA256 != spec.Catalog.SHA256 {
		return Projection{}, fmt.Errorf("javabind: the catalog on disk is not the catalog the spec pins")
	}
	if len(catalog.Obligations) != CatalogDenominator {
		return Projection{}, fmt.Errorf("javabind: catalog holds %d obligations, not the fixed denominator %d", len(catalog.Obligations), CatalogDenominator)
	}

	bindings := map[string]Binding{}
	for _, binding := range spec.Bindings {
		bindings[binding.ObligationID] = binding
	}
	unbound := map[string]Unbound{}
	for _, entry := range spec.Unbound {
		unbound[entry.ObligationID] = entry
	}
	for id := range bindings {
		if _, ok := catalog.Obligation(id); !ok {
			return Projection{}, fmt.Errorf("javabind: spec binds %q, which is not in the immutable catalog", id)
		}
	}
	for id := range unbound {
		if _, ok := catalog.Obligation(id); !ok {
			return Projection{}, fmt.Errorf("javabind: spec declares %q unbound, which is not in the immutable catalog", id)
		}
	}

	rows := make([]ObligationCoverage, 0, CatalogDenominator)
	counts := Counts{Denominator: CatalogDenominator}
	for _, obligation := range catalog.Obligations {
		row := ObligationCoverage{
			ObligationID:     obligation.ObligationID,
			CatalogStatement: obligation.Statement,
			RequiredStrength: obligation.RequiredStrength,
			BindingState:     StateDisconnected,
		}
		if java, ok := catalog.JavaBinding(obligation.ObligationID); ok {
			row.CatalogSymbol = java.ProductionSymbol
		}
		binding, isBound := bindings[obligation.ObligationID]
		if !isBound {
			entry, ok := unbound[obligation.ObligationID]
			if !ok {
				return Projection{}, fmt.Errorf("javabind: obligation %q is neither bound nor given a typed unbound reason", obligation.ObligationID)
			}
			row.ReasonCode = entry.ReasonCode
			row.ReasonDetail = entry.Detail
			counts.JavaBindingsDisconnected++
			rows = append(rows, row)
			continue
		}
		if binding.CatalogSymbol != row.CatalogSymbol {
			return Projection{}, fmt.Errorf("javabind: binding for %q echoes symbol %q but the catalog declares %q",
				obligation.ObligationID, binding.CatalogSymbol, row.CatalogSymbol)
		}
		row.SourceFile = binding.SourceFile
		row.Chain = binding.Chain
		row.ObservedStrength = ObservedStrength
		row.MeetsRequired = false
		if root, ok := receipt.Construct(obligation.ObligationID, binding.Chain[0]); ok {
			row.SpanSHA256 = root.SpanSHA256
			row.DescriptorAgreement = root.DescriptorAgreement
		} else {
			return Projection{}, fmt.Errorf("javabind: receipt has no resolved construct for %q chain root %q", obligation.ObligationID, binding.Chain[0])
		}

		clauseResults, err := evaluateClauses(binding, receipt)
		if err != nil {
			return Projection{}, err
		}
		row.Clauses = clauseResults
		row.ClausesDeclared = len(clauseResults)
		allSatisfied := len(clauseResults) > 0
		for _, clause := range clauseResults {
			counts.ClausesDeclared++
			if clause.Satisfied {
				counts.ClausesSatisfied++
				row.ClausesSatisfied++
			} else {
				allSatisfied = false
			}
			if clause.Mutation != nil {
				counts.CanariesDeclared++
				if clause.Mutation.Killed {
					counts.CanariesKilled++
					row.CanariesKilled++
				}
			}
		}
		if row.CanariesKilled > 0 {
			counts.JavaMutationSensitive++
		}
		switch {
		case allSatisfied:
			row.BindingState = StateConnected
			counts.JavaBindingsConnected++
		case row.ClausesSatisfied > 0:
			row.BindingState = StatePartial
			counts.JavaBindingsPartial++
		default:
			row.BindingState = StateDisconnected
			counts.JavaBindingsDisconnected++
		}
		rows = append(rows, row)
	}
	if len(rows) != CatalogDenominator {
		return Projection{}, fmt.Errorf("javabind: derived %d rows over a denominator of %d", len(rows), CatalogDenominator)
	}
	if counts.JavaBindingsConnected+counts.JavaBindingsPartial+counts.JavaBindingsDisconnected != CatalogDenominator {
		return Projection{}, fmt.Errorf("javabind: derived counts do not sum to the denominator")
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ObligationID < rows[j].ObligationID })

	return Projection{
		SchemaVersion:    "1.0.0",
		ProjectionID:     "java-formal-binding-coverage",
		CatalogID:        catalog.CatalogID,
		Assurance:        DefaultAssurance(),
		ObservedStrength: ObservedStrength,
		RequiredStrength: RequiredStrength,
		Claim:            DefaultClaim(),
		Spec:             specIdentity,
		Catalog:          catalogIdentity,
		Receipt:          receiptIdentity,
		PinnedSource:     spec.PinnedSource,
		PinnedRuntime:    spec.PinnedRuntime,
		Counts:           counts,
		Obligations:      rows,
	}, nil
}

func evaluateClauses(binding Binding, receipt Receipt) ([]ClauseResult, error) {
	results := make([]ClauseResult, 0, len(binding.Clauses))
	for _, clause := range binding.Clauses {
		result := ClauseResult{ClauseID: clause.ClauseID, Statement: clause.Statement, WitnessesHold: true}
		for _, witness := range clause.Witnesses {
			run, ok := receipt.Run(witness.ScenarioID, VariantBaseline)
			if !ok {
				return nil, fmt.Errorf("javabind: receipt has no baseline run for scenario %q", witness.ScenarioID)
			}
			satisfied, observed, err := witness.Predicate.Evaluate([]byte(run.ResponseLine))
			if err != nil {
				return nil, err
			}
			result.Witnesses = append(result.Witnesses, WitnessResult{
				ScenarioID: witness.ScenarioID,
				Predicate:  witness.Predicate.Describe(),
				Satisfied:  satisfied,
				Observed:   observed,
			})
			if !satisfied {
				result.WitnessesHold = false
			}
		}
		if clause.Mutation == nil {
			result.NoCanaryReason = clause.NoCanary
			result.UnsatisfiedReason = "NO_CANARY_IN_BOUND_CHAIN"
			results = append(results, result)
			continue
		}
		mutationResult, err := evaluateMutation(binding, clause, receipt)
		if err != nil {
			return nil, err
		}
		result.Mutation = &mutationResult
		switch {
		case !result.WitnessesHold:
			result.UnsatisfiedReason = "WITNESS_PREDICATE_FAILED"
		case !mutationResult.Applied:
			result.UnsatisfiedReason = "CANARY_NOT_APPLIED"
		case !mutationResult.ControlAgrees:
			result.UnsatisfiedReason = "CONTROL_DIVERGED_FROM_BASELINE"
		case !mutationResult.Killed:
			result.UnsatisfiedReason = "CANARY_SURVIVED"
		default:
			result.Satisfied = true
		}
		results = append(results, result)
	}
	return results, nil
}

func evaluateMutation(binding Binding, clause Clause, receipt Receipt) (MutationResult, error) {
	mutation := *clause.Mutation
	result := MutationResult{
		MutationID:  mutation.MutationID,
		ScenarioID:  mutation.ScenarioID,
		ChainMember: mutation.ChainMember,
	}
	application, ok := receipt.MutationApplication(mutation.MutationID)
	if !ok {
		result.Detail = "the receipt records no application of this mutation"
		return result, nil
	}
	if application.ObligationID != binding.ObligationID || application.ChainMember != mutation.ChainMember {
		return result, fmt.Errorf("javabind: mutation %q application is attributed to a different obligation or member", mutation.MutationID)
	}
	if application.RemovedSHA256 != mutation.RemovedSHA256 {
		return result, fmt.Errorf("javabind: mutation %q removed-bytes digest does not match the spec", mutation.MutationID)
	}
	if application.Length != mutation.Length {
		return result, fmt.Errorf("javabind: mutation %q length does not match the spec", mutation.MutationID)
	}
	construct, ok := receipt.Construct(binding.ObligationID, mutation.ChainMember)
	if !ok {
		return result, fmt.Errorf("javabind: receipt has no construct for mutation member %q", mutation.ChainMember)
	}
	if application.AbsoluteOffset < construct.Start || application.AbsoluteOffset+application.Length > construct.End {
		return result, fmt.Errorf("javabind: mutation %q lands outside the bound span [%d,%d)", mutation.MutationID, construct.Start, construct.End)
	}
	if application.MutatedFileSHA256 == construct.FileSHA256 {
		return result, fmt.Errorf("javabind: mutation %q left the pinned file unchanged", mutation.MutationID)
	}
	if application.ControlRuntime == application.MutantRuntime {
		return result, fmt.Errorf("javabind: mutation %q control and mutant runtimes are the same archive", mutation.MutationID)
	}
	result.Applied = true

	mutantRun, ok := receipt.Run(mutation.ScenarioID, "MUTANT:"+mutation.MutationID)
	if !ok {
		result.Detail = "the receipt records no mutant run for this mutation"
		return result, nil
	}
	baselineRun, ok := receipt.Run(mutation.ScenarioID, VariantBaseline)
	if !ok {
		return result, fmt.Errorf("javabind: receipt has no baseline run for mutation scenario %q", mutation.ScenarioID)
	}
	if baselineRun.RequestDigest != mutantRun.RequestDigest {
		return result, fmt.Errorf("javabind: mutation %q baseline and mutant ran different requests", mutation.MutationID)
	}
	// The control run recompiles and repackages the SAME source. If its
	// observation already differs from the baseline, the toolchain moved the
	// result and the mutant tells us nothing about the edit.
	controlRun, ok := receipt.Run(mutation.ScenarioID, "CONTROL:"+mutation.MutationID)
	if !ok {
		result.Detail = "the receipt records no control run for this mutation"
		return result, nil
	}
	if controlRun.RequestDigest != baselineRun.RequestDigest {
		return result, fmt.Errorf("javabind: mutation %q control and baseline ran different requests", mutation.MutationID)
	}
	baselineProjection, err := SemanticProjection([]byte(baselineRun.ResponseLine))
	if err != nil {
		return result, err
	}
	controlProjection, err := SemanticProjection([]byte(controlRun.ResponseLine))
	if err != nil {
		return result, err
	}
	if string(baselineProjection) != string(controlProjection) {
		result.Detail = "the recompiled, repackaged control already diverges from the baseline, so the mutant is not attributable to the edit"
		return result, nil
	}
	result.ControlAgrees = true
	// The canary must flip a witness of ITS OWN clause. A canary that only
	// disturbs some other clause's witness proves nothing about this clause.
	for _, witness := range clause.Witnesses {
		if witness.ScenarioID != mutation.ScenarioID {
			continue
		}
		baselineOK, baselineObserved, err := witness.Predicate.Evaluate([]byte(baselineRun.ResponseLine))
		if err != nil {
			return result, err
		}
		if !baselineOK {
			continue
		}
		mutantOK, mutantObserved, err := witness.Predicate.Evaluate([]byte(mutantRun.ResponseLine))
		if err != nil {
			return result, err
		}
		if !mutantOK {
			result.Killed = true
			result.FlippedClauseID = clause.ClauseID
			result.FlippedPredicate = witness.Predicate.Describe()
			result.BaselineObserved = baselineObserved
			result.MutantObserved = mutantObserved
			return result, nil
		}
	}
	result.Detail = "no predicate of this clause that held on the baseline failed under the mutant"
	return result, nil
}
