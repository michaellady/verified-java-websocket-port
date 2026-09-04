package foundation

import "time"

var (
	evidenceEntityTypeNames = []string{"Laboratory", "SourcePin", "SurfaceItem", "SemanticId", "MigrationMap", "PortSeamDossier", "BehaviorDelta", "Oracle", "Corpus", "SemanticEvent", "Trace", "Divergence", "Claim", "ClaimReplayBundle", "Model", "ProofObligation", "EvidenceRun", "MutationResult", "BenchmarkRun", "Review", "SkillRevision", "ForwardTest", "ProgramSnapshotManifest", "DeveloperToolRun", "ResourceClaim", "PerformanceEnvelope", "JavaIntakeManifest", "CompatibilitySurface", "CutoverContract", "FailureEnvelope", "Attempt", "GeneralizationDecision", "AuthorizationAction", "ArtifactClassification", "StalenessEdge"}
	evidenceEdgeTypeNames   = []string{"supports", "discharges", "attests", "depends-on", "produced-by", "classifies", "migrates", "stales", "pins"}
)

// currentEvidenceSchemaValid applies the non-cognitive constraints in the
// retained evidence-model-1.1.0 schema. Assurance disposition is deliberately
// absent: schema-valid blocked evidence remains valid migration output.
func currentEvidenceSchemaValid(value evidenceCase) bool {
	valid := value.SchemaVersion == currentEvidenceSchemaVersion && stableEvidenceID.MatchString(value.CaseID) && len(value.Scenario) > 0 && schemaRFC3339(value.SnapshotTime)
	valid = len(value.Entities) >= 35 && len(value.AssuranceProfiles) >= 5 && len(value.Claims) > 0 && valid
	valid = schemaEntitiesValid(value.Entities) && schemaAssuranceProfilesValid(value.AssuranceProfiles) && schemaClaimsValid(value.Claims) && valid
	valid = schemaCommonGateValid(value.CommonGate) && schemaMutationResultsValid(value.MutationResults) && schemaStableIDsValid(value.SignedMutationDenominatorIDs, 0, true) && valid
	valid = schemaReviewsValid(value.Reviews) && schemaProofObligationsValid(value.ProofObligations) && schemaReplayBundlesValid(value.ReplayBundles) && valid
	valid = schemaMigrationMapsValid(value.MigrationMaps) && schemaFailureEnvelopesValid(value.Failures) && schemaAttemptsValid(value.Attempts) && schemaSnapshotValid(value.Snapshot) && valid
	return valid
}

func schemaEntitiesValid(values []evidenceEntity) bool {
	entityTypes := stringSet(evidenceEntityTypeNames)
	edgeTypes := stringSet(evidenceEdgeTypeNames)
	valid := true
	for _, value := range values {
		valid = stableEvidenceID.MatchString(value.ID) && entityTypes[value.Type] && valid
		seenEdges := make(map[string]bool, len(value.Edges))
		for _, edge := range value.Edges {
			identity := edge.Type + "\x00" + edge.To
			valid = edgeTypes[edge.Type] && stableEvidenceID.MatchString(edge.To) && !seenEdges[identity] && valid
			seenEdges[identity] = true
		}
	}
	return valid
}

func schemaAssuranceProfilesValid(values []assuranceProfile) bool {
	labels := stringSet([]string{"observed", "differential", "bounded", "proved-model", "proved-production/refinement"})
	ceilings := stringSet([]string{"LAB", "CANDIDATE", "PUBLISHED"})
	valid := true
	for _, value := range values {
		valid = labels[value.Label] && schemaNonEmptyStringsValid(value.RequiredArtifactTypes) && schemaNonEmptyStringsValid(value.TrustedComputingBase) && schemaNonEmptyStringsValid(value.Disclosures) && schemaNonEmptyStringsValid(value.ProhibitedInferences) && schemaNonEmptyStringsValid(value.FailureStates) && len(value.ExpiryRule) > 0 && len(value.FreshnessRule) > 0 && ceilings[value.ReadinessCeiling] && valid
		for _, artifactType := range assuranceArtifactRequirements()[value.Label] {
			valid = containsString(value.RequiredArtifactTypes, artifactType) && valid
		}
	}
	return valid
}

func schemaClaimsValid(values []claim) bool {
	assuranceLabels := stringSet([]string{"observed", "differential", "bounded", "proved-model", "proved-production/refinement"})
	statuses := stringSet([]string{"SUPPORTED", "CONTRADICTORY", "UNSUPPORTED"})
	freshnessStates := stringSet([]string{"FRESH", "STALE"})
	readinessStates := stringSet([]string{"LAB", "CANDIDATE", "ACCEPTED", "PUBLISHED"})
	valid := true
	for _, value := range values {
		valid = stableEvidenceID.MatchString(value.ID) && assuranceLabels[value.Assurance] && assuranceLabels[value.RequiredLevel] && stableEvidenceID.MatchString(value.SubjectID) && schemaStableIDsValid(value.EvidenceIDs, 1, true) && statuses[value.Status] && freshnessStates[value.Freshness] && schemaRFC3339(value.ExpiresAt) && readinessStates[value.Readiness] && valid
	}
	return valid
}

func schemaCommonGateValid(value commonGate) bool {
	performanceStates := stringSet([]string{"regress", "match", "outperform"})
	return schemaNonNegativeInt(value.UnexplainedDifferentialMismatches) && schemaNonNegativeInt(value.Flakes) && schemaNonNegativeInt(value.FirstPartyUnsafeRust) && schemaNonNegativeInt(value.MissedEligibleMutations) && performanceStates[value.PerformanceVsJava]
}

func schemaMutationResultsValid(values []mutationResult) bool {
	tools := stringSet([]string{"PIT", "cargo-mutants"})
	dispositions := stringSet([]string{"killed", "survived", "not_executed", "uncovered", "timeout", "tool_failure", "flaky", "equivalent", "technically_unviable"})
	valid := true
	for _, value := range values {
		valid = stableEvidenceID.MatchString(value.ID) && stableEvidenceID.MatchString(value.ClaimID) && tools[value.SourceTool] && len(value.RawStatus) > 0 && dispositions[value.Disposition] && value.Eligible != nil && schemaStableIDsValid(value.ReviewIDs, 0, false) && valid
	}
	return valid
}

func schemaReviewsValid(values []review) bool {
	dispositions := stringSet([]string{"APPROVE", "REJECT"})
	valid := true
	for _, value := range values {
		valid = stableEvidenceID.MatchString(value.ID) && stableEvidenceID.MatchString(value.ClaimID) && stableEvidenceID.MatchString(value.ReviewerID) && value.Role == "independent-reviewer" && value.Blind && dispositions[value.Disposition] && valid
	}
	return valid
}

func schemaProofObligationsValid(values []proofObligation) bool {
	outcomes := stringSet([]string{"ProofEstablished", "BoundedCheckPassed", "model_observation", "trace_observation", "unsupported", "inconclusive", "stale", "disconnected"})
	valid := true
	for _, value := range values {
		valid = stableEvidenceID.MatchString(value.ID) && stableEvidenceID.MatchString(value.ClaimID) && outcomes[value.RequiredOutcome] && outcomes[value.Outcome] && stableEvidenceID.MatchString(value.ModelID) && schemaProductionCodeIDsValid(value.ProductionCodeIDs) && valid
	}
	return valid
}

func schemaReplayBundlesValid(values []claimReplayBundle) bool {
	valid := true
	for _, value := range values {
		valid = stableEvidenceID.MatchString(value.ID) && stableEvidenceID.MatchString(value.ClaimID) && len(value.SourceRevision) > 0 && len(value.SpecificationRevision) > 0 && len(value.JavaRevision) > 0 && len(value.RustRevision) > 0 && valid
		valid = schemaNonEmptyStringsValid(value.JavaSemanticIDs) && schemaNonEmptyStringsValid(value.RustSemanticIDs) && len(value.Command) > 0 && len(value.WorkingDirectory) > 0 && schemaNonEmptyStringsValid(value.ToolHashes) && schemaNonEmptyStringsValid(value.ContainerHashes) && schemaNonEmptyStringsValid(value.Environment) && valid
		valid = len(value.Seed) > 0 && len(value.Hardware) > 0 && schemaNonEmptyStringsValid(value.Assumptions) && schemaNonEmptyStringsValid(value.TrustedBase) && schemaNonNegativeInt(value.ExitCount) && schemaNonNegativeInt(value.ObligationCount) && valid
		valid = schemaNonEmptyStringsValid(value.RawLogIDs) && schemaNonEmptyStringsValid(value.ArtifactIDs) && len(value.NormalizedDiffID) > 0 && schemaNonEmptyStringsValid(value.CounterexampleOrCorpusIDs) && len(value.ReplayCommand) > 0 && valid
	}
	return valid
}

func schemaMigrationMapsValid(values []migrationMap) bool {
	resolvers := stringSet([]string{"rust-analyzer", "reviewed-glancer"})
	lookupStrengths := stringSet([]string{"semantic", "ast-fallback", "grep-fallback"})
	valid := true
	for _, value := range values {
		valid = stableEvidenceID.MatchString(value.ID) && resolvers[value.RustResolver] && schemaNonEmptyStringsValid(value.ApplicabilityConditions) && schemaNonEmptyStringsValid(value.KnownNonEquivalentCases) && schemaNonEmptyStringsValid(value.TouchedFiles) && valid
		valid = schemaNonEmptyStringsValid(value.SpecificationIDs) && schemaNonEmptyStringsValid(value.ObservedBehaviorIDs) && schemaNonEmptyStringsValid(value.OracleIDs) && schemaNonEmptyStringsValid(value.VectorIDs) && schemaNonEmptyStringsValid(value.PropertyClaimIDs) && valid
		valid = schemaNonEmptyStringsValid(value.FormalClaimIDs) && schemaNonEmptyStringsValid(value.EvidenceIDs) && lookupStrengths[value.LookupStrength] && valid
	}
	return valid
}

func schemaFailureEnvelopesValid(values []failureEnvelope) bool {
	dispositions := stringSet([]string{"RETRY", "DEGRADE_NON_ASSURANCE", "BLOCK", "INVALIDATE", "QUARANTINE", "REVOKE"})
	valid := true
	for _, value := range values {
		valid = stableEvidenceID.MatchString(value.FailureID) && dispositions[value.Disposition] && schemaNonEmptyStringsValid(value.AffectedClaimIDs) && schemaNonEmptyStringsValid(value.AffectedArtifactIDs) && schemaNonEmptyStringsValid(value.CauseChain) && schemaRFC3339(value.Timestamp) && valid
	}
	return valid
}

func schemaAttemptsValid(values []attempt) bool {
	valid := true
	for _, value := range values {
		valid = stableEvidenceID.MatchString(value.ID) && stableEvidenceID.MatchString(value.FailureID) && valid
	}
	return valid
}

func schemaSnapshotValid(value programSnapshot) bool {
	states := stringSet([]string{"PROPOSED", "QUALIFIED", "CANDIDATE", "ACCEPTED", "PUBLISHED", "BLOCKED", "STALE", "SUPERSEDED", "REVOKED"})
	valid := stableEvidenceID.MatchString(value.ID) && states[value.State] && schemaNonEmptyStringsValid(value.Schemas) && schemaNonEmptyStringsValid(value.Validators) && schemaNonEmptyStringsValid(value.Policies)
	valid = schemaNonEmptyStringsValid(value.SourceCommits) && schemaNonEmptyStringsValid(value.PortCommits) && schemaNonEmptyStringsValid(value.Suites) && schemaNonEmptyStringsValid(value.Toolchains) && valid
	valid = schemaNonEmptyStringsValid(value.Platforms) && schemaNonEmptyStringsValid(value.LSPProfiles) && schemaNonEmptyStringsValid(value.EvidenceRoots) && schemaNonEmptyUniqueStringsValid(value.ReviewerAttestations) && len(value.CutoverPrerequisites) > 0 && valid
	return valid
}

func schemaStableIDsValid(values []string, minimum int, unique bool) bool {
	valid := len(values) >= minimum
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		valid = stableEvidenceID.MatchString(value) && (!unique || !seen[value]) && valid
		seen[value] = true
	}
	return valid
}

func schemaNonEmptyStringsValid(values []string) bool {
	valid := len(values) > 0
	for _, value := range values {
		valid = len(value) > 0 && valid
	}
	return valid
}

func schemaNonEmptyUniqueStringsValid(values []string) bool {
	valid := schemaNonEmptyStringsValid(values)
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		valid = !seen[value] && valid
		seen[value] = true
	}
	return valid
}

func schemaProductionCodeIDsValid(values []string) bool {
	valid := true
	for _, value := range values {
		valid = productionCodeID.MatchString(value) && valid
	}
	return valid
}

func schemaNonNegativeInt(value *int) bool {
	return value != nil && *value >= 0
}

func schemaRFC3339(value string) bool {
	normalized := []byte(value)
	if len(normalized) > 10 && normalized[10] == 't' {
		normalized[10] = 'T'
	}
	if len(normalized) > 0 && normalized[len(normalized)-1] == 'z' {
		normalized[len(normalized)-1] = 'Z'
	}
	_, err := time.Parse(time.RFC3339, string(normalized))
	return err == nil
}
