// Package mutdenom verifies the US-022 normalized mutation denominator against
// the repository it describes.
//
// AC1 verbatim: "PIT and cargo-mutants run from promoted tool/dependency graphs
// against the declared production and test surfaces and normalize killed,
// survived, not-executed, uncovered, timeout, tool-failure, flaky, equivalent,
// and technically-unviable dispositions into one signed denominator."
//
// The defect class this package exists to stop is A COUNT STANDING IN FOR A
// POPULATION. A mutation score is a ratio, and every way of making it look good
// is a way of shrinking or hiding the thing underneath it:
//
//   - a mutant that is never enumerated never appears in any denominator;
//   - a mutant enumerated and then dropped from the report is a silent absence;
//   - a mutant relabelled `equivalent` or `technically-unviable` leaves the
//     eligible set without leaving the denominator, which is legitimate ONLY
//     with technical evidence and an independent explicit review;
//   - a hand-curated catalogue of mutants somebody chose is not a population a
//     tool enumerated over a declared surface, however many entries it has;
//   - an engine that never ran produces no dispositions at all, and reporting
//     that as "nothing survived" is the same lie told by omission.
//
// So nothing here is taken on trust. Every count is recomputed from the records,
// every record must land in exactly one of the nine AC1 classes, the declared
// production and test surfaces are digest-re-derived from the tree, the engine
// probes are executed and their exit codes read from the real ProcessState, and
// the manifest's own claim may not outrun its findings.
//
// Unavailable tooling BLOCKS in both directions, following the precedent this
// repository already set in internal/fuzzpin, internal/formalplan
// (UNAVAILABLE_REPRESENTED_AS_SKIP / UNAVAILABLE_BACKEND_CLAIM) and the ledger
// gate's refusal when VJWP_PROTECTED_STORE is unreachable:
//
//   - an engine whose probe does not exit 0 is UNAVAILABLE and raises
//     MUT_ENGINE_UNAVAILABLE (BLOCK) unconditionally;
//   - a population, arm, or campaign that claims to have RUN on an unavailable
//     engine raises UNAVAILABLE_REPRESENTED_AS_SKIP (BLOCK);
//   - the inverse evasion -- parking a population or arm as
//     NOT_ENUMERATED_ENGINE_UNAVAILABLE / NOT_RUN_ENGINE_UNAVAILABLE while the
//     engine probes AVAILABLE -- raises the same finding, because that hides a
//     campaign nobody ran behind a tool that is right there;
//   - claiming any AC met while a BLOCK stands raises
//     UNAVAILABLE_REPRESENTED_AS_SUCCESS (BLOCK);
//   - there is no SKIPPED status. Writing one raises
//     MUT_STATUS_SKIPPED_FORBIDDEN (BLOCK).
package mutdenom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// DigestScheme is the repo-incumbent canonical tree digest, the same scheme
// assurance/replay/fixtures/us006-cases.json and assurance/fuzz/manifest.json
// use: sha256 over "relative-path\x00sha256(file-bytes)\n" lines in sorted
// relative-path order.
const DigestScheme = "CANONICAL_PATH_SHA256_V1"

// PayloadDigestScheme names how the signed payload is derived: the manifest
// with signature.payload_digest and signature.signature blanked, marshalled in
// declaration order, sha256'd. The signature therefore covers every surface,
// population, record, arm, and claim in the document -- there is no field a
// signer can leave out.
const PayloadDigestScheme = "MUTDENOM_PAYLOAD_SHA256_V1"

// Dispositions. BLOCK is the only failing disposition; NOTE is visible and
// non-failing. There is deliberately no SKIP.
const (
	Block = "BLOCK"
	Note  = "NOTE"
)

// The nine AC1 disposition classes, verbatim from the acceptance criterion and
// identical to the MutationResultRecord enum already frozen in
// assurance/schema/evidence-model-1.1.0.schema.json. Every mutant in the
// denominator lands in exactly one of these. There is no tenth class, and there
// is no absence.
const (
	DispKilled              = "killed"
	DispSurvived            = "survived"
	DispNotExecuted         = "not_executed"
	DispUncovered           = "uncovered"
	DispTimeout             = "timeout"
	DispToolFailure         = "tool_failure"
	DispFlaky               = "flaky"
	DispEquivalent          = "equivalent"
	DispTechnicallyUnviable = "technically_unviable"
)

// Dispositions is the closed class set, in AC1's order.
var Dispositions = []string{
	DispKilled, DispSurvived, DispNotExecuted, DispUncovered, DispTimeout,
	DispToolFailure, DispFlaky, DispEquivalent, DispTechnicallyUnviable,
}

// IneligibleDispositions are the two classes AC2 allows OUT of the eligible
// numerator and denominator while requiring them to stay VISIBLE in the signed
// denominator, each with technical evidence and an independent explicit review.
// Every other class is eligible, so every other non-killed class is MISSED.
var IneligibleDispositions = map[string]bool{
	DispEquivalent:          true,
	DispTechnicallyUnviable: true,
}

// MissedDispositions are the eligible classes that are not a kill. AC2 requires
// this count to be zero. not_executed, uncovered, timeout, tool_failure and
// flaky are MISSED for the same reason survived is: none of them is a
// demonstration that a test caught the mutant.
var MissedDispositions = map[string]bool{
	DispSurvived:    true,
	DispNotExecuted: true,
	DispUncovered:   true,
	DispTimeout:     true,
	DispToolFailure: true,
	DispFlaky:       true,
}

// IsDisposition reports whether s is one of the nine classes.
func IsDisposition(s string) bool {
	for _, d := range Dispositions {
		if d == s {
			return true
		}
	}
	return false
}

// Source tools, matching the frozen MutationResultRecord.source_tool enum.
const (
	ToolPIT          = "PIT"
	ToolCargoMutants = "cargo-mutants"
)

// Population enumeration statuses. There is no SKIPPED.
const (
	// EnumEnumerated: the engine really enumerated this surface and every
	// mutant it produced is recorded below.
	EnumEnumerated = "ENUMERATED"
	// EnumNotEnumeratedEngineUnavailable: the engine is not installed, so no
	// population exists. This is honest AND it BLOCKS.
	EnumNotEnumeratedEngineUnavailable = "NOT_ENUMERATED_ENGINE_UNAVAILABLE"
	// StatusSkippedForbidden is never valid. It is named so the checker can
	// refuse it by name rather than by falling through to "unknown".
	StatusSkippedForbidden = "SKIPPED"
)

// Population provenance.
const (
	// ProvenanceToolEnumerated: the mutant set is whatever the engine produced
	// over the declared surface. This is the only provenance AC1 accepts.
	ProvenanceToolEnumerated = "tool_enumerated"
	// ProvenanceHandCurated: somebody chose the mutants. However good the
	// choices, the set has no denominator relationship to the surface, because
	// the mutants nobody wrote down were never counted.
	ProvenanceHandCurated = "hand_curated"
)

// Arm run statuses. There is no SKIPPED.
const (
	ArmRun                     = "RUN"
	ArmNotRunEngineUnavailable = "NOT_RUN_ENGINE_UNAVAILABLE"
)

// Dependency-graph promotion status (US-001 promotion vocabulary).
const (
	GraphPromoted    = "PROMOTED"
	GraphNotPromoted = "NOT_PROMOTED"
)

// SeparationDimensions are the six AC4 names, verbatim: "Hidden and sealed runs
// use separate identities, filesystems, caches, credentials, signing keys, and
// workspaces". Each must be declared per arm, and no two arms may share a value.
var SeparationDimensions = []string{
	"identity", "filesystem", "cache", "credential", "signing_key", "workspace",
}

// AC5Legs are the six clauses of AC5, verbatim: "Pinned Java passes 100%,
// empty/stub Rust and planted mutants fail, the candidate passes, all cases
// reconcile, and zero protected case, output, raw diagnostic, or oracle secret
// enters public artifacts."
var AC5Legs = []string{
	"pinned-java-passes-100",
	"empty-stub-rust-fails",
	"planted-mutants-fail",
	"candidate-passes",
	"all-cases-reconcile",
	"zero-protected-leakage",
}

// ReconciliationLegs are AC3's four required runs: "no-stub and test-manifest
// reconciliation run before and after mutation."
var ReconciliationLegs = []string{
	"no-stub-before", "no-stub-after",
	"test-manifest-before", "test-manifest-after",
}

// ClaimGrades is the program's assurance vocabulary, from
// assurance/schema/evidence-model-1.1.0.schema.json AssuranceProfile.label.
var ClaimGrades = map[string]bool{
	"observed": true, "differential": true, "bounded": true,
	"proved-model": true, "proved-production/refinement": true,
}

// Finding codes. Every rule has its own code. US-021's deletion attack found
// two checks that survived deletion because a sibling rule sharing their code
// fired in their place and kept the fixture green; a check whose only witness is
// another check's finding is not evidence. That lesson is why this list is long.
const (
	FindingManifestSchemaInvalid = "MUT_MANIFEST_SCHEMA_INVALID"
	FindingDigestSchemeInvalid   = "MUT_DIGEST_SCHEME_INVALID"

	// Engines and tooling availability.
	FindingEngineUnavailable          = "MUT_ENGINE_UNAVAILABLE"
	FindingToolchainVersionMismatch   = "MUT_TOOLCHAIN_VERSION_MISMATCH"
	FindingDependencyGraphNotPromoted = "MUT_DEPENDENCY_GRAPH_NOT_PROMOTED"
	FindingPromotionRecordAbsent      = "MUT_PROMOTION_RECORD_ABSENT"
	FindingUnknownEngineReference     = "MUT_UNKNOWN_ENGINE_REFERENCE"
	FindingUnavailableAsSkip          = "UNAVAILABLE_REPRESENTED_AS_SKIP"
	FindingUnavailableAsSuccess       = "UNAVAILABLE_REPRESENTED_AS_SUCCESS"
	FindingStatusSkippedForbidden     = "MUT_STATUS_SKIPPED_FORBIDDEN"

	// Declared surfaces.
	FindingSurfaceUndeclared       = "MUT_SURFACE_UNDECLARED"
	FindingSurfaceDigestDrift      = "MUT_SURFACE_DIGEST_DRIFT"
	FindingSurfaceFileCountDrift   = "MUT_SURFACE_FILE_COUNT_DRIFT"
	FindingSurfaceUnmapped         = "MUT_SURFACE_HAS_NO_POPULATION"
	FindingUnknownSurfaceReference = "MUT_UNKNOWN_SURFACE_REFERENCE"

	// The population: the thing a denominator is a count OF.
	FindingPopulationNotEnumerated     = "MUT_POPULATION_NOT_ENUMERATED"
	FindingPopulationNotToolEnumerated = "MUT_POPULATION_NOT_TOOL_ENUMERATED"
	FindingPopulationRecordCountDrift  = "MUT_POPULATION_RECORD_COUNT_DRIFT"
	FindingClassSumMismatch            = "MUT_CLASS_SUM_MISMATCH"
	FindingClassTallyDrift             = "MUT_CLASS_TALLY_DRIFT"
	FindingSourceManifestCountDrift    = "MUT_SOURCE_MANIFEST_COUNT_DRIFT"
	FindingSourceManifestUnreadable    = "MUT_SOURCE_MANIFEST_UNREADABLE"

	// Per-mutant records.
	FindingDispositionUnknown     = "MUT_DISPOSITION_UNKNOWN"
	FindingDispositionAbsent      = "MUT_DISPOSITION_ABSENT"
	FindingMutantIDDuplicate      = "MUT_MUTANT_ID_DUPLICATE"
	FindingRecordExcluded         = "MUT_RECORD_EXCLUDED_FROM_DENOMINATOR"
	FindingEligibilityMislabelled = "MUT_ELIGIBILITY_MISLABELLED"
	FindingSourceToolInvalid      = "MUT_SOURCE_TOOL_INVALID"
	FindingRawStatusAbsent        = "MUT_RAW_STATUS_ABSENT"

	// AC2: equivalent / technically-unviable gating.
	FindingEquivalenceEvidenceAbsent = "MUT_EQUIVALENCE_EVIDENCE_ABSENT"
	FindingEquivalenceReviewAbsent   = "MUT_EQUIVALENCE_REVIEW_ABSENT"
	FindingReviewRecordMissing       = "MUT_REVIEW_RECORD_MISSING"
	FindingReviewNotIndependent      = "MUT_REVIEW_NOT_INDEPENDENT"
	FindingReviewNotBlind            = "MUT_REVIEW_NOT_BLIND"
	FindingReviewNotApproved         = "MUT_REVIEW_NOT_APPROVED"

	// AC2: the score itself.
	FindingDenominatorTotalDrift = "MUT_DENOMINATOR_TOTAL_DRIFT"
	FindingEligibleTotalDrift    = "MUT_ELIGIBLE_TOTAL_DRIFT"
	FindingKilledTotalDrift      = "MUT_KILLED_TOTAL_DRIFT"
	FindingMissedTotalDrift      = "MUT_MISSED_TOTAL_DRIFT"
	FindingScorePercentDrift     = "MUT_SCORE_PERCENT_DRIFT"
	FindingMissedNonZero         = "MUT_MISSED_NONZERO"
	FindingScoreNotComputable    = "MUT_SCORE_NOT_COMPUTABLE"

	// AC3: no requirement-bearing test deleted, weakened, skipped or filtered.
	FindingReconciliationLegAbsent = "MUT_RECONCILIATION_LEG_ABSENT"
	FindingReconciliationLegNotRun = "MUT_RECONCILIATION_LEG_NOT_RUN"
	FindingTestSurfaceMutated      = "MUT_TEST_SURFACE_MUTATED"

	// AC4: hidden/sealed separation.
	FindingArmSeparationDimensionMissing     = "MUT_ARM_SEPARATION_DIMENSION_MISSING"
	FindingArmSeparationWitnessUnreadable    = "MUT_ARM_SEPARATION_WITNESS_UNREADABLE"
	FindingArmSeparationWitnessDrift         = "MUT_ARM_SEPARATION_WITNESS_DRIFT"
	FindingArmSeparationShared               = "MUT_ARM_SEPARATION_SHARED"
	FindingArmNetworkDenialUndeclared        = "MUT_ARM_NETWORK_DENIAL_UNDECLARED"
	FindingArmProtectedStoreDenialUndeclared = "MUT_ARM_PROTECTED_STORE_DENIAL_UNDECLARED"
	FindingArmBudgetNotMonotonic             = "MUT_ARM_BUDGET_NOT_MONOTONIC"
	FindingArmDiagnosticPolicyAbsent         = "MUT_ARM_DIAGNOSTIC_POLICY_ABSENT"
	FindingArmNotRun                         = "MUT_ARM_NOT_RUN"
	FindingArmMissing                        = "MUT_ARM_MISSING"

	// AC5.
	FindingAC5LegAbsent    = "MUT_AC5_LEG_ABSENT"
	FindingAC5LegNotPassed = "MUT_AC5_LEG_NOT_PASSED"

	// AC1: "one SIGNED denominator".
	FindingSignatureAbsent        = "MUT_SIGNATURE_ABSENT"
	FindingSignatureSchemeInvalid = "MUT_SIGNATURE_SCHEME_INVALID"
	FindingPayloadDigestDrift     = "MUT_PAYLOAD_DIGEST_DRIFT"
	FindingSigningKeyAbsent       = "MUT_SIGNING_KEY_ABSENT"

	// The manifest's own claim.
	FindingClaimGradeInvalid = "MUT_CLAIM_GRADE_INVALID"
)

// Manifest is the US-022 normalized mutation denominator.
type Manifest struct {
	SchemaVersion string            `json:"schema_version"`
	DocumentID    string            `json:"document_id"`
	EntityType    string            `json:"entity_type"`
	Story         string            `json:"story"`
	DigestScheme  string            `json:"digest_scheme"`
	Statement     string            `json:"statement"`
	ACVerbatim    map[string]string `json:"ac_verbatim"`
	Note          string            `json:"note"`

	Engines       []Engine      `json:"engines"`
	Surfaces      []Surface     `json:"surfaces"`
	Populations   []Population  `json:"populations"`
	Reviews       []Review      `json:"reviews"`
	Score         Score         `json:"score"`
	TestIntegrity TestIntegrity `json:"test_integrity"`
	Arms          []Arm         `json:"arms"`
	AC5Legs       []AC5Leg      `json:"ac5_legs"`
	Signature     Signature     `json:"signature"`
	Claim         Claim         `json:"claim"`
}

// Engine is one mutation engine plus how its availability and its promoted
// tool/dependency graph are decided.
type Engine struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	Tool string `json:"tool"`
	// ProbeCommand decides availability. An engine whose availability cannot be
	// decided is unavailable.
	ProbeCommand []string  `json:"probe_command"`
	ProbeDir     string    `json:"probe_dir"`
	Toolchain    Toolchain `json:"toolchain"`
	// DependencyGraph is AC1's "promoted tool/dependency graph". A graph that
	// was never promoted cannot be run from.
	DependencyGraph DependencyGraph `json:"dependency_graph"`
	Note            string          `json:"note"`
}

// Toolchain pins the runtime the campaign must execute under. VersionPattern,
// when non-empty, must appear in the combined output of ProbeCommand: the
// pinned runtime being absent is a fact about the environment, read from the
// environment, never asserted.
type Toolchain struct {
	Required       string   `json:"required"`
	ProbeCommand   []string `json:"probe_command"`
	ProbeDir       string   `json:"probe_dir"`
	VersionPattern string   `json:"version_pattern"`
}

// DependencyGraph records AC1's promotion precondition.
type DependencyGraph struct {
	Status          string `json:"status"`
	PromotionRecord string `json:"promotion_record"`
	Note            string `json:"note"`
}

// Surface is one declared production or test surface. AC1 names both.
type Surface struct {
	ID        string   `json:"id"`
	Kind      string   `json:"kind"` // "production" | "test"
	Language  string   `json:"language"`
	Paths     []string `json:"paths"`
	FileCount int      `json:"file_count"`
	Digest    string   `json:"digest"`
	Note      string   `json:"note"`
}

// Population is one (surface, engine) mutant population -- the thing a
// denominator is a count of.
type Population struct {
	ID                string         `json:"id"`
	Surface           string         `json:"surface"`
	Engine            string         `json:"engine"`
	EnumerationStatus string         `json:"enumeration_status"`
	Provenance        string         `json:"provenance"`
	SourceManifest    string         `json:"source_manifest"`
	SourceManifestKey string         `json:"source_manifest_key"`
	DeclaredTotal     int            `json:"declared_total"`
	Classes           map[string]int `json:"classes"`
	Records           []Record       `json:"records"`
	Rationale         string         `json:"rationale"`
}

// Record is one mutant, normalized. It carries the raw tool status it came from
// so normalization is auditable rather than assumed.
type Record struct {
	ID            string   `json:"id"`
	SourceTool    string   `json:"source_tool"`
	RawStatus     string   `json:"raw_status"`
	Disposition   string   `json:"disposition"`
	Eligible      bool     `json:"eligible"`
	InDenominator bool     `json:"in_denominator"`
	Evidence      string   `json:"evidence"`
	ReviewIDs     []string `json:"review_ids"`
}

// Review is AC2's "independent explicit review" of an equivalent or
// technically-unviable classification. The master story (docs/prd-pack/
// 02-master-stories-foundation.md) says DUAL-BLIND, and the frozen
// ReviewRecord schema requires role "independent-reviewer" and blind true.
type Review struct {
	ID          string `json:"id"`
	ReviewerID  string `json:"reviewer_id"`
	Role        string `json:"role"`
	Blind       bool   `json:"blind"`
	Disposition string `json:"disposition"`
	Basis       string `json:"basis"`
}

// Score is the declared arithmetic. Every field is recomputed from the records.
type Score struct {
	DenominatorTotal     int     `json:"denominator_total"`
	EligibleTotal        int     `json:"eligible_total"`
	KilledTotal          int     `json:"killed_total"`
	MissedTotal          int     `json:"missed_total"`
	EligibleScorePercent float64 `json:"eligible_score_percent"`
	Computable           bool    `json:"computable"`
	Note                 string  `json:"note"`
}

// TestIntegrity is AC3's before/after reconciliation and the test-surface
// immutability binding.
type TestIntegrity struct {
	Legs                    []ReconciliationLeg `json:"legs"`
	TestSurfaceDigestBefore string              `json:"test_surface_digest_before"`
	TestSurfaceDigestAfter  string              `json:"test_surface_digest_after"`
	Note                    string              `json:"note"`
}

// ReconciliationLeg is one no-stub or test-manifest run.
type ReconciliationLeg struct {
	ID      string `json:"id"`
	Status  string `json:"status"` // "RUN" | "NOT_RUN"
	Command string `json:"command"`
	Exit    int    `json:"exit"`
	Note    string `json:"note"`
}

// Arm is one evaluation arm. AC4 governs the hidden and sealed ones.
type Arm struct {
	ID                   string                       `json:"id"`
	MutationRunStatus    string                       `json:"mutation_run_status"`
	Separation           map[string]SeparationWitness `json:"separation"`
	NetworkDenial        string                       `json:"network_denial"`
	ProtectedStoreDenial string                       `json:"protected_store_denial"`
	BudgetMonotonic      bool                         `json:"budget_monotonic"`
	BudgetBasis          string                       `json:"budget_basis"`
	AntiEvasion          string                       `json:"anti_evasion"`
	DiagnosticPolicy     string                       `json:"diagnostic_policy"`
	Rationale            string                       `json:"rationale"`
}

// SeparationWitness is one AC4 dimension made checkable: the value the arm
// claims, and the exact file and dotted JSON path the checker READS to confirm
// it. A dimension with no witness source is a promise; a dimension with one is
// a reading.
type SeparationWitness struct {
	Declared string `json:"declared"`
	Source   string `json:"source"`
	Field    string `json:"field"`
	Note     string `json:"note"`
}

// AC5Leg is one clause of AC5.
type AC5Leg struct {
	ID          string `json:"id"`
	Requirement string `json:"requirement"`
	Status      string `json:"status"` // "PASSED" | anything else blocks
	Evidence    string `json:"evidence"`
}

// Signature is AC1's "one signed denominator".
type Signature struct {
	Scheme        string `json:"scheme"`
	PayloadScheme string `json:"payload_scheme"`
	KeyID         string `json:"key_id"`
	PublicKeyHex  string `json:"public_key_hex"`
	PayloadDigest string `json:"payload_digest"`
	Signature     string `json:"signature"`
	Note          string `json:"note"`
}

// Claim is the manifest's own verdict. It may not claim any AC met while a
// BLOCK stands.
type Claim struct {
	AC1Met      bool   `json:"ac1_met"`
	AC2Met      bool   `json:"ac2_met"`
	AC3Met      bool   `json:"ac3_met"`
	AC4Met      bool   `json:"ac4_met"`
	AC5Met      bool   `json:"ac5_met"`
	ClaimGrade  string `json:"claim_grade"`
	HonestState string `json:"honest_state"`
}

// Finding is one typed verdict line.
type Finding struct {
	Code        string `json:"code"`
	Disposition string `json:"disposition"`
	Target      string `json:"target"`
	Detail      string `json:"detail"`
}

// EngineProbe is one availability probe outcome.
type EngineProbe struct {
	Engine    string `json:"engine"`
	Command   string `json:"command"`
	Exit      int    `json:"exit"`
	ExitText  string `json:"exit_text"`
	Available bool   `json:"available"`
}

// Verdict is the check result.
type Verdict struct {
	State              string        `json:"state"`
	Findings           []Finding     `json:"findings"`
	EngineAvailability []EngineProbe `json:"engine_availability"`
}

// LoadManifest reads and decodes a manifest, rejecting unknown fields so a typo
// cannot silently drop a required binding.
func LoadManifest(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return &manifest, nil
}

// PayloadDigest computes MUTDENOM_PAYLOAD_SHA256_V1 over the manifest with the
// signature's own digest and signature blanked. Everything else -- every
// surface, every record, every arm, the claim -- is inside the digest, so there
// is no field a signer can decline to cover.
func PayloadDigest(manifest *Manifest) (string, error) {
	clone := *manifest
	clone.Signature.PayloadDigest = ""
	clone.Signature.Signature = ""
	data, err := json.Marshal(clone)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// TreeDigest computes CANONICAL_PATH_SHA256_V1 over every regular file under
// the given roots, relative to base. A root that does not exist is an error: a
// missing surface is not an empty surface.
func TreeDigest(base string, roots []string) (string, int, error) {
	type entry struct {
		rel    string
		digest string
	}
	var entries []entry
	appendFile := func(path string) error {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(base, path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		entries = append(entries, entry{rel: filepath.ToSlash(rel), digest: hex.EncodeToString(sum[:])})
		return nil
	}
	for _, root := range roots {
		abs := filepath.Join(base, root)
		info, err := os.Stat(abs)
		if err != nil {
			return "", 0, fmt.Errorf("surface root %s: %w", root, err)
		}
		if !info.IsDir() {
			if err := appendFile(abs); err != nil {
				return "", 0, err
			}
			continue
		}
		err = filepath.Walk(abs, func(path string, fi os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if fi.IsDir() {
				return nil
			}
			return appendFile(path)
		})
		if err != nil {
			return "", 0, err
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })
	hasher := sha256.New()
	for _, e := range entries {
		fmt.Fprintf(hasher, "%s\x00%s\n", e.rel, e.digest)
	}
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil)), len(entries), nil
}

// LookupJSONField reads a dotted path out of a decoded JSON document and returns
// the value as a string. This is how an AC4 separation witness is READ rather
// than asserted.
func LookupJSONField(path string, field string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	current := doc
	for _, segment := range strings.Split(field, ".") {
		switch container := current.(type) {
		case map[string]any:
			next, present := container[segment]
			if !present {
				return "", fmt.Errorf("%s: no field %q (at segment %q)", path, field, segment)
			}
			current = next
		case []any:
			index, err := strconv.Atoi(segment)
			if err != nil {
				return "", fmt.Errorf("%s: segment %q of %q is not an array index", path, segment, field)
			}
			if index < 0 || index >= len(container) {
				return "", fmt.Errorf("%s: index %d of %q is out of range (len %d)", path, index, field, len(container))
			}
			current = container[index]
		default:
			return "", fmt.Errorf("%s: %q is not a container at segment %q", path, field, segment)
		}
	}
	switch value := current.(type) {
	case string:
		return value, nil
	case float64:
		return fmt.Sprintf("%v", value), nil
	case bool:
		return fmt.Sprintf("%t", value), nil
	default:
		return "", fmt.Errorf("%s: field %q is not a scalar", path, field)
	}
}
