package lab

import (
	"fmt"
	"sort"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

const (
	JavaBuildEvidenceSchema   = "../../schemas/java-build-receipt-1.0.0.schema.json"
	JavaAdapterEvidenceSchema = "../../schemas/java-adapter-baseline-1.0.0.schema.json"
	JavaTestEvidenceSchema    = "../../schemas/java-test-manifest-1.0.0.schema.json"
	JavaDefaultPolicySchema   = "../../schemas/java-default-policy-behavior-1.0.0.schema.json"
	AutobahnEvidenceSchema    = "../../schemas/autobahn-baseline-1.0.0.schema.json"
	// BehaviorLedgerSchema is the LEDGER DOCUMENT schema, bumped to 1.1.0 under
	// the owner ruling of 2026-08-28 so the document can carry a first-class
	// `supersessions` array that this package's readiness gate consumes. The
	// PER-RECORD schema_version stays 1.0.0: it is inside every record's digest
	// preimage, so bumping it would rewrite the hash chain from sequence 1 and
	// break the frozen prefix the same ruling protects.
	BehaviorLedgerSchema        = "../../schemas/behavior-delta-ledger-1.1.0.schema.json"
	BehaviorLedgerSchemaVersion = "1.1.0"
)

const (
	pinnedJavaSourceDigest = "sha256:f44e7647b4aee40819b51947cf0bb5f35a48293a202b77704c3c79e98ed13cb4"
	pinnedJDKDigest        = "sha256:6d51e51e754dc75437c5c552eea568ec2f166e39fc3faa256e668083a8620c17"
	pinnedMavenDigest      = "sha256:4b7195b6a4f5c81af4c0212677a32ee8143643401bc6e1e8412e6b06ea82beac"
	pinnedRuntimeDigest    = "sha256:eae29213e4f16515639c28957200f011b3967fffcada1962cf0255d24919c22f"
)

type BaselineEvidenceDocuments struct {
	Build    []byte
	Adapter  []byte
	Tests    []byte
	Autobahn []byte
	Ledger   []byte
}

type EvidenceReadiness struct {
	SchemaVersion string            `json:"schema_version"`
	Status        string            `json:"status"`
	Blockers      []EvidenceFinding `json:"blockers"`
}

type EvidenceFinding struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

type evidenceEnvelope struct {
	Schema             string `json:"$schema"`
	SchemaVersion      string `json:"schema_version"`
	EvidenceKind       string `json:"evidence_kind"`
	AcceptedRootDigest string `json:"accepted_root_digest"`
	Production         bool   `json:"production"`
	Publication        bool   `json:"publication"`
}

type evidenceObject struct {
	ObjectID string `json:"object_id"`
	Digest   string `json:"digest"`
	Version  string `json:"version"`
}

type buildEvidence struct {
	evidenceEnvelope
	Status                   string `json:"status"`
	Assurance                string `json:"assurance"`
	IndependentReviewClaimed bool   `json:"independent_review_claimed"`
	Source                   struct {
		evidenceObject
		ProductionSourceModified bool `json:"production_source_modified"`
	} `json:"source"`
	Toolchains []evidenceObject `json:"toolchains"`
	Cache      struct {
		Isolated                bool   `json:"isolated"`
		ClosureFrozen           bool   `json:"closure_frozen"`
		OfflineAuthoritativeRun bool   `json:"offline_authoritative_run"`
		Qualification           string `json:"qualification"`
	} `json:"cache"`
	Sandbox struct {
		SourceReadOnlyRequired   bool   `json:"source_read_only_required"`
		Secrets                  string `json:"secrets"`
		Egress                   string `json:"egress"`
		BoundedResourcesRequired bool   `json:"bounded_resources_required"`
		EnforcementStatus        string `json:"enforcement_status"`
	} `json:"sandbox"`
	Build struct {
		Executed      bool `json:"executed"`
		ExitCode      *int `json:"exit_code"`
		TestsExecuted bool `json:"tests_executed"`
	} `json:"build"`
	Blockers []EvidenceFinding `json:"blockers"`
}

type adapterEvidence struct {
	evidenceEnvelope
	Status   string `json:"status"`
	Protocol struct {
		Name               string `json:"name"`
		Version            string `json:"version"`
		Transport          string `json:"transport"`
		StdoutProtocolOnly bool   `json:"stdout_protocol_only"`
		DiagnosticsBounded bool   `json:"diagnostics_bounded"`
	} `json:"protocol"`
	Runtime struct {
		evidenceObject
		StartupDigestEnforced bool `json:"startup_digest_enforced"`
	} `json:"runtime"`
	Tests struct {
		GroupsPassed                 int  `json:"groups_passed"`
		DeterministicReplayPassed    bool `json:"deterministic_replay_passed"`
		StrictInputCanariesPassed    bool `json:"strict_input_canaries_passed"`
		RuntimeBindingCanariesPassed bool `json:"runtime_binding_canaries_passed"`
	} `json:"tests"`
	AuthoritativeSandboxRun  bool `json:"authoritative_sandbox_run"`
	ProductionSourceModified bool `json:"production_source_modified"`
	RFC6455Normative         bool `json:"rfc6455_normative"`
}

type testEvidence struct {
	evidenceEnvelope
	Status          string `json:"status"`
	InventoryStatus string `json:"inventory_status"`
	Inventory       struct {
		Path   string `json:"path"`
		Schema string `json:"schema"`
		Digest string `json:"digest"`
	} `json:"inventory"`
	Discovery struct {
		Strategy                     string `json:"strategy"`
		ConcreteSelectorCount        int    `json:"concrete_selector_count"`
		AggregateSuiteContainerCount int    `json:"aggregate_suite_container_count"`
		AggregateSuitesExecutable    bool   `json:"aggregate_suites_are_executable_containers"`
		AggregateSuitesExcluded      bool   `json:"aggregate_suites_excluded_from_selector"`
		DefaultDiscoveryDelta        string `json:"default_discovery_delta"`
	} `json:"discovery"`
	Counts struct {
		StaticAnnotationOccurrences int `json:"static_annotation_occurrences"`
		ConcreteClasses             int `json:"concrete_classes"`
		AggregateSuiteContainers    int `json:"aggregate_suite_containers"`
		Discovered                  int `json:"discovered"`
		Executed                    int `json:"executed"`
		Passed                      int `json:"passed"`
		Failed                      int `json:"failed"`
		Skipped                     int `json:"skipped"`
		Filtered                    int `json:"filtered"`
		TimedOut                    int `json:"timed_out"`
		Quarantined                 int `json:"quarantined"`
		RuntimeInvocations          int `json:"runtime_invocations"`
		PassedInvocations           int `json:"passed_invocations"`
		FailedInvocations           int `json:"failed_invocations"`
		SkippedInvocations          int `json:"skipped_invocations"`
	} `json:"counts"`
	NonTests []struct {
		Path          string `json:"path"`
		Kind          string `json:"kind"`
		Executable    bool   `json:"executable"`
		CountedAsTest bool   `json:"counted_as_test"`
	} `json:"non_tests"`
	AuthoritativeRun struct {
		PlanDigest           string               `json:"plan_digest"`
		StartedAt            string               `json:"started_at"`
		FinishedAt           string               `json:"finished_at"`
		ExitCode             int                  `json:"exit_code"`
		TimedOut             bool                 `json:"timed_out"`
		SourceBeforeDigest   string               `json:"source_before_digest"`
		SourceAfterDigest    string               `json:"source_after_digest"`
		CacheManifestDigest  string               `json:"cache_manifest_digest"`
		EnvironmentDigest    string               `json:"environment_digest"`
		Stdout               evidenceArtifact     `json:"stdout"`
		Stderr               evidenceArtifact     `json:"stderr"`
		ExecutionCodeBinding executionCodeBinding `json:"execution_code_binding"`
		ObservedEndpoints    []string             `json:"observed_endpoints"`
		AllCanariesPassed    bool                 `json:"all_enforcement_canaries_passed"`
	} `json:"authoritative_run"`
	TestPolicy struct {
		DefaultPolicyEvidencePath   string `json:"default_policy_evidence_path"`
		DefaultPolicyEvidenceDigest string `json:"default_policy_evidence_digest"`
		JavaSecurityDigest          string `json:"java_security_digest"`
		OverlayPath                 string `json:"overlay_path"`
		OverlayDigest               string `json:"overlay_digest"`
		Assurance                   string `json:"assurance"`
		IndependentReviewClaimed    bool   `json:"independent_review_claimed"`
		LocalOnly                   bool   `json:"local_only"`
		NoSecretAccess              bool   `json:"no_secret_access"`
		ProductionPolicyModified    bool   `json:"production_policy_modified"`
	} `json:"test_policy"`
	Blocker *EvidenceFinding `json:"blocker"`
}

type evidenceArtifact struct {
	Digest string `json:"digest"`
	Bytes  int    `json:"bytes"`
}

type executionCodeBinding struct {
	ArtifactID                   string                  `json:"artifact_id"`
	Binary                       evidenceArtifact        `json:"binary"`
	Sources                      []evidenceSourceBinding `json:"sources"`
	PostRunDriftChecked          bool                    `json:"post_run_drift_checked"`
	MaterialExecutionPathChanged bool                    `json:"material_execution_path_changed_after_run"`
}

type evidenceSourceBinding struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
	Bytes  int    `json:"bytes"`
}

type defaultPolicyEvidence struct {
	evidenceEnvelope
	Status      string `json:"status"`
	PromotedJDK struct {
		Version                    string   `json:"version"`
		JavaSecurityDigest         string   `json:"java_security_digest"`
		DisabledAlgorithmsContains []string `json:"disabled_algorithms_contains"`
	} `json:"promoted_jdk"`
	DefaultPolicyResult struct {
		Authoritative   bool             `json:"authoritative"`
		Selector        string           `json:"selector"`
		Outcome         string           `json:"outcome"`
		Counts          policyTestCounts `json:"counts"`
		FailingIdentity string           `json:"failing_identity"`
		ExceptionClass  string           `json:"exception_class"`
		Diagnostic      string           `json:"diagnostic"`
		Report          evidenceArtifact `json:"report"`
		Stdout          evidenceArtifact `json:"stdout"`
	} `json:"default_policy_result"`
	TestOnlyOverlay struct {
		Path                               string   `json:"path"`
		Digest                             string   `json:"digest"`
		LoadMode                           string   `json:"load_mode"`
		RemovedTokens                      []string `json:"removed_tokens"`
		OtherPromotedRestrictionsPreserved bool     `json:"other_promoted_restrictions_preserved"`
		Assurance                          string   `json:"assurance"`
		IndependentReviewClaimed           bool     `json:"independent_review_claimed"`
		FocusedResult                      struct {
			Authoritative bool             `json:"authoritative"`
			Outcome       string           `json:"outcome"`
			Counts        policyTestCounts `json:"counts"`
			Report        evidenceArtifact `json:"report"`
		} `json:"focused_result"`
	} `json:"test_only_overlay"`
	Scope struct {
		LocalOnly                bool `json:"local_only"`
		NoSecretAccess           bool `json:"no_secret_access"`
		TestOnly                 bool `json:"test_only"`
		ProductionPolicyModified bool `json:"production_policy_modified"`
	} `json:"scope"`
}

type policyTestCounts struct {
	Tests    int `json:"tests"`
	Passed   int `json:"passed"`
	Failures int `json:"failures"`
	Errors   int `json:"errors"`
	Skipped  int `json:"skipped"`
}

func DecodeDefaultPolicyEvidence(data []byte) (defaultPolicyEvidence, error) {
	var value defaultPolicyEvidence
	if err := intake.DecodeStrict(data, &value); err != nil {
		return defaultPolicyEvidence{}, err
	}
	return value, validateDefaultPolicyEvidence(value)
}

func validateDefaultPolicyEvidence(value defaultPolicyEvidence) error {
	if err := validateEnvelope(value.evidenceEnvelope, JavaDefaultPolicySchema, "java-default-policy-behavior"); err != nil {
		return err
	}
	defaultCounts := policyTestCounts{Tests: 4, Passed: 3, Failures: 0, Errors: 1, Skipped: 0}
	overlayCounts := policyTestCounts{Tests: 4, Passed: 4, Failures: 0, Errors: 0, Skipped: 0}
	if value.Status != "PASS" || value.PromotedJDK.Version != "17.0.19" || value.PromotedJDK.JavaSecurityDigest != promotedJavaSecurityDigest || !equalStrings(value.PromotedJDK.DisabledAlgorithmsContains, []string{"TLS_RSA_*"}) || value.DefaultPolicyResult.Authoritative || value.DefaultPolicyResult.Selector != "org.java_websocket.server.CustomSSLWebSocketServerFactoryTest" || value.DefaultPolicyResult.Outcome != "EXPECTED_PROMOTED_POLICY_FAILURE" || value.DefaultPolicyResult.Counts != defaultCounts || value.DefaultPolicyResult.FailingIdentity != "org.java_websocket.server.CustomSSLWebSocketServerFactoryTest#testWrapChannel" || value.DefaultPolicyResult.ExceptionClass != "javax.net.ssl.SSLHandshakeException" || value.DefaultPolicyResult.Diagnostic != "No appropriate protocol (protocol is disabled or cipher suites are inappropriate)" {
		return finding("DEFAULT_POLICY_EVIDENCE_MISMATCH", "$.default_policy_result", "default promoted-JDK TLS policy failure differs from the exact focused observation")
	}
	overlay := value.TestOnlyOverlay
	if overlay.Path != "evidence/java/test-only-java.security" || overlay.Digest != mavenTestSecurityOverlayDigest || overlay.LoadMode != "APPEND_SINGLE_EQUALS" || !equalStrings(overlay.RemovedTokens, []string{"TLS_RSA_*"}) || !overlay.OtherPromotedRestrictionsPreserved || overlay.Assurance != ownerAttestedNotIndependent || overlay.IndependentReviewClaimed || overlay.FocusedResult.Authoritative || overlay.FocusedResult.Outcome != "PASS" || overlay.FocusedResult.Counts != overlayCounts || !value.Scope.LocalOnly || !value.Scope.NoSecretAccess || !value.Scope.TestOnly || value.Scope.ProductionPolicyModified || value.Production || value.Publication {
		return finding("TEST_SECURITY_OVERLAY_MISMATCH", "$.test_only_overlay", "overlay evidence must remain exact, local, test-only, owner-attested, and non-production")
	}
	for path, artifact := range map[string]evidenceArtifact{"$.default_policy_result.report": value.DefaultPolicyResult.Report, "$.default_policy_result.stdout": value.DefaultPolicyResult.Stdout, "$.test_only_overlay.focused_result.report": overlay.FocusedResult.Report} {
		if !isDigest(artifact.Digest) || artifact.Bytes <= 0 {
			return finding("INVALID_EVIDENCE_ARTIFACT", path, "focused artifact requires an exact digest and positive size")
		}
	}
	return nil
}

type autobahnEvidence struct {
	evidenceEnvelope
	Status                   string `json:"status"`
	Assurance                string `json:"assurance"`
	IndependentReviewClaimed bool   `json:"independent_review_claimed"`
	Image                    struct {
		ManifestDigest   string `json:"manifest_digest"`
		ManifestBytes    int    `json:"manifest_bytes"`
		ConfigDigest     string `json:"config_digest"`
		Platform         string `json:"platform"`
		Layers           int    `json:"layers"`
		PullPolicy       string `json:"pull_policy"`
		IdentityVerified bool   `json:"identity_verified"`
	} `json:"image"`
	SelectedFamilies []string `json:"selected_families"`
	ExcludedFamilies []string `json:"excluded_families"`
	Registry         struct {
		Digest                  string `json:"digest"`
		StaticExpansionComplete bool   `json:"static_expansion_complete"`
	} `json:"registry"`
	Client          autobahnEvidenceRun `json:"client"`
	Server          autobahnEvidenceRun `json:"server"`
	RiskDisposition struct {
		Classification           string `json:"classification"`
		ApprovedCriticalFindings int    `json:"approved_critical_findings"`
		ApprovedHighFindings     int    `json:"approved_high_findings"`
	} `json:"risk_disposition"`
	RerunDisposition struct {
		AuthorizedRemediationAttemptsPerMode int    `json:"authorized_remediation_attempts_per_mode"`
		ConsumedRemediationAttemptsPerMode   int    `json:"consumed_remediation_attempts_per_mode"`
		OriginalReceiptRetained              bool   `json:"original_receipt_retained"`
		FurtherRerunsAuthorized              bool   `json:"further_reruns_authorized"`
		Disposition                          string `json:"disposition"`
	} `json:"rerun_disposition"`
	Blocker *EvidenceFinding `json:"blocker"`
}

type autobahnEvidenceRun struct {
	Attempted            bool                      `json:"attempted"`
	AttemptCount         int                       `json:"attempt_count"`
	Completed            bool                      `json:"completed"`
	Executed             bool                      `json:"executed"`
	FirstCaseID          string                    `json:"first_case_id"`
	SelectedCount        int                       `json:"selected_count"`
	CompletedCount       int                       `json:"completed_count"`
	ResultCount          int                       `json:"result_count"`
	AttemptStateDigest   string                    `json:"attempt_state_digest"`
	AttemptReceiptDigest string                    `json:"attempt_receipt_digest"`
	AttemptReceiptBytes  int                       `json:"attempt_receipt_bytes"`
	ConfigurationDigest  string                    `json:"configuration_digest"`
	ConfigurationBytes   int                       `json:"configuration_bytes"`
	BlockerDigest        *string                   `json:"blocker_digest"`
	BlockerBytes         *int                      `json:"blocker_bytes"`
	Attempts             []autobahnEvidenceAttempt `json:"attempts"`
	Results              []AutobahnResult          `json:"results,omitempty"`
}

type autobahnEvidenceAttempt struct {
	Sequence       int              `json:"sequence"`
	Classification string           `json:"classification"`
	PlanDigest     string           `json:"plan_digest"`
	ReceiptDigest  string           `json:"receipt_digest"`
	ReceiptBytes   int              `json:"receipt_bytes"`
	Completed      bool             `json:"completed"`
	Executed       bool             `json:"executed"`
	CompletedCount int              `json:"completed_count"`
	ResultCount    int              `json:"result_count"`
	Blocker        *EvidenceFinding `json:"blocker"`
}

type ledgerEvidence struct {
	evidenceEnvelope
	Status               string                 `json:"status"`
	NormativeAuthority   string                 `json:"normative_authority"`
	Head                 string                 `json:"head"`
	Records              []BehaviorLedgerRecord `json:"records"`
	AppendImplementation string                 `json:"append_implementation"`
	// Supersessions is the 1.1.0 addition. It is DECLARED by the document and
	// CHECKED against what the record chain's own hashed rationales carry, so a
	// consumer never has to choose between trusting the declaration and
	// re-deriving it.
	Supersessions           []SupersessionLink `json:"supersessions"`
	UnledgeredDisagreements int                `json:"unledgered_disagreements"`
}

// VerifyBaselineEvidence is the single fail-closed readiness decision. Every
// document is strictly decoded, rooted to the same accepted tree, and checked
// both independently and against the other baseline claims.
func VerifyBaselineEvidence(expectedRoot string, documents BaselineEvidenceDocuments) (EvidenceReadiness, error) {
	if !isDigest(expectedRoot) {
		return EvidenceReadiness{}, finding("INVALID_DIGEST", "$.expected_root", "expected accepted root must be an exact SHA-256 digest")
	}
	var build buildEvidence
	var adapter adapterEvidence
	var tests testEvidence
	var autobahn autobahnEvidence
	var ledger ledgerEvidence
	for _, document := range []struct {
		name string
		raw  []byte
		out  any
	}{
		{"build", documents.Build, &build}, {"adapter", documents.Adapter, &adapter}, {"tests", documents.Tests, &tests},
		{"autobahn", documents.Autobahn, &autobahn}, {"ledger", documents.Ledger, &ledger},
	} {
		if len(document.raw) == 0 || len(document.raw) > maxManifestBytes {
			return EvidenceReadiness{}, finding("INVALID_BASELINE_EVIDENCE", "$."+document.name, "each evidence document must be present and bounded")
		}
		if err := intake.DecodeStrict(document.raw, document.out); err != nil {
			return EvidenceReadiness{}, err
		}
	}
	for name, envelope := range map[string]evidenceEnvelope{
		"build": build.evidenceEnvelope, "adapter": adapter.evidenceEnvelope, "tests": tests.evidenceEnvelope,
		"autobahn": autobahn.evidenceEnvelope, "ledger": ledger.evidenceEnvelope,
	} {
		if envelope.AcceptedRootDigest != expectedRoot {
			return EvidenceReadiness{}, finding("BASELINE_ROOT_MISMATCH", "$."+name+".accepted_root_digest", "every evidence document must bind the exact accepted root")
		}
		if envelope.Production || envelope.Publication {
			return EvidenceReadiness{}, finding("LAB_SCOPE_VIOLATION", "$."+name, "qualification evidence cannot authorize production or publication")
		}
	}
	if err := validateBuildEvidence(build); err != nil {
		return EvidenceReadiness{}, err
	}
	if err := validateAdapterEvidence(adapter); err != nil {
		return EvidenceReadiness{}, err
	}
	if err := validateTestEvidence(tests); err != nil {
		return EvidenceReadiness{}, err
	}
	if err := validateAutobahnEvidence(autobahn); err != nil {
		return EvidenceReadiness{}, err
	}
	if err := validateLedgerEvidence(ledger); err != nil {
		return EvidenceReadiness{}, err
	}
	if err := validateAggregateDisagreementLedger(autobahn, ledger); err != nil {
		return EvidenceReadiness{}, err
	}
	baselinesReady := build.Status == "PASS" && adapter.Status == "PASS" && tests.Status == "PASS" && autobahn.Status == "PASS"
	if ledger.Status == "READY" && !baselinesReady {
		return EvidenceReadiness{}, finding("CONTRADICTORY_EVIDENCE_STATUS", "$.ledger.status", "ledger cannot be READY while a prerequisite baseline is blocked")
	}
	if baselinesReady && ledger.Status != "READY" {
		return EvidenceReadiness{}, finding("CONTRADICTORY_EVIDENCE_STATUS", "$.ledger.status", "successful prerequisites require a READY ledger")
	}
	if baselinesReady {
		return EvidenceReadiness{SchemaVersion: "1.0.0", Status: "READY", Blockers: []EvidenceFinding{}}, nil
	}
	blockers := append([]EvidenceFinding(nil), build.Blockers...)
	if tests.Blocker != nil {
		blockers = append(blockers, *tests.Blocker)
	}
	if autobahn.Blocker != nil {
		blockers = append(blockers, *autobahn.Blocker)
	}
	if adapter.Status != "PASS" {
		blockers = append(blockers, EvidenceFinding{Code: "JAVA_ADAPTER_NOT_AUTHORITATIVE", Detail: "Java adapter has no authoritative sandbox baseline."})
	}
	if len(blockers) == 0 {
		return EvidenceReadiness{}, finding("CONTRADICTORY_EVIDENCE_STATUS", "$", "blocked aggregate evidence must identify a concrete blocker")
	}
	sort.Slice(blockers, func(i, j int) bool {
		if blockers[i].Code == blockers[j].Code {
			return blockers[i].Detail < blockers[j].Detail
		}
		return blockers[i].Code < blockers[j].Code
	})
	return EvidenceReadiness{SchemaVersion: "1.0.0", Status: "BLOCKED", Blockers: blockers}, nil
}

// validateAggregateDisagreementLedger requires every non-OK terminal Autobahn
// behavior to be bound by an AUTHORITATIVE ledger record.
//
// ROUND-2 FINDING 6, reproduced before this line changed: the coverage map was
// built from `ledger.Records` — every record, superseded or not — so a
// WITHDRAWN record went on covering a live Autobahn failure and readiness said
// READY. internal/deltaledger had made supersession machine-visible and this,
// the one consumer that decides release readiness, could not see it. The map is
// now built from AuthoritativeRecords, so a record the chain records as
// superseded covers nothing, exactly as the censuses in internal/deltaledger
// already treat it.
func validateAggregateDisagreementLedger(autobahn autobahnEvidence, ledger ledgerEvidence) error {
	if autobahn.Status != "PASS" {
		return nil
	}
	authoritative, err := AuthoritativeRecords(ledger.Records)
	if err != nil {
		return finding("INVALID_BEHAVIOR_LEDGER", "$.ledger.supersessions", err.Error())
	}
	ledgered := make(map[string]struct{}, len(authoritative))
	for _, record := range authoritative {
		ledgered[record.Delta.AutobahnResultDigest] = struct{}{}
	}
	for mode, results := range map[string][]AutobahnResult{"client": autobahn.Client.Results, "server": autobahn.Server.Results} {
		for index, result := range results {
			if result.Status == "OK" || result.Status == "INFORMATIONAL" {
				continue
			}
			if _, exists := ledgered[result.BindingDigest]; !exists {
				return finding("UNLEDGERED_BEHAVIOR_DISAGREEMENT", fmt.Sprintf("$.autobahn.%s.results[%d]", mode, index), "non-OK terminal Autobahn behavior has no exact bound delta record")
			}
		}
	}
	return nil
}

func validateEnvelope(envelope evidenceEnvelope, schema, kind string) error {
	return validateVersionedEnvelope(envelope, schema, kind, "1.0.0")
}

// validateVersionedEnvelope exists because the behavior-delta ledger DOCUMENT
// is at 1.1.0 while every other baseline document is at 1.0.0. The version is
// an argument rather than a constant so the two cannot silently swap.
func validateVersionedEnvelope(envelope evidenceEnvelope, schema, kind, version string) error {
	if envelope.Schema != schema || envelope.SchemaVersion != version || envelope.EvidenceKind != kind || !isDigest(envelope.AcceptedRootDigest) {
		return finding("INVALID_EVIDENCE_ENVELOPE", "$", "schema path, version, evidence kind, and root digest must be exact")
	}
	return nil
}

func validateEvidenceFinding(value EvidenceFinding, path string) error {
	if !regexpEvidenceCode(value.Code) || value.Detail == "" || len(value.Detail) > 2048 {
		return finding("INVALID_EVIDENCE_FINDING", path, "finding code and bounded detail are required")
	}
	return nil
}

func regexpEvidenceCode(value string) bool {
	if len(value) == 0 || value[0] < 'A' || value[0] > 'Z' {
		return false
	}
	for _, character := range value {
		if character != '_' && (character < 'A' || character > 'Z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func validateBuildEvidence(value buildEvidence) error {
	if err := validateEnvelope(value.evidenceEnvelope, JavaBuildEvidenceSchema, "java-build-receipt"); err != nil {
		return err
	}
	if value.Assurance != "OWNER_ATTESTED_NOT_INDEPENDENT" || value.IndependentReviewClaimed || value.Source.ObjectID != "java-websocket-source-archive" || value.Source.Version != "1.6.0" || value.Source.Digest != pinnedJavaSourceDigest || value.Source.ProductionSourceModified {
		return finding("JAVA_BUILD_IDENTITY_MISMATCH", "$.build", "source and assurance must equal the pinned Java 1.6.0 baseline")
	}
	expectedTools := []evidenceObject{{"openjdk-17.0.19-homebrew-bottle", pinnedJDKDigest, "17.0.19"}, {"apache-maven-3.9.11", pinnedMavenDigest, "3.9.11"}}
	if len(value.Toolchains) != len(expectedTools) {
		return finding("JAVA_BUILD_IDENTITY_MISMATCH", "$.build.toolchains", "exact JDK and Maven toolchain objects are required")
	}
	for index := range expectedTools {
		if value.Toolchains[index] != expectedTools[index] {
			return finding("JAVA_BUILD_IDENTITY_MISMATCH", fmt.Sprintf("$.build.toolchains[%d]", index), "toolchain identity differs from its pin")
		}
	}
	if !value.Cache.Isolated || !value.Sandbox.SourceReadOnlyRequired || value.Sandbox.Secrets != "none" || value.Sandbox.Egress != "deny-by-default" || !value.Sandbox.BoundedResourcesRequired {
		return finding("INVALID_JAVA_BUILD_POLICY", "$.build", "isolated cache and exact deny-default sandbox policy are mandatory")
	}
	for index, blocker := range value.Blockers {
		if err := validateEvidenceFinding(blocker, fmt.Sprintf("$.build.blockers[%d]", index)); err != nil {
			return err
		}
	}
	if !value.Build.Executed && (value.Build.ExitCode != nil || value.Build.TestsExecuted) || value.Build.Executed && value.Build.ExitCode == nil {
		return finding("CONTRADICTORY_BUILD_RECEIPT", "$.build.build", "execution, exit-code, and test claims must describe one coherent run")
	}
	ready := value.Cache.ClosureFrozen && value.Cache.OfflineAuthoritativeRun && value.Cache.Qualification == "QUALIFIED_NOT_PROMOTED" && value.Sandbox.EnforcementStatus == "VERIFIED" && value.Build.Executed && value.Build.ExitCode != nil && *value.Build.ExitCode == 0 && value.Build.TestsExecuted
	switch value.Status {
	case "PASS":
		if !ready || len(value.Blockers) != 0 {
			return finding("CONTRADICTORY_EVIDENCE_STATUS", "$.build.status", "PASS requires verified enforcement, frozen offline closure, successful build/tests, and no blockers")
		}
	case "BLOCKED":
		if ready || len(value.Blockers) == 0 {
			return finding("CONTRADICTORY_EVIDENCE_STATUS", "$.build.status", "BLOCKED requires an incomplete readiness condition and at least one blocker")
		}
	default:
		return finding("INVALID_EVIDENCE_STATUS", "$.build.status", "status must be PASS or BLOCKED")
	}
	if value.Sandbox.EnforcementStatus != "VERIFIED" && value.Sandbox.EnforcementStatus != "UNAVAILABLE" {
		return finding("INVALID_JAVA_BUILD_POLICY", "$.build.sandbox.enforcement_status", "sandbox enforcement status must be VERIFIED or UNAVAILABLE")
	}
	return nil
}

func validateAdapterEvidence(value adapterEvidence) error {
	if err := validateEnvelope(value.evidenceEnvelope, JavaAdapterEvidenceSchema, "java-adapter-baseline"); err != nil {
		return err
	}
	if value.Protocol.Name != "java-websocket-oracle" || value.Protocol.Version != "1.0.0" || value.Protocol.Transport != "strict-jsonl" || !value.Protocol.StdoutProtocolOnly || !value.Protocol.DiagnosticsBounded || value.Runtime.ObjectID != "java-websocket-runtime-jar" || value.Runtime.Digest != pinnedRuntimeDigest || value.Runtime.Version != "1.6.0" || !value.Runtime.StartupDigestEnforced || value.ProductionSourceModified || !value.RFC6455Normative {
		return finding("JAVA_ADAPTER_IDENTITY_MISMATCH", "$.adapter", "adapter protocol, runtime, and RFC authority must equal their pins")
	}
	componentReady := value.Tests.GroupsPassed == 12 && value.Tests.DeterministicReplayPassed && value.Tests.StrictInputCanariesPassed && value.Tests.RuntimeBindingCanariesPassed
	switch value.Status {
	case "PASS":
		if !componentReady || !value.AuthoritativeSandboxRun {
			return finding("CONTRADICTORY_EVIDENCE_STATUS", "$.adapter.status", "PASS requires all exact component groups and an authoritative sandbox run")
		}
	case "QUALIFIED_COMPONENT_ONLY":
		if !componentReady || value.AuthoritativeSandboxRun {
			return finding("CONTRADICTORY_EVIDENCE_STATUS", "$.adapter.status", "component-only status requires all component checks but no authoritative run")
		}
	case "BLOCKED":
		if value.AuthoritativeSandboxRun && componentReady {
			return finding("CONTRADICTORY_EVIDENCE_STATUS", "$.adapter.status", "fully authoritative adapter cannot claim BLOCKED")
		}
	default:
		return finding("INVALID_EVIDENCE_STATUS", "$.adapter.status", "adapter status is outside the exact vocabulary")
	}
	return nil
}

func validateTestEvidence(value testEvidence) error {
	if err := validateEnvelope(value.evidenceEnvelope, JavaTestEvidenceSchema, "java-test-manifest"); err != nil {
		return err
	}
	if value.Status != "PASS" || value.InventoryStatus != "RECONCILED" || value.Blocker != nil {
		return finding("CONTRADICTORY_EVIDENCE_STATUS", "$.tests.status", "test evidence requires one exact reconciled authoritative PASS and no blocker")
	}
	if value.Inventory.Path != "evidence/java/test-inventory.json" || value.Inventory.Schema != "schemas/java-test-inventory-1.0.0.schema.json" || value.Inventory.Digest != "sha256:cc704b3fa71864bfb065243504e7f5d89315f8d5ae3b793c0a08ad6ba70d3fc7" {
		return finding("INVALID_TEST_INVENTORY", "$.tests.inventory", "manifest must bind the exact reconciled inventory artifact")
	}
	if value.Discovery.Strategy != "EXPLICIT_CONCRETE_CLASS_ONCE" || value.Discovery.ConcreteSelectorCount != 62 || value.Discovery.AggregateSuiteContainerCount != 10 || !value.Discovery.AggregateSuitesExecutable || !value.Discovery.AggregateSuitesExcluded || value.Discovery.DefaultDiscoveryDelta == "" {
		return finding("TEST_SELECTOR_MISMATCH", "$.tests.discovery", "canonical discovery must retain executable suites while selecting each concrete class once")
	}
	wantCounts := []int{231, 62, 10, 231, 231, 231, 0, 0, 0, 0, 0, 326, 326, 0, 0}
	gotCounts := []int{value.Counts.StaticAnnotationOccurrences, value.Counts.ConcreteClasses, value.Counts.AggregateSuiteContainers, value.Counts.Discovered, value.Counts.Executed, value.Counts.Passed, value.Counts.Failed, value.Counts.Skipped, value.Counts.Filtered, value.Counts.TimedOut, value.Counts.Quarantined, value.Counts.RuntimeInvocations, value.Counts.PassedInvocations, value.Counts.FailedInvocations, value.Counts.SkippedInvocations}
	for index := range wantCounts {
		if gotCounts[index] != wantCounts[index] {
			return finding("TEST_COUNT_MISMATCH", "$.tests.counts", "method identities and raw invocation totals must equal the authoritative reconciliation")
		}
	}
	expected := []struct {
		path, kind string
		executable bool
	}{
		{"src/test/resources/org/java_websocket/AutobahnClient.feature", "feature-file", false},
		{"src/test/java/org/java_websocket/example/AutobahnClientTest.java", "autobahn-utility", true},
		{"src/test/java/org/java_websocket/example/AutobahnSSLServerTest.java", "autobahn-utility", true},
		{"src/test/java/org/java_websocket/example/AutobahnServerTest.java", "autobahn-utility", true},
	}
	if len(value.NonTests) != len(expected) {
		return finding("INVALID_NON_TEST_CLASSIFICATION", "$.tests.non_tests", "exact feature and Autobahn utility classifications are required")
	}
	for index := range expected {
		actual := value.NonTests[index]
		if actual.Path != expected[index].path || actual.Kind != expected[index].kind || actual.Executable != expected[index].executable || actual.CountedAsTest {
			return finding("INVALID_NON_TEST_CLASSIFICATION", fmt.Sprintf("$.tests.non_tests[%d]", index), "non-test classification differs from the frozen inventory")
		}
	}
	run := value.AuthoritativeRun
	started, startErr := time.Parse(time.RFC3339Nano, run.StartedAt)
	finished, finishErr := time.Parse(time.RFC3339Nano, run.FinishedAt)
	if run.PlanDigest != "sha256:1802bf80d4fd5843be860e9a60136f3add67f9a4c6322cb32b48941e3d1ee89b" || startErr != nil || finishErr != nil || !finished.After(started) || run.ExitCode != 0 || run.TimedOut || run.SourceBeforeDigest != "sha256:455234b5cb26e46a80cd749316e40d6f6fb4bf1c43a096d8c70d1f856908cbc2" || run.SourceAfterDigest != run.SourceBeforeDigest || run.CacheManifestDigest != "sha256:19518e08afbbd7a0dfbf893c713158487db85ea945ae1b8145897e200a007590" || run.EnvironmentDigest != "sha256:d776cfb8105226c3105dd7e47be46107a59c355291c00c465709ad955c148111" || run.Stdout != (evidenceArtifact{Digest: "sha256:62929ef08bcbd1bcca8648ee43e31174786508e72e35d1e97a0b29ffec8810a8", Bytes: 15125}) || run.Stderr != (evidenceArtifact{Digest: "sha256:b111cc480fc22b7e83203b6ea0af9290b3a758f096b61764132e8de8798b26db", Bytes: 4596}) || !equalStrings(run.ObservedEndpoints, []string{"127.0.0.1:*"}) || !run.AllCanariesPassed {
		return finding("AUTHORITATIVE_TEST_RECEIPT_MISMATCH", "$.tests.authoritative_run", "authoritative receipt differs from the single exact sandbox execution")
	}
	binding := run.ExecutionCodeBinding
	if binding.ArtifactID != "us002-canonical-final-labctl" || binding.Binary != (evidenceArtifact{Digest: "sha256:10f056f86a2a0abc021c310fdb27bc7162ec01b3bb92c2e0cdf034b3a062c94f", Bytes: 9761330}) || len(binding.Sources) != 4 || !binding.PostRunDriftChecked || binding.MaterialExecutionPathChanged {
		return finding("EXECUTION_CODE_BINDING_MISMATCH", "$.tests.authoritative_run.execution_code_binding", "receipt must bind the exact executor binary/source snapshot and deny post-run drift")
	}
	expectedSources := []evidenceSourceBinding{{"internal/lab/executor_darwin.go", "sha256:863bc6d7c2b3e6d4b13332f2b883539676c206d3df283158b8a9c254713cfa42", 52560}, {"internal/lab/inventory.go", "sha256:f34e5787f2055b61a0431f239c9085914dacd3182b2a7392b1acead30816187d", 24593}, {"internal/lab/sandbox.go", "sha256:acb7ecd0b2cf917673342506ad25a43cbce83ab87b2ea4832cdfefd23f7374cf", 30704}, {"cmd/labctl/main.go", "sha256:7197bfc73774ecf2f010d14364f25b8ca49d2dad99605babcbfc087499b1b13f", 17306}}
	for index := range expectedSources {
		if binding.Sources[index] != expectedSources[index] {
			return finding("EXECUTION_CODE_BINDING_MISMATCH", "$.tests.authoritative_run.execution_code_binding.sources", "execution-path source digest differs from the run snapshot")
		}
	}
	policy := value.TestPolicy
	if policy.DefaultPolicyEvidencePath != "evidence/java/default-policy-behavior.json" || policy.DefaultPolicyEvidenceDigest != "sha256:8166ea6baa84399c17074ea771aa126bce612e833642e04dfb736e616ef7ef36" || policy.JavaSecurityDigest != promotedJavaSecurityDigest || policy.OverlayPath != "evidence/java/test-only-java.security" || policy.OverlayDigest != mavenTestSecurityOverlayDigest || policy.Assurance != ownerAttestedNotIndependent || policy.IndependentReviewClaimed || !policy.LocalOnly || !policy.NoSecretAccess || policy.ProductionPolicyModified {
		return finding("TEST_POLICY_BINDING_MISMATCH", "$.tests.test_policy", "test policy must bind the exact local owner-attested overlay without an independent-review claim")
	}
	return nil
}

func validateAutobahnEvidence(value autobahnEvidence) error {
	if err := validateEnvelope(value.evidenceEnvelope, AutobahnEvidenceSchema, "autobahn-baseline"); err != nil {
		return err
	}
	disposition := value.RerunDisposition
	if value.Assurance != ownerAttestedNotIndependent || value.IndependentReviewClaimed || value.Image.ManifestDigest != intake.AutobahnManifestDigest || value.Image.ManifestBytes != 3477 || value.Image.ConfigDigest != intake.AutobahnConfigDigest || value.Image.Platform != "linux/amd64" || value.Image.Layers != 15 || value.Image.PullPolicy != "never" || !value.Image.IdentityVerified || !equalStrings(value.SelectedFamilies, selectedAutobahnFamilies) || !equalStrings(value.ExcludedFamilies, excludedAutobahnFamilies) || value.Registry.Digest != PinnedAutobahnRegistryDigest || value.RiskDisposition.Classification != "QUARANTINED_LABORATORY_QUALIFICATION_ONLY" || value.RiskDisposition.ApprovedCriticalFindings != 12 || value.RiskDisposition.ApprovedHighFindings != 147 || disposition.AuthorizedRemediationAttemptsPerMode != 1 || disposition.ConsumedRemediationAttemptsPerMode != 1 || !disposition.OriginalReceiptRetained || disposition.FurtherRerunsAuthorized || disposition.Disposition != "NO_FURTHER_RERUNS_AUTHORIZED" {
		return finding("AUTOBAHN_BASELINE_IDENTITY_MISMATCH", "$.autobahn", "image, families, registry, and approved risk disposition must equal their pins")
	}
	if value.Blocker != nil {
		if err := validateEvidenceFinding(*value.Blocker, "$.autobahn.blocker"); err != nil {
			return err
		}
	}
	clientCases, clientReady, err := validateAutobahnEvidenceRun("client", value.Client)
	if err != nil {
		return err
	}
	serverCases, serverReady, err := validateAutobahnEvidenceRun("server", value.Server)
	if err != nil {
		return err
	}
	ready := value.Registry.StaticExpansionComplete && clientReady && serverReady && equalStrings(clientCases, serverCases)
	if ready {
		seenFamilies := make(map[string]bool)
		for _, id := range clientCases {
			seenFamilies[stringsBefore(id, ".")+".*"] = true
		}
		for _, family := range selectedAutobahnFamilies {
			if !seenFamilies[family] {
				ready = false
				break
			}
		}
	}
	switch value.Status {
	case "PASS":
		if !ready || value.Blocker != nil {
			return finding("CONTRADICTORY_EVIDENCE_STATUS", "$.autobahn.status", "PASS requires exact static expansion, matching executed client/server inventories, and no blocker")
		}
	case "BLOCKED":
		if ready || value.Blocker == nil {
			return finding("CONTRADICTORY_EVIDENCE_STATUS", "$.autobahn.status", "BLOCKED requires incomplete execution/reconciliation and a blocker")
		}
	default:
		return finding("INVALID_EVIDENCE_STATUS", "$.autobahn.status", "Autobahn status must be PASS or BLOCKED")
	}
	return nil
}

func validateAutobahnEvidenceRun(mode string, run autobahnEvidenceRun) ([]string, bool, error) {
	if !run.Attempted || run.AttemptCount != 2 || len(run.Attempts) != run.AttemptCount || run.FirstCaseID != "1.1.1" || run.SelectedCount != AutobahnSelectedCaseCount || !isDigest(run.AttemptStateDigest) || !isDigest(run.AttemptReceiptDigest) || run.AttemptReceiptBytes <= 0 || !isDigest(run.ConfigurationDigest) || run.ConfigurationBytes <= 0 {
		return nil, false, finding("INVALID_AUTOBAHN_ATTEMPT", "$.autobahn."+mode, "each mode requires the retained original attempt and the one owner-authorized remediation attempt over the 247-case selection")
	}
	for index, attempt := range run.Attempts {
		wantClassification := "ORIGINAL_AUTHORITATIVE"
		if index == 1 {
			wantClassification = "OWNER_AUTHORIZED_REMEDIATION"
		}
		path := fmt.Sprintf("$.autobahn.%s.attempts[%d]", mode, index)
		if attempt.Sequence != index+1 || attempt.Classification != wantClassification || !isDigest(attempt.PlanDigest) || !isDigest(attempt.ReceiptDigest) || attempt.ReceiptBytes <= 0 || attempt.Completed != attempt.Executed || attempt.CompletedCount < 0 || attempt.CompletedCount > run.SelectedCount || attempt.ResultCount < 0 || attempt.ResultCount > attempt.CompletedCount {
			return nil, false, finding("INVALID_AUTOBAHN_ATTEMPT_HISTORY", path, "attempt sequence, classification, receipt binding, execution state, or counts disagree")
		}
		if attempt.Completed {
			if attempt.CompletedCount != run.SelectedCount || attempt.ResultCount != run.SelectedCount || attempt.Blocker != nil {
				return nil, false, finding("INVALID_AUTOBAHN_ATTEMPT_HISTORY", path, "a completed attempt requires all 247 results and no blocker")
			}
		} else {
			if attempt.CompletedCount != 0 || attempt.ResultCount != 0 || attempt.Blocker == nil {
				return nil, false, finding("INVALID_AUTOBAHN_ATTEMPT_HISTORY", path, "an incomplete attempt requires zero results and a blocker")
			}
			if err := validateEvidenceFinding(*attempt.Blocker, path+".blocker"); err != nil {
				return nil, false, err
			}
		}
	}
	if first := run.Attempts[0]; first.ReceiptDigest != run.AttemptReceiptDigest || first.ReceiptBytes != run.AttemptReceiptBytes || first.Completed {
		return nil, false, finding("INVALID_AUTOBAHN_ATTEMPT_HISTORY", "$.autobahn."+mode+".attempts[0]", "retained original attempt must match the original detailed receipt binding")
	}
	latest := run.Attempts[len(run.Attempts)-1]
	if latest.Completed != run.Completed || latest.Executed != run.Executed || latest.CompletedCount != run.CompletedCount || latest.ResultCount != run.ResultCount {
		return nil, false, finding("CONTRADICTORY_AUTOBAHN_RUN", "$.autobahn."+mode, "run summary must equal the terminal authorized-remediation attempt")
	}
	if run.Completed != run.Executed || run.CompletedCount < 0 || run.CompletedCount > run.SelectedCount || run.ResultCount < 0 || run.ResultCount > run.CompletedCount || len(run.Results) != run.ResultCount {
		return nil, false, finding("CONTRADICTORY_AUTOBAHN_RUN", "$.autobahn."+mode, "attempt completion, execution, and exact result counts disagree")
	}
	if !run.Completed {
		if run.CompletedCount != 0 || run.ResultCount != 0 || len(run.Results) != 0 || run.BlockerDigest == nil || !isDigest(*run.BlockerDigest) || run.BlockerBytes == nil || *run.BlockerBytes <= 0 {
			return nil, false, finding("CONTRADICTORY_AUTOBAHN_RUN", "$.autobahn."+mode, "incomplete attempt requires zero completed results and an exact blocker artifact")
		}
		return nil, false, nil
	}
	if run.CompletedCount != run.SelectedCount || run.ResultCount != run.SelectedCount || run.BlockerDigest != nil || run.BlockerBytes != nil {
		return nil, false, finding("AUTOBAHN_RESULT_MISMATCH", "$.autobahn."+mode, "executed run must contain every exact selected result")
	}
	ids := make([]string, 0, len(run.Results))
	seen := make(map[string]struct{}, len(run.Results))
	for index, result := range run.Results {
		family := stringsBefore(result.CaseID, ".") + ".*"
		if !contains(selectedAutobahnFamilies, family) {
			return nil, false, finding("AUTOBAHN_RESULT_MISMATCH", fmt.Sprintf("$.autobahn.%s.results[%d]", mode, index), "result is outside the exact selected families")
		}
		if _, duplicate := seen[result.CaseID]; duplicate {
			return nil, false, finding("DUPLICATE_ENTRY", fmt.Sprintf("$.autobahn.%s.results[%d]", mode, index), "case result is duplicated")
		}
		binding, err := AutobahnResultBindingDigest(mode, result)
		if err != nil {
			return nil, false, err
		}
		if binding != result.BindingDigest {
			return nil, false, finding("AUTOBAHN_RESULT_BINDING_MISMATCH", fmt.Sprintf("$.autobahn.%s.results[%d]", mode, index), "result binding does not cover exact terminal evidence")
		}
		seen[result.CaseID] = struct{}{}
		ids = append(ids, result.CaseID)
	}
	sort.Strings(ids)
	return ids, true, nil
}

func stringsBefore(value, separator string) string {
	for index := 0; index+len(separator) <= len(value); index++ {
		if value[index:index+len(separator)] == separator {
			return value[:index]
		}
	}
	return value
}

func validateLedgerEvidence(value ledgerEvidence) error {
	if err := validateVersionedEnvelope(value.evidenceEnvelope, BehaviorLedgerSchema, "behavior-delta-ledger",
		BehaviorLedgerSchemaVersion); err != nil {
		return err
	}
	if value.NormativeAuthority != "rfc6455" || value.AppendImplementation != "hash-chained-cas" || !isDigest(value.Head) || value.UnledgeredDisagreements < 0 {
		return finding("INVALID_BEHAVIOR_LEDGER", "$.ledger", "ledger authority, append implementation, head, and disagreement count must be exact")
	}
	head, err := validateRecordChain(value.Records)
	if err != nil {
		return err
	}
	if head != value.Head {
		return finding("BEHAVIOR_LEDGER_HASH_MISMATCH", "$.ledger.head", "declared head does not equal the verified record chain")
	}
	// THE 1.1.0 ADDITION. The declared supersession array must equal the one the
	// records' own hashed rationales carry. Deriving it here rather than
	// believing the declaration is what makes the next check load-bearing: the
	// gate cannot be told that nothing is superseded.
	carried, err := ReadSupersessionLinks(value.Records)
	if err != nil {
		return finding("INVALID_BEHAVIOR_LEDGER", "$.ledger.supersessions", err.Error())
	}
	declared := value.Supersessions
	if declared == nil {
		declared = []SupersessionLink{}
	}
	if carried == nil {
		carried = []SupersessionLink{}
	}
	if !SupersessionLinksEqual(declared, carried) {
		return finding("BEHAVIOR_LEDGER_SUPERSESSION_MISMATCH", "$.ledger.supersessions",
			"declared supersessions do not equal the links the record chain's hashed rationales carry")
	}
	if value.UnledgeredDisagreements != 0 {
		return finding("UNLEDGERED_BEHAVIOR_DISAGREEMENT", "$.ledger.unledgered_disagreements", "readiness requires every observed disagreement to be ledgered")
	}
	switch value.Status {
	case "READY":
	case "BLOCKED_PENDING_BASELINE":
	default:
		return finding("INVALID_EVIDENCE_STATUS", "$.ledger.status", "ledger status is outside the exact vocabulary")
	}
	return nil
}
