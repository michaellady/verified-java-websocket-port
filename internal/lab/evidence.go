package lab

import (
	"fmt"
	"sort"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

const (
	JavaBuildEvidenceSchema   = "../../schemas/java-build-receipt-1.0.0.schema.json"
	JavaAdapterEvidenceSchema = "../../schemas/java-adapter-baseline-1.0.0.schema.json"
	JavaTestEvidenceSchema    = "../../schemas/java-test-manifest-1.0.0.schema.json"
	AutobahnEvidenceSchema    = "../../schemas/autobahn-baseline-1.0.0.schema.json"
	BehaviorLedgerSchema      = "../../schemas/behavior-delta-ledger-1.0.0.schema.json"
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
	Status    string `json:"status"`
	Assurance string `json:"assurance"`
	Source    struct {
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
	Counts          struct {
		StaticAnnotationOccurrences int  `json:"static_annotation_occurrences"`
		Discovered                  *int `json:"discovered"`
		Executed                    *int `json:"executed"`
		Passed                      *int `json:"passed"`
		Failed                      *int `json:"failed"`
		Skipped                     *int `json:"skipped"`
		Filtered                    *int `json:"filtered"`
		TimedOut                    *int `json:"timed_out"`
		Quarantined                 *int `json:"quarantined"`
	} `json:"counts"`
	NonTests []struct {
		Path          string `json:"path"`
		Kind          string `json:"kind"`
		Executable    bool   `json:"executable"`
		CountedAsTest bool   `json:"counted_as_test"`
	} `json:"non_tests"`
	Blocker *EvidenceFinding `json:"blocker"`
}

type autobahnEvidence struct {
	evidenceEnvelope
	Status string `json:"status"`
	Image  struct {
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
	Blocker *EvidenceFinding `json:"blocker"`
}

type autobahnEvidenceRun struct {
	Executed      bool             `json:"executed"`
	SelectedCount *int             `json:"selected_count"`
	ResultCount   *int             `json:"result_count"`
	Results       []AutobahnResult `json:"results,omitempty"`
}

type ledgerEvidence struct {
	evidenceEnvelope
	Status                  string                 `json:"status"`
	NormativeAuthority      string                 `json:"normative_authority"`
	Head                    string                 `json:"head"`
	Records                 []BehaviorLedgerRecord `json:"records"`
	AppendImplementation    string                 `json:"append_implementation"`
	UnledgeredDisagreements int                    `json:"unledgered_disagreements"`
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

func validateAggregateDisagreementLedger(autobahn autobahnEvidence, ledger ledgerEvidence) error {
	if autobahn.Status != "PASS" {
		return nil
	}
	ledgered := make(map[string]struct{}, len(ledger.Records))
	for _, record := range ledger.Records {
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
	if envelope.Schema != schema || envelope.SchemaVersion != "1.0.0" || envelope.EvidenceKind != kind || !isDigest(envelope.AcceptedRootDigest) {
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
	if value.Assurance != "OWNER_ATTESTED_NOT_INDEPENDENT" || value.Source.ObjectID != "java-websocket-source-archive" || value.Source.Version != "1.6.0" || value.Source.Digest != pinnedJavaSourceDigest || value.Source.ProductionSourceModified {
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
	if value.Counts.StaticAnnotationOccurrences != 231 {
		return finding("INVALID_TEST_INVENTORY", "$.tests.counts", "static annotation inventory must equal the pinned source count")
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
	if value.Blocker != nil {
		if err := validateEvidenceFinding(*value.Blocker, "$.tests.blocker"); err != nil {
			return err
		}
	}
	counts := []*int{value.Counts.Discovered, value.Counts.Executed, value.Counts.Passed, value.Counts.Failed, value.Counts.Skipped, value.Counts.Filtered, value.Counts.TimedOut, value.Counts.Quarantined}
	allCounts := true
	for _, count := range counts {
		if count == nil {
			allCounts = false
		} else if *count < 0 {
			return finding("INVALID_TEST_INVENTORY", "$.tests.counts", "dynamic counts cannot be negative")
		}
	}
	ready := allCounts && value.InventoryStatus == "RECONCILED" && *value.Counts.Discovered == value.Counts.StaticAnnotationOccurrences && *value.Counts.Executed == *value.Counts.Discovered && *value.Counts.Passed == *value.Counts.Executed && *value.Counts.Failed == 0 && *value.Counts.Skipped == 0 && *value.Counts.Filtered == 0 && *value.Counts.TimedOut == 0 && *value.Counts.Quarantined == 0
	switch value.Status {
	case "PASS":
		if !ready || value.Blocker != nil {
			return finding("CONTRADICTORY_EVIDENCE_STATUS", "$.tests.status", "PASS requires exact reconciled discovery/execution counts and no blocker")
		}
	case "BLOCKED":
		if ready || value.Blocker == nil {
			return finding("CONTRADICTORY_EVIDENCE_STATUS", "$.tests.status", "BLOCKED requires an unreconciled or unsuccessful inventory and a blocker")
		}
	default:
		return finding("INVALID_EVIDENCE_STATUS", "$.tests.status", "test status must be PASS or BLOCKED")
	}
	if value.InventoryStatus != "RECONCILED" && value.InventoryStatus != "NOT_RECONCILED" {
		return finding("INVALID_TEST_INVENTORY", "$.tests.inventory_status", "inventory status is outside the exact vocabulary")
	}
	return nil
}

func validateAutobahnEvidence(value autobahnEvidence) error {
	if err := validateEnvelope(value.evidenceEnvelope, AutobahnEvidenceSchema, "autobahn-baseline"); err != nil {
		return err
	}
	if value.Image.ManifestDigest != intake.AutobahnManifestDigest || value.Image.ManifestBytes != 3477 || value.Image.ConfigDigest != intake.AutobahnConfigDigest || value.Image.Platform != "linux/amd64" || value.Image.Layers != 15 || value.Image.PullPolicy != "never" || !value.Image.IdentityVerified || !equalStrings(value.SelectedFamilies, selectedAutobahnFamilies) || !equalStrings(value.ExcludedFamilies, excludedAutobahnFamilies) || value.Registry.Digest != PinnedAutobahnRegistryDigest || value.RiskDisposition.Classification != "QUARANTINED_LABORATORY_QUALIFICATION_ONLY" || value.RiskDisposition.ApprovedCriticalFindings != 12 || value.RiskDisposition.ApprovedHighFindings != 147 {
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
	if !run.Executed {
		if run.SelectedCount != nil || run.ResultCount != nil || len(run.Results) != 0 {
			return nil, false, finding("CONTRADICTORY_AUTOBAHN_RUN", "$.autobahn."+mode, "unexecuted runs cannot claim counts or results")
		}
		return nil, false, nil
	}
	if run.SelectedCount == nil || run.ResultCount == nil || *run.SelectedCount <= 0 || *run.ResultCount != *run.SelectedCount || len(run.Results) != *run.ResultCount {
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
	if err := validateEnvelope(value.evidenceEnvelope, BehaviorLedgerSchema, "behavior-delta-ledger"); err != nil {
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
