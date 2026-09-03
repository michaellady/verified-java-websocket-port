package lab

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/corpora"
	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

const (
	RustAutobahnStatus             = "READY_NO_LIVE_CONFORMANCE"
	RustAutobahnLiveStatus         = "BLOCKED_NOT_EXECUTED"
	RustAutobahnFixtureAgent       = "verified-rust-websocket-port-us019"
	rustAutobahnManifestRelative   = "autobahn/case-manifest.json"
	rustAutobahnClientPlanRelative = "autobahn/fuzzingclient.json"
	rustAutobahnServerPlanRelative = "autobahn/fuzzingserver.json"
	rustAutobahnUS018Relative      = "evidence/us018-blocking-adapters.json"
	rustAutobahnBaselineRelative   = "evidence/java/autobahn-baseline.json"
	rustAutobahnSchemaRelative     = "schemas/us019-autobahn-rust-readiness-1.0.0.schema.json"
	rustAutobahnEvidenceRelative   = "evidence/us019-autobahn-rust-readiness.json"
	rustAutobahnCargoLockRelative  = "rust/Cargo.lock"
	rustAutobahnSourceTreeRelative = "rust/websocket-testee/src"
	rustAutobahnMaximumDocument    = 16 << 20
	rustAutobahnMaximumExecutable  = 128 << 20
	rustAutobahnProcessOutputLimit = 4096
	rustAutobahnPreparationVersion = "1.0.0"
	rustAutobahnSyntheticOrigin    = "SYNTHETIC_RECONCILIATION_FIXTURE"
	rustAutobahnSelectionPolicy    = "STATIC_SELECTED_AND_NONSELECTED_NEVER_SKIPS"
	rustAutobahnStaticNonceDomain  = "us019-static-client-nonce-v1"
	rustAutobahnHistoricalTree     = "sha256:ee9c54136153a002bd4f7a28298140a59841daaa75386d4595847511be7fdcf1"
	rustAutobahnSelectedIDsDigest  = "sha256:9cfd2be36f5b48445e6bfd7664b54cfe6f06911ac89b49660cf90ae432e96697"
	rustAutobahnExcludedIDsDigest  = "sha256:ef3712e4397fc23e906e7581c20d1c271cf4b256b3698853a5717e9f44dd1224"
	rustAutobahnGateNotExecuted    = "NOT_EXECUTED_BY_PREPARATION"
)

var rustAutobahnBlockers = []string{
	"APPLICATION_ECHO_UNAVAILABLE",
	"MULTI_CASE_LIFECYCLE_UNAVAILABLE",
	"SERVER_READINESS_UNAVAILABLE",
	"LIVE_RUN_NOT_AUTHORIZED",
	"LINUX_X86_64_NOT_EXECUTED",
}

var rustAutobahnNonclaims = []string{
	"no fresh Autobahn fuzzing-server or fuzzing-client execution",
	"no Rust Autobahn case executed passed failed timed out skipped or strict-passed",
	"no application echo or multi-case lifecycle",
	"no historical Java or sibling result applies to Rust",
	"no empty or planted Rust binary Autobahn execution",
	"reference-model mutants are not Rust binary mutation evidence",
	"no Linux x86_64 or second host",
	"no production publication signing release or reproducible build",
	"no independent review formal proof or exhaustive security",
	"no authorization for a later suite run",
	"testee binary digest, byte count, host, and rustc version are preparation-only observations and are not reverified by static receipt verification",
}

var rustAutobahnHostPattern = regexp.MustCompile(`^[a-z0-9_]+/[a-z0-9_]+$`)

type RustAutobahnPreparationConfig struct {
	RepositoryRoot       string
	SourceArchivePath    string
	CaseManifestPath     string
	ClientPlanPath       string
	ServerPlanPath       string
	TesteePath           string
	US018EvidencePath    string
	RetainedBaselinePath string
}

type RustAutobahnCaseManifest struct {
	SchemaVersion         string   `json:"schema_version"`
	SourceArchiveDigest   string   `json:"source_archive_digest"`
	RegistrySourceDigest  string   `json:"registry_source_digest"`
	ReportSourceDigest    string   `json:"report_source_digest"`
	ImageManifestDigest   string   `json:"image_manifest_digest"`
	ImageConfigDigest     string   `json:"image_config_digest"`
	SelectedFamilies      []string `json:"selected_families"`
	NonselectedFamilies   []string `json:"nonselected_families"`
	SelectedCaseIDs       []string `json:"selected_case_ids"`
	NonselectedCaseIDs    []string `json:"nonselected_case_ids"`
	SelectedCount         int      `json:"selected_count"`
	NonselectedCount      int      `json:"nonselected_count"`
	SelectedCaseIDsDigest string   `json:"selected_case_ids_digest"`
	NonselectedIDsDigest  string   `json:"nonselected_case_ids_digest"`
	SelectionPolicy       string   `json:"selection_policy"`
}

type RustAutobahnRoute struct {
	CaseID           string `json:"case_id"`
	RustProcessRoute string `json:"rust_process_route"`
	SessionKind      string `json:"session_kind"`
	StaticNonceHex   string `json:"static_nonce_hex,omitempty"`
}

type RustAutobahnArgumentTemplate struct {
	SessionKind   string   `json:"session_kind"`
	RequestTarget string   `json:"request_target,omitempty"`
	HostAuthority string   `json:"host_authority,omitempty"`
	Tokens        []string `json:"tokens"`
}

type RustAutobahnInertPlan struct {
	SchemaVersion         string                         `json:"schema_version"`
	Status                string                         `json:"status"`
	ExecutionAuthorized   bool                           `json:"execution_authorized"`
	SuiteProcessAllowed   bool                           `json:"suite_process_allowed"`
	SuiteMode             string                         `json:"suite_mode"`
	RustRole              string                         `json:"rust_role"`
	FixtureAgent          string                         `json:"fixture_agent"`
	CaseManifestDigest    string                         `json:"case_manifest_digest"`
	ImageManifestDigest   string                         `json:"image_manifest_digest"`
	ImageConfigDigest     string                         `json:"image_config_digest"`
	ReportSourceDigest    string                         `json:"report_source_digest"`
	Transport             string                         `json:"transport"`
	CleanWorkspace        bool                           `json:"clean_workspace"`
	ExpectedCases         int                            `json:"expected_cases"`
	PlannedConfigurations int                            `json:"planned_configurations"`
	PlannedSessions       int                            `json:"planned_sessions"`
	ResourceBounds        RustAutobahnBounds             `json:"resource_bounds"`
	Blockers              []string                       `json:"blockers"`
	ArgumentTemplates     []RustAutobahnArgumentTemplate `json:"argument_templates"`
	Routes                []RustAutobahnRoute            `json:"routes"`
}

type RustAutobahnBounds struct {
	LoopbackOnly       bool `json:"loopback_only"`
	OneCasePerProcess  bool `json:"one_case_per_process"`
	ProcessTimeoutSecs int  `json:"process_timeout_seconds"`
	MaximumOutputBytes int  `json:"maximum_output_bytes"`
}

type RustAutobahnCounts struct {
	Expected      int `json:"expected"`
	Selected      int `json:"selected"`
	Executed      int `json:"executed"`
	Passed        int `json:"passed"`
	Failed        int `json:"failed"`
	NonStrict     int `json:"non_strict"`
	Informational int `json:"informational"`
	Skipped       int `json:"skipped"`
	Filtered      int `json:"filtered"`
	TimedOut      int `json:"timed_out"`
	Missing       int `json:"missing"`
}

type RustAutobahnFixtureSummary struct {
	Mode                 string `json:"mode"`
	Origin               string `json:"origin"`
	LiveExecution        bool   `json:"live_execution"`
	SuiteInvoked         bool   `json:"suite_invoked"`
	FixtureObserved      int    `json:"fixture_observed"`
	FixtureOK            int    `json:"fixture_ok"`
	FixtureFailed        int    `json:"fixture_failed"`
	FixtureNonStrict     int    `json:"fixture_non_strict"`
	FixtureInformational int    `json:"fixture_informational"`
	FixtureUnimplemented int    `json:"fixture_unimplemented"`
	Missing              int    `json:"missing"`
	ResultDigest         string `json:"result_digest"`
	EnvelopeDigest       string `json:"envelope_digest"`
	Disposition          string `json:"disposition"`
}

type RustAutobahnControlOutcome struct {
	ControlID string `json:"control_id"`
	Outcome   string `json:"outcome"`
}

type RustAutobahnReferenceMutants struct {
	Total             int `json:"total"`
	Killed            int `json:"killed"`
	Surviving         int `json:"surviving"`
	IdentitySurviving int `json:"identity_surviving"`
}

type RustAutobahnControls struct {
	Repetitions      int                          `json:"repetitions"`
	OutcomeDigest    string                       `json:"outcome_digest"`
	EmptyStub        RustAutobahnControlOutcome   `json:"empty_stub"`
	FixtureMutants   []RustAutobahnControlOutcome `json:"fixture_mutants"`
	LineageMutants   []RustAutobahnControlOutcome `json:"lineage_mutants"`
	HistoryFirewall  RustAutobahnControlOutcome   `json:"history_firewall"`
	ReferenceMutants RustAutobahnReferenceMutants `json:"reference_model_mutants"`
}

type RustAutobahnRetainedHistory struct {
	Path                    string   `json:"path"`
	Digest                  string   `json:"digest"`
	Status                  string   `json:"status"`
	Disposition             string   `json:"disposition"`
	FurtherRerunsAuthorized bool     `json:"further_reruns_authorized"`
	ClientAttempts          int      `json:"client_attempts"`
	ServerAttempts          int      `json:"server_attempts"`
	ClientExecuted          bool     `json:"client_executed"`
	ServerExecuted          bool     `json:"server_executed"`
	ClientResultCount       int      `json:"client_result_count"`
	ServerResultCount       int      `json:"server_result_count"`
	AttemptReceiptDigests   []string `json:"attempt_receipt_digests"`
}

type RustAutobahnPreparationReceipt struct {
	Schema                   string                      `json:"$schema"`
	SchemaVersion            string                      `json:"schema_version"`
	EvidenceID               string                      `json:"evidence_id"`
	StoryID                  string                      `json:"story_id"`
	Status                   string                      `json:"status"`
	LiveConformanceStatus    string                      `json:"live_conformance_status"`
	Assurance                string                      `json:"assurance"`
	IndependentReviewClaimed bool                        `json:"independent_review_claimed"`
	StrictPassClaimed        bool                        `json:"strict_pass_claimed"`
	Production               bool                        `json:"production"`
	Publication              bool                        `json:"publication"`
	Signing                  bool                        `json:"signing"`
	Manifest                 RustAutobahnArtifact        `json:"manifest"`
	ClientPlan               RustAutobahnArtifact        `json:"client_plan"`
	ServerPlan               RustAutobahnArtifact        `json:"server_plan"`
	Source                   RustAutobahnSource          `json:"source"`
	Testee                   RustAutobahnTestee          `json:"testee"`
	US018                    RustAutobahnUS018           `json:"us018"`
	LiveClient               RustAutobahnCounts          `json:"live_client"`
	LiveServer               RustAutobahnCounts          `json:"live_server"`
	SyntheticClient          RustAutobahnFixtureSummary  `json:"synthetic_client"`
	SyntheticServer          RustAutobahnFixtureSummary  `json:"synthetic_server"`
	Controls                 RustAutobahnControls        `json:"controls"`
	RetainedHistory          RustAutobahnRetainedHistory `json:"retained_history"`
	Architecture             RustAutobahnArchitecture    `json:"architecture"`
	Gates                    RustAutobahnGates           `json:"gates"`
	Nonclaims                []string                    `json:"nonclaims"`
}

type RustAutobahnArtifact struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
	Bytes  int64  `json:"bytes"`
}

type RustAutobahnSource struct {
	ArchiveDigest       string `json:"archive_digest"`
	RegistryDigest      string `json:"registry_digest"`
	ReportSourceDigest  string `json:"report_source_digest"`
	ImageManifestDigest string `json:"image_manifest_digest"`
	ImageConfigDigest   string `json:"image_config_digest"`
}

type RustAutobahnTestee struct {
	PreparationObservedBinaryDigest  string `json:"preparation_observed_binary_digest"`
	PreparationObservedBinaryBytes   int64  `json:"preparation_observed_binary_bytes"`
	BinaryReverifiedByStaticVerifier bool   `json:"binary_reverified_by_static_verifier"`
	SourceTreeDigest                 string `json:"source_tree_digest"`
	CargoLockDigest                  string `json:"cargo_lock_digest"`
	Host                             string `json:"host"`
	RustcVersion                     string `json:"rustc_version"`
	Challenge                        string `json:"challenge"`
	TranscriptDigest                 string `json:"transcript_digest"`
	ArgumentContract                 string `json:"argument_contract"`
}

type RustAutobahnUS018 struct {
	Path            string `json:"path"`
	Digest          string `json:"digest"`
	Status          string `json:"status"`
	RustcVersion    string `json:"rustc_version"`
	ApplicationEcho bool   `json:"application_echo"`
	Conformance     bool   `json:"conformance"`
	LinuxX8664      bool   `json:"linux_x86_64"`
}

type RustAutobahnArchitecture struct {
	InertLiveLinkage         bool `json:"inert_live_linkage"`
	TesteeLinkagePresent     bool `json:"testee_linkage_present"`
	ManifestExact            bool `json:"manifest_exact"`
	SyntheticHistoryDistinct bool `json:"synthetic_history_distinct"`
	ArchitectureCanaries     int  `json:"architecture_canaries"`
}

type RustAutobahnGates struct {
	FocusedGo   string `json:"focused_go"`
	RustDebug   string `json:"rust_debug"`
	RustRelease string `json:"rust_release"`
	Rustfmt     string `json:"rustfmt"`
	Clippy      string `json:"clippy"`
	Rustgate    string `json:"rustgate"`
	FullGo      string `json:"full_go"`
}

type rustAutobahnFixtureEnvelope struct {
	Origin            string `json:"origin"`
	LiveExecution     bool   `json:"live_execution"`
	SuiteInvoked      bool   `json:"suite_invoked"`
	PreparationDigest string `json:"preparation_digest"`
	ChallengeDigest   string `json:"challenge_digest"`
	ManifestDigest    string `json:"manifest_digest"`
	Mode              string `json:"mode"`
	ControlID         string `json:"control_id"`
	ResultsDigest     string `json:"results_digest"`
}

type rustAutobahnBaseline struct {
	Status                   string `json:"status"`
	Assurance                string `json:"assurance"`
	IndependentReviewClaimed bool   `json:"independent_review_claimed"`
	RerunDisposition         struct {
		Authorized       int    `json:"authorized_remediation_attempts_per_mode"`
		Consumed         int    `json:"consumed_remediation_attempts_per_mode"`
		OriginalRetained bool   `json:"original_receipt_retained"`
		Further          bool   `json:"further_reruns_authorized"`
		Disposition      string `json:"disposition"`
	} `json:"rerun_disposition"`
	Client rustAutobahnBaselineMode `json:"client"`
	Server rustAutobahnBaselineMode `json:"server"`
}

type rustAutobahnBaselineMode struct {
	AttemptCount int  `json:"attempt_count"`
	Executed     bool `json:"executed"`
	ResultCount  int  `json:"result_count"`
	Attempts     []struct {
		Sequence       int    `json:"sequence"`
		Classification string `json:"classification"`
		ReceiptDigest  string `json:"receipt_digest"`
		Executed       bool   `json:"executed"`
		ResultCount    int    `json:"result_count"`
	} `json:"attempts"`
}

func BuildRustAutobahnStaticDocuments(archive []byte) ([]byte, []byte, []byte, error) {
	registry, err := ParsePinnedAutobahnRegistryArchive(archive, PinnedAutobahnSourceArchiveDigest)
	if err != nil {
		return nil, nil, nil, err
	}
	selection, err := SelectAutobahnRegistry(registry)
	if err != nil {
		return nil, nil, nil, err
	}
	manifest := RustAutobahnCaseManifest{
		SchemaVersion:         rustAutobahnPreparationVersion,
		SourceArchiveDigest:   PinnedAutobahnSourceArchiveDigest,
		RegistrySourceDigest:  PinnedAutobahnRegistryDigest,
		ReportSourceDigest:    PinnedAutobahnReportSourceDigest,
		ImageManifestDigest:   AutobahnImageManifestDigest,
		ImageConfigDigest:     AutobahnImageConfigDigest,
		SelectedFamilies:      append([]string(nil), selection.SelectedFamilies...),
		NonselectedFamilies:   append([]string(nil), selection.ExcludedFamilies...),
		SelectedCaseIDs:       append([]string(nil), selection.SelectedCaseIDs...),
		NonselectedCaseIDs:    append([]string(nil), selection.ExcludedCaseIDs...),
		SelectedCount:         len(selection.SelectedCaseIDs),
		NonselectedCount:      len(selection.ExcludedCaseIDs),
		SelectedCaseIDsDigest: digestStringSlice(selection.SelectedCaseIDs),
		NonselectedIDsDigest:  digestStringSlice(selection.ExcludedCaseIDs),
		SelectionPolicy:       rustAutobahnSelectionPolicy,
	}
	manifestBytes, err := canonicalDocument(manifest)
	if err != nil {
		return nil, nil, nil, err
	}
	client := buildRustAutobahnPlan(manifest, intake.DigestBytes(manifestBytes), "fuzzing-server", "client")
	server := buildRustAutobahnPlan(manifest, intake.DigestBytes(manifestBytes), "fuzzing-client", "server")
	clientBytes, err := canonicalDocument(client)
	if err != nil {
		return nil, nil, nil, err
	}
	serverBytes, err := canonicalDocument(server)
	if err != nil {
		return nil, nil, nil, err
	}
	return manifestBytes, clientBytes, serverBytes, nil
}

func buildRustAutobahnPlan(manifest RustAutobahnCaseManifest, manifestDigest, suiteMode, role string) RustAutobahnInertPlan {
	plan := RustAutobahnInertPlan{
		SchemaVersion:         rustAutobahnPreparationVersion,
		Status:                RustAutobahnStatus,
		ExecutionAuthorized:   false,
		SuiteProcessAllowed:   false,
		SuiteMode:             suiteMode,
		RustRole:              role,
		FixtureAgent:          RustAutobahnFixtureAgent,
		CaseManifestDigest:    manifestDigest,
		ImageManifestDigest:   AutobahnImageManifestDigest,
		ImageConfigDigest:     AutobahnImageConfigDigest,
		ReportSourceDigest:    PinnedAutobahnReportSourceDigest,
		Transport:             "loopback-only-inert-plan",
		CleanWorkspace:        true,
		ExpectedCases:         manifest.SelectedCount,
		PlannedConfigurations: manifest.SelectedCount,
		ResourceBounds:        RustAutobahnBounds{LoopbackOnly: true, OneCasePerProcess: true, ProcessTimeoutSecs: 30, MaximumOutputBytes: rustAutobahnProcessOutputLimit},
		Blockers:              append([]string(nil), rustAutobahnBlockers...),
	}
	if role == "client" {
		plan.ArgumentTemplates = []RustAutobahnArgumentTemplate{
			{SessionKind: "run-case", RequestTarget: "/runCase?case=1&agent=" + RustAutobahnFixtureAgent, HostAuthority: "127.0.0.1", Tokens: []string{"client", "{loopback-address}", "{request-target}", "{host-authority}", "{static-nonce}", "{io-bounds}"}},
			{SessionKind: "update-reports", RequestTarget: "/updateReports?agent=" + RustAutobahnFixtureAgent, HostAuthority: "127.0.0.1", Tokens: []string{"client", "{loopback-address}", "{request-target}", "{host-authority}", "{static-nonce}", "{io-bounds}"}},
		}
	} else {
		plan.ArgumentTemplates = []RustAutobahnArgumentTemplate{{SessionKind: "one-case-server", Tokens: []string{"server", "{loopback-address}", "{io-bounds}"}}}
	}
	for _, caseID := range manifest.SelectedCaseIDs {
		if role == "client" {
			plan.Routes = append(plan.Routes,
				RustAutobahnRoute{CaseID: caseID, RustProcessRoute: role, SessionKind: "run-case", StaticNonceHex: staticRustAutobahnNonce(manifestDigest, caseID, "run-case")},
				RustAutobahnRoute{CaseID: caseID, RustProcessRoute: role, SessionKind: "update-reports", StaticNonceHex: staticRustAutobahnNonce(manifestDigest, caseID, "update-reports")},
			)
		} else {
			plan.Routes = append(plan.Routes, RustAutobahnRoute{CaseID: caseID, RustProcessRoute: role, SessionKind: "one-case-server"})
		}
	}
	plan.PlannedSessions = len(plan.Routes)
	return plan
}

func staticRustAutobahnNonce(manifestDigest, caseID, kind string) string {
	return strings.TrimPrefix(intake.DigestBytes([]byte(rustAutobahnStaticNonceDomain+"\x00"+manifestDigest+"\x00"+caseID+"\x00"+kind)), "sha256:")[:32]
}

func canonicalDocument(value any) ([]byte, error) {
	data, err := intake.CanonicalJSON(value)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func VerifyRustAutobahnStaticFiles(repositoryRoot string) error {
	root, err := realRepositoryRoot(repositoryRoot)
	if err != nil {
		return err
	}
	manifestBytes, err := readBoundedRegular(filepath.Join(root, rustAutobahnManifestRelative), rustAutobahnMaximumDocument)
	if err != nil {
		return err
	}
	var manifest RustAutobahnCaseManifest
	if err := intake.DecodeStrict(manifestBytes, &manifest); err != nil {
		return finding("AUTOBAHN_MANIFEST_DRIFT", "$.manifest", err.Error())
	}
	if err := validateRustAutobahnManifest(manifest); err != nil {
		return err
	}
	canonicalManifest, err := canonicalDocument(manifest)
	if err != nil || !bytes.Equal(canonicalManifest, manifestBytes) {
		return finding("AUTOBAHN_MANIFEST_DRIFT", "$.manifest", "manifest must be canonical JSON")
	}
	manifestDigest := intake.DigestBytes(manifestBytes)
	for _, item := range []struct{ path, mode, role string }{
		{rustAutobahnClientPlanRelative, "fuzzing-server", "client"},
		{rustAutobahnServerPlanRelative, "fuzzing-client", "server"},
	} {
		actual, err := readBoundedRegular(filepath.Join(root, item.path), rustAutobahnMaximumDocument)
		if err != nil {
			return err
		}
		expected, err := canonicalDocument(buildRustAutobahnPlan(manifest, manifestDigest, item.mode, item.role))
		if err != nil || !bytes.Equal(expected, actual) {
			return finding("AUTOBAHN_MANIFEST_DRIFT", item.path, "inert plan differs from the exact manifest-derived role inventory")
		}
	}
	return nil
}

func validateRustAutobahnManifest(manifest RustAutobahnCaseManifest) error {
	if manifest.SchemaVersion != rustAutobahnPreparationVersion || manifest.SourceArchiveDigest != PinnedAutobahnSourceArchiveDigest || manifest.RegistrySourceDigest != PinnedAutobahnRegistryDigest || manifest.ReportSourceDigest != PinnedAutobahnReportSourceDigest || manifest.ImageManifestDigest != AutobahnImageManifestDigest || manifest.ImageConfigDigest != AutobahnImageConfigDigest || manifest.SelectionPolicy != rustAutobahnSelectionPolicy {
		return finding("AUTOBAHN_MANIFEST_DRIFT", "$.manifest", "manifest pins or policy differ")
	}
	if !equalStrings(manifest.SelectedFamilies, selectedAutobahnFamilies) || !equalStrings(manifest.NonselectedFamilies, excludedAutobahnFamilies) || manifest.SelectedCount != AutobahnSelectedCaseCount || manifest.NonselectedCount != AutobahnExcludedCaseCount || len(manifest.SelectedCaseIDs) != manifest.SelectedCount || len(manifest.NonselectedCaseIDs) != manifest.NonselectedCount || manifest.SelectedCaseIDsDigest != rustAutobahnSelectedIDsDigest || manifest.NonselectedIDsDigest != rustAutobahnExcludedIDsDigest || manifest.SelectedCaseIDsDigest != digestStringSlice(manifest.SelectedCaseIDs) || manifest.NonselectedIDsDigest != digestStringSlice(manifest.NonselectedCaseIDs) {
		return finding("AUTOBAHN_MANIFEST_DRIFT", "$.manifest", "family, count, or list digest differs")
	}
	if !sort.StringsAreSorted(manifest.SelectedCaseIDs) || !sort.StringsAreSorted(manifest.NonselectedCaseIDs) {
		return finding("AUTOBAHN_MANIFEST_DRIFT", "$.manifest", "case identities must be lexically ordered")
	}
	all := append(append([]string(nil), manifest.SelectedCaseIDs...), manifest.NonselectedCaseIDs...)
	seen := map[string]bool{}
	for _, id := range all {
		if !autobahnCasePattern.MatchString(id) || strings.ContainsAny(id, "*Xx") || seen[id] {
			return finding("AUTOBAHN_MANIFEST_DRIFT", "$.manifest", "case identities must be unique fully numeric IDs")
		}
		seen[id] = true
	}
	return nil
}

func PrepareRustAutobahn(ctx context.Context, config RustAutobahnPreparationConfig) (RustAutobahnPreparationReceipt, error) {
	if ctx == nil {
		return RustAutobahnPreparationReceipt{}, finding("INVALID_AUTOBAHN_RUST_CONFIG", "$", "context is required")
	}
	root, err := realRepositoryRoot(config.RepositoryRoot)
	if err != nil {
		return RustAutobahnPreparationReceipt{}, err
	}
	expectedPaths := map[string]string{
		"$.case_manifest":     rustAutobahnManifestRelative,
		"$.client_plan":       rustAutobahnClientPlanRelative,
		"$.server_plan":       rustAutobahnServerPlanRelative,
		"$.us018_evidence":    rustAutobahnUS018Relative,
		"$.retained_baseline": rustAutobahnBaselineRelative,
	}
	actualPaths := map[string]string{
		"$.case_manifest":     config.CaseManifestPath,
		"$.client_plan":       config.ClientPlanPath,
		"$.server_plan":       config.ServerPlanPath,
		"$.us018_evidence":    config.US018EvidencePath,
		"$.retained_baseline": config.RetainedBaselinePath,
	}
	for field, relative := range expectedPaths {
		if actualPaths[field] != filepath.Join(root, filepath.FromSlash(relative)) {
			return RustAutobahnPreparationReceipt{}, finding("INVALID_PATH", field, "path must equal the exact repository artifact")
		}
	}
	for field, value := range map[string]string{"$.source_archive": config.SourceArchivePath, "$.testee": config.TesteePath} {
		if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value || value == string(filepath.Separator) {
			return RustAutobahnPreparationReceipt{}, finding("INVALID_PATH", field, "path must be clean, absolute, and narrower than the filesystem root")
		}
	}
	if err := VerifyRustAutobahnStaticFiles(root); err != nil {
		return RustAutobahnPreparationReceipt{}, err
	}
	if err := VerifyRustAutobahnArchitectureFiles(root); err != nil {
		return RustAutobahnPreparationReceipt{}, err
	}
	archive, err := readBoundedRegular(config.SourceArchivePath, 16<<20)
	if err != nil {
		return RustAutobahnPreparationReceipt{}, err
	}
	expectedManifest, expectedClient, expectedServer, err := BuildRustAutobahnStaticDocuments(archive)
	if err != nil {
		return RustAutobahnPreparationReceipt{}, err
	}
	for _, pair := range []struct {
		path     string
		expected []byte
	}{{config.CaseManifestPath, expectedManifest}, {config.ClientPlanPath, expectedClient}, {config.ServerPlanPath, expectedServer}} {
		actual, readErr := readBoundedRegular(pair.path, rustAutobahnMaximumDocument)
		if readErr != nil || !bytes.Equal(actual, pair.expected) {
			return RustAutobahnPreparationReceipt{}, finding("AUTOBAHN_MANIFEST_DRIFT", pair.path, "committed static artifact differs from pinned archive derivation")
		}
	}
	manifestBytes, _ := readBoundedRegular(config.CaseManifestPath, rustAutobahnMaximumDocument)
	clientBytes, _ := readBoundedRegular(config.ClientPlanPath, rustAutobahnMaximumDocument)
	serverBytes, _ := readBoundedRegular(config.ServerPlanPath, rustAutobahnMaximumDocument)
	var manifest RustAutobahnCaseManifest
	_ = intake.DecodeStrict(manifestBytes, &manifest)
	var clientPlan, serverPlan RustAutobahnInertPlan
	_ = intake.DecodeStrict(clientBytes, &clientPlan)
	_ = intake.DecodeStrict(serverBytes, &serverPlan)

	us018Bytes, err := readBoundedRegular(config.US018EvidencePath, rustAutobahnMaximumDocument)
	if err != nil {
		return RustAutobahnPreparationReceipt{}, err
	}
	us018, err := verifyUS018RustAutobahnInput(us018Bytes)
	if err != nil {
		return RustAutobahnPreparationReceipt{}, err
	}
	baselineBytes, err := readBoundedRegular(config.RetainedBaselinePath, rustAutobahnMaximumDocument)
	if err != nil {
		return RustAutobahnPreparationReceipt{}, err
	}
	history, err := validateRustAutobahnHistory(baselineBytes)
	if err != nil {
		return RustAutobahnPreparationReceipt{}, err
	}

	testeeBytes, err := readBoundedRegular(config.TesteePath, rustAutobahnMaximumExecutable)
	if err != nil {
		return RustAutobahnPreparationReceipt{}, err
	}
	info, err := os.Lstat(config.TesteePath)
	if err != nil || info.Mode().Perm()&0o111 == 0 {
		return RustAutobahnPreparationReceipt{}, finding("RUST_TESTEE_NOT_EXERCISED", "$.testee", "testee must be one executable regular file")
	}
	challengeRaw := make([]byte, 32)
	if _, err := rand.Read(challengeRaw); err != nil {
		return RustAutobahnPreparationReceipt{}, finding("RANDOMNESS_UNAVAILABLE", "$.challenge", err.Error())
	}
	challenge := hex.EncodeToString(challengeRaw)
	stagedTestee, cleanupStagedTestee, err := stageRustAutobahnTestee(testeeBytes)
	if err != nil {
		return RustAutobahnPreparationReceipt{}, err
	}
	defer cleanupStagedTestee()
	transcript, err := runRustAutobahnContract(ctx, stagedTestee, challenge)
	if err != nil {
		return RustAutobahnPreparationReceipt{}, err
	}
	observedTesteeBytes, err := readBoundedRegular(stagedTestee, rustAutobahnMaximumExecutable)
	if err != nil || !bytes.Equal(observedTesteeBytes, testeeBytes) {
		return RustAutobahnPreparationReceipt{}, finding("CONCURRENT_FILE_DRIFT", "$.testee", "private testee copy changed while exercising the process contract")
	}

	sourceTreeDigest, _, err := digestTree(filepath.Join(root, rustAutobahnSourceTreeRelative), true)
	if err != nil {
		return RustAutobahnPreparationReceipt{}, err
	}
	cargoLock, err := readBoundedRegular(filepath.Join(root, rustAutobahnCargoLockRelative), rustAutobahnMaximumDocument)
	if err != nil {
		return RustAutobahnPreparationReceipt{}, err
	}
	manifestDigest := intake.DigestBytes(manifestBytes)
	clientPlanDigest := intake.DigestBytes(clientBytes)
	serverPlanDigest := intake.DigestBytes(serverBytes)
	clientFixture, err := deriveRustAutobahnFixture(manifest, "client", clientPlanDigest, manifestDigest, challenge)
	if err != nil {
		return RustAutobahnPreparationReceipt{}, err
	}
	serverFixture, err := deriveRustAutobahnFixture(manifest, "server", serverPlanDigest, manifestDigest, challenge)
	if err != nil {
		return RustAutobahnPreparationReceipt{}, err
	}
	for _, digest := range []string{clientFixture.EnvelopeDigest, serverFixture.EnvelopeDigest} {
		if digest == history.Digest || contains(history.AttemptReceiptDigests, digest) {
			return RustAutobahnPreparationReceipt{}, finding("AUTOBAHN_HISTORY_SUBSTITUTION", "$.synthetic", "synthetic fixture identity collides with retained history")
		}
	}
	controls, err := deriveRustAutobahnControls(manifest, manifestDigest, clientPlanDigest, challenge, baselineBytes)
	if err != nil {
		return RustAutobahnPreparationReceipt{}, err
	}
	live := RustAutobahnCounts{Expected: AutobahnSelectedCaseCount, Selected: AutobahnSelectedCaseCount, Missing: AutobahnSelectedCaseCount}
	receipt := RustAutobahnPreparationReceipt{
		Schema:                "../" + rustAutobahnSchemaRelative,
		SchemaVersion:         rustAutobahnPreparationVersion,
		EvidenceID:            "evidence.us-019-autobahn-rust-readiness",
		StoryID:               "US-019",
		Status:                RustAutobahnStatus,
		LiveConformanceStatus: RustAutobahnLiveStatus,
		Assurance:             "OWNER_ATTESTED_NOT_INDEPENDENT",
		Manifest:              artifact(rustAutobahnManifestRelative, manifestBytes),
		ClientPlan:            artifact(rustAutobahnClientPlanRelative, clientBytes),
		ServerPlan:            artifact(rustAutobahnServerPlanRelative, serverBytes),
		Source:                RustAutobahnSource{ArchiveDigest: PinnedAutobahnSourceArchiveDigest, RegistryDigest: PinnedAutobahnRegistryDigest, ReportSourceDigest: PinnedAutobahnReportSourceDigest, ImageManifestDigest: AutobahnImageManifestDigest, ImageConfigDigest: AutobahnImageConfigDigest},
		Testee: RustAutobahnTestee{
			PreparationObservedBinaryDigest:  intake.DigestBytes(testeeBytes),
			PreparationObservedBinaryBytes:   int64(len(testeeBytes)),
			BinaryReverifiedByStaticVerifier: false,
			SourceTreeDigest:                 sourceTreeDigest,
			CargoLockDigest:                  intake.DigestBytes(cargoLock),
			Host:                             runtime.GOOS + "/" + runtime.GOARCH,
			RustcVersion:                     us018.RustcVersion,
			Challenge:                        challenge,
			TranscriptDigest:                 intake.DigestBytes(transcript),
			ArgumentContract:                 "harness-contract <64-lowercase-hex-challenge>",
		},
		US018:           us018,
		LiveClient:      live,
		LiveServer:      live,
		SyntheticClient: clientFixture,
		SyntheticServer: serverFixture,
		Controls:        controls,
		RetainedHistory: history,
		Architecture:    RustAutobahnArchitecture{InertLiveLinkage: false, TesteeLinkagePresent: true, ManifestExact: true, SyntheticHistoryDistinct: true, ArchitectureCanaries: 12},
		Gates: RustAutobahnGates{
			FocusedGo: rustAutobahnGateNotExecuted, RustDebug: rustAutobahnGateNotExecuted,
			RustRelease: rustAutobahnGateNotExecuted, Rustfmt: rustAutobahnGateNotExecuted,
			Clippy: rustAutobahnGateNotExecuted, Rustgate: rustAutobahnGateNotExecuted,
			FullGo: rustAutobahnGateNotExecuted,
		},
		Nonclaims: append([]string(nil), rustAutobahnNonclaims...),
	}
	if err := validateRustAutobahnReceipt(root, receipt); err != nil {
		return RustAutobahnPreparationReceipt{}, err
	}
	return receipt, nil
}

func artifact(path string, data []byte) RustAutobahnArtifact {
	return RustAutobahnArtifact{Path: path, Digest: intake.DigestBytes(data), Bytes: int64(len(data))}
}

func stageRustAutobahnTestee(validated []byte) (string, func(), error) {
	directory, err := os.MkdirTemp("", "us019-rust-testee-")
	if err != nil {
		return "", func() {}, finding("RUST_TESTEE_NOT_EXERCISED", "$.testee", "cannot create private testee directory")
	}
	path := filepath.Join(directory, "websocket-testee")
	cleanup := func() {
		_ = os.Chmod(directory, 0o700)
		_ = os.Remove(path)
		_ = os.Remove(directory)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		cleanup()
		return "", func() {}, finding("RUST_TESTEE_NOT_EXERCISED", "$.testee", "cannot create private testee copy")
	}
	written, writeErr := file.Write(validated)
	syncErr := file.Sync()
	chmodErr := file.Chmod(0o500)
	closeErr := file.Close()
	directorySyncErr := syncDir(directory)
	directoryChmodErr := os.Chmod(directory, 0o500)
	if writeErr != nil || syncErr != nil || chmodErr != nil || closeErr != nil || written != len(validated) || directorySyncErr != nil || directoryChmodErr != nil {
		cleanup()
		return "", func() {}, finding("RUST_TESTEE_NOT_EXERCISED", "$.testee", "cannot seal private testee copy")
	}
	staged, err := readBoundedRegular(path, rustAutobahnMaximumExecutable)
	if err != nil || !bytes.Equal(staged, validated) {
		cleanup()
		return "", func() {}, finding("CONCURRENT_FILE_DRIFT", "$.testee", "private testee copy differs from validated bytes")
	}
	return path, cleanup, nil
}

func runRustAutobahnContract(ctx context.Context, testee, challenge string) ([]byte, error) {
	deadline, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stdout := &boundedProcessBuffer{limit: rustAutobahnProcessOutputLimit}
	stderr := &boundedProcessBuffer{limit: rustAutobahnProcessOutputLimit}
	command := exec.CommandContext(deadline, testee, "harness-contract", challenge)
	command.Env = []string{"LANG=C", "LC_ALL=C"}
	command.Stdin = bytes.NewReader(nil)
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	exitCode := -1
	if command.ProcessState != nil {
		exitCode = command.ProcessState.ExitCode()
	}
	if err != nil || deadline.Err() != nil || validateRustAutobahnContractOutcome(stdout.Bytes(), stderr.Bytes(), exitCode, challenge, stdout.exceeded || stderr.exceeded) != nil {
		return nil, finding("RUST_TESTEE_NOT_EXERCISED", "$.testee", "testee did not emit the exact fresh non-networked capability contract")
	}
	return append([]byte(nil), stdout.Bytes()...), nil
}

func validateRustAutobahnContractOutcome(stdout, stderr []byte, exitCode int, challenge string, exceeded bool) error {
	if len(challenge) != 64 || strings.Trim(challenge, "0123456789abcdef") != "" || exceeded || exitCode != 0 || len(stderr) != 0 || !bytes.Equal(stdout, []byte(rustAutobahnContractLine(challenge))) {
		return finding("RUST_TESTEE_NOT_EXERCISED", "$.testee", "process outcome is not the exact fresh harness-contract response")
	}
	return nil
}

func rustAutobahnContractLine(challenge string) string {
	return "schema=1 status=" + RustAutobahnStatus + " roles=client,server network_routes=client,server application_echo=false multi_case=false conformance=false challenge=" + challenge + "\n"
}

func deriveRustAutobahnFixture(manifest RustAutobahnCaseManifest, mode, planDigest, manifestDigest, challenge string) (RustAutobahnFixtureSummary, error) {
	registry, selection, err := registryFromManifest(manifest)
	if err != nil {
		return RustAutobahnFixtureSummary{}, err
	}
	results, err := goodRustAutobahnResults(mode, manifest.SelectedCaseIDs)
	if err != nil {
		return RustAutobahnFixtureSummary{}, err
	}
	if err := ReconcileAutobahn(registry, selection, mode, results); err != nil {
		return RustAutobahnFixtureSummary{}, err
	}
	resultBytes, err := intake.CanonicalJSON(results)
	if err != nil {
		return RustAutobahnFixtureSummary{}, err
	}
	envelope := rustAutobahnFixtureEnvelope{Origin: rustAutobahnSyntheticOrigin, PreparationDigest: planDigest, ChallengeDigest: intake.DigestBytes([]byte(challenge)), ManifestDigest: manifestDigest, Mode: mode, ControlID: "good", ResultsDigest: intake.DigestBytes(resultBytes)}
	if err := validateRustAutobahnLineage(envelope, mode, planDigest, manifestDigest, challenge); err != nil {
		return RustAutobahnFixtureSummary{}, err
	}
	envelopeBytes, _ := intake.CanonicalJSON(envelope)
	return RustAutobahnFixtureSummary{Mode: mode, Origin: rustAutobahnSyntheticOrigin, FixtureObserved: len(results), FixtureOK: len(results), ResultDigest: envelope.ResultsDigest, EnvelopeDigest: intake.DigestBytes(envelopeBytes), Disposition: "SYNTHETIC_RECONCILED"}, nil
}

func registryFromManifest(manifest RustAutobahnCaseManifest) (AutobahnRegistry, AutobahnSelection, error) {
	ids := append(append([]string(nil), manifest.SelectedCaseIDs...), manifest.NonselectedCaseIDs...)
	sort.Strings(ids)
	registry := AutobahnRegistry{SchemaVersion: rustAutobahnPreparationVersion, SourceDigest: PinnedAutobahnRegistryDigest, CaseIDs: ids, UnresolvedGenerators: []string{}, sourceValidated: true, caseIDsDigest: digestStringSlice(ids)}
	selection, err := SelectAutobahnRegistry(registry)
	return registry, selection, err
}

func goodRustAutobahnResults(mode string, ids []string) ([]AutobahnResult, error) {
	results := make([]AutobahnResult, len(ids))
	for index, id := range ids {
		result := AutobahnResult{CaseID: id, Status: "OK", ResultDigest: intake.DigestBytes([]byte("us019-synthetic-result\x00" + mode + "\x00" + id)), ObservationDigest: intake.DigestBytes([]byte("us019-synthetic-observation\x00" + mode + "\x00" + id))}
		binding, err := AutobahnResultBindingDigest(mode, result)
		if err != nil {
			return nil, err
		}
		result.BindingDigest = binding
		results[index] = result
	}
	return results, nil
}

func validateRustAutobahnLineage(envelope rustAutobahnFixtureEnvelope, mode, planDigest, manifestDigest, challenge string) error {
	if envelope.Origin != rustAutobahnSyntheticOrigin || envelope.LiveExecution || envelope.SuiteInvoked || envelope.PreparationDigest != planDigest || envelope.ChallengeDigest != intake.DigestBytes([]byte(challenge)) || envelope.ManifestDigest != manifestDigest || envelope.Mode != mode || !isDigest(envelope.ResultsDigest) {
		return finding("AUTOBAHN_FIXTURE_LINEAGE_MISMATCH", "$.fixture", "synthetic fixture lineage differs from the current challenge, plan, manifest, or mode")
	}
	return nil
}

func deriveRustAutobahnControls(manifest RustAutobahnCaseManifest, manifestDigest, planDigest, challenge string, retainedBaseline []byte) (RustAutobahnControls, error) {
	first, err := deriveRustAutobahnControlRun(manifest, manifestDigest, planDigest, challenge, retainedBaseline)
	if err != nil {
		return RustAutobahnControls{}, err
	}
	second, err := deriveRustAutobahnControlRun(manifest, manifestDigest, planDigest, challenge, retainedBaseline)
	if err != nil {
		return RustAutobahnControls{}, err
	}
	left, _ := intake.CanonicalJSON(first)
	right, _ := intake.CanonicalJSON(second)
	if !bytes.Equal(left, right) {
		return RustAutobahnControls{}, finding("AUTOBAHN_CONTROL_NONDETERMINISTIC", "$.controls", "two fixed control repetitions differ")
	}
	first.Repetitions = 2
	projection, _ := intake.CanonicalJSON(first)
	first.OutcomeDigest = intake.DigestBytes(projection)
	return first, nil
}

func deriveRustAutobahnControlRun(manifest RustAutobahnCaseManifest, manifestDigest, planDigest, challenge string, retainedBaseline []byte) (RustAutobahnControls, error) {
	registry, selection, err := registryFromManifest(manifest)
	if err != nil {
		return RustAutobahnControls{}, err
	}
	good, err := goodRustAutobahnResults("client", manifest.SelectedCaseIDs)
	if err != nil {
		return RustAutobahnControls{}, err
	}
	mutants := []struct {
		id     string
		mutate func([]AutobahnResult) []AutobahnResult
	}{
		{"omitted-selected", func(v []AutobahnResult) []AutobahnResult { return v[:len(v)-1] }},
		{"duplicate-selected", func(v []AutobahnResult) []AutobahnResult { v[len(v)-1] = v[0]; return v }},
		{"nonselected-injected", func(v []AutobahnResult) []AutobahnResult {
			v[len(v)-1].CaseID = manifest.NonselectedCaseIDs[0]
			return v
		}},
		{"nonterminal", func(v []AutobahnResult) []AutobahnResult { v[0].Status = "RUNNING"; return v }},
		{"altered-result", func(v []AutobahnResult) []AutobahnResult {
			v[0].ResultDigest = intake.DigestBytes([]byte("altered"))
			return v
		}},
		{"altered-observation", func(v []AutobahnResult) []AutobahnResult {
			v[0].ObservationDigest = intake.DigestBytes([]byte("altered"))
			return v
		}},
		{"wrong-role-binding", func(v []AutobahnResult) []AutobahnResult {
			v[0].BindingDigest, _ = AutobahnResultBindingDigest("server", v[0])
			return v
		}},
		{"missing-case", func(v []AutobahnResult) []AutobahnResult { return append([]AutobahnResult(nil), v[1:]...) }},
	}
	emptyErr := validateRustAutobahnContractOutcome(nil, nil, 0, challenge, false)
	if findingCode(emptyErr) != "RUST_TESTEE_NOT_EXERCISED" {
		return RustAutobahnControls{}, finding("AUTOBAHN_CONTROL_SURVIVED", "$.controls.empty-stub", "empty process outcome was accepted")
	}
	history, err := validateRustAutobahnHistory(retainedBaseline)
	if err != nil {
		return RustAutobahnControls{}, err
	}
	historyErr := rejectRustAutobahnHistoricalFixture(retainedBaseline, history)
	if findingCode(historyErr) != "AUTOBAHN_HISTORY_SUBSTITUTION" {
		return RustAutobahnControls{}, finding("AUTOBAHN_CONTROL_SURVIVED", "$.controls.retained-history", "retained baseline was accepted as a synthetic fixture")
	}
	controls := RustAutobahnControls{EmptyStub: RustAutobahnControlOutcome{ControlID: "empty-stub", Outcome: findingCode(emptyErr)}, HistoryFirewall: RustAutobahnControlOutcome{ControlID: "retained-history-substitution", Outcome: findingCode(historyErr)}}
	for _, mutant := range mutants {
		copyResults := append([]AutobahnResult(nil), good...)
		err := ReconcileAutobahn(registry, selection, "client", mutant.mutate(copyResults))
		if err == nil {
			return RustAutobahnControls{}, finding("AUTOBAHN_CONTROL_SURVIVED", "$.controls."+mutant.id, "fixture mutant was accepted")
		}
		controls.FixtureMutants = append(controls.FixtureMutants, RustAutobahnControlOutcome{ControlID: mutant.id, Outcome: findingCode(err)})
	}
	baseEnvelope := rustAutobahnFixtureEnvelope{Origin: rustAutobahnSyntheticOrigin, PreparationDigest: planDigest, ChallengeDigest: intake.DigestBytes([]byte(challenge)), ManifestDigest: manifestDigest, Mode: "client", ControlID: "lineage", ResultsDigest: intake.DigestBytes([]byte("results"))}
	lineage := []struct {
		id     string
		mutate func(*rustAutobahnFixtureEnvelope)
	}{
		{"stale-challenge", func(v *rustAutobahnFixtureEnvelope) { v.ChallengeDigest = intake.DigestBytes([]byte("stale")) }},
		{"stale-plan", func(v *rustAutobahnFixtureEnvelope) { v.PreparationDigest = intake.DigestBytes([]byte("stale")) }},
		{"stale-manifest", func(v *rustAutobahnFixtureEnvelope) { v.ManifestDigest = intake.DigestBytes([]byte("stale")) }},
		{"wrong-origin", func(v *rustAutobahnFixtureEnvelope) { v.Origin = "HISTORICAL_REPORT" }},
	}
	for _, mutant := range lineage {
		value := baseEnvelope
		mutant.mutate(&value)
		err := validateRustAutobahnLineage(value, "client", planDigest, manifestDigest, challenge)
		if findingCode(err) != "AUTOBAHN_FIXTURE_LINEAGE_MISMATCH" {
			return RustAutobahnControls{}, finding("AUTOBAHN_CONTROL_SURVIVED", "$.controls."+mutant.id, "lineage mutant was accepted")
		}
		controls.LineageMutants = append(controls.LineageMutants, RustAutobahnControlOutcome{ControlID: mutant.id, Outcome: findingCode(err)})
	}
	generated, err := corpora.GenerateAll(corpora.GenerationInput{PublicSeed: "us019-public-reference-control-v1", Secret: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", Epoch: 1})
	if err != nil {
		return RustAutobahnControls{}, err
	}
	report, err := corpora.RunMutationAnalysis(generated, corpora.BuiltinMutants())
	if err != nil || report.Surviving != 0 || report.Killed != len(report.Mutants) {
		return RustAutobahnControls{}, finding("AUTOBAHN_CONTROL_SURVIVED", "$.controls.reference", "reference protocol mutant survived")
	}
	identity := corpora.Mutant{MutantID: "us019-identity", Kind: "behavior", Operator: "no-op", Behavior: corpora.ReferenceBehavior}
	identityReport, err := corpora.RunMutationAnalysis(generated, []corpora.Mutant{identity})
	if err != nil || identityReport.Surviving != 1 || identityReport.Killed != 0 {
		return RustAutobahnControls{}, finding("AUTOBAHN_CONTROL_MANUFACTURED_KILL", "$.controls.reference", "identity control must survive")
	}
	controls.ReferenceMutants = RustAutobahnReferenceMutants{Total: len(report.Mutants), Killed: report.Killed, Surviving: report.Surviving, IdentitySurviving: identityReport.Surviving}
	return controls, nil
}

func rejectRustAutobahnHistoricalFixture(candidate []byte, history RustAutobahnRetainedHistory) error {
	digest := intake.DigestBytes(candidate)
	if digest == history.Digest || contains(history.AttemptReceiptDigests, digest) {
		return finding("AUTOBAHN_HISTORY_SUBSTITUTION", "$.fixture", "retained baseline or attempt receipt cannot occupy a synthetic fixture position")
	}
	return nil
}

func findingCode(err error) string {
	if err == nil {
		return ""
	}
	var typed *intake.Finding
	if errors.As(err, &typed) {
		return typed.Code
	}
	return "UNTYPED_FAILURE"
}

func validateRustAutobahnHistory(data []byte) (RustAutobahnRetainedHistory, error) {
	var object map[string]json.RawMessage
	if err := intake.DecodeStrict(data, &object); err != nil {
		return RustAutobahnRetainedHistory{}, finding("AUTOBAHN_HISTORY_SUBSTITUTION", "$.retained_history", err.Error())
	}
	var baseline rustAutobahnBaseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		return RustAutobahnRetainedHistory{}, finding("AUTOBAHN_HISTORY_SUBSTITUTION", "$.retained_history", err.Error())
	}
	if baseline.Status != "BLOCKED" || baseline.Assurance != "OWNER_ATTESTED_NOT_INDEPENDENT" || baseline.IndependentReviewClaimed || baseline.RerunDisposition.Authorized != 1 || baseline.RerunDisposition.Consumed != 1 || !baseline.RerunDisposition.OriginalRetained || baseline.RerunDisposition.Further || baseline.RerunDisposition.Disposition != "NO_FURTHER_RERUNS_AUTHORIZED" {
		return RustAutobahnRetainedHistory{}, finding("AUTOBAHN_HISTORY_SUBSTITUTION", "$.retained_history", "baseline assurance or rerun disposition differs")
	}
	if err := validateRustAutobahnHistoryMode(baseline.Client); err != nil {
		return RustAutobahnRetainedHistory{}, err
	}
	if err := validateRustAutobahnHistoryMode(baseline.Server); err != nil {
		return RustAutobahnRetainedHistory{}, err
	}
	digests := []string{}
	for _, mode := range []rustAutobahnBaselineMode{baseline.Client, baseline.Server} {
		for _, attempt := range mode.Attempts {
			if !contains(digests, attempt.ReceiptDigest) {
				digests = append(digests, attempt.ReceiptDigest)
			}
		}
	}
	sort.Strings(digests)
	return RustAutobahnRetainedHistory{Path: rustAutobahnBaselineRelative, Digest: intake.DigestBytes(data), Status: baseline.Status, Disposition: baseline.RerunDisposition.Disposition, FurtherRerunsAuthorized: false, ClientAttempts: baseline.Client.AttemptCount, ServerAttempts: baseline.Server.AttemptCount, ClientExecuted: false, ServerExecuted: false, ClientResultCount: 0, ServerResultCount: 0, AttemptReceiptDigests: digests}, nil
}

func validateRustAutobahnHistoryMode(mode rustAutobahnBaselineMode) error {
	if mode.AttemptCount != 2 || len(mode.Attempts) != 2 || mode.Executed || mode.ResultCount != 0 {
		return finding("AUTOBAHN_HISTORY_SUBSTITUTION", "$.retained_history", "mode attempts or zero-execution counts differ")
	}
	for index, attempt := range mode.Attempts {
		if attempt.Sequence != index+1 || !isDigest(attempt.ReceiptDigest) || attempt.Executed || attempt.ResultCount != 0 || index == 0 && attempt.Classification != "ORIGINAL_AUTHORITATIVE" || index == 1 && attempt.Classification != "OWNER_AUTHORIZED_REMEDIATION" {
			return finding("AUTOBAHN_HISTORY_SUBSTITUTION", "$.retained_history.attempts", "retained attempt sequence or identity differs")
		}
	}
	return nil
}

func verifyUS018RustAutobahnInput(data []byte) (RustAutobahnUS018, error) {
	var object map[string]json.RawMessage
	if err := intake.DecodeStrict(data, &object); err != nil {
		return RustAutobahnUS018{}, finding("AUTOBAHN_TESTEE_LINKAGE_MISSING", "$.us018", err.Error())
	}
	var value struct {
		Status    string `json:"status"`
		Toolchain struct {
			Rustc string `json:"rustc"`
		} `json:"toolchain"`
		Nonclaims []string `json:"nonclaims"`
	}
	if err := json.Unmarshal(data, &value); err != nil || value.Status != "PASS_OWNER_RELAXED_CURRENT_HOST" || value.Toolchain.Rustc == "" {
		return RustAutobahnUS018{}, finding("AUTOBAHN_TESTEE_LINKAGE_MISSING", "$.us018", "US-018 evidence is not the current owner-relaxed adapter receipt")
	}
	required := []string{"no Linux x86_64 or second-platform execution", "no Autobahn execution or conformance claim", "no application echo or conformance-runner routing"}
	for _, claim := range required {
		if !contains(value.Nonclaims, claim) {
			return RustAutobahnUS018{}, finding("AUTOBAHN_TESTEE_LINKAGE_MISSING", "$.us018.nonclaims", "US-018 missing required nonclaim: "+claim)
		}
	}
	return RustAutobahnUS018{Path: rustAutobahnUS018Relative, Digest: intake.DigestBytes(data), Status: value.Status, RustcVersion: value.Toolchain.Rustc}, nil
}

func realRepositoryRoot(value string) (string, error) {
	clean, err := cleanAbsoluteDirectory(value, "$.repository_root")
	if err != nil {
		return "", err
	}
	if err := requireRealDirectory(clean); err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(clean)
	if err != nil || real != clean {
		return "", finding("INVALID_PATH", "$.repository_root", "repository root must be a real canonical directory")
	}
	return clean, nil
}

func VerifyRustAutobahnPreparation(repositoryRoot string, receiptBytes []byte) error {
	root, err := realRepositoryRoot(repositoryRoot)
	if err != nil {
		return err
	}
	var receipt RustAutobahnPreparationReceipt
	if err := intake.DecodeStrict(receiptBytes, &receipt); err != nil {
		return finding("INVALID_RUST_AUTOBAHN_EVIDENCE", "$", err.Error())
	}
	return validateRustAutobahnReceipt(root, receipt)
}

func validateRustAutobahnReceipt(root string, receipt RustAutobahnPreparationReceipt) error {
	if receipt.Schema != "../"+rustAutobahnSchemaRelative || receipt.SchemaVersion != rustAutobahnPreparationVersion || receipt.EvidenceID != "evidence.us-019-autobahn-rust-readiness" || receipt.StoryID != "US-019" || receipt.Status != RustAutobahnStatus || receipt.LiveConformanceStatus != RustAutobahnLiveStatus || receipt.Assurance != "OWNER_ATTESTED_NOT_INDEPENDENT" || receipt.IndependentReviewClaimed || receipt.StrictPassClaimed || receipt.Production || receipt.Publication || receipt.Signing {
		return finding("AUTOBAHN_CONFORMANCE_OVERCLAIM", "$", "receipt status or assurance exceeds inert preparation")
	}
	schemaBytes, err := readBoundedRegular(filepath.Join(root, rustAutobahnSchemaRelative), rustAutobahnMaximumDocument)
	if err != nil {
		return err
	}
	var schema map[string]json.RawMessage
	if err := intake.DecodeStrict(schemaBytes, &schema); err != nil || len(schema) == 0 {
		return finding("INVALID_RUST_AUTOBAHN_EVIDENCE", "$.schema", "closed receipt schema is missing or invalid")
	}
	if err := VerifyRustAutobahnStaticFiles(root); err != nil {
		return err
	}
	if err := VerifyRustAutobahnArchitectureFiles(root); err != nil {
		return err
	}
	for _, item := range []RustAutobahnArtifact{receipt.Manifest, receipt.ClientPlan, receipt.ServerPlan} {
		if item.Path != rustAutobahnManifestRelative && item.Path != rustAutobahnClientPlanRelative && item.Path != rustAutobahnServerPlanRelative {
			return finding("INVALID_PATH", "$.artifact", "receipt artifact path is not fixed")
		}
		data, err := readBoundedRegular(filepath.Join(root, item.Path), rustAutobahnMaximumDocument)
		if err != nil || item.Digest != intake.DigestBytes(data) || item.Bytes != int64(len(data)) {
			return finding("AUTOBAHN_MANIFEST_DRIFT", item.Path, "receipt artifact digest differs from current bytes")
		}
	}
	if receipt.Source != (RustAutobahnSource{ArchiveDigest: PinnedAutobahnSourceArchiveDigest, RegistryDigest: PinnedAutobahnRegistryDigest, ReportSourceDigest: PinnedAutobahnReportSourceDigest, ImageManifestDigest: AutobahnImageManifestDigest, ImageConfigDigest: AutobahnImageConfigDigest}) {
		return finding("AUTOBAHN_MANIFEST_DRIFT", "$.source", "source pins differ")
	}
	if receipt.Testee.BinaryReverifiedByStaticVerifier {
		return finding("AUTOBAHN_CONFORMANCE_OVERCLAIM", "$.testee.binary_reverified_by_static_verifier", "static receipt verification does not reopen or rebind the preparation testee binary")
	}
	if receipt.Testee.ArgumentContract != "harness-contract <64-lowercase-hex-challenge>" || len(receipt.Testee.Challenge) != 64 || strings.Trim(receipt.Testee.Challenge, "0123456789abcdef") != "" || receipt.Testee.TranscriptDigest != intake.DigestBytes([]byte(rustAutobahnContractLine(receipt.Testee.Challenge))) || !isDigest(receipt.Testee.PreparationObservedBinaryDigest) || receipt.Testee.PreparationObservedBinaryBytes <= 0 || !rustAutobahnHostPattern.MatchString(receipt.Testee.Host) || receipt.Testee.RustcVersion == "" {
		return finding("RUST_TESTEE_NOT_EXERCISED", "$.testee", "testee binding or transcript is invalid")
	}
	if receipt.Testee.SourceTreeDigest != rustAutobahnHistoricalTree {
		return finding("AUTOBAHN_TESTEE_LINKAGE_MISSING", "$.testee.source_tree_digest", "historical Rust testee source identity differs")
	}
	lock, err := readBoundedRegular(filepath.Join(root, rustAutobahnCargoLockRelative), rustAutobahnMaximumDocument)
	if err != nil || receipt.Testee.CargoLockDigest != intake.DigestBytes(lock) {
		return finding("AUTOBAHN_TESTEE_LINKAGE_MISSING", "$.testee.cargo_lock_digest", "Cargo lock differs")
	}
	us018Data, err := readBoundedRegular(filepath.Join(root, rustAutobahnUS018Relative), rustAutobahnMaximumDocument)
	if err != nil || receipt.US018.Digest != intake.DigestBytes(us018Data) {
		return finding("AUTOBAHN_TESTEE_LINKAGE_MISSING", "$.us018", "US-018 evidence differs")
	}
	us018, err := verifyUS018RustAutobahnInput(us018Data)
	if err != nil || receipt.US018 != us018 {
		return finding("AUTOBAHN_TESTEE_LINKAGE_MISSING", "$.us018", "US-018 nonclaims or identity differ")
	}
	baseline, err := readBoundedRegular(filepath.Join(root, rustAutobahnBaselineRelative), rustAutobahnMaximumDocument)
	if err != nil {
		return err
	}
	history, err := validateRustAutobahnHistory(baseline)
	if err != nil || !equalRustAutobahnHistory(receipt.RetainedHistory, history) {
		return finding("AUTOBAHN_HISTORY_SUBSTITUTION", "$.retained_history", "retained baseline identity differs")
	}
	live := RustAutobahnCounts{Expected: AutobahnSelectedCaseCount, Selected: AutobahnSelectedCaseCount, Missing: AutobahnSelectedCaseCount}
	if receipt.LiveClient != live || receipt.LiveServer != live {
		return finding("AUTOBAHN_CONFORMANCE_OVERCLAIM", "$.live_modes", "live counts must remain zero-executed and fully missing")
	}
	manifestBytes, _ := readBoundedRegular(filepath.Join(root, rustAutobahnManifestRelative), rustAutobahnMaximumDocument)
	var manifest RustAutobahnCaseManifest
	_ = intake.DecodeStrict(manifestBytes, &manifest)
	clientBytes, _ := readBoundedRegular(filepath.Join(root, rustAutobahnClientPlanRelative), rustAutobahnMaximumDocument)
	serverBytes, _ := readBoundedRegular(filepath.Join(root, rustAutobahnServerPlanRelative), rustAutobahnMaximumDocument)
	clientFixture, err := deriveRustAutobahnFixture(manifest, "client", intake.DigestBytes(clientBytes), intake.DigestBytes(manifestBytes), receipt.Testee.Challenge)
	if err != nil || receipt.SyntheticClient != clientFixture {
		return finding("AUTOBAHN_FIXTURE_LINEAGE_MISMATCH", "$.synthetic_client", "synthetic client summary differs")
	}
	serverFixture, err := deriveRustAutobahnFixture(manifest, "server", intake.DigestBytes(serverBytes), intake.DigestBytes(manifestBytes), receipt.Testee.Challenge)
	if err != nil || receipt.SyntheticServer != serverFixture {
		return finding("AUTOBAHN_FIXTURE_LINEAGE_MISMATCH", "$.synthetic_server", "synthetic server summary differs")
	}
	controls, err := deriveRustAutobahnControls(manifest, intake.DigestBytes(manifestBytes), intake.DigestBytes(clientBytes), receipt.Testee.Challenge, baseline)
	if err != nil {
		return err
	}
	left, _ := intake.CanonicalJSON(receipt.Controls)
	right, _ := intake.CanonicalJSON(controls)
	if !bytes.Equal(left, right) {
		return finding("AUTOBAHN_CONTROL_SURVIVED", "$.controls", "control outcomes differ from deterministic replay")
	}
	if receipt.Architecture != (RustAutobahnArchitecture{InertLiveLinkage: false, TesteeLinkagePresent: true, ManifestExact: true, SyntheticHistoryDistinct: true, ArchitectureCanaries: 12}) {
		return finding("AUTOBAHN_STATIC_LIVE_LINKAGE", "$.architecture", "architecture claim differs")
	}
	notExecutedGates := RustAutobahnGates{FocusedGo: rustAutobahnGateNotExecuted, RustDebug: rustAutobahnGateNotExecuted, RustRelease: rustAutobahnGateNotExecuted, Rustfmt: rustAutobahnGateNotExecuted, Clippy: rustAutobahnGateNotExecuted, Rustgate: rustAutobahnGateNotExecuted, FullGo: rustAutobahnGateNotExecuted}
	if receipt.Gates != notExecutedGates || !equalStrings(receipt.Nonclaims, rustAutobahnNonclaims) {
		return finding("AUTOBAHN_CONFORMANCE_OVERCLAIM", "$.gates", "closed gate or nonclaim inventory differs")
	}
	return nil
}

func equalRustAutobahnHistory(left, right RustAutobahnRetainedHistory) bool {
	leftBytes, _ := intake.CanonicalJSON(left)
	rightBytes, _ := intake.CanonicalJSON(right)
	return bytes.Equal(leftBytes, rightBytes)
}
