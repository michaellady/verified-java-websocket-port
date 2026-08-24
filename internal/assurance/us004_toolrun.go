package assurance

import (
	"fmt"
	"sort"
	"strings"

	vendorprotocol "github.com/michaellady/verified-java-to-rust/foundation/protocol"
)

type developerToolRunDocument struct {
	SchemaVersion             string                         `json:"schema_version"`
	EntityType                string                         `json:"entity_type"`
	RunID                     string                         `json:"run_id"`
	QualificationID           string                         `json:"qualification_id"`
	ProfileID                 string                         `json:"profile_id"`
	Language                  string                         `json:"language"`
	Tool                      developerToolRunTool           `json:"tool"`
	WorkspaceProfileID        string                         `json:"workspace_profile_id"`
	SourceRevision            string                         `json:"source_revision"`
	Target                    string                         `json:"target"`
	Features                  []string                       `json:"features"`
	Client                    string                         `json:"client"`
	CorpusID                  string                         `json:"corpus_id"`
	ExecutionEvidence         developerToolRunArtifactRef    `json:"execution_evidence"`
	Episodes                  []developerToolRunEpisode      `json:"episodes"`
	Measurements              developerToolRunMeasurements   `json:"measurements"`
	CapabilityObservations    []developerToolRunCapability   `json:"capability_observations"`
	Reliability               developerToolRunReliability    `json:"reliability"`
	Disagreements             []developerToolRunDisagreement `json:"disagreements"`
	AuthoritativeResultSource string                         `json:"authoritative_result_source"`
	BuildAuthoritative        bool                           `json:"build_authoritative"`
	AssuranceClaims           []any                          `json:"assurance_claims"`
	GateEffects               []any                          `json:"gate_effects"`
	Reproduction              developerToolRunReproduction   `json:"reproduction"`
	Limitations               []string                       `json:"limitations"`
}

type developerToolRunTool struct {
	Name                   string  `json:"name"`
	Version                string  `json:"version"`
	Commit                 *string `json:"commit"`
	ArtifactSHA256         string  `json:"artifact_sha256"`
	InstallationProvenance string  `json:"installation_provenance"`
}

type developerToolRunArtifactRef struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type developerToolRunEpisode struct {
	CacheState        string `json:"cache_state"`
	Sequence          int    `json:"sequence"`
	ObservationStatus string `json:"observation_status"`
	Outcome           string `json:"outcome"`
	Failure           string `json:"failure"`
	Recovery          string `json:"recovery"`
}

type developerToolRunMeasurements struct {
	ColdReadinessMS   *int `json:"cold_readiness_ms"`
	WarmReadinessMS   *int `json:"warm_readiness_ms"`
	InitialIndexMS    *int `json:"initial_index_ms"`
	ReindexMS         *int `json:"reindex_ms"`
	IdleRSSBytes      *int `json:"idle_rss_bytes"`
	PeakRSSBytes      *int `json:"peak_rss_bytes"`
	CacheSizeBytes    *int `json:"cache_size_bytes"`
	AgentElapsedMS    *int `json:"agent_elapsed_ms"`
	ToolCalls         *int `json:"tool_calls"`
	IncorrectEdits    *int `json:"incorrect_edits"`
	RecoveryWorkItems *int `json:"recovery_work_items"`
}

type developerToolRunCapability struct {
	Capability string `json:"capability"`
	Status     string `json:"status"`
}

type developerToolRunReliability struct {
	Crashes      string `json:"crashes"`
	Hangs        string `json:"hangs"`
	Corruption   string `json:"corruption"`
	StaleResults string `json:"stale_results"`
	Recovery     string `json:"recovery"`
}

type developerToolRunDisagreement struct {
	QueryID     string `json:"query_id"`
	LSPResult   string `json:"lsp_result"`
	BuildResult string `json:"build_result"`
	Resolution  string `json:"resolution"`
}

type developerToolRunReproduction struct {
	Mode               string                             `json:"mode"`
	Procedure          string                             `json:"procedure"`
	Network            string                             `json:"network"`
	Secrets            string                             `json:"secrets"`
	InputFixture       developerToolRunInputFixture       `json:"input_fixture"`
	ExecutionWorkspace developerToolRunExecutionWorkspace `json:"execution_workspace"`
}

type developerToolRunInputFixture struct {
	SHA256 string `json:"sha256"`
	Access string `json:"access"`
}

type developerToolRunExecutionWorkspace struct {
	InitialSHA256 string `json:"initial_sha256"`
	Mode          string `json:"mode"`
}

func validateDeveloperToolRunDocument(data []byte, expected developerToolExpectation) error {
	var run developerToolRunDocument
	if err := vendorprotocol.DecodeStrict(data, &run); err != nil {
		return err
	}
	if run.SchemaVersion != vendorprotocol.SchemaVersion || run.EntityType != "DeveloperToolRun" || run.ProfileID != expected.ProfileID || run.Language != expected.Language || run.Tool.Name != expected.Name || run.Tool.Version != expected.Version || !run.BuildAuthoritative {
		return fmt.Errorf("developer-tool run does not match the frozen profile identity")
	}
	if run.RunID == "" || run.QualificationID == "" || run.WorkspaceProfileID == "" || run.SourceRevision == "" || run.Target == "" || run.Client == "" || run.CorpusID == "" || run.AuthoritativeResultSource == "" || run.ExecutionEvidence.Path == "" || run.ExecutionEvidence.SHA256 == "" || run.Reproduction.Procedure == "" {
		return fmt.Errorf("developer-tool run is missing required non-empty fields")
	}
	if !isSHA256(run.SourceRevision) || !isSHA256(run.Tool.ArtifactSHA256) || !isSHA256(run.ExecutionEvidence.SHA256) || !isSHA256(run.Reproduction.InputFixture.SHA256) || !isSHA256(run.Reproduction.ExecutionWorkspace.InitialSHA256) {
		return fmt.Errorf("developer-tool run sha256 fields must be exact sha256 digests")
	}
	if len(run.Features) == 0 || len(run.Limitations) == 0 || len(run.Episodes) != 4 || len(run.CapabilityObservations) < 6 {
		return fmt.Errorf("developer-tool run cardinalities drifted from the accepted schema")
	}
	cacheStates := map[string]bool{}
	for _, episode := range run.Episodes {
		if !containsString([]string{"cold", "warm", "invalidated", "corrupted"}, episode.CacheState) ||
			episode.Sequence < 1 || episode.Sequence > 4 ||
			!containsString([]string{"OBSERVED", "BLOCKED_UNAVAILABLE"}, episode.ObservationStatus) ||
			!containsString([]string{"PASS", "FAIL", "NOT_OBSERVED"}, episode.Outcome) ||
			strings.TrimSpace(episode.Recovery) == "" || cacheStates[episode.CacheState] {
			return fmt.Errorf("developer-tool run episode semantics drifted from the accepted schema")
		}
		cacheStates[episode.CacheState] = true
	}
	capabilities := map[string]bool{}
	for _, capability := range run.CapabilityObservations {
		if capability.Capability == "" || !containsString([]string{"PASS", "FAIL", "STALE", "NOT_OBSERVED"}, capability.Status) || capabilities[capability.Capability] {
			return fmt.Errorf("developer-tool run capability observations drifted from the accepted schema")
		}
		capabilities[capability.Capability] = true
	}
	for _, status := range []string{run.Reliability.Crashes, run.Reliability.Hangs, run.Reliability.Corruption, run.Reliability.StaleResults, run.Reliability.Recovery} {
		if !containsString([]string{"PASS", "FAIL", "NOT_OBSERVED"}, status) {
			return fmt.Errorf("developer-tool run reliability semantics drifted from the accepted schema")
		}
	}
	for _, disagreement := range run.Disagreements {
		if disagreement.QueryID == "" || disagreement.LSPResult == "" || disagreement.BuildResult == "" || disagreement.Resolution != "AUTHORITATIVE_BUILD_WINS" {
			return fmt.Errorf("developer-tool run disagreement semantics drifted from the accepted schema")
		}
	}
	if !containsString([]string{"EXECUTED", "BLOCKED"}, run.Reproduction.Mode) ||
		run.Reproduction.Network != "DENY" ||
		run.Reproduction.Secrets != "NONE" ||
		run.Reproduction.InputFixture.Access != "READ_ONLY" ||
		run.Reproduction.ExecutionWorkspace.Mode != "WRITABLE_DISPOSABLE_COPY" {
		return fmt.Errorf("developer-tool run reproduction semantics drifted from the accepted schema")
	}
	return nil
}

func sortedStringsStable(values []string) []string {
	clone := append([]string(nil), values...)
	sort.Strings(clone)
	return clone
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func isSHA256(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, r := range value[len("sha256:"):] {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
