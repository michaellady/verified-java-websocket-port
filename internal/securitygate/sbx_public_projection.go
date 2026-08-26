package securitygate

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

const (
	classifiedPublicProjectionSchema         = "1.0.0"
	classifiedPublicProjectionClassification = "PUBLIC_DERIVED"
	classifiedPublicProjectionProject        = "verified-java-websocket-port"
	classifiedPublicProjectionStory          = "US-007"
	classifiedPublicProjectionAttemptPrefix  = "us007-sbx-output-live-"
	classifiedPublicProjectionStaleAttempt   = "0012"

	// These digests pin the protected classifier's compiled template and rule
	// set without exposing either raw protected observations or host paths in
	// the public projection contract.
	classifiedPublicProjectionTemplateDigest = "sha256:113547b4bf0f85f83b04a948b45d8a9a962fa0a2dc38eed5180588dbdac611fc"
	classifiedPublicProjectionRuleDigest     = "sha256:c69d5471dc6803291a59575dc513ac30e0774c2d4e7e43edaa604703b6f2f432"
)

type ClassifiedProjectionDigests struct {
	FixedPlanDigest            string `json:"fixed_plan_digest"`
	ProfileDigest              string `json:"profile_digest"`
	PolicyDigest               string `json:"policy_digest"`
	RuntimeDigest              string `json:"runtime_digest"`
	TemplateDigest             string `json:"template_digest"`
	SupervisorDigest           string `json:"supervisor_digest"`
	AuthorizationClosureDigest string `json:"authorization_closure_digest"`
}

type ClassifiedDescriptorSummary struct {
	DescriptorID     string `json:"descriptor_id"`
	Accepted         bool   `json:"accepted"`
	RawReceiptDigest string `json:"raw_receipt_digest"`
}

type ClassifiedArtifact struct {
	Digest string `json:"digest"`
	Bytes  int64  `json:"bytes"`
}

type ClassifiedCleanup struct {
	RemoveDigest  string `json:"remove_digest"`
	AbsenceDigest string `json:"absence_digest"`
	SandboxAbsent bool   `json:"sandbox_absent"`
}

type ClassifiedClassifier struct {
	RuleDigest   string `json:"rule_digest"`
	InputDigest  string `json:"input_digest"`
	ActionDigest string `json:"action_digest"`
	OutputDigest string `json:"output_digest"`
}

// ProtectedPublicProjection is the complete public contract emitted by the
// protected-host classifier. It contains only classified summaries and
// digests; raw observations remain in the protected evidence store.
type ProtectedPublicProjection struct {
	Schema                   string                        `json:"schema"`
	Classification           string                        `json:"classification"`
	Project                  string                        `json:"project"`
	Story                    string                        `json:"story"`
	AttemptID                string                        `json:"attempt_id"`
	TargetCommit             string                        `json:"target_commit"`
	TargetTree               string                        `json:"target_tree"`
	Digests                  ClassifiedProjectionDigests   `json:"digests"`
	ResourceEnvelope         resources                     `json:"resource_envelope"`
	DescriptorSummaries      []ClassifiedDescriptorSummary `json:"descriptor_summaries"`
	BenignArtifact           ClassifiedArtifact            `json:"benign_artifact"`
	Cleanup                  ClassifiedCleanup             `json:"cleanup"`
	Classifier               ClassifiedClassifier          `json:"classifier"`
	Assurance                string                        `json:"assurance"`
	IndependentReviewClaimed bool                          `json:"independent_review_claimed"`
	AutobahnReruns           int                           `json:"autobahn_reruns"`
}

// DecodeProtectedPublicProjection validates bytes already classified on the
// protected host. It cannot create a classification or replace the external
// classifier required by Project.
func DecodeProtectedPublicProjection(data []byte) (ProtectedPublicProjection, error) {
	var projection ProtectedPublicProjection
	if err := intake.DecodeStrict(data, &projection); err != nil {
		return ProtectedPublicProjection{}, fmt.Errorf("PUBLIC_PROJECTION_INVALID/QUARANTINE: %w", err)
	}
	if err := validateProtectedPublicProjection(projection); err != nil {
		return ProtectedPublicProjection{}, err
	}

	claimedDigest := projection.Classifier.OutputDigest
	projection.Classifier.OutputDigest = ""
	canonical, err := intake.CanonicalJSON(projection)
	if err != nil || claimedDigest != intake.DigestBytes(canonical) {
		return ProtectedPublicProjection{}, errors.New("PUBLIC_PROJECTION_DIGEST_DRIFT/QUARANTINE")
	}
	projection.Classifier.OutputDigest = claimedDigest
	return projection, nil
}

func validateProtectedPublicProjection(projection ProtectedPublicProjection) error {
	if projection.Schema != classifiedPublicProjectionSchema ||
		projection.Classification != classifiedPublicProjectionClassification ||
		projection.Project != classifiedPublicProjectionProject ||
		projection.Story != classifiedPublicProjectionStory ||
		projection.Assurance != AssuranceOwnerOnly ||
		projection.IndependentReviewClaimed || projection.AutobahnReruns != 0 {
		return errors.New("PUBLIC_PROJECTION_SEMANTIC_INVALID/QUARANTINE")
	}
	if !validClassifiedAttemptID(projection.AttemptID) ||
		!sbxGitObjectPattern.MatchString(projection.TargetCommit) ||
		!sbxGitObjectPattern.MatchString(projection.TargetTree) {
		return errors.New("PUBLIC_PROJECTION_BINDING_INVALID/QUARANTINE")
	}

	digests := projection.Digests
	if digests.FixedPlanDigest != protectedFixedPlanDigest() ||
		digests.ProfileDigest != classifiedPublicProjectionProfileDigest() ||
		digests.TemplateDigest != classifiedPublicProjectionTemplateDigest ||
		!allClassifiedDigests(
			digests.PolicyDigest,
			digests.RuntimeDigest,
			digests.SupervisorDigest,
			digests.AuthorizationClosureDigest,
		) {
		return errors.New("PUBLIC_PROJECTION_PROVENANCE_INVALID/QUARANTINE")
	}
	if projection.ResourceEnvelope != exactProtectedEnvelope() {
		return errors.New("PUBLIC_PROJECTION_RESOURCE_ENVELOPE_INVALID/QUARANTINE")
	}

	plan := protectedFixedPlan()
	if len(projection.DescriptorSummaries) != len(plan) {
		return errors.New("PUBLIC_PROJECTION_DESCRIPTOR_COUNT_INVALID/QUARANTINE")
	}
	for index, summary := range projection.DescriptorSummaries {
		if summary.DescriptorID != plan[index] || !summary.Accepted || !isSHA256Digest(summary.RawReceiptDigest) {
			return errors.New("PUBLIC_PROJECTION_DESCRIPTOR_ORDER_INVALID/QUARANTINE")
		}
	}

	if !isSHA256Digest(projection.BenignArtifact.Digest) ||
		projection.BenignArtifact.Bytes <= 0 || projection.BenignArtifact.Bytes > 4<<20 ||
		!allClassifiedDigests(projection.Cleanup.RemoveDigest, projection.Cleanup.AbsenceDigest) ||
		!projection.Cleanup.SandboxAbsent ||
		projection.Classifier.RuleDigest != classifiedPublicProjectionRuleDigest ||
		!allClassifiedDigests(projection.Classifier.InputDigest, projection.Classifier.ActionDigest, projection.Classifier.OutputDigest) {
		return errors.New("PUBLIC_PROJECTION_OBSERVATION_INVALID/QUARANTINE")
	}
	return nil
}

func validClassifiedAttemptID(value string) bool {
	if !strings.HasPrefix(value, classifiedPublicProjectionAttemptPrefix) {
		return false
	}
	suffix := strings.TrimPrefix(value, classifiedPublicProjectionAttemptPrefix)
	if len(suffix) != 4 || suffix == classifiedPublicProjectionStaleAttempt {
		return false
	}
	for _, character := range []byte(suffix) {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func allClassifiedDigests(values ...string) bool {
	for _, value := range values {
		if !isSHA256Digest(value) {
			return false
		}
	}
	return true
}

func exactProtectedEnvelope() resources {
	return resources{WallSeconds: 60, CPUSeconds: 60, MemoryBytes: 1073741824, PIDs: 64, OpenFiles: 256, OutputBytes: 8388608, WorkspaceBytes: 67108864, CacheBytes: 67108864, DiskBytes: 67108864, Inodes: 16384}
}

func classifiedPublicProjectionProfileDigest() string {
	data, _ := json.Marshal(exactProtectedEnvelope())
	return intake.DigestBytes(data)
}

func protectedFixedPlan() []string {
	return []string{"CACHE_WRITE_DENIED", "CLEAN_EXIT", "CPU_BOUND", "ENV_SENTINEL_ABSENT", "FD_BOUND", "MEMORY_BOUND", "NETWORK_SOCKET_DENIED", "OUTPUT_BOUND", "PID_BOUND", "PROTECTED_SENTINEL_DENIED", "SESSION_ESCAPE_CLEANUP", "SOURCE_WRITE_DENIED", "WALL_BOUND", "WORKSPACE_BOUND", "BENIGN_OPERATION"}
}

func protectedFixedPlanDigest() string {
	type descriptor struct {
		ID              string `json:"id"`
		ProgramKey      string `json:"program_key"`
		ExpectedOutcome string `json:"expected_outcome"`
	}
	items := make([]descriptor, 0, len(protectedFixedPlan()))
	for _, id := range protectedFixedPlan() {
		_, expectation, _ := sbxDescriptorContract(id)
		keys := map[string]string{"CACHE_WRITE_DENIED": "cache", "CLEAN_EXIT": "clean", "CPU_BOUND": "cpu", "ENV_SENTINEL_ABSENT": "secret", "FD_BOUND": "fd", "MEMORY_BOUND": "memory", "NETWORK_SOCKET_DENIED": "network", "OUTPUT_BOUND": "output", "PID_BOUND": "pid", "PROTECTED_SENTINEL_DENIED": "protected", "SESSION_ESCAPE_CLEANUP": "session", "SOURCE_WRITE_DENIED": "source", "WALL_BOUND": "wall", "WORKSPACE_BOUND": "workspace", "BENIGN_OPERATION": "benign"}
		items = append(items, descriptor{id, keys[id], expectation})
	}
	data, _ := json.Marshal(items)
	return intake.DigestBytes(data)
}
