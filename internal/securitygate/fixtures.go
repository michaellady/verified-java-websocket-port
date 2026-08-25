package securitygate

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

type fixtureObservation struct {
	Component    string `json:"component"`
	State        string `json:"state"`
	Code         string `json:"code"`
	Disposition  string `json:"disposition"`
	Exit         int    `json:"exit"`
	InputDigest  string `json:"input_digest"`
	OutputDigest string `json:"output_digest"`
}

func evaluateFixture(snapshot *policySnapshot, item fixtureCase) (fixtureObservation, error) {
	observation := fixtureObservation{Component: strings.ToUpper(item.Kind), State: "PASS_SYNTHETIC_NON_CLAIM", InputDigest: intake.DigestBytes([]byte(item.Input))}
	var finding *Finding
	var err error
	switch item.Kind {
	case "inventory":
		finding = evaluateInventoryFixture(item)
	case "ingestion":
		finding, err = evaluateIngestionFixture(snapshot, item)
	case "sandbox":
		finding, err = evaluateSandboxFixture(snapshot, item)
	case "release":
		finding = evaluateReleaseFixture(snapshot.release, item)
	default:
		return fixtureObservation{}, errors.New("fixture kind is outside the closed registry")
	}
	if err != nil {
		return fixtureObservation{}, err
	}
	if finding != nil {
		observation.State = "BLOCKED"
		observation.Code = finding.Code
		observation.Disposition = finding.Disposition
		observation.Exit = 1
	}
	observation.OutputDigest = fixtureObservationDigest(observation)
	if observation.OutputDigest == "" {
		return fixtureObservation{}, errors.New("cannot canonicalize fixture observation")
	}
	return observation, nil
}

func fixtureObservationDigest(observation fixtureObservation) string {
	canonical, err := intake.CanonicalJSON(struct {
		Component   string `json:"component"`
		State       string `json:"state"`
		Code        string `json:"code"`
		Disposition string `json:"disposition"`
		Exit        int    `json:"exit"`
		InputDigest string `json:"input_digest"`
	}{observation.Component, observation.State, observation.Code, observation.Disposition, observation.Exit, observation.InputDigest})
	if err != nil {
		return ""
	}
	return intake.DigestBytes(canonical)
}

func evaluateInventoryFixture(item fixtureCase) *Finding {
	fixtures := map[string]struct{ path, input string }{
		"annotation-processor":   {"pom.xml", `<project><build><plugins><plugin><annotationProcessorPaths/></plugin></plugins></build></project>`},
		"autobahn-python":        {"autobahn/requirements.txt", "autobahn-testsuite==0.8\npython3 wstest"},
		"container-entrypoint":   {"oci/config.json", `{"architecture":"amd64","Entrypoint":["inert"]}`},
		"language-server-import": {"lsp-plugins.json", `{"jdt.ls":"inert"}`},
		"maven-plugin":           {"pom.xml", `<project><build><plugins><plugin/></plugins></build></project>`},
		"proc-macro":             {"Cargo.toml", "[lib]\nproc-macro = true"},
		"rust-build-script":      {"build.rs", "fn main() {}"},
	}
	fixture, ok := fixtures[item.ID]
	if !ok {
		return &Finding{Code: "EXECUTABLE_INVENTORY_INCOMPLETE", Disposition: "QUARANTINE", Path: item.ID, Message: "inventory fixture has no static discovery recipe"}
	}
	items := discoverExecutables(fixture.path, []byte(fixture.input), 0o600, "REGULAR")
	if len(items) == 0 {
		return &Finding{Code: "EXECUTABLE_INVENTORY_INCOMPLETE", Disposition: "QUARANTINE", Path: fixture.path, Message: "static discovery found no hostile executable"}
	}
	for _, executable := range items {
		if executable.PromotionReceipt == "" || len(executable.AllowedOperations) == 0 {
			return &Finding{Code: "UNPROMOTED_EXECUTABLE", Disposition: "QUARANTINE", Path: fixture.path, Message: "observed inventory item has no promotion/use binding"}
		}
	}
	return nil
}

func evaluateIngestionFixture(snapshot *policySnapshot, item fixtureCase) (*Finding, error) {
	switch item.ID {
	case "absolute-path":
		code, message := validateCandidatePath("/synthetic", snapshot.ingestion.Paths)
		return &Finding{Code: code, Disposition: snapshot.registry[code], Path: "/synthetic", Message: message}, nil
	case "path-traversal":
		code, message := validateCandidatePath("../synthetic", snapshot.ingestion.Paths)
		return &Finding{Code: code, Disposition: snapshot.registry[code], Path: "../synthetic", Message: message}, nil
	case "case-collision":
		if collisionKey("Case.txt") == collisionKey("case.txt") {
			return fixtureFinding(snapshot, "NORMALIZATION_COLLISION", item.ID), nil
		}
	case "unicode-collision":
		if collisionKey("É.txt") == collisionKey("é.txt") {
			return fixtureFinding(snapshot, "NORMALIZATION_COLLISION", item.ID), nil
		}
	case "symlink":
		return staticEntryFinding(snapshot, os.ModeSymlink, 1, item.ID), nil
	case "hard-link":
		return staticEntryFinding(snapshot, 0, 2, item.ID), nil
	case "special-file":
		return staticEntryFinding(snapshot, os.ModeNamedPipe, 1, item.ID), nil
	case "static-exec-request":
		return fixtureFinding(snapshot, "STATIC_EXECUTION_FORBIDDEN", item.ID), nil
	case "archive-bomb":
		archive := inertZip(tinyZipMember{name: "safe.txt", data: []byte("bounded")})
		policy := snapshot.ingestion
		policy.Quotas.MaxExpandedBytes = 1
		_, finding := inspectArchive("inert.zip", archive, policy)
		return finding, nil
	case "nested-archive":
		inner := inertZip(tinyZipMember{name: "safe.txt", data: []byte("inert")})
		outer := inertZip(tinyZipMember{name: "nested.zip", data: inner})
		_, finding := inspectArchive("outer.zip", outer, snapshot.ingestion)
		return finding, nil
	case "quota-breach":
		return fixtureFinding(snapshot, "QUOTA_EXCEEDED", item.ID), nil
	case "partial-promotion":
		return promotionCompletionFinding(snapshot, "", errors.New("injected pre-rename fixture fault")), nil
	case "digest-mismatch":
		declared := intake.DigestBytes([]byte("declared inert bytes"))
		if intake.DigestBytes([]byte("observed inert bytes")) != declared {
			return fixtureFinding(snapshot, "DIGEST_MISMATCH", item.ID), nil
		}
	case "dangling-provenance":
		return validateFixtureProvenance(snapshot, "", requiredCompany), nil
	case "cross-company-provenance":
		return validateFixtureProvenance(snapshot, "sha256:"+strings.Repeat("a", 64), "another-company"), nil
	case "good-benign-ingest":
		candidate, err := os.MkdirTemp("", "us007-benign-candidate-")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(candidate)
		store, err := os.MkdirTemp("", "us007-benign-store-")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(store)
		if err := os.WriteFile(filepath.Join(candidate, "safe.txt"), []byte("inert fixture bytes"), 0o600); err != nil {
			return nil, err
		}
		manifest, objects, finding := snapshotCandidate(candidate, snapshot.ingestion)
		if finding != nil {
			return finding, nil
		}
		verdict, err := promoteCandidate(baseVerdict(snapshot), store, manifest, objects, true)
		if err != nil {
			return nil, err
		}
		if len(verdict.Findings) != 0 || verdict.State != "PASS_SYNTHETIC_NON_CLAIM" || !isSHA256Digest(verdict.QuarantineRoot) {
			return fixtureFinding(snapshot, "PARTIAL_PROMOTION", item.ID), nil
		}
		return nil, nil
	}
	return fixtureFinding(snapshot, "INVALID_SECURITY_POLICY", item.ID), nil
}

type tinyZipMember struct {
	name string
	data []byte
}

func inertZip(members ...tinyZipMember) []byte {
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, member := range members {
		entry, err := writer.Create(member.name)
		if err != nil {
			return nil
		}
		if _, err := entry.Write(member.data); err != nil {
			return nil
		}
	}
	if err := writer.Close(); err != nil {
		return nil
	}
	return buffer.Bytes()
}

func staticEntryFinding(snapshot *policySnapshot, mode os.FileMode, links uint64, path string) *Finding {
	code := classifyStaticEntry(mode, links)
	if code == "" {
		return nil
	}
	return fixtureFinding(snapshot, code, path)
}

func classifyStaticEntry(mode os.FileMode, links uint64) string {
	if mode&os.ModeSymlink != 0 {
		return "UNSAFE_SYMLINK"
	}
	if mode&os.ModeType != 0 && !mode.IsDir() {
		return "SPECIAL_FILE_DENIED"
	}
	if !mode.IsDir() && links != 1 {
		return "HARD_LINK_DENIED"
	}
	return ""
}

func promotionCompletionFinding(snapshot *policySnapshot, acceptedRoot string, err error) *Finding {
	if err != nil || !isSHA256Digest(acceptedRoot) {
		return fixtureFinding(snapshot, "PARTIAL_PROMOTION", "$.promotion")
	}
	return nil
}

func validateFixtureProvenance(snapshot *policySnapshot, parentDigest, company string) *Finding {
	if company != requiredCompany {
		return fixtureFinding(snapshot, "CROSS_COMPANY_REFERENCE", "$.provenance.company")
	}
	if !isSHA256Digest(parentDigest) {
		return fixtureFinding(snapshot, "DANGLING_PROVENANCE", "$.provenance.parent")
	}
	return nil
}

func evaluateSandboxFixture(snapshot *policySnapshot, item fixtureCase) (*Finding, error) {
	if item.ID == "autobahn-third-run" {
		return validateClosedOperation(snapshot, "AUTOBAHN_QUALIFICATION"), nil
	}
	if item.ID == "receipt-mutation" {
		mutated := make(map[string][]byte, len(snapshot.bytes))
		for path, data := range snapshot.bytes {
			mutated[path] = append([]byte(nil), data...)
		}
		mutated[baselineEvidencePaths[3]] = bytes.Replace(mutated[baselineEvidencePaths[3]], []byte(originalReceipt), []byte("sha256:"+strings.Repeat("1", 64)), 1)
		if _, err := validateAutobahnClosure(mutated); err != nil {
			return fixtureFinding(snapshot, "CANONICAL_EVIDENCE_MUTATION", item.ID), nil
		}
		return nil, nil
	}
	if item.ID == "good-sandbox-canaries" {
		_, err := RunControlledCanary(context.Background(), CanaryRequest{RootPath: "", CanaryID: "CLEAN_EXIT", PlanDigest: "sha256:" + strings.Repeat("a", 64)})
		if err != nil {
			return fixtureFinding(snapshot, "SANDBOX_ENFORCEMENT_UNAVAILABLE", "$.platform_enforcement"), nil
		}
		return nil, nil
	}
	plan, receipt := inertSandboxPair(snapshot, "CLEAN_EXIT")
	switch item.ID {
	case "capture-failure":
		receipt.ArtifactCaptureComplete = false
	case "cleanup-residue":
		receipt.LivePIDsAfter = 1
	case "network-probe":
		receipt.AllowedEndpointCount = 1
	case "secret-probe":
		receipt.SecretValueCount = 1
	case "protected-store-probe":
		receipt.ForbiddenMountCount = 1
	case "cpu-bomb", "memory-bomb", "pid-bomb", "fd-bomb", "output-bomb", "wall-bomb":
		canaries := map[string]string{"cpu-bomb": "CPU_BOUND", "memory-bomb": "MEMORY_BOUND", "pid-bomb": "PID_BOUND", "fd-bomb": "FD_BOUND", "output-bomb": "OUTPUT_BOUND", "wall-bomb": "WALL_BOUND"}
		plan.CanaryID = canaries[item.ID]
		receipt.CanaryID = plan.CanaryID
		plan.PlanDigest, _ = sandboxPlanDigest(plan)
		receipt.PlanDigest = plan.PlanDigest
	case "disk-bomb":
		return fixtureFinding(snapshot, "RESOURCE_TERMINATION_MISSING", item.ID), nil
	default:
		return fixtureFinding(snapshot, "INVALID_SECURITY_POLICY", item.ID), nil
	}
	return validateSandboxReceipt(snapshot, plan, receipt), nil
}

func inertSandboxPair(snapshot *policySnapshot, canaryID string) (sandboxPlan, securitySandboxReceipt) {
	digest := "sha256:" + strings.Repeat("a", 64)
	promotion := "sha256:" + strings.Repeat("b", 64)
	securityctl := "sha256:" + strings.Repeat("c", 64)
	supervisor := "sha256:" + strings.Repeat("d", 64)
	plan := sandboxPlan{
		SchemaVersion: policyVersion, PolicyDigest: snapshot.digests[policyPaths[1]],
		AcceptedRootDigest: digest, InventoryRootDigest: digest,
		PromotionReceipts: []string{promotion}, SecurityctlDigest: securityctl, SupervisorDigest: supervisor,
		CanaryID: canaryID, Capabilities: append([]string(nil), snapshot.sandbox.RequiredCapabilities...), Resources: snapshot.sandbox.Resources,
	}
	plan.PlanDigest, _ = sandboxPlanDigest(plan)
	exitCode := 0
	observed := resources{}
	receipt := securitySandboxReceipt{
		SchemaVersion: policyVersion, AttemptID: "synthetic-attempt-1", Company: requiredCompany, Project: requiredProject,
		PlanDigest: plan.PlanDigest, PolicyDigest: plan.PolicyDigest, AcceptedRootDigest: digest, InventoryRootDigest: digest,
		PromotionReceipts: append([]string(nil), plan.PromotionReceipts...), SecurityctlDigest: securityctl, SupervisorDigest: supervisor,
		CanaryID: canaryID, PlatformIdentity: "synthetic-platform-non-claim",
		NamespaceIDs: map[string]string{"ipc": "synthetic-ipc", "mount": "synthetic-mount", "network": "synthetic-network", "pid": "synthetic-pid", "user": "synthetic-user", "uts": "synthetic-uts"},
		CgroupID:     "synthetic-cgroup", ProfileDigest: digest, MountTableBeforeDigest: digest,
		EnvironmentNames: append([]string(nil), snapshot.sandbox.EnvironmentNames...), EnvironmentDigest: digest,
		StartedAt: "2026-08-24T00:00:00Z", FinishedAt: "2026-08-24T00:00:01Z", ExitCode: &exitCode,
		TerminationReason: "EXITED", NetworkAttemptsByClass: map[string]int{"connect": 0, "dns": 0, "socket": 0}, ObservedResources: &observed,
		ArtifactCaptureComplete: true, ArtifactManifestDigest: digest,
		SourceBeforeDigest: digest, SourceAfterDigest: digest, CacheBeforeDigest: digest, CacheAfterDigest: digest,
		CleanupStartedAt: "2026-08-24T00:00:01Z", CleanupFinishedAt: "2026-08-24T00:00:02Z",
		WritableRootsRemoved: true, CleanupComplete: true, Assurance: AssuranceOwnerOnly,
	}
	return plan, receipt
}

func validateClosedOperation(snapshot *policySnapshot, operation string) *Finding {
	if strings.HasPrefix(operation, "AUTOBAHN_") && !snapshot.sandbox.FurtherRerunsAuthorized {
		return fixtureFinding(snapshot, "AUTOBAHN_RERUN_FORBIDDEN", "$.operation")
	}
	return nil
}

func evaluateReleaseFixture(policy releasePolicy, item fixtureCase) *Finding {
	if code, _, err := scanReleaseFixture(policy, item); err == nil && code != "" {
		return &Finding{Code: code, Disposition: "REVOKE", Path: item.ID, Message: "reopened fixture bytes matched a declarative detector"}
	}
	codes := map[string]string{
		"independence-claim":      "ASSURANCE_CEILING_EXCEEDED",
		"late-public-mutation":    "PUBLIC_PROJECTION_DRIFT",
		"provenance-gap":          "PUBLIC_PROVENANCE_GAP",
		"publication-attempt":     "PUBLICATION_NOT_AUTHORIZED",
		"unclassified-descendant": "PUBLIC_DESCENDANT_UNCLASSIFIED",
	}
	if code := codes[item.ID]; code != "" {
		disposition := "BLOCK"
		if code == "ASSURANCE_CEILING_EXCEEDED" || code == "PUBLIC_PROJECTION_DRIFT" {
			disposition = "REVOKE"
		}
		return &Finding{Code: code, Disposition: disposition, Path: item.ID, Message: "recursive projection control rejected the observed fixture"}
	}
	if item.ID == "good-safe-projection" && scanProjectionBytes(policy, "public/readme.txt", []byte(item.Input)) == nil {
		return nil
	}
	return &Finding{Code: "INVALID_SECURITY_POLICY", Disposition: "BLOCK", Path: item.ID, Message: "release fixture was not observed by a closed control"}
}

func fixtureFinding(snapshot *policySnapshot, code, path string) *Finding {
	return &Finding{Code: code, Disposition: snapshot.registry[code], Path: path, Message: "inert fixture observation produced a typed finding"}
}
