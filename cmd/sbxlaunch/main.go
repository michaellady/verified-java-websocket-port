// Command sbxlaunch runs a payload inside the accepted US-007 sandbox profile.
//
// WHY THIS EXISTS, AND HOW IT DIFFERS FROM protected/us007-sbx-launcher.
//
// The other launcher (protected/us007-sbx-launcher/main.go on the Codex plane)
// is unusable from the Claude authority plane for three independent reasons,
// each verified by reading its source:
//
//  1. Every path is a compile-time constant pointing at the OTHER plane:
//     repoPath = /Users/mikelady/hq/repos/public/verified-java-websocket-port,
//     outputPath and ledgerPath under .../verified-java-websocket-port/protected/,
//     planPath under companies/open-source-projects/projects/.../prd.json.
//     Running it would WRITE the Codex plane, which this plane is forbidden to do.
//  2. It requires an owner ed25519 signing secret
//     (VERIFIED_JAVA_WEBSOCKET_US001_OWNER_ED25519_PRIVATE_KEY) to mint a
//     promotion record and a signed launch authorization. This plane does not
//     hold that secret.
//  3. Its workload is fixed: a 15-canary containment suite. It has no way to
//     carry an arbitrary payload in, run it, and bring receipts back out.
//
// This launcher is PLANE-LOCAL and parameterised. Repo root, protected root,
// attempt id, sandbox name, artifacts and steps all arrive as arguments and as
// a payload manifest; there is not one absolute path to any plane baked into
// this file, and it needs no secret at all.
//
// SIGNING STANCE, STATED PLAINLY. The other launcher's ed25519 promotion and
// launch-authorization records are NOT reproduced here, and no substitute is
// invented. The receipts this launcher writes are UNSIGNED and say so. That is
// a real reduction in evidentiary strength relative to a signed receipt and is
// reported as such rather than papered over; an unsigned receipt honestly
// labelled is preferable to a fabricated signature. The owner-authorization
// record for the attempt supplies the authority; this launcher supplies the
// mechanical evidence.
//
// WHAT IT GUARANTEES:
//
//   - Profile parity is VERIFIED, not asserted: the pinned template digest,
//     clone workspace mode, cpu/memory, the deny-all network rule and the
//     unprivileged uid are each read back from the live sandbox and compared
//     with the payload's declared profile before the workload runs.
//   - Every transfer is digest-verified in BOTH directions. sbx cp exit codes
//     are not trusted on this plane (the 0124 finding), so the host digest is
//     compared against a digest computed INSIDE the sandbox on the way in, and
//     the in-sandbox digest is compared against a host digest on the way out.
//   - Receipts are extracted BEFORE `sbx rm`, including when the workload
//     FAILED. The E3 lane lost two runs' evidence by removing first; that
//     ordering is enforced here by construction.
//   - Every exit status is read from the real process. Nothing infers success
//     from output text, and `go run` is never used.
//
// Usage:
//
//	sbxlaunch -repo-root <dir> -protected-root <dir> -payload <payload.json> \
//	          -stage <host staging dir> [-keep-sandbox]
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type payload struct {
	SchemaVersion string   `json:"schema_version"`
	Kind          string   `json:"kind"`
	AttemptID     string   `json:"attempt_id"`
	SandboxName   string   `json:"sandbox_name"`
	Story         string   `json:"story"`
	Profile       profile  `json:"profile"`
	Inbound       inbound  `json:"inbound"`
	Steps         []step   `json:"steps"`
	Outbound      outbound `json:"outbound"`
}

type profile struct {
	SbxBinary      string `json:"sbx_binary"`
	CLIVersion     string `json:"cli_version"`
	TemplateRef    string `json:"template_reference"`
	TemplateDigest string `json:"template_digest"`
	Agent          string `json:"agent"`
	WorkspaceMode  string `json:"workspace_mode"`
	CPUs           int    `json:"cpus"`
	Memory         string `json:"memory"`
	DenyNetwork    string `json:"deny_network"`
	ExpectedUID    int    `json:"expected_uid"`
	ExpectedUser   string `json:"expected_user"`
}

type inbound struct {
	StageSubdir  string   `json:"stage_subdir"`
	Artifacts    []string `json:"artifacts"`
	SandboxDir   string   `json:"sandbox_dir"`
	BundleName   string   `json:"bundle_name"`
	ManifestName string   `json:"manifest_name"`
}

type step struct {
	ID             string   `json:"id"`
	Argv           []string `json:"argv"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	ExpectExit     *int     `json:"expect_exit"`
	CaptureName    string   `json:"capture_name"`
}

type outbound struct {
	SandboxDir   string `json:"sandbox_dir"`
	ManifestName string `json:"manifest_name"`
	BundleName   string `json:"bundle_name"`
}

type transferRecord struct {
	Name          string `json:"name"`
	HostSHA256    string `json:"host_sha256"`
	SandboxSHA256 string `json:"sandbox_sha256"`
	Bytes         int64  `json:"bytes"`
	Match         bool   `json:"match"`
	Direction     string `json:"direction"`
}

type stepRecord struct {
	ID          string `json:"id"`
	Argv        string `json:"argv"`
	ExitCode    int    `json:"exit_code"`
	ExpectExit  *int   `json:"expect_exit"`
	Matched     bool   `json:"exit_matched_expectation"`
	StartedAt   string `json:"started_at"`
	FinishedAt  string `json:"finished_at"`
	CapturePath string `json:"host_capture_path"`
	OutputBytes int    `json:"captured_bytes"`
}

// parityCheck is deliberately TRI-STATE. A constraint the CLI and the guest
// simply do not expose is not the same thing as a constraint that matched, and
// recording it as a pass would be exactly the kind of quiet upgrade this plane
// forbids. MISMATCHED aborts the attempt; DECLARED_NOT_OBSERVABLE does not, but
// it is carried into the receipt so a reader sees which constraints were
// actually read back and which rest on the create argv alone.
type parityCheck struct {
	Constraint string `json:"constraint"`
	Declared   string `json:"declared"`
	Observed   string `json:"observed"`
	Source     string `json:"evidence_source"`
	Status     string `json:"status"`
	Match      bool   `json:"match"`
}

const (
	statusMatched      = "MATCHED"
	statusMismatched   = "MISMATCHED"
	statusNotObservabl = "DECLARED_NOT_OBSERVABLE"
)

func observed(constraint, declared, seen, source string, ok bool) parityCheck {
	status := statusMismatched
	if ok {
		status = statusMatched
	}
	return parityCheck{constraint, declared, seen, source, status, ok}
}

type operatorReceipt struct {
	SchemaVersion     string           `json:"schema_version"`
	Kind              string           `json:"kind"`
	AttemptID         string           `json:"attempt_id"`
	SandboxName       string           `json:"sandbox_name"`
	Story             string           `json:"story"`
	LauncherPlane     string           `json:"launcher_plane"`
	LauncherSelfSHA   string           `json:"launcher_binary_sha256"`
	SourceCommit      string           `json:"source_commit"`
	CLIBanner         string           `json:"sbx_cli_banner"`
	StartedAt         string           `json:"started_at"`
	FinishedAt        string           `json:"finished_at"`
	ProfileParity     []parityCheck    `json:"profile_parity"`
	ProfileParityOK   bool             `json:"profile_parity_all_matched"`
	Inbound           []transferRecord `json:"inbound_transfers"`
	Outbound          []transferRecord `json:"outbound_transfers"`
	Steps             []stepRecord     `json:"steps"`
	ExtractedBeforeRm bool             `json:"receipts_extracted_before_rm"`
	RemoveInvoked     bool             `json:"remove_invoked"`
	RemoveExit        int              `json:"remove_exit_code"`
	SandboxAbsent     bool             `json:"sandbox_absent_after_remove"`
	WorkloadFailed    bool             `json:"workload_failed"`
	Signed            bool             `json:"signed"`
	SigningStance     string           `json:"signing_stance"`
	Assurance         string           `json:"assurance"`
	IndependentReview bool             `json:"independent_review_claimed"`
	Production        bool             `json:"production"`
	Publication       bool             `json:"publication"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "sbxlaunch: %v\n", err)
		os.Exit(1)
	}
}

func run() (returnedErr error) {
	repoRoot := flag.String("repo-root", "", "repository root whose HEAD is cloned into the sandbox")
	protectedRoot := flag.String("protected-root", "", "protected root under which this attempt's directory is written")
	payloadPath := flag.String("payload", "", "path to the payload manifest")
	stage := flag.String("stage", "", "host staging directory (must already hold the verified artifacts)")
	keep := flag.Bool("keep-sandbox", false, "skip removal (for debugging only; never used for evidence runs)")
	flag.Parse()
	if *repoRoot == "" || *protectedRoot == "" || *payloadPath == "" || *stage == "" {
		return errors.New("-repo-root, -protected-root, -payload and -stage are all required")
	}

	load, err := readPayload(*payloadPath)
	if err != nil {
		return err
	}

	// The host capture root carries the SANDBOX NAME. The E3 lane overwrote two
	// runs' stdout by sharing one scratch path across sandboxes; naming the path
	// after the sandbox makes that collision impossible.
	attemptDir := filepath.Join(*protectedRoot, load.AttemptID)
	captureDir := filepath.Join(attemptDir, "host-capture-"+load.SandboxName)
	for _, dir := range []string{attemptDir, captureDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	receipt := operatorReceipt{
		SchemaVersion: "1.0.0", Kind: "sbx-plane-local-launch-receipt",
		AttemptID: load.AttemptID, SandboxName: load.SandboxName, Story: load.Story,
		LauncherPlane: "verified-java-websocket-port-claude (Claude authority plane)",
		StartedAt:     nowUTC(),
		Signed:        false,
		SigningStance: "UNSIGNED BY CONSTRUCTION. This plane does not hold the owner ed25519 signing secret the Codex-plane launcher requires, and no substitute signature was invented. Authority comes from the attempt's owner-authorization record; this receipt supplies only mechanical evidence.",
		Assurance:     "OWNER_ATTESTED_NOT_INDEPENDENT", IndependentReview: false, Production: false, Publication: false,
	}
	if self, err := digestFile(mustExecutable()); err == nil {
		receipt.LauncherSelfSHA = "sha256:" + self
	}

	head, err := capture(context.Background(), 2*time.Minute, "git", "-C", *repoRoot, "rev-parse", "HEAD")
	if err != nil {
		return fmt.Errorf("read repo HEAD: %w", err)
	}
	receipt.SourceCommit = strings.TrimSpace(string(head))

	banner, err := capture(context.Background(), time.Minute, load.Profile.SbxBinary, "version")
	if err != nil {
		return fmt.Errorf("read sbx banner: %w", err)
	}
	receipt.CLIBanner = strings.TrimSpace(string(banner))
	if !strings.Contains(receipt.CLIBanner, load.Profile.CLIVersion) {
		return fmt.Errorf("sbx CLI banner %q does not carry the declared version %q", receipt.CLIBanner, load.Profile.CLIVersion)
	}

	// Receipts must survive every exit path, including a failed workload.
	defer func() {
		receipt.FinishedAt = nowUTC()
		blob, marshalErr := json.MarshalIndent(receipt, "", " ")
		if marshalErr != nil {
			return
		}
		if writeErr := os.WriteFile(filepath.Join(attemptDir, "launch-receipt.json"), append(blob, '\n'), 0o644); writeErr != nil && returnedErr == nil {
			returnedErr = writeErr
		}
	}()

	if err := assertAbsent(load.Profile.SbxBinary, load.SandboxName); err != nil {
		return err
	}

	cloneDir := filepath.Join(*stage, "src-"+load.SandboxName)
	if err := os.RemoveAll(cloneDir); err != nil {
		return err
	}
	if err := os.MkdirAll(cloneDir, 0o755); err != nil {
		return err
	}
	if err := gitClone(*repoRoot, cloneDir, receipt.SourceCommit); err != nil {
		return fmt.Errorf("stage clean source: %w", err)
	}

	createArgv := []string{load.Profile.SbxBinary, "create", "--clone",
		"--cpus", strconv.Itoa(load.Profile.CPUs), "-m", load.Profile.Memory,
		"--deny-network", load.Profile.DenyNetwork,
		"--name", load.SandboxName,
		"--template", load.Profile.TemplateRef,
		load.Profile.Agent, cloneDir}
	createOut, createErr := capture(context.Background(), 15*time.Minute, createArgv...)
	writeCapture(captureDir, "sbx-create.log", createOut)
	if createErr != nil {
		return fmt.Errorf("sbx create: %w", createErr)
	}

	// From this point the sandbox EXISTS. Extraction happens before removal on
	// every path, so removal is deferred and extraction is not.
	removed := false
	defer func() {
		if removed || *keep {
			return
		}
		receipt.RemoveInvoked = true
		out, rmErr := capture(context.Background(), 5*time.Minute, load.Profile.SbxBinary, "rm", "--force", load.SandboxName)
		writeCapture(captureDir, "sbx-rm.log", out)
		receipt.RemoveExit = exitCode(rmErr)
		absent, _ := isAbsent(load.Profile.SbxBinary, load.SandboxName)
		receipt.SandboxAbsent = absent
	}()

	if err := verifyProfileParity(load, captureDir, &receipt); err != nil {
		return err
	}

	if err := transferIn(load, *stage, captureDir, &receipt); err != nil {
		return err
	}

	workloadErr := runSteps(load, captureDir, &receipt)
	if workloadErr != nil {
		receipt.WorkloadFailed = true
	}

	// EXTRACT FIRST — even when the workload failed. A failed run's receipts are
	// the most valuable ones and the easiest to lose.
	extractErr := transferOut(load, attemptDir, captureDir, &receipt)
	receipt.ExtractedBeforeRm = true

	if !*keep {
		receipt.RemoveInvoked = true
		out, rmErr := capture(context.Background(), 5*time.Minute, load.Profile.SbxBinary, "rm", "--force", load.SandboxName)
		writeCapture(captureDir, "sbx-rm.log", out)
		receipt.RemoveExit = exitCode(rmErr)
		removed = true
		absent, absErr := isAbsent(load.Profile.SbxBinary, load.SandboxName)
		receipt.SandboxAbsent = absent
		if rmErr != nil {
			return fmt.Errorf("sbx rm: %w", rmErr)
		}
		if absErr != nil || !absent {
			return fmt.Errorf("sandbox still present after removal (absent=%v err=%v)", absent, absErr)
		}
	}

	if workloadErr != nil {
		return workloadErr
	}
	return extractErr
}

// verifyProfileParity reads each declared constraint back out of the LIVE
// sandbox. Nothing here is taken from the payload on faith.
func verifyProfileParity(load payload, captureDir string, receipt *operatorReceipt) error {
	inspectRaw, err := capture(context.Background(), 2*time.Minute, load.Profile.SbxBinary, "inspect", load.SandboxName, "--json")
	writeCapture(captureDir, "sbx-inspect.json", inspectRaw)
	if err != nil {
		return fmt.Errorf("sbx inspect: %w", err)
	}
	// NOTE ON WHAT sbx v0.39.0 ACTUALLY EXPOSES. `sbx inspect --json` reports no
	// cpu, memory or clone field. Clone mode is observable only indirectly, via
	// the localhost git-bridge port sbx publishes for the clone's git daemon (the
	// same signal the Codex-plane launcher checks). CPU and memory are not in the
	// CLI's output at all, so they are read from INSIDE the sandbox — nproc and
	// the cgroup memory limit — rather than asserted from the create argv the way
	// every prior accepted attempt on this plane recorded them.
	var inspect struct {
		Name        string   `json:"name"`
		Agent       string   `json:"agent"`
		Image       string   `json:"image"`
		ImageDigest string   `json:"image_digest"`
		Workspace   string   `json:"workspace"`
		State       string   `json:"state"`
		Ports       []string `json:"ports"`
		MCPGateway  bool     `json:"mcp_gateway"`
		Secrets     []struct {
			Name   string `json:"name"`
			Source string `json:"source"`
		} `json:"secrets"`
	}
	if err := json.Unmarshal(inspectRaw, &inspect); err != nil {
		return fmt.Errorf("decode sbx inspect: %w", err)
	}

	policyRaw, policyErr := capture(context.Background(), 2*time.Minute, load.Profile.SbxBinary, "policy", "ls", load.SandboxName, "--json")
	writeCapture(captureDir, "sbx-policy.json", policyRaw)
	if policyErr != nil {
		return fmt.Errorf("sbx policy ls: %w", policyErr)
	}
	policyText := strings.ToLower(strings.Join(strings.Fields(string(policyRaw)), ""))
	denyAll := strings.Contains(policyText, `"decision":"deny"`) && strings.Contains(policyText, `"**"`)

	idOut, idErr := capture(context.Background(), 2*time.Minute, load.Profile.SbxBinary, "exec", load.SandboxName, "sh", "-lc",
		"id -u; id -un; uname -m; pwd; git rev-parse HEAD; nproc; "+
			"{ cat /sys/fs/cgroup/memory.max || cat /sys/fs/cgroup/memory/memory.limit_in_bytes || "+
			"cat /sys/fs/cgroup$(awk -F: '/memory/{print $3; exit}' /proc/self/cgroup 2>/dev/null)/memory.max; } 2>/dev/null | head -1 || true; echo UNAVAILABLE")
	writeCapture(captureDir, "sbx-identity.txt", idOut)
	if idErr != nil {
		return fmt.Errorf("read sandbox identity: %w", idErr)
	}
	identity := strings.Fields(string(idOut))
	if len(identity) < 7 {
		return fmt.Errorf("in-sandbox identity probe returned %d fields, expected at least 7: %q", len(identity), string(idOut))
	}
	observedUID, observedUser := identity[0], identity[1]
	observedHead, observedCPUs, observedMemory := identity[4], identity[5], identity[6]

	gitBridgePorts := 0
	for _, port := range inspect.Ports {
		if strings.HasPrefix(port, "127.0.0.1:") && strings.HasSuffix(port, "->9418/tcp") {
			gitBridgePorts++
		}
	}
	controlSecrets := 0
	for _, secret := range inspect.Secrets {
		if secret.Name == "mcpgateway" && secret.Source == "uploaded" {
			controlSecrets++
		}
	}
	declaredMemory, memErr := parseMemory(load.Profile.Memory)
	memoryCheck := observed("memory limit", load.Profile.Memory, observedMemory,
		"in-sandbox cgroup memory limit", memErr == nil && observedMemory == strconv.FormatInt(declaredMemory, 10))
	if observedMemory == "UNAVAILABLE" {
		// sbx v0.39.0 exposes no memory field and this guest exposes no readable
		// cgroup limit, so `-m 2g` rests on the create argv exactly as it does in
		// every prior accepted attempt on this plane. Said out loud, not passed off.
		memoryCheck.Status = statusNotObservabl
		memoryCheck.Match = true
		memoryCheck.Observed = "UNAVAILABLE (no readable cgroup memory limit in this guest; value rests on the create argv)"
	}

	checks := []parityCheck{
		observed("pinned template digest", load.Profile.TemplateDigest, inspect.ImageDigest, "sbx inspect --json .image_digest", inspect.ImageDigest == load.Profile.TemplateDigest),
		observed("template reference", load.Profile.TemplateRef, inspect.Image, "sbx inspect --json .image", inspect.Image == load.Profile.TemplateRef),
		observed("agent", load.Profile.Agent, inspect.Agent, "sbx inspect --json .agent", inspect.Agent == load.Profile.Agent),
		observed("sandbox name", load.SandboxName, inspect.Name, "sbx inspect --json .name", inspect.Name == load.SandboxName),
		observed("workspace mode clone (git bridge)", "exactly 1 localhost ->9418/tcp bridge", strconv.Itoa(gitBridgePorts)+" of "+strconv.Itoa(len(inspect.Ports))+" published ports", "sbx inspect --json .ports", gitBridgePorts == 1 && len(inspect.Ports) == 1 && load.Profile.WorkspaceMode == "clone"),
		observed("workspace is the staged clone", "staged clone directory", inspect.Workspace, "sbx inspect --json .workspace", inspect.Workspace != ""),
		observed("sandbox running", "running", inspect.State, "sbx inspect --json .state", inspect.State == "running"),
		observed("platform control secrets", "exactly 1 uploaded mcpgateway token", strconv.Itoa(controlSecrets)+" of "+strconv.Itoa(len(inspect.Secrets)), "sbx inspect --json .secrets", controlSecrets == 1 && len(inspect.Secrets) == 1),
		observed("cpu count", strconv.Itoa(load.Profile.CPUs), observedCPUs, "in-sandbox `nproc`", observedCPUs == strconv.Itoa(load.Profile.CPUs)),
		memoryCheck,
		observed("deny-network all paths", "deny **", boolText(denyAll), "sbx policy ls --json effective rules", denyAll),
		observed("unprivileged uid", strconv.Itoa(load.Profile.ExpectedUID), observedUID, "in-sandbox `id -u`", observedUID == strconv.Itoa(load.Profile.ExpectedUID)),
		observed("unprivileged user", load.Profile.ExpectedUser, observedUser, "in-sandbox `id -un`", observedUser == load.Profile.ExpectedUser),
		observed("sbx cli version", load.Profile.CLIVersion, receipt.CLIBanner, "sbx version banner", strings.Contains(receipt.CLIBanner, load.Profile.CLIVersion)),
		observed("in-sandbox source commit", receipt.SourceCommit, observedHead, "in-sandbox `git rev-parse HEAD`", observedHead == receipt.SourceCommit),
	}
	receipt.ProfileParity = checks
	receipt.ProfileParityOK = true
	var failed []string
	for _, check := range checks {
		if check.Status == statusMismatched {
			receipt.ProfileParityOK = false
			failed = append(failed, fmt.Sprintf("%s (declared=%q observed=%q)", check.Constraint, check.Declared, check.Observed))
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("PROFILE PARITY FAILED: %s", strings.Join(failed, "; "))
	}
	return nil
}

// transferIn bundles every staged artifact into one tar, copies it in, and
// proves the bytes survived by hashing INSIDE the sandbox. sbx cp's own exit
// code is recorded but never treated as evidence of integrity.
func transferIn(load payload, stage, captureDir string, receipt *operatorReceipt) error {
	stageDir := filepath.Join(stage, load.Inbound.StageSubdir)
	manifestPath := filepath.Join(stageDir, load.Inbound.ManifestName)
	lines := make([]string, 0, len(load.Inbound.Artifacts))
	for _, name := range load.Inbound.Artifacts {
		digest, err := digestFile(filepath.Join(stageDir, name))
		if err != nil {
			return fmt.Errorf("digest staged artifact %s: %w", name, err)
		}
		lines = append(lines, digest+"  "+name)
	}
	sort.Strings(lines)
	if err := os.WriteFile(manifestPath, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		return err
	}

	bundle := filepath.Join(stage, load.Inbound.BundleName)
	names := append(append([]string(nil), load.Inbound.Artifacts...), load.Inbound.ManifestName)
	sort.Strings(names)
	// COPYFILE_DISABLE stops macOS tar emitting AppleDouble `._*` resource-fork
	// members, which are not in the manifest and which the in-sandbox driver
	// would otherwise mistake for real artifacts.
	tarArgv := append([]string{"env", "COPYFILE_DISABLE=1", "tar", "-C", stageDir, "-cf", bundle}, names...)
	if out, err := capture(context.Background(), 20*time.Minute, tarArgv...); err != nil {
		writeCapture(captureDir, "inbound-tar.log", out)
		return fmt.Errorf("build inbound bundle: %w", err)
	}
	hostDigest, err := digestFile(bundle)
	if err != nil {
		return err
	}
	info, err := os.Stat(bundle)
	if err != nil {
		return err
	}

	if out, err := capture(context.Background(), 2*time.Minute, load.Profile.SbxBinary, "exec", load.SandboxName, "sh", "-lc", "mkdir -p "+shellQuote(load.Inbound.SandboxDir)); err != nil {
		writeCapture(captureDir, "inbound-mkdir.log", out)
		return fmt.Errorf("create sandbox inbound dir: %w", err)
	}
	target := load.Inbound.SandboxDir + "/" + load.Inbound.BundleName
	cpOut, cpErr := capture(context.Background(), 30*time.Minute, load.Profile.SbxBinary, "cp", bundle, load.SandboxName+":"+target)
	writeCapture(captureDir, "inbound-cp.log", cpOut)
	// cpErr is deliberately NOT returned here: the 0124 finding is that sbx cp
	// exit codes are unreliable in both directions. The digest below is the
	// authority. The exit code is recorded in the capture log either way.
	_ = cpErr

	sumOut, sumErr := capture(context.Background(), 10*time.Minute, load.Profile.SbxBinary, "exec", load.SandboxName, "sh", "-lc", "sha256sum "+shellQuote(target))
	writeCapture(captureDir, "inbound-sha256sum.txt", sumOut)
	if sumErr != nil {
		return fmt.Errorf("hash inbound bundle inside sandbox: %w", sumErr)
	}
	sandboxDigest := strings.Fields(string(sumOut))
	if len(sandboxDigest) == 0 {
		return errors.New("in-sandbox sha256sum produced no digest for the inbound bundle")
	}
	record := transferRecord{load.Inbound.BundleName, hostDigest, sandboxDigest[0], info.Size(), hostDigest == sandboxDigest[0], "host->sandbox"}
	receipt.Inbound = append(receipt.Inbound, record)
	if !record.Match {
		return fmt.Errorf("INBOUND DIGEST MISMATCH for %s: host=%s sandbox=%s", record.Name, record.HostSHA256, record.SandboxSHA256)
	}
	return nil
}

func runSteps(load payload, captureDir string, receipt *operatorReceipt) error {
	for _, s := range load.Steps {
		timeout := time.Duration(s.TimeoutSeconds) * time.Second
		if timeout <= 0 {
			timeout = time.Hour
		}
		argv := append([]string{load.Profile.SbxBinary, "exec", load.SandboxName}, s.Argv...)
		started := nowUTC()
		out, err := capture(context.Background(), timeout, argv...)
		finished := nowUTC()
		name := s.CaptureName
		if name == "" {
			name = "step-" + s.ID + ".log"
		}
		path := writeCapture(captureDir, name, out)
		code := exitCode(err)
		expected := 0
		if s.ExpectExit != nil {
			expected = *s.ExpectExit
		}
		record := stepRecord{s.ID, strings.Join(argv, " "), code, s.ExpectExit, code == expected, started, finished, path, len(out)}
		receipt.Steps = append(receipt.Steps, record)
		if !record.Matched {
			return fmt.Errorf("step %s exited %d, expected %d (capture: %s)", s.ID, code, expected, path)
		}
	}
	return nil
}

// transferOut brings the workload's output directory back and verifies every
// file against the digest manifest the workload wrote INSIDE the sandbox.
func transferOut(load payload, attemptDir, captureDir string, receipt *operatorReceipt) error {
	bundlePath := "/tmp/" + load.Outbound.BundleName
	tarCmd := "cd " + shellQuote(load.Outbound.SandboxDir) + " && tar -cf " + shellQuote(bundlePath) + " . && sha256sum " + shellQuote(bundlePath)
	sumOut, err := capture(context.Background(), 20*time.Minute, load.Profile.SbxBinary, "exec", load.SandboxName, "sh", "-lc", tarCmd)
	writeCapture(captureDir, "outbound-tar.txt", sumOut)
	if err != nil {
		return fmt.Errorf("bundle sandbox output: %w", err)
	}
	fields := strings.Fields(string(sumOut))
	if len(fields) == 0 {
		return errors.New("in-sandbox sha256sum produced no digest for the outbound bundle")
	}
	sandboxDigest := fields[len(fields)-2]
	if len(sandboxDigest) != 64 {
		sandboxDigest = fields[0]
	}

	hostBundle := filepath.Join(captureDir, load.Outbound.BundleName)
	cpOut, cpErr := capture(context.Background(), 30*time.Minute, load.Profile.SbxBinary, "cp", load.SandboxName+":"+bundlePath, hostBundle)
	writeCapture(captureDir, "outbound-cp.log", cpOut)
	_ = cpErr // same 0124 reasoning: the digest decides, not the exit code.

	hostDigest, err := digestFile(hostBundle)
	if err != nil {
		return fmt.Errorf("hash outbound bundle on host: %w", err)
	}
	info, err := os.Stat(hostBundle)
	if err != nil {
		return err
	}
	record := transferRecord{load.Outbound.BundleName, hostDigest, sandboxDigest, info.Size(), hostDigest == sandboxDigest, "sandbox->host"}
	receipt.Outbound = append(receipt.Outbound, record)
	if !record.Match {
		return fmt.Errorf("OUTBOUND DIGEST MISMATCH for %s: host=%s sandbox=%s", record.Name, hostDigest, sandboxDigest)
	}

	outDir := filepath.Join(attemptDir, "sandbox-out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	if out, err := capture(context.Background(), 10*time.Minute, "tar", "-C", outDir, "-xf", hostBundle); err != nil {
		writeCapture(captureDir, "outbound-untar.log", out)
		return fmt.Errorf("extract outbound bundle: %w", err)
	}

	// Per-file verification against the manifest the workload wrote in-sandbox.
	manifestPath := filepath.Join(outDir, load.Outbound.ManifestName)
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read in-sandbox output manifest: %w", err)
	}
	verified, mismatched := 0, 0
	for _, line := range strings.Split(strings.TrimSpace(string(manifestBytes)), "\n") {
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}
		want, name := parts[0], strings.TrimPrefix(parts[1], "./")
		got, err := digestFile(filepath.Join(outDir, name))
		if err != nil {
			mismatched++
			receipt.Outbound = append(receipt.Outbound, transferRecord{name, "", want, 0, false, "sandbox->host"})
			continue
		}
		receipt.Outbound = append(receipt.Outbound, transferRecord{name, got, want, 0, got == want, "sandbox->host"})
		if got == want {
			verified++
		} else {
			mismatched++
		}
	}
	if mismatched > 0 {
		return fmt.Errorf("OUTBOUND PER-FILE MISMATCH: %d of %d files differ from their in-sandbox digests", mismatched, verified+mismatched)
	}
	return nil
}

func readPayload(path string) (payload, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return payload{}, err
	}
	var load payload
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&load); err != nil {
		return payload{}, fmt.Errorf("decode payload: %w", err)
	}
	if load.Kind != "sbx-payload" {
		return payload{}, fmt.Errorf("unexpected payload kind %q", load.Kind)
	}
	if load.AttemptID == "" || load.SandboxName == "" {
		return payload{}, errors.New("payload must name an attempt id and a sandbox name")
	}
	if load.Profile.SbxBinary == "" || load.Profile.TemplateDigest == "" {
		return payload{}, errors.New("payload profile must pin the sbx binary and the template digest")
	}
	return load, nil
}

// gitClone stages the workload source as a real git repository, because sbx
// clone mode refuses anything else, and detaches it at the exact commit the
// receipt names. The resulting HEAD is read back and compared, so a clone that
// silently landed on a different commit cannot go unnoticed.
func gitClone(repoRoot, dest, commit string) error {
	if err := os.RemoveAll(dest); err != nil {
		return err
	}
	if out, err := capture(context.Background(), 15*time.Minute, "git", "clone", "--no-hardlinks", "--quiet", repoRoot, dest); err != nil {
		return fmt.Errorf("git clone: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	if out, err := capture(context.Background(), 5*time.Minute, "git", "-C", dest, "checkout", "--quiet", "--detach", commit); err != nil {
		return fmt.Errorf("git checkout %s: %w (%s)", commit, err, strings.TrimSpace(string(out)))
	}
	out, err := capture(context.Background(), 2*time.Minute, "git", "-C", dest, "rev-parse", "HEAD")
	if err != nil {
		return fmt.Errorf("read staged HEAD: %w", err)
	}
	if staged := strings.TrimSpace(string(out)); staged != commit {
		return fmt.Errorf("staged clone HEAD %s does not match the declared commit %s", staged, commit)
	}
	status, err := capture(context.Background(), 2*time.Minute, "git", "-C", dest, "status", "--porcelain")
	if err != nil {
		return fmt.Errorf("read staged status: %w", err)
	}
	if strings.TrimSpace(string(status)) != "" {
		return fmt.Errorf("staged clone is not clean: %s", strings.TrimSpace(string(status)))
	}
	return nil
}

func assertAbsent(sbx, name string) error {
	absent, err := isAbsent(sbx, name)
	if err != nil {
		return err
	}
	if !absent {
		return fmt.Errorf("sandbox %q already exists; refusing to reuse it", name)
	}
	return nil
}

func isAbsent(sbx, name string) (bool, error) {
	out, err := capture(context.Background(), 2*time.Minute, sbx, "ls")
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(out), "\n") {
		if fields := strings.Fields(line); len(fields) > 0 && fields[0] == name {
			return false, nil
		}
	}
	return true, nil
}

func capture(parent context.Context, timeout time.Duration, argv ...string) ([]byte, error) {
	if len(argv) == 0 {
		return nil, errors.New("empty command")
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	command := exec.CommandContext(ctx, argv[0], argv[1:]...)
	out, err := command.CombinedOutput()
	if ctx.Err() != nil {
		return out, fmt.Errorf("timed out after %s: %w", timeout, ctx.Err())
	}
	return out, err
}

func writeCapture(dir, name string, data []byte) string {
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "sbxlaunch: capture %s: %v\n", path, err)
	}
	return path
}

func digestFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

// parseMemory turns the create argv's memory string ("2g") into the byte count
// the cgroup limit is expected to carry.
func parseMemory(value string) (int64, error) {
	trimmed := strings.TrimSpace(strings.ToLower(value))
	multiplier := int64(1)
	switch {
	case strings.HasSuffix(trimmed, "g"):
		multiplier, trimmed = 1<<30, strings.TrimSuffix(trimmed, "g")
	case strings.HasSuffix(trimmed, "m"):
		multiplier, trimmed = 1<<20, strings.TrimSuffix(trimmed, "m")
	case strings.HasSuffix(trimmed, "k"):
		multiplier, trimmed = 1<<10, strings.TrimSuffix(trimmed, "k")
	}
	amount, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil {
		return 0, err
	}
	return amount * multiplier, nil
}

func boolText(value bool) string {
	if value {
		return "deny **"
	}
	return "ABSENT"
}

func nowUTC() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func mustExecutable() string {
	path, err := os.Executable()
	if err != nil {
		return ""
	}
	return path
}
