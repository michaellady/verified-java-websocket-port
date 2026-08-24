package assurance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	vendorprotocol "github.com/michaellady/verified-java-to-rust/foundation/protocol"
)

func TestUS004Adversarial_UpstreamManifestBoundaries(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		mutate      func(t *testing.T, root string)
		expected    string
		disposition vendorprotocol.Disposition
	}{
		{
			name: "upstream roots pin",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				manifest := readUpstreamManifest(t, root)
				manifest.AcceptedSnapshotRoot = "sha256:deadbeef"
				writeJSONFile(t, filepath.Join(root, upstreamManifestPath), manifest)
			},
			expected:    "UPSTREAM_ROOT_MISMATCH",
			disposition: vendorprotocol.Block,
		},
		{
			name: "missing vendored file",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				target := filepath.Join(root, "third_party", "verified-java-to-rust-foundation", "protocol", "canonical.go")
				if err := os.Remove(target); err != nil {
					t.Fatalf("remove vendored file: %v", err)
				}
			},
			expected:    "MISSING_VENDORED_FILE",
			disposition: vendorprotocol.Block,
		},
		{
			name: "extra vendored file",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				target := filepath.Join(root, "assurance", "schema", "unexpected.schema.json")
				if err := os.WriteFile(target, []byte(`{"schema_version":"1.0.0"}`), 0o600); err != nil {
					t.Fatalf("write unexpected vendored file: %v", err)
				}
			},
			expected:    "UNEXPECTED_VENDORED_FILE",
			disposition: vendorprotocol.Block,
		},
		{
			name: "digest drift",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				target := filepath.Join(root, "assurance", "schema", "developer-tool-run.schema.json")
				if err := os.WriteFile(target, []byte(`{"drifted":true}`), 0o600); err != nil {
					t.Fatalf("drift schema bytes: %v", err)
				}
			},
			expected:    "VENDORED_FILE_DIGEST_MISMATCH",
			disposition: vendorprotocol.Block,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			root := copiedAssuranceRoot(t)
			testCase.mutate(t, root)

			verdict, err := Verify(context.Background(), Request{
				RootPath:      root,
				LifecyclePath: lifecyclePathDefault,
				Mode:          ModeVerify,
			})
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			assertFinding(t, verdict.Findings, testCase.expected, testCase.disposition)
		})
	}
}

func TestUS004Adversarial_StrictLifecycleJSON(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		contents       string
		errorSubstring string
	}{
		{
			name:           "duplicate keys",
			contents:       `{"schema_version":"1.0.0","schema_version":"1.0.0"}`,
			errorSubstring: `duplicate JSON object key "schema_version"`,
		},
		{
			name:           "unknown field",
			contents:       `{"schema_version":"1.0.0","company":"open-source-projects","project":"verified-java-websocket-port","verified_at":"2026-08-23T23:56:35Z","snapshot":{"id":"snapshot-us004","candidate_digest":"sha256:93417adcf9047fc4cf97f6df95c4a6248f39f922e273c279dfde241d08f890f4","previous_state":"PROPOSED","state":"BLOCKED","stale":false},"root_node_id":"claim-us004","nodes":[],"edges":[],"stages":[],"attempts":[],"failures":[],"authorization":{"actor_id":"github:michaellady","role":"release-attestor","snapshot_roles":["release-attestor"],"snapshot_digest":"sha256:93417adcf9047fc4cf97f6df95c4a6248f39f922e273c279dfde241d08f890f4","policy_version":"foundation-1.0.0+java-websocket-single-owner-1.0.0","nonce":"nonce","prior_nonces":[],"issued_at":"2026-08-23T23:56:35Z","expires_at":"2026-08-23T23:57:35Z","signature_verified":true,"revoked":false},"attestations":[],"publication":{"requested":false,"complete":false,"classification":"PUBLIC","object_digests":[],"replay_command":""},"unexpected":true}`,
			errorSubstring: `unknown field "unexpected"`,
		},
		{
			name:           "trailing values",
			contents:       string(mustReadRepoFile(t, "assurance/lifecycle.json")) + "\n{}",
			errorSubstring: "multiple JSON values",
		},
		{
			name:           "null lifecycle field",
			contents:       `{"schema_version":"1.0.0","company":"open-source-projects","project":"verified-java-websocket-port","verified_at":"2026-08-23T23:56:35Z","snapshot":{"id":"snapshot-us004","candidate_digest":"sha256:93417adcf9047fc4cf97f6df95c4a6248f39f922e273c279dfde241d08f890f4","previous_state":"PROPOSED","state":"BLOCKED","stale":false},"root_node_id":"claim-us004","nodes":[],"edges":[],"stages":[],"attempts":[],"failures":[],"authorization":{"actor_id":"github:michaellady","role":"release-attestor","snapshot_roles":["release-attestor"],"snapshot_digest":"sha256:93417adcf9047fc4cf97f6df95c4a6248f39f922e273c279dfde241d08f890f4","policy_version":"foundation-1.0.0+java-websocket-single-owner-1.0.0","nonce":"nonce","prior_nonces":[],"issued_at":"2026-08-23T23:56:35Z","expires_at":"2026-08-23T23:57:35Z","signature_verified":true,"revoked":false},"attestations":[],"publication":{"requested":null,"complete":false,"classification":"PUBLIC","object_digests":[],"replay_command":""}}`,
			errorSubstring: "cannot unmarshal",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			root := copiedAssuranceRoot(t)
			writeRawFile(t, filepath.Join(root, lifecyclePathDefault), []byte(testCase.contents))

			_, err := Verify(context.Background(), Request{
				RootPath:      root,
				LifecyclePath: lifecyclePathDefault,
				Mode:          ModeVerify,
			})
			if err == nil || !strings.Contains(err.Error(), testCase.errorSubstring) {
				t.Fatalf("error = %v, want substring %q", err, testCase.errorSubstring)
			}
		})
	}
}

func TestUS004Adversarial_ProtocolBoundaryFindings(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		lifecyclePath string
		mutate        func(t *testing.T, root string)
		expected      string
		disposition   vendorprotocol.Disposition
	}{
		{
			name:          "cycle",
			lifecyclePath: "assurance/replay/fixtures/cycle/lifecycle.json",
			expected:      "CYCLIC_GRAPH",
			disposition:   vendorprotocol.Block,
		},
		{
			name: "dangling edge",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				bundle := readLifecycleBundle(t, root, lifecyclePathDefault)
				bundle.Edges[0].To = "missing-node"
				writeJSONFile(t, filepath.Join(root, lifecyclePathDefault), bundle)
			},
			expected:    "DANGLING_EDGE",
			disposition: vendorprotocol.Block,
		},
		{
			name: "disconnected evidence",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				bundle := readLifecycleBundle(t, root, lifecyclePathDefault)
				bundle.Edges = bundle.Edges[1:]
				writeJSONFile(t, filepath.Join(root, lifecyclePathDefault), bundle)
			},
			expected:    "DISCONNECTED_EVIDENCE",
			disposition: vendorprotocol.Block,
		},
		{
			name:          "cross company",
			lifecyclePath: "assurance/replay/fixtures/cross-company/lifecycle.json",
			expected:      "CROSS_COMPANY_REFERENCE",
			disposition:   vendorprotocol.Quarantine,
		},
		{
			name:          "stale",
			lifecyclePath: "assurance/replay/fixtures/stale/lifecycle.json",
			expected:      "STALE_INPUT",
			disposition:   vendorprotocol.Invalidate,
		},
		{
			name:          "role conflict",
			lifecyclePath: "assurance/replay/fixtures/role-conflict/lifecycle.json",
			expected:      "ROLE_CONFLICT",
			disposition:   vendorprotocol.Quarantine,
		},
		{
			name: "dag projection mismatch",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				writeRawFile(t, filepath.Join(root, evidenceDAGPath), []byte(`{"schema_version":"1.0.0","root_node_id":"claim-us004","nodes":[],"edges":[]}`))
			},
			expected:    "ROOT_BINDING_MISMATCH",
			disposition: vendorprotocol.Block,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			root := copiedAssuranceRoot(t)
			lifecyclePath := lifecyclePathDefault
			if testCase.lifecyclePath != "" {
				lifecyclePath = testCase.lifecyclePath
			}
			if testCase.mutate != nil {
				testCase.mutate(t, root)
			}

			verdict, err := Replay(context.Background(), Request{
				RootPath:      root,
				LifecyclePath: lifecyclePath,
				Mode:          ModeReplay,
			})
			if err != nil {
				t.Fatalf("replay: %v", err)
			}
			assertFinding(t, verdict.Findings, testCase.expected, testCase.disposition)
		})
	}
}

func TestUS004Adversarial_RootConfinement(t *testing.T) {
	t.Parallel()

	root := copiedAssuranceRoot(t)

	testCases := []struct {
		name           string
		lifecyclePath  string
		mutate         func(t *testing.T, root string) string
		errorSubstring string
	}{
		{name: "absolute path", lifecyclePath: "/tmp/lifecycle.json", errorSubstring: "path must be slash-relative"},
		{name: "parent path", lifecyclePath: "../assurance/lifecycle.json", errorSubstring: "path escapes root"},
		{name: "backslash path", lifecyclePath: `assurance\\lifecycle.json`, errorSubstring: "path must be slash-relative"},
		{name: "redundant slash path", lifecyclePath: "assurance//lifecycle.json", errorSubstring: "path must be canonical"},
		{
			name: "symlink lifecycle",
			mutate: func(t *testing.T, root string) string {
				t.Helper()
				target := filepath.Join(root, "assurance", "linked-lifecycle.json")
				if err := os.Symlink(filepath.Join(root, "assurance", "lifecycle.json"), target); err != nil {
					t.Fatalf("symlink lifecycle: %v", err)
				}
				return "assurance/linked-lifecycle.json"
			},
			errorSubstring: "not a regular file",
		},
		{
			name: "hardlink lifecycle",
			mutate: func(t *testing.T, root string) string {
				t.Helper()
				target := filepath.Join(root, "assurance", "hardlinked-lifecycle.json")
				if err := os.Link(filepath.Join(root, "assurance", "lifecycle.json"), target); err != nil {
					t.Fatalf("hardlink lifecycle: %v", err)
				}
				return "assurance/hardlinked-lifecycle.json"
			},
			errorSubstring: "not an immutable single-link file",
		},
		{
			name: "directory lifecycle",
			mutate: func(t *testing.T, root string) string {
				t.Helper()
				target := filepath.Join(root, "assurance", "directory-lifecycle")
				if err := os.MkdirAll(target, 0o755); err != nil {
					t.Fatalf("mkdir lifecycle directory: %v", err)
				}
				return "assurance/directory-lifecycle"
			},
			errorSubstring: "not a regular file",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			lifecyclePath := testCase.lifecyclePath
			if testCase.mutate != nil {
				lifecyclePath = testCase.mutate(t, root)
			}
			_, err := Verify(context.Background(), Request{
				RootPath:      root,
				LifecyclePath: lifecyclePath,
				Mode:          ModeVerify,
			})
			if err == nil || !strings.Contains(err.Error(), testCase.errorSubstring) {
				t.Fatalf("error = %v, want substring %q", err, testCase.errorSubstring)
			}
		})
	}
}

func TestUS004Adversarial_DeveloperToolRuns(t *testing.T) {
	t.Parallel()

	t.Run("canonical pinned versions", func(t *testing.T) {
		verdict, err := Verify(context.Background(), Request{
			RootPath:      repoRoot(t),
			LifecyclePath: lifecyclePathDefault,
			Mode:          ModeVerify,
		})
		if err != nil {
			t.Fatalf("verify canonical lifecycle: %v", err)
		}
		assertNoFindingCode(t, verdict.Findings, "MISSING_DEVELOPER_TOOL_RUN")
		assertNoFindingCode(t, verdict.Findings, "INVALID_DEVELOPER_TOOL_RUN")
		assertNoFindingCode(t, verdict.Findings, "LSP_ASSURANCE_BOUNDARY")
	})

	testCases := []struct {
		name        string
		mutate      func(t *testing.T, root string)
		expected    string
		disposition vendorprotocol.Disposition
	}{
		{
			name: "missing run",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				if err := os.Remove(filepath.Join(root, rustAnalyzerPath)); err != nil {
					t.Fatalf("remove rust-analyzer run: %v", err)
				}
			},
			expected:    "MISSING_DEVELOPER_TOOL_RUN",
			disposition: vendorprotocol.Block,
		},
		{
			name: "wrong version",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				run := readToolRun(t, root, jdtLSPath)
				tool := run["tool"].(map[string]any)
				tool["version"] = "9.9.9"
				writeJSONFile(t, filepath.Join(root, jdtLSPath), run)
			},
			expected:    "INVALID_DEVELOPER_TOOL_RUN",
			disposition: vendorprotocol.Block,
		},
		{
			name: "nonempty assurance claims",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				run := readToolRun(t, root, rustAnalyzerPath)
				run["assurance_claims"] = []map[string]any{{"claim": "independent"}}
				writeJSONFile(t, filepath.Join(root, rustAnalyzerPath), run)
			},
			expected:    "LSP_ASSURANCE_BOUNDARY",
			disposition: vendorprotocol.Block,
		},
		{
			name: "nonempty gate effects",
			mutate: func(t *testing.T, root string) {
				t.Helper()
				run := readToolRun(t, root, glancerPath)
				run["gate_effects"] = []map[string]any{{"gate": "publish"}}
				writeJSONFile(t, filepath.Join(root, glancerPath), run)
			},
			expected:    "LSP_ASSURANCE_BOUNDARY",
			disposition: vendorprotocol.Block,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			root := copiedAssuranceRoot(t)
			testCase.mutate(t, root)

			verdict, err := Verify(context.Background(), Request{
				RootPath:      root,
				LifecyclePath: lifecyclePathDefault,
				Mode:          ModeVerify,
			})
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			assertFinding(t, verdict.Findings, testCase.expected, testCase.disposition)
		})
	}
}

func TestUS004Adversarial_PublicContractLeakage(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		value string
	}{
		{name: "protected token", value: "protected_case canary"},
		{name: "raw diagnostic token", value: "raw_diagnostic canary"},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			root := copiedAssuranceRoot(t)
			contract := readPublicContract(t, root)
			contract.WhyBlocked = testCase.value
			writeJSONFile(t, filepath.Join(root, publicContractPath), contract)

			verdict, err := Verify(context.Background(), Request{
				RootPath:      root,
				LifecyclePath: lifecyclePathDefault,
				Mode:          ModeVerify,
			})
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			assertFinding(t, verdict.Findings, "PROTECTED_PUBLICATION_DISCLOSURE", vendorprotocol.Revoke)
		})
	}
}

func TestUS004Adversarial_CanonicalVerifyReplayAgreement(t *testing.T) {
	t.Parallel()

	verifyVerdict, err := Verify(context.Background(), Request{
		RootPath:      repoRoot(t),
		LifecyclePath: lifecyclePathDefault,
		Mode:          ModeVerify,
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	replayVerdict, err := Replay(context.Background(), Request{
		RootPath:      repoRoot(t),
		LifecyclePath: lifecyclePathDefault,
		Mode:          ModeReplay,
	})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}

	if verifyVerdict.State != "BLOCKED" || replayVerdict.State != "BLOCKED" {
		t.Fatalf("states = %q / %q, want BLOCKED", verifyVerdict.State, replayVerdict.State)
	}
	if verifyVerdict.Assurance != assuranceCeiling || replayVerdict.Assurance != assuranceCeiling {
		t.Fatalf("assurance = %q / %q, want %q", verifyVerdict.Assurance, replayVerdict.Assurance, assuranceCeiling)
	}
	if verifyVerdict.IndependentReviewClaimed || replayVerdict.IndependentReviewClaimed {
		t.Fatalf("independent review claimed = %v / %v, want false", verifyVerdict.IndependentReviewClaimed, replayVerdict.IndependentReviewClaimed)
	}
	if verifyVerdict.SnapshotRoot != replayVerdict.SnapshotRoot || verifyVerdict.PublicEvidenceRoot != replayVerdict.PublicEvidenceRoot {
		t.Fatalf("roots differ: verify=%+v replay=%+v", verifyVerdict, replayVerdict)
	}
	left, err := vendorprotocol.CanonicalJSON(struct {
		SnapshotRoot       string                   `json:"snapshot_root"`
		PublicEvidenceRoot string                   `json:"public_evidence_root"`
		Findings           []vendorprotocol.Finding `json:"findings"`
	}{SnapshotRoot: verifyVerdict.SnapshotRoot, PublicEvidenceRoot: verifyVerdict.PublicEvidenceRoot, Findings: verifyVerdict.Findings})
	if err != nil {
		t.Fatalf("canonical verify verdict: %v", err)
	}
	right, err := vendorprotocol.CanonicalJSON(struct {
		SnapshotRoot       string                   `json:"snapshot_root"`
		PublicEvidenceRoot string                   `json:"public_evidence_root"`
		Findings           []vendorprotocol.Finding `json:"findings"`
	}{SnapshotRoot: replayVerdict.SnapshotRoot, PublicEvidenceRoot: replayVerdict.PublicEvidenceRoot, Findings: replayVerdict.Findings})
	if err != nil {
		t.Fatalf("canonical replay verdict: %v", err)
	}
	if !bytes.Equal(left, right) {
		t.Fatalf("verify/replay findings differ:\nverify=%s\nreplay=%s", left, right)
	}

	command := exec.Command(assurectlBinaryForUS004(t), "replay", "--root", repoRoot(t), "--lifecycle", "assurance/replay/fixtures/cycle/lifecycle.json")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("assurectl replay succeeded unexpectedly: %s", output)
	}
	var payload map[string]any
	if decodeErr := json.Unmarshal(output, &payload); decodeErr != nil {
		t.Fatalf("assurectl replay emitted invalid JSON: %v\n%s", decodeErr, output)
	}
}

func readLifecycleBundle(t *testing.T, root, relativePath string) vendorprotocol.Bundle {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relativePath)))
	if err != nil {
		t.Fatalf("read lifecycle: %v", err)
	}
	var bundle vendorprotocol.Bundle
	if err := vendorprotocol.DecodeStrict(data, &bundle); err != nil {
		t.Fatalf("decode lifecycle: %v", err)
	}
	return bundle
}

func readUpstreamManifest(t *testing.T, root string) upstreamManifest {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(upstreamManifestPath)))
	if err != nil {
		t.Fatalf("read upstream manifest: %v", err)
	}
	var manifest upstreamManifest
	if err := vendorprotocol.DecodeStrict(data, &manifest); err != nil {
		t.Fatalf("decode upstream manifest: %v", err)
	}
	return manifest
}

func readToolRun(t *testing.T, root, relativePath string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relativePath)))
	if err != nil {
		t.Fatalf("read tool run: %v", err)
	}
	var run map[string]any
	if err := vendorprotocol.DecodeStrict(data, &run); err != nil {
		t.Fatalf("decode tool run: %v", err)
	}
	return run
}

func readPublicContract(t *testing.T, root string) publicContract {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(publicContractPath)))
	if err != nil {
		t.Fatalf("read public contract: %v", err)
	}
	var contract publicContract
	if err := vendorprotocol.DecodeStrict(data, &contract); err != nil {
		t.Fatalf("decode public contract: %v", err)
	}
	return contract
}

func writeJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal %s: %v", path, err)
	}
	writeRawFile(t, path, data)
}

func writeRawFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func assertNoFindingCode(t *testing.T, findings []vendorprotocol.Finding, code string) {
	t.Helper()
	for _, finding := range findings {
		if finding.Code == code {
			t.Fatalf("unexpected finding %s in %+v", code, findings)
		}
	}
}

func mustReadRepoFile(t *testing.T, relativePath string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(relativePath)))
	if err != nil {
		t.Fatalf("read repo file %s: %v", relativePath, err)
	}
	return data
}

func assurectlBinaryForUS004(t *testing.T) string {
	t.Helper()
	repo := repoRoot(t)
	binary := filepath.Join(t.TempDir(), "assurectl")
	command := exec.Command("go", "build", "-o", binary, "./cmd/assurectl")
	command.Dir = repo
	command.Env = append(os.Environ(), "GOCACHE=/private/tmp/us004-adapter-acceptance-cache")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build assurectl: %v\n%s", err, output)
	}
	return binary
}

func TestUS004Adversarial_SmokeHelpersCompile(t *testing.T) {
	t.Skip("package-level helper anchor")
	_ = errors.Is
}
