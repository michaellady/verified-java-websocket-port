package assurance_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/assurance"
)

const (
	acceptanceTargetCommit   = "1ff89fa30cb0ab6ff339afd3ce486a36e9f7f325"
	acceptanceTargetTree     = "dfb1950301e9680b1c47f0bd9debc0fc026d0e4f"
	acceptanceCandidateRoot  = "sha256:84740e62f7f2905dab355672511e34daa83aa5381e1f6fb5e71156cc1d39c7ab"
	acceptanceEvaluationRoot = "sha256:149b654853ea5475159be44bede437c1ea9876100cb8ad600a6d846ec70db62e"
	acceptanceHistoricalDAG  = "sha256:7dfaad953d9356369a9f4ee471163f8002b0b8e0c170f935af96778e830505bf"
)

func TestUS023AcceptanceExactFrozenBlockedVerifyReplay(t *testing.T) {
	repo := acceptanceRepoRoot(t)
	binary := buildAcceptanceCLI(t, repo)
	outputs := make([][]byte, 0, 2)
	for _, mode := range []string{"candidate-verify", "candidate-replay"} {
		output, exit := runAcceptanceCLI(t, binary, mode, repo, 90*time.Second)
		if exit != 0 {
			t.Fatalf("%s exit = %d, want 0\n%s", mode, exit, output)
		}
		var verdict assurance.CandidateVerdict
		if err := json.Unmarshal(output, &verdict); err != nil {
			t.Fatalf("%s output is not a candidate verdict: %v\n%s", mode, err, output)
		}
		if verdict.SnapshotState != "FROZEN" || verdict.ParityState != "BLOCKED" ||
			verdict.CandidateRoot != acceptanceCandidateRoot || verdict.EvaluationRoot != acceptanceEvaluationRoot ||
			verdict.TargetCommit != acceptanceTargetCommit || verdict.TargetTree != acceptanceTargetTree ||
			verdict.Assurance != "OWNER_ATTESTED_NOT_INDEPENDENT" || verdict.IndependentReviewClaimed ||
			verdict.GateCounts != (assurance.GateCounts{Required: 44, Satisfied: 0, Blocked: 44}) ||
			len(verdict.Findings) != 0 {
			t.Fatalf("%s accepted the wrong snapshot: %#v", mode, verdict)
		}
		if len(verdict.Blockers) == 0 {
			t.Fatalf("%s hid the honest parity blockers", mode)
		}
		outputs = append(outputs, output)
	}
	if !bytes.Equal(outputs[0], outputs[1]) {
		t.Fatalf("VERIFY and REPLAY are not byte-identical:\nVERIFY %s\nREPLAY %s", outputs[0], outputs[1])
	}

	working := readAcceptanceFile(t, filepath.Join(repo, "assurance/evidence-dag.json"))
	committed := gitAcceptanceOutput(t, repo, "show", acceptanceTargetCommit+":assurance/evidence-dag.json")
	if !bytes.Equal(working, committed) || digestAcceptance(working) != acceptanceHistoricalDAG {
		t.Fatalf("historical assurance/evidence-dag.json drifted: working=%s committed=%s", digestAcceptance(working), digestAcceptance(committed))
	}
	manifest := readAcceptanceJSON(t, filepath.Join(repo, "assurance/candidate-manifest.json"))
	node := findAcceptanceNode(t, manifest, "assurance/evidence-dag.json")
	gitIdentity := objectAcceptance(t, node, "git")
	if node["kind"] != "HISTORICAL_DAG" || node["sha256"] != acceptanceHistoricalDAG ||
		gitIdentity["commit"] != acceptanceTargetCommit || gitIdentity["tree"] != acceptanceTargetTree ||
		gitIdentity["blob"] != "77fe33c534401cba9b1f7fc0f0326dc61e2af0d2" {
		t.Fatalf("historical DAG is not the exact bound input: %#v", node)
	}
}

func TestUS023AcceptanceHostileSemanticClassesFailTyped(t *testing.T) {
	repo := acceptanceRepoRoot(t)
	binary := buildAcceptanceCLI(t, repo)
	tests := []struct {
		name     string
		wantCode string
		mutate   func(*testing.T, string)
	}{
		{name: "candidate-envelope-byte-drift", wantCode: "ROOT_ENVELOPE_GIT_DRIFT", mutate: func(t *testing.T, root string) {
			appendAcceptanceBytes(t, filepath.Join(root, "assurance/candidate-manifest.json"), []byte(" \n"))
		}},
		{name: "evaluation-report-byte-drift", wantCode: "EVALUATION_REPORT_GIT_DRIFT", mutate: func(t *testing.T, root string) {
			appendAcceptanceBytes(t, filepath.Join(root, "evidence/parity-replay.json"), []byte(" \n"))
		}},
		{name: "human-report-byte-drift", wantCode: "PARITY_REPORT_DRIFT", mutate: func(t *testing.T, root string) {
			appendAcceptanceBytes(t, filepath.Join(root, "docs/us023-parity-coverage.md"), []byte("drift\n"))
		}},
		{name: "historical-dag-byte-drift", wantCode: "GRAPH_GIT_OR_DIGEST_DRIFT", mutate: func(t *testing.T, root string) {
			appendAcceptanceBytes(t, filepath.Join(root, "assurance/evidence-dag.json"), []byte(" \n"))
		}},
		{name: "target-tree-drift", wantCode: "TARGET_SUBJECT_DRIFT", mutate: func(t *testing.T, root string) {
			mutateAcceptanceJSON(t, root, "assurance/candidate-manifest.json", func(document map[string]any) {
				objectAcceptance(t, document, "target")["tree"] = strings.Repeat("0", 40)
			})
		}},
		{name: "git-blob-drift", wantCode: "GRAPH_GIT_OR_DIGEST_DRIFT", mutate: func(t *testing.T, root string) {
			mutateAcceptanceJSON(t, root, "assurance/candidate-manifest.json", func(document map[string]any) {
				nodes := arrayAcceptance(t, objectAcceptance(t, document, "graph"), "nodes")
				objectAcceptance(t, nodes[0].(map[string]any), "git")["blob"] = strings.Repeat("0", 40)
			})
			commitAcceptanceFixture(t, root, "assurance/candidate-manifest.json")
		}},
		{name: "anchor-derived-membership-omission", wantCode: "GRAPH_MEMBERSHIP_DRIFT", mutate: func(t *testing.T, root string) {
			mutateAcceptanceJSON(t, root, "assurance/candidate-manifest.json", func(document map[string]any) {
				graph := objectAcceptance(t, document, "graph")
				nodes := arrayAcceptance(t, graph, "nodes")
				kept := make([]any, 0, len(nodes)-1)
				removedID := ""
				for _, raw := range nodes {
					node := raw.(map[string]any)
					if node["path"] == "assurance/evidence-dag.json" {
						removedID = node["id"].(string)
						continue
					}
					kept = append(kept, node)
				}
				graph["nodes"] = kept
				edges := arrayAcceptance(t, graph, "edges")
				keptEdges := make([]any, 0, len(edges)-1)
				for _, raw := range edges {
					edge := raw.(map[string]any)
					if edge["from"] != removedID && edge["to"] != removedID {
						keptEdges = append(keptEdges, edge)
					}
				}
				graph["edges"] = keptEdges
			})
			commitAcceptanceFixture(t, root, "assurance/candidate-manifest.json")
		}},
		{name: "self-reference-or-review-cycle", wantCode: "GRAPH_EDGE_OR_REACHABILITY_DRIFT", mutate: func(t *testing.T, root string) {
			mutateAcceptanceJSON(t, root, "assurance/candidate-manifest.json", func(document map[string]any) {
				graph := objectAcceptance(t, document, "graph")
				edges := arrayAcceptance(t, graph, "edges")
				graph["edges"] = append(edges, map[string]any{"from": "file.assurance.reviews.codex.json", "to": "root.us023-candidate", "relation": "BINDS"})
			})
			commitAcceptanceFixture(t, root, "assurance/candidate-manifest.json")
		}},
		{name: "ai-occupies-human-slot", wantCode: "AI_AS_HUMAN", mutate: func(t *testing.T, root string) {
			mutateAcceptanceJSON(t, root, "assurance/reviews/human.json", func(document map[string]any) {
				document["status"], document["review_kind"], document["comments_only"] = "EXECUTED", "FULL", true
				document["provider"], document["model"], document["reasoning_effort"], document["invocation_id"] = "openai", "gpt-5.6-sol", "xhigh", "/root/acceptance"
				document["reviewer_identity"] = "Codex AI"
			})
		}},
		{name: "second-full-review-smuggled-through-qa", wantCode: "REVIEW_SUBJECT_OR_ROLE_DRIFT", mutate: func(t *testing.T, root string) {
			for _, file := range []string{"assurance/reviews/codex.json", "assurance/reviews/qa.json"} {
				mutateAcceptanceJSON(t, root, file, func(document map[string]any) {
					document["role"], document["status"], document["review_kind"], document["comments_only"] = "CODEX_REVIEWER", "EXECUTED", "FULL", true
					document["provider"], document["model"], document["reasoning_effort"], document["invocation_id"] = "openai", "gpt-5.6-sol", "xhigh", "/root/acceptance"
				})
			}
		}},
		{name: "independence-and-release-overclaim", wantCode: "ASSURANCE_OR_RELEASE_OVERCLAIM", mutate: func(t *testing.T, root string) {
			mutateAcceptanceJSON(t, root, "assurance/candidate-manifest.json", func(document map[string]any) {
				document["independent_review_claimed"], document["publication"], document["production"], document["signing"] = true, true, true, true
				document["performance_claimed"], document["cutover_claimed"] = true, true
			})
		}},
		{name: "missing-case-unresolved-count-and-current-subject-relabel", wantCode: "CLAIM_DERIVATION_DRIFT", mutate: func(t *testing.T, root string) {
			mutateAcceptanceJSON(t, root, "assurance/candidate-claims.json", func(document map[string]any) {
				families := arrayAcceptance(t, document, "evidence_families")
				first := families[0].(map[string]any)
				first["current_rust_connection"], first["unresolved_finding_count"], first["divergence_count"] = "CONNECTED", float64(1), float64(1)
				document["evidence_families"] = families[1:]
			})
			rebindAcceptanceContent(t, root)
		}},
		{name: "stub-deleted-filtered-silent-unsafe-dependency-lock-pass", wantCode: "ATTEMPT_OR_RECONCILIATION_DRIFT", mutate: func(t *testing.T, root string) {
			mutateAcceptanceJSON(t, root, "evidence/us023/attempts.json", func(document map[string]any) {
				attempts := arrayAcceptance(t, document, "platform_attempts")
				for _, raw := range attempts {
					attempt := raw.(map[string]any)
					gate := attempt["gate_id"]
					if gate == "gate.ac1.no-stub" || gate == "gate.ac1.unsafe" || gate == "gate.ac1.dependencies" || gate == "gate.ac1.lockfile" {
						attempt["execution_state"], attempt["blocker_code"] = "EXECUTED_PASS", ""
					}
				}
				reconciliation := objectAcceptance(t, document, "test_reconciliation")
				current := arrayAcceptance(t, reconciliation, "current_paths")
				if len(current) > 0 {
					reconciliation["current_paths"], reconciliation["missing_paths"] = current[1:], []any{current[0]}
				}
				reconciliation["state"] = "SATISFIED"
			})
			rebindAcceptanceContent(t, root)
		}},
		{name: "disconnected-shipped-rust", wantCode: "SHIPPED_RUST_DISCONNECTED", mutate: func(t *testing.T, root string) {
			mutateAcceptanceJSON(t, root, "assurance/formal/obligation-catalog.json", func(document map[string]any) {
				binding := arrayAcceptance(t, document, "rust_bindings")[0].(map[string]any)
				binding["connection_state"], binding["reachable_from_entry"] = "DISCONNECTED", false
			})
			rebindAcceptanceContent(t, root)
		}},
		{name: "disconnected-proof-overclaimed-complete", wantCode: "FORMAL_STRENGTH_OVERSTATED", mutate: func(t *testing.T, root string) {
			mutateAcceptanceJSON(t, root, "assurance/formal/obligation-catalog.json", func(document map[string]any) {
				coverage := arrayAcceptance(t, document, "coverage")[0].(map[string]any)
				coverage["aggregate_status"] = "SATISFIED"
			})
			rebindAcceptanceContent(t, root)
		}},
		{name: "incompatible-formal-bound", wantCode: "FORMAL_BOUND_OR_ASSUMPTION_INCOMPATIBLE", mutate: func(t *testing.T, root string) {
			mutateAcceptanceJSON(t, root, "assurance/formal/obligation-catalog.json", func(document map[string]any) {
				bounds := objectAcceptance(t, arrayAcceptance(t, document, "evidence")[0].(map[string]any), "bounds")
				bounds["max_steps"] = float64(1)
			})
			rebindAcceptanceContent(t, root)
		}},
		{name: "overstated-evidence-strength", wantCode: "FORMAL_STRENGTH_OVERSTATED", mutate: func(t *testing.T, root string) {
			mutateAcceptanceJSON(t, root, "assurance/formal/obligation-catalog.json", func(document map[string]any) {
				arrayAcceptance(t, document, "evidence")[0].(map[string]any)["observed_strength"] = "PRODUCTION_REFINEMENT"
			})
			rebindAcceptanceContent(t, root)
		}},
		{name: "mutation-survivor", wantCode: "MUTATION_SURVIVOR", mutate: func(t *testing.T, root string) {
			mutateAcceptanceJSON(t, root, "assurance/formal/obligation-catalog.json", func(document map[string]any) {
				evidence := arrayAcceptance(t, document, "evidence")[0].(map[string]any)
				arrayAcceptance(t, evidence, "mutation_sensitivity")[0].(map[string]any)["disposition"] = "SURVIVED"
			})
			rebindAcceptanceContent(t, root)
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := cloneAcceptanceRepo(t, repo)
			test.mutate(t, fixture)
			output, exit := runAcceptanceCLI(t, binary, "candidate-verify", fixture, 30*time.Second)
			if exit == 0 {
				t.Fatalf("hostile variant succeeded:\n%s", output)
			}
			var verdict assurance.CandidateVerdict
			if err := json.Unmarshal(output, &verdict); err != nil {
				t.Fatalf("invalid CLI verdict: %v\n%s", err, output)
			}
			if verdict.SnapshotState != "INVALID" || verdict.ParityState != "BLOCKED" || len(verdict.Findings) != 1 || verdict.Findings[0].Code != test.wantCode {
				t.Fatalf("finding = %#v, want one %s finding\n%s", verdict.Findings, test.wantCode, output)
			}
		})
	}
}

func TestUS023AcceptanceProtectedPathsAndSpecialFilesFailBeforeAccess(t *testing.T) {
	repo := acceptanceRepoRoot(t)
	binary := buildAcceptanceCLI(t, repo)

	t.Run("protected-edge-does-not-follow-fifo-decoy", func(t *testing.T) {
		fixture := cloneAcceptanceRepo(t, repo)
		protected := "corpora/hidden/private/scenarios.jsonl"
		full := filepath.Join(fixture, filepath.FromSlash(protected))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(full, 0o600); err != nil {
			t.Fatal(err)
		}
		mutateAcceptanceJSON(t, fixture, "assurance/candidate-manifest.json", func(document map[string]any) {
			graph := objectAcceptance(t, document, "graph")
			node := arrayAcceptance(t, graph, "nodes")[0].(map[string]any)
			oldID := node["id"]
			node["id"], node["path"], node["kind"], node["family"] = "file.corpora.hidden.private.scenarios.jsonl", protected, "CORPUS_PUBLIC_PROJECTION", "HIDDEN"
			for _, raw := range arrayAcceptance(t, graph, "edges") {
				edge := raw.(map[string]any)
				if edge["to"] == oldID {
					edge["to"] = node["id"]
				}
			}
		})
		commitAcceptanceFixture(t, fixture, "assurance/candidate-manifest.json")
		output, exit := runAcceptanceCLI(t, binary, "candidate-verify", fixture, 10*time.Second)
		assertAcceptanceFinding(t, output, exit, "GRAPH_ORDER_OR_DENOMINATOR_DRIFT")
	})

	for _, kind := range []string{"symlink", "fifo", "hardlink"} {
		t.Run(kind+"-manifest", func(t *testing.T) {
			fixture := cloneAcceptanceRepo(t, repo)
			manifest := filepath.Join(fixture, "assurance/candidate-manifest.json")
			original := readAcceptanceFile(t, manifest)
			if err := os.Remove(manifest); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "symlink":
				decoy := filepath.Join(fixture, "protected-decoy.fifo")
				if err := syscall.Mkfifo(decoy, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(decoy, manifest); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(manifest, 0o600); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				decoy := filepath.Join(fixture, "protected-decoy.json")
				if err := os.WriteFile(decoy, original, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(decoy, manifest); err != nil {
					t.Fatal(err)
				}
			}
			output, exit := runAcceptanceCLI(t, binary, "candidate-verify", fixture, 10*time.Second)
			assertAcceptanceFinding(t, output, exit, "CANDIDATE_MANIFEST_READ_FAILED")
		})
	}

	for _, variant := range []struct{ name, value string }{
		{name: "path-traversal", value: "../protected/secret.json"},
		{name: "decoded-secret", value: "sk-hostile-decoded-value"},
	} {
		t.Run(variant.name, func(t *testing.T) {
			fixture := cloneAcceptanceRepo(t, repo)
			mutateAcceptanceJSON(t, fixture, "assurance/candidate-manifest.json", func(document map[string]any) {
				arrayAcceptance(t, objectAcceptance(t, document, "graph"), "nodes")[0].(map[string]any)["path"] = variant.value
			})
			output, exit := runAcceptanceCLI(t, binary, "candidate-verify", fixture, 10*time.Second)
			assertAcceptanceFinding(t, output, exit, "CANDIDATE_MANIFEST_INVALID")
		})
	}
}

func acceptanceRepoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func buildAcceptanceCLI(t *testing.T, root string) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "assurectl")
	command := exec.Command("go", "build", "-o", binary, "./cmd/assurectl")
	command.Dir = root
	command.Env = pinnedAcceptanceEnv()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build assurectl: %v\n%s", err, output)
	}
	return binary
}

func runAcceptanceCLI(t *testing.T, binary, mode, root string, timeout time.Duration) ([]byte, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(ctx, binary, mode, "--root", root)
	command.Env = pinnedAcceptanceEnv()
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("%s followed a protected/special path or exceeded %s: %v", mode, timeout, ctx.Err())
	}
	if err == nil {
		return output, 0
	}
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) {
		t.Fatalf("run %s: %v\n%s", mode, err, output)
	}
	return output, exitError.ExitCode()
}

func pinnedAcceptanceEnv() []string {
	drop := map[string]bool{"JAVA_HOME": true, "PATH": true, "LANG": true, "LC_ALL": true}
	environment := make([]string, 0, len(os.Environ())+4)
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if !drop[name] {
			environment = append(environment, entry)
		}
	}
	return append(environment,
		"JAVA_HOME=/Users/mikelady/.jenv/versions/17",
		"PATH=/Users/mikelady/.jenv/versions/17/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
		"LANG=C", "LC_ALL=C",
	)
}

func cloneAcceptanceRepo(t *testing.T, source string) string {
	t.Helper()
	destination := filepath.Join(t.TempDir(), "fixture")
	command := exec.Command("git", "clone", "--quiet", "--shared", source, destination)
	command.Env = pinnedAcceptanceEnv()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("clone fixture: %v\n%s", err, output)
	}
	return destination
}

func commitAcceptanceFixture(t *testing.T, root string, paths ...string) string {
	t.Helper()
	arguments := append([]string{"-C", root, "add", "--"}, paths...)
	command := exec.Command("git", arguments...)
	command.Env = pinnedAcceptanceEnv()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("stage fixture: %v\n%s", err, output)
	}
	command = exec.Command("git", "-C", root, "-c", "user.name=US023 acceptance", "-c", "user.email=us023@example.invalid", "commit", "--quiet", "-m", "hostile acceptance fixture")
	command.Env = pinnedAcceptanceEnv()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("commit fixture: %v\n%s", err, output)
	}
	return strings.TrimSpace(string(gitAcceptanceOutput(t, root, "rev-parse", "HEAD")))
}

func rebindAcceptanceContent(t *testing.T, root string) {
	t.Helper()
	contentCommit := commitAcceptanceFixture(t, root, "assurance/candidate-claims.json", "assurance/formal/obligation-catalog.json", "evidence/us023/attempts.json")
	if err := assurance.MaterializeCandidateManifest(root, acceptanceTargetCommit, contentCommit); err != nil {
		t.Fatalf("materialize hostile manifest: %v", err)
	}
	commitAcceptanceFixture(t, root, "assurance/candidate-manifest.json")
}

func assertAcceptanceFinding(t *testing.T, output []byte, exit int, code string) {
	t.Helper()
	if exit == 0 {
		t.Fatalf("hostile variant succeeded:\n%s", output)
	}
	var verdict assurance.CandidateVerdict
	if err := json.Unmarshal(output, &verdict); err != nil {
		t.Fatalf("invalid CLI verdict: %v\n%s", err, output)
	}
	if verdict.SnapshotState != "INVALID" || len(verdict.Findings) != 1 || verdict.Findings[0].Code != code {
		t.Fatalf("finding = %#v, want %s\n%s", verdict.Findings, code, output)
	}
}

func mutateAcceptanceJSON(t *testing.T, root, relative string, mutate func(map[string]any)) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	document := readAcceptanceJSON(t, path)
	mutate(document)
	raw, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readAcceptanceJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(readAcceptanceFile(t, path), &document); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return document
}

func readAcceptanceFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func appendAcceptanceBytes(t *testing.T, path string, suffix []byte) {
	t.Helper()
	raw := append(readAcceptanceFile(t, path), suffix...)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func objectAcceptance(t *testing.T, document map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := document[key].(map[string]any)
	if !ok {
		t.Fatalf("%s is not an object: %#v", key, document[key])
	}
	return value
}

func arrayAcceptance(t *testing.T, document map[string]any, key string) []any {
	t.Helper()
	value, ok := document[key].([]any)
	if !ok {
		t.Fatalf("%s is not an array: %#v", key, document[key])
	}
	return value
}

func findAcceptanceNode(t *testing.T, manifest map[string]any, path string) map[string]any {
	t.Helper()
	for _, raw := range arrayAcceptance(t, objectAcceptance(t, manifest, "graph"), "nodes") {
		node := raw.(map[string]any)
		if node["path"] == path {
			return node
		}
	}
	t.Fatalf("graph node %s not found", path)
	return nil
}

func gitAcceptanceOutput(t *testing.T, root string, arguments ...string) []byte {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, arguments...)...)
	command.Env = pinnedAcceptanceEnv()
	output, err := command.Output()
	if err != nil {
		t.Fatalf("git %v: %v", arguments, err)
	}
	return output
}

func digestAcceptance(raw []byte) string {
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}
