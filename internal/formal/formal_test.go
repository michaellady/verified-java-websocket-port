package formal

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	vendorprotocol "github.com/michaellady/verified-java-to-rust/foundation/protocol"
)

var fixtureFiles = []string{
	proofTargetsPath,
	backendQualificationPath,
	connectionModelPath,
	concurrencyPlanPath,
	proofTargetsSchemaPath,
	backendSchemaPath,
	concurrencySchemaPath,
	"assurance/evidence-model.json",
	"corpora/public/manifest.json",
	"corpora/public/scenarios.jsonl",
	"evidence/corpus-calibration.json",
	"evidence/intake/compatibility-surface.json",
	"evidence/intake/cutover-contract.json",
	"evidence/intake/port-seam-dossier.json",
	"evidence/sbx-validation.json",
	"evidence/security-validation.json",
	"security/sandbox-policy.json",
	"security/sbx-template.json",
}

func TestUS006CanonicalPreflightAndReplayAreDeterministic(t *testing.T) {
	root := repositoryRoot(t)
	before := readFile(t, filepath.Join(root, backendQualificationPath))
	preflight, err := Validate(context.Background(), Request{RootPath: root, Mode: ModePreflight})
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	replay, err := Validate(context.Background(), Request{RootPath: root, Mode: ModeReplay})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !preflight.Valid || preflight.State != "BLOCKED" || len(preflight.Findings) != 0 {
		t.Fatalf("preflight = %#v, want mechanically valid BLOCKED", preflight)
	}
	wantedScopes := []string{"FUTURE_PRODUCTION_REFINEMENT", "SYSTEMATIC_CONCURRENCY_TESTING", "UNAVAILABLE_BACKEND_BLOCKED"}
	if !equalStrings(preflight.ClaimScopes, wantedScopes) {
		t.Fatalf("claim scopes = %v, want %v", preflight.ClaimScopes, wantedScopes)
	}
	preflightBytes, _ := json.Marshal(preflight)
	replayBytes, _ := json.Marshal(replay)
	if !bytes.Equal(preflightBytes, replayBytes) {
		t.Fatalf("unchanged preflight/replay differ:\n%s\n%s", preflightBytes, replayBytes)
	}
	after := readFile(t, filepath.Join(root, backendQualificationPath))
	if !bytes.Equal(before, after) {
		t.Fatal("Validate mutated retained qualification")
	}
}

func TestUS006HostileFixtureMatrix(t *testing.T) {
	type hostileCase struct {
		id          string
		code        string
		disposition string
		reason      string
		mutate      func(*testing.T, string)
	}
	cases := []hostileCase{
		{"concurrency-bound-drift", "STALE_INPUT", "INVALIDATE", "CONCURRENCY_BOUND_DRIFT", mutateConcurrencyBounds},
		{"digest-substitution", "DIGEST_MISMATCH", "QUARANTINE", "DIGEST_SUBSTITUTION", mutateBorrowedDigest},
		{"disconnected-symbol", "SEMANTIC_INCONSISTENCY", "BLOCK", "DISCONNECTED_TARGET", mutateDisconnectedCallPath},
		{"disconnected-proof-copy", "SEMANTIC_INCONSISTENCY", "BLOCK", "PROOF_ONLY_DUPLICATE", mutateDisconnectedProofCopy},
		{"duplicate-json-member", "SEMANTIC_INCONSISTENCY", "BLOCK", "DUPLICATE_JSON_MEMBER", mutateDuplicateMember},
		{"inflated-finite-proof", "SEMANTIC_INCONSISTENCY", "BLOCK", "INFLATED_CLAIM", mutateInflatedClaim},
		{"inflated-loom-proof", "SEMANTIC_INCONSISTENCY", "BLOCK", "INFLATED_CLAIM", mutateInflatedLoomProof},
		{"inflated-model-production", "SEMANTIC_INCONSISTENCY", "BLOCK", "REFINEMENT_MISSING", mutateInflatedModelProduction},
		{"inflated-schedule-count", "SEMANTIC_INCONSISTENCY", "BLOCK", "INFLATED_COUNT", mutateInflatedScheduleCount},
		{"known-bad-survives", "SEMANTIC_INCONSISTENCY", "BLOCK", "KNOWN_BAD_CANARY_SURVIVED", mutateKnownBadSurvives},
		{"malformed-tla-module", "SEMANTIC_INCONSISTENCY", "BLOCK", "MALFORMED_TLA_MODULE", mutateMalformedTLA},
		{"missing-required-artifact", "SEMANTIC_INCONSISTENCY", "BLOCK", "MISSING_REQUIRED_ARTIFACT", mutateRequiredArtifactInventory},
		{"missing-required-file", "SEMANTIC_INCONSISTENCY", "BLOCK", "MISSING_REQUIRED_ARTIFACT", mutateMissingRequiredFile},
		{"missing-digest", "SEMANTIC_INCONSISTENCY", "BLOCK", "MISSING_DIGEST", mutateMissingDigest},
		{"missing-target", "SEMANTIC_INCONSISTENCY", "BLOCK", "MISSING_TARGET", mutateMissingTarget},
		{"noncanonical-artifact-path", "SEMANTIC_INCONSISTENCY", "BLOCK", "NONCANONICAL_PATH", mutateNoncanonicalPath},
		{"replay-digest-mismatch", "SEMANTIC_INCONSISTENCY", "BLOCK", "REPLAY_MISMATCH", mutateReplayDigest},
		{"unsupported-claimed-covered", "SEMANTIC_INCONSISTENCY", "BLOCK", "UNSUPPORTED_CONSTRUCT_CLAIMED", mutateUnsupportedCovered},
		{"unavailable-as-success", "SEMANTIC_INCONSISTENCY", "BLOCK", "UNAVAILABLE_REPRESENTED_AS_SUCCESS", mutateUnavailableSuccess},
		{"unavailable-as-skip", "SEMANTIC_INCONSISTENCY", "BLOCK", "UNAVAILABLE_REPRESENTED_AS_SKIP", mutateUnavailableSkip},
		{"zero-obligations", "SEMANTIC_INCONSISTENCY", "BLOCK", "ZERO_OBLIGATIONS", mutateZeroObligations},
	}
	for _, test := range cases {
		t.Run(test.id, func(t *testing.T) {
			root := copyFixtureRoot(t)
			test.mutate(t, root)
			for _, mode := range []string{ModePreflight, ModeReplay} {
				verdict, err := Validate(context.Background(), Request{RootPath: root, Mode: mode})
				if err != nil {
					t.Fatalf("%s: %v", mode, err)
				}
				if verdict.Valid {
					t.Fatalf("%s unexpectedly valid: %#v", mode, verdict)
				}
				if !hasFinding(verdict.Findings, test.code, test.disposition, test.reason) {
					t.Fatalf("%s findings = %#v, want %s/%s/%s", mode, verdict.Findings, test.code, test.disposition, test.reason)
				}
			}
		})
	}
}

func TestUS006StrictClosedDecoding(t *testing.T) {
	cases := []struct {
		name   string
		reason string
		mutate func(*testing.T, string)
	}{
		{
			name: "unknown member", reason: "UNKNOWN_JSON_MEMBER",
			mutate: func(t *testing.T, root string) {
				value := loadObject(t, filepath.Join(root, backendQualificationPath))
				value["unexpected"] = true
				writeObject(t, filepath.Join(root, backendQualificationPath), value)
			},
		},
		{
			name: "trailing value", reason: "TRAILING_JSON_VALUE",
			mutate: func(t *testing.T, root string) {
				path := filepath.Join(root, backendQualificationPath)
				data := readFile(t, path)
				writeFile(t, path, append(data, []byte("{}\n")...))
			},
		},
		{
			name: "null document", reason: "NULL_JSON_DOCUMENT",
			mutate: func(t *testing.T, root string) {
				writeFile(t, filepath.Join(root, backendQualificationPath), []byte("null\n"))
			},
		},
		{
			name: "invalid UTF-8", reason: "INVALID_UTF8",
			mutate: func(t *testing.T, root string) {
				path := filepath.Join(root, backendQualificationPath)
				writeFile(t, path, append(readFile(t, path), 0xff))
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			root := copyFixtureRoot(t)
			test.mutate(t, root)
			verdict, err := Validate(context.Background(), Request{RootPath: root, Mode: ModePreflight})
			if err != nil {
				t.Fatal(err)
			}
			if !hasReason(verdict.Findings, test.reason) {
				t.Fatalf("findings = %#v, want %s", verdict.Findings, test.reason)
			}
		})
	}
}

func TestUS006RejectsNonSingleLinkSnapshot(t *testing.T) {
	root := copyFixtureRoot(t)
	model := filepath.Join(root, connectionModelPath)
	if err := os.Link(model, filepath.Join(root, "connection-model-hardlink.tla")); err != nil {
		t.Fatal(err)
	}
	verdict, err := Validate(context.Background(), Request{RootPath: root, Mode: ModePreflight})
	if err != nil {
		t.Fatal(err)
	}
	if !hasReason(verdict.Findings, "INVALID_ARTIFACT_SNAPSHOT") {
		t.Fatalf("findings = %#v, want INVALID_ARTIFACT_SNAPSHOT", verdict.Findings)
	}
}

func TestUS006FixtureCatalogMatchesHostileCases(t *testing.T) {
	type fixtureCase struct {
		FixtureID           string   `json:"fixture_id"`
		Mutation            string   `json:"mutation"`
		FixtureTreeDigest   string   `json:"fixture_tree_digest"`
		ExpectedCode        string   `json:"expected_code"`
		ExpectedDisposition string   `json:"expected_disposition"`
		ExpectedReason      string   `json:"expected_reason"`
		ExpectedExit        int      `json:"expected_exit"`
		ExpectedState       string   `json:"expected_state"`
		ExpectedClaimScopes []string `json:"expected_claim_scopes"`
		SyntheticNonClaim   bool     `json:"synthetic_non_claim"`
	}
	type catalog struct {
		Schema                   string        `json:"$schema"`
		SchemaVersion            string        `json:"schema_version"`
		EntityType               string        `json:"entity_type"`
		FixtureTreeAlgorithm     string        `json:"fixture_tree_algorithm"`
		Assurance                string        `json:"assurance"`
		IndependentReviewClaimed bool          `json:"independent_review_claimed"`
		Cases                    []fixtureCase `json:"cases"`
	}
	path := filepath.Join(repositoryRoot(t), "assurance/formal/fixtures/cases.json")
	var value catalog
	if err := decodeStrict(readFile(t, path), &value); err != nil {
		t.Fatal(err)
	}
	schemaPath := filepath.Join(repositoryRoot(t), "schemas/formal-fixture-catalog-1.0.0.schema.json")
	schema, err := compileSchema(readFile(t, schemaPath), schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	var untyped any
	if err := decodeStrict(readFile(t, path), &untyped); err != nil || schema.Validate(untyped) != nil {
		t.Fatalf("fixture catalog does not satisfy its closed schema: decode=%v schema=%v", err, schema.Validate(untyped))
	}
	if value.SchemaVersion != "1.0.0" || value.EntityType != "FormalFixtureCatalog" || value.FixtureTreeAlgorithm != "CANONICAL_PATH_SHA256_V1" || value.Assurance != "SYNTHETIC_NON_CLAIM" || value.IndependentReviewClaimed {
		t.Fatalf("fixture catalog posture drifted: %#v", value)
	}
	mutations := fixtureContractMutations()
	ids := make([]string, 0, len(value.Cases))
	seenIDs := map[string]bool{}
	for _, item := range value.Cases {
		ids = append(ids, item.FixtureID)
		if seenIDs[item.FixtureID] {
			t.Fatalf("duplicate fixture id %s", item.FixtureID)
		}
		seenIDs[item.FixtureID] = true
		mutate, ok := mutations[item.FixtureID]
		if item.Mutation == "" || !item.SyntheticNonClaim || !ok || (!strings.HasPrefix(item.FixtureID, "good-") && item.ExpectedExit != 1) {
			t.Fatalf("invalid fixture record: %#v", item)
		}
		root := copyFixtureRoot(t)
		mutate(t, root)
		if actual := fixtureTreeDigest(t, root); actual != item.FixtureTreeDigest {
			t.Errorf("%s fixture_tree_digest = %s, want %s", item.FixtureID, actual, item.FixtureTreeDigest)
		}
		for _, mode := range []string{ModePreflight, ModeReplay} {
			verdict, err := Validate(context.Background(), Request{RootPath: root, Mode: mode})
			if err != nil {
				t.Fatalf("%s %s: %v", item.FixtureID, mode, err)
			}
			if verdict.State != item.ExpectedState || !equalStrings(verdict.ClaimScopes, item.ExpectedClaimScopes) || boolToExit(!verdict.Valid) != item.ExpectedExit {
				t.Errorf("%s %s envelope = state:%s scopes:%v valid:%v", item.FixtureID, mode, verdict.State, verdict.ClaimScopes, verdict.Valid)
			}
			if item.ExpectedExit == 1 && !hasFinding(verdict.Findings, item.ExpectedCode, item.ExpectedDisposition, item.ExpectedReason) {
				t.Errorf("%s %s findings = %#v", item.FixtureID, mode, verdict.Findings)
			}
		}
	}
	if !sort.StringsAreSorted(ids) {
		t.Fatalf("fixture ids not sorted: %v", ids)
	}
	if len(ids) != len(mutations) {
		t.Fatalf("catalog has %d cases, exact contract has %d", len(ids), len(mutations))
	}
	for id := range mutations {
		if !seenIDs[id] {
			t.Fatalf("fixture contract is missing %s", id)
		}
	}
}

func fixtureContractMutations() map[string]func(*testing.T, string) {
	return map[string]func(*testing.T, string){
		"disconnected-proof-copy": mutateDisconnectedProofCopy,
		"disconnected-symbol":     mutateDisconnectedCallPath,
		"good-finite-mask-bounded": func(t *testing.T, root string) {
			makeSyntheticExecutedBackend(t, root, "backend.finite-mask-prototype")
		},
		"good-proved-model-only":           func(t *testing.T, root string) { makeSyntheticExecutedBackend(t, root, "backend.tlc-connection-model") },
		"good-systematic-concurrency":      func(t *testing.T, root string) { makeSyntheticExecutedBackend(t, root, "backend.loom-concurrency") },
		"good-unavailable-backend-blocked": func(*testing.T, string) {},
		"good-unresolved-production-plan":  func(*testing.T, string) {},
		"inflated-finite-proof":            mutateInflatedClaim,
		"inflated-loom-proof":              mutateInflatedLoomProof,
		"inflated-model-production":        mutateInflatedModelProduction,
		"inflated-schedule-count":          mutateInflatedScheduleCount,
		"known-bad-survives":               mutateKnownBadSurvives,
		"missing-digest":                   mutateMissingDigest,
		"missing-required-artifact":        mutateRequiredArtifactInventory,
		"missing-target":                   mutateMissingTarget,
		"replay-digest-mismatch":           mutateReplayDigest,
		"unavailable-as-skip":              mutateUnavailableSkip,
		"unavailable-as-success":           mutateUnavailableSuccess,
		"unsupported-claimed-covered":      mutateUnsupportedCovered,
		"zero-obligations":                 mutateZeroObligations,
	}
}

func fixtureTreeDigest(t *testing.T, root string) string {
	t.Helper()
	type entry struct{ Path, SHA256 string }
	entries := []entry{}
	if err := filepath.WalkDir(root, func(path string, item os.DirEntry, err error) error {
		if err != nil || item.IsDir() {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		entries = append(entries, entry{filepath.ToSlash(relative), vendorprotocol.DigestBytes(readFile(t, path))})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	data, err := vendorprotocol.CanonicalJSON(entries)
	if err != nil {
		t.Fatal(err)
	}
	return vendorprotocol.DigestBytes(data)
}

func boolToExit(failed bool) int {
	if failed {
		return 1
	}
	return 0
}

func mutateConcurrencyBounds(t *testing.T, root string) {
	planPath := filepath.Join(root, concurrencyPlanPath)
	plan := loadObject(t, planPath)
	plan["bounds"].(map[string]any)["max_tasks"] = float64(8)
	writeObject(t, planPath, plan)
	qualificationPath := filepath.Join(root, backendQualificationPath)
	qualification := loadObject(t, qualificationPath)
	qualification["concurrency_plan"].(map[string]any)["sha256"] = digestFile(t, planPath)
	backendByID(t, qualification, "backend.loom-concurrency")["bounds"].(map[string]any)["max_tasks"] = float64(8)
	writeObject(t, qualificationPath, qualification)
}

func mutateBorrowedDigest(t *testing.T, root string) {
	path := filepath.Join(root, "evidence/security-validation.json")
	before := readFile(t, path)
	after := bytes.Replace(before, []byte(`"schema_version": "1.0.0"`), []byte(`"schema_version": "1.0.1"`), 1)
	if len(after) != len(before) || bytes.Equal(after, before) {
		t.Fatal("same-length digest substitution fixture did not mutate exactly one retained value")
	}
	writeFile(t, path, after)
}

func mutateDisconnectedCallPath(t *testing.T, root string) {
	path := filepath.Join(root, proofTargetsPath)
	value := loadObject(t, path)
	target := value["targets"].([]any)[0].(map[string]any)
	target["required_call_paths"].([]any)[0].(map[string]any)["state"] = "DISCONNECTED"
	writeObject(t, path, value)
	rebindQualification(t, root, "proof_targets", path)
}

func mutateDisconnectedProofCopy(t *testing.T, root string) {
	path := filepath.Join(root, proofTargetsPath)
	value := loadObject(t, path)
	value["targets"].([]any)[0].(map[string]any)["rust_symbol"] = "proof_only::frame_header_copy"
	writeObject(t, path, value)
	rebindQualification(t, root, "proof_targets", path)
}

func mutateDuplicateMember(t *testing.T, root string) {
	path := filepath.Join(root, backendQualificationPath)
	data := readFile(t, path)
	data = bytes.Replace(data, []byte(`"schema_version": "1.0.0",`), []byte(`"schema_version": "1.0.0", "schema_version": "1.0.0",`), 1)
	writeFile(t, path, data)
}

func mutateInflatedClaim(t *testing.T, root string) {
	path := filepath.Join(root, backendQualificationPath)
	value := loadObject(t, path)
	backendByID(t, value, "backend.finite-mask-prototype")["claim_scope"] = "PROVED_MODEL"
	writeObject(t, path, value)
}

func mutateInflatedLoomProof(t *testing.T, root string) {
	path := filepath.Join(root, backendQualificationPath)
	value := loadObject(t, path)
	backendByID(t, value, "backend.loom-concurrency")["claim_scope"] = "PROVED_MODEL"
	writeObject(t, path, value)
}

func mutateInflatedModelProduction(t *testing.T, root string) {
	path := filepath.Join(root, proofTargetsPath)
	value := loadObject(t, path)
	value["targets"].([]any)[0].(map[string]any)["obligations"].([]any)[0].(map[string]any)["production_refinement_required"] = false
	writeObject(t, path, value)
	rebindQualification(t, root, "proof_targets", path)
}

func mutateInflatedScheduleCount(t *testing.T, root string) {
	path := filepath.Join(root, backendQualificationPath)
	value := loadObject(t, path)
	bounds := backendByID(t, value, "backend.loom-concurrency")["bounds"].(map[string]any)
	bounds["schedule_count"] = bounds["max_schedules"].(float64) + 1
	writeObject(t, path, value)
}

func mutateKnownBadSurvives(t *testing.T, root string) {
	path := filepath.Join(root, backendQualificationPath)
	value := loadObject(t, path)
	backend := backendByID(t, value, "backend.finite-mask-prototype")
	backend["known_bad_canaries"].([]any)[0].(map[string]any)["observed_outcome"] = "PASS"
	writeObject(t, path, value)
}

func mutateMalformedTLA(t *testing.T, root string) {
	path := filepath.Join(root, connectionModelPath)
	data := bytes.Replace(readFile(t, path), []byte("MODULE ConnectionModel"), []byte("MODULE WrongModel"), 1)
	writeFile(t, path, data)
	rebindQualification(t, root, "connection_model", path)
}

func mutateRequiredArtifactInventory(t *testing.T, root string) {
	path := filepath.Join(root, backendQualificationPath)
	value := loadObject(t, path)
	backend := backendByID(t, value, "backend.finite-mask-prototype")
	items := backend["required_artifacts"].([]any)
	filtered := make([]any, 0, len(items)-1)
	for _, item := range items {
		if item != "TOOL_IDENTITY" {
			filtered = append(filtered, item)
		}
	}
	backend["required_artifacts"] = filtered
	writeObject(t, path, value)
}

func mutateMissingRequiredFile(t *testing.T, root string) {
	if err := os.Remove(filepath.Join(root, connectionModelPath)); err != nil {
		t.Fatal(err)
	}
}

func mutateMissingDigest(t *testing.T, root string) {
	path := filepath.Join(root, proofTargetsPath)
	value := loadObject(t, path)
	delete(value["source_basis"].([]any)[0].(map[string]any), "sha256")
	writeObject(t, path, value)
	rebindQualification(t, root, "proof_targets", path)
}

func mutateMissingTarget(t *testing.T, root string) {
	path := filepath.Join(root, backendQualificationPath)
	value := loadObject(t, path)
	backend := backendByID(t, value, "backend.finite-mask-prototype")
	backend["obligation_ids"].([]any)[0] = "obligation.unknown"
	backend["outcomes"].([]any)[0].(map[string]any)["obligation_id"] = "obligation.unknown"
	writeObject(t, path, value)
}

func mutateReplayDigest(t *testing.T, root string) {
	path := filepath.Join(root, backendQualificationPath)
	value := loadObject(t, path)
	backend := backendByID(t, value, "backend.finite-mask-prototype")
	backend["replay"].(map[string]any)["semantic_output_digest"] = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	writeObject(t, path, value)
}

func mutateNoncanonicalPath(t *testing.T, root string) {
	path := filepath.Join(root, proofTargetsPath)
	value := loadObject(t, path)
	source := value["source_basis"].([]any)[0].(map[string]any)
	source["path"] = "./assurance/evidence-model.json"
	writeObject(t, path, value)
	rebindQualification(t, root, "proof_targets", path)
}

func mutateUnsupportedCovered(t *testing.T, root string) {
	path := filepath.Join(root, backendQualificationPath)
	value := loadObject(t, path)
	backend := backendByID(t, value, "backend.finite-mask-prototype")
	backend["unsupported_constructs"] = []any{"construct.dynamic-dispatch"}
	backend["outcomes"].([]any)[0].(map[string]any)["raw_outcome"] = "BOUNDED_CHECK_PASSED"
	writeObject(t, path, value)
}

func mutateUnavailableSuccess(t *testing.T, root string) {
	path := filepath.Join(root, backendQualificationPath)
	value := loadObject(t, path)
	backend := backendByID(t, value, "backend.finite-mask-prototype")
	backend["claim_scope"] = "BOUNDED_TEST_EVIDENCE"
	outcome := backend["outcomes"].([]any)[0].(map[string]any)
	outcome["raw_outcome"] = "BOUNDED_CHECK_PASSED"
	outcome["claim_scope"] = "BOUNDED_TEST_EVIDENCE"
	writeObject(t, path, value)
}

func mutateUnavailableSkip(t *testing.T, root string) {
	path := filepath.Join(root, backendQualificationPath)
	value := loadObject(t, path)
	backendByID(t, value, "backend.finite-mask-prototype")["claim_scope"] = "SKIP"
	writeObject(t, path, value)
}

func mutateZeroObligations(t *testing.T, root string) {
	path := filepath.Join(root, backendQualificationPath)
	value := loadObject(t, path)
	backend := backendByID(t, value, "backend.finite-mask-prototype")
	backend["obligation_ids"] = []any{}
	backend["obligation_count"] = float64(0)
	backend["outcomes"] = []any{}
	writeObject(t, path, value)
}

func copyFixtureRoot(t *testing.T) string {
	t.Helper()
	source := repositoryRoot(t)
	destination := t.TempDir()
	for _, relative := range fixtureFiles {
		target := filepath.Join(destination, relative)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, target, readFile(t, filepath.Join(source, relative)))
	}
	return destination
}

func rebindQualification(t *testing.T, root, field, artifactPath string) {
	t.Helper()
	path := filepath.Join(root, backendQualificationPath)
	value := loadObject(t, path)
	value[field].(map[string]any)["sha256"] = digestFile(t, artifactPath)
	writeObject(t, path, value)
}

func backendByID(t *testing.T, qualification map[string]any, id string) map[string]any {
	t.Helper()
	for _, raw := range qualification["backends"].([]any) {
		backend := raw.(map[string]any)
		if backend["backend_id"] == id {
			return backend
		}
	}
	t.Fatalf("backend %s not found", id)
	return nil
}

func loadObject(t *testing.T, path string) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(readFile(t, path), &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func writeObject(t *testing.T, path string, value map[string]any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, append(data, '\n'))
}

func digestFile(t *testing.T, path string) string {
	t.Helper()
	return vendorprotocol.DigestBytes(readFile(t, path))
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func hasFinding(findings []Finding, code, disposition, reason string) bool {
	for _, finding := range findings {
		if finding.Code == code && finding.Disposition == disposition && finding.Reason == reason {
			return true
		}
	}
	return false
}

func hasReason(findings []Finding, reason string) bool {
	for _, finding := range findings {
		if finding.Reason == reason {
			return true
		}
	}
	return false
}
