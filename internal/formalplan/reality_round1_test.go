package formalplan

// US-006 reality-check round 1 (review session 01a040fe) regression tests.
//
// BLOCKING-1: the merged artifacts contradicted each other on close-delivery
// semantics — lane A's proof target truthfully records AT-LEAST-ONCE terminal
// callback delivery under listener re-entry (WebSocketImpl.java:530/557/566),
// while the model header, backend qualification, and concurrency plan still
// attributed exactly-once delivery to the Java monitor. The cross-artifact
// consistency check tested here blocks any regression back to a
// Java-attributed exactly-once terminal-delivery claim.
//
// BLOCKING-2: formal-preflight deep-validated only the backend qualification
// (proof targets and concurrency plan were schema-only), and a passing
// obligation with no resolvable production link silently yielded
// productionLinked=false with no typed finding. The tests here drive the
// lane A/B deep wiring and the DISCONNECTED_PROOF blocking finding.
//
// TDD: these tests were written RED against the pre-fix validator and
// artifacts, then turned green by the reconciliation + enforcement commit.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/portplan"
)

const us006BaseManifestPath = "assurance/replay/fixtures/us006-base/mutation.json"

// rr1RealizeBase realizes the shared us006-base fixture tree (real lane A/B/C
// documents plus every input their deep validators read, including the pinned
// quarantine archive) into a temp root. It ensures the quarantine archive
// exists in the repository working tree first, matching the incumbent lane A
// acquisition behavior.
func rr1RealizeBase(t *testing.T) string {
	t.Helper()
	if _, err := portplan.EnsureQuarantinedSource(us006RepoRoot(t)); err != nil {
		t.Fatalf("ensure quarantined source: %v", err)
	}
	root := t.TempDir()
	us006ApplyManifest(t, root, us006BaseManifestPath, 0)
	return root
}

func rr1MutateJSON(t *testing.T, root, relative, pointer string, value any) {
	t.Helper()
	target := filepath.Join(root, filepath.FromSlash(relative))
	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read %s: %v", relative, err)
	}
	var document any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("decode %s: %v", relative, err)
	}
	updated, err := us006SetPointer(document, pointer, value)
	if err != nil {
		t.Fatalf("mutate %s%s: %v", relative, pointer, err)
	}
	encoded, err := json.MarshalIndent(updated, "", "  ")
	if err != nil {
		t.Fatalf("encode %s: %v", relative, err)
	}
	us006WriteFile(t, target, append(encoded, '\n'))
}

// The realized base tree must be clean through the full preflight: all three
// documents present and deep-validated (lane A proof targets, lane B
// concurrency plan + connection model, lane C backend qualification) with
// zero findings of any disposition.
func TestFormalPreflightBaseTreeDeepClean(t *testing.T) {
	root := rr1RealizeBase(t)
	verdict, err := FormalPreflight(PreflightRequest{RootPath: root})
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	if len(verdict.Findings) != 0 {
		t.Fatalf("base tree must be clean under deep validation, got: %+v", verdict.Findings)
	}
	if verdict.State != "OK" {
		t.Fatalf("state = %s, want OK", verdict.State)
	}
	if len(verdict.Documents) != 3 {
		t.Fatalf("documents = %d, want 3", len(verdict.Documents))
	}
	for _, document := range verdict.Documents {
		if !document.Present || !document.SchemaPresent {
			t.Fatalf("document %s must be present with schema: %+v", document.Path, document)
		}
	}
}

// BLOCKING-2(a): the proof-targets document must receive lane A's deep
// semantic validation inside formal-preflight, not schema-only validation. A
// stale migration-map digest pin is invisible to the schema and must surface
// as the lane A typed finding through the preflight verdict.
func TestFormalPreflightDeepValidatesProofTargets(t *testing.T) {
	root := rr1RealizeBase(t)
	rr1MutateJSON(t, root, ProofTargetsDocumentPath, "/sources/migration_map/sha256",
		"sha256:"+strings.Repeat("a", 64))
	verdict, err := FormalPreflight(PreflightRequest{RootPath: root})
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	if !hasFindingCode(verdict, TargetsFindingMigrationMapDigestMismatch) {
		t.Fatalf("missing %s through preflight: %+v", TargetsFindingMigrationMapDigestMismatch, verdict.Findings)
	}
	if verdict.State != "BLOCKED" {
		t.Fatalf("state = %s, want BLOCKED", verdict.State)
	}
}

// BLOCKING-2(a): the concurrency plan must receive lane B's deep semantic
// validation inside formal-preflight. Renaming a census seam to a
// schema-legal but unknown id (L9 matches the seam-id pattern) is invisible
// to the schema and must surface as the lane B census-incompleteness rule.
func TestFormalPreflightDeepValidatesConcurrencyPlan(t *testing.T) {
	root := rr1RealizeBase(t)
	rr1MutateJSON(t, root, ConcurrencyPlanDocumentPath, "/seam_census/seams/0/seam_id", "L9")
	verdict, err := FormalPreflight(PreflightRequest{RootPath: root})
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	if !hasFindingCode(verdict, "PLAN_SEAM_CENSUS_INCOMPLETE") {
		t.Fatalf("missing PLAN_SEAM_CENSUS_INCOMPLETE through preflight: %+v", verdict.Findings)
	}
	if verdict.State != "BLOCKED" {
		t.Fatalf("state = %s, want BLOCKED", verdict.State)
	}
}

// BLOCKING-2(a): the connection model artifact must be validated by lane B's
// model validator inside formal-preflight; a missing model file blocks.
func TestFormalPreflightDeepValidatesConnectionModel(t *testing.T) {
	root := rr1RealizeBase(t)
	if err := os.Remove(filepath.Join(root, filepath.FromSlash(ConnectionModelTLAPath))); err != nil {
		t.Fatalf("remove model: %v", err)
	}
	verdict, err := FormalPreflight(PreflightRequest{RootPath: root})
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	if !hasFindingCode(verdict, "MODEL_FILE_UNREADABLE") {
		t.Fatalf("missing MODEL_FILE_UNREADABLE through preflight: %+v", verdict.Findings)
	}
	if verdict.State != "BLOCKED" {
		t.Fatalf("state = %s, want BLOCKED", verdict.State)
	}
}

// BLOCKING-2(b): an obligation with a genuine lattice pass but no resolvable
// production link must emit the typed blocking finding DISCONNECTED_PROOF and
// be excluded from both pass counters.
func TestFormalPreflightDisconnectedProof(t *testing.T) {
	prepare := func(t *testing.T) string {
		root := us006UnitRoot(t)
		receipt := []byte("{\"kind\":\"seeded-unit-receipt\"}\n")
		receiptDigest := sha256.Sum256(receipt)
		us006WriteFile(t, filepath.Join(root, "seeded", "receipt.json"), receipt)
		us006MutateDocument(t, root, "/backends/2/sbx_execution", map[string]any{
			"status":           "EXECUTED",
			"reason":           "unit fixture",
			"required_profile": "sandbox_profile (this document)",
			"receipt": map[string]any{
				"path":   "seeded/receipt.json",
				"sha256": "sha256:" + hex.EncodeToString(receiptDigest[:]),
			},
			"evidence_run": rr1CompleteEvidenceRun(),
		})
		us006MutateDocument(t, root, "/backends/2/selected", true)
		us006MutateDocument(t, root, "/backends/2/selection_state", "SELECTED_EXECUTED")
		us006MutateDocument(t, root, "/backends/2/canaries/known_good/status", "PASSED")
		us006MutateDocument(t, root, "/backends/2/canaries/known_bad/status", "DETECTED")
		us006MutateDocument(t, root, "/backends/2/canaries/known_bad/counterexample_digest", "sha256:"+strings.Repeat("d", 64))
		us006MutateDocument(t, root, "/backends/2/obligations/0/outcome", "ProofEstablished")
		return root
	}

	cases := []struct {
		name  string
		value any
	}{
		{"empty-production-code-ids", []any{}},
		{"unresolvable-production-file", []any{"rust/connection-core/src/missing.rs#connection_state_machine"}},
		// Integration round 2: the file exists but never mentions the cited
		// symbol — the link's second half must fail resolution.
		{"symbol-absent-from-existing-file", []any{"rust/connection-core/src/connection.rs#no_such_symbol_present"}},
	}
	for _, item := range cases {
		item := item
		t.Run(item.name, func(t *testing.T) {
			root := prepare(t)
			us006MutateDocument(t, root, "/backends/2/obligations/0/production_code_ids", item.value)
			verdict, err := FormalPreflight(PreflightRequest{RootPath: root})
			if err != nil {
				t.Fatalf("preflight: %v", err)
			}
			if !hasFindingCode(verdict, "DISCONNECTED_PROOF") {
				t.Fatalf("missing DISCONNECTED_PROOF: %+v", verdict.Findings)
			}
			if verdict.ObligationsPassed != 0 || verdict.ProductionLinkedObligationsPassed != 0 {
				t.Fatalf("disconnected proof must be excluded from both pass counters: passed=%d production=%d",
					verdict.ObligationsPassed, verdict.ProductionLinkedObligationsPassed)
			}
			if verdict.State != "BLOCKED" {
				t.Fatalf("state = %s, want BLOCKED", verdict.State)
			}
		})
	}

	t.Run("linked-pass-still-counts", func(t *testing.T) {
		root := prepare(t)
		us006WriteFile(t, filepath.Join(root, "fixtures-production", "connection_state_machine.rs"),
			[]byte("// test production stand-in\npub fn connection_state_machine() {}\n"))
		us006MutateDocument(t, root, "/backends/2/obligations/0/production_code_ids",
			[]any{"fixtures-production/connection_state_machine.rs#connection_state_machine"})
		verdict, err := FormalPreflight(PreflightRequest{RootPath: root})
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		if hasFindingCode(verdict, "DISCONNECTED_PROOF") {
			t.Fatalf("resolvable link must not be flagged: %+v", verdict.Findings)
		}
		if verdict.ObligationsPassed != 1 || verdict.ProductionLinkedObligationsPassed != 1 {
			t.Fatalf("linked pass must count 1/1, got passed=%d production=%d",
				verdict.ObligationsPassed, verdict.ProductionLinkedObligationsPassed)
		}
	})
}

// BLOCKING-1(d): the three documents' close-delivery statements must agree
// with the proof-targets record — no artifact may claim Java-attributed
// exactly-once terminal delivery, the model must declare its no-re-entrancy
// restriction, and the proof-targets truth anchor (at-least-once under
// listener re-entry) must stay present.
func TestFormalPreflightCloseDeliveryConsistency(t *testing.T) {
	t.Run("backend-qualification-regression-to-java-exactly-once", func(t *testing.T) {
		root := rr1RealizeBase(t)
		rr1MutateJSON(t, root, BackendQualificationDocumentPath,
			"/backends/2/expected_property_inventory/1/description",
			"close is terminal-absorbing: exactly-once terminal delivery, second close path is a no-op (L2 monitor)")
		verdict, err := FormalPreflight(PreflightRequest{RootPath: root})
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		if !hasFindingCode(verdict, "JAVA_EXACTLY_ONCE_TERMINAL_CLAIM") {
			t.Fatalf("missing JAVA_EXACTLY_ONCE_TERMINAL_CLAIM: %+v", verdict.Findings)
		}
		if verdict.State != "BLOCKED" {
			t.Fatalf("state = %s, want BLOCKED", verdict.State)
		}
	})

	t.Run("concurrency-plan-regression-to-java-exactly-once", func(t *testing.T) {
		root := rr1RealizeBase(t)
		rr1MutateJSON(t, root, ConcurrencyPlanDocumentPath,
			"/seam_census/seams/1/note",
			"The de-facto connection lock: exactly-once terminal transition with onWebsocketClose at 557 and CLOSED at 566 (WebSocketImpl.java).")
		verdict, err := FormalPreflight(PreflightRequest{RootPath: root})
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		if !hasFindingCode(verdict, "JAVA_EXACTLY_ONCE_TERMINAL_CLAIM") {
			t.Fatalf("missing JAVA_EXACTLY_ONCE_TERMINAL_CLAIM: %+v", verdict.Findings)
		}
	})

	t.Run("model-comment-regression-to-java-exactly-once", func(t *testing.T) {
		root := rr1RealizeBase(t)
		tlaPath := filepath.Join(root, filepath.FromSlash(ConnectionModelTLAPath))
		raw, err := os.ReadFile(tlaPath)
		if err != nil {
			t.Fatalf("read model: %v", err)
		}
		text := string(raw) // append an unscoped Java-attributed claim comment before module end
		text = strings.Replace(text, "\n====",
			"\n\\* JAVA: WebSocketImpl.java:530-567 terminal transition, exactly-once\n\\* onWebsocketClose at 557.\n====", 1)
		us006WriteFile(t, tlaPath, []byte(text))
		verdict, err := FormalPreflight(PreflightRequest{RootPath: root})
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		if !hasFindingCode(verdict, "JAVA_EXACTLY_ONCE_TERMINAL_CLAIM") {
			t.Fatalf("missing JAVA_EXACTLY_ONCE_TERMINAL_CLAIM: %+v", verdict.Findings)
		}
	})

	t.Run("model-restriction-undeclared", func(t *testing.T) {
		root := rr1RealizeBase(t)
		tlaPath := filepath.Join(root, filepath.FromSlash(ConnectionModelTLAPath))
		raw, err := os.ReadFile(tlaPath)
		if err != nil {
			t.Fatalf("read model: %v", err)
		}
		text := strings.ReplaceAll(string(raw), "listener re-entrancy", "listener behavior")
		us006WriteFile(t, tlaPath, []byte(text))
		verdict, err := FormalPreflight(PreflightRequest{RootPath: root})
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		if !hasFindingCode(verdict, "MODEL_REENTRANCY_RESTRICTION_UNDECLARED") {
			t.Fatalf("missing MODEL_REENTRANCY_RESTRICTION_UNDECLARED: %+v", verdict.Findings)
		}
	})

	t.Run("proof-targets-truth-anchor-removed", func(t *testing.T) {
		root := rr1RealizeBase(t)
		rr1MutateJSON(t, root, ProofTargetsDocumentPath, "/targets/4/statement",
			"closeConnection is the only shipped terminal transition; the monitor delivers the terminal callback.")
		verdict, err := FormalPreflight(PreflightRequest{RootPath: root})
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		if !hasFindingCode(verdict, "CLOSE_DELIVERY_TRUTH_ANCHOR_MISSING") {
			t.Fatalf("missing CLOSE_DELIVERY_TRUTH_ANCHOR_MISSING: %+v", verdict.Findings)
		}
	})
}

// rr1CompleteEvidenceRun returns an EvidenceRun-complete execution record for
// unit fixtures (mirrors the foundation completeness field set).
func rr1CompleteEvidenceRun() map[string]any {
	return map[string]any{
		"source_revision":              "rev",
		"specification_revision":       "rev",
		"java_revision":                "rev",
		"rust_revision":                "rev",
		"java_semantic_ids":            []any{"java-id"},
		"rust_semantic_ids":            []any{"rust-id"},
		"command":                      "./tool run",
		"working_directory":            ".",
		"tool_hashes":                  []any{"sha256:" + strings.Repeat("b", 64)},
		"container_hashes":             []any{"sha256:" + strings.Repeat("c", 64)},
		"environment":                  []any{"LANG=C"},
		"seed":                         "0",
		"hardware":                     "fixture",
		"assumptions":                  []any{"fixture"},
		"bounds":                       map[string]any{"states": "412"},
		"unsupported_constructs":       []any{"none"},
		"trusted_base":                 []any{"fixture"},
		"exit_count":                   float64(2),
		"obligation_count":             float64(2),
		"raw_log_ids":                  []any{"log-1"},
		"artifact_ids":                 []any{"artifact-1"},
		"normalized_diff_id":           "diff-1",
		"counterexample_or_corpus_ids": []any{"cx-1"},
		"replay_command":               "./tool run",
	}
}
