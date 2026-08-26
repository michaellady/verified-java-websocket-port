package formalplan

// Lane A (US-006) tests: proof-targets claim-ID bijection validator.
// All identifiers in this file are lane-scoped (targets* / ProofTargets*) so
// lanes B and C can add their own files to this package without collisions.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func targetsRepoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repo root missing go.mod: %v", err)
	}
	return root
}

// TestProofTargetsRealDocumentVerifies is the good path over the real
// committed artifact: the full bijection, every Java anchor against the
// digest-pinned quarantined tree, and every rust identity against the
// migration map must verify with zero findings.
func TestProofTargetsRealDocumentVerifies(t *testing.T) {
	root := targetsRepoRoot(t)
	report := VerifyProofTargets(root)
	for _, finding := range report.Findings {
		t.Errorf("unexpected finding %s at %s: %s", finding.Code, finding.Path, finding.Message)
	}
	if !report.OK {
		t.Fatalf("real proof-targets document must verify")
	}
	if report.ClaimsCovered != 10 {
		t.Fatalf("claims covered = %d, want 10 (one per migration-map formal.* claim)", report.ClaimsCovered)
	}
	if report.AnchorsVerified == 0 {
		t.Fatalf("no Java anchors verified; the plan must cite the quarantined tree")
	}
	if report.BindingsVerified == 0 || report.SymbolsPlanned == 0 {
		t.Fatalf("bindings=%d symbols=%d; both must be nonzero", report.BindingsVerified, report.SymbolsPlanned)
	}
}

// TestProofTargetsBijectionIsExact asserts the document covers exactly the
// migration map's formal claim inventory: every claim once, no extras.
func TestProofTargetsBijectionIsExact(t *testing.T) {
	root := targetsRepoRoot(t)
	document, err := LoadProofTargets(root)
	if err != nil {
		t.Fatalf("load proof targets: %v", err)
	}
	seen := map[string]int{}
	for _, target := range document.Targets {
		seen[target.FormalClaimID]++
	}
	expected := []string{
		"formal.adapter.no-protocol-logic",
		"formal.close.terminal-absorbing",
		"formal.concurrency.no-data-race",
		"formal.connection.no-terminal-escape",
		"formal.control.payload-length-bound",
		"formal.fragmentation.no-unbounded-growth",
		"formal.framing.allocation-limit",
		"formal.framing.length-bounds",
		"formal.handshake.accept-derivation",
		"formal.messages.utf8-validation-total",
	}
	if len(seen) != len(expected) {
		t.Fatalf("distinct claims = %d, want %d", len(seen), len(expected))
	}
	for _, claim := range expected {
		if seen[claim] != 1 {
			t.Errorf("claim %s covered %d times, want exactly once", claim, seen[claim])
		}
	}
}

// TestProofTargetsHandshakeEncodesShippedPredicate pins the US-005 outcome:
// the accept-derivation target must reference the live handshake mapping and
// record the Java-permissive predicate as the shipped behavior, with zero
// unledgered RFC-strictness deltas anywhere in the document.
func TestProofTargetsHandshakeEncodesShippedPredicate(t *testing.T) {
	root := targetsRepoRoot(t)
	document, err := LoadProofTargets(root)
	if err != nil {
		t.Fatalf("load proof targets: %v", err)
	}
	var handshake *ProofTarget
	for index := range document.Targets {
		if document.Targets[index].FormalClaimID == "formal.handshake.accept-derivation" {
			handshake = &document.Targets[index]
		}
	}
	if handshake == nil {
		t.Fatalf("handshake accept-derivation target missing")
	}
	if handshake.BehaviorFidelity.LiveEvidence == nil {
		t.Fatalf("handshake target must cite evidence/us005-handshake-live-mapping.json")
	}
	if handshake.BehaviorFidelity.LiveEvidence.Path != "evidence/us005-handshake-live-mapping.json" {
		t.Fatalf("handshake live evidence path = %q", handshake.BehaviorFidelity.LiveEvidence.Path)
	}
	for _, target := range document.Targets {
		for _, delta := range target.BehaviorFidelity.RFCStrictnessDeltas {
			t.Errorf("target %s carries strictness delta %s but the behavior-delta ledger has no records",
				target.TargetID, delta.DeltaID)
		}
	}
}

// targetsMutate loads the committed document as generic JSON, applies the
// mutation, writes the result to a temp file, and returns its path.
func targetsMutate(t *testing.T, root string, mutate func(document map[string]interface{})) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(root, ProofTargetsDocumentPath))
	if err != nil {
		t.Fatalf("read committed document: %v", err)
	}
	var document map[string]interface{}
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatalf("decode committed document: %v", err)
	}
	mutate(document)
	mutated, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatalf("encode mutated document: %v", err)
	}
	path := filepath.Join(t.TempDir(), "proof-targets.json")
	if err := os.WriteFile(path, mutated, 0o644); err != nil {
		t.Fatalf("write mutated document: %v", err)
	}
	return path
}

// targetsList and targetsFindByClaim run inside mutation closures, so they
// panic (failing the test loudly) instead of taking a *testing.T.
func targetsList(document map[string]interface{}) []interface{} {
	list, ok := document["targets"].([]interface{})
	if !ok || len(list) == 0 {
		panic("mutated document has no targets list")
	}
	return list
}

func targetsFindByClaim(document map[string]interface{}, claim string) map[string]interface{} {
	for _, entry := range targetsList(document) {
		target, ok := entry.(map[string]interface{})
		if !ok {
			continue
		}
		if target["formal_claim_id"] == claim {
			return target
		}
	}
	panic("claim " + claim + " not found in mutated document")
}

func targetsRequireCode(t *testing.T, report ProofTargetsReport, code string) {
	t.Helper()
	if report.OK {
		t.Fatalf("mutated document must not verify (want finding %s)", code)
	}
	for _, finding := range report.Findings {
		if finding.Code == code {
			return
		}
	}
	codes := make([]string, 0, len(report.Findings))
	for _, finding := range report.Findings {
		codes = append(codes, finding.Code)
	}
	t.Fatalf("finding %s absent; got %v", code, codes)
}

// TestProofTargetsSeededDefectsBlockWithTypedFindings drives the validator
// over seeded-bad documents. Every failure family carries its own finding
// code; a catch-all code is the Codex gap this lane must not repeat.
func TestProofTargetsSeededDefectsBlockWithTypedFindings(t *testing.T) {
	root := targetsRepoRoot(t)

	cases := []struct {
		name   string
		code   string
		mutate func(document map[string]interface{})
	}{
		{
			name: "removed-target-orphans-map-claim",
			code: TargetsFindingClaimNotCovered,
			mutate: func(document map[string]interface{}) {
				document["targets"] = targetsListWithout(document, "formal.framing.length-bounds")
			},
		},
		{
			name: "duplicated-claim-breaks-bijection",
			code: TargetsFindingClaimDuplicated,
			mutate: func(document map[string]interface{}) {
				list := document["targets"].([]interface{})
				document["targets"] = append(list[:len(list)-1], list[len(list)-2], list[len(list)-2])
			},
		},
		{
			name: "invented-claim-id-is-unknown",
			code: TargetsFindingClaimUnknown,
			mutate: func(document map[string]interface{}) {
				target := targetsList(document)[0].(map[string]interface{})
				target["formal_claim_id"] = "formal.mask.invented-claim"
			},
		},
		{
			name: "tampered-rust-identity-mismatches-map",
			code: TargetsFindingBindingRustIdentityMismatch,
			mutate: func(document map[string]interface{}) {
				target := targetsList(document)[0].(map[string]interface{})
				bindings := target["migration_bindings"].([]interface{})
				binding := bindings[0].(map[string]interface{})
				binding["rust_semantic_id"] = "ws_core::framing::RenamedType"
			},
		},
		{
			name: "dropped-binding-row-is-omitted",
			code: TargetsFindingBindingRowOmitted,
			mutate: func(document map[string]interface{}) {
				target := targetsList(document)[0].(map[string]interface{})
				bindings := target["migration_bindings"].([]interface{})
				target["migration_bindings"] = bindings[1:]
			},
		},
		{
			name: "bogus-binding-row-is-unknown",
			code: TargetsFindingBindingRowUnknown,
			mutate: func(document map[string]interface{}) {
				target := targetsList(document)[0].(map[string]interface{})
				bindings := target["migration_bindings"].([]interface{})
				target["migration_bindings"] = append(bindings, map[string]interface{}{
					"row_id":                 "migration.org-java-websocket-invented-type",
					"java_semantic_id":       "org.java_websocket.Invented",
					"rust_semantic_id":       "ws_core::framing::Invented",
					"excluded":               false,
					"rust_identity_verified": false,
				})
			},
		},
		{
			name: "tampered-anchor-digest-blocks",
			code: TargetsFindingJavaAnchorDigestMismatch,
			mutate: func(document map[string]interface{}) {
				target := targetsList(document)[0].(map[string]interface{})
				anchors := target["java_authority"].([]interface{})
				anchor := anchors[0].(map[string]interface{})
				anchor["sha256"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
			},
		},
		{
			name: "missing-anchor-file-blocks",
			code: TargetsFindingJavaAnchorFileMissing,
			mutate: func(document map[string]interface{}) {
				target := targetsList(document)[0].(map[string]interface{})
				anchors := target["java_authority"].([]interface{})
				anchor := anchors[0].(map[string]interface{})
				anchor["file"] = "src/main/java/org/java_websocket/drafts/Draft_9999.java"
			},
		},
		{
			name: "anchor-range-beyond-file-blocks",
			code: TargetsFindingJavaAnchorRangeInvalid,
			mutate: func(document map[string]interface{}) {
				target := targetsList(document)[0].(map[string]interface{})
				anchors := target["java_authority"].([]interface{})
				anchor := anchors[0].(map[string]interface{})
				anchor["end_line"] = float64(999999)
			},
		},
		{
			name: "codex-namespace-is-unbound",
			code: TargetsFindingSymbolNamespaceUnbound,
			mutate: func(document map[string]interface{}) {
				target := targetsList(document)[0].(map[string]interface{})
				symbols := target["production_symbols"].([]interface{})
				symbol := symbols[0].(map[string]interface{})
				symbol["namespace_rust_semantic_id"] = "ws_core::frame::FrameHeaderDecoder"
				symbol["planned_symbol"] = "ws_core::frame::FrameHeaderDecoder::decode_header"
			},
		},
		{
			name: "symbol-outside-namespace-blocks",
			code: TargetsFindingSymbolPrefixMismatch,
			mutate: func(document map[string]interface{}) {
				target := targetsFindByClaim(document, "formal.framing.length-bounds")
				symbols := target["production_symbols"].([]interface{})
				symbol := symbols[0].(map[string]interface{})
				symbol["planned_symbol"] = "ws_core::connection::WebSocketImpl::decode_frame_header"
			},
		},
		{
			name: "resolver-overclaim-on-symbol-blocks",
			code: TargetsFindingSymbolResolutionOverclaim,
			mutate: func(document map[string]interface{}) {
				target := targetsList(document)[0].(map[string]interface{})
				symbols := target["production_symbols"].([]interface{})
				symbol := symbols[0].(map[string]interface{})
				symbol["resolution"] = map[string]interface{}{
					"state":           "RESOLVER_VERIFIED",
					"resolved_symbol": symbol["planned_symbol"],
				}
			},
		},
		{
			name: "resolver-overclaim-on-document-blocks",
			code: TargetsFindingResolutionStateOverclaim,
			mutate: func(document map[string]interface{}) {
				resolution := document["rust_identity_resolution"].(map[string]interface{})
				resolution["state"] = "RESOLVER_VERIFIED"
				resolution["resolver_verified_at"] = "2026-08-26T00:00:00Z"
			},
		},
		{
			name: "missing-conformance-invoker-blocks",
			code: TargetsFindingInvokerRoleMissing,
			mutate: func(document map[string]interface{}) {
				target := targetsList(document)[0].(map[string]interface{})
				invokers := target["required_invokers"].([]interface{})
				kept := make([]interface{}, 0, len(invokers))
				for _, entry := range invokers {
					invoker := entry.(map[string]interface{})
					if invoker["role"] != "conformance" {
						kept = append(kept, entry)
					}
				}
				target["required_invokers"] = kept
			},
		},
		{
			name: "bound-invoker-while-unresolved-blocks",
			code: TargetsFindingInvokerStateOverclaim,
			mutate: func(document map[string]interface{}) {
				target := targetsList(document)[0].(map[string]interface{})
				invokers := target["required_invokers"].([]interface{})
				invoker := invokers[0].(map[string]interface{})
				invoker["state"] = "BOUND"
				invoker["invoker_symbol"] = "ws_conformance::harness::exercise"
			},
		},
		{
			name: "handshake-live-evidence-removed-blocks",
			code: TargetsFindingHandshakeLiveEvidenceMissing,
			mutate: func(document map[string]interface{}) {
				target := targetsFindByClaim(document, "formal.handshake.accept-derivation")
				fidelity := target["behavior_fidelity"].(map[string]interface{})
				fidelity["live_evidence"] = nil
			},
		},
		{
			name: "handshake-live-evidence-digest-tamper-blocks",
			code: TargetsFindingHandshakeLiveEvidenceDigestMismatch,
			mutate: func(document map[string]interface{}) {
				target := targetsFindByClaim(document, "formal.handshake.accept-derivation")
				fidelity := target["behavior_fidelity"].(map[string]interface{})
				evidence := fidelity["live_evidence"].(map[string]interface{})
				evidence["sha256"] = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
			},
		},
		{
			// The Codex US-006 gap this lane exists to not repeat: a
			// reject-noncanonical-length obligation the pinned Java decode
			// path does not implement, frozen without a ledger entry.
			name: "unledgered-strictness-delta-blocks",
			code: TargetsFindingStrictnessDeltaUnledgered,
			mutate: func(document map[string]interface{}) {
				target := targetsFindByClaim(document, "formal.framing.length-bounds")
				fidelity := target["behavior_fidelity"].(map[string]interface{})
				fidelity["rfc_strictness_deltas"] = []interface{}{
					map[string]interface{}{
						"delta_id":         "reject-noncanonical-16bit-length",
						"ledger_record_id": "delta.noncanonical-length-reject",
						"statement":        "decoder rejects 16-bit lengths below 126 (Java does not)",
					},
				}
			},
		},
		{
			name: "ac1-family-removed-blocks",
			code: TargetsFindingAC1FamilyMissing,
			mutate: func(document map[string]interface{}) {
				coverage := document["ac1_coverage"].([]interface{})
				kept := make([]interface{}, 0, len(coverage))
				for _, entry := range coverage {
					family := entry.(map[string]interface{})
					if family["family"] != "mask-equation-involution" {
						kept = append(kept, entry)
					}
				}
				document["ac1_coverage"] = kept
			},
		},
		{
			name: "ac1-family-citing-missing-symbol-blocks",
			code: TargetsFindingAC1FamilyUnbound,
			mutate: func(document map[string]interface{}) {
				coverage := document["ac1_coverage"].([]interface{})
				family := coverage[0].(map[string]interface{})
				family["symbol_ids"] = []interface{}{"sym.invented.missing-symbol"}
			},
		},
		{
			name: "migration-map-digest-pin-tamper-blocks",
			code: TargetsFindingMigrationMapDigestMismatch,
			mutate: func(document map[string]interface{}) {
				sources := document["sources"].(map[string]interface{})
				migration := sources["migration_map"].(map[string]interface{})
				migration["sha256"] = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
			},
		},
		{
			name: "unknown-top-level-field-fails-strict-decode",
			code: TargetsFindingStrictDecodeFailed,
			mutate: func(document map[string]interface{}) {
				document["injected_unknown_field"] = "x"
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			path := targetsMutate(t, root, testCase.mutate)
			report := VerifyProofTargetsAt(root, path)
			targetsRequireCode(t, report, testCase.code)
		})
	}
}

// targetsListWithout returns the targets list minus the target carrying the
// given claim.
func targetsListWithout(document map[string]interface{}, claim string) []interface{} {
	list := document["targets"].([]interface{})
	kept := make([]interface{}, 0, len(list))
	for _, entry := range list {
		target, ok := entry.(map[string]interface{})
		if ok && target["formal_claim_id"] == claim {
			continue
		}
		kept = append(kept, entry)
	}
	return kept
}

// TestProofTargetsSchemaViolationIsTyped: a structurally broken document must
// surface the schema-violation family, not a decode panic or a generic error.
func TestProofTargetsSchemaViolationIsTyped(t *testing.T) {
	root := targetsRepoRoot(t)
	path := targetsMutate(t, root, func(document map[string]interface{}) {
		document["schema_version"] = "9.9.9"
	})
	report := VerifyProofTargetsAt(root, path)
	targetsRequireCode(t, report, TargetsFindingSchemaViolation)
}

// TestProofTargetsFindingsAreDeterministic: two runs over the same seeded-bad
// document must produce identical, sorted findings.
func TestProofTargetsFindingsAreDeterministic(t *testing.T) {
	root := targetsRepoRoot(t)
	path := targetsMutate(t, root, func(document map[string]interface{}) {
		target := targetsList(document)[0].(map[string]interface{})
		bindings := target["migration_bindings"].([]interface{})
		target["migration_bindings"] = bindings[1:]
		anchors := target["java_authority"].([]interface{})
		anchor := anchors[0].(map[string]interface{})
		anchor["sha256"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	})
	first := VerifyProofTargetsAt(root, path)
	second := VerifyProofTargetsAt(root, path)
	firstEncoded, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("encode first report: %v", err)
	}
	secondEncoded, err := json.Marshal(second)
	if err != nil {
		t.Fatalf("encode second report: %v", err)
	}
	if string(firstEncoded) != string(secondEncoded) {
		t.Fatalf("reports differ between runs:\n%s\n%s", firstEncoded, secondEncoded)
	}
	for index := 1; index < len(first.Findings); index++ {
		previous, current := first.Findings[index-1], first.Findings[index]
		if previous.Code > current.Code ||
			(previous.Code == current.Code && previous.Path > current.Path) {
			t.Fatalf("findings not sorted at index %d: %v then %v", index, previous, current)
		}
	}
}
