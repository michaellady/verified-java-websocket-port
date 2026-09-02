package formalcoverage

import (
	"strings"
	"testing"
)

// Attacks on the checks the deletion sweep found unguarded. Each test here
// exists because neutralising its check left the suite green, and a check that
// nothing can turn red is decoration — worse than nothing in an evidence tool,
// because it reads like a guarantee.

// tamperProposal mutates the first correction the picker accepts and returns
// the findings VerifyCorrections then reports.
func tamperProposal(t *testing.T, mutate func(correction map[string]any) bool) []CorrectionFinding {
	t.Helper()
	root := sandbox(t)
	applied := false
	rewriteJSON(t, root, CorrectionPath, func(tree map[string]any) {
		corrections, _ := tree["corrections"].([]any)
		for _, entry := range corrections {
			correction, _ := entry.(map[string]any)
			if mutate(correction) {
				applied = true
				return
			}
		}
	})
	if !applied {
		t.Fatal("no correction accepted the mutation, so this attack tests nothing")
	}
	findings, _, err := VerifyCorrections(root)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return findings
}

func TestAProposalReadAgainstAnEditedCatalogIsRefused(t *testing.T) {
	root := sandbox(t)
	rewriteJSON(t, root, CatalogPath, func(tree map[string]any) {
		obligations, _ := tree["obligations"].([]any)
		first, _ := obligations[0].(map[string]any)
		first["statement"] = "Something else entirely."
	})
	findings, _, err := VerifyCorrections(root)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !hasCheck(findings, "CATALOG_STILL_VENDORED_BYTES") {
		t.Fatalf("the proposal was checked against an edited catalog without complaint; findings=%v", findings)
	}
}

func TestACorrectionThatMisquotesTheObligationStatementIsRefused(t *testing.T) {
	findings := tamperProposal(t, func(correction map[string]any) bool {
		correction["obligation_statement"] = "Masking is fine, probably."
		return true
	})
	if !hasCheck(findings, "OBLIGATION_STATEMENT_QUOTED_VERBATIM") {
		t.Fatalf("a misquoted obligation statement was accepted; findings=%v", findings)
	}
}

func TestACurrentJavaKeyThatIsNotDerivedFromItsSymbolIsRefused(t *testing.T) {
	findings := tamperProposal(t, func(correction map[string]any) bool {
		current, _ := correction["current"].(map[string]any)
		current["java_key"] = "Draft_6455#somethingElse"
		return true
	})
	if !hasCheck(findings, "CURRENT_JAVA_KEY_IS_DERIVED_FROM_THE_CATALOG_SYMBOL") {
		t.Fatalf("a java key that its own symbol does not derive was accepted; findings=%v", findings)
	}
}

func TestAProposalThatProposesTheSymbolItIsCorrectingIsRefused(t *testing.T) {
	findings := tamperProposal(t, func(correction map[string]any) bool {
		current, _ := correction["current"].(map[string]any)
		proposed, _ := correction["proposed"].(map[string]any)
		chain, _ := proposed["chain"].([]any)
		member, _ := chain[0].(map[string]any)
		member["production_symbol"] = current["production_symbol"]
		member["java_key"] = current["java_key"]
		return true
	})
	if !hasCheck(findings, "PROPOSED_SYMBOL_DIFFERS_FROM_THE_CURRENT_ONE") {
		t.Fatalf("a correction that proposes the symbol it is correcting was accepted; findings=%v", findings)
	}
}

func TestAProposedJavaKeyThatIsNotDerivedFromItsSymbolIsRefused(t *testing.T) {
	findings := tamperProposal(t, func(correction map[string]any) bool {
		proposed, _ := correction["proposed"].(map[string]any)
		chain, _ := proposed["chain"].([]any)
		member, _ := chain[0].(map[string]any)
		member["java_key"] = "Draft_6455#inventedName"
		return true
	})
	if !hasCheck(findings, "PROPOSED_JAVA_KEY_IS_DERIVED_FROM_THE_PROPOSED_SYMBOL") {
		t.Fatalf("a proposed java key its own symbol does not derive was accepted; findings=%v", findings)
	}
}

func TestAnUnbindableMemberWithNoStatedReasonIsRefused(t *testing.T) {
	findings := tamperProposal(t, func(correction map[string]any) bool {
		proposed, _ := correction["proposed"].(map[string]any)
		chain, _ := proposed["chain"].([]any)
		for _, entry := range chain {
			member, _ := entry.(map[string]any)
			if bindable, _ := member["bindable_under_current_resolver"].(bool); !bindable {
				member["not_bindable_reason"] = ""
				return true
			}
		}
		return false
	})
	if !hasCheck(findings, "UNBINDABLE_MEMBER_STATES_WHY") {
		t.Fatalf("an unbindable member with no stated reason was accepted; findings=%v", findings)
	}
}

func TestABindableMemberCarryingAnExcuseIsRefused(t *testing.T) {
	findings := tamperProposal(t, func(correction map[string]any) bool {
		proposed, _ := correction["proposed"].(map[string]any)
		chain, _ := proposed["chain"].([]any)
		for _, entry := range chain {
			member, _ := entry.(map[string]any)
			if bindable, _ := member["bindable_under_current_resolver"].(bool); bindable {
				member["not_bindable_reason"] = "it might not work"
				return true
			}
		}
		return false
	})
	if !hasCheck(findings, "BINDABLE_MEMBER_CARRIES_NO_EXCUSE") {
		t.Fatalf("a bindable member carrying a not-bindable excuse was accepted; findings=%v", findings)
	}
}

func TestACorrectionWithNoResidualGapIsRefused(t *testing.T) {
	findings := tamperProposal(t, func(correction map[string]any) bool {
		effect, _ := correction["effect_if_adopted"].(map[string]any)
		effect["residual_gap"] = "   "
		return true
	})
	if !hasCheck(findings, "EVERY_CORRECTION_STATES_ITS_RESIDUAL_GAP") {
		t.Fatalf("a correction claiming no residual gap was accepted; findings=%v", findings)
	}
}

func TestAnUnknownCorroborationCodeIsRefused(t *testing.T) {
	findings := tamperProposal(t, func(correction map[string]any) bool {
		current, _ := correction["current"].(map[string]any)
		citations, _ := current["citations"].([]any)
		citation, _ := citations[0].(map[string]any)
		citation["corroboration"] = "TRUST_ME"
		return true
	})
	if !hasCheck(findings, "CORROBORATION_VOCABULARY_IS_CLOSED") {
		t.Fatalf("an unknown corroboration code was accepted; findings=%v", findings)
	}
}

func TestACitationWithNoStatedEffectIsRefused(t *testing.T) {
	findings := tamperProposal(t, func(correction map[string]any) bool {
		current, _ := correction["current"].(map[string]any)
		citations, _ := current["citations"].([]any)
		citation, _ := citations[0].(map[string]any)
		citation["effect_at_these_lines"] = ""
		return true
	})
	if !hasCheck(findings, "CITATION_STATES_WHAT_IS_AT_THOSE_LINES") {
		t.Fatalf("a citation that says nothing about what is at those lines was accepted; findings=%v", findings)
	}
}

func TestACitationWithAnImpossibleLineRangeIsRefused(t *testing.T) {
	findings := tamperProposal(t, func(correction map[string]any) bool {
		current, _ := correction["current"].(map[string]any)
		citations, _ := current["citations"].([]any)
		citation, _ := citations[0].(map[string]any)
		citation["start_line"] = 900
		citation["end_line"] = 12
		return true
	})
	if !hasCheck(findings, "CITATION_LINES_ARE_A_REAL_RANGE") {
		t.Fatalf("an impossible line range was accepted; findings=%v", findings)
	}
}

func TestACitationWithAMalformedDigestIsRefused(t *testing.T) {
	findings := tamperProposal(t, func(correction map[string]any) bool {
		current, _ := correction["current"].(map[string]any)
		citations, _ := current["citations"].([]any)
		citation, _ := citations[0].(map[string]any)
		citation["file_sha256"] = "probably-the-right-file"
		return true
	})
	if !hasCheck(findings, "CITATION_FILE_DIGEST_IS_WELL_FORMED") {
		t.Fatalf("a malformed file digest was accepted; findings=%v", findings)
	}
}

func TestAProjectedTargetThatDoesNotExistIsRefused(t *testing.T) {
	findings := tamperProposal(t, func(correction map[string]any) bool {
		effect, _ := correction["effect_if_adopted"].(map[string]any)
		effect["would_map_onto_targets"] = []any{"target.formal.wishful.thinking"}
		return true
	})
	if !hasCheck(findings, "PROJECTED_TARGET_EXISTS") {
		t.Fatalf("a projected target that is in no plan was accepted; findings=%v", findings)
	}
}

func TestAProjectedTargetSymbolThatDoesNotExistIsRefused(t *testing.T) {
	findings := tamperProposal(t, func(correction map[string]any) bool {
		effect, _ := correction["effect_if_adopted"].(map[string]any)
		effect["target_symbol_id"] = "sym.imaginary.thing"
		return true
	})
	if !hasCheck(findings, "PROJECTED_TARGET_SYMBOL_EXISTS") {
		t.Fatalf("a projected target symbol that is in no plan was accepted; findings=%v", findings)
	}
}

// tamperProposalTree mutates the whole proposal document, for attacks that are
// about the SET of corrections rather than one of them.
func tamperProposalTree(t *testing.T, mutate func(tree map[string]any)) []CorrectionFinding {
	t.Helper()
	root := sandbox(t)
	rewriteJSON(t, root, CorrectionPath, mutate)
	findings, _, err := VerifyCorrections(root)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return findings
}

func TestACorrectionThatCitesNothingAgainstTheCurrentSymbolIsRefused(t *testing.T) {
	findings := tamperProposal(t, func(correction map[string]any) bool {
		current, _ := correction["current"].(map[string]any)
		current["citations"] = []any{}
		return true
	})
	if !hasCheck(findings, "CURRENT_DEFECT_IS_CITED") {
		t.Fatalf("a correction that cites nothing against the symbol it condemns was accepted; findings=%v", findings)
	}
}

func TestACorrectionThatNamesNoReplacementIsRefused(t *testing.T) {
	findings := tamperProposal(t, func(correction map[string]any) bool {
		proposed, _ := correction["proposed"].(map[string]any)
		proposed["chain"] = []any{}
		return true
	})
	if !hasCheck(findings, "PROPOSAL_NAMES_A_REPLACEMENT") {
		t.Fatalf("a correction that proposes nothing was accepted; findings=%v", findings)
	}
}

func TestAProposalPinningTheWrongCatalogIdentityIsRefused(t *testing.T) {
	findings := tamperProposalTree(t, func(tree map[string]any) {
		immutability, _ := tree["immutability"].(map[string]any)
		immutability["catalog_sha256"] = "sha256:" + strings.Repeat("f", 64)
	})
	if !hasCheck(findings, "PROPOSAL_ECHOES_THE_VENDORED_IDENTITY") {
		t.Fatalf("a proposal pinning a catalog identity that is not the vendored one was accepted; findings=%v", findings)
	}
}

func TestTwoCorrectionsForOneObligationAreRefused(t *testing.T) {
	findings := tamperProposalTree(t, func(tree map[string]any) {
		corrections, _ := tree["corrections"].([]any)
		first, _ := corrections[0].(map[string]any)
		second, _ := corrections[1].(map[string]any)
		second["obligation_id"] = first["obligation_id"]
	})
	if !hasCheck(findings, "ONE_CORRECTION_PER_OBLIGATION") {
		t.Fatalf("two corrections for one obligation were accepted; findings=%v", findings)
	}
}

func TestADuplicateCorrectionIDIsRefused(t *testing.T) {
	findings := tamperProposalTree(t, func(tree map[string]any) {
		corrections, _ := tree["corrections"].([]any)
		first, _ := corrections[0].(map[string]any)
		second, _ := corrections[1].(map[string]any)
		second["correction_id"] = first["correction_id"]
	})
	if !hasCheck(findings, "CORRECTION_ID_UNIQUE") {
		t.Fatalf("a duplicate correction id was accepted; findings=%v", findings)
	}
}

func TestACorrectionForAnObligationOutsideTheCatalogIsRefused(t *testing.T) {
	findings := tamperProposal(t, func(correction map[string]any) bool {
		correction["obligation_id"] = "obligation.invented-for-the-occasion"
		return true
	})
	if !hasCheck(findings, "OBLIGATION_IS_IN_THE_CATALOG") {
		t.Fatalf("a correction for an obligation outside the 24 was accepted; findings=%v", findings)
	}
}

// TestFlippingTheResolverCeilingInTheInputRefusesTheWholeReport is the
// strongest form of the ceiling check, and the only invariant a real input can
// break. Someone who marks a migration binding rust_identity_verified without
// ever running the resolver does not get a slightly better number; they get no
// report at all.
func TestFlippingTheResolverCeilingInTheInputRefusesTheWholeReport(t *testing.T) {
	root := sandbox(t)
	rewriteJSON(t, root, ProofTargetsPath, func(tree map[string]any) {
		targets, _ := tree["targets"].([]any)
		first, _ := targets[0].(map[string]any)
		bindings, _ := first["migration_bindings"].([]any)
		binding, _ := bindings[0].(map[string]any)
		binding["rust_identity_verified"] = true
	})
	_, err := DeriveReport(root)
	if err == nil {
		t.Fatal("DeriveReport produced a report after a migration binding claimed resolver verification the plan does not record")
	}
	if !strings.Contains(err.Error(), "NH11") {
		t.Fatalf("the refusal was not the resolver-ceiling invariant: %v", err)
	}
}

// TestMarkingAPlannedSymbolResolverVerifiedRefusesTheWholeReport is the same
// attack from the other direction: the plan's own production symbols.
func TestMarkingAPlannedSymbolResolverVerifiedRefusesTheWholeReport(t *testing.T) {
	root := sandbox(t)
	rewriteJSON(t, root, ProofTargetsPath, func(tree map[string]any) {
		targets, _ := tree["targets"].([]any)
		first, _ := targets[0].(map[string]any)
		symbols, _ := first["production_symbols"].([]any)
		symbol, _ := symbols[0].(map[string]any)
		resolution, _ := symbol["resolution"].(map[string]any)
		resolution["state"] = "RESOLVER_VERIFIED"
		resolution["resolved_symbol"] = "ws_core::framing::Draft6455::decode_frame_header"
	})
	_, err := DeriveReport(root)
	if err == nil {
		t.Fatal("DeriveReport produced a report after a planned symbol claimed resolver verification the plan does not record")
	}
	if !strings.Contains(err.Error(), "NH11") {
		t.Fatalf("the refusal was not the resolver-ceiling invariant: %v", err)
	}
}
