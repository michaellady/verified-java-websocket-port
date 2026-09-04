package formalcoverage

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// CorroborationCode names how strongly one Java citation's file identity is
// backed by something other than the pinned tree itself. The vocabulary is
// closed and each code is asserted EXACTLY: a citation labelled
// PINNED_SOURCE_ONLY whose digest is in fact corroborated is refused, and so is
// a citation claiming corroboration that no other artifact supplies. Labels
// that can only be too weak are as bad as labels that can only be too strong;
// both let existence stand in for identity.
const (
	CorroborationProofTargets = "PROOF_TARGETS_JAVA_AUTHORITY"
	CorroborationReceipt      = "JAVABIND_RECEIPT_SOURCE_CONSTRUCT"
	CorroborationPinnedOnly   = "PINNED_SOURCE_ONLY"
)

// Citation is one file:line reading of the pinned Java tree.
type Citation struct {
	File                 string  `json:"file"`
	StartLine            int     `json:"start_line"`
	EndLine              int     `json:"end_line"`
	FileSHA256           string  `json:"file_sha256"`
	SpanSHA256           *string `json:"span_sha256"`
	StructureFingerprint *string `json:"structure_fingerprint"`
	Corroboration        string  `json:"corroboration"`
	CorroboratingMember  string  `json:"corroborating_proof_target_member,omitempty"`
	Effect               string  `json:"effect_at_these_lines"`
}

// ChainMember is one construct a correction proposes in place of the catalog's.
type ChainMember struct {
	Role              string   `json:"role"`
	ProductionSymbol  string   `json:"production_symbol"`
	JavaKey           string   `json:"java_key"`
	BindableNow       bool     `json:"bindable_under_current_resolver"`
	NotBindableReason string   `json:"not_bindable_reason"`
	Citation          Citation `json:"citation"`
}

// AdapterCitation points at this laboratory's own adapter, when the defect is
// that the adapter shadows the declared symbol rather than that the symbol is
// wrong about the library.
type AdapterCitation struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Effect    string `json:"effect_at_these_lines"`
}

// Correction is one proposed catalog correction.
type Correction struct {
	CorrectionID        string `json:"correction_id"`
	ObligationID        string `json:"obligation_id"`
	ObligationStatement string `json:"obligation_statement"`
	DefectFamily        string `json:"defect_family"`
	Current             struct {
		ProductionSymbol string           `json:"production_symbol"`
		JavaKey          string           `json:"java_key"`
		DefectClass      string           `json:"defect_class"`
		Citations        []Citation       `json:"citations"`
		WhyWrong         string           `json:"why_wrong"`
		AdapterCitation  *AdapterCitation `json:"adapter_citation,omitempty"`
	} `json:"current"`
	Proposed struct {
		DescriptorNote string        `json:"descriptor_note"`
		Chain          []ChainMember `json:"chain"`
	} `json:"proposed"`
	Effect struct {
		WouldBind      string   `json:"would_bind"`
		ResidualGap    string   `json:"residual_gap"`
		WouldMapOnto   []string `json:"would_map_onto_targets"`
		TargetSymbolID string   `json:"target_symbol_id"`
	} `json:"effect_if_adopted"`
}

// CorrectionProposal is the whole authored proposal document.
type CorrectionProposal struct {
	SchemaVersion string `json:"schema_version"`
	DocumentID    string `json:"document_id"`
	Statement     string `json:"statement"`
	Immutability  struct {
		CatalogPath     string   `json:"catalog_path"`
		CatalogSHA256   string   `json:"catalog_sha256"`
		CatalogGitBlob  string   `json:"catalog_git_blob"`
		ModifiesCatalog bool     `json:"this_document_modifies_the_catalog"`
		Rule            string   `json:"rule"`
		WhyRight        []string `json:"why_the_constraint_is_right"`
	} `json:"immutability"`
	PinnedSource struct {
		ArchiveSHA256  string `json:"archive_sha256"`
		TreeDirectory  string `json:"tree_directory"`
		SourceRevision string `json:"source_revision"`
		SourceRoot     string `json:"source_root"`
	} `json:"pinned_source"`
	Corrections []Correction `json:"corrections"`
	NotClaims   []string     `json:"not_claims"`
}

// ExpectedCorrections is how many corrections the proposal must carry. It is a
// constant so that quietly dropping one — the easiest way to make a report look
// better — fails instead of shrinking a list nobody counted.
const ExpectedCorrections = 5

// DecodeCorrectionProposal reads the proposal.
func DecodeCorrectionProposal(data []byte) (CorrectionProposal, error) {
	var proposal CorrectionProposal
	if err := json.Unmarshal(data, &proposal); err != nil {
		return CorrectionProposal{}, fmt.Errorf("formalcoverage: decode correction proposal: %w", err)
	}
	if proposal.DocumentID != "us023-catalog-correction-proposal" {
		return CorrectionProposal{}, fmt.Errorf("formalcoverage: correction proposal id is %q", proposal.DocumentID)
	}
	return proposal, nil
}

// receiptFileDigests reads the Java receipt's per-construct file digests. These
// are the file identities an executed lane already stood behind.
func receiptFileDigests(data []byte) (map[string]bool, error) {
	var receipt struct {
		SourceConstructs []struct {
			SourceFile string `json:"source_file"`
			FileSHA256 string `json:"file_sha256"`
		} `json:"source_constructs"`
	}
	if err := json.Unmarshal(data, &receipt); err != nil {
		return nil, fmt.Errorf("formalcoverage: decode receipt: %w", err)
	}
	digests := map[string]bool{}
	for _, construct := range receipt.SourceConstructs {
		digests[construct.FileSHA256] = true
	}
	return digests, nil
}

// CorrectionFinding is one refusal. Findings are returned as a list rather than
// as the first error, so a reviewer sees every defect in one pass.
type CorrectionFinding struct {
	CorrectionID string `json:"correction_id"`
	Check        string `json:"check"`
	Detail       string `json:"detail"`
}

// VerifyCorrections checks every claim the proposal makes that can be checked
// without the quarantined Java tree. The tree-dependent claims — the line
// numbers, byte spans, span digests, structure fingerprints, parameter lists,
// return types and the two ambiguity refusals — are recomputed from the pinned
// tree by the formalcovere2e lane, which is stated here rather than left to be
// discovered.
func VerifyCorrections(root string) ([]CorrectionFinding, CorrectionProposal, error) {
	proposalBytes, _, err := LoadArtifact(root, CorrectionPath)
	if err != nil {
		return nil, CorrectionProposal{}, err
	}
	proposal, err := DecodeCorrectionProposal(proposalBytes)
	if err != nil {
		return nil, CorrectionProposal{}, err
	}
	catalogBytes, catalogIdentity, err := LoadArtifact(root, CatalogPath)
	if err != nil {
		return nil, proposal, err
	}
	catalog, err := DecodeCatalog(catalogBytes)
	if err != nil {
		return nil, proposal, err
	}
	specBytes, _, err := LoadArtifact(root, BindingSpecPath)
	if err != nil {
		return nil, proposal, err
	}
	spec, err := DecodeBindingSpec(specBytes)
	if err != nil {
		return nil, proposal, err
	}
	planBytes, _, err := LoadArtifact(root, ProofTargetsPath)
	if err != nil {
		return nil, proposal, err
	}
	plan, err := DecodeProofTargets(planBytes)
	if err != nil {
		return nil, proposal, err
	}
	receiptBytes, _, err := LoadArtifact(root, ReceiptPath)
	if err != nil {
		return nil, proposal, err
	}
	receiptDigests, err := receiptFileDigests(receiptBytes)
	if err != nil {
		return nil, proposal, err
	}

	planDigests := map[string]bool{}
	planMembers := map[string]bool{}
	planTargets := map[string]bool{}
	planSymbolIDs := map[string]bool{}
	for _, target := range plan.Targets {
		planTargets[target.TargetID] = true
		for _, anchor := range target.JavaAuthority {
			planDigests[anchor.SHA256] = true
		}
		for _, symbol := range target.ProductionSymbols {
			planSymbolIDs[symbol.SymbolID] = true
			for _, member := range symbol.JavaAuthorityMember {
				planMembers[member] = true
			}
		}
	}

	var findings []CorrectionFinding
	add := func(id, check, format string, args ...any) {
		findings = append(findings, CorrectionFinding{CorrectionID: id, Check: check, Detail: fmt.Sprintf(format, args...)})
	}

	// The proposal must not have edited the thing it proposes to correct.
	if catalogIdentity.SHA256 != CatalogSHA256 || catalogIdentity.GitBlob != CatalogGitBlob {
		add("", "CATALOG_STILL_VENDORED_BYTES",
			"catalog on disk is %s/%s, not the vendored %s/%s", catalogIdentity.SHA256, catalogIdentity.GitBlob, CatalogSHA256, CatalogGitBlob)
	}
	if proposal.Immutability.CatalogSHA256 != CatalogSHA256 || proposal.Immutability.CatalogGitBlob != CatalogGitBlob {
		add("", "PROPOSAL_ECHOES_THE_VENDORED_IDENTITY",
			"proposal pins %s/%s", proposal.Immutability.CatalogSHA256, proposal.Immutability.CatalogGitBlob)
	}
	if proposal.Immutability.ModifiesCatalog {
		add("", "PROPOSAL_DOES_NOT_MODIFY_THE_CATALOG", "the proposal declares that it modifies the catalog")
	}
	if len(proposal.Corrections) != ExpectedCorrections {
		add("", "CORRECTION_COUNT", "proposal carries %d corrections, not %d", len(proposal.Corrections), ExpectedCorrections)
	}

	seenIDs := map[string]bool{}
	seenObligations := map[string]bool{}
	for _, correction := range proposal.Corrections {
		id := correction.CorrectionID
		if seenIDs[id] {
			add(id, "CORRECTION_ID_UNIQUE", "duplicate correction id")
		}
		seenIDs[id] = true
		if seenObligations[correction.ObligationID] {
			add(id, "ONE_CORRECTION_PER_OBLIGATION", "obligation %q already corrected", correction.ObligationID)
		}
		seenObligations[correction.ObligationID] = true

		// The obligation must exist, and the proposal must quote it verbatim.
		var obligation CatalogObligation
		found := false
		for _, row := range catalog.Obligations {
			if row.ObligationID == correction.ObligationID {
				obligation, found = row, true
				break
			}
		}
		if !found {
			add(id, "OBLIGATION_IS_IN_THE_CATALOG", "%q is not one of the 24", correction.ObligationID)
			continue
		}
		if correction.ObligationStatement != obligation.Statement {
			add(id, "OBLIGATION_STATEMENT_QUOTED_VERBATIM",
				"proposal says %q, catalog says %q", correction.ObligationStatement, obligation.Statement)
		}

		// The current symbol must be the catalog's, byte for byte.
		binding, ok := catalog.JavaBinding(correction.ObligationID)
		if !ok {
			add(id, "CATALOG_HAS_A_JAVA_BINDING", "no java binding for %q", correction.ObligationID)
			continue
		}
		if correction.Current.ProductionSymbol != binding.ProductionSymbol {
			add(id, "CURRENT_SYMBOL_ECHOES_THE_CATALOG",
				"proposal says %q, catalog says %q", correction.Current.ProductionSymbol, binding.ProductionSymbol)
		}
		if want := string(CatalogJavaKey(binding.ProductionSymbol)); correction.Current.JavaKey != want {
			add(id, "CURRENT_JAVA_KEY_IS_DERIVED_FROM_THE_CATALOG_SYMBOL",
				"proposal says %q, the catalog symbol derives %q", correction.Current.JavaKey, want)
		}

		// The defect class must be the one the Java lane already recorded, so
		// the proposal cannot invent a defect the binding lane never found.
		reason, _, hasReason := spec.UnboundReason(correction.ObligationID)
		if !hasReason {
			add(id, "DEFECT_CLASS_MATCHES_THE_BINDING_LANE", "the binding spec records no unbound reason for %q", correction.ObligationID)
		} else if correction.Current.DefectClass != reason {
			add(id, "DEFECT_CLASS_MATCHES_THE_BINDING_LANE",
				"proposal says %q, the binding spec says %q", correction.Current.DefectClass, reason)
		}

		if len(correction.Current.Citations) == 0 {
			add(id, "CURRENT_DEFECT_IS_CITED", "no citation proves the declared symbol cannot carry the obligation")
		}
		for index, citation := range correction.Current.Citations {
			checkCitation(add, id, fmt.Sprintf("current.citations[%d]", index), citation, planDigests, planMembers, receiptDigests)
		}

		// The proposal must actually propose something different.
		if len(correction.Proposed.Chain) == 0 {
			add(id, "PROPOSAL_NAMES_A_REPLACEMENT", "the proposed chain is empty")
		}
		for index, member := range correction.Proposed.Chain {
			label := fmt.Sprintf("proposed.chain[%d]", index)
			if member.ProductionSymbol == binding.ProductionSymbol {
				add(id, "PROPOSED_SYMBOL_DIFFERS_FROM_THE_CURRENT_ONE",
					"%s proposes the symbol the catalog already declares", label)
			}
			if want := string(CatalogJavaKey(member.ProductionSymbol)); member.JavaKey != want {
				add(id, "PROPOSED_JAVA_KEY_IS_DERIVED_FROM_THE_PROPOSED_SYMBOL",
					"%s says %q, its own symbol derives %q", label, member.JavaKey, want)
			}
			if !member.BindableNow && strings.TrimSpace(member.NotBindableReason) == "" {
				add(id, "UNBINDABLE_MEMBER_STATES_WHY",
					"%s is not bindable under the current resolver and gives no reason", label)
			}
			if member.BindableNow && strings.TrimSpace(member.NotBindableReason) != "" {
				add(id, "BINDABLE_MEMBER_CARRIES_NO_EXCUSE",
					"%s is bindable yet carries a not-bindable reason", label)
			}
			checkCitation(add, id, label+".citation", member.Citation, planDigests, planMembers, receiptDigests)
		}

		// A correction that promised the obligation would connect would be the
		// exact over-claim this programme forbids, so the vocabulary excludes it.
		switch correction.Effect.WouldBind {
		case "PARTIAL_AT_BEST", "STILL_UNBINDABLE_THROUGH_THE_CURRENT_ADAPTER":
		default:
			add(id, "EFFECT_VOCABULARY_IS_CLOSED_AND_CLAIMS_NO_CONNECTION",
				"would_bind is %q, which is not one of the two honest outcomes", correction.Effect.WouldBind)
		}
		if strings.TrimSpace(correction.Effect.ResidualGap) == "" {
			add(id, "EVERY_CORRECTION_STATES_ITS_RESIDUAL_GAP", "residual_gap is empty")
		}
		for _, target := range correction.Effect.WouldMapOnto {
			if !planTargets[target] {
				add(id, "PROJECTED_TARGET_EXISTS", "would_map_onto_targets names %q, which is not a proof target", target)
			}
		}
		if correction.Effect.TargetSymbolID != "" && !planSymbolIDs[correction.Effect.TargetSymbolID] {
			add(id, "PROJECTED_TARGET_SYMBOL_EXISTS", "target_symbol_id %q is in no proof target", correction.Effect.TargetSymbolID)
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].CorrectionID != findings[j].CorrectionID {
			return findings[i].CorrectionID < findings[j].CorrectionID
		}
		return findings[i].Check < findings[j].Check
	})
	return findings, proposal, nil
}

// checkCitation enforces the corroboration vocabulary exactly in both
// directions.
func checkCitation(add func(string, string, string, ...any), id, label string, citation Citation,
	planDigests, planMembers, receiptDigests map[string]bool) {
	inPlan := planDigests[citation.FileSHA256]
	inReceipt := receiptDigests[citation.FileSHA256]
	switch citation.Corroboration {
	case CorroborationProofTargets:
		if !inPlan {
			add(id, "CORROBORATION_LABEL_IS_EXACT",
				"%s claims proof-target corroboration but %s pins no such file digest", label, ProofTargetsPath)
		}
		if citation.CorroboratingMember != "" && !planMembers[citation.CorroboratingMember] {
			add(id, "CORROBORATING_MEMBER_APPEARS_VERBATIM",
				"%s names member %q, which appears in no java_authority_members list", label, citation.CorroboratingMember)
		}
	case CorroborationReceipt:
		if !inReceipt {
			add(id, "CORROBORATION_LABEL_IS_EXACT",
				"%s claims receipt corroboration but %s pins no such file digest", label, ReceiptPath)
		}
	case CorroborationPinnedOnly:
		if inPlan || inReceipt {
			add(id, "CORROBORATION_LABEL_IS_EXACT",
				"%s claims to rest on the pinned source alone, but its file digest IS corroborated elsewhere in the tree", label)
		}
		if citation.CorroboratingMember != "" {
			add(id, "CORROBORATION_LABEL_IS_EXACT",
				"%s claims no corroboration yet names a corroborating member", label)
		}
	default:
		add(id, "CORROBORATION_VOCABULARY_IS_CLOSED", "%s uses unknown corroboration %q", label, citation.Corroboration)
	}
	if citation.StartLine <= 0 || citation.EndLine < citation.StartLine {
		add(id, "CITATION_LINES_ARE_A_REAL_RANGE", "%s cites lines %d-%d", label, citation.StartLine, citation.EndLine)
	}
	if !strings.HasPrefix(citation.FileSHA256, "sha256:") || len(citation.FileSHA256) != len("sha256:")+64 {
		add(id, "CITATION_FILE_DIGEST_IS_WELL_FORMED", "%s file digest %q", label, citation.FileSHA256)
	}
	if strings.TrimSpace(citation.Effect) == "" {
		add(id, "CITATION_STATES_WHAT_IS_AT_THOSE_LINES", "%s carries no effect statement", label)
	}
}
