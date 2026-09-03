package formalcoverage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// PlaneCorrespondencePath is the authored record of what is, and is not, known
// about the relationship between the plane the vendored catalog is ABOUT and
// the plane it is being read ON.
const PlaneCorrespondencePath = "assurance/formal/plane-correspondence.json"

// Correspondence states. The vocabulary is closed and only ONE of these states
// authorises measuring this plane against a Codex-plane obligation:
// ESTABLISHED_BY_OWNER_DECISION, which additionally requires a decision record
// that exists and names the mapping. The others each say something true and
// weaker.
//
// The distinction this vocabulary exists to keep is between a correspondence
// that has been DECIDED and one that merely LOOKS plausible. `websocket_core`
// and `ws_core` are two names for crates that descend from one scaffold; that
// is shared ancestry, and it is not permission to read a proof about one as a
// proof about the other. Collapsing the two would be a name-normalising rule
// applied silently, which is the defect this whole document exists to refuse.
const (
	// The owner has decided that the two are the same subject for the purpose
	// of measurement, and a decision record says so.
	CorrespondenceEstablished = "ESTABLISHED_BY_OWNER_DECISION"
	// The two crates descend from one scaffold in this repository's own
	// history, and the planes' contents have diverged since. Ancestry is a
	// fact about commits, not about behaviour.
	CorrespondenceAncestryOnly = "SHARED_ANCESTRY_ONLY"
	// A borrow receipt records this plane adapting that plane's file. The
	// receipts say "adapted", never "identical", and several say "studied, NOT
	// grafted"; an adaptation is weaker than an identity by construction.
	CorrespondenceBorrowAdapted = "BORROW_RECEIPT_RECORDS_AN_ADAPTATION"
	// Nothing on this plane is recorded as the counterpart. This covers both
	// "there is nothing here" and the more dangerous "there is something here
	// that looks like it" -- a resemblance nobody wrote down is not a mapping.
	CorrespondenceNone = "NO_RECORDED_CORRESPONDENCE_ON_THIS_PLANE"
)

// correspondenceStates is the closed set, so an unknown state is refused rather
// than treated as one of the weak ones.
var correspondenceStates = map[string]bool{
	CorrespondenceEstablished:   true,
	CorrespondenceAncestryOnly:  true,
	CorrespondenceBorrowAdapted: true,
	CorrespondenceNone:          true,
}

// AuthorisesMeasurement reports whether a correspondence state permits reading
// an obligation written about the origin plane as an obligation about this one.
// Exactly one state does.
func AuthorisesMeasurement(state string) bool { return state == CorrespondenceEstablished }

// PlaneIdentity names one plane by the ref and commit it was read at.
type PlaneIdentity struct {
	Name      string `json:"name"`
	Ref       string `json:"ref"`
	Commit    string `json:"commit"`
	Writable  bool   `json:"writable_from_here"`
	Statement string `json:"statement"`
}

// PlaneCrateRow is one catalog namespace, and what this plane has instead.
type PlaneCrateRow struct {
	CatalogNamespace     string   `json:"catalog_namespace"`
	ObligationCount      int      `json:"obligation_count"`
	OriginPlaneDirectory string   `json:"origin_plane_directory"`
	OriginPlaneLibName   string   `json:"origin_plane_lib_name"`
	CandidateDirectory   string   `json:"candidate_directory_on_this_plane"`
	CandidateLibName     string   `json:"candidate_lib_name_on_this_plane"`
	State                string   `json:"correspondence_state"`
	OwnerDecision        string   `json:"owner_decision_record,omitempty"`
	OwnerDecisionKey     string   `json:"owner_decision_key,omitempty"`
	Evidence             []string `json:"evidence"`
	WhyNotAnIdentity     string   `json:"why_this_is_not_an_identity"`
}

// PlanePathRow is one catalog source path, and what this plane has instead.
type PlanePathRow struct {
	CatalogSourcePath string   `json:"catalog_source_path"`
	ObligationCount   int      `json:"obligation_count"`
	ExistsHere        bool     `json:"catalog_path_exists_on_this_plane"`
	Candidate         string   `json:"candidate_path_on_this_plane"`
	CandidateExists   bool     `json:"candidate_path_exists_on_this_plane"`
	State             string   `json:"correspondence_state"`
	OwnerDecision     string   `json:"owner_decision_record,omitempty"`
	OwnerDecisionKey  string   `json:"owner_decision_key,omitempty"`
	Evidence          []string `json:"evidence"`
	WhyNotAnIdentity  string   `json:"why_this_is_not_an_identity"`
}

// PlaneSymbolRow is one catalog production symbol and the nearest thing this
// plane declares, cited at a line so the claim can be checked rather than read.
type PlaneSymbolRow struct {
	CatalogSymbol    string `json:"catalog_production_symbol"`
	ObligationCount  int    `json:"obligation_count"`
	NearestFile      string `json:"nearest_declaration_file_on_this_plane"`
	NearestLine      int    `json:"nearest_declaration_line"`
	NearestText      string `json:"nearest_declaration_text"`
	State            string `json:"correspondence_state"`
	OwnerDecision    string `json:"owner_decision_record,omitempty"`
	OwnerDecisionKey string `json:"owner_decision_key,omitempty"`
	Difference       string `json:"difference_that_defeats_substitution"`
}

// PlaneCorrespondence is the whole authored record.
type PlaneCorrespondence struct {
	SchemaVersion string `json:"schema_version"`
	DocumentID    string `json:"document_id"`
	EntityType    string `json:"entity_type"`
	Statement     string `json:"statement"`
	Catalog       struct {
		Path    string `json:"path"`
		SHA256  string `json:"sha256"`
		GitBlob string `json:"git_blob"`
	} `json:"catalog"`
	OriginPlane      PlaneIdentity    `json:"origin_plane"`
	ThisPlane        PlaneIdentity    `json:"this_plane"`
	Crates           []PlaneCrateRow  `json:"crates"`
	Paths            []PlanePathRow   `json:"source_paths"`
	Symbols          []PlaneSymbolRow `json:"production_symbols"`
	OwnerQuestion    string           `json:"owner_question"`
	EvidenceRequired []string         `json:"evidence_required_to_answer_it"`
	NotClaims        []string         `json:"not_claims"`
}

// DecodePlaneCorrespondence reads the record.
func DecodePlaneCorrespondence(data []byte) (PlaneCorrespondence, error) {
	var doc PlaneCorrespondence
	if err := json.Unmarshal(data, &doc); err != nil {
		return PlaneCorrespondence{}, fmt.Errorf("formalcoverage: decode plane correspondence: %w", err)
	}
	if doc.DocumentID != "us023-plane-correspondence" {
		return PlaneCorrespondence{}, fmt.Errorf("formalcoverage: plane correspondence id is %q", doc.DocumentID)
	}
	return doc, nil
}

// PlaneFinding is one refusal, in the same shape as a correction finding.
type PlaneFinding struct {
	Subject string `json:"subject"`
	Check   string `json:"check"`
	Detail  string `json:"detail"`
}

// VerifyPlaneCorrespondence recomputes every claim in the record that can be
// recomputed from the two trees this process can read, and refuses the rest.
//
// What it CANNOT check is stated rather than left to be discovered: the origin
// plane is read-only from here and is not required to be fetched, so the
// origin-plane columns (directory, lib name, commit) are asserted provenance,
// not recomputed. Everything about THIS plane is recomputed, and every claim of
// an established correspondence must produce a decision record that exists.
func VerifyPlaneCorrespondence(root string) ([]PlaneFinding, PlaneCorrespondence, error) {
	docBytes, _, err := LoadArtifact(root, PlaneCorrespondencePath)
	if err != nil {
		return nil, PlaneCorrespondence{}, err
	}
	doc, err := DecodePlaneCorrespondence(docBytes)
	if err != nil {
		return nil, PlaneCorrespondence{}, err
	}
	catalogBytes, catalogIdentity, err := LoadArtifact(root, CatalogPath)
	if err != nil {
		return nil, doc, err
	}
	catalog, err := DecodeCatalog(catalogBytes)
	if err != nil {
		return nil, doc, err
	}

	var findings []PlaneFinding
	add := func(subject, check, format string, args ...any) {
		findings = append(findings, PlaneFinding{Subject: subject, Check: check, Detail: fmt.Sprintf(format, args...)})
	}

	// The record must be about the catalog that is actually on disk, and that
	// catalog must still be the vendored one.
	if catalogIdentity.SHA256 != CatalogSHA256 || catalogIdentity.GitBlob != CatalogGitBlob {
		add("", "CATALOG_STILL_VENDORED_BYTES",
			"catalog on disk is %s/%s, not the vendored %s/%s", catalogIdentity.SHA256, catalogIdentity.GitBlob, CatalogSHA256, CatalogGitBlob)
	}
	if doc.Catalog.SHA256 != CatalogSHA256 || doc.Catalog.GitBlob != CatalogGitBlob {
		add("", "RECORD_ECHOES_THE_VENDORED_IDENTITY",
			"the record pins %s/%s", doc.Catalog.SHA256, doc.Catalog.GitBlob)
	}
	if doc.OriginPlane.Writable {
		add("", "ORIGIN_PLANE_IS_NOT_WRITABLE_FROM_HERE", "the record declares the origin plane writable from here")
	}

	// --- the catalog's own three groupings, counted from the catalog -------
	namespaceCounts := map[string]int{}
	pathCounts := map[string]int{}
	symbolCounts := map[string]int{}
	for _, binding := range catalog.RustBindings {
		namespaceCounts[strings.Split(binding.ProductionSymbol, "::")[0]]++
		pathCounts[binding.SourcePath]++
		symbolCounts[binding.ProductionSymbol]++
	}

	checkOwnerDecision := func(subject, state, record, key string) {
		if state != CorrespondenceEstablished {
			if record != "" || key != "" {
				add(subject, "ONLY_AN_ESTABLISHED_ROW_CITES_AN_OWNER_DECISION",
					"state %s cites decision record %q key %q", state, record, key)
			}
			return
		}
		// An ESTABLISHED row is the one state that authorises measurement, so
		// it is the one state that must produce a record. A row that could
		// claim it for free is a name-normalising rule with extra steps.
		if strings.TrimSpace(record) == "" || strings.TrimSpace(key) == "" {
			add(subject, "ESTABLISHED_REQUIRES_A_NAMED_OWNER_DECISION",
				"the row claims %s and names record %q key %q", CorrespondenceEstablished, record, key)
			return
		}
		if !strings.HasPrefix(record, "evidence/governance/decisions/") {
			add(subject, "OWNER_DECISION_LIVES_IN_THE_PROTECTED_STORE", "record %q", record)
			return
		}
		data, _, readErr := LoadArtifact(root, record)
		if readErr != nil {
			add(subject, "OWNER_DECISION_RECORD_EXISTS", "cannot read %s: %v", record, readErr)
			return
		}
		if !strings.Contains(string(data), key) {
			add(subject, "OWNER_DECISION_RECORD_NAMES_THE_KEY", "%s does not contain %q", record, key)
		}
	}

	checkState := func(subject, state string) {
		if !correspondenceStates[state] {
			add(subject, "CORRESPONDENCE_VOCABULARY_IS_CLOSED", "unknown correspondence state %q", state)
		}
	}

	// --- crates ------------------------------------------------------------
	seenNamespaces := map[string]bool{}
	for _, row := range doc.Crates {
		subject := row.CatalogNamespace
		if seenNamespaces[subject] {
			add(subject, "ONE_ROW_PER_CATALOG_NAMESPACE", "duplicate row")
		}
		seenNamespaces[subject] = true
		want, ok := namespaceCounts[subject]
		if !ok {
			add(subject, "ROW_NAMES_A_NAMESPACE_THE_CATALOG_USES", "the catalog's Rust column never uses this namespace")
			continue
		}
		if row.ObligationCount != want {
			add(subject, "OBLIGATION_COUNT_IS_THE_CATALOG_COUNT", "record says %d, the catalog says %d", row.ObligationCount, want)
		}
		checkState(subject, row.State)
		checkOwnerDecision(subject, row.State, row.OwnerDecision, row.OwnerDecisionKey)
		// The candidate's namespace is THIS plane's, so it is recomputed from
		// this plane's manifest rather than believed.
		manifest, _, readErr := LoadArtifact(root, row.CandidateDirectory+"/Cargo.toml")
		switch {
		case row.CandidateDirectory == "":
			if row.State != CorrespondenceNone {
				add(subject, "A_ROW_WITH_NO_CANDIDATE_IS_NO_CORRESPONDENCE", "state is %s with no candidate directory", row.State)
			}
		case readErr != nil:
			add(subject, "CANDIDATE_CRATE_EXISTS_ON_THIS_PLANE", "cannot read %s/Cargo.toml: %v", row.CandidateDirectory, readErr)
		default:
			if got := CrateLibNamespace(manifest); got != row.CandidateLibName {
				add(subject, "CANDIDATE_LIB_NAME_IS_RECOMPUTED_FROM_THIS_PLANE",
					"%s/Cargo.toml ships %q, the record says %q", row.CandidateDirectory, got, row.CandidateLibName)
			}
		}
		if row.CandidateLibName == row.CatalogNamespace && row.State != CorrespondenceEstablished {
			add(subject, "AN_EQUAL_NAMESPACE_IS_NOT_SILENTLY_WEAKENED",
				"this plane ships the catalog's own namespace yet the row claims %s", row.State)
		}
		if row.State != CorrespondenceEstablished && strings.TrimSpace(row.WhyNotAnIdentity) == "" {
			add(subject, "EVERY_UNESTABLISHED_ROW_SAYS_WHY", "why_this_is_not_an_identity is empty")
		}
		if len(row.Evidence) == 0 {
			add(subject, "EVERY_ROW_CITES_ITS_EVIDENCE", "evidence list is empty")
		}
	}
	for namespace := range namespaceCounts {
		if !seenNamespaces[namespace] {
			add(namespace, "EVERY_CATALOG_NAMESPACE_HAS_A_ROW", "the record has no row for this namespace")
		}
	}

	// --- source paths ------------------------------------------------------
	seenPaths := map[string]bool{}
	for _, row := range doc.Paths {
		subject := row.CatalogSourcePath
		if seenPaths[subject] {
			add(subject, "ONE_ROW_PER_CATALOG_SOURCE_PATH", "duplicate row")
		}
		seenPaths[subject] = true
		want, ok := pathCounts[subject]
		if !ok {
			add(subject, "ROW_NAMES_A_PATH_THE_CATALOG_USES", "the catalog's Rust column never names this path")
			continue
		}
		if row.ObligationCount != want {
			add(subject, "OBLIGATION_COUNT_IS_THE_CATALOG_COUNT", "record says %d, the catalog says %d", row.ObligationCount, want)
		}
		checkState(subject, row.State)
		checkOwnerDecision(subject, row.State, row.OwnerDecision, row.OwnerDecisionKey)
		if got := pathExists(root, subject); got != row.ExistsHere {
			add(subject, "CATALOG_PATH_EXISTENCE_IS_RECOMPUTED", "record says %t, this plane says %t", row.ExistsHere, got)
		}
		if row.Candidate != "" {
			if got := pathExists(root, row.Candidate); got != row.CandidateExists {
				add(subject, "CANDIDATE_PATH_EXISTENCE_IS_RECOMPUTED",
					"record says %s exists=%t, this plane says %t", row.Candidate, row.CandidateExists, got)
			}
			if !row.CandidateExists && row.State != CorrespondenceNone {
				add(subject, "A_CANDIDATE_THAT_DOES_NOT_EXIST_IS_NO_CORRESPONDENCE",
					"state is %s with a candidate that is not on this plane", row.State)
			}
		} else if row.State != CorrespondenceNone {
			add(subject, "A_ROW_WITH_NO_CANDIDATE_IS_NO_CORRESPONDENCE", "state is %s with no candidate path", row.State)
		}
		if row.State != CorrespondenceEstablished && strings.TrimSpace(row.WhyNotAnIdentity) == "" {
			add(subject, "EVERY_UNESTABLISHED_ROW_SAYS_WHY", "why_this_is_not_an_identity is empty")
		}
		if len(row.Evidence) == 0 {
			add(subject, "EVERY_ROW_CITES_ITS_EVIDENCE", "evidence list is empty")
		}
	}
	for path := range pathCounts {
		if !seenPaths[path] {
			add(path, "EVERY_CATALOG_SOURCE_PATH_HAS_A_ROW", "the record has no row for this path")
		}
	}

	// --- production symbols -------------------------------------------------
	seenSymbols := map[string]bool{}
	for _, row := range doc.Symbols {
		subject := row.CatalogSymbol
		if seenSymbols[subject] {
			add(subject, "ONE_ROW_PER_CATALOG_SYMBOL", "duplicate row")
		}
		seenSymbols[subject] = true
		want, ok := symbolCounts[subject]
		if !ok {
			add(subject, "ROW_NAMES_A_SYMBOL_THE_CATALOG_USES", "the catalog's Rust column never declares this symbol")
			continue
		}
		if row.ObligationCount != want {
			add(subject, "OBLIGATION_COUNT_IS_THE_CATALOG_COUNT", "record says %d, the catalog says %d", row.ObligationCount, want)
		}
		checkState(subject, row.State)
		checkOwnerDecision(subject, row.State, row.OwnerDecision, row.OwnerDecisionKey)
		if strings.TrimSpace(row.Difference) == "" && row.State != CorrespondenceEstablished {
			add(subject, "EVERY_UNESTABLISHED_SYMBOL_SAYS_WHAT_DEFEATS_SUBSTITUTION", "difference is empty")
		}
		// The nearest declaration is a file:line citation of THIS plane, so it
		// is read back rather than believed. A citation nobody reads back is a
		// name; a citation checked at its line is an observation.
		if row.NearestFile == "" {
			if row.State != CorrespondenceNone {
				add(subject, "A_ROW_WITH_NO_NEAREST_DECLARATION_IS_NO_CORRESPONDENCE", "state is %s with no citation", row.State)
			}
			continue
		}
		lines, readErr := readLines(root, row.NearestFile)
		if readErr != nil {
			add(subject, "NEAREST_DECLARATION_FILE_EXISTS", "cannot read %s: %v", row.NearestFile, readErr)
			continue
		}
		if row.NearestLine <= 0 || row.NearestLine > len(lines) {
			add(subject, "NEAREST_DECLARATION_LINE_IS_IN_THE_FILE",
				"%s has %d lines, the record cites line %d", row.NearestFile, len(lines), row.NearestLine)
			continue
		}
		if got := lines[row.NearestLine-1]; got != row.NearestText {
			add(subject, "NEAREST_DECLARATION_IS_AT_THE_LINE_IT_CITES",
				"%s:%d reads %q, the record says %q", row.NearestFile, row.NearestLine, got, row.NearestText)
		}
	}
	for symbol := range symbolCounts {
		if !seenSymbols[symbol] {
			add(symbol, "EVERY_CATALOG_SYMBOL_HAS_A_ROW", "the record has no row for this symbol")
		}
	}

	if strings.TrimSpace(doc.OwnerQuestion) == "" {
		add("", "THE_RECORD_STATES_THE_OWNER_QUESTION", "owner_question is empty")
	}
	if len(doc.EvidenceRequired) == 0 {
		add("", "THE_OWNER_QUESTION_STATES_ITS_EVIDENCE_REQUIREMENT", "evidence_required_to_answer_it is empty")
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Subject != findings[j].Subject {
			return findings[i].Subject < findings[j].Subject
		}
		return findings[i].Check < findings[j].Check
	})
	return findings, doc, nil
}

// PlaneStates is the lookup the reconciliation and the report use: catalog
// namespace and catalog source path to correspondence state.
type PlaneStates struct {
	ByNamespace map[string]string
	ByPath      map[string]string
	BySymbol    map[string]string
}

// States indexes the record.
func (doc PlaneCorrespondence) States() PlaneStates {
	states := PlaneStates{
		ByNamespace: map[string]string{},
		ByPath:      map[string]string{},
		BySymbol:    map[string]string{},
	}
	for _, row := range doc.Crates {
		states.ByNamespace[row.CatalogNamespace] = row.State
	}
	for _, row := range doc.Paths {
		states.ByPath[row.CatalogSourcePath] = row.State
	}
	for _, row := range doc.Symbols {
		states.BySymbol[row.CatalogSymbol] = row.State
	}
	return states
}

func pathExists(root, relative string) bool {
	_, err := os.Stat(filepath.Join(root, filepath.FromSlash(relative)))
	return err == nil
}

func readLines(root, relative string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n"), nil
}
