package divergencesweep

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// LedgerPath is the committed behavior-delta ledger. This package only READS
// it. The ledger is append-only with a frozen prefix and is edited by a
// different track; proposals from this sweep are drafted under
// drafts/ledger-proposals/ instead.
const LedgerPath = "evidence/java/behavior-delta-ledger.json"

// RegisterPath is the committed behaviour-class divergence register produced
// with the run.
const RegisterPath = EvidenceRoot + "/comparison/behavior-class-divergences.json"

type ledgerFile struct {
	Records []struct {
		Sequence int `json:"sequence"`
		Delta    struct {
			SubjectRef   string   `json:"subject_ref"`
			DeltaID      string   `json:"delta_id"`
			AutobahnRefs []string `json:"autobahn_refs"`
		} `json:"delta"`
	} `json:"records"`
}

// LedgerSubjectRefs reads the committed ledger and returns, for every record,
// its subject_ref keyed to its sequence.
func LedgerSubjectRefs(root string) (map[string]int, error) {
	data, err := os.ReadFile(filepath.Join(root, LedgerPath))
	if err != nil {
		return nil, fmt.Errorf("behavior-delta ledger: %w", err)
	}
	var ledger ledgerFile
	if err := decodeJSON(data, &ledger); err != nil {
		return nil, fmt.Errorf("behavior-delta ledger: %w", err)
	}
	if len(ledger.Records) == 0 {
		return nil, fmt.Errorf("behavior-delta ledger holds no records")
	}
	refs := map[string]int{}
	for _, record := range ledger.Records {
		refs[record.Delta.SubjectRef] = record.Sequence
	}
	return refs, nil
}

type registerFile struct {
	Entries []struct {
		CaseID         string `json:"case_id"`
		Role           string `json:"role"`
		LedgerSequence int    `json:"ledger_sequence"`
	} `json:"entries"`
}

// RegisteredBehaviourClassDivergences reads the committed behaviour-class
// divergence register and returns its case identities per subject role,
// together with the ledger sequence each entry cites.
func RegisteredBehaviourClassDivergences(root string) (map[string][]string, map[string]int, error) {
	data, err := os.ReadFile(filepath.Join(root, RegisterPath))
	if err != nil {
		return nil, nil, fmt.Errorf("behaviour-class divergence register: %w", err)
	}
	var register registerFile
	if err := decodeJSON(data, &register); err != nil {
		return nil, nil, fmt.Errorf("behaviour-class divergence register: %w", err)
	}
	if len(register.Entries) == 0 {
		return nil, nil, fmt.Errorf("behaviour-class divergence register holds no entries")
	}
	cases := map[string][]string{}
	sequences := map[string]int{}
	for _, entry := range register.Entries {
		cases[entry.Role] = append(cases[entry.Role], entry.CaseID)
		sequences[entry.Role+"/"+entry.CaseID] = entry.LedgerSequence
	}
	for role := range cases {
		sort.Strings(cases[role])
	}
	return cases, sequences, nil
}
