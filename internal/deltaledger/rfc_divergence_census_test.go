package deltaledger

// The public-corpus RFC-divergence census.
//
// WHY IT EXISTS. The reserved-bit ready-state divergence (us005.pub.0005
// /final_state) was found by a cross-plane audit reading another plane's
// manifest by hand. No gate on this plane would have found it. Worse, once
// found, sweeping the corpus for the same predicate showed it was not one
// scenario but nineteen — so the hand-audit found roughly five percent of the
// class it had stumbled into.
//
// This census closes that. It enumerates the public-corpus propositions where
// the port follows the pinned Java oracle over an RFC-strict reading, and
// requires every one to carry a ledger record. Two properties make it a gate
// rather than a document:
//
//   - COMPLETENESS is re-derived, not asserted. The protocol-rejection class
//     is swept from corpora/public/scenarios.jsonl and the live transcript on
//     every run, so a new corpus scenario that falls in the class fails the
//     suite until it is enrolled.
//   - COVERAGE is enforced. Every row must name a ledger delta that actually
//     resolves, so observing a new divergence refuses the gate until it is
//     ledgered — the same polarity as the observed-disagreement set.
//
// It is deliberately sourced from OUR evidence only. The Codex plane holds a
// comparable artifact (evidence/oracle-hierarchy.json), and making our gate
// read it would couple the planes and let their normative choices silently
// become ours. The two planes disagree at this exact pointer on purpose; that
// disagreement has to stay separately auditable.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const censusRelativePath = "evidence/us005-public-rfc-divergence-census.json"

type censusEntry struct {
	ScenarioID           string   `json:"scenario_id"`
	Pointer              string   `json:"pointer"`
	Family               string   `json:"family"`
	Class                string   `json:"class"`
	Derivation           string   `json:"derivation"`
	RFCClauses           []string `json:"rfc_clauses"`
	RFCStrictExpectation string   `json:"rfc_strict_expectation"`
	RecordedObservable   string   `json:"recorded_observable"`
	RecordedCloseCode    int      `json:"recorded_close_code"`
	PortFollows          string   `json:"port_follows"`
	JavaEntryPointNote   string   `json:"java_entry_point_note"`
	LedgerDeltaID        string   `json:"ledger_delta_id"`
	Evidence             []string `json:"evidence"`
}

type censusDocument struct {
	SchemaVersion string        `json:"schema_version"`
	EvidenceKind  string        `json:"evidence_kind"`
	Statement     string        `json:"statement"`
	Completeness  string        `json:"completeness"`
	Entries       []censusEntry `json:"entries"`
}

// protocolRejectionClass is the class whose membership is decided mechanically.
const protocolRejectionClass = "protocol-rejection-readystate"

func readCensus(t *testing.T) censusDocument {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(ledgerTestRepoRoot, filepath.FromSlash(censusRelativePath)))
	if err != nil {
		t.Fatalf("read %s: %v", censusRelativePath, err)
	}
	var document censusDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("decode %s: %v", censusRelativePath, err)
	}
	if document.SchemaVersion != "1.0.0" || document.EvidenceKind != "public-rfc-divergence-census" {
		t.Fatalf("census envelope drifted: version=%q kind=%q", document.SchemaVersion, document.EvidenceKind)
	}
	if len(document.Entries) == 0 {
		t.Fatalf("%s has no entries; the gate would be vacuous", censusRelativePath)
	}
	return document
}

type publicScenario struct {
	ScenarioID string `json:"scenario_id"`
	Family     string `json:"family"`
	Expected   struct {
		Outcome    string `json:"outcome"`
		FinalState string `json:"final_state"`
		Error      *struct {
			CloseCode int `json:"close_code"`
		} `json:"error"`
	} `json:"expected"`
}

func readPublicScenarios(t *testing.T) []publicScenario {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(ledgerTestRepoRoot, "corpora", "public", "scenarios.jsonl"))
	if err != nil {
		t.Fatalf("read public corpus: %v", err)
	}
	var scenarios []publicScenario
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var scenario publicScenario
		if err := json.Unmarshal([]byte(line), &scenario); err != nil {
			t.Fatalf("decode a public scenario: %v", err)
		}
		scenarios = append(scenarios, scenario)
	}
	if len(scenarios) == 0 {
		t.Fatal("public corpus yielded no scenarios")
	}
	return scenarios
}

// inProtocolRejectionClass is the sweep predicate, stated once so the census
// artifact and this test cannot drift on what the class means.
func inProtocolRejectionClass(scenario publicScenario) bool {
	if scenario.Expected.Outcome != "error" || scenario.Expected.FinalState != "open" {
		return false
	}
	if scenario.Expected.Error == nil {
		return false
	}
	switch scenario.Expected.Error.CloseCode {
	case 1002, 1007, 1009:
		return true
	}
	return false
}

// TestProtocolRejectionClassIsEnumeratedCompletely re-derives the class from
// the committed corpus and requires the census to enumerate exactly it. This
// is what makes the census a live gate: a corpus scenario added tomorrow that
// falls in the class fails here until it is enrolled and ledgered.
func TestProtocolRejectionClassIsEnumeratedCompletely(t *testing.T) {
	document := readCensus(t)
	derived := map[string]bool{}
	for _, scenario := range readPublicScenarios(t) {
		if inProtocolRejectionClass(scenario) {
			derived[scenario.ScenarioID] = true
		}
	}
	if len(derived) == 0 {
		t.Fatal("the sweep predicate matched nothing; it cannot be validating anything")
	}
	enrolled := map[string]bool{}
	for _, entry := range document.Entries {
		if entry.Class == protocolRejectionClass {
			enrolled[entry.ScenarioID] = true
		}
	}
	var missing, extra []string
	for id := range derived {
		if !enrolled[id] {
			missing = append(missing, id)
		}
	}
	for id := range enrolled {
		if !derived[id] {
			extra = append(extra, id)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) != 0 {
		t.Errorf("public-corpus scenarios in the protocol-rejection class but ABSENT from %s: %v\n"+
			"predicate: outcome==error AND error.close_code in {1002,1007,1009} AND final_state==open",
			censusRelativePath, missing)
	}
	if len(extra) != 0 {
		t.Errorf("%s enrolls scenarios that are NOT in the class: %v", censusRelativePath, extra)
	}
}

// TestCensusRowsMatchTheCommittedEvidence binds every row to the artifacts it
// claims, so the census cannot drift into a story of its own.
func TestCensusRowsMatchTheCommittedEvidence(t *testing.T) {
	document := readCensus(t)
	scenarios := map[string]publicScenario{}
	for _, scenario := range readPublicScenarios(t) {
		scenarios[scenario.ScenarioID] = scenario
	}
	for _, entry := range document.Entries {
		scenario, exists := scenarios[entry.ScenarioID]
		if !exists {
			t.Errorf("census cites %s, which is not in the public corpus", entry.ScenarioID)
			continue
		}
		if entry.Pointer == "/final_state" && scenario.Expected.FinalState != entry.RecordedObservable {
			t.Errorf("%s%s: census records %q but the corpus expectation is %q",
				entry.ScenarioID, entry.Pointer, entry.RecordedObservable, scenario.Expected.FinalState)
		}
		if entry.Family != scenario.Family {
			t.Errorf("%s: census family %q != corpus family %q", entry.ScenarioID, entry.Family, scenario.Family)
		}
		if scenario.Expected.Error != nil && entry.RecordedCloseCode != scenario.Expected.Error.CloseCode {
			t.Errorf("%s: census close code %d != corpus close code %d",
				entry.ScenarioID, entry.RecordedCloseCode, scenario.Expected.Error.CloseCode)
		}
		if strings.TrimSpace(entry.JavaEntryPointNote) == "" {
			t.Errorf("%s: every row must carry the java_entry_point_note; flattening this divergence back into a "+
				"binary RFC-versus-Java split is the specific misreading the note exists to prevent", entry.ScenarioID)
		}
		if len(entry.RFCClauses) == 0 || len(entry.Evidence) == 0 {
			t.Errorf("%s: row names no RFC clause or no evidence", entry.ScenarioID)
		}
	}
}

// TestEveryCensusRowIsLedgered is the coverage gate: a proposition recorded
// here as a divergence the port retains must be disclosed in the ledger.
func TestEveryCensusRowIsLedgered(t *testing.T) {
	document := readCensus(t)
	committed, err := ReadCommittedLedger(ledgerTestRepoRoot)
	if err != nil {
		t.Fatalf("read committed ledger: %v", err)
	}
	known := map[string]bool{}
	for _, record := range committed.Records {
		known[record.Delta.DeltaID] = true
	}
	uncovered := map[string][]string{}
	for _, entry := range document.Entries {
		if entry.LedgerDeltaID == "" {
			t.Errorf("%s%s names no ledger record", entry.ScenarioID, entry.Pointer)
			continue
		}
		if !known[entry.LedgerDeltaID] {
			uncovered[entry.LedgerDeltaID] = append(uncovered[entry.LedgerDeltaID],
				entry.ScenarioID+entry.Pointer)
		}
	}
	if len(uncovered) != 0 {
		var report []string
		for delta, rows := range uncovered {
			sort.Strings(rows)
			report = append(report, fmt.Sprintf("  %s covers %d census row(s) but is NOT in the ledger: %s",
				delta, len(rows), strings.Join(rows, ", ")))
		}
		sort.Strings(report)
		t.Fatalf("census rows whose ledger record does not exist:\n%s\n"+
			"coverage rule: every public-corpus proposition where the port follows Java over an RFC-strict reading "+
			"must be disclosed by a ledger record.", strings.Join(report, "\n"))
	}
}
