package lab

import (
	"strings"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

func pinnedRegistrySource() []byte {
	return []byte(strings.Join([]string{
		"Case1_1", "Case2_1", "Case3_1", "Case4_1", "Case5_1", "Case6_X_X", "Case7_1",
		"Case9_1", "Case10_1", "Case12_1", "Case13_1",
	}, "\n"))
}

func parsedRegistry(t *testing.T) AutobahnRegistry {
	t.Helper()
	raw := pinnedRegistrySource()
	registry, err := ParsePinnedAutobahnRegistry(raw, intake.DigestBytes(raw), map[string]RegistryExpansion{
		"Case6_X_X": {SourceDigest: intake.DigestBytes([]byte("Case6_1_1 Case6_1_2")), Source: []byte("Case6_1_1 Case6_1_2"), CaseIDs: []string{"6.1.1", "6.1.2"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func TestStaticAutobahnRegistrySelectionAndExactReconciliation(t *testing.T) {
	registry := parsedRegistry(t)
	selection, err := SelectAutobahnRegistry(registry)
	if err != nil {
		t.Fatal(err)
	}
	if len(selection.SelectedCaseIDs) != 9 || len(selection.ExcludedCaseIDs) != 3 {
		t.Fatalf("selection = %+v", selection)
	}
	results := make([]AutobahnResult, len(selection.SelectedCaseIDs))
	for index, id := range selection.SelectedCaseIDs {
		results[index] = AutobahnResult{CaseID: id, Status: "OK"}
	}
	for _, mode := range []string{"client", "server"} {
		if err := ReconcileAutobahn(registry, selection, mode, results); err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
	}
	mutated := append([]AutobahnResult(nil), results[:len(results)-1]...)
	assertFinding(t, ReconcileAutobahn(registry, selection, "client", mutated), "AUTOBAHN_RESULT_MISMATCH")
	mutated = append([]AutobahnResult(nil), results...)
	mutated[0].CaseID = selection.ExcludedCaseIDs[0]
	assertFinding(t, ReconcileAutobahn(registry, selection, "server", mutated), "AUTOBAHN_RESULT_MISMATCH")
}

func TestStaticAutobahnParserFailsClosedOnGeneratorsAndSourceDrift(t *testing.T) {
	raw := pinnedRegistrySource()
	_, err := ParsePinnedAutobahnRegistry(raw, intake.DigestBytes(raw), nil)
	assertFinding(t, err, "UNRESOLVED_AUTOBAHN_GENERATOR")
	_, err = ParsePinnedAutobahnRegistry(raw, intake.DigestBytes([]byte("different")), nil)
	assertFinding(t, err, "INVALID_AUTOBAHN_REGISTRY_SOURCE")
	_, err = ParsePinnedAutobahnRegistry(raw, intake.DigestBytes(raw), map[string]RegistryExpansion{
		"Case6_X_X": {SourceDigest: intake.DigestBytes([]byte("Case7_1_1")), Source: []byte("Case7_1_1"), CaseIDs: []string{"7.1.1"}},
	})
	assertFinding(t, err, "INVALID_AUTOBAHN_EXPANSION")
	registry := AutobahnRegistry{SchemaVersion: "1.0.0", SourceDigest: intake.DigestBytes(raw), CaseIDs: parsedRegistry(t).CaseIDs}
	assertFinding(t, func() error { _, err := SelectAutobahnRegistry(registry); return err }(), "AUTOBAHN_REGISTRY_PROVENANCE_REQUIRED")
}
