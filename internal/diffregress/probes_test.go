package diffregress

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/michaellady/verified-java-websocket-port/internal/corpora"
)

// repoRoot resolves the repository root from this test file's own location, so
// the tests do not depend on the working directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate this test file")
	}
	root, err := filepath.Abs(filepath.Join(filepath.Dir(file), "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func evidencePath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(repoRoot(t), EvidenceDir, name)
}

// TestCatalogRegeneratesCommittedProbes is the reproducibility gate: the
// committed probes.jsonl must be exactly what the Go catalog emits. A probe
// edited by hand in the JSONL, or a catalog change that silently altered the
// bytes fed to both oracles, fails here.
func TestCatalogRegeneratesCommittedProbes(t *testing.T) {
	generated, err := RequestsJSONL()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	committed, err := os.ReadFile(evidencePath(t, ProbesFile))
	if err != nil {
		t.Fatalf("read committed probes: %v", err)
	}
	if !bytes.Equal(generated, committed) {
		t.Fatalf("committed %s is not byte-identical to the catalog output (%d vs %d bytes)",
			ProbesFile, len(committed), len(generated))
	}
}

// TestEveryProbeDigestBindsItsRequest recomputes each request_digest exactly as
// java-oracle's OracleMain and ws-oracle-harness both recompute it. Both
// implementations REFUSE a request whose digest does not bind it, so this also
// proves every probe is one both oracles would accept.
func TestEveryProbeDigestBindsItsRequest(t *testing.T) {
	for _, probe := range Catalog() {
		request, err := RequestObject(probe)
		if err != nil {
			t.Fatalf("%s: %v", probe.ID, err)
		}
		claimed, _ := request["request_digest"].(string)
		unsigned := make(map[string]any, len(request))
		for k, v := range request {
			if k != "request_digest" {
				unsigned[k] = v
			}
		}
		canonical, err := corpora.CanonicalJSON(unsigned)
		if err != nil {
			t.Fatalf("%s: %v", probe.ID, err)
		}
		if recomputed := corpora.DigestSHA256(canonical); recomputed != claimed {
			t.Fatalf("%s: digest %s does not bind the canonical request (recomputed %s)",
				probe.ID, claimed, recomputed)
		}
	}
}

// TestCatalogIsWellFormed pins the invariants a reader of the manifest relies
// on: unique ids, known classes and origins, and a declared rationale.
func TestCatalogIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	classes := map[Class]bool{ClassConsumption: true, ClassClosedBytes: true, ClassEmptyChunk: true}
	origins := map[Origin]bool{OriginRecovered: true, OriginReconstructed: true, OriginNew: true}
	states := map[string]bool{"open": true, "closing": true, "closed": true, "connecting": true}
	for _, probe := range Catalog() {
		if seen[probe.ID] {
			t.Fatalf("duplicate probe id %s", probe.ID)
		}
		seen[probe.ID] = true
		if !classes[probe.Class] {
			t.Fatalf("%s: unknown class %q", probe.ID, probe.Class)
		}
		if !origins[probe.Origin] {
			t.Fatalf("%s: unknown origin %q", probe.ID, probe.Origin)
		}
		if !states[probe.InitialState] {
			t.Fatalf("%s: unknown initial_state %q", probe.ID, probe.InitialState)
		}
		if probe.Rationale == "" {
			t.Fatalf("%s: no rationale, so the probe does not say what it stresses", probe.ID)
		}
		if len(probe.Chunks) == 0 {
			t.Fatalf("%s: no input steps", probe.ID)
		}
	}
	// All three defect classes must stay represented: a refactor that dropped a
	// class would otherwise leave a silently narrower regression set.
	byClass := map[Class]int{}
	for _, probe := range Catalog() {
		byClass[probe.Class]++
	}
	for class := range classes {
		if byClass[class] == 0 {
			t.Fatalf("defect class %q has no probes", class)
		}
	}
}

// TestRecoveredProbesAreTheAuditsEightExactly pins WHICH probes carry the
// "recovered" provenance. The recovered set is a factual claim about where the
// bytes came from, so it must not drift as new probes are added.
func TestRecoveredProbesAreTheAuditsEightExactly(t *testing.T) {
	want := map[string]bool{
		"xd.a1.rsv-midchunk": true, "xd.a2.rsv-split": true,
		"xd.b1.closed-64bytes": true, "xd.b2.closed-empty-then-bytes": true,
		"xd.b3.closed-valid-frame": true, "xd.d1.closing-empty": true,
		"xd.d2.open-empty": true, "xd.d3.closed-empty-twice": true,
	}
	got := map[string]bool{}
	for _, probe := range Catalog() {
		if probe.Origin == OriginRecovered {
			got[probe.ID] = true
		}
	}
	if len(got) != len(want) {
		t.Fatalf("recovered probe count %d, want %d", len(got), len(want))
	}
	for id := range want {
		if !got[id] {
			t.Fatalf("probe %s is no longer marked recovered", id)
		}
	}
}

// TestInvisibilityClaimsAreWellFormed enforces the shape of the per-probe
// corpus-invisibility verdict. A probe claiming to be genuinely invisible may
// not also name a scenario that pins it, and a probe admitting redundancy must
// name the scenario that makes it redundant. This exists because an earlier
// round asserted invisibility in prose for a probe the corpus already pinned.
func TestInvisibilityClaimsAreWellFormed(t *testing.T) {
	known := map[Invisibility]bool{
		GenuinelyInvisible: true, PartiallyInvisible: true, Redundant: true,
	}
	for _, probe := range Catalog() {
		if !known[probe.Invisibility] {
			t.Fatalf("%s: unknown invisibility verdict %q", probe.ID, probe.Invisibility)
		}
		if probe.InvisibilityNote == "" {
			t.Fatalf("%s: invisibility verdict carries no justification", probe.ID)
		}
		switch probe.Invisibility {
		case GenuinelyInvisible:
			if len(probe.PinnedBy) != 0 {
				t.Fatalf("%s: claims genuine invisibility but names pinning scenarios %v",
					probe.ID, probe.PinnedBy)
			}
		case Redundant, PartiallyInvisible:
			if len(probe.PinnedBy) == 0 {
				t.Fatalf("%s: verdict %q must name the public scenario(s) that pin it",
					probe.ID, probe.Invisibility)
			}
			for _, id := range probe.PinnedBy {
				if !strings.HasPrefix(id, "us005.pub.") {
					t.Fatalf("%s: pinning scenario %q is not a public corpus id", probe.ID, id)
				}
			}
		}
	}
}

// TestPinningScenariosExistInThePublicCorpus proves every named pinning
// scenario is real. A redundancy citation that names a nonexistent scenario
// would be worse than no citation.
func TestPinningScenariosExistInThePublicCorpus(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "corpora", "public", "scenarios.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	present := map[string]bool{}
	for _, line := range bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var scenario struct {
			ScenarioID string `json:"scenario_id"`
		}
		if err := json.Unmarshal(line, &scenario); err != nil {
			t.Fatal(err)
		}
		present[scenario.ScenarioID] = true
	}
	for _, probe := range Catalog() {
		for _, id := range probe.PinnedBy {
			if !present[id] {
				t.Fatalf("%s cites pinning scenario %s, which is not in the public corpus", probe.ID, id)
			}
		}
	}
}

// TestCommittedProbesParseAsOracleRequests guards the committed file itself
// against corruption independent of the catalog.
func TestCommittedProbesParseAsOracleRequests(t *testing.T) {
	raw, err := os.ReadFile(evidencePath(t, ProbesFile))
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n"))
	if len(lines) != len(Catalog()) {
		t.Fatalf("committed probes have %d lines, catalog has %d", len(lines), len(Catalog()))
	}
	for i, line := range lines {
		var request map[string]any
		if err := json.Unmarshal(line, &request); err != nil {
			t.Fatalf("line %d: %v", i+1, err)
		}
		if request["protocol"] != Protocol || request["version"] != Version {
			t.Fatalf("line %d: wrong protocol identity %v/%v", i+1, request["protocol"], request["version"])
		}
	}
}
