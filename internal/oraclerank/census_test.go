package oraclerank

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot walks up from the package directory to the repository root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not find the repository root")
	return ""
}

// mirrorRoot builds a throwaway repository root that reads the real tree
// through symlinked FILES, except for the paths in overrides, which are
// materialized with the given bytes. It is how every RED test below plants
// exactly one difference and asks whether the gate notices.
//
// Directories on the path to an override are recreated as real directories
// (with their file children symlinked and their directory children mirrored the
// same way) rather than symlinked, because filepath.Walk does not descend into
// a symlinked directory and the evidence-integrity check walks the tree.
//
// A path mapped to nil is DELETED from the mirror.
func mirrorRoot(t *testing.T, real string, overrides map[string][]byte) string {
	t.Helper()
	mirror := t.TempDir()
	linkChildren(t, real, mirror)

	for rel, content := range overrides {
		parts := strings.Split(rel, "/")
		realDir, mirrorDir := real, mirror
		for _, segment := range parts[:len(parts)-1] {
			realDir = filepath.Join(realDir, segment)
			mirrorDir = filepath.Join(mirrorDir, segment)
			info, err := os.Lstat(mirrorDir)
			switch {
			case err == nil && info.Mode()&os.ModeSymlink != 0:
				if err := os.Remove(mirrorDir); err != nil {
					t.Fatal(err)
				}
				deepMirror(t, realDir, mirrorDir)
			case os.IsNotExist(err):
				if err := os.MkdirAll(mirrorDir, 0o755); err != nil {
					t.Fatal(err)
				}
			}
		}
		target := filepath.Join(mirrorDir, parts[len(parts)-1])
		_ = os.Remove(target)
		if content == nil {
			continue
		}
		if err := os.WriteFile(target, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return mirror
}

// deepMirror recreates a directory tree with real directories and symlinked
// files, so a walk of the mirror sees the same shape as a walk of the real
// tree without copying any content.
func deepMirror(t *testing.T, from, to string) {
	t.Helper()
	if err := os.MkdirAll(to, 0o755); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(from)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		src, dst := filepath.Join(from, entry.Name()), filepath.Join(to, entry.Name())
		if entry.IsDir() {
			deepMirror(t, src, dst)
			continue
		}
		if err := os.Symlink(src, dst); err != nil {
			t.Fatal(err)
		}
	}
}

func linkChildren(t *testing.T, from, to string) {
	t.Helper()
	entries, err := os.ReadDir(from)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if err := os.Symlink(filepath.Join(from, entry.Name()), filepath.Join(to, entry.Name())); err != nil {
			t.Fatal(err)
		}
	}
}

func mustRead(t *testing.T, root, rel string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// ---------------------------------------------------------------------------
// The committed tree
// ---------------------------------------------------------------------------

func TestCommittedRegisterEqualsItsRecomputation(t *testing.T) {
	if err := Verify(repoRoot(t)); err != nil {
		t.Fatalf("the committed register does not equal its recomputation from the evidence: %v", err)
	}
}

func TestCommittedRegisterSatisfiesTheAdjudicationRules(t *testing.T) {
	if err := VerifyRules(repoRoot(t)); err != nil {
		t.Fatalf("the adjudication rules do not hold over the committed evidence: %v", err)
	}
}

// TestNoRankIsDeclaredAndSilent is the structural guard against the failure
// mode this package exists to avoid: a rank that is named in a family and never
// speaks there exists in name only.
func TestNoRankIsDeclaredAndSilent(t *testing.T) {
	families, err := Census(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(families) == 0 {
		t.Fatal("the census produced no families")
	}
	for _, f := range families {
		if len(f.Propositions) == 0 {
			t.Fatalf("family %s has no propositions", f.ID)
		}
		voted := map[Rank]int{}
		for _, p := range f.Propositions {
			for _, o := range p.Opinions {
				if !o.Abstains {
					voted[o.Rank]++
				}
			}
		}
		for _, rs := range f.RankSources {
			switch rs.Strength {
			case SourceAbsent:
				if voted[rs.Rank] != 0 {
					t.Fatalf("family %s declares %s ABSENT and it voted %d times", f.ID, rs.Rank, voted[rs.Rank])
				}
				if rs.ArtifactGroup != "" {
					t.Fatalf("family %s declares %s ABSENT with artifact group %q", f.ID, rs.Rank, rs.ArtifactGroup)
				}
			default:
				if voted[rs.Rank] == 0 {
					t.Fatalf("family %s declares %s with strength %s and it never voted", f.ID, rs.Rank, rs.Strength)
				}
				if rs.ArtifactGroup == "" {
					t.Fatalf("family %s declares %s with strength %s and no artifact group", f.ID, rs.Rank, rs.Strength)
				}
				if rs.Note == "" {
					t.Fatalf("family %s declares %s with no note", f.ID, rs.Rank)
				}
			}
		}
	}
}

// TestTheDiscriminatingCasesAreRealAndNotPlanted pins the finding this whole
// mechanism was built to expose, so a later change that quietly loses it fails
// here rather than passing silently. These are committed Autobahn cases where
// the pinned Java and the Rust port were graded at the SAME behaviour class and
// that class is not the one the suite's own per-case expectation endorses.
func TestTheDiscriminatingCasesAreRealAndNotPlanted(t *testing.T) {
	reg, _, err := Recompute(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"3.2": true, "3.3": true,
		"4.1.3": true, "4.1.4": true, "4.2.3": true, "4.2.4": true,
		"6.4.1": true, "6.4.2": true, "6.4.3": true, "6.4.4": true,
	}
	seen := map[string]int{}
	for _, e := range reg.Overridden {
		if e.Family != FamilyAutobahn {
			continue
		}
		if e.Governing != RankAutobahnInScope {
			t.Fatalf("%s is governed by %s; an Autobahn override must be governed by rank two", e.PropositionID, e.Governing)
		}
		if e.ConsensusVerdict == e.GoverningVerdict {
			t.Fatalf("%s is enrolled as overridden with consensus == governing verdict %q", e.PropositionID, e.ConsensusVerdict)
		}
		if e.GoverningVerdict != "OK" {
			t.Fatalf("%s: governing verdict %q, want OK", e.PropositionID, e.GoverningVerdict)
		}
		parts := strings.Split(e.PropositionID, "/")
		seen[parts[len(parts)-1]]++
	}
	for id := range want {
		if seen[id] != 2 {
			t.Fatalf("case %s is enrolled %d times, want 2 (one per subject role); the real discriminating set has changed", id, seen[id])
		}
	}
	if len(seen) != len(want) {
		t.Fatalf("the Autobahn override set is %v, want exactly %v", seen, want)
	}
}

// TestThePolarityControlFamilyNeverFires proves the check discriminates against
// REAL evidence, not only against planted opinions: the differential regression
// probes are exactly the rank-four-against-rank-five comparison AC2 talks about,
// with no higher oracle present, and no proposition in them may be overridden.
func TestThePolarityControlFamilyNeverFires(t *testing.T) {
	families, err := Census(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range families {
		if f.ID != FamilyDiffProbe {
			continue
		}
		found = true
		agreements := 0
		for _, p := range f.Propositions {
			a, err := Adjudicate(p)
			if err != nil {
				t.Fatal(err)
			}
			if a.JavaRustConsensusOverridden {
				t.Fatalf("%s: the override rule fired in a family with no higher oracle", p.ID)
			}
			if a.JavaRustConsensus {
				agreements++
				if _, err := ParityFromJavaRustAgreement(p); err != nil {
					t.Fatalf("%s: the guarded parity reading refused an unopposed agreement: %v", p.ID, err)
				}
			}
		}
		if agreements == 0 {
			t.Fatal("the polarity-control family exhibits no Java/Rust agreement at all, so it controls nothing")
		}
	}
	if !found {
		t.Fatalf("family %s is absent from the census", FamilyDiffProbe)
	}
}

// ---------------------------------------------------------------------------
// RED: every check below is deleted or contradicted in a mirror of the tree,
// and must fail. A check that stays green when its evidence is broken is not
// evidence.
// ---------------------------------------------------------------------------

func TestRedRegisterThatDropsAnExhibitedOverrideFails(t *testing.T) {
	root := repoRoot(t)
	var doc map[string]any
	if err := json.Unmarshal(mustRead(t, root, RegisterPath), &doc); err != nil {
		t.Fatal(err)
	}
	list, _ := doc["java_rust_agreements_overridden_by_a_higher_oracle"].([]any)
	if len(list) < 2 {
		t.Fatalf("the committed register enrols %d overrides; this RED test needs at least 2", len(list))
	}
	doc["java_rust_agreements_overridden_by_a_higher_oracle"] = list[1:]
	edited, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	mirror := mirrorRoot(t, root, map[string][]byte{RegisterPath: append(edited, '\n')})
	if err := VerifyRules(mirror); err == nil {
		t.Fatal("RED FAILED: the register dropped an override the evidence exhibits and VerifyRules passed")
	} else if !strings.Contains(err.Error(), "does not enrol") {
		t.Fatalf("VerifyRules failed with %q, which does not name the missing enrolment", err)
	}
	if err := Verify(mirror); err == nil {
		t.Fatal("RED FAILED: the register was edited and Verify passed")
	}
}

func TestRedRegisterThatEnrolsAnUnexhibitedOverrideFails(t *testing.T) {
	root := repoRoot(t)
	var doc map[string]any
	if err := json.Unmarshal(mustRead(t, root, RegisterPath), &doc); err != nil {
		t.Fatal(err)
	}
	list, _ := doc["java_rust_agreements_overridden_by_a_higher_oracle"].([]any)
	doc["java_rust_agreements_overridden_by_a_higher_oracle"] = append(list, map[string]any{
		"proposition_id":              "autobahn-behavior-class/server/1.1.1",
		"family":                      FamilyAutobahn,
		"question":                    "planted",
		"java_rust_consensus_verdict": "OK",
		"governing_rank":              2,
		"governing_rank_name":         RankAutobahnInScope.String(),
		"governing_verdict":           "NON-STRICT",
		"governing_source":            "planted",
	})
	edited, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	mirror := mirrorRoot(t, root, map[string][]byte{RegisterPath: append(edited, '\n')})
	if err := VerifyRules(mirror); err == nil {
		t.Fatal("RED FAILED: the register enrolled an override the evidence does not exhibit and VerifyRules passed; it would be a waiver list")
	} else if !strings.Contains(err.Error(), "not a waiver list") {
		t.Fatalf("VerifyRules failed with %q, which does not name the unexhibited enrolment", err)
	}
}

func TestRedEditedRegisterBytesFail(t *testing.T) {
	root := repoRoot(t)
	edited := append([]byte(nil), mustRead(t, root, RegisterPath)...)
	edited = append(edited, ' ')
	mirror := mirrorRoot(t, root, map[string][]byte{RegisterPath: edited})
	if err := Verify(mirror); err == nil {
		t.Fatal("RED FAILED: a single appended byte left Verify green")
	}
}

// TestRedFlippedRustObservationChangesTheAdjudication proves rank five is load
// bearing: the Rust transcript is read per scenario, and changing one recorded
// ready state changes the census.
func TestRedFlippedRustObservationChangesTheAdjudication(t *testing.T) {
	root := repoRoot(t)
	original := mustRead(t, root, RustPublicTranscriptPath)
	lines := strings.Split(strings.TrimRight(string(original), "\n"), "\n")

	flipped := 0
	for i, line := range lines {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		if rec["final_state"] != "open" {
			continue
		}
		rec["final_state"] = "closed"
		edited, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		lines[i] = string(edited)
		flipped++
		break
	}
	if flipped == 0 {
		t.Fatal("no scenario in the Rust transcript records final_state open; this RED test needs one")
	}

	mirror := mirrorRoot(t, root, map[string][]byte{
		RustPublicTranscriptPath: []byte(strings.Join(lines, "\n") + "\n"),
	})
	if err := Verify(mirror); err == nil {
		t.Fatal("RED FAILED: one Rust observation was flipped and the register still matched; rank five is not load bearing")
	}
}

// TestRedFlippedJavaObservationChangesTheAdjudication does the same for rank
// four in the Autobahn family, where the Java leg is read from its own report
// bytes.
func TestRedFlippedJavaObservationChangesTheAdjudication(t *testing.T) {
	root := repoRoot(t)
	rel := AutobahnEvidenceRoot + "/java/fuzzingclient-run1/cases/verified_java_websocket_port_1_6_0_case_6_4_1.json"
	var report map[string]any
	if err := json.Unmarshal(mustRead(t, root, rel), &report); err != nil {
		t.Fatal(err)
	}
	if report["behavior"] != "NON-STRICT" {
		t.Fatalf("case 6.4.1 java leg records behavior %v, this RED test expects NON-STRICT", report["behavior"])
	}
	report["behavior"] = "OK"
	edited, err := json.MarshalIndent(report, "", " ")
	if err != nil {
		t.Fatal(err)
	}

	mirror := mirrorRoot(t, root, map[string][]byte{rel: edited})
	if _, err := Census(mirror); err == nil {
		t.Fatal("RED FAILED: a Java per-case report was edited and the census accepted it")
	}
}

// TestRedRemovedRFCPinFailsRankOne proves rank one is not a free-floating label:
// with the pin gone there is nothing for it to be declared against.
func TestRedRemovedRFCPinFailsRankOne(t *testing.T) {
	root := repoRoot(t)
	var doc any
	if err := json.Unmarshal(mustRead(t, root, SourcePinsPath), &doc); err != nil {
		t.Fatal(err)
	}
	stripped := stripPin(doc, RFCPinID)
	edited, err := json.MarshalIndent(stripped, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	mirror := mirrorRoot(t, root, map[string][]byte{SourcePinsPath: edited})
	if _, err := ReadRFCPin(mirror); err == nil {
		t.Fatal("RED FAILED: the rfc6455-text pin was removed and rank one still read a pin")
	}
	if _, err := Bindings(mirror, nil); err == nil {
		t.Fatal("RED FAILED: the rfc6455-text pin was removed and the bindings still built")
	}
}

// TestRedUnpinnedRFCTextIsRefused proves the rank-one upgrade path cannot be
// taken with bytes that are not the pinned ones. This is the one path the
// committed tree does NOT exercise -- the RFC text is not here -- so it is
// exercised with a planted file instead, and the planted file must be refused.
func TestRedUnpinnedRFCTextIsRefused(t *testing.T) {
	root := repoRoot(t)
	pin, err := ReadRFCPin(root)
	if err != nil {
		t.Fatal(err)
	}
	present, err := RFCTextPresent(root, pin)
	if err != nil {
		t.Fatal(err)
	}
	if present {
		t.Skip("the pinned RFC text is now committed; this RED test covers its absence")
	}

	// The planted bytes are EXACTLY the pinned length. A deletion attack
	// found that a shorter plant was caught by the byte-size check, which
	// left the digest check itself unexercised and therefore not evidence.
	imposter := make([]byte, pin.ByteSize)
	for i := range imposter {
		imposter[i] = 'x'
	}
	mirror := mirrorRoot(t, root, map[string][]byte{RFCTextCandidatePath: imposter})
	if _, err := RFCTextPresent(mirror, pin); err == nil {
		t.Fatal("RED FAILED: unpinned bytes at the RFC path were accepted as the normative text")
	}
	if _, err := Bindings(mirror, nil); err == nil {
		t.Fatal("RED FAILED: the bindings built over unpinned RFC bytes")
	}
}

// TestRedShortenedPublicCorpusIsRefused proves the census cannot silently cover
// less than it claims.
func TestRedShortenedPublicCorpusIsRefused(t *testing.T) {
	root := repoRoot(t)
	lines := strings.Split(strings.TrimRight(string(mustRead(t, root, PublicCorpusPath)), "\n"), "\n")
	mirror := mirrorRoot(t, root, map[string][]byte{
		PublicCorpusPath: []byte(strings.Join(lines[:len(lines)-1], "\n") + "\n"),
	})
	if _, err := Census(mirror); err == nil {
		t.Fatal("RED FAILED: a scenario was dropped from the public corpus and the census accepted a smaller tier")
	}
}

// TestRedDirtySweepRefusesTheRankFourDeduction proves the aggregate-derived
// rank-four opinion is guarded: the deduction is only sound under a clean
// sweep, and a dirty aggregate must refuse rather than weaken it.
func TestRedDirtySweepRefusesTheRankFourDeduction(t *testing.T) {
	root := repoRoot(t)
	var manifest map[string]any
	if err := json.Unmarshal(mustRead(t, root, PublicCorpusManifestPath), &manifest); err != nil {
		t.Fatal(err)
	}
	counts, _ := manifest["counts"].(map[string]any)
	if counts == nil {
		t.Fatal("the public manifest has no counts object")
	}
	counts["passed"] = float64(PublicCorpusSize - 1)
	counts["failed"] = float64(1)
	edited, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	mirror := mirrorRoot(t, root, map[string][]byte{PublicCorpusManifestPath: edited})
	if _, err := Census(mirror); err == nil {
		t.Fatal("RED FAILED: the public sweep was made dirty and the census still deduced a per-scenario Java observation from it")
	} else if !strings.Contains(err.Error(), "clean sweep") {
		t.Fatalf("the census failed with %q, which does not name the clean-sweep precondition", err)
	}
}

// TestRedBrokenDivergentConditionalCoincidenceIsRefused proves the handshake
// family's stated reach is asserted rather than described.
func TestRedBrokenDivergentConditionalCoincidenceIsRefused(t *testing.T) {
	root := repoRoot(t)
	var doc map[string]any
	if err := json.Unmarshal(mustRead(t, root, HandshakeLiveMappingPath), &doc); err != nil {
		t.Fatal(err)
	}
	entries, _ := doc["entries"].([]any)
	changed := false
	for _, raw := range entries {
		entry, _ := raw.(map[string]any)
		if entry == nil || entry["java_observable"] != "conditional" {
			continue
		}
		entry["java_observable"] = "reject"
		changed = true
		break
	}
	if !changed {
		t.Fatal("the mapping records no conditional java_observable; this RED test needs one")
	}
	edited, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	mirror := mirrorRoot(t, root, map[string][]byte{HandshakeLiveMappingPath: edited})
	if _, err := Census(mirror); err == nil {
		t.Fatal("RED FAILED: the divergent/conditional coincidence was broken and the census accepted it")
	}
}

// TestRedMissingRustTranscriptFailsRankFive proves rank five in the public
// family is bound to bytes, not to a label.
func TestRedMissingRustTranscriptFailsRankFive(t *testing.T) {
	root := repoRoot(t)
	mirror := mirrorRoot(t, root, map[string][]byte{RustPublicTranscriptPath: nil})
	if _, err := Census(mirror); err == nil {
		t.Fatal("RED FAILED: the Rust public transcript was deleted and the census still produced rank-five opinions")
	}
}

func stripPin(node any, id string) any {
	switch v := node.(type) {
	case map[string]any:
		if got, ok := v["id"].(string); ok && got == id {
			return nil
		}
		out := map[string]any{}
		for k, child := range v {
			out[k] = stripPin(child, id)
		}
		return out
	case []any:
		var out []any
		for _, item := range v {
			stripped := stripPin(item, id)
			if stripped == nil {
				continue
			}
			out = append(out, stripped)
		}
		return out
	default:
		return node
	}
}
