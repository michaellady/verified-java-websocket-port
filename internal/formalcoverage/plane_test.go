package formalcoverage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// The namespace a crate ships is declared inside its manifest, not by the
// directory it sits in. These two are the RED reading for that fix, and they
// are written as fixtures rather than against this tree on purpose: on THIS
// plane every directory name happens to agree with its [lib] name, so a test
// against this tree alone would pass with the old code and prove nothing. The
// fixture is the shape of the plane the catalog came from.
// ---------------------------------------------------------------------------

func TestACrateShipsTheNamespaceItsManifestDeclaresNotItsDirectoryName(t *testing.T) {
	root := t.TempDir()
	// Exactly the origin plane's shape: the directory is connection-core and
	// the library it ships is websocket_core.
	writeCrate(t, root, "connection-core", "[package]\nname = \"websocket-core\"\n\n[lib]\nname = \"websocket_core\"\n")
	// And a crate that declares no [lib] name, so the package name is used.
	writeCrate(t, root, "some-dir", "[package]\nname = \"other-package\"\n")

	namespaces, err := shippedCrateNamespaces(root)
	if err != nil {
		t.Fatalf("shippedCrateNamespaces: %v", err)
	}
	got := strings.Join(namespaces, ",")
	if got != "other_package,websocket_core" {
		t.Fatalf("the workspace ships %q; reading the DIRECTORY name would have said connection_core,some_dir", got)
	}
	for _, wrong := range []string{"connection_core", "some_dir"} {
		if strings.Contains(got, wrong) {
			t.Fatalf("%q is a directory name, not a shipped namespace", wrong)
		}
	}
}

func TestTheCatalogsOwnNamespaceIsFoundOnThePlaneItIsAbout(t *testing.T) {
	// The point of the fix, stated as the claim it defends: on a tree shaped
	// like the origin plane, the catalog's namespace websocket_core DOES match
	// a shipped crate. The old directory-reading check would have reported
	// NAMESPACE_MATCHES_NO_SHIPPED_CRATE there -- a false accusation against
	// the plane the document is about.
	root := t.TempDir()
	writeCrate(t, root, "connection-core", "[package]\nname = \"websocket-core\"\n\n[lib]\nname = \"websocket_core\"\n")
	writeCrate(t, root, "websocket-driver", "[package]\nname = \"websocket-driver\"\n")
	namespaces, err := shippedCrateNamespaces(root)
	if err != nil {
		t.Fatalf("shippedCrateNamespaces: %v", err)
	}
	shipped := map[string]bool{}
	for _, namespace := range namespaces {
		shipped[namespace] = true
	}
	for _, want := range []string{"websocket_core", "websocket_driver"} {
		if !shipped[want] {
			t.Fatalf("the catalog's namespace %q is not found on a tree shaped like the plane it came from: %v", want, namespaces)
		}
	}
}

func TestThisPlaneShipsNeitherOfTheCatalogsNamespaces(t *testing.T) {
	// The mirror reading, against the real tree. The fix must not have made an
	// unbound column look bound here.
	namespaces, err := shippedCrateNamespaces(repoRoot(t))
	if err != nil {
		t.Fatalf("shippedCrateNamespaces: %v", err)
	}
	for _, namespace := range namespaces {
		if namespace == "websocket_core" || namespace == "websocket_driver" {
			t.Fatalf("this plane is reported as shipping %q; it ships ws_core and ws_driver", namespace)
		}
	}
	if len(namespaces) == 0 {
		t.Fatal("no crate namespace was derived at all, so the absence above proves nothing")
	}
}

func writeCrate(t *testing.T, root, dir, manifest string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "rust", dir), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "rust", dir, "Cargo.toml"), []byte(manifest), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}

// ---------------------------------------------------------------------------
// The plane-correspondence record. Every check below is proved able to fail by
// making the record say something false and reading the finding back by name.
// ---------------------------------------------------------------------------

func TestTheRetainedPlaneRecordChecksOut(t *testing.T) {
	findings, doc, err := VerifyPlaneCorrespondence(repoRoot(t))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("the retained plane record does not check out: %+v", findings)
	}
	if len(doc.Crates) == 0 || len(doc.Paths) == 0 || len(doc.Symbols) == 0 {
		t.Fatal("the record is empty, so a clean verification proves nothing")
	}
}

func TestNoRowInTheRetainedRecordEstablishesACorrespondence(t *testing.T) {
	// The load-bearing claim of the whole document. If a future edit quietly
	// promoted a row to ESTABLISHED, every catalog Rust row on that path would
	// become "measurable here" and 24/24 would stop blocking for the right
	// reason. This is the test that notices.
	_, doc, err := VerifyPlaneCorrespondence(repoRoot(t))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	states := doc.States()
	for subject, state := range states.ByNamespace {
		if AuthorisesMeasurement(state) {
			t.Fatalf("namespace %s claims %s; no owner decision has established a plane correspondence", subject, state)
		}
	}
	for subject, state := range states.ByPath {
		if AuthorisesMeasurement(state) {
			t.Fatalf("path %s claims %s; no owner decision has established a plane correspondence", subject, state)
		}
	}
	for subject, state := range states.BySymbol {
		if AuthorisesMeasurement(state) {
			t.Fatalf("symbol %s claims %s; no owner decision has established a plane correspondence", subject, state)
		}
	}
}

// planeFinding runs the verifier over a sandbox whose record has been mutated
// and returns whether the named check fired.
func planeFinding(t *testing.T, mutate func(map[string]any), check string) {
	t.Helper()
	root := sandbox(t)
	rewriteJSON(t, root, PlaneCorrespondencePath, mutate)
	findings, _, err := VerifyPlaneCorrespondence(root)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	for _, finding := range findings {
		if finding.Check == check {
			return
		}
	}
	t.Fatalf("the mutation did not raise %s; findings were %+v", check, findings)
}

func rows(tree map[string]any, key string) []any {
	list, _ := tree[key].([]any)
	return list
}

func TestDroppingASourcePathRowIsRefused(t *testing.T) {
	planeFinding(t, func(tree map[string]any) {
		list := rows(tree, "source_paths")
		tree["source_paths"] = list[1:]
	}, "EVERY_CATALOG_SOURCE_PATH_HAS_A_ROW")
}

func TestDroppingANamespaceRowIsRefused(t *testing.T) {
	planeFinding(t, func(tree map[string]any) {
		list := rows(tree, "crates")
		tree["crates"] = list[1:]
	}, "EVERY_CATALOG_NAMESPACE_HAS_A_ROW")
}

func TestDroppingASymbolRowIsRefused(t *testing.T) {
	planeFinding(t, func(tree map[string]any) {
		list := rows(tree, "production_symbols")
		tree["production_symbols"] = list[1:]
	}, "EVERY_CATALOG_SYMBOL_HAS_A_ROW")
}

func TestAnInventedObligationCountIsRefused(t *testing.T) {
	planeFinding(t, func(tree map[string]any) {
		rows(tree, "source_paths")[0].(map[string]any)["obligation_count"] = 99.0
	}, "OBLIGATION_COUNT_IS_THE_CATALOG_COUNT")
}

func TestClaimingTheCatalogPathIsHereIsRefused(t *testing.T) {
	planeFinding(t, func(tree map[string]any) {
		rows(tree, "source_paths")[0].(map[string]any)["catalog_path_exists_on_this_plane"] = true
	}, "CATALOG_PATH_EXISTENCE_IS_RECOMPUTED")
}

func TestClaimingACandidateThatIsNotHereIsRefused(t *testing.T) {
	planeFinding(t, func(tree map[string]any) {
		row := rows(tree, "source_paths")[0].(map[string]any)
		row["candidate_path_on_this_plane"] = "rust/ws-core/src/there-is-no-such-file.rs"
	}, "CANDIDATE_PATH_EXISTENCE_IS_RECOMPUTED")
}

func TestAnInventedCandidateNamespaceIsRefused(t *testing.T) {
	planeFinding(t, func(tree map[string]any) {
		// The most tempting lie in the whole document: say this plane's crate
		// ships the namespace the catalog names.
		rows(tree, "crates")[0].(map[string]any)["candidate_lib_name_on_this_plane"] = "websocket_core"
	}, "CANDIDATE_LIB_NAME_IS_RECOMPUTED_FROM_THIS_PLANE")
}

func TestACitationThatIsNotAtItsLineIsRefused(t *testing.T) {
	planeFinding(t, func(tree map[string]any) {
		rows(tree, "production_symbols")[0].(map[string]any)["nearest_declaration_line"] = 1.0
	}, "NEAREST_DECLARATION_IS_AT_THE_LINE_IT_CITES")
}

func TestACitationTextThatDoesNotMatchIsRefused(t *testing.T) {
	planeFinding(t, func(tree map[string]any) {
		rows(tree, "production_symbols")[0].(map[string]any)["nearest_declaration_text"] = "    pub fn step(&mut self) {"
	}, "NEAREST_DECLARATION_IS_AT_THE_LINE_IT_CITES")
}

func TestAnUnknownCorrespondenceStateIsRefused(t *testing.T) {
	planeFinding(t, func(tree map[string]any) {
		rows(tree, "source_paths")[0].(map[string]any)["correspondence_state"] = "PROBABLY_FINE"
	}, "CORRESPONDENCE_VOCABULARY_IS_CLOSED")
}

func TestClaimingAnEstablishedCorrespondenceWithoutADecisionIsRefused(t *testing.T) {
	// The defect this document exists to prevent, attempted directly.
	planeFinding(t, func(tree map[string]any) {
		rows(tree, "crates")[0].(map[string]any)["correspondence_state"] = CorrespondenceEstablished
	}, "ESTABLISHED_REQUIRES_A_NAMED_OWNER_DECISION")
}

func TestClaimingAnEstablishedCorrespondenceAgainstAMissingDecisionIsRefused(t *testing.T) {
	planeFinding(t, func(tree map[string]any) {
		row := rows(tree, "crates")[0].(map[string]any)
		row["correspondence_state"] = CorrespondenceEstablished
		row["owner_decision_record"] = "evidence/governance/decisions/no-such-decision.json"
		row["owner_decision_key"] = "plane_correspondence"
	}, "OWNER_DECISION_RECORD_EXISTS")
}

func TestClaimingAnEstablishedCorrespondenceAgainstADecisionThatDoesNotSaySoIsRefused(t *testing.T) {
	root := sandbox(t)
	decision := filepath.Join(root, "evidence", "governance", "decisions", "some-other-decision.json")
	if err := os.MkdirAll(filepath.Dir(decision), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(decision, []byte(`{"decisions":{"something_else":{"choice":"yes"}}}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	rewriteJSON(t, root, PlaneCorrespondencePath, func(tree map[string]any) {
		row := rows(tree, "crates")[0].(map[string]any)
		row["correspondence_state"] = CorrespondenceEstablished
		row["owner_decision_record"] = "evidence/governance/decisions/some-other-decision.json"
		row["owner_decision_key"] = "plane_correspondence_websocket_core_to_ws_core"
	})
	findings, _, err := VerifyPlaneCorrespondence(root)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	for _, finding := range findings {
		if finding.Check == "OWNER_DECISION_RECORD_NAMES_THE_KEY" {
			return
		}
	}
	t.Fatalf("a decision record that does not name the key was accepted; findings were %+v", findings)
}

func TestADecisionCitedByAnUnestablishedRowIsRefused(t *testing.T) {
	// The mirror direction: a row that stays weak must not carry a decision
	// reference, or a reader would take the weak label as a formality over a
	// decision that has in fact been made.
	planeFinding(t, func(tree map[string]any) {
		row := rows(tree, "crates")[0].(map[string]any)
		row["owner_decision_record"] = "evidence/governance/decisions/us009-us008-owner-decisions-2026-08-27.json"
		row["owner_decision_key"] = "us009_crate_naming"
	}, "ONLY_AN_ESTABLISHED_ROW_CITES_AN_OWNER_DECISION")
}

func TestARecordAboutADifferentCatalogIsRefused(t *testing.T) {
	planeFinding(t, func(tree map[string]any) {
		tree["catalog"].(map[string]any)["sha256"] = "sha256:" + strings.Repeat("0", 64)
	}, "RECORD_ECHOES_THE_VENDORED_IDENTITY")
}

func TestARowThatNamesNoCandidateAndStillClaimsCorrespondenceIsRefused(t *testing.T) {
	planeFinding(t, func(tree map[string]any) {
		row := rows(tree, "crates")[0].(map[string]any)
		row["candidate_directory_on_this_plane"] = ""
	}, "A_ROW_WITH_NO_CANDIDATE_IS_NO_CORRESPONDENCE")
}

func TestAnUnestablishedRowMustSayWhy(t *testing.T) {
	planeFinding(t, func(tree map[string]any) {
		rows(tree, "source_paths")[0].(map[string]any)["why_this_is_not_an_identity"] = "   "
	}, "EVERY_UNESTABLISHED_ROW_SAYS_WHY")
}

// ---------------------------------------------------------------------------
// The reconciliation and the report must actually USE the record. A verifier
// nothing consults is decoration.
// ---------------------------------------------------------------------------

func TestAPlaneRecordThatDoesNotCheckOutRefusesTheWholeReconciliation(t *testing.T) {
	root := sandbox(t)
	rewriteJSON(t, root, PlaneCorrespondencePath, func(tree map[string]any) {
		rows(tree, "crates")[0].(map[string]any)["candidate_lib_name_on_this_plane"] = "websocket_core"
	})
	if _, err := Reconcile(root); err == nil {
		t.Fatal("the reconciliation accepted a plane record that claims this plane ships the catalog's namespace")
	} else if !strings.Contains(err.Error(), "plane-correspondence record does not check out") {
		t.Fatalf("the refusal was not the plane record: %v", err)
	}
}

func TestEveryObligationBlocksOnTheUnestablishedPlaneCorrespondence(t *testing.T) {
	report, err := DeriveReport(repoRoot(t))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(report.Obligations) != CatalogDenominator {
		t.Fatalf("report carries %d obligations", len(report.Obligations))
	}
	for _, row := range report.Obligations {
		found := false
		for _, reason := range row.BlockingReasons {
			if reason == BlockPlaneNotEstablished {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s does not block on %s", row.ObligationID, BlockPlaneNotEstablished)
		}
	}
	if report.Denominator.RustRowsMeasurableHere != 0 {
		t.Fatalf("%d catalog Rust rows are reported measurable here with no correspondence established",
			report.Denominator.RustRowsMeasurableHere)
	}
	if len(report.PlaneMismatches) == 0 {
		t.Fatal("no plane mismatch is published, so the blocking reason above has nothing behind it")
	}
	// The mismatch rows must NOT also be filed as catalog defects: the whole
	// correction is that they are not defects in the catalog.
	for _, defect := range report.CatalogDefects {
		if defect.Side == "RUST" {
			t.Fatalf("a Rust plane mismatch is still filed as a defect in the catalog: %+v", defect)
		}
	}
}

func TestAnEstablishedCorrespondenceRemovesThePlaneBlockForThoseObligationsOnly(t *testing.T) {
	// The counterpart reading. A blocking reason that can never be absent is
	// not derived from anything; this proves the report reads the record rather
	// than hard-coding the block. It establishes the correspondence only inside
	// a throwaway sandbox, with a decision record written for the purpose.
	root := sandbox(t)
	decision := filepath.Join(root, "evidence", "governance", "decisions", "sandbox-plane-decision.json")
	if err := os.MkdirAll(filepath.Dir(decision), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body := `{"decisions":{"sandbox_plane_correspondence_driver":{"choice":"ESTABLISHED"}}}`
	if err := os.WriteFile(decision, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	const record = "evidence/governance/decisions/sandbox-plane-decision.json"
	const key = "sandbox_plane_correspondence_driver"
	rewriteJSON(t, root, PlaneCorrespondencePath, func(tree map[string]any) {
		for _, raw := range rows(tree, "crates") {
			row := raw.(map[string]any)
			if row["catalog_namespace"] == "websocket_driver" {
				row["correspondence_state"] = CorrespondenceEstablished
				row["owner_decision_record"] = record
				row["owner_decision_key"] = key
			}
		}
		for _, raw := range rows(tree, "source_paths") {
			row := raw.(map[string]any)
			if row["catalog_source_path"] == "rust/websocket-driver/src/lib.rs" {
				row["correspondence_state"] = CorrespondenceEstablished
				row["owner_decision_record"] = record
				row["owner_decision_key"] = key
			}
		}
	})
	report, err := DeriveReport(root)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	blocked, cleared := 0, 0
	for _, row := range report.Obligations {
		onDriver := row.Rust.CatalogSourcePath == "rust/websocket-driver/src/lib.rs"
		has := false
		for _, reason := range row.BlockingReasons {
			if reason == BlockPlaneNotEstablished {
				has = true
			}
		}
		switch {
		case onDriver && has:
			t.Fatalf("%s still blocks on the plane correspondence after it was established", row.ObligationID)
		case onDriver:
			cleared++
		case has:
			blocked++
		default:
			t.Fatalf("%s does not block on the plane correspondence and is not on the established path", row.ObligationID)
		}
	}
	if cleared != 2 || blocked != 22 {
		t.Fatalf("cleared=%d blocked=%d; the catalog puts 2 obligations on the driver path and 22 elsewhere", cleared, blocked)
	}
	if report.Denominator.RustRowsMeasurableHere != 2 {
		t.Fatalf("measurable rows = %d, want 2", report.Denominator.RustRowsMeasurableHere)
	}
	// Still 24/24 blocking: the plane correspondence was never the only reason
	// any obligation blocked, and clearing it must not clear the freeze.
	if report.Freeze.BlockingObligations != CatalogDenominator {
		t.Fatalf("freeze blocks %d of %d after clearing two plane rows", report.Freeze.BlockingObligations, CatalogDenominator)
	}
}

// ---------------------------------------------------------------------------
// The Java-column finding is plane-independent, and this correction must not
// have softened it.
// ---------------------------------------------------------------------------

func TestTheJavaColumnFindingSurvivesTheCorrection(t *testing.T) {
	catalogBytes, _, err := LoadArtifact(repoRoot(t), CatalogPath)
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	catalog, err := DecodeCatalog(catalogBytes)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	digests := map[string]bool{}
	paths := map[string]bool{}
	disconnected := 0
	for _, binding := range catalog.JavaBindings {
		digests[binding.SourceSHA256] = true
		paths[binding.SourcePath] = true
		if binding.ConnectionState == "DISCONNECTED" {
			disconnected++
		}
	}
	if len(catalog.JavaBindings) != CatalogDenominator {
		t.Fatalf("%d java bindings", len(catalog.JavaBindings))
	}
	if len(digests) != 1 {
		t.Fatalf("the java column carries %d distinct source digests; the finding is that all %d rows share ONE whole-archive digest",
			len(digests), CatalogDenominator)
	}
	if disconnected != CatalogDenominator {
		t.Fatalf("%d of %d java bindings read DISCONNECTED", disconnected, CatalogDenominator)
	}
	// Every Java source_path is synthesised: it treats a METHOD as a file, and
	// it exists on NO plane. This plane is the one this process can read.
	for path := range paths {
		if _, err := os.Stat(filepath.Join(repoRoot(t), filepath.FromSlash(path))); err == nil {
			t.Fatalf("java source_path %q exists on this plane; the finding is that none of them do", path)
		}
	}
	if len(paths) == 0 {
		t.Fatal("no java source paths were read, so the absence above proves nothing")
	}
}

// TestThePlaneRecordDoesNotWeakenTheJavaFinding pins the record's own text: the
// correction is about the Rust column only, and the document must say so.
func TestThePlaneRecordDoesNotWeakenTheJavaFinding(t *testing.T) {
	data, _, err := LoadArtifact(repoRoot(t), PlaneCorrespondencePath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	var doc PlaneCorrespondence
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	joined := strings.Join(doc.NotClaims, " ")
	for _, want := range []string{"JAVA column", "NEITHER plane", "DISCONNECTED"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("the record's not_claims do not keep the Java finding visible: missing %q", want)
		}
	}
}
