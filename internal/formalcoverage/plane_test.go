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

// ---------------------------------------------------------------------------
// The nineteen checks that survived the first deletion sweep. Each one below
// exists because deleting the check left every test green, which is not
// evidence that the check holds -- it is evidence that nothing was reading it.
// ---------------------------------------------------------------------------

func TestATamperedCatalogIsRefusedByThePlaneVerifier(t *testing.T) {
	root := sandbox(t)
	path := filepath.Join(root, filepath.FromSlash(CatalogPath))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// One trailing byte. The JSON still decodes; the identity does not.
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	findings, _, err := VerifyPlaneCorrespondence(root)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !hasPlaneCheck(findings, "CATALOG_STILL_VENDORED_BYTES") {
		t.Fatalf("a one-byte change to the vendored catalog was accepted; findings were %+v", findings)
	}
}

func TestAWritableOriginPlaneIsRefused(t *testing.T) {
	planeFinding(t, func(tree map[string]any) {
		tree["origin_plane"].(map[string]any)["writable_from_here"] = true
	}, "ORIGIN_PLANE_IS_NOT_WRITABLE_FROM_HERE")
}

func TestABlankOwnerQuestionIsRefused(t *testing.T) {
	planeFinding(t, func(tree map[string]any) {
		tree["owner_question"] = "  "
	}, "THE_RECORD_STATES_THE_OWNER_QUESTION")
}

func TestAnOwnerQuestionWithNoEvidenceRequirementIsRefused(t *testing.T) {
	planeFinding(t, func(tree map[string]any) {
		tree["evidence_required_to_answer_it"] = []any{}
	}, "THE_OWNER_QUESTION_STATES_ITS_EVIDENCE_REQUIREMENT")
}

func TestADuplicateNamespaceRowIsRefused(t *testing.T) {
	planeFinding(t, func(tree map[string]any) {
		list := rows(tree, "crates")
		tree["crates"] = append(list, list[0])
	}, "ONE_ROW_PER_CATALOG_NAMESPACE")
}

func TestADuplicateSourcePathRowIsRefused(t *testing.T) {
	planeFinding(t, func(tree map[string]any) {
		list := rows(tree, "source_paths")
		tree["source_paths"] = append(list, list[0])
	}, "ONE_ROW_PER_CATALOG_SOURCE_PATH")
}

func TestADuplicateSymbolRowIsRefused(t *testing.T) {
	planeFinding(t, func(tree map[string]any) {
		list := rows(tree, "production_symbols")
		tree["production_symbols"] = append(list, list[0])
	}, "ONE_ROW_PER_CATALOG_SYMBOL")
}

func TestARowForANamespaceTheCatalogNeverUsesIsRefused(t *testing.T) {
	planeFinding(t, func(tree map[string]any) {
		tree["crates"] = append(rows(tree, "crates"), map[string]any{
			"catalog_namespace":    "namespace_the_catalog_never_names",
			"obligation_count":     1.0,
			"correspondence_state": CorrespondenceNone,
			"evidence":             []any{"invented"},
		})
	}, "ROW_NAMES_A_NAMESPACE_THE_CATALOG_USES")
}

func TestARowForAPathTheCatalogNeverNamesIsRefused(t *testing.T) {
	planeFinding(t, func(tree map[string]any) {
		tree["source_paths"] = append(rows(tree, "source_paths"), map[string]any{
			"catalog_source_path":  "rust/invented/src/lib.rs",
			"obligation_count":     1.0,
			"correspondence_state": CorrespondenceNone,
			"evidence":             []any{"invented"},
		})
	}, "ROW_NAMES_A_PATH_THE_CATALOG_USES")
}

func TestARowForASymbolTheCatalogNeverDeclaresIsRefused(t *testing.T) {
	planeFinding(t, func(tree map[string]any) {
		tree["production_symbols"] = append(rows(tree, "production_symbols"), map[string]any{
			"catalog_production_symbol": "invented::Symbol::method",
			"obligation_count":          1.0,
			"correspondence_state":      CorrespondenceNone,
		})
	}, "ROW_NAMES_A_SYMBOL_THE_CATALOG_USES")
}

func TestARowWithNoEvidenceIsRefused(t *testing.T) {
	planeFinding(t, func(tree map[string]any) {
		rows(tree, "crates")[0].(map[string]any)["evidence"] = []any{}
	}, "EVERY_ROW_CITES_ITS_EVIDENCE")
}

func TestASymbolRowThatDoesNotSayWhatDefeatsSubstitutionIsRefused(t *testing.T) {
	planeFinding(t, func(tree map[string]any) {
		rows(tree, "production_symbols")[0].(map[string]any)["difference_that_defeats_substitution"] = " "
	}, "EVERY_UNESTABLISHED_SYMBOL_SAYS_WHAT_DEFEATS_SUBSTITUTION")
}

func TestACandidateCrateDirectoryThatIsNotHereIsRefused(t *testing.T) {
	planeFinding(t, func(tree map[string]any) {
		rows(tree, "crates")[0].(map[string]any)["candidate_directory_on_this_plane"] = "rust/no-such-crate"
	}, "CANDIDATE_CRATE_EXISTS_ON_THIS_PLANE")
}

func TestACandidatePathThatIsHonestlyAbsentStillDefeatsCorrespondence(t *testing.T) {
	// Declaring the candidate absent AND still claiming an adaptation is the
	// subtle version: the existence column is truthful, the correspondence
	// claim on top of it is not.
	planeFinding(t, func(tree map[string]any) {
		row := rows(tree, "source_paths")[0].(map[string]any)
		row["candidate_path_on_this_plane"] = "rust/ws-core/src/no-such-file.rs"
		row["candidate_path_exists_on_this_plane"] = false
	}, "A_CANDIDATE_THAT_DOES_NOT_EXIST_IS_NO_CORRESPONDENCE")
}

func TestASymbolRowWithNoCitationStillClaimingCorrespondenceIsRefused(t *testing.T) {
	planeFinding(t, func(tree map[string]any) {
		row := rows(tree, "production_symbols")[0].(map[string]any)
		row["nearest_declaration_file_on_this_plane"] = ""
		row["correspondence_state"] = CorrespondenceBorrowAdapted
	}, "A_ROW_WITH_NO_NEAREST_DECLARATION_IS_NO_CORRESPONDENCE")
}

func TestACitationInAFileThatIsNotHereIsRefused(t *testing.T) {
	planeFinding(t, func(tree map[string]any) {
		rows(tree, "production_symbols")[0].(map[string]any)["nearest_declaration_file_on_this_plane"] = "rust/ws-core/src/no-such-file.rs"
	}, "NEAREST_DECLARATION_FILE_EXISTS")
}

func TestACitationPastTheEndOfItsFileIsRefused(t *testing.T) {
	planeFinding(t, func(tree map[string]any) {
		rows(tree, "production_symbols")[0].(map[string]any)["nearest_declaration_line"] = 999999.0
	}, "NEAREST_DECLARATION_LINE_IS_IN_THE_FILE")
}

func TestAnEstablishedDecisionOutsideTheProtectedStoreIsRefused(t *testing.T) {
	planeFinding(t, func(tree map[string]any) {
		row := rows(tree, "crates")[0].(map[string]any)
		row["correspondence_state"] = CorrespondenceEstablished
		row["owner_decision_record"] = "drafts/self-review/i-decided-this-myself.md"
		row["owner_decision_key"] = "plane_correspondence"
	}, "OWNER_DECISION_LIVES_IN_THE_PROTECTED_STORE")
}

func TestAPlaneThatActuallyShipsTheCatalogsNamespaceMayNotBeCalledUnestablished(t *testing.T) {
	// The mirror of every other check here. All of them hunt a record that
	// claims MORE than the tree supports. This one hunts a record that claims
	// LESS: if this plane really did ship websocket_core, labelling the row
	// SHARED_ANCESTRY_ONLY would understate a correspondence that exists, and
	// a label that can only be too weak is as bad as one that can only be too
	// strong.
	root := sandbox(t)
	manifest := filepath.Join(root, "rust", "ws-core", "Cargo.toml")
	if err := os.WriteFile(manifest, []byte("[package]\nname = \"ws-core\"\n\n[lib]\nname = \"websocket_core\"\n"), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	rewriteJSON(t, root, PlaneCorrespondencePath, func(tree map[string]any) {
		for _, raw := range rows(tree, "crates") {
			row := raw.(map[string]any)
			if row["catalog_namespace"] == "websocket_core" {
				row["candidate_lib_name_on_this_plane"] = "websocket_core"
			}
		}
	})
	findings, _, err := VerifyPlaneCorrespondence(root)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !hasPlaneCheck(findings, "AN_EQUAL_NAMESPACE_IS_NOT_SILENTLY_WEAKENED") {
		t.Fatalf("a plane that ships the catalog's own namespace was still reported as having no established correspondence; findings were %+v", findings)
	}
}

func hasPlaneCheck(findings []PlaneFinding, check string) bool {
	for _, finding := range findings {
		if finding.Check == check {
			return true
		}
	}
	return false
}

// TestALibNameThatDisagreesWithThePackageNameWins closes the one mutation that
// survived the second deletion sweep. Everywhere in either plane the package
// name with hyphens replaced happens to EQUAL the [lib] name, so a mutation
// that ignored [lib] name entirely left every test green -- which is not
// evidence that the [lib] branch works, only that nothing distinguished it.
// Cargo does not require the two to agree, and the namespace `use` resolves
// against is the [lib] one.
func TestALibNameThatDisagreesWithThePackageNameWins(t *testing.T) {
	root := t.TempDir()
	writeCrate(t, root, "some-dir", "[package]\nname = \"package-name\"\n\n[lib]\nname = \"a_quite_different_namespace\"\n")
	namespaces, err := shippedCrateNamespaces(root)
	if err != nil {
		t.Fatalf("shippedCrateNamespaces: %v", err)
	}
	if len(namespaces) != 1 || namespaces[0] != "a_quite_different_namespace" {
		t.Fatalf("the workspace ships %v; the [lib] name is the namespace, not the package name", namespaces)
	}
}

// TestBinTargetNamesAreNotCrateNamespaces: a manifest's [[bin]] name is a
// binary, not a library namespace, and this repository ships a crate whose
// [[bin]] names differ from its package name. Reading the first `name =` in
// the file would take the wrong one.
func TestBinTargetNamesAreNotCrateNamespaces(t *testing.T) {
	root := t.TempDir()
	writeCrate(t, root, "candidate-stub",
		"[package]\nname = \"candidate-stub\"\n\n[[bin]]\nname = \"us005-candidate-stub\"\n\n[[bin]]\nname = \"us005-mutant\"\n")
	namespaces, err := shippedCrateNamespaces(root)
	if err != nil {
		t.Fatalf("shippedCrateNamespaces: %v", err)
	}
	if len(namespaces) != 1 || namespaces[0] != "candidate_stub" {
		t.Fatalf("the workspace ships %v; a [[bin]] name is not a crate namespace", namespaces)
	}
}

// TestTheRustReasonCodesNameThePlaneTheyAreTrueOf is the semantic reading for
// the rename. Without it the only thing that noticed a revert was the retained
// artifact byte comparison, which detects that the output CHANGED and says
// nothing about whether it is right.
func TestTheRustReasonCodesNameThePlaneTheyAreTrueOf(t *testing.T) {
	for _, code := range []string{BlockRustPathAbsent, BlockRustNamespaceAbsent, RustPathAbsent, RustNamespaceDisagrees} {
		if !strings.Contains(code, "THIS_PLANE") {
			t.Fatalf("%q does not say which tree it is true of; the catalog's paths and namespaces resolve on the plane it came from, and a code that omits the plane reads as an accusation against the document", code)
		}
	}
	// And the two that DO resolve here must not have acquired the same
	// hedge: a state that is true everywhere needs no plane qualifier beyond
	// naming the one it was read on.
	if !strings.Contains(RustPathPresent, "THIS_PLANE") || !strings.Contains(RustNamespaceAgrees, "THIS_PLANE") {
		t.Fatalf("the positive states %q/%q should also name the plane they were read on", RustPathPresent, RustNamespaceAgrees)
	}
	if BlockPlaneNotEstablished == "" || !strings.Contains(BlockPlaneNotEstablished, "ANOTHER_PLANE") {
		t.Fatalf("the cause code %q does not name the cause", BlockPlaneNotEstablished)
	}
	// The old codes must be gone, not merely unused: a grep for them is how a
	// reader would find the corrected diagnosis.
	for _, retired := range []string{"CATALOG_RUST_SOURCE_PATH_EXISTS_IN_NO_TREE", "CATALOG_RUST_NAMESPACE_MATCHES_NO_SHIPPED_CRATE"} {
		if BlockRustPathAbsent == retired || BlockRustNamespaceAbsent == retired {
			t.Fatalf("%q is back", retired)
		}
	}
}

// TestThePlaneBlockAppearsBesideTheSymptomsNotInsteadOfThem: the two
// observations about this tree stay, because they are true; the cause is added
// beside them. Dropping the symptoms would lose real information and dropping
// the cause is what made the old diagnosis wrong.
func TestThePlaneBlockAppearsBesideTheSymptomsNotInsteadOfThem(t *testing.T) {
	report, err := DeriveReport(repoRoot(t))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	for _, row := range report.Obligations {
		reasons := map[string]bool{}
		for _, reason := range row.BlockingReasons {
			reasons[reason] = true
		}
		for _, want := range []string{BlockRustPathAbsent, BlockRustNamespaceAbsent, BlockPlaneNotEstablished} {
			if !reasons[want] {
				t.Fatalf("%s does not carry %s", row.ObligationID, want)
			}
		}
	}
	if report.Freeze.BlockingObligations != CatalogDenominator {
		t.Fatalf("freeze blocks %d of %d; the corrected diagnosis must not reduce the blocked count",
			report.Freeze.BlockingObligations, CatalogDenominator)
	}
}
