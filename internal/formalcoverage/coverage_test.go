package formalcoverage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// repoRoot walks up from the test's working directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no go.mod above %s", dir)
		}
		dir = parent
	}
}

// filesTheDerivationReads is every repository path Reconcile and DeriveReport
// open. It is written out rather than discovered so that a new input cannot be
// added without a test author noticing that the sandbox needs it too.
var filesTheDerivationReads = []string{
	CatalogPath,
	ProofTargetsPath,
	BindingSpecPath,
	ProjectionPath,
	LinkagePath,
	ReceiptPath,
	CorrectionPath,
	PlaneCorrespondencePath,
	"assurance/developer-tools/port-seam-dossier.json",
	"evidence/intake/compatibility-surface.json",
	"evidence/intake/semantic-id-migration-map.json",
	// Added when the artifact this pin declares was brought onto this line
	// under OA-catalog-plane-denominator. Reconcile opens every declared basis
	// path, so this one is now an input; leaving it out would give the sandbox
	// a basis pin the repository does not have and make every sandbox test
	// read a tree that differs from the one the gate reads.
	"corpora/frame/codec.json",
	// The plane-correspondence verifier reads back every file:line citation it
	// makes about THIS plane, so the sandbox needs the cited files themselves.
	// A citation nobody reads back is a name; these four are what make the
	// difference.
	"rust/ws-core/src/connection.rs",
	"rust/ws-core/src/error.rs",
	"rust/ws-core/src/framing.rs",
	"rust/ws-driver/src/lib.rs",
}

// sandbox materialises a throwaway copy of exactly those inputs, plus the
// shipped crate layout the Rust-side check reads, so a test can tamper with one
// input without touching the repository.
func sandbox(t *testing.T) string {
	t.Helper()
	root := repoRoot(t)
	dst := t.TempDir()
	for _, relative := range filesTheDerivationReads {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatalf("read %s: %v", relative, err)
		}
		target := filepath.Join(dst, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", relative, err)
		}
		if err := os.WriteFile(target, data, 0o644); err != nil {
			t.Fatalf("write %s: %v", relative, err)
		}
	}
	crates, err := os.ReadDir(filepath.Join(root, "rust"))
	if err != nil {
		t.Fatalf("read rust/: %v", err)
	}
	for _, entry := range crates {
		if !entry.IsDir() {
			continue
		}
		manifest := filepath.Join(root, "rust", entry.Name(), "Cargo.toml")
		if _, err := os.Stat(manifest); err != nil {
			continue
		}
		target := filepath.Join(dst, "rust", entry.Name())
		if err := os.MkdirAll(target, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", target, err)
		}
		// The manifest is copied whole rather than stubbed. The namespace a
		// crate ships is declared INSIDE the manifest ([lib] name), so a stub
		// would give the sandbox a crate layout with no namespaces at all and
		// the Rust-side check would pass for the wrong reason.
		manifestBytes, err := os.ReadFile(manifest)
		if err != nil {
			t.Fatalf("read %s: %v", manifest, err)
		}
		if err := os.WriteFile(filepath.Join(target, "Cargo.toml"), manifestBytes, 0o644); err != nil {
			t.Fatalf("write manifest: %v", err)
		}
	}
	return dst
}

// rewriteJSON loads one sandbox file as a generic tree, hands it to mutate, and
// writes it back.
func rewriteJSON(t *testing.T, root, relative string, mutate func(map[string]any)) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", relative, err)
	}
	var tree map[string]any
	if err := json.Unmarshal(data, &tree); err != nil {
		t.Fatalf("decode %s: %v", relative, err)
	}
	mutate(tree)
	encoded, err := json.MarshalIndent(tree, "", "  ")
	if err != nil {
		t.Fatalf("encode %s: %v", relative, err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
		t.Fatalf("write %s: %v", relative, err)
	}
}

// ---------------------------------------------------------------------------
// Identity: the denominator must still be the bytes it was borrowed as.
// ---------------------------------------------------------------------------

// TestCatalogIsStillTheVendoredCodexBytes duplicates internal/javabind's
// assertion on purpose. This package computes numbers over that catalog, so it
// must not depend on another package's test still existing to know it is
// reading the catalog it thinks it is.
func TestCatalogIsStillTheVendoredCodexBytes(t *testing.T) {
	data, identity, err := LoadArtifact(repoRoot(t), CatalogPath)
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	if identity.SHA256 != CatalogSHA256 {
		t.Fatalf("catalog sha256 is %s, want the vendored %s", identity.SHA256, CatalogSHA256)
	}
	if identity.GitBlob != CatalogGitBlob {
		t.Fatalf("catalog git blob is %s, want the Codex original %s", identity.GitBlob, CatalogGitBlob)
	}
	if len(data) == 0 {
		t.Fatal("catalog is empty")
	}
}

// TestTheCorrectionProposalDoesNotEditTheCatalog is the whole point of putting
// the corrections in a separate file. The proposal must pin the same identity
// the catalog on disk still has.
func TestTheCorrectionProposalDoesNotEditTheCatalog(t *testing.T) {
	root := repoRoot(t)
	_, identity, err := LoadArtifact(root, CatalogPath)
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	proposalBytes, _, err := LoadArtifact(root, CorrectionPath)
	if err != nil {
		t.Fatalf("load proposal: %v", err)
	}
	proposal, err := DecodeCorrectionProposal(proposalBytes)
	if err != nil {
		t.Fatalf("decode proposal: %v", err)
	}
	if proposal.Immutability.ModifiesCatalog {
		t.Fatal("the proposal declares that it modifies the catalog")
	}
	if proposal.Immutability.CatalogSHA256 != identity.SHA256 || proposal.Immutability.CatalogGitBlob != identity.GitBlob {
		t.Fatalf("proposal pins %s/%s but the catalog on disk is %s/%s",
			proposal.Immutability.CatalogSHA256, proposal.Immutability.CatalogGitBlob, identity.SHA256, identity.GitBlob)
	}
	if len(proposal.Immutability.WhyRight) < 3 {
		t.Fatalf("the proposal gives %d reasons the immutability constraint is right; it must argue the constraint, not just obey it", len(proposal.Immutability.WhyRight))
	}
}

func TestReconcileRefusesACatalogThatIsNotTheVendoredBytes(t *testing.T) {
	root := sandbox(t)
	rewriteJSON(t, root, CatalogPath, func(tree map[string]any) { tree["assurance"] = "TAMPERED" })
	if _, err := Reconcile(root); err == nil {
		t.Fatal("Reconcile accepted a catalog whose bytes are not the vendored ones")
	}
}

// ---------------------------------------------------------------------------
// The retained artifacts are exactly what the inputs derive.
// ---------------------------------------------------------------------------

func TestRetainedReconciliationIsExactlyWhatTheDenominatorsDerive(t *testing.T) {
	root := repoRoot(t)
	derived, err := Reconcile(root)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	encoded, err := MarshalArtifact(derived)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	stored, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(ReconciliationPath)))
	if err != nil {
		t.Fatalf("read stored reconciliation: %v", err)
	}
	if !bytes.Equal(bytes.TrimRight(stored, "\n"), bytes.TrimRight(encoded, "\n")) {
		t.Fatal("the retained reconciliation is not what the two denominators derive")
	}
}

func TestRetainedReportsAreExactlyWhatTheEvidenceDerives(t *testing.T) {
	root := repoRoot(t)
	report, err := DeriveReport(root)
	if err != nil {
		t.Fatalf("derive report: %v", err)
	}
	encoded, err := MarshalArtifact(report)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	storedJSON, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(ReportJSONPath)))
	if err != nil {
		t.Fatalf("read stored report: %v", err)
	}
	if !bytes.Equal(bytes.TrimRight(storedJSON, "\n"), bytes.TrimRight(encoded, "\n")) {
		t.Fatal("the retained machine-readable report is not what the evidence derives")
	}
	storedMarkdown, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(ReportMarkdownPath)))
	if err != nil {
		t.Fatalf("read stored markdown: %v", err)
	}
	if !bytes.Equal(bytes.TrimRight(storedMarkdown, "\n"), bytes.TrimRight(RenderMarkdown(report), "\n")) {
		t.Fatal("the retained human-readable report is not what the same derived report renders")
	}
}

// TestARewrittenNumberFailsTheComparison is the RED reading for the two tests
// above: a hand-edited numerator must not survive.
func TestARewrittenNumberFailsTheComparison(t *testing.T) {
	root := repoRoot(t)
	report, err := DeriveReport(root)
	if err != nil {
		t.Fatalf("derive report: %v", err)
	}
	for index := range report.Axes {
		if report.Axes[index].Axis == AxisAggregate {
			report.Axes[index].Numerator = 24
		}
	}
	encoded, err := MarshalArtifact(report)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	stored, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(ReportJSONPath)))
	if err != nil {
		t.Fatalf("read stored report: %v", err)
	}
	if bytes.Equal(bytes.TrimRight(stored, "\n"), bytes.TrimRight(encoded, "\n")) {
		t.Fatal("an inflated aggregate compared equal to the retained report")
	}
}

// ---------------------------------------------------------------------------
// The reconciliation, checked against an independently written join.
// ---------------------------------------------------------------------------

// independentCatalogKey and independentTargetKey are a SECOND implementation of
// the join key, written differently on purpose. If the artifact agreed with
// CatalogJavaKey only because both call the same function, the reconciliation
// would be checking nothing.
func independentCatalogKey(symbol string) string {
	head := symbol
	if cut := strings.SplitN(symbol, "(", 2); len(cut) == 2 {
		head = cut[0]
	}
	segments := strings.Split(head, ".")
	tail := segments[len(segments)-1]
	if tail != "" && strings.ToUpper(tail[:1]) == tail[:1] {
		return tail + "#" + tail
	}
	if len(segments) < 2 {
		return tail + "#" + tail
	}
	return segments[len(segments)-2] + "#" + tail
}

var independentMemberPattern = regexp.MustCompile(`^([A-Za-z0-9_.$]+)#([A-Za-z0-9_$]*)`)

func independentTargetKey(member string) string {
	match := independentMemberPattern.FindStringSubmatch(strings.TrimSpace(member))
	if match == nil {
		word := strings.Fields(strings.TrimSpace(member))
		if len(word) == 0 {
			return ""
		}
		segments := strings.Split(word[0], ".")
		tail := segments[len(segments)-1]
		return tail + "#" + tail
	}
	segments := strings.Split(match[1], ".")
	simple := segments[len(segments)-1]
	if match[2] == "" {
		return simple + "#" + simple
	}
	return simple + "#" + match[2]
}

func TestTheJoinAgreesWithAnIndependentlyWrittenJoin(t *testing.T) {
	root := repoRoot(t)
	catalogBytes, _, err := LoadArtifact(root, CatalogPath)
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}
	catalog, err := DecodeCatalog(catalogBytes)
	if err != nil {
		t.Fatalf("decode catalog: %v", err)
	}
	planBytes, _, err := LoadArtifact(root, ProofTargetsPath)
	if err != nil {
		t.Fatalf("load plan: %v", err)
	}
	plan, err := DecodeProofTargets(planBytes)
	if err != nil {
		t.Fatalf("decode plan: %v", err)
	}
	catalogKeys := map[string]bool{}
	for _, binding := range catalog.JavaBindings {
		catalogKeys[independentCatalogKey(binding.ProductionSymbol)] = true
	}
	targetKeys := map[string]bool{}
	for _, target := range plan.Targets {
		for _, symbol := range target.ProductionSymbols {
			for _, member := range symbol.JavaAuthorityMember {
				targetKeys[independentTargetKey(member)] = true
			}
		}
	}
	var both, catalogOnly, targetOnly []string
	for key := range catalogKeys {
		if targetKeys[key] {
			both = append(both, key)
		} else {
			catalogOnly = append(catalogOnly, key)
		}
	}
	for key := range targetKeys {
		if !catalogKeys[key] {
			targetOnly = append(targetOnly, key)
		}
	}
	sort.Strings(both)
	sort.Strings(catalogOnly)
	sort.Strings(targetOnly)

	reconciliation, err := Reconcile(root)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	for _, pair := range []struct {
		name           string
		mine, artifact []string
	}{
		{"both", both, reconciliation.JavaKeysBoth},
		{"catalog only", catalogOnly, reconciliation.JavaKeysCatalog},
		{"proof-target only", targetOnly, reconciliation.JavaKeysTarget},
	} {
		if strings.Join(pair.mine, ",") != strings.Join(pair.artifact, ",") {
			t.Fatalf("%s key set disagrees:\n independent %v\n artifact    %v", pair.name, pair.mine, pair.artifact)
		}
	}
}

func TestEveryObligationAndTargetAppearsExactlyOnceInTheReconciliation(t *testing.T) {
	reconciliation, err := Reconcile(repoRoot(t))
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(reconciliation.Obligations) != CatalogDenominator {
		t.Fatalf("%d obligation rows, want %d", len(reconciliation.Obligations), CatalogDenominator)
	}
	if len(reconciliation.Targets) != ProofTargetDenominator {
		t.Fatalf("%d target rows, want %d", len(reconciliation.Targets), ProofTargetDenominator)
	}
	seen := map[string]int{}
	for _, row := range reconciliation.Obligations {
		seen[row.ObligationID]++
	}
	for id, count := range seen {
		if count != 1 {
			t.Fatalf("obligation %s appears %d times", id, count)
		}
	}
}

// TestUnmappedObligationsAndTargetsAreNamedNotSummarised is the finding this
// reconciliation exists to make. A count with no list is exactly the shape in
// which an interesting case gets rounded away.
func TestUnmappedObligationsAndTargetsAreNamedNotSummarised(t *testing.T) {
	reconciliation, err := Reconcile(repoRoot(t))
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var unmappedObligations, unmappedTargets []string
	for _, row := range reconciliation.Obligations {
		if row.State == MappingObligationNoTarget {
			if len(row.TargetIDs) != 0 {
				t.Fatalf("%s is marked unmapped yet names %v", row.ObligationID, row.TargetIDs)
			}
			unmappedObligations = append(unmappedObligations, row.ObligationID)
		}
	}
	for _, row := range reconciliation.Targets {
		if row.State == MappingTargetNoObligation {
			if len(row.ObligationIDs) != 0 {
				t.Fatalf("%s is marked unmapped yet names %v", row.TargetID, row.ObligationIDs)
			}
			unmappedTargets = append(unmappedTargets, row.TargetID)
		}
	}
	if len(unmappedObligations) != reconciliation.Counts.ObligationsWithNoTarget {
		t.Fatalf("counts say %d obligations with no target, rows name %d",
			reconciliation.Counts.ObligationsWithNoTarget, len(unmappedObligations))
	}
	if len(unmappedTargets) != reconciliation.Counts.TargetsWithNoObligation {
		t.Fatalf("counts say %d targets with no obligation, rows name %d",
			reconciliation.Counts.TargetsWithNoObligation, len(unmappedTargets))
	}
	if len(unmappedObligations) == 0 || len(unmappedTargets) == 0 {
		t.Fatal("the reconciliation reports a perfect mapping; that would be a finding in itself and is not what these two documents say")
	}
}

// TestCatalogBasisPinsAreComparedAgainstTheFilesOnDisk: the catalog declares
// which documents its denominator was derived from, with digests. A pin that is
// never compared is decoration.
func TestCatalogBasisPinsAreComparedAgainstTheFilesOnDisk(t *testing.T) {
	reconciliation, err := Reconcile(repoRoot(t))
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(reconciliation.BasisPins) == 0 {
		t.Fatal("no basis pin was compared")
	}
	drifted, absent := 0, 0
	for _, pin := range reconciliation.BasisPins {
		switch pin.Agreement {
		case BasisAgreementExact:
			if pin.OnDiskSHA != pin.DeclaredSHA {
				t.Fatalf("%s is reported as matching but %s != %s", pin.Path, pin.OnDiskSHA, pin.DeclaredSHA)
			}
		case BasisAgreementDrifted:
			if pin.OnDiskSHA == pin.DeclaredSHA && pin.OnDiskBlob == pin.DeclaredBlob {
				t.Fatalf("%s is reported as drifted but both identities match", pin.Path)
			}
			if _, statErr := os.Stat(filepath.Join(repoRoot(t), filepath.FromSlash(pin.Path))); statErr != nil {
				t.Fatalf("%s is reported as DRIFTED but it is not on this plane at all; drift and absence are different findings", pin.Path)
			}
			drifted++
		case BasisAgreementPathAbsent:
			// A pin whose path is absent here has NOT drifted, and the check
			// must not be satisfied by the label alone: the file really must
			// be missing.
			if _, statErr := os.Stat(filepath.Join(repoRoot(t), filepath.FromSlash(pin.Path))); statErr == nil {
				t.Fatalf("%s is reported as absent from this plane but the file is here", pin.Path)
			}
			absent++
		default:
			t.Fatalf("%s carries agreement %q, which is not in the vocabulary", pin.Path, pin.Agreement)
		}
	}
	if drifted == 0 {
		t.Fatal("every declared basis pin matches the file on disk; that is not what this tree contains and the check is therefore not reading the tree")
	}
	// `absent` is deliberately NOT required to be non-zero any more, and the
	// change is a fact about the tree rather than a weakening of the rule.
	// corpora/frame/codec.json was the one basis path this plane did not hold,
	// and it was brought onto this line under OA-catalog-plane-denominator, so
	// no declared basis path is absent here today. Requiring one would be a
	// test that fails when the tree gets BETTER. What must not be lost is the
	// discrimination the old assertion was really about -- that an absent path
	// is reported as absent and never as drift -- so that polarity moved to
	// TestARemovedBasisFileIsReportedAbsentAndNotDrifted, where the absence is
	// created on purpose instead of being borrowed from whatever the tree
	// happens to be missing.
	if absent > 0 {
		t.Logf("%d basis pin(s) name a path absent from this plane", absent)
	}
}

// TestARemovedBasisFileIsReportedAbsentAndNotDrifted is the polarity the live
// tree used to supply by accident: absence and drift are different findings and
// must not share a code. Reading them as one is absence standing in for defect.
//
// The absence is MADE here rather than found, so the check keeps working
// whatever the repository happens to hold. The control is the same pin before
// the removal: it must not already be absent, or the test would prove nothing.
func TestARemovedBasisFileIsReportedAbsentAndNotDrifted(t *testing.T) {
	root := sandbox(t)
	before, err := Reconcile(root)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var subject string
	for _, pin := range before.BasisPins {
		if pin.Agreement == BasisAgreementExact {
			subject = pin.Path
			break
		}
	}
	if subject == "" {
		t.Fatal("no basis pin matches its file in the sandbox, so removing one would not distinguish absence from drift")
	}
	if err := os.Remove(filepath.Join(root, filepath.FromSlash(subject))); err != nil {
		t.Fatalf("remove %s: %v", subject, err)
	}
	after, err := Reconcile(root)
	if err != nil {
		t.Fatalf("reconcile after removal: %v", err)
	}
	found := false
	for _, pin := range after.BasisPins {
		if pin.Path != subject {
			continue
		}
		found = true
		if pin.Agreement != BasisAgreementPathAbsent {
			t.Fatalf("%s was removed and is reported as %q, not %q", subject, pin.Agreement, BasisAgreementPathAbsent)
		}
		if pin.OnDiskSHA != "PATH_ABSENT" || pin.OnDiskBlob != "" {
			t.Fatalf("%s is absent but carries an on-disk identity %q/%q", subject, pin.OnDiskSHA, pin.OnDiskBlob)
		}
	}
	if !found {
		t.Fatalf("%s disappeared from the basis pins entirely; an absent path is still a declared pin", subject)
	}
}

func TestTamperingWithABasisFileFlipsItsPin(t *testing.T) {
	root := sandbox(t)
	before, err := Reconcile(root)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var matching string
	for _, pin := range before.BasisPins {
		if pin.Agreement == BasisAgreementExact {
			matching = pin.Path
		}
	}
	if matching == "" {
		t.Skip("no basis pin currently matches, so there is nothing to break")
	}
	path := filepath.Join(root, filepath.FromSlash(matching))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", matching, err)
	}
	if err := os.WriteFile(path, append(data, ' '), 0o644); err != nil {
		t.Fatalf("write %s: %v", matching, err)
	}
	after, err := Reconcile(root)
	if err != nil {
		t.Fatalf("reconcile after tamper: %v", err)
	}
	for _, pin := range after.BasisPins {
		if pin.Path == matching && pin.Agreement != BasisAgreementDrifted {
			t.Fatalf("appending one byte to %s left its pin reading %q", matching, pin.Agreement)
		}
	}
}

// TestCatalogRustBindingsAreCheckedAgainstTheShippedTree: the catalog's Rust
// column is checked for existence, not accepted as a name.
func TestCatalogRustBindingsAreCheckedAgainstTheShippedTree(t *testing.T) {
	root := repoRoot(t)
	reconciliation, err := Reconcile(root)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(reconciliation.RustBindingCheck) == 0 {
		t.Fatal("no catalog Rust binding was checked")
	}
	total := 0
	for _, check := range reconciliation.RustBindingCheck {
		total += check.ObligationCount
		switch check.PathState {
		case RustPathPresent:
			if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(check.SourcePath))); err != nil {
				t.Fatalf("%s is reported present but does not stat", check.SourcePath)
			}
		case RustPathAbsent:
			if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(check.SourcePath))); err == nil {
				t.Fatalf("%s is reported absent but exists", check.SourcePath)
			}
		default:
			t.Fatalf("%s carries path state %q", check.SourcePath, check.PathState)
		}
		if len(check.ShippedCrates) == 0 {
			t.Fatal("the check lists no shipped crate namespaces, so its namespace comparison compares nothing")
		}
	}
	if total != CatalogDenominator {
		t.Fatalf("the Rust checks account for %d obligations, not %d", total, CatalogDenominator)
	}
}

// ---------------------------------------------------------------------------
// The no-hiding rule.
// ---------------------------------------------------------------------------

func TestEveryNoHidingInvariantHolds(t *testing.T) {
	report, err := DeriveReport(repoRoot(t))
	if err != nil {
		t.Fatalf("derive report: %v", err)
	}
	if len(report.Invariants) < 11 {
		t.Fatalf("only %d invariants are enforced", len(report.Invariants))
	}
	for _, invariant := range report.Invariants {
		if !invariant.Holds {
			t.Fatalf("invariant %s does not hold: %s", invariant.ID, invariant.Detail)
		}
	}
}

// mustDerive returns the real report for the mutation attacks below.
func mustDerive(t *testing.T) Report {
	t.Helper()
	report, err := DeriveReport(repoRoot(t))
	if err != nil {
		t.Fatalf("derive report: %v", err)
	}
	return report
}

// failed reports whether the named invariant is violated after a mutation.
func failed(invariants []Invariant, id string) bool {
	for _, invariant := range invariants {
		if invariant.ID == id && !invariant.Holds {
			return true
		}
	}
	return false
}

func TestInflatingANumeratorWithoutItsMembersIsRefused(t *testing.T) {
	report := mustDerive(t)
	for index := range report.Axes {
		if report.Axes[index].Axis == AxisJavaCoverage {
			report.Axes[index].Numerator = 24
		}
	}
	if !failed(enforceNoHiding(report), "NH1") {
		t.Fatal("NH1 accepted a numerator larger than the member list it publishes")
	}
}

func TestDroppingAnObligationFromAnAxisIsRefused(t *testing.T) {
	report := mustDerive(t)
	for index := range report.Axes {
		if report.Axes[index].Axis == AxisJavaCoverage && len(report.Axes[index].BlockingObligations) > 0 {
			report.Axes[index].BlockingObligations = report.Axes[index].BlockingObligations[1:]
		}
	}
	if !failed(enforceNoHiding(report), "NH2") {
		t.Fatal("NH2 accepted an axis that no longer partitions the denominator")
	}
}

func TestCountingAnObligationThatAlsoBlocksIsRefused(t *testing.T) {
	report := mustDerive(t)
	for index := range report.Axes {
		axis := &report.Axes[index]
		if axis.Axis == AxisJavaCoverage && len(axis.BlockingObligations) > 0 {
			axis.CountedObligations = append(axis.CountedObligations, axis.BlockingObligations[0])
			axis.Numerator = len(axis.CountedObligations)
		}
	}
	if !failed(enforceNoHiding(report), "NH3") {
		t.Fatal("NH3 accepted an obligation counted and blocked on the same axis")
	}
}

func TestAnAggregateThatExceedsACoverageAxisIsRefused(t *testing.T) {
	report := mustDerive(t)
	var borrowed string
	for _, axis := range report.Axes {
		if axis.Axis == AxisJavaCoverage && len(axis.BlockingObligations) > 0 {
			borrowed = axis.BlockingObligations[0]
		}
	}
	for index := range report.Axes {
		axis := &report.Axes[index]
		if axis.Axis != AxisAggregate {
			continue
		}
		axis.CountedObligations = append(axis.CountedObligations, borrowed)
		axis.Numerator = len(axis.CountedObligations)
		for position, id := range axis.BlockingObligations {
			if id == borrowed {
				axis.BlockingObligations = append(axis.BlockingObligations[:position], axis.BlockingObligations[position+1:]...)
				break
			}
		}
	}
	if !failed(enforceNoHiding(report), "NH4") {
		t.Fatal("NH4 accepted an aggregate counting an obligation no coverage axis counts")
	}
}

func TestAWeightedAxisIsRefused(t *testing.T) {
	report := mustDerive(t)
	report.Axes[0].Weighting = "0.4 java, 0.6 rust"
	if !failed(enforceNoHiding(report), "NH5") {
		t.Fatal("NH5 accepted a weighted axis")
	}
}

func TestDeletingABlockingGapIsRefused(t *testing.T) {
	report := mustDerive(t)
	if len(report.BlockingGaps) == 0 {
		t.Fatal("no blocking gaps to delete")
	}
	report.BlockingGaps = report.BlockingGaps[1:]
	if !failed(enforceNoHiding(report), "NH6") {
		t.Fatal("NH6 accepted a report that dropped one of its blocking gaps")
	}
}

func TestEmptyingAGapsReasonsIsRefused(t *testing.T) {
	report := mustDerive(t)
	report.BlockingGaps[0].Reasons = nil
	if !failed(enforceNoHiding(report), "NH6") {
		t.Fatal("NH6 accepted a blocking gap with no reason")
	}
}

// TestSubRequiredStrengthMustBlock is AC3's own sentence, mechanised: evidence
// below the obligation's required strength blocks the freeze.
func TestSubRequiredStrengthMustBlock(t *testing.T) {
	report := mustDerive(t)
	cleared := false
	for index := range report.Obligations {
		row := &report.Obligations[index]
		if !row.Java.MeetsRequired || !row.Rust.MeetsRequired {
			row.Blocking = false
			row.BlockingReasons = nil
			cleared = true
			break
		}
	}
	if !cleared {
		t.Fatal("every obligation already meets required strength on both sides; there is nothing to test")
	}
	if !failed(enforceNoHiding(report), "NH7") {
		t.Fatal("NH7 accepted an obligation below required strength that is not blocking")
	}
}

func TestAFreezeVerdictThatIgnoresTheBlockingListIsRefused(t *testing.T) {
	report := mustDerive(t)
	report.Freeze.Verdict = "NOT_BLOCKED"
	if !failed(enforceNoHiding(report), "NH8") {
		t.Fatal("NH8 accepted NOT_BLOCKED with blocking obligations present")
	}
}

func TestLettingANonCoverageAxisFeedTheAggregateIsRefused(t *testing.T) {
	report := mustDerive(t)
	promoted := false
	for index := range report.Axes {
		if !report.Axes[index].IsCoverage {
			report.Axes[index].FeedsAggregate = true
			promoted = true
			break
		}
	}
	if !promoted {
		t.Fatal("no non-coverage axis exists to promote")
	}
	if !failed(enforceNoHiding(report), "NH9") {
		t.Fatal("NH9 accepted a non-coverage axis feeding the aggregate")
	}
}

func TestANonZeroNonCoverageAxisMustSayItIsNotCoverage(t *testing.T) {
	report := mustDerive(t)
	stripped := false
	for index := range report.Axes {
		axis := &report.Axes[index]
		if !axis.IsCoverage && axis.Numerator > 0 {
			axis.Note = ""
			stripped = true
			break
		}
	}
	if !stripped {
		t.Fatal("no non-coverage axis has a non-zero numerator, so this check is not reading the tree")
	}
	if !failed(enforceNoHiding(report), "NH9") {
		t.Fatal("NH9 accepted a non-zero non-coverage numerator that says nowhere that it is not coverage")
	}
}

func TestShrinkingTheDenominatorIsRefused(t *testing.T) {
	report := mustDerive(t)
	report.Obligations = report.Obligations[1:]
	if !failed(enforceNoHiding(report), "NH10") {
		t.Fatal("NH10 accepted a report over fewer than 24 obligations")
	}
}

// TestTheResolverCeilingCannotBeClaimedAway is the ceiling this branch was told
// to carry forward. While the plan records no resolver verification, no number
// in the report may say formal evidence reaches a resolver-verified symbol.
func TestTheResolverCeilingCannotBeClaimedAway(t *testing.T) {
	report := mustDerive(t)
	if report.ResolverCeiling.ResolverVerifiedAt != "null" {
		t.Fatalf("resolver_verified_at reads %q; this test assumes the unverified state that this tree is in",
			report.ResolverCeiling.ResolverVerifiedAt)
	}
	if report.ResolverCeiling.ObligationsOnResolverVerified != 0 {
		t.Fatalf("%d obligations are reported as bound to a resolver-verified Rust symbol",
			report.ResolverCeiling.ObligationsOnResolverVerified)
	}
	claimed := report
	claimed.ResolverCeiling.ObligationsOnResolverVerified = 24
	if !failed(enforceNoHiding(claimed), "NH11") {
		t.Fatal("NH11 accepted a resolver-verified claim while resolver_verified_at is null")
	}
	claimed = report
	claimed.ResolverCeiling.MigrationBindingsVerified = 98
	if !failed(enforceNoHiding(claimed), "NH11") {
		t.Fatal("NH11 accepted verified migration bindings while resolver_verified_at is null")
	}
}

// TestTheResolverCeilingQuotesTheOverlayItRestsOn: the ceiling must name the
// declaration scan by its own words, not paraphrase them upward.
func TestTheResolverCeilingQuotesTheOverlayItRestsOn(t *testing.T) {
	root := repoRoot(t)
	report := mustDerive(t)
	linkageBytes, _, err := LoadArtifact(root, LinkagePath)
	if err != nil {
		t.Fatalf("load linkage: %v", err)
	}
	linkage, err := DecodeLinkage(linkageBytes)
	if err != nil {
		t.Fatalf("decode linkage: %v", err)
	}
	if report.ResolverCeiling.StrongestOverlayStrength != linkage.Resolver.Strength {
		t.Fatalf("the report quotes strength %q, the overlay declares %q",
			report.ResolverCeiling.StrongestOverlayStrength, linkage.Resolver.Strength)
	}
	if !strings.Contains(report.ResolverCeiling.Statement, linkage.Resolver.Strength) {
		t.Fatal("the resolver-ceiling statement does not carry the overlay's own strength label")
	}
	if !strings.Contains(report.ResolverCeiling.Statement, "declaration scan") {
		t.Fatal("the resolver-ceiling statement does not say that the linkage rests on a declaration scan")
	}
}

// ---------------------------------------------------------------------------
// The strength lattice.
// ---------------------------------------------------------------------------

func TestAnUnrankedStrengthIsAnErrorNotAPass(t *testing.T) {
	if _, err := StrengthRank("TOTALLY_PROVED"); err == nil {
		t.Fatal("an unranked strength label was ranked")
	}
	if _, err := MeetsRequired("TOTALLY_PROVED", "PRODUCTION_REFINEMENT"); err == nil {
		t.Fatal("an unranked observed strength was compared instead of refused")
	}
	if _, err := MeetsRequired("NONE", "TOTALLY_REQUIRED"); err == nil {
		t.Fatal("an unranked required strength was compared instead of refused")
	}
}

func TestTheJavaObservedStrengthIsStrictlyWeakerThanWhatIsRequired(t *testing.T) {
	observed, err := StrengthRank("EXECUTED_OBSERVATION_WITH_MUTATION_SENSITIVITY")
	if err != nil {
		t.Fatalf("rank: %v", err)
	}
	required, err := StrengthRank("PRODUCTION_REFINEMENT")
	if err != nil {
		t.Fatalf("rank: %v", err)
	}
	if observed >= required {
		t.Fatalf("executed observation ranks %d against a required %d; the lattice would let the Java lane discharge the catalog", observed, required)
	}
	meets, err := MeetsRequired("EXECUTED_OBSERVATION_WITH_MUTATION_SENSITIVITY", "PRODUCTION_REFINEMENT")
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if meets {
		t.Fatal("executed observation was reported as meeting production refinement")
	}
}

// TestDeriveRefusesAProjectionAgainstADifferentCatalog: the Java numbers this
// report quotes must have been computed over the same denominator.
func TestDeriveRefusesAProjectionAgainstADifferentCatalog(t *testing.T) {
	root := sandbox(t)
	rewriteJSON(t, root, ProjectionPath, func(tree map[string]any) {
		catalog, _ := tree["catalog"].(map[string]any)
		catalog["sha256"] = "sha256:" + strings.Repeat("0", 64)
	})
	if _, err := DeriveReport(root); err == nil {
		t.Fatal("DeriveReport accepted a Java projection computed against a different catalog")
	}
}

// TestDeriveRefusesAProjectionThatDisagreesAboutRequiredStrength: this report
// recomputes meets_required from the lattice and refuses to paper over a
// disagreement with the retained projection.
func TestDeriveRefusesAProjectionThatDisagreesAboutRequiredStrength(t *testing.T) {
	root := sandbox(t)
	rewriteJSON(t, root, ProjectionPath, func(tree map[string]any) {
		rows, _ := tree["obligations"].([]any)
		for _, entry := range rows {
			row, _ := entry.(map[string]any)
			if row["binding_state"] == "CONNECTED" {
				row["meets_required_strength"] = true
				break
			}
		}
	})
	if _, err := DeriveReport(root); err == nil {
		t.Fatal("DeriveReport accepted a projection claiming an obligation meets a strength the lattice says it does not")
	}
}

// ---------------------------------------------------------------------------
// The catalog correction proposal.
// ---------------------------------------------------------------------------

func TestTheCorrectionProposalChecksOut(t *testing.T) {
	findings, proposal, err := VerifyCorrections(repoRoot(t))
	if err != nil {
		t.Fatalf("verify corrections: %v", err)
	}
	for _, finding := range findings {
		t.Errorf("finding %s %s: %s", finding.CorrectionID, finding.Check, finding.Detail)
	}
	if len(proposal.Corrections) != ExpectedCorrections {
		t.Fatalf("%d corrections, want %d", len(proposal.Corrections), ExpectedCorrections)
	}
}

// TestEveryCorrectionCitesTheDefectAndStatesItsResidualGap: a correction that
// only asserted a better symbol would be an opinion.
func TestEveryCorrectionCitesTheDefectAndStatesItsResidualGap(t *testing.T) {
	_, proposal, err := VerifyCorrections(repoRoot(t))
	if err != nil {
		t.Fatalf("verify corrections: %v", err)
	}
	for _, correction := range proposal.Corrections {
		if len(correction.Current.Citations) == 0 {
			t.Errorf("%s cites nothing against the current symbol", correction.CorrectionID)
		}
		if len(correction.Proposed.Chain) == 0 {
			t.Errorf("%s proposes no replacement", correction.CorrectionID)
		}
		if strings.TrimSpace(correction.Effect.ResidualGap) == "" {
			t.Errorf("%s claims no residual gap", correction.CorrectionID)
		}
		if correction.Effect.WouldBind == "CONNECTED" {
			t.Errorf("%s claims adoption would connect the obligation", correction.CorrectionID)
		}
	}
}

func TestACorrectionThatMisquotesTheCatalogSymbolIsRefused(t *testing.T) {
	root := sandbox(t)
	rewriteJSON(t, root, CorrectionPath, func(tree map[string]any) {
		corrections, _ := tree["corrections"].([]any)
		first, _ := corrections[0].(map[string]any)
		current, _ := first["current"].(map[string]any)
		current["production_symbol"] = "org.java_websocket.Nonsense.method()V"
	})
	findings, _, err := VerifyCorrections(root)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !hasCheck(findings, "CURRENT_SYMBOL_ECHOES_THE_CATALOG") {
		t.Fatalf("a misquoted catalog symbol was accepted; findings=%v", findings)
	}
}

func TestACorrectionThatInventsADefectClassIsRefused(t *testing.T) {
	root := sandbox(t)
	rewriteJSON(t, root, CorrectionPath, func(tree map[string]any) {
		corrections, _ := tree["corrections"].([]any)
		first, _ := corrections[0].(map[string]any)
		current, _ := first["current"].(map[string]any)
		current["defect_class"] = "TOTALLY_BROKEN"
	})
	findings, _, err := VerifyCorrections(root)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !hasCheck(findings, "DEFECT_CLASS_MATCHES_THE_BINDING_LANE") {
		t.Fatalf("an invented defect class was accepted; findings=%v", findings)
	}
}

// TestCorroborationLabelsAreExactInBothDirections is the anti-"existence stands
// in for identity" check. A citation may not claim corroboration it does not
// have, and it may not claim to be uncorroborated when it is.
func TestCorroborationLabelsAreExactInBothDirections(t *testing.T) {
	t.Run("claimed corroboration that does not exist", func(t *testing.T) {
		root := sandbox(t)
		rewriteJSON(t, root, CorrectionPath, func(tree map[string]any) {
			corrections, _ := tree["corrections"].([]any)
			for _, entry := range corrections {
				correction, _ := entry.(map[string]any)
				current, _ := correction["current"].(map[string]any)
				citations, _ := current["citations"].([]any)
				for _, citationEntry := range citations {
					citation, _ := citationEntry.(map[string]any)
					if citation["corroboration"] == CorroborationPinnedOnly {
						citation["corroboration"] = CorroborationProofTargets
						return
					}
				}
			}
			t.Fatal("no PINNED_SOURCE_ONLY citation to promote")
		})
		findings, _, err := VerifyCorrections(root)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if !hasCheck(findings, "CORROBORATION_LABEL_IS_EXACT") {
			t.Fatalf("an over-claimed corroboration label was accepted; findings=%v", findings)
		}
	})
	t.Run("understated corroboration", func(t *testing.T) {
		root := sandbox(t)
		rewriteJSON(t, root, CorrectionPath, func(tree map[string]any) {
			corrections, _ := tree["corrections"].([]any)
			for _, entry := range corrections {
				correction, _ := entry.(map[string]any)
				current, _ := correction["current"].(map[string]any)
				citations, _ := current["citations"].([]any)
				for _, citationEntry := range citations {
					citation, _ := citationEntry.(map[string]any)
					if citation["corroboration"] == CorroborationProofTargets {
						citation["corroboration"] = CorroborationPinnedOnly
						delete(citation, "corroborating_proof_target_member")
						return
					}
				}
			}
			t.Fatal("no corroborated citation to understate")
		})
		findings, _, err := VerifyCorrections(root)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if !hasCheck(findings, "CORROBORATION_LABEL_IS_EXACT") {
			t.Fatalf("an understated corroboration label was accepted; findings=%v", findings)
		}
	})
	t.Run("invented corroborating member", func(t *testing.T) {
		root := sandbox(t)
		rewriteJSON(t, root, CorrectionPath, func(tree map[string]any) {
			corrections, _ := tree["corrections"].([]any)
			for _, entry := range corrections {
				correction, _ := entry.(map[string]any)
				proposed, _ := correction["proposed"].(map[string]any)
				chain, _ := proposed["chain"].([]any)
				for _, memberEntry := range chain {
					member, _ := memberEntry.(map[string]any)
					citation, _ := member["citation"].(map[string]any)
					if citation["corroboration"] == CorroborationProofTargets {
						citation["corroborating_proof_target_member"] = "org.java_websocket.Nowhere#nothing()"
						return
					}
				}
			}
			t.Fatal("no proof-target-corroborated chain member")
		})
		findings, _, err := VerifyCorrections(root)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if !hasCheck(findings, "CORROBORATING_MEMBER_APPEARS_VERBATIM") {
			t.Fatalf("an invented corroborating member was accepted; findings=%v", findings)
		}
	})
}

func TestACorrectionClaimingItWouldConnectIsRefused(t *testing.T) {
	root := sandbox(t)
	rewriteJSON(t, root, CorrectionPath, func(tree map[string]any) {
		corrections, _ := tree["corrections"].([]any)
		first, _ := corrections[0].(map[string]any)
		effect, _ := first["effect_if_adopted"].(map[string]any)
		effect["would_bind"] = "CONNECTED"
	})
	findings, _, err := VerifyCorrections(root)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !hasCheck(findings, "EFFECT_VOCABULARY_IS_CLOSED_AND_CLAIMS_NO_CONNECTION") {
		t.Fatalf("a correction claiming it would connect its obligation was accepted; findings=%v", findings)
	}
}

func TestDroppingACorrectionIsRefused(t *testing.T) {
	root := sandbox(t)
	rewriteJSON(t, root, CorrectionPath, func(tree map[string]any) {
		corrections, _ := tree["corrections"].([]any)
		tree["corrections"] = corrections[1:]
	})
	findings, _, err := VerifyCorrections(root)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !hasCheck(findings, "CORRECTION_COUNT") {
		t.Fatalf("a proposal missing a correction was accepted; findings=%v", findings)
	}
}

func TestAProposalThatDeclaresItEditsTheCatalogIsRefused(t *testing.T) {
	root := sandbox(t)
	rewriteJSON(t, root, CorrectionPath, func(tree map[string]any) {
		immutability, _ := tree["immutability"].(map[string]any)
		immutability["this_document_modifies_the_catalog"] = true
	})
	findings, _, err := VerifyCorrections(root)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !hasCheck(findings, "PROPOSAL_DOES_NOT_MODIFY_THE_CATALOG") {
		t.Fatalf("a proposal that says it edits the catalog was accepted; findings=%v", findings)
	}
}

func TestDeriveRefusesToReportOverAFailingCorrectionProposal(t *testing.T) {
	root := sandbox(t)
	rewriteJSON(t, root, CorrectionPath, func(tree map[string]any) {
		corrections, _ := tree["corrections"].([]any)
		first, _ := corrections[0].(map[string]any)
		effect, _ := first["effect_if_adopted"].(map[string]any)
		effect["would_bind"] = "CONNECTED"
	})
	if _, err := DeriveReport(root); err == nil {
		t.Fatal("DeriveReport produced a report over a correction proposal that does not check out")
	}
}

// TestTheFiveCorrectionsAreTheFiveTheBindingLaneCouldNotRepair ties the
// proposal to the reasons another lane already recorded, so the set cannot be
// quietly reshaped to whatever is convenient.
func TestTheFiveCorrectionsAreTheFiveTheBindingLaneCouldNotRepair(t *testing.T) {
	root := repoRoot(t)
	_, proposal, err := VerifyCorrections(root)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	want := map[string]string{
		"obligation.mask-equation":   "CATALOG_SYMBOL_SCOPE_MISMATCH",
		"obligation.mask-involution": "CATALOG_SYMBOL_SCOPE_MISMATCH",
		"surface.control.ping-pong":  "CATALOG_SYMBOL_NOT_ON_EXECUTED_PATH",
		"surface.messages.binary":    "INTERFACE_DECLARATION_NO_IMPLEMENTATION_SITE",
		"surface.messages.text-utf8": "INTERFACE_DECLARATION_NO_IMPLEMENTATION_SITE",
	}
	got := map[string]string{}
	for _, correction := range proposal.Corrections {
		got[correction.ObligationID] = correction.Current.DefectClass
	}
	if fmt.Sprint(want) != fmt.Sprint(got) {
		t.Fatalf("the corrected set is\n %v\nwant\n %v", got, want)
	}
}

func hasCheck(findings []CorrectionFinding, check string) bool {
	for _, finding := range findings {
		if finding.Check == check {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// The human-readable report is a pure rendering of the machine-readable one.
// ---------------------------------------------------------------------------

func TestTheMarkdownNamesEveryBlockingObligation(t *testing.T) {
	report := mustDerive(t)
	rendered := string(RenderMarkdown(report))
	for _, gap := range report.BlockingGaps {
		if !strings.Contains(rendered, gap.ObligationID) {
			t.Fatalf("the rendered report does not name blocking obligation %s", gap.ObligationID)
		}
		for _, reason := range gap.Reasons {
			if !strings.Contains(rendered, reason) {
				t.Fatalf("the rendered report does not carry reason %s for %s", reason, gap.ObligationID)
			}
		}
	}
	if !strings.Contains(rendered, report.Freeze.Verdict) {
		t.Fatal("the rendered report does not state the freeze verdict")
	}
	for _, axis := range report.Axes {
		want := fmt.Sprintf("%d/%d", axis.Numerator, axis.Denominator)
		if !strings.Contains(rendered, want) {
			t.Fatalf("the rendered report does not carry %s = %s", axis.Axis, want)
		}
	}
}

// TestTheMarkdownLabelsEveryNonCoverageAxis: the one thing a coverage-style
// report must never do is let an attribution number read as coverage.
func TestTheMarkdownLabelsEveryNonCoverageAxis(t *testing.T) {
	report := mustDerive(t)
	rendered := string(RenderMarkdown(report))
	for _, axis := range report.Axes {
		if axis.IsCoverage || axis.Numerator == 0 {
			continue
		}
		index := strings.Index(rendered, "**`"+axis.Axis+"` —")
		if index < 0 {
			t.Fatalf("the rendered report has no section for %s", axis.Axis)
		}
		window := rendered[index:min(index+1600, len(rendered))]
		if !strings.Contains(window, "NOT COVERAGE") {
			t.Fatalf("the section for non-coverage axis %s (numerator %d) does not say it is not coverage", axis.Axis, axis.Numerator)
		}
	}
}

func TestTheMarkdownIsAPureFunctionOfTheReport(t *testing.T) {
	report := mustDerive(t)
	if !bytes.Equal(RenderMarkdown(report), RenderMarkdown(report)) {
		t.Fatal("rendering the same report twice produced different bytes")
	}
	moved := report
	moved.Freeze.Verdict = "NOT_BLOCKED"
	if bytes.Equal(RenderMarkdown(report), RenderMarkdown(moved)) {
		t.Fatal("changing the freeze verdict did not change the rendering")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
