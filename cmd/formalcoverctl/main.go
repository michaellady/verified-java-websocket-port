// Command formalcoverctl reconciles the two formal denominators this
// repository carries and derives the US-023 AC3 formal-coverage reports.
//
//	formalcoverctl reconcile   -repo .   # derive and write the reconciliation
//	formalcoverctl report      -repo .   # derive and write both AC3 reports
//	formalcoverctl verify      -repo .   # recompute all three, compare, exit 1 on drift
//	formalcoverctl freeze-gate -repo .   # the AC3 decision; exit 2 while anything blocks
//
// "verify" and "freeze-gate" are separate on purpose. Verification asks whether
// the retained artifacts are what the evidence derives; the freeze gate asks
// whether the freeze may proceed. A tool that answered both with one exit code
// would let a clean recomputation of a blocked freeze read as a pass.
//
// Nothing here proves anything. See docs/us023-formal-coverage.md.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/michaellady/verified-java-websocket-port/internal/formalcoverage"
)

// Exit codes. 1 is a tool or verification failure; 2 is a well-formed report
// whose verdict is BLOCKED. They are distinct so a blocked freeze can never be
// mistaken for a broken tool, or the reverse.
const (
	exitFailure = 1
	exitBlocked = 2
)

func main() {
	code, err := run(os.Args[1:], os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "formalcoverctl:", err)
	}
	os.Exit(code)
}

func run(args []string, out io.Writer) (int, error) {
	if len(args) == 0 {
		return exitFailure, fmt.Errorf("usage: formalcoverctl <reconcile|report|verify|freeze-gate> -repo <path>")
	}
	root, err := repoRoot(args[1:])
	if err != nil {
		return exitFailure, err
	}
	switch args[0] {
	case "reconcile":
		return runReconcile(root, out)
	case "report":
		return runReport(root, out)
	case "verify":
		return runVerify(root, out)
	case "freeze-gate":
		return runFreezeGate(root, out)
	default:
		return exitFailure, fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func repoRoot(args []string) (string, error) {
	flags := flag.NewFlagSet("formalcoverctl", flag.ContinueOnError)
	repo := flags.String("repo", "", "repository root")
	if err := flags.Parse(args); err != nil {
		return "", err
	}
	return filepath.Abs(*repo)
}

func writeArtifact(root, relative string, data []byte) error {
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func runReconcile(root string, out io.Writer) (int, error) {
	reconciliation, err := formalcoverage.Reconcile(root)
	if err != nil {
		return exitFailure, err
	}
	encoded, err := formalcoverage.MarshalArtifact(reconciliation)
	if err != nil {
		return exitFailure, err
	}
	if err := writeArtifact(root, formalcoverage.ReconciliationPath, encoded); err != nil {
		return exitFailure, err
	}
	reportReconciliation(out, reconciliation)
	return 0, nil
}

func runReport(root string, out io.Writer) (int, error) {
	reconciliation, err := formalcoverage.Reconcile(root)
	if err != nil {
		return exitFailure, err
	}
	reconciliationBytes, err := formalcoverage.MarshalArtifact(reconciliation)
	if err != nil {
		return exitFailure, err
	}
	if err := writeArtifact(root, formalcoverage.ReconciliationPath, reconciliationBytes); err != nil {
		return exitFailure, err
	}
	report, err := formalcoverage.DeriveReport(root)
	if err != nil {
		return exitFailure, err
	}
	reportBytes, err := formalcoverage.MarshalArtifact(report)
	if err != nil {
		return exitFailure, err
	}
	if err := writeArtifact(root, formalcoverage.ReportJSONPath, reportBytes); err != nil {
		return exitFailure, err
	}
	if err := writeArtifact(root, formalcoverage.ReportMarkdownPath, formalcoverage.RenderMarkdown(report)); err != nil {
		return exitFailure, err
	}
	reportReconciliation(out, reconciliation)
	reportCoverage(out, report)
	return 0, nil
}

// runVerify recomputes everything from the inputs and compares against the
// retained bytes. It prints the honest numbers BEFORE failing, so an operator
// who hits a drift still sees what the evidence actually derives rather than
// only that a comparison failed.
func runVerify(root string, out io.Writer) (int, error) {
	reconciliation, err := formalcoverage.Reconcile(root)
	if err != nil {
		return exitFailure, err
	}
	derivedReconciliation, err := formalcoverage.MarshalArtifact(reconciliation)
	if err != nil {
		return exitFailure, err
	}
	report, err := formalcoverage.DeriveReport(root)
	if err != nil {
		return exitFailure, err
	}
	derivedReport, err := formalcoverage.MarshalArtifact(report)
	if err != nil {
		return exitFailure, err
	}
	derivedMarkdown := formalcoverage.RenderMarkdown(report)

	findings, _, err := formalcoverage.VerifyCorrections(root)
	if err != nil {
		return exitFailure, err
	}
	planeFindings, _, err := formalcoverage.VerifyPlaneCorrespondence(root)
	if err != nil {
		return exitFailure, err
	}

	reportReconciliation(out, reconciliation)
	reportCoverage(out, report)
	fmt.Fprintf(out, "correction_proposal_findings=%d\n", len(findings))
	for _, finding := range findings {
		fmt.Fprintf(out, "  FINDING %s %s: %s\n", finding.CorrectionID, finding.Check, finding.Detail)
	}
	fmt.Fprintf(out, "plane_correspondence_findings=%d\n", len(planeFindings))
	for _, finding := range planeFindings {
		fmt.Fprintf(out, "  FINDING %s %s: %s\n", finding.Subject, finding.Check, finding.Detail)
	}

	for _, pair := range []struct {
		path    string
		derived []byte
	}{
		{formalcoverage.ReconciliationPath, derivedReconciliation},
		{formalcoverage.ReportJSONPath, derivedReport},
		{formalcoverage.ReportMarkdownPath, derivedMarkdown},
	} {
		stored, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(pair.path)))
		if readErr != nil {
			return exitFailure, readErr
		}
		if !bytes.Equal(bytes.TrimRight(stored, "\n"), bytes.TrimRight(pair.derived, "\n")) {
			return exitFailure, fmt.Errorf("the retained %s is not what the evidence derives", pair.path)
		}
	}
	if len(findings) > 0 {
		return exitFailure, fmt.Errorf("the catalog correction proposal has %d findings", len(findings))
	}
	return 0, nil
}

// runFreezeGate is the AC3 decision. It derives the report fresh — it never
// reads the retained one — so a hand-edited artifact cannot open the gate.
func runFreezeGate(root string, out io.Writer) (int, error) {
	report, err := formalcoverage.DeriveReport(root)
	if err != nil {
		return exitFailure, err
	}
	reportCoverage(out, report)
	fmt.Fprintf(out, "freeze_verdict=%s blocking=%d/%d\n",
		report.Freeze.Verdict, report.Freeze.BlockingObligations, report.Freeze.Denominator)
	for _, gap := range report.BlockingGaps {
		fmt.Fprintf(out, "  BLOCKED %s: %v\n", gap.ObligationID, gap.Reasons)
	}
	if report.Freeze.Verdict != "NOT_BLOCKED" {
		return exitBlocked, fmt.Errorf("US-023 freeze is BLOCKED by %d of %d obligations",
			report.Freeze.BlockingObligations, report.Freeze.Denominator)
	}
	return 0, nil
}

func reportReconciliation(out io.Writer, reconciliation formalcoverage.Reconciliation) {
	counts := reconciliation.Counts
	fmt.Fprintf(out, "obligations=%d proof_targets=%d\n", counts.Obligations, counts.ProofTargets)
	fmt.Fprintf(out, "obligations_mapped_to_a_target=%d/%d\n", counts.ObligationsMapped, counts.Obligations)
	fmt.Fprintf(out, "obligations_with_no_target=%d/%d\n", counts.ObligationsWithNoTarget, counts.Obligations)
	fmt.Fprintf(out, "targets_named_by_an_obligation=%d/%d\n", counts.TargetsMapped, counts.ProofTargets)
	fmt.Fprintf(out, "targets_with_no_obligation=%d/%d\n", counts.TargetsWithNoObligation, counts.ProofTargets)
	fmt.Fprintf(out, "java_keys catalog=%d proof_targets=%d both=%d catalog_only=%d target_only=%d\n",
		counts.CatalogDistinctJavaKeys, counts.TargetDistinctJavaKeys,
		counts.JavaKeysInBoth, counts.JavaKeysCatalogOnly, counts.JavaKeysTargetOnly)
	// The absent-path count is printed BESIDE what that absence means. Printed
	// alone it reads as "the catalog is broken"; the line under it is the
	// difference between an observation about this tree and an accusation
	// about someone else's document.
	fmt.Fprintf(out, "catalog_rust_binding_rows_with_source_path_absent_from_this_plane=%d/%d\n",
		counts.RustBindingPathsAbsent, counts.Obligations)
	fmt.Fprintf(out, "catalog_is_about_plane=%s (%s); catalog_rust_rows_measurable_on_this_plane=%d/%d\n",
		reconciliation.CatalogPlane.Ref, reconciliation.CatalogPlane.Name,
		counts.RustBindingRowsMeasurableHere, counts.Obligations)
	for _, check := range reconciliation.RustBindingCheck {
		fmt.Fprintf(out, "plane_mismatch %s obligations=%d path=%s namespace=%s path_correspondence=%s namespace_correspondence=%s\n",
			check.SourcePath, check.ObligationCount, check.PathState, check.NamespaceState,
			check.PathCorrespondence, check.NamespaceCorrespondence)
	}
	for _, pin := range reconciliation.BasisPins {
		switch pin.Agreement {
		case formalcoverage.BasisAgreementExact:
		case formalcoverage.BasisAgreementPathAbsent:
			// Not drift. A pin whose path is not on this plane has not moved;
			// it is about a tree this one is not.
			fmt.Fprintf(out, "basis_pin_path_absent_from_this_plane %s declared=%s\n", pin.Path, pin.DeclaredSHA)
		default:
			fmt.Fprintf(out, "basis_pin_drift %s declared=%s on_disk=%s\n", pin.Path, pin.DeclaredSHA, pin.OnDiskSHA)
		}
	}
}

// reportCoverage prints every axis on ONE screen, coverage and non-coverage
// together with the freeze verdict, so a non-zero attribution number can never
// be read in isolation from the zero coverage numbers beside it. This is the
// same discipline javabindctl uses when it prints at_required_strength=0/24 on
// the same screen as connected=4/24.
func reportCoverage(out io.Writer, report formalcoverage.Report) {
	fmt.Fprintf(out, "report=%s denominator=%d\n", report.ReportID, formalcoverage.CatalogDenominator)
	for _, axis := range report.Axes {
		label := "coverage"
		if !axis.IsCoverage {
			label = "NOT_COVERAGE"
		}
		fmt.Fprintf(out, "%s=%d/%d [%s weighting=%s]\n", axis.Axis, axis.Numerator, axis.Denominator, label, axis.Weighting)
	}
	fmt.Fprintf(out, "blocking_obligations=%d/%d\n", report.Freeze.BlockingObligations, report.Freeze.Denominator)
	fmt.Fprintf(out, "resolver_ceiling obligations_on_resolver_verified_rust=%d/%d resolver_verified_at=%s strongest_linkage=%q\n",
		report.ResolverCeiling.ObligationsOnResolverVerified, report.ResolverCeiling.Denominator,
		report.ResolverCeiling.ResolverVerifiedAt, report.ResolverCeiling.StrongestOverlayStrength)
	for _, invariant := range report.Invariants {
		if !invariant.Holds {
			fmt.Fprintf(out, "NO_HIDING_INVARIANT_VIOLATED %s: %s\n", invariant.ID, invariant.Detail)
		}
	}
	fmt.Fprintf(out, "assurance=%s independent_review_claimed=%t\n",
		report.Assurance.Assurance, report.Assurance.IndependentReviewClaim)
}
