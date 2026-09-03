package formalcoverage

import (
	"fmt"
	"strings"
)

// RenderMarkdown renders the human-readable coverage-style report from the SAME
// derived Report the machine-readable artifact is written from. It is a pure
// function of that value: nothing here reads an artifact, recomputes a number,
// or is typed by hand, so the two reports cannot disagree. A coverage-style
// report that could drift from its own data would be the same defect as a
// coverage number that could drift from its own evidence.
func RenderMarkdown(report Report) []byte {
	var out strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&out, format+"\n", args...) }

	line("# US-023 formal coverage — %s", report.Freeze.Verdict)
	line("")
	line("`%s` · schema %s · %s · independent_review_claimed: %t",
		report.ReportID, report.SchemaVersion, report.Assurance.Assurance, report.Assurance.IndependentReviewClaim)
	line("")
	line("> **FREEZE %s.** %d of %d obligations block. %s",
		report.Freeze.Verdict, report.Freeze.BlockingObligations, report.Freeze.Denominator, report.Freeze.Rule)
	line("")
	line("%s", report.Statement)
	line("")

	line("## The denominator, and what reconciling it exposed")
	line("")
	line("This repository carries **two** formal denominators. They are reconciled in `%s`; the mapping is derived, "+
		"not asserted, and joins on the one key both documents carry — the pinned-Java construct "+
		"`DeclaringType#memberName`, anchored on both sides to the same digest-pinned Java-WebSocket archive.",
		report.Denominator.Reconciliation.Path)
	line("")
	line("| | count |")
	line("| --- | ---: |")
	line("| Obligations in the immutable catalog | %d |", report.Denominator.CatalogObligations)
	line("| Targets in the US-006 proof-target plan | %d |", report.Denominator.ProofTargets)
	line("| **Obligations that map onto no planned proof target** | **%d** |", report.Denominator.ObligationsWithNoTarget)
	line("| **Proof targets named by no obligation** | **%d** |", report.Denominator.TargetsWithNoObligation)
	line("| Catalog Rust binding rows whose declared source path is absent from THIS plane | %d |", report.Denominator.RustBindingRowsPathAbsent)
	line("| Catalog Rust binding rows measurable on this plane | %d |", report.Denominator.RustRowsMeasurableHere)
	line("")
	if len(report.Denominator.ObligationIDsWithNoTarget) > 0 {
		line("Obligations with no proof target — named, not summarised:")
		line("")
		for _, id := range report.Denominator.ObligationIDsWithNoTarget {
			line("- `%s`", id)
		}
		line("")
	}
	if len(report.Denominator.TargetIDsWithNoObligation) > 0 {
		line("Proof targets no obligation names:")
		line("")
		for _, id := range report.Denominator.TargetIDsWithNoObligation {
			line("- `%s`", id)
		}
		line("")
	}

	line("## Coverage")
	line("")
	line("Every numerator below is an unweighted count of named obligations. Axes marked **not coverage** are " +
		"reported because AC3 requires them and because they are non-zero; they are excluded from the aggregate by " +
		"construction, and a reader who quotes one of them as coverage is quoting it against the artifact.")
	line("")
	line("| axis | | coverage? | feeds aggregate | weighting |")
	line("| --- | ---: | --- | --- | --- |")
	for _, axis := range report.Axes {
		coverage := "**not coverage**"
		if axis.IsCoverage {
			coverage = "coverage"
		}
		feeds := "no"
		if axis.FeedsAggregate {
			feeds = "yes"
		}
		line("| `%s` | **%d/%d** | %s | %s | %s |", axis.Axis, axis.Numerator, axis.Denominator, coverage, feeds, axis.Weighting)
	}
	line("")
	for _, axis := range report.Axes {
		line("**`%s` — %d/%d.** %s", axis.Axis, axis.Numerator, axis.Denominator, axis.Definition)
		if axis.Note != "" {
			line("")
			line("> %s", axis.Note)
		}
		line("")
		if len(axis.CountedObligations) > 0 {
			line("Counted: %s", codeList(axis.CountedObligations))
			line("")
		}
		line("Blocking on this axis: %d — %s", len(axis.BlockingObligations), codeList(axis.BlockingObligations))
		line("")
	}

	line("## How the no-hiding rule is enforced")
	line("")
	line("%s", report.NoHidingRule)
	line("")
	line("| invariant | holds | statement |")
	line("| --- | --- | --- |")
	for _, invariant := range report.Invariants {
		holds := "FAIL"
		if invariant.Holds {
			holds = "holds"
		}
		line("| `%s` | %s | %s |", invariant.ID, holds, invariant.Statement)
	}
	line("")
	line("A violated invariant does not annotate the report. `DeriveReport` returns an error and writes nothing, so " +
		"a report that hides a blocking obligation cannot be produced by this tool at all.")
	line("")

	line("## The resolver ceiling")
	line("")
	line("%s", report.ResolverCeiling.Statement)
	line("")
	line("| | |")
	line("| --- | --- |")
	line("| proof-target resolver state | `%s` |", report.ResolverCeiling.State)
	line("| planned resolver | `%s` |", report.ResolverCeiling.PlannedResolver)
	line("| resolver_verified_at | `%s` |", report.ResolverCeiling.ResolverVerifiedAt)
	line("| planned production symbols / resolver-verified | %d / **%d** |",
		report.ResolverCeiling.PlannedProductionSymbols, report.ResolverCeiling.PlannedSymbolsResolverVerified)
	line("| migration bindings / rust_identity_verified | %d / **%d** |",
		report.ResolverCeiling.MigrationBindings, report.ResolverCeiling.MigrationBindingsVerified)
	line("| strongest linkage overlay | `%s` |", report.ResolverCeiling.StrongestOverlayPath)
	line("| its method | %s |", report.ResolverCeiling.StrongestOverlayMethod)
	line("| its own declared strength | %s |", report.ResolverCeiling.StrongestOverlayStrength)
	line("| its rows resolved | %d / %d |", report.ResolverCeiling.OverlayRowsVerified, report.ResolverCeiling.OverlayRowsTotal)
	line("| **obligations bound to a resolver-verified shipped Rust symbol** | **%d / %d** |",
		report.ResolverCeiling.ObligationsOnResolverVerified, report.ResolverCeiling.Denominator)
	line("")

	line("## Defects in the denominator itself")
	line("")
	line("These are findings about the catalog, not about the programs it measures. An obligation declared against a " +
		"symbol that cannot carry it is not an uncovered obligation; it is an unmeasurable one, and a coverage " +
		"number over it would be a number about a name.")
	line("")
	line("Every row below is on the **Java** side. The catalog's Rust side is NOT listed here, and an earlier " +
		"version of this report listed it: its Rust source paths and namespaces resolve cleanly on the plane the " +
		"catalog is vendored from and resolve here to nothing because they are about another tree. That is a plane " +
		"mismatch, not a defect, and it has its own section below.")
	line("")
	line("| obligation | side | defect | correction |")
	line("| --- | --- | --- | --- |")
	for _, defect := range report.CatalogDefects {
		correction := "—"
		if defect.CorrectionID != "" {
			correction = "`" + defect.CorrectionID + "`"
		}
		line("| `%s` | %s | `%s` | %s |", defect.ObligationID, defect.Side, defect.DefectClass, correction)
	}
	line("")

	line("## Plane mismatch: what the catalog's Rust column is about")
	line("")
	line("The catalog is vendored byte-identically from another plane and its Rust column names that plane's "+
		"crates, files and symbols. Read here, none of them resolves. That is a statement about which tree the "+
		"lookup was performed against, not about the catalog: on its own plane the same names resolve. `%s` "+
		"records, crate by crate and symbol by symbol, what is known about the relationship between the two "+
		"planes and what it falls short of. No row in it reaches `ESTABLISHED_BY_OWNER_DECISION`, so **%d of %d** "+
		"catalog Rust rows are measurable here.", PlaneCorrespondencePath,
		report.Denominator.RustRowsMeasurableHere, report.Denominator.CatalogObligations)
	line("")
	line("| obligations | catalog source path | namespace | on this plane | path correspondence | namespace correspondence |")
	line("| ---: | --- | --- | --- | --- | --- |")
	for _, row := range report.PlaneMismatches {
		line("| %d | `%s` | `%s` | `%s` | `%s` | `%s` |", row.ObligationCount, row.CatalogSourcePath,
			row.CatalogNamespace, row.PathState, row.PathCorrespondence, row.NamespaceCorrespondence)
	}
	line("")

	line("## Every obligation")
	line("")
	line("| obligation | java | rust | refinement | bound parity | targets | blocking |")
	line("| --- | --- | --- | --- | --- | --- | --- |")
	for _, row := range report.Obligations {
		blocking := fmt.Sprintf("**%d**", len(row.BlockingReasons))
		if !row.Blocking {
			blocking = "—"
		}
		targets := "**none**"
		if len(row.ProofTargetIDs) > 0 {
			targets = fmt.Sprintf("%d", len(row.ProofTargetIDs))
		}
		line("| `%s` | %s | %s | %s | %s | %s | %s |",
			row.ObligationID, row.Java.ObservedStrength, row.Rust.ObservedStrength,
			row.RefinementState, row.BoundParity, targets, blocking)
	}
	line("")

	line("## Every blocking gap")
	line("")
	line("All %d of them, each with its reasons. No aggregate in this report can shrink this list.", len(report.BlockingGaps))
	line("")
	for _, gap := range report.BlockingGaps {
		line("### `%s`", gap.ObligationID)
		line("")
		line("%s", gap.Statement)
		line("")
		for _, reason := range gap.Reasons {
			line("- `%s`", reason)
		}
		line("")
	}

	line("## What this report does not claim")
	line("")
	for _, notClaim := range report.NotClaims {
		line("- %s", notClaim)
	}
	line("")

	line("## Inputs")
	line("")
	line("| artifact | sha256 |")
	line("| --- | --- |")
	for _, input := range report.Inputs {
		line("| `%s` | `%s` |", input.Path, input.SHA256)
	}
	line("")
	line("Generated by `go run ./cmd/formalcoverctl report -repo .` from the artifacts above. " +
		"`go run ./cmd/formalcoverctl verify -repo .` recomputes both reports and fails if the retained bytes are " +
		"not what the evidence derives; `go run ./cmd/formalcoverctl freeze-gate -repo .` exits non-zero while any " +
		"obligation blocks.")
	return []byte(out.String())
}

func codeList(ids []string) string {
	if len(ids) == 0 {
		return "_none_"
	}
	quoted := make([]string, 0, len(ids))
	for _, id := range ids {
		quoted = append(quoted, "`"+id+"`")
	}
	return strings.Join(quoted, ", ")
}
