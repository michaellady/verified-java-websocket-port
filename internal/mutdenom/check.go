package mutdenom

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// exitNoProcessState marks a probe command that never produced a ProcessState
// (it never started). There is no real exit code to read, so none is invented.
// Same sentinel discipline as cmd/rustgatectl and internal/fuzzpin.
const exitNoProcessState = -998

// completedExit reads the exit code from the ProcessState of a completed
// command -- success and failure alike -- and renders it verbatim. A command
// that never produced a ProcessState has no exit code; that absence is stated
// rather than rendered as a number.
func completedExit(state *os.ProcessState, runErr error) (int, string) {
	if state != nil {
		exit := state.ExitCode()
		return exit, fmt.Sprintf("exit=%d", exit)
	}
	detail := "none"
	if runErr != nil {
		detail = runErr.Error()
	}
	return exitNoProcessState, fmt.Sprintf("exit=none process_state=absent error=%q", detail)
}

// ProbeEngine runs an engine's availability probe and reports the outcome. The
// exit code is read from the real process state. An engine with no probe
// command is UNAVAILABLE: availability that cannot be decided is not
// availability.
func ProbeEngine(root string, engine Engine) EngineProbe {
	probe := EngineProbe{Engine: engine.ID, Command: strings.Join(engine.ProbeCommand, " ")}
	if len(engine.ProbeCommand) == 0 {
		probe.Exit = exitNoProcessState
		probe.ExitText = "exit=none process_state=absent error=\"no probe command declared\""
		probe.Available = false
		return probe
	}
	cmd := exec.Command(engine.ProbeCommand[0], engine.ProbeCommand[1:]...)
	cmd.Dir = filepath.Join(root, engine.ProbeDir)
	runErr := cmd.Run()
	exit, text := completedExit(cmd.ProcessState, runErr)
	probe.Exit = exit
	probe.ExitText = text
	probe.Available = exit == 0
	return probe
}

// probeToolchainVersion runs the toolchain probe and returns its combined
// output. The pinned runtime being present or absent is READ from the host.
func probeToolchainVersion(root string, toolchain Toolchain) (string, error) {
	if len(toolchain.ProbeCommand) == 0 {
		return "", fmt.Errorf("no toolchain probe command declared")
	}
	cmd := exec.Command(toolchain.ProbeCommand[0], toolchain.ProbeCommand[1:]...)
	cmd.Dir = filepath.Join(root, toolchain.ProbeDir)
	out, err := cmd.CombinedOutput()
	if len(out) == 0 && err != nil {
		return "", err
	}
	return string(out), nil
}

// Check verifies a manifest against the tree at root and returns a typed
// verdict. State is "OK" only when no BLOCK finding was raised.
func Check(root string, manifest *Manifest) Verdict {
	verdict := Verdict{State: "OK"}
	add := func(code, disposition, target, detail string) {
		verdict.Findings = append(verdict.Findings, Finding{
			Code: code, Disposition: disposition, Target: target, Detail: detail,
		})
	}

	if manifest.DigestScheme != DigestScheme {
		add(FindingDigestSchemeInvalid, Block, "", fmt.Sprintf(
			"digest_scheme is %q, want %q", manifest.DigestScheme, DigestScheme))
	}

	availability := checkEngines(root, manifest, &verdict, add)
	surfaces := checkSurfaces(root, manifest, add)
	reviews := indexReviews(manifest)
	records := checkPopulations(root, manifest, availability, surfaces, reviews, add)
	checkScore(manifest, records, add)
	checkTestIntegrity(root, manifest, surfaces, add)
	checkArms(root, manifest, availability, add)
	checkAC5(manifest, add)
	checkSignature(manifest, add)
	checkClaim(manifest, &verdict, add)

	sort.SliceStable(verdict.Findings, func(i, j int) bool {
		if verdict.Findings[i].Target != verdict.Findings[j].Target {
			return verdict.Findings[i].Target < verdict.Findings[j].Target
		}
		return verdict.Findings[i].Code < verdict.Findings[j].Code
	})
	if BlockingCount(verdict) > 0 {
		verdict.State = "BLOCKED"
	}
	return verdict
}

// BlockingCount counts BLOCK findings.
func BlockingCount(verdict Verdict) int {
	blocking := 0
	for _, finding := range verdict.Findings {
		if finding.Disposition == Block {
			blocking++
		}
	}
	return blocking
}

// --- engines ---------------------------------------------------------------

func checkEngines(
	root string, manifest *Manifest, verdict *Verdict,
	add func(code, disposition, target, detail string),
) map[string]bool {
	availability := map[string]bool{}
	for _, engine := range manifest.Engines {
		probe := ProbeEngine(root, engine)
		verdict.EngineAvailability = append(verdict.EngineAvailability, probe)
		availability[engine.ID] = probe.Available
		if !probe.Available {
			// AC1 presumes these engines RAN. A failed probe is not a reason to
			// move on; it is the finding.
			add(FindingEngineUnavailable, Block, engine.ID, fmt.Sprintf(
				"probe %q %s -- engine %q is NOT installed in this environment; "+
					"AC1 requires it to have RUN, so this blocks",
				strings.Join(engine.ProbeCommand, " "), probe.ExitText, engine.Tool))
		}

		if engine.Toolchain.VersionPattern != "" {
			output, err := probeToolchainVersion(root, engine.Toolchain)
			switch {
			case err != nil:
				add(FindingToolchainVersionMismatch, Block, engine.ID, fmt.Sprintf(
					"toolchain probe %q failed: %v -- the pinned runtime %q could not be "+
						"observed at all", strings.Join(engine.Toolchain.ProbeCommand, " "),
					err, engine.Toolchain.Required))
			case !strings.Contains(output, engine.Toolchain.VersionPattern):
				add(FindingToolchainVersionMismatch, Block, engine.ID, fmt.Sprintf(
					"toolchain probe %q output does not contain the pinned version %q "+
						"(required %q); observed: %s",
					strings.Join(engine.Toolchain.ProbeCommand, " "),
					engine.Toolchain.VersionPattern, engine.Toolchain.Required,
					firstLine(output)))
			}
		}

		switch engine.DependencyGraph.Status {
		case GraphPromoted:
			if engine.DependencyGraph.PromotionRecord == "" {
				add(FindingPromotionRecordAbsent, Block, engine.ID,
					"dependency graph is declared PROMOTED with no promotion record; "+
						"promotion that names no record is an adjective")
			} else if _, err := os.Stat(filepath.Join(root, engine.DependencyGraph.PromotionRecord)); err != nil {
				add(FindingPromotionRecordAbsent, Block, engine.ID, fmt.Sprintf(
					"promotion record %s absent: %v", engine.DependencyGraph.PromotionRecord, err))
			}
		case GraphNotPromoted:
			// AC1: "run from promoted tool/dependency graphs". An unpromoted
			// graph is not a graph the campaign may run from.
			add(FindingDependencyGraphNotPromoted, Block, engine.ID, fmt.Sprintf(
				"engine %q has no promoted tool/dependency graph: %s",
				engine.Tool, engine.DependencyGraph.Note))
		default:
			add(FindingManifestSchemaInvalid, Block, engine.ID, fmt.Sprintf(
				"unknown dependency_graph.status %q", engine.DependencyGraph.Status))
		}
	}
	return availability
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "Picked up ") {
			return line
		}
	}
	return s
}

// --- surfaces --------------------------------------------------------------

func checkSurfaces(
	root string, manifest *Manifest,
	add func(code, disposition, target, detail string),
) map[string]Surface {
	surfaces := map[string]Surface{}
	for _, surface := range manifest.Surfaces {
		surfaces[surface.ID] = surface
		if len(surface.Paths) == 0 {
			add(FindingSurfaceUndeclared, Block, surface.ID,
				"surface declares no paths; AC1 mutates a DECLARED surface, and an "+
					"undeclared one has no denominator")
			continue
		}
		digest, count, err := TreeDigest(root, surface.Paths)
		if err != nil {
			add(FindingSurfaceDigestDrift, Block, surface.ID, fmt.Sprintf(
				"surface unreadable: %v", err))
			continue
		}
		if digest != surface.Digest {
			add(FindingSurfaceDigestDrift, Block, surface.ID, fmt.Sprintf(
				"surface digest %s over %d files, manifest pins %s",
				digest, count, surface.Digest))
		}
		if count != surface.FileCount {
			add(FindingSurfaceFileCountDrift, Block, surface.ID, fmt.Sprintf(
				"surface holds %d files, manifest declares %d", count, surface.FileCount))
		}
	}
	// A production surface nobody enumerated a population over is a surface
	// nobody mutated. Silence there is the flattering direction.
	covered := map[string]bool{}
	for _, population := range manifest.Populations {
		covered[population.Surface] = true
	}
	for _, surface := range manifest.Surfaces {
		if surface.Kind == "production" && !covered[surface.ID] {
			add(FindingSurfaceUnmapped, Block, surface.ID,
				"declared production surface has no mutant population; "+
					"a surface nobody enumerated contributes nothing to any denominator")
		}
	}
	return surfaces
}

// --- reviews ---------------------------------------------------------------

func indexReviews(manifest *Manifest) map[string]Review {
	reviews := map[string]Review{}
	for _, review := range manifest.Reviews {
		reviews[review.ID] = review
	}
	return reviews
}

// --- populations and records ------------------------------------------------

func checkPopulations(
	root string, manifest *Manifest,
	availability map[string]bool,
	surfaces map[string]Surface,
	reviews map[string]Review,
	add func(code, disposition, target, detail string),
) []Record {
	var all []Record
	seenID := map[string]string{}

	for _, population := range manifest.Populations {
		if _, known := surfaces[population.Surface]; !known {
			add(FindingUnknownSurfaceReference, Block, population.ID, fmt.Sprintf(
				"population references surface %q, which the manifest does not declare",
				population.Surface))
		}
		engineAvailable, engineKnown := availability[population.Engine]
		if !engineKnown {
			add(FindingUnknownEngineReference, Block, population.ID, fmt.Sprintf(
				"population references engine %q, which the manifest does not declare",
				population.Engine))
		}

		switch population.EnumerationStatus {
		case StatusSkippedForbidden:
			// Named explicitly so the refusal is by name, not by fallthrough.
			add(FindingStatusSkippedForbidden, Block, population.ID,
				"enumeration_status is SKIPPED; there is no skip in this model -- "+
					"a population that was not enumerated BLOCKS")
		case EnumEnumerated:
			if engineKnown && !engineAvailable {
				add(FindingUnavailableAsSkip, Block, population.ID, fmt.Sprintf(
					"population is recorded %s, which asserts a real enumeration, but "+
						"engine %q probed UNAVAILABLE; the honest status is %s",
					EnumEnumerated, population.Engine, EnumNotEnumeratedEngineUnavailable))
			}
		case EnumNotEnumeratedEngineUnavailable:
			// The inverse evasion: parking work as blocked-on-tooling while the
			// tool is right there hides a campaign nobody ran.
			if engineKnown && engineAvailable {
				add(FindingUnavailableAsSkip, Block, population.ID, fmt.Sprintf(
					"population is parked %s but engine %q probed AVAILABLE",
					EnumNotEnumeratedEngineUnavailable, population.Engine))
			}
			add(FindingPopulationNotEnumerated, Block, population.ID, fmt.Sprintf(
				"no mutant population exists for surface %q under engine %q: %s",
				population.Surface, population.Engine, population.Rationale))
		default:
			add(FindingManifestSchemaInvalid, Block, population.ID, fmt.Sprintf(
				"unknown enumeration_status %q", population.EnumerationStatus))
		}

		switch population.Provenance {
		case ProvenanceToolEnumerated:
		case ProvenanceHandCurated:
			// The substitution this story is most likely to be offered.
			add(FindingPopulationNotToolEnumerated, Block, population.ID, fmt.Sprintf(
				"population provenance is %s: the mutants were CHOSEN, not enumerated by "+
					"%q over surface %q. A curated catalogue has no denominator relationship "+
					"to the surface -- the mutants nobody wrote down were never counted -- "+
					"so its ratio is not AC1's eligible mutation score",
				ProvenanceHandCurated, population.Engine, population.Surface))
		default:
			add(FindingManifestSchemaInvalid, Block, population.ID, fmt.Sprintf(
				"unknown provenance %q", population.Provenance))
		}

		// The count in the header must equal the records under it. This is the
		// rule that makes a silent absence impossible: a mutant removed from
		// the record list moves this equality.
		if len(population.Records) != population.DeclaredTotal {
			add(FindingPopulationRecordCountDrift, Block, population.ID, fmt.Sprintf(
				"declared_total is %d but the population carries %d records; a mutant "+
					"that is in the count and not in the records is a silent absence",
				population.DeclaredTotal, len(population.Records)))
		}

		// The class table must equal the header count AND the per-record tally.
		// Two separate rules, two separate codes: the class table could agree
		// with the total while disagreeing with the records.
		classSum := 0
		for _, count := range population.Classes {
			classSum += count
		}
		if classSum != population.DeclaredTotal {
			add(FindingClassSumMismatch, Block, population.ID, fmt.Sprintf(
				"class counts sum to %d, declared_total is %d", classSum, population.DeclaredTotal))
		}
		tally := map[string]int{}
		for _, record := range population.Records {
			tally[record.Disposition]++
		}
		for _, class := range Dispositions {
			if tally[class] != population.Classes[class] {
				add(FindingClassTallyDrift, Block, population.ID, fmt.Sprintf(
					"class %q: records hold %d, class table declares %d",
					class, tally[class], population.Classes[class]))
			}
		}
		for class := range population.Classes {
			if !IsDisposition(class) {
				// Its own code, not the per-record one. A tenth class invented in
				// the class table and a tenth class invented on a record are two
				// different defects, and sharing a code would let a deletion of
				// either hide behind the other -- the exact masking US-021's
				// deletion attack found.
				add(FindingClassTableDispositionUnknown, Block, population.ID, fmt.Sprintf(
					"class table names %q, which is not one of the nine AC1 dispositions", class))
			}
		}

		// If the population was normalized from an on-disk campaign manifest,
		// re-derive its size from that file. The normalization is auditable,
		// not asserted.
		if population.SourceManifest != "" {
			count, err := countSourceMutants(root, population.SourceManifest, population.SourceManifestKey)
			switch {
			case err != nil:
				add(FindingSourceManifestUnreadable, Block, population.ID, fmt.Sprintf(
					"source manifest %s unreadable: %v", population.SourceManifest, err))
			case count != population.DeclaredTotal:
				add(FindingSourceManifestCountDrift, Block, population.ID, fmt.Sprintf(
					"source manifest %s holds %d entries under %q, population declares %d",
					population.SourceManifest, count, population.SourceManifestKey,
					population.DeclaredTotal))
			}
		}

		for _, record := range population.Records {
			checkRecord(population.ID, record, reviews, seenID, add)
			all = append(all, record)
		}
	}
	return all
}

func countSourceMutants(root, path, key string) (int, error) {
	raw, err := os.ReadFile(filepath.Join(root, path))
	if err != nil {
		return 0, err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return 0, err
	}
	if key == "" {
		key = "mutants"
	}
	value, present := doc[key]
	if !present {
		return 0, fmt.Errorf("no array %q", key)
	}
	list, ok := value.([]any)
	if !ok {
		return 0, fmt.Errorf("%q is not an array", key)
	}
	return len(list), nil
}

func checkRecord(
	populationID string, record Record,
	reviews map[string]Review,
	seenID map[string]string,
	add func(code, disposition, target, detail string),
) {
	target := populationID + "/" + record.ID

	if previous, duplicate := seenID[record.ID]; duplicate {
		add(FindingMutantIDDuplicate, Block, target, fmt.Sprintf(
			"mutant id %q already appears in %s; one mutant counted twice inflates "+
				"any denominator it is in", record.ID, previous))
	} else {
		seenID[record.ID] = populationID
	}

	if record.Disposition == "" {
		add(FindingDispositionAbsent, Block, target,
			"record carries no disposition; every mutant lands in exactly one of the "+
				"nine AC1 classes, and 'none' is not one of them")
		return
	}
	if !IsDisposition(record.Disposition) {
		add(FindingDispositionUnknown, Block, target, fmt.Sprintf(
			"disposition %q is not one of the nine AC1 classes %v",
			record.Disposition, Dispositions))
		return
	}
	if record.SourceTool != ToolPIT && record.SourceTool != ToolCargoMutants {
		add(FindingSourceToolInvalid, Block, target, fmt.Sprintf(
			"source_tool %q is neither %q nor %q; AC1 normalizes the output of those two "+
				"engines and of nothing else", record.SourceTool, ToolPIT, ToolCargoMutants))
	}
	if strings.TrimSpace(record.RawStatus) == "" {
		add(FindingRawStatusAbsent, Block, target,
			"record carries no raw_status; without the tool's own word the normalization "+
				"into an AC1 class cannot be audited")
	}
	if !record.InDenominator {
		add(FindingRecordExcluded, Block, target, fmt.Sprintf(
			"record is marked in_denominator=false; AC2 requires EVERY classification "+
				"to remain visible in the denominator (disposition %q)", record.Disposition))
	}

	ineligible := IneligibleDispositions[record.Disposition]
	if ineligible && record.Eligible {
		add(FindingEligibilityMislabelled, Block, target, fmt.Sprintf(
			"disposition %q is marked eligible=true; the two ineligible classes leave the "+
				"ELIGIBLE set and stay in the denominator, never the reverse", record.Disposition))
	}
	if !ineligible && !record.Eligible {
		add(FindingEligibilityMislabelled, Block, target, fmt.Sprintf(
			"disposition %q is marked eligible=false; only %q and %q may leave the eligible "+
				"set, and only with evidence and independent review",
			record.Disposition, DispEquivalent, DispTechnicallyUnviable))
	}
	if !ineligible {
		return
	}

	// AC2's two gates on the only two classes that can shrink the numerator's
	// denominator. Both are required; neither substitutes for the other.
	if strings.TrimSpace(record.Evidence) == "" {
		add(FindingEquivalenceEvidenceAbsent, Block, target, fmt.Sprintf(
			"disposition %q carries no technical evidence; AC2 requires it", record.Disposition))
	}
	if len(record.ReviewIDs) == 0 {
		add(FindingEquivalenceReviewAbsent, Block, target, fmt.Sprintf(
			"disposition %q carries no independent explicit review; AC2 requires one, and "+
				"the author's own analysis -- however exhaustive -- is not it", record.Disposition))
		return
	}
	for _, reviewID := range record.ReviewIDs {
		review, present := reviews[reviewID]
		if !present {
			add(FindingReviewRecordMissing, Block, target, fmt.Sprintf(
				"review %q is cited but the manifest carries no such review record", reviewID))
			continue
		}
		if review.Role != "independent-reviewer" {
			add(FindingReviewNotIndependent, Block, target, fmt.Sprintf(
				"review %q has role %q, want %q", reviewID, review.Role, "independent-reviewer"))
		}
		if !review.Blind {
			add(FindingReviewNotBlind, Block, target, fmt.Sprintf(
				"review %q is not blind; the master story requires DUAL-BLIND independent "+
					"review of equivalent and technically-unviable classifications", reviewID))
		}
		if review.Disposition != "APPROVE" {
			add(FindingReviewNotApproved, Block, target, fmt.Sprintf(
				"review %q disposition is %q, not APPROVE", reviewID, review.Disposition))
		}
	}
}

// --- score -----------------------------------------------------------------

func checkScore(
	manifest *Manifest, records []Record,
	add func(code, disposition, target, detail string),
) {
	denominator := 0
	eligible := 0
	killed := 0
	missed := 0
	for _, record := range records {
		if record.InDenominator {
			denominator++
		}
		if IneligibleDispositions[record.Disposition] {
			continue
		}
		eligible++
		if record.Disposition == DispKilled {
			killed++
		}
		if MissedDispositions[record.Disposition] {
			missed++
		}
	}
	percent := 0.0
	if eligible > 0 {
		percent = 100.0 * float64(killed) / float64(eligible)
	}

	if manifest.Score.DenominatorTotal != denominator {
		add(FindingDenominatorTotalDrift, Block, "score", fmt.Sprintf(
			"declared denominator_total %d, recomputed from records %d",
			manifest.Score.DenominatorTotal, denominator))
	}
	if manifest.Score.EligibleTotal != eligible {
		add(FindingEligibleTotalDrift, Block, "score", fmt.Sprintf(
			"declared eligible_total %d, recomputed %d", manifest.Score.EligibleTotal, eligible))
	}
	if manifest.Score.KilledTotal != killed {
		add(FindingKilledTotalDrift, Block, "score", fmt.Sprintf(
			"declared killed_total %d, recomputed %d", manifest.Score.KilledTotal, killed))
	}
	if manifest.Score.MissedTotal != missed {
		add(FindingMissedTotalDrift, Block, "score", fmt.Sprintf(
			"declared missed_total %d, recomputed %d", manifest.Score.MissedTotal, missed))
	}
	if math.Abs(manifest.Score.EligibleScorePercent-percent) > 1e-9 {
		add(FindingScorePercentDrift, Block, "score", fmt.Sprintf(
			"declared eligible_score_percent %.6f, recomputed %.6f",
			manifest.Score.EligibleScorePercent, percent))
	}
	if missed > 0 {
		add(FindingMissedNonZero, Block, "score", fmt.Sprintf(
			"%d eligible mutants are MISSED; AC2 requires zero", missed))
	}

	// The score is arithmetic over a population. If any population was never
	// enumerated, the arithmetic is over a fragment and the ratio is not the
	// eligible mutation score of the declared surface.
	unenumerated := []string{}
	for _, population := range manifest.Populations {
		if population.EnumerationStatus != EnumEnumerated {
			unenumerated = append(unenumerated, population.ID)
		}
	}
	if len(unenumerated) > 0 {
		if manifest.Score.Computable {
			add(FindingScoreNotComputable, Block, "score", fmt.Sprintf(
				"score is declared computable while %d population(s) were never "+
					"enumerated (%s); a ratio over a fragment of the surface is not the "+
					"eligible mutation score of the surface",
				len(unenumerated), strings.Join(unenumerated, ", ")))
		} else {
			add(FindingScoreNotComputable, Block, "score", fmt.Sprintf(
				"the eligible mutation score of the declared surfaces is NOT COMPUTABLE: "+
					"%d population(s) were never enumerated (%s)",
				len(unenumerated), strings.Join(unenumerated, ", ")))
		}
	}
}

// --- AC3: test integrity ----------------------------------------------------

func checkTestIntegrity(
	root string, manifest *Manifest, surfaces map[string]Surface,
	add func(code, disposition, target, detail string),
) {
	legs := map[string]ReconciliationLeg{}
	for _, leg := range manifest.TestIntegrity.Legs {
		legs[leg.ID] = leg
	}
	for _, required := range ReconciliationLegs {
		leg, present := legs[required]
		if !present {
			add(FindingReconciliationLegAbsent, Block, "test-integrity", fmt.Sprintf(
				"AC3 requires the %q reconciliation leg and the manifest carries no record "+
					"for it", required))
			continue
		}
		if leg.Status != "RUN" {
			add(FindingReconciliationLegNotRun, Block, "test-integrity", fmt.Sprintf(
				"reconciliation leg %q status is %q, not RUN: %s", required, leg.Status, leg.Note))
		}
	}

	// AC3's own rule, made mechanical. If the test surfaces are digest-pinned
	// before and after the campaign and the two digests differ, some test moved
	// during mutation -- which is the exact thing AC3 forbids. When no campaign
	// ran, before and after are the same reading of the same tree and this rule
	// is satisfied without being informative; that is stated, not hidden.
	before := manifest.TestIntegrity.TestSurfaceDigestBefore
	after := manifest.TestIntegrity.TestSurfaceDigestAfter
	if before != after {
		add(FindingTestSurfaceMutated, Block, "test-integrity", fmt.Sprintf(
			"test surface digest moved across the campaign: before %s, after %s -- AC3 "+
				"forbids deleting, weakening, skipping, filtering or replacing a "+
				"requirement-bearing test because a mutant made it inconvenient",
			before, after))
		return
	}
	// And the pinned digest must still be the tree's digest now.
	var testPaths []string
	for _, surface := range manifest.Surfaces {
		if surface.Kind == "test" {
			testPaths = append(testPaths, surface.Paths...)
		}
	}
	if len(testPaths) == 0 {
		return
	}
	digest, _, err := TreeDigest(root, testPaths)
	if err != nil {
		add(FindingTestSurfaceMutated, Block, "test-integrity", fmt.Sprintf(
			"test surfaces unreadable: %v", err))
		return
	}
	if digest != after {
		add(FindingTestSurfaceMutated, Block, "test-integrity", fmt.Sprintf(
			"test surface digest is %s on the tree now, manifest pins %s across the campaign",
			digest, after))
	}
}

// --- AC4: hidden/sealed separation ------------------------------------------

func checkArms(
	root string, manifest *Manifest, availability map[string]bool,
	add func(code, disposition, target, detail string),
) {
	// AC4 governs the hidden and sealed runs by name. Neither may be absent.
	present := map[string]bool{}
	for _, arm := range manifest.Arms {
		present[arm.ID] = true
	}
	for _, required := range []string{"hidden", "sealed"} {
		if !present[required] {
			add(FindingArmMissing, Block, "arms", fmt.Sprintf(
				"AC4 governs the %q run by name and the manifest carries no arm for it",
				required))
		}
	}

	// Observed witness values, per dimension, so a value shared between two arms
	// is caught as a shared value rather than as two separate declarations.
	observedBy := map[string]map[string][]string{}

	for _, arm := range manifest.Arms {
		switch arm.MutationRunStatus {
		case StatusSkippedForbidden:
			add(FindingStatusSkippedForbidden, Block, arm.ID,
				"mutation_run_status is SKIPPED; there is no skip in this model")
		case ArmRun:
			for engineID, available := range availability {
				if !available {
					add(FindingUnavailableAsSkip, Block, arm.ID, fmt.Sprintf(
						"arm is recorded %s, which asserts a mutation campaign, while "+
							"engine %q probed UNAVAILABLE", ArmRun, engineID))
				}
			}
		case ArmNotRunEngineUnavailable:
			allAvailable := len(availability) > 0
			for _, available := range availability {
				if !available {
					allAvailable = false
				}
			}
			if allAvailable {
				add(FindingUnavailableAsSkip, Block, arm.ID, fmt.Sprintf(
					"arm is parked %s but every declared engine probed AVAILABLE",
					ArmNotRunEngineUnavailable))
			}
			add(FindingArmNotRun, Block, arm.ID, fmt.Sprintf(
				"no mutation campaign ran on the %q arm: %s", arm.ID, arm.Rationale))
		default:
			add(FindingManifestSchemaInvalid, Block, arm.ID, fmt.Sprintf(
				"unknown mutation_run_status %q", arm.MutationRunStatus))
		}

		for _, dimension := range SeparationDimensions {
			witness, declared := arm.Separation[dimension]
			if !declared || strings.TrimSpace(witness.Declared) == "" {
				detail := fmt.Sprintf(
					"AC4 requires a separate %s and the arm declares none", dimension)
				if strings.TrimSpace(witness.Note) != "" {
					// State the requirement as structure even where it cannot be
					// satisfied yet: what would have to be true, and what this
					// check would read to confirm it.
					detail += "; what would have to be true, and what this check would " +
						"read once the run exists: " + witness.Note
				}
				add(FindingArmSeparationDimensionMissing, Block, arm.ID, detail)
				continue
			}
			value := witness.Declared
			if witness.Source != "" {
				observed, err := LookupJSONField(filepath.Join(root, witness.Source), witness.Field)
				switch {
				case err != nil:
					add(FindingArmSeparationWitnessUnreadable, Block, arm.ID, fmt.Sprintf(
						"%s witness unreadable: %v -- a separation dimension whose witness "+
							"cannot be read is a promise, not a reading", dimension, err))
					continue
				case observed != witness.Declared:
					add(FindingArmSeparationWitnessDrift, Block, arm.ID, fmt.Sprintf(
						"%s: %s#%s reads %q, arm declares %q",
						dimension, witness.Source, witness.Field, observed, witness.Declared))
					continue
				default:
					value = observed
				}
			}
			if observedBy[dimension] == nil {
				observedBy[dimension] = map[string][]string{}
			}
			observedBy[dimension][value] = append(observedBy[dimension][value], arm.ID)
		}

		if strings.TrimSpace(arm.NetworkDenial) == "" {
			add(FindingArmNetworkDenialUndeclared, Block, arm.ID,
				"AC4 requires candidate execution to DENY network APIs and the arm declares "+
					"no denial mechanism")
		}
		if strings.TrimSpace(arm.ProtectedStoreDenial) == "" {
			add(FindingArmProtectedStoreDenialUndeclared, Block, arm.ID,
				"AC4 requires candidate execution to DENY protected-store APIs and the arm "+
					"declares no denial mechanism")
		}
		if !arm.BudgetMonotonic {
			add(FindingArmBudgetNotMonotonic, Block, arm.ID, fmt.Sprintf(
				"AC4 requires monotonic budgets and anti-evasion; the arm declares "+
					"budget_monotonic=false (basis %q, anti-evasion %q)",
				arm.BudgetBasis, arm.AntiEvasion))
		}
		if strings.TrimSpace(arm.DiagnosticPolicy) == "" {
			add(FindingArmDiagnosticPolicyAbsent, Block, arm.ID,
				"AC4 releases only POLICY-LIMITED diagnostics and the arm declares no policy")
		}
	}

	// The rule AC4 is actually about: two arms may not share a dimension.
	for _, dimension := range SeparationDimensions {
		values := observedBy[dimension]
		keys := make([]string, 0, len(values))
		for value := range values {
			keys = append(keys, value)
		}
		sort.Strings(keys)
		for _, value := range keys {
			arms := values[value]
			if len(arms) < 2 {
				continue
			}
			sort.Strings(arms)
			add(FindingArmSeparationShared, Block, strings.Join(arms, "+"), fmt.Sprintf(
				"arms %s share one %s (%q); AC4 requires SEPARATE identities, filesystems, "+
					"caches, credentials, signing keys and workspaces, and a shared one is "+
					"the leakage channel the criterion exists to close",
				strings.Join(arms, " and "), dimension, value))
		}
	}
}

// --- AC5 --------------------------------------------------------------------

func checkAC5(manifest *Manifest, add func(code, disposition, target, detail string)) {
	legs := map[string]AC5Leg{}
	for _, leg := range manifest.AC5Legs {
		legs[leg.ID] = leg
	}
	for _, required := range AC5Legs {
		leg, present := legs[required]
		if !present {
			add(FindingAC5LegAbsent, Block, "ac5", fmt.Sprintf(
				"AC5 names the %q leg and the manifest carries no record for it", required))
			continue
		}
		if leg.Status != "PASSED" {
			add(FindingAC5LegNotPassed, Block, "ac5", fmt.Sprintf(
				"AC5 leg %q status is %q, not PASSED: %s", required, leg.Status, leg.Evidence))
		}
	}
}

// --- AC1: one SIGNED denominator --------------------------------------------

func checkSignature(manifest *Manifest, add func(code, disposition, target, detail string)) {
	if manifest.Signature.Scheme != "ed25519" {
		add(FindingSignatureSchemeInvalid, Block, "signature", fmt.Sprintf(
			"signature scheme is %q; this repository signs with ed25519 "+
				"(internal/intake/sign.go)", manifest.Signature.Scheme))
	}
	digest, err := PayloadDigest(manifest)
	if err != nil {
		add(FindingPayloadDigestDrift, Block, "signature", fmt.Sprintf(
			"payload digest not computable: %v", err))
	} else if digest != manifest.Signature.PayloadDigest {
		add(FindingPayloadDigestDrift, Block, "signature", fmt.Sprintf(
			"payload digest is %s, manifest declares %s -- the document changed after the "+
				"digest was taken", digest, manifest.Signature.PayloadDigest))
	}
	if strings.TrimSpace(manifest.Signature.PublicKeyHex) == "" {
		add(FindingSigningKeyAbsent, Block, "signature", fmt.Sprintf(
			"no signing key is available (key_id %q); the protected operator holds the "+
				"Ed25519 key material and this session has none", manifest.Signature.KeyID))
	}
	if strings.TrimSpace(manifest.Signature.Signature) == "" {
		add(FindingSignatureAbsent, Block, "signature",
			"AC1 requires ONE SIGNED denominator and this document is unsigned; an "+
				"unsigned denominator is a draft")
		return
	}
	// A signature is present: it must verify. Anything else is worse than none.
	key, err := hex.DecodeString(strings.TrimSpace(manifest.Signature.PublicKeyHex))
	if err != nil || len(key) == 0 {
		add(FindingSigningKeyAbsent, Block, "signature",
			"a signature is present but no usable public key accompanies it, so it "+
				"cannot be verified; an unverifiable signature is not a signature")
		return
	}
	if !verifySignature(key, digest, manifest.Signature.Signature) {
		add(FindingSignatureAbsent, Block, "signature",
			"the declared signature does not verify over the recomputed payload digest")
	}
}

// --- claim ------------------------------------------------------------------

func checkClaim(
	manifest *Manifest, verdict *Verdict,
	add func(code, disposition, target, detail string),
) {
	if !ClaimGrades[manifest.Claim.ClaimGrade] {
		add(FindingClaimGradeInvalid, Block, "claim", fmt.Sprintf(
			"claim_grade %q is not one of the program's assurance labels",
			manifest.Claim.ClaimGrade))
	}
	blocking := BlockingCount(*verdict)
	if blocking == 0 {
		return
	}
	claims := []struct {
		name string
		met  bool
	}{
		{"ac1_met", manifest.Claim.AC1Met}, {"ac2_met", manifest.Claim.AC2Met},
		{"ac3_met", manifest.Claim.AC3Met}, {"ac4_met", manifest.Claim.AC4Met},
		{"ac5_met", manifest.Claim.AC5Met},
	}
	for _, claim := range claims {
		if claim.met {
			add(FindingUnavailableAsSuccess, Block, "claim", fmt.Sprintf(
				"manifest claims %s=true while %d BLOCK findings stand", claim.name, blocking))
		}
	}
}
