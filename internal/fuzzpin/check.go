package fuzzpin

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// exitNoProcessState marks a probe command that never produced a ProcessState
// (it never started). There is no real exit code to read, so none is invented.
// Same sentinel discipline as cmd/rustgatectl.
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

// rustTestPattern matches a `#[test]`-attributed function definition. The
// attribute must be present: a plain helper `fn` of the same name is not a
// test entrypoint.
func rustTestPattern(name string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^#\[test\]\s*\n(?:^\s*#\[[^\]]*\]\s*\n)*^\s*fn\s+` + regexp.QuoteMeta(name) + `\s*\(`)
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
		add(FindingManifestSchemaInvalid, Block, "", fmt.Sprintf(
			"digest_scheme is %q, want %q", manifest.DigestScheme, DigestScheme))
	}

	// --- engines: source/toolchain pins and availability -------------------
	engines := map[string]Engine{}
	availability := map[string]bool{}
	for _, engine := range manifest.Engines {
		engines[engine.ID] = engine

		if len(engine.SourceFiles) > 0 {
			digest, _, err := TreeDigest(root, engine.SourceFiles)
			switch {
			case err != nil:
				add(FindingEngineSourceDigestDrift, Block, engine.ID, fmt.Sprintf(
					"generator source unreadable: %v", err))
			case digest != engine.SourceDigest:
				add(FindingEngineSourceDigestDrift, Block, engine.ID, fmt.Sprintf(
					"generator source digest %s, manifest pins %s", digest, engine.SourceDigest))
			}
		}

		if engine.Toolchain.PinFile != "" {
			digest, _, err := TreeDigest(root, []string{engine.Toolchain.PinFile})
			switch {
			case err != nil:
				add(FindingToolchainPinDrift, Block, engine.ID, fmt.Sprintf(
					"toolchain pin file unreadable: %v", err))
			case digest != engine.Toolchain.PinDigest:
				add(FindingToolchainPinDrift, Block, engine.ID, fmt.Sprintf(
					"toolchain pin digest %s, manifest pins %s", digest, engine.Toolchain.PinDigest))
			}
		}

		probe := ProbeEngine(root, engine)
		verdict.EngineAvailability = append(verdict.EngineAvailability, probe)
		availability[engine.ID] = probe.Available
		if !probe.Available {
			// AC3: "unavailable tooling blocks instead of skipping". The block
			// is raised here, unconditionally, the moment the probe fails.
			add(FindingEngineUnavailable, Block, engine.ID, fmt.Sprintf(
				"probe %q %s -- engine is NOT installed in this environment; AC3 blocks",
				probe.Command, probe.ExitText))
		}
	}

	// --- targets -----------------------------------------------------------
	mapped := map[string]bool{}
	for _, target := range manifest.Targets {
		mapped[target.AC2Family] = true
		checkTarget(root, target, engines, availability, add)
	}

	// Every AC2 family must appear. An unmapped family is a family nobody
	// looked at, which is the flattering direction.
	for _, family := range AC2Families {
		if !mapped[family] {
			add(FindingFamilyUnmapped, Block, family,
				"AC2 names this target family and the manifest carries no record for it")
		}
	}

	// --- the manifest's own claim -----------------------------------------
	blocking := 0
	for _, finding := range verdict.Findings {
		if finding.Disposition == Block {
			blocking++
		}
	}
	if blocking > 0 {
		if manifest.Claim.AC3Met {
			add(FindingUnavailableAsSuccess, Block, "claim", fmt.Sprintf(
				"manifest claims ac3_met=true while %d BLOCK findings stand", blocking))
			blocking++
		}
		if manifest.Claim.AC2Met {
			add(FindingUnavailableAsSuccess, Block, "claim", fmt.Sprintf(
				"manifest claims ac2_met=true while %d BLOCK findings stand", blocking))
			blocking++
		}
	}

	sort.SliceStable(verdict.Findings, func(i, j int) bool {
		if verdict.Findings[i].Target != verdict.Findings[j].Target {
			return verdict.Findings[i].Target < verdict.Findings[j].Target
		}
		return verdict.Findings[i].Code < verdict.Findings[j].Code
	})
	if blocking > 0 {
		verdict.State = "BLOCKED"
	}
	return verdict
}

func checkTarget(
	root string,
	target Target,
	engines map[string]Engine,
	availability map[string]bool,
	add func(code, disposition, target, detail string),
) {
	switch target.Status {
	case StatusAbsent:
		// An AC2 family with no generative target. This is the honest record
		// of a gap and it BLOCKS: AC2 requires the target to exist.
		add(FindingTargetAbsent, Block, target.ID, fmt.Sprintf(
			"AC2 family %q has no generative fuzz target: %s", target.AC2Family, target.Rationale))
		return
	case StatusBlockedUnavailable:
		// The engine must actually be unavailable. Recording a target as
		// blocked-unavailable when its engine IS installed hides a target
		// nobody ran; the engine-unavailable BLOCK is raised at the engine.
		if available, known := availability[target.Engine]; known && available {
			add(FindingUnavailableAsSkip, Block, target.ID, fmt.Sprintf(
				"target is recorded %s but engine %q probed AVAILABLE",
				StatusBlockedUnavailable, target.Engine))
		}
		return
	case StatusSharedNoDedicatedTarget:
		add(FindingSharedTargetNotDedicated, Note, target.ID, fmt.Sprintf(
			"AC2 family %q is generated only inside another family's target; no dedicated "+
				"target, corpus, or campaign bound of its own: %s", target.AC2Family, target.Rationale))
		// A shared family still has to prove the target it rides on exists,
		// so the entrypoint/campaign checks below run for it too.
	case StatusPinned:
	default:
		add(FindingManifestSchemaInvalid, Block, target.ID, fmt.Sprintf(
			"unknown target status %q", target.Status))
		return
	}

	engine, known := engines[target.Engine]
	if !known {
		add(FindingUnknownEngineReference, Block, target.ID, fmt.Sprintf(
			"target references engine %q, which the manifest does not declare", target.Engine))
		return
	}
	// A target may never be recorded as running when its engine is not
	// installed. This is the us006-unavailable-as-skip shape: the skip is the
	// defect, not the missing tool.
	if available := availability[engine.ID]; !available {
		add(FindingUnavailableAsSkip, Block, target.ID, fmt.Sprintf(
			"target status %q asserts a campaign, but engine %q is UNAVAILABLE; "+
				"the honest status is %s", target.Status, engine.ID, StatusBlockedUnavailable))
	}

	// --- exact target manifest: entrypoints must exist and match -----------
	if len(target.Entrypoints) == 0 {
		add(FindingEntrypointMissing, Block, target.ID, "no entrypoint declared")
	}
	declaredCases := 0
	for _, entry := range target.Entrypoints {
		declaredCases += entry.Cases
		abs := filepath.Join(root, entry.File)
		data, err := os.ReadFile(abs)
		if err != nil {
			add(FindingEntrypointMissing, Block, target.ID, fmt.Sprintf(
				"entrypoint file %s unreadable: %v", entry.File, err))
			continue
		}
		source := string(data)
		if !rustTestPattern(entry.Test).MatchString(source) {
			add(FindingEntrypointMissing, Block, target.ID, fmt.Sprintf(
				"%s declares no #[test] fn %s", entry.File, entry.Test))
			continue
		}
		// Identity, not existence: the campaign size the manifest claims must
		// be the loop literal in the code, and the seed must be the seed.
		if entry.CaseLiteral != "" && !strings.Contains(source, entry.CaseLiteral) {
			add(FindingCampaignLiteralDrift, Block, target.ID, fmt.Sprintf(
				"%s: declared case literal %q for %s does not appear in the source; "+
					"the manifest's campaign size is not the code's campaign size",
				entry.File, entry.CaseLiteral, entry.Test))
		}
		if entry.Seed != "" && !strings.Contains(source, entry.Seed) {
			add(FindingCampaignLiteralDrift, Block, target.ID, fmt.Sprintf(
				"%s: declared seed %q for %s does not appear in the source",
				entry.File, entry.Seed, entry.Test))
		}
	}

	// --- corpus digest -----------------------------------------------------
	if len(target.Corpus.Paths) > 0 {
		digest, count, err := TreeDigest(root, target.Corpus.Paths)
		switch {
		case err != nil:
			add(FindingCorpusDigestMismatch, Block, target.ID, fmt.Sprintf(
				"corpus unreadable: %v", err))
		case digest != target.Corpus.Digest:
			add(FindingCorpusDigestMismatch, Block, target.ID, fmt.Sprintf(
				"corpus digest %s over %d files, manifest pins %s",
				digest, count, target.Corpus.Digest))
		case count != target.Corpus.FileCount:
			add(FindingCorpusDigestMismatch, Block, target.ID, fmt.Sprintf(
				"corpus holds %d files, manifest declares %d", count, target.Corpus.FileCount))
		}
	}

	// --- bounded campaign + F005 liveness rule -----------------------------
	//
	// Each of these four rules carries its OWN finding code. The first deletion
	// attack over this package found two checks that survived deletion because
	// a sibling rule sharing their code fired in their place and kept the
	// fixture green: the case-literal check was masked by the total-sum check,
	// and the wall-clock-kind check was masked by the positive-deadline check.
	// A check whose only witness is another check's finding is not evidence.
	if target.Campaign.TotalCases != declaredCases {
		add(FindingCampaignTotalMismatch, Block, target.ID, fmt.Sprintf(
			"campaign total_cases %d does not equal the sum of its entrypoint cases %d",
			target.Campaign.TotalCases, declaredCases))
	}
	if target.Campaign.TotalCases <= 0 {
		add(FindingCampaignEmpty, Block, target.ID,
			"campaign declares no cases; a corpus is not a campaign")
	}
	if target.Campaign.LivenessGuard.Kind != "wall_clock" {
		add(FindingLivenessGuardNotWallClock, Block, target.ID, fmt.Sprintf(
			"liveness guard kind is %q; finding F005 requires a wall-clock deadline, "+
				"never a count of iterations", target.Campaign.LivenessGuard.Kind))
	}
	if target.Campaign.LivenessGuard.DeadlineSeconds <= 0 {
		add(FindingLivenessDeadlineAbsent, Block, target.ID,
			"liveness guard declares no positive wall-clock deadline")
	}

	// --- timeout/OOM/crash policy -----------------------------------------
	if target.Policy.Crash == "" || target.Policy.Timeout == "" || target.Policy.OOM == "" {
		add(FindingPolicyIncomplete, Block, target.ID, fmt.Sprintf(
			"policy incomplete (crash=%q timeout=%q oom=%q); AC3 requires all three",
			target.Policy.Crash, target.Policy.Timeout, target.Policy.OOM))
	}

	// --- artifact capture --------------------------------------------------
	if target.Artifacts.Dir == "" {
		add(FindingArtifactCaptureAbsent, Block, target.ID, "no artifact capture directory declared")
	} else if _, err := os.Stat(filepath.Join(root, target.Artifacts.Dir)); err != nil {
		add(FindingArtifactCaptureAbsent, Block, target.ID, fmt.Sprintf(
			"artifact directory %s absent: %v -- a declared capture path that does not "+
				"exist captured nothing", target.Artifacts.Dir, err))
	}

	// --- replay command ----------------------------------------------------
	if len(target.Replay.Command) == 0 {
		add(FindingReplayCommandAbsent, Block, target.ID, "no replay command declared")
	}
}
