package corpora

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Mutant is one reference-model mutation operator. Behavior mutants perturb
// the frame/state model; handshake mutants perturb the RFC rule chain. These
// measure the corpus's discriminative power against the Go reference model;
// they are not Java or Rust binary mutants, which remain a live gate.
type Mutant struct {
	MutantID  string
	Kind      string
	Operator  string
	Behavior  func() Behavior
	Handshake func() HandshakeBehavior
}

// BuiltinMutants is the committed reference mutant inventory.
func BuiltinMutants() []Mutant {
	behaviorMutant := func(id, operator string, mutate func(*Behavior)) Mutant {
		return Mutant{MutantID: id, Kind: "behavior", Operator: operator,
			Behavior: func() Behavior {
				b := ReferenceBehavior()
				mutate(&b)
				return b
			}}
	}
	handshakeMutant := func(id, operator string, mutate func(*HandshakeBehavior)) Mutant {
		return Mutant{MutantID: id, Kind: "handshake", Operator: operator,
			Handshake: func() HandshakeBehavior {
				b := ReferenceHandshakeBehavior()
				mutate(&b)
				return b
			}}
	}
	return []Mutant{
		behaviorMutant("mut-control-limit-200",
			"raise the 125-octet control payload limit to 200",
			func(b *Behavior) { b.ControlPayloadLimit = 200 }),
		behaviorMutant("mut-utf8-off",
			"accept invalid UTF-8 in text payloads",
			func(b *Behavior) { b.ValidateUTF8 = false }),
		behaviorMutant("mut-close-code-any",
			"accept reserved close codes on the wire and on send",
			func(b *Behavior) { b.EnforceCloseCodeValidity = false }),
		behaviorMutant("mut-echo-close-off",
			"skip echoing the close frame during the two-way close handshake",
			func(b *Behavior) { b.EchoCloseWhileOpen = false }),
		behaviorMutant("mut-state-open-ignored",
			"allow local commands outside the OPEN state",
			func(b *Behavior) { b.EnforceOpenStateForActions = false }),
		behaviorMutant("mut-continuation-start-off",
			"accept continuation frames without a started sequence",
			func(b *Behavior) { b.EnforceContinuationStart = false }),
		behaviorMutant("mut-frame-size-limit-off",
			"ignore the declared maximum frame size",
			func(b *Behavior) { b.EnforceFrameSizeLimit = false }),
		behaviorMutant("mut-client-mask-off",
			"send client frames unmasked",
			func(b *Behavior) { b.ClientMasksOutbound = false }),
		behaviorMutant("mut-rsv-ignored",
			"accept frames with reserved bits set",
			func(b *Behavior) { b.EnforceReservedBits = false }),
		handshakeMutant("hs-mut-method-any",
			"accept any HTTP method for the opening handshake",
			func(b *HandshakeBehavior) { b.RequireMethodGet = false }),
		handshakeMutant("hs-mut-version-any",
			"accept any Sec-WebSocket-Version",
			func(b *HandshakeBehavior) { b.RequireVersion13 = false }),
		handshakeMutant("hs-mut-key-length-any",
			"accept keys that do not decode to 16 bytes",
			func(b *HandshakeBehavior) { b.RequireKeyLength16 = false }),
		handshakeMutant("hs-mut-accept-any",
			"skip Sec-WebSocket-Accept verification",
			func(b *HandshakeBehavior) { b.RequireAcceptMatch = false }),
		handshakeMutant("hs-mut-duplicates-ok",
			"accept duplicated singleton headers",
			func(b *HandshakeBehavior) { b.RejectDuplicates = false }),
		handshakeMutant("hs-mut-limits-off",
			"ignore configured byte and header limits",
			func(b *HandshakeBehavior) { b.EnforceLimits = false }),
		handshakeMutant("hs-mut-upgrade-value-any",
			"accept any Upgrade and Connection values",
			func(b *HandshakeBehavior) { b.RequireUpgradeValue = false }),
	}
}

// MutantResult is one mutant's derived kill inventory.
type MutantResult struct {
	MutantID         string         `json:"mutant_id"`
	Kind             string         `json:"kind"`
	Operator         string         `json:"operator"`
	Killed           bool           `json:"killed"`
	KillingScenarios map[string]int `json:"killing_scenarios"`
	TotalKilling     int            `json:"total_killing"`
}

// MutationReport is the derived mutation-analysis outcome.
type MutationReport struct {
	Mutants   []MutantResult `json:"mutants"`
	Killed    int            `json:"killed"`
	Surviving int            `json:"surviving"`
}

// RunMutationAnalysis measures, for every mutant, which scenarios distinguish
// the mutated model from the committed expectations. Every count is derived.
func RunMutationAnalysis(g *GeneratedCorpora, mutants []Mutant) (MutationReport, error) {
	var report MutationReport
	tiers := map[string][]Scenario{
		"public": g.Public, "hidden": g.Hidden, "sealed": g.Sealed}
	for _, mutant := range mutants {
		result := MutantResult{
			MutantID: mutant.MutantID,
			Kind:     mutant.Kind,
			Operator: mutant.Operator,
			KillingScenarios: map[string]int{
				"public": 0, "hidden": 0, "sealed": 0, "handshake": 0},
		}
		switch mutant.Kind {
		case "behavior":
			behavior := mutant.Behavior()
			for tier, scenarios := range tiers {
				for _, sc := range scenarios {
					mutated, err := DeriveExpectedWith(sc.Core, behavior)
					diverged := err != nil
					if err == nil {
						left, err := CanonicalJSON(mutated.toMap())
						if err != nil {
							return report, err
						}
						right, err := CanonicalJSON(sc.Expected.toMap())
						if err != nil {
							return report, err
						}
						diverged = !bytes.Equal(left, right)
					}
					if diverged {
						result.KillingScenarios[tier]++
						result.TotalKilling++
					}
				}
			}
		case "handshake":
			behavior := mutant.Handshake()
			for _, c := range g.Handshake {
				raw, err := base64.StdEncoding.DecodeString(c.RawBase64)
				if err != nil {
					return report, fmt.Errorf("case %s raw: %w", c.CaseID, err)
				}
				mutated, err := DeriveHandshakeWith(c.Direction, raw, c.Config,
					c.Context, behavior)
				diverged := err != nil
				if err == nil {
					left, err := CanonicalJSON(mutated.toMap())
					if err != nil {
						return report, err
					}
					right, err := CanonicalJSON(c.Expected.toMap())
					if err != nil {
						return report, err
					}
					diverged = !bytes.Equal(left, right)
				}
				if diverged {
					result.KillingScenarios["handshake"]++
					result.TotalKilling++
				}
			}
		default:
			return report, fmt.Errorf("mutant %s has unsupported kind %q",
				mutant.MutantID, mutant.Kind)
		}
		result.Killed = result.TotalKilling > 0
		if result.Killed {
			report.Killed++
		} else {
			report.Surviving++
		}
		report.Mutants = append(report.Mutants, result)
	}
	return report, nil
}

// StubReport is the derived negative-control outcome for an inert target.
type StubReport struct {
	Total    int `json:"total"`
	Passes   int `json:"passes"`
	Failures int `json:"failures"`
}

// EvaluateStubTarget runs the real evaluator against an inert stub: behavior
// scenarios receive an empty-behavior response; handshake cases receive no
// verdict at all. This is a negative control of the corpus and evaluator,
// not a Rust execution.
func EvaluateStubTarget(g *GeneratedCorpora) StubReport {
	var report StubReport
	for _, scenarios := range [][]Scenario{g.Public, g.Hidden, g.Sealed} {
		for _, sc := range scenarios {
			report.Total++
			response, err := synthesizeStubResponse(sc)
			if err != nil {
				report.Failures++
				continue
			}
			if passed, _ := EvaluateOracleResponse(sc, response); passed {
				report.Passes++
			} else {
				report.Failures++
			}
		}
	}
	// An empty target emits no handshake verdicts: the real handshake
	// evaluator scores its empty transcript as all-missing.
	handshakeReport, err := EvaluateHandshakeTranscript(g.Handshake, nil)
	report.Total += len(g.Handshake)
	if err != nil {
		report.Failures += len(g.Handshake)
		return report
	}
	report.Passes += handshakeReport.Passed
	report.Failures += handshakeReport.Missing + handshakeReport.Failed + handshakeReport.Unmatched
	return report
}

// RerunReport reconciles repeated full generations.
type RerunReport struct {
	Runs       int      `json:"runs"`
	Digests    []string `json:"digests"`
	Reconciled bool     `json:"reconciled"`
}

// RunGenerationReruns regenerates everything n times and reconciles digests.
func RunGenerationReruns(input GenerationInput, runs int) (RerunReport, error) {
	report := RerunReport{Runs: runs, Reconciled: true}
	for i := 0; i < runs; i++ {
		generated, err := GenerateAll(input)
		if err != nil {
			return report, err
		}
		digest, err := generated.CanonicalDigest()
		if err != nil {
			return report, err
		}
		report.Digests = append(report.Digests, digest)
		if digest != report.Digests[0] {
			report.Reconciled = false
		}
	}
	return report, nil
}

// ProtectedOverride is an attempt to change a verdict using evidence sourced
// from the protected store.
type ProtectedOverride struct {
	ScenarioID string `json:"scenario_id"`
	Source     string `json:"source"`
	Claim      string `json:"claim"`
}

// RejectProtectedRescue blocks any protected-sourced override of a public
// scenario verdict: public results derive only from public artifacts.
func RejectProtectedRescue(publicScenarioIDs map[string]bool,
	overrides []ProtectedOverride) []Finding {
	var findings []Finding
	for _, override := range overrides {
		if publicScenarioIDs[override.ScenarioID] {
			findings = append(findings, Finding{
				Code: "PROTECTED_RESCUE_BLOCKED",
				Path: override.ScenarioID,
				Detail: "protected evidence cannot rescue a public failure: " +
					override.Source,
			})
		}
	}
	return findings
}

// LoadGenerationInput reconstructs the generation input from the committed
// manifests and the protected master secret.
func LoadGenerationInput(root, protectedRoot string) (GenerationInput, error) {
	publicManifest, err := readManifest(filepath.Join(root, repoCorporaDir, "public/manifest.json"))
	if err != nil {
		return GenerationInput{}, err
	}
	hiddenManifest, err := readManifest(filepath.Join(root, repoCorporaDir, "hidden/manifest.json"))
	if err != nil {
		return GenerationInput{}, err
	}
	generator, _ := publicManifest["generator"].(map[string]any)
	publicSeed, _ := generator["public_seed"].(string)
	heldOutGenerator, _ := hiddenManifest["generator"].(map[string]any)
	epochValue, _ := heldOutGenerator["epoch"].(float64)
	secretRaw, err := os.ReadFile(filepath.Join(protectedRoot, protectedSecretFile))
	if err != nil {
		return GenerationInput{}, err
	}
	return GenerationInput{
		PublicSeed: publicSeed,
		Secret:     strings.TrimSpace(string(secretRaw)),
		Epoch:      int(epochValue),
	}, nil
}

func gateStatus(pass bool) string {
	if pass {
		return "PASS"
	}
	return "BLOCKED"
}

// BuildCalibration assembles evidence/corpus-calibration.json from derived
// reports only. Offline gates carry computed numbers; live gates stay
// fail-closed with the exact constraint that blocks them in this runtime.
func BuildCalibration(root, protectedRoot string, g *GeneratedCorpora) (map[string]any, error) {
	input, err := LoadGenerationInput(root, protectedRoot)
	if err != nil {
		return nil, err
	}
	verifyFindings, err := VerifyAll(root, protectedRoot)
	if err != nil {
		return nil, err
	}
	rerun, err := RunGenerationReruns(input, 2)
	if err != nil {
		return nil, err
	}
	mutation, err := RunMutationAnalysis(g, BuiltinMutants())
	if err != nil {
		return nil, err
	}
	stub := EvaluateStubTarget(g)

	corpora := map[string]any{}
	for tier, plan := range g.PlanCounts {
		manifestPath := filepath.Join(repoCorporaDir, tier, "manifest.json")
		raw, err := os.ReadFile(filepath.Join(root, manifestPath))
		if err != nil {
			return nil, err
		}
		corpora[tier] = map[string]any{
			"manifest_path":   manifestPath,
			"manifest_sha256": DigestSHA256(raw),
			"selected":        plan.Selected,
			"expected":        plan.Expected,
			"filtered":        plan.Filtered,
		}
	}

	mutantEntries := make([]any, 0, len(mutation.Mutants))
	for _, result := range mutation.Mutants {
		killing := map[string]any{}
		for tier, count := range result.KillingScenarios {
			killing[tier] = count
		}
		mutantEntries = append(mutantEntries, map[string]any{
			"mutant_id":         result.MutantID,
			"kind":              result.Kind,
			"operator":          result.Operator,
			"killed":            result.Killed,
			"killing_scenarios": killing,
			"total_killing":     result.TotalKilling,
		})
	}

	findingsEntries := make([]any, 0, len(verifyFindings))
	for _, finding := range verifyFindings {
		findingsEntries = append(findingsEntries, map[string]any{
			"code": finding.Code, "path": finding.Path, "detail": finding.Detail})
	}

	digests := make([]any, len(rerun.Digests))
	for i, digest := range rerun.Digests {
		digests[i] = digest
	}

	offlinePass := len(verifyFindings) == 0 && rerun.Reconciled &&
		mutation.Surviving == 0 && len(mutation.Mutants) > 0 && stub.Passes == 0

	sbxConstraint := "candidate execution requires the accepted US-007 Docker sbx workload " +
		"profile (default-deny network, no shared skills, no local MCP, no secrets, no " +
		"protected-store mounts); live sbx attempts are owner-authorized per attempt and " +
		"run by the orchestrating owner session, never by this offline calibration"

	document := map[string]any{
		"$schema":            "../schemas/corpus-calibration-1.0.0.schema.json",
		"schema_version":     "1.0.0",
		"evidence_kind":      "corpus-calibration",
		"corpora":            corpora,
		"expectation_status": ExpectationStatusReferenceModel,
		"offline_gates": map[string]any{
			"generation_determinism": map[string]any{
				"status":     gateStatus(rerun.Reconciled),
				"runs":       rerun.Runs,
				"digests":    digests,
				"reconciled": rerun.Reconciled,
			},
			"manifest_reconciliation": map[string]any{
				"status":         gateStatus(len(verifyFindings) == 0),
				"findings_count": len(verifyFindings),
				"findings":       findingsEntries,
			},
			"reference_mutation_analysis": map[string]any{
				"status": gateStatus(mutation.Surviving == 0 && len(mutation.Mutants) > 0),
				"model": "Go reference model mutants measuring corpus discriminative " +
					"power; not Java or Rust binary mutants (those remain a live gate)",
				"total_mutants": len(mutation.Mutants),
				"killed":        mutation.Killed,
				"surviving":     mutation.Surviving,
				"mutants":       mutantEntries,
			},
			"stub_target_analysis": map[string]any{
				"status": gateStatus(stub.Passes == 0 && stub.Total > 0),
				"model": "inert empty-behavior stub evaluated by the real corpus " +
					"evaluator; a negative control of the corpus, not a Rust execution",
				"total":    stub.Total,
				"passes":   stub.Passes,
				"failures": stub.Failures,
			},
			"protected_rescue_rule": map[string]any{
				"status": "ENFORCED",
				"rule": "public verdicts derive only from public artifacts; any " +
					"protected-sourced override of a public result blocks with " +
					"PROTECTED_RESCUE_BLOCKED",
			},
		},
		"live_gates": map[string]any{
			"java_oracle_pass_rate": map[string]any{
				"status":      "BLOCKED_PENDING_LIVE_EXECUTION",
				"requirement": "the pinned Java oracle passes 100% of behavior scenarios",
				"constraint": "the pinned Java-WebSocket 1.6.0 runtime jar (sha256:" +
					oracleRuntimeSHA256 + ") is not materialized in this workspace; " +
					"acquiring it and executing java-oracle are owner-authorized live steps",
			},
			"empty_rust_target_fails": map[string]any{
				"status":      "BLOCKED_PENDING_LIVE_EXECUTION",
				"requirement": "an empty or stub Rust target fails the behavior corpus",
				"constraint":  sbxConstraint,
			},
			"planted_java_rust_mutants_killed": map[string]any{
				"status":      "BLOCKED_PENDING_LIVE_EXECUTION",
				"requirement": "planted Java and Rust binary mutants are killed with nonzero inventories",
				"constraint":  sbxConstraint,
			},
			"execution_rerun_reconciliation": map[string]any{
				"status":      "BLOCKED_PENDING_LIVE_EXECUTION",
				"requirement": "two live calibration executions reconcile exactly with zero flakes",
				"constraint":  "requires the live java-oracle and sbx candidate executions above",
			},
			"sealed_network_denial": map[string]any{
				"status":      "BLOCKED_PENDING_LIVE_EXECUTION",
				"requirement": "sealed-tier execution observes the default-deny network policy live",
				"constraint":  sbxConstraint,
			},
		},
		"live_steps": []any{
			"materialize the pinned Java-WebSocket 1.6.0 jar per evidence/intake/source-pins.json and verify sha256:" + oracleRuntimeSHA256,
			"build java-oracle (make -C java-oracle build JAVA_WEBSOCKET_JAR=... RUNTIME_SUPPORT_CP=...) and run: corporactl oracle-requests --root . --protected-root <root> --tier public | java -jar java-oracle/build/java-oracle.jar > public-transcript.jsonl",
			"evaluate: corporactl evaluate --root . --protected-root <root> --tier public --transcript public-transcript.jsonl (requires 100% pass)",
			"repeat oracle-requests/evaluate for hidden and sealed tiers inside the custodian boundary; each held-out invocation spends the hash-chained ledger's query budget, failure diagnostics spend the diagnostic budget, and transcripts stay in the protected store",
			"execute the handshake corpus against an executable handshake target: corporactl oracle-requests --tier handshake emits the raw cases, corporactl evaluate --tier handshake scores the verdict transcript",
			"run the empty Rust target and planted Java/Rust mutants inside the accepted US-007 sbx profile (owner authorization per attempt) and evaluate their transcripts; all must fail or be killed",
			"rerun the full live calibration once more and reconcile both transcripts exactly",
			"probe sealed-network denial inside the sbx profile and attach the receipt",
			"record completions by setting manifest execution_status=LIVE_EXECUTED with execution_evidence digests and live gate PASS/FAIL results with transcript digests; the schemas accept both pending and completed states",
		},
		"model_scoping": []any{
			"masking-role violations are a documented Java-compatibility non-goal, not RFC coverage: the pinned 1.6.0 runtime does not enforce RFC 6455 section 5.1 masking on receive (Draft_6455.translateSingleFrame reads the mask bit only), so the corpus stays spec-conformant on masking and the deriver rejects wrong-masked inputs as out of scope instead of asserting either behavior",
			"error-path counts are asserted from the pinned sources; frames that straddle chunk boundaries with invalid content remain out of the generated space because their partial-completion consumption depends on incompleteframe growth internals",
			"send-side control payloads above 125 octets are pinned as sendable (ControlFrame.isValid has no length check) and covered by a held-out family",
		},
		"status": func() string {
			if offlinePass {
				return "OFFLINE_CALIBRATED_PENDING_LIVE_EXECUTION"
			}
			return "BLOCKED"
		}(),
	}
	for k, v := range assuranceLabels() {
		document[k] = v
	}
	return document, nil
}

// WriteCalibration writes evidence/corpus-calibration.json.
func WriteCalibration(root string, document map[string]any) error {
	return writeJSONFile(filepath.Join(root, "evidence/corpus-calibration.json"), document)
}
