// Command corporactl generates, verifies, and calibrates the US-005 public,
// hidden, sealed, and handshake corpora, and projects scenarios onto the
// java-oracle JSONL protocol for live execution by the owner.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/michaellady/verified-java-websocket-port/internal/corpora"
)

// DefaultPublicSeed is the committed public-tier seed. Changing it changes
// the public and handshake corpora and must be a deliberate, reviewed act.
const DefaultPublicSeed = "us005-public-calibration-seed-v1"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 {
		printUsage(stderr)
		return 2
	}
	switch arguments[0] {
	case "generate":
		return runGenerate(arguments[1:], stdout, stderr)
	case "verify":
		return runVerify(arguments[1:], stdout, stderr)
	case "calibrate":
		return runCalibrate(arguments[1:], stdout, stderr)
	case "oracle-requests":
		return runOracleRequests(arguments[1:], stdout, stderr)
	case "evaluate":
		return runEvaluate(arguments[1:], stdout, stderr)
	default:
		printUsage(stderr)
		return 2
	}
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "usage:")
	fmt.Fprintln(output, "  corporactl generate --root DIR --protected-root DIR [--epoch N] [--public-seed SEED]")
	fmt.Fprintln(output, "  corporactl verify --root DIR --protected-root DIR [--schemas DIR]")
	fmt.Fprintln(output, "  corporactl calibrate --root DIR --protected-root DIR [--schemas DIR]")
	fmt.Fprintln(output, "  corporactl oracle-requests --root DIR --protected-root DIR --tier public|hidden|sealed|handshake [--out FILE] [--wire]")
	fmt.Fprintln(output, "  corporactl evaluate --root DIR --protected-root DIR --tier public|hidden|sealed|handshake --transcript FILE [--live]")
	fmt.Fprintln(output, "    --wire  handshake tier only: emit java-oracle handshake protocol requests")
	fmt.Fprintln(output, "    --live  handshake tier only: score a java-runtime observable transcript")
}

type commonFlags struct {
	root          string
	protectedRoot string
}

func parseCommon(flags *flag.FlagSet) *commonFlags {
	common := &commonFlags{}
	flags.StringVar(&common.root, "root", "", "repository root")
	flags.StringVar(&common.protectedRoot, "protected-root", "", "protected custodian root")
	return common
}

func (c *commonFlags) valid() bool {
	return c.root != "" && c.protectedRoot != ""
}

func regenerate(common *commonFlags) (*corpora.GeneratedCorpora, error) {
	input, err := corpora.LoadGenerationInput(common.root, common.protectedRoot)
	if err != nil {
		return nil, err
	}
	return corpora.GenerateAll(input)
}

func runGenerate(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("generate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	common := parseCommon(flags)
	epoch := flags.Int("epoch", 1, "held-out rotation epoch")
	publicSeed := flags.String("public-seed", DefaultPublicSeed, "committed public seed")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || !common.valid() {
		printUsage(stderr)
		return 2
	}
	secret, err := corpora.EnsureSecret(common.protectedRoot)
	if err != nil {
		fmt.Fprintln(stderr, "generate:", err)
		return 1
	}
	input := corpora.GenerationInput{PublicSeed: *publicSeed, Secret: secret, Epoch: *epoch}
	generated, err := corpora.GenerateAll(input)
	if err != nil {
		fmt.Fprintln(stderr, "generate:", err)
		return 1
	}
	if err := corpora.WriteAll(common.root, common.protectedRoot, input, generated); err != nil {
		fmt.Fprintln(stderr, "generate:", err)
		return 1
	}
	digest, err := generated.CanonicalDigest()
	if err != nil {
		fmt.Fprintln(stderr, "generate:", err)
		return 1
	}
	return printJSON(stdout, stderr, map[string]any{
		"ok":                true,
		"generation_digest": digest,
		"counts":            generated.PlanCounts,
	})
}

func collectFindings(common *commonFlags, schemasDir string) ([]corpora.Finding, error) {
	findings, err := corpora.VerifyAll(common.root, common.protectedRoot)
	if err != nil {
		return nil, err
	}
	if schemasDir != "" {
		schemaFindings, err := corpora.ValidateCorpusSchemas(schemasDir,
			common.root, common.protectedRoot)
		if err != nil {
			return nil, err
		}
		findings = append(findings, schemaFindings...)
	}
	return findings, nil
}

func runVerify(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	common := parseCommon(flags)
	schemasDir := flags.String("schemas", "", "schemas directory (enables schema validation)")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || !common.valid() {
		printUsage(stderr)
		return 2
	}
	findings, err := collectFindings(common, *schemasDir)
	if err != nil {
		fmt.Fprintln(stderr, "verify:", err)
		return 1
	}
	code := 0
	if len(findings) != 0 {
		code = 1
	}
	if rc := printJSON(stdout, stderr, map[string]any{
		"ok": len(findings) == 0, "findings": findings}); rc != 0 {
		return rc
	}
	return code
}

func runCalibrate(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("calibrate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	common := parseCommon(flags)
	schemasDir := flags.String("schemas", "", "schemas directory (enables schema validation)")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || !common.valid() {
		printUsage(stderr)
		return 2
	}
	generated, err := regenerate(common)
	if err != nil {
		fmt.Fprintln(stderr, "calibrate:", err)
		return 1
	}
	document, err := corpora.BuildCalibration(common.root, common.protectedRoot, generated)
	if err != nil {
		fmt.Fprintln(stderr, "calibrate:", err)
		return 1
	}
	if err := corpora.WriteCalibration(common.root, document); err != nil {
		fmt.Fprintln(stderr, "calibrate:", err)
		return 1
	}
	if *schemasDir != "" {
		findings, err := corpora.ValidateCorpusSchemas(*schemasDir,
			common.root, common.protectedRoot)
		if err != nil {
			fmt.Fprintln(stderr, "calibrate:", err)
			return 1
		}
		if len(findings) != 0 {
			_ = printJSON(stdout, stderr, map[string]any{
				"ok": false, "findings": findings})
			return 1
		}
	}
	status, _ := document["status"].(string)
	if rc := printJSON(stdout, stderr, map[string]any{
		"ok":     status == "OFFLINE_CALIBRATED_PENDING_LIVE_EXECUTION",
		"status": status}); rc != 0 {
		return rc
	}
	if status != "OFFLINE_CALIBRATED_PENDING_LIVE_EXECUTION" {
		return 1
	}
	return 0
}

func tierScenarios(generated *corpora.GeneratedCorpora, tier string) ([]corpora.Scenario, bool) {
	switch tier {
	case "public":
		return generated.Public, true
	case "hidden":
		return generated.Hidden, true
	case "sealed":
		return generated.Sealed, true
	}
	return nil, false
}

func heldOutTier(tier string) bool {
	return tier == "hidden" || tier == "sealed"
}

var useCustodianGeneration = corpora.UseCustodianGeneration

func emitRequestLines(stdout io.Writer, outPath string, lines [][]byte) error {
	output := stdout
	var file *os.File
	if outPath != "" {
		var err error
		file, err = os.Create(outPath)
		if err != nil {
			return err
		}
		output = file
	}
	for _, line := range lines {
		if _, err := fmt.Fprintf(output, "%s\n", line); err != nil {
			if file != nil {
				_ = file.Close()
			}
			return err
		}
	}
	if file != nil {
		return file.Close()
	}
	return nil
}

func runOracleRequests(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("oracle-requests", flag.ContinueOnError)
	flags.SetOutput(stderr)
	common := parseCommon(flags)
	tier := flags.String("tier", "", "corpus tier")
	outPath := flags.String("out", "", "output file (default stdout)")
	wire := flags.Bool("wire", false,
		"emit java-oracle handshake protocol requests (handshake tier only)")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || !common.valid() {
		printUsage(stderr)
		return 2
	}
	if *wire && *tier != "handshake" {
		printUsage(stderr)
		return 2
	}
	generated, err := regenerate(common)
	if err != nil {
		fmt.Fprintln(stderr, "oracle-requests:", err)
		return 1
	}
	var lines [][]byte
	if *tier == "handshake" {
		for _, c := range generated.Handshake {
			project := corpora.HandshakeRequestLine
			if *wire {
				project = corpora.HandshakeOracleRequestLine
			}
			line, err := project(c)
			if err != nil {
				fmt.Fprintln(stderr, "oracle-requests:", err)
				return 1
			}
			lines = append(lines, line)
		}
	} else {
		scenarios, known := tierScenarios(generated, *tier)
		if !known {
			printUsage(stderr)
			return 2
		}
		for _, sc := range scenarios {
			line, err := corpora.OracleRequestLine(sc)
			if err != nil {
				fmt.Fprintln(stderr, "oracle-requests:", err)
				return 1
			}
			lines = append(lines, line)
		}
	}
	if heldOutTier(*tier) {
		var digestInput []byte
		for _, line := range lines {
			digestInput = append(digestInput, line...)
			digestInput = append(digestInput, '\n')
		}
		queryDigest := corpora.DigestSHA256(append([]byte("oracle-requests|"+*tier+"|"),
			digestInput...))
		if err := useCustodianGeneration(common.root, common.protectedRoot, generated,
			func(ledger *corpora.Ledger) error {
				if err := ledger.RecordQuery("tier:"+*tier, queryDigest); err != nil {
					return fmt.Errorf("custodian denied: %w", err)
				}
				return emitRequestLines(stdout, *outPath, lines)
			}); err != nil {
			fmt.Fprintln(stderr, "oracle-requests:", err)
			return 1
		}
		return 0
	}
	if err := emitRequestLines(stdout, *outPath, lines); err != nil {
		fmt.Fprintln(stderr, "oracle-requests:", err)
		return 1
	}
	return 0
}

func runEvaluate(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("evaluate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	common := parseCommon(flags)
	tier := flags.String("tier", "", "corpus tier")
	transcriptPath := flags.String("transcript", "", "JSONL response transcript")
	live := flags.Bool("live", false,
		"score a java-runtime observable transcript (handshake tier only)")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 ||
		!common.valid() || *transcriptPath == "" {
		printUsage(stderr)
		return 2
	}
	if *live && *tier != "handshake" {
		printUsage(stderr)
		return 2
	}
	generated, err := regenerate(common)
	if err != nil {
		fmt.Fprintln(stderr, "evaluate:", err)
		return 1
	}
	if *tier != "handshake" {
		if _, known := tierScenarios(generated, *tier); !known {
			printUsage(stderr)
			return 2
		}
	}
	transcript, err := os.ReadFile(*transcriptPath)
	if err != nil {
		fmt.Fprintln(stderr, "evaluate:", err)
		return 1
	}

	var report corpora.TranscriptReport
	evaluateAndPrint := func(ledger *corpora.Ledger) error {
		if ledger != nil {
			queryDigest := corpora.DigestSHA256(
				append([]byte("evaluate|"+*tier+"|"), transcript...))
			if err := ledger.RecordQuery("tier:"+*tier, queryDigest); err != nil {
				return fmt.Errorf("custodian denied: %w", err)
			}
		}

		var divergences []string
		if *tier == "handshake" {
			if *live {
				// A java-runtime observable transcript is scored against the
				// source-derived Java expectations; RFC-vs-Java divergences are
				// documented in evidence/us005-handshake-live-mapping.json and
				// surfaced in the output rather than silently reconciled away.
				var liveReport corpora.HandshakeLiveReport
				liveReport, err = corpora.EvaluateHandshakeLiveTranscript(
					generated.Handshake, transcript)
				report = liveReport.TranscriptReport
				divergences = liveReport.Divergences
			} else {
				report, err = corpora.EvaluateHandshakeTranscript(generated.Handshake, transcript)
			}
		} else {
			scenarios, _ := tierScenarios(generated, *tier)
			report, err = corpora.EvaluateTranscript(scenarios, transcript)
		}
		if err != nil {
			return err
		}

		// Per-scenario failure details on held-out tiers are diagnostics: they
		// cost one diagnostic-budget unit and are redacted when exhausted.
		output := map[string]any{
			"executed":  report.Executed,
			"passed":    report.Passed,
			"failed":    report.Failed,
			"missing":   report.Missing,
			"unmatched": report.Unmatched,
		}
		if *live {
			output["divergences"] = divergences
		}
		if len(report.Failures) > 0 && ledger != nil {
			diagnosticDigest := corpora.DigestSHA256(
				append([]byte("diagnostics|"+*tier+"|"), transcript...))
			if err := ledger.RecordDiagnostic("tier:"+*tier, diagnosticDigest); err != nil {
				output["diagnostics_redacted"] = true
				output["redaction_reason"] = err.Error()
			} else {
				output["failures"] = report.Failures
			}
		} else if len(report.Failures) > 0 {
			output["failures"] = report.Failures
		}
		if rc := printJSON(stdout, stderr, output); rc != 0 {
			return fmt.Errorf("write evaluation report")
		}
		return nil
	}
	if heldOutTier(*tier) {
		err = useCustodianGeneration(common.root, common.protectedRoot, generated,
			evaluateAndPrint)
	} else {
		err = evaluateAndPrint(nil)
	}
	if err != nil {
		fmt.Fprintln(stderr, "evaluate:", err)
		return 1
	}
	if !report.Reconciled() {
		return 1
	}
	return 0
}

func printJSON(stdout, stderr io.Writer, value any) int {
	rendered, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "%s\n", rendered)
	return 0
}
