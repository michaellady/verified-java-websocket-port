// Command ac5ctl executes the US-020 AC5 class register
// (internal/ac5class): it applies every seeded class variant to an isolated
// scratch copy of the rust/ workspace, runs the named evidence that must
// detect it, MEASURES which normalized differential observation fields the
// variant moves, and compares all of that against what the register declares.
//
// Two subcommands, deliberately of very different cost:
//
//	ac5ctl verify -root DIR
//	    The static half. No cargo, no Java, no network, seconds. Fails when a
//	    US-020 AC5 class loses its seeded variant, when a variant's site has
//	    drifted out of the shipped tree, when a variant stops discriminating
//	    without registering the collision, or when a detector is named by
//	    suite instead of by test.
//
//	ac5ctl run -root DIR [-workdir DIR] [-requests FILE ...]
//	           [-receipt-out FILE] [-only id[,id...]] [-skip-witness]
//	    The executed half. Every external command's exit code is read from
//	    its real ProcessState and recorded; the pristine scratch must be
//	    green before any variant runs; each variant must be killed by the
//	    NAMED test the register declares (a nonzero exit whose failing set
//	    does not contain that name is reported as an unrelated kill, not a
//	    detection); and each variant's measured field set must equal the
//	    declared one exactly.
//
// WHAT `run` COMPARES, AND WHY IT NEEDS NO JAVA. The register's field paths
// are expressed in the differential's own observation vocabulary and computed
// with the differential's own comparator (internal/diffregress), but the two
// arms compared here are the PRISTINE port and the MUTATED port rather than
// Java and the port. That is exact, not an approximation: the pristine port
// and the live pinned Java oracle agree on every behavioural field of all 74
// public and 23 probe cases (recorded in
// evidence/ac5-class-completeness/receipt.json from a real run of
// Java-WebSocket 1.6.0), so a field moves against Java exactly when it moves
// against the pristine port. Dropping the Java arm from the GATE keeps it
// runnable without the pinned jar; the Java arm stays as the recorded
// evidence that the vocabulary being measured is the differential's.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/michaellady/verified-java-websocket-port/internal/ac5class"
	"github.com/michaellady/verified-java-websocket-port/internal/diffregress"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "run":
		return runCampaign(args[1:], stdout, stderr)
	default:
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage:")
	fmt.Fprintln(w, "  ac5ctl verify -root DIR")
	fmt.Fprintln(w, "  ac5ctl run -root DIR [-workdir DIR] [-requests FILE ...]")
	fmt.Fprintln(w, "             [-receipt-out FILE] [-only id[,id...]] [-skip-witness]")
}

func runVerify(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", "", "repository root")
	if err := flags.Parse(args); err != nil || *root == "" {
		usage(stderr)
		return 2
	}
	classes, err := ac5class.ClassesFromPRD(*root)
	if err != nil {
		fmt.Fprintln(stderr, "verify:", err)
		return 1
	}
	problems := ac5class.Verify(*root)
	for _, p := range problems {
		fmt.Fprintln(stderr, "verify: US-020 AC5 class register:", p)
	}
	if len(problems) > 0 {
		return 1
	}
	fmt.Fprintf(stdout, "ac5ctl: %d US-020 AC5 classes from %s, %d seeded variants, every site resolved\n",
		len(classes), ac5class.PRDPath, len(ac5class.Register()))
	for _, v := range ac5class.Register() {
		line, _ := ac5class.ResolveSite(*root, v)
		kind := "discriminates " + strings.Join(v.Discriminates, " ")
		if v.Collision != nil {
			kind = "COLLISION " + v.Collision.DivergenceID
		}
		fmt.Fprintf(stdout, "  %-24s %-38s %s:%d  %s\n", v.Class, v.ID, v.File, line, kind)
	}
	return 0
}

// stringList collects a repeatable flag.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// VariantResult is one register row's executed reading.
type VariantResult struct {
	Class    string `json:"class"`
	ID       string `json:"id"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Operator string `json:"operator"`
	// DetectorCmd is the exact command run, DetectorExit its real exit code.
	DetectorCmd     string   `json:"detector_cmd"`
	DetectorExit    int      `json:"detector_exit"`
	DetectorFailed  []string `json:"detector_failed_tests,omitempty"`
	DetectorDetail  string   `json:"detector_kill_detail,omitempty"`
	NamedTestFailed bool     `json:"named_test_failed"`
	// HarnessExit is the mutated harness process exit; MeasuredFields is the
	// set of normalized observation field paths that moved against the
	// pristine arm, with array indices collapsed.
	HarnessBuildExit int      `json:"harness_build_exit"`
	HarnessExit      int      `json:"harness_exit"`
	MeasuredFields   []string `json:"measured_fields"`
	DeclaredFields   []string `json:"declared_fields"`
	FieldsAgree      bool     `json:"fields_agree"`
	// Collision-only readings.
	IsCollision        bool     `json:"is_collision"`
	WitnessCmd         string   `json:"witness_cmd,omitempty"`
	WitnessPristine    *int     `json:"witness_exit_pristine,omitempty"`
	WitnessMutated     *int     `json:"witness_exit_mutated,omitempty"`
	WitnessFailed      []string `json:"witness_failed_tests,omitempty"`
	BlindJudgeWsCore   *int     `json:"blind_judge_ws_core_exit,omitempty"`
	CollisionConfirmed bool     `json:"collision_confirmed,omitempty"`
	Verdict            string   `json:"verdict"`
	Problems           []string `json:"problems,omitempty"`
	Seconds            float64  `json:"seconds"`
}

func runCampaign(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", "", "repository root")
	workdir := flags.String("workdir", "", "campaign workdir (default: a fresh temp dir)")
	receiptOut := flags.String("receipt-out", "", "write the receipt JSON here")
	only := flags.String("only", "", "comma-separated variant ids")
	skipWitness := flags.Bool("skip-witness", false,
		"skip the real-socket out-of-band witness (its readings are then absent, never assumed)")
	var requests stringList
	flags.Var(&requests, "requests", "an oracle request JSONL stream (repeatable)")
	if err := flags.Parse(args); err != nil || *root == "" {
		usage(stderr)
		return 2
	}
	absRoot, err := filepath.Abs(*root)
	if err != nil {
		fmt.Fprintln(stderr, "run:", err)
		return 1
	}
	if len(requests) == 0 {
		requests = stringList{filepath.Join(absRoot, "evidence/differential-regression/probes.jsonl")}
	}
	if problems := ac5class.Verify(absRoot); len(problems) > 0 {
		for _, p := range problems {
			fmt.Fprintln(stderr, "run: register refused before any process ran:", p)
		}
		return 1
	}
	if *workdir == "" {
		dir, err := os.MkdirTemp("", "ac5ctl-")
		if err != nil {
			fmt.Fprintln(stderr, "run:", err)
			return 1
		}
		*workdir = dir
	}
	absWork, err := filepath.Abs(*workdir)
	if err != nil {
		fmt.Fprintln(stderr, "run:", err)
		return 1
	}
	if err := verifyWorkdirOutsideRepo(absWork, absRoot); err != nil {
		fmt.Fprintln(stderr, "run: repository isolation refused:", err)
		return 2
	}
	scratchParent := filepath.Join(absWork, "scratch")
	scratchRust := filepath.Join(scratchParent, "rust")
	if err := requireFreshScratch(scratchParent); err != nil {
		fmt.Fprintln(stderr, "run:", err)
		return 2
	}
	repoRust := filepath.Join(absRoot, "rust")
	judged, err := treeDigest(repoRust)
	if err != nil {
		fmt.Fprintln(stderr, "run: digesting rust/:", err)
		return 1
	}
	fmt.Fprintln(stdout, "ac5ctl: copying rust/ into a fresh scratch...")
	if err := copyTree(repoRust, scratchRust); err != nil {
		fmt.Fprintln(stderr, "run: scratch copy:", err)
		return 1
	}
	if err := verifyWorkdirOutsideRepo(scratchRust, absRoot); err != nil {
		fmt.Fprintln(stderr, "run: scratch isolation refused after creation:", err)
		return 2
	}
	scratchDigest, err := treeDigest(scratchRust)
	if err != nil {
		fmt.Fprintln(stderr, "run: digesting the scratch:", err)
		return 1
	}
	if scratchDigest != judged {
		fmt.Fprintf(stderr, "run: scratch digest %s != rust/ digest %s\n", scratchDigest, judged)
		return 2
	}

	register := ac5class.Register()
	if *only != "" {
		keep := map[string]bool{}
		for _, id := range strings.Split(*only, ",") {
			keep[strings.TrimSpace(id)] = true
		}
		var filtered []ac5class.Variant
		for _, v := range register {
			if keep[v.ID] {
				filtered = append(filtered, v)
			}
		}
		register = filtered
		// A filter that selects nothing must not produce a green receipt over
		// zero variants; that is the same "vacuously passed" shape this whole
		// register exists to refuse.
		if len(register) == 0 {
			fmt.Fprintf(stderr, "run: -only %q selected no registered variant\n", *only)
			return 2
		}
	}

	// Merge every request stream into one, so a variant's observation is
	// measured over exactly the same input on the pristine and mutated arms.
	requestPath := filepath.Join(absWork, "requests.jsonl")
	requestDigests := map[string]string{}
	var merged bytes.Buffer
	for _, r := range requests {
		raw, err := os.ReadFile(r)
		if err != nil {
			fmt.Fprintln(stderr, "run:", err)
			return 1
		}
		sum := sha256.Sum256(raw)
		requestDigests[filepath.Base(r)] = "sha256:" + hex.EncodeToString(sum[:])
		merged.Write(bytes.TrimRight(raw, "\n"))
		merged.WriteByte('\n')
	}
	if err := os.WriteFile(requestPath, merged.Bytes(), 0o644); err != nil {
		fmt.Fprintln(stderr, "run:", err)
		return 1
	}
	requestCount := bytes.Count(merged.Bytes(), []byte("\n"))

	// GREEN polarity: the pristine scratch must pass judge 1 and produce a
	// transcript before any variant is applied.
	fmt.Fprintln(stdout, "ac5ctl: baseline judge (cargo test -p ws-core, pristine scratch)...")
	baseTestExit, baseOut, err := command(scratchRust, nil, "cargo", "test", "-p", "ws-core")
	if err != nil || baseTestExit != 0 {
		fmt.Fprintf(stderr, "run: pristine cargo test exit=%d err=%v\n%s",
			baseTestExit, err, tail(baseOut, 2000))
		return 1
	}
	baseBuildExit, baseHarnessExit, pristineTranscript, err :=
		harnessRun(scratchRust, merged.Bytes(), filepath.Join(absWork, "pristine-transcript.jsonl"))
	if err != nil || baseBuildExit != 0 || baseHarnessExit != 0 {
		fmt.Fprintf(stderr, "run: pristine harness build_exit=%d exit=%d err=%v\n",
			baseBuildExit, baseHarnessExit, err)
		return 1
	}
	fmt.Fprintf(stdout, "ac5ctl: baseline green — tests exit 0, harness exit 0, %d requests\n",
		requestCount)

	var results []VariantResult
	problems := 0
	for _, v := range register {
		started := time.Now()
		line, err := ac5class.ResolveSite(absRoot, v)
		if err != nil {
			fmt.Fprintf(stderr, "run: %s: %v\n", v.ID, err)
			return 1
		}
		result := VariantResult{
			Class: v.Class, ID: v.ID, File: v.File, Line: line, Operator: v.Operator,
			DeclaredFields: v.Discriminates, IsCollision: v.Collision != nil,
		}
		// The collision witness's GREEN reading is taken BEFORE the seed is
		// applied: a witness that already fails proves nothing.
		if v.Collision != nil && !*skipWitness {
			cmd := cargoArgs(v.Collision.Witness)
			exit, out, err := command(scratchRust, nil, "cargo", cmd...)
			if err != nil {
				fmt.Fprintf(stderr, "run: %s witness (pristine): %v\n", v.ID, err)
				return 1
			}
			result.WitnessCmd = "cargo " + strings.Join(cmd, " ")
			result.WitnessPristine = &exit
			if exit != 0 {
				result.Problems = append(result.Problems, fmt.Sprintf(
					"the out-of-band witness already fails on the PRISTINE tree (exit %d): it cannot "+
						"witness anything about the seed", exit))
			}
			_ = out
		}

		pristineBytes, err := applyVariant(scratchRust, v)
		if err != nil {
			fmt.Fprintf(stderr, "run: %s apply: %v\n", v.ID, err)
			return 1
		}
		// The detector: the named test must be among the failures.
		cmd := cargoArgs(v.Detector)
		exit, out, err := command(scratchRust, nil, "cargo", cmd...)
		if err != nil {
			restoreVariant(scratchRust, v, pristineBytes, stderr)
			fmt.Fprintf(stderr, "run: %s detector: %v\n", v.ID, err)
			return 1
		}
		result.DetectorCmd = "cargo " + strings.Join(cmd, " ")
		result.DetectorExit = exit
		result.DetectorFailed = failedTests(out)
		result.DetectorDetail = killDetail(out)
		result.NamedTestFailed = contains(result.DetectorFailed, v.Detector.MustFail)
		if exit == 0 {
			result.Problems = append(result.Problems,
				"the detector exited 0: nothing detects this seeded class")
		} else if !result.NamedTestFailed {
			result.Problems = append(result.Problems, fmt.Sprintf(
				"the detector exited %d but %q is not among the failures %v: an unrelated kill is "+
					"existence, not identity", exit, v.Detector.MustFail, result.DetectorFailed))
		}
		// The measured observation.
		buildExit, harnessExit, mutatedTranscript, err := harnessRun(
			scratchRust, merged.Bytes(), filepath.Join(absWork, "transcript-"+v.ID+".jsonl"))
		result.HarnessBuildExit = buildExit
		result.HarnessExit = harnessExit
		if err != nil || buildExit != 0 {
			result.Problems = append(result.Problems, fmt.Sprintf(
				"harness build_exit=%d harness_exit=%d err=%v", buildExit, harnessExit, err))
		} else {
			fields, cmpErr := measureFields(pristineTranscript, mutatedTranscript)
			if cmpErr != nil {
				result.Problems = append(result.Problems, "comparing transcripts: "+cmpErr.Error())
			} else {
				result.MeasuredFields = fields
				result.FieldsAgree = equalSets(fields, v.Discriminates)
				if !result.FieldsAgree {
					result.Problems = append(result.Problems, fmt.Sprintf(
						"the register declares the differential moves %v and it measured %v",
						v.Discriminates, fields))
				}
			}
		}
		// The collision's second half.
		if v.Collision != nil {
			if *skipWitness {
				// The flag makes the run cheaper; it must never make the
				// receipt greener. A collision with no witness reading is
				// indistinguishable from an equivalent mutant, so it is
				// reported as unconfirmed and the run does not pass.
				result.Problems = append(result.Problems,
					"-skip-witness was set: the out-of-band witness that proves the two behaviours "+
						"actually differ was not run, so this collision is UNCONFIRMED")
			}
			if !*skipWitness {
				wcmd := cargoArgs(v.Collision.Witness)
				wexit, wout, werr := command(scratchRust, nil, "cargo", wcmd...)
				if werr != nil {
					restoreVariant(scratchRust, v, pristineBytes, stderr)
					fmt.Fprintf(stderr, "run: %s witness (mutated): %v\n", v.ID, werr)
					return 1
				}
				result.WitnessMutated = &wexit
				result.WitnessFailed = failedTests(wout)
				if wexit == 0 {
					result.Problems = append(result.Problems,
						"the out-of-band witness PASSES with the seed applied: the two behaviours are "+
							"not different, so this is an equivalent mutant and not a collision")
				} else if !contains(result.WitnessFailed, v.Collision.Witness.MustFail) {
					result.Problems = append(result.Problems, fmt.Sprintf(
						"the witness failed but %q is not among %v",
						v.Collision.Witness.MustFail, result.WitnessFailed))
				}
			}
			// The blindness half, read rather than asserted: ws-core must
			// stay green under a seed the ws-core judges cannot see.
			if v.Detector.Package != "ws-core" {
				bexit, _, berr := command(scratchRust, nil, "cargo", "test", "-p", "ws-core")
				if berr != nil {
					restoreVariant(scratchRust, v, pristineBytes, stderr)
					fmt.Fprintf(stderr, "run: %s blind-judge: %v\n", v.ID, berr)
					return 1
				}
				result.BlindJudgeWsCore = &bexit
				if bexit != 0 {
					result.Problems = append(result.Problems, fmt.Sprintf(
						"the registered blind judge `cargo test -p ws-core` FIRED (exit %d): the "+
							"collision record is stale", bexit))
				}
			}
			result.CollisionConfirmed = len(result.Problems) == 0
		}
		restoreVariant(scratchRust, v, pristineBytes, stderr)
		result.Seconds = time.Since(started).Seconds()
		switch {
		case len(result.Problems) > 0 && v.Collision != nil && *skipWitness:
			result.Verdict = "COLLISION_UNCONFIRMED"
			problems++
		case len(result.Problems) > 0:
			result.Verdict = "REGISTER_STALE"
			problems++
		case v.Collision != nil:
			result.Verdict = "COLLISION_DETECTED"
		default:
			result.Verdict = "CLASS_DETECTED"
		}
		results = append(results, result)
		fmt.Fprintf(stdout, "ac5ctl: %-24s %-38s %-20s detector_exit=%d (%.1fs)\n",
			result.Class, result.ID, result.Verdict, result.DetectorExit, result.Seconds)
		for _, p := range result.Problems {
			fmt.Fprintln(stderr, "  problem:", p)
		}
	}

	// The scratch must digest back to the tree it started as.
	finalDigest, err := treeDigest(scratchRust)
	if err != nil {
		fmt.Fprintln(stderr, "run: post-campaign digest:", err)
		return 1
	}
	if finalDigest != judged {
		fmt.Fprintf(stderr, "run: post-campaign digest %s != %s: a variant was not restored\n",
			finalDigest, judged)
		return 1
	}
	postExit, _, err := command(scratchRust, nil, "cargo", "test", "-p", "ws-core")
	if err != nil || postExit != 0 {
		fmt.Fprintf(stderr, "run: post-campaign pristine verification exit=%d err=%v\n", postExit, err)
		return 1
	}

	receipt := map[string]any{
		"schema_version": "1.0.0",
		"kind":           "us020-ac5-class-completeness-receipt",
		"generated_at":   time.Now().UTC().Format(time.RFC3339),
		"prd_clause_source": ac5class.PRDPath +
			" (US-020 AC5, parsed — never retyped)",
		"classes_from_prd": mustClasses(absRoot),
		"judged_tree_digest": map[string]any{
			"rust":                     judged,
			"algorithm":                "sha256 over sorted (relative path, length, bytes) of rust/, excluding target/; symlinks refused",
			"scratch_created_fresh":    true,
			"scratch_identical":        scratchDigest == judged,
			"post_campaign_digest":     finalDigest,
			"post_campaign_restored":   finalDigest == judged,
			"post_campaign_tests_exit": postExit,
		},
		"requests": map[string]any{
			"streams": requestDigests,
			"count":   requestCount,
		},
		"baseline": map[string]any{
			"ws_core_test_exit":  baseTestExit,
			"harness_build_exit": baseBuildExit,
			"harness_exit":       baseHarnessExit,
		},
		"exit_discipline":        "every exit code in this receipt was read from the command's real ProcessState; none is inferred from output text",
		"witness_skipped":        *skipWitness,
		"variants":               results,
		"rejected_bindings":      ac5class.RejectedBindings(),
		"rejected_bindings_note": "operators this repository could have claimed for a class and which MEASUREMENT says do not discriminate it",
	}
	rendered, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, "run:", err)
		return 1
	}
	rendered = append(rendered, '\n')
	if *receiptOut != "" {
		if err := os.WriteFile(*receiptOut, rendered, 0o644); err != nil {
			fmt.Fprintln(stderr, "run:", err)
			return 1
		}
		fmt.Fprintf(stdout, "ac5ctl: receipt written to %s\n", *receiptOut)
	} else {
		fmt.Fprintf(stdout, "%s", rendered)
	}
	if problems > 0 {
		fmt.Fprintf(stderr, "ac5ctl: %d of %d registered variants disagree with the register\n",
			problems, len(results))
		return 3
	}
	fmt.Fprintf(stdout, "ac5ctl: %d registered variants, every class detected by its named evidence\n",
		len(results))
	return 0
}

func mustClasses(root string) []string {
	classes, err := ac5class.ClassesFromPRD(root)
	if err != nil {
		return []string{"UNREADABLE: " + err.Error()}
	}
	return classes
}

func cargoArgs(d ac5class.Detector) []string {
	args := []string{"test", "-p", d.Package}
	args = append(args, d.Args...)
	return args
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func equalSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

var indexPattern = regexp.MustCompile(`\[\d+\]`)

// measureFields compares two transcripts with the differential's own
// comparator and returns the sorted set of moved field paths, with array
// indices collapsed so the set is a shape rather than a case count.
func measureFields(pristine, mutated string) ([]string, error) {
	left, order, err := diffregress.LoadTranscript(pristine)
	if err != nil {
		return nil, err
	}
	right, _, err := diffregress.LoadTranscript(mutated)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, id := range order {
		a, ok := left[id]
		if !ok {
			continue
		}
		b, ok := right[id]
		if !ok {
			seen["<response missing from the mutated arm>"] = true
			continue
		}
		for _, p := range diffregress.CompareResponses(a, b).DiffPaths {
			seen[indexPattern.ReplaceAllString(p, "[]")] = true
		}
	}
	fields := make([]string, 0, len(seen))
	for f := range seen {
		fields = append(fields, f)
	}
	sort.Strings(fields)
	return fields, nil
}

// harnessRun builds the scratch harness, replays the requests through it and
// records the transcript, returning both real exit codes.
func harnessRun(scratchRust string, requests []byte, transcriptPath string) (int, int, string, error) {
	buildExit, buildOut, err := command(scratchRust, nil, "cargo", "build", "-p", "ws-oracle-harness")
	if err != nil || buildExit != 0 {
		return buildExit, -1, "", fmt.Errorf("harness build exit=%d err=%v: %s",
			buildExit, err, tail(buildOut, 1200))
	}
	harness := filepath.Join(scratchRust, "target", "debug", "ws-oracle-harness")
	harnessExit, transcript, err := command(scratchRust, requests, harness)
	if err != nil {
		return buildExit, -1, "", fmt.Errorf("harness run: %w", err)
	}
	if err := os.WriteFile(transcriptPath, []byte(transcript), 0o644); err != nil {
		return buildExit, harnessExit, "", err
	}
	return buildExit, harnessExit, transcriptPath, nil
}

func applyVariant(scratchRust string, v ac5class.Variant) ([]byte, error) {
	path := filepath.Join(scratchRust, strings.TrimPrefix(v.File, "rust/"))
	pristine, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	offset, err := ac5class.OccurrenceOffset(string(pristine), v.Match, v.Occurrence)
	if err != nil {
		return nil, err
	}
	mutated := string(pristine[:offset]) + v.Replace + string(pristine[offset+len(v.Match):])
	if err := os.WriteFile(path, []byte(mutated), 0o644); err != nil {
		return nil, err
	}
	return pristine, nil
}

func restoreVariant(scratchRust string, v ac5class.Variant, pristine []byte, stderr io.Writer) {
	path := filepath.Join(scratchRust, strings.TrimPrefix(v.File, "rust/"))
	if err := os.WriteFile(path, pristine, 0o644); err != nil {
		fmt.Fprintf(stderr, "run: FATAL restore failure for %s: %v\n", v.ID, err)
		os.Exit(1)
	}
}

var failedTestPattern = regexp.MustCompile(`(?m)^test (\S+) \.\.\. FAILED$`)
var assertionPattern = regexp.MustCompile(`panicked at ([^\n]*\.rs:\d+:\d+):\n([^\n]*)`)

func failedTests(output string) []string {
	var names []string
	seen := map[string]bool{}
	for _, m := range failedTestPattern.FindAllStringSubmatch(output, -1) {
		if seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		names = append(names, m[1])
	}
	return names
}

func killDetail(output string) string {
	matches := assertionPattern.FindAllStringSubmatch(output, -1)
	if len(matches) == 0 {
		return ""
	}
	for _, m := range matches {
		if strings.Contains(m[1], "tests/") {
			return strings.TrimSpace(m[1]) + ": " + strings.TrimSpace(m[2])
		}
	}
	return strings.TrimSpace(matches[0][1]) + ": " + strings.TrimSpace(matches[0][2])
}

// command runs one external command, capturing combined output and the
// verbatim exit code read from the real ProcessState.
func command(dir string, stdin []byte, name string, args ...string) (int, string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err == nil {
		return 0, out.String(), nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode(), out.String(), nil
	}
	return -1, out.String(), err
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}

// ---- isolation helpers (same discipline as cmd/mutctl) ---------------------

func resolvePath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	remainder := ""
	current := abs
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			if remainder == "" {
				return resolved, nil
			}
			return filepath.Join(resolved, remainder), nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return abs, nil
		}
		remainder = filepath.Join(filepath.Base(current), remainder)
		current = parent
	}
}

func pathContains(outer, inner string) bool {
	rel, err := filepath.Rel(outer, inner)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func verifyWorkdirOutsideRepo(workdir, root string) error {
	resolvedWork, err := resolvePath(workdir)
	if err != nil {
		return fmt.Errorf("resolving workdir %q: %w", workdir, err)
	}
	resolvedRoot, err := resolvePath(root)
	if err != nil {
		return fmt.Errorf("resolving repository root %q: %w", root, err)
	}
	if pathContains(resolvedRoot, resolvedWork) {
		return fmt.Errorf("workdir %q resolves to %q, INSIDE the repository %q (resolved %q)",
			workdir, resolvedWork, root, resolvedRoot)
	}
	if pathContains(resolvedWork, resolvedRoot) {
		return fmt.Errorf("workdir %q resolves to %q, which CONTAINS the repository %q (resolved %q)",
			workdir, resolvedWork, root, resolvedRoot)
	}
	return nil
}

func requireFreshScratch(scratchParent string) error {
	info, err := os.Lstat(scratchParent)
	if err == nil {
		kind := "directory"
		if info.Mode()&os.ModeSymlink != 0 {
			kind = "symlink"
		}
		return fmt.Errorf("scratch %s already exists at %q: refusing to reuse it", kind, scratchParent)
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("checking scratch path %q: %w", scratchParent, err)
	}
	return nil
}

func treeDigest(root string) (string, error) {
	type entry struct {
		rel  string
		data []byte
	}
	var entries []entry
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "target" {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink in judged tree at %q: refusing to digest", rel)
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("non-regular file in judged tree at %q: refusing to digest", rel)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		entries = append(entries, entry{rel: filepath.ToSlash(rel), data: data})
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })
	sum := sha256.New()
	for _, e := range entries {
		fmt.Fprintf(sum, "%s\x00%d\x00", e.rel, len(e.data))
		sum.Write(e.data)
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "target" {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), data, 0o644)
	})
}
