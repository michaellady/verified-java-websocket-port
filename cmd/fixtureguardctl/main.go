// fixtureguardctl refuses a count-shaped liveness guard in a Rust test
// fixture.
//
// WHY THIS EXISTS. The same defect has been filed three times against this
// program — F002 (a backpressure fixture sized to a host's socket buffer),
// F004 (`refusals_before_the_drop < 4096`, which failed 2 runs in 5 with the
// crate under test byte-identical), F005 (`polls < POLL_BUDGET`, which failed
// `test-release` with `left: 179 right: 200` under load with no defect
// anywhere). Each was fixed by hand and each cost a red gate. F005's own bin
// note is the finding: "a portable rule that lives only in a findings file
// does not bind anything". This tool is the binding.
//
// WHAT IT CLAIMS. Two mechanical shapes, defined in scan.go, over `loop` and
// `while` in Rust test fixtures. It does NOT claim to detect F002's shape (a
// magnitude assumption about a host resource, which is not a loop guard); see
// drafts/self-review/fixture-liveness-guard-detector.md for the full list of
// errors this rule knowingly makes in both directions.
//
// HONESTY CONTRACT. The tool prints what it actually looked at — files
// scanned, loops examined — and FAILS if either is zero, because a scanner
// that matched nothing and reported PASS is theatre. Before scanning the tree
// it runs a polarity self-check over committed fixtures extracted verbatim
// from git: the pre-fix text of F004's and F005's guards MUST fire and their
// post-fix text MUST NOT. A self-check that does not come out as declared
// fails the gate, so the detector cannot rot into a no-op unnoticed.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	gateName = "fixture-liveness-guard"
	// selfcheckRel holds the polarity fixtures and their declared outcomes.
	selfcheckRel = "cmd/fixtureguardctl/testdata"
	manifestRel  = selfcheckRel + "/polarity.json"
)

type polarityCase struct {
	Path       string `json:"path"`
	Provenance string `json:"provenance"`
	Why        string `json:"why"`
	// Expect is the EXACT set of findings this fixture must produce, each
	// written "line|shape|counter|bound|waived". An empty list means the
	// detector must stay silent. Declaring the rows rather than a count is
	// what makes the removal of any single shape visible: drop shape B and
	// shape A still fires, so a "did anything fire?" check would stay green.
	Expect []string `json:"expect"`
}

func (c polarityCase) mustFire() bool {
	for _, row := range c.Expect {
		if !strings.HasSuffix(row, "|true") {
			return true
		}
	}
	return false
}

type polarityManifest struct {
	Note  string         `json:"note"`
	Cases []polarityCase `json:"cases"`
}

type result struct {
	files      int
	loops      int
	violations []Violation
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("fixtureguardctl", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "repository root")
	maxWaivers := flags.Int("max-waivers", 0, "how many justified count-guard waivers this tree is allowed to carry")
	skipSelfcheck := flags.Bool("no-selfcheck", false, "skip the polarity self-check (for debugging only; the gate never sets it)")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(stderr, "fixtureguardctl: unexpected argument %q\n", flags.Arg(0))
		return 2
	}

	ok := true
	if !*skipSelfcheck {
		if !selfcheck(*root, stdout, stderr) {
			ok = false
		}
	} else {
		fmt.Fprintf(stdout, "gate=%s step=selfcheck result=SKIPPED note=%q\n", gateName,
			"-no-selfcheck was passed: this run makes no claim that the detector still fires on F004 and F005")
	}

	res, err := scanTree(*root)
	if err != nil {
		fmt.Fprintf(stderr, "gate=%s step=scan result=FAIL error=%v\n", gateName, err)
		return 1
	}

	var live, waived []Violation
	for _, v := range res.violations {
		if v.Waived {
			waived = append(waived, v)
		} else {
			live = append(live, v)
		}
	}
	for _, v := range waived {
		fmt.Fprintf(stdout, "gate=%s waiver file=%s line=%d counter=%s bound=%s shape=%s why=%q\n",
			gateName, v.File, v.Line, v.Counter, v.Bound, v.Shape, v.Reason)
	}
	for _, v := range live {
		fmt.Fprintf(stdout, "gate=%s VIOLATION file=%s line=%d shape=%s counter=%s bound=%s loop=%s@%d\n",
			gateName, v.File, v.Line, v.Shape, v.Counter, v.Bound, v.Loop, v.LoopLn)
		fmt.Fprintf(stdout, "    %s\n", v.Text)
		fmt.Fprintf(stdout, "    %s\n", explain(v))
	}

	fmt.Fprintf(stdout, "gate=%s step=scan files=%d loops=%d violations=%d waivers=%d max_waivers=%d\n",
		gateName, res.files, res.loops, len(live), len(waived), *maxWaivers)

	if res.files == 0 || res.loops == 0 {
		fmt.Fprintf(stderr, "gate=%s result=FAIL reason=%q\n", gateName,
			"the scan matched no fixture files or no loops: a detector that looked at nothing is not evidence")
		ok = false
	}
	if len(live) > 0 {
		fmt.Fprintf(stderr, "gate=%s result=FAIL reason=%q\n", gateName,
			fmt.Sprintf("%d count-shaped liveness guard(s) in test fixtures", len(live)))
		ok = false
	}
	if len(waived) > *maxWaivers {
		fmt.Fprintf(stderr, "gate=%s result=FAIL reason=%q\n", gateName,
			fmt.Sprintf("%d waiver(s) present, ceiling is %d: raise -max-waivers in rust/Makefile in the same change, so the pile is visible", len(waived), *maxWaivers))
		ok = false
	}
	if !ok {
		return 1
	}
	fmt.Fprintf(stdout, "gate=%s result=PASS\n", gateName)
	return 0
}

func explain(v Violation) string {
	switch v.Shape {
	case "A":
		return fmt.Sprintf("`%s` is incremented once per iteration and then decides, in the loop header, whether the loop keeps going. "+
			"That is a measurement of how fast this host runs the body, not a bound. Replace it with a generous wall-clock deadline "+
			"(`started.elapsed() < DEADLINE`) and let `%s` appear only in the failure message.", v.Counter, v.Counter)
	case "B1":
		return fmt.Sprintf("`%s` is counted inside this loop and then decides, from inside it, whether to ABORT. "+
			"Reaching the bound is a failure, so the bound is a liveness guard: it says how fast this host is. "+
			"Bound the loop by a generous wall-clock deadline instead; `%s` may REPORT in the failure message, never decide.", v.Counter, v.Counter)
	case "B2":
		return fmt.Sprintf("`%s` is incremented once per iteration and then decides, from inside the loop, whether to break. "+
			"The loop therefore stops after a number of MACHINE operations, and whatever is asserted afterwards is asserted about a truncated run. "+
			"Break on a generous wall-clock deadline instead, and let `%s` only report.", v.Counter, v.Counter)
	}
	return ""
}

// scanTree walks the Rust workspace and applies the rule to every fixture.
func scanTree(root string) (result, error) {
	var res result
	rustRoot := filepath.Join(root, "rust")
	if _, err := os.Stat(rustRoot); err != nil {
		return res, fmt.Errorf("rust workspace not found at %s: %w", rustRoot, err)
	}
	err := filepath.WalkDir(rustRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "target" || d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".rs") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		src := string(data)
		var regions []region
		if !isTestsTreeFile(rel) {
			regions = cfgTestRegions(maskSource(src))
			if len(regions) == 0 {
				return nil
			}
		}
		vs, loops := scanFile(rel, src, regions)
		res.files++
		res.loops += loops
		res.violations = append(res.violations, vs...)
		return nil
	})
	sort.Slice(res.violations, func(i, j int) bool {
		if res.violations[i].File != res.violations[j].File {
			return res.violations[i].File < res.violations[j].File
		}
		return res.violations[i].Line < res.violations[j].Line
	})
	return res, err
}

// isTestsTreeFile reports whether the path is inside a crate's tests/
// directory, where the whole file is fixture code.
func isTestsTreeFile(rel string) bool {
	for _, part := range strings.Split(rel, "/") {
		if part == "tests" {
			return true
		}
	}
	return false
}

// selfcheck runs the detector over committed fixtures whose expected polarity
// is declared, and reports whether every case came out as declared. The
// pre-fix text of F004 and F005 is in there verbatim from git: if the rule
// ever stops firing on the three instances that motivated it, this fails.
func selfcheck(root string, stdout, stderr io.Writer) bool {
	manifestPath := filepath.Join(root, filepath.FromSlash(manifestRel))
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		fmt.Fprintf(stderr, "gate=%s step=selfcheck result=FAIL error=%q\n", gateName,
			fmt.Sprintf("polarity manifest unreadable at %s: %v", manifestRel, err))
		return false
	}
	var manifest polarityManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		fmt.Fprintf(stderr, "gate=%s step=selfcheck result=FAIL error=%q\n", gateName,
			fmt.Sprintf("polarity manifest is not valid JSON: %v", err))
		return false
	}
	if len(manifest.Cases) == 0 {
		fmt.Fprintf(stderr, "gate=%s step=selfcheck result=FAIL error=%q\n", gateName,
			"the polarity manifest declares no cases: an empty self-check proves nothing")
		return false
	}
	firing, silent := 0, 0
	ok := true
	for _, c := range manifest.Cases {
		p := filepath.Join(root, filepath.FromSlash(selfcheckRel), filepath.FromSlash(c.Path))
		src, err := os.ReadFile(p)
		if err != nil {
			fmt.Fprintf(stderr, "gate=%s step=selfcheck case=%s result=FAIL error=%q\n", gateName, c.Path, err.Error())
			ok = false
			continue
		}
		var regions []region
		if !isTestsTreeFile(c.Path) && strings.Contains(string(src), "#[cfg(test)]") {
			regions = cfgTestRegions(maskSource(string(src)))
		}
		vs, loops := scanFile(c.Path, string(src), regions)
		if c.mustFire() {
			firing++
		} else {
			silent++
		}
		verdict := "OK"
		if diff := rowDiff(Rows(vs), c.Expect); diff != "" {
			verdict = "POLARITY-FAIL"
			ok = false
			fmt.Fprintf(stderr, "gate=%s step=selfcheck case=%s POLARITY-FAIL %s\n", gateName, c.Path, diff)
		}
		fmt.Fprintf(stdout, "gate=%s step=selfcheck case=%s expect=%d found=%d loops=%d result=%s provenance=%q\n",
			gateName, c.Path, len(c.Expect), len(vs), loops, verdict, c.Provenance)
		// Print WHAT fired, so the gate log is itself the historical proof
		// rather than a bare count that could come from anywhere in the file.
		for _, v := range vs {
			state := "fires"
			if v.Waived {
				state = "waived"
			}
			fmt.Fprintf(stdout, "    %s line=%d shape=%s counter=%s bound=%s loop=%s@%d | %s\n",
				state, v.Line, v.Shape, v.Counter, v.Bound, v.Loop, v.LoopLn, v.Text)
		}
	}
	if firing == 0 || silent == 0 {
		fmt.Fprintf(stderr, "gate=%s step=selfcheck result=FAIL error=%q\n", gateName,
			fmt.Sprintf("the self-check needs both polarities to mean anything: %d firing case(s), %d silent case(s)", firing, silent))
		ok = false
	}
	verdict := "PASS"
	if !ok {
		verdict = "FAIL"
	}
	fmt.Fprintf(stdout, "gate=%s step=selfcheck cases=%d firing=%d silent=%d result=%s\n",
		gateName, len(manifest.Cases), firing, silent, verdict)
	return ok
}

// rowDiff compares an observed finding set against the declared one and
// returns "" when they are identical.
func rowDiff(got, want []string) string {
	if want == nil {
		want = []string{}
	}
	if len(got) == len(want) {
		same := true
		for i := range got {
			if got[i] != want[i] {
				same = false
				break
			}
		}
		if same {
			return ""
		}
	}
	return fmt.Sprintf("declared %v, observed %v", want, got)
}
