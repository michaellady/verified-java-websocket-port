// Command gosuitectl runs the Go test suite as a GATE, with its exclusions
// declared rather than implied.
//
// `make -C rust gates` exited 0 all day on 2026-09-03 while
// `internal/deltaledger` was failing three subtests, two of them the governance
// gate ACCEPTING a document it exists to refuse. The gates chain simply does not
// run the Go packages, and "gates green" was read as "the tree is good" -- by me,
// repeatedly. A chain that does not cover something must say so where it is read,
// not in a file someone might consult.
//
// One package genuinely cannot pass on this host. It is named here with the
// reason, and the reason is CHECKED: an exclusion naming a package that no longer
// exists fails the gate, so the list cannot quietly outlive the problem it
// describes. Everything not excluded is run; a package added tomorrow is covered
// without anyone remembering to add it.
//
// It was two until `internal/portplan` was FIXED rather than re-excused. Its
// exclusion said the reproduction check byte-compared a regenerated semantic-id
// oracle against a committed one recording jdk_vendor "Homebrew", and that a
// Linux Temurin regeneration differed in that ONE line with all 969 declarations
// identical. The owner ruled the check vendor-agnostic; the comparison now
// excludes that single field by name and the package passes here, so the
// exclusion went with it. That is the only way an entry leaves this list: the
// EXCLUSION_NO_LONGER_FAILS finding exists so a fixed package cannot keep its
// exemption.
//
//	gosuitectl -root . [-timeout 40m]
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/michaellady/verified-java-websocket-port/internal/portplan"
)

// excluded is the complete set of packages this gate does not run, each with the
// reason it cannot pass on this host. Adding an entry is a decision someone has
// to defend in review; it is not a place to park a failure.
var excluded = map[string]string{
	"internal/lab": "CONTROLLED_CANARY requires Darwin sandbox-exec; " +
		"PLATFORM_EXECUTOR_UNSUPPORTED on Linux. Owner gate: a macOS host.",
}

func main() {
	root := flag.String("root", ".", "repository root")
	timeout := flag.String("timeout", "40m", "go test -timeout value")
	flag.Parse()

	// A PRECONDITION, refused by name rather than worked around -- the same
	// shape ledger-gates already uses for VJWP_PROTECTED_STORE. `.quarantine/`
	// is gitignored, so it exists only in the checkout that populated it, and a
	// fresh `git worktree` has none. Without it internal/formalplan and
	// internal/portplan fail citing the archive as HTTP 403, which reads exactly
	// like the proxy refusal and is not it. Two agents reported that as a third
	// environmental failure before anyone noticed the tree was simply not staged.
	// Refusing here costs one command; guessing costs a wrong baseline.
	if info, err := os.Stat(filepath.Join(*root, ".quarantine",
		"Java-WebSocket-1.6.0.jar")); err != nil || info.Size() == 0 {
		fmt.Printf("gate=go-suite result=REFUSED reason=%q remedy=%q\n",
			".quarantine/ is not staged in this tree, so the packages that consume the "+
				"pinned Java source cannot be told apart from ones that are genuinely "+
				"broken. This is a refusal, not a failure, and not a skip.",
			"ln -s /home/user/verified-java-websocket-port/.quarantine "+*root+"/.quarantine")
		os.Exit(2)
	}

	// The SECOND precondition, and it was missing while the first was enforced.
	// `internal/portplan` pins javac 17.0.19 and this container's default javac is
	// 21.0.10, so with the pinned JDK off PATH the package fails
	// JAVAC_UNAVAILABLE -- which reads as a broken pin or a version regression and
	// is neither. The comment further down this file already recorded that shape;
	// recording it was not enough, because the failure still arrives as a red
	// package at the bottom of a 250-line log. It cost a full diagnosis cycle on
	// 2026-09-04, and the asymmetry was the giveaway: ledger-gates REFUSES by name
	// when VJWP_PROTECTED_STORE is unset, while this one let a missing PATH look
	// like a regression. So it refuses too, and names the export.
	if javac, err := exec.LookPath("javac"); err != nil {
		refuseJavac("no javac on PATH at all", *root)
	} else if out, err := exec.Command(javac, "-version").CombinedOutput(); err != nil {
		refuseJavac("javac -version failed: "+err.Error(), *root)
	} else if !strings.Contains(string(out), portplan.PinnedJavacVersion) {
		refuseJavac(fmt.Sprintf("javac on PATH is %q, and internal/portplan pins %s",
			firstLine(string(out)), portplan.PinnedJavacVersion), *root)
	}

	packages, err := listPackages(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gosuitectl: %v\n", err)
		os.Exit(2)
	}

	present := make(map[string]bool, len(packages))
	for _, name := range packages {
		present[name] = true
	}

	// A stale exclusion is a lie about coverage, so it fails the gate.
	var stale []string
	for name := range excluded {
		if !present[name] {
			stale = append(stale, name)
		}
	}
	sort.Strings(stale)
	for _, name := range stale {
		fmt.Printf("gate=go-suite finding=STALE_EXCLUSION package=%s "+
			"detail=\"excluded but no longer in the module; the exclusion outlived "+
			"the package and must be removed\"\n", name)
	}

	var run []string
	for _, name := range packages {
		if _, skip := excluded[name]; !skip {
			run = append(run, name)
		}
	}

	// AN EXCLUSION IS A CLAIM THAT THE PACKAGE CANNOT PASS HERE, SO THE CLAIM IS
	// RUN. Checking only that the package still EXISTS is the weaker half: the
	// list can outlive the PROBLEM as easily as it outlives the package, and
	// adversarial review B5 added an exclusion for `internal/rfcneutral`, which
	// passes cleanly, with a reason clearing the 80-byte floor and containing
	// "Owner" -- every check this gate had accepted it, `go test
	// ./cmd/gosuitectl/` exited 0, and a passing package was removed from
	// coverage with a fabricated reason. Its sibling gate already refuses this
	// shape: pinconsumerctl fails a FIXED pin as STALE_ALLOWANCE. This is the
	// same refusal.
	//
	// The observed first failing line is PRINTED beside the declared reason so a
	// reader can see whether they still describe the same thing. They do not
	// always: while `internal/portplan` was excluded for a jdk_vendor mismatch it
	// failed JAVAC_UNAVAILABLE instead whenever the pinned JDK was off PATH, which
	// is a different problem wearing the exclusion's name. This gate does not
	// judge that -- it makes it readable.
	var passing []string
	for _, name := range sortedKeys(excluded) {
		if !present[name] {
			continue
		}
		fmt.Printf("gate=go-suite excluded=%s reason=%q\n", name, excluded[name])
		probe := exec.Command("go", "test", "-count=1", "-timeout", *timeout, "./"+name)
		probe.Dir = *root
		output, probeErr := probe.CombinedOutput()
		if probeErr == nil {
			passing = append(passing, name)
			fmt.Printf("gate=go-suite finding=EXCLUSION_NO_LONGER_FAILS package=%s "+
				"detail=%q\n", name,
				"the package is excluded as unable to pass on this host and it PASSED: "+
					"the exclusion outlived the problem it describes. Remove it, or say "+
					"what it now excludes.")
			continue
		}
		fmt.Printf("gate=go-suite excluded=%s still_fails=yes observed=%q\n",
			name, firstFailure(string(output)))
	}
	// WHAT `run=` DOES NOT MEAN. `go test ./pkg` on a package with no test files
	// prints "ok [no test files]" and exits 0, and a _test.go file behind an
	// unsatisfied build tag is not compiled and not reported at all. Both are
	// PASSES over zero assertions, and neither moves any number this gate prints,
	// so `run=59 result=PASS` reads as 59 packages verified when it is not.
	//
	// This is not hypothetical and it is not small. Adversarial review B2 hid a
	// deliberate `t.Fatal` behind `//go:build darwin` and the census stayed
	// byte-identical at packages=61 run=59 excluded=2 result=PASS; B3 put a whole
	// failing package behind the same tag and `go list ./...` reported the same 61
	// with nothing on stderr. And the tree ALREADY does this on purpose: FIVE
	// _test.go files in the run set sit behind javabinde2e, diffregress,
	// normcollide and formalcovere2e, none of which this gate satisfies, and two
	// more sit inside the excluded internal/lab. Those are UNDECLARED exclusions
	// inside a gate whose founding claim is that exclusions are declared -- the
	// named package gets an 80-byte reason, an owner action and a staleness check,
	// and seven test files get silence.
	//
	// 15 of the run packages carry no test file at all, so `run=` was never a
	// coverage number; it is now printed beside with_tests=. Measured on
	// 2026-09-04, after internal/portplan was fixed and left the exclusion list:
	// packages=61 run=60 excluded=1 with_tests=45 no_test_files=15
	// unbuilt_test_files=5. The B2/B3 figures quoted above are what those reviews
	// measured when run=59 excluded=2, and are left as the history they are.
	//
	// Refusing them would be wrong: they are deliberate opt-in lanes. Saying
	// nothing is what this gate exists to stop, so they are counted and named.
	untested, unbuilt, detailErr := coverageDetail(*root, run)
	if detailErr != nil {
		fmt.Printf("gate=go-suite result=FAIL reason=%q\n",
			fmt.Sprintf("cannot read what the run covers: %v", detailErr))
		os.Exit(1)
	}
	for _, name := range untested {
		fmt.Printf("gate=go-suite finding=NO_TEST_FILES package=%s detail=%q\n", name,
			"in the run set and carries no test file, so `go test` reports ok over zero "+
				"assertions; deleting a package's last test moves it here and changes no count")
	}
	for _, file := range unbuilt {
		fmt.Printf("gate=go-suite finding=UNBUILT_TEST_FILE package=%s file=%s constraint=%q "+
			"detail=%q\n", file.pkg, file.name, file.constraint,
			"a test file this run does not compile: an exclusion with no declaration, no "+
				"reason and no owner action, invisible in packages=/run=/excluded=")
	}
	fmt.Printf("gate=go-suite packages=%d run=%d excluded=%d with_tests=%d "+
		"no_test_files=%d unbuilt_test_files=%d\n",
		len(packages), len(run), len(packages)-len(run), len(run)-len(untested),
		len(untested), len(unbuilt))

	if len(stale) > 0 {
		fmt.Printf("gate=go-suite result=FAIL reason=\"%d stale exclusion(s)\"\n", len(stale))
		os.Exit(1)
	}
	if len(passing) > 0 {
		fmt.Printf("gate=go-suite result=FAIL reason=\"%d exclusion(s) name a package that "+
			"now PASSES: %s\"\n", len(passing), strings.Join(passing, " "))
		os.Exit(1)
	}

	argv := append([]string{"test", "-count=1", "-timeout", *timeout}, prefixed(run)...)
	command := exec.Command("go", argv...)
	command.Dir = *root
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		fmt.Printf("gate=go-suite result=FAIL detail=%q\n", err.Error())
		os.Exit(1)
	}
	fmt.Printf("gate=go-suite result=PASS detail=%q\n", fmt.Sprintf(
		"%d package(s) run of which %d carry a test file, %d excluded by name with a reason "+
			"that was RUN and still fails, %d test file(s) not compiled by this run",
		len(run), len(run)-len(untested), len(packages)-len(run), len(unbuilt)))
}

func listPackages(root string) ([]string, error) {
	command := exec.Command("go", "list", "./...")
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("go list: %w", err)
	}
	modulePath, err := modulePath(root)
	if err != nil {
		return nil, err
	}
	var packages []string
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if line == "" {
			continue
		}
		packages = append(packages, strings.TrimPrefix(strings.TrimPrefix(line, modulePath), "/"))
	}
	sort.Strings(packages)
	return packages, nil
}

func modulePath(root string) (string, error) {
	command := exec.Command("go", "list", "-m")
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("go list -m: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

func prefixed(names []string) []string {
	out := make([]string, 0, len(names))
	for _, name := range names {
		if name == "" {
			out = append(out, ".")
			continue
		}
		out = append(out, "./"+name)
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// firstFailure returns the first line of `go test` output that reports a
// failure, so the gate log carries the observed reason next to the declared one
// instead of asking a reader to take the declaration on trust.
func firstFailure(output string) string {
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "--- FAIL") || strings.HasPrefix(trimmed, "FAIL\t") ||
			strings.Contains(trimmed, ".go:") {
			if len(trimmed) > 300 {
				trimmed = trimmed[:300] + " …"
			}
			return trimmed
		}
	}
	return "failed with no recognisable failure line"
}

// unbuiltTest is a _test.go file `go list` reports as ignored for this build:
// present in the package, not compiled, not run, and not named by any exclusion.
type unbuiltTest struct {
	pkg        string
	name       string
	constraint string
}

// coverageDetail asks `go list` what the run set actually contains: which
// packages have no test file at all, and which test files this build excludes.
// It reads the SAME package list the gate runs, so the two cannot disagree.
func coverageDetail(root string, run []string) ([]string, []unbuiltTest, error) {
	if len(run) == 0 {
		return nil, nil, fmt.Errorf("the run set is empty: this gate would run nothing")
	}
	const format = "{{.ImportPath}}\t{{len .TestGoFiles}}\t{{len .XTestGoFiles}}\t" +
		"{{range .IgnoredGoFiles}}{{.}} {{end}}\t{{.Dir}}"
	argv := append([]string{"list", "-e", "-f", format}, prefixed(run)...)
	command := exec.Command("go", argv...)
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		return nil, nil, fmt.Errorf("go list -f: %w", err)
	}
	modulePath, err := modulePath(root)
	if err != nil {
		return nil, nil, err
	}
	var untested []string
	var unbuilt []unbuiltTest
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) < 5 {
			continue
		}
		name := strings.TrimPrefix(strings.TrimPrefix(fields[0], modulePath), "/")
		if fields[1] == "0" && fields[2] == "0" {
			untested = append(untested, name)
		}
		for _, ignored := range strings.Fields(fields[3]) {
			if !strings.HasSuffix(ignored, "_test.go") {
				continue
			}
			unbuilt = append(unbuilt, unbuiltTest{
				pkg:        name,
				name:       ignored,
				constraint: buildConstraint(filepath.Join(fields[4], ignored)),
			})
		}
	}
	sort.Strings(untested)
	sort.Slice(unbuilt, func(i, j int) bool {
		if unbuilt[i].pkg != unbuilt[j].pkg {
			return unbuilt[i].pkg < unbuilt[j].pkg
		}
		return unbuilt[i].name < unbuilt[j].name
	})
	return untested, unbuilt, nil
}

// buildConstraint reads a file's //go:build line so the gate names the tag that
// would have to be set, rather than reporting that something is missing and
// leaving the reader to find out why.
func buildConstraint(path string) string {
	content, err := os.ReadFile(path)
	if err != nil {
		return "unreadable"
	}
	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//go:build ") {
			return strings.TrimSpace(strings.TrimPrefix(trimmed, "//go:build "))
		}
		if strings.HasPrefix(trimmed, "package ") {
			break
		}
	}
	return "no //go:build line found"
}

// refuseJavac exits 2 with the remedy named. It is a refusal, not a failure: the
// tree may be perfectly good, and a gate that cannot tell says so.
func refuseJavac(observed, root string) {
	fmt.Printf("gate=go-suite result=REFUSED reason=%q remedy=%q\n",
		"the pinned JDK is not on PATH, so internal/portplan cannot be told apart from a "+
			"genuinely broken package: "+observed+". This is a refusal, not a failure, "+
			"and not a skip.",
		"export PATH=/home/user/verified-java-websocket-port/.quarantine/jdk-"+
			portplan.PinnedJavacVersion+"+10/bin:$PATH")
	os.Exit(2)
}

func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "javac ") {
			return strings.TrimSpace(line)
		}
	}
	return strings.TrimSpace(s)
}
