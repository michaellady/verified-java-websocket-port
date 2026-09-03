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
// Two packages genuinely cannot pass on this host. They are named here with the
// reason, and the reason is CHECKED: an exclusion naming a package that no longer
// exists fails the gate, so the list cannot quietly outlive the problem it
// describes. Everything not excluded is run; a package added tomorrow is covered
// without anyone remembering to add it.
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
)

// excluded is the complete set of packages this gate does not run, each with the
// reason it cannot pass on this host. Adding an entry is a decision someone has
// to defend in review; it is not a place to park a failure.
var excluded = map[string]string{
	"internal/lab": "CONTROLLED_CANARY requires Darwin sandbox-exec; " +
		"PLATFORM_EXECUTOR_UNSUPPORTED on Linux. Owner gate: a macOS host.",
	"internal/portplan": "TestDeriveReproducesCommittedEvidence byte-compares the " +
		"regenerated semantic-id oracle against the committed one, which records " +
		"jdk_vendor \"Homebrew\"; a Linux Temurin regeneration differs in that ONE " +
		"line, all 969 declarations identical. Owner decision: make the check " +
		"vendor-agnostic, or pin the vendor as a host requirement.",
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

	for _, name := range sortedKeys(excluded) {
		if present[name] {
			fmt.Printf("gate=go-suite excluded=%s reason=%q\n", name, excluded[name])
		}
	}
	fmt.Printf("gate=go-suite packages=%d run=%d excluded=%d\n",
		len(packages), len(run), len(packages)-len(run))

	if len(stale) > 0 {
		fmt.Printf("gate=go-suite result=FAIL reason=\"%d stale exclusion(s)\"\n", len(stale))
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
	fmt.Printf("gate=go-suite result=PASS detail=\"%d package(s) run, %d excluded by name with a reason\"\n",
		len(run), len(packages)-len(run))
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
