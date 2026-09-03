// Command pinconsumerctl answers the question that cost this repository two
// chain-walks in one day: WHEN I CHANGE A FILE, WHICH ARTIFACTS PIN IT?
//
// The evidence tree is full of digest pins, and they work -- each of today's two
// failures was a pin correctly reporting an un-propagated change. What was
// missing is any way to ask the question in advance. Both times the first
// artifact's failure named only itself, and the consumer behind it was found only
// by breaking it.
//
// This tool is deliberately SHAPE-AGNOSTIC. The tree pins paths under at least
// twelve different key names (`path`, `reportfile`, `file`, `manifest_path`,
// `source_path`, `catalog_source_path`, `mutation_manifest_path`, `source`,
// `target_path`, `pin_file`, `lifecycle_path`, `adapted_path`), so a parser that
// understood schemas would be wrong the moment a thirteenth appeared. Instead it
// indexes by DIGEST VALUE: a consumer of a file is any artifact whose text
// carries that file's current sha256.
//
//	pinconsumerctl consumers <path>...   # who pins these files' CURRENT content
//	pinconsumerctl dangling              # pins whose named file no longer matches
//
// `dangling` reports CANDIDATES, not verdicts, and the distinction is load-bearing:
// co-location of a path and a digest inside one JSON object is evidence that the
// digest is OF that path, not proof. Every candidate must be read before it is
// acted on. The census prints its own false-positive surface rather than implying
// a clean number.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var digestPattern = regexp.MustCompile(`^(?:sha256:)?([0-9a-f]{64})$`)

type pin struct {
	artifact  string
	pointer   string
	namedPath string
	declared  string
	actual    string
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: pinconsumerctl <consumers <path>...|dangling> [-root DIR]")
		os.Exit(2)
	}
	root := "."
	args := os.Args[2:]
	var positional []string
	for index := 0; index < len(args); index++ {
		if args[index] == "-root" && index+1 < len(args) {
			root = args[index+1]
			index++
			continue
		}
		positional = append(positional, args[index])
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pinconsumerctl: %v\n", err)
		os.Exit(2)
	}

	switch os.Args[1] {
	case "consumers":
		if len(positional) == 0 {
			fmt.Fprintln(os.Stderr, "pinconsumerctl: consumers needs at least one path")
			os.Exit(2)
		}
		os.Exit(runConsumers(absoluteRoot, positional))
	case "dangling":
		os.Exit(runDangling(absoluteRoot))
	default:
		fmt.Fprintf(os.Stderr, "pinconsumerctl: unknown subcommand %q\n", os.Args[1])
		os.Exit(2)
	}
}

// trackedFiles lists what git tracks, so untracked scratch files and ignored
// trees (.quarantine, target/) never enter the index.
func trackedFiles(root string) ([]string, error) {
	command := exec.Command("git", "-C", root, "ls-files", "-z")
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %w", err)
	}
	var paths []string
	for _, entry := range strings.Split(string(output), "\x00") {
		if entry != "" {
			paths = append(paths, entry)
		}
	}
	return paths, nil
}

func fileDigest(root, relative string) (string, bool) {
	content, err := os.ReadFile(filepath.Join(root, relative))
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:]), true
}

type consumerTarget struct {
	path    string
	digest  string
	current []string
	stale   []pin
}

// analyseConsumers answers "who must I update if I change this file?" -- which is
// TWO questions, and the first version of this tool answered only one. An
// artifact holding the file's CURRENT digest is a consumer. So is an artifact
// that NAMES the file while carrying some other digest: that one is a pin which
// has ALREADY drifted, and reporting "nothing pins this" for it was the opposite
// of the truth in exactly the case where the answer matters most.
func analyseConsumers(root string, targets []string) ([]consumerTarget, error) {
	tracked, err := trackedFiles(root)
	if err != nil {
		return nil, err
	}
	trackedSet := make(map[string]bool, len(tracked))
	for _, relative := range tracked {
		trackedSet[relative] = true
	}

	var artifacts []string
	for _, relative := range tracked {
		if strings.HasSuffix(relative, ".json") {
			artifacts = append(artifacts, relative)
		}
	}

	var report []consumerTarget
	for _, target := range targets {
		relative := target
		if filepath.IsAbs(target) {
			if rel, err := filepath.Rel(root, target); err == nil {
				relative = rel
			}
		}
		relative = strings.TrimPrefix(relative, "./")

		entry := consumerTarget{path: relative}
		digest, ok := fileDigest(root, relative)
		if !ok {
			report = append(report, entry)
			continue
		}
		entry.digest = digest

		for _, artifact := range artifacts {
			if artifact == relative {
				continue
			}
			content, err := os.ReadFile(filepath.Join(root, artifact))
			if err != nil {
				continue
			}
			if strings.Contains(string(content), digest) {
				entry.current = append(entry.current, artifact)
			}
			entry.stale = append(entry.stale,
				stalePinsNaming(content, artifact, relative, digest, trackedSet)...)
		}
		sort.Strings(entry.current)
		sort.Slice(entry.stale, func(i, j int) bool {
			if entry.stale[i].artifact != entry.stale[j].artifact {
				return entry.stale[i].artifact < entry.stale[j].artifact
			}
			return entry.stale[i].pointer < entry.stale[j].pointer
		})
		report = append(report, entry)
	}
	return report, nil
}

// stalePinsNaming finds objects in one artifact that name `relative` alongside a
// digest that is not the file's current one.
func stalePinsNaming(content []byte, artifact, relative, actual string,
	trackedSet map[string]bool) []pin {
	var document any
	if err := json.Unmarshal(content, &document); err != nil {
		return nil
	}
	var found []pin
	walk(document, "$", func(object map[string]any, pointer string) {
		paths, digests := splitPinFields(object, trackedSet)
		if len(paths) != 1 || paths[0] != relative || len(digests) == 0 {
			return
		}
		for _, declared := range digests {
			if declared == actual {
				return
			}
		}
		found = append(found, pin{
			artifact: artifact, pointer: pointer, namedPath: relative,
			declared: digests[0], actual: actual,
		})
	})
	return found
}

func runConsumers(root string, targets []string) int {
	report, err := analyseConsumers(root, targets)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pinconsumerctl: %v\n", err)
		return 2
	}
	status := 0
	for _, target := range report {
		if target.digest == "" {
			fmt.Printf("gate=pin-consumers target=%s result=UNREADABLE\n", target.path)
			status = 2
			continue
		}
		fmt.Printf("gate=pin-consumers target=%s sha256=%s current=%d stale=%d\n",
			target.path, target.digest, len(target.current), len(target.stale))
		for _, artifact := range target.current {
			fmt.Printf("    pinned_by %s\n", artifact)
		}
		for _, stale := range target.stale {
			fmt.Printf("    ALREADY_STALE %s pointer=%s declared=sha256:%s\n",
				stale.artifact, stale.pointer, stale.declared)
		}
		if len(target.current) == 0 && len(target.stale) == 0 {
			fmt.Printf("    no artifact holds this file's digest and none names it beside a" +
				" different one\n")
		}
		if len(target.stale) > 0 {
			status = 1
		}
	}
	return status
}

func mustAbs(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return absolute
}

type danglingCensus struct {
	candidates []pin
	artifacts  int
	unparsable int
}

func runDangling(root string) int {
	census, err := analyseDangling(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pinconsumerctl: %v\n", err)
		return 2
	}
	for _, candidate := range census.candidates {
		fmt.Printf("gate=pin-dangling artifact=%s pointer=%s names=%s declared=sha256:%s actual=sha256:%s\n",
			candidate.artifact, candidate.pointer, candidate.namedPath,
			candidate.declared, candidate.actual)
	}
	fmt.Printf("gate=pin-dangling json_artifacts=%d unparsable=%d candidates=%d\n",
		census.artifacts, census.unparsable, len(census.candidates))
	fmt.Printf("gate=pin-dangling ceiling=%q\n", danglingCeiling)
	if len(census.candidates) > 0 {
		return 1
	}
	return 0
}

const danglingCeiling = "candidates are objects where a tracked path and a sha256" +
	" share one JSON object and no digest in that object matches the file;" +
	" co-location is evidence that the digest is OF that path, NOT proof, so every" +
	" candidate must be READ before it is acted on. A pin whose digest covers" +
	" something other than the file it sits beside is a false positive by" +
	" construction, and a pin split across two objects is a false negative."

func analyseDangling(root string) (danglingCensus, error) {
	tracked, err := trackedFiles(root)
	if err != nil {
		return danglingCensus{}, err
	}
	trackedSet := make(map[string]bool, len(tracked))
	for _, relative := range tracked {
		trackedSet[relative] = true
	}

	digestCache := map[string]string{}
	digestOf := func(relative string) (string, bool) {
		if cached, ok := digestCache[relative]; ok {
			return cached, cached != ""
		}
		digest, ok := fileDigest(root, relative)
		if !ok {
			digestCache[relative] = ""
			return "", false
		}
		digestCache[relative] = digest
		return digest, true
	}

	var candidates []pin
	artifacts := 0
	unparsable := 0

	for _, relative := range tracked {
		if !strings.HasSuffix(relative, ".json") {
			continue
		}
		content, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			continue
		}
		var document any
		if err := json.Unmarshal(content, &document); err != nil {
			unparsable++
			continue
		}
		artifacts++
		walk(document, "$", func(object map[string]any, pointer string) {
			paths, digests := splitPinFields(object, trackedSet)
			// One unambiguous named path, at least one digest beside it.
			if len(paths) != 1 || len(digests) == 0 {
				return
			}
			named := paths[0]
			if named == relative {
				return // a document pinning its own digest is a different check
			}
			actual, ok := digestOf(named)
			if !ok {
				return
			}
			for _, declared := range digests {
				if declared == actual {
					return // some digest in this object matches; not dangling
				}
			}
			candidates = append(candidates, pin{
				artifact:  relative,
				pointer:   pointer,
				namedPath: named,
				declared:  digests[0],
				actual:    actual,
			})
		})
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].artifact != candidates[j].artifact {
			return candidates[i].artifact < candidates[j].artifact
		}
		return candidates[i].pointer < candidates[j].pointer
	})

	return danglingCensus{candidates: candidates, artifacts: artifacts, unparsable: unparsable}, nil
}

// splitPinFields returns the tracked-file paths and the sha256 digests found
// among an object's immediate string values.
func splitPinFields(object map[string]any, trackedSet map[string]bool) ([]string, []string) {
	var paths, digests []string
	for _, value := range object {
		text, ok := value.(string)
		if !ok {
			continue
		}
		if match := digestPattern.FindStringSubmatch(text); match != nil {
			digests = append(digests, match[1])
			continue
		}
		cleaned := strings.TrimPrefix(text, "./")
		if trackedSet[cleaned] {
			paths = append(paths, cleaned)
		}
	}
	sort.Strings(paths)
	sort.Strings(digests)
	return paths, digests
}

func walk(node any, pointer string, visit func(map[string]any, string)) {
	switch typed := node.(type) {
	case map[string]any:
		visit(typed, pointer)
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			walk(typed[key], pointer+"."+key, visit)
		}
	case []any:
		for index, element := range typed {
			walk(element, fmt.Sprintf("%s[%d]", pointer, index), visit)
		}
	}
}

var _ = fs.SkipDir
