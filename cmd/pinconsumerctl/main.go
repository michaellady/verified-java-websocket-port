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

func runConsumers(root string, targets []string) int {
	tracked, err := trackedFiles(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pinconsumerctl: %v\n", err)
		return 2
	}

	// Only JSON artifacts can pin; reading every tracked file would be waste.
	var artifacts []string
	for _, relative := range tracked {
		if strings.HasSuffix(relative, ".json") {
			artifacts = append(artifacts, relative)
		}
	}

	status := 0
	for _, target := range targets {
		relative, err := filepath.Rel(root, mustAbs(target))
		if err != nil {
			relative = target
		}
		digest, ok := fileDigest(root, relative)
		if !ok {
			fmt.Printf("gate=pin-consumers target=%s result=UNREADABLE\n", relative)
			status = 2
			continue
		}
		var consumers []string
		for _, artifact := range artifacts {
			if artifact == relative {
				continue
			}
			content, err := os.ReadFile(filepath.Join(root, artifact))
			if err != nil {
				continue
			}
			if strings.Contains(string(content), digest) {
				consumers = append(consumers, artifact)
			}
		}
		sort.Strings(consumers)
		fmt.Printf("gate=pin-consumers target=%s sha256=%s consumers=%d\n",
			relative, digest, len(consumers))
		for _, consumer := range consumers {
			fmt.Printf("    pinned_by %s\n", consumer)
		}
		if len(consumers) == 0 {
			fmt.Printf("    nothing in the tree pins this file's current content\n")
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
