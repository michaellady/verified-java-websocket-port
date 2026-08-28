// Command hsdiff scores the 49-case live handshake exam as a DIRECT field
// differential: the Rust harness transcript against the RECORDED live Java
// transcript, comparing every field except `runtime`.
//
// `runtime` is excluded and reported separately because it is each producer's
// self-attestation (the Java jar's sha256 vs the Rust harness binary's), so it
// differs by construction and is not a behavioral field. This is the same
// runtime-neutralized scoring the borrow-batch-b receipt documents; the honest
// `corporactl evaluate --live` exit is 1 for a Rust candidate for exactly that
// reason, which is a runtime-pin fact and not a behavioral failure.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"reflect"
	"sort"
)

func readLines(path string) ([]map[string]any, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<24)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, sc.Err()
}

func main() {
	rustPath := flag.String("rust", "", "Rust harness transcript (jsonl)")
	javaPath := flag.String("java", "", "recorded live Java transcript (jsonl)")
	flag.Parse()

	rust, err := readLines(*rustPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hsdiff:", err)
		os.Exit(2)
	}
	java, err := readLines(*javaPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hsdiff:", err)
		os.Exit(2)
	}
	if len(rust) != len(java) {
		fmt.Fprintf(os.Stderr, "hsdiff: line count mismatch rust=%d java=%d\n", len(rust), len(java))
		os.Exit(1)
	}

	byCase := map[string]map[string]any{}
	for _, j := range java {
		id, _ := j["case_id"].(string)
		byCase[id] = j
	}

	executed, passed := 0, 0
	var failures []string
	runtimeDiffers := 0
	for _, r := range rust {
		executed++
		id, _ := r["case_id"].(string)
		j, ok := byCase[id]
		if !ok {
			failures = append(failures, id+": no recorded Java case")
			continue
		}
		if !reflect.DeepEqual(r["runtime"], j["runtime"]) {
			runtimeDiffers++
		}
		keys := map[string]bool{}
		for k := range r {
			keys[k] = true
		}
		for k := range j {
			keys[k] = true
		}
		var names []string
		for k := range keys {
			if k != "runtime" {
				names = append(names, k)
			}
		}
		sort.Strings(names)
		mismatch := ""
		for _, k := range names {
			if !reflect.DeepEqual(r[k], j[k]) {
				mismatch = fmt.Sprintf("%s: field %q rust=%v java=%v", id, k, r[k], j[k])
				break
			}
		}
		if mismatch == "" {
			passed++
		} else {
			failures = append(failures, mismatch)
		}
	}

	report := map[string]any{
		"executed":                      executed,
		"passed":                        passed,
		"failed":                        executed - passed,
		"behavioral_fields_compared":    "every field except runtime",
		"runtime_self_attestation_diff": runtimeDiffers,
		"failures":                      failures,
	}
	blob, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(blob))
	if passed != executed {
		os.Exit(1)
	}
}
