package normcollide

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"

	"github.com/michaellady/verified-java-websocket-port/internal/diffregress"
)

// Runner executes oracle request lines and returns one response line each, in
// order. The real implementation runs the harness process; tests inject a
// stub so the DECIDING logic can be attacked without a Rust build.
type Runner interface {
	Run(lines []string) ([]string, error)
	// Identity names what answered, for the document's provenance.
	Identity() string
}

// HarnessRunner runs the real ws-oracle-harness binary and reads its exit
// code from the process. A nonzero exit, or any byte on stderr, is a hard
// error: this package never scores a run it could not fully trust.
type HarnessRunner struct {
	// Binary is the path to ws-oracle-harness.
	Binary string
	// Digest is the SHA-256 of that binary, recorded in the document.
	Digest string
}

// Identity reports the binary and its digest.
func (h HarnessRunner) Identity() string { return h.Binary + " " + h.Digest }

// Run feeds every line to one harness invocation and returns its answers.
func (h HarnessRunner) Run(lines []string) ([]string, error) {
	var stdin bytes.Buffer
	for _, line := range lines {
		stdin.WriteString(line)
		stdin.WriteString("\n")
	}
	var stdout, stderr bytes.Buffer
	command := exec.Command(h.Binary)
	command.Stdin = &stdin
	command.Stdout = &stdout
	command.Stderr = &stderr
	runErr := command.Run()
	exit := command.ProcessState.ExitCode()
	if runErr != nil || exit != 0 {
		return nil, fmt.Errorf("ws-oracle-harness exit %d (err %v): %s", exit, runErr, stderr.String())
	}
	if stderr.Len() != 0 {
		return nil, fmt.Errorf("ws-oracle-harness wrote %d bytes to stderr: %s", stderr.Len(), stderr.String())
	}
	out := bytes.Split(bytes.TrimRight(stdout.Bytes(), "\n"), []byte("\n"))
	answers := make([]string, 0, len(out))
	for _, line := range out {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		answers = append(answers, string(line))
	}
	if len(answers) != len(lines) {
		return nil, fmt.Errorf("harness answered %d lines for %d requests", len(answers), len(lines))
	}
	return answers, nil
}

// Verdict is a probe's decision. There is no third value: a probe is decided
// by a run or it is not in the catalog.
type Verdict string

const (
	// Confirmed means the collision pair moved NOTHING the comparator can
	// report, and the pair was proved genuinely different.
	Confirmed Verdict = "CONFIRMED"
	// Refuted means the comparator moved: the surface represents the
	// distinction after all.
	Refuted Verdict = "REFUTED"
)

// Result is one probe's decided outcome, every field of it measured.
type Result struct {
	// ProbeID identifies the probe.
	ProbeID string `json:"probe_id"`
	// Verdict is the decision.
	Verdict Verdict `json:"verdict"`
	// CollisionPaths are the behavioural paths the comparator reported on
	// the collision pair, identity fields removed. CONFIRMED requires this
	// to be empty; the field is emitted even when empty so a reader can see
	// the check ran.
	CollisionPaths []string `json:"collision_diff_paths"`
	// WitnessPaths are the paths the comparator reported on the witness
	// pair. A witnessed probe requires this to be NON-empty.
	WitnessPaths []string `json:"witness_diff_paths,omitempty"`
	// WitnessKind is "pair" or "wire".
	WitnessKind string `json:"witness_kind"`
	// KeysA and KeysB are the top-level members each collision answer
	// actually carried. These are recomputed from the run, which is what
	// makes the Projections() Drops lists checkable rather than asserted.
	KeysA []string `json:"collision_a_keys"`
	KeysB []string `json:"collision_b_keys"`
	// IdentityMoved lists the identity fields that DID differ. A collision
	// claim over two requests whose identity fields are equal would be a
	// claim about one request compared with itself, so this must be
	// non-empty.
	IdentityMoved []string `json:"identity_fields_that_differ"`
}

// Decide runs one probe and reports what actually happened. It predicts
// nothing: every field of the Result comes from the two response lines the
// runner returned.
func Decide(runner Runner, probe Probe) (Result, error) {
	result := Result{ProbeID: probe.ID, WitnessKind: "wire"}

	lines := make([]string, 0, 4)
	for _, seed := range []Seed{probe.CollisionA, probe.CollisionB} {
		line, err := seed.Line()
		if err != nil {
			return result, err
		}
		lines = append(lines, line)
	}
	if lines[0] == lines[1] {
		return result, fmt.Errorf("probe %s: the two collision seeds render the SAME request line; "+
			"a collision claim needs two different inputs", probe.ID)
	}
	witnessed := probe.WitnessA != nil && probe.WitnessB != nil
	if witnessed {
		result.WitnessKind = "pair"
		for _, seed := range []Seed{*probe.WitnessA, *probe.WitnessB} {
			line, err := seed.Line()
			if err != nil {
				return result, err
			}
			lines = append(lines, line)
		}
	} else if probe.WireWitness == "" {
		return result, fmt.Errorf("probe %s has neither a witness pair nor a wire witness; "+
			"an unwitnessed collision claim is not falsifiable", probe.ID)
	}

	answers, err := runner.Run(lines)
	if err != nil {
		return result, fmt.Errorf("probe %s: %w", probe.ID, err)
	}

	collisionA, err := decodeResponse(answers[0])
	if err != nil {
		return result, fmt.Errorf("probe %s collision A: %w", probe.ID, err)
	}
	collisionB, err := decodeResponse(answers[1])
	if err != nil {
		return result, fmt.Errorf("probe %s collision B: %w", probe.ID, err)
	}
	result.KeysA = topLevelKeys(collisionA)
	result.KeysB = topLevelKeys(collisionB)
	result.IdentityMoved = identityFieldsThatDiffer(collisionA, collisionB)
	result.CollisionPaths = behaviouralPaths(collisionA, collisionB)

	if witnessed {
		witnessA, err := decodeResponse(answers[2])
		if err != nil {
			return result, fmt.Errorf("probe %s witness A: %w", probe.ID, err)
		}
		witnessB, err := decodeResponse(answers[3])
		if err != nil {
			return result, fmt.Errorf("probe %s witness B: %w", probe.ID, err)
		}
		result.WitnessPaths = behaviouralPaths(witnessA, witnessB)
	}

	// The three checks, in the order that makes a failure legible. Each one
	// can fail on its own; TestDeletingAnyDecisionCheckLetsABadProbePass
	// proves that by feeding a probe that only that check rejects.
	switch {
	case len(result.IdentityMoved) == 0:
		return result, fmt.Errorf("probe %s: the two collision answers agree on every identity "+
			"field, so they are not two requests", probe.ID)
	case witnessed && len(result.WitnessPaths) == 0:
		return result, fmt.Errorf("probe %s: the witness pair moved NOTHING, so the two "+
			"behaviours were never shown to differ; the probe proves only that two equal "+
			"things are equal", probe.ID)
	case len(result.CollisionPaths) != 0:
		result.Verdict = Refuted
	default:
		result.Verdict = Confirmed
	}
	return result, nil
}

// behaviouralPaths runs the REAL differential comparator over two responses
// and returns the paths it reported, minus the identity fields. Nothing else
// is removed: the whole point is that this is the comparator the headline
// number is computed with, not a weakened copy of it.
func behaviouralPaths(a, b map[string]any) []string {
	comparison := diffregress.CompareResponses(a, b)
	identity := map[string]bool{}
	for _, field := range IdentityFields() {
		identity[field] = true
	}
	var kept []string
	for _, path := range comparison.DiffPaths {
		if identity[path] {
			continue
		}
		kept = append(kept, path)
	}
	sort.Strings(kept)
	return kept
}

func identityFieldsThatDiffer(a, b map[string]any) []string {
	var moved []string
	for _, field := range IdentityFields() {
		av, aok := a[field]
		bv, bok := b[field]
		if aok != bok || fmt.Sprint(av) != fmt.Sprint(bv) {
			moved = append(moved, field)
		}
	}
	sort.Strings(moved)
	return moved
}

func decodeResponse(line string) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader([]byte(line)))
	decoder.UseNumber()
	var object map[string]any
	if err := decoder.Decode(&object); err != nil {
		return nil, err
	}
	return object, nil
}

func topLevelKeys(object map[string]any) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
