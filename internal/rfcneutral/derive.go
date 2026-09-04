package rfcneutral

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unicode/utf8"
)

// PublicCorpusPath is the committed public tier this derivation reads. It reads
// only the fields Scenario declares, and Scenario has no expected field.
const PublicCorpusPath = "corpora/public/scenarios.jsonl"

// Step is one scenario step. Only kind, the inbound octets and the action name
// are read; a step's recorded consequences are not in this struct.
type Step struct {
	Kind   string `json:"kind"`
	Data   string `json:"data_base64"`
	Action string `json:"action"`
}

// Limits are the scenario's own declared harness bounds. RFC 6455 states none
// of them, so meeting one is an abstention, never a verdict.
type Limits struct {
	MaxActions       uint64 `json:"max_actions"`
	MaxBufferedBytes uint64 `json:"max_buffered_bytes"`
	MaxFrames        uint64 `json:"max_frames"`
	MaxInputBytes    uint64 `json:"max_input_bytes"`
	MaxOutputBytes   uint64 `json:"max_output_bytes"`
}

// Scenario is EXACTLY the part of a corpus line this derivation may see.
//
// There is deliberately no Expected field, no ExpectationBasis and no Family.
// A recorded expectation cannot reach a verdict here even by accident, and
// TestDerivationIgnoresRecordedExpectation re-derives over a corpus whose
// expectations have been replaced with contradictory ones and requires the
// decisions to be byte-identical.
type Scenario struct {
	ScenarioID   string `json:"scenario_id"`
	Role         string `json:"role"`
	InitialState string `json:"initial_state"`
	Limits       Limits `json:"limits"`
	Steps        []Step `json:"steps"`
}

// Decision is this derivation's neutral expectation for one scenario.
type Decision struct {
	ScenarioID string `json:"scenario_id"`
	// Verdict is "open" or "closed", or empty when Abstains is true.
	Verdict  string `json:"verdict,omitempty"`
	Abstains bool   `json:"abstains,omitempty"`
	// RuleID is the rule in rules.go that decided this scenario, whether it
	// decided a verdict or an abstention.
	RuleID  string   `json:"rule_id"`
	Clauses []string `json:"rfc_clauses"`
	// Detail says what in this scenario's own octets triggered the rule.
	Detail string `json:"detail"`
	// StepIndex is the step the rule fired on, or -1 when the rule fired
	// after every step was consumed.
	StepIndex int `json:"step_index"`
}

// Derive reads the committed public corpus and returns one decision per
// scenario, in corpus order.
func Derive(root string) ([]Decision, error) {
	scenarios, err := ReadScenarios(root)
	if err != nil {
		return nil, err
	}
	return DeriveScenarios(scenarios)
}

// DeriveScenarios decides a slice of scenarios. Exported so a test can feed it
// a corpus it has mutated.
func DeriveScenarios(scenarios []Scenario) ([]Decision, error) {
	out := make([]Decision, 0, len(scenarios))
	seen := make(map[string]struct{}, len(scenarios))
	for _, s := range scenarios {
		if _, dup := seen[s.ScenarioID]; dup {
			return nil, fmt.Errorf("%s: scenario id %s appears twice", PublicCorpusPath, s.ScenarioID)
		}
		seen[s.ScenarioID] = struct{}{}
		d, err := decide(s)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

// ReadScenarios decodes the committed corpus into the reduced Scenario shape.
func ReadScenarios(root string) ([]Scenario, error) {
	full := filepath.Join(root, filepath.FromSlash(PublicCorpusPath))
	f, err := os.Open(full)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", PublicCorpusPath, err)
	}
	defer f.Close()

	var out []Scenario
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<26)
	for line := 1; sc.Scan(); line++ {
		raw := sc.Bytes()
		if len(raw) == 0 {
			continue
		}
		var s Scenario
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("%s line %d: %w", PublicCorpusPath, line, err)
		}
		if s.ScenarioID == "" {
			return nil, fmt.Errorf("%s line %d: no scenario_id", PublicCorpusPath, line)
		}
		out = append(out, s)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", PublicCorpusPath, err)
	}
	return out, nil
}

func abstain(id, ruleID, detail string, step int) (Decision, error) {
	r, ok := LookupRule(ruleID)
	if !ok {
		return Decision{}, fmt.Errorf("scenario %s: no rule %q in the table", id, ruleID)
	}
	if r.Effect != "" {
		return Decision{}, fmt.Errorf("scenario %s: rule %q has effect %q and cannot abstain", id, ruleID, r.Effect)
	}
	return Decision{ScenarioID: id, Abstains: true, RuleID: ruleID, Clauses: r.Clauses, Detail: detail, StepIndex: step}, nil
}

func decided(id, ruleID, detail string, step int) (Decision, error) {
	r, ok := LookupRule(ruleID)
	if !ok {
		return Decision{}, fmt.Errorf("scenario %s: no rule %q in the table", id, ruleID)
	}
	if r.Effect == "" {
		return Decision{}, fmt.Errorf("scenario %s: rule %q abstains and cannot decide a verdict", id, ruleID)
	}
	return Decision{ScenarioID: id, Verdict: r.Effect, RuleID: ruleID, Clauses: r.Clauses, Detail: detail, StepIndex: step}, nil
}

// decide walks one scenario's steps and applies the table.
//
// Order matters and is stated here rather than left to the reader:
//
//  1. A non-open declared initial state abstains before any octet is read;
//     RFC 6455 has no readyState to start from.
//  2. Steps are walked in order. A `bytes` step's octets are appended to the
//     decode buffer and every whole frame in it is checked against the table.
//     The FIRST rule that fires decides the scenario.
//  3. A local `action` step abstains, unless a rule already fired on an
//     earlier step -- a connection RFC 6455 already required to be failed is
//     not reopened by what the application does next.
//  4. With every step consumed and no rule fired, RuleNoViolation gives open.
func decide(s Scenario) (Decision, error) {
	switch s.Role {
	case "client", "server":
	default:
		return Decision{}, fmt.Errorf("scenario %s: role %q is neither client nor server", s.ScenarioID, s.Role)
	}
	serverRole := s.Role == "server"

	if s.InitialState != "open" {
		return abstain(s.ScenarioID, AbstainNonOpenInitialState,
			fmt.Sprintf("the scenario declares initial_state %q", s.InitialState), 0)
	}

	var (
		buf          []byte
		totalInput   uint64
		frameCount   uint64
		fragmentOpen bool
		fragmentText bool
		fragmentData []byte
	)
	maxBuffered := s.Limits.MaxBufferedBytes
	if maxBuffered == 0 {
		maxBuffered = ^uint64(0)
	}
	maxFrames := s.Limits.MaxFrames
	if maxFrames == 0 {
		maxFrames = ^uint64(0)
	}
	maxInput := s.Limits.MaxInputBytes
	if maxInput == 0 {
		maxInput = ^uint64(0)
	}

	for i, st := range s.Steps {
		switch st.Kind {
		case "action":
			return abstain(s.ScenarioID, AbstainLocalAPIAction,
				fmt.Sprintf("step %d is a local %s action", i, actionName(st)), i)
		case "bytes":
		default:
			return Decision{}, fmt.Errorf("scenario %s step %d: kind %q is neither bytes nor action", s.ScenarioID, i, st.Kind)
		}

		chunk, err := base64.StdEncoding.DecodeString(st.Data)
		if err != nil {
			return Decision{}, fmt.Errorf("scenario %s step %d: data_base64: %w", s.ScenarioID, i, err)
		}
		totalInput += uint64(len(chunk))
		if totalInput > maxInput {
			return abstain(s.ScenarioID, AbstainHarnessLimit,
				fmt.Sprintf("step %d takes the inbound octet count to %d and the scenario's own max_input_bytes is %d",
					i, totalInput, maxInput), i)
		}
		buf = append(buf, chunk...)

		for {
			f, err := decodeFrame(buf, serverRole, maxBuffered)
			if err != nil {
				var need errNeedMore
				var v violation
				var lim harnessLimit
				switch {
				case errors.As(err, &need):
					// Wait for more octets; not a violation.
				case errors.As(err, &lim):
					return abstain(s.ScenarioID, AbstainHarnessLimit, lim.detail+fmt.Sprintf(" (step %d)", i), i)
				case errors.As(err, &v):
					return decided(s.ScenarioID, v.ruleID, v.detail+fmt.Sprintf(" (step %d)", i), i)
				default:
					return Decision{}, fmt.Errorf("scenario %s step %d: %w", s.ScenarioID, i, err)
				}
				break
			}
			buf = buf[f.wire:]
			frameCount++
			if frameCount > maxFrames {
				return abstain(s.ScenarioID, AbstainHarnessLimit,
					fmt.Sprintf("the stream carries more than the scenario's own max_frames of %d (step %d)", maxFrames, i), i)
			}

			// Section 5.4 sequencing, then per-opcode rules.
			switch {
			case f.isControl():
				// Control frames may be injected mid-message and do
				// not touch the fragment state.
				if f.opcode == opClose {
					if err := checkClosePayload(f.payload); err != nil {
						var v violation
						if errors.As(err, &v) {
							return decided(s.ScenarioID, v.ruleID, v.detail+fmt.Sprintf(" (step %d)", i), i)
						}
						return Decision{}, err
					}
					return abstain(s.ScenarioID, AbstainClosingHandshake,
						fmt.Sprintf("a well-formed Close frame arrives at step %d", i), i)
				}
			case f.opcode == opContinuation:
				if !fragmentOpen {
					return decided(s.ScenarioID, RuleOrphanContinuation,
						fmt.Sprintf("a continuation frame arrives with no fragmented message in progress (step %d)", i), i)
				}
				fragmentData = append(fragmentData, f.payload...)
				if f.fin {
					if fragmentText && !utf8.Valid(fragmentData) {
						return decided(s.ScenarioID, RuleTextNotUTF8,
							fmt.Sprintf("the reassembled text message of %d octets is not valid UTF-8 (step %d)", len(fragmentData), i), i)
					}
					fragmentOpen, fragmentText, fragmentData = false, false, nil
				}
			default: // opText or opBinary
				if fragmentOpen {
					return decided(s.ScenarioID, RuleInterleavedData,
						fmt.Sprintf("a data frame with opcode 0x%x arrives while a fragmented message is in progress (step %d)", f.opcode, i), i)
				}
				if !f.fin {
					fragmentOpen = true
					fragmentText = f.opcode == opText
					fragmentData = append([]byte(nil), f.payload...)
					break
				}
				if f.opcode == opText && !utf8.Valid(f.payload) {
					return decided(s.ScenarioID, RuleTextNotUTF8,
						fmt.Sprintf("the text message of %d octets is not valid UTF-8 (step %d)", len(f.payload), i), i)
				}
			}
		}
	}

	if len(buf) > 0 {
		return abstain(s.ScenarioID, AbstainTruncatedTrailer,
			fmt.Sprintf("%d octets remain that do not complete a frame", len(buf)), -1)
	}
	return decided(s.ScenarioID, RuleNoViolation,
		fmt.Sprintf("%d frame(s) decoded across %d step(s); no rule in the table fired", frameCount, len(s.Steps)), -1)
}

func actionName(st Step) string {
	if st.Action == "" {
		return "(unnamed)"
	}
	return st.Action
}
