package corpora

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Limits mirrors the oracle protocol's limits object.
type Limits struct {
	MaxInputBytes    int `json:"max_input_bytes"`
	MaxBufferedBytes int `json:"max_buffered_bytes"`
	MaxActions       int `json:"max_actions"`
	MaxFrames        int `json:"max_frames"`
	MaxOutputBytes   int `json:"max_output_bytes"`
}

func (l Limits) toMap() map[string]any {
	return map[string]any{
		"max_input_bytes":    l.MaxInputBytes,
		"max_buffered_bytes": l.MaxBufferedBytes,
		"max_actions":        l.MaxActions,
		"max_frames":         l.MaxFrames,
		"max_output_bytes":   l.MaxOutputBytes,
	}
}

// Step is one neutral scenario step: either arbitrary byte input or a local
// command, using exactly the oracle protocol's field sets.
type Step struct {
	Kind       string `json:"kind"`
	Action     string `json:"action,omitempty"`
	DataBase64 string `json:"data_base64,omitempty"`
	Text       string `json:"text,omitempty"`
	Code       int    `json:"code,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Opcode     string `json:"opcode,omitempty"`
	Fin        bool   `json:"fin,omitempty"`
}

// toMap returns the exact oracle-protocol field set for the step kind.
func (s Step) toMap() (map[string]any, error) {
	switch s.Kind {
	case "bytes":
		return map[string]any{"kind": "bytes", "data_base64": s.DataBase64}, nil
	case "action":
		switch s.Action {
		case "send_text":
			return map[string]any{"kind": "action", "action": "send_text", "text": s.Text}, nil
		case "send_binary", "send_ping", "send_pong":
			return map[string]any{"kind": "action", "action": s.Action,
				"data_base64": s.DataBase64}, nil
		case "send_close":
			return map[string]any{"kind": "action", "action": "send_close",
				"code": s.Code, "reason": s.Reason}, nil
		case "send_fragment":
			return map[string]any{"kind": "action", "action": "send_fragment",
				"data_base64": s.DataBase64, "fin": s.Fin, "opcode": s.Opcode}, nil
		case "eof":
			return map[string]any{"kind": "action", "action": "eof"}, nil
		}
		return nil, fmt.Errorf("unsupported action %q", s.Action)
	}
	return nil, fmt.Errorf("unsupported step kind %q", s.Kind)
}

func (s Step) payload() ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(s.DataBase64)
	if err != nil {
		return nil, fmt.Errorf("data_base64 is not canonical base64: %w", err)
	}
	if base64.StdEncoding.EncodeToString(decoded) != s.DataBase64 {
		return nil, fmt.Errorf("data_base64 is not canonical base64")
	}
	return decoded, nil
}

// ScenarioCore is the executable portion of a scenario: role, initial
// connection state, limits, and steps. It carries no runner semantics.
type ScenarioCore struct {
	Role         string `json:"role"`
	InitialState string `json:"initial_state"`
	Limits       Limits `json:"limits"`
	Steps        []Step `json:"steps"`
}

// Counts mirrors the oracle response counts object.
type Counts struct {
	Actions              int `json:"actions"`
	BufferedBytes        int `json:"buffered_bytes"`
	ConsumedBytes        int `json:"consumed_bytes"`
	Frames               int `json:"frames"`
	InputBytes           int `json:"input_bytes"`
	MessageBufferedBytes int `json:"message_buffered_bytes"`
	WireBufferedBytes    int `json:"wire_buffered_bytes"`
}

func (c Counts) toMap() map[string]any {
	return map[string]any{
		"actions":                c.Actions,
		"buffered_bytes":         c.BufferedBytes,
		"consumed_bytes":         c.ConsumedBytes,
		"frames":                 c.Frames,
		"input_bytes":            c.InputBytes,
		"message_buffered_bytes": c.MessageBufferedBytes,
		"wire_buffered_bytes":    c.WireBufferedBytes,
	}
}

// ExpectedError is the asserted rejection for error-outcome scenarios.
type ExpectedError struct {
	Code      string `json:"code"`
	CloseCode *int   `json:"close_code,omitempty"`
}

// Expected is a scenario's language-independent expectation. Success outcomes
// assert the full semantic surface: events, frames, transitions, close
// details, and consumed/buffered counts. Error outcomes assert the rejection
// code, optional close code, final state, and the exact counts too: the
// oracle's failure responses include the counters, and their values are
// pinned by the quarantined runtime sources.
type Expected struct {
	Outcome     string           `json:"outcome"`
	FinalState  string           `json:"final_state"`
	Events      []map[string]any `json:"events,omitempty"`
	Frames      []map[string]any `json:"frames,omitempty"`
	Transitions []map[string]any `json:"transitions,omitempty"`
	Close       map[string]any   `json:"close,omitempty"`
	Counts      *Counts          `json:"counts,omitempty"`
	Error       *ExpectedError   `json:"error,omitempty"`
}

func (e Expected) toMap() map[string]any {
	out := map[string]any{
		"outcome":     e.Outcome,
		"final_state": e.FinalState,
	}
	if e.Outcome == "ok" {
		out["events"] = anySlice(e.Events)
		out["frames"] = anySlice(e.Frames)
		out["transitions"] = anySlice(e.Transitions)
		if e.Close == nil {
			out["close"] = nil
		} else {
			out["close"] = e.Close
		}
	}
	if e.Counts != nil {
		out["counts"] = e.Counts.toMap()
	}
	if e.Error != nil {
		errorMap := map[string]any{"code": e.Error.Code}
		if e.Error.CloseCode != nil {
			errorMap["close_code"] = *e.Error.CloseCode
		}
		out["error"] = errorMap
	}
	return out
}

func anySlice[T any](items []T) []any {
	out := make([]any, len(items))
	for i, item := range items {
		out[i] = item
	}
	return out
}

// Scenario is one committed corpus record.
type Scenario struct {
	ScenarioID        string `json:"scenario_id"`
	Tier              string `json:"tier"`
	Family            string `json:"family"`
	SeedIndex         int    `json:"seed_index"`
	Core              ScenarioCore
	Expected          Expected `json:"expected"`
	ExpectationBasis  []string `json:"expectation_basis"`
	ExpectationStatus string   `json:"expectation_status"`
}

// ExpectationStatusReferenceModel labels every US-005 behavior expectation:
// derived from the Go reference model of the frozen seam dossier and RFC 6455,
// pending confirmation against the pinned Java oracle in the live calibration
// step. No expectation in this corpus claims Java execution occurred.
const ExpectationStatusReferenceModel = "REFERENCE_MODEL_DERIVED_PENDING_ORACLE_CONFIRMATION"

// toMap returns the canonical scenario record.
func (s Scenario) toMap() (map[string]any, error) {
	steps := make([]any, len(s.Core.Steps))
	for i, step := range s.Core.Steps {
		m, err := step.toMap()
		if err != nil {
			return nil, err
		}
		steps[i] = m
	}
	basis := make([]any, len(s.ExpectationBasis))
	for i, b := range s.ExpectationBasis {
		basis[i] = b
	}
	return map[string]any{
		"scenario_id":        s.ScenarioID,
		"tier":               s.Tier,
		"family":             s.Family,
		"seed_index":         s.SeedIndex,
		"role":               s.Core.Role,
		"initial_state":      s.Core.InitialState,
		"limits":             s.Core.Limits.toMap(),
		"steps":              steps,
		"expected":           s.Expected.toMap(),
		"expectation_basis":  basis,
		"expectation_status": s.ExpectationStatus,
	}, nil
}

// CanonicalLine renders the scenario as one canonical JSONL line (no newline).
func (s Scenario) CanonicalLine() ([]byte, error) {
	m, err := s.toMap()
	if err != nil {
		return nil, err
	}
	return CanonicalJSON(m)
}

// MarshalJSON keeps ordinary JSON encoding aligned with the canonical map.
func (s Scenario) MarshalJSON() ([]byte, error) {
	m, err := s.toMap()
	if err != nil {
		return nil, err
	}
	return json.Marshal(m)
}
