package javabind

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// OracleProtocol and OracleVersion are the adapter's own protocol identity.
const (
	OracleProtocol = "java-websocket-oracle"
	OracleVersion  = "1.0.0"
)

func decodeJSON(data []byte, into any) error { return json.Unmarshal(data, into) }

// canonicalJSON matches internal/intake.CanonicalJSON: encoding/json emits object
// keys in lexical order, and Compact removes insignificant whitespace.
func canonicalJSON(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, data); err != nil {
		return nil, err
	}
	return compact.Bytes(), nil
}

// EncodeRequest turns a scenario into the exact canonical request line the
// adapter will accept, together with its request digest. The digest is computed
// over the canonical object with request_digest removed, which is what the Java
// adapter independently recomputes before it loads any scenario bytes.
func EncodeRequest(scenario Scenario) ([]byte, string, error) {
	steps := make([]any, 0, len(scenario.Steps))
	for index, step := range scenario.Steps {
		encoded := map[string]any{"kind": step.Kind}
		switch step.Kind {
		case "bytes":
			encoded["data_base64"] = step.DataBase64
		case "action":
			if step.Action == "" {
				return nil, "", fmt.Errorf("javabind: scenario %q step %d has no action", scenario.ScenarioID, index)
			}
			encoded["action"] = step.Action
			switch step.Action {
			case "send_text":
				encoded["text"] = step.Text
			case "send_binary", "send_ping", "send_pong":
				encoded["data_base64"] = step.DataBase64
			case "send_fragment":
				if step.Fin == nil {
					return nil, "", fmt.Errorf("javabind: scenario %q step %d omits fin", scenario.ScenarioID, index)
				}
				encoded["opcode"] = step.Opcode
				encoded["data_base64"] = step.DataBase64
				encoded["fin"] = *step.Fin
			case "send_close":
				if step.Code == nil || step.Reason == nil {
					return nil, "", fmt.Errorf("javabind: scenario %q step %d omits close code or reason", scenario.ScenarioID, index)
				}
				encoded["code"] = *step.Code
				encoded["reason"] = *step.Reason
			case "eof":
			default:
				return nil, "", fmt.Errorf("javabind: scenario %q step %d has unknown action %q", scenario.ScenarioID, index, step.Action)
			}
		default:
			return nil, "", fmt.Errorf("javabind: scenario %q step %d has unknown kind %q", scenario.ScenarioID, index, step.Kind)
		}
		steps = append(steps, encoded)
	}
	request := map[string]any{
		"protocol":      OracleProtocol,
		"version":       OracleVersion,
		"request_id":    scenario.ScenarioID,
		"role":          scenario.Role,
		"initial_state": scenario.InitialState,
		"steps":         steps,
		"limits": map[string]any{
			"max_input_bytes":    scenario.Limits.MaxInputBytes,
			"max_buffered_bytes": scenario.Limits.MaxBufferedBytes,
			"max_actions":        scenario.Limits.MaxActions,
			"max_frames":         scenario.Limits.MaxFrames,
			"max_output_bytes":   scenario.Limits.MaxOutputBytes,
		},
	}
	unsigned, err := canonicalJSON(request)
	if err != nil {
		return nil, "", err
	}
	digest := Digest(unsigned)
	request["request_digest"] = digest
	line, err := canonicalJSON(request)
	if err != nil {
		return nil, "", err
	}
	return line, digest, nil
}
