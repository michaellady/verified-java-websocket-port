package corpora

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Oracle protocol pins matching the vendored java-oracle adapter.
const (
	oracleProtocol        = "java-websocket-oracle"
	oracleVersion         = "1.0.0"
	oracleRuntimeSHA256   = "eae29213e4f16515639c28957200f011b3967fffcada1962cf0255d24919c22f"
	oracleRuntimeArtifact = "org.java-websocket:Java-WebSocket:1.6.0"
)

// OracleRequest projects a neutral scenario onto the java-oracle JSONL
// request protocol, including the canonical request digest the oracle
// recomputes and verifies.
func OracleRequest(sc Scenario) (map[string]any, error) {
	steps := make([]any, len(sc.Core.Steps))
	for i, step := range sc.Core.Steps {
		m, err := step.toMap()
		if err != nil {
			return nil, err
		}
		steps[i] = m
	}
	request := map[string]any{
		"initial_state": sc.Core.InitialState,
		"limits":        sc.Core.Limits.toMap(),
		"protocol":      oracleProtocol,
		"version":       oracleVersion,
		"request_id":    sc.ScenarioID,
		"role":          sc.Core.Role,
		"steps":         steps,
	}
	canonical, err := CanonicalJSON(request)
	if err != nil {
		return nil, err
	}
	request["request_digest"] = DigestSHA256(canonical)
	return request, nil
}

// OracleRequestLine renders one JSONL request line (no trailing newline).
func OracleRequestLine(sc Scenario) ([]byte, error) {
	request, err := OracleRequest(sc)
	if err != nil {
		return nil, err
	}
	return CanonicalJSON(request)
}

// synthesizeResponse builds the oracle-shaped response a faithful target
// would produce for a scenario. It exists to exercise the evaluator and the
// stub negative control; it is never live evidence and is not exported.
func synthesizeResponse(sc Scenario) ([]byte, error) {
	request, err := OracleRequest(sc)
	if err != nil {
		return nil, err
	}
	base := map[string]any{
		"outcome":        string(sc.Expected.Outcome),
		"protocol":       oracleProtocol,
		"request_digest": request["request_digest"],
		"request_id":     sc.ScenarioID,
		"version":        oracleVersion,
	}
	runtime := map[string]any{
		"artifact": oracleRuntimeArtifact,
		"sha256":   oracleRuntimeSHA256,
	}
	if sc.Expected.Outcome == "ok" {
		var closeValue any
		if sc.Expected.Close != nil {
			closeValue = sc.Expected.Close
		}
		base["close"] = closeValue
		base["counts"] = sc.Expected.Counts.toMap()
		base["events"] = anySlice(sc.Expected.Events)
		base["final_state"] = sc.Expected.FinalState
		base["frames"] = anySlice(sc.Expected.Frames)
		base["initial_state"] = sc.Core.InitialState
		base["role"] = sc.Core.Role
		base["runtime"] = runtime
		base["transitions"] = anySlice(sc.Expected.Transitions)
		return CanonicalJSON(base)
	}
	errorMap := map[string]any{
		"code":   sc.Expected.Error.Code,
		"detail": "synthesized rejection detail",
	}
	if sc.Expected.Error.CloseCode != nil {
		errorMap["close_code"] = *sc.Expected.Error.CloseCode
	}
	base["error"] = errorMap
	base["counts"] = Counts{}.toMap()
	base["final_state"] = sc.Expected.FinalState
	base["runtime"] = runtime
	return CanonicalJSON(base)
}

// synthesizeStubResponse models an inert target: it answers the protocol
// envelope but reports no behavior at all.
func synthesizeStubResponse(sc Scenario) ([]byte, error) {
	request, err := OracleRequest(sc)
	if err != nil {
		return nil, err
	}
	return CanonicalJSON(map[string]any{
		"outcome":        "ok",
		"protocol":       oracleProtocol,
		"request_digest": request["request_digest"],
		"request_id":     sc.ScenarioID,
		"version":        oracleVersion,
		"close":          nil,
		"counts":         Counts{}.toMap(),
		"events":         []any{},
		"final_state":    sc.Core.InitialState,
		"frames":         []any{},
		"initial_state":  sc.Core.InitialState,
		"role":           sc.Core.Role,
		"runtime": map[string]any{
			"artifact": "stub-target",
			"sha256":   "sha256:" + zero64(),
		},
		"transitions": []any{},
	})
}

func fieldCanonical(value any) (string, error) {
	canonical, err := canonicalizeJSONValue(value)
	if err != nil {
		return "", err
	}
	return string(canonical), nil
}

// EvaluateOracleResponse compares one response line against a scenario's
// expectation. Success outcomes compare the full semantic surface; error
// outcomes compare the rejection code, close code, and final state.
func EvaluateOracleResponse(sc Scenario, responseLine []byte) (bool, string) {
	var response map[string]any
	decoder := json.NewDecoder(bytes.NewReader(responseLine))
	if err := decoder.Decode(&response); err != nil {
		return false, "response is not valid JSON: " + err.Error()
	}
	request, err := OracleRequest(sc)
	if err != nil {
		return false, "request projection failed: " + err.Error()
	}
	if response["request_id"] != sc.ScenarioID {
		return false, fmt.Sprintf("request_id %v does not match %s",
			response["request_id"], sc.ScenarioID)
	}
	if response["request_digest"] != request["request_digest"] {
		return false, "request_digest does not bind this scenario"
	}
	if response["protocol"] != oracleProtocol || response["version"] != oracleVersion {
		return false, "protocol pin mismatch"
	}
	if response["outcome"] != sc.Expected.Outcome {
		return false, fmt.Sprintf("outcome %v, expected %s",
			response["outcome"], sc.Expected.Outcome)
	}
	if sc.Expected.Outcome == "error" {
		errorMap, _ := response["error"].(map[string]any)
		if errorMap == nil {
			return false, "error outcome without error object"
		}
		if errorMap["code"] != sc.Expected.Error.Code {
			return false, fmt.Sprintf("error code %v, expected %s",
				errorMap["code"], sc.Expected.Error.Code)
		}
		if sc.Expected.Error.CloseCode != nil {
			closeCode, isNumber := errorMap["close_code"].(float64)
			if !isNumber || int(closeCode) != *sc.Expected.Error.CloseCode {
				return false, fmt.Sprintf("close_code %v, expected %d",
					errorMap["close_code"], *sc.Expected.Error.CloseCode)
			}
		} else if _, present := errorMap["close_code"]; present {
			return false, "unexpected close_code on error"
		}
		if state, present := response["final_state"]; present &&
			state != sc.Expected.FinalState {
			return false, fmt.Sprintf("final_state %v, expected %s",
				state, sc.Expected.FinalState)
		}
		return true, ""
	}

	expectedFields := map[string]any{
		"close":         nil,
		"counts":        sc.Expected.Counts.toMap(),
		"events":        anySlice(sc.Expected.Events),
		"final_state":   sc.Expected.FinalState,
		"frames":        anySlice(sc.Expected.Frames),
		"initial_state": sc.Core.InitialState,
		"role":          sc.Core.Role,
		"transitions":   anySlice(sc.Expected.Transitions),
	}
	if sc.Expected.Close != nil {
		expectedFields["close"] = sc.Expected.Close
	}
	for field, want := range expectedFields {
		got, present := response[field]
		if !present {
			return false, "response lacks " + field
		}
		wantCanonical, err := fieldCanonical(want)
		if err != nil {
			return false, "expected field not canonicalizable: " + err.Error()
		}
		gotCanonical, err := fieldCanonical(got)
		if err != nil {
			return false, field + " not canonicalizable: " + err.Error()
		}
		if wantCanonical != gotCanonical {
			return false, fmt.Sprintf("%s diverges: got %s want %s",
				field, clip(gotCanonical), clip(wantCanonical))
		}
	}
	return true, ""
}

func clip(value string) string {
	if len(value) <= 160 {
		return value
	}
	return value[:160] + "..."
}

// TranscriptReport reconciles one execution transcript with a scenario set.
type TranscriptReport struct {
	Executed  int      `json:"executed"`
	Passed    int      `json:"passed"`
	Failed    int      `json:"failed"`
	Missing   int      `json:"missing"`
	Unmatched int      `json:"unmatched"`
	Failures  []string `json:"failures,omitempty"`
}

// Reconciled reports whether every scenario executed exactly once and passed.
func (r TranscriptReport) Reconciled() bool {
	return r.Executed > 0 && r.Missing == 0 && r.Unmatched == 0 && r.Failed == 0
}

// EvaluateTranscript evaluates a JSONL response transcript fail-closed:
// duplicate responses error, missing and unmatched responses block.
func EvaluateTranscript(scenarios []Scenario, transcript []byte) (TranscriptReport, error) {
	var report TranscriptReport
	responses := map[string][]byte{}
	for lineNumber, line := range bytes.Split(bytes.TrimRight(transcript, "\n"), []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var envelope struct {
			RequestID string `json:"request_id"`
		}
		if err := json.Unmarshal(line, &envelope); err != nil {
			return report, fmt.Errorf("transcript line %d is not JSON: %w", lineNumber+1, err)
		}
		if envelope.RequestID == "" {
			return report, fmt.Errorf("transcript line %d lacks request_id", lineNumber+1)
		}
		if _, duplicate := responses[envelope.RequestID]; duplicate {
			return report, fmt.Errorf("duplicate response for %s", envelope.RequestID)
		}
		responses[envelope.RequestID] = append([]byte{}, line...)
	}
	known := map[string]bool{}
	for _, sc := range scenarios {
		known[sc.ScenarioID] = true
		line, present := responses[sc.ScenarioID]
		if !present {
			report.Missing++
			continue
		}
		report.Executed++
		passed, detail := EvaluateOracleResponse(sc, line)
		if passed {
			report.Passed++
		} else {
			report.Failed++
			report.Failures = append(report.Failures, sc.ScenarioID+": "+detail)
		}
	}
	for id := range responses {
		if !known[id] {
			report.Unmatched++
		}
	}
	return report, nil
}
