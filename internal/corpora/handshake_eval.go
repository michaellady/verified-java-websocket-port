package corpora

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// HandshakeRequestLine renders one executable handshake request line for an
// external target: the raw bytes, direction, limit config, and context, but
// never the expected verdict.
func HandshakeRequestLine(c HandshakeCase) ([]byte, error) {
	context := map[string]any{}
	if c.Context.ClientKey != "" {
		context["client_key"] = c.Context.ClientKey
	}
	return CanonicalJSON(map[string]any{
		"case_id":    c.CaseID,
		"direction":  c.Direction,
		"raw_base64": c.RawBase64,
		"config":     c.Config.toMap(),
		"context":    context,
	})
}

// synthesizeHandshakeResponse builds the response a faithful target would
// produce for a case. Testing and negative controls only; never live
// evidence, and not exported.
func synthesizeHandshakeResponse(c HandshakeCase) ([]byte, error) {
	response := map[string]any{
		"case_id": c.CaseID,
		"verdict": c.Expected.Verdict,
	}
	if c.Expected.RejectCode != "" {
		response["reject_code"] = c.Expected.RejectCode
	}
	if c.Expected.SecWebSocketAccept != "" {
		response["sec_websocket_accept"] = c.Expected.SecWebSocketAccept
	}
	return CanonicalJSON(response)
}

// EvaluateHandshakeResponse compares one response line against a case's
// RFC-derived expectation: verdict, reject code, and accept value must all
// match with presence parity.
func EvaluateHandshakeResponse(c HandshakeCase, responseLine []byte) (bool, string) {
	var response map[string]any
	if err := json.Unmarshal(responseLine, &response); err != nil {
		return false, "response is not valid JSON: " + err.Error()
	}
	if response["case_id"] != c.CaseID {
		return false, fmt.Sprintf("case_id %v does not match %s", response["case_id"], c.CaseID)
	}
	if response["verdict"] != c.Expected.Verdict {
		return false, fmt.Sprintf("verdict %v, expected %s",
			response["verdict"], c.Expected.Verdict)
	}
	rejectCode, hasReject := response["reject_code"]
	if c.Expected.RejectCode != "" {
		if !hasReject || rejectCode != c.Expected.RejectCode {
			return false, fmt.Sprintf("reject_code %v, expected %s",
				rejectCode, c.Expected.RejectCode)
		}
	} else if hasReject {
		return false, "unexpected reject_code"
	}
	accept, hasAccept := response["sec_websocket_accept"]
	if c.Expected.SecWebSocketAccept != "" {
		if !hasAccept || accept != c.Expected.SecWebSocketAccept {
			return false, fmt.Sprintf("sec_websocket_accept %v, expected %s",
				accept, c.Expected.SecWebSocketAccept)
		}
	} else if hasAccept {
		return false, "unexpected sec_websocket_accept"
	}
	return true, ""
}

// EvaluateHandshakeTranscript evaluates a JSONL response transcript
// fail-closed: duplicate responses error, missing and unmatched block.
func EvaluateHandshakeTranscript(cases []HandshakeCase, transcript []byte) (TranscriptReport, error) {
	var report TranscriptReport
	responses := map[string][]byte{}
	for lineNumber, line := range bytes.Split(bytes.TrimRight(transcript, "\n"), []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var envelope struct {
			CaseID string `json:"case_id"`
		}
		if err := json.Unmarshal(line, &envelope); err != nil {
			return report, fmt.Errorf("transcript line %d is not JSON: %w", lineNumber+1, err)
		}
		if envelope.CaseID == "" {
			return report, fmt.Errorf("transcript line %d lacks case_id", lineNumber+1)
		}
		if _, duplicate := responses[envelope.CaseID]; duplicate {
			return report, fmt.Errorf("duplicate response for %s", envelope.CaseID)
		}
		responses[envelope.CaseID] = append([]byte{}, line...)
	}
	known := map[string]bool{}
	for _, c := range cases {
		known[c.CaseID] = true
		line, present := responses[c.CaseID]
		if !present {
			report.Missing++
			continue
		}
		report.Executed++
		passed, detail := EvaluateHandshakeResponse(c, line)
		if passed {
			report.Passed++
		} else {
			report.Failed++
			report.Failures = append(report.Failures, c.CaseID+": "+detail)
		}
	}
	for id := range responses {
		if !known[id] {
			report.Unmatched++
		}
	}
	return report, nil
}
