package lab

import (
	"encoding/base64"
	"fmt"
	"slices"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

type OracleRole string

const (
	OracleClient OracleRole = "client"
	OracleServer OracleRole = "server"
)

type LocalActionKind string

const (
	ActionSendText   LocalActionKind = "send-text"
	ActionSendBinary LocalActionKind = "send-binary"
	ActionPing       LocalActionKind = "ping"
	ActionPong       LocalActionKind = "pong"
	ActionClose      LocalActionKind = "close"
)

type OracleLimits struct {
	MaxFrameBytes    int64 `json:"max_frame_bytes"`
	MaxMessageBytes  int64 `json:"max_message_bytes"`
	MaxBufferedBytes int64 `json:"max_buffered_bytes"`
	MaxEvents        int   `json:"max_events"`
}

type LocalAction struct {
	Kind          LocalActionKind `json:"kind"`
	PayloadBase64 string          `json:"payload_base64"`
	CloseCode     int             `json:"close_code"`
}

type OracleRequest struct {
	SchemaVersion string        `json:"schema_version"`
	ScenarioID    string        `json:"scenario_id"`
	Role          OracleRole    `json:"role"`
	InitialState  string        `json:"initial_state"`
	ByteChunks    []string      `json:"byte_chunks_base64"`
	LocalActions  []LocalAction `json:"local_actions"`
	Limits        OracleLimits  `json:"limits"`
}

func DecodeOracleRequest(data []byte) (OracleRequest, error) {
	var request OracleRequest
	if err := intake.DecodeStrict(data, &request); err != nil {
		return OracleRequest{}, err
	}
	return request, request.Validate()
}

func (r OracleRequest) Validate() error {
	if r.SchemaVersion != "1.0.0" || !refPattern.MatchString(r.ScenarioID) || r.Role != OracleClient && r.Role != OracleServer {
		return finding("INVALID_JAVA_ORACLE_REQUEST", "$", "schema, scenario, or role is invalid")
	}
	if r.InitialState != "not-yet-connected" && r.InitialState != "open" && r.InitialState != "closing" {
		return finding("INVALID_JAVA_ORACLE_REQUEST", "$.initial_state", "initial state is outside the adapter vocabulary")
	}
	if r.Limits.MaxFrameBytes <= 0 || r.Limits.MaxMessageBytes < r.Limits.MaxFrameBytes || r.Limits.MaxBufferedBytes < r.Limits.MaxFrameBytes || r.Limits.MaxFrameBytes > 64<<20 || r.Limits.MaxMessageBytes > 256<<20 || r.Limits.MaxBufferedBytes > 256<<20 || r.Limits.MaxEvents <= 0 || r.Limits.MaxEvents > 100000 {
		return finding("INVALID_JAVA_ORACLE_REQUEST", "$.limits", "oracle limits are missing, inconsistent, or unbounded")
	}
	if len(r.ByteChunks) > 100000 || len(r.LocalActions) > 100000 {
		return finding("INPUT_TOO_LARGE", "$", "oracle request has too many chunks or actions")
	}
	var inputBytes int64
	for index, chunk := range r.ByteChunks {
		decoded, err := base64.StdEncoding.Strict().DecodeString(chunk)
		if err != nil || len(decoded) == 0 {
			return finding("INVALID_JAVA_ORACLE_REQUEST", fmt.Sprintf("$.byte_chunks_base64[%d]", index), "chunk must be canonical nonempty base64")
		}
		if base64.StdEncoding.EncodeToString(decoded) != chunk || inputBytes > r.Limits.MaxBufferedBytes-int64(len(decoded)) {
			return finding("INVALID_JAVA_ORACLE_REQUEST", fmt.Sprintf("$.byte_chunks_base64[%d]", index), "chunk encoding is noncanonical or exceeds the byte budget")
		}
		inputBytes += int64(len(decoded))
	}
	for index, action := range r.LocalActions {
		if action.Kind != ActionSendText && action.Kind != ActionSendBinary && action.Kind != ActionPing && action.Kind != ActionPong && action.Kind != ActionClose {
			return finding("INVALID_JAVA_ORACLE_REQUEST", fmt.Sprintf("$.local_actions[%d].kind", index), "local action is outside the adapter vocabulary")
		}
		payload, err := base64.StdEncoding.Strict().DecodeString(action.PayloadBase64)
		if err != nil || base64.StdEncoding.EncodeToString(payload) != action.PayloadBase64 || int64(len(payload)) > r.Limits.MaxFrameBytes {
			return finding("INVALID_JAVA_ORACLE_REQUEST", fmt.Sprintf("$.local_actions[%d].payload_base64", index), "action payload is invalid or oversized")
		}
		if action.Kind == ActionClose {
			if action.CloseCode < 1000 || action.CloseCode > 4999 {
				return finding("INVALID_JAVA_ORACLE_REQUEST", fmt.Sprintf("$.local_actions[%d].close_code", index), "close action requires an explicit wire-range code")
			}
		} else if action.CloseCode != 0 {
			return finding("INVALID_JAVA_ORACLE_REQUEST", fmt.Sprintf("$.local_actions[%d].close_code", index), "non-close action cannot carry a close code")
		}
	}
	return nil
}

func (r OracleRequest) Digest() (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	data, err := intake.CanonicalJSON(r)
	if err != nil {
		return "", err
	}
	return intake.DigestBytes(data), nil
}

type OracleEvent struct {
	Sequence      int    `json:"sequence"`
	Kind          string `json:"kind"`
	State         string `json:"state"`
	Opcode        string `json:"opcode"`
	PayloadDigest string `json:"payload_digest"`
	CloseCode     int    `json:"close_code"`
	CloseReason   string `json:"close_reason"`
	ErrorCode     string `json:"error_code"`
	ConsumedBytes int64  `json:"consumed_bytes"`
	BufferedBytes int64  `json:"buffered_bytes"`
}

var oracleEventKinds = map[string]struct{}{
	"state-transition": {}, "frame": {}, "message": {}, "transport-write": {}, "close": {}, "error": {},
}

var oracleStates = map[string]struct{}{
	"": {}, "not-yet-connected": {}, "open": {}, "closing": {}, "closed": {},
}

var oracleOpcodes = map[string]struct{}{
	"": {}, "continuation": {}, "text": {}, "binary": {}, "close": {}, "ping": {}, "pong": {},
}

type OracleObservation struct {
	SchemaVersion string        `json:"schema_version"`
	ScenarioID    string        `json:"scenario_id"`
	RequestDigest string        `json:"request_digest"`
	FinalState    string        `json:"final_state"`
	ConsumedBytes int64         `json:"consumed_bytes"`
	BufferedBytes int64         `json:"buffered_bytes"`
	Events        []OracleEvent `json:"events"`
}

func DecodeOracleObservation(data []byte) (OracleObservation, error) {
	var observation OracleObservation
	if err := intake.DecodeStrict(data, &observation); err != nil {
		return OracleObservation{}, err
	}
	return observation, observation.Validate()
}

func (o OracleObservation) Validate() error {
	if o.SchemaVersion != "1.0.0" || !refPattern.MatchString(o.ScenarioID) || !isDigest(o.RequestDigest) || o.ConsumedBytes < 0 || o.BufferedBytes < 0 || len(o.Events) > 100000 {
		return finding("INVALID_JAVA_ORACLE_OBSERVATION", "$", "observation identity, counts, or bounds are invalid")
	}
	if o.FinalState != "not-yet-connected" && o.FinalState != "open" && o.FinalState != "closing" && o.FinalState != "closed" {
		return finding("INVALID_JAVA_ORACLE_OBSERVATION", "$.final_state", "final state is outside the normalized vocabulary")
	}
	var previousConsumed int64
	for index, event := range o.Events {
		_, validKind := oracleEventKinds[event.Kind]
		_, validState := oracleStates[event.State]
		_, validOpcode := oracleOpcodes[event.Opcode]
		if event.Sequence != index || !validKind || !validState || !validOpcode || event.ConsumedBytes < previousConsumed || event.ConsumedBytes > o.ConsumedBytes || event.BufferedBytes < 0 || event.PayloadDigest != "" && !isDigest(event.PayloadDigest) || event.CloseCode != 0 && (event.CloseCode < 1000 || event.CloseCode > 4999) || len(event.CloseReason) > 123 || event.ErrorCode != "" && !refPattern.MatchString(event.ErrorCode) {
			return finding("INVALID_JAVA_ORACLE_OBSERVATION", fmt.Sprintf("$.events[%d]", index), "event order, identity, digest, or byte counters are invalid")
		}
		previousConsumed = event.ConsumedBytes
	}
	if len(o.Events) > 0 {
		last := o.Events[len(o.Events)-1]
		if last.ConsumedBytes != o.ConsumedBytes || last.BufferedBytes != o.BufferedBytes {
			return finding("INVALID_JAVA_ORACLE_OBSERVATION", "$.events", "terminal event counters do not match the observation")
		}
	}
	return nil
}

func (o OracleObservation) Digest() (string, error) {
	if err := o.Validate(); err != nil {
		return "", err
	}
	data, err := intake.CanonicalJSON(o)
	if err != nil {
		return "", err
	}
	return intake.DigestBytes(data), nil
}

// CompareJavaObservations is exact: identical requests must produce identical
// normalized observations. The caller decides what to do with stable Java/RFC
// disagreements; this function only detects run-to-run drift.
func CompareJavaObservations(first, second OracleObservation) error {
	if err := first.Validate(); err != nil {
		return err
	}
	if err := second.Validate(); err != nil {
		return err
	}
	if first.ScenarioID != second.ScenarioID || first.RequestDigest != second.RequestDigest {
		return finding("JAVA_OBSERVATION_SCOPE_MISMATCH", "$", "observations do not bind the same scenario and request")
	}
	left, err := intake.CanonicalJSON(first)
	if err != nil {
		return err
	}
	right, err := intake.CanonicalJSON(second)
	if err != nil {
		return err
	}
	if !slices.Equal(left, right) {
		return finding("NONDETERMINISTIC_JAVA_OBSERVATION", "$.events", "identical scenario bytes produced different normalized observations")
	}
	return nil
}
