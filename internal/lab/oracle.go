package lab

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/michaellady/verified-java-websocket-port/internal/intake"
)

const (
	JavaOracleProtocol          = "java-websocket-oracle"
	JavaOracleVersion           = "1.0.0"
	JavaWebSocketRuntimeDigest  = "sha256:eae29213e4f16515639c28957200f011b3967fffcada1962cf0255d24919c22f"
	javaOracleMaximumInputBytes = 1 << 20
	javaOracleMaximumOutput     = 4 << 20
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
	if r.SchemaVersion != JavaOracleVersion || !refPattern.MatchString(r.ScenarioID) || r.Role != OracleClient && r.Role != OracleServer {
		return finding("INVALID_JAVA_ORACLE_REQUEST", "$", "schema, scenario, or role is invalid")
	}
	if r.InitialState != "open" && r.InitialState != "closing" && r.InitialState != "closed" {
		return finding("INVALID_JAVA_ORACLE_REQUEST", "$.initial_state", "initial state is outside the executable Java adapter vocabulary")
	}
	if r.Limits.MaxFrameBytes <= 0 || r.Limits.MaxMessageBytes < r.Limits.MaxFrameBytes || r.Limits.MaxBufferedBytes < r.Limits.MaxFrameBytes || r.Limits.MaxFrameBytes > javaOracleMaximumInputBytes || r.Limits.MaxMessageBytes > javaOracleMaximumInputBytes || r.Limits.MaxBufferedBytes > javaOracleMaximumInputBytes || r.Limits.MaxEvents <= 0 || r.Limits.MaxEvents > 4096 {
		return finding("INVALID_JAVA_ORACLE_REQUEST", "$.limits", "oracle limits are missing, inconsistent, or exceed the Java adapter hard limits")
	}
	if len(r.ByteChunks) > 16384 || len(r.LocalActions) > 1024 || len(r.LocalActions) > r.Limits.MaxEvents {
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
		if action.Kind == ActionSendText && !utf8.Valid(payload) || action.Kind == ActionClose && (!utf8.Valid(payload) || len(payload) > 123) {
			return finding("INVALID_JAVA_ORACLE_REQUEST", fmt.Sprintf("$.local_actions[%d].payload_base64", index), "text and close payloads must be bounded UTF-8")
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

// javaOracleWireRequest is deliberately a map-only shape: Go's JSON encoder
// sorts map keys, matching StrictJson's TreeMap canonicalization in Java.
func (r OracleRequest) javaWireRequest() (map[string]any, string, error) {
	if err := r.Validate(); err != nil {
		return nil, "", err
	}
	steps := make([]any, 0, len(r.ByteChunks)+len(r.LocalActions))
	for _, chunk := range r.ByteChunks {
		steps = append(steps, map[string]any{"data_base64": chunk, "kind": "bytes"})
	}
	for _, local := range r.LocalActions {
		payload, _ := base64.StdEncoding.Strict().DecodeString(local.PayloadBase64)
		step := map[string]any{"kind": "action"}
		switch local.Kind {
		case ActionSendText:
			step["action"] = "send_text"
			step["text"] = string(payload)
		case ActionSendBinary:
			step["action"] = "send_binary"
			step["data_base64"] = local.PayloadBase64
		case ActionPing:
			step["action"] = "send_ping"
			step["data_base64"] = local.PayloadBase64
		case ActionPong:
			step["action"] = "send_pong"
			step["data_base64"] = local.PayloadBase64
		case ActionClose:
			step["action"] = "send_close"
			step["code"] = local.CloseCode
			step["reason"] = string(payload)
		}
		steps = append(steps, step)
	}
	request := map[string]any{
		"initial_state": r.InitialState,
		"limits": map[string]any{
			"max_actions":        len(r.LocalActions),
			"max_buffered_bytes": r.Limits.MaxMessageBytes,
			"max_frames":         r.Limits.MaxEvents,
			"max_input_bytes":    r.Limits.MaxBufferedBytes,
			"max_output_bytes":   javaOracleMaximumOutput,
		},
		"protocol":   JavaOracleProtocol,
		"request_id": r.ScenarioID,
		"role":       r.Role,
		"steps":      steps,
		"version":    JavaOracleVersion,
	}
	unsigned, err := intake.CanonicalJSON(request)
	if err != nil {
		return nil, "", err
	}
	digest := intake.DigestBytes(unsigned)
	request["request_digest"] = digest
	return request, digest, nil
}

// EncodeJavaOracleRequest is the sole Go-to-Java protocol translator.
func EncodeJavaOracleRequest(request OracleRequest) ([]byte, error) {
	wire, _, err := request.javaWireRequest()
	if err != nil {
		return nil, err
	}
	return intake.CanonicalJSON(wire)
}

func (r OracleRequest) Digest() (string, error) {
	_, digest, err := r.javaWireRequest()
	return digest, err
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
	SchemaVersion  string        `json:"schema_version"`
	ScenarioID     string        `json:"scenario_id"`
	RequestDigest  string        `json:"request_digest"`
	ResponseDigest string        `json:"response_digest,omitempty"`
	FinalState     string        `json:"final_state"`
	ConsumedBytes  int64         `json:"consumed_bytes"`
	BufferedBytes  int64         `json:"buffered_bytes"`
	Events         []OracleEvent `json:"events"`
}

func DecodeOracleObservation(data []byte) (OracleObservation, error) {
	var observation OracleObservation
	if err := intake.DecodeStrict(data, &observation); err != nil {
		return OracleObservation{}, err
	}
	return observation, observation.Validate()
}

func (o OracleObservation) Validate() error {
	if o.SchemaVersion != JavaOracleVersion || !refPattern.MatchString(o.ScenarioID) || !isDigest(o.RequestDigest) || o.ResponseDigest != "" && !isDigest(o.ResponseDigest) || o.ConsumedBytes < 0 || o.BufferedBytes < 0 || len(o.Events) > 100000 {
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
		if event.Sequence != index || !validKind || !validState || !validOpcode || event.ConsumedBytes < previousConsumed || event.ConsumedBytes > o.ConsumedBytes || event.BufferedBytes < 0 || event.PayloadDigest != "" && !isDigest(event.PayloadDigest) || event.CloseCode != 0 && (event.CloseCode < 1000 || event.CloseCode > 4999) || len([]byte(event.CloseReason)) > 123 || !utf8.ValidString(event.CloseReason) || event.ErrorCode != "" && !refPattern.MatchString(event.ErrorCode) {
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
		return finding("NONDETERMINISTIC_JAVA_OBSERVATION", "$", "identical scenario bytes produced different Java observations")
	}
	return nil
}

type JavaOracleArtifact struct {
	Path   string
	Digest string
}

type JavaOracleProcessConfig struct {
	JavaExecutable string
	Adapter        JavaOracleArtifact
	Runtime        JavaOracleArtifact
	RuntimeSupport []JavaOracleArtifact
}

type javaOracleResponse struct {
	Close         *javaOracleClose       `json:"close"`
	Counts        *javaOracleCounts      `json:"counts"`
	Error         *javaOracleError       `json:"error"`
	Events        []javaOracleEvent      `json:"events"`
	FinalState    string                 `json:"final_state"`
	Frames        []javaOracleFrame      `json:"frames"`
	InitialState  string                 `json:"initial_state"`
	Outcome       string                 `json:"outcome"`
	Protocol      string                 `json:"protocol"`
	RequestDigest string                 `json:"request_digest"`
	RequestID     string                 `json:"request_id"`
	Role          string                 `json:"role"`
	Runtime       *javaOracleRuntime     `json:"runtime"`
	Transitions   []javaOracleTransition `json:"transitions"`
	Version       string                 `json:"version"`
}

type javaOracleClose struct {
	Code              int    `json:"code"`
	HandshakeComplete bool   `json:"handshake_complete"`
	Origin            string `json:"origin"`
	Reason            string `json:"reason"`
	Remote            bool   `json:"remote"`
}

type javaOracleCounts struct {
	Actions              int   `json:"actions"`
	BufferedBytes        int64 `json:"buffered_bytes"`
	ConsumedBytes        int64 `json:"consumed_bytes"`
	Frames               int   `json:"frames"`
	InputBytes           int64 `json:"input_bytes"`
	MessageBufferedBytes int64 `json:"message_buffered_bytes"`
	WireBufferedBytes    int64 `json:"wire_buffered_bytes"`
}

type javaOracleError struct {
	CloseCode int    `json:"close_code"`
	Code      string `json:"code"`
	Detail    string `json:"detail"`
}

type javaOracleEvent struct {
	Bytes             int    `json:"bytes"`
	Class             string `json:"class"`
	Code              int    `json:"code"`
	DataBase64        string `json:"data_base64"`
	HandshakeComplete bool   `json:"handshake_complete"`
	Opcode            string `json:"opcode"`
	Origin            string `json:"origin"`
	Reason            string `json:"reason"`
	Remote            bool   `json:"remote"`
	Step              int    `json:"step"`
	Text              string `json:"text"`
	Type              string `json:"type"`
	UTF8Bytes         int    `json:"utf8_bytes"`
}

type javaOracleFrame struct {
	Direction     string `json:"direction"`
	Fin           bool   `json:"fin"`
	Masked        bool   `json:"masked"`
	Opcode        string `json:"opcode"`
	PayloadBase64 string `json:"payload_base64"`
	PayloadBytes  int    `json:"payload_bytes"`
	RSV1          bool   `json:"rsv1"`
	RSV2          bool   `json:"rsv2"`
	RSV3          bool   `json:"rsv3"`
	Step          int    `json:"step"`
	WireBytes     int    `json:"wire_bytes"`
}

type javaOracleRuntime struct {
	Artifact string `json:"artifact"`
	SHA256   string `json:"sha256"`
}

type javaOracleTransition struct {
	Cause string `json:"cause"`
	From  string `json:"from"`
	Step  int    `json:"step"`
	To    string `json:"to"`
}

// RunJavaOracle executes the accepted Java adapter as a bounded JSONL process
// and converts its exact response into the comparison contract.
func RunJavaOracle(ctx context.Context, config JavaOracleProcessConfig, request OracleRequest) (OracleObservation, error) {
	if ctx == nil {
		return OracleObservation{}, finding("INVALID_JAVA_ORACLE_PROCESS", "$.context", "context is required")
	}
	encoded, err := EncodeJavaOracleRequest(request)
	if err != nil {
		return OracleObservation{}, err
	}
	requestDigest, err := request.Digest()
	if err != nil {
		return OracleObservation{}, err
	}
	classpath, err := validateJavaOracleProcess(config)
	if err != nil {
		return OracleObservation{}, err
	}
	stdout := boundedProcessBuffer{limit: javaOracleMaximumOutput + 2}
	stderr := boundedProcessBuffer{limit: 4096}
	command := exec.CommandContext(ctx, config.JavaExecutable,
		"-Xms16m", "-Xmx128m", "-Dslf4j.internal.verbosity=ERROR",
		"-cp", strings.Join(classpath, string(os.PathListSeparator)), "OracleMain")
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	command.Stdin = bytes.NewReader(append(encoded, '\n'))
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return OracleObservation{}, finding("JAVA_ORACLE_PROCESS_FAILED", "$.process", boundedDiagnostic(err.Error()+": "+stderr.String()))
	}
	if stdout.exceeded || stderr.exceeded {
		return OracleObservation{}, finding("JAVA_ORACLE_PROCESS_LIMIT_EXCEEDED", "$.process", "Java oracle output exceeded its hard byte limit")
	}
	if stderr.Len() != 0 {
		return OracleObservation{}, finding("JAVA_ORACLE_DIAGNOSTIC_DENIED", "$.stderr", boundedDiagnostic(stderr.String()))
	}
	output := stdout.Bytes()
	if bytes.Count(output, []byte{'\n'}) != 1 || len(output) == 0 || output[len(output)-1] != '\n' {
		return OracleObservation{}, finding("INVALID_JAVA_ORACLE_RESPONSE", "$", "Java oracle must emit exactly one newline-terminated JSON record")
	}
	line := output[:len(output)-1]
	var response javaOracleResponse
	if err := intake.DecodeStrict(line, &response); err != nil {
		return OracleObservation{}, err
	}
	if response.Protocol != JavaOracleProtocol || response.Version != JavaOracleVersion || response.RequestID != request.ScenarioID || response.RequestDigest != requestDigest {
		return OracleObservation{}, finding("JAVA_ORACLE_CONTRACT_DRIFT", "$", "Java response does not bind the exact protocol, scenario, and canonical request")
	}
	if response.Runtime == nil || response.Runtime.Artifact != "org.java-websocket:Java-WebSocket:1.6.0" || response.Runtime.SHA256 != JavaWebSocketRuntimeDigest {
		return OracleObservation{}, finding("JAVA_ORACLE_RUNTIME_DRIFT", "$.runtime", "Java response does not bind the accepted runtime")
	}
	if response.Outcome == "error" {
		if response.Error == nil || !refPattern.MatchString(response.Error.Code) {
			return OracleObservation{}, finding("INVALID_JAVA_ORACLE_RESPONSE", "$.error", "typed Java error is missing or invalid")
		}
		return OracleObservation{}, finding("JAVA_ORACLE_RESPONSE_ERROR", "$.error."+response.Error.Code, boundedDiagnostic(response.Error.Detail))
	}
	if response.Outcome != "ok" || response.Error != nil || response.Counts == nil || response.FinalState == "" || response.InitialState != request.InitialState || response.Role != string(request.Role) || response.Frames == nil || response.Events == nil || response.Transitions == nil {
		return OracleObservation{}, finding("JAVA_ORACLE_CONTRACT_DRIFT", "$", "Java success response is incomplete or inconsistent")
	}
	return normalizeJavaOracleResponse(request, response, intake.DigestBytes(line))
}

func validateJavaOracleProcess(config JavaOracleProcessConfig) ([]string, error) {
	if config.JavaExecutable == "" || filepath.Clean(config.JavaExecutable) != config.JavaExecutable || !filepath.IsAbs(config.JavaExecutable) {
		return nil, finding("INVALID_JAVA_ORACLE_PROCESS", "$.java_executable", "Java executable must be a clean absolute path")
	}
	info, err := os.Stat(config.JavaExecutable)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		return nil, finding("INVALID_JAVA_ORACLE_PROCESS", "$.java_executable", "Java executable must be an executable regular file")
	}
	if config.Runtime.Digest != JavaWebSocketRuntimeDigest {
		return nil, finding("JAVA_ORACLE_RUNTIME_DRIFT", "$.runtime.digest", "runtime digest is not the accepted US-001 identity")
	}
	if len(config.RuntimeSupport) > 2 {
		return nil, finding("INVALID_JAVA_ORACLE_PROCESS", "$.runtime_support", "at most two explicitly pinned runtime support JARs are allowed")
	}
	artifacts := append([]JavaOracleArtifact{config.Adapter, config.Runtime}, config.RuntimeSupport...)
	paths := make([]string, 0, len(artifacts))
	for index, artifact := range artifacts {
		if artifact.Path == "" || filepath.Clean(artifact.Path) != artifact.Path || !filepath.IsAbs(artifact.Path) || !isDigest(artifact.Digest) {
			return nil, finding("INVALID_JAVA_ORACLE_PROCESS", fmt.Sprintf("$.artifacts[%d]", index), "artifact needs a clean absolute path and SHA-256 digest")
		}
		data, err := readBoundedRegular(artifact.Path, 16<<20)
		if err != nil {
			return nil, err
		}
		if intake.DigestBytes(data) != artifact.Digest {
			return nil, finding("JAVA_ORACLE_ARTIFACT_DRIFT", fmt.Sprintf("$.artifacts[%d]", index), "artifact bytes do not match the pinned digest")
		}
		paths = append(paths, artifact.Path)
	}
	return paths, nil
}

func normalizeJavaOracleResponse(request OracleRequest, response javaOracleResponse, responseDigest string) (OracleObservation, error) {
	counts := response.Counts
	if counts.ConsumedBytes < 0 || counts.BufferedBytes < 0 || counts.InputBytes < 0 || counts.Actions < 0 || counts.Frames < 0 || counts.Frames != len(response.Frames) || counts.Actions > len(request.LocalActions) || counts.InputBytes > request.Limits.MaxBufferedBytes || counts.ConsumedBytes > counts.InputBytes || counts.BufferedBytes > request.Limits.MaxMessageBytes {
		return OracleObservation{}, finding("INVALID_JAVA_ORACLE_RESPONSE", "$.counts", "Java response counts are inconsistent or outside request limits")
	}
	events := make([]OracleEvent, 0, len(response.Transitions)+len(response.Frames)+len(response.Events))
	add := func(event OracleEvent) {
		event.Sequence = len(events)
		event.ConsumedBytes = counts.ConsumedBytes
		event.BufferedBytes = counts.BufferedBytes
		if event.State == "" {
			event.State = response.FinalState
		}
		events = append(events, event)
	}
	for _, transition := range response.Transitions {
		if _, ok := oracleStates[transition.From]; !ok {
			return OracleObservation{}, finding("INVALID_JAVA_ORACLE_RESPONSE", "$.transitions", "Java transition uses an unknown state")
		}
		if _, ok := oracleStates[transition.To]; !ok || transition.Step < 0 {
			return OracleObservation{}, finding("INVALID_JAVA_ORACLE_RESPONSE", "$.transitions", "Java transition uses an unknown state or step")
		}
		add(OracleEvent{Kind: "state-transition", State: transition.To})
	}
	for _, frame := range response.Frames {
		payload, err := canonicalBase64(frame.PayloadBase64)
		if err != nil || frame.PayloadBytes != len(payload) || frame.Step < 0 || frame.WireBytes < frame.PayloadBytes || frame.Direction != "inbound" && frame.Direction != "outbound" {
			return OracleObservation{}, finding("INVALID_JAVA_ORACLE_RESPONSE", "$.frames", "Java frame is malformed or inconsistent")
		}
		opcode := normalizeJavaOpcode(frame.Opcode)
		if _, ok := oracleOpcodes[opcode]; !ok || opcode == "" {
			return OracleObservation{}, finding("INVALID_JAVA_ORACLE_RESPONSE", "$.frames.opcode", "Java frame opcode is outside the normalized vocabulary")
		}
		kind := "frame"
		if frame.Direction == "outbound" {
			kind = "transport-write"
		}
		add(OracleEvent{Kind: kind, Opcode: opcode, PayloadDigest: intake.DigestBytes(payload)})
	}
	for _, event := range response.Events {
		normalized, err := normalizeJavaEvent(event)
		if err != nil {
			return OracleObservation{}, err
		}
		add(normalized)
	}
	observation := OracleObservation{
		SchemaVersion: JavaOracleVersion,
		ScenarioID:    request.ScenarioID, RequestDigest: response.RequestDigest,
		ResponseDigest: responseDigest, FinalState: response.FinalState,
		ConsumedBytes: counts.ConsumedBytes, BufferedBytes: counts.BufferedBytes, Events: events,
	}
	if err := observation.Validate(); err != nil {
		return OracleObservation{}, err
	}
	return observation, nil
}

func normalizeJavaEvent(event javaOracleEvent) (OracleEvent, error) {
	if event.Step < 0 || event.Bytes < 0 || event.UTF8Bytes < 0 {
		return OracleEvent{}, finding("INVALID_JAVA_ORACLE_RESPONSE", "$.events", "Java event has invalid counts or step")
	}
	result := OracleEvent{Kind: "frame", Opcode: normalizeJavaOpcode(event.Opcode)}
	switch event.Type {
	case "text":
		result.Kind, result.Opcode, result.PayloadDigest = "message", "text", intake.DigestBytes([]byte(event.Text))
		if event.UTF8Bytes != len([]byte(event.Text)) {
			return OracleEvent{}, finding("INVALID_JAVA_ORACLE_RESPONSE", "$.events.utf8_bytes", "Java text event byte count is inconsistent")
		}
	case "binary", "ping", "pong":
		payload, err := canonicalBase64(event.DataBase64)
		if err != nil || event.Bytes != len(payload) {
			return OracleEvent{}, finding("INVALID_JAVA_ORACLE_RESPONSE", "$.events.data_base64", "Java semantic payload is inconsistent")
		}
		result.PayloadDigest = intake.DigestBytes(payload)
		result.Opcode = event.Type
		if event.Type == "binary" {
			result.Kind = "message"
		}
	case "close", "close_initiated", "eof", "runtime_close", "runtime_closing", "runtime_close_initiated":
		result.Kind, result.Opcode = "close", "close"
		result.CloseCode, result.CloseReason = event.Code, event.Reason
	case "listener_error":
		result.Kind, result.ErrorCode = "error", event.Class
	case "send_text", "send_binary", "send_ping", "send_pong", "send_fragment", "echo_close", "write_demand":
		result.Kind = "transport-write"
	case "open":
		result.Kind = "state-transition"
	case "input_chunk":
		result.Kind = "frame"
	default:
		return OracleEvent{}, finding("INVALID_JAVA_ORACLE_RESPONSE", "$.events.type", "Java event type is outside the normalized vocabulary")
	}
	if result.Opcode != "" {
		if _, ok := oracleOpcodes[result.Opcode]; !ok {
			return OracleEvent{}, finding("INVALID_JAVA_ORACLE_RESPONSE", "$.events.opcode", "Java event opcode is outside the normalized vocabulary")
		}
	}
	return result, nil
}

func canonicalBase64(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, finding("INVALID_JAVA_ORACLE_RESPONSE", "$", "Java response contains noncanonical base64")
	}
	return decoded, nil
}

func normalizeJavaOpcode(value string) string {
	switch value {
	case "continuous":
		return "continuation"
	case "closing":
		return "close"
	default:
		return value
	}
}

type boundedProcessBuffer struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func (b *boundedProcessBuffer) Write(data []byte) (int, error) {
	original := len(data)
	remaining := b.limit - b.Len()
	if remaining <= 0 {
		b.exceeded = true
		return original, nil
	}
	if len(data) > remaining {
		_, _ = b.Buffer.Write(data[:remaining])
		b.exceeded = true
		return original, nil
	}
	_, _ = b.Buffer.Write(data)
	return original, nil
}

func boundedDiagnostic(value string) string {
	value = strings.Map(func(character rune) rune {
		if character == '\n' || character == '\r' || character == '\t' || character < 0x20 || character == 0x7f {
			return ' '
		}
		return character
	}, value)
	value = strings.TrimSpace(value)
	if len(value) > 300 {
		value = value[:300]
	}
	if value == "" {
		return "Java oracle failed without a diagnostic"
	}
	return value
}
