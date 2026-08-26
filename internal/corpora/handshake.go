package corpora

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// websocketGUID is the RFC 6455 section 1.3 accept-derivation constant.
const websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// ComputeAccept derives Sec-WebSocket-Accept from a client key
// (RFC 6455 section 1.3): base64(SHA-1(key + GUID)).
func ComputeAccept(clientKey string) string {
	sum := sha1.Sum([]byte(clientKey + websocketGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// HandshakeConfig carries the configured byte and header limits a handshake
// case is evaluated under.
type HandshakeConfig struct {
	MaxHandshakeBytes  int `json:"max_handshake_bytes"`
	MaxHeaderCount     int `json:"max_header_count"`
	MaxHeaderLineBytes int `json:"max_header_line_bytes"`
}

func (c HandshakeConfig) toMap() map[string]any {
	return map[string]any{
		"max_handshake_bytes":   c.MaxHandshakeBytes,
		"max_header_count":      c.MaxHeaderCount,
		"max_header_line_bytes": c.MaxHeaderLineBytes,
	}
}

// HandshakeContext supplies cross-message context: the client key a server
// response must answer.
type HandshakeContext struct {
	ClientKey string `json:"client_key,omitempty"`
}

// HandshakeExpected is the RFC-derived verdict for one handshake case.
type HandshakeExpected struct {
	Verdict            string   `json:"verdict"`
	RejectCode         string   `json:"reject_code,omitempty"`
	SecWebSocketAccept string   `json:"sec_websocket_accept,omitempty"`
	Basis              []string `json:"basis"`
}

func (e HandshakeExpected) toMap() map[string]any {
	basis := make([]any, len(e.Basis))
	for i, b := range e.Basis {
		basis[i] = b
	}
	out := map[string]any{"verdict": e.Verdict, "basis": basis}
	if e.RejectCode != "" {
		out["reject_code"] = e.RejectCode
	}
	if e.SecWebSocketAccept != "" {
		out["sec_websocket_accept"] = e.SecWebSocketAccept
	}
	return out
}

// HandshakeCase is one committed handshake corpus record.
type HandshakeCase struct {
	CaseID    string            `json:"case_id"`
	Family    string            `json:"family"`
	SeedIndex int               `json:"seed_index"`
	Direction string            `json:"direction"`
	RawBase64 string            `json:"raw_base64"`
	Config    HandshakeConfig   `json:"config"`
	Context   HandshakeContext  `json:"context"`
	Expected  HandshakeExpected `json:"expected"`
}

func (h HandshakeCase) toMap() map[string]any {
	context := map[string]any{}
	if h.Context.ClientKey != "" {
		context["client_key"] = h.Context.ClientKey
	}
	return map[string]any{
		"case_id":    h.CaseID,
		"family":     h.Family,
		"seed_index": h.SeedIndex,
		"direction":  h.Direction,
		"raw_base64": h.RawBase64,
		"config":     h.Config.toMap(),
		"context":    context,
		"expected":   h.Expected.toMap(),
	}
}

// CanonicalLine renders the case as one canonical JSONL line (no newline).
func (h HandshakeCase) CanonicalLine() ([]byte, error) {
	return CanonicalJSON(h.toMap())
}

// MarshalJSON keeps ordinary encoding aligned with the canonical map.
func (h HandshakeCase) MarshalJSON() ([]byte, error) {
	return json.Marshal(h.toMap())
}

// HandshakeBehavior parameterizes the handshake rule engine for mutation
// analysis. Defaults enforce every RFC rule.
type HandshakeBehavior struct {
	RequireMethodGet    bool
	RequireVersion13    bool
	RequireKeyLength16  bool
	RequireAcceptMatch  bool
	RejectDuplicates    bool
	EnforceLimits       bool
	RequireUpgradeValue bool
}

// ReferenceHandshakeBehavior enforces the full RFC 6455 rule chain.
func ReferenceHandshakeBehavior() HandshakeBehavior {
	return HandshakeBehavior{
		RequireMethodGet:    true,
		RequireVersion13:    true,
		RequireKeyLength16:  true,
		RequireAcceptMatch:  true,
		RejectDuplicates:    true,
		EnforceLimits:       true,
		RequireUpgradeValue: true,
	}
}

// DeriveHandshake evaluates raw handshake bytes under the reference rules.
func DeriveHandshake(direction string, raw []byte, config HandshakeConfig,
	context HandshakeContext) (HandshakeExpected, error) {
	return DeriveHandshakeWith(direction, raw, config, context, ReferenceHandshakeBehavior())
}

func reject(code string, basis ...string) HandshakeExpected {
	return HandshakeExpected{Verdict: "reject", RejectCode: code, Basis: basis}
}

// DeriveHandshakeWith evaluates raw handshake bytes under explicit behavior,
// used by calibration mutation analysis.
func DeriveHandshakeWith(direction string, raw []byte, config HandshakeConfig,
	context HandshakeContext, behavior HandshakeBehavior) (HandshakeExpected, error) {
	if direction != "client_request" && direction != "server_response" {
		return HandshakeExpected{}, fmt.Errorf("unsupported handshake direction %q", direction)
	}
	if config.MaxHandshakeBytes < 1 || config.MaxHeaderCount < 1 || config.MaxHeaderLineBytes < 1 {
		return HandshakeExpected{}, fmt.Errorf("handshake limits must be positive")
	}
	if behavior.EnforceLimits && len(raw) > config.MaxHandshakeBytes {
		return reject("HS_LIMIT_TOTAL_BYTES", "rfc6455.section-10-4"), nil
	}
	text := string(raw)
	head, _, found := strings.Cut(text, "\r\n\r\n")
	if !found {
		return HandshakeExpected{Verdict: "incomplete",
			Basis: []string{"rfc6455.section-4-1"}}, nil
	}
	// The head was split on CRLF, so any remaining CR or LF inside a line is
	// a bare line ending (RFC 9112 section 2.2).
	lines := strings.Split(head, "\r\n")
	for _, line := range lines {
		if strings.ContainsAny(line, "\r\n") {
			return reject("HS_BARE_LF", "rfc9112.section-2-2"), nil
		}
	}

	startLine := lines[0]
	headerLines := lines[1:]
	if behavior.EnforceLimits && len(headerLines) > config.MaxHeaderCount {
		return reject("HS_LIMIT_HEADER_COUNT", "rfc6455.section-10-4"), nil
	}

	if direction == "client_request" {
		if verdict, done := checkRequestLine(startLine, behavior); done {
			return verdict, nil
		}
	} else {
		if verdict, done := checkStatusLine(startLine); done {
			return verdict, nil
		}
	}

	headers, verdict, done := parseHeaders(headerLines, config, behavior)
	if done {
		return verdict, nil
	}

	if direction == "client_request" {
		return evaluateClientRequest(headers, behavior), nil
	}
	return evaluateServerResponse(headers, context, behavior), nil
}

func checkRequestLine(line string, behavior HandshakeBehavior) (HandshakeExpected, bool) {
	parts := strings.Split(line, " ")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return reject("HS_MALFORMED_REQUEST_LINE", "rfc9112.section-3"), true
	}
	if behavior.RequireMethodGet && parts[0] != "GET" {
		return reject("HS_METHOD_NOT_GET", "rfc6455.section-4-1"), true
	}
	if parts[2] != "HTTP/1.1" {
		return reject("HS_HTTP_VERSION", "rfc6455.section-4-1"), true
	}
	return HandshakeExpected{}, false
}

func checkStatusLine(line string) (HandshakeExpected, bool) {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return reject("HS_MALFORMED_STATUS_LINE", "rfc9112.section-4"), true
	}
	if parts[0] != "HTTP/1.1" {
		return reject("HS_HTTP_VERSION", "rfc6455.section-4-2-2"), true
	}
	status, err := strconv.Atoi(parts[1])
	if err != nil {
		return reject("HS_MALFORMED_STATUS_LINE", "rfc9112.section-4"), true
	}
	if status != 101 {
		return reject("HS_STATUS_NOT_101", "rfc6455.section-4-2-2"), true
	}
	return HandshakeExpected{}, false
}

func isToken(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("!#$%&'*+-.^_`|~", r):
		default:
			return false
		}
	}
	return true
}

type headerSet struct {
	values map[string][]string
	order  []string
}

func parseHeaders(lines []string, config HandshakeConfig,
	behavior HandshakeBehavior) (headerSet, HandshakeExpected, bool) {
	headers := headerSet{values: map[string][]string{}}
	for _, line := range lines {
		if behavior.EnforceLimits && len(line)+2 > config.MaxHeaderLineBytes {
			return headers, reject("HS_LIMIT_HEADER_LINE_BYTES", "rfc6455.section-10-4"), true
		}
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			return headers, reject("HS_OBS_FOLD", "rfc9112.section-5-2"), true
		}
		name, value, found := strings.Cut(line, ":")
		if !found {
			return headers, reject("HS_MALFORMED_HEADER", "rfc9112.section-5"), true
		}
		if !isToken(name) {
			return headers, reject("HS_HEADER_NAME_NOT_TOKEN", "rfc9112.section-5"), true
		}
		lower := strings.ToLower(name)
		headers.values[lower] = append(headers.values[lower], strings.Trim(value, " \t"))
		headers.order = append(headers.order, lower)
	}
	if behavior.RejectDuplicates {
		for _, single := range []string{"host", "sec-websocket-key", "sec-websocket-version",
			"sec-websocket-accept"} {
			if len(headers.values[single]) > 1 {
				return headers, reject("HS_DUPLICATE_HEADER", "rfc9110.section-5-3"), true
			}
		}
	}
	return headers, HandshakeExpected{}, false
}

func (h headerSet) single(name string) (string, bool) {
	values := h.values[name]
	if len(values) == 0 {
		return "", false
	}
	return values[0], true
}

func (h headerSet) tokenListContains(name, token string) (present, contains bool) {
	values := h.values[name]
	if len(values) == 0 {
		return false, false
	}
	for _, value := range values {
		for _, member := range strings.Split(value, ",") {
			if strings.EqualFold(strings.Trim(member, " \t"), token) {
				return true, true
			}
		}
	}
	return true, false
}

func strictBase64Decode(value string) ([]byte, bool) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, false
	}
	if base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, false
	}
	return decoded, true
}

func evaluateClientRequest(headers headerSet, behavior HandshakeBehavior) HandshakeExpected {
	if _, ok := headers.single("host"); !ok {
		return reject("HS_MISSING_HOST", "rfc6455.section-4-1")
	}
	upgradePresent, upgradeOK := headers.tokenListContains("upgrade", "websocket")
	if !upgradePresent {
		return reject("HS_MISSING_UPGRADE", "rfc6455.section-4-1")
	}
	if behavior.RequireUpgradeValue && !upgradeOK {
		return reject("HS_UPGRADE_VALUE", "rfc6455.section-4-1")
	}
	connectionPresent, connectionOK := headers.tokenListContains("connection", "upgrade")
	if !connectionPresent {
		return reject("HS_MISSING_CONNECTION", "rfc6455.section-4-1")
	}
	if behavior.RequireUpgradeValue && !connectionOK {
		return reject("HS_CONNECTION_VALUE", "rfc6455.section-4-1")
	}
	key, ok := headers.single("sec-websocket-key")
	if !ok {
		return reject("HS_MISSING_KEY", "rfc6455.section-4-1")
	}
	decoded, valid := strictBase64Decode(key)
	if !valid {
		return reject("HS_KEY_NOT_BASE64", "rfc6455.section-4-1")
	}
	if behavior.RequireKeyLength16 && len(decoded) != 16 {
		return reject("HS_KEY_LENGTH", "rfc6455.section-4-1")
	}
	version, ok := headers.single("sec-websocket-version")
	if !ok {
		return reject("HS_MISSING_VERSION", "rfc6455.section-4-1")
	}
	if behavior.RequireVersion13 && version != "13" {
		return reject("HS_VERSION_UNSUPPORTED", "rfc6455.section-4-1")
	}
	return HandshakeExpected{
		Verdict:            "accept",
		SecWebSocketAccept: ComputeAccept(key),
		Basis:              []string{"rfc6455.section-1-3", "rfc6455.section-4-1", "rfc6455.section-4-2-1"},
	}
}

func evaluateServerResponse(headers headerSet, context HandshakeContext,
	behavior HandshakeBehavior) HandshakeExpected {
	upgradePresent, upgradeOK := headers.tokenListContains("upgrade", "websocket")
	if !upgradePresent {
		return reject("HS_MISSING_UPGRADE", "rfc6455.section-4-2-2")
	}
	if behavior.RequireUpgradeValue && !upgradeOK {
		return reject("HS_UPGRADE_VALUE", "rfc6455.section-4-2-2")
	}
	connectionPresent, connectionOK := headers.tokenListContains("connection", "upgrade")
	if !connectionPresent {
		return reject("HS_MISSING_CONNECTION", "rfc6455.section-4-2-2")
	}
	if behavior.RequireUpgradeValue && !connectionOK {
		return reject("HS_CONNECTION_VALUE", "rfc6455.section-4-2-2")
	}
	accept, ok := headers.single("sec-websocket-accept")
	if !ok {
		return reject("HS_MISSING_ACCEPT", "rfc6455.section-4-1")
	}
	if behavior.RequireAcceptMatch && accept != ComputeAccept(context.ClientKey) {
		return reject("HS_ACCEPT_MISMATCH", "rfc6455.section-4-1")
	}
	return HandshakeExpected{
		Verdict: "accept",
		Basis:   []string{"rfc6455.section-1-3", "rfc6455.section-4-2-2"},
	}
}
