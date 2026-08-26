package corpora

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// This file is the Go side of the Java-runtime handshake live adapter. It
// contains three tightly coupled pieces:
//
//  1. HandshakeOracleRequestLine — the wire projection of a handshake case
//     onto the java-oracle handshake protocol (digest-bound JSONL).
//  2. ExpectedJavaHandshakeObservable — a line-referenced transcription of the
//     quarantined Java-WebSocket 1.6.0 handshake path. It predicts, per case,
//     the observable the real runtime produces. Every branch cites the
//     quarantined source (revision da3cf2a777aed862f2f5b5cf060cae7969958667).
//  3. EvaluateHandshakeLiveTranscript — the fail-closed evaluator that scores
//     a java-oracle handshake transcript against those predictions and
//     surfaces every RFC-vs-Java divergence explicitly.
//
// The mapping is derived from source, never invented: where the Java runtime
// cannot observably distinguish HS_* verdicts (or disagrees with the RFC
// model outright), HandshakeVerdictMapping records that granularity mismatch
// and evidence/us005-handshake-live-mapping.json commits it. The Java-side
// harness tests execute the same families against the real jar.

// Handshake oracle protocol pins. The protocol id is distinct from the
// behavior protocol so behavior request digests are untouched.
const (
	handshakeOracleProtocol = "java-websocket-handshake-oracle"
	handshakeOracleVersion  = "1.0.0"
)

// Java-runtime observable classes and reject channels. On a real server every
// rejection collapses to one wire observable (an HTTP error response plus a
// PROTOCOL_ERROR close: WebSocketImpl.closeConnectionDueToWrongHandshake,
// WebSocketImpl.java:426-429); the channel below is the draft-API-level
// distinction the adapter can still observe and report.
const (
	JavaObservableAccept      = "accept"
	JavaObservableReject      = "reject"
	JavaObservableIncomplete  = "incomplete"
	JavaObservableConditional = "conditional"

	// InvalidHandshakeException thrown while parsing or while building the
	// server response (Draft.java:95-132, Draft_6455.java:437-440).
	JavaRejectInvalidHandshake = "invalid_handshake"
	// HandshakeState.NOT_MATCHED returned by acceptHandshakeAsServer or
	// acceptHandshakeAsClient (Draft_6455.java:262-286, 306-343).
	JavaRejectNotMatched = "not_matched"

	// InvalidHandshakeException always carries CloseFrame.PROTOCOL_ERROR
	// (InvalidHandshakeException.java), and the NOT_MATCHED paths close with
	// CloseFrame.PROTOCOL_ERROR too (WebSocketImpl.java:313, 332, 363).
	javaHandshakeCloseCode = 1002
)

// HandshakeOracleRequest projects a handshake case onto the java-oracle
// handshake wire protocol, including the canonical request digest the oracle
// recomputes and verifies (same digest scheme as the behavior protocol).
func HandshakeOracleRequest(c HandshakeCase) (map[string]any, error) {
	context := map[string]any{}
	if c.Context.ClientKey != "" {
		context["client_key"] = c.Context.ClientKey
	}
	request := map[string]any{
		"case_id":    c.CaseID,
		"config":     c.Config.toMap(),
		"context":    context,
		"direction":  c.Direction,
		"protocol":   handshakeOracleProtocol,
		"raw_base64": c.RawBase64,
		"version":    handshakeOracleVersion,
	}
	canonical, err := CanonicalJSON(request)
	if err != nil {
		return nil, err
	}
	request["request_digest"] = DigestSHA256(canonical)
	return request, nil
}

// HandshakeOracleRequestLine renders one JSONL wire request (no newline).
func HandshakeOracleRequestLine(c HandshakeCase) ([]byte, error) {
	request, err := HandshakeOracleRequest(c)
	if err != nil {
		return nil, err
	}
	return CanonicalJSON(request)
}

// JavaHandshakeObservable is the runtime-observable outcome the quarantined
// Java-WebSocket 1.6.0 source produces for one handshake input.
type JavaHandshakeObservable struct {
	Observable         string
	RejectChannel      string
	SecWebSocketAccept string
}

// javaHeaderSet mirrors HandshakedataImpl1: a case-insensitive field map
// (TreeMap with String.CASE_INSENSITIVE_ORDER, HandshakedataImpl1.java:50)
// whose duplicate puts were already joined by the parser.
type javaHeaderSet map[string]string

func (h javaHeaderSet) get(name string) string {
	return h[strings.ToLower(name)]
}

func (h javaHeaderSet) has(name string) bool {
	_, present := h[strings.ToLower(name)]
	return present
}

// javaReadLine mirrors Draft.readLine (Draft.java:70-88): a line terminates
// only on the exact CRLF pair; a bare LF or bare CR stays inside the line.
// The second result reports whether a terminator was found.
func javaReadLine(input []byte, at int) (line string, next int, found bool) {
	for i := at + 1; i < len(input); i++ {
		if input[i-1] == '\r' && input[i] == '\n' {
			return string(input[at : i-1]), i + 1, true
		}
	}
	return "", at, false
}

// javaTrim mirrors String.trim: both ends stripped of chars <= U+0020.
func javaTrim(value string) string {
	return strings.TrimFunc(value, func(r rune) bool { return r <= ' ' })
}

// javaParseHandshake mirrors Draft.translateHandshakeHttp
// (Draft.java:95-132): first line split(" ", 3), headers split(":", 2) with
// leading-space stripping and "; " duplicate joining, terminated by an empty
// line. It reports incomplete when either the first line or the terminating
// empty line is missing.
func javaParseHandshake(raw []byte) (firstLine []string, headers javaHeaderSet,
	observable *JavaHandshakeObservable) {
	incomplete := &JavaHandshakeObservable{Observable: JavaObservableIncomplete}
	rejectParse := &JavaHandshakeObservable{Observable: JavaObservableReject,
		RejectChannel: JavaRejectInvalidHandshake}

	line, at, found := javaReadLine(raw, 0)
	if !found {
		// Draft.java:100-102: IncompleteHandshakeException.
		return nil, nil, incomplete
	}
	// Draft.java:104-107: line.split(" ", 3) must yield exactly 3 tokens.
	firstLine = strings.SplitN(line, " ", 3)
	if len(firstLine) != 3 {
		return nil, nil, rejectParse
	}
	headers = javaHeaderSet{}
	for {
		line, next, found := javaReadLine(raw, at)
		if !found {
			// Draft.java:128-130: headers not terminated by an empty line.
			return nil, nil, incomplete
		}
		at = next
		if line == "" {
			return firstLine, headers, nil
		}
		// Draft.java:115-125: split(":", 2); no colon rejects; the value has
		// leading spaces (only spaces) stripped; duplicates join with "; ".
		pair := strings.SplitN(line, ":", 2)
		if len(pair) != 2 {
			return nil, nil, rejectParse
		}
		value := strings.TrimLeft(pair[1], " ")
		key := strings.ToLower(pair[0])
		if existing, present := headers[key]; present {
			headers[key] = existing + "; " + value
		} else {
			headers[key] = value
		}
	}
}

// javaReadVersion mirrors Draft.readVersion (Draft.java:329-341):
// Integer.parseInt over the trimmed Sec-WebSocket-Version value, -1 on any
// parse failure or absence.
func javaReadVersion(headers javaHeaderSet) int {
	value := headers.get("Sec-WebSocket-Version")
	if len(value) == 0 {
		return -1
	}
	parsed, err := strconv.Atoi(javaTrim(value))
	if err != nil {
		return -1
	}
	return parsed
}

// javaEqualsIgnoreCase mirrors String.equalsIgnoreCase for the ASCII inputs
// this model accepts.
func javaEqualsIgnoreCase(a, b string) bool {
	return strings.EqualFold(a, b)
}

// ExpectedJavaHandshakeObservable predicts the observable the real
// Java-WebSocket 1.6.0 runtime produces for one handshake case. It is a
// transcription of the quarantined source, validated against the real jar by
// the java-oracle handshake harness tests. Non-ASCII input is outside the
// calibrated scope and fails closed.
func ExpectedJavaHandshakeObservable(c HandshakeCase) (JavaHandshakeObservable, error) {
	raw, err := base64.StdEncoding.DecodeString(c.RawBase64)
	if err != nil {
		return JavaHandshakeObservable{}, fmt.Errorf("case %s: raw_base64: %w", c.CaseID, err)
	}
	for _, b := range raw {
		if b > 0x7f {
			return JavaHandshakeObservable{}, fmt.Errorf(
				"case %s: non-ASCII handshake bytes are outside the calibrated mapping",
				c.CaseID)
		}
	}
	switch c.Direction {
	case "client_request":
		return javaServerObservable(raw), nil
	case "server_response":
		return javaClientObservable(raw, c.Context.ClientKey), nil
	}
	return JavaHandshakeObservable{}, fmt.Errorf("case %s: unsupported direction %q",
		c.CaseID, c.Direction)
}

// javaServerObservable mirrors the server side of
// WebSocketImpl.decodeHandshake (WebSocketImpl.java:269-315): translate,
// acceptHandshakeAsServer, then postProcessHandshakeResponseAsServer. The
// Java server never enforces handshake byte/header limits and never checks
// Host, Upgrade, Connection, or the key encoding.
func javaServerObservable(raw []byte) JavaHandshakeObservable {
	firstLine, headers, early := javaParseHandshake(raw)
	if early != nil {
		return *early
	}
	// Draft.java:141-155 (translateHandshakeHttpServer): method and HTTP
	// version, both equalsIgnoreCase.
	if !javaEqualsIgnoreCase(firstLine[0], "GET") ||
		!javaEqualsIgnoreCase(firstLine[2], "HTTP/1.1") {
		return JavaHandshakeObservable{Observable: JavaObservableReject,
			RejectChannel: JavaRejectInvalidHandshake}
	}
	// Draft_6455.java:262-286 (acceptHandshakeAsServer): only the version is
	// checked; the default extension and empty protocol accept anything
	// (DefaultExtension.java:52-58, Protocol.java:58-61).
	if javaReadVersion(headers) != 13 {
		return JavaHandshakeObservable{Observable: JavaObservableReject,
			RejectChannel: JavaRejectNotMatched}
	}
	// Draft_6455.java:432-441 (postProcessHandshakeResponseAsServer): a
	// missing or empty Sec-WebSocket-Key throws InvalidHandshakeException;
	// otherwise the response carries generateFinalKey(seckey)
	// (Draft_6455.java:832-841: SHA-1 over trim(key) + GUID).
	seckey := headers.get("Sec-WebSocket-Key")
	if seckey == "" {
		return JavaHandshakeObservable{Observable: JavaObservableReject,
			RejectChannel: JavaRejectInvalidHandshake}
	}
	return JavaHandshakeObservable{Observable: JavaObservableAccept,
		SecWebSocketAccept: ComputeAccept(javaTrim(seckey))}
}

// javaClientObservable mirrors the client side of
// WebSocketImpl.decodeHandshake (WebSocketImpl.java:336-364): translate, then
// acceptHandshakeAsClient against the recorded client key.
func javaClientObservable(raw []byte, clientKey string) JavaHandshakeObservable {
	firstLine, headers, early := javaParseHandshake(raw)
	if early != nil {
		return *early
	}
	// Draft.java:164-180 (translateHandshakeHttpClient): the status code is
	// compared literally against "101" before the HTTP version check.
	if firstLine[1] != "101" || !javaEqualsIgnoreCase(firstLine[0], "HTTP/1.1") {
		return JavaHandshakeObservable{Observable: JavaObservableReject,
			RejectChannel: JavaRejectInvalidHandshake}
	}
	// Draft_6455.java:306-343 (acceptHandshakeAsClient) with
	// Draft.basicAccept (Draft.java:188-191): Upgrade equalsIgnoreCase
	// "websocket" and Connection containing "upgrade" case-insensitively.
	if !javaEqualsIgnoreCase(headers.get("Upgrade"), "websocket") ||
		!strings.Contains(strings.ToLower(headers.get("Connection")), "upgrade") {
		return JavaHandshakeObservable{Observable: JavaObservableReject,
			RejectChannel: JavaRejectNotMatched}
	}
	// Draft_6455.java:312-316: both the request key and the response accept
	// must be present.
	if clientKey == "" || !headers.has("Sec-WebSocket-Accept") {
		return JavaHandshakeObservable{Observable: JavaObservableReject,
			RejectChannel: JavaRejectNotMatched}
	}
	// Draft_6455.java:318-325: generateFinalKey(challenge) compared literally
	// against the response value.
	if ComputeAccept(javaTrim(clientKey)) != headers.get("Sec-WebSocket-Accept") {
		return JavaHandshakeObservable{Observable: JavaObservableReject,
			RejectChannel: JavaRejectNotMatched}
	}
	return JavaHandshakeObservable{Observable: JavaObservableAccept}
}

// HandshakeMappingEntry is one row of the machine-checkable verdict mapping:
// what the Go reference model emits versus what the Java runtime observably
// does, with the quarantined source basis for the claim.
type HandshakeMappingEntry struct {
	Direction      string   `json:"direction"`
	Key            string   `json:"key"`
	RFCVerdict     string   `json:"rfc_verdict"`
	JavaObservable string   `json:"java_observable"`
	RejectChannel  string   `json:"reject_channel,omitempty"`
	Divergent      bool     `json:"divergent"`
	Condition      string   `json:"condition,omitempty"`
	Basis          []string `json:"basis"`
	Note           string   `json:"note,omitempty"`
}

// HandshakeVerdictMapping is the source-derived mapping from every verdict
// the Go reference model can emit (per direction) to the Java-runtime
// observable. Conditional entries name the exact source behavior that decides
// the outcome; ExpectedJavaHandshakeObservable resolves them per case.
func HandshakeVerdictMapping() []HandshakeMappingEntry {
	served := func(entries ...HandshakeMappingEntry) []HandshakeMappingEntry {
		return entries
	}
	parse := []string{"Draft.java:70-132 (readLine, translateHandshakeHttp)"}
	acceptServer := []string{"Draft_6455.java:262-286 (acceptHandshakeAsServer)",
		"WebSocketImpl.java:269-315 (decodeHandshake server loop)"}
	postProcess := []string{"Draft_6455.java:432-441 (postProcessHandshakeResponseAsServer)"}
	acceptClient := []string{"Draft_6455.java:306-343 (acceptHandshakeAsClient)",
		"Draft.java:188-191 (basicAccept)",
		"WebSocketImpl.java:336-364 (decodeHandshake client path)"}
	statusLine := []string{"Draft.java:164-180 (translateHandshakeHttpClient)"}
	requestLine := []string{"Draft.java:141-155 (translateHandshakeHttpServer)"}
	noLimits := "Java-WebSocket 1.6.0 has no handshake byte, header-count, or " +
		"header-line limits (translateHandshakeHttp reads unboundedly; " +
		"WebSocketImpl.java:370-387 grows tmpHandshakeBytes); the observable is " +
		"decided by the remaining Java checks over the same bytes"
	unchecked := "the Java server handshake never evaluates this rule " +
		"(acceptHandshakeAsServer checks only Sec-WebSocket-Version; " +
		"postProcessHandshakeResponseAsServer requires only a non-empty key); " +
		"the observable is decided by the remaining Java checks"

	client := served(
		HandshakeMappingEntry{Direction: "client_request", Key: "accept",
			RFCVerdict: "accept", JavaObservable: JavaObservableAccept,
			Basis: append(append([]string{}, acceptServer...), postProcess...),
			Note: "Sec-WebSocket-Accept equals the RFC value: generateFinalKey " +
				"(Draft_6455.java:832-841) is the same SHA-1 derivation after String.trim"},
		HandshakeMappingEntry{Direction: "client_request", Key: "incomplete",
			RFCVerdict: "incomplete", JavaObservable: JavaObservableIncomplete,
			Basis: []string{"Draft.java:100-102, 128-130 (IncompleteHandshakeException)",
				"WebSocketImpl.java:370-387 (buffered, nothing written)"}},
		HandshakeMappingEntry{Direction: "client_request", Key: "HS_LIMIT_TOTAL_BYTES",
			RFCVerdict: "reject", JavaObservable: JavaObservableConditional,
			Divergent: true, Condition: noLimits, Basis: parse,
			Note: "committed corpus family limit-total-bytes resolves to a divergent Java accept"},
		HandshakeMappingEntry{Direction: "client_request", Key: "HS_LIMIT_HEADER_COUNT",
			RFCVerdict: "reject", JavaObservable: JavaObservableConditional,
			Divergent: true, Condition: noLimits, Basis: parse,
			Note: "committed corpus family limit-header-count resolves to a divergent Java accept"},
		HandshakeMappingEntry{Direction: "client_request", Key: "HS_LIMIT_HEADER_LINE_BYTES",
			RFCVerdict: "reject", JavaObservable: JavaObservableConditional,
			Divergent: true, Condition: noLimits, Basis: parse,
			Note: "committed corpus family limit-header-line resolves to a divergent Java accept"},
		HandshakeMappingEntry{Direction: "client_request", Key: "HS_BARE_LF",
			RFCVerdict: "reject", JavaObservable: JavaObservableConditional,
			Divergent: true,
			Condition: "Draft.readLine terminates only on CRLF (Draft.java:78), so a " +
				"bare-LF line folds into the following CRLF-terminated line as one " +
				"header; the observable is decided by the surviving fields",
			Basis: parse,
			Note:  "committed corpus family bare-lf resolves to a divergent Java accept"},
		HandshakeMappingEntry{Direction: "client_request", Key: "HS_OBS_FOLD",
			RFCVerdict: "reject", JavaObservable: JavaObservableReject,
			RejectChannel: JavaRejectInvalidHandshake, Basis: parse,
			Note: "a folded continuation line has no colon and rejects as " +
				"'not an http header' (Draft.java:115-118); coarser than HS_OBS_FOLD"},
		HandshakeMappingEntry{Direction: "client_request", Key: "HS_MALFORMED_HEADER",
			RFCVerdict: "reject", JavaObservable: JavaObservableReject,
			RejectChannel: JavaRejectInvalidHandshake, Basis: parse,
			Note:          "coarser: every parse-level rejection is the same observable"},
		HandshakeMappingEntry{Direction: "client_request", Key: "HS_HEADER_NAME_NOT_TOKEN",
			RFCVerdict: "reject", JavaObservable: JavaObservableConditional,
			Divergent: true,
			Condition: "Java performs no header-name token validation " +
				"(Draft.java:115-125 stores any name); the observable is decided " +
				"by the remaining Java checks",
			Basis: parse,
			Note:  "committed corpus family header-name-not-token resolves to a divergent Java accept"},
		HandshakeMappingEntry{Direction: "client_request", Key: "HS_DUPLICATE_HEADER",
			RFCVerdict: "reject", JavaObservable: JavaObservableConditional,
			Divergent: true,
			Condition: "duplicates join with '; ' (Draft.java:119-125): a duplicated " +
				"Sec-WebSocket-Version becomes unparseable and rejects NOT_MATCHED, " +
				"while a duplicated Sec-WebSocket-Key is accepted with the accept " +
				"value computed over the joined string",
			Basis: parse,
			Note: "committed corpus family duplicate-header splits: seed 0 (key) is a " +
				"divergent Java accept, seed 1 (version) rejects NOT_MATCHED"},
		HandshakeMappingEntry{Direction: "client_request", Key: "HS_MALFORMED_REQUEST_LINE",
			RFCVerdict: "reject", JavaObservable: JavaObservableReject,
			RejectChannel: JavaRejectInvalidHandshake,
			Basis:         append(append([]string{}, parse...), requestLine...),
			Note: "Java splits with limit 3 (Draft.java:104), so extra tokens fold " +
				"into the version token and reject on the HTTP/1.1 comparison"},
		HandshakeMappingEntry{Direction: "client_request", Key: "HS_METHOD_NOT_GET",
			RFCVerdict: "reject", JavaObservable: JavaObservableReject,
			RejectChannel: JavaRejectInvalidHandshake, Basis: requestLine,
			Note: "granularity: Java compares equalsIgnoreCase, so a lowercase " +
				"'get' would be accepted by Java and rejected by the RFC model"},
		HandshakeMappingEntry{Direction: "client_request", Key: "HS_HTTP_VERSION",
			RFCVerdict: "reject", JavaObservable: JavaObservableReject,
			RejectChannel: JavaRejectInvalidHandshake, Basis: requestLine,
			Note:          "granularity: Java compares equalsIgnoreCase('HTTP/1.1')"},
		HandshakeMappingEntry{Direction: "client_request", Key: "HS_MISSING_HOST",
			RFCVerdict: "reject", JavaObservable: JavaObservableConditional,
			Divergent: true, Condition: unchecked, Basis: acceptServer,
			Note: "committed corpus family missing-host resolves to a divergent Java accept"},
		HandshakeMappingEntry{Direction: "client_request", Key: "HS_MISSING_UPGRADE",
			RFCVerdict: "reject", JavaObservable: JavaObservableConditional,
			Divergent: true, Condition: unchecked, Basis: acceptServer,
			Note: "committed corpus family missing-upgrade resolves to a divergent Java accept"},
		HandshakeMappingEntry{Direction: "client_request", Key: "HS_UPGRADE_VALUE",
			RFCVerdict: "reject", JavaObservable: JavaObservableConditional,
			Divergent: true, Condition: unchecked, Basis: acceptServer,
			Note: "committed corpus family upgrade-value resolves to a divergent Java accept"},
		HandshakeMappingEntry{Direction: "client_request", Key: "HS_MISSING_CONNECTION",
			RFCVerdict: "reject", JavaObservable: JavaObservableConditional,
			Divergent: true, Condition: unchecked, Basis: acceptServer,
			Note: "committed corpus family missing-connection resolves to a divergent Java accept"},
		HandshakeMappingEntry{Direction: "client_request", Key: "HS_CONNECTION_VALUE",
			RFCVerdict: "reject", JavaObservable: JavaObservableConditional,
			Divergent: true, Condition: unchecked, Basis: acceptServer,
			Note: "committed corpus family connection-value resolves to a divergent Java accept"},
		HandshakeMappingEntry{Direction: "client_request", Key: "HS_MISSING_KEY",
			RFCVerdict: "reject", JavaObservable: JavaObservableReject,
			RejectChannel: JavaRejectInvalidHandshake, Basis: postProcess,
			Note: "the version check passes (MATCHED) but building the response " +
				"throws 'missing Sec-WebSocket-Key'"},
		HandshakeMappingEntry{Direction: "client_request", Key: "HS_KEY_NOT_BASE64",
			RFCVerdict: "reject", JavaObservable: JavaObservableConditional,
			Divergent: true,
			Condition: "generateFinalKey (Draft_6455.java:832-841) hashes any " +
				"non-empty string; the key encoding is never validated",
			Basis: postProcess,
			Note: "committed corpus family key-not-base64 resolves to a divergent " +
				"Java accept whose accept value hashes the malformed key"},
		HandshakeMappingEntry{Direction: "client_request", Key: "HS_KEY_LENGTH",
			RFCVerdict: "reject", JavaObservable: JavaObservableConditional,
			Divergent: true,
			Condition: "the decoded key length is never validated; " +
				"generateFinalKey hashes the raw header string",
			Basis: postProcess,
			Note:  "committed corpus family key-wrong-length resolves to a divergent Java accept"},
		HandshakeMappingEntry{Direction: "client_request", Key: "HS_MISSING_VERSION",
			RFCVerdict: "reject", JavaObservable: JavaObservableReject,
			RejectChannel: JavaRejectNotMatched,
			Basis: []string{"Draft.java:329-341 (readVersion returns -1)",
				"Draft_6455.java:262-268 (NOT_MATCHED when != 13)"}},
		HandshakeMappingEntry{Direction: "client_request", Key: "HS_VERSION_UNSUPPORTED",
			RFCVerdict: "reject", JavaObservable: JavaObservableReject,
			RejectChannel: JavaRejectNotMatched,
			Basis: []string{"Draft.java:329-341 (readVersion)",
				"Draft_6455.java:262-268 (NOT_MATCHED when != 13)"},
			Note: "granularity: Java accepts any Integer.parseInt spelling of 13 " +
				"after trim ('+13', '0013', ' 13 '), which the RFC model rejects"},
	)
	server := served(
		HandshakeMappingEntry{Direction: "server_response", Key: "accept",
			RFCVerdict: "accept", JavaObservable: JavaObservableAccept,
			Basis: acceptClient,
			Note:  "no accept value is observable on the client side"},
		HandshakeMappingEntry{Direction: "server_response", Key: "incomplete",
			RFCVerdict: "incomplete", JavaObservable: JavaObservableIncomplete,
			Basis: []string{"Draft.java:100-102, 128-130 (IncompleteHandshakeException)"}},
		HandshakeMappingEntry{Direction: "server_response", Key: "HS_LIMIT_TOTAL_BYTES",
			RFCVerdict: "reject", JavaObservable: JavaObservableConditional,
			Divergent: true, Condition: noLimits, Basis: parse},
		HandshakeMappingEntry{Direction: "server_response", Key: "HS_LIMIT_HEADER_COUNT",
			RFCVerdict: "reject", JavaObservable: JavaObservableConditional,
			Divergent: true, Condition: noLimits, Basis: parse},
		HandshakeMappingEntry{Direction: "server_response", Key: "HS_LIMIT_HEADER_LINE_BYTES",
			RFCVerdict: "reject", JavaObservable: JavaObservableConditional,
			Divergent: true, Condition: noLimits, Basis: parse},
		HandshakeMappingEntry{Direction: "server_response", Key: "HS_BARE_LF",
			RFCVerdict: "reject", JavaObservable: JavaObservableConditional,
			Divergent: true,
			Condition: "a bare-LF line folds into the following CRLF-terminated " +
				"line; unlike the server side, basicAccept still checks Upgrade and " +
				"Connection, so folded responses usually reject NOT_MATCHED",
			Basis: append(append([]string{}, parse...), acceptClient...)},
		HandshakeMappingEntry{Direction: "server_response", Key: "HS_OBS_FOLD",
			RFCVerdict: "reject", JavaObservable: JavaObservableReject,
			RejectChannel: JavaRejectInvalidHandshake, Basis: parse},
		HandshakeMappingEntry{Direction: "server_response", Key: "HS_MALFORMED_HEADER",
			RFCVerdict: "reject", JavaObservable: JavaObservableReject,
			RejectChannel: JavaRejectInvalidHandshake, Basis: parse},
		HandshakeMappingEntry{Direction: "server_response", Key: "HS_HEADER_NAME_NOT_TOKEN",
			RFCVerdict: "reject", JavaObservable: JavaObservableConditional,
			Divergent: true,
			Condition: "Java performs no header-name token validation; the " +
				"observable is decided by basicAccept and the accept comparison",
			Basis: parse},
		HandshakeMappingEntry{Direction: "server_response", Key: "HS_DUPLICATE_HEADER",
			RFCVerdict: "reject", JavaObservable: JavaObservableConditional,
			Divergent: true,
			Condition: "duplicates join with '; '; a duplicated " +
				"Sec-WebSocket-Accept joins to a value that cannot equal the " +
				"derived key and rejects NOT_MATCHED",
			Basis: append(append([]string{}, parse...), acceptClient...)},
		HandshakeMappingEntry{Direction: "server_response", Key: "HS_MALFORMED_STATUS_LINE",
			RFCVerdict: "reject", JavaObservable: JavaObservableReject,
			RejectChannel: JavaRejectInvalidHandshake,
			Basis:         append(append([]string{}, parse...), statusLine...),
			Note: "granularity: Java requires exactly three tokens and the literal " +
				"'101', so a two-token status line or '0101' rejects in Java while " +
				"the RFC model reads them differently"},
		HandshakeMappingEntry{Direction: "server_response", Key: "HS_HTTP_VERSION",
			RFCVerdict: "reject", JavaObservable: JavaObservableReject,
			RejectChannel: JavaRejectInvalidHandshake, Basis: statusLine,
			Note: "Java checks the status code before the HTTP version; both " +
				"paths reject the committed corpus inputs"},
		HandshakeMappingEntry{Direction: "server_response", Key: "HS_STATUS_NOT_101",
			RFCVerdict: "reject", JavaObservable: JavaObservableReject,
			RejectChannel: JavaRejectInvalidHandshake, Basis: statusLine},
		HandshakeMappingEntry{Direction: "server_response", Key: "HS_MISSING_UPGRADE",
			RFCVerdict: "reject", JavaObservable: JavaObservableReject,
			RejectChannel: JavaRejectNotMatched, Basis: acceptClient,
			Note: "coarser: basicAccept failures on Upgrade and Connection are " +
				"one indistinguishable NOT_MATCHED observable"},
		HandshakeMappingEntry{Direction: "server_response", Key: "HS_UPGRADE_VALUE",
			RFCVerdict: "reject", JavaObservable: JavaObservableReject,
			RejectChannel: JavaRejectNotMatched, Basis: acceptClient},
		HandshakeMappingEntry{Direction: "server_response", Key: "HS_MISSING_CONNECTION",
			RFCVerdict: "reject", JavaObservable: JavaObservableReject,
			RejectChannel: JavaRejectNotMatched, Basis: acceptClient},
		HandshakeMappingEntry{Direction: "server_response", Key: "HS_CONNECTION_VALUE",
			RFCVerdict: "reject", JavaObservable: JavaObservableReject,
			RejectChannel: JavaRejectNotMatched, Basis: acceptClient},
		HandshakeMappingEntry{Direction: "server_response", Key: "HS_MISSING_ACCEPT",
			RFCVerdict: "reject", JavaObservable: JavaObservableReject,
			RejectChannel: JavaRejectNotMatched,
			Basis:         []string{"Draft_6455.java:312-316 (missing key or accept)"}},
		HandshakeMappingEntry{Direction: "server_response", Key: "HS_ACCEPT_MISMATCH",
			RFCVerdict: "reject", JavaObservable: JavaObservableReject,
			RejectChannel: JavaRejectNotMatched,
			Basis:         []string{"Draft_6455.java:318-325 (literal accept comparison)"}},
	)
	return append(client, server...)
}

// RenderHandshakeLiveMappingDocument renders the committed evidence document
// for the mapping table. The document and the table are asserted
// byte-identical by test so they cannot drift.
func RenderHandshakeLiveMappingDocument() ([]byte, error) {
	document := map[string]any{
		"schema_version": "1.0.0",
		"evidence_kind":  "handshake-live-verdict-mapping",
		"map_id":         "us005-handshake-live-mapping",
		"source": map[string]any{
			"artifact":  oracleRuntimeArtifact,
			"sha256":    "sha256:" + oracleRuntimeSHA256,
			"revision":  "da3cf2a777aed862f2f5b5cf060cae7969958667",
			"statement": "Every row was derived by reading the quarantined Java-WebSocket 1.6.0 source at the cited lines and is validated against the real jar by the java-oracle handshake harness tests. No row was inferred from documentation or invented.",
		},
		"granularity_statement": "The Java runtime cannot observably distinguish most HS_* reject codes: on a real server every rejection collapses to one HTTP error response plus a PROTOCOL_ERROR (1002) close. The adapter reports the draft-API channel (invalid_handshake vs not_matched) as the finest honest granularity. Rows marked divergent identify inputs the RFC-derived Go model rejects but the Java runtime observably accepts (or splits); conditional rows name the exact source behavior that decides the outcome, resolved per case by ExpectedJavaHandshakeObservable.",
		"protocol": map[string]any{
			"id":      handshakeOracleProtocol,
			"version": handshakeOracleVersion,
		},
		"entries": HandshakeVerdictMapping(),
	}
	rendered, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(rendered, '\n'), nil
}

// synthesizeHandshakeLiveResponse builds the transcript line a faithful
// java-oracle handshake adapter emits for a case. Testing only; never live
// evidence, and not exported.
func synthesizeHandshakeLiveResponse(c HandshakeCase) ([]byte, error) {
	request, err := HandshakeOracleRequest(c)
	if err != nil {
		return nil, err
	}
	expected, err := ExpectedJavaHandshakeObservable(c)
	if err != nil {
		return nil, err
	}
	response := map[string]any{
		"case_id":         c.CaseID,
		"java_observable": expected.Observable,
		"protocol":        handshakeOracleProtocol,
		"request_digest":  request["request_digest"],
		"runtime": map[string]any{
			"artifact": oracleRuntimeArtifact,
			"sha256":   "sha256:" + oracleRuntimeSHA256,
		},
		"version": handshakeOracleVersion,
	}
	if expected.Observable == JavaObservableReject {
		response["reject_channel"] = expected.RejectChannel
		response["close_code"] = javaHandshakeCloseCode
	}
	if expected.SecWebSocketAccept != "" {
		response["sec_websocket_accept"] = expected.SecWebSocketAccept
	}
	return CanonicalJSON(response)
}

// HandshakeLiveReport is the reconciliation of a java-oracle handshake
// transcript against the source-derived Java expectations, with every
// RFC-vs-Java divergence surfaced explicitly.
type HandshakeLiveReport struct {
	TranscriptReport
	Divergences []string `json:"divergences,omitempty"`
}

type handshakeLiveResponse struct {
	CaseID             string `json:"case_id"`
	Protocol           string `json:"protocol"`
	Version            string `json:"version"`
	RequestDigest      string `json:"request_digest"`
	JavaObservable     string `json:"java_observable"`
	RejectChannel      string `json:"reject_channel"`
	CloseCode          *int   `json:"close_code"`
	SecWebSocketAccept string `json:"sec_websocket_accept"`
}

// evaluateHandshakeLiveResponse scores one transcript line against the
// source-derived Java expectation for its case: observable class, reject
// channel, close code, accept value, digest binding, and presence parity.
func evaluateHandshakeLiveResponse(c HandshakeCase, line []byte) (bool, string) {
	var response handshakeLiveResponse
	if err := json.Unmarshal(line, &response); err != nil {
		return false, "response is not valid JSON: " + err.Error()
	}
	var fields map[string]any
	if err := json.Unmarshal(line, &fields); err != nil {
		return false, "response is not valid JSON: " + err.Error()
	}
	if response.Protocol != handshakeOracleProtocol ||
		response.Version != handshakeOracleVersion {
		return false, "protocol pin mismatch"
	}
	request, err := HandshakeOracleRequest(c)
	if err != nil {
		return false, "request projection failed: " + err.Error()
	}
	if response.RequestDigest != request["request_digest"] {
		return false, "request_digest does not bind this case"
	}
	expected, err := ExpectedJavaHandshakeObservable(c)
	if err != nil {
		return false, "no calibrated Java expectation: " + err.Error()
	}
	if response.JavaObservable != expected.Observable {
		return false, fmt.Sprintf("java_observable %q, expected %q",
			response.JavaObservable, expected.Observable)
	}
	if expected.Observable == JavaObservableReject {
		if response.RejectChannel != expected.RejectChannel {
			return false, fmt.Sprintf("reject_channel %q, expected %q",
				response.RejectChannel, expected.RejectChannel)
		}
		if response.CloseCode == nil || *response.CloseCode != javaHandshakeCloseCode {
			return false, fmt.Sprintf("close_code %v, expected %d",
				response.CloseCode, javaHandshakeCloseCode)
		}
	} else {
		if _, present := fields["reject_channel"]; present {
			return false, "unexpected reject_channel"
		}
		if _, present := fields["close_code"]; present {
			return false, "unexpected close_code"
		}
	}
	accept, hasAccept := fields["sec_websocket_accept"]
	if expected.SecWebSocketAccept != "" {
		if !hasAccept || accept != expected.SecWebSocketAccept {
			return false, fmt.Sprintf("sec_websocket_accept %v, expected %s",
				accept, expected.SecWebSocketAccept)
		}
	} else if hasAccept {
		return false, "unexpected sec_websocket_accept"
	}
	return true, ""
}

// EvaluateHandshakeLiveTranscript evaluates a java-oracle handshake JSONL
// transcript fail-closed: duplicate responses error, missing and unmatched
// responses block, and every case that passed through a documented
// RFC-vs-Java divergence is listed in the report.
func EvaluateHandshakeLiveTranscript(cases []HandshakeCase,
	transcript []byte) (HandshakeLiveReport, error) {
	var report HandshakeLiveReport
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
		passed, detail := evaluateHandshakeLiveResponse(c, line)
		if !passed {
			report.Failed++
			report.Failures = append(report.Failures, c.CaseID+": "+detail)
			continue
		}
		report.Passed++
		if expected, err := ExpectedJavaHandshakeObservable(c); err == nil &&
			expected.Observable != c.Expected.Verdict {
			key := c.Expected.Verdict
			if c.Expected.RejectCode != "" {
				key = c.Expected.RejectCode
			}
			report.Divergences = append(report.Divergences, fmt.Sprintf(
				"%s: rfc %s observed as java %s (documented divergence)",
				c.CaseID, key, expected.Observable))
		}
	}
	for id := range responses {
		if !known[id] {
			report.Unmatched++
		}
	}
	return report, nil
}
