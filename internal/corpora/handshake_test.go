package corpora

import (
	"strings"
	"testing"
)

func handshakeConfig() HandshakeConfig {
	return HandshakeConfig{MaxHandshakeBytes: 4096, MaxHeaderCount: 32, MaxHeaderLineBytes: 512}
}

const rfcSampleKey = "dGhlIHNhbXBsZSBub25jZQ=="

func validClientRequest() string {
	return "GET /chat HTTP/1.1\r\n" +
		"Host: server.example.com\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + rfcSampleKey + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"\r\n"
}

func deriveHS(t *testing.T, direction, raw string, context HandshakeContext) HandshakeExpected {
	t.Helper()
	expected, err := DeriveHandshake(direction, []byte(raw), handshakeConfig(), context)
	if err != nil {
		t.Fatalf("DeriveHandshake failed: %v", err)
	}
	return expected
}

// RFC 6455 section 1.3 fixes the accept value for the sample nonce.
func TestComputeAcceptMatchesRFCExample(t *testing.T) {
	if got := ComputeAccept(rfcSampleKey); got != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("accept = %q", got)
	}
}

func TestHandshakeValidClientRequestAccepts(t *testing.T) {
	expected := deriveHS(t, "client_request", validClientRequest(), HandshakeContext{})
	if expected.Verdict != "accept" || expected.RejectCode != "" {
		t.Fatalf("expected accept, got %+v", expected)
	}
	if expected.SecWebSocketAccept != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("accept value = %q", expected.SecWebSocketAccept)
	}
}

// Header names are case-insensitive; token lists may carry other members.
func TestHandshakeCaseInsensitiveHeadersAccept(t *testing.T) {
	raw := "GET / HTTP/1.1\r\n" +
		"host: h\r\n" +
		"upgrade: WebSocket\r\n" +
		"CONNECTION: keep-alive, Upgrade\r\n" +
		"sec-websocket-key: " + rfcSampleKey + "\r\n" +
		"SEC-WEBSOCKET-VERSION: 13\r\n" +
		"\r\n"
	expected := deriveHS(t, "client_request", raw, HandshakeContext{})
	if expected.Verdict != "accept" {
		t.Fatalf("expected accept, got %+v", expected)
	}
}

func TestHandshakeClientRejections(t *testing.T) {
	base := validClientRequest()
	cases := []struct {
		name string
		raw  string
		code string
	}{
		{"method", strings.Replace(base, "GET ", "POST ", 1), "HS_METHOD_NOT_GET"},
		{"http10", strings.Replace(base, "HTTP/1.1", "HTTP/1.0", 1), "HS_HTTP_VERSION"},
		{"missing host", strings.Replace(base, "Host: server.example.com\r\n", "", 1), "HS_MISSING_HOST"},
		{"missing upgrade", strings.Replace(base, "Upgrade: websocket\r\n", "", 1), "HS_MISSING_UPGRADE"},
		{"upgrade value", strings.Replace(base, "Upgrade: websocket", "Upgrade: h2c", 1), "HS_UPGRADE_VALUE"},
		{"missing connection", strings.Replace(base, "Connection: Upgrade\r\n", "", 1), "HS_MISSING_CONNECTION"},
		{"connection value", strings.Replace(base, "Connection: Upgrade", "Connection: close", 1), "HS_CONNECTION_VALUE"},
		{"missing key", strings.Replace(base, "Sec-WebSocket-Key: "+rfcSampleKey+"\r\n", "", 1), "HS_MISSING_KEY"},
		{"key not base64", strings.Replace(base, rfcSampleKey, "!!not-base64!!", 1), "HS_KEY_NOT_BASE64"},
		{"key wrong length", strings.Replace(base, rfcSampleKey, "c2hvcnQ=", 1), "HS_KEY_LENGTH"},
		{"missing version", strings.Replace(base, "Sec-WebSocket-Version: 13\r\n", "", 1), "HS_MISSING_VERSION"},
		{"version 8", strings.Replace(base, "Sec-WebSocket-Version: 13", "Sec-WebSocket-Version: 8", 1), "HS_VERSION_UNSUPPORTED"},
		{"duplicate key", strings.Replace(base, "Sec-WebSocket-Version: 13\r\n",
			"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: "+rfcSampleKey+"\r\n", 1), "HS_DUPLICATE_HEADER"},
		{"header name not token", strings.Replace(base, "Host:", "Ho st:", 1), "HS_HEADER_NAME_NOT_TOKEN"},
		{"obs fold", strings.Replace(base, "Upgrade: websocket\r\n", "Upgrade: websocket\r\n continued\r\n", 1), "HS_OBS_FOLD"},
		{"malformed request line", strings.Replace(base, "GET /chat HTTP/1.1", "GET/chat HTTP/1.1", 1), "HS_MALFORMED_REQUEST_LINE"},
		{"bare lf", strings.Replace(base, "Host: server.example.com\r\n", "Host: server.example.com\n", 1), "HS_BARE_LF"},
	}
	for _, tc := range cases {
		expected := deriveHS(t, "client_request", tc.raw, HandshakeContext{})
		if expected.Verdict != "reject" || expected.RejectCode != tc.code {
			t.Fatalf("%s: got %+v want reject/%s", tc.name, expected, tc.code)
		}
	}
}

func TestHandshakePartialInputIsIncomplete(t *testing.T) {
	full := validClientRequest()
	for _, cut := range []int{5, 20, len(full) - 2} {
		expected := deriveHS(t, "client_request", full[:cut], HandshakeContext{})
		if expected.Verdict != "incomplete" {
			t.Fatalf("cut=%d got %+v", cut, expected)
		}
	}
}

func TestHandshakeLimits(t *testing.T) {
	config := HandshakeConfig{MaxHandshakeBytes: 64, MaxHeaderCount: 32, MaxHeaderLineBytes: 512}
	expected, err := DeriveHandshake("client_request", []byte(validClientRequest()), config, HandshakeContext{})
	if err != nil || expected.Verdict != "reject" || expected.RejectCode != "HS_LIMIT_TOTAL_BYTES" {
		t.Fatalf("total bytes limit = %+v err=%v", expected, err)
	}

	config = HandshakeConfig{MaxHandshakeBytes: 4096, MaxHeaderCount: 3, MaxHeaderLineBytes: 512}
	expected, err = DeriveHandshake("client_request", []byte(validClientRequest()), config, HandshakeContext{})
	if err != nil || expected.RejectCode != "HS_LIMIT_HEADER_COUNT" {
		t.Fatalf("header count limit = %+v err=%v", expected, err)
	}

	config = HandshakeConfig{MaxHandshakeBytes: 4096, MaxHeaderCount: 32, MaxHeaderLineBytes: 16}
	expected, err = DeriveHandshake("client_request", []byte(validClientRequest()), config, HandshakeContext{})
	if err != nil || expected.RejectCode != "HS_LIMIT_HEADER_LINE_BYTES" {
		t.Fatalf("header line limit = %+v err=%v", expected, err)
	}
}

func validServerResponse(clientKey string) string {
	return "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + ComputeAccept(clientKey) + "\r\n" +
		"\r\n"
}

func TestHandshakeServerResponse(t *testing.T) {
	context := HandshakeContext{ClientKey: rfcSampleKey}
	expected := deriveHS(t, "server_response", validServerResponse(rfcSampleKey), context)
	if expected.Verdict != "accept" {
		t.Fatalf("valid response = %+v", expected)
	}

	wrongStatus := strings.Replace(validServerResponse(rfcSampleKey), "101 Switching Protocols", "200 OK", 1)
	expected = deriveHS(t, "server_response", wrongStatus, context)
	if expected.RejectCode != "HS_STATUS_NOT_101" {
		t.Fatalf("status = %+v", expected)
	}

	badAccept := strings.Replace(validServerResponse(rfcSampleKey),
		ComputeAccept(rfcSampleKey), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo!", 1)
	expected = deriveHS(t, "server_response", badAccept, context)
	if expected.RejectCode != "HS_ACCEPT_MISMATCH" {
		t.Fatalf("accept mismatch = %+v", expected)
	}

	noAccept := strings.Replace(validServerResponse(rfcSampleKey),
		"Sec-WebSocket-Accept: "+ComputeAccept(rfcSampleKey)+"\r\n", "", 1)
	expected = deriveHS(t, "server_response", noAccept, context)
	if expected.RejectCode != "HS_MISSING_ACCEPT" {
		t.Fatalf("missing accept = %+v", expected)
	}
}

func TestHandshakeExpectationCarriesRFCBasis(t *testing.T) {
	expected := deriveHS(t, "client_request", validClientRequest(), HandshakeContext{})
	if len(expected.Basis) == 0 {
		t.Fatal("accepted handshake expectations must cite RFC sections")
	}
	for _, id := range expected.Basis {
		if !strings.HasPrefix(id, "rfc") {
			t.Fatalf("basis id %q is not an RFC citation", id)
		}
	}
}
