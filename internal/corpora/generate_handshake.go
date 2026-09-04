package corpora

import (
	"fmt"
	"strings"
)

// DefaultHandshakeConfig is the standard limit envelope for handshake cases.
func DefaultHandshakeConfig() HandshakeConfig {
	return HandshakeConfig{MaxHandshakeBytes: 4096, MaxHeaderCount: 32, MaxHeaderLineBytes: 512}
}

type hsDraft struct {
	raw     []byte
	config  HandshakeConfig
	context HandshakeContext
}

type hsFamilySpec struct {
	name      string
	count     int
	direction string
	// intent is "accept", "incomplete", or the exact expected reject code.
	// Generation fails closed when the rule engine disagrees with intent.
	intent string
	build  func(s *Stream, i int) hsDraft
}

func hsKey(s *Stream) string {
	return base64Std(s.Bytes(16))
}

func clientRequestLines(host, path, key, version string) []string {
	return []string{
		"GET " + path + " HTTP/1.1",
		"Host: " + host,
		"Upgrade: websocket",
		"Connection: Upgrade",
		"Sec-WebSocket-Key: " + key,
		"Sec-WebSocket-Version: " + version,
	}
}

func joinRequest(lines []string) []byte {
	return []byte(strings.Join(lines, "\r\n") + "\r\n\r\n")
}

func seededHost(s *Stream) string {
	return fmt.Sprintf("host-%x.example", s.Bytes(3))
}

func seededPath(s *Stream) string {
	return fmt.Sprintf("/socket/%x", s.Bytes(4))
}

func validRequestDraft(s *Stream) hsDraft {
	lines := clientRequestLines(seededHost(s), seededPath(s), hsKey(s), "13")
	return hsDraft{raw: joinRequest(lines), config: DefaultHandshakeConfig()}
}

func serverResponseLines(accept string) []string {
	return []string{
		"HTTP/1.1 101 Switching Protocols",
		"Upgrade: websocket",
		"Connection: Upgrade",
		"Sec-WebSocket-Accept: " + accept,
	}
}

func validResponseDraft(s *Stream) hsDraft {
	key := hsKey(s)
	return hsDraft{
		raw:     joinRequest(serverResponseLines(ComputeAccept(key))),
		config:  DefaultHandshakeConfig(),
		context: HandshakeContext{ClientKey: key},
	}
}

func replaceLine(draft hsDraft, old, new string) hsDraft {
	draft.raw = []byte(strings.Replace(string(draft.raw), old, new, 1))
	return draft
}

func handshakePlan() []hsFamilySpec {
	return []hsFamilySpec{
		{"valid-client-request", 4, "client_request", "accept",
			func(s *Stream, i int) hsDraft {
				draft := validRequestDraft(s)
				if i == 3 {
					draft = replaceLine(draft, "Sec-WebSocket-Version: 13",
						"Sec-WebSocket-Version: 13\r\nX-Extra-Header: "+s.ASCII(6))
				}
				return draft
			}},
		{"valid-client-case-insensitive", 2, "client_request", "accept",
			func(s *Stream, i int) hsDraft {
				lines := []string{
					"GET " + seededPath(s) + " HTTP/1.1",
					"host: " + seededHost(s),
					"upgrade: WebSocket",
					"CONNECTION: keep-alive, Upgrade",
					"sec-websocket-key: " + hsKey(s),
					"SEC-WEBSOCKET-VERSION: 13",
				}
				return hsDraft{raw: joinRequest(lines), config: DefaultHandshakeConfig()}
			}},
		{"valid-server-response", 3, "server_response", "accept",
			func(s *Stream, i int) hsDraft { return validResponseDraft(s) }},
		{"method-not-get", 2, "client_request", "HS_METHOD_NOT_GET",
			func(s *Stream, i int) hsDraft {
				method := "POST"
				if i == 1 {
					method = "PATCH"
				}
				return replaceLine(validRequestDraft(s), "GET ", method+" ")
			}},
		{"http-version", 2, "client_request", "HS_HTTP_VERSION",
			func(s *Stream, i int) hsDraft {
				version := "HTTP/1.0"
				if i == 1 {
					version = "HTTP/0.9"
				}
				return replaceLine(validRequestDraft(s), "HTTP/1.1", version)
			}},
		{"missing-host", 1, "client_request", "HS_MISSING_HOST",
			func(s *Stream, i int) hsDraft {
				draft := validRequestDraft(s)
				lines := strings.Split(strings.TrimSuffix(string(draft.raw), "\r\n\r\n"), "\r\n")
				var kept []string
				for _, line := range lines {
					if strings.HasPrefix(strings.ToLower(line), "host:") {
						continue
					}
					kept = append(kept, line)
				}
				draft.raw = joinRequest(kept)
				return draft
			}},
		{"missing-upgrade", 1, "client_request", "HS_MISSING_UPGRADE",
			func(s *Stream, i int) hsDraft {
				return replaceLine(validRequestDraft(s), "Upgrade: websocket\r\n", "")
			}},
		{"upgrade-value", 1, "client_request", "HS_UPGRADE_VALUE",
			func(s *Stream, i int) hsDraft {
				return replaceLine(validRequestDraft(s), "Upgrade: websocket", "Upgrade: h2c")
			}},
		{"missing-connection", 1, "client_request", "HS_MISSING_CONNECTION",
			func(s *Stream, i int) hsDraft {
				return replaceLine(validRequestDraft(s), "Connection: Upgrade\r\n", "")
			}},
		{"connection-value", 1, "client_request", "HS_CONNECTION_VALUE",
			func(s *Stream, i int) hsDraft {
				return replaceLine(validRequestDraft(s), "Connection: Upgrade", "Connection: close")
			}},
		{"missing-key", 1, "client_request", "HS_MISSING_KEY",
			func(s *Stream, i int) hsDraft {
				draft := validRequestDraft(s)
				lines := strings.Split(strings.TrimSuffix(string(draft.raw), "\r\n\r\n"), "\r\n")
				var kept []string
				for _, line := range lines {
					if strings.HasPrefix(strings.ToLower(line), "sec-websocket-key:") {
						continue
					}
					kept = append(kept, line)
				}
				draft.raw = joinRequest(kept)
				return draft
			}},
		{"key-not-base64", 2, "client_request", "HS_KEY_NOT_BASE64",
			func(s *Stream, i int) hsDraft {
				bad := "!!definitely-not-base64!!"
				if i == 1 {
					// Non-canonical padding bits form.
					bad = "AAAAAAAAAAAAAAAAAAAAAB=="
				}
				draft := validRequestDraft(s)
				lines := strings.Split(strings.TrimSuffix(string(draft.raw), "\r\n\r\n"), "\r\n")
				for j, line := range lines {
					if strings.HasPrefix(strings.ToLower(line), "sec-websocket-key:") {
						lines[j] = "Sec-WebSocket-Key: " + bad
					}
				}
				draft.raw = joinRequest(lines)
				return draft
			}},
		{"key-wrong-length", 2, "client_request", "HS_KEY_LENGTH",
			func(s *Stream, i int) hsDraft {
				length := 15
				if i == 1 {
					length = 17
				}
				draft := validRequestDraft(s)
				lines := strings.Split(strings.TrimSuffix(string(draft.raw), "\r\n\r\n"), "\r\n")
				for j, line := range lines {
					if strings.HasPrefix(strings.ToLower(line), "sec-websocket-key:") {
						lines[j] = "Sec-WebSocket-Key: " + base64Std(s.Bytes(length))
					}
				}
				draft.raw = joinRequest(lines)
				return draft
			}},
		{"missing-version", 1, "client_request", "HS_MISSING_VERSION",
			func(s *Stream, i int) hsDraft {
				return replaceLine(validRequestDraft(s), "Sec-WebSocket-Version: 13\r\n", "")
			}},
		{"version-unsupported", 3, "client_request", "HS_VERSION_UNSUPPORTED",
			func(s *Stream, i int) hsDraft {
				value := []string{"8", "25", "thirteen"}[i]
				return replaceLine(validRequestDraft(s),
					"Sec-WebSocket-Version: 13", "Sec-WebSocket-Version: "+value)
			}},
		{"duplicate-header", 2, "client_request", "HS_DUPLICATE_HEADER",
			func(s *Stream, i int) hsDraft {
				draft := validRequestDraft(s)
				if i == 0 {
					return replaceLine(draft, "Sec-WebSocket-Version: 13",
						"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: "+hsKey(s))
				}
				return replaceLine(draft, "Sec-WebSocket-Version: 13",
					"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Version: 13")
			}},
		{"header-name-not-token", 2, "client_request", "HS_HEADER_NAME_NOT_TOKEN",
			func(s *Stream, i int) hsDraft {
				bad := "Ho st: value"
				if i == 1 {
					bad = "Bad\"Name: value"
				}
				return replaceLine(validRequestDraft(s), "Upgrade: websocket",
					bad+"\r\nUpgrade: websocket")
			}},
		{"malformed-request-line", 2, "client_request", "HS_MALFORMED_REQUEST_LINE",
			func(s *Stream, i int) hsDraft {
				draft := validRequestDraft(s)
				lines := strings.Split(strings.TrimSuffix(string(draft.raw), "\r\n\r\n"), "\r\n")
				if i == 0 {
					lines[0] = "GET" + strings.TrimPrefix(lines[0], "GET ")
					lines[0] = strings.Replace(lines[0], " HTTP/1.1", "HTTP/1.1", 1)
				} else {
					lines[0] = lines[0] + " EXTRA"
				}
				draft.raw = joinRequest(lines)
				return draft
			}},
		{"obs-fold", 1, "client_request", "HS_OBS_FOLD",
			func(s *Stream, i int) hsDraft {
				return replaceLine(validRequestDraft(s), "Upgrade: websocket\r\n",
					"Upgrade: websocket\r\n folded\r\n")
			}},
		{"bare-lf", 1, "client_request", "HS_BARE_LF",
			func(s *Stream, i int) hsDraft {
				draft := validRequestDraft(s)
				text := string(draft.raw)
				text = strings.Replace(text, "Upgrade: websocket\r\n", "Upgrade: websocket\n", 1)
				draft.raw = []byte(text)
				return draft
			}},
		{"status-not-101", 3, "server_response", "HS_STATUS_NOT_101",
			func(s *Stream, i int) hsDraft {
				status := []string{"200 OK", "404 Not Found", "301 Moved Permanently"}[i]
				return replaceLine(validResponseDraft(s), "101 Switching Protocols", status)
			}},
		{"missing-accept", 1, "server_response", "HS_MISSING_ACCEPT",
			func(s *Stream, i int) hsDraft {
				draft := validResponseDraft(s)
				lines := strings.Split(strings.TrimSuffix(string(draft.raw), "\r\n\r\n"), "\r\n")
				var kept []string
				for _, line := range lines {
					if strings.HasPrefix(strings.ToLower(line), "sec-websocket-accept:") {
						continue
					}
					kept = append(kept, line)
				}
				draft.raw = joinRequest(kept)
				return draft
			}},
		{"accept-mismatch", 2, "server_response", "HS_ACCEPT_MISMATCH",
			func(s *Stream, i int) hsDraft {
				draft := validResponseDraft(s)
				correct := ComputeAccept(draft.context.ClientKey)
				wrong := ComputeAccept(draft.context.ClientKey + "x")
				if i == 1 {
					wrong = strings.ToLower(correct)
				}
				return replaceLine(draft, correct, wrong)
			}},
		{"response-missing-upgrade", 1, "server_response", "HS_MISSING_UPGRADE",
			func(s *Stream, i int) hsDraft {
				return replaceLine(validResponseDraft(s), "Upgrade: websocket\r\n", "")
			}},
		{"partial-input", 4, "client_request", "incomplete",
			func(s *Stream, i int) hsDraft {
				draft := validRequestDraft(s)
				full := string(draft.raw)
				cuts := []int{0, 4, len(full) / 2, len(full) - 2}
				draft.raw = []byte(full[:cuts[i]])
				return draft
			}},
		{"limit-total-bytes", 1, "client_request", "HS_LIMIT_TOTAL_BYTES",
			func(s *Stream, i int) hsDraft {
				draft := validRequestDraft(s)
				draft.config.MaxHandshakeBytes = len(draft.raw) - 1
				return draft
			}},
		{"limit-header-count", 1, "client_request", "HS_LIMIT_HEADER_COUNT",
			func(s *Stream, i int) hsDraft {
				draft := validRequestDraft(s)
				draft.config.MaxHeaderCount = 2
				return draft
			}},
		{"limit-header-line", 1, "client_request", "HS_LIMIT_HEADER_LINE_BYTES",
			func(s *Stream, i int) hsDraft {
				draft := validRequestDraft(s)
				draft.config.MaxHeaderLineBytes = 8
				return draft
			}},
	}
}

func generateHandshakeTier(seed string) ([]HandshakeCase, PlanCount, error) {
	type draftWithMeta struct {
		family    string
		seedIndex int
		direction string
		draft     hsDraft
		expected  HandshakeExpected
	}
	var drafts []draftWithMeta
	expected := 0
	for _, family := range handshakePlan() {
		for i := 0; i < family.count; i++ {
			expected++
			stream := NewStream(seed, fmt.Sprintf("hs|%s|%d", family.name, i))
			draft := family.build(stream, i)
			verdict, err := DeriveHandshake(family.direction, draft.raw,
				draft.config, draft.context)
			if err != nil {
				return nil, PlanCount{}, fmt.Errorf("handshake %s[%d]: %w",
					family.name, i, err)
			}
			// Fail closed if the rule engine disagrees with the family intent.
			switch family.intent {
			case "accept", "incomplete":
				if verdict.Verdict != family.intent {
					return nil, PlanCount{}, fmt.Errorf(
						"handshake %s[%d]: intent %s but verdict %s (%s)",
						family.name, i, family.intent, verdict.Verdict, verdict.RejectCode)
				}
			default:
				if verdict.Verdict != "reject" || verdict.RejectCode != family.intent {
					return nil, PlanCount{}, fmt.Errorf(
						"handshake %s[%d]: intent %s but verdict %s (%s)",
						family.name, i, family.intent, verdict.Verdict, verdict.RejectCode)
				}
			}
			drafts = append(drafts, draftWithMeta{family: family.name, seedIndex: i,
				direction: family.direction, draft: draft, expected: verdict})
		}
	}

	seen := map[string]bool{}
	var cases []HandshakeCase
	for _, d := range drafts {
		record := HandshakeCase{
			Family:    d.family,
			SeedIndex: d.seedIndex,
			Direction: d.direction,
			RawBase64: base64Std(d.draft.raw),
			Config:    d.draft.config,
			Context:   d.draft.context,
			Expected:  d.expected,
		}
		record.CaseID = "dedup-probe"
		line, err := record.CanonicalLine()
		if err != nil {
			return nil, PlanCount{}, err
		}
		digest := DigestSHA256(line)
		if seen[digest] {
			continue
		}
		seen[digest] = true
		record.CaseID = fmt.Sprintf("us005.hs.%04d", len(cases))
		cases = append(cases, record)
	}
	plan := PlanCount{Expected: expected, Selected: len(cases),
		Filtered: expected - len(cases)}
	return cases, plan, nil
}
