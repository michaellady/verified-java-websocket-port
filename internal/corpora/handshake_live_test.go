package corpora

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// familyJavaResolution is the source-derived Java-runtime observable for every
// committed handshake family. Each row was derived by reading the quarantined
// Java-WebSocket 1.6.0 source (Draft.translateHandshakeHttp,
// Draft_6455.acceptHandshakeAsServer/Client, postProcessHandshakeResponseAsServer,
// WebSocketImpl.decodeHandshake). The Java-side harness tests execute five
// synthetic representative divergence families against the real jar (missing
// Host, missing Upgrade, non-base64 key, duplicated key, bare LF) plus
// synthetic reject/incomplete/client-direction probes; the committed corpus
// itself has not been executed against the jar yet.
//
// stage is the draft-API call that decides a rejection, derived from the same
// source reading and held here INDEPENDENTLY of the model under test: the
// test compares this hand-derived column against what
// ExpectedJavaHandshakeObservable computes, so agreement is a check rather
// than a tautology. Empty for families that do not reject.
var familyJavaResolution = map[string]struct {
	observable string
	channel    string
	stage      string
	divergent  bool
}{
	"valid-client-request":          {JavaObservableAccept, "", "", false},
	"valid-client-case-insensitive": {JavaObservableAccept, "", "", false},
	"valid-server-response":         {JavaObservableAccept, "", "", false},
	"method-not-get":                {JavaObservableReject, JavaRejectInvalidHandshake, JavaStageTranslate, false},
	"http-version":                  {JavaObservableReject, JavaRejectInvalidHandshake, JavaStageTranslate, false},
	"missing-host":                  {JavaObservableAccept, "", "", true},
	"missing-upgrade":               {JavaObservableAccept, "", "", true},
	"upgrade-value":                 {JavaObservableAccept, "", "", true},
	"missing-connection":            {JavaObservableAccept, "", "", true},
	"connection-value":              {JavaObservableAccept, "", "", true},
	"missing-key":                   {JavaObservableReject, JavaRejectInvalidHandshake, JavaStageResponseBuild, false},
	"key-not-base64":                {JavaObservableAccept, "", "", true},
	"key-wrong-length":              {JavaObservableAccept, "", "", true},
	"missing-version":               {JavaObservableReject, JavaRejectNotMatched, JavaStageAcceptPredicate, false},
	"version-unsupported":           {JavaObservableReject, JavaRejectNotMatched, JavaStageAcceptPredicate, false},
	"header-name-not-token":         {JavaObservableAccept, "", "", true},
	"malformed-request-line":        {JavaObservableReject, JavaRejectInvalidHandshake, JavaStageTranslate, false},
	"obs-fold":                      {JavaObservableReject, JavaRejectInvalidHandshake, JavaStageTranslate, false},
	"bare-lf":                       {JavaObservableAccept, "", "", true},
	"status-not-101":                {JavaObservableReject, JavaRejectInvalidHandshake, JavaStageTranslate, false},
	"missing-accept":                {JavaObservableReject, JavaRejectNotMatched, JavaStageAcceptPredicate, false},
	"accept-mismatch":               {JavaObservableReject, JavaRejectNotMatched, JavaStageAcceptPredicate, false},
	"response-missing-upgrade":      {JavaObservableReject, JavaRejectNotMatched, JavaStageAcceptPredicate, false},
	"partial-input":                 {JavaObservableIncomplete, "", "", false},
	"limit-total-bytes":             {JavaObservableAccept, "", "", true},
	"limit-header-count":            {JavaObservableAccept, "", "", true},
	"limit-header-line":             {JavaObservableAccept, "", "", true},
}

func generatedHandshake(t *testing.T) []HandshakeCase {
	t.Helper()
	generated, err := GenerateAll(testInput())
	if err != nil {
		t.Fatalf("GenerateAll: %v", err)
	}
	return generated.Handshake
}

// The wire projection binds the raw case onto the java-oracle handshake
// protocol with a canonical request digest and never leaks the expectation.
func TestHandshakeOracleRequestLineShape(t *testing.T) {
	cases := generatedHandshake(t)
	line, err := HandshakeOracleRequestLine(cases[0])
	if err != nil {
		t.Fatalf("HandshakeOracleRequestLine: %v", err)
	}
	var request map[string]any
	if err := json.Unmarshal(line, &request); err != nil {
		t.Fatalf("wire request not JSON: %v", err)
	}
	for _, field := range []string{"case_id", "direction", "raw_base64", "config",
		"context", "protocol", "version", "request_digest"} {
		if _, present := request[field]; !present {
			t.Fatalf("wire request lacks %s: %s", field, line)
		}
	}
	if request["protocol"] != "java-websocket-handshake-oracle" {
		t.Fatalf("wrong protocol pin: %v", request["protocol"])
	}
	if _, present := request["expected"]; present {
		t.Fatal("wire request must not leak the expected verdict")
	}
	// The digest binds the canonical request without the digest member.
	digest, _ := request["request_digest"].(string)
	delete(request, "request_digest")
	canonical, err := canonicalizeJSONValue(request)
	if err != nil {
		t.Fatal(err)
	}
	if DigestSHA256(canonical) != digest {
		t.Fatal("request_digest does not bind the canonical request")
	}
}

// The Java-parity model resolves every committed case to its source-derived
// runtime observable, including the documented divergences.
func TestExpectedJavaHandshakeObservableAgainstCorpus(t *testing.T) {
	cases := generatedHandshake(t)
	if len(cases) == 0 {
		t.Fatal("no handshake cases generated")
	}
	divergent := 0
	for _, c := range cases {
		family := c.Family
		if family == "duplicate-header" {
			continue // split by seed below
		}
		want, known := familyJavaResolution[family]
		if !known {
			t.Fatalf("family %s has no documented Java resolution", family)
		}
		got, err := ExpectedJavaHandshakeObservable(c)
		if err != nil {
			t.Fatalf("%s (%s): %v", c.CaseID, family, err)
		}
		if got.Observable != want.observable || got.RejectChannel != want.channel {
			t.Fatalf("%s (%s): observable=%s channel=%s, want %s/%s",
				c.CaseID, family, got.Observable, got.RejectChannel,
				want.observable, want.channel)
		}
		if want.divergent != (got.Observable != c.Expected.Verdict) {
			t.Fatalf("%s (%s): divergence flag mismatch (java=%s rfc=%s)",
				c.CaseID, family, got.Observable, c.Expected.Verdict)
		}
		if got.Observable != c.Expected.Verdict {
			divergent++
		}
		// Non-divergent client-request accepts must reproduce the RFC accept
		// value; the Java formula is the same SHA-1 derivation after trim.
		if !want.divergent && got.Observable == JavaObservableAccept &&
			c.Direction == "client_request" {
			if got.SecWebSocketAccept != c.Expected.SecWebSocketAccept {
				t.Fatalf("%s: accept value %q, want %q",
					c.CaseID, got.SecWebSocketAccept, c.Expected.SecWebSocketAccept)
			}
		}
		// Divergent accepts still carry the exact Java-computed accept value.
		if got.Observable == JavaObservableAccept && c.Direction == "client_request" &&
			got.SecWebSocketAccept == "" {
			t.Fatalf("%s: client-request accept lacks the Java accept value", c.CaseID)
		}
		// A client-side ACCEPT carries the value the client MATCHED: the
		// derivation acceptHandshakeAsClient runs over the recorded key
		// (Draft_6455.java:318-325). A client-side REJECT carries none —
		// nothing was matched.
		if c.Direction == "server_response" {
			if got.Observable == JavaObservableAccept {
				derived := ComputeAccept(javaTrim(c.Context.ClientKey))
				if got.SecWebSocketAccept != derived {
					t.Fatalf("%s: server-response accept value %q, want the client's own "+
						"derivation %q", c.CaseID, got.SecWebSocketAccept, derived)
				}
			} else if got.SecWebSocketAccept != "" {
				t.Fatalf("%s: a non-accepting server-response observable must carry no "+
					"accept value, got %q", c.CaseID, got.SecWebSocketAccept)
			}
		}
		// Every rejection names the draft-API call that decided it.
		if got.Observable == JavaObservableReject {
			switch got.RejectStage {
			case JavaStageTranslate, JavaStageAcceptPredicate, JavaStageResponseBuild:
			default:
				t.Fatalf("%s (%s): rejection carries no draft-API stage (got %q)",
					c.CaseID, family, got.RejectStage)
			}
			if want.stage != "" && got.RejectStage != want.stage {
				t.Fatalf("%s (%s): reject_stage %q, want %q",
					c.CaseID, family, got.RejectStage, want.stage)
			}
		} else if got.RejectStage != "" {
			t.Fatalf("%s (%s): non-rejection carries reject_stage %q",
				c.CaseID, family, got.RejectStage)
		}
	}
	// duplicate-header splits on which header is duplicated: a duplicated
	// Sec-WebSocket-Key joins to "a; b" and is accepted; a duplicated
	// Sec-WebSocket-Version joins to "13; 13", fails Integer.parseInt, and is
	// rejected NOT_MATCHED.
	for _, c := range cases {
		if c.Family != "duplicate-header" {
			continue
		}
		got, err := ExpectedJavaHandshakeObservable(c)
		if err != nil {
			t.Fatalf("%s: %v", c.CaseID, err)
		}
		switch c.SeedIndex {
		case 0:
			if got.Observable != JavaObservableAccept {
				t.Fatalf("%s: duplicated key must be a divergent Java accept, got %s/%s",
					c.CaseID, got.Observable, got.RejectChannel)
			}
			divergent++
		case 1:
			if got.Observable != JavaObservableReject || got.RejectChannel != JavaRejectNotMatched {
				t.Fatalf("%s: duplicated version must reject NOT_MATCHED, got %s/%s",
					c.CaseID, got.Observable, got.RejectChannel)
			}
		default:
			t.Fatalf("unexpected duplicate-header seed %d", c.SeedIndex)
		}
	}
	if divergent != 16 {
		t.Fatalf("committed corpus must carry exactly 16 documented divergences, got %d",
			divergent)
	}
}

// The joined duplicate key produces an accept value over the joined string,
// not over either individual key.
func TestDuplicateKeyJoinAcceptValue(t *testing.T) {
	raw := "GET /x HTTP/1.1\r\nHost: h.example\r\nUpgrade: websocket\r\n" +
		"Connection: Upgrade\r\nSec-WebSocket-Key: AAAA\r\nSec-WebSocket-Key: BBBB\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	c := HandshakeCase{CaseID: "t", Direction: "client_request",
		RawBase64: base64Std([]byte(raw)), Config: DefaultHandshakeConfig()}
	got, err := ExpectedJavaHandshakeObservable(c)
	if err != nil {
		t.Fatal(err)
	}
	if got.Observable != JavaObservableAccept {
		t.Fatalf("joined duplicate key must accept, got %s", got.Observable)
	}
	if got.SecWebSocketAccept != ComputeAccept("AAAA; BBBB") {
		t.Fatalf("accept must be computed over the joined value, got %s",
			got.SecWebSocketAccept)
	}
}

// Non-ASCII handshake bytes are outside the calibrated mapping and fail
// closed instead of guessing charset behavior.
func TestParityRejectsNonASCII(t *testing.T) {
	c := HandshakeCase{CaseID: "t", Direction: "client_request",
		RawBase64: base64Std([]byte("GET /\xc3\xa9 HTTP/1.1\r\n\r\n")),
		Config:    DefaultHandshakeConfig()}
	if _, err := ExpectedJavaHandshakeObservable(c); err == nil {
		t.Fatal("non-ASCII bytes must fail closed")
	}
}

// The mapping table covers exactly the reachable (direction, key) surface of
// the Go reference model and stays coherent with the parity model over the
// committed corpus.
func TestHandshakeVerdictMappingCoverage(t *testing.T) {
	// Every verdict key DeriveHandshakeWith can emit, per direction, read from
	// internal/corpora/handshake.go.
	reachable := map[string][]string{
		"client_request": {
			"accept", "incomplete",
			"HS_LIMIT_TOTAL_BYTES", "HS_BARE_LF", "HS_LIMIT_HEADER_COUNT",
			"HS_MALFORMED_REQUEST_LINE", "HS_METHOD_NOT_GET", "HS_HTTP_VERSION",
			"HS_LIMIT_HEADER_LINE_BYTES", "HS_OBS_FOLD", "HS_MALFORMED_HEADER",
			"HS_HEADER_NAME_NOT_TOKEN", "HS_DUPLICATE_HEADER", "HS_MISSING_HOST",
			"HS_MISSING_UPGRADE", "HS_UPGRADE_VALUE", "HS_MISSING_CONNECTION",
			"HS_CONNECTION_VALUE", "HS_MISSING_KEY", "HS_KEY_NOT_BASE64",
			"HS_KEY_LENGTH", "HS_MISSING_VERSION", "HS_VERSION_UNSUPPORTED",
		},
		"server_response": {
			"accept", "incomplete",
			"HS_LIMIT_TOTAL_BYTES", "HS_BARE_LF", "HS_LIMIT_HEADER_COUNT",
			"HS_MALFORMED_STATUS_LINE", "HS_HTTP_VERSION", "HS_STATUS_NOT_101",
			"HS_LIMIT_HEADER_LINE_BYTES", "HS_OBS_FOLD", "HS_MALFORMED_HEADER",
			"HS_HEADER_NAME_NOT_TOKEN", "HS_DUPLICATE_HEADER",
			"HS_MISSING_UPGRADE", "HS_UPGRADE_VALUE", "HS_MISSING_CONNECTION",
			"HS_CONNECTION_VALUE", "HS_MISSING_ACCEPT", "HS_ACCEPT_MISMATCH",
		},
	}
	table := HandshakeVerdictMapping()
	indexed := map[string]HandshakeMappingEntry{}
	for _, entry := range table {
		key := entry.Direction + "|" + entry.Key
		if _, duplicate := indexed[key]; duplicate {
			t.Fatalf("duplicate mapping entry %s", key)
		}
		if len(entry.Basis) == 0 {
			t.Fatalf("mapping entry %s carries no source basis", key)
		}
		indexed[key] = entry
	}
	total := 0
	for direction, keys := range reachable {
		for _, key := range keys {
			total++
			entry, present := indexed[direction+"|"+key]
			if !present {
				t.Fatalf("mapping table lacks %s|%s", direction, key)
			}
			switch entry.JavaObservable {
			case JavaObservableAccept, JavaObservableReject, JavaObservableIncomplete,
				JavaObservableConditional:
			default:
				t.Fatalf("mapping %s|%s has invalid observable %q",
					direction, key, entry.JavaObservable)
			}
			// A fixed accept where the model rejects (or the reverse) must be
			// flagged divergent; conditional entries document their condition.
			if entry.JavaObservable == JavaObservableConditional && entry.Condition == "" {
				t.Fatalf("conditional mapping %s|%s lacks its condition", direction, key)
			}
		}
	}
	if len(table) != total {
		t.Fatalf("mapping table has %d entries, reachable surface is %d",
			len(table), total)
	}

	// Coherence with the parity model over every committed case.
	for _, c := range generatedHandshake(t) {
		key := c.Expected.Verdict
		if c.Expected.RejectCode != "" {
			key = c.Expected.RejectCode
		}
		entry, present := indexed[c.Direction+"|"+key]
		if !present {
			t.Fatalf("committed case %s has no mapping entry %s|%s",
				c.CaseID, c.Direction, key)
		}
		got, err := ExpectedJavaHandshakeObservable(c)
		if err != nil {
			t.Fatalf("%s: %v", c.CaseID, err)
		}
		if entry.JavaObservable != JavaObservableConditional {
			if got.Observable != entry.JavaObservable {
				t.Fatalf("%s: parity %s disagrees with mapping %s for %s|%s",
					c.CaseID, got.Observable, entry.JavaObservable, c.Direction, key)
			}
			if entry.Divergent != (got.Observable != c.Expected.Verdict) {
				t.Fatalf("%s: mapping divergence flag incoherent for %s|%s",
					c.CaseID, c.Direction, key)
			}
		}
	}
}

// The committed evidence document is byte-identical to the in-code table so
// the document and the adapter can never drift apart.
func TestHandshakeLiveMappingEvidenceDocument(t *testing.T) {
	path, err := filepath.Abs("../../evidence/us005-handshake-live-mapping.json")
	if err != nil {
		t.Fatal(err)
	}
	committed, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("mapping evidence document missing: %v", err)
	}
	rendered, err := RenderHandshakeLiveMappingDocument()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(committed, rendered) {
		t.Fatal("evidence/us005-handshake-live-mapping.json is not byte-identical " +
			"to HandshakeVerdictMapping(); regenerate the document from the table")
	}
}

func liveTranscript(t *testing.T, cases []HandshakeCase) []byte {
	t.Helper()
	var transcript bytes.Buffer
	for _, c := range cases {
		line, err := synthesizeHandshakeLiveResponse(c)
		if err != nil {
			t.Fatal(err)
		}
		transcript.Write(line)
		transcript.WriteByte('\n')
	}
	return transcript.Bytes()
}

// A faithful Java-runtime transcript reconciles and surfaces every
// documented divergence explicitly.
func TestEvaluateHandshakeLiveTranscript(t *testing.T) {
	cases := generatedHandshake(t)
	report, err := EvaluateHandshakeLiveTranscript(cases, liveTranscript(t, cases))
	if err != nil {
		t.Fatalf("EvaluateHandshakeLiveTranscript: %v", err)
	}
	if report.Executed != len(cases) || report.Passed != len(cases) ||
		!report.Reconciled() {
		t.Fatalf("faithful transcript must reconcile: %+v", report.TranscriptReport)
	}
	if len(report.Divergences) != 16 {
		t.Fatalf("report must surface the 16 documented divergences, got %d",
			len(report.Divergences))
	}
}

func TestEvaluateHandshakeLiveTranscriptFailsClosed(t *testing.T) {
	cases := generatedHandshake(t)[:6]
	transcript := string(liveTranscript(t, cases))

	// A flipped observable fails.
	flipped := strings.Replace(transcript, `"java_observable":"`,
		`"java_observable":"x`, 1)
	report, err := EvaluateHandshakeLiveTranscript(cases, []byte(flipped))
	if err != nil {
		t.Fatal(err)
	}
	if report.Failed == 0 || report.Reconciled() {
		t.Fatalf("flipped observable must fail: %+v", report.TranscriptReport)
	}

	// A drifted accept value fails.
	drifted := strings.Replace(transcript, `"sec_websocket_accept":"`,
		`"sec_websocket_accept":"x`, 1)
	report, err = EvaluateHandshakeLiveTranscript(cases, []byte(drifted))
	if err != nil {
		t.Fatal(err)
	}
	if report.Failed == 0 {
		t.Fatalf("drifted accept value must fail: %+v", report.TranscriptReport)
	}

	// A drifted reject stage fails. The seed slice above is all accepts, so
	// this one runs over the reject families.
	rejects := generatedHandshake(t)[9:13] // method-not-get, http-version
	rejectTranscript := string(liveTranscript(t, rejects))
	if !strings.Contains(rejectTranscript, `"reject_stage":"translate"`) {
		t.Fatalf("fixture must carry a translate-stage rejection: %s", rejectTranscript)
	}
	for _, drift := range []string{"accept_predicate", "response_build", ""} {
		drifted := strings.Replace(rejectTranscript, `"reject_stage":"translate"`,
			`"reject_stage":"`+drift+`"`, 1)
		report, err := EvaluateHandshakeLiveTranscript(rejects, []byte(drifted))
		if err != nil {
			t.Fatal(err)
		}
		if report.Failed == 0 {
			t.Fatalf("reject_stage drifted to %q must fail: %+v",
				drift, report.TranscriptReport)
		}
	}
	// An ABSENT reject stage fails too: the check is fail-closed, not
	// "compare it when it happens to be there".
	stripped := strings.Replace(rejectTranscript, `"reject_stage":"translate",`, "", 1)
	report, err = EvaluateHandshakeLiveTranscript(rejects, []byte(stripped))
	if err != nil {
		t.Fatal(err)
	}
	if report.Failed == 0 {
		t.Fatalf("absent reject_stage must fail: %+v", report.TranscriptReport)
	}

	// A client-side accept that reports NO accept value fails: the client
	// derives one on every acceptance and matching it is the whole predicate.
	clientAccepts := generatedHandshake(t)[6:9] // valid-server-response
	clientTranscript := string(liveTranscript(t, clientAccepts))
	if !strings.Contains(clientTranscript, `"sec_websocket_accept"`) {
		t.Fatalf("client-side accept fixture must carry an accept value: %s",
			clientTranscript)
	}
	first := strings.SplitN(clientTranscript, "\n", 2)
	var decoded map[string]any
	if err := json.Unmarshal([]byte(first[0]), &decoded); err != nil {
		t.Fatal(err)
	}
	delete(decoded, "sec_websocket_accept")
	reencoded, err := CanonicalJSON(decoded)
	if err != nil {
		t.Fatal(err)
	}
	report, err = EvaluateHandshakeLiveTranscript(clientAccepts,
		append(append([]byte{}, reencoded...), append([]byte("\n"), first[1]...)...))
	if err != nil {
		t.Fatal(err)
	}
	if report.Failed == 0 {
		t.Fatalf("client-side accept without an accept value must fail: %+v",
			report.TranscriptReport)
	}
	// And a client-side accept whose value is not the client's own derivation
	// fails: a port that echoed some other string would be caught.
	forged := strings.Replace(clientTranscript, `"sec_websocket_accept":"`,
		`"sec_websocket_accept":"x`, 1)
	report, err = EvaluateHandshakeLiveTranscript(clientAccepts, []byte(forged))
	if err != nil {
		t.Fatal(err)
	}
	if report.Failed == 0 {
		t.Fatalf("forged client-side accept value must fail: %+v",
			report.TranscriptReport)
	}

	// A drifted request digest fails.
	lines := strings.Split(strings.TrimRight(transcript, "\n"), "\n")
	unbound := strings.Replace(lines[0], `"request_digest":"sha256:`,
		`"request_digest":"sha256:0`, 1)
	report, err = EvaluateHandshakeLiveTranscript(cases,
		[]byte(unbound+"\n"+strings.Join(lines[1:], "\n")))
	if err != nil {
		t.Fatal(err)
	}
	if report.Failed == 0 {
		t.Fatalf("unbound digest must fail: %+v", report.TranscriptReport)
	}

	// Missing responses block.
	report, err = EvaluateHandshakeLiveTranscript(cases,
		[]byte(strings.Join(lines[1:], "\n")))
	if err != nil {
		t.Fatal(err)
	}
	if report.Missing != 1 || report.Reconciled() {
		t.Fatalf("missing response must block: %+v", report.TranscriptReport)
	}

	// Duplicates error.
	if _, err = EvaluateHandshakeLiveTranscript(cases,
		[]byte(transcript+lines[0]+"\n")); err == nil {
		t.Fatal("duplicate response must error")
	}

	// Unmatched responses count.
	report, err = EvaluateHandshakeLiveTranscript(cases[:5], []byte(transcript))
	if err != nil {
		t.Fatal(err)
	}
	if report.Unmatched != 1 || report.Reconciled() {
		t.Fatalf("unmatched response must block: %+v", report.TranscriptReport)
	}

	// A line without case_id is a hard error.
	if _, err = EvaluateHandshakeLiveTranscript(cases,
		[]byte(`{"protocol":"x"}`+"\n")); err == nil {
		t.Fatal("line without case_id must error")
	}
}

// The evaluator binds the runtime attestation fail-closed, mirroring the
// behavior evaluate path (RunJavaOracle, internal/lab/oracle.go): a transcript
// line whose runtime binding is absent or forged — removed field, wrong jar
// digest, wrong artifact, wrong protocol id — never passes.
func TestEvaluateHandshakeLiveRuntimeBinding(t *testing.T) {
	cases := generatedHandshake(t)[:1]
	line, err := synthesizeHandshakeLiveResponse(cases[0])
	if err != nil {
		t.Fatal(err)
	}
	faithful := string(line)
	if !strings.Contains(faithful, `"runtime":`) {
		t.Fatalf("synthesized response must carry the runtime attestation: %s", faithful)
	}

	mutations := map[string]string{
		"removed runtime binding": strings.Replace(faithful,
			`"runtime":`, `"runtime_removed":`, 1),
		"wrong jar digest": strings.Replace(faithful,
			`"sha256":"sha256:e`, `"sha256":"sha256:0`, 1),
		"wrong runtime artifact": strings.Replace(faithful,
			`"artifact":"org.java-websocket:Java-WebSocket:1.6.0"`,
			`"artifact":"org.java-websocket:Java-WebSocket:1.5.7"`, 1),
		"wrong protocol id": strings.Replace(faithful,
			`"protocol":"java-websocket-handshake-oracle"`,
			`"protocol":"java-websocket-oracle"`, 1),
	}
	for name, mutated := range mutations {
		if mutated == faithful {
			t.Fatalf("%s: mutation did not apply", name)
		}
		report, err := EvaluateHandshakeLiveTranscript(cases, []byte(mutated+"\n"))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if report.Failed != 1 || report.Reconciled() {
			t.Fatalf("%s must fail closed: %+v", name, report.TranscriptReport)
		}
	}

	// The faithful attestation still passes.
	report, err := EvaluateHandshakeLiveTranscript(cases, []byte(faithful+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed != 1 || !report.Reconciled() {
		t.Fatalf("faithful runtime binding must pass: %+v", report.TranscriptReport)
	}
}

// Presence parity: accepts must not appear without their observable payload
// and rejects must carry the runtime close code and channel.
func TestEvaluateHandshakeLivePresenceParity(t *testing.T) {
	cases := generatedHandshake(t)
	var acceptCase, rejectCase *HandshakeCase
	for i := range cases {
		expected, err := ExpectedJavaHandshakeObservable(cases[i])
		if err != nil {
			t.Fatal(err)
		}
		if acceptCase == nil && expected.Observable == JavaObservableAccept &&
			cases[i].Direction == "client_request" {
			acceptCase = &cases[i]
		}
		if rejectCase == nil && expected.Observable == JavaObservableReject {
			rejectCase = &cases[i]
		}
	}
	if acceptCase == nil || rejectCase == nil {
		t.Fatal("corpus lacks accept or reject representatives")
	}

	acceptLine, err := synthesizeHandshakeLiveResponse(*acceptCase)
	if err != nil {
		t.Fatal(err)
	}
	stripped := strings.Replace(string(acceptLine), `"sec_websocket_accept"`,
		`"sec_websocket_removed"`, 1)
	report, err := EvaluateHandshakeLiveTranscript(
		[]HandshakeCase{*acceptCase}, []byte(stripped+"\n"))
	if err == nil && report.Failed == 0 {
		t.Fatal("accept without its accept value must not pass")
	}

	rejectLine, err := synthesizeHandshakeLiveResponse(*rejectCase)
	if err != nil {
		t.Fatal(err)
	}
	noChannel := strings.Replace(string(rejectLine), `"reject_channel"`,
		`"reject_removed"`, 1)
	report, err = EvaluateHandshakeLiveTranscript(
		[]HandshakeCase{*rejectCase}, []byte(noChannel+"\n"))
	if err == nil && report.Failed == 0 {
		t.Fatal("reject without its channel must not pass")
	}

	// Presence parity runs the other way too: a NON-rejection that carries a
	// reject_stage must not pass. Without this, a responder could attach a
	// stage to an accept and nothing would notice.
	acceptWithStage := strings.Replace(string(acceptLine), `"sec_websocket_accept"`,
		`"reject_stage":"translate","sec_websocket_accept"`, 1)
	report, err = EvaluateHandshakeLiveTranscript(
		[]HandshakeCase{*acceptCase}, []byte(acceptWithStage+"\n"))
	if err == nil && report.Failed == 0 {
		t.Fatal("accept carrying a reject_stage must not pass")
	}

	// And a rejection stripped of its stage must not pass, mirroring the
	// channel check directly above it.
	noStage := strings.Replace(string(rejectLine), `"reject_stage"`,
		`"stage_removed"`, 1)
	report, err = EvaluateHandshakeLiveTranscript(
		[]HandshakeCase{*rejectCase}, []byte(noStage+"\n"))
	if err == nil && report.Failed == 0 {
		t.Fatal("reject without its stage must not pass")
	}
}
