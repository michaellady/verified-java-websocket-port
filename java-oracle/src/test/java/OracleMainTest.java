import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** Dependency-free executable test harness; intentionally outside the upstream Maven inventory. */
public final class OracleMainTest {
  private static int tests;
  private static String runtimeDigest;

  private OracleMainTest() {}

  public static void main(String[] args) throws Exception {
    System.setProperty("slf4j.internal.verbosity", "ERROR");
    runtimeDigest = OracleMain.verifyRuntime();
    testRuntimeBinding();
    testUtf8ProtocolOutput();
    testDeterministicReplay();
    testChunkPartitionSemantics();
    testFragmentAndBufferedCounts();
    testLocalActionsAndClose();
    testRemoteCloseAndServerMasking();
    testJavaRuntimeInvalidFrame();
    testStrictJsonAndShapeRejections();
    testLimits();
    testJsonlBoundaryAndStdoutIsolation();
    testCanonicalKeyOrder();
    testMavenProjectContract();
    testHandshakeAcceptVector();
    testHandshakeDivergentAccepts();
    testHandshakeServerRejections();
    testHandshakeIncomplete();
    testHandshakeClientDirection();
    testHandshakeProtocolStrictness();
    System.out.println("PASS " + tests + " java-oracle tests");
  }

  private static void testUtf8ProtocolOutput() {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    PrintStream protocol = OracleMain.protocolOutput(output);
    protocol.print("漢ñ");
    protocol.flush();
    equal("漢ñ", output.toString(StandardCharsets.UTF_8),
        "protocol output is UTF-8 independent of the process locale");
    pass();
  }

  private static void testRuntimeBinding() {
    equal("sha256:" + OracleMain.EXPECTED_RUNTIME_SHA256, runtimeDigest,
        "loaded runtime digest");
    pass();
  }

  private static void testDeterministicReplay() throws Exception {
    String request = request("replay-1",
        "[{\"kind\":\"bytes\",\"data_base64\":\"gQJoaQ==\"},"
            + "{\"kind\":\"action\",\"action\":\"send_ping\",\"data_base64\":\"\"}]");
    String first = StrictJson.write(OracleEngine.process(request, runtimeDigest));
    String second = StrictJson.write(OracleEngine.process(request, runtimeDigest));
    equal(first, second, "same scenario must be byte-identical");
    Map<String, Object> response = object(StrictJson.parse(first));
    equal("ok", response.get("outcome"), "replay outcome");
    equal("open", response.get("final_state"), "replay state");
    pass();
  }

  private static void testChunkPartitionSemantics() throws Exception {
    Map<String, Object> whole = OracleEngine.process(request("whole",
        "[{\"kind\":\"bytes\",\"data_base64\":\"gQJoaQ==\"}]"), runtimeDigest);
    Map<String, Object> split = OracleEngine.process(request("split",
        "[{\"kind\":\"bytes\",\"data_base64\":\"gQ==\"},"
            + "{\"kind\":\"bytes\",\"data_base64\":\"Amhp\"}]"), runtimeDigest);
    equal(stripSteps(whole.get("frames")), stripSteps(split.get("frames")),
        "semantic frames are chunk-partition invariant");
    equal(semanticEvents(whole.get("events")), semanticEvents(split.get("events")),
        "semantic events are chunk-partition invariant");
    Map<String, Object> wholeCounts = object(whole.get("counts"));
    Map<String, Object> splitCounts = object(split.get("counts"));
    equal(wholeCounts.get("consumed_bytes"), splitCounts.get("consumed_bytes"),
        "consumed byte count");
    equal(0L, ((Number) splitCounts.get("buffered_bytes")).longValue(),
        "split frame drains buffering");
    pass();
  }

  private static void testLocalActionsAndClose() throws Exception {
    String steps = "["
        + "{\"kind\":\"action\",\"action\":\"send_text\",\"text\":\"hello\"},"
        + "{\"kind\":\"action\",\"action\":\"send_binary\",\"data_base64\":\"AAE=\"},"
        + "{\"kind\":\"action\",\"action\":\"send_ping\",\"data_base64\":\"eA==\"},"
        + "{\"kind\":\"action\",\"action\":\"send_pong\",\"data_base64\":\"eQ==\"},"
        + "{\"kind\":\"action\",\"action\":\"send_fragment\","
        + "\"opcode\":\"text\",\"data_base64\":\"YQ==\",\"fin\":false},"
        + "{\"kind\":\"action\",\"action\":\"send_fragment\","
        + "\"opcode\":\"text\",\"data_base64\":\"Yg==\",\"fin\":true},"
        + "{\"kind\":\"action\",\"action\":\"send_close\","
        + "\"code\":1000,\"reason\":\"done\"},"
        + "{\"kind\":\"action\",\"action\":\"eof\"}]";
    Map<String, Object> response = OracleEngine.process(request("actions", steps), runtimeDigest);
    equal("ok", response.get("outcome"), "actions outcome");
    equal("closed", response.get("final_state"), "actions final state");
    Map<String, Object> close = object(response.get("close"));
    equal(1000L, ((Number) close.get("code")).longValue(), "close code");
    equal("done", close.get("reason"), "close reason");
    equal(Boolean.FALSE, close.get("handshake_complete"),
        "local close followed by EOF lacks peer close");
    List<Object> frames = list(response.get("frames"));
    equal(7, frames.size(), "outbound frame count");
    for (Object item : frames) {
      equal(Boolean.TRUE, object(item).get("masked"), "client output is masked");
    }
    List<Object> transitions = list(response.get("transitions"));
    equal(2, transitions.size(), "close transitions");
    pass();
  }

  private static void testFragmentAndBufferedCounts() throws Exception {
    Map<String, Object> partial = OracleEngine.process(request("partial",
        "[{\"kind\":\"bytes\",\"data_base64\":\"gQ==\"}]"), runtimeDigest);
    equal("ok", partial.get("outcome"), "partial input remains observable");
    Map<String, Object> partialCounts = object(partial.get("counts"));
    equal(1L, ((Number) partialCounts.get("consumed_bytes")).longValue(),
        "partial input consumed");
    equal(1L, ((Number) partialCounts.get("wire_buffered_bytes")).longValue(),
        "partial wire buffering");

    Map<String, Object> fragmented = OracleEngine.process(request("fragmented",
        "[{\"kind\":\"bytes\",\"data_base64\":\"AQJoZQ==\"},"
            + "{\"kind\":\"bytes\",\"data_base64\":\"gANsbG8=\"}]"), runtimeDigest);
    equal("ok", fragmented.get("outcome"), "fragmented input outcome");
    List<Object> semantic = list(semanticEvents(fragmented.get("events")));
    equal(1, semantic.size(), "one reassembled semantic event");
    equal("hello", object(semantic.get(0)).get("text"), "reassembled text");
    equal(0L, ((Number) object(fragmented.get("counts")).get("buffered_bytes")).longValue(),
        "fragment buffering drains");
    pass();
  }

  private static void testRemoteCloseAndServerMasking() throws Exception {
    Map<String, Object> close = OracleEngine.process(request("remote-close",
        "[{\"kind\":\"bytes\",\"data_base64\":\"iAA=\"}]"), runtimeDigest);
    equal("closing", close.get("final_state"), "remote close enters closing");
    List<Object> closeFrames = list(close.get("frames"));
    equal(2, closeFrames.size(), "remote close is echoed by two-way Java handshake");
    equal("inbound", object(closeFrames.get(0)).get("direction"), "received close");
    equal("outbound", object(closeFrames.get(1)).get("direction"), "echoed close");
    equal(Boolean.TRUE, object(close.get("close")).get("handshake_complete"),
        "received and echoed close completes handshake");

    String serverRequest = request("server-mask",
        "[{\"kind\":\"action\",\"action\":\"send_text\",\"text\":\"x\"}]")
        .replace("\"role\":\"client\"", "\"role\":\"server\"");
    serverRequest = rebind(serverRequest);
    Map<String, Object> server = OracleEngine.process(serverRequest, runtimeDigest);
    equal(Boolean.FALSE, object(list(server.get("frames")).get(0)).get("masked"),
        "server output is unmasked");

    Map<String, Object> stateError = OracleEngine.process(
        rebind(request("closed-state",
            "[{\"kind\":\"action\",\"action\":\"send_text\",\"text\":\"x\"}]")
            .replace("\"initial_state\":\"open\"", "\"initial_state\":\"closed\"")),
        runtimeDigest);
    equal("STATE_VIOLATION", object(stateError.get("error")).get("code"),
        "closed state rejects sends");
    pass();
  }

  private static void testJavaRuntimeInvalidFrame() throws Exception {
    // Reserved opcode 3: translation must be rejected by the accepted Java runtime.
    Map<String, Object> response = OracleEngine.process(request("invalid-frame",
        "[{\"kind\":\"bytes\",\"data_base64\":\"gwA=\"}]"), runtimeDigest);
    equal("error", response.get("outcome"), "invalid frame outcome");
    Map<String, Object> error = object(response.get("error"));
    equal("JAVA_INVALID_DATA", error.get("code"), "runtime invalid-data type");
    equal(1002L, ((Number) error.get("close_code")).longValue(), "runtime close code");
    pass();
  }

  private static void testStrictJsonAndShapeRejections() throws Exception {
    expectCode("DUPLICATE_FIELD", () -> StrictJson.parse("{\"x\":1,\"x\":2}"));
    expectCode("INVALID_UNICODE", () -> StrictJson.parse("\"\\ud800\""));
    expectCode("UNKNOWN_FIELD", () -> OracleEngine.process(
        request("unknown", "[]").replace("\"steps\":[]", "\"steps\":[],\"extra\":1"),
        runtimeDigest));
    expectCode("TYPE_MISMATCH", () -> OracleEngine.process(
        rebind(request("type", "[]").replace("\"max_frames\":32", "\"max_frames\":1.5")),
        runtimeDigest));
    expectCode("INVALID_ENUM", () -> OracleEngine.process(
        rebind(request("case", "[]").replace("\"role\":\"client\"", "\"role\":\"CLIENT\"")),
        runtimeDigest));
    expectCode("REQUEST_DIGEST_MISMATCH", () -> OracleEngine.process(
        request("digest", "[]").replace("\"role\":\"client\"", "\"role\":\"server\""),
        runtimeDigest));
    Map<String, Object> badBase64 = OracleEngine.process(request("b64",
        "[{\"kind\":\"bytes\",\"data_base64\":\"gQ\"}]"), runtimeDigest);
    equal("INVALID_BASE64", object(badBase64.get("error")).get("code"),
        "non-canonical base64 denied");
    Map<String, Object> badField = OracleEngine.process(request("action-field",
        "[{\"kind\":\"action\",\"action\":\"eof\",\"reason\":\"x\"}]"), runtimeDigest);
    equal("UNKNOWN_FIELD", object(badField.get("error")).get("code"),
        "action unknown field denied");
    pass();
  }

  private static void testLimits() throws Exception {
    Map<String, Object> input = OracleEngine.process(request("input-limit",
        "[{\"kind\":\"bytes\",\"data_base64\":\"gQJoaQ==\"}]", 3, 64, 8, 32, 65536),
        runtimeDigest);
    equal("INPUT_LIMIT_EXCEEDED", object(input.get("error")).get("code"), "input limit");

    Map<String, Object> actions = OracleEngine.process(request("action-limit",
        "[{\"kind\":\"action\",\"action\":\"send_ping\",\"data_base64\":\"\"}]",
        64, 64, 0, 32, 65536), runtimeDigest);
    equal("ACTION_LIMIT_EXCEEDED", object(actions.get("error")).get("code"), "action limit");

    Map<String, Object> buffered = OracleEngine.process(request("buffer-limit",
        "[{\"kind\":\"bytes\",\"data_base64\":\"gn5hYg==\"}]",
        64, 1, 8, 32, 65536), runtimeDigest);
    equal("JAVA_INVALID_DATA", object(buffered.get("error")).get("code"), "runtime frame limit");

    Map<String, Object> manyCompleteFrames = OracleEngine.process(request("small-buffer-many-frames",
        "[{\"kind\":\"bytes\",\"data_base64\":\"gQCBAA==\"}]",
        64, 1, 8, 32, 65536), runtimeDigest);
    equal("ok", manyCompleteFrames.get("outcome"),
        "buffer limit does not reject multiple complete empty frames");

    Map<String, Object> output = OracleEngine.process(request("output-limit",
        "[{\"kind\":\"action\",\"action\":\"send_text\",\"text\":\""
            + "x".repeat(400) + "\"}]", 1024, 1024, 8, 32, 512), runtimeDigest);
    equal("OUTPUT_LIMIT_EXCEEDED", object(output.get("error")).get("code"), "output limit");
    pass();
  }

  private static void testJsonlBoundaryAndStdoutIsolation() throws Exception {
    String input = request("line-1", "[]") + "\n" + request("line-2", "[]") + "\n";
    ByteArrayOutputStream stdout = new ByteArrayOutputStream();
    ByteArrayOutputStream stderr = new ByteArrayOutputStream();
    OracleMain.run(new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)),
        new PrintStream(stdout, true, StandardCharsets.UTF_8),
        new PrintStream(stderr, true, StandardCharsets.UTF_8), runtimeDigest);
    String[] lines = stdout.toString(StandardCharsets.UTF_8).split("\\n");
    equal(2, lines.length, "one output per input line");
    equal("line-1", object(StrictJson.parse(lines[0])).get("request_id"), "first id");
    equal("line-2", object(StrictJson.parse(lines[1])).get("request_id"), "second id");
    equal("", stderr.toString(StandardCharsets.UTF_8), "valid requests emit no diagnostics");

    byte[] longLine = (" ".repeat(OracleMain.HARD_LINE_BYTES + 1) + "\n")
        .getBytes(StandardCharsets.UTF_8);
    stdout.reset();
    OracleMain.run(new ByteArrayInputStream(longLine),
        new PrintStream(stdout, true, StandardCharsets.UTF_8),
        new PrintStream(stderr, true, StandardCharsets.UTF_8), runtimeDigest);
    Map<String, Object> response = object(StrictJson.parse(
        stdout.toString(StandardCharsets.UTF_8).trim()));
    equal("LINE_LIMIT_EXCEEDED", object(response.get("error")).get("code"), "line limit");
    pass();
  }

  private static void testCanonicalKeyOrder() throws Exception {
    String output = StrictJson.write(OracleEngine.process(request("keys", "[]"), runtimeDigest));
    check(output.startsWith("{\"close\":"), "top-level keys must be lexicographically ordered");
    equal(output, StrictJson.write(StrictJson.parse(output)), "canonical output round-trip");
    pass();
  }

  private static void testMavenProjectContract() throws Exception {
    String pom = java.nio.file.Files.readString(java.nio.file.Path.of("pom.xml"),
        StandardCharsets.UTF_8);
    check(pom.contains("<maven.compiler.release>17</maven.compiler.release>"),
        "Maven build must target Java 17");
    check(pom.contains("<arg>-Xlint:all</arg>") && pom.contains("<arg>-Werror</arg>"),
        "Maven build must fail on compiler warnings");
    check(pom.contains("<systemPath>${java.websocket.jar}</systemPath>"),
        "Maven build must consume the external promoted runtime path");
    check(pom.contains("<id>run-oracle-main-test</id>")
            && pom.contains("classname=\"OracleMainTest\""),
        "Maven test phase must execute the pure Java harness");
    check(!pom.contains("<repositories>") && !pom.toLowerCase(java.util.Locale.ROOT).contains("junit"),
        "Maven project must not add repositories or a test framework");
    pass();
  }

  // --- handshake mode -------------------------------------------------------

  private static final String RFC_SAMPLE_KEY = "dGhlIHNhbXBsZSBub25jZQ==";
  private static final String RFC_SAMPLE_ACCEPT = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

  private static String validClientRequest(String key) {
    return "GET /chat HTTP/1.1\r\nHost: server.example.com\r\n"
        + "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        + "Sec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n\r\n";
  }

  private static String validServerResponse(String accept) {
    return "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
        + "Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n";
  }

  private static String handshakeRequest(String caseId, String direction, String raw,
      String clientKey) {
    String context = clientKey == null ? "{}" : "{\"client_key\":\"" + clientKey + "\"}";
    String unsigned = "{\"case_id\":\"" + caseId + "\",\"config\":{"
        + "\"max_handshake_bytes\":4096,\"max_header_count\":32,"
        + "\"max_header_line_bytes\":512},\"context\":" + context + ","
        + "\"direction\":\"" + direction + "\","
        + "\"protocol\":\"java-websocket-handshake-oracle\","
        + "\"raw_base64\":\"" + java.util.Base64.getEncoder()
            .encodeToString(raw.getBytes(StandardCharsets.US_ASCII)) + "\","
        + "\"version\":\"1.0.0\"}";
    return rebind(unsigned);
  }

  /** RFC 6455 section 1.3 accept derivation after Java's String.trim, computed independently. */
  private static String acceptFor(String key) throws Exception {
    byte[] digest = java.security.MessageDigest.getInstance("SHA-1").digest(
        (key.trim() + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
            .getBytes(StandardCharsets.US_ASCII));
    return java.util.Base64.getEncoder().encodeToString(digest);
  }

  private static Map<String, Object> handshake(String caseId, String direction, String raw,
      String clientKey) throws Exception {
    Map<String, Object> response = OracleEngine.process(
        handshakeRequest(caseId, direction, raw, clientKey), runtimeDigest);
    equal(caseId, response.get("case_id"), "handshake response case binding");
    equal("java-websocket-handshake-oracle", response.get("protocol"),
        "handshake response protocol pin");
    equal("1.0.0", response.get("version"), "handshake response version pin");
    equal(runtimeDigest, object(response.get("runtime")).get("sha256"),
        "handshake response runtime binding");
    return response;
  }

  private static void expectHandshakeReject(String caseId, String raw, String direction,
      String clientKey, String channel) throws Exception {
    Map<String, Object> response = handshake(caseId, direction, raw, clientKey);
    equal("reject", response.get("java_observable"), caseId + " observable");
    equal(channel, response.get("reject_channel"), caseId + " reject channel");
    equal(1002L, ((Number) response.get("close_code")).longValue(),
        caseId + " close code");
    check(!response.containsKey("sec_websocket_accept"),
        caseId + " reject must not carry an accept value");
  }

  /** The real runtime accepts the RFC 6455 sample handshake with the published accept value. */
  private static void testHandshakeAcceptVector() throws Exception {
    Map<String, Object> response = handshake("hs-accept", "client_request",
        validClientRequest(RFC_SAMPLE_KEY), null);
    equal("accept", response.get("java_observable"), "sample handshake observable");
    equal(RFC_SAMPLE_ACCEPT, response.get("sec_websocket_accept"),
        "RFC 6455 sample accept value");
    check(!response.containsKey("reject_channel"), "accept has no reject channel");
    check(!response.containsKey("close_code"), "accept has no close code");

    // Deterministic replay: the same case is byte-identical.
    String request = handshakeRequest("hs-replay", "client_request",
        validClientRequest(RFC_SAMPLE_KEY), null);
    equal(StrictJson.write(OracleEngine.process(request, runtimeDigest)),
        StrictJson.write(OracleEngine.process(request, runtimeDigest)),
        "handshake replay is byte-identical");

    // Case-insensitive header names and token lists still accept.
    String insensitive = "GET /chat HTTP/1.1\r\nhost: server.example.com\r\n"
        + "upgrade: WebSocket\r\nCONNECTION: keep-alive, Upgrade\r\n"
        + "sec-websocket-key: " + RFC_SAMPLE_KEY + "\r\nSEC-WEBSOCKET-VERSION: 13\r\n\r\n";
    Map<String, Object> mixed = handshake("hs-insensitive", "client_request",
        insensitive, null);
    equal("accept", mixed.get("java_observable"), "case-insensitive observable");
    equal(RFC_SAMPLE_ACCEPT, mixed.get("sec_websocket_accept"),
        "case-insensitive accept value");
    pass();
  }

  /**
   * Source-derived divergences, proven against the real jar: the server
   * handshake never checks Host, Upgrade, Connection, or the key encoding
   * (acceptHandshakeAsServer checks only Sec-WebSocket-Version), duplicates
   * join with "; ", and a bare LF folds into the following CRLF line.
   */
  private static void testHandshakeDivergentAccepts() throws Exception {
    String missingHost = validClientRequest(RFC_SAMPLE_KEY)
        .replace("Host: server.example.com\r\n", "");
    equal("accept", handshake("hs-missing-host", "client_request", missingHost, null)
        .get("java_observable"), "missing Host is a divergent Java accept");

    String missingUpgrade = validClientRequest(RFC_SAMPLE_KEY)
        .replace("Upgrade: websocket\r\n", "");
    equal("accept", handshake("hs-missing-upgrade", "client_request", missingUpgrade, null)
        .get("java_observable"), "missing Upgrade is a divergent Java accept");

    String badKey = "!!definitely-not-base64!!";
    Map<String, Object> nonBase64 = handshake("hs-bad-key", "client_request",
        validClientRequest(badKey), null);
    equal("accept", nonBase64.get("java_observable"),
        "non-base64 key is a divergent Java accept");
    equal(acceptFor(badKey), nonBase64.get("sec_websocket_accept"),
        "the accept value hashes the malformed key string");

    String duplicateKey = validClientRequest("AAAA").replace(
        "Sec-WebSocket-Version: 13",
        "Sec-WebSocket-Key: BBBB\r\nSec-WebSocket-Version: 13");
    Map<String, Object> joined = handshake("hs-dup-key", "client_request",
        duplicateKey, null);
    equal("accept", joined.get("java_observable"),
        "duplicated key joins and accepts");
    equal(acceptFor("AAAA; BBBB"), joined.get("sec_websocket_accept"),
        "the accept value hashes the '; '-joined keys");

    String bareLf = validClientRequest(RFC_SAMPLE_KEY)
        .replace("Upgrade: websocket\r\n", "Upgrade: websocket\n");
    Map<String, Object> folded = handshake("hs-bare-lf", "client_request", bareLf, null);
    equal("accept", folded.get("java_observable"),
        "a bare LF folds into the next line and accepts");
    equal(acceptFor(RFC_SAMPLE_KEY), folded.get("sec_websocket_accept"),
        "bare-LF accept value still derives from the key");
    pass();
  }

  private static void testHandshakeServerRejections() throws Exception {
    expectHandshakeReject("hs-post",
        validClientRequest(RFC_SAMPLE_KEY).replace("GET ", "POST "),
        "client_request", null, "invalid_handshake");
    expectHandshakeReject("hs-http10",
        validClientRequest(RFC_SAMPLE_KEY).replace("HTTP/1.1", "HTTP/1.0"),
        "client_request", null, "invalid_handshake");
    expectHandshakeReject("hs-garbled-line",
        validClientRequest(RFC_SAMPLE_KEY).replace("GET /chat HTTP/1.1", "GET/chatHTTP/1.1"),
        "client_request", null, "invalid_handshake");
    expectHandshakeReject("hs-no-colon",
        validClientRequest(RFC_SAMPLE_KEY).replace("Host: server.example.com",
            "Host server.example.com"),
        "client_request", null, "invalid_handshake");
    expectHandshakeReject("hs-obs-fold",
        validClientRequest(RFC_SAMPLE_KEY).replace("Upgrade: websocket\r\n",
            "Upgrade: websocket\r\n folded\r\n"),
        "client_request", null, "invalid_handshake");
    expectHandshakeReject("hs-missing-key",
        validClientRequest(RFC_SAMPLE_KEY).replace(
            "Sec-WebSocket-Key: " + RFC_SAMPLE_KEY + "\r\n", ""),
        "client_request", null, "invalid_handshake");
    expectHandshakeReject("hs-version-8",
        validClientRequest(RFC_SAMPLE_KEY).replace("Sec-WebSocket-Version: 13",
            "Sec-WebSocket-Version: 8"),
        "client_request", null, "not_matched");
    expectHandshakeReject("hs-version-words",
        validClientRequest(RFC_SAMPLE_KEY).replace("Sec-WebSocket-Version: 13",
            "Sec-WebSocket-Version: thirteen"),
        "client_request", null, "not_matched");
    expectHandshakeReject("hs-missing-version",
        validClientRequest(RFC_SAMPLE_KEY).replace("Sec-WebSocket-Version: 13\r\n", ""),
        "client_request", null, "not_matched");
    expectHandshakeReject("hs-dup-version",
        validClientRequest(RFC_SAMPLE_KEY).replace("Sec-WebSocket-Version: 13",
            "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Version: 13"),
        "client_request", null, "not_matched");
    pass();
  }

  private static void testHandshakeIncomplete() throws Exception {
    String full = validClientRequest(RFC_SAMPLE_KEY);
    for (int cut : new int[] {0, 4, full.length() / 2, full.length() - 2}) {
      Map<String, Object> response = handshake("hs-cut-" + cut, "client_request",
          full.substring(0, cut), null);
      equal("incomplete", response.get("java_observable"),
          "cut at " + cut + " is incomplete");
      check(!response.containsKey("reject_channel") && !response.containsKey("close_code")
          && !response.containsKey("sec_websocket_accept"),
          "incomplete carries no verdict payload");
    }
    pass();
  }

  private static void testHandshakeClientDirection() throws Exception {
    String valid = validServerResponse(RFC_SAMPLE_ACCEPT);
    Map<String, Object> accepted = handshake("hs-client-ok", "server_response",
        valid, RFC_SAMPLE_KEY);
    equal("accept", accepted.get("java_observable"), "valid response accepted");
    check(!accepted.containsKey("sec_websocket_accept"),
        "client-side accept exposes no accept value");

    expectHandshakeReject("hs-status-200",
        valid.replace("101 Switching Protocols", "200 OK"),
        "server_response", RFC_SAMPLE_KEY, "invalid_handshake");
    expectHandshakeReject("hs-accept-mismatch",
        valid.replace(RFC_SAMPLE_ACCEPT, RFC_SAMPLE_ACCEPT.toLowerCase(java.util.Locale.ROOT)),
        "server_response", RFC_SAMPLE_KEY, "not_matched");
    expectHandshakeReject("hs-response-no-upgrade",
        valid.replace("Upgrade: websocket\r\n", ""),
        "server_response", RFC_SAMPLE_KEY, "not_matched");
    expectHandshakeReject("hs-response-no-accept",
        valid.replace("Sec-WebSocket-Accept: " + RFC_SAMPLE_ACCEPT + "\r\n", ""),
        "server_response", RFC_SAMPLE_KEY, "not_matched");
    // Without the recorded client key the challenge cannot match.
    expectHandshakeReject("hs-no-context", valid, "server_response", null, "not_matched");
    pass();
  }

  private static void testHandshakeProtocolStrictness() throws Exception {
    String request = handshakeRequest("hs-strict", "client_request",
        validClientRequest(RFC_SAMPLE_KEY), null);
    expectCode("UNKNOWN_FIELD", () -> OracleEngine.process(
        rebind(request.replace("\"direction\"", "\"extra\":1,\"direction\"")),
        runtimeDigest));
    expectCode("REQUEST_DIGEST_MISMATCH", () -> OracleEngine.process(
        request.replace("\"direction\":\"client_request\"",
            "\"direction\":\"server_response\""), runtimeDigest));
    expectCode("INVALID_ENUM", () -> OracleEngine.process(
        rebind(request.replace("\"direction\":\"client_request\"",
            "\"direction\":\"sideways\"")), runtimeDigest));
    expectCode("INVALID_BASE64", () -> OracleEngine.process(
        rebind(request.replaceFirst("\"raw_base64\":\"[^\"]*\"",
            "\"raw_base64\":\"@@@@\"")), runtimeDigest));
    expectCode("MISSING_FIELD", () -> OracleEngine.process(
        rebind(request.replace("\"context\":{},", "")), runtimeDigest));
    pass();
  }

  private static String request(String id, String steps) {
    return request(id, steps, 4096, 4096, 32, 32, 65536);
  }

  private static String request(
      String id, String steps, int input, int buffered, int actions, int frames, int output) {
    String unsigned = "{\"protocol\":\"java-websocket-oracle\",\"version\":\"1.0.0\","
        + "\"request_id\":\"" + id + "\",\"role\":\"client\","
        + "\"initial_state\":\"open\",\"steps\":" + steps + ",\"limits\":{"
        + "\"max_input_bytes\":" + input + ",\"max_buffered_bytes\":" + buffered + ","
        + "\"max_actions\":" + actions + ",\"max_frames\":" + frames + ","
        + "\"max_output_bytes\":" + output + "}}";
    return rebind(unsigned);
  }

  private static String rebind(String json) {
    try {
      Map<String, Object> object = object(StrictJson.parse(json));
      object.remove("request_digest");
      String canonical = StrictJson.write(object);
      String digest = "sha256:" + java.util.HexFormat.of().formatHex(
          java.security.MessageDigest.getInstance("SHA-256")
              .digest(canonical.getBytes(StandardCharsets.UTF_8)));
      object.put("request_digest", digest);
      return StrictJson.write(object);
    } catch (Exception e) {
      throw new AssertionError("cannot bind test request digest", e);
    }
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> object(Object value) {
    return (Map<String, Object>) value;
  }

  @SuppressWarnings("unchecked")
  private static List<Object> list(Object value) {
    return (List<Object>) value;
  }

  private static Object stripSteps(Object value) {
    List<Object> result = new ArrayList<>();
    for (Object item : list(value)) {
      Map<String, Object> copy = new TreeMap<>(object(item));
      copy.remove("step");
      result.add(copy);
    }
    return result;
  }

  private static Object semanticEvents(Object value) {
    List<Object> result = new ArrayList<>();
    for (Object item : list(value)) {
      Map<String, Object> copy = new TreeMap<>(object(item));
      if ("input_chunk".equals(copy.get("type"))) {
        continue;
      }
      copy.remove("step");
      result.add(copy);
    }
    return result;
  }

  private static void expectCode(String code, ThrowingRunnable runnable) throws Exception {
    try {
      runnable.run();
      throw new AssertionError("expected " + code);
    } catch (ProtocolException e) {
      equal(code, e.code(), "protocol exception code");
    }
  }

  private static void equal(Object expected, Object actual, String message) {
    if (!java.util.Objects.equals(expected, actual)) {
      throw new AssertionError(message + ": expected=" + expected + " actual=" + actual);
    }
  }

  private static void check(boolean condition, String message) {
    if (!condition) {
      throw new AssertionError(message);
    }
  }

  private static void pass() {
    tests++;
  }

  @FunctionalInterface
  private interface ThrowingRunnable {
    void run() throws Exception;
  }
}
