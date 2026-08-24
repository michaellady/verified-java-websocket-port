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
    System.out.println("PASS " + tests + " java-oracle tests");
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
    Map<String, Object> server = OracleEngine.process(serverRequest, runtimeDigest);
    equal(Boolean.FALSE, object(list(server.get("frames")).get(0)).get("masked"),
        "server output is unmasked");

    Map<String, Object> stateError = OracleEngine.process(
        request("closed-state",
            "[{\"kind\":\"action\",\"action\":\"send_text\",\"text\":\"x\"}]")
            .replace("\"initial_state\":\"open\"", "\"initial_state\":\"closed\""),
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
        request("type", "[]").replace("\"max_frames\":32", "\"max_frames\":1.5"),
        runtimeDigest));
    expectCode("INVALID_ENUM", () -> OracleEngine.process(
        request("case", "[]").replace("\"role\":\"client\"", "\"role\":\"CLIENT\""),
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

  private static String request(String id, String steps) {
    return request(id, steps, 4096, 4096, 32, 32, 65536);
  }

  private static String request(
      String id, String steps, int input, int buffered, int actions, int frames, int output) {
    return "{\"protocol\":\"java-websocket-oracle\",\"version\":\"1.0.0\","
        + "\"request_id\":\"" + id + "\",\"role\":\"client\","
        + "\"initial_state\":\"open\",\"steps\":" + steps + ",\"limits\":{"
        + "\"max_input_bytes\":" + input + ",\"max_buffered_bytes\":" + buffered + ","
        + "\"max_actions\":" + actions + ",\"max_frames\":" + frames + ","
        + "\"max_output_bytes\":" + output + "}}";
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
