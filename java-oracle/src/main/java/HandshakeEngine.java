import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;
import org.java_websocket.drafts.Draft_6455;
import org.java_websocket.enums.HandshakeState;
import org.java_websocket.enums.Role;
import org.java_websocket.exceptions.IncompleteHandshakeException;
import org.java_websocket.exceptions.InvalidHandshakeException;
import org.java_websocket.framing.CloseFrame;
import org.java_websocket.handshake.ClientHandshake;
import org.java_websocket.handshake.ClientHandshakeBuilder;
import org.java_websocket.handshake.HandshakeBuilder;
import org.java_websocket.handshake.HandshakeImpl1Client;
import org.java_websocket.handshake.HandshakeImpl1Server;
import org.java_websocket.handshake.Handshakedata;
import org.java_websocket.handshake.ServerHandshake;
import org.java_websocket.handshake.ServerHandshakeBuilder;

/**
 * Handshake mode of the java-oracle adapter: one corpus case's raw handshake
 * bytes are fed through the real Java-WebSocket 1.6.0 handshake path and the
 * runtime observable is reported without interpretation.
 *
 * The execution mirrors WebSocketImpl.decodeHandshake at the draft API level
 * (the same style the behavior mode uses for translateFrame):
 *
 * server side (direction=client_request, WebSocketImpl.java:269-315):
 * translateHandshake, acceptHandshakeAsServer, then the default listener
 * response through postProcessHandshakeResponseAsServer and createHandshake;
 * the reported Sec-WebSocket-Accept is parsed back out of the rendered
 * response bytes by the library's own client-side parser.
 *
 * client side (direction=server_response, WebSocketImpl.java:336-364):
 * translateHandshake, then acceptHandshakeAsClient against a request carrying
 * the recorded client key.
 *
 * The adapter reports Java behavior and does not claim that behavior matches
 * RFC 6455: the Go-side mapping (internal/corpora/handshake_live.go and
 * evidence/us005-handshake-live-mapping.json) documents every divergence. The
 * corpus config limits are digest-bound but deliberately not enforced here,
 * because Java-WebSocket 1.6.0 itself enforces no handshake limits.
 */
final class HandshakeEngine {
  static final String PROTOCOL = "java-websocket-handshake-oracle";
  static final String VERSION = "1.0.0";
  private static final Set<String> REQUEST_FIELDS = Set.of(
      "case_id", "config", "context", "direction", "protocol", "raw_base64",
      "request_digest", "version");
  private static final Set<String> CONFIG_FIELDS = Set.of(
      "max_handshake_bytes", "max_header_count", "max_header_line_bytes");
  private static final Set<String> CONTEXT_FIELDS = Set.of("client_key");
  private static final Pattern CASE_ID = Pattern.compile("[A-Za-z0-9._:-]{1,128}");

  private HandshakeEngine() {}

  static Map<String, Object> process(Map<String, Object> request, String runtimeDigest)
      throws ProtocolException {
    OracleEngine.rejectUnknown(request, REQUEST_FIELDS, "request");
    OracleEngine.requireFields(request, REQUEST_FIELDS, "request");
    String caseId = OracleEngine.string(request, "case_id");
    if (!CASE_ID.matcher(caseId).matches()) {
      throw new ProtocolException("INVALID_REQUEST_ID",
          "case_id must match [A-Za-z0-9._:-]{1,128}");
    }
    OracleEngine.requireLiteral(request, "protocol", PROTOCOL);
    OracleEngine.requireLiteral(request, "version", VERSION);
    String requestDigest = OracleEngine.string(request, "request_digest");
    if (!requestDigest.matches("sha256:[0-9a-f]{64}")) {
      throw new ProtocolException("INVALID_REQUEST_DIGEST",
          "request_digest must be a lowercase SHA-256 identity");
    }
    String computedDigest = OracleEngine.canonicalRequestDigest(request);
    if (!java.security.MessageDigest.isEqual(
        requestDigest.getBytes(java.nio.charset.StandardCharsets.US_ASCII),
        computedDigest.getBytes(java.nio.charset.StandardCharsets.US_ASCII))) {
      throw new ProtocolException("REQUEST_DIGEST_MISMATCH",
          "request_digest does not bind the canonical request");
    }
    Map<String, Object> config = OracleEngine.object(request.get("config"), "config");
    OracleEngine.rejectUnknown(config, CONFIG_FIELDS, "config");
    OracleEngine.requireFields(config, CONFIG_FIELDS, "config");
    for (String field : CONFIG_FIELDS) {
      // Shape-validated and digest-bound; not enforced (Java has no limits).
      OracleEngine.boundedInt(config, field, 1, Integer.MAX_VALUE);
    }
    Map<String, Object> context = OracleEngine.object(request.get("context"), "context");
    OracleEngine.rejectUnknown(context, CONTEXT_FIELDS, "context");
    String clientKey = null;
    if (context.containsKey("client_key")) {
      clientKey = OracleEngine.string(context, "client_key");
      if (clientKey.isEmpty()) {
        throw new ProtocolException("TYPE_MISMATCH", "client_key must be non-empty");
      }
    }
    String direction = OracleEngine.string(request, "direction");
    if (!"client_request".equals(direction) && !"server_response".equals(direction)) {
      throw new ProtocolException("INVALID_ENUM", "direction has unsupported value");
    }
    byte[] raw = OracleEngine.base64(
        OracleEngine.string(request, "raw_base64"), "raw_base64");

    Outcome outcome = "client_request".equals(direction)
        ? serverSide(raw) : clientSide(raw, clientKey);

    Map<String, Object> response = new TreeMap<>();
    response.put("case_id", caseId);
    response.put("java_observable", outcome.observable);
    response.put("protocol", PROTOCOL);
    response.put("request_digest", requestDigest);
    Map<String, Object> runtime = new TreeMap<>();
    runtime.put("artifact", "org.java-websocket:Java-WebSocket:1.6.0");
    runtime.put("sha256", runtimeDigest);
    response.put("runtime", runtime);
    response.put("version", VERSION);
    if (outcome.rejectChannel != null) {
      response.put("close_code", outcome.closeCode);
      response.put("reject_channel", outcome.rejectChannel);
      response.put("reject_stage", outcome.rejectStage);
    }
    if (outcome.secWebSocketAccept != null) {
      response.put("sec_websocket_accept", outcome.secWebSocketAccept);
    }
    return response;
  }

  /**
   * Which draft-API call decided a rejection. The channel says which failure
   * vocabulary the rejection took; the stage says which CALL produced it, and
   * it separates the two events the invalid_handshake channel conflates.
   */
  private static final String STAGE_TRANSLATE = "translate";
  private static final String STAGE_ACCEPT_PREDICATE = "accept_predicate";
  private static final String STAGE_RESPONSE_BUILD = "response_build";

  private record Outcome(
      String observable, String rejectChannel, String rejectStage, Integer closeCode,
      String secWebSocketAccept) {
    static Outcome accept(String secWebSocketAccept) {
      return new Outcome("accept", null, null, null, secWebSocketAccept);
    }

    static Outcome reject(String channel, String stage, int closeCode) {
      return new Outcome("reject", channel, stage, closeCode, null);
    }

    static Outcome incomplete() {
      return new Outcome("incomplete", null, null, null, null);
    }
  }

  /**
   * Mirrors WebSocketImpl.decodeHandshake server branch (WebSocketImpl.java:269-315).
   *
   * <p>The three draft-API calls sit in SEPARATE try blocks rather than one,
   * so the reported reject_stage is the call that actually produced the
   * outcome instead of a guess about which of three sites inside one try
   * threw. This is a reporting change only: the same Java calls run in the
   * same order and decide the same observable, channel and close code.
   */
  private static Outcome serverSide(byte[] raw) throws ProtocolException {
    // The library default draft: DefaultExtension plus the empty Protocol,
    // exactly what new WebSocketServer(...) negotiates with.
    Draft_6455 draft = new Draft_6455();
    draft.setParseMode(Role.SERVER);
    Handshakedata handshake;
    try {
      handshake = draft.translateHandshake(ByteBuffer.wrap(raw));
    } catch (IncompleteHandshakeException e) {
      // WebSocketImpl.java:370-387: buffered, nothing written.
      return Outcome.incomplete();
    } catch (InvalidHandshakeException e) {
      // Swallowed per draft (WebSocketImpl.java:306-308) and reported as one
      // PROTOCOL_ERROR rejection (WebSocketImpl.java:310-314, 426-429). No
      // Handshakedata was ever built, so the application listener was never
      // reached.
      return Outcome.reject("invalid_handshake", STAGE_TRANSLATE, closeCodeOf(e));
    }
    if (!(handshake instanceof ClientHandshake)) {
      // WebSocketImpl.java:277-282 "wrong http function".
      return Outcome.reject("wrong_http_function", STAGE_TRANSLATE, CloseFrame.PROTOCOL_ERROR);
    }
    ClientHandshake clientHandshake = (ClientHandshake) handshake;
    HandshakeState state;
    try {
      state = draft.acceptHandshakeAsServer(clientHandshake);
    } catch (InvalidHandshakeException e) {
      return Outcome.reject("invalid_handshake", STAGE_ACCEPT_PREDICATE, closeCodeOf(e));
    }
    if (state != HandshakeState.MATCHED) {
      // WebSocketImpl.java:310-314: no draft matches, PROTOCOL_ERROR.
      return Outcome.reject("not_matched", STAGE_ACCEPT_PREDICATE, CloseFrame.PROTOCOL_ERROR);
    }
    // WebSocketAdapter.onWebsocketHandshakeReceivedAsServer default response
    // (WebSocketAdapter returns a fresh HandshakeImpl1Server), then the real
    // response bytes (WebSocketImpl.java:287-301). Reaching this line is
    // exactly what STAGE_RESPONSE_BUILD records: the predicate MATCHED and
    // the library has already called the application listener.
    ServerHandshakeBuilder response = new HandshakeImpl1Server();
    try {
      HandshakeBuilder complete =
          draft.postProcessHandshakeResponseAsServer(clientHandshake, response);
      List<ByteBuffer> rendered = draft.createHandshake(complete);
      return Outcome.accept(acceptValueFrom(rendered));
    } catch (InvalidHandshakeException e) {
      return Outcome.reject("invalid_handshake", STAGE_RESPONSE_BUILD, closeCodeOf(e));
    }
  }

  /** InvalidHandshakeException.getCloseCode with Java's 0 default mapped. */
  private static int closeCodeOf(InvalidHandshakeException e) {
    return e.getCloseCode() == 0 ? CloseFrame.PROTOCOL_ERROR : e.getCloseCode();
  }

  /** Mirrors WebSocketImpl.decodeHandshake client branch (WebSocketImpl.java:336-364). */
  private static Outcome clientSide(byte[] raw, String clientKey) {
    Draft_6455 draft = new Draft_6455();
    draft.setParseMode(Role.CLIENT);
    Handshakedata handshake;
    try {
      handshake = draft.translateHandshake(ByteBuffer.wrap(raw));
    } catch (IncompleteHandshakeException e) {
      return Outcome.incomplete();
    } catch (InvalidHandshakeException e) {
      // WebSocketImpl.java:366-368: close(e) with the exception's close code.
      // translateHandshakeHttpClient (Draft.java:164-180) throws here when the
      // status token is not literally "101", before any Handshakedata exists.
      return Outcome.reject("invalid_handshake", STAGE_TRANSLATE, closeCodeOf(e));
    }
    if (!(handshake instanceof ServerHandshake)) {
      return Outcome.reject("wrong_http_function", STAGE_TRANSLATE, CloseFrame.PROTOCOL_ERROR);
    }
    ServerHandshake serverHandshake = (ServerHandshake) handshake;
    ClientHandshakeBuilder challenge = new HandshakeImpl1Client();
    if (clientKey != null) {
      // The recorded key the corpus client sent; without it the challenge
      // comparison in acceptHandshakeAsClient cannot match
      // (Draft_6455.java:312-316).
      challenge.put("Sec-WebSocket-Key", clientKey);
    }
    HandshakeState state;
    try {
      state = draft.acceptHandshakeAsClient(challenge, serverHandshake);
    } catch (InvalidHandshakeException e) {
      return Outcome.reject("invalid_handshake", STAGE_ACCEPT_PREDICATE, closeCodeOf(e));
    }
    if (state != HandshakeState.MATCHED) {
      // WebSocketImpl.java:361-364: close PROTOCOL_ERROR.
      return Outcome.reject("not_matched", STAGE_ACCEPT_PREDICATE, CloseFrame.PROTOCOL_ERROR);
    }
    // The client never SENDS an accept value, but it derives one and matching
    // it is the whole acceptance predicate: acceptHandshakeAsClient returns
    // MATCHED only when generateFinalKey(trim(challenge key)) equals the
    // response field literally (Draft_6455.java:318-325). So the field the
    // library parsed off the wire IS the value this client derived; it is read
    // back through the library's own Handshakedata rather than recomputed
    // here, exactly as the server side reads its value back out of the bytes
    // it rendered.
    return Outcome.accept(serverHandshake.getFieldValue("Sec-WebSocket-Accept"));
  }

  /**
   * Extracts Sec-WebSocket-Accept from the rendered 101 response using the
   * library's own client-side parser, so the reported value is read from the
   * exact bytes a real server would have written.
   */
  private static String acceptValueFrom(List<ByteBuffer> rendered) throws ProtocolException {
    int total = 0;
    for (ByteBuffer buffer : rendered) {
      total += buffer.remaining();
    }
    ByteBuffer combined = ByteBuffer.allocate(total);
    for (ByteBuffer buffer : rendered) {
      combined.put(buffer.duplicate());
    }
    combined.flip();
    try {
      Draft_6455 reader = new Draft_6455();
      reader.setParseMode(Role.CLIENT);
      Handshakedata parsed = reader.translateHandshake(combined);
      String accept = parsed.getFieldValue("Sec-WebSocket-Accept");
      if (accept == null || accept.isEmpty()) {
        throw new ProtocolException("ADAPTER_RUNTIME_DIVERGENCE",
            "accepted handshake response carries no Sec-WebSocket-Accept");
      }
      return accept;
    } catch (InvalidHandshakeException | IncompleteHandshakeException e) {
      throw new ProtocolException("ADAPTER_RUNTIME_DIVERGENCE",
          "rendered handshake response failed to re-parse: " + e.getClass().getSimpleName());
    }
  }
}
