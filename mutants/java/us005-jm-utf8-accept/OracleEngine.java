import java.math.BigDecimal;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;
import org.java_websocket.WebSocket;
import org.java_websocket.WebSocketAdapter;
import org.java_websocket.WebSocketImpl;
import org.java_websocket.drafts.Draft_6455;
import org.java_websocket.enums.Opcode;
import org.java_websocket.enums.Role;
import org.java_websocket.exceptions.InvalidDataException;
import org.java_websocket.framing.CloseFrame;
import org.java_websocket.framing.ContinuousFrame;
import org.java_websocket.framing.Framedata;
import org.java_websocket.framing.FramedataImpl1;
import org.java_websocket.framing.PingFrame;
import org.java_websocket.framing.PongFrame;
import org.java_websocket.handshake.Handshakedata;

/** Request validation and the narrow Java-WebSocket v1.6.0 oracle projection. */
// PLANTED MUTANT OVERLAY us005-jm-utf8-accept — never a pristine oracle source. Built only via
// cmd/us005-mutantctl against a staged copy; the pristine java-oracle tree is
// untouched. Deviation documented in mutants/manifest.json.
final class OracleEngine {
  private static final Set<String> REQUEST_FIELDS = Set.of(
      "initial_state", "limits", "protocol", "request_digest", "request_id", "role", "steps",
      "version");
  private static final Set<String> LIMIT_FIELDS = Set.of(
      "max_actions", "max_buffered_bytes", "max_frames", "max_input_bytes",
      "max_output_bytes");
  private static final Pattern REQUEST_ID = Pattern.compile("[A-Za-z0-9._:-]{1,128}");
  private static final int HARD_INPUT_BYTES = 1_048_576;
  private static final int HARD_BUFFERED_BYTES = 1_048_576;
  private static final int HARD_ACTIONS = 1_024;
  private static final int HARD_FRAMES = 4_096;
  private static final int HARD_OUTPUT_BYTES = 4_194_304;

  private OracleEngine() {}

  static Map<String, Object> process(String json, String runtimeDigest) throws ProtocolException {
    Object parsed = StrictJson.parse(json);
    Map<String, Object> request = object(parsed, "request");
    rejectUnknown(request, REQUEST_FIELDS, "request");

    String requestId = string(request, "request_id");
    if (!REQUEST_ID.matcher(requestId).matches()) {
      throw new ProtocolException("INVALID_REQUEST_ID",
          "request_id must match [A-Za-z0-9._:-]{1,128}");
    }
    requireLiteral(request, "protocol", OracleMain.PROTOCOL);
    requireLiteral(request, "version", OracleMain.VERSION);
    String requestDigest = string(request, "request_digest");
    if (!requestDigest.matches("sha256:[0-9a-f]{64}")) {
      throw new ProtocolException("INVALID_REQUEST_DIGEST",
          "request_digest must be a lowercase SHA-256 identity");
    }
    String computedDigest = canonicalRequestDigest(request);
    if (!MessageDigest.isEqual(requestDigest.getBytes(StandardCharsets.US_ASCII),
        computedDigest.getBytes(StandardCharsets.US_ASCII))) {
      throw new ProtocolException("REQUEST_DIGEST_MISMATCH",
          "request_digest does not bind the canonical request");
    }
    Role role = enumValue(request, "role", Role.class);
    State initialState = enumValue(request, "initial_state", State.class);
    Limits limits = limits(request.get("limits"));
    List<Object> steps = array(request, "steps");

    Execution execution;
    try {
      execution = new Execution(requestId, requestDigest, role, initialState, limits, runtimeDigest);
    } catch (NoClassDefFoundError e) {
      return OracleMain.error(requestId, "RUNTIME_DEPENDENCY_UNAVAILABLE",
          "Java-WebSocket runtime dependency is unavailable", null);
    } catch (LinkageError e) {
      return OracleMain.error(requestId, "RUNTIME_LINKAGE_ERROR",
          "Java-WebSocket runtime linkage failed closed", null);
    }
    Map<String, Object> response;
    try {
      execution.run(steps);
      response = execution.success();
    } catch (ProtocolException e) {
      response = execution.failure(e);
    } catch (InvalidDataException e) {
      // MUTANT us005-jm-utf8-accept (PLANTED, DELIBERATE): skips the strict
      // UTF-8 rejection — an invalid-UTF-8 rejection (close code 1007,
      // CloseFrame.NO_UTF8) is swallowed and reported as a successful run.
      // Expected kill signature: "outcome ok, expected error" on every
      // scenario expecting JAVA_INVALID_DATA close_code 1007.
      // See mutants/manifest.json.
      if (e.getCloseCode() == CloseFrame.NO_UTF8) {
        response = execution.success();
      } else {
        response = execution.failure(new ProtocolException(
            "JAVA_INVALID_DATA", safeRuntimeMessage(e), e.getCloseCode()));
      }
    } catch (RuntimeException e) {
      response = execution.failure(new ProtocolException(
          "JAVA_RUNTIME_REJECTION", "Java-WebSocket rejected the operation: "
              + e.getClass().getSimpleName()));
    }
    if (StrictJson.utf8Length(response) > limits.maxOutputBytes()) {
      return execution.failure(new ProtocolException("OUTPUT_LIMIT_EXCEEDED",
          "normalized response exceeds max_output_bytes"), true);
    }
    return response;
  }

  private static String canonicalRequestDigest(Map<String, Object> request)
      throws ProtocolException {
    try {
      Map<String, Object> unsigned = new TreeMap<>(request);
      unsigned.remove("request_digest");
      byte[] canonical = StrictJson.write(unsigned).getBytes(StandardCharsets.UTF_8);
      return "sha256:" + HexFormat.of().formatHex(
          MessageDigest.getInstance("SHA-256").digest(canonical));
    } catch (java.security.NoSuchAlgorithmException e) {
      throw new ProtocolException("DIGEST_UNAVAILABLE", "SHA-256 is unavailable");
    }
  }

  private static String safeRuntimeMessage(Exception e) {
    String message = e.getMessage();
    if (message == null || message.isBlank()) {
      return "Java-WebSocket rejected invalid data";
    }
    message = message.replace('\r', ' ').replace('\n', ' ');
    return message.length() <= 200 ? message : message.substring(0, 200);
  }

  private static Limits limits(Object value) throws ProtocolException {
    Map<String, Object> object = object(value, "limits");
    rejectUnknown(object, LIMIT_FIELDS, "limits");
    requireFields(object, LIMIT_FIELDS, "limits");
    return new Limits(
        boundedInt(object, "max_input_bytes", 1, HARD_INPUT_BYTES),
        boundedInt(object, "max_buffered_bytes", 1, HARD_BUFFERED_BYTES),
        boundedInt(object, "max_actions", 0, HARD_ACTIONS),
        boundedInt(object, "max_frames", 1, HARD_FRAMES),
        boundedInt(object, "max_output_bytes", 512, HARD_OUTPUT_BYTES));
  }

  private static int boundedInt(Map<String, Object> object, String field, int min, int max)
      throws ProtocolException {
    Object value = required(object, field);
    if (!(value instanceof BigDecimal decimal)) {
      throw new ProtocolException("TYPE_MISMATCH", field + " must be an integer");
    }
    final int number;
    try {
      number = decimal.intValueExact();
    } catch (ArithmeticException e) {
      throw new ProtocolException("TYPE_MISMATCH", field + " must be an integer");
    }
    if (number < min || number > max) {
      throw new ProtocolException("LIMIT_OUT_OF_RANGE",
          field + " must be between " + min + " and " + max);
    }
    return number;
  }

  private static <E extends Enum<E>> E enumValue(
      Map<String, Object> object, String field, Class<E> type) throws ProtocolException {
    String value = string(object, field);
    for (E candidate : type.getEnumConstants()) {
      if (candidate.name().toLowerCase(java.util.Locale.ROOT).equals(value)) {
        return candidate;
      }
    }
    throw new ProtocolException("INVALID_ENUM", field + " has unsupported value");
  }

  private static void requireLiteral(Map<String, Object> object, String field, String expected)
      throws ProtocolException {
    if (!expected.equals(string(object, field))) {
      throw new ProtocolException("UNSUPPORTED_PROTOCOL",
          field + " must equal " + expected);
    }
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> object(Object value, String name) throws ProtocolException {
    if (!(value instanceof Map<?, ?> map)) {
      throw new ProtocolException("TYPE_MISMATCH", name + " must be an object");
    }
    return (Map<String, Object>) map;
  }

  @SuppressWarnings("unchecked")
  private static List<Object> array(Map<String, Object> object, String field)
      throws ProtocolException {
    Object value = required(object, field);
    if (!(value instanceof List<?> list)) {
      throw new ProtocolException("TYPE_MISMATCH", field + " must be an array");
    }
    return (List<Object>) list;
  }

  private static String string(Map<String, Object> object, String field)
      throws ProtocolException {
    Object value = required(object, field);
    if (!(value instanceof String string)) {
      throw new ProtocolException("TYPE_MISMATCH", field + " must be a string");
    }
    return string;
  }

  private static boolean bool(Map<String, Object> object, String field)
      throws ProtocolException {
    Object value = required(object, field);
    if (!(value instanceof Boolean bool)) {
      throw new ProtocolException("TYPE_MISMATCH", field + " must be a boolean");
    }
    return bool;
  }

  private static int integer(Map<String, Object> object, String field)
      throws ProtocolException {
    Object value = required(object, field);
    if (!(value instanceof BigDecimal decimal)) {
      throw new ProtocolException("TYPE_MISMATCH", field + " must be an integer");
    }
    try {
      return decimal.intValueExact();
    } catch (ArithmeticException e) {
      throw new ProtocolException("TYPE_MISMATCH", field + " must be an integer");
    }
  }

  private static Object required(Map<String, Object> object, String field)
      throws ProtocolException {
    if (!object.containsKey(field)) {
      throw new ProtocolException("MISSING_FIELD", "missing required field: " + field);
    }
    return object.get(field);
  }

  private static void rejectUnknown(
      Map<String, Object> object, Set<String> allowed, String location) throws ProtocolException {
    for (String field : object.keySet()) {
      if (!allowed.contains(field)) {
        throw new ProtocolException("UNKNOWN_FIELD",
            "unknown field in " + location + ": " + clipped(field));
      }
    }
  }

  private static void requireFields(
      Map<String, Object> object, Set<String> required, String location) throws ProtocolException {
    for (String field : required) {
      if (!object.containsKey(field)) {
        throw new ProtocolException("MISSING_FIELD",
            "missing required field in " + location + ": " + field);
      }
    }
  }

  private static String clipped(String value) {
    return value.length() <= 80 ? value : value.substring(0, 80);
  }

  private enum State { OPEN, CLOSING, CLOSED }

  private record Limits(
      int maxInputBytes,
      int maxBufferedBytes,
      int maxActions,
      int maxFrames,
      int maxOutputBytes) {}

  private static final class Execution {
    private final String requestId;
    private final String requestDigest;
    private final Role role;
    private final State initialState;
    private final Limits limits;
    private final String runtimeDigest;
    private final Draft_6455 draft;
    private final OracleListener listener;
    private final WebSocketImpl socket;
    private final WireTracker wire;
    private final List<Object> frames = new ArrayList<>();
    private final List<Object> events = new ArrayList<>();
    private final List<Object> transitions = new ArrayList<>();
    private State state;
    private int inputBytes;
    private int consumedBytes;
    private int actionCount;
    private int messageBufferedBytes;
    private Opcode inboundFragmentOpcode;
    private Map<String, Object> close;

    Execution(String requestId, String requestDigest, Role role, State state, Limits limits,
        String runtimeDigest) {
      this.requestId = requestId;
      this.requestDigest = requestDigest;
      this.role = role;
      this.initialState = state;
      this.state = state;
      this.limits = limits;
      this.runtimeDigest = runtimeDigest;
      this.draft = new Draft_6455(
          Collections.emptyList(), Collections.emptyList(), limits.maxBufferedBytes());
      this.draft.setParseMode(role);
      this.listener = new OracleListener(events);
      this.socket = new WebSocketImpl(listener, draft);
      this.wire = new WireTracker(limits.maxBufferedBytes());
    }

    void run(List<Object> steps) throws ProtocolException, InvalidDataException {
      for (int stepIndex = 0; stepIndex < steps.size(); stepIndex++) {
        Map<String, Object> step = object(steps.get(stepIndex), "steps[" + stepIndex + "]");
        String kind = string(step, "kind");
        listener.step = stepIndex;
        switch (kind) {
          case "bytes" -> input(step, stepIndex);
          case "action" -> action(step, stepIndex);
          default -> throw new ProtocolException("INVALID_ENUM", "step kind has unsupported value");
        }
      }
    }

    private void input(Map<String, Object> step, int index)
        throws ProtocolException, InvalidDataException {
      rejectUnknown(step, Set.of("data_base64", "kind"), "bytes step");
      byte[] bytes = base64(string(step, "data_base64"), "data_base64");
      if (state == State.CLOSED && bytes.length != 0) {
        throw new ProtocolException("STATE_VIOLATION", "bytes cannot be consumed in CLOSED state");
      }
      inputBytes = addBounded(inputBytes, bytes.length, limits.maxInputBytes(),
          "INPUT_LIMIT_EXCEEDED", "decoded byte input exceeds max_input_bytes");
      if (bytes.length == 0) {
        event("input_chunk", index, Map.of("bytes", 0));
        return;
      }

      List<WireMeta> metas = wire.accept(bytes);
      ByteBuffer input = ByteBuffer.wrap(bytes);
      int before = input.remaining();
      List<Framedata> parsed;
      try {
        parsed = draft.translateFrame(input);
      } finally {
        consumedBytes += before - input.remaining();
      }
      if (parsed.size() != metas.size()) {
        throw new ProtocolException("ADAPTER_RUNTIME_DIVERGENCE",
            "wire accounting disagrees with Java-WebSocket frame translation");
      }
      event("input_chunk", index, Map.of("bytes", bytes.length));
      for (int i = 0; i < parsed.size(); i++) {
        if (frames.size() >= limits.maxFrames()) {
          throw new ProtocolException("FRAME_LIMIT_EXCEEDED",
              "frame count exceeds max_frames");
        }
        Framedata frame = parsed.get(i);
        WireMeta meta = metas.get(i);
        frames.add(frame(frame, "inbound", index, meta.masked(), meta.wireBytes()));
        processInbound(frame, index);
      }
    }

    private void processInbound(Framedata frame, int index)
        throws ProtocolException, InvalidDataException {
      Opcode opcode = frame.getOpcode();
      if (state == State.CLOSED) {
        throw new ProtocolException("STATE_VIOLATION", "frame received in CLOSED state");
      }
      if (state == State.CLOSING && opcode != Opcode.CLOSING) {
        throw new ProtocolException("STATE_VIOLATION",
            "only a close frame may be received in CLOSING state");
      }
      if (opcode == Opcode.CLOSING) {
        CloseFrame closeFrame = (CloseFrame) frame;
        close = close("remote", closeFrame.getCloseCode(), closeFrame.getMessage(), true, true);
        event("close", index, close);
        if (state == State.CLOSING) {
          transition(State.CLOSED, "receive_close", index);
        } else {
          // Java-WebSocket's two-way close handshake echoes the received payload while OPEN.
          emitOutbound(List.of(frame), index, "echo_close");
          transition(State.CLOSING, "receive_close", index);
        }
        return;
      }
      draft.processFrame(socket, frame);
      updateMessageBuffer(frame);
    }

    private void updateMessageBuffer(Framedata frame) throws ProtocolException {
      Opcode opcode = frame.getOpcode();
      int payload = frame.getPayloadData().remaining();
      if ((opcode == Opcode.TEXT || opcode == Opcode.BINARY) && !frame.isFin()) {
        if (inboundFragmentOpcode != null) {
          throw new ProtocolException("JAVA_FRAGMENT_STATE_DIVERGENCE",
              "fragment sequence state was not reset");
        }
        inboundFragmentOpcode = opcode;
        messageBufferedBytes = payload;
      } else if (opcode == Opcode.CONTINUOUS) {
        messageBufferedBytes = addBounded(messageBufferedBytes, payload,
            limits.maxBufferedBytes(), "BUFFER_LIMIT_EXCEEDED",
            "fragmented message exceeds max_buffered_bytes");
        if (frame.isFin()) {
          inboundFragmentOpcode = null;
          messageBufferedBytes = 0;
        }
      }
    }

    private void action(Map<String, Object> step, int index)
        throws ProtocolException, InvalidDataException {
      actionCount++;
      if (actionCount > limits.maxActions()) {
        throw new ProtocolException("ACTION_LIMIT_EXCEEDED",
            "action count exceeds max_actions");
      }
      String action = string(step, "action");
      switch (action) {
        case "send_text" -> sendText(step, index);
        case "send_binary" -> sendBinary(step, index);
        case "send_ping" -> sendControl(step, index, new PingFrame(), "ping");
        case "send_pong" -> sendControl(step, index, new PongFrame(), "pong");
        case "send_close" -> sendClose(step, index);
        case "send_fragment" -> sendFragment(step, index);
        case "eof" -> eof(step, index);
        default -> throw new ProtocolException("INVALID_ENUM", "action has unsupported value");
      }
    }

    private void sendText(Map<String, Object> step, int index) throws ProtocolException {
      rejectUnknown(step, Set.of("action", "kind", "text"), "send_text action");
      requireOpen("send_text");
      String text = string(step, "text");
      requirePayloadLimit(text.getBytes(StandardCharsets.UTF_8).length);
      List<Framedata> created = draft.createFrames(text, role == Role.CLIENT);
      emitOutbound(created, index, "send_text");
    }

    private void sendBinary(Map<String, Object> step, int index) throws ProtocolException {
      rejectUnknown(step, Set.of("action", "data_base64", "kind"), "send_binary action");
      requireOpen("send_binary");
      byte[] payload = base64(string(step, "data_base64"), "data_base64");
      requirePayloadLimit(payload.length);
      List<Framedata> created = draft.createFrames(ByteBuffer.wrap(payload), role == Role.CLIENT);
      emitOutbound(created, index, "send_binary");
    }

    private void sendControl(
        Map<String, Object> step, int index, FramedataImpl1 frame, String kind)
        throws ProtocolException, InvalidDataException {
      rejectUnknown(step, Set.of("action", "data_base64", "kind"), "send_" + kind + " action");
      requireOpen("send_" + kind);
      byte[] payload = base64(string(step, "data_base64"), "data_base64");
      frame.setPayload(ByteBuffer.wrap(payload));
      frame.isValid();
      emitOutbound(List.of(frame), index, "send_" + kind);
    }

    private void sendClose(Map<String, Object> step, int index)
        throws ProtocolException, InvalidDataException {
      rejectUnknown(step, Set.of("action", "code", "kind", "reason"), "send_close action");
      requireOpen("send_close");
      int code = integer(step, "code");
      String reason = string(step, "reason");
      CloseFrame frame = new CloseFrame();
      frame.setCode(code);
      frame.setReason(reason);
      frame.isValid();
      emitOutbound(List.of(frame), index, "send_close");
      close = close("local", code, reason, false, false);
      event("close_initiated", index, close);
      transition(State.CLOSING, "send_close", index);
    }

    private void sendFragment(Map<String, Object> step, int index) throws ProtocolException {
      rejectUnknown(step, Set.of("action", "data_base64", "fin", "kind", "opcode"),
          "send_fragment action");
      requireOpen("send_fragment");
      Opcode opcode = enumValue(step, "opcode", Opcode.class);
      if (opcode != Opcode.TEXT && opcode != Opcode.BINARY) {
        throw new ProtocolException("INVALID_ENUM",
            "send_fragment opcode must be text or binary");
      }
      byte[] payload = base64(string(step, "data_base64"), "data_base64");
      requirePayloadLimit(payload.length);
      List<Framedata> created;
      try {
        created = draft.continuousFrame(opcode, ByteBuffer.wrap(payload), bool(step, "fin"));
      } catch (IllegalArgumentException e) {
        throw new ProtocolException("JAVA_NOT_SENDABLE",
            "Java-WebSocket rejected the fragmented frame");
      }
      emitOutbound(created, index, "send_fragment");
    }

    private void eof(Map<String, Object> step, int index) throws ProtocolException {
      rejectUnknown(step, Set.of("action", "kind"), "eof action");
      if (state == State.CLOSED) {
        throw new ProtocolException("STATE_VIOLATION", "eof repeated in CLOSED state");
      }
      int code = state == State.CLOSING && close != null
          ? ((Number) close.get("code")).intValue() : CloseFrame.ABNORMAL_CLOSE;
      String reason = state == State.CLOSING && close != null
          ? (String) close.get("reason") : "transport EOF before close handshake completed";
      boolean handshakeComplete = close != null
          && Boolean.TRUE.equals(close.get("handshake_complete"));
      close = close("transport", code, reason, state == State.CLOSING, handshakeComplete);
      event("eof", index, close);
      transition(State.CLOSED, "eof", index);
    }

    private void emitOutbound(List<Framedata> created, int index, String cause)
        throws ProtocolException {
      for (Framedata frame : created) {
        if (frames.size() >= limits.maxFrames()) {
          throw new ProtocolException("FRAME_LIMIT_EXCEEDED",
              "frame count exceeds max_frames");
        }
        ByteBuffer encoded;
        ByteBuffer payload = frame.getPayloadData();
        int payloadPosition = payload.position();
        int payloadLimit = payload.limit();
        try {
          encoded = draft.createBinaryFrame(frame);
        } catch (RuntimeException e) {
          throw new ProtocolException("JAVA_NOT_SENDABLE",
              "Java-WebSocket rejected the outbound frame");
        } finally {
          payload.limit(payloadLimit);
          payload.position(payloadPosition);
        }
        frames.add(frame(frame, "outbound", index, role == Role.CLIENT, encoded.remaining()));
        event(cause, index, Map.of("opcode", opcode(frame.getOpcode())));
      }
    }

    private void requirePayloadLimit(int size) throws ProtocolException {
      if (size > limits.maxBufferedBytes()) {
        throw new ProtocolException("BUFFER_LIMIT_EXCEEDED",
            "action payload exceeds max_buffered_bytes");
      }
    }

    private void requireOpen(String action) throws ProtocolException {
      if (state != State.OPEN) {
        throw new ProtocolException("STATE_VIOLATION", action + " requires OPEN state");
      }
    }

    private void transition(State next, String cause, int index) {
      if (state == next) {
        return;
      }
      Map<String, Object> value = new TreeMap<>();
      value.put("cause", cause);
      value.put("from", state.name().toLowerCase(java.util.Locale.ROOT));
      value.put("step", index);
      value.put("to", next.name().toLowerCase(java.util.Locale.ROOT));
      transitions.add(value);
      state = next;
    }

    private void event(String type, int index, Map<String, ?> detail) {
      Map<String, Object> value = new TreeMap<>();
      value.putAll(detail);
      value.put("step", index);
      value.put("type", type);
      events.add(value);
    }

    Map<String, Object> success() {
      Map<String, Object> response = base("ok");
      response.put("close", close);
      response.put("counts", counts());
      response.put("events", events);
      response.put("final_state", state.name().toLowerCase(java.util.Locale.ROOT));
      response.put("frames", frames);
      response.put("initial_state", initialState.name().toLowerCase(java.util.Locale.ROOT));
      response.put("role", role.name().toLowerCase(java.util.Locale.ROOT));
      response.put("runtime", runtime());
      response.put("transitions", transitions);
      return response;
    }

    Map<String, Object> failure(ProtocolException error) {
      return failure(error, false);
    }

    Map<String, Object> failure(ProtocolException error, boolean minimal) {
      Map<String, Object> response = base("error");
      Map<String, Object> detail = new TreeMap<>();
      detail.put("code", error.code());
      if (error.closeCode() != null) {
        detail.put("close_code", error.closeCode());
      }
      detail.put("detail", error.getMessage());
      response.put("error", detail);
      if (!minimal) {
        response.put("counts", counts());
        response.put("final_state", state.name().toLowerCase(java.util.Locale.ROOT));
        response.put("runtime", runtime());
      }
      return response;
    }

    private Map<String, Object> base(String outcome) {
      Map<String, Object> response = new TreeMap<>();
      response.put("outcome", outcome);
      response.put("protocol", OracleMain.PROTOCOL);
      response.put("request_digest", requestDigest);
      response.put("request_id", requestId);
      response.put("version", OracleMain.VERSION);
      return response;
    }

    private Map<String, Object> counts() {
      Map<String, Object> counts = new TreeMap<>();
      counts.put("actions", actionCount);
      counts.put("buffered_bytes", wire.bufferedBytes() + messageBufferedBytes);
      counts.put("consumed_bytes", consumedBytes);
      counts.put("frames", frames.size());
      counts.put("input_bytes", inputBytes);
      counts.put("message_buffered_bytes", messageBufferedBytes);
      counts.put("wire_buffered_bytes", wire.bufferedBytes());
      return counts;
    }

    private Map<String, Object> runtime() {
      Map<String, Object> runtime = new TreeMap<>();
      runtime.put("artifact", "org.java-websocket:Java-WebSocket:1.6.0");
      runtime.put("sha256", runtimeDigest);
      return runtime;
    }
  }

  private static Map<String, Object> frame(
      Framedata frame, String direction, int step, boolean masked, int wireBytes) {
    ByteBuffer payload = frame.getPayloadData().asReadOnlyBuffer();
    byte[] bytes = new byte[payload.remaining()];
    payload.get(bytes);
    Map<String, Object> result = new TreeMap<>();
    result.put("direction", direction);
    result.put("fin", frame.isFin());
    result.put("masked", masked);
    result.put("opcode", opcode(frame.getOpcode()));
    result.put("payload_base64", Base64.getEncoder().encodeToString(bytes));
    result.put("payload_bytes", bytes.length);
    result.put("rsv1", frame.isRSV1());
    result.put("rsv2", frame.isRSV2());
    result.put("rsv3", frame.isRSV3());
    result.put("step", step);
    result.put("wire_bytes", wireBytes);
    return result;
  }

  private static String opcode(Opcode opcode) {
    return opcode.name().toLowerCase(java.util.Locale.ROOT);
  }

  private static Map<String, Object> close(
      String origin, int code, String reason, boolean remote, boolean handshakeComplete) {
    Map<String, Object> value = new TreeMap<>();
    value.put("code", code);
    value.put("handshake_complete", handshakeComplete);
    value.put("origin", origin);
    value.put("reason", reason);
    value.put("remote", remote);
    return value;
  }

  private static byte[] base64(String encoded, String field) throws ProtocolException {
    try {
      byte[] decoded = Base64.getDecoder().decode(encoded);
      if (!Base64.getEncoder().encodeToString(decoded).equals(encoded)) {
        throw new IllegalArgumentException("non-canonical encoding");
      }
      return decoded;
    } catch (IllegalArgumentException e) {
      throw new ProtocolException("INVALID_BASE64", field + " is not canonical base64");
    }
  }

  private static int addBounded(int current, int increment, int limit, String code, String detail)
      throws ProtocolException {
    long total = (long) current + increment;
    if (total > limit) {
      throw new ProtocolException(code, detail);
    }
    return (int) total;
  }

  private record WireMeta(boolean masked, int wireBytes) {}

  /** Independent byte accounting; Java-WebSocket remains the semantic parser. */
  private static final class WireTracker {
    private final int limit;
    private byte[] pending = new byte[0];

    WireTracker(int limit) {
      this.limit = limit;
    }

    int bufferedBytes() {
      return pending.length;
    }

    List<WireMeta> accept(byte[] chunk) throws ProtocolException {
      byte[] combined = new byte[pending.length + chunk.length];
      System.arraycopy(pending, 0, combined, 0, pending.length);
      System.arraycopy(chunk, 0, combined, pending.length, chunk.length);
      List<WireMeta> complete = new ArrayList<>();
      int at = 0;
      while (true) {
        long length = frameLength(combined, at);
        if (length < 0 || length > combined.length - at) {
          break;
        }
        if (length > Integer.MAX_VALUE) {
          throw new ProtocolException("BUFFER_LIMIT_EXCEEDED",
              "wire frame length exceeds adapter capacity");
        }
        boolean masked = (combined[at + 1] & 0x80) != 0;
        complete.add(new WireMeta(masked, (int) length));
        at += (int) length;
      }
      pending = java.util.Arrays.copyOfRange(combined, at, combined.length);
      if (pending.length > limit + 14L) {
        throw new ProtocolException("BUFFER_LIMIT_EXCEEDED",
            "incomplete wire frame exceeds max_buffered_bytes");
      }
      return complete;
    }

    private long frameLength(byte[] bytes, int at) throws ProtocolException {
      int available = bytes.length - at;
      if (available < 2) {
        return -1;
      }
      int marker = bytes[at + 1] & 0x7f;
      int header = 2;
      long payload;
      if (marker <= 125) {
        payload = marker;
      } else if (marker == 126) {
        if (available < 4) {
          return -1;
        }
        header = 4;
        payload = ((bytes[at + 2] & 0xffL) << 8) | (bytes[at + 3] & 0xffL);
      } else {
        if (available < 10) {
          return -1;
        }
        header = 10;
        if ((bytes[at + 2] & 0x80) != 0) {
          throw new ProtocolException("JAVA_INVALID_DATA",
              "wire frame declares a negative 64-bit payload length", CloseFrame.TOOBIG);
        }
        payload = 0;
        for (int i = 0; i < 8; i++) {
          payload = (payload << 8) | (bytes[at + 2 + i] & 0xffL);
          if (payload > Integer.MAX_VALUE) {
            throw new ProtocolException("BUFFER_LIMIT_EXCEEDED",
                "wire frame length exceeds adapter capacity", CloseFrame.TOOBIG);
          }
        }
      }
      if ((bytes[at + 1] & 0x80) != 0) {
        header += 4;
      }
      return header + payload;
    }
  }

  private static final class OracleListener extends WebSocketAdapter {
    private final List<Object> events;
    int step;

    OracleListener(List<Object> events) {
      this.events = events;
    }

    @Override
    public void onWebsocketMessage(WebSocket socket, String message) {
      add("text", Map.of("text", message, "utf8_bytes",
          message.getBytes(StandardCharsets.UTF_8).length));
    }

    @Override
    public void onWebsocketMessage(WebSocket socket, ByteBuffer message) {
      ByteBuffer copy = message.asReadOnlyBuffer();
      byte[] bytes = new byte[copy.remaining()];
      copy.get(bytes);
      add("binary", Map.of(
          "data_base64", Base64.getEncoder().encodeToString(bytes), "bytes", bytes.length));
    }

    @Override
    public void onWebsocketPing(WebSocket socket, Framedata frame) {
      addControl("ping", frame);
    }

    @Override
    public void onWebsocketPong(WebSocket socket, Framedata frame) {
      addControl("pong", frame);
    }

    @Override
    public void onWebsocketOpen(WebSocket socket, Handshakedata handshake) {
      add("open", Map.of());
    }

    @Override
    public void onWebsocketClose(WebSocket socket, int code, String reason, boolean remote) {
      add("runtime_close", Map.of("code", code, "reason", reason, "remote", remote));
    }

    @Override
    public void onWebsocketClosing(WebSocket socket, int code, String reason, boolean remote) {
      add("runtime_closing", Map.of("code", code, "reason", reason, "remote", remote));
    }

    @Override
    public void onWebsocketCloseInitiated(WebSocket socket, int code, String reason) {
      add("runtime_close_initiated", Map.of("code", code, "reason", reason));
    }

    @Override
    public void onWebsocketError(WebSocket socket, Exception error) {
      add("listener_error", Map.of("class", error.getClass().getSimpleName()));
    }

    @Override
    public void onWriteDemand(WebSocket socket) {
      add("write_demand", Map.of());
    }

    @Override
    public java.net.InetSocketAddress getLocalSocketAddress(WebSocket socket) {
      return new java.net.InetSocketAddress("127.0.0.1", 0);
    }

    @Override
    public java.net.InetSocketAddress getRemoteSocketAddress(WebSocket socket) {
      return new java.net.InetSocketAddress("127.0.0.1", 0);
    }

    private void addControl(String type, Framedata frame) {
      ByteBuffer copy = frame.getPayloadData().asReadOnlyBuffer();
      byte[] bytes = new byte[copy.remaining()];
      copy.get(bytes);
      add(type, Map.of(
          "data_base64", Base64.getEncoder().encodeToString(bytes), "bytes", bytes.length));
    }

    private void add(String type, Map<String, ?> details) {
      Map<String, Object> event = new TreeMap<>();
      event.putAll(details);
      event.put("step", step);
      event.put("type", type);
      events.add(event);
    }
  }
}
