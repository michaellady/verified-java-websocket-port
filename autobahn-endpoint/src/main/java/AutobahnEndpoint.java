import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.java_websocket.WebSocket;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.drafts.Draft_6455;
import org.java_websocket.handshake.ClientHandshake;
import org.java_websocket.handshake.ServerHandshake;
import org.java_websocket.server.WebSocketServer;

/**
 * Deterministic, noninteractive Autobahn endpoint for the exact accepted
 * Java-WebSocket 1.6.0 runtime. Control and report interpretation remain in
 * the Go controller; this class only supplies client/server transport.
 */
public final class AutobahnEndpoint {
  private static final String RUNTIME_DIGEST =
      "sha256:eae29213e4f16515639c28957200f011b3967fffcada1962cf0255d24919c22f";
  private static final String SUPPORT_DIGEST =
      "sha256:e7c2a48e8515ba1f49fa637d57b4e2f590b3f5bd97407ac699c3aa5efb1204a9";
  private static final String AGENT = "verified-java-websocket-port-1.6.0";
  private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
  private static final Duration CASE_TIMEOUT = Duration.ofSeconds(45);

  private AutobahnEndpoint() {}

  public static void main(String[] arguments) {
    try {
      Arguments parsed = Arguments.parse(arguments);
      verifyBindings(parsed);
      switch (parsed.mode()) {
        case "selftest":
          parsed.requireExactly("adapter", "adapter-digest", "runtime", "support");
          runSelfTest();
          printStatus("SELFTEST_PASS", parsed);
          break;
        case "client":
          parsed.requireExactly(
              "adapter", "adapter-digest", "runtime", "support", "url", "case-count");
          runClient(parsed.value("url"), parsed.positiveInt("case-count"));
          printStatus("CLIENT_COMPLETE", parsed);
          break;
        case "server":
          parsed.requireExactly(
              "adapter", "adapter-digest", "runtime", "support", "bind", "port",
              "max-seconds");
          runServer(parsed.value("bind"), parsed.nonnegativePort("port"), parsed.positiveInt("max-seconds"));
          break;
        default:
          throw new IllegalArgumentException("unsupported mode");
      }
    } catch (Exception exception) {
      System.err.println("ENDPOINT_DENIED " + sanitize(exception.getMessage()));
      System.exit(2);
    }
  }

  private static void verifyBindings(Arguments arguments) throws Exception {
    Path adapter = verifiedFile(arguments.value("adapter"), arguments.value("adapter-digest"));
    Path runtime = verifiedFile(arguments.value("runtime"), RUNTIME_DIGEST);
    Path support = verifiedFile(arguments.value("support"), SUPPORT_DIGEST);
    Path loaded = Path.of(
        AutobahnEndpoint.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath();
    if (!loaded.equals(adapter)) {
      throw new IllegalArgumentException("adapter code source does not equal bound adapter path");
    }
    List<Path> expected = List.of(adapter, runtime, support);
    String[] classpath = System.getProperty("java.class.path", "").split(
        java.util.regex.Pattern.quote(File.pathSeparator), -1);
    if (classpath.length != expected.size()) {
      throw new IllegalArgumentException("classpath must contain exactly adapter, runtime, support");
    }
    for (int index = 0; index < classpath.length; index++) {
      if (!Path.of(classpath[index]).toRealPath().equals(expected.get(index))) {
        throw new IllegalArgumentException("classpath binding differs at index " + index);
      }
    }
  }

  private static Path verifiedFile(String value, String expectedDigest) throws Exception {
    if (!expectedDigest.matches("sha256:[0-9a-f]{64}")) {
      throw new IllegalArgumentException("invalid expected digest");
    }
    Path path = Path.of(value);
    if (!path.isAbsolute() || Files.isSymbolicLink(path)
        || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
      throw new IllegalArgumentException("artifact must be an absolute regular non-link file");
    }
    Path real = path.toRealPath();
    if (!digest(real).equals(expectedDigest)) {
      throw new IllegalArgumentException("artifact digest mismatch");
    }
    return real;
  }

  private static String digest(Path path) throws IOException, NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    try (java.io.InputStream input = Files.newInputStream(path)) {
      byte[] buffer = new byte[64 * 1024];
      int count;
      while ((count = input.read(buffer)) != -1) {
        digest.update(buffer, 0, count);
      }
    }
    StringBuilder hexadecimal = new StringBuilder(64);
    for (byte value : digest.digest()) {
      hexadecimal.append(String.format("%02x", value & 0xff));
    }
    return "sha256:" + hexadecimal;
  }

  private static void runClient(String baseURL, int caseCount) throws Exception {
    URI base = strictLoopbackURI(baseURL);
    if (caseCount > 10000) {
      throw new IllegalArgumentException("case-count exceeds bound");
    }
    String agent = URLEncoder.encode(AGENT, StandardCharsets.UTF_8);
    for (int caseNumber = 1; caseNumber <= caseCount; caseNumber++) {
      URI uri = base.resolve("/runCase?case=" + caseNumber + "&agent=" + agent);
      EchoClient client = new EchoClient(uri);
      if (!client.connectBlocking(CONNECT_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)) {
        throw new IOException(
            "case " + caseNumber + " did not connect: " + client.connectionFailure());
      }
      if (!client.awaitClose(CASE_TIMEOUT)) {
        client.close();
        throw new IOException("case " + caseNumber + " exceeded endpoint timeout");
      }
      client.closeBlocking();
    }
    EchoClient update = new EchoClient(base.resolve("/updateReports?agent=" + agent));
    if (!update.connectBlocking(CONNECT_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)) {
      throw new IOException("report update did not connect: " + update.connectionFailure());
    }
    if (!update.awaitClose(CASE_TIMEOUT)) {
      update.close();
      throw new IOException("report update exceeded endpoint timeout");
    }
    update.closeBlocking();
  }

  private static URI strictLoopbackURI(String value) {
    URI uri = URI.create(value);
    if (!"ws".equals(uri.getScheme()) || uri.getUserInfo() != null || uri.getFragment() != null
        || uri.getPort() < 1 || uri.getPort() > 65535
        || !("127.0.0.1".equals(uri.getHost()) || "localhost".equals(uri.getHost()))
        || !(uri.getPath().isEmpty() || "/".equals(uri.getPath())) || uri.getQuery() != null) {
      throw new IllegalArgumentException("client URL must be an exact loopback ws origin");
    }
    return uri;
  }

  private static void runServer(String bind, int port, int maxSeconds) throws Exception {
    if (!"127.0.0.1".equals(bind) || maxSeconds > 7200) {
      throw new IllegalArgumentException("invalid server binding or duration");
    }
    EchoServer server = new EchoServer(new InetSocketAddress(bind, port));
    Runtime.getRuntime().addShutdownHook(new Thread(() -> {
      try {
        server.stop(5);
      } catch (InterruptedException interrupted) {
        Thread.currentThread().interrupt();
      }
    }, "autobahn-endpoint-shutdown"));
    server.start();
    if (!server.awaitStart(CONNECT_TIMEOUT)) {
      throw new IOException("server did not start: " + server.startupFailure());
    }
    System.out.println("SERVER_READY " + server.getPort());
    System.out.flush();
    Thread.sleep(Duration.ofSeconds(maxSeconds).toMillis());
    server.stop(5);
  }

  private static void runSelfTest() throws Exception {
    EchoServer server = new EchoServer(new InetSocketAddress("127.0.0.1", 0));
    server.start();
    if (!server.awaitStart(CONNECT_TIMEOUT)) {
      throw new IOException("self-test server did not start: " + server.startupFailure());
    }
    CanaryClient client = new CanaryClient(new URI("ws://127.0.0.1:" + server.getPort()));
    if (!client.connectBlocking(CONNECT_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)
        || !client.await(CASE_TIMEOUT)) {
      client.close();
      server.stop(5);
      throw new IOException("self-test client did not complete");
    }
    client.closeBlocking();
    server.stop(5);
    if (client.failure() != null) {
      throw new IOException("self-test failed: " + client.failure());
    }
  }

  private static void printStatus(String status, Arguments arguments) {
    System.out.println(status + " runtime=" + RUNTIME_DIGEST + " support=" + SUPPORT_DIGEST
        + " adapter=" + arguments.value("adapter-digest"));
  }

  private static String sanitize(String value) {
    if (value == null) {
      return "unspecified";
    }
    String sanitized = value.replaceAll("[^A-Za-z0-9 ._:/=-]", "?");
    return sanitized.substring(0, Math.min(512, sanitized.length()));
  }

  private static final class EchoClient extends WebSocketClient {
    private final CountDownLatch closed = new CountDownLatch(1);
    private final AtomicReference<String> connectionFailure = new AtomicReference<>();
    private volatile boolean opened;

    EchoClient(URI uri) {
      super(uri, new Draft_6455());
      setConnectionLostTimeout(0);
    }

    @Override
    public void onOpen(ServerHandshake handshake) {
      opened = true;
    }

    @Override
    public void onMessage(String message) {
      send(message);
    }

    @Override
    public void onMessage(ByteBuffer message) {
      send(message);
    }

    @Override
    public void onClose(int code, String reason, boolean remote) {
      closed.countDown();
    }

    @Override
    public void onError(Exception exception) {
      if (!opened) {
        String message = exception.getMessage();
        connectionFailure.compareAndSet(
            null,
            exception.getClass().getSimpleName()
                + (message == null || message.isBlank() ? "" : ":" + message));
      }
      // Protocol-error cases intentionally surface endpoint errors. Autobahn's
      // digest-bound report, not this thin transport, classifies the outcome.
    }

    String connectionFailure() {
      String failure = connectionFailure.get();
      return failure == null ? "timeout without endpoint error" : failure;
    }

    boolean awaitClose(Duration timeout) throws InterruptedException {
      return closed.await(timeout.toMillis(), TimeUnit.MILLISECONDS);
    }
  }

  private static final class EchoServer extends WebSocketServer {
    private final CountDownLatch started = new CountDownLatch(1);
    private final AtomicReference<String> startupFailure = new AtomicReference<>();

    EchoServer(InetSocketAddress address) {
      super(address, Collections.singletonList(new Draft_6455()));
      setConnectionLostTimeout(0);
    }

    @Override
    public void onOpen(WebSocket connection, ClientHandshake handshake) {}

    @Override
    public void onClose(WebSocket connection, int code, String reason, boolean remote) {}

    @Override
    public void onMessage(WebSocket connection, String message) {
      connection.send(message);
    }

    @Override
    public void onMessage(WebSocket connection, ByteBuffer message) {
      connection.send(message);
    }

    @Override
    public void onError(WebSocket connection, Exception exception) {
      if (connection == null && started.getCount() != 0) {
        startupFailure.compareAndSet(null, exception.getClass().getSimpleName());
        started.countDown();
      }
      // Invalid-frame cases intentionally provoke errors; the suite report is
      // authoritative for each exact case result.
    }

    @Override
    public void onStart() {
      started.countDown();
    }

    boolean awaitStart(Duration timeout) throws InterruptedException {
      return started.await(timeout.toMillis(), TimeUnit.MILLISECONDS) && startupFailure.get() == null;
    }

    String startupFailure() {
      String failure = startupFailure.get();
      return failure == null ? "timeout" : failure;
    }
  }

  private static final class CanaryClient extends WebSocketClient {
    private static final String TEXT = "verified-autobahn-canary";
    private static final byte[] BINARY = new byte[] {0, 1, 2, 3, 4, 5};
    private final CountDownLatch complete = new CountDownLatch(1);
    private final AtomicReference<String> failure = new AtomicReference<>();
    private boolean textSeen;

    CanaryClient(URI uri) {
      super(uri, new Draft_6455());
      setConnectionLostTimeout(0);
    }

    @Override
    public void onOpen(ServerHandshake handshake) {
      send(TEXT);
    }

    @Override
    public void onMessage(String message) {
      if (!TEXT.equals(message) || textSeen) {
        failure.compareAndSet(null, "text echo mismatch");
        close();
        return;
      }
      textSeen = true;
      send(BINARY);
    }

    @Override
    public void onMessage(ByteBuffer message) {
      byte[] actual = new byte[message.remaining()];
      message.get(actual);
      if (!textSeen || !Arrays.equals(BINARY, actual)) {
        failure.compareAndSet(null, "binary echo mismatch");
      }
      close();
    }

    @Override
    public void onClose(int code, String reason, boolean remote) {
      if (!textSeen) {
        failure.compareAndSet(null, "closed before echo");
      }
      complete.countDown();
    }

    @Override
    public void onError(Exception exception) {
      failure.compareAndSet(null, exception.getClass().getSimpleName());
      complete.countDown();
    }

    boolean await(Duration timeout) throws InterruptedException {
      return complete.await(timeout.toMillis(), TimeUnit.MILLISECONDS);
    }

    String failure() {
      return failure.get();
    }
  }

  private record Arguments(String mode, Map<String, String> values) {
    static Arguments parse(String[] arguments) {
      if (arguments.length < 1 || arguments.length % 2 == 0) {
        throw new IllegalArgumentException("mode and exact --key value pairs are required");
      }
      String mode = arguments[0];
      Map<String, String> values = new HashMap<>();
      for (int index = 1; index < arguments.length; index += 2) {
        String key = arguments[index];
        if (!key.matches("--[a-z][a-z-]{0,31}") || arguments[index + 1].isEmpty()
            || values.put(key.substring(2), arguments[index + 1]) != null) {
          throw new IllegalArgumentException("invalid or duplicate argument");
        }
      }
      return new Arguments(mode, Collections.unmodifiableMap(values));
    }

    String value(String key) {
      String value = values.get(key);
      if (value == null) {
        throw new IllegalArgumentException("missing --" + key);
      }
      return value;
    }

    void requireExactly(String... keys) {
      List<String> expected = new ArrayList<>(Arrays.asList(keys));
      List<String> actual = new ArrayList<>(values.keySet());
      Collections.sort(expected);
      Collections.sort(actual);
      if (!expected.equals(actual)) {
        throw new IllegalArgumentException("argument set differs from fixed mode contract");
      }
    }

    int positiveInt(String key) {
      int value = Integer.parseInt(value(key));
      if (value < 1) {
        throw new IllegalArgumentException(key + " must be positive");
      }
      return value;
    }

    int port(String key) {
      int value = positiveInt(key);
      if (value > 65535) {
        throw new IllegalArgumentException("port is out of range");
      }
      return value;
    }

    int nonnegativePort(String key) {
      int value = Integer.parseInt(value(key));
      if (value < 0 || value > 65535) {
        throw new IllegalArgumentException(key + " is out of range");
      }
      return value;
    }
  }
}
