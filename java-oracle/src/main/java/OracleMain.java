import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Map;
import java.util.TreeMap;
import org.java_websocket.drafts.Draft_6455;

/** Versioned JSONL entry point. Standard output is reserved for protocol records. */
public final class OracleMain {
  static final String PROTOCOL = "java-websocket-oracle";
  static final String VERSION = "1.0.0";
  static final int HARD_LINE_BYTES = 1_048_576;
  static final int HARD_DIAGNOSTIC_BYTES = 512;
  static final String EXPECTED_RUNTIME_SHA256 =
      "eae29213e4f16515639c28957200f011b3967fffcada1962cf0255d24919c22f";

  private OracleMain() {}

  public static void main(String[] args) {
    if (args.length != 0) {
      diagnostic(System.err, "oracle accepts no command-line arguments");
      System.exit(64);
    }
    try {
      // The oracle never emits library diagnostics. Protocol errors are returned on stdout and
      // fatal adapter diagnostics are emitted through the bounded path below.
      System.setProperty("slf4j.internal.verbosity", "ERROR");
      String runtimeDigest = verifyRuntime();
      run(System.in, protocolOutput(System.out), System.err, runtimeDigest);
    } catch (ProtocolException e) {
      diagnostic(System.err, "oracle startup denied: " + e.code() + ": " + e.getMessage());
      System.exit(78);
    } catch (NoClassDefFoundError e) {
      diagnostic(System.err, "oracle startup denied: RUNTIME_CLASS_UNAVAILABLE");
      System.exit(78);
    } catch (IOException e) {
      diagnostic(System.err, "oracle I/O failure");
      System.exit(74);
    } catch (RuntimeException | LinkageError e) {
      diagnostic(System.err, "oracle startup failure: " + e.getClass().getSimpleName());
      System.exit(70);
    }
  }

  static PrintStream protocolOutput(OutputStream output) {
    return new PrintStream(output, true, StandardCharsets.UTF_8);
  }

  static void run(InputStream in, PrintStream out, PrintStream err, String runtimeDigest)
      throws IOException {
    System.setProperty("slf4j.internal.verbosity", "ERROR");
    BoundedLineReader reader = new BoundedLineReader(in, HARD_LINE_BYTES);
    while (true) {
      Line line = reader.next();
      if (line == null) {
        return;
      }
      Map<String, Object> response;
      if (line.tooLong()) {
        response = error(null, "LINE_LIMIT_EXCEEDED",
            "JSONL record exceeds " + HARD_LINE_BYTES + " bytes", null);
      } else if (line.bytes().length == 0) {
        response = error(null, "EMPTY_LINE", "empty JSONL records are forbidden", null);
      } else {
        try {
          String json = decodeUtf8(line.bytes());
          response = OracleEngine.process(json, runtimeDigest);
        } catch (ProtocolException e) {
          response = error(null, e.code(), e.getMessage(), e.closeCode());
        } catch (RuntimeException | LinkageError e) {
          response = error(null, "INTERNAL_ADAPTER_ERROR",
              "adapter failed closed: " + e.getClass().getSimpleName(), null);
          diagnostic(err, "oracle request failed closed: " + e.getClass().getSimpleName());
        }
      }
      out.println(StrictJson.write(response));
      out.flush();
    }
  }

  static Map<String, Object> error(
      String requestId, String code, String detail, Integer closeCode) {
    Map<String, Object> error = new TreeMap<>();
    error.put("code", code);
    if (closeCode != null) {
      error.put("close_code", closeCode);
    }
    error.put("detail", detail == null ? "unspecified protocol error" : detail);
    Map<String, Object> response = new TreeMap<>();
    response.put("error", error);
    response.put("outcome", "error");
    response.put("protocol", PROTOCOL);
    response.put("request_id", requestId);
    response.put("version", VERSION);
    return response;
  }

  private static String decodeUtf8(byte[] bytes) throws ProtocolException {
    try {
      return StandardCharsets.UTF_8.newDecoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .decode(ByteBuffer.wrap(bytes)).toString();
    } catch (CharacterCodingException e) {
      throw new ProtocolException("INVALID_UTF8", "JSONL record is not valid UTF-8");
    }
  }

  static String verifyRuntime() throws ProtocolException {
    try {
      var source = Draft_6455.class.getProtectionDomain().getCodeSource();
      if (source == null) {
        throw new ProtocolException("RUNTIME_IDENTITY_UNAVAILABLE",
            "Java-WebSocket code source is unavailable");
      }
      var path = java.nio.file.Path.of(source.getLocation().toURI());
      if (!java.nio.file.Files.isRegularFile(path)) {
        throw new ProtocolException("RUNTIME_NOT_PINNED_JAR",
            "Java-WebSocket runtime must be loaded from the accepted JAR");
      }
      byte[] bytes = java.nio.file.Files.readAllBytes(path);
      String actual = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
      if (!MessageDigest.isEqual(actual.getBytes(StandardCharsets.US_ASCII),
          EXPECTED_RUNTIME_SHA256.getBytes(StandardCharsets.US_ASCII))) {
        throw new ProtocolException("RUNTIME_DIGEST_MISMATCH",
            "loaded Java-WebSocket JAR does not match the accepted v1.6.0 digest");
      }
      return "sha256:" + actual;
    } catch (ProtocolException e) {
      throw e;
    } catch (Exception e) {
      throw new ProtocolException("RUNTIME_IDENTITY_UNAVAILABLE",
          "cannot verify the loaded Java-WebSocket runtime");
    }
  }

  private static void diagnostic(PrintStream err, String value) {
    byte[] bytes = value.replace('\r', ' ').replace('\n', ' ').getBytes(StandardCharsets.UTF_8);
    int length = Math.min(bytes.length, HARD_DIAGNOSTIC_BYTES);
    err.write(bytes, 0, length);
    err.println();
    err.flush();
  }

  record Line(byte[] bytes, boolean tooLong) {}

  static final class BoundedLineReader {
    private final InputStream in;
    private final int limit;

    BoundedLineReader(InputStream in, int limit) {
      this.in = in;
      this.limit = limit;
    }

    Line next() throws IOException {
      ByteArrayOutputStream buffer = new ByteArrayOutputStream();
      boolean tooLong = false;
      boolean sawAny = false;
      while (true) {
        int value = in.read();
        if (value < 0) {
          return sawAny ? new Line(buffer.toByteArray(), tooLong) : null;
        }
        sawAny = true;
        if (value == '\n') {
          return new Line(buffer.toByteArray(), tooLong);
        }
        if (buffer.size() < limit) {
          buffer.write(value);
        } else {
          tooLong = true;
        }
      }
    }
  }
}
