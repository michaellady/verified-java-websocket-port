import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import org.java_websocket.drafts.Draft_6455;

/**
 * Mutant and control entry point for the Java formal-binding evidence lane.
 *
 * <p>{@code OracleMain} pins the loaded Java-WebSocket runtime to the single accepted v1.6.0
 * digest and refuses to start against anything else. That control is exactly right for a baseline
 * observation and it is deliberately left untouched: this class does not modify, relax or bypass
 * it, and baseline runs still go through {@code OracleMain}.
 *
 * <p>A mutation canary, however, has to run the same scenario against a runtime that differs from
 * the accepted one in exactly one recorded way. This entry point therefore takes the expected
 * runtime digest as a command-line argument instead of holding a constant, verifies that the loaded
 * {@code Draft_6455} really came from that regular file with that digest, and then hands the JSONL
 * loop straight to {@code OracleMain.run}, so mutant, control and baseline observations are produced
 * by identical protocol and engine code.
 *
 * <p>The Go side computes the expected digest itself from the archive it built, so this class can
 * only confirm an identity that was decided outside it. It cannot admit an unpinned runtime: a
 * missing argument, a non-file code source or any digest disagreement exits before the loop starts.
 */
public final class MutantOracleMain {

  private MutantOracleMain() {}

  public static void main(String[] args) {
    if (args.length != 1 || args[0].length() != 64) {
      diagnostic("mutant oracle requires exactly one 64-character expected runtime digest");
      System.exit(64);
      return;
    }
    try {
      System.setProperty("slf4j.internal.verbosity", "ERROR");
      String digest = verifyRuntimeAgainst(args[0]);
      OracleMain.run(System.in, System.out, System.err, digest);
    } catch (IllegalStateException e) {
      diagnostic("mutant oracle startup denied: " + e.getMessage());
      System.exit(78);
    } catch (IOException e) {
      diagnostic("mutant oracle I/O failure");
      System.exit(74);
    } catch (RuntimeException | LinkageError e) {
      diagnostic("mutant oracle startup failure: " + e.getClass().getSimpleName());
      System.exit(70);
    }
  }

  static String verifyRuntimeAgainst(String expectedHex) {
    try {
      var source = Draft_6455.class.getProtectionDomain().getCodeSource();
      if (source == null) {
        throw new IllegalStateException("RUNTIME_IDENTITY_UNAVAILABLE");
      }
      var path = java.nio.file.Path.of(source.getLocation().toURI());
      if (!java.nio.file.Files.isRegularFile(path)) {
        throw new IllegalStateException("RUNTIME_NOT_A_PINNED_ARCHIVE");
      }
      byte[] bytes = java.nio.file.Files.readAllBytes(path);
      String actual = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
      if (!MessageDigest.isEqual(actual.getBytes(StandardCharsets.US_ASCII),
          expectedHex.getBytes(StandardCharsets.US_ASCII))) {
        throw new IllegalStateException("RUNTIME_DIGEST_MISMATCH");
      }
      return "sha256:" + actual;
    } catch (IllegalStateException e) {
      throw e;
    } catch (Exception e) {
      throw new IllegalStateException("RUNTIME_IDENTITY_UNAVAILABLE");
    }
  }

  private static void diagnostic(String value) {
    PrintStream err = System.err;
    byte[] bytes = value.replace('\r', ' ').replace('\n', ' ').getBytes(StandardCharsets.UTF_8);
    err.write(bytes, 0, Math.min(bytes.length, 512));
    err.println();
    err.flush();
  }
}
