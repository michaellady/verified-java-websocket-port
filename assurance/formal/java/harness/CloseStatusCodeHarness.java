/*
 * J1 bounded-model-checking harness for obligation `surface.close.status-code`.
 *
 * SUBJECT LANGUAGE: JAVA
 * METHOD:           BOUNDED_MODEL (JBMC / CBMC bounded model checking)
 *
 * ATTESTATION -- NO DUPLICATE IMPLEMENTATION
 * ------------------------------------------
 * This harness CALLS the shipped production symbol
 *
 *     org.java_websocket.framing.CloseFrame.isValid()V
 *
 * on a `CloseFrame` instance built by the shipped production constructor and
 * mutated by the shipped production setter `CloseFrame.setCode(I)V`. It does
 * NOT reimplement, inline, copy, transcribe, or otherwise duplicate any part
 * of the close-frame validation algorithm. The only logic authored here is
 * `rfcSendableWithEmptyReason`, which is a DECLARATIVE SPECIFICATION stated as
 * closed integer ranges drawn from RFC 6455 section 7.4.1 plus the library's
 * own documented outbound restriction. It is deliberately written as a set of
 * interval tests, with a shape that does not mirror the implementation's
 * branch structure, so that agreement between the two is evidence rather than
 * tautology.
 *
 * NON-VACUITY ARGUMENT
 * --------------------
 * JBMC 6.11.0 ships no model for `java.nio` (see core-models.jar in the
 * receipt's trusted computing base), so any obligation whose decision surface
 * reads a `ByteBuffer` is vacuous under this tool. This obligation is not such
 * a case, and that is why it was selected first:
 *
 *   - `CloseFrame.isValid()` reads exactly two fields: the `int code` and the
 *     `String reason`. Both are plain modelled JVM types.
 *   - Its `super.isValid()` call (`ControlFrame.isValid()`) reads exactly four
 *     booleans: fin, rsv1, rsv2, rsv3. All are plain modelled JVM types, and
 *     all are assigned concretely by the `FramedataImpl1` constructor.
 *   - The only `java.nio` contact on this path is `CloseFrame.updatePayload()`,
 *     which WRITES the inherited `unmaskedpayload` field. `isValid()` never
 *     READS that field. The nondeterminism introduced by the unmodelled
 *     ByteBuffer therefore cannot reach the property under check.
 *
 * The `reason` field is pinned to the empty string by the shipped constructor
 * and is not varied by this harness; that is a declared bound, not an
 * accident, and it is recorded in the receipt's `bounds` section.
 */

import org.cprover.CProver;
import org.java_websocket.exceptions.InvalidDataException;
import org.java_websocket.framing.CloseFrame;

public final class CloseStatusCodeHarness {

  private CloseStatusCodeHarness() {
  }

  /**
   * DECLARATIVE SPECIFICATION.
   *
   * The set of close status codes that a conforming endpoint may place on the
   * wire in an outbound Close frame that carries an EMPTY reason, expressed as
   * closed intervals:
   *
   *   [1000, 1003]  normal / going-away / protocol-error / refuse
   *   [1008, 1014]  policy .. bad-gateway
   *   [3000, 4999]  registered and private-use ranges
   *
   * Everything else is not sendable: the reserved singletons 1004, 1005, 1006
   * and 1015, the code 1007 (which RFC 6455 permits in general but which this
   * library rejects when the reason is empty), the unassigned band
   * [1016, 2999], and everything below 1000 or above 4999.
   *
   * This method contains no close-frame logic from the production source. It
   * is a membership test over integer intervals.
   */
  static boolean rfcSendableWithEmptyReason(int code) {
    if (code >= 1000 && code <= 1003) {
      return true;
    }
    if (code >= 1008 && code <= 1014) {
      return true;
    }
    if (code >= 3000 && code <= 4999) {
      return true;
    }
    return false;
  }

  /**
   * The property. Over ALL 2^32 values of the 32-bit close code, the shipped
   * `CloseFrame.isValid()` throws `InvalidDataException` (or its subclass
   * `InvalidFrameException`) if and only if the code is not sendable with an
   * empty reason.
   */
  public static void check() {
    int code = CProver.nondetInt();

    // SHIPPED production constructor.
    CloseFrame frame = new CloseFrame();
    // SHIPPED production setter. Note this setter itself rewrites the
    // reserved code 1015 to 1005; that rewrite is production behaviour and is
    // intentionally exercised rather than modelled here.
    frame.setCode(code);

    boolean rejected;
    try {
      // ===== SHIPPED PRODUCTION SYMBOL UNDER CHECK =====
      frame.isValid();
      // =================================================
      rejected = false;
    } catch (InvalidDataException e) {
      rejected = true;
    }

    assert rejected == !rfcSendableWithEmptyReason(code);
  }
}
