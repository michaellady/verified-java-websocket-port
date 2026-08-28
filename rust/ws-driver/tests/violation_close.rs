//! The C6 layer-split composer: which close frame, if any, shipped
//! `WebSocketImpl` puts on the wire in answer to a protocol violation
//! (owner decision `us017-c6-layer-split-owner-decision-2026-08-28.json`,
//! sha256 d41b5307…).
//!
//! Every interesting case is a Java carve-out, and none of them should need
//! a TCP connection to test — which is why the composition is a pure
//! function in this crate rather than hand-rolled in the adapter that writes
//! the bytes. `rust/ws-testee/tests/loopback.rs` covers the same reaction on
//! a real socket.

use ws_core::error::FailureCode;
use ws_core::{ReadyState, Role, TypedProtocolFailure};
use ws_driver::{ABNORMAL_CLOSE_CODE, compose_violation_close};

/// The exploration/default mask-key seed; irrelevant to every server-role
/// case and pinned here so the client-role case is reproducible.
const SEED: u64 = 0;

/// The Autobahn seam case: a server answering a protocol violation puts
/// shipped Java's close frame on the wire, UNMASKED (a masked
/// server->client frame is itself a protocol error).
#[test]
fn server_role_composes_the_unmasked_1002_close() {
    let frame = compose_violation_close(
        &TypedProtocolFailure::java_invalid_data(1002),
        Role::Server,
        ReadyState::Open,
        SEED,
    );
    assert_eq!(frame, Some((1002, vec![0x88, 0x02, 0x03, 0xEA])));
}

/// The close code travels through, it is not hardcoded to 1002: an
/// invalid-UTF-8 rejection carries 1007 and a too-large frame 1009, and
/// Java sends `e.getCloseCode()` (WebSocketImpl.java:631-633).
#[test]
fn the_failures_own_close_code_reaches_the_wire() {
    for (code, low) in [(1007u16, 0xEFu8), (1009, 0xF1)] {
        let frame = compose_violation_close(
            &TypedProtocolFailure::java_invalid_data(code),
            Role::Server,
            ReadyState::Open,
            SEED,
        );
        assert_eq!(
            frame,
            Some((code, vec![0x88, 0x02, 0x03, low])),
            "close code {code} must reach the wire unchanged"
        );
    }
}

/// A client-role endpoint MUST mask (RFC 6455 5.3). The payload is
/// checked by unmasking, so this cannot pass on an unmasked frame.
#[test]
fn client_role_masks_the_violation_close() {
    let (code, frame) = compose_violation_close(
        &TypedProtocolFailure::java_invalid_data(1002),
        Role::Client,
        ReadyState::Open,
        SEED,
    )
    .expect("client composes a close frame");
    assert_eq!(code, 1002);
    assert_eq!(frame.len(), 8, "2 header + 4 mask key + 2 payload");
    assert_eq!(frame[0], 0x88);
    assert_eq!(frame[1], 0x82, "MASK bit set, payload length 2");
    let key = [frame[2], frame[3], frame[4], frame[5]];
    let unmasked = [frame[6] ^ key[0], frame[7] ^ key[1]];
    assert_eq!(
        unmasked,
        [0x03, 0xEA],
        "the masked payload must decode to close code 1002"
    );
}

/// A fatal with NO close code never reached `close(e)` in Java, so it
/// must not invent a frame. STATE_VIOLATION and every limit code land
/// here — including the fatal command rejection the C5 fix now surfaces.
#[test]
fn a_failure_without_a_close_code_composes_nothing() {
    for code in [
        FailureCode::StateViolation,
        FailureCode::InputLimitExceeded,
        FailureCode::BufferLimitExceeded,
        FailureCode::FrameLimitExceeded,
        FailureCode::ActionLimitExceeded,
    ] {
        let failure = TypedProtocolFailure::protocol(code);
        assert_eq!(
            failure.close_code, None,
            "fixture precondition for {code:?}"
        );
        assert_eq!(
            compose_violation_close(&failure, Role::Server, ReadyState::Open, SEED),
            None,
            "{code:?} must not fabricate a close frame"
        );
    }
}

/// 1006 is the one close code `WebSocketImpl.close` answers by reaching
/// CLOSING with NOTHING on the wire (WebSocketImpl.java:466-471).
#[test]
fn abnormal_close_1006_composes_nothing() {
    assert_eq!(
        compose_violation_close(
            &TypedProtocolFailure::java_invalid_data(ABNORMAL_CLOSE_CODE),
            Role::Server,
            ReadyState::Open,
            SEED,
        ),
        None
    );
}

/// Outside OPEN the whole method is a no-op (`close`'s :464 guard), so a
/// violation surfacing while already Closing or Closed sends nothing.
#[test]
fn outside_open_composes_nothing() {
    for state in [
        ReadyState::NotYetConnected,
        ReadyState::Closing,
        ReadyState::Closed,
    ] {
        assert_eq!(
            compose_violation_close(
                &TypedProtocolFailure::java_invalid_data(1002),
                Role::Server,
                state,
                SEED,
            ),
            None,
            "{state:?} must not send a close frame"
        );
    }
}
