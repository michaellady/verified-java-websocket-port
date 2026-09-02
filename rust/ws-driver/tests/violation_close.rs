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
//!
//! Two things are checked here that the reaction's first landing did not:
//! that the reaction is gated on the failure's ARRIVAL PATH, and that the
//! client-role frame's mask key comes from the connection's own masking
//! sequence rather than a parallel derivation that collides with it.
//!
//! # The gate is enforced by this file's ability to COMPILE
//!
//! Every case below reaches the encoder by minting a [`ViolationClose`]
//! through [`violation_close_verdict`], because from out here — an
//! integration test is a separate crate, exactly like an adapter — there is
//! no other way to obtain one. Round 2 blocked the previous shape, where
//! `violation_close_frame(1002, None)` was directly callable and these
//! tests used it: an adapter could compose the C6 bytes without naming an
//! origin, so the gate was conventional. All four manufacture routes were
//! run against the fixed crate and refused by rustc: passing a bare code
//! (E0308), a struct literal over the private field (E0451), `Default`
//! (E0277) and `From<u16>` (E0277).

use ws_core::config::ConnectionConfig;
use ws_core::connection::{CommandSender, InitialState, LocalCommand};
use ws_core::error::FailureCode;
use ws_core::{ReadyState, Role, TypedProtocolFailure};
use ws_driver::{
    ABNORMAL_CLOSE_CODE, ConnectionDriver, DriverInput, DriverOutput, FailureOrigin,
    ViolationClose, connection_driver_in_state, violation_close_frame, violation_close_verdict,
};

/// The one route to a [`ViolationClose`]: the origin gate, on the arrival
/// path and lifecycle state Java answers. Panics if the gate refuses, so a
/// fixture that stopped reaching the encoder fails loudly rather than
/// silently testing nothing.
fn decode_path_verdict(code: u16) -> ViolationClose {
    violation_close_verdict(
        &TypedProtocolFailure::java_invalid_data(code),
        FailureOrigin::InboundDecode,
        ReadyState::Open,
    )
    .expect("a decode-path violation while Open is the case Java answers")
}

/// The exploration/default mask-key seed; irrelevant to every server-role
/// case and pinned here so the client-role cases are reproducible.
const SEED: u64 = 0;

/// Every non-decode arrival path, for the gate cases below.
const NON_DECODE_ORIGINS: [FailureOrigin; 3] = [
    FailureOrigin::LocalCommand,
    FailureOrigin::TransportEof,
    FailureOrigin::AutomaticReply,
];

/// The Autobahn seam case: a server answering a decode-path protocol
/// violation puts shipped Java's close frame on the wire, UNMASKED (a masked
/// server->client frame is itself a protocol error).
#[test]
fn server_role_composes_the_unmasked_1002_close() {
    let verdict = decode_path_verdict(1002);
    assert_eq!(verdict.code(), 1002);
    assert_eq!(
        violation_close_frame(verdict, None),
        vec![0x88, 0x02, 0x03, 0xEA]
    );
}

/// The close code travels through, it is not hardcoded to 1002: an
/// invalid-UTF-8 rejection carries 1007 and a too-large frame 1009, and
/// Java sends `e.getCloseCode()` (WebSocketImpl.java:631-633).
#[test]
fn the_failures_own_close_code_reaches_the_wire() {
    for (code, low) in [(1007u16, 0xEFu8), (1009, 0xF1)] {
        let verdict = decode_path_verdict(code);
        assert_eq!(
            verdict.code(),
            code,
            "close code {code} must survive the carve-outs"
        );
        assert_eq!(
            violation_close_frame(verdict, None),
            vec![0x88, 0x02, 0x03, low],
            "close code {code} must reach the wire unchanged"
        );
    }
}

/// A client-role endpoint MUST mask (RFC 6455 5.3). The payload is
/// checked by unmasking, so this cannot pass on an unmasked frame.
#[test]
fn client_role_masks_the_violation_close() {
    let key = [0xA1u8, 0xB2, 0xC3, 0xD4];
    let frame = violation_close_frame(decode_path_verdict(1002), Some(key));
    assert_eq!(frame.len(), 8, "2 header + 4 mask key + 2 payload");
    assert_eq!(frame[0], 0x88);
    assert_eq!(frame[1], 0x82, "MASK bit set, payload length 2");
    assert_eq!([frame[2], frame[3], frame[4], frame[5]], key);
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
            violation_close_verdict(&failure, FailureOrigin::InboundDecode, ReadyState::Open),
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
        violation_close_verdict(
            &TypedProtocolFailure::java_invalid_data(ABNORMAL_CLOSE_CODE),
            FailureOrigin::InboundDecode,
            ReadyState::Open,
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
            violation_close_verdict(
                &TypedProtocolFailure::java_invalid_data(1002),
                FailureOrigin::InboundDecode,
                state,
            ),
            None,
            "{state:?} must not send a close frame"
        );
    }
}

/// C6 IS GATED ON THE ARRIVAL PATH (review finding: "C6 loses failure
/// provenance").
///
/// `decodeFrames`' InvalidDataException arm is Java's ONLY route to
/// `close(e)`. The fixture failure is deliberately the exact value a local
/// `send_close {code: 999}` rejection produces — `JAVA_INVALID_DATA` with
/// close code 1002 — which is also the exact value an inbound RSV1
/// violation produces. Nothing inside the failure distinguishes them, which
/// is why the origin has to travel beside it.
#[test]
fn only_an_inbound_decode_failure_gets_a_close_frame() {
    let failure = TypedProtocolFailure::java_invalid_data(1002);
    assert_eq!(
        violation_close_verdict(&failure, FailureOrigin::InboundDecode, ReadyState::Open)
            .map(ViolationClose::code),
        Some(1002),
        "the decode path is the one that answers"
    );
    for origin in NON_DECODE_ORIGINS {
        assert_eq!(
            violation_close_verdict(&failure, origin, ReadyState::Open),
            None,
            "REGRESSION: {origin:?} is not a decode-path violation and Java answers it with \
             nothing"
        );
    }
}

/// The same gate at the DRIVER seam an adapter actually calls, driven
/// through the real command path rather than by handing the composer a
/// synthetic failure: `send_close {code: 999}` is rejected by the core's
/// Q13 validity chain, C5 surfaces it as `DriverOutput::Failure`, and the
/// reaction must still compose nothing.
///
/// The pinned Java oracle's own recorded run of `us005.pub.0000` (the same
/// command) reports `final_state: "open"` — nothing went on the wire there,
/// so nothing may go on the wire here.
#[test]
fn a_locally_rejected_send_close_composes_no_violation_frame() {
    let (sender, mut driver) = connection_driver_in_state(
        ConnectionConfig::default(),
        Role::Client,
        InitialState::Open,
    );
    sender
        .try_send(LocalCommand::SendClose {
            code: 999,
            reason: String::new(),
        })
        .expect("bounded enqueue within capacity");

    let result = driver.poll(DriverInput::Wake);
    let DriverOutput::Failure { failure, origin } = result.output else {
        panic!("fixture precondition: C5 must surface the fatal command rejection");
    };
    assert_eq!(failure.code, FailureCode::JavaInvalidData);
    assert_eq!(
        failure.close_code,
        Some(1002),
        "fixture precondition: the rejection reports close code 1002"
    );
    assert_eq!(origin, FailureOrigin::LocalCommand);

    assert_eq!(
        driver.compose_violation_close(&failure, origin),
        None,
        "REGRESSION: a locally rejected command composed C6's inbound-violation close"
    );
}

/// MASK-KEY REUSE (review finding: "Client-side C6 close frames can reuse an
/// earlier masking key").
///
/// `next_mask_key` (ws-core connection.rs) mixes `mask_key_seed +
/// counter * K` through a SplitMix64 finalizer. The C6 composer used to
/// derive its key from `mask_key_seed + close_code * K` through the
/// IDENTICAL mixer, so the two agreed exactly whenever `counter ==
/// close_code`: a 1002 reaction after the 1002nd outbound masked frame
/// repeated that frame's key. The mixer is a bijection on u64, so that was
/// an algebraic identity, not a probabilistic collision.
///
/// `mask_key_derivation_advances_per_outbound_frame` (ws-core
/// adversarial_fuzz.rs) pins the contract it broke: successive masked frames
/// carry distinct keys. The violation close is the frame that SUCCEEDS the
/// last outbound frame on the wire, so it is inside that contract.
///
/// 1002 outbound frames is reachable: `max_frames` ceils at 4096 and
/// `max_actions` at 1024.
///
/// Driven through the DRIVER seam, which is where the reservation happens —
/// a core-only version of this test would pass while the shipped path still
/// collided.
#[test]
fn the_violation_close_never_repeats_the_preceding_frames_mask_key() {
    const COLLIDING_CODE: u16 = 1002;
    let config = ConnectionConfig::builder()
        .mask_key_seed(SEED)
        .max_frames(u64::from(COLLIDING_CODE) + 8)
        .max_actions(1024)
        .build()
        .expect("valid config");
    let (sender, mut driver) = connection_driver_in_state(config, Role::Client, InitialState::Open);

    // Drive the connection to the COLLIDING_CODE-th outbound masked frame
    // and keep that frame's key. One command in flight at a time, enqueued
    // only at quiescence, so neither bounded queue ever backpressures.
    let mut preceding_key = [0u8; 4];
    let mut frames = 0u16;
    for _ in 0..200_000 {
        let pending = match driver.poll(DriverInput::Wake).output {
            DriverOutput::Write(suffix) => suffix.to_vec(),
            DriverOutput::Failure { failure, .. } => panic!("unexpected failure: {failure:?}"),
            DriverOutput::Idle => {
                if frames == COLLIDING_CODE {
                    break;
                }
                sender
                    .try_send(LocalCommand::SendBinary { data: vec![0x11] })
                    .expect("bounded enqueue at quiescence");
                continue;
            }
            _ => continue,
        };
        assert_eq!(pending.len(), 7, "header(2) + mask(4) + payload(1)");
        preceding_key = [pending[2], pending[3], pending[4], pending[5]];
        frames += 1;
        driver.poll(DriverInput::WriteProgress {
            bytes: pending.len(),
        });
    }
    assert_eq!(
        frames, COLLIDING_CODE,
        "the fixture must actually reach outbound frame {COLLIDING_CODE}"
    );

    let (code, frame) = driver
        .compose_violation_close(
            &TypedProtocolFailure::java_invalid_data(COLLIDING_CODE),
            FailureOrigin::InboundDecode,
        )
        .expect("client composes a close frame");
    assert_eq!(code, COLLIDING_CODE);
    let violation_key = [frame[2], frame[3], frame[4], frame[5]];

    assert_ne!(
        preceding_key, violation_key,
        "REGRESSION: the C6 close frame reuses the mask key of outbound frame \
         {COLLIDING_CODE}"
    );
}

/// Drive ONE ordinary outbound masked frame out of `driver` — a plain
/// `send_binary` through the real command path — and return the 4-byte mask
/// key the wire bytes carry.
///
/// This reads the key off the FRAME, not out of any reservation API, which
/// is what makes it usable as an independent expectation below.
fn next_ordinary_outbound_mask_key(
    sender: &CommandSender,
    driver: &mut ConnectionDriver,
) -> [u8; 4] {
    sender
        .try_send(LocalCommand::SendBinary { data: vec![0x11] })
        .expect("bounded enqueue at quiescence");
    for _ in 0..64 {
        match driver.poll(DriverInput::Wake).output {
            DriverOutput::Write(suffix) => {
                let bytes = suffix.to_vec();
                assert_eq!(bytes.len(), 7, "header(2) + mask(4) + payload(1)");
                let key = [bytes[2], bytes[3], bytes[4], bytes[5]];
                driver.poll(DriverInput::WriteProgress { bytes: bytes.len() });
                return key;
            }
            DriverOutput::Failure { failure, .. } => panic!("unexpected failure: {failure:?}"),
            _ => {}
        }
    }
    panic!("the driver never produced the ordinary outbound frame");
}

/// The mask key of a client-role driver's `nth` ordinary outbound frame,
/// counting from 1, on a FRESH connection with the default config.
fn ordinary_outbound_mask_key(nth: usize) -> [u8; 4] {
    let (sender, mut driver) = connection_driver_in_state(
        ConnectionConfig::default(),
        Role::Client,
        InitialState::Open,
    );
    let mut key = [0u8; 4];
    for _ in 0..nth {
        key = next_ordinary_outbound_mask_key(&sender, &mut driver);
    }
    key
}

/// THE C6 FRAME TAKES EXACTLY ONE SLOT OF THE ORDINARY MASK SEQUENCE — the
/// FIRST — and the next ordinary frame takes EXACTLY the SECOND.
///
/// # Why the expectation is derived this way
///
/// Review 01a04899 round 2 blocked the previous version of this test as
/// SELF-FULFILLING: it obtained the "next key" expectation by calling
/// `reserve_mask_key` on a reference core — the very method under test. An
/// implementation that advanced the counter TWICE and returned the second
/// key satisfied that expectation exactly, so it passed while silently
/// burning a slot of the connection's masking sequence. That was measured,
/// not argued: with `reserve_mask_key` mutated to advance twice, the whole
/// Rust workspace — 403 tests across 37 binaries — passed.
///
/// So the expectation now comes from OUTSIDE the reservation API entirely:
/// keys 1 and 2 are read off the wire bytes of an independent connection's
/// ORDINARY outbound frames, composed by the core's own `emit_outbound`
/// path with no reservation anywhere in it. The one-slot contract is then
/// pinned from both sides, which is what makes it discriminating:
///
/// * take MORE than one slot (advance twice) and the C6 frame carries key 2
///   instead of key 1 — the first assertion fails;
/// * take FEWER than one slot (peek without advancing) and the C6 frame
///   still carries key 1, but the following ordinary frame carries key 1
///   again instead of key 2 — the second assertion fails.
///
/// Both mutations were run against this test and both were read failing.
#[test]
fn the_violation_close_takes_exactly_one_slot_of_the_ordinary_mask_sequence() {
    // Expectations from ordinary outbound frames — no reservation API.
    let ordinary_first = ordinary_outbound_mask_key(1);
    let ordinary_second = ordinary_outbound_mask_key(2);
    assert_ne!(
        ordinary_first, ordinary_second,
        "fixture precondition: successive ordinary frames must carry distinct keys"
    );

    let (sender, mut subject) = connection_driver_in_state(
        ConnectionConfig::default(),
        Role::Client,
        InitialState::Open,
    );

    // The C6 frame is the FIRST thing this connection masks, so it must
    // carry exactly the key an ordinary first frame would have carried.
    let (_code, frame) = subject
        .compose_violation_close(
            &TypedProtocolFailure::java_invalid_data(1002),
            FailureOrigin::InboundDecode,
        )
        .expect("client composes a close frame");
    assert_eq!(
        [frame[2], frame[3], frame[4], frame[5]],
        ordinary_first,
        "REGRESSION: the C6 frame did not take the FIRST key of the connection's ordinary \
         masking sequence — it drew from a parallel derivation, or it burned a slot first"
    );

    // ...and exactly ONE slot is gone, so the next ordinary frame on the
    // SAME connection must carry the ordinary SECOND key.
    assert_eq!(
        next_ordinary_outbound_mask_key(&sender, &mut subject),
        ordinary_second,
        "REGRESSION: the outbound frame following the C6 close did not take the SECOND key of \
         the ordinary masking sequence — the reservation consumed the wrong number of slots"
    );
}
