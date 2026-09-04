//! E5b: the WIRE-LEVEL close-echo composition at the WebSocketImpl mirror.
//!
//! Fidelity authority (every site verified in the digest-pinned quarantined
//! Java-WebSocket 1.6.0 tree, `.quarantine/Java-WebSocket-da3cf2a777aed…`):
//!
//! 1. `FramedataImpl1.get(Opcode.CLOSING)` returns `new CloseFrame()`
//!    (framing/FramedataImpl1.java:241-242), whose constructor sets the
//!    payload to `[0x03,0xE8]` via `setReason("")` + `setCode(NORMAL)`
//!    (framing/CloseFrame.java:168-172).
//! 2. `CloseFrame.setPayload` (framing/CloseFrame.java:246-271) OVERRIDES the
//!    base method and never calls `super.setPayload`: it only assigns the
//!    `code`/`reason` FIELDS. So a received close frame OBJECT keeps the
//!    constructor payload while carrying the wire code/reason in its fields
//!    — quirk Q10, and the reason `ws_core` records `[0x03,0xE8]` for both
//!    the inbound record and its Draft-level echo.
//! 3. The full stack does NOT put that object back on the wire.
//!    `Draft_6455.processFrame` routes CLOSING to `processFrameClosing`
//!    (drafts/Draft_6455.java:896-897), which reads `cf.getCloseCode()` /
//!    `cf.getMessage()` (drafts/Draft_6455.java:1055-1060) and — the draft's
//!    handshake type being TWOWAY (drafts/Draft_6455.java:1111-1113) — calls
//!    `webSocketImpl.close(code, reason, true)` (drafts/Draft_6455.java:1067-1068).
//! 4. `WebSocketImpl.close(int,String,boolean)` builds its OWN frame:
//!    `new CloseFrame(); setReason(message); setCode(code); isValid();
//!    sendFrame(closeFrame);` (WebSocketImpl.java:482-486), and
//!    `CloseFrame.updatePayload` (framing/CloseFrame.java:294-302) composes
//!    the payload as the low two bytes of the code, big-endian, followed by
//!    the UTF-8 reason.
//!
//! So the shipped full-stack wire reply to an inbound close is
//! `code(2 BE) || reason`, composed by the SAME `WebSocketImpl.close` method
//! that a local close goes through — which `ws_core::connection::send_close`
//! already ports byte-for-byte.
//!
//! Why `ws_core` diverges here and MUST NOT be changed: the core's echo arm
//! is pinned to the java-oracle harness, which re-emits the RECEIVED frame
//! object (`java-oracle/src/main/java/OracleEngine.java:382`
//! `emitOutbound(List.of(frame), index, "echo_close")`). That observable is
//! LIVE-ORACLE-CONFIRMED at the core level (74/74) and ledgered
//! (delta-954132f2… constructor-payload-echo, delta-d509ac38…
//! one-byte-close-payload). The harness's echo composition is the harness's,
//! not `WebSocketImpl`'s — so the full-stack composition belongs HERE, in the
//! WebSocketImpl mirror, exactly like the US-015 automatic pong.
//!
//! Autobahn 7.3.2 (close frame with a 1-byte payload) is the case that
//! separates the two: `CloseFrame.setPayload` maps a 1-byte payload to
//! PROTOCOL_ERROR 1002 (framing/CloseFrame.java:252-253), so the full stack
//! replies 1002 while the Draft-level echo replies 1000 — `WRONG CODE` under
//! wstest.

use ws_core::config::ConnectionConfig;
use ws_core::{InitialState, ReadyState, Role};
use ws_driver::{
    CloseEchoPolicy, ConnectionDriver, DriverInput, DriverOutput, connection_driver_in_state,
    connection_driver_in_state_with_policies,
};

/// One owned poll output (the borrowed write suffix copied out so the next
/// poll can borrow the driver again).
enum Owned {
    Idle,
    Write(Vec<u8>),
    Other,
}

fn poll_owned(driver: &mut ConnectionDriver, input: DriverInput<'_>) -> Owned {
    match driver.poll(input).output {
        DriverOutput::Idle => Owned::Idle,
        DriverOutput::Write(suffix) => Owned::Write(suffix.to_vec()),
        _ => Owned::Other,
    }
}

/// Every completed wire frame a bounded fair drain accepted, in order.
fn drain_writes(driver: &mut ConnectionDriver) -> Vec<Vec<u8>> {
    let mut writes = Vec::new();
    let mut next = poll_owned(driver, DriverInput::Wake);
    for _ in 0..512 {
        match next {
            Owned::Write(bytes) => {
                let len = bytes.len();
                writes.push(bytes);
                next = poll_owned(driver, DriverInput::WriteProgress { bytes: len });
            }
            Owned::Other => next = poll_owned(driver, DriverInput::Wake),
            Owned::Idle => break,
        }
    }
    writes
}

fn feed(driver: &mut ConnectionDriver, chunk: &[u8]) {
    let result = driver.poll(DriverInput::Inbound(chunk));
    assert!(
        matches!(result.input, ws_driver::InputDisposition::Consumed { .. }),
        "test chunk must be consumed, got {:?}",
        result.input
    );
}

/// A masked (client-to-server) close frame with an all-zero mask key, so the
/// masked payload bytes equal the semantic payload — the exact shape wstest
/// puts on the wire for the 7.3.x family.
fn masked_close(payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![
        0x88,
        0x80 | u8::try_from(payload.len()).expect("short test payload"),
        0,
        0,
        0,
        0,
    ];
    frame.extend_from_slice(payload);
    frame
}

fn server_driver() -> (ws_core::CommandSender, ConnectionDriver) {
    connection_driver_in_state(
        ConnectionConfig::default(),
        Role::Server,
        InitialState::Open,
    )
}

#[test]
fn autobahn_7_3_2_one_byte_close_is_answered_with_1002_on_the_wire() {
    // The exact Autobahn 7.3.2 stimulus: a close frame whose payload is one
    // byte. `CloseFrame.setPayload` maps it to PROTOCOL_ERROR
    // (framing/CloseFrame.java:252-253), so `processFrameClosing` hands 1002
    // to `WebSocketImpl.close` (drafts/Draft_6455.java:1055-1068) and the
    // frame that method builds carries 1002 (WebSocketImpl.java:482-486;
    // framing/CloseFrame.java:294-302). wstest requires 1002 or a drop.
    let (_sender, mut driver) = server_driver();
    feed(&mut driver, &masked_close(&[0x03]));
    let writes = drain_writes(&mut driver);
    assert_eq!(writes.len(), 1, "exactly one echo frame: {writes:?}");
    assert_eq!(
        writes[0],
        vec![0x88, 0x02, 0x03, 0xEA],
        "the full-stack echo carries the RECEIVED close code 1002, not the \
         CloseFrame constructor payload 1000"
    );
    assert_eq!(driver.state(), ReadyState::Closing);
    let detail = driver.close_detail().expect("governing close");
    assert_eq!(detail.code, 1002, "the core's governing close is untouched");
}

#[test]
fn the_echo_mirrors_the_received_code_and_reason() {
    // `WebSocketImpl.close` composes code || reason for EVERY inbound close,
    // not just the malformed one: `processFrameClosing` passes
    // `cf.getMessage()` straight through (drafts/Draft_6455.java:1058-1060)
    // and `updatePayload` appends the UTF-8 reason
    // (framing/CloseFrame.java:294-302).
    let (_sender, mut driver) = server_driver();
    let mut payload = vec![0x03, 0xF0]; // 1008
    payload.extend_from_slice(b"why");
    feed(&mut driver, &masked_close(&payload));
    let writes = drain_writes(&mut driver);
    assert_eq!(writes.len(), 1, "exactly one echo frame: {writes:?}");
    let mut expected = vec![0x88, 0x05, 0x03, 0xF0];
    expected.extend_from_slice(b"why");
    assert_eq!(writes[0], expected);
}

#[test]
fn a_1000_close_with_no_reason_is_byte_identical_to_the_core_echo() {
    // The composition COINCIDES with the Draft-level constructor payload
    // whenever the received close is 1000 with an empty reason — which is
    // why the divergence stayed invisible until Autobahn 7.3.2.
    let (_sender, mut driver) = server_driver();
    feed(&mut driver, &masked_close(&[0x03, 0xE8]));
    let writes = drain_writes(&mut driver);
    assert_eq!(writes, vec![vec![0x88, 0x02, 0x03, 0xE8]]);
}

#[test]
fn the_draft_echo_policy_leaves_the_core_write_untouched() {
    // The opt-out keeps the Draft-level/oracle-harness composition
    // (OracleEngine.java:382) for callers that score against the core
    // observable rather than the shipped full stack.
    let (_sender, mut driver) = connection_driver_in_state_with_policies(
        ConnectionConfig::default(),
        Role::Server,
        InitialState::Open,
        ws_driver::AutoResponsePolicy::default(),
        CloseEchoPolicy::CoreDraftEcho,
    );
    feed(&mut driver, &masked_close(&[0x03]));
    let writes = drain_writes(&mut driver);
    assert_eq!(
        writes,
        vec![vec![0x88, 0x02, 0x03, 0xE8]],
        "the core's Q19/Q10 echo is preserved verbatim under the opt-out"
    );
}

#[test]
fn a_client_role_echo_keeps_the_cores_mask_key_and_masks_the_new_payload() {
    // Client-role frames MUST stay masked (RFC 6455 5.3). The recomposition
    // reuses the mask key the core already derived for this frame, so the
    // core's deterministic mask sequence (quirk Q28) is not disturbed.
    let (_sender, mut driver) = connection_driver_in_state(
        ConnectionConfig::default(),
        Role::Client,
        InitialState::Open,
    );
    // Server-to-client frames are unmasked.
    feed(&mut driver, &[0x88, 0x01, 0x03]);
    let writes = drain_writes(&mut driver);
    assert_eq!(writes.len(), 1, "exactly one echo frame: {writes:?}");
    let frame = &writes[0];
    assert_eq!(frame[0], 0x88, "close, FIN set");
    assert_eq!(frame[1], 0x82, "masked, 2-byte payload");
    let key = [frame[2], frame[3], frame[4], frame[5]];
    let unmasked = [frame[6] ^ key[0], frame[7] ^ key[1]];
    assert_eq!(unmasked, [0x03, 0xEA], "1002 under the core's own mask key");
}

#[test]
fn an_inbound_close_while_closing_still_writes_nothing() {
    // Q19's other arm: a close received while already CLOSING completes the
    // handshake with no echo at all (drafts/Draft_6455.java:1062-1064 ->
    // `closeConnection`), so there is nothing to recompose.
    let (sender, mut driver) = server_driver();
    sender
        .try_send(ws_core::LocalCommand::SendClose {
            code: 1000,
            reason: String::new(),
        })
        .expect("enqueue local close");
    let local = drain_writes(&mut driver);
    assert_eq!(local, vec![vec![0x88, 0x02, 0x03, 0xE8]], "the local close");
    feed(&mut driver, &masked_close(&[0x03]));
    assert!(
        drain_writes(&mut driver).is_empty(),
        "no echo once the local close already moved the state"
    );
    assert_eq!(driver.state(), ReadyState::Closed);
}
