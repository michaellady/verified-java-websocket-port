//! US-015 AC1 at the driver seam: the CONFIGURABLE automatic ping-response
//! policy.
//!
//! Fidelity authority: the sans-io core is Q18-faithful and never
//! auto-pongs (pinned by the public corpus and the live-oracle
//! confirmation). Shipped Java-WebSocket 1.6.0 DOES auto-pong — one layer
//! ABOVE the Draft: `Draft_6455.processFrame` dispatches an inbound PING to
//! the listener (drafts/Draft_6455.java:898-899), and the default listener
//! `WebSocketAdapter.onWebsocketPing` replies with
//! `conn.sendFrame(new PongFrame((PingFrame) f))`
//! (WebSocketAdapter.java:84-86), where the `PongFrame(PingFrame)`
//! constructor copies the ping's payload byte-for-byte
//! (framing/PongFrame.java:47-50). The US-018 cross-peer exam proved the
//! behavior live (rust-client ping -> Java auto-pong,
//! protected/us018-closure/crosspeer/). The driver is the WebSocketImpl
//! pump's port-side home, so the automatic reply lives here, injected
//! through the ordinary command seam (`LocalCommand::SendPong`), and the
//! reply's send-time state gate is Java's own `send(Collection)` isOpen
//! throw (WebSocketImpl.java:667-670): a reply whose connection has left
//! Open produces no wire write, exactly as Java's sendFrame would.

use ws_core::config::ConnectionConfig;
use ws_core::{InitialState, ReadyState, Role, SemanticEventKind};
use ws_driver::{
    AutoResponsePolicy, ConnectionDriver, DriverInput, DriverOutput, connection_driver_in_state,
    connection_driver_in_state_with_policy,
};

/// Everything one bounded fair drain observed, in surfacing order.
#[derive(Debug, Default)]
struct Drained {
    /// Completed wire frames in acceptance order (each offered write fully
    /// accepted).
    writes: Vec<Vec<u8>>,
    /// Drained semantic event kinds in order.
    events: Vec<SemanticEventKind>,
    /// Interleaved order tokens: `W<index>` / `E<index>` for cross-stream
    /// ordering assertions.
    order: Vec<String>,
    terminals: u64,
    failures: u64,
}

/// One owned poll output (the borrowed write suffix copied out so the next
/// poll can borrow the driver again).
enum Owned {
    Idle,
    Write(Vec<u8>),
    Event(ws_core::SemanticEvent),
    Failure,
    Terminal,
}

fn poll_owned(driver: &mut ConnectionDriver, input: DriverInput<'_>) -> Owned {
    match driver.poll(input).output {
        DriverOutput::Idle => Owned::Idle,
        DriverOutput::Write(suffix) => Owned::Write(suffix.to_vec()),
        DriverOutput::Event(event) => Owned::Event(event),
        DriverOutput::Failure(_) => Owned::Failure,
        DriverOutput::Terminal(_) => Owned::Terminal,
    }
}

fn drain(driver: &mut ConnectionDriver) -> Drained {
    let mut out = Drained::default();
    let mut next = poll_owned(driver, DriverInput::Wake);
    for _ in 0..512 {
        match next {
            Owned::Write(bytes) => {
                let len = bytes.len();
                out.order.push(format!("W{}", out.writes.len()));
                out.writes.push(bytes);
                // The WriteProgress result may itself surface the next
                // output; absorb it instead of dropping it.
                next = poll_owned(driver, DriverInput::WriteProgress { bytes: len });
            }
            Owned::Event(event) => {
                out.order.push(format!("E{}", out.events.len()));
                out.events.push(event.kind);
                next = poll_owned(driver, DriverInput::Wake);
            }
            Owned::Failure => {
                out.failures += 1;
                next = poll_owned(driver, DriverInput::Wake);
            }
            Owned::Terminal => {
                out.terminals += 1;
                next = poll_owned(driver, DriverInput::Wake);
            }
            Owned::Idle => break,
        }
    }
    out
}

fn feed(driver: &mut ConnectionDriver, chunk: &[u8]) {
    let result = driver.poll(DriverInput::Inbound(chunk));
    assert!(
        matches!(result.input, ws_driver::InputDisposition::Consumed { .. }),
        "test chunk must be consumed, got {:?}",
        result.input
    );
}

/// A masked (client-to-server) control frame with an all-zero mask key, so
/// the masked payload bytes equal the semantic payload.
fn masked_control(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![
        0x80 | opcode,
        0x80 | u8::try_from(payload.len()).expect("short test payload"),
        0,
        0,
        0,
        0,
    ];
    frame.extend_from_slice(payload);
    frame
}

fn pong_frames(drained: &Drained) -> Vec<&Vec<u8>> {
    drained
        .writes
        .iter()
        .filter(|frame| frame.first().is_some_and(|byte| byte & 0x0F == 0x0A))
        .collect()
}

#[test]
fn default_policy_answers_an_inbound_ping_with_a_byte_identical_pong() {
    let (_sender, mut driver) = connection_driver_in_state(
        ConnectionConfig::default(),
        Role::Server,
        InitialState::Open,
    );
    feed(&mut driver, &masked_control(0x09, &[0x01, 0x02, 0x03]));
    let drained = drain(&mut driver);
    // AC1: the Ping semantic event AND a pong write with byte-identical
    // payload.
    let ping_index = drained
        .events
        .iter()
        .position(|kind| matches!(kind, SemanticEventKind::Ping { data } if data == &[1, 2, 3]))
        .expect("the Ping semantic event is delivered");
    let pongs = pong_frames(&drained);
    assert_eq!(pongs.len(), 1, "exactly one automatic pong");
    assert_eq!(
        pongs[0].as_slice(),
        &[0x8A, 0x03, 0x01, 0x02, 0x03],
        "server pong: fin, unmasked, the ping's payload byte-identically \
         (PongFrame(PingFrame) payload copy)"
    );
    // The reply travels the ordinary command seam, so its outbound frame
    // record and cause event exist too.
    assert!(drained.events.iter().any(|kind| matches!(
        kind,
        SemanticEventKind::OutboundCause {
            cause: ws_core::event::OutboundCause::SendPong,
            ..
        }
    )));
    // Ordering: the Ping event surfaces before the pong write reaches the
    // wire (the reply is injected when the ping is delivered, as Java's
    // listener dispatch does).
    let pong_write_index = drained
        .writes
        .iter()
        .position(|frame| frame.first().is_some_and(|byte| byte & 0x0F == 0x0A))
        .expect("pong write present");
    let ping_token = format!("E{ping_index}");
    let pong_token = format!("W{pong_write_index}");
    let ping_at = drained.order.iter().position(|t| *t == ping_token).unwrap();
    let pong_at = drained.order.iter().position(|t| *t == pong_token).unwrap();
    assert!(
        ping_at < pong_at,
        "Ping event before the pong write: {:?}",
        drained.order
    );
    assert_eq!(drained.failures, 0);
}

#[test]
fn inbound_pong_emits_one_event_and_no_automatic_write() {
    // AC1 second clause: inbound pong -> one Pong event, NO automatic data
    // write (nothing in Java replies to a pong; onWebsocketPong is a no-op,
    // WebSocketAdapter.java:93-95).
    let (_sender, mut driver) = connection_driver_in_state(
        ConnectionConfig::default(),
        Role::Server,
        InitialState::Open,
    );
    feed(&mut driver, &masked_control(0x0A, &[0x09, 0x09]));
    let drained = drain(&mut driver);
    let pong_events = drained
        .events
        .iter()
        .filter(|kind| matches!(kind, SemanticEventKind::Pong { data } if data == &[9, 9]))
        .count();
    assert_eq!(pong_events, 1, "exactly one Pong event");
    assert!(drained.writes.is_empty(), "no automatic write of any kind");
    assert_eq!(drained.failures, 0);
}

#[test]
fn disabled_policy_never_writes_an_automatic_reply() {
    // The configurable side of AC1: a policy that suppresses the automatic
    // response (a custom onWebsocketPing override in Java vocabulary).
    let (_sender, mut driver) = connection_driver_in_state_with_policy(
        ConnectionConfig::default(),
        Role::Server,
        InitialState::Open,
        AutoResponsePolicy::Disabled,
    );
    feed(&mut driver, &masked_control(0x09, &[0x42]));
    let drained = drain(&mut driver);
    assert!(
        drained
            .events
            .iter()
            .any(|kind| matches!(kind, SemanticEventKind::Ping { data } if data == &[0x42])),
        "the Ping event still delivers"
    );
    assert!(
        drained.writes.is_empty(),
        "no automatic pong under Disabled"
    );
}

#[test]
fn client_role_masks_the_automatic_pong() {
    let (_sender, mut driver) = connection_driver_in_state(
        ConnectionConfig::default(),
        Role::Client,
        InitialState::Open,
    );
    // Server-to-client pings arrive unmasked.
    feed(&mut driver, &[0x89, 0x02, 0x05, 0x06]);
    let drained = drain(&mut driver);
    let pongs = pong_frames(&drained);
    assert_eq!(pongs.len(), 1);
    let frame = pongs[0];
    assert_eq!(frame[0], 0x8A);
    assert_eq!(frame[1], 0x80 | 0x02, "client pong is masked");
    assert_eq!(frame.len(), 8, "2 header + 4 mask key + 2 payload");
    let mask = [frame[2], frame[3], frame[4], frame[5]];
    let payload: Vec<u8> = frame[6..]
        .iter()
        .zip(mask.iter().cycle())
        .map(|(byte, key)| byte ^ key)
        .collect();
    assert_eq!(
        payload,
        vec![0x05, 0x06],
        "byte-identical payload under the mask"
    );
}

#[test]
fn every_ping_in_a_chunk_gets_its_own_pong_in_order() {
    let (_sender, mut driver) = connection_driver_in_state(
        ConnectionConfig::default(),
        Role::Server,
        InitialState::Open,
    );
    let mut chunk = masked_control(0x09, &[0xAA]);
    chunk.extend_from_slice(&masked_control(0x09, &[0xBB]));
    feed(&mut driver, &chunk);
    let drained = drain(&mut driver);
    let pongs = pong_frames(&drained);
    assert_eq!(pongs.len(), 2, "one pong per ping");
    assert_eq!(pongs[0].as_slice(), &[0x8A, 0x01, 0xAA]);
    assert_eq!(pongs[1].as_slice(), &[0x8A, 0x01, 0xBB]);
    assert_eq!(drained.failures, 0);
}

#[test]
fn a_close_that_already_moved_the_state_supersedes_the_reply() {
    // One chunk: ping then close. By the time the Ping event is delivered
    // the core is already Closing, and Java's own reply path at that state
    // throws WebsocketNotConnectedException with no wire write
    // (WebSocketImpl.java:667-670) — so the driver sends nothing, surfaces
    // no failure, and the close lifecycle proceeds untouched.
    let (_sender, mut driver) = connection_driver_in_state(
        ConnectionConfig::default(),
        Role::Server,
        InitialState::Open,
    );
    let mut chunk = masked_control(0x09, &[0x77]);
    chunk.extend_from_slice(&[0x88, 0x82, 0, 0, 0, 0, 0x03, 0xE8]);
    feed(&mut driver, &chunk);
    let drained = drain(&mut driver);
    assert!(
        pong_frames(&drained).is_empty(),
        "no pong once the connection left Open: {:?}",
        drained.writes
    );
    assert_eq!(drained.writes.len(), 1, "exactly the close echo");
    assert_eq!(drained.writes[0][0], 0x88, "the Q19 close echo");
    assert_eq!(drained.failures, 0, "the dropped reply is not a failure");
    assert_eq!(driver.state(), ReadyState::Closing);
}

#[test]
fn eof_landing_before_the_ping_delivers_drops_the_reply_and_converges() {
    // EOF latches and takes the first quiescent turn (the pinned US-017
    // driver contract), so a ping whose event has not yet drained loses its
    // reply — within Java's own envelope: closeConnection closes the
    // channel without flushing the outQueue, so an immediate EOF can drop
    // the queued pong there too. The connection must still converge to the
    // exactly-once terminal with the Q20 1006 close.
    let (_sender, mut driver) = connection_driver_in_state(
        ConnectionConfig::default(),
        Role::Server,
        InitialState::Open,
    );
    feed(&mut driver, &masked_control(0x09, &[0x55]));
    let _ = driver.poll(DriverInput::TransportEof);
    let drained = drain(&mut driver);
    assert!(pong_frames(&drained).is_empty(), "the reply is dropped");
    assert_eq!(drained.failures, 0);
    assert_eq!(drained.terminals, 1, "exactly-once terminal");
    assert_eq!(driver.state(), ReadyState::Closed);
    let close = driver.close_detail().expect("governing close");
    assert_eq!(close.code, 1006, "Q20 transport close");
}
