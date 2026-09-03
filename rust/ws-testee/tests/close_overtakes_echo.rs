//! DIV-05 (behavior-delta ledger sequence 54): a Close that arrives in the
//! SAME transport read as the completion of a data frame must not cancel the
//! echo of that message.
//!
//! # What shipped Java does (PINNED SOURCE CITATION, not an executed run)
//!
//! Pinned tree `.quarantine/Java-WebSocket-da3cf2a777aed862f2f5b5cf060cae7969958667`
//! (archive sha256 f44e7647b4aee40819b51947cf0bb5f35a48293a202b77704c3c79e98ed13cb4,
//! `evidence/intake/source-pins.json` -> `java-websocket-source-archive`):
//!
//! * `WebSocketImpl.decodeFrames(ByteBuffer)` (WebSocketImpl.java:391-419)
//!   translates the WHOLE socket buffer into a `List<Framedata>` in one call
//!   (`frames = draft.translateFrame(socketBuffer)`, :394) and then walks it
//!   ONE FRAME AT A TIME — `for (Framedata f : frames) { draft.processFrame(this, f); }`
//!   (:395-398).
//! * `Draft_6455.processFrame` (drafts/Draft_6455.java:893-918) dispatches
//!   TEXT to `processFrameText` (:982-990), which calls
//!   `onWebsocketMessage(...)` **synchronously**, inside that loop iteration.
//!   An echoing listener therefore appends its echo to `outQueue`
//!   (`WebSocketImpl.send(String)` :640-646 -> `send(Collection)` :667-680)
//!   BEFORE the next iteration is reached.
//! * Only then does the CLOSE frame's iteration run:
//!   `processFrameClosing` (drafts/Draft_6455.java:1054-1073) calls
//!   `webSocketImpl.close(code, reason, true)` (:1068), which appends the
//!   close frame to the SAME `outQueue` at WebSocketImpl.java:481-487 and
//!   then calls `flushAndClose` (:494), whose `onWriteDemand` "ensures that
//!   all outgoing frames are flushed before closing the connection"
//!   (:594-595).
//! * `SocketChannelIOHelper.batch` (SocketChannelIOHelper.java:110-113) only
//!   closes the TCP connection once `ws.outQueue.isEmpty()`.
//!
//! So shipped Java's wire order for `[data frame][close frame]` in one read
//! is: **the echo, then the close echo, then the hang-up.** The synchronous
//! per-frame dispatch inside `decodeFrames`' loop is what guarantees it.
//!
//! # What the port did
//!
//! `ws_core::ConnectionCore::handle(TransportBytes)` applies EVERY frame in a
//! chunk in one call and queues the semantic events for the owner to drain
//! afterwards. When a close shares a chunk with a completed data frame the
//! core is already `Closing` by the time the adapter's echo policy sees the
//! message event, so the echo command it enqueues meets the core's
//! `requireOpen` gate (Q26) and is refused with a fatal `STATE_VIOLATION` —
//! the same gate as Java's own `send(Collection)` isOpen throw
//! (WebSocketImpl.java:667-670), reached only because the port's delivery is
//! asynchronous where Java's is synchronous. The message is dropped.
//!
//! # Where the fix lives, and why the fixture is here
//!
//! THE FIX IS IN `ws-driver` (`InboundFeedPolicy`, `FrameAlignedFeed`). An
//! earlier revision of this file argued for `ws-testee` and that argument is
//! withdrawn — it is wrong twice:
//!
//! * `ws-testee` is mechanically forbidden. The US-018 `adapter-linkage`
//!   architecture gate scans `rust/ws-testee/src` and refuses the three
//!   symbols a boundary-finder must name (`Draft6455`, `HeaderDecode`,
//!   `ws_core::framing`, `cmd/rustgatectl/adapter_linkage.go:48-65`). Seeding
//!   them there reproduces three `ADAPTER_PROTOCOL_SURFACE` findings and
//!   `exit 1`.
//! * `ws-driver` is NOT on the corpus differential path by default. The
//!   objection was that `ws-oracle-harness/src/core_adapter.rs` runs through
//!   this crate — true, but through `connection_driver_in_state_with_policies`,
//!   which keeps `InboundFeedPolicy::default()` = `WholeChunk`, the oracle
//!   observable the public corpus scores as `input_chunk {bytes}`. Only
//!   `connection_driver`, the fresh-connection full-stack constructor these
//!   fixtures reach, opts into `OneFramePerTurn`. Measured: the release oracle
//!   harness built from this branch and from mainline produces byte-identical
//!   transcripts on all 74 public and all 49 handshake cases.
//!
//! `ws-core` remains excluded, for the reason first given: chunk-atomic frame
//! processing IS its pinned oracle behaviour and its `input_chunk {bytes}`
//! records are scored by `corpora/public/scenarios.jsonl`.
//!
//! The FIXTURE is here because only this crate owns a real socket, and the
//! divergence is about what a peer receives.

use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use ws_core::ConnectionConfig;
use ws_testee::io_loop::{EventPolicy, drive_connection, drive_until_open, empty_report};
use ws_testee::{IoBounds, ServerFixture, run_server_once};

/// Every wait in this file is a WALL-CLOCK deadline, never an iteration
/// count (`make -C rust fixture-guard`; findings F002/F004/F005).
const DEADLINE: Duration = Duration::from_secs(20);

/// The mask key the raw client peers here use.
const TEST_MASK: [u8; 4] = [0x11, 0x22, 0x33, 0x44];

/// A masked client->server frame.
fn masked(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = header(opcode, payload.len(), true);
    for (index, byte) in payload.iter().enumerate() {
        frame.push(byte ^ TEST_MASK[index % 4]);
    }
    frame
}

/// An unmasked server->client frame.
fn unmasked(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = header(opcode, payload.len(), false);
    frame.extend_from_slice(payload);
    frame
}

fn header(opcode: u8, len: usize, mask: bool) -> Vec<u8> {
    let mut frame = vec![0x80 | opcode];
    let flag = if mask { 0x80 } else { 0x00 };
    if len < 126 {
        #[allow(clippy::cast_possible_truncation)]
        frame.push(flag | len as u8);
    } else if len <= 0xFFFF {
        frame.push(flag | 126);
        #[allow(clippy::cast_possible_truncation)]
        frame.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        frame.push(flag | 127);
        frame.extend_from_slice(&(len as u64).to_be_bytes());
    }
    if mask {
        frame.extend_from_slice(&TEST_MASK);
    }
    frame
}

/// One decoded frame off the wire: `(opcode, payload)`. The subject is never
/// a masking peer toward these tests' raw peers on the paths exercised here,
/// so this reader only understands unmasked frames and says so loudly.
fn split_frames(raw: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut frames = Vec::new();
    let mut at = 0usize;
    while at + 2 <= raw.len() {
        let opcode = raw[at] & 0x0F;
        let masked_bit = raw[at + 1] & 0x80 != 0;
        assert!(
            !masked_bit,
            "the subject masked a frame these tests decode raw"
        );
        let marker = usize::from(raw[at + 1] & 0x7F);
        let (len, head) = if marker < 126 {
            (marker, 2usize)
        } else if marker == 126 {
            if at + 4 > raw.len() {
                break;
            }
            (
                usize::from(u16::from_be_bytes([raw[at + 2], raw[at + 3]])),
                4usize,
            )
        } else {
            if at + 10 > raw.len() {
                break;
            }
            let mut wide = [0u8; 8];
            wide.copy_from_slice(&raw[at + 2..at + 10]);
            #[allow(clippy::cast_possible_truncation)]
            (u64::from_be_bytes(wide) as usize, 10usize)
        };
        if at + head + len > raw.len() {
            break;
        }
        frames.push((opcode, raw[at + head..at + head + len].to_vec()));
        at += head + len;
    }
    frames
}

/// Read the HTTP head off `peer`, bounded by a wall-clock deadline.
fn read_head(peer: &mut TcpStream, budget: Duration) -> Option<String> {
    let deadline = Instant::now() + budget;
    let mut received: Vec<u8> = Vec::new();
    let mut buffer = [0u8; 1024];
    while Instant::now() < deadline {
        match peer.read(&mut buffer) {
            Ok(0) => return None,
            Ok(n) => received.extend_from_slice(&buffer[..n]),
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(_) => return None,
        }
        if let Some(end) = received.windows(4).position(|w| w == b"\r\n\r\n") {
            return String::from_utf8(received[..end + 4].to_vec()).ok();
        }
    }
    None
}

/// Drain `peer` until the subject hangs up or the wall-clock budget expires.
fn drain(peer: &mut TcpStream, budget: Duration) -> Vec<u8> {
    let deadline = Instant::now() + budget;
    let mut received = Vec::new();
    let mut buffer = [0u8; 8192];
    while Instant::now() < deadline {
        match peer.read(&mut buffer) {
            Ok(0) => return received,
            Ok(n) => received.extend_from_slice(&buffer[..n]),
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(_) => return received,
        }
    }
    received
}

/// Drain `peer` until a CLOSE frame has arrived whole, the peer hangs up, or
/// the wall-clock budget expires.
fn drain_until_close(peer: &mut TcpStream, budget: Duration) -> Vec<u8> {
    let deadline = Instant::now() + budget;
    let mut received = Vec::new();
    let mut buffer = [0u8; 8192];
    while Instant::now() < deadline {
        match peer.read(&mut buffer) {
            Ok(0) => return received,
            Ok(n) => received.extend_from_slice(&buffer[..n]),
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(_) => return received,
        }
        if split_frames_masked(&received)
            .iter()
            .any(|(opcode, _)| *opcode == 0x8)
        {
            return received;
        }
    }
    received
}

/// The Autobahn fixture's ceiling-tier limits (`ws-testee/src/main.rs`
/// `autobahn_serve_config`), so the 256 KiB case runs the configuration the
/// recorded run used.
fn autobahn_config() -> ConnectionConfig {
    ConnectionConfig::builder()
        .max_frame_payload_bytes(1_048_576)
        .max_message_bytes(1_048_576)
        .max_buffered_bytes(1_048_576)
        .max_input_bytes(1_048_576)
        .max_frames(4096)
        .max_actions(1024)
        .event_queue_capacity(16_384)
        .command_queue_capacity(4096)
        .write_queue_capacity(4096)
        .build()
        .expect("the ceiling-tier limits are valid by construction")
}

fn prompt_bounds() -> IoBounds {
    IoBounds {
        read_timeout: Duration::from_millis(1),
        max_polls: 2_000_000,
        ..IoBounds::default()
    }
}

const UPGRADE_REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: example.com\r\n\
    Upgrade: websocket\r\nConnection: Upgrade\r\n\
    Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";

/// Runs one echo SERVER under test, hands it `burst` in a single socket
/// write, and returns every byte it put on the wire afterwards.
fn server_answer_to(burst: &[u8], config: ConnectionConfig) -> Vec<u8> {
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let address = listener.local_addr().expect("bound address");
    let subject = thread::spawn(move || {
        let fixture = ServerFixture {
            config,
            bounds: prompt_bounds(),
        };
        run_server_once(&listener, &fixture)
    });

    let mut peer = TcpStream::connect(address).expect("connect to the server under test");
    peer.set_read_timeout(Some(Duration::from_millis(25)))
        .expect("peer read timeout");
    peer.write_all(UPGRADE_REQUEST).expect("upgrade request");
    peer.flush().expect("flush the upgrade request");
    let head = read_head(&mut peer, DEADLINE).expect("the 101 head must arrive in the budget");
    assert!(head.starts_with("HTTP/1.1 101"), "handshake head: {head:?}");

    // ONE write, so the data frame and the close frame reach the subject's
    // transport together — the shape Autobahn 7.1.6 puts on the wire.
    peer.write_all(burst).expect("write the burst");
    peer.flush().expect("flush the burst");

    let received = drain(&mut peer, DEADLINE);
    let _ = subject
        .join()
        .expect("subject thread")
        .expect("subject setup");
    received
}

/// The echo policy the Autobahn server fixture runs (`ws-testee/src/server.rs`
/// `EchoPolicy`), rebuilt here so the CLIENT role can be driven with it too —
/// Autobahn's fuzzingserver leg drives the subject as an echoing client.
struct Echo;

impl EventPolicy for Echo {
    fn on_event(&mut self, event: &ws_core::SemanticEvent, sender: &ws_core::CommandSender) {
        match &event.kind {
            ws_core::SemanticEventKind::Text { text } => {
                let _ = sender.try_send(ws_core::LocalCommand::SendText { text: text.clone() });
            }
            ws_core::SemanticEventKind::Binary { data } => {
                let _ = sender.try_send(ws_core::LocalCommand::SendBinary { data: data.clone() });
            }
            _ => {}
        }
    }
}

/// THE DIVERGENCE, at its smallest: a five-byte text message and a close in
/// ONE read. The 256 KiB the ledger record names plays no part — see the
/// draft correction under `drafts/ledger-proposals/`.
#[test]
fn a_close_sharing_one_read_with_a_completed_text_frame_does_not_cancel_the_echo() {
    let mut burst = masked(0x1, b"hello");
    burst.extend_from_slice(&masked(0x8, &[0x03, 0xE8, b'd', b'o', b'n', b'e']));

    let received = server_answer_to(&burst, ConnectionConfig::default());
    let frames = split_frames(&received);
    let shape: Vec<(u8, usize)> = frames.iter().map(|(op, p)| (*op, p.len())).collect();

    assert_eq!(
        shape,
        vec![(0x1, 5), (0x8, 6)],
        "DIV-05: a close arriving in the same transport read as a completed \
         text frame must not cancel the echo. Shipped Java dispatches frame \
         by frame inside decodeFrames' loop (WebSocketImpl.java:394-398) with \
         a SYNCHRONOUS onWebsocketMessage (Draft_6455.java:982-990), so the \
         echo is in outQueue before processFrameClosing (Draft_6455.java:1054-1073) \
         appends the close, and flushAndClose flushes both \
         (WebSocketImpl.java:494, :594-595). Expected the text echo then the \
         close echo; the subject wrote {shape:?} (raw {received:02X?})."
    );
    assert_eq!(
        frames[0].1, b"hello",
        "the echo must carry the message back"
    );
}

/// The recorded Autobahn 7.1.6 wire shape, verbatim: a 256 KiB text message,
/// `Hello World!`, a close and a ping, written back to back. Java's recorded
/// server leg returned both echoes and the close
/// (`rxFrameStats {"1":2,"8":1}`); the port returned nothing
/// (`rxFrameStats {}`).
#[test]
fn the_autobahn_7_1_6_burst_returns_both_echoes_before_the_close() {
    let big: Vec<u8> = b"BAsd7&jh23"
        .iter()
        .copied()
        .cycle()
        .take(256 * 1024)
        .collect();
    let mut burst = masked(0x1, &big);
    burst.extend_from_slice(&masked(0x1, b"Hello World!"));
    burst.extend_from_slice(&masked(0x8, &[0x03, 0xE8]));
    burst.extend_from_slice(&masked(0x9, b""));

    let received = server_answer_to(&burst, autobahn_config());
    let frames = split_frames(&received);
    let shape: Vec<(u8, usize)> = frames.iter().map(|(op, p)| (*op, p.len())).collect();

    assert_eq!(
        shape,
        vec![(0x1, 256 * 1024), (0x1, 12), (0x8, 2)],
        "DIV-05 on Autobahn 7.1.6 (server role). The recorded native run has \
         shipped Java answering with rxFrameStats {{\"1\":2,\"8\":1}} and the \
         port with {{}} — the suite's own verdict on the port was \"Close was \
         processed before text message could be returned.\". Expected both \
         echoes and then the close; the subject wrote {shape:?}."
    );
    assert_eq!(frames[0].1, big, "the 256 KiB echo must come back verbatim");
}

/// The client half of the divergence (the ledger record counts one client
/// case and one server case). Autobahn's fuzzingserver leg drives the subject
/// as an ECHOING CLIENT, so the same burst is delivered to a client-role
/// endpoint running the same echo policy.
///
/// The burst is written only after the subject reports its handshake
/// consumed, over an `mpsc` rendezvous rather than a sleep. That is not
/// timing convenience: it keeps THIS fixture on THIS divergence. A burst that
/// coalesces with the 101 into the subject's handshake-phase read exposes a
/// DIFFERENT and unfixed defect — `drive_until_open` hands the whole read to
/// the core, whose `finish_handshake_open` parks the trailing frame bytes in
/// `pending` (ws-core/src/connection.rs:1017-1034), and nothing ever decodes
/// them because the core only decodes on a bytes input. The message is then
/// lost outright (observed: `texts=0 close=1006:transport`), which is a
/// stronger failure than the ordering this fixture is about. Shipped Java
/// handles that case at WebSocketImpl.java:232-240 — after `decodeHandshake`
/// it runs `decodeFrames` on whichever buffer still has remaining bytes. See
/// `drafts/self-review/div05-close-overtakes-echo.md`.
#[test]
fn a_client_role_endpoint_echoes_before_answering_a_close_in_the_same_read() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let address = listener.local_addr().expect("bound address");
    let (handshake_done, wait_for_handshake) = std::sync::mpsc::channel::<()>();

    // The raw server peer completes a real handshake through ws_core and then
    // hands the subject the burst in ONE write.
    let peer = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let (_sender, mut driver) =
            ws_driver::connection_driver(ConnectionConfig::default(), ws_core::Role::Server);
        let mut report = empty_report();
        assert!(
            drive_until_open(&mut driver, &mut stream, &prompt_bounds(), &mut report),
            "the peer's server handshake must complete"
        );
        // Flush the 101 the peer's own core composed.
        let deadline = Instant::now() + DEADLINE;
        while Instant::now() < deadline {
            match driver.poll(ws_driver::DriverInput::Wake).output {
                ws_driver::DriverOutput::Write(suffix) => {
                    let pending = suffix.to_vec();
                    let written = stream.write(&pending).expect("flush the 101");
                    driver.poll(ws_driver::DriverInput::WriteProgress { bytes: written });
                }
                ws_driver::DriverOutput::Idle => break,
                _ => {}
            }
        }
        wait_for_handshake
            .recv_timeout(DEADLINE)
            .expect("the subject must report its handshake consumed within the budget");
        let mut burst = unmasked(0x1, b"hello");
        burst.extend_from_slice(&unmasked(0x8, &[0x03, 0xE8, b'd', b'o', b'n', b'e']));
        stream.write_all(&burst).expect("write the burst");
        stream.flush().expect("flush the burst");
        stream
            .set_read_timeout(Some(Duration::from_millis(25)))
            .expect("peer read timeout");
        // A CLIENT subject never hangs up (shipped Java's client has no
        // counterpart to SocketChannelIOHelper.batch's server-only close), so
        // stop at its close frame rather than at an EOF that will not come.
        drain_until_close(&mut stream, DEADLINE)
    });

    let mut stream = TcpStream::connect(address).expect("connect");
    let (sender, mut driver) =
        ws_driver::connection_driver(ConnectionConfig::default(), ws_core::Role::Client);
    driver
        .begin_client_handshake("/chat", "localhost")
        .expect("client handshake start");
    let mut report = empty_report();
    let bounds = prompt_bounds();
    assert!(
        drive_until_open(&mut driver, &mut stream, &bounds, &mut report),
        "the subject client handshake must complete"
    );
    handshake_done.send(()).expect("the peer is still waiting");
    let mut policy = Echo;
    drive_connection(
        &mut driver,
        &sender,
        &mut stream,
        &bounds,
        ws_core::Role::Client,
        &mut policy,
        &mut report,
    );

    // The subject client does not close the TCP connection (shipped Java's
    // client has no counterpart to SocketChannelIOHelper.batch's server-only
    // hang-up), so the peer only sees EOF once this side lets the socket go.
    drop(stream);
    let received = peer.join().expect("peer thread");
    let frames = split_frames_masked(&received);
    let shape: Vec<(u8, usize)> = frames.iter().map(|(op, p)| (*op, p.len())).collect();
    assert_eq!(
        shape,
        vec![(0x1, 5), (0x8, 6)],
        "DIV-05, client role. Shipped Java's per-frame dispatch is role-blind \
         — decodeFrames (WebSocketImpl.java:391-419) is the same method on \
         both roles — so a client that echoes must also return the message \
         before answering the close. The subject wrote {shape:?}."
    );
    assert_eq!(
        frames[0].1, b"hello",
        "the client echo must carry the message"
    );
}

/// A frame with an explicit FIN bit, masked client->server. Only the 5.15
/// shape below needs FIN=false, so [`masked`] keeps its always-FIN signature.
fn masked_fin(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = header(opcode, payload.len(), true);
    if !fin {
        frame[0] &= 0x7F;
    }
    for (index, byte) in payload.iter().enumerate() {
        frame.push(byte ^ TEST_MASK[index % 4]);
    }
    frame
}

/// **A SIDE EFFECT ON ANOTHER LEDGER RECORD, PINNED SO IT IS NOT SILENT.**
///
/// This test is NOT part of DIV-05. It pins a behaviour change the DIV-05 fix
/// causes on the subject of **behavior-delta ledger sequence 34**
/// (`delta-71c02bf6294792a4689c89bbd4c9b859c5667215e311dd6059013e14b7809ee8`,
/// Autobahn 5.15), whose disposition is **`unresolved`** — the owner has not
/// decided it.
///
/// Sequence 34 describes the port's behaviour as: *"the Rust adapter's typed
/// failure lands before the completed message's Text event is delivered, so
/// the echo is never enqueued at all"*, against Java, which *"translates the
/// whole chop first, then dispatches frame by frame, so the echo is ENQUEUED
/// during the second fragment's dispatch and the failure path's flushAndClose
/// write demand flushes it"*. The DIV-05 fix installs exactly that Java
/// dispatch order in the full-stack path, so it moves this case too.
///
/// Measured, same wire, one chop, `ServerFixture` echo policy:
///
/// | build | peer received | `texts` delivered |
/// | --- | --- | --- |
/// | mainline 131b7b8 | `[(0x8, 2)]` — close 1002 only | 0 |
/// | this branch | `[(0x1, 18), (0x8, 2)]` — echo then close | 1 |
///
/// The branch's answer is shipped Java's. It is ALSO the RFC-*less*-strict
/// answer: RFC 6455 7.1.7 permits failing immediately on the violation, which
/// is what the port used to do, and that is why sequence 34 is `unresolved`
/// rather than a defect. **Nothing here decides that record.** This test
/// exists so the change cannot happen silently, and
/// `drafts/ledger-proposals/div05-close-overtakes-echo-description-correction.json`
/// puts it in front of the owner.
#[test]
fn the_autobahn_5_15_chop_now_returns_the_completed_echo_before_the_violation_close() {
    // A complete 2-fragment text message, then a continuation with FIN=false
    // where there is nothing to continue (the violation), then an
    // unfragmented text — all in one chop.
    let mut burst = masked_fin(false, 0x1, b"fragment1");
    burst.extend_from_slice(&masked_fin(true, 0x0, b"fragment2"));
    burst.extend_from_slice(&masked_fin(false, 0x0, b"fragment3"));
    burst.extend_from_slice(&masked_fin(true, 0x1, b"fragment4"));

    let received = server_answer_to(&burst, ConnectionConfig::default());
    let frames = split_frames(&received);
    let shape: Vec<(u8, usize)> = frames.iter().map(|(op, p)| (*op, p.len())).collect();

    assert_eq!(
        shape,
        vec![(0x1, 18), (0x8, 2)],
        "ledger sequence 34 (Autobahn 5.15, disposition `unresolved`) is MOVED \
         by the DIV-05 inbound feed policy: the completed message's echo now \
         reaches the wire before the violation close, which is shipped Java's \
         order (WebSocketImpl.java:394-398) and was NOT the port's. Mainline \
         131b7b8 writes [(8, 2)]. The subject wrote {shape:?}."
    );
    assert_eq!(
        frames[0].1, b"fragment1fragment2",
        "the echo must be the reassembled message"
    );
    assert_eq!(
        frames[1].1,
        vec![0x03, 0xEA],
        "the violation close must still be 1002"
    );
}

/// Client->server frames are masked; unmask before comparing.
fn split_frames_masked(raw: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut frames = Vec::new();
    let mut at = 0usize;
    while at + 2 <= raw.len() {
        let opcode = raw[at] & 0x0F;
        let is_masked = raw[at + 1] & 0x80 != 0;
        let marker = usize::from(raw[at + 1] & 0x7F);
        let (len, mut head) = if marker < 126 {
            (marker, 2usize)
        } else if marker == 126 {
            if at + 4 > raw.len() {
                break;
            }
            (
                usize::from(u16::from_be_bytes([raw[at + 2], raw[at + 3]])),
                4usize,
            )
        } else {
            if at + 10 > raw.len() {
                break;
            }
            let mut wide = [0u8; 8];
            wide.copy_from_slice(&raw[at + 2..at + 10]);
            #[allow(clippy::cast_possible_truncation)]
            (u64::from_be_bytes(wide) as usize, 10usize)
        };
        let key = if is_masked {
            if at + head + 4 > raw.len() {
                break;
            }
            let mut key = [0u8; 4];
            key.copy_from_slice(&raw[at + head..at + head + 4]);
            head += 4;
            Some(key)
        } else {
            None
        };
        if at + head + len > raw.len() {
            break;
        }
        let mut payload = raw[at + head..at + head + len].to_vec();
        if let Some(key) = key {
            for (index, byte) in payload.iter_mut().enumerate() {
                *byte ^= key[index % 4];
            }
        }
        frames.push((opcode, payload));
        at += head + len;
    }
    frames
}
