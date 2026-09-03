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
//! # Why this file, and not `ws-core` or `ws-driver`
//!
//! `ws-core` cannot discriminate: chunk-atomic frame processing IS its pinned
//! oracle behaviour, and its `input_chunk {bytes}` records are scored by the
//! public corpus (`corpora/public/scenarios.jsonl`), so splitting a chunk
//! there would move corpus bytes. `ws-driver` cannot discriminate either: it
//! is the seam the corpus differential harness runs through
//! (`ws-oracle-harness/src/core_adapter.rs`), so the same objection applies.
//! The decision that actually differs from Java is HOW MUCH INPUT IS APPLIED
//! PER TURN, which is a transport concern owned here — and this crate is
//! structurally invisible to the corpus (`ws-oracle-harness` declares only
//! `ws-core` and `ws-driver`), which is the same layering the C6 owner
//! decision `us017-c6-layer-split-owner-decision-2026-08-28.json` already
//! established for shipped-library fidelity.

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
        assert!(!masked_bit, "the subject masked a frame these tests decode raw");
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
    let _ = subject.join().expect("subject thread").expect("subject setup");
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
    assert_eq!(frames[0].1, b"hello", "the echo must carry the message back");
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
#[test]
fn a_client_role_endpoint_echoes_before_answering_a_close_in_the_same_read() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let address = listener.local_addr().expect("bound address");

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
        let mut burst = unmasked(0x1, b"hello");
        burst.extend_from_slice(&unmasked(0x8, &[0x03, 0xE8, b'd', b'o', b'n', b'e']));
        stream.write_all(&burst).expect("write the burst");
        stream.flush().expect("flush the burst");
        stream
            .set_read_timeout(Some(Duration::from_millis(25)))
            .expect("peer read timeout");
        drain(&mut stream, DEADLINE)
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
    assert_eq!(frames[0].1, b"hello", "the client echo must carry the message");
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
