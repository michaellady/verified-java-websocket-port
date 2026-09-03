//! EXPERIMENT (scratch): does a close sharing one read with a completed
//! text frame cancel the echo?

use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use ws_core::ConnectionConfig;
use ws_testee::{IoBounds, ServerFixture, run_server_once};

const TEST_MASK: [u8; 4] = [0x11, 0x22, 0x33, 0x44];

fn masked(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x80 | opcode];
    let len = payload.len();
    if len < 126 {
        #[allow(clippy::cast_possible_truncation)]
        frame.push(0x80 | len as u8);
    } else if len <= 0xFFFF {
        frame.push(0x80 | 126);
        #[allow(clippy::cast_possible_truncation)]
        frame.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        frame.push(0x80 | 127);
        frame.extend_from_slice(&(len as u64).to_be_bytes());
    }
    frame.extend_from_slice(&TEST_MASK);
    for (index, byte) in payload.iter().enumerate() {
        frame.push(byte ^ TEST_MASK[index % 4]);
    }
    frame
}

fn read_head(peer: &mut TcpStream, budget: Duration) -> Option<String> {
    let deadline = Instant::now() + budget;
    let mut received: Vec<u8> = Vec::new();
    let mut buffer = [0u8; 1024];
    while Instant::now() < deadline {
        match peer.read(&mut buffer) {
            Ok(0) => return None,
            Ok(n) => received.extend_from_slice(&buffer[..n]),
            Err(_) => {}
        }
        if let Some(end) = received.windows(4).position(|w| w == b"\r\n\r\n") {
            return String::from_utf8(received[..end + 4].to_vec()).ok();
        }
    }
    None
}

fn drain(peer: &mut TcpStream, budget: Duration) -> (Vec<u8>, bool) {
    let deadline = Instant::now() + budget;
    let mut received = Vec::new();
    let mut buffer = [0u8; 4096];
    while Instant::now() < deadline {
        match peer.read(&mut buffer) {
            Ok(0) => return (received, true),
            Ok(n) => received.extend_from_slice(&buffer[..n]),
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(_) => return (received, false),
        }
    }
    (received, false)
}

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
        .expect("valid")
}

#[test]
fn experiment_exact_7_1_6_shape() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("addr");
    let server = thread::spawn(move || {
        let fixture = ServerFixture {
            config: autobahn_config(),
            bounds: IoBounds {
                read_timeout: Duration::from_millis(1),
                max_polls: 200_000,
                ..IoBounds::default()
            },
        };
        run_server_once(&listener, &fixture)
    });

    let mut peer = TcpStream::connect(address).expect("connect");
    peer.set_read_timeout(Some(Duration::from_millis(50)))
        .expect("read timeout");
    peer.write_all(
        b"GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n\
          Connection: Upgrade\r\n\
          Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    )
    .expect("upgrade request");
    peer.flush().expect("flush");
    let head = read_head(&mut peer, Duration::from_secs(10)).expect("101 head");
    assert!(head.starts_with("HTTP/1.1 101"), "head: {head:?}");

    // Autobahn 7.1.6 verbatim: a 256 KiB text message, "Hello World!", a
    // close, and a ping, written back to back.
    let big: Vec<u8> = b"BAsd7&jh23".iter().copied().cycle().take(256 * 1024).collect();
    let mut burst = masked(0x1, &big);
    burst.extend_from_slice(&masked(0x1, b"Hello World!"));
    burst.extend_from_slice(&masked(0x8, &[0x03, 0xE8]));
    burst.extend_from_slice(&masked(0x9, b""));
    peer.write_all(&burst).expect("burst");
    peer.flush().expect("flush burst");

    let (received, eof) = drain(&mut peer, Duration::from_secs(5));
    let report = server.join().expect("server thread").expect("server setup");
    panic!(
        "7.1.6 OBSERVED received_len={} first16={:02X?} eof={eof} summary={} outcome={:?}",
        received.len(),
        &received[..received.len().min(16)],
        report.summary(),
        report.outcome
    );
}

#[test]
fn experiment_one_byte_reads_do_not_coalesce_the_close_with_the_text() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("addr");
    let server = thread::spawn(move || {
        let fixture = ServerFixture {
            config: ConnectionConfig::default(),
            bounds: IoBounds {
                read_buffer: 1,
                read_timeout: Duration::from_millis(1),
                max_polls: 200_000,
                ..IoBounds::default()
            },
        };
        run_server_once(&listener, &fixture)
    });

    let mut peer = TcpStream::connect(address).expect("connect");
    peer.set_read_timeout(Some(Duration::from_millis(50)))
        .expect("read timeout");
    peer.write_all(
        b"GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n\
          Connection: Upgrade\r\n\
          Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    )
    .expect("upgrade request");
    peer.flush().expect("flush");
    let head = read_head(&mut peer, Duration::from_secs(10)).expect("101 head");
    assert!(head.starts_with("HTTP/1.1 101"), "head: {head:?}");

    let mut burst = masked(0x1, b"hello");
    burst.extend_from_slice(&masked(0x8, &[0x03, 0xE8, b'd', b'o', b'n', b'e']));
    peer.write_all(&burst).expect("burst");
    peer.flush().expect("flush burst");

    let (received, eof) = drain(&mut peer, Duration::from_secs(5));
    let report = server.join().expect("server thread").expect("server setup");
    panic!(
        "1-BYTE-READS OBSERVED bytes={received:02X?} eof={eof} summary={} outcome={:?}",
        report.summary(),
        report.outcome
    );
}

#[test]
fn experiment_close_in_the_same_read_as_a_completed_text_frame() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("addr");
    let server = thread::spawn(move || {
        let fixture = ServerFixture {
            config: ConnectionConfig::default(),
            bounds: IoBounds {
                read_timeout: Duration::from_millis(1),
                max_polls: 200_000,
                ..IoBounds::default()
            },
        };
        run_server_once(&listener, &fixture)
    });

    let mut peer = TcpStream::connect(address).expect("connect");
    peer.set_read_timeout(Some(Duration::from_millis(50)))
        .expect("read timeout");
    peer.write_all(
        b"GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n\
          Connection: Upgrade\r\n\
          Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    )
    .expect("upgrade request");
    peer.flush().expect("flush");
    let head = read_head(&mut peer, Duration::from_secs(10)).expect("101 head");
    assert!(head.starts_with("HTTP/1.1 101"), "head: {head:?}");

    // ONE socket write: a complete text frame immediately followed by a
    // close frame — the shape Autobahn 7.1.6 puts on the wire.
    let mut burst = masked(0x1, b"hello");
    burst.extend_from_slice(&masked(0x8, &[0x03, 0xE8, b'd', b'o', b'n', b'e']));
    peer.write_all(&burst).expect("burst");
    peer.flush().expect("flush burst");

    let (received, eof) = drain(&mut peer, Duration::from_secs(5));
    let report = server.join().expect("server thread").expect("server setup");
    panic!(
        "OBSERVED bytes={received:02X?} eof={eof} summary={} texts={:?} outcome={:?}",
        report.summary(),
        report.texts,
        report.outcome
    );
}
