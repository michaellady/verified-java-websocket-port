#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

const RFC_REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
const RFC_RESPONSE: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_websocket-testee")
}

fn bounds() -> [&'static str; 8] {
    ["16", "7", "500", "500", "500", "500", "10000", "1024"]
}

fn read_headers(stream: &mut TcpStream) -> Vec<u8> {
    let mut result = Vec::new();
    let mut byte = [0_u8; 1];
    while !result.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).unwrap();
        result.push(byte[0]);
    }
    result
}

#[test]
fn invalid_cli_and_failed_connect_have_stable_exit_classes() {
    let invalid = Command::new(binary()).arg("unknown").output().unwrap();
    assert_eq!(invalid.status.code(), Some(2));
    assert_eq!(String::from_utf8(invalid.stderr).unwrap(), "usage-error\n");

    let unused = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = unused.local_addr().unwrap();
    drop(unused);
    let mut arguments = vec![
        "client".to_owned(),
        address.to_string(),
        "/chat".to_owned(),
        "server.example.com".to_owned(),
        "7468652073616d706c65206e6f6e6365".to_owned(),
    ];
    arguments.extend(bounds().map(str::to_owned));
    let failed = Command::new(binary()).args(arguments).output().unwrap();
    assert_eq!(failed.status.code(), Some(3));
    let summary = String::from_utf8(failed.stdout).unwrap();
    assert!(summary.starts_with("role=client setup=connect-failed "));
    assert!(!summary.contains("7468652073616d706c65206e6f6e6365"));
}

#[test]
fn client_process_uses_the_same_adapter_and_summary() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let peer = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        assert_eq!(read_headers(&mut stream), RFC_REQUEST);
        for chunk in RFC_RESPONSE.chunks(3) {
            stream.write_all(chunk).unwrap();
        }
        stream.shutdown(Shutdown::Write).unwrap();
        let mut discarded = Vec::new();
        let _ = stream.read_to_end(&mut discarded);
    });

    let mut arguments = vec![
        "client".to_owned(),
        address.to_string(),
        "/chat".to_owned(),
        "server.example.com".to_owned(),
        "7468652073616d706c65206e6f6e6365".to_owned(),
    ];
    arguments.extend(bounds().map(str::to_owned));
    let output = Command::new(binary()).args(arguments).output().unwrap();
    peer.join().unwrap();

    assert_eq!(output.status.code(), Some(0));
    let summary = String::from_utf8(output.stdout).unwrap();
    assert!(summary.starts_with("role=client setup=connected termination=peer-eof terminal=1 "));
    assert!(!summary.contains("server.example.com"));
}

#[test]
fn server_process_binds_one_loopback_peer_and_exits() {
    let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let mut arguments = vec!["server".to_owned(), address.to_string()];
    arguments.extend(bounds().map(str::to_owned));
    let child = Command::new(binary())
        .args(arguments)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_millis(500);
    let mut peer = loop {
        match TcpStream::connect(address) {
            Ok(stream) => break stream,
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(1)),
            Err(error) => panic!("server process did not bind: {error}"),
        }
    };
    peer.write_all(RFC_REQUEST).unwrap();
    peer.shutdown(Shutdown::Write).unwrap();
    let mut response = Vec::new();
    peer.read_to_end(&mut response).unwrap();
    let output = child.wait_with_output().unwrap();

    assert_eq!(response, RFC_RESPONSE);
    assert_eq!(output.status.code(), Some(0));
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .starts_with("role=server setup=connected termination=peer-eof terminal=1 ")
    );
}
