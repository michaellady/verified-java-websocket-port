#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::process::Command;
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant};

const RFC_REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
const RFC_RESPONSE: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_websocket-testee")
}

fn tlv(tag: u8, value: &[u8], output: &mut Vec<u8>) {
    output.push(tag);
    output.extend_from_slice(&u32::try_from(value.len()).unwrap().to_be_bytes());
    output.extend_from_slice(value);
}

fn neutral_request() -> Vec<u8> {
    neutral_request_for(2, 1, &[])
}

fn neutral_request_for(role: u8, initial_state: u8, steps: &[Vec<u8>]) -> Vec<u8> {
    let mut body = b"NDRV1".to_vec();
    tlv(1, b"us020.process.open-server", &mut body);
    tlv(2, &[role], &mut body);
    tlv(3, &[initial_state], &mut body);
    let mut limits = Vec::new();
    for value in [64_u64, 65_536, 64, 65_536, 4_194_304] {
        limits.extend_from_slice(&value.to_be_bytes());
    }
    tlv(4, &limits, &mut body);
    let mut encoded_steps = u16::try_from(steps.len()).unwrap().to_be_bytes().to_vec();
    for step in steps {
        encoded_steps.extend_from_slice(&u32::try_from(step.len()).unwrap().to_be_bytes());
        encoded_steps.extend_from_slice(step);
    }
    tlv(5, &encoded_steps, &mut body);
    let mut record = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
    record.extend_from_slice(&body);
    record
}

fn run_neutral(input: &[u8]) -> std::process::Output {
    let mut child = Command::new(binary())
        .args(["neutral-oracle", "--protocol", "NDRV1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

fn response_field(response: &[u8], wanted_tag: u8) -> &[u8] {
    let declared = u32::from_be_bytes(response[..4].try_into().unwrap()) as usize;
    assert_eq!(declared, response.len() - 4);
    assert_eq!(&response[4..9], b"NOBS1");
    let mut remaining = &response[9..];
    while !remaining.is_empty() {
        let tag = remaining[0];
        let length = u32::from_be_bytes(remaining[1..5].try_into().unwrap()) as usize;
        let value = &remaining[5..5 + length];
        if tag == wanted_tag {
            return value;
        }
        remaining = &remaining[5 + length..];
    }
    panic!("missing response tag {wanted_tag}");
}

#[test]
fn neutral_oracle_is_one_record_and_bootstraps_the_real_server_owner() {
    let output = run_neutral(&neutral_request());
    assert_eq!(output.status.code(), Some(0), "{:?}", output.stderr);
    assert!(output.stderr.is_empty());
    assert!(output.stdout.len() >= 9);
    let declared = u32::from_be_bytes(output.stdout[..4].try_into().unwrap()) as usize;
    assert_eq!(declared, output.stdout.len() - 4);
    assert_eq!(&output.stdout[4..9], b"NOBS1");
}

#[test]
fn neutral_oracle_rejects_truncated_and_trailing_records() {
    let request = neutral_request();
    for hostile in [
        &request[..request.len() - 1],
        &[request.as_slice(), b"x"].concat(),
    ] {
        let output = run_neutral(hostile);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, b"neutral-protocol-error\n");
    }
}

#[test]
fn neutral_oracle_bootstraps_both_roles_through_open_closing_and_closed() {
    for role in [1, 2] {
        for state in [1, 2, 3] {
            let output = run_neutral(&neutral_request_for(role, state, &[]));
            assert_eq!(
                output.status.code(),
                Some(0),
                "role={role} state={state} stderr={:?}",
                output.stderr
            );
            assert_eq!(&output.stdout[4..9], b"NOBS1");
        }
    }
}

#[test]
fn neutral_oracle_drives_outbound_fragments_through_the_owner() {
    let first = [vec![0x12, 1, 0, 0], b"snng".to_vec()].concat();
    let second = [vec![0x12, 1, 1, 0], "éjé".as_bytes().to_vec()].concat();
    let output = run_neutral(&neutral_request_for(2, 1, &[first, second]));
    assert_eq!(output.status.code(), Some(0), "{:?}", output.stderr);
    assert_eq!(&output.stdout[4..9], b"NOBS1");
    assert!(output.stdout.windows(4).any(|window| window == b"snng"));
    assert!(
        output
            .stdout
            .windows(5)
            .any(|window| window == "éjé".as_bytes())
    );
}

#[test]
fn neutral_oracle_reports_full_offered_chunk_for_public_rsv_rejection() {
    const US005_PUBLIC_0005: &[u8] = b"\xa1\x83\x74\xb3\xd8\xd2\x08\xe9\x85";
    let step = [vec![1], US005_PUBLIC_0005.to_vec()].concat();
    let output = run_neutral(&neutral_request_for(2, 1, &[step]));
    assert_eq!(output.status.code(), Some(0), "{:?}", output.stderr);
    assert!(output.stderr.is_empty());

    let steps = response_field(&output.stdout, 5);
    assert_eq!(&steps[..2], &1_u16.to_be_bytes());
    let record_length = u32::from_be_bytes(steps[2..6].try_into().unwrap()) as usize;
    assert_eq!(record_length, steps.len() - 6);
    let record = &steps[6..];
    assert_eq!(&record[..5], &[0, 0, 1, 1, 3]);
    assert_eq!(
        u64::from_be_bytes(record[5..13].try_into().unwrap()),
        US005_PUBLIC_0005.len() as u64
    );
    assert_eq!(u64::from_be_bytes(record[13..21].try_into().unwrap()), 0);
    assert_eq!(u64::from_be_bytes(record[21..29].try_into().unwrap()), 0);

    let observation_count = u16::from_be_bytes(record[29..31].try_into().unwrap());
    let mut remaining = &record[31..];
    let mut error_class = None;
    for _ in 0..observation_count {
        let length = u32::from_be_bytes(remaining[..4].try_into().unwrap()) as usize;
        let observation = &remaining[4..4 + length];
        if observation[0] == 5 {
            assert_eq!(observation[1], 1, "RSV rejection must remain terminal");
            let class_length = u16::from_be_bytes(observation[2..4].try_into().unwrap()) as usize;
            error_class = Some(&observation[4..4 + class_length]);
        }
        remaining = &remaining[4 + length..];
    }
    assert!(remaining.is_empty());
    assert_eq!(error_class, Some(b"FRAME_RESERVED_BITS".as_slice()));
    assert_eq!(response_field(&output.stdout, 6), &[3]);
}

#[test]
fn neutral_oracle_does_not_consume_bytes_rejected_in_closed() {
    const US005_PUBLIC_0015: &[u8] = b"\x5d\x87\x0a";
    let step = [vec![1], US005_PUBLIC_0015.to_vec()].concat();
    let output = run_neutral(&neutral_request_for(2, 3, &[step]));
    assert_eq!(output.status.code(), Some(0), "{:?}", output.stderr);
    assert!(output.stderr.is_empty());

    let steps = response_field(&output.stdout, 5);
    assert_eq!(&steps[..2], &1_u16.to_be_bytes());
    let record_length = u32::from_be_bytes(steps[2..6].try_into().unwrap()) as usize;
    assert_eq!(record_length, steps.len() - 6);
    let record = &steps[6..];
    assert_eq!(&record[..5], &[0, 0, 1, 3, 3]);
    assert_eq!(u64::from_be_bytes(record[5..13].try_into().unwrap()), 0);
    assert_eq!(u64::from_be_bytes(record[13..21].try_into().unwrap()), 0);
    assert_eq!(u64::from_be_bytes(record[21..29].try_into().unwrap()), 0);

    let observation_count = u16::from_be_bytes(record[29..31].try_into().unwrap());
    let mut remaining = &record[31..];
    let mut error_class = None;
    for _ in 0..observation_count {
        let length = u32::from_be_bytes(remaining[..4].try_into().unwrap()) as usize;
        let observation = &remaining[4..4 + length];
        if observation[0] == 5 {
            assert_eq!(observation[1], 1);
            let class_length = u16::from_be_bytes(observation[2..4].try_into().unwrap()) as usize;
            error_class = Some(&observation[4..4 + class_length]);
        }
        remaining = &remaining[4 + length..];
    }
    assert!(remaining.is_empty());
    assert_eq!(error_class, Some(b"INVALID_STATE".as_slice()));
    assert_eq!(response_field(&output.stdout, 6), &[3]);
}

#[test]
fn harness_contract_is_non_networked_and_challenge_bound() {
    let challenge = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let output = Command::new(binary())
        .args(["harness-contract", challenge])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!(
            "schema=1 status=READY_NO_LIVE_CONFORMANCE roles=client,server network_routes=client,server application_echo=false multi_case=false conformance=false challenge={challenge}\n"
        )
    );

    for invalid in [
        "",
        "ABCDEF",
        "00",
        "g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    ] {
        let rejected = Command::new(binary())
            .args(["harness-contract", invalid])
            .output()
            .unwrap();
        assert_eq!(rejected.status.code(), Some(2));
        assert!(rejected.stdout.is_empty());
    }
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
