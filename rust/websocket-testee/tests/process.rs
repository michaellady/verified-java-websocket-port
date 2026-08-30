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
    neutral_request_with_limits(
        role,
        initial_state,
        steps,
        [64, 65_536, 64, 65_536, 4_194_304],
    )
}

fn neutral_request_with_limits(
    role: u8,
    initial_state: u8,
    steps: &[Vec<u8>],
    limits: [u64; 5],
) -> Vec<u8> {
    let mut body = b"NDRV1".to_vec();
    tlv(1, b"us020.process.open-server", &mut body);
    tlv(2, &[role], &mut body);
    tlv(3, &[initial_state], &mut body);
    let mut encoded_limits = Vec::new();
    for value in limits {
        encoded_limits.extend_from_slice(&value.to_be_bytes());
    }
    tlv(4, &encoded_limits, &mut body);
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
    run_neutral_with_args(input, &["neutral-oracle", "--protocol", "NDRV1"])
}

fn run_neutral_java(input: &[u8]) -> std::process::Output {
    run_neutral_with_args(
        input,
        &[
            "neutral-oracle",
            "--protocol",
            "NDRV1",
            "--behavior-profile",
            "java-websocket-1.6.0",
        ],
    )
}

fn run_neutral_with_args(input: &[u8], args: &[&str]) -> std::process::Output {
    let mut child = Command::new(binary())
        .args(args)
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

fn response_steps(response: &[u8]) -> Vec<&[u8]> {
    let mut remaining = response_field(response, 5);
    let count = u16::from_be_bytes(remaining[..2].try_into().unwrap());
    remaining = &remaining[2..];
    let mut records = Vec::new();
    for _ in 0..count {
        let length = u32::from_be_bytes(remaining[..4].try_into().unwrap()) as usize;
        records.push(&remaining[4..4 + length]);
        remaining = &remaining[4 + length..];
    }
    assert!(remaining.is_empty());
    records
}

fn step_observations(record: &[u8]) -> Vec<&[u8]> {
    let count = u16::from_be_bytes(record[29..31].try_into().unwrap());
    let mut remaining = &record[31..];
    let mut observations = Vec::new();
    for _ in 0..count {
        let length = u32::from_be_bytes(remaining[..4].try_into().unwrap()) as usize;
        observations.push(&remaining[4..4 + length]);
        remaining = &remaining[4 + length..];
    }
    assert!(remaining.is_empty());
    observations
}

fn step_error_class(record: &[u8]) -> Option<&[u8]> {
    step_observations(record)
        .into_iter()
        .find_map(|observation| {
            if observation[0] != 5 {
                return None;
            }
            let length = u16::from_be_bytes(observation[2..4].try_into().unwrap()) as usize;
            Some(&observation[4..4 + length])
        })
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
fn neutral_oracle_reports_java_state_and_full_chunk_for_public_rsv_rejection() {
    const US005_PUBLIC_0005: &[u8] = b"\xa1\x83\x74\xb3\xd8\xd2\x08\xe9\x85";
    let step = [vec![1], US005_PUBLIC_0005.to_vec()].concat();
    let output = run_neutral_java(&neutral_request_for(2, 1, &[step]));
    assert_eq!(output.status.code(), Some(0), "{:?}", output.stderr);
    assert!(output.stderr.is_empty());

    let steps = response_field(&output.stdout, 5);
    assert_eq!(&steps[..2], &1_u16.to_be_bytes());
    let record_length = u32::from_be_bytes(steps[2..6].try_into().unwrap()) as usize;
    assert_eq!(record_length, steps.len() - 6);
    let record = &steps[6..];
    assert_eq!(&record[..5], &[0, 0, 1, 1, 1]);
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
            assert_eq!(observation[1], 0, "Java records the still-open state");
            let class_length = u16::from_be_bytes(observation[2..4].try_into().unwrap()) as usize;
            error_class = Some(&observation[4..4 + class_length]);
        }
        remaining = &remaining[4 + length..];
    }
    assert!(remaining.is_empty());
    assert_eq!(error_class, Some(b"FRAME_RESERVED_BITS".as_slice()));
    assert_eq!(response_field(&output.stdout, 6), &[1]);
}

#[test]
fn neutral_oracle_default_remains_strict_for_public_rsv_rejection() {
    const US005_PUBLIC_0005: &[u8] = b"\xa1\x83\x74\xb3\xd8\xd2\x08\xe9\x85";
    let step = [vec![1], US005_PUBLIC_0005.to_vec()].concat();
    let output = run_neutral(&neutral_request_for(2, 1, &[step]));

    assert_eq!(output.status.code(), Some(0), "{:?}", output.stderr);
    let steps = response_steps(&output.stdout);
    assert_eq!(&steps[0][..5], &[0, 0, 1, 1, 3]);
    assert_eq!(
        step_error_class(steps[0]),
        Some(b"FRAME_RESERVED_BITS".as_slice())
    );
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

    let eof_output = run_neutral(&neutral_request_for(1, 3, &[vec![2]]));
    assert_eq!(eof_output.status.code(), Some(0), "{:?}", eof_output.stderr);
    let eof_steps = response_steps(&eof_output.stdout);
    assert_eq!(
        step_error_class(eof_steps[0]),
        Some(b"INVALID_STATE".as_slice())
    );
    assert_eq!(response_field(&eof_output.stdout, 6), &[3]);
}

#[test]
fn neutral_oracle_treats_empty_bytes_in_closed_as_a_no_op() {
    let output = run_neutral(&neutral_request_for(2, 3, &[vec![1]]));
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
    assert_eq!(&record[29..31], &0_u16.to_be_bytes());
    assert_eq!(record.len(), 31);
    assert_eq!(response_field(&output.stdout, 6), &[3]);
}

#[test]
fn neutral_oracle_encodes_action_input_and_frame_limits_as_typed_steps() {
    let action_a = vec![0x10, 1, 1, 2, 3, 4, b'a'];
    let action_b = vec![0x10, 1, 5, 6, 7, 8, b'b'];
    let action_output = run_neutral(&neutral_request_with_limits(
        1,
        1,
        &[action_a, action_b],
        [1, 65_536, 64, 65_536, 4_194_304],
    ));
    assert_eq!(
        action_output.status.code(),
        Some(0),
        "{:?}",
        action_output.stderr
    );
    let action_steps = response_steps(&action_output.stdout);
    assert_eq!(action_steps.len(), 2);
    assert_eq!(step_error_class(action_steps[0]), None);
    assert_eq!(
        step_error_class(action_steps[1]),
        Some(b"ACTION_LIMIT_EXCEEDED".as_slice())
    );
    assert_eq!(response_field(&action_output.stdout, 6), &[1]);

    const INPUT_OVER_LIMIT: &[u8] = b"\x8a\x4b\x59\xeb\x79\x48\xf1\x88\x02";
    let input_step = [vec![1], INPUT_OVER_LIMIT.to_vec()].concat();
    let input_output = run_neutral(&neutral_request_with_limits(
        2,
        1,
        &[input_step],
        [64, 65_536, 64, 8, 4_194_304],
    ));
    assert_eq!(
        input_output.status.code(),
        Some(0),
        "{:?}",
        input_output.stderr
    );
    let input_steps = response_steps(&input_output.stdout);
    assert_eq!(input_steps.len(), 1);
    assert_eq!(
        u64::from_be_bytes(input_steps[0][5..13].try_into().unwrap()),
        0
    );
    assert_eq!(
        step_error_class(input_steps[0]),
        Some(b"INPUT_LIMIT_EXCEEDED".as_slice())
    );
    assert_eq!(response_field(&input_output.stdout, 6), &[1]);

    const TWO_TEXT_FRAMES: &[u8] =
        b"\x81\x82\xf2\x48\x4a\x75\x85\x0f\x82\x82\x2e\x72\xfc\x2e\x75\xac";
    let frame_step = [vec![1], TWO_TEXT_FRAMES.to_vec()].concat();
    let frame_output = run_neutral(&neutral_request_with_limits(
        2,
        1,
        &[frame_step],
        [64, 65_536, 1, 65_536, 4_194_304],
    ));
    assert_eq!(
        frame_output.status.code(),
        Some(0),
        "{:?}",
        frame_output.stderr
    );
    let frame_steps = response_steps(&frame_output.stdout);
    assert_eq!(frame_steps.len(), 1);
    assert_eq!(
        u64::from_be_bytes(frame_steps[0][5..13].try_into().unwrap()),
        TWO_TEXT_FRAMES.len() as u64
    );
    assert_eq!(
        step_observations(frame_steps[0])
            .iter()
            .filter(|item| item[0] == 2)
            .count(),
        1
    );
    assert_eq!(
        step_error_class(frame_steps[0]),
        Some(b"FRAME_LIMIT_EXCEEDED".as_slice())
    );
    assert_eq!(response_field(&frame_output.stdout, 6), &[1]);
}

#[test]
fn neutral_oracle_projects_peer_close_event_and_terminal_transition() {
    const EMPTY_PEER_CLOSE: &[u8] = b"\x88\x80\xd2\x81\x14\x8b";
    let step = [vec![1], EMPTY_PEER_CLOSE.to_vec()].concat();
    let output = run_neutral(&neutral_request_for(2, 1, &[step]));
    assert_eq!(output.status.code(), Some(0), "{:?}", output.stderr);
    let steps = response_steps(&output.stdout);
    let observations = step_observations(steps[0]);
    assert!(
        observations
            .iter()
            .any(|item| item == &[1, 5, 0, 0, 0, 0, 0, 1, 2])
    );
    assert!(
        observations
            .iter()
            .any(|item| item == &[4, 0, 0, 0, 0, 0, 1, 2])
    );
    assert!(observations.iter().any(|item| item == &[3, 1, 2]));
    assert_eq!(response_field(&output.stdout, 6), &[2]);
    assert_eq!(response_field(&output.stdout, 7), &[1, 0, 0, 0, 0, 0, 1, 2]);

    const PEER_ACK_IN_CLOSING: &[u8] = b"\x88\x86\x0f\x82\xd0\x5e\x0c\x71\xad\x35\x56\xaa";
    let closing_step = [vec![1], PEER_ACK_IN_CLOSING.to_vec()].concat();
    let closing_output = run_neutral(&neutral_request_for(2, 2, &[closing_step]));
    assert_eq!(
        closing_output.status.code(),
        Some(0),
        "{:?}",
        closing_output.stderr
    );
    let closing_steps = response_steps(&closing_output.stdout);
    let closing_observations = step_observations(closing_steps[0]);
    assert!(closing_observations.iter().any(|item| {
        item.starts_with(&[1, 5, 1, 0x03, 0xf3, 0, 0, 0, 4]) && item.ends_with(&[1, 2])
    }));
    assert!(closing_observations.iter().any(|item| item == &[3, 2, 3]));
    assert_eq!(response_field(&closing_output.stdout, 6), &[3]);
    assert!(response_field(&closing_output.stdout, 7).ends_with(&[1, 2]));
}

#[test]
fn neutral_oracle_java_profile_projects_empty_close_constructor_code() {
    const EMPTY_PEER_CLOSE: &[u8] = b"\x88\x80\xd2\x81\x14\x8b";
    let step = [vec![1], EMPTY_PEER_CLOSE.to_vec()].concat();
    let output = run_neutral_java(&neutral_request_for(2, 1, &[step]));

    assert_eq!(output.status.code(), Some(0), "{:?}", output.stderr);
    let observations = step_observations(response_steps(&output.stdout)[0]);
    assert!(
        observations
            .iter()
            .any(|item| { item.starts_with(&[1, 5, 1, 0x03, 0xe8]) && item.ends_with(&[1, 2]) })
    );
    assert_eq!(
        response_field(&output.stdout, 7),
        &[1, 1, 0x03, 0xe8, 0, 0, 0, 0, 1, 2]
    );
}

#[test]
fn neutral_oracle_projects_java_one_byte_close_constructor_semantics() {
    const ONE_BYTE_PEER_CLOSE: &[u8] = b"\x88\x81\xb7\xbe\x28\x83\xb4";
    let step = [vec![1], ONE_BYTE_PEER_CLOSE.to_vec()].concat();
    let output = run_neutral_java(&neutral_request_for(2, 1, &[step]));

    assert_eq!(output.status.code(), Some(0), "{:?}", output.stderr);
    let steps = response_steps(&output.stdout);
    let observations = step_observations(steps[0]);
    let frames: Vec<_> = observations
        .iter()
        .filter(|observation| observation[0] == 2)
        .collect();
    assert_eq!(frames.len(), 2);
    assert_eq!(&frames[0][..11], &[2, 1, 1, 8, 1, 0, 0, 0, 2, 3, 232]);
    assert_eq!(
        u64::from_be_bytes(frames[0][11..].try_into().unwrap()),
        ONE_BYTE_PEER_CLOSE.len() as u64
    );
    assert_eq!(&frames[1][..11], &[2, 2, 1, 8, 0, 0, 0, 0, 2, 3, 232]);
    assert_eq!(u64::from_be_bytes(frames[1][11..].try_into().unwrap()), 4);
    assert!(
        observations
            .iter()
            .any(|item| { item == &[4, 1, 0x03, 0xea, 0, 0, 0, 0, 1, 2] })
    );
    assert!(observations.iter().any(|item| item == &[3, 1, 2]));
    assert_eq!(response_field(&output.stdout, 6), &[2]);
    assert_eq!(
        response_field(&output.stdout, 7),
        &[1, 1, 0x03, 0xea, 0, 0, 0, 0, 1, 2]
    );
}

#[test]
fn neutral_oracle_client_echoes_peer_close_with_a_deterministic_mask() {
    const REASON: &[u8] = b"]=tbBn@k0+(AHwE]Ne";
    let mut payload = 1008_u16.to_be_bytes().to_vec();
    payload.extend_from_slice(REASON);
    let mut wire = vec![0x88, u8::try_from(payload.len()).unwrap()];
    wire.extend_from_slice(&payload);
    let step = [vec![1], wire].concat();

    let output = run_neutral(&neutral_request_for(1, 1, &[step]));
    assert_eq!(output.status.code(), Some(0), "{:?}", output.stderr);
    let steps = response_steps(&output.stdout);
    let observations = step_observations(steps[0]);
    let frames: Vec<_> = observations
        .iter()
        .filter(|observation| observation[0] == 2)
        .collect();
    assert_eq!(frames.len(), 2, "missing automatic peer-Close echo");
    let echo = frames[1];
    assert_eq!(&echo[..5], &[2, 2, 1, 8, 1]);
    assert_eq!(
        u32::from_be_bytes(echo[5..9].try_into().unwrap()),
        u32::try_from(payload.len()).unwrap()
    );
    assert_eq!(&echo[9..9 + payload.len()], payload);
    assert_eq!(
        u64::from_be_bytes(echo[9 + payload.len()..].try_into().unwrap()),
        26
    );
    assert_eq!(step_error_class(steps[0]), None);
    assert!(
        observations
            .iter()
            .any(|item| { item.starts_with(&[1, 5, 1, 0x03, 0xf0]) && item.ends_with(&[1, 2]) })
    );
    assert!(observations.iter().any(|item| item == &[3, 1, 2]));
    assert!(!observations.iter().any(|item| item == &[3, 2, 3]));
    assert_eq!(response_field(&output.stdout, 6), &[2]);
    assert!(response_field(&output.stdout, 7).ends_with(&[1, 2]));
}

#[test]
fn neutral_oracle_java_client_ack_uses_close_constructor_payload() {
    const REASON: &[u8] = b"]=tbBn@k0+(AHwE]Ne";
    let mut payload = 1008_u16.to_be_bytes().to_vec();
    payload.extend_from_slice(REASON);
    let mut wire = vec![0x88, u8::try_from(payload.len()).unwrap()];
    wire.extend_from_slice(&payload);
    let step = [vec![1], wire].concat();

    let output = run_neutral_java(&neutral_request_for(1, 1, &[step]));
    assert_eq!(output.status.code(), Some(0), "{:?}", output.stderr);
    let observations = step_observations(response_steps(&output.stdout)[0]);
    let frames: Vec<_> = observations
        .iter()
        .filter(|observation| observation[0] == 2)
        .collect();
    assert_eq!(frames.len(), 2);
    let echo = frames[1];
    assert_eq!(&echo[..11], &[2, 2, 1, 8, 1, 0, 0, 0, 2, 3, 232]);
    assert_eq!(u64::from_be_bytes(echo[11..].try_into().unwrap()), 8);
}

#[test]
fn neutral_oracle_projects_local_close_then_transport_eof() {
    let local_close = [
        vec![0x15, 1, 1, 2, 3, 4, 1],
        1001_u16.to_be_bytes().to_vec(),
        b"MR{fS".to_vec(),
    ]
    .concat();
    let output = run_neutral(&neutral_request_for(1, 1, &[local_close, vec![2]]));
    assert_eq!(output.status.code(), Some(0), "{:?}", output.stderr);
    let steps = response_steps(&output.stdout);
    assert_eq!(steps.len(), 2);
    assert_eq!(step_error_class(steps[0]), None);
    assert_eq!(step_error_class(steps[1]), None);
    assert!(step_observations(steps[0]).iter().any(|item| {
        item.starts_with(&[1, 5, 1, 0x03, 0xe9, 0, 0, 0, 5]) && item.ends_with(&[0, 1])
    }));
    assert!(step_observations(steps[1]).iter().any(|item| {
        item.starts_with(&[1, 5, 1, 0x03, 0xe9, 0, 0, 0, 5]) && item.ends_with(&[0, 5])
    }));
    assert!(
        step_observations(steps[1])
            .iter()
            .any(|item| item == &[3, 2, 3])
    );
    assert_eq!(response_field(&output.stdout, 6), &[3]);
    assert!(response_field(&output.stdout, 7).ends_with(&[0, 5]));
}

#[test]
fn neutral_oracle_projects_abnormal_eof_without_protocol_error() {
    let output = run_neutral(&neutral_request_for(2, 1, &[vec![2]]));
    assert_eq!(output.status.code(), Some(0), "{:?}", output.stderr);
    let steps = response_steps(&output.stdout);
    assert_eq!(step_error_class(steps[0]), None);
    let observations = step_observations(steps[0]);
    assert!(
        observations
            .iter()
            .any(|item| item.starts_with(&[1, 5, 1, 0x03, 0xee]))
    );
    assert!(observations.iter().any(|item| item.ends_with(&[0, 5])));
    assert!(observations.iter().any(|item| item == &[3, 1, 3]));
    assert_eq!(response_field(&output.stdout, 6), &[3]);
    assert!(response_field(&output.stdout, 7).ends_with(&[0, 5]));
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

    let address = "127.0.0.1:0";
    let mut arguments = vec![
        "client".to_owned(),
        address.to_owned(),
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
    let mut child = Command::new(binary())
        .args(arguments)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut peer = loop {
        match TcpStream::connect(address) {
            Ok(stream) => break stream,
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(1)),
            Err(error) => {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "server process did not bind: {error}; status={:?} stdout={:?} stderr={:?}",
                    output.status.code(),
                    output.stdout,
                    output.stderr
                );
            }
        }
    };
    peer.write_all(RFC_REQUEST).unwrap();
    peer.shutdown(Shutdown::Write).unwrap();
    let mut response = vec![0_u8; RFC_RESPONSE.len()];
    let response_result = peer.read_exact(&mut response);
    let mut trailing = [0_u8; 1];
    let teardown_result = peer.read(&mut trailing);
    let output = child.wait_with_output().unwrap();

    response_result.unwrap();
    match teardown_result {
        Ok(0) => {}
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        Ok(bytes) => panic!("server emitted {bytes} trailing response bytes"),
        Err(error) => panic!("server response teardown failed: {error}"),
    }

    assert_eq!(response, RFC_RESPONSE);
    assert_eq!(output.status.code(), Some(0));
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .starts_with("role=server setup=connected termination=peer-eof terminal=1 ")
    );
}
