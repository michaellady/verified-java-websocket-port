//! US-008 suite-calibration blind spot: framing inside the NDRV1 step list.
//!
//! NEW in US-008. `process` already rejects a truncated and a trailing-octet
//! *record*, but never presents a well-framed record whose step list carries
//! octets past its declared step count. Dropping that inner check therefore
//! survived the whole workspace, which would let a differential run silently
//! ignore part of a scenario.

#![forbid(unsafe_code)]

use std::io::Write;
use std::process::{Command, Stdio};

fn tlv(tag: u8, value: &[u8], output: &mut Vec<u8>) {
    output.push(tag);
    output.extend_from_slice(&u32::try_from(value.len()).expect("tlv length").to_be_bytes());
    output.extend_from_slice(value);
}

fn request_with_step_blob(step_blob: &[u8]) -> Vec<u8> {
    let mut body = b"NDRV1".to_vec();
    tlv(1, b"us008.calibration.step-framing", &mut body);
    tlv(2, &[2], &mut body);
    tlv(3, &[1], &mut body);
    let mut encoded_limits = Vec::new();
    for value in [64_u64, 65_536, 64, 65_536, 4_194_304] {
        encoded_limits.extend_from_slice(&value.to_be_bytes());
    }
    tlv(4, &encoded_limits, &mut body);
    tlv(5, step_blob, &mut body);
    let mut record = u32::try_from(body.len())
        .expect("record length")
        .to_be_bytes()
        .to_vec();
    record.extend_from_slice(&body);
    record
}

fn run_neutral(input: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_websocket-testee"))
        .args(["neutral-oracle", "--protocol", "NDRV1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn neutral oracle");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(input)
        .expect("write request");
    drop(child.stdin.take());
    child.wait_with_output().expect("wait for neutral oracle")
}

#[test]
fn step_list_framing_rejects_trailing_and_truncated_octets() {
    // A well-framed empty step list is still accepted.
    let accepted = run_neutral(&request_with_step_blob(&0_u16.to_be_bytes()));
    assert_eq!(accepted.status.code(), Some(0));

    // Octets past the declared step count are a neutral-protocol error.
    let mut trailing = 0_u16.to_be_bytes().to_vec();
    trailing.extend_from_slice(b"TRAILING");
    // A declared step whose length header is truncated is likewise an error.
    let mut truncated = 1_u16.to_be_bytes().to_vec();
    truncated.extend_from_slice(&[0x00, 0x00]);

    for hostile in [trailing, truncated] {
        let output = run_neutral(&request_with_step_blob(&hostile));
        assert_eq!(
            output.status.code(),
            Some(2),
            "step blob {hostile:02x?} must be a neutral-protocol error"
        );
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, b"neutral-protocol-error\n");
    }
}
