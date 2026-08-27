//! US-018 process-lifecycle checks for the `ws-testee` binary: usage
//! errors, loopback refusal, and one full two-process echo round-trip.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

fn testee() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ws-testee"))
}

#[test]
fn missing_arguments_exit_with_the_usage_code() {
    let status = testee()
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn");
    assert_eq!(status.code(), Some(2));
}

#[test]
fn non_loopback_server_address_is_refused() {
    let output = testee()
        .args(["server", "192.0.2.1:9001"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("non-loopback-refused"), "got: {stdout}");
}

#[test]
fn two_process_echo_round_trip_exits_cleanly() {
    let mut server = testee()
        .args(["server", "127.0.0.1:0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn server");
    let stdout = server.stdout.take().expect("server stdout");
    let mut lines = BufReader::new(stdout).lines();
    let listening = lines
        .next()
        .expect("server prints its bound address")
        .expect("readable line");
    let address = listening
        .strip_prefix("listening ")
        .expect("listening line")
        .to_owned();

    let client = testee()
        .args(["client", &address, "/chat", "localhost", "proc-echo"])
        .output()
        .expect("spawn client");
    let client_stdout = String::from_utf8_lossy(&client.stdout);
    assert_eq!(client.status.code(), Some(0), "client: {client_stdout}");
    assert!(client_stdout.contains("texts=1"), "client: {client_stdout}");
    assert!(
        client_stdout.contains("close=1000:remote"),
        "client: {client_stdout}"
    );

    let server_status = server.wait().expect("server exit");
    let server_summary = lines
        .next()
        .expect("server prints its report")
        .expect("readable line");
    assert_eq!(server_status.code(), Some(0), "server: {server_summary}");
    assert!(
        server_summary.contains("texts=1"),
        "server: {server_summary}"
    );
}
