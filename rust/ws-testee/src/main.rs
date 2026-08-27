//! Minimal CLI for the US-018 loopback adapters. Verification fixture
//! only: `server <loopback-addr>` accepts and echoes ONE connection;
//! `client <loopback-addr> <target> <host> <message>` runs one echo
//! round-trip with a clean close.

#![forbid(unsafe_code)]

use std::env;
use std::net::{SocketAddr, TcpListener};
use std::process::exit;

use ws_core::ConnectionConfig;
use ws_testee::{ClientFixture, IoBounds, ServerFixture, run_client_once, run_server_once};

const EXIT_OK: i32 = 0;
const EXIT_UNCLEAN: i32 = 1;
const EXIT_USAGE: i32 = 2;
const EXIT_SETUP: i32 = 3;

fn main() {
    let arguments: Vec<String> = env::args().collect();
    let code = match arguments.get(1).map(String::as_str) {
        Some("server") => server(&arguments[2..]),
        Some("client") => client(&arguments[2..]),
        _ => {
            eprintln!(
                "usage: ws-testee server <loopback-addr> | ws-testee client <loopback-addr> <target> <host> <message>"
            );
            EXIT_USAGE
        }
    };
    exit(code);
}

fn server(arguments: &[String]) -> i32 {
    let [address] = arguments else {
        eprintln!("usage-error");
        return EXIT_USAGE;
    };
    let Ok(address) = address.parse::<SocketAddr>() else {
        eprintln!("usage-error");
        return EXIT_USAGE;
    };
    if ws_testee::loopback_only(&address).is_err() {
        println!("setup=non-loopback-refused");
        return EXIT_SETUP;
    }
    let listener = match TcpListener::bind(address) {
        Ok(listener) => listener,
        Err(error) => {
            println!("setup=bind-failed kind={:?}", error.kind());
            return EXIT_SETUP;
        }
    };
    match listener.local_addr() {
        Ok(bound) => println!("listening {bound}"),
        Err(error) => {
            println!("setup=local-addr-failed kind={:?}", error.kind());
            return EXIT_SETUP;
        }
    }
    let fixture = ServerFixture {
        config: ConnectionConfig::default(),
        bounds: IoBounds::default(),
    };
    match run_server_once(&listener, &fixture) {
        Ok(report) => {
            println!("{}", report.summary());
            if report.clean() {
                EXIT_OK
            } else {
                EXIT_UNCLEAN
            }
        }
        Err(outcome) => {
            println!("setup={outcome:?}");
            EXIT_SETUP
        }
    }
}

fn client(arguments: &[String]) -> i32 {
    let [address, target, host, message] = arguments else {
        eprintln!("usage-error");
        return EXIT_USAGE;
    };
    let Ok(address) = address.parse::<SocketAddr>() else {
        eprintln!("usage-error");
        return EXIT_USAGE;
    };
    let fixture = ClientFixture {
        address,
        config: ConnectionConfig::default(),
        request_target: target,
        host,
        message,
        bounds: IoBounds::default(),
    };
    match run_client_once(&fixture) {
        Ok(report) => {
            println!("{}", report.summary());
            let echoed = report.texts.iter().any(|text| text == message);
            if report.clean() && echoed {
                EXIT_OK
            } else {
                EXIT_UNCLEAN
            }
        }
        Err(outcome) => {
            println!("setup={outcome:?}");
            EXIT_SETUP
        }
    }
}
