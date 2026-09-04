//! Minimal CLI for the US-018 loopback adapters. Verification fixture
//! only: `server <loopback-addr> [write-chunk]` accepts and echoes ONE
//! connection; `client <loopback-addr> <target> <host> <message>
//! [ping-hex|-] [write-chunk]` runs one echo round-trip with a clean
//! close. The optional ping payload (hex, `-` for none) scripts the AC4
//! control integration against auto-ponging peers (shipped Java's adapter
//! layer); the optional write-chunk caps every socket write to force the
//! partial-write path (backpressure rehearsal).

#![forbid(unsafe_code)]

use std::env;
use std::net::{SocketAddr, TcpListener};
use std::process::exit;

use ws_core::ConnectionConfig;
use ws_testee::{
    AgentFixture, ClientFixture, IoBounds, ServerFixture, autobahn_config, run_client_once,
    run_server_once, run_server_sessions,
};

const EXIT_OK: i32 = 0;
const EXIT_UNCLEAN: i32 = 1;
const EXIT_USAGE: i32 = 2;
const EXIT_SETUP: i32 = 3;

fn main() {
    let arguments: Vec<String> = env::args().collect();
    let code = match arguments.get(1).map(String::as_str) {
        Some("server") => server(&arguments[2..]),
        Some("serve") => serve(&arguments[2..]),
        Some("client") => client(&arguments[2..]),
        Some("autobahn-client") => autobahn_client(&arguments[2..]),
        _ => {
            eprintln!(
                "usage: ws-testee server <loopback-addr> [write-chunk] | ws-testee serve <loopback-addr> <sessions> | ws-testee client <loopback-addr> <target> <host> <message> [ping-hex|-] [write-chunk] | ws-testee autobahn-client <loopback-addr> <host> <agent> [first last]"
            );
            EXIT_USAGE
        }
    };
    exit(code);
}

/// Decodes an even-length lowercase/uppercase hex payload argument.
fn parse_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        out.push(u8::try_from(high * 16 + low).expect("two hex digits fit a byte"));
    }
    Some(out)
}

/// Applies an optional positional write-chunk argument to the bounds.
fn apply_write_chunk(bounds: &mut IoBounds, argument: Option<&String>) -> bool {
    match argument {
        None => true,
        Some(text) => match text.parse::<usize>() {
            Ok(chunk) if chunk > 0 => {
                bounds.write_chunk = chunk;
                true
            }
            _ => false,
        },
    }
}

fn server(arguments: &[String]) -> i32 {
    if arguments.is_empty() || arguments.len() > 2 {
        eprintln!("usage-error");
        return EXIT_USAGE;
    }
    let Ok(address) = arguments[0].parse::<SocketAddr>() else {
        eprintln!("usage-error");
        return EXIT_USAGE;
    };
    let mut bounds = IoBounds::default();
    if !apply_write_chunk(&mut bounds, arguments.get(1)) {
        eprintln!("usage-error");
        return EXIT_USAGE;
    }
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
        bounds,
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

fn serve(arguments: &[String]) -> i32 {
    if arguments.len() != 2 {
        eprintln!("usage-error");
        return EXIT_USAGE;
    }
    let Ok(address) = arguments[0].parse::<SocketAddr>() else {
        eprintln!("usage-error");
        return EXIT_USAGE;
    };
    let sessions = match arguments[1].parse::<u64>() {
        Ok(count) if count > 0 => count,
        _ => {
            eprintln!("usage-error");
            return EXIT_USAGE;
        }
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
        config: autobahn_config(),
        bounds: IoBounds::default(),
    };
    let mut reported = 0_u64;
    let outcome = run_server_sessions(&listener, &fixture, sessions, &mut |index, report| {
        reported = index;
        println!("session={index} {}", report.summary());
    });
    match outcome {
        Ok(()) => {
            println!("served={reported}");
            EXIT_OK
        }
        Err(outcome) => {
            println!("setup={outcome:?} served={reported}");
            EXIT_SETUP
        }
    }
}

/// `autobahn-client <loopback-addr> <host> <agent> [first last]`: the
/// fuzzingserver-mode CLIENT agent (US-019 AC3).
///
/// Prints one deterministic line per case plus a terminal summary, all read
/// from the real connection reports. The EXIT CODE reports only whether the
/// HARNESS ran: a case ending in a typed protocol failure is the correct
/// outcome for the cases that provoke one and never fails this process. The
/// conformance verdict is wstest's own report, read separately.
fn autobahn_client(arguments: &[String]) -> i32 {
    if arguments.len() != 3 && arguments.len() != 5 {
        eprintln!("usage-error");
        return EXIT_USAGE;
    }
    let Ok(address) = arguments[0].parse::<SocketAddr>() else {
        eprintln!("usage-error");
        return EXIT_USAGE;
    };
    let (host, agent) = (&arguments[1], &arguments[2]);
    if !ws_testee::valid_agent_name(agent) {
        eprintln!("usage-error");
        return EXIT_USAGE;
    }
    let range = if arguments.len() == 5 {
        match (arguments[3].parse::<u32>(), arguments[4].parse::<u32>()) {
            (Ok(first), Ok(last)) if first >= 1 && last >= first => Some((first, last)),
            _ => {
                eprintln!("usage-error");
                return EXIT_USAGE;
            }
        }
    } else {
        None
    };
    let fixture = AgentFixture {
        address,
        host,
        agent,
        config: autobahn_config(),
        bounds: IoBounds::default(),
    };
    // Step 1: read the suite's own selected-case count, and ALWAYS print
    // that connection's report — a suite-side refusal (a rejected Host
    // header, a failed upgrade) shows up here and nowhere else.
    let counted = match ws_testee::fetch_case_count(&fixture) {
        Ok(counted) => counted,
        Err(outcome) => {
            println!("setup={outcome:?}");
            return EXIT_SETUP;
        }
    };
    println!("count-connection={}", counted.report.summary());
    let Some(case_count) = counted.count else {
        println!("setup=NoCaseCount texts={:?}", counted.report.texts);
        return EXIT_SETUP;
    };
    println!("case-count={case_count}");

    // Step 2: run the cases, streaming each result as it completes so a long
    // sweep is observable while it runs.
    let cases = match ws_testee::run_cases(&fixture, case_count, range, &mut |case| {
        println!("case={} {}", case.case, case.report.summary());
    }) {
        Ok(cases) => cases,
        Err(outcome) => {
            println!("setup={outcome:?}");
            return EXIT_SETUP;
        }
    };

    // Step 3: flush the suite's reports.
    let reports = match ws_testee::update_reports(&fixture) {
        Ok(report) => report,
        Err(outcome) => {
            println!("setup={outcome:?}");
            return EXIT_SETUP;
        }
    };
    let sweep = ws_testee::AgentSweep {
        case_count,
        cases,
        reports_updated: reports.outcome == ws_testee::LoopOutcome::Terminal,
    };
    println!("reports-connection={}", reports.summary());
    println!(
        "ran={} terminal={} protocol-failures={} harness-faults={} reports-updated={}",
        sweep.cases.len(),
        sweep.terminal(),
        sweep.protocol_failures(),
        sweep.harness_faults(),
        sweep.reports_updated,
    );
    if sweep.harness_faults() == 0 && sweep.reports_updated {
        EXIT_OK
    } else {
        EXIT_UNCLEAN
    }
}

fn client(arguments: &[String]) -> i32 {
    if arguments.len() < 4 || arguments.len() > 6 {
        eprintln!("usage-error");
        return EXIT_USAGE;
    }
    let (address, target, host, message) =
        (&arguments[0], &arguments[1], &arguments[2], &arguments[3]);
    let Ok(address) = address.parse::<SocketAddr>() else {
        eprintln!("usage-error");
        return EXIT_USAGE;
    };
    let ping = match arguments.get(4).map(String::as_str) {
        None | Some("-") => None,
        Some(hex) => match parse_hex(hex) {
            Some(payload) => Some(payload),
            None => {
                eprintln!("usage-error");
                return EXIT_USAGE;
            }
        },
    };
    let mut bounds = IoBounds::default();
    if !apply_write_chunk(&mut bounds, arguments.get(5)) {
        eprintln!("usage-error");
        return EXIT_USAGE;
    }
    let want_pong = ping.is_some();
    let fixture = ClientFixture {
        address,
        config: ConnectionConfig::default(),
        request_target: target,
        host,
        message,
        ping,
        bounds,
    };
    match run_client_once(&fixture) {
        Ok(report) => {
            println!("{}", report.summary());
            let echoed = report.texts.iter().any(|text| text == message);
            let ponged = !want_pong || !report.pongs.is_empty();
            if report.clean() && echoed && ponged {
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
