//! The two-role CLI every control binary shares.
//!
//! Both Autobahn modes are reachable from every control, so one artifact can
//! be scored in either direction without a second build:
//!
//! | subcommand | Autobahn mode | the control's role |
//! |---|---|---|
//! | `serve <loopback-addr> <sessions>` | `wstest --mode fuzzingclient` | SERVER (the suite dials in) |
//! | `client <loopback-addr> <host> <agent>` | `wstest --mode fuzzingserver` | CLIENT agent (the suite listens) |
//!
//! ## What the exit code means (and what it does NOT)
//!
//! The exit code reports only whether this CONTROL ran the sessions it was
//! asked to run. It is never a conformance verdict, and for these artifacts
//! it is emphatically not a pass signal: the negative control exits 0 having
//! failed every case by construction, which is the whole point of it. The
//! discrimination verdict is wstest's own report, read separately.

use std::net::{SocketAddr, TcpListener};

use ws_testee::LoopOutcome;

use crate::inert::{InertBounds, run_inert_agent_attempts, serve_inert_sessions};
use crate::mutant::{
    Mutant, MutantAgentFixture, MutantServerFixture, mutant_fetch_case_count,
    mutant_update_reports, run_mutant_cases, run_mutant_server_sessions,
};
use crate::{NEGATIVE_CONTROL_BINARY, autobahn_config};

/// The control ran everything it was asked to run.
pub const EXIT_OK: i32 = 0;
/// The control ran, but some session did not reach a real outcome (a harness
/// fault, never a conformance verdict).
pub const EXIT_UNCLEAN: i32 = 1;
/// The arguments could not be used.
pub const EXIT_USAGE: i32 = 2;
/// The control could not be set up (bind, connect, loopback refusal).
pub const EXIT_SETUP: i32 = 3;

/// Parses the shared `serve` arguments: a loopback address and a positive
/// session count.
fn parse_serve(arguments: &[String]) -> Option<(SocketAddr, u64)> {
    if arguments.len() != 2 {
        return None;
    }
    let address = arguments[0].parse::<SocketAddr>().ok()?;
    let sessions = arguments[1]
        .parse::<u64>()
        .ok()
        .filter(|count| *count > 0)?;
    Some((address, sessions))
}

/// Binds the control's listener, printing the same `listening <addr>` line
/// the shipped adapter prints so the harness can wait on it identically.
fn bind_listener(address: SocketAddr) -> Result<TcpListener, i32> {
    if ws_testee::loopback_only(&address).is_err() {
        println!("setup=non-loopback-refused");
        return Err(EXIT_SETUP);
    }
    let listener = TcpListener::bind(address).map_err(|error| {
        println!("setup=bind-failed kind={:?}", error.kind());
        EXIT_SETUP
    })?;
    match listener.local_addr() {
        Ok(bound) => println!("listening {bound}"),
        Err(error) => {
            println!("setup=local-addr-failed kind={:?}", error.kind());
            return Err(EXIT_SETUP);
        }
    }
    Ok(listener)
}

/// Entry point for the empty/stub negative control binary.
///
/// `arguments` is the whole `argv`; `arguments[0]` is the program name.
#[must_use]
pub fn run_negative_control(arguments: &[String]) -> i32 {
    match arguments.get(1).map(String::as_str) {
        Some("serve") => negative_control_serve(&arguments[2..]),
        Some("client") => negative_control_client(&arguments[2..]),
        _ => {
            eprintln!(
                "usage: {NEGATIVE_CONTROL_BINARY} serve <loopback-addr> <sessions> | {NEGATIVE_CONTROL_BINARY} client <loopback-addr> <host> <agent>"
            );
            EXIT_USAGE
        }
    }
}

fn negative_control_serve(arguments: &[String]) -> i32 {
    let Some((address, sessions)) = parse_serve(arguments) else {
        eprintln!("usage-error");
        return EXIT_USAGE;
    };
    let listener = match bind_listener(address) {
        Ok(listener) => listener,
        Err(code) => return code,
    };
    let bounds = InertBounds::default();
    let mut served = 0_u64;
    let outcome = serve_inert_sessions(&listener, &bounds, sessions, &mut |index, session| {
        served = index;
        println!("session={index} {}", session.summary());
    });
    match outcome {
        Ok(()) => {
            println!("served={served} handshakes-completed=0");
            EXIT_OK
        }
        Err(setup) => {
            println!("setup={setup:?} served={served}");
            EXIT_SETUP
        }
    }
}

fn negative_control_client(arguments: &[String]) -> i32 {
    if arguments.len() != 3 {
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
    // `host` and `agent` are accepted for CLI parity with the mutants and are
    // echoed back for the run record. They cannot reach the wire: this
    // control sends no bytes at all, so there is no request target to place
    // them in.
    println!("inert-agent host={host} agent={agent} sends-no-bytes=true");
    match run_inert_agent_attempts(address, &InertBounds::default()) {
        Ok(attempts) => {
            for (index, attempt) in attempts.iter().enumerate() {
                println!("attempt={} {}", index + 1, attempt.summary());
            }
            println!("attempts={} handshakes-completed=0", attempts.len());
            EXIT_OK
        }
        Err(setup) => {
            println!("setup={setup:?}");
            EXIT_SETUP
        }
    }
}

/// Entry point shared by every planted-mutant binary.
///
/// `arguments` is the whole `argv`; `arguments[0]` is the program name.
#[must_use]
pub fn run_mutant(mutant: Mutant, arguments: &[String]) -> i32 {
    match arguments.get(1).map(String::as_str) {
        Some("serve") => mutant_serve(mutant, &arguments[2..]),
        Some("client") => mutant_client(mutant, &arguments[2..]),
        _ => {
            let binary = mutant.binary();
            eprintln!(
                "usage: {binary} serve <loopback-addr> <sessions> | {binary} client <loopback-addr> <host> <agent>"
            );
            EXIT_USAGE
        }
    }
}

fn mutant_serve(mutant: Mutant, arguments: &[String]) -> i32 {
    let Some((address, sessions)) = parse_serve(arguments) else {
        eprintln!("usage-error");
        return EXIT_USAGE;
    };
    println!("mutant={} deviation={}", mutant.id(), mutant.deviation());
    let listener = match bind_listener(address) {
        Ok(listener) => listener,
        Err(code) => return code,
    };
    let fixture = MutantServerFixture {
        mutant,
        config: autobahn_config(),
        bounds: ws_testee::IoBounds::default(),
    };
    let mut served = 0_u64;
    let outcome =
        run_mutant_server_sessions(&listener, &fixture, sessions, &mut |index, report| {
            served = index;
            println!("session={index} {}", report.summary());
        });
    match outcome {
        Ok(()) => {
            println!("served={served}");
            EXIT_OK
        }
        Err(setup) => {
            println!("setup={setup:?} served={served}");
            EXIT_SETUP
        }
    }
}

fn mutant_client(mutant: Mutant, arguments: &[String]) -> i32 {
    if arguments.len() != 3 {
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
    println!("mutant={} deviation={}", mutant.id(), mutant.deviation());
    let fixture = MutantAgentFixture {
        mutant,
        address,
        host,
        agent,
        config: autobahn_config(),
        bounds: ws_testee::IoBounds::default(),
    };
    // Step 1: read the suite's OWN selected-case count. Never assumed, never
    // coerced to zero — a sweep that tested nothing must not look like a run.
    let counted = match mutant_fetch_case_count(&fixture) {
        Ok(counted) => counted,
        Err(setup) => {
            println!("setup={setup:?}");
            return EXIT_SETUP;
        }
    };
    println!("count-connection={}", counted.report.summary());
    let Some(selected) = counted.count else {
        println!("setup=NoCaseCount texts={:?}", counted.report.texts);
        return EXIT_SETUP;
    };
    println!("selected-cases={selected}");

    // Step 2: run every selected case with the planted deviation in force.
    let cases = match run_mutant_cases(&fixture, selected, &mut |case| {
        println!("case={} {}", case.case, case.report.summary());
    }) {
        Ok(cases) => cases,
        Err(setup) => {
            println!("setup={setup:?}");
            return EXIT_SETUP;
        }
    };

    // Step 3: flush the suite's reports so the failures are recorded.
    let reports = match mutant_update_reports(&fixture) {
        Ok(report) => report,
        Err(setup) => {
            println!("setup={setup:?}");
            return EXIT_SETUP;
        }
    };
    println!("reports-connection={}", reports.summary());
    let sweep = ws_testee::AgentSweep {
        case_count: selected,
        cases,
        reports_updated: reports.outcome == LoopOutcome::Terminal,
    };
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
