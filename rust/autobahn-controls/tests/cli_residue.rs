//! Residue probes for the two-role control CLI and the mutant identity table.
//!
//! The round-4 US-019 survivor sweep declared "all Rust-side checks" unswept.
//! Sweeping them found that `cli.rs` — the entry point EVERY control binary
//! runs, and therefore the only code the Autobahn harness actually invokes —
//! had no test at all: every argument guard, every dispatch arm and every
//! early return in it survived deletion silently.
//!
//! Every test here is a DISCRIMINATION: with the named line neutralised and no
//! other change it goes red, and it is written against the exit code rather
//! than a printed line, because a test in this process cannot read the
//! control's stdout.
//!
//! Nothing here opens a listening socket or completes a connection. The two
//! addresses used are a refused loopback port (nothing binds port 1 without
//! privilege) and `0.0.0.0:0`, which is refused by the control BEFORE it
//! binds, so the whole file is bounded by connect(2) failing.

use std::io::Read;
use std::net::{Shutdown, SocketAddr, TcpListener};
use std::thread;
use std::time::Duration;

use autobahn_controls::cli::{
    EXIT_OK, EXIT_SETUP, EXIT_UNCLEAN, EXIT_USAGE, run_mutant, run_negative_control,
};
use autobahn_controls::inert::AGENT_PROTOCOL_ATTEMPTS;
use autobahn_controls::mutant::Mutant;
use ws_driver::AutoResponsePolicy;

/// A loopback port nothing can be listening on: binding below 1024 needs
/// privilege this test process does not have, so connect(2) is refused
/// immediately rather than waiting.
const REFUSED: &str = "127.0.0.1:1";
/// Parseable and NOT loopback, which the control must refuse before it binds.
///
/// It is deliberately an address this host CANNOT bind (TEST-NET-1, RFC 5737,
/// assigned to no interface here), so no test in this file can leave a
/// listener blocked in accept(2) — a probe that HANGS when a guard is removed
/// is not a kill, it is a stalled suite.
const NON_LOOPBACK: &str = "192.0.2.1:9";

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_string()).collect()
}

// ---------------------------------------------------------------------------
// cli.rs:80 / cli.rs:158 — the subcommand dispatch.
// ---------------------------------------------------------------------------

#[test]
fn a_control_invoked_with_no_subcommand_reports_a_usage_error() {
    // cli.rs:83 and cli.rs:161 — the `_` arm. Its only observable is the exit
    // code it returns; a control that answered EXIT_OK to an unusable command
    // line would look like a control that ran.
    assert_eq!(
        run_negative_control(&argv(&["us019-negative-control"])),
        EXIT_USAGE
    );
    assert_eq!(
        run_negative_control(&argv(&["us019-negative-control", "not-a-subcommand"])),
        EXIT_USAGE
    );
    for mutant in Mutant::ALL {
        assert_eq!(run_mutant(mutant, &argv(&[mutant.binary()])), EXIT_USAGE);
        assert_eq!(
            run_mutant(mutant, &argv(&[mutant.binary(), "not-a-subcommand"])),
            EXIT_USAGE
        );
    }
}

#[test]
fn the_serve_subcommand_is_dispatched_rather_than_treated_as_unknown() {
    // cli.rs:81 and cli.rs:159 — the `Some("serve")` arms. A well-formed
    // serve command line against a NON-loopback address must reach the
    // control's own loopback refusal (EXIT_SETUP), not the usage arm.
    assert_eq!(
        run_negative_control(&argv(&[
            "us019-negative-control",
            "serve",
            NON_LOOPBACK,
            "1"
        ])),
        EXIT_SETUP
    );
    for mutant in Mutant::ALL {
        assert_eq!(
            run_mutant(
                mutant,
                &argv(&[mutant.binary(), "serve", NON_LOOPBACK, "1"])
            ),
            EXIT_SETUP
        );
    }
}

#[test]
fn the_client_subcommand_is_dispatched_rather_than_treated_as_unknown() {
    // cli.rs:82 and cli.rs:160 — the `Some("client")` arms. A well-formed
    // client command line against a refused address must reach the connect
    // failure (EXIT_SETUP), not the usage arm.
    assert_eq!(
        run_negative_control(&argv(&[
            "us019-negative-control",
            "client",
            REFUSED,
            "localhost",
            "an-agent"
        ])),
        EXIT_SETUP
    );
    for mutant in Mutant::ALL {
        assert_eq!(
            run_mutant(
                mutant,
                &argv(&[mutant.binary(), "client", REFUSED, "localhost", "an-agent"])
            ),
            EXIT_SETUP
        );
    }
}

// ---------------------------------------------------------------------------
// cli.rs:42-52 — parse_serve, and the let-else that consumes it.
// ---------------------------------------------------------------------------

#[test]
fn serve_refuses_an_argument_count_it_cannot_use_instead_of_indexing_past_it() {
    // cli.rs:43 — `arguments.len() != 2`. The address here PARSES, so with
    // the length guard gone the very next line indexes `arguments[1]` on a
    // one-element slice and the control panics instead of reporting usage.
    assert_eq!(
        run_negative_control(&argv(&["us019-negative-control", "serve", REFUSED])),
        EXIT_USAGE
    );
    assert_eq!(
        run_mutant(
            Mutant::NoEcho,
            &argv(&[Mutant::NoEcho.binary(), "serve", REFUSED])
        ),
        EXIT_USAGE
    );
}

#[test]
fn serve_refuses_a_session_count_of_zero() {
    // cli.rs:50 — `.filter(|count| *count > 0)`. A control asked to serve
    // zero sessions would exit 0 having done nothing, which is exactly the
    // "a sweep that tested nothing must not look like a run" failure the
    // rest of this crate is built to refuse.
    assert_eq!(
        run_negative_control(&argv(&["us019-negative-control", "serve", REFUSED, "0"])),
        EXIT_USAGE
    );
}

#[test]
fn a_well_formed_serve_command_line_is_not_reported_as_a_usage_error() {
    // cli.rs:93 and cli.rs:172 — the `let ... else` that consumes
    // parse_serve. If that binding could never succeed, every serve
    // invocation would report a usage error and no control could ever run.
    // The observable that separates the two is EXIT_SETUP: the control got
    // past its argument parsing and refused the ADDRESS.
    let code = run_negative_control(&argv(&[
        "us019-negative-control",
        "serve",
        NON_LOOPBACK,
        "1",
    ]));
    assert_eq!(
        code, EXIT_SETUP,
        "a serve command line the control can use must reach the address check; \
         EXIT_USAGE here means parse_serve never succeeds for anything"
    );
    assert_ne!(code, EXIT_USAGE);
}

// ---------------------------------------------------------------------------
// cli.rs:97-100 / 177-180 — the bind_listener result match.
// ---------------------------------------------------------------------------

#[test]
fn a_setup_failure_while_binding_is_propagated_rather_than_reported_as_success() {
    // cli.rs:99 and cli.rs:179 — `Err(code) => return code`. Swallowing the
    // setup code would make a control that never bound a listener exit 0,
    // and an exit-0 control is indistinguishable from one that served.
    for code in [
        run_negative_control(&argv(&[
            "us019-negative-control",
            "serve",
            NON_LOOPBACK,
            "1",
        ])),
        run_mutant(
            Mutant::OpcodeSwap,
            &argv(&[Mutant::OpcodeSwap.binary(), "serve", NON_LOOPBACK, "1"]),
        ),
    ] {
        assert_eq!(code, EXIT_SETUP);
        assert_ne!(code, EXIT_OK);
        assert_ne!(code, EXIT_UNCLEAN);
    }
}

// ---------------------------------------------------------------------------
// cli.rs:119-137 / 204-217 — the client argument surface.
// ---------------------------------------------------------------------------

#[test]
fn client_refuses_an_argument_count_it_cannot_use_instead_of_indexing_past_it() {
    // cli.rs:120 and cli.rs:205 — `arguments.len() != 3`. The address parses,
    // so without the guard the next statement indexes `arguments[1]` and
    // `arguments[2]` on a one-element slice.
    assert_eq!(
        run_negative_control(&argv(&["us019-negative-control", "client", REFUSED])),
        EXIT_USAGE
    );
    assert_eq!(
        run_mutant(
            Mutant::PongSuppressed,
            &argv(&[Mutant::PongSuppressed.binary(), "client", REFUSED])
        ),
        EXIT_USAGE
    );
}

#[test]
fn client_refuses_an_agent_name_that_could_forge_a_request_target() {
    // cli.rs:129 and cli.rs:214 — `!valid_agent_name(agent)`. The name is
    // interpolated into the query string, so a name carrying `&` selects a
    // different case or report scope. Without the guard the control connects
    // and the forged target reaches the suite; the exit code separates the
    // two because the connect is refused (EXIT_SETUP), not usage.
    for forged in ["", "an agent", "a&agent=1", "a/agent", "a#agent", "a%41"] {
        assert_eq!(
            run_negative_control(&argv(&[
                "us019-negative-control",
                "client",
                REFUSED,
                "localhost",
                forged
            ])),
            EXIT_USAGE,
            "agent name {forged:?} must be refused before any connect"
        );
        assert_eq!(
            run_mutant(
                Mutant::PayloadTruncate,
                &argv(&[
                    Mutant::PayloadTruncate.binary(),
                    "client",
                    REFUSED,
                    "localhost",
                    forged
                ])
            ),
            EXIT_USAGE,
            "agent name {forged:?} must be refused before any connect"
        );
    }
}

#[test]
fn client_refuses_an_unparseable_address_but_accepts_a_parseable_one() {
    // cli.rs:124 and cli.rs:209 — the `let Ok(address) = ... else`. Both
    // directions are asserted: a name that is not an address is a usage
    // error, and one that IS an address must get PAST the parse to the
    // connect. Without the second half a binding that always failed would
    // look correct.
    assert_eq!(
        run_negative_control(&argv(&[
            "us019-negative-control",
            "client",
            "not-an-address",
            "localhost",
            "an-agent"
        ])),
        EXIT_USAGE
    );
    assert_eq!(
        run_negative_control(&argv(&[
            "us019-negative-control",
            "client",
            REFUSED,
            "localhost",
            "an-agent"
        ])),
        EXIT_SETUP
    );
    assert_eq!(
        run_mutant(
            Mutant::NoEcho,
            &argv(&[
                Mutant::NoEcho.binary(),
                "client",
                "not-an-address",
                "localhost",
                "an-agent"
            ])
        ),
        EXIT_USAGE
    );
}

#[test]
fn a_mutant_client_that_cannot_reach_the_suite_reports_setup_not_success() {
    // cli.rs:233 — `return EXIT_SETUP;` in the case-count arm. A mutant that
    // never reached the suite must not exit 0: an exit-0 mutant run is read
    // as "the deviation was carried and scored", which is the exact
    // substitution the AC4 calibration exists to prevent.
    for mutant in Mutant::ALL {
        let code = run_mutant(
            mutant,
            &argv(&[mutant.binary(), "client", REFUSED, "localhost", "an-agent"]),
        );
        assert_eq!(
            code,
            EXIT_SETUP,
            "{} must report setup failure",
            mutant.id()
        );
        assert_ne!(code, EXIT_OK);
    }
}

// ---------------------------------------------------------------------------
// mutant.rs:81-124 — the three per-variant tables.
// ---------------------------------------------------------------------------

#[test]
fn every_mutant_variant_carries_its_own_identity() {
    // mutant.rs:82-85. `manifest.rs` asserts only that each returned id is
    // PRESENT in manifest.json, so two variants returning the same id — or
    // returning each other's — satisfies it. This binds each arm to its own
    // variant and requires the four to be distinct.
    assert_eq!(Mutant::NoEcho.id(), "us019-mutant-no-echo");
    assert_eq!(Mutant::OpcodeSwap.id(), "us019-mutant-opcode-swap");
    assert_eq!(
        Mutant::PayloadTruncate.id(),
        "us019-mutant-payload-truncate"
    );
    assert_eq!(Mutant::PongSuppressed.id(), "us019-mutant-pong-suppressed");
    let mut ids: Vec<&str> = Mutant::ALL.iter().map(|mutant| mutant.id()).collect();
    ids.sort_unstable();
    let count = ids.len();
    ids.dedup();
    assert_eq!(
        ids.len(),
        count,
        "two mutants sharing one id would calibrate the suite against the wrong artifact"
    );
    for mutant in Mutant::ALL {
        assert_eq!(mutant.binary(), mutant.id());
    }
}

#[test]
fn every_mutant_variant_states_its_own_deviation() {
    // mutant.rs:102-107. The deviation sentence is what the manifest
    // publishes as the single planted difference; an arm that returned
    // another arm's sentence would mis-describe what a scoring difference is
    // attributable to.
    assert_eq!(
        Mutant::NoEcho.deviation(),
        "delivered messages are never re-sent"
    );
    assert_eq!(
        Mutant::OpcodeSwap.deviation(),
        "text is echoed as binary and binary as text"
    );
    assert_eq!(
        Mutant::PayloadTruncate.deviation(),
        "the final byte of every non-empty echoed payload is dropped"
    );
    assert_eq!(
        Mutant::PongSuppressed.deviation(),
        "inbound pings are never answered"
    );
    let mut said: Vec<&str> = Mutant::ALL
        .iter()
        .map(|mutant| mutant.deviation())
        .collect();
    said.sort_unstable();
    let count = said.len();
    said.dedup();
    assert_eq!(
        said.len(),
        count,
        "each mutant must state its OWN deviation"
    );
}

#[test]
fn only_the_pong_suppressed_mutant_disables_the_shipped_auto_response() {
    // mutant.rs:119-122. This is the one deviation that lives in the DRIVER
    // rather than in the message policy, so a wrong arm here moves a
    // deviation onto a mutant that is supposed to be indistinguishable from
    // the real port on ping/pong.
    assert_eq!(
        Mutant::PongSuppressed.auto_response(),
        AutoResponsePolicy::Disabled
    );
    for mutant in [Mutant::NoEcho, Mutant::OpcodeSwap, Mutant::PayloadTruncate] {
        assert_eq!(
            mutant.auto_response(),
            AutoResponsePolicy::PongInboundPing,
            "{} must carry the shipped-Java listener default",
            mutant.id()
        );
    }
}

// ---------------------------------------------------------------------------
// cli.rs:107-116 / 138-150 — the run-outcome arms, over a real loopback
// session. These are the only tests in this file that transact.
// ---------------------------------------------------------------------------

/// Accepts `count` raw loopback connections and drains each one, so the
/// control's own session bounds are what end them.
fn raw_acceptor(count: usize) -> (SocketAddr, thread::JoinHandle<usize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral loopback bind");
    let address = listener.local_addr().expect("bound address");
    let handle = thread::spawn(move || {
        let mut accepted = 0usize;
        for _ in 0..count {
            let Ok((mut stream, _peer)) = listener.accept() else {
                break;
            };
            accepted += 1;
            let _ = stream.set_read_timeout(Some(Duration::from_millis(2)));
            let mut buffer = [0u8; 1024];
            // Drain whatever arrives (nothing: the control writes no bytes)
            // until the control's own linger ends the session and it hangs up.
            for _ in 0..512 {
                match stream.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(_) => {}
                }
            }
            let _ = stream.shutdown(Shutdown::Both);
        }
        accepted
    });
    (address, handle)
}

#[test]
fn an_inert_client_run_that_completes_every_attempt_reports_success() {
    // cli.rs:139-144 — the `Ok(attempts)` arm of the inert client's run. Its
    // exit code is the only thing a harness reads, and a completed control
    // run must be EXIT_OK: the negative control exits 0 having failed every
    // conformance case by construction, which is the whole point of it.
    // Reporting EXIT_SETUP here would make the control look like a control
    // that never ran, and an absent run cannot discriminate anything.
    // Exactly the number of attempts the control makes: an acceptor waiting
    // for one more connection than the control opens would block in accept(2)
    // for ever, and a probe that HANGS when a guard is removed is not a kill.
    let (address, acceptor) = raw_acceptor(AGENT_PROTOCOL_ATTEMPTS);
    let code = run_negative_control(&argv(&[
        "us019-negative-control",
        "client",
        &address.to_string(),
        "localhost",
        "an-agent",
    ]));
    let accepted = acceptor.join().expect("acceptor thread");
    assert_eq!(
        code, EXIT_OK,
        "a control that completed all of its connection attempts must exit 0; \
         accepted={accepted}"
    );
    assert!(
        accepted > 0,
        "the probe must actually have transacted, or the arm under test was never reached"
    );
}
