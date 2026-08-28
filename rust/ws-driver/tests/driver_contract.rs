//! US-017 driver-contract tests: the pull-driven poll contract, FIFO write
//! ordering with partial progress, inbound/command alternation, EOF and
//! shutdown latching, and the exactly-once terminal delivery.
//!
//! Seed provenance: `fuzz-seeds/us017/*.seed` adopted byte-verbatim with
//! attribution from the Codex plane (codex-import 6a7606a, per-file blob
//! identity verified). Each seed names a property, a defect mutation, a
//! bounded schedule, and the counterexample observation; the interpreter
//! below executes the seed's OWN schedule verbs against this driver and
//! asserts the counterexample never occurs. Expectations are re-derived
//! for the ws_core seam (their `StepResult` batch API differs; the
//! properties are seam-independent).

use std::collections::BTreeMap;

use ws_core::config::ConnectionConfig;
use ws_core::{FailureCode, InitialState, LocalCommand, ReadyState, Role, SemanticEvent};
use ws_driver::{
    CommandDisposition, ConnectionDriver, DeferredReason, DriverInput, DriverInputError,
    DriverOutput, InputDisposition, connection_driver_in_state,
};

fn seed_lines(name: &str) -> BTreeMap<String, String> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz-seeds")
        .join(name);
    let body = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("seed {name} must be readable: {err}"));
    body.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let (key, value) = line.split_once('=').expect("seed lines are key=value");
            (key.trim().to_owned(), value.trim().to_owned())
        })
        .collect()
}

/// One deterministic schedule run: the observable trace the seed's
/// counterexample line is checked against.
struct Run {
    driver: ConnectionDriver,
    sender: ws_core::CommandSender,
    /// Bytes the modeled transport accepted, in acceptance order.
    wire: Vec<u8>,
    /// Every surfaced command disposition, in order.
    dispositions: Vec<CommandDisposition>,
    /// Every drained semantic event, in order.
    events: Vec<SemanticEvent>,
    /// Terminal deliveries observed (the property demands exactly one).
    terminals: u64,
}

impl Run {
    fn new() -> Run {
        let (sender, driver) = connection_driver_in_state(
            ConnectionConfig::default(),
            Role::Server,
            InitialState::Open,
        );
        Run {
            driver,
            sender,
            wire: Vec::new(),
            dispositions: Vec::new(),
            events: Vec::new(),
            terminals: 0,
        }
    }

    /// One poll with trace recording; returns the write suffix offered (if
    /// any) WITHOUT accepting it.
    fn poll(&mut self, input: DriverInput<'_>) -> Option<Vec<u8>> {
        let result = self.driver.poll(input);
        if let Some(disposition) = result.command {
            self.dispositions.push(disposition);
        }
        match result.output {
            DriverOutput::Write(suffix) => Some(suffix.to_vec()),
            DriverOutput::Event(event) => {
                self.events.push(event);
                None
            }
            DriverOutput::Terminal(_) => {
                self.terminals += 1;
                None
            }
            DriverOutput::Failure(_) | DriverOutput::Idle => None,
        }
    }

    fn accept_write(&mut self, bytes: usize, suffix: &[u8]) {
        self.wire.extend_from_slice(&suffix[..bytes]);
        let result = self.driver.poll(DriverInput::WriteProgress { bytes });
        assert!(
            matches!(result.input, InputDisposition::Consumed { .. }),
            "in-range write progress must be consumed"
        );
        if let Some(disposition) = result.command {
            self.dispositions.push(disposition);
        }
        if let DriverOutput::Event(event) = result.output {
            self.events.push(event);
        } else if let DriverOutput::Terminal(_) = result.output {
            self.terminals += 1;
        }
    }

    fn exec_verb(&mut self, verb: &str) {
        match verb {
            "open" => {
                assert_eq!(self.driver.state(), ReadyState::Open);
            }
            "enqueue-a" => self.enqueue("a"),
            "enqueue-b" => self.enqueue("b"),
            "wake" => {
                let _ = self.poll(DriverInput::Wake);
            }
            "write-all" => {
                // Drain the currently offered/queued writes to completion.
                while let Some(suffix) = self.poll(DriverInput::Wake) {
                    let len = suffix.len();
                    self.accept_write(len, &suffix);
                }
            }
            "write-partial" => {
                let suffix = self
                    .poll(DriverInput::Wake)
                    .expect("write-partial requires an offered write");
                self.accept_write(1, &suffix);
            }
            "shutdown" => {
                let _ = self.poll(DriverInput::Shutdown);
            }
            "drain" => {
                // Fair drain: poll until a full pass yields Idle with no
                // disposition movement.
                for _ in 0..64 {
                    let before = (self.dispositions.len(), self.events.len(), self.terminals);
                    let offered = self.poll(DriverInput::Wake);
                    if let Some(suffix) = offered {
                        let len = suffix.len();
                        self.accept_write(len, &suffix);
                        continue;
                    }
                    if before == (self.dispositions.len(), self.events.len(), self.terminals) {
                        break;
                    }
                }
            }
            other => panic!("unknown schedule verb {other:?}"),
        }
    }

    fn enqueue(&mut self, text: &str) {
        // lock-sharing property (single-owner): a producer enqueue is pure
        // transport of the command — it must not move ANY protocol
        // observable; only the owner's poll may.
        let actions_before = self.driver.counts().actions;
        let state_before = self.driver.state();
        self.sender
            .try_send(LocalCommand::SendText {
                text: text.to_owned(),
            })
            .expect("bounded enqueue within capacity");
        assert_eq!(
            self.driver.counts().actions,
            actions_before,
            "producer enqueue must not mutate protocol state"
        );
        assert_eq!(self.driver.state(), state_before);
    }
}

fn run_seed(name: &str) -> Run {
    let seed = seed_lines(name);
    let mut run = Run::new();
    for verb in seed["schedule"].split(',') {
        run.exec_verb(verb.trim());
    }
    run
}

fn server_text_frame(text: &str) -> Vec<u8> {
    let mut frame = vec![0x81, u8::try_from(text.len()).expect("short test payload")];
    frame.extend_from_slice(text.as_bytes());
    frame
}

fn applied_texts(run: &Run) -> Vec<String> {
    run.dispositions
        .iter()
        .filter_map(|disposition| match disposition {
            CommandDisposition::Applied(LocalCommand::SendText { text }) => Some(text.clone()),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The six adopted seeds, each asserting its counterexample never occurs
// ---------------------------------------------------------------------------

#[test]
fn seed_write_reorder_fifo_owner_order() {
    let run = run_seed("us017/write-reorder.seed");
    let frame_a = server_text_frame("a");
    let frame_b = server_text_frame("b");
    let mut expected = frame_a;
    expected.extend_from_slice(&frame_b);
    assert_eq!(
        run.wire, expected,
        "counterexample wire-order-b-a must not occur: committed writes drain FIFO"
    );
}

#[test]
fn seed_queue_bypass_no_write_bypass() {
    let run = run_seed("us017/queue-bypass.seed");
    let frame_a = server_text_frame("a");
    let frame_b = server_text_frame("b");
    // The second frame's bytes must never appear before the first frame is
    // complete on the wire.
    let a_end = run
        .wire
        .windows(frame_a.len())
        .position(|window| window == frame_a)
        .expect("frame a completes on the wire")
        + frame_a.len();
    let b_start = run
        .wire
        .windows(frame_b.len())
        .position(|window| window == frame_b)
        .expect("frame b completes on the wire");
    assert!(
        b_start >= a_end,
        "counterexample second-wire-observed-before-first-completes must not occur"
    );
}

#[test]
fn seed_lost_command_accepted_eventual_exactly_once() {
    let run = run_seed("us017/lost-command.seed");
    assert_eq!(
        applied_texts(&run),
        vec!["a".to_owned(), "b".to_owned()],
        "counterexample accepted-not-equal-disposed must not occur"
    );
    assert_eq!(
        run.dispositions.len(),
        2,
        "each accepted command disposed once"
    );
}

#[test]
fn seed_close_race_terminal_after_fair_drain() {
    let run = run_seed("us017/close-race.seed");
    assert_eq!(
        run.terminals, 1,
        "counterexample no-terminal-after-fair-drain must not occur"
    );
    assert_eq!(run.driver.state(), ReadyState::Closed);
}

#[test]
fn seed_duplicate_delivery_terminal_exactly_once() {
    let run = run_seed("us017/duplicate-delivery.seed");
    assert_eq!(
        run.terminals, 1,
        "counterexample terminal-count-two must not occur across repeated drains"
    );
}

#[test]
fn seed_lock_sharing_single_owner() {
    // The per-enqueue assertion inside Run::enqueue is the property check;
    // the schedule simply must complete with the command applied by the
    // OWNER, not the producer.
    let run = run_seed("us017/lock-sharing.seed");
    assert_eq!(applied_texts(&run), vec!["a".to_owned()]);
    assert_eq!(run.terminals, 1);
}

// ---------------------------------------------------------------------------
// Poll-contract details beyond the seeds
// ---------------------------------------------------------------------------

#[test]
fn write_progress_is_validated_exactly() {
    let mut run = Run::new();
    // No offered write: any progress is rejected without mutation.
    let result = run.driver.poll(DriverInput::WriteProgress { bytes: 5 });
    assert_eq!(
        result.input,
        InputDisposition::Rejected(DriverInputError::InvalidWriteProgress {
            attempted: 5,
            remaining: 0,
        })
    );
    // Offer a write, then over-report: rejected with the exact remaining.
    run.enqueue("a");
    let suffix = run.poll(DriverInput::Wake).expect("offered write");
    let result = run.driver.poll(DriverInput::WriteProgress {
        bytes: suffix.len() + 1,
    });
    assert_eq!(
        result.input,
        InputDisposition::Rejected(DriverInputError::InvalidWriteProgress {
            attempted: suffix.len() + 1,
            remaining: suffix.len(),
        })
    );
    // Exact partial progress advances; the next offer is the suffix.
    run.accept_write(1, &suffix);
    let next = run.poll(DriverInput::Wake).expect("suffix still offered");
    assert_eq!(next, suffix[1..].to_vec());
}

#[test]
fn inbound_defers_while_a_write_is_in_flight() {
    let mut run = Run::new();
    run.enqueue("a");
    let _suffix = run.poll(DriverInput::Wake).expect("offered write");
    let ping = [0x89, 0x80, 0x00, 0x00, 0x00, 0x00];
    let result = run.driver.poll(DriverInput::Inbound(&ping));
    assert_eq!(
        result.input,
        InputDisposition::Deferred(DeferredReason::OutputPending),
        "committed wire output delivers before new inbound facts apply"
    );
}

#[test]
fn inbound_yields_one_turn_to_a_queued_command_then_applies() {
    let mut run = Run::new();
    run.enqueue("a");
    let ping = [0x89, 0x80, 0x00, 0x00, 0x00, 0x00];
    // First inbound poll: the fairness turn applies the queued command and
    // defers the identical bytes.
    let result = run.driver.poll(DriverInput::Inbound(&ping));
    assert_eq!(
        result.input,
        InputDisposition::Deferred(DeferredReason::CommandTurn)
    );
    assert!(matches!(
        result.command,
        Some(CommandDisposition::Applied(LocalCommand::SendText { .. }))
    ));
    // Drain the command's write, then the retry consumes the bytes.
    let suffix = run.poll(DriverInput::Wake).expect("command write offered");
    let len = suffix.len();
    run.accept_write(len, &suffix);
    let result = run.driver.poll(DriverInput::Inbound(&ping));
    assert_eq!(
        result.input,
        InputDisposition::Consumed { bytes: ping.len() }
    );
}

#[test]
fn backpressure_defers_the_chunk_without_consuming_it() {
    let config = ConnectionConfig::builder()
        .event_queue_capacity(4)
        .build()
        .expect("valid test config");
    let (_sender, mut driver) =
        connection_driver_in_state(config, Role::Server, InitialState::Open);
    // Two masked pings need more slots than the 4-slot queue offers.
    let chunk = [
        0x89, 0x80, 0x00, 0x00, 0x00, 0x00, 0x89, 0x80, 0x00, 0x00, 0x00, 0x00,
    ];
    let result = driver.poll(DriverInput::Inbound(&chunk));
    assert_eq!(
        result.input,
        InputDisposition::Deferred(DeferredReason::Backpressure)
    );
    assert_eq!(driver.counts().input_bytes, 0, "nothing was consumed");
}

#[test]
fn rejected_command_surfaces_its_typed_failure() {
    let mut run = Run::new();
    run.sender
        .try_send(LocalCommand::SendClose {
            code: 999,
            reason: "bad".to_owned(),
        })
        .expect("enqueue");
    let result = run.driver.poll(DriverInput::Wake);
    let Some(CommandDisposition::Rejected { command, failure }) = result.command else {
        panic!("expected a rejected disposition, got {:?}", result.command);
    };
    assert!(matches!(command, LocalCommand::SendClose { code: 999, .. }));
    assert_eq!(failure.code, FailureCode::JavaInvalidData);
    assert_eq!(failure.close_code, Some(1002));
}

/// BEHAVIOUR CHANGED BY OWNER RULING — disclosed, not quietly rewritten.
///
/// This test was `commands_queued_at_terminal_are_terminal_rejected` and
/// asserted `CommandDisposition::TerminalRejected`, i.e. that the driver
/// disposed a post-terminal command WITHOUT ever calling the core. Owner
/// decision `us017-post-terminal-owner-decision-2026-08-28.json`
/// (`post-terminal-command`) ruled that verdict defective: every
/// post-terminal path must pass through to the core so the refusal that
/// surfaces is the core's own. The `TerminalRejected` variant was removed,
/// so this test could not be left unmodified — its expectation was the
/// behaviour being corrected. The scenario it covers is preserved exactly;
/// only the expectation moved, from a driver-invented verdict to the core's
/// typed `STATE_VIOLATION`.
#[test]
fn commands_queued_at_terminal_are_refused_by_the_core() {
    let mut run = Run::new();
    run.exec_verb("shutdown");
    run.exec_verb("drain");
    assert_eq!(run.terminals, 1);
    run.sender
        .try_send(LocalCommand::SendText {
            text: "late".to_owned(),
        })
        .expect("enqueue after terminal");
    let result = run.driver.poll(DriverInput::Wake);
    let Some(CommandDisposition::Rejected { command, failure }) = result.command else {
        panic!(
            "a post-terminal command must reach the core; got {:?}",
            result.command
        );
    };
    assert_eq!(
        command,
        LocalCommand::SendText {
            text: "late".to_owned()
        },
        "the producer's own command comes back with the disposition"
    );
    assert_eq!(
        failure.code.wire_code(),
        Some("STATE_VIOLATION"),
        "the refusal is the core's typed failure, not a driver-invented one"
    );
    assert!(matches!(result.output, DriverOutput::Idle));
}

#[test]
fn queue_full_returns_the_command_to_the_producer() {
    let config = ConnectionConfig::builder()
        .command_queue_capacity(1)
        .build()
        .expect("valid test config");
    let (sender, _driver) = connection_driver_in_state(config, Role::Server, InitialState::Open);
    sender
        .try_send(LocalCommand::SendText {
            text: "first".to_owned(),
        })
        .expect("capacity 1 admits one command");
    let refused = sender
        .try_send(LocalCommand::SendText {
            text: "second".to_owned(),
        })
        .expect_err("the bounded queue must refuse, never grow");
    assert_eq!(
        refused.command,
        LocalCommand::SendText {
            text: "second".to_owned(),
        },
        "ownership returns to the producer intact"
    );
}

/// Regression (found by the US-017 bounded schedule exploration, minimized
/// reproduction `fuzz-seeds/us017/regressions/eof-backpressure-livelock.seed`):
/// a transport EOF that the core refuses with non-fatal event-queue
/// backpressure must stay latched and be retried after outputs drain —
/// never latched as applied and lost. Before the fix the connection below
/// stayed in `Closing` forever and no terminal was ever delivered.
#[test]
fn eof_refused_by_event_backpressure_is_retried_until_the_core_accepts_it() {
    let config = ConnectionConfig::builder()
        .event_queue_capacity(4)
        .build()
        .expect("valid test config");
    let (sender, mut driver) = connection_driver_in_state(config, Role::Server, InitialState::Open);
    // A local close queues its wire frame plus three semantic events,
    // leaving fewer free event slots than the core's EOF precheck needs.
    sender
        .try_send(LocalCommand::SendClose {
            code: 1000,
            reason: String::new(),
        })
        .expect("enqueue close");
    let applied = driver.poll(DriverInput::Wake);
    assert!(matches!(
        applied.command,
        Some(CommandDisposition::Applied(LocalCommand::SendClose { .. }))
    ));
    let offered = {
        let result = driver.poll(DriverInput::Wake);
        match result.output {
            DriverOutput::Write(suffix) => suffix.to_vec(),
            other => panic!("close frame write expected, got {other:?}"),
        }
    };
    let _ = driver.poll(DriverInput::WriteProgress {
        bytes: offered.len(),
    });
    assert_eq!(driver.state(), ReadyState::Closing);
    // EOF arrives while the event queue is still congested.
    let _ = driver.poll(DriverInput::TransportEof);
    // Fair drain: every poll surfaces at most one queued output, the EOF
    // retry happens on quiescent turns, and the run must converge to the
    // absorbing Closed state with exactly one terminal and NO surfaced
    // failure (the backpressure refusal is the driver's to absorb).
    let mut terminals = 0;
    for _ in 0..32 {
        let result = driver.poll(DriverInput::Wake);
        match result.output {
            DriverOutput::Terminal(_) => terminals += 1,
            DriverOutput::Failure(failure) => {
                panic!("no failure may surface for a retried EOF: {failure:?}")
            }
            _ => {}
        }
        if terminals == 1 {
            break;
        }
    }
    assert_eq!(terminals, 1, "the retried EOF converges to one terminal");
    assert_eq!(driver.state(), ReadyState::Closed);
    let close = driver.close_detail().expect("governing close detail");
    assert_eq!(close.code, 1000, "the local close governs the EOF (Q20)");
}

/// AC2 receiver-drop stance, made explicit: the `ws_core` bounded channel
/// has no disconnect signal BY DESIGN (batch-C receipt; producer lifecycle
/// belongs to the embedding adapter), so after the owner half drops, a
/// producer's `try_send` keeps its bounded typed behavior — accepted up to
/// the fixed capacity, then `CommandRefused` with the command returned
/// intact. Nothing blocks, grows, or panics.
#[test]
fn receiver_drop_keeps_try_send_bounded_and_typed() {
    let config = ConnectionConfig::builder()
        .command_queue_capacity(1)
        .build()
        .expect("valid test config");
    let (sender, driver) = connection_driver_in_state(config, Role::Server, InitialState::Open);
    drop(driver);
    sender
        .try_send(LocalCommand::SendText {
            text: "into-the-void".to_owned(),
        })
        .expect("capacity admits one command even with the owner gone");
    let refused = sender
        .try_send(LocalCommand::SendText {
            text: "beyond-capacity".to_owned(),
        })
        .expect_err("the bounded queue refuses, never grows");
    assert_eq!(
        refused.command,
        LocalCommand::SendText {
            text: "beyond-capacity".to_owned(),
        },
        "ownership returns to the producer intact"
    );
    assert_eq!(
        refused.reason,
        ws_core::connection::CommandRefusalReason::Full,
        "the refusal is the explicit typed backpressure, not a hang"
    );
}

#[test]
fn transport_eof_reaches_the_core_q20_vocabulary() {
    let mut run = Run::new();
    let _ = run.poll(DriverInput::TransportEof);
    run.exec_verb("drain");
    assert_eq!(run.terminals, 1);
    let close = run.driver.close_detail().expect("eof close detail");
    assert_eq!(close.code, 1006);
    assert!(!close.remote);
    assert_eq!(run.driver.state(), ReadyState::Closed);
}

// ---------------------------------------------------------------------------
// Post-terminal input paths (owner decision
// us017-post-terminal-owner-decision-2026-08-28.json, sha b52d244b,
// decisions `post-terminal-inbound` and `post-terminal-command`).
//
// The eof-after-closed defect had two siblings, both gated on
// `terminal_delivered`: inbound bytes were reported Consumed while the core
// never saw them, and queued commands were disposed TerminalRejected without
// a core call. The owner ruled BOTH must pass through to the core so its own
// typed refusal is what surfaces. These are the regression guards.
// ---------------------------------------------------------------------------

/// Inbound bytes admitted after the once-only terminal MUST reach the core,
/// so the core's `STATE_VIOLATION` for a frame in CLOSED is what the adapter
/// sees. The defect returned `InputDisposition::Consumed { bytes: N }` with
/// an `Idle` output and no core call — reporting success for work never
/// done, which no adapter could detect.
///
/// WHAT THE DEFECT MARKER IS, precisely. This test was first written
/// asserting `!Consumed`, which was a WRONG PROXY: `Consumed` is the
/// CORRECT disposition once the bytes do reach the core and are fatally
/// refused, because the adapter must not retry them — the identical shape
/// the eof-after-closed fix produces. The real marker is the presence of
/// the core's typed refusal on the output. Counting is not a usable marker
/// either: the core refuses a CLOSED-state byte input BEFORE accounting it,
/// so `counts` is unchanged either way (matching `us005.pub.0015`, which
/// live Java reports with input_bytes 0 and consumed_bytes 0). Recorded so
/// the weaker proxies are not reintroduced.
#[test]
fn post_terminal_inbound_reaches_the_core() {
    let mut run = Run::new();
    run.exec_verb("shutdown");
    run.exec_verb("drain");
    assert_eq!(run.terminals, 1, "the terminal is delivered once");
    assert_eq!(run.driver.state(), ReadyState::Closed);

    // A well-formed masked 1-byte binary frame: real bytes a real peer could
    // deliver on a socket that has not yet been torn down.
    let frame = [0x82u8, 0x81, 0x00, 0x00, 0x00, 0x00, 0xA8];
    let result = run.driver.poll(DriverInput::Inbound(&frame));
    let DriverOutput::Failure(surfaced) = result.output else {
        panic!(
            "REGRESSION: post-terminal inbound bytes did not reach the core — the owner \
             reported them consumed and surfaced no refusal (false success defeats detection)"
        );
    };
    assert_eq!(
        surfaced.code.wire_code(),
        Some("STATE_VIOLATION"),
        "the core refuses a frame received in CLOSED"
    );
    assert!(
        matches!(result.input, InputDisposition::Consumed { bytes: 7 }),
        "the bytes were delivered and fatally refused, so they must not be retried"
    );
}

// NOTE: the post-terminal COMMAND guard is
// `commands_queued_at_terminal_are_refused_by_the_core` above — the
// pre-existing test whose expectation the same owner ruling moved. It was
// written RED here first as `post_terminal_command_reaches_the_core` and
// then folded into that test rather than left as a duplicate of it.

/// The once-only terminal stays once-only after both fixes: passing
/// post-terminal work through must not re-arm a second delivery.
#[test]
fn terminal_stays_once_only_after_post_terminal_work() {
    let mut run = Run::new();
    run.exec_verb("shutdown");
    run.exec_verb("drain");
    assert_eq!(run.terminals, 1);

    let frame = [0x82u8, 0x81, 0x00, 0x00, 0x00, 0x00, 0xA8];
    let _ = run.driver.poll(DriverInput::Inbound(&frame));
    run.sender
        .try_send(LocalCommand::SendText {
            text: "late".to_owned(),
        })
        .expect("enqueue after terminal");
    run.exec_verb("drain");
    assert_eq!(
        run.terminals, 1,
        "the terminal is delivered exactly once for the connection's lifetime"
    );
}
