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
    DriverOutput, FailureOrigin, InputDisposition, connection_driver_in_state,
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
    /// Typed dropped-write dispositions observed, in order (US-017 AC2).
    dropped_writes: Vec<ws_driver::DroppedWrites>,
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
            dropped_writes: Vec::new(),
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
            DriverOutput::WritesDropped(dropped) => {
                self.dropped_writes.push(dropped);
                None
            }
            DriverOutput::Failure { .. } | DriverOutput::Idle => None,
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

/// The chunk both arms feed: two masked, empty-payload pings.
const TWO_MASKED_PINGS: [u8; 12] = [
    0x89, 0x80, 0x00, 0x00, 0x00, 0x00, 0x89, 0x80, 0x00, 0x00, 0x00, 0x00,
];

fn driver_with_event_capacity(capacity: u64) -> ConnectionDriver {
    let config = ConnectionConfig::builder()
        .event_queue_capacity(capacity)
        .build()
        .expect("valid test config");
    let (_sender, driver) = connection_driver_in_state(config, Role::Server, InitialState::Open);
    driver
}

#[test]
fn backpressure_defers_the_chunk_without_consuming_it() {
    // The core commits `input_bytes` only AFTER its backpressure precheck
    // (ws-core/src/connection.rs: "the precheck must precede all mutation"),
    // so a deferred chunk must leave the counter alone and stay retryable.
    let mut driver = driver_with_event_capacity(4);
    let result = driver.poll(DriverInput::Inbound(&TWO_MASKED_PINGS));
    assert_eq!(
        result.input,
        InputDisposition::Deferred(DeferredReason::Backpressure)
    );
    assert_eq!(driver.counts().input_bytes, 0, "nothing was consumed");
}

/// PAIRED POSITIVE CONTROL for the assertion above.
///
/// `input_bytes` is 0 on a freshly built driver, so "still 0 after a deferred
/// chunk" passes whether the deferral protected the counter or the counter
/// simply never moves in this fixture. Nothing else in this crate ever
/// asserts `input_bytes` NON-zero, so without this arm the guard could not
/// tell a working precheck from a dead counter.
///
/// Same constructor, same chunk, only the event-queue capacity changes: at 10
/// slots the identical bytes ARE admitted and the counter DOES move to the
/// full chunk length.
///
/// The capacity is MEASURED, not reasoned about — the first draft of this
/// control guessed 8 and failed, because the two-ping chunk still defers
/// there. Sweeping the fixture gives Deferred at 4/6/8 and
/// `Consumed { bytes: 12 }` with `input_bytes = 12` from 10 upward, so 10 is
/// the smallest capacity that makes this a true positive control.
#[test]
fn an_admitted_chunk_does_move_the_input_counter() {
    let mut driver = driver_with_event_capacity(10);
    assert_eq!(
        driver.counts().input_bytes,
        0,
        "precondition: the counter starts at zero, as it does in the deferred arm"
    );
    let result = driver.poll(DriverInput::Inbound(&TWO_MASKED_PINGS));
    assert_eq!(
        result.input,
        InputDisposition::Consumed {
            bytes: TWO_MASKED_PINGS.len()
        },
        "capacity 10 admits what capacity 4 defers"
    );
    assert_eq!(
        driver.counts().input_bytes,
        TWO_MASKED_PINGS.len() as u64,
        "the counter is live: a consumed chunk moves it, so the zero in the \
         deferred arm is the precheck's doing and not a dead observable"
    );
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
///
/// SECOND OWNER RULING, SAME PATTERN, ALSO DISCLOSED. The final assertion
/// used to read `matches!(result.output, DriverOutput::Idle)`. Owner
/// decision `us017-post-failure-owner-decisions-2026-08-28.json`
/// (`c5-fatal-command-rejection-surfaces-failure`) ruled exactly that
/// `Idle` defective: `STATE_VIOLATION` is fatal, it poisons the core, and a
/// fatal must surface as a `DriverOutput::Failure` however it arrived. The
/// old assertion encoded the ruled-defective behaviour, so leaving it would
/// have pinned the defect rather than the contract. The scenario is again
/// untouched and the expectation is STRICTLY STRONGER than the one it
/// replaces: it now demands the surfaced failure carry the SAME verdict as
/// the disposition, which `Idle` asserted nothing about.
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
    let DriverOutput::Failure {
        failure: surfaced,
        origin,
    } = result.output
    else {
        panic!(
            "a post-terminal command refused with a FATAL STATE_VIOLATION must surface a \
             DriverOutput::Failure, not stay silent"
        );
    };
    assert_eq!(
        origin,
        FailureOrigin::LocalCommand,
        "a refused COMMAND is not an inbound decode violation"
    );
    assert_eq!(
        surfaced.code, failure.code,
        "the surfaced failure is the same verdict the disposition carries"
    );
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
            DriverOutput::Failure { failure, .. } => {
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
    // US-017 story review BLOCKING-1 (session 01a04626): the prior pin
    // asserted "capacity admits one command even with the owner gone" —
    // an ACCEPTED send into a queue no owner will ever drain. AC2 requires
    // receiver-drop to have EXPLICIT TYPED BEHAVIOR and not to leak, so
    // acceptance is exactly what must NOT happen: `Ok(())` is a promise
    // the driver seam can no longer keep.
    let refused = sender
        .try_send(LocalCommand::SendText {
            text: "into-the-void".to_owned(),
        })
        .expect_err("a send after the sole owner is dropped must never report accepted");
    assert_eq!(
        refused.reason,
        ws_core::connection::CommandRefusalReason::ReceiverDropped,
        "the receiver-drop outcome is its own typed disposition, not queue-full backpressure"
    );
    assert_eq!(
        refused.command,
        LocalCommand::SendText {
            text: "into-the-void".to_owned(),
        },
        "ownership returns to the producer intact"
    );
    // Terminal and stable: it never degrades into Full (the queue stays
    // empty because nothing was ever admitted) and never blocks.
    let again = sender
        .try_send(LocalCommand::SendText {
            text: "beyond-capacity".to_owned(),
        })
        .expect_err("the refusal is terminal for this channel");
    assert_eq!(
        again.reason,
        ws_core::connection::CommandRefusalReason::ReceiverDropped,
    );
    // Every surviving clone sees the same typed outcome: the drop is a
    // property of the channel, not of one handle.
    let clone = sender.clone();
    let cloned_refusal = clone
        .try_send(LocalCommand::SendPing { data: Vec::new() })
        .expect_err("clones observe the dropped receiver too");
    assert_eq!(
        cloned_refusal.reason,
        ws_core::connection::CommandRefusalReason::ReceiverDropped,
    );
}

/// The receiver-drop disposition must not swallow the queue-full one: with
/// the owner ALIVE, a full bounded queue still refuses with `Full` (US-017
/// AC2 queue-full arm, unchanged by BLOCKING-1).
#[test]
fn a_live_owner_still_refuses_a_full_queue_with_the_full_reason() {
    let config = ConnectionConfig::builder()
        .command_queue_capacity(1)
        .build()
        .expect("valid test config");
    let (sender, driver) = connection_driver_in_state(config, Role::Server, InitialState::Open);
    sender
        .try_send(LocalCommand::SendText {
            text: "first".to_owned(),
        })
        .expect("capacity admits one command while the owner is alive");
    let refused = sender
        .try_send(LocalCommand::SendText {
            text: "second".to_owned(),
        })
        .expect_err("the bounded queue refuses, never grows");
    assert_eq!(
        refused.reason,
        ws_core::connection::CommandRefusalReason::Full,
        "a live owner's full queue is backpressure, not receiver-drop"
    );
    drop(driver);
}

#[test]
fn transport_eof_reaches_the_core_q20_vocabulary() {
    let mut run = Run::new();
    let _ = run.poll(DriverInput::TransportEof);
    run.exec_verb("drain");
    assert_eq!(run.terminals, 1);
    let close = run.driver.close_detail().expect("eof close detail");
    assert_eq!(close.code, 1006);
    // `remote` is a live two-valued observable, not a field that is always
    // false: the same core sets it TRUE for a closing-state EOF
    // (ws-core/tests/core_semantics.rs, "closing-state EOF echoes
    // remote=true"). The driver returns the core's `CloseDetail` verbatim,
    // so that is this assertion's positive control.
    assert!(
        !close.remote,
        "an open-state EOF is a local close, not a remote one"
    );
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
    let DriverOutput::Failure {
        failure: surfaced,
        origin,
    } = result.output
    else {
        panic!(
            "REGRESSION: post-terminal inbound bytes did not reach the core — the owner \
             reported them consumed and surfaced no refusal (false success defeats detection)"
        );
    };
    assert_eq!(
        origin,
        FailureOrigin::InboundDecode,
        "these were inbound bytes"
    );
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

/// A REPEATED transport EOF is a SCORED EVENT, not an idempotent transport
/// fact the owner may absorb (owner decision
/// `us017-repeated-eof-owner-decision-2026-08-28.json`, sha f6270948, which
/// AMENDS the earlier bd7849c3 decision's retention of the `eof_applied`
/// latch). The core's own state machine already answers a repeated EOF —
/// `handle_eof` counts the action and refuses with `STATE_VIOLATION`, which
/// live Java reports as "eof repeated in CLOSED state" — so at-most-once
/// APPLICATION was the wrong invariant to protect at the driver layer.
#[test]
fn repeated_transport_eof_reaches_the_core() {
    let mut run = Run::new();
    let _ = run.poll(DriverInput::TransportEof);
    run.exec_verb("drain");
    assert_eq!(run.driver.state(), ReadyState::Closed);
    assert_eq!(run.terminals, 1, "the first EOF converges cleanly");
    assert_eq!(
        run.driver.counts().actions,
        1,
        "the first EOF counted its action"
    );

    let result = run.driver.poll(DriverInput::TransportEof);
    let DriverOutput::Failure {
        failure: surfaced,
        origin,
    } = result.output
    else {
        panic!(
            "REGRESSION: the owner absorbed a repeated transport EOF instead of handing it \
             to the core (the eof latch skipped the core call)"
        );
    };
    assert_eq!(
        origin,
        FailureOrigin::TransportEof,
        "an EOF refusal is not an inbound decode violation"
    );
    assert_eq!(
        surfaced.code.wire_code(),
        Some("STATE_VIOLATION"),
        "the core refuses a repeated EOF in CLOSED"
    );
    assert_eq!(
        run.driver.counts().actions,
        2,
        "the core saw the second EOF and counted its action too"
    );
}

/// `Shutdown` arriving after an EOF was already applied inherits the same
/// fix: it latches the same protocol EOF, so it must reach the core too.
#[test]
fn shutdown_after_applied_eof_reaches_the_core() {
    let mut run = Run::new();
    let _ = run.poll(DriverInput::TransportEof);
    run.exec_verb("drain");
    assert_eq!(run.driver.counts().actions, 1);

    let result = run.driver.poll(DriverInput::Shutdown);
    let DriverOutput::Failure {
        failure: surfaced,
        origin,
    } = result.output
    else {
        panic!("REGRESSION: shutdown-after-applied-EOF was absorbed instead of reaching the core");
    };
    assert_eq!(origin, FailureOrigin::TransportEof);
    assert_eq!(surfaced.code.wire_code(), Some("STATE_VIOLATION"));
    assert_eq!(run.driver.counts().actions, 2);
}

/// Each ADMITTED transport-EOF notification gets its own core call, even
/// when it is admitted in a state where the EOF arm cannot run yet.
///
/// This is the window the fourth sibling audit missed and review
/// 01a04866-df4b-7521-8abe-d8bad09edf38 found: while a write is OFFERED the
/// EOF arm is skipped, so two notifications used to collapse into the same
/// boolean and produce ONE core action after the drain. The earlier
/// four-consecutive-EOF probe only ever exercised notifications that were
/// applied immediately, so it established the per-notification property for
/// the easy path and assumed it for this one.
#[test]
fn every_admitted_eof_notification_gets_its_own_core_call() {
    let mut run = Run::new();
    run.enqueue("a");
    let _ = run.poll(DriverInput::Wake); // apply the command -> queues a write
    let offered = run.poll(DriverInput::Wake);
    assert!(
        offered.is_some(),
        "fixture precondition: a write must be OFFERED so the EOF arm cannot run"
    );
    let actions_before = run.driver.counts().actions;
    assert_eq!(actions_before, 1, "only the send command has been counted");

    // TWO notifications admitted while the arm is unreachable.
    let first = run.driver.poll(DriverInput::TransportEof);
    assert!(matches!(first.input, InputDisposition::Consumed { .. }));
    let second = run.driver.poll(DriverInput::TransportEof);
    assert!(matches!(second.input, InputDisposition::Consumed { .. }));

    run.exec_verb("drain");
    assert_eq!(
        run.driver.counts().actions,
        3,
        "REGRESSION: multiple EOF notifications admitted before the arm could run were \
         collapsed into one core call (1 command + 2 EOF actions expected)"
    );
}

/// A fatal must surface as a `Failure` output no matter which way it
/// arrived (owner decision
/// `us017-post-failure-owner-decisions-2026-08-28.json`, decision
/// `c5-fatal-command-rejection-surfaces-failure`).
///
/// THE DEFECT THIS PINS. A fatal reaches the owner by two routes. The
/// inbound-bytes route returns `finish_poll(.., Some(failure))`, which
/// yields `DriverOutput::Failure`. The COMMAND route returned
/// `Some(CommandDisposition::Rejected { .. })` and then called
/// `finish_poll` with `failure = None`, so `next_output()` ran normally and
/// no `Failure` was ever produced — while `ConnectionCore::handle` had
/// already set `poisoned` on exactly the same failure. Both halt models key
/// on `DriverOutput::Failure` (`ws-testee`'s `io_loop` and the exploration
/// interpreter), so neither halted, and a driver whose core was already
/// poisoned could still go on to deliver a clean `Terminal`.
///
/// `send_close` with code 999 is the fixture because it is a
/// `JAVA_INVALID_DATA` rejection with a real close code, so the test also
/// pins that the surfaced failure carries the SAME code and close code the
/// disposition carries — a `Failure` with a different verdict from the
/// rejection would be a new defect wearing this fix's clothes.
#[test]
fn a_fatal_command_rejection_surfaces_a_failure_output() {
    let mut run = Run::new();
    run.sender
        .try_send(LocalCommand::SendClose {
            code: 999,
            reason: "bad".to_owned(),
        })
        .expect("bounded enqueue within capacity");

    let result = run.driver.poll(DriverInput::Wake);

    let Some(CommandDisposition::Rejected { failure, .. }) = result.command.clone() else {
        panic!("fixture precondition: send_close 999 must be a fatal command rejection");
    };
    assert_eq!(failure.code, FailureCode::JavaInvalidData);
    assert_eq!(failure.close_code, Some(1002));

    let DriverOutput::Failure {
        failure: surfaced,
        origin,
    } = result.output
    else {
        panic!(
            "REGRESSION: a fatal arriving as CommandDisposition::Rejected produced no \
             DriverOutput::Failure, so neither halt model halts on it and the poisoned core \
             can still deliver a clean Terminal"
        );
    };
    assert_eq!(
        surfaced.code, failure.code,
        "the surfaced failure must be the SAME verdict the rejection carries"
    );
    assert_eq!(surfaced.close_code, failure.close_code);
    // THE OTHER HALF OF THIS FIX. Surfacing uniformly is about the HALT.
    // The arrival path must NOT be erased with it: this failure is
    // byte-identical to the one an inbound RSV1 violation produces
    // (JAVA_INVALID_DATA, close code 1002), and the C6 wire reaction is
    // gated on telling them apart. When this assertion was absent, a
    // locally rejected send_close put a 1002 close frame on a real socket.
    assert_eq!(
        origin,
        FailureOrigin::LocalCommand,
        "REGRESSION: a locally rejected command reported the INBOUND DECODE origin, which \
         is what makes C6 answer it with a 1002 close frame Java never sends"
    );
}

/// The companion half: the fatal really did poison the core, so the
/// `Failure` above is reporting a poisoning that already happened rather
/// than inventing a verdict of the driver's own.
#[test]
fn a_fatal_command_rejection_poisons_the_core() {
    let mut run = Run::new();
    run.sender
        .try_send(LocalCommand::SendClose {
            code: 999,
            reason: "bad".to_owned(),
        })
        .expect("bounded enqueue within capacity");
    let _ = run.driver.poll(DriverInput::Wake);

    // A masked, well-formed inbound close frame — legal work on a healthy
    // server core, refused by a poisoned one.
    let result = run
        .driver
        .poll(DriverInput::Inbound(&[0x88, 0x80, 0x00, 0x00, 0x00, 0x00]));
    let DriverOutput::Failure {
        failure: refusal,
        origin,
    } = result.output
    else {
        panic!("the core must refuse further work after a fatal command rejection");
    };
    assert_eq!(refusal.code, FailureCode::StateViolation);
    assert_eq!(origin, FailureOrigin::InboundDecode);
}

/// The same property for `Shutdown`, which latches the same protocol EOF.
#[test]
fn shutdown_and_eof_admitted_together_each_reach_the_core() {
    let mut run = Run::new();
    run.enqueue("a");
    let _ = run.poll(DriverInput::Wake);
    let offered = run.poll(DriverInput::Wake);
    assert!(
        offered.is_some(),
        "fixture precondition: a write is offered"
    );

    let _ = run.driver.poll(DriverInput::TransportEof);
    let _ = run.driver.poll(DriverInput::Shutdown);
    run.exec_verb("drain");
    assert_eq!(
        run.driver.counts().actions,
        3,
        "REGRESSION: an EOF and a Shutdown admitted in the same window collapsed into one \
         core call"
    );
}

// ---------------------------------------------------------------------------
// US-017 story review BLOCKING-2 (session 01a04626): AC2 requires adapter
// shutdown to have EXPLICIT TYPED BEHAVIOR and not to "leak". Writes the
// core has COMMITTED are already promised to the producer (it saw
// `CommandDisposition::Applied`); aborting them with the transport is
// correct, abandoning them SILENTLY is the leak. The driver hands the loss
// back as `DriverOutput::WritesDropped`, ahead of the terminal delivery.
// ---------------------------------------------------------------------------

/// Drain every output after `input`, copying each out of the owner borrow,
/// until `Idle` or a budget stop. Returns the ordered output labels plus
/// any dropped-write report observed.
fn drain_outputs(driver: &mut ConnectionDriver, first: DriverInput<'_>) -> Vec<String> {
    let mut labels = Vec::new();
    let mut input = first;
    for _ in 0..64 {
        let result = driver.poll(input);
        input = DriverInput::Wake;
        match result.output {
            DriverOutput::Idle => {
                labels.push("idle".to_owned());
                if labels.iter().rev().take(2).all(|label| label == "idle") {
                    break;
                }
            }
            DriverOutput::Write(suffix) => labels.push(format!("write:{}", suffix.len())),
            DriverOutput::Event(_) => labels.push("event".to_owned()),
            DriverOutput::Failure { .. } => labels.push("failure".to_owned()),
            DriverOutput::WritesDropped(dropped) => labels.push(format!(
                "writes-dropped:frames={},bytes={},partial_front={}",
                dropped.frames, dropped.bytes, dropped.partial_front
            )),
            DriverOutput::Terminal(_) => {
                labels.push("terminal".to_owned());
                break;
            }
        }
    }
    labels
}

#[test]
fn shutdown_reports_the_partially_drained_committed_write_as_a_typed_drop() {
    let (sender, mut driver) = connection_driver_in_state(
        ConnectionConfig::default(),
        Role::Server,
        InitialState::Open,
    );
    sender
        .try_send(LocalCommand::SendText {
            text: "a1".to_owned(),
        })
        .expect("enqueue");
    // The command is applied and its committed frame is offered.
    let applied = driver.poll(DriverInput::Wake);
    assert!(matches!(
        applied.command,
        Some(CommandDisposition::Applied(_))
    ));
    let DriverOutput::Write(suffix) = applied.output else {
        panic!("the applied command commits a wire write");
    };
    assert_eq!(suffix, server_text_frame("a1").as_slice());
    // One byte reaches the wire; three stay committed-but-undelivered.
    let progressed = driver.poll(DriverInput::WriteProgress { bytes: 1 });
    assert!(matches!(
        progressed.input,
        InputDisposition::Consumed { .. }
    ));

    let labels = drain_outputs(&mut driver, DriverInput::Shutdown);
    assert_eq!(
        labels.first().map(String::as_str),
        Some("writes-dropped:frames=1,bytes=3,partial_front=true"),
        "the abandoned committed suffix is reported, not silently dropped: {labels:?}"
    );
    assert_eq!(
        labels
            .iter()
            .filter(|label| label.starts_with("writes-dropped"))
            .count(),
        1,
        "the dropped-write disposition is delivered exactly once: {labels:?}"
    );
    let dropped_at = labels
        .iter()
        .position(|label| label.starts_with("writes-dropped"))
        .expect("dropped report present");
    let terminal_at = labels
        .iter()
        .position(|label| label == "terminal")
        .expect("shutdown still converges to the terminal");
    assert!(
        dropped_at < terminal_at,
        "no adapter can see the terminal without first seeing the loss: {labels:?}"
    );
    assert!(
        !labels.iter().any(|label| label.starts_with("write:")),
        "a shut-down transport is never offered a write: {labels:?}"
    );
}

#[test]
fn shutdown_reports_an_untouched_committed_write_as_a_whole_frame_drop() {
    // The other reachable polarity of the front write: committed and
    // offered, but not one byte accepted. The whole frame is lost and the
    // peer saw nothing of it, so `partial_front` is false.
    let (sender, mut driver) = connection_driver_in_state(
        ConnectionConfig::default(),
        Role::Server,
        InitialState::Open,
    );
    sender
        .try_send(LocalCommand::SendText {
            text: "a1".to_owned(),
        })
        .expect("enqueue");
    let applied = driver.poll(DriverInput::Wake);
    assert!(matches!(
        applied.command,
        Some(CommandDisposition::Applied(_))
    ));
    assert!(matches!(applied.output, DriverOutput::Write(_)));

    let labels = drain_outputs(&mut driver, DriverInput::Shutdown);
    assert_eq!(
        labels.first().map(String::as_str),
        Some("writes-dropped:frames=1,bytes=4,partial_front=false"),
        "the whole committed frame is reported: {labels:?}"
    );
}

/// The committed-pending-write set at any shutdown instant is bounded at
/// ONE frame by the driver's own structure, and this test pins the reason
/// so the plural accounting in `abort_pending_writes` is not mistaken for
/// a reachable-but-untested path: `next_output` moves a committed write
/// into the offered slot as soon as one exists, and no command, inbound
/// chunk, or EOF is applied while a write is offered. So the core's
/// ordered write stream is empty whenever a write is in flight, and the
/// in-flight write is the only thing a shutdown can abandon.
///
/// A committed write appearing AFTER shutdown would also be a leak; the
/// only post-shutdown input the driver applies is the latched EOF, which
/// emits events and no write. Both halves are asserted here.
#[test]
fn no_committed_write_survives_or_appears_after_the_shutdown_report() {
    let (sender, mut driver) = connection_driver_in_state(
        ConnectionConfig::default(),
        Role::Server,
        InitialState::Open,
    );
    // A close command commits a write AND drives the lifecycle, so the
    // post-shutdown EOF has real work to do on top of the abandoned frame.
    sender
        .try_send(LocalCommand::SendClose {
            code: 1000,
            reason: String::new(),
        })
        .expect("enqueue");
    let applied = driver.poll(DriverInput::Wake);
    assert!(matches!(
        applied.command,
        Some(CommandDisposition::Applied(_))
    ));
    let DriverOutput::Write(suffix) = applied.output else {
        panic!("the close command commits a wire write");
    };
    let committed = suffix.len();
    assert_eq!(committed, 4, "close frame with the constructor payload");

    let labels = drain_outputs(&mut driver, DriverInput::Shutdown);
    assert_eq!(
        labels
            .iter()
            .filter(|label| label.starts_with("writes-dropped"))
            .count(),
        1,
        "exactly one dropped-write report, so no write appeared after it: {labels:?}"
    );
    assert_eq!(
        labels.first().map(String::as_str),
        Some("writes-dropped:frames=1,bytes=4,partial_front=false"),
        "{labels:?}"
    );
    assert!(
        !labels.iter().any(|label| label.starts_with("write:")),
        "a shut-down transport is never offered a write: {labels:?}"
    );
    assert!(
        labels.iter().any(|label| label == "terminal"),
        "the run still converges: {labels:?}"
    );
}

#[test]
fn shutdown_with_nothing_committed_reports_no_dropped_writes() {
    // Polarity: the typed disposition reports a real loss, it is not
    // manufactured on every shutdown.
    let (_sender, mut driver) = connection_driver_in_state(
        ConnectionConfig::default(),
        Role::Server,
        InitialState::Open,
    );
    let labels = drain_outputs(&mut driver, DriverInput::Shutdown);
    assert!(
        !labels
            .iter()
            .any(|label| label.starts_with("writes-dropped")),
        "no committed write was pending, so nothing is reported: {labels:?}"
    );
    assert!(
        labels.iter().any(|label| label == "terminal"),
        "shutdown still converges: {labels:?}"
    );
}

// ---------------------------------------------------------------------------
// Pre-landing review finding 1 (session 01a04960): "Post-shutdown automatic
// responses can commit new writes and emit multiple drop reports,
// contradicting the asserted one-report/one-frame structure."
//
// Both halves were reproduced by execution before either was fixed. They are
// DIFFERENT claims and get different treatment:
//
//   * multiple REPORTS was a driver defect and is fixed (the automatic reply
//     is suppressed once shutdown has latched);
//   * multiple FRAMES in one report is correct accounting that the evidence
//     wrongly called structurally impossible, so it is pinned as supported
//     behaviour here and the artifact's claim was corrected.
//
// The bounded schedule exploration runs under `AutoResponsePolicy::Disabled`
// and therefore cannot reach either path; these two tests are where the
// DEFAULT `PongInboundPing` policy meets shutdown.
// ---------------------------------------------------------------------------

/// A masked (client-to-server) control frame with an all-zero mask key, so
/// the masked payload bytes equal the semantic payload.
fn masked_control(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![
        0x80 | opcode,
        0x80 | u8::try_from(payload.len()).expect("short test payload"),
        0,
        0,
        0,
        0,
    ];
    frame.extend_from_slice(payload);
    frame
}

/// RED READ (pre-fix, `event_queue_capacity(6)`, default policy):
/// `SHUTDOWN => writes-dropped:frames=1,bytes=3` then
/// `post1 => Event(Ping{data:[0]})` then
/// `post2 => writes-dropped:frames=1,bytes=3` — TWO reports in one run,
/// because the congested event queue refuses the latched EOF with non-fatal
/// backpressure, so the Ping is delivered while the core is still `Open` and
/// the automatic pong commits a frame the ended transport can never carry.
#[test]
fn a_ping_delivered_after_shutdown_injects_no_pong_and_emits_no_second_report() {
    // Capacity 6 is the exact congestion that keeps the latched EOF refused
    // (`handle_eof` needs `MAX_EVENT_SLOTS_PER_INPUT` = 4 free slots) across
    // the poll that delivers the Ping.
    let config = ConnectionConfig::builder()
        .event_queue_capacity(6)
        .build()
        .expect("valid test config");
    let (sender, mut driver) = connection_driver_in_state(config, Role::Server, InitialState::Open);
    let fed = driver.poll(DriverInput::Inbound(&masked_control(0x09, &[0])));
    assert!(
        matches!(fed.input, InputDisposition::Consumed { .. }),
        "the ping chunk is consumed: {:?}",
        fed.input
    );
    // A producer command commits the one frame the shutdown legitimately
    // abandons, so the run has a real first report to be a SECOND one after.
    sender
        .try_send(LocalCommand::SendText {
            text: "x".to_owned(),
        })
        .expect("enqueue");
    let applied = driver.poll(DriverInput::Wake);
    let DriverOutput::Write(suffix) = applied.output else {
        panic!("the text command commits a wire write");
    };
    assert_eq!(suffix.len(), 3, "server text frame [0x81,0x01,'x']");

    let labels = drain_outputs(&mut driver, DriverInput::Shutdown);
    let reports: Vec<&String> = labels
        .iter()
        .filter(|label| label.starts_with("writes-dropped"))
        .collect();
    assert_eq!(
        reports.len(),
        1,
        "the dropped-write disposition is ONE report per run, not a stream: {labels:?}"
    );
    assert_eq!(
        reports[0].as_str(),
        "writes-dropped:frames=1,bytes=3,partial_front=false",
        "only the frame committed BEFORE the shutdown is reported: {labels:?}"
    );
    assert!(
        !labels.iter().any(|label| label.starts_with("write:")),
        "a shut-down transport is never offered a write: {labels:?}"
    );
    assert!(
        labels.iter().any(|label| label == "terminal"),
        "the run still converges: {labels:?}"
    );
}

/// The plural arm of `abort_pending_writes` is a REACHED path under the
/// default automatic-response policy, not the unexercised guarantee the
/// evidence used to claim.
///
/// An automatic pong is injected while a semantic event is being RETURNED,
/// which is the one commit that does not pass through the offered-write
/// gate. It therefore sits in the core's write queue rather than the offered
/// slot, and the next poll applies a producer command on top of it — two
/// committed frames pending at one shutdown instant.
#[test]
fn a_shutdown_report_accounts_for_every_committed_frame_not_just_the_offered_one() {
    let (sender, mut driver) = connection_driver_in_state(
        ConnectionConfig::default(),
        Role::Server,
        InitialState::Open,
    );
    let fed = driver.poll(DriverInput::Inbound(&masked_control(0x09, &[1, 2, 3])));
    assert!(matches!(fed.input, InputDisposition::Consumed { .. }));
    // Drain up to and including the Ping delivery: that is the poll that
    // injects the automatic pong into the core's write queue.
    let mut delivered = false;
    for _ in 0..8 {
        if let DriverOutput::Event(event) = driver.poll(DriverInput::Wake).output
            && matches!(event.kind, ws_core::SemanticEventKind::Ping { .. })
        {
            delivered = true;
            break;
        }
    }
    assert!(delivered, "the Ping semantic event is delivered");
    sender
        .try_send(LocalCommand::SendText {
            text: "hello".to_owned(),
        })
        .expect("enqueue");
    // This poll applies the command (no write is OFFERED yet, so nothing
    // holds the owner's turn) and only then offers the pong.
    let applied = driver.poll(DriverInput::Wake);
    assert!(matches!(
        applied.command,
        Some(CommandDisposition::Applied(_))
    ));
    let DriverOutput::Write(suffix) = applied.output else {
        panic!("the automatic pong is offered first (FIFO owner order)");
    };
    assert_eq!(suffix.len(), 5, "server pong [0x8A,0x03,1,2,3]");

    let labels = drain_outputs(&mut driver, DriverInput::Shutdown);
    let reports: Vec<&String> = labels
        .iter()
        .filter(|label| label.starts_with("writes-dropped"))
        .collect();
    assert_eq!(reports.len(), 1, "still exactly one report: {labels:?}");
    assert_eq!(
        reports[0].as_str(),
        // 5 pong bytes (offered, untouched) + 7 text bytes still in the
        // core's write queue.
        "writes-dropped:frames=2,bytes=12,partial_front=false",
        "the report accounts for BOTH committed frames: {labels:?}"
    );
    assert!(
        !labels.iter().any(|label| label.starts_with("write:")),
        "a shut-down transport is never offered a write: {labels:?}"
    );
}

// ---------------------------------------------------------------------------
// US-017 story review ROUND 2 (session 01a0464f) BLOCKING-1: "A pending
// `WritesDropped` disposition is suppressed by a fatal `Failure`, after
// which the adapter halts, leaving a reachable committed write silently
// unreported."
//
// AC2 lists adapter shutdown in the SAME typed-behaviour clause as every
// other terminal disposition and carves out no exception for fatal
// termination, so "cannot leak" binds the fatal route exactly as it binds
// the clean one. A report queued BEHIND the Failure is unreachable by
// construction, because a faithful adapter stops at the first Failure it
// observes (that stop is itself required, and is what the earlier
// exploration review forced). The report must therefore be surfaced before
// any Failure can be produced.
// ---------------------------------------------------------------------------

/// Adapter-faithful drain: stops at the FIRST surfaced `Failure`, exactly
/// like the ws-testee io_loop (`StepOutput::Failure` ends the connection).
/// Anything this drain does not observe is, for a real adapter, lost.
fn drain_until_halt(driver: &mut ConnectionDriver, first: DriverInput<'_>) -> Vec<String> {
    let mut labels = Vec::new();
    let mut input = first;
    for _ in 0..64 {
        let result = driver.poll(input);
        input = DriverInput::Wake;
        match result.output {
            DriverOutput::Idle => {
                labels.push("idle".to_owned());
                if labels.iter().rev().take(2).all(|label| label == "idle") {
                    break;
                }
            }
            DriverOutput::Write(suffix) => labels.push(format!("write:{}", suffix.len())),
            DriverOutput::Event(_) => labels.push("event".to_owned()),
            DriverOutput::WritesDropped(dropped) => labels.push(format!(
                "writes-dropped:frames={},bytes={},partial_front={}",
                dropped.frames, dropped.bytes, dropped.partial_front
            )),
            DriverOutput::Failure { failure, .. } => {
                labels.push(format!("failure:{:?}", failure.code));
                // The adapter stops here and never polls again.
                break;
            }
            DriverOutput::Terminal(_) => {
                labels.push("terminal".to_owned());
                break;
            }
        }
    }
    labels
}

#[test]
fn a_fatal_failure_ending_the_run_cannot_suppress_the_dropped_write_report() {
    // max_actions(1) spends the whole action budget on the producer's send,
    // so the EOF the shutdown latches is action 2 and the core refuses it
    // FATALLY with ActionLimitExceeded — while that send's frame is still a
    // committed, undelivered write. This is the reviewer's case: a reachable
    // schedule where a committed write is pending and a fatal Failure ends
    // the run.
    let config = ConnectionConfig::builder()
        .max_actions(1)
        .build()
        .expect("valid test config");
    let (sender, mut driver) = connection_driver_in_state(config, Role::Server, InitialState::Open);
    sender
        .try_send(LocalCommand::SendText {
            text: "a1".to_owned(),
        })
        .expect("enqueue");
    let applied = driver.poll(DriverInput::Wake);
    assert!(matches!(
        applied.command,
        Some(CommandDisposition::Applied(_))
    ));
    let DriverOutput::Write(suffix) = applied.output else {
        panic!("the applied command commits a wire write");
    };
    assert_eq!(suffix, server_text_frame("a1").as_slice());

    let labels = drain_until_halt(&mut driver, DriverInput::Shutdown);
    // The run must really end fatally, or this test is not exercising the
    // path the finding names.
    assert!(
        labels
            .iter()
            .any(|label| label == "failure:ActionLimitExceeded"),
        "the fatal termination path must actually be taken: {labels:?}"
    );
    let dropped_at = labels
        .iter()
        .position(|label| label.starts_with("writes-dropped"))
        .unwrap_or_else(|| {
            panic!(
                "the abandoned committed write must be reported on the FATAL path too: {labels:?}"
            )
        });
    let failure_at = labels
        .iter()
        .position(|label| label.starts_with("failure:"))
        .expect("failure observed");
    assert!(
        dropped_at < failure_at,
        "the report must precede the Failure the adapter halts on, never be queued behind it: {labels:?}"
    );
    assert_eq!(
        labels[dropped_at], "writes-dropped:frames=1,bytes=4,partial_front=false",
        "the whole abandoned frame is accounted for: {labels:?}"
    );
}

#[test]
fn a_fatal_failure_with_a_partially_written_frame_reports_only_the_lost_suffix() {
    // Same fatal route, but one byte of the committed frame reached the
    // wire first: the peer saw a truncated frame and only the undrained
    // suffix is lost.
    let config = ConnectionConfig::builder()
        .max_actions(1)
        .build()
        .expect("valid test config");
    let (sender, mut driver) = connection_driver_in_state(config, Role::Server, InitialState::Open);
    sender
        .try_send(LocalCommand::SendText {
            text: "a1".to_owned(),
        })
        .expect("enqueue");
    assert!(matches!(
        driver.poll(DriverInput::Wake).output,
        DriverOutput::Write(_)
    ));
    let progressed = driver.poll(DriverInput::WriteProgress { bytes: 1 });
    assert!(matches!(
        progressed.input,
        InputDisposition::Consumed { .. }
    ));

    let labels = drain_until_halt(&mut driver, DriverInput::Shutdown);
    assert!(
        labels
            .iter()
            .any(|label| label == "failure:ActionLimitExceeded"),
        "the fatal termination path must actually be taken: {labels:?}"
    );
    assert_eq!(
        labels.first().map(String::as_str),
        Some("writes-dropped:frames=1,bytes=3,partial_front=true"),
        "{labels:?}"
    );
}

/// Polarity for the fatal route: when the fatal failure ends a run with
/// nothing committed outstanding, no drop report is manufactured and the
/// Failure is still the first thing the adapter sees.
#[test]
fn a_fatal_failure_with_nothing_committed_still_surfaces_the_failure_first() {
    let config = ConnectionConfig::builder()
        .max_actions(0)
        .build()
        .expect("valid test config");
    let (_sender, mut driver) =
        connection_driver_in_state(config, Role::Server, InitialState::Open);
    let labels = drain_until_halt(&mut driver, DriverInput::Shutdown);
    assert_eq!(
        labels.first().map(String::as_str),
        Some("failure:ActionLimitExceeded"),
        "no committed write was pending, so nothing delays the failure: {labels:?}"
    );
    assert!(
        !labels
            .iter()
            .any(|label| label.starts_with("writes-dropped")),
        "the disposition is not manufactured: {labels:?}"
    );
}

/// US-017 AC2, pre-landing review ROUND 2: a fatal core step that COMMITS a
/// wire write must not let the failure overtake it.
///
/// A server handshake rejection is the exact shape the review named: the core
/// queues its HTTP error head and returns the fatal `JavaInvalidData` from the
/// SAME `ConnectionCore::handle` call. The shipped adapter halts at its first
/// `Failure` by contract, so if the failure came first those bytes would be
/// abandoned with nothing counted — proven at the peer by
/// `ws-testee/tests/loopback.rs`. This is the seam-level guarantee the
/// adapter's narrowed protocol-failure exception rests on.
#[test]
fn a_fatal_input_that_commits_a_write_offers_the_write_before_the_failure() {
    let (_sender, mut driver) =
        ws_driver::connection_driver(ConnectionConfig::default(), Role::Server);
    // Well-formed HTTP, not a websocket upgrade: the version-only draft match
    // fails and the core rejects.
    let request = b"GET /chat HTTP/1.1\r\nHost: localhost\r\n\r\n";

    let first = driver.poll(DriverInput::Inbound(request));
    let committed = match first.output {
        DriverOutput::Write(suffix) => suffix.to_vec(),
        other => panic!("the committed rejection head must be offered first, got {other:?}"),
    };
    assert!(
        !committed.is_empty(),
        "the rejection head is a real committed write"
    );

    // Draining it is what releases the held failure.
    let acked = driver.poll(DriverInput::WriteProgress {
        bytes: committed.len(),
    });
    match acked.output {
        DriverOutput::Failure { failure, .. } => {
            assert_eq!(failure.code, FailureCode::JavaInvalidData)
        }
        other => panic!("the failure must follow the drained write, got {other:?}"),
    }

    // Nothing is applied while the failure is held, and the failure is
    // delivered exactly once.
    assert!(matches!(
        driver.poll(DriverInput::Wake).output,
        DriverOutput::Idle
    ));
}

/// The accounted polarity of the same guarantee: an adapter that cannot
/// deliver the committed head ends transport service instead, and the head
/// comes back as the typed disposition rather than vanishing with the
/// failure.
#[test]
fn an_undrained_committed_write_is_reported_when_the_failing_run_shuts_down() {
    let (_sender, mut driver) =
        ws_driver::connection_driver(ConnectionConfig::default(), Role::Server);
    let request = b"GET /chat HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let offered = match driver.poll(DriverInput::Inbound(request)).output {
        DriverOutput::Write(suffix) => suffix.len(),
        other => panic!("expected the committed head, got {other:?}"),
    };
    match driver.poll(DriverInput::Shutdown).output {
        DriverOutput::WritesDropped(dropped) => {
            assert_eq!(dropped.frames, 1);
            assert_eq!(dropped.bytes, offered);
            assert!(!dropped.partial_front);
        }
        other => panic!("the undelivered head must be reported, got {other:?}"),
    }
    match driver.poll(DriverInput::Wake).output {
        DriverOutput::Failure { failure, .. } => {
            assert_eq!(failure.code, FailureCode::JavaInvalidData)
        }
        other => panic!("the failure follows the report, got {other:?}"),
    }
}
