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

#[test]
fn commands_queued_at_terminal_are_terminal_rejected() {
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
    assert_eq!(
        result.command,
        Some(CommandDisposition::TerminalRejected(
            LocalCommand::SendText {
                text: "late".to_owned(),
            }
        ))
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
    assert!(!close.remote);
    assert_eq!(run.driver.state(), ReadyState::Closed);
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
            DriverOutput::Failure(_) => labels.push("failure".to_owned()),
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
            DriverOutput::Failure(failure) => {
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
