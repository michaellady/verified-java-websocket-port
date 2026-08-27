//! US-009 AC2/AC4 core-semantics tests: dual-instance determinism, chunking
//! invariance, poisoning, state gates, EOF close vocabulary, and counts.
//!
//! Every behavioral assertion mirrors `internal/corpora/derive.go` (the Go
//! reference model derived line-by-line from the pinned Java-WebSocket 1.6.0
//! source); citations name the mirrored function and the fidelity quirk ids
//! from the US-009 design draft.

use ws_core::close::CloseOrigin;
use ws_core::config::ConnectionConfig;
use ws_core::connection::{
    ConnectionCore, DataOpcode, InitialState, Input, LocalCommand, ReadyState, Role,
};
use ws_core::error::{FailureCode, QueueKind, TypedProtocolFailure};
use ws_core::event::{SemanticEvent, SemanticEventKind, TransitionCause};

/// One fully drained observation of a core after a sequence of inputs.
#[derive(Debug, PartialEq, Eq)]
struct Observation {
    results: Vec<Result<(), TypedProtocolFailure>>,
    events: Vec<SemanticEvent>,
    writes: Vec<Vec<u8>>,
    state: ReadyState,
    counts: ws_core::event::Counts,
    close: Option<ws_core::close::CloseDetail>,
}

/// Owned input so test scripts can be cloned and replayed.
#[derive(Debug, Clone)]
enum Step {
    Bytes(Vec<u8>),
    Eof,
    Command(LocalCommand),
}

fn run(core: &mut ConnectionCore, steps: &[Step]) -> Observation {
    let mut results = Vec::new();
    let mut events = Vec::new();
    let mut writes = Vec::new();
    for step in steps {
        let result = match step {
            Step::Bytes(chunk) => core.handle(Input::TransportBytes(chunk)),
            Step::Eof => core.handle(Input::TransportEof),
            Step::Command(cmd) => core.handle(Input::Command(cmd.clone())),
        };
        // Drain eagerly, as the corpus harness does.
        while let Some(event) = core.next_event() {
            events.push(event);
        }
        while let Some(write) = core.next_write() {
            writes.push(write.bytes);
        }
        results.push(result);
    }
    Observation {
        results,
        events,
        writes,
        state: core.state(),
        counts: core.counts(),
        close: core.close_detail().cloned(),
    }
}

fn open_core() -> ConnectionCore {
    ConnectionCore::new_in_state(
        ConnectionConfig::default(),
        Role::Server,
        InitialState::Open,
    )
}

// ---------------------------------------------------------------------------
// AC2 e2e: dual-instance determinism
// ---------------------------------------------------------------------------

#[test]
fn two_fresh_cores_with_identical_inputs_emit_identical_typed_sequences() {
    // The US-009 e2e criterion: identical configs, commands, and byte chunks
    // into two fresh instances, without networking, yield identical typed
    // sequences.
    let steps = vec![
        Step::Bytes(vec![0x81, 0x03]),
        Step::Bytes(vec![]),
        Step::Bytes(vec![0x01, 0x02, 0x03]),
        Step::Eof,
        Step::Bytes(vec![0xFF]), // post-terminal: poisoned-state refusal
    ];
    let mut a = open_core();
    let mut b = open_core();
    let obs_a = run(&mut a, &steps);
    let obs_b = run(&mut b, &steps);
    assert_eq!(obs_a, obs_b);
}

#[test]
fn determinism_holds_for_client_role_and_command_scripts() {
    let steps = vec![
        Step::Command(LocalCommand::SendPing { data: vec![1, 2] }),
        Step::Command(LocalCommand::SendText {
            text: "hi".to_owned(),
        }),
    ];
    let make = || {
        ConnectionCore::new_in_state(
            ConnectionConfig::default(),
            Role::Client,
            InitialState::Open,
        )
    };
    let (mut a, mut b) = (make(), make());
    assert_eq!(run(&mut a, &steps), run(&mut b, &steps));
}

// ---------------------------------------------------------------------------
// AC4: determinism under arbitrary byte chunking
// ---------------------------------------------------------------------------

/// Split `bytes` into the given chunk lengths (must sum to bytes.len()).
fn chunked(bytes: &[u8], lens: &[usize]) -> Vec<Step> {
    let mut steps = Vec::new();
    let mut at = 0;
    for &len in lens {
        steps.push(Step::Bytes(bytes[at..at + len].to_vec()));
        at += len;
    }
    assert_eq!(at, bytes.len(), "chunk lengths must cover the stream");
    steps
}

fn kinds_without_input_chunks(events: &[SemanticEvent]) -> Vec<SemanticEventKind> {
    events
        .iter()
        .filter(|e| !matches!(e.kind, SemanticEventKind::InputChunk { .. }))
        .map(|e| match &e.kind {
            // Frame records carry the chunking-relative step tag inside the
            // kind; normalize it so the invariance property quantifies over
            // the frame's protocol content only (the corpus comparison
            // always uses the scenario's exact chunking, so step tags are
            // out of scope here by design).
            SemanticEventKind::FrameObserved(frame) => {
                let mut frame = frame.clone();
                frame.step = 0;
                SemanticEventKind::FrameObserved(frame)
            }
            kind => kind.clone(),
        })
        .collect()
}

#[test]
fn rechunking_an_in_limits_stream_yields_identical_observables_modulo_input_chunk() {
    // Same logical byte stream, three chunkings: whole, 1-byte, and uneven.
    // Everything observable except the chunking record itself must be
    // identical: the sequence of non-input_chunk event kinds (frame records
    // normalized over their chunking-relative step tag), writes,
    // transitions, final state, close detail, and counts (consumed_bytes
    // advances by whole surviving chunks, derive.go:359 region, so totals
    // agree across chunkings). The input_chunk events and the step TAGS are
    // chunking-relative by definition — step indexes the input sequence —
    // which is exactly why the corpus comparison always uses the scenario's
    // exact chunking (design draft AC4 note); the invariance property
    // quantifies over the rest of the observable stream.
    //
    // The stream is a well-formed wire sequence (US-012 decodes for real
    // now): one masked text frame "hi" then one masked binary frame,
    // toward a server.
    let stream: Vec<u8> = vec![
        0x81, 0x82, 0x00, 0x00, 0x00, 0x00, b'h', b'i', // text "hi"
        0x82, 0x83, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, // binary
    ];
    let chunkings: [Vec<usize>; 3] = [vec![17], vec![1; 17], vec![3, 7, 1, 6]];
    let mut observations = Vec::new();
    for lens in &chunkings {
        let mut steps = chunked(&stream, lens);
        steps.push(Step::Eof);
        let mut core = open_core();
        observations.push(run(&mut core, &steps));
    }
    // The stream genuinely decodes: two frames, a text and a binary event.
    assert_eq!(observations[0].counts.frames, 2);
    assert!(
        observations[0]
            .events
            .iter()
            .any(|e| matches!(&e.kind, SemanticEventKind::Text { text } if text == "hi"))
    );
    let reference = &observations[0];
    for obs in &observations[1..] {
        assert_eq!(
            kinds_without_input_chunks(&obs.events),
            kinds_without_input_chunks(&reference.events)
        );
        assert_eq!(obs.writes, reference.writes);
        assert_eq!(obs.state, reference.state);
        assert_eq!(obs.close, reference.close);
        assert_eq!(obs.counts, reference.counts);
        // Every per-step result must agree in failure code (all Ok here).
        assert!(obs.results.iter().all(Result::is_ok));
    }
}

#[test]
fn rechunking_a_buffer_overflowing_stream_yields_the_same_failure_code() {
    // A stream over max_buffered_bytes + 14 (quirk Q24 slack) but within
    // max_input_bytes fails BUFFER_LIMIT_EXCEEDED under every chunking. The
    // failing counts legitimately depend on chunk boundaries (they do in the
    // Java oracle too); the failure code and final poisoning must not.
    let config = ConnectionConfig::builder()
        .max_buffered_bytes(64)
        .max_input_bytes(1024)
        .build()
        .expect("valid test config");
    // One INCOMPLETE masked binary frame declaring a 16 KiB payload (within
    // the default frame cap, so the header screen passes): the leftover
    // grows past 64 + 14 under every chunking without ever completing.
    let mut stream = vec![0x82, 0xFE, 0x40, 0x00];
    stream.extend(std::iter::repeat_n(0u8, 96)); // 100 > 64 + 14
    for lens in [vec![100], vec![1; 100], vec![50, 50], vec![79, 21]] {
        let mut core =
            ConnectionCore::new_in_state(config.clone(), Role::Server, InitialState::Open);
        let obs = run(&mut core, &chunked(&stream, &lens));
        let failure = obs
            .results
            .iter()
            .find_map(|r| r.as_ref().err())
            .expect("stream must overflow the wire buffer");
        assert_eq!(failure.code, FailureCode::BufferLimitExceeded);
        assert_eq!(failure.close_code, None, "limit codes carry no close code");
    }
}

// ---------------------------------------------------------------------------
// Byte-path semantics (derive.go inputStep)
// ---------------------------------------------------------------------------

#[test]
fn surviving_chunks_emit_input_chunk_and_advance_counts() {
    let mut core = open_core();
    let obs = run(
        &mut core,
        &[Step::Bytes(vec![0x81, 0x02]), Step::Bytes(vec![])],
    );
    assert!(obs.results.iter().all(Result::is_ok));
    assert_eq!(
        obs.events,
        vec![
            SemanticEvent {
                step: 0,
                kind: SemanticEventKind::InputChunk { bytes: 2 }
            },
            SemanticEvent {
                step: 1,
                kind: SemanticEventKind::InputChunk { bytes: 0 }
            },
        ]
    );
    // Counts mirror derive.go: input counted, the whole surviving chunk
    // counted as consumed (derive.go "d.consumedBytes += len(payload)"),
    // undecoded bytes buffered in the wire buffer.
    assert_eq!(obs.counts.input_bytes, 2);
    assert_eq!(obs.counts.consumed_bytes, 2);
    assert_eq!(obs.counts.wire_buffered_bytes, 2);
    assert_eq!(obs.counts.message_buffered_bytes, 0);
    assert_eq!(obs.counts.buffered_bytes, 2);
    assert_eq!(obs.counts.actions, 0);
    assert_eq!(obs.counts.frames, 0);
}

#[test]
fn input_limit_uses_add_bounded_semantics() {
    // derive.go:295-299: the counter is only updated when within bounds, so
    // the rejected chunk is NOT included in input_bytes.
    let config = ConnectionConfig::builder()
        .max_input_bytes(4)
        .build()
        .expect("valid test config");
    let mut core = ConnectionCore::new_in_state(config, Role::Server, InitialState::Open);
    assert!(core.handle(Input::TransportBytes(&[1, 2, 3])).is_ok());
    let err = core
        .handle(Input::TransportBytes(&[4, 5]))
        .expect_err("3 + 2 > 4 must exceed the input limit");
    assert_eq!(err.code, FailureCode::InputLimitExceeded);
    assert_eq!(
        core.counts().input_bytes,
        3,
        "addBounded: no partial update"
    );
    // No input_chunk event for the rejected chunk (derive.go emits it only
    // after the chunk survives limits).
    let events: Vec<_> = std::iter::from_fn(|| core.next_event()).collect();
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e.kind, SemanticEventKind::InputChunk { .. }))
            .count(),
        1
    );
}

#[test]
fn wire_buffer_overflow_reports_oversized_pending_and_zero_consumed() {
    // Quirk Q24 (WireTracker.accept, derive.go:313-319): the overflow is
    // detected before translation; consumed_bytes stays 0 for the chunk; the
    // failure counts report the oversized leftover length exactly as the
    // oracle does. The port strengthens the ordering (bound checked before
    // the retained allocation) without changing any observable.
    let config = ConnectionConfig::builder()
        .max_buffered_bytes(8)
        .build()
        .expect("valid test config");
    let mut core = ConnectionCore::new_in_state(config, Role::Server, InitialState::Open);
    // An incomplete masked binary frame declaring 256 payload bytes: no
    // complete span exists, so all 30 bytes are leftover.
    let mut stream = vec![0x82, 0xFE, 0x01, 0x00];
    stream.extend(std::iter::repeat_n(0u8, 26));
    let err = core
        .handle(Input::TransportBytes(&stream))
        .expect_err("30 > 8 + 14 must overflow the wire buffer");
    assert_eq!(err.code, FailureCode::BufferLimitExceeded);
    let counts = core.counts();
    assert_eq!(
        counts.input_bytes, 30,
        "input limit passed before buffering"
    );
    assert_eq!(counts.consumed_bytes, 0, "Q24: consumed stays 0");
    assert_eq!(
        counts.wire_buffered_bytes, 30,
        "oracle reports the leftover"
    );
    assert_eq!(counts.buffered_bytes, 30);
}

#[test]
fn wire_buffer_accepts_exactly_the_java_slack() {
    // The pending cap is max_buffered_bytes + 14, the max frame header slack
    // the reference model pins (quirk Q24).
    let config = ConnectionConfig::builder()
        .max_buffered_bytes(8)
        .build()
        .expect("valid test config");
    let mut core = ConnectionCore::new_in_state(config, Role::Server, InitialState::Open);
    // 22 leftover bytes of one incomplete frame: exactly 8 + 14.
    let mut stream = vec![0x82, 0xFE, 0x01, 0x00];
    stream.extend(std::iter::repeat_n(0u8, 18));
    assert!(core.handle(Input::TransportBytes(&stream)).is_ok());
    assert_eq!(core.counts().wire_buffered_bytes, 22);
}

// ---------------------------------------------------------------------------
// State gates (quirk Q26) and poisoning
// ---------------------------------------------------------------------------

#[test]
fn nonzero_bytes_into_closed_are_a_state_violation_but_empty_bytes_pass() {
    // derive.go:292-294: closed + nonzero payload -> STATE_VIOLATION; an
    // empty chunk is recorded as input_chunk {bytes: 0}.
    let mut core = ConnectionCore::new_in_state(
        ConnectionConfig::default(),
        Role::Server,
        InitialState::Closed,
    );
    assert!(core.handle(Input::TransportBytes(&[])).is_ok());
    let err = core
        .handle(Input::TransportBytes(&[1]))
        .expect_err("bytes into closed must be refused");
    assert_eq!(err.code, FailureCode::StateViolation);
    assert_eq!(err.close_code, None);
}

#[test]
fn actions_outside_open_are_state_violations() {
    // derive.go requireOpen (:811-816): every send action requires open.
    for initial in [InitialState::Closing, InitialState::Closed] {
        let mut core =
            ConnectionCore::new_in_state(ConnectionConfig::default(), Role::Server, initial);
        let err = core
            .handle(Input::Command(LocalCommand::SendText {
                text: "x".to_owned(),
            }))
            .expect_err("send_text outside open must be refused");
        assert_eq!(err.code, FailureCode::StateViolation);
    }
}

#[test]
fn action_limit_counts_the_rejected_action() {
    // derive.go actionStep: the counter increments before the limit check,
    // so the rejected action is included in the failure counts.
    let config = ConnectionConfig::builder()
        .max_actions(1)
        .build()
        .expect("valid test config");
    let mut core = ConnectionCore::new_in_state(config, Role::Server, InitialState::Open);
    // First action: passes the action limit, then hits the honest
    // Unimplemented refusal (outbound framing is US-012+); that poisons the
    // core, so rebuild for the pure limit observation.
    let first = core.handle(Input::Command(LocalCommand::SendPing { data: vec![] }));
    assert_eq!(
        first.expect_err("skeleton refuses outbound framing").code,
        FailureCode::Unimplemented
    );
    let config = ConnectionConfig::builder()
        .max_actions(0)
        .build()
        .expect("valid test config");
    let mut core = ConnectionCore::new_in_state(config, Role::Server, InitialState::Open);
    let err = core
        .handle(Input::Command(LocalCommand::SendPing { data: vec![] }))
        .expect_err("max_actions 0 must reject the first action");
    assert_eq!(err.code, FailureCode::ActionLimitExceeded);
    assert_eq!(core.counts().actions, 1, "rejected action is counted");
}

#[test]
fn send_payload_limit_asymmetry_matches_java_control_frames() {
    // Quirk Q17 via derive.go actionStep: send_text/send_binary/send_fragment
    // check the payload against max_buffered_bytes (BUFFER_LIMIT_EXCEEDED);
    // send_ping/send_pong perform NO payload-size check (ControlFrame.isValid
    // checks only fin and reserved bits), so an oversized ping reaches the
    // skeleton's Unimplemented refusal instead of a limit failure.
    let config = || {
        ConnectionConfig::builder()
            .max_buffered_bytes(4)
            .build()
            .expect("valid test config")
    };
    let oversized = vec![0u8; 8];
    let cases: [(LocalCommand, FailureCode); 4] = [
        (
            LocalCommand::SendText {
                text: "12345678".to_owned(),
            },
            FailureCode::BufferLimitExceeded,
        ),
        (
            LocalCommand::SendBinary {
                data: oversized.clone(),
            },
            FailureCode::BufferLimitExceeded,
        ),
        (
            LocalCommand::SendFragment {
                opcode: DataOpcode::Text,
                data: oversized.clone(),
                fin: true,
            },
            FailureCode::BufferLimitExceeded,
        ),
        (
            LocalCommand::SendPing {
                data: oversized.clone(),
            },
            FailureCode::Unimplemented,
        ),
    ];
    for (command, expected) in cases {
        let mut core = ConnectionCore::new_in_state(config(), Role::Server, InitialState::Open);
        let err = core
            .handle(Input::Command(command.clone()))
            .expect_err("skeleton must refuse every send");
        assert_eq!(err.code, expected, "command {command:?}");
    }
}

#[test]
fn fatal_failures_poison_the_core_into_state_violation_refusals() {
    // Design draft section 1.4: after a fatal failure the core is poisoned
    // into its final state; further inputs return StateViolation-class
    // failures, mirroring the oracle's partial-execution semantics. Counts
    // and state freeze.
    let config = ConnectionConfig::builder()
        .max_input_bytes(2)
        .build()
        .expect("valid test config");
    let mut core = ConnectionCore::new_in_state(config, Role::Server, InitialState::Open);
    let err = core
        .handle(Input::TransportBytes(&[1, 2, 3]))
        .expect_err("over-limit chunk must fail");
    assert_eq!(err.code, FailureCode::InputLimitExceeded);
    let frozen_counts = core.counts();
    let frozen_state = core.state();
    for input in [
        Input::TransportBytes(&[]),
        Input::TransportEof,
        Input::Command(LocalCommand::SendPing { data: vec![] }),
    ] {
        let err = core.handle(input).expect_err("poisoned core must refuse");
        assert_eq!(err.code, FailureCode::StateViolation);
    }
    assert_eq!(core.counts(), frozen_counts);
    assert_eq!(core.state(), frozen_state);
}

// ---------------------------------------------------------------------------
// EOF close vocabulary (quirk Q20, derive.go eof)
// ---------------------------------------------------------------------------

#[test]
fn eof_while_open_closes_1006_transport_with_the_pinned_reason() {
    let mut core = open_core();
    let obs = run(&mut core, &[Step::Eof]);
    assert!(obs.results[0].is_ok());
    assert_eq!(obs.state, ReadyState::Closed);
    let close = obs.close.expect("eof must record a close detail");
    assert_eq!(close.code, 1006);
    assert_eq!(
        close.reason,
        "transport EOF before close handshake completed"
    );
    assert_eq!(close.origin, CloseOrigin::Transport);
    assert!(!close.remote, "open-state EOF is not a remote close");
    assert!(!close.handshake_complete);
    // Event stream: eof detail event, then the transition record.
    assert_eq!(
        obs.events,
        vec![
            SemanticEvent {
                step: 0,
                kind: SemanticEventKind::Eof(close.clone())
            },
            SemanticEvent {
                step: 0,
                kind: SemanticEventKind::Transition {
                    from: ReadyState::Open,
                    to: ReadyState::Closed,
                    cause: TransitionCause::Eof,
                }
            },
        ]
    );
    // eof is an action step (corpus steps[kind=action][action=eof]).
    assert_eq!(obs.counts.actions, 1);
}

#[test]
fn eof_while_closing_without_prior_close_keeps_defaults_but_marks_remote() {
    // derive.go eof: code/reason fall back to the 1006 defaults when no close
    // detail exists; the `remote` flag is (state == closing).
    let mut core = ConnectionCore::new_in_state(
        ConnectionConfig::default(),
        Role::Server,
        InitialState::Closing,
    );
    let obs = run(&mut core, &[Step::Eof]);
    assert_eq!(obs.state, ReadyState::Closed);
    let close = obs.close.expect("eof must record a close detail");
    assert_eq!(close.code, 1006);
    assert_eq!(
        close.reason,
        "transport EOF before close handshake completed"
    );
    assert_eq!(close.origin, CloseOrigin::Transport);
    assert!(close.remote, "closing-state EOF echoes remote=true");
    assert!(!close.handshake_complete);
    assert_eq!(
        obs.events[1],
        SemanticEvent {
            step: 0,
            kind: SemanticEventKind::Transition {
                from: ReadyState::Closing,
                to: ReadyState::Closed,
                cause: TransitionCause::Eof,
            }
        }
    );
}

#[test]
fn eof_in_closed_is_a_state_violation_after_action_accounting() {
    // derive.go eof: closed -> STATE_VIOLATION; the action was still counted
    // by actionStep before the gate.
    let mut core = ConnectionCore::new_in_state(
        ConnectionConfig::default(),
        Role::Server,
        InitialState::Closed,
    );
    let err = core
        .handle(Input::TransportEof)
        .expect_err("eof in closed must be refused");
    assert_eq!(err.code, FailureCode::StateViolation);
    assert_eq!(core.counts().actions, 1);
}

// ---------------------------------------------------------------------------
// NotYetConnected: the handshake plane (US-010/US-011, borrow batch B)
// ---------------------------------------------------------------------------

#[test]
fn not_yet_connected_bytes_now_drive_the_handshake_plane() {
    // US-009's honest Unimplemented refusal on this arm is replaced by the
    // landed US-010/US-011 handshake entry: a server core buffers an
    // incomplete upgrade request (no transition, no events, no corpus
    // counter movement — handshake bytes are pre-corpus vocabulary).
    let mut core = ConnectionCore::new(ConnectionConfig::default(), Role::Server);
    assert_eq!(core.state(), ReadyState::NotYetConnected);
    core.handle(Input::TransportBytes(b"G"))
        .expect("handshake bytes buffer incrementally");
    assert_eq!(core.state(), ReadyState::NotYetConnected);
    assert_eq!(core.counts().input_bytes, 0);
    assert!(core.next_event().is_none());
    assert!(core.next_write().is_none());
}

// ---------------------------------------------------------------------------
// The skeleton cannot claim protocol behavior (protocol-stub property)
// ---------------------------------------------------------------------------

#[test]
fn later_story_behavior_still_refuses_honestly() {
    // The US-009 protocol-stub gate ("skeleton never produces protocol
    // events") retired when US-012/US-013/US-014 landed the data path; the
    // surviving honesty property is that behavior still owned by later
    // stories — inbound control frames (US-015) and control sends — keeps
    // refusing with the non-oracle Unimplemented code instead of faking
    // Java, so those corpus families keep failing until their stories land.
    let mut core = open_core();
    let obs = run(
        &mut core,
        &[
            // A complete masked ping frame: US-012 records it, but its
            // processing arm is US-015's.
            Step::Bytes(vec![0x89, 0x82, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02]),
        ],
    );
    let err = obs.results[0]
        .as_ref()
        .expect_err("inbound ping processing is US-015 behavior");
    assert_eq!(err.code, FailureCode::Unimplemented);
    assert_eq!(obs.counts.frames, 1, "the frame record precedes processing");
    let mut core = open_core();
    let err = core
        .handle(Input::Command(LocalCommand::SendPing { data: vec![] }))
        .expect_err("send_ping is US-015 behavior");
    assert_eq!(err.code, FailureCode::Unimplemented);
}

#[test]
fn data_path_decodes_frames_and_emits_real_writes() {
    // US-012/US-013 e2e: a masked text frame decodes into a frame record
    // plus a text event, and an outbound send produces a real wire write.
    let mut core = open_core();
    let obs = run(
        &mut core,
        &[
            Step::Bytes(vec![0x81, 0x82, 0x00, 0x00, 0x00, 0x00, b'h', b'i']),
            Step::Command(LocalCommand::SendText {
                text: "ok".to_owned(),
            }),
        ],
    );
    assert!(obs.results.iter().all(Result::is_ok));
    assert!(
        obs.events
            .iter()
            .any(|e| matches!(&e.kind, SemanticEventKind::Text { text } if text == "hi"))
    );
    assert_eq!(obs.counts.frames, 2, "one inbound + one outbound frame");
    // The server role writes an unmasked fin text frame verbatim.
    assert_eq!(obs.writes, vec![vec![0x81, 0x02, b'o', b'k']]);
    assert_eq!(obs.state, ReadyState::Open);
}

#[test]
fn backpressure_is_not_fatal_and_the_refused_input_can_be_retried() {
    // AC4: backpressure surfaces as a typed output rather than unbounded
    // allocation, and the refused input is retryable after draining.
    let config = ConnectionConfig::builder()
        .event_queue_capacity(4)
        .build()
        .expect("valid test config");
    let mut core = ConnectionCore::new_in_state(config, Role::Server, InitialState::Open);
    // Fill the event queue with four undrained input_chunk events.
    for _ in 0..4 {
        assert!(core.handle(Input::TransportBytes(&[])).is_ok());
    }
    let err = core
        .handle(Input::TransportBytes(&[]))
        .expect_err("full event queue must refuse the input");
    assert_eq!(err.code, FailureCode::Backpressure(QueueKind::Event));
    assert!(!err.code.is_fatal());
    let counts_before = core.counts();
    // Drain, then the same input succeeds; the refused attempt consumed no
    // step index and mutated nothing.
    let drained: Vec<_> = std::iter::from_fn(|| core.next_event()).collect();
    assert_eq!(drained.len(), 4);
    assert_eq!(core.counts(), counts_before);
    assert!(core.handle(Input::TransportBytes(&[])).is_ok());
    let event = core
        .next_event()
        .expect("retried input must emit its event");
    assert_eq!(event.step, 4, "refused attempt must not consume a step");
}

#[test]
fn eof_requires_two_event_slots_before_processing() {
    // The per-input capacity precheck keeps input handling atomic: an EOF
    // needs the eof event plus the transition record, so with only one free
    // slot it must refuse without any partial emission.
    let config = ConnectionConfig::builder()
        .event_queue_capacity(4)
        .build()
        .expect("valid test config");
    let mut core = ConnectionCore::new_in_state(config, Role::Server, InitialState::Open);
    for _ in 0..3 {
        assert!(core.handle(Input::TransportBytes(&[])).is_ok());
    }
    let err = core
        .handle(Input::TransportEof)
        .expect_err("one free slot is not enough for eof + transition");
    assert_eq!(err.code, FailureCode::Backpressure(QueueKind::Event));
    assert_eq!(core.state(), ReadyState::Open, "no partial transition");
    assert_eq!(core.counts().actions, 0, "no partial action accounting");
    while core.next_event().is_some() {}
    assert!(core.handle(Input::TransportEof).is_ok());
    assert_eq!(core.state(), ReadyState::Closed);
}
