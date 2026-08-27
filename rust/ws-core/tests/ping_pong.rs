//! US-015 control-frame tests: inbound ping/pong delivery, fragmentation
//! interleave, the Q17 send-path asymmetry, and the control state gates.
//!
//! Seed provenance: `fuzz-seeds/us015/*.hex` adopted byte-verbatim with
//! attribution from the Codex plane (codex-import 8f18f91, per-file blob
//! identity verified); every expectation below is RE-DERIVED from the
//! reference model `internal/corpora/derive.go` (`processInbound` ping/pong
//! arms, `actionStep` send_ping/send_pong, `decodeFrame`,
//! `screenIncompleteHeader`). Where the Codex chain asserted RFC-strict
//! behavior the shipped Java runtime does not have, the expectation here is
//! the Java-faithful one (each site documented inline):
//!
//! - NO automatic pong reply exists in the reference model's observable
//!   space (their `AutomaticPongPolicy::ServerOnly` machinery is not
//!   adopted; quirk Q18 — the port core never replies on its own);
//! - mask-by-role rejections are not Java behavior (the pinned runtime
//!   accepts either masking toward either role, derive.go:439-447), so the
//!   `wrong-mask-*` seeds assert ACCEPTANCE, inverted from their originals;
//! - send-path control payloads are NOT size-capped (quirk Q17:
//!   `ControlFrame.isValid` checks only fin and reserved bits, so the
//!   pinned runtime sends oversized control payloads successfully — their
//!   encoder preflight rejects >125, stripped here).

use ws_core::config::ConnectionConfig;
use ws_core::connection::{ConnectionCore, InitialState, Input, LocalCommand, ReadyState, Role};
use ws_core::error::{FailureCode, QueueKind, TypedProtocolFailure};
use ws_core::event::{Counts, OutboundCause, SemanticEvent, SemanticEventKind};
use ws_core::framing::Opcode;

fn seed(name: &str) -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz-seeds")
        .join(name);
    let hex = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("seed {name} must be readable: {err}"));
    let hex = hex.trim();
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("seed files are lowercase hex"))
        .collect()
}

struct Replay {
    result: Result<(), TypedProtocolFailure>,
    events: Vec<SemanticEvent>,
    writes: Vec<Vec<u8>>,
    counts: Counts,
    state: ReadyState,
}

fn replay_bytes(config: ConnectionConfig, role: Role, bytes: &[u8]) -> Replay {
    let mut core = ConnectionCore::new_in_state(config, role, InitialState::Open);
    let result = core.handle(Input::TransportBytes(bytes));
    let events = std::iter::from_fn(|| core.next_event()).collect();
    let writes = std::iter::from_fn(|| core.next_write())
        .map(|w| w.bytes)
        .collect();
    Replay {
        result,
        events,
        writes,
        counts: core.counts(),
        state: core.state(),
    }
}

fn replay_seed(name: &str, role: Role) -> Replay {
    replay_bytes(ConnectionConfig::default(), role, &seed(name))
}

fn controls(replay: &Replay) -> Vec<SemanticEventKind> {
    replay
        .events
        .iter()
        .filter(|e| {
            matches!(
                e.kind,
                SemanticEventKind::Ping { .. } | SemanticEventKind::Pong { .. }
            )
        })
        .map(|e| e.kind.clone())
        .collect()
}

fn ping(data: &[u8]) -> SemanticEventKind {
    SemanticEventKind::Ping {
        data: data.to_vec(),
    }
}

fn pong(data: &[u8]) -> SemanticEventKind {
    SemanticEventKind::Pong {
        data: data.to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Inbound delivery (derive.go processInbound ping/pong arms)
// ---------------------------------------------------------------------------

#[test]
fn empty_ping_and_pong_deliver_events_and_never_reply() {
    // Q18: the reference model's ping arm ONLY records the event
    // (derive.go:671-675) — no automatic pong exists in its observable
    // space, so the core must emit ZERO writes.
    let obs = replay_seed("us015/empty-ping.hex", Role::Client);
    assert!(obs.result.is_ok());
    assert_eq!(controls(&obs), vec![ping(&[])]);
    assert!(obs.writes.is_empty(), "no automatic pong (Q18)");
    assert_eq!(obs.counts.frames, 1);
    assert_eq!(obs.counts.consumed_bytes, 2);

    let obs = replay_seed("us015/empty-pong.hex", Role::Client);
    assert!(obs.result.is_ok());
    assert_eq!(controls(&obs), vec![pong(&[])]);
    assert!(obs.writes.is_empty());
}

#[test]
fn pong_with_payload_is_observed_but_never_replied_to() {
    let obs = replay_seed("us015/no-unwanted-reply.hex", Role::Client);
    assert!(obs.result.is_ok());
    assert_eq!(controls(&obs), vec![pong(b"stable")]);
    assert!(obs.writes.is_empty(), "pong never triggers any reply");
    assert_eq!(obs.state, ReadyState::Open);
}

#[test]
fn masked_control_payloads_unmask_byte_exactly() {
    let obs = replay_seed("us015/masked-ping.hex", Role::Server);
    assert!(obs.result.is_ok());
    assert_eq!(controls(&obs), vec![ping(b"ping")]);

    let obs = replay_seed("us015/masked-pong.hex", Role::Server);
    assert!(obs.result.is_ok());
    assert_eq!(controls(&obs), vec![pong(b"pong")]);
}

#[test]
fn control_payload_bytes_are_preserved_exactly() {
    // The payload-loss seed regression: arbitrary (non-UTF-8) control bytes
    // deliver verbatim — control payloads are NEVER charset-validated
    // (derive.go has no UTF-8 gate on ping/pong).
    let obs = replay_seed("us015/payload-loss.hex", Role::Client);
    assert!(obs.result.is_ok());
    assert_eq!(
        controls(&obs),
        vec![ping(&[0x00, 0xff, 0x70, 0x69, 0x6e, 0x67])]
    );
}

#[test]
fn unmasked_payload_bytes_survive_the_mask_removal_path() {
    let obs = replay_seed("us015/total-limit.hex", Role::Server);
    assert!(obs.result.is_ok());
    assert_eq!(controls(&obs), vec![ping(b"1234")]);
}

#[test]
fn coalesced_controls_deliver_in_wire_order() {
    let obs = replay_seed("us015/coalesced-controls.hex", Role::Client);
    assert!(obs.result.is_ok());
    assert_eq!(controls(&obs), vec![ping(&[]), pong(&[]), ping(b"x")]);
    assert_eq!(obs.counts.frames, 3);
    assert_eq!(obs.counts.consumed_bytes, 7);
    assert!(obs.writes.is_empty());
}

#[test]
fn repeated_pings_deliver_and_write_nothing() {
    let obs = replay_seed("us015/write-limit.hex", Role::Server);
    assert!(obs.result.is_ok());
    assert_eq!(controls(&obs), vec![ping(&[]), ping(&[])]);
    assert_eq!(obs.counts.frames, 2);
    assert!(obs.writes.is_empty());
}

// ---------------------------------------------------------------------------
// Mask-by-role: the port accepts either masking toward either role
// (derive.go:439-447 marks the mismatched shapes outside the model's
// verified space; batch A stripped the Codex rejections — these seeds
// assert the documented port acceptance, INVERTED from their originals)
// ---------------------------------------------------------------------------

#[test]
fn mask_role_mismatch_seeds_are_accepted_not_rejected() {
    let obs = replay_seed("us015/wrong-mask-client.hex", Role::Client);
    assert!(obs.result.is_ok(), "masked bytes toward a client accepted");
    assert_eq!(controls(&obs), vec![ping(&[])]);

    let obs = replay_seed("us015/wrong-mask-server.hex", Role::Server);
    assert!(
        obs.result.is_ok(),
        "unmasked bytes toward a server accepted"
    );
    assert_eq!(controls(&obs), vec![ping(&[])]);
}

// ---------------------------------------------------------------------------
// Malformed control frames (translate-time sites, quirk Q25 offsets)
// ---------------------------------------------------------------------------

#[test]
fn non_fin_control_rejects_1002_after_the_full_frame() {
    // ControlFrame.isValid fin check runs post-payload: the whole frame is
    // consumed, no frame is recorded (translate rejections discard the
    // chunk's frames and suppress input_chunk).
    let obs = replay_seed("us015/fragmented-control.hex", Role::Server);
    let err = obs.result.as_ref().expect_err("non-fin control");
    assert_eq!(err.code, FailureCode::JavaInvalidData);
    assert_eq!(err.close_code, Some(1002));
    assert_eq!(obs.counts.frames, 0);
    assert_eq!(obs.counts.consumed_bytes, 6, "full frame consumed (Q25)");
    assert!(obs.events.is_empty(), "input_chunk suppressed");
}

#[test]
fn extended_length_control_marker_rejects_at_the_base_header() {
    // derive.go:403-407 / screenIncompleteHeader: a control frame declaring
    // an extended length rejects after the 2 base header bytes, BEFORE the
    // extended length is read — here via the incomplete-header screen (the
    // declared 126-byte payload never arrives).
    let obs = replay_seed("us015/payload-126.hex", Role::Client);
    let err = obs.result.as_ref().expect_err("extended control length");
    assert_eq!(err.code, FailureCode::JavaInvalidData);
    assert_eq!(err.close_code, Some(1002));
    assert_eq!(obs.counts.consumed_bytes, 2, "base header only");
    assert_eq!(obs.counts.frames, 0);
    assert_eq!(
        obs.counts.wire_buffered_bytes, 8,
        "pending replaced before the screen (Q24 ordering)"
    );
}

#[test]
fn valid_control_before_a_reserved_opcode_is_discarded_with_the_chunk() {
    // Translate rejections discard ALL frames decoded from the same chunk
    // (Q25): the leading valid ping is never recorded or delivered.
    let obs = replay_seed("us015/valid-prefix-reserved.hex", Role::Client);
    let err = obs.result.as_ref().expect_err("reserved opcode 0xB");
    assert_eq!(err.code, FailureCode::JavaInvalidData);
    assert_eq!(err.close_code, Some(1002));
    assert_eq!(obs.counts.frames, 0, "prior valid frame discarded");
    assert_eq!(obs.counts.consumed_bytes, 4, "2 (ping) + 2 (bad header)");
    assert!(controls(&obs).is_empty());
}

// ---------------------------------------------------------------------------
// Fragmentation interleave (derive.go: control arms never touch the
// continuation accumulator)
// ---------------------------------------------------------------------------

#[test]
fn ping_interleaves_without_touching_fragment_state_and_fin_still_gates() {
    // Text start (0xf0 dangling tail passes the translate DFA), interleaved
    // empty ping, then the fin: the assembled payload f0 9f fails the
    // STRICT process-time gate with 1007 while the ping delivered normally.
    let obs = replay_seed("us015/fragment-interleave.hex", Role::Client);
    let err = obs.result.as_ref().expect_err("assembled text truncated");
    assert_eq!(err.code, FailureCode::JavaInvalidData);
    assert_eq!(err.close_code, Some(1007));
    assert_eq!(controls(&obs), vec![ping(&[])]);
    assert_eq!(obs.counts.frames, 3);
    assert_eq!(
        obs.counts.message_buffered_bytes, 1,
        "fragment accounting untouched by the ping, retained past the fin failure"
    );
}

// ---------------------------------------------------------------------------
// State gates (derive.go processInbound:637-641)
// ---------------------------------------------------------------------------

#[test]
fn inbound_ping_while_closing_is_a_state_violation_after_its_record() {
    let mut core = ConnectionCore::new_in_state(
        ConnectionConfig::default(),
        Role::Client,
        InitialState::Closing,
    );
    let err = core
        .handle(Input::TransportBytes(&seed("us015/empty-ping.hex")))
        .expect_err("closing refuses non-close frames");
    assert_eq!(err.code, FailureCode::StateViolation);
    assert_eq!(core.counts().frames, 1, "recorded before the gate");
    assert_eq!(core.counts().consumed_bytes, 2, "chunk consumed first");
}

// ---------------------------------------------------------------------------
// Send path (derive.go actionStep send_ping/send_pong; quirk Q17)
// ---------------------------------------------------------------------------

#[test]
fn send_ping_and_send_pong_emit_real_frames_with_cause_events() {
    let mut core = ConnectionCore::new_in_state(
        ConnectionConfig::default(),
        Role::Server,
        InitialState::Open,
    );
    core.handle(Input::Command(LocalCommand::SendPing {
        data: b"lively".to_vec(),
    }))
    .expect("send_ping is real behavior now");
    core.handle(Input::Command(LocalCommand::SendPong { data: vec![] }))
        .expect("send_pong is real behavior now");
    let writes: Vec<_> = std::iter::from_fn(|| core.next_write())
        .map(|w| w.bytes)
        .collect();
    assert_eq!(
        writes,
        vec![
            vec![0x89, 0x06, b'l', b'i', b'v', b'e', b'l', b'y'],
            vec![0x8a, 0x00],
        ],
        "server frames are unmasked fin controls"
    );
    let causes: Vec<_> = std::iter::from_fn(|| core.next_event())
        .filter_map(|e| match e.kind {
            SemanticEventKind::OutboundCause { cause, opcode } => Some((cause, opcode)),
            _ => None,
        })
        .collect();
    assert_eq!(
        causes,
        vec![
            (OutboundCause::SendPing, Opcode::Ping),
            (OutboundCause::SendPong, Opcode::Pong),
        ]
    );
    assert_eq!(core.counts().frames, 2);
    assert_eq!(core.counts().actions, 2);
}

#[test]
fn client_control_sends_are_masked() {
    let mut core = ConnectionCore::new_in_state(
        ConnectionConfig::default(),
        Role::Client,
        InitialState::Open,
    );
    core.handle(Input::Command(LocalCommand::SendPing {
        data: b"hb".to_vec(),
    }))
    .expect("client send_ping");
    let write = core.next_write().expect("one write");
    assert_eq!(write.bytes[0], 0x89);
    assert_eq!(write.bytes[1], 0x80 | 0x02, "mask bit set");
    assert_eq!(write.bytes.len(), 2 + 4 + 2);
    let frame = std::iter::from_fn(|| core.next_event())
        .find_map(|e| match e.kind {
            SemanticEventKind::FrameObserved(record) => Some(record),
            _ => None,
        })
        .expect("outbound frame record");
    assert!(frame.masked);
    assert_eq!(
        frame.payload,
        b"hb".to_vec(),
        "record carries semantic bytes"
    );
    assert_eq!(frame.wire_bytes, 8);
}

#[test]
fn oversized_control_payloads_send_successfully_quirk_q17() {
    // Q17: Execution.sendControl performs NO payload-size check
    // (ControlFrame.isValid checks only fin and reserved bits), so a
    // 200-byte ping SENDS with a 16-bit extended length. The Codex encoder's
    // >125 preflight rejection is deliberately NOT adopted.
    let mut core = ConnectionCore::new_in_state(
        ConnectionConfig::default(),
        Role::Server,
        InitialState::Open,
    );
    let payload = vec![0xAB; 200];
    core.handle(Input::Command(LocalCommand::SendPing {
        data: payload.clone(),
    }))
    .expect("oversized control payload sends successfully");
    let write = core.next_write().expect("one write");
    assert_eq!(write.bytes[0], 0x89);
    assert_eq!(write.bytes[1], 126, "16-bit length marker, unmasked");
    assert_eq!(&write.bytes[2..4], &200u16.to_be_bytes());
    assert_eq!(write.bytes.len(), 4 + 200);
    assert_eq!(core.counts().frames, 1);
}

#[test]
fn control_sends_require_the_open_state() {
    for initial in [InitialState::Closing, InitialState::Closed] {
        let mut core =
            ConnectionCore::new_in_state(ConnectionConfig::default(), Role::Server, initial);
        let err = core
            .handle(Input::Command(LocalCommand::SendPing { data: vec![] }))
            .expect_err("requireOpen (Q26)");
        assert_eq!(err.code, FailureCode::StateViolation);
        assert_eq!(core.counts().actions, 1, "rejected action still counted");
        assert_eq!(core.counts().frames, 0);
    }
}

// ---------------------------------------------------------------------------
// Backpressure atomicity for the raised control-era event bounds
// ---------------------------------------------------------------------------

#[test]
fn undersized_event_queue_refuses_the_chunk_before_any_mutation() {
    // Two complete ping spans need 1 + 3*2 + 2 = 9 slots under the batch-C
    // bound; a 4-slot queue must refuse with Backpressure and consume
    // NOTHING (the atomicity precheck precedes every mutation).
    let config = ConnectionConfig::builder()
        .event_queue_capacity(4)
        .build()
        .expect("valid test config");
    let mut core = ConnectionCore::new_in_state(config, Role::Client, InitialState::Open);
    let err = core
        .handle(Input::TransportBytes(&seed("us015/event-limit.hex")))
        .expect_err("4 slots < the 9-slot bound");
    assert_eq!(err.code, FailureCode::Backpressure(QueueKind::Event));
    assert_eq!(core.counts().input_bytes, 0, "nothing consumed");
    assert_eq!(core.counts().frames, 0);
    assert!(core.next_event().is_none());
    assert_eq!(core.state(), ReadyState::Open, "not poisoned (non-fatal)");
}

#[test]
fn adequately_sized_queue_delivers_the_same_chunk() {
    let obs = replay_seed("us015/event-limit.hex", Role::Client);
    assert!(obs.result.is_ok());
    assert_eq!(controls(&obs), vec![ping(&[]), ping(&[])]);
}
