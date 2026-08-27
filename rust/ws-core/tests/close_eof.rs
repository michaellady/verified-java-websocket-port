//! US-016 close-lifecycle tests: the two-way close handshake, echo-while-open
//! (Q19) with the constructor payload (Q10), close-payload parsing
//! (Q11/Q12/Q13), send-close normalization (Q14), EOF vocabulary (Q20), and
//! the closing/closed state gates (Q26).
//!
//! Scenario provenance: the six `fuzz-seeds/us016/*.seed` scenario names are
//! adopted with attribution from the Codex plane (codex-import f53f479,
//! per-file blob identity verified); each named scenario below is
//! RE-DERIVED from the reference model `internal/corpora/derive.go`
//! (`processInbound` close arm, `sendClose`, `eof`, `parseCloseSemantics`).
//! The Codex close machine is RFC-strict where shipped Java is not, so its
//! behavioral expectations are corrected wholesale (each site documented at
//! its test):
//!
//! - their one-byte-payload rejection (`PayloadLengthOne`) is NOT Java:
//!   `CloseFrame.setPayload` maps one byte to code 1002 with an empty
//!   reason, a VALID close (Q11);
//! - their exact code/reason acknowledgement echo (`AcknowledgementMismatch`)
//!   is NOT Java: the echoed frame object always carries the CONSTRUCTOR
//!   payload `[0x03, 0xe8]` (Q10), never the wire payload;
//! - their EOF failure classes (`UnexpectedEofOpen`, `EofBeforePeerClose`,
//!   ...) are NOT Java: EOF is always an ordinary transition with the Q20
//!   close vocabulary;
//! - their RFC close-code table (role-dependent codes, unassigned-code
//!   rejection) is replaced by the shipped `CloseFrame.isValid` chain,
//!   which lives in the existing US-009 pure functions
//!   `ws_core::close::{normalize_send_close_code, close_code_rejection}` —
//!   the lifecycle here CALLS those functions, it does not reimplement them.

use ws_core::CloseDetail;
use ws_core::close::CloseOrigin;
use ws_core::config::ConnectionConfig;
use ws_core::connection::{ConnectionCore, InitialState, Input, LocalCommand, ReadyState, Role};
use ws_core::error::FailureCode;
use ws_core::event::{OutboundCause, SemanticEventKind, TransitionCause};
use ws_core::framing::{CLOSE_CONSTRUCTOR_PAYLOAD, Opcode};

fn open_core(role: Role) -> ConnectionCore {
    ConnectionCore::new_in_state(ConnectionConfig::default(), role, InitialState::Open)
}

fn drain_events(core: &mut ConnectionCore) -> Vec<SemanticEventKind> {
    std::iter::from_fn(|| core.next_event())
        .map(|e| e.kind)
        .collect()
}

fn drain_writes(core: &mut ConnectionCore) -> Vec<Vec<u8>> {
    std::iter::from_fn(|| core.next_write())
        .map(|w| w.bytes)
        .collect()
}

fn remote_close(code: u16, reason: &str, handshake_complete: bool) -> CloseDetail {
    CloseDetail {
        code,
        reason: reason.to_owned(),
        origin: CloseOrigin::Remote,
        remote: true,
        handshake_complete,
    }
}

// ---------------------------------------------------------------------------
// Inbound close while OPEN: event, echo (Q19/Q10), Closing (derive.go
// processInbound close arm)
// ---------------------------------------------------------------------------

#[test]
fn inbound_close_while_open_echoes_the_constructor_payload() {
    let mut core = open_core(Role::Client);
    // Unmasked close toward a client: code 1011, reason "c".
    core.handle(Input::TransportBytes(&[0x88, 0x03, 0x03, 0xf3, b'c']))
        .expect("remote close while open is an ok outcome");
    assert_eq!(core.state(), ReadyState::Closing, "closing, NOT closed");
    assert_eq!(
        core.close_detail(),
        Some(&remote_close(1011, "c", true)),
        "remote close: handshake_complete true (derive.go closeMap)"
    );
    let writes = drain_writes(&mut core);
    assert_eq!(writes.len(), 1, "exactly one echo write");
    // Client echo: fin close frame, masked, constructor payload (Q10) —
    // never the wire code/reason (the Codex AcknowledgementMismatch echo
    // contract is NOT adopted).
    assert_eq!(writes[0][0], 0x88);
    assert_eq!(writes[0][1], 0x80 | 0x02, "masked 2-byte payload");
    let events = drain_events(&mut core);
    let mut frames = events.iter().filter_map(|kind| match kind {
        SemanticEventKind::FrameObserved(record) => Some(record),
        _ => None,
    });
    let inbound = frames.next().expect("inbound record");
    assert_eq!(
        inbound.payload,
        CLOSE_CONSTRUCTOR_PAYLOAD.to_vec(),
        "Q10: the inbound close RECORD carries the constructor payload"
    );
    assert_eq!(inbound.wire_bytes, 5, "wire size is the real frame");
    let echo = frames.next().expect("echo record");
    assert_eq!(echo.opcode, Opcode::Closing);
    assert_eq!(echo.payload, CLOSE_CONSTRUCTOR_PAYLOAD.to_vec());
    assert_eq!(echo.wire_bytes, 8, "2 header + 4 mask + 2 payload");
    assert!(
        events.iter().any(|kind| matches!(
            kind,
            SemanticEventKind::OutboundCause {
                cause: OutboundCause::EchoClose,
                opcode: Opcode::Closing,
            }
        )),
        "echo_close cause event"
    );
    assert!(
        events.iter().any(|kind| matches!(
            kind,
            SemanticEventKind::Transition {
                from: ReadyState::Open,
                to: ReadyState::Closing,
                cause: TransitionCause::ReceiveClose,
            }
        )),
        "open -> closing via receive_close"
    );
    // Event order: close BEFORE the echo cause (derive.go emits the close
    // event, then emitOutbound).
    let close_at = events
        .iter()
        .position(|kind| matches!(kind, SemanticEventKind::Close(_)))
        .expect("close event");
    let echo_at = events
        .iter()
        .position(|kind| {
            matches!(
                kind,
                SemanticEventKind::OutboundCause {
                    cause: OutboundCause::EchoClose,
                    ..
                }
            )
        })
        .expect("echo cause");
    assert!(close_at < echo_at);
    assert_eq!(core.counts().frames, 2);
}

#[test]
fn server_echo_is_unmasked() {
    let mut core = open_core(Role::Server);
    // Masked close toward a server: code 1000, empty reason.
    core.handle(Input::TransportBytes(&[
        0x88, 0x82, 0x00, 0x00, 0x00, 0x00, 0x03, 0xe8,
    ]))
    .expect("remote close ok");
    let writes = drain_writes(&mut core);
    assert_eq!(writes, vec![vec![0x88, 0x02, 0x03, 0xe8]], "unmasked echo");
    assert_eq!(core.state(), ReadyState::Closing);
}

// ---------------------------------------------------------------------------
// Inbound close while CLOSING: terminal, no echo
// ---------------------------------------------------------------------------

#[test]
fn inbound_close_while_closing_terminates_without_echo() {
    let mut core = ConnectionCore::new_in_state(
        ConnectionConfig::default(),
        Role::Server,
        InitialState::Closing,
    );
    core.handle(Input::TransportBytes(&[
        0x88, 0x82, 0x00, 0x00, 0x00, 0x00, 0x03, 0xf3,
    ]))
    .expect("close in closing completes the handshake");
    assert_eq!(core.state(), ReadyState::Closed);
    assert_eq!(core.close_detail(), Some(&remote_close(1011, "", true)));
    assert!(drain_writes(&mut core).is_empty(), "no echo from closing");
    let events = drain_events(&mut core);
    assert!(events.iter().any(|kind| matches!(
        kind,
        SemanticEventKind::Transition {
            from: ReadyState::Closing,
            to: ReadyState::Closed,
            cause: TransitionCause::ReceiveClose,
        }
    )));
    assert_eq!(core.counts().frames, 1, "no outbound frame");
}

#[test]
fn peer_close_twice_in_one_chunk_reaches_closed() {
    // us016/duplicate-terminal.seed scenario (peer-close-twice), re-derived:
    // Java treats the second peer close as the CLOSING-state completion —
    // ok outcome, closed — not the Codex DuplicatePeerClose failure.
    let mut core = open_core(Role::Client);
    core.handle(Input::TransportBytes(&[
        0x88, 0x02, 0x03, 0xe8, 0x88, 0x02, 0x03, 0xe8,
    ]))
    .expect("both closes process");
    assert_eq!(core.state(), ReadyState::Closed);
    assert_eq!(core.counts().frames, 3, "in + echo + in");
    assert_eq!(drain_writes(&mut core).len(), 1, "one echo only");
    let transitions: Vec<_> = drain_events(&mut core)
        .into_iter()
        .filter(|kind| matches!(kind, SemanticEventKind::Transition { .. }))
        .collect();
    assert_eq!(transitions.len(), 2, "open->closing, closing->closed");
}

#[test]
fn a_third_close_after_terminal_is_a_state_violation() {
    let mut core = open_core(Role::Client);
    let err = core
        .handle(Input::TransportBytes(&[
            0x88, 0x02, 0x03, 0xe8, 0x88, 0x02, 0x03, 0xe8, 0x88, 0x02, 0x03, 0xe8,
        ]))
        .expect_err("closed refuses everything");
    assert_eq!(err.code, FailureCode::StateViolation);
    assert_eq!(
        core.counts().frames,
        4,
        "the third close records, then gates"
    );
}

// ---------------------------------------------------------------------------
// Local close (derive.go sendClose; Q13/Q14 via the US-009 pure fns)
// ---------------------------------------------------------------------------

#[test]
fn local_close_emits_frame_detail_and_transition() {
    let mut core = open_core(Role::Server);
    core.handle(Input::Command(LocalCommand::SendClose {
        code: 1011,
        reason: "KXidn".to_owned(),
    }))
    .expect("valid local close");
    assert_eq!(core.state(), ReadyState::Closing);
    assert_eq!(
        core.close_detail(),
        Some(&CloseDetail {
            code: 1011,
            reason: "KXidn".to_owned(),
            origin: CloseOrigin::Local,
            remote: false,
            handshake_complete: false,
        })
    );
    let writes = drain_writes(&mut core);
    assert_eq!(
        writes,
        vec![vec![0x88, 0x07, 0x03, 0xf3, b'K', b'X', b'i', b'd', b'n']],
        "BE code + reason payload, unmasked for the server"
    );
    let events = drain_events(&mut core);
    let cause_at = events
        .iter()
        .position(|kind| {
            matches!(
                kind,
                SemanticEventKind::OutboundCause {
                    cause: OutboundCause::SendClose,
                    opcode: Opcode::Closing,
                }
            )
        })
        .expect("send_close cause");
    let initiated_at = events
        .iter()
        .position(|kind| matches!(kind, SemanticEventKind::CloseInitiated(_)))
        .expect("close_initiated event");
    assert!(
        cause_at < initiated_at,
        "derive.go: emitOutbound precedes close_initiated"
    );
    assert!(events.iter().any(|kind| matches!(
        kind,
        SemanticEventKind::Transition {
            from: ReadyState::Open,
            to: ReadyState::Closing,
            cause: TransitionCause::SendClose,
        }
    )));
    assert_eq!(core.counts().actions, 1);
    assert_eq!(core.counts().frames, 1);
}

#[test]
fn local_close_then_remote_close_terminates() {
    // us016/premature-closed.seed scenario (local-peer-before-flush),
    // re-derived: Java completes the handshake regardless of write flushing
    // (flush timing is transport policy, not core state).
    let mut core = open_core(Role::Client);
    core.handle(Input::Command(LocalCommand::SendClose {
        code: 1011,
        reason: "KXidn".to_owned(),
    }))
    .expect("local close");
    core.handle(Input::TransportBytes(&[0x88, 0x03, 0x03, 0xf3, b'c']))
        .expect("remote close completes");
    assert_eq!(core.state(), ReadyState::Closed);
    assert_eq!(
        core.close_detail(),
        Some(&remote_close(1011, "c", true)),
        "the REMOTE close overwrites the governing detail (derive.go)"
    );
    assert_eq!(core.counts().frames, 2, "outbound close + inbound close");
    assert_eq!(drain_writes(&mut core).len(), 1, "no echo from closing");
}

#[test]
fn local_close_then_eof_reports_the_governing_close_over_transport() {
    // us016/missing-ack.seed scenario (peer-first-client-eof analog for the
    // local-first order; corpus family close-local-then-eof): EOF after a
    // local close is Java's ordinary Q20 vocabulary — never the Codex
    // EofBeforePeerClose failure.
    let mut core = open_core(Role::Client);
    core.handle(Input::Command(LocalCommand::SendClose {
        code: 1001,
        reason: "MR{fS".to_owned(),
    }))
    .expect("local close");
    core.handle(Input::TransportEof).expect("eof in closing");
    assert_eq!(core.state(), ReadyState::Closed);
    assert_eq!(
        core.close_detail(),
        Some(&CloseDetail {
            code: 1001,
            reason: "MR{fS".to_owned(),
            origin: CloseOrigin::Transport,
            remote: true,
            handshake_complete: false,
        }),
        "Q20: closing echoes the governing code/reason; handshake_complete \
         stays false for a local-only close"
    );
    assert_eq!(
        core.counts().actions,
        2,
        "eof participates in the accounting"
    );
}

#[test]
fn remote_close_then_eof_keeps_handshake_complete() {
    let mut core = open_core(Role::Client);
    core.handle(Input::TransportBytes(&[0x88, 0x02, 0x03, 0xe8]))
        .expect("remote close");
    core.handle(Input::TransportEof).expect("eof in closing");
    let detail = core.close_detail().expect("governing close");
    assert_eq!(detail.origin, CloseOrigin::Transport);
    assert_eq!(detail.code, 1000);
    assert!(detail.handshake_complete, "remote close had completed it");
    assert!(detail.remote);
}

#[test]
fn send_close_invalid_code_rejects_without_a_frame() {
    // Corpus family send-close-invalid-code (us005.pub.0000): code 999 fails
    // the CloseFrame.isValid chain (Q13, via close_code_rejection) with
    // reported code 1002; NO frame is emitted, the state stays open, the
    // action is counted.
    let mut core = open_core(Role::Client);
    let err = core
        .handle(Input::Command(LocalCommand::SendClose {
            code: 999,
            reason: "bad".to_owned(),
        }))
        .expect_err("code below 1000 rejects");
    assert_eq!(err.code, FailureCode::JavaInvalidData);
    assert_eq!(err.close_code, Some(1002));
    assert_eq!(core.counts().frames, 0);
    assert_eq!(core.counts().actions, 1);
    assert_eq!(core.state(), ReadyState::Open);
    assert!(core.close_detail().is_none());
    assert!(drain_writes(&mut core).is_empty());
}

#[test]
fn send_close_1015_normalizes_to_1005_then_rejects_1002() {
    // Q14 wiring: setCode maps 1015 -> 1005 BEFORE validation
    // (normalize_send_close_code), then isValid rejects 1005 as 1002
    // (close_code_rejection) — the lifecycle must call the existing US-009
    // pure functions in exactly this order.
    let mut core = open_core(Role::Server);
    let err = core
        .handle(Input::Command(LocalCommand::SendClose {
            code: 1015,
            reason: String::new(),
        }))
        .expect_err("1015 normalizes into the rejected 1005");
    assert_eq!(err.code, FailureCode::JavaInvalidData);
    assert_eq!(err.close_code, Some(1002));
}

#[test]
fn send_close_1007_with_empty_reason_reports_1007() {
    // Q13 first chain link: 1007 with an empty reason rejects as 1007.
    let mut core = open_core(Role::Server);
    let err = core
        .handle(Input::Command(LocalCommand::SendClose {
            code: 1007,
            reason: String::new(),
        }))
        .expect_err("1007 empty-reason link");
    assert_eq!(err.code, FailureCode::JavaInvalidData);
    assert_eq!(err.close_code, Some(1007));
}

#[test]
fn send_close_requires_the_open_state() {
    for initial in [InitialState::Closing, InitialState::Closed] {
        let mut core =
            ConnectionCore::new_in_state(ConnectionConfig::default(), Role::Server, initial);
        let err = core
            .handle(Input::Command(LocalCommand::SendClose {
                code: 1000,
                reason: String::new(),
            }))
            .expect_err("requireOpen (Q26)");
        assert_eq!(err.code, FailureCode::StateViolation);
        assert_eq!(core.counts().actions, 1);
    }
}

// ---------------------------------------------------------------------------
// Close payload parsing at translate time (Q11/Q12/Q13)
// ---------------------------------------------------------------------------

#[test]
fn one_byte_close_payload_is_a_valid_1002_close() {
    // Q11 (us016 corpus family close-payload-1): CloseFrame.setPayload maps
    // a one-byte payload to code 1002 with an empty reason — a VALID close
    // (the Codex PayloadLengthOne rejection is NOT Java). The frame record
    // still carries the constructor payload (Q10).
    let mut core = open_core(Role::Server);
    core.handle(Input::TransportBytes(&[
        0x88, 0x81, 0xb7, 0xbe, 0x28, 0x83, 0xb4,
    ]))
    .expect("one-byte close is valid");
    assert_eq!(core.state(), ReadyState::Closing);
    assert_eq!(core.close_detail(), Some(&remote_close(1002, "", true)));
    let events = drain_events(&mut core);
    let inbound = events
        .iter()
        .find_map(|kind| match kind {
            SemanticEventKind::FrameObserved(record) if record.wire_bytes == 7 => Some(record),
            _ => None,
        })
        .expect("inbound record");
    assert_eq!(inbound.payload, CLOSE_CONSTRUCTOR_PAYLOAD.to_vec());
}

#[test]
fn inbound_close_code_1005_rejects_at_translate() {
    // us016/wrong-code.seed scenario (inbound-invalid-code-1005): the wire
    // sentinel 1005 fails CloseFrame.isValid with reported code 1002 at
    // TRANSLATE time — the whole frame consumed, nothing recorded.
    let mut core = open_core(Role::Client);
    let err = core
        .handle(Input::TransportBytes(&[0x88, 0x02, 0x03, 0xed]))
        .expect_err("1005 on the wire rejects");
    assert_eq!(err.code, FailureCode::JavaInvalidData);
    assert_eq!(err.close_code, Some(1002));
    assert_eq!(core.counts().frames, 0);
    assert_eq!(core.counts().consumed_bytes, 4, "full frame (Q25)");
    assert_eq!(core.state(), ReadyState::Open);
    assert!(core.close_detail().is_none());
}

#[test]
fn invalid_utf8_close_reason_is_the_java_runtime_rejection() {
    // Q12: an invalid reason becomes a null reason whose isValid dereference
    // raises Java's NullPointerException — JAVA_RUNTIME_REJECTION, no close
    // code, at translate time.
    let mut core = open_core(Role::Client);
    let err = core
        .handle(Input::TransportBytes(&[0x88, 0x03, 0x03, 0xe8, 0xff]))
        .expect_err("invalid reason bytes");
    assert_eq!(err.code, FailureCode::JavaRuntimeRejection);
    assert_eq!(err.close_code, None);
    assert_eq!(core.counts().consumed_bytes, 5);
    assert_eq!(core.counts().frames, 0);
}

// ---------------------------------------------------------------------------
// Interaction with data state (us016 data-after-close / stale-fragment)
// ---------------------------------------------------------------------------

#[test]
fn send_text_after_local_close_is_a_state_violation() {
    // us016/data-after-close.seed scenario (local-close-then-text),
    // re-derived: Java refuses through requireOpen (STATE_VIOLATION with the
    // action counted) — not the Codex DataAfterClose close-failure.
    let mut core = open_core(Role::Server);
    core.handle(Input::Command(LocalCommand::SendClose {
        code: 1000,
        reason: String::new(),
    }))
    .expect("local close");
    let err = core
        .handle(Input::Command(LocalCommand::SendText {
            text: "late".to_owned(),
        }))
        .expect_err("sends after closing refuse");
    assert_eq!(err.code, FailureCode::StateViolation);
    assert_eq!(core.counts().actions, 2, "the refused send is counted");
}

#[test]
fn continuation_after_local_close_is_stale() {
    // us016/stale-fragment.seed scenario (fragment-local-close-continuation),
    // re-derived: Java permits send_close DURING an open inbound fragment
    // (sendClose has no fragment gate), and the later continuation then hits
    // the CLOSING state gate — STATE_VIOLATION after its frame record.
    let mut core = open_core(Role::Client);
    core.handle(Input::TransportBytes(&[0x01, 0x01, b'a']))
        .expect("fragment start");
    core.handle(Input::Command(LocalCommand::SendClose {
        code: 1000,
        reason: String::new(),
    }))
    .expect("close during an open inbound fragment is legal");
    let err = core
        .handle(Input::TransportBytes(&[0x80, 0x01, b'b']))
        .expect_err("continuation in closing");
    assert_eq!(err.code, FailureCode::StateViolation);
    assert_eq!(
        core.counts().frames,
        3,
        "start + close + continuation record"
    );
    assert_eq!(
        core.counts().message_buffered_bytes,
        1,
        "fragment accounting retained"
    );
}

// ---------------------------------------------------------------------------
// The echo respects the frame budget (derive.go emitOutbound)
// ---------------------------------------------------------------------------

#[test]
fn echo_close_hits_the_frame_budget_after_the_close_event() {
    let config = ConnectionConfig::builder()
        .max_frames(1)
        .build()
        .expect("valid test config");
    let mut core = ConnectionCore::new_in_state(config, Role::Client, InitialState::Open);
    let err = core
        .handle(Input::TransportBytes(&[0x88, 0x02, 0x03, 0xe8]))
        .expect_err("no budget for the echo frame");
    assert_eq!(err.code, FailureCode::FrameLimitExceeded);
    let events = drain_events(&mut core);
    assert!(
        events
            .iter()
            .any(|kind| matches!(kind, SemanticEventKind::Close(_))),
        "the close event precedes the budget failure (derive.go order)"
    );
    assert_eq!(core.counts().frames, 1, "inbound recorded; echo refused");
}
