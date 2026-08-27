//! US-014 fragmentation tests: reassembly, sequence violations, retention
//! accounting (Q23/Q24 interplay), cross-frame UTF-8 timing, and the
//! outbound `send_fragment` path (written fresh against the reference model
//! — the borrowed chain has no outbound fragment path).
//!
//! Seed provenance: `fuzz-seeds/us014/*.hex` adopted with attribution from
//! the Codex plane (codex-import dca0fdb); every expectation below is
//! re-derived from `internal/corpora/derive.go` `processDataFrame` /
//! `sendFragment`.

use ws_core::config::ConnectionConfig;
use ws_core::connection::{
    ConnectionCore, DataOpcode, InitialState, Input, LocalCommand, ReadyState, Role,
};
use ws_core::error::{FailureCode, TypedProtocolFailure};
use ws_core::event::{Counts, SemanticEvent, SemanticEventKind};
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
    counts: Counts,
    state: ReadyState,
}

fn replay_bytes(config: ConnectionConfig, bytes: &[u8]) -> Replay {
    let mut core = ConnectionCore::new_in_state(config, Role::Client, InitialState::Open);
    let result = core.handle(Input::TransportBytes(bytes));
    let events = std::iter::from_fn(|| core.next_event()).collect();
    Replay {
        result,
        events,
        counts: core.counts(),
        state: core.state(),
    }
}

fn replay_seed(name: &str) -> Replay {
    replay_bytes(ConnectionConfig::default(), &seed(name))
}

fn messages(replay: &Replay) -> Vec<SemanticEventKind> {
    replay
        .events
        .iter()
        .filter(|e| {
            matches!(
                e.kind,
                SemanticEventKind::Text { .. } | SemanticEventKind::Binary { .. }
            )
        })
        .map(|e| e.kind.clone())
        .collect()
}

fn text(value: &str) -> SemanticEventKind {
    SemanticEventKind::Text {
        text: value.to_owned(),
    }
}

fn binary(data: &[u8]) -> SemanticEventKind {
    SemanticEventKind::Binary {
        data: data.to_vec(),
    }
}

// ---------------------------------------------------------------------------
// Legal reassembly
// ---------------------------------------------------------------------------

#[test]
fn legal_text_and_binary_sequences_reassemble() {
    let obs = replay_seed("us014/legal-text.hex");
    assert!(obs.result.is_ok());
    assert_eq!(messages(&obs), vec![text("hi!!")]);
    assert_eq!(obs.counts.frames, 2);
    assert_eq!(obs.counts.message_buffered_bytes, 0, "reset after delivery");

    let obs = replay_seed("us014/legal-binary.hex");
    assert!(obs.result.is_ok());
    assert_eq!(messages(&obs), vec![binary(&[0x00, 0x02])]);
}

#[test]
fn empty_fragments_assemble_an_empty_message() {
    let obs = replay_seed("us014/empty-message.hex");
    assert!(obs.result.is_ok());
    assert_eq!(messages(&obs), vec![text("")]);
    assert_eq!(obs.counts.frames, 2);
}

#[test]
fn delivery_resets_state_for_the_next_message() {
    for (name, expected) in [
        ("us014/reset-next-message.hex", vec![text("ab"), text("cd")]),
        (
            "us014/double-delivery.hex",
            vec![text("ab"), binary(&[0x63])],
        ),
    ] {
        let obs = replay_seed(name);
        assert!(obs.result.is_ok(), "{name}");
        assert_eq!(messages(&obs), expected, "{name}");
        assert_eq!(obs.counts.message_buffered_bytes, 0, "{name}");
    }
}

#[test]
fn cross_frame_utf8_scalar_split_reassembles() {
    // A 4-byte scalar split across the fragment boundary: the translate DFA
    // accepts each fragment's dangling tail; the strict gate sees the
    // assembled whole.
    let obs = replay_seed("us014/utf8-cross-frame.hex");
    assert!(obs.result.is_ok());
    assert_eq!(messages(&obs), vec![text("\u{1F980}")]);
}

// ---------------------------------------------------------------------------
// Sequence violations (process-time 1002, after the frame record)
// ---------------------------------------------------------------------------

#[test]
fn orphan_continuation_rejects_1002_after_its_frame_record() {
    let obs = replay_seed("us014/orphan-continuation.hex");
    let err = obs.result.as_ref().expect_err("orphan continuation");
    assert_eq!(err.code, FailureCode::JavaInvalidData);
    assert_eq!(err.close_code, Some(1002));
    assert_eq!(
        obs.counts.frames, 1,
        "process-time rejection: the frame IS recorded (unlike translate rejections)"
    );
    assert_eq!(obs.counts.consumed_bytes, 3, "whole chunk consumed first");
}

#[test]
fn prior_delivery_survives_a_later_orphan_in_the_same_chunk() {
    // derive.go processes frames sequentially AFTER translate: the first
    // frame's binary delivery stands; the orphan continuation then rejects.
    let obs = replay_seed("us014/prior-valid-orphan.hex");
    let err = obs.result.as_ref().expect_err("orphan follows delivery");
    assert_eq!(err.code, FailureCode::JavaInvalidData);
    assert_eq!(err.close_code, Some(1002));
    assert_eq!(messages(&obs), vec![binary(&[0x62])], "delivery retained");
    assert_eq!(obs.counts.frames, 2);
}

#[test]
fn data_frame_during_an_open_fragment_rejects_1002() {
    let obs = replay_seed("us014/data-restart.hex");
    let err = obs.result.as_ref().expect_err("data during fragment");
    assert_eq!(err.code, FailureCode::JavaInvalidData);
    assert_eq!(err.close_code, Some(1002));
    assert_eq!(obs.counts.frames, 2, "both frames recorded before the gate");
    assert_eq!(
        obs.counts.message_buffered_bytes, 1,
        "the open fragment's accounting is retained"
    );
}

#[test]
fn control_interleave_is_honestly_unimplemented_until_us015() {
    // The seed interleaves a ping inside an open fragment sequence. The
    // fragment plane is US-014's, but the ping PROCESSING arm is US-015's:
    // the port records the ping frame and then refuses with the non-oracle
    // Unimplemented code instead of faking Java. Batch C replaces this
    // expectation with the full interleave delivery.
    let obs = replay_seed("us014/control-interleave.hex");
    let err = obs.result.as_ref().expect_err("ping processing is US-015");
    assert_eq!(err.code, FailureCode::Unimplemented);
    assert_eq!(err.close_code, None);
    assert_eq!(obs.counts.frames, 2, "start + ping recorded before the arm");
    assert_eq!(obs.counts.message_buffered_bytes, 1);
}

// ---------------------------------------------------------------------------
// Retention accounting: Q23 fin-time 1009 vs adapter add-bounded
// ---------------------------------------------------------------------------

fn tight_config(limit: u64) -> ConnectionConfig {
    // The corpus maps max_buffered_bytes onto the frame/message/buffer trio;
    // mirror that mapping so the retention gates see the same value.
    ConnectionConfig::builder()
        .max_frame_payload_bytes(limit)
        .max_message_bytes(limit)
        .max_buffered_bytes(limit)
        .build()
        .expect("valid test config")
}

#[test]
fn exact_retention_at_the_cap_delivers() {
    // Assembled size 4 against cap 4: checkBufferLimit passes (strictly
    // greater rejects — derive.go:722-726).
    let obs = replay_bytes(tight_config(4), &seed("us014/exact-retention.hex"));
    assert!(obs.result.is_ok());
    assert_eq!(messages(&obs), vec![binary(b"abcd")]);
    assert_eq!(obs.counts.message_buffered_bytes, 0);
}

#[test]
fn plus_one_retention_rejects_1009_at_the_fin_with_accounting_retained() {
    // The same wire bytes against cap 3: the fin-time cumulative check
    // rejects with close code 1009 (Q23), and message_buffered_bytes stays
    // at the pre-fin value (derive.go returns before resetting it).
    let obs = replay_bytes(tight_config(3), &seed("us014/plus-one-retention.hex"));
    let err = obs.result.as_ref().expect_err("4 > 3 at the fin");
    assert_eq!(err.code, FailureCode::JavaInvalidData);
    assert_eq!(err.close_code, Some(1009));
    assert_eq!(obs.counts.frames, 2);
    assert_eq!(
        obs.counts.message_buffered_bytes, 2,
        "pre-fin value retained"
    );
    assert!(messages(&obs).is_empty());
}

#[test]
fn non_fin_continuation_overflow_is_the_adapter_add_bounded_failure() {
    // derive.go:707-712: a NON-fin continuation that overflows trips the
    // adapter's own accounting — BUFFER_LIMIT_EXCEEDED with NO close code,
    // and the counter is never updated past the bound.
    let mut stream = vec![0x02, 0x02, b'a', b'b']; // binary start, 2 bytes
    stream.extend_from_slice(&[0x00, 0x02, b'c', b'd']); // non-fin continuation
    let obs = replay_bytes(tight_config(3), &stream);
    let err = obs.result.as_ref().expect_err("2 + 2 > 3 mid-sequence");
    assert_eq!(err.code, FailureCode::BufferLimitExceeded);
    assert_eq!(
        err.close_code, None,
        "adapter accounting carries no close code"
    );
    assert_eq!(
        obs.counts.message_buffered_bytes, 2,
        "add-bounded: no partial update"
    );
    assert_eq!(obs.counts.frames, 2);
}

#[test]
fn invalid_middle_utf8_stays_buffered_until_a_fin_forces_the_strict_gate() {
    // A continuation fragment carrying invalid UTF-8 is NOT validated
    // mid-sequence (Java validates the assembled text only at the fin):
    // without a fin the sequence simply stays open.
    let obs = replay_seed("us014/invalid-middle-utf8.hex");
    assert!(obs.result.is_ok(), "no fin, no strict validation yet");
    assert_eq!(obs.counts.frames, 2);
    assert_eq!(obs.counts.message_buffered_bytes, 2);
    assert_eq!(obs.state, ReadyState::Open);
}

#[test]
fn truncated_final_utf8_rejects_1007_at_the_fin_and_keeps_the_accounting() {
    // Two-stage timing across fragments: the dangling tail passed every
    // translate DFA; the strict gate rejects the ASSEMBLED text at the fin
    // with 1007, and message_buffered_bytes keeps its pre-fin value
    // (derive.go emitMessage fails before messageBuffered resets).
    let obs = replay_seed("us014/truncated-final-utf8.hex");
    let err = obs
        .result
        .as_ref()
        .expect_err("assembled text is truncated");
    assert_eq!(err.code, FailureCode::JavaInvalidData);
    assert_eq!(err.close_code, Some(1007));
    assert_eq!(obs.counts.frames, 2);
    assert_eq!(
        obs.counts.message_buffered_bytes, 1,
        "pre-fin value retained"
    );
}

// ---------------------------------------------------------------------------
// Outbound send_fragment (derive.go sendFragment / Draft.continuousFrame)
// ---------------------------------------------------------------------------

fn open_core(role: Role) -> ConnectionCore {
    ConnectionCore::new_in_state(ConnectionConfig::default(), role, InitialState::Open)
}

fn send_fragment(
    core: &mut ConnectionCore,
    opcode: DataOpcode,
    data: &[u8],
    fin: bool,
) -> Result<(), TypedProtocolFailure> {
    core.handle(Input::Command(LocalCommand::SendFragment {
        opcode,
        data: data.to_vec(),
        fin,
    }))
}

#[test]
fn send_fragment_sequence_declares_then_continues_then_closes() {
    // derive.go sendFragment: first frame keeps the declared opcode; later
    // frames are continuations; fin closes the sequence and the next
    // sequence redeclares.
    let mut core = open_core(Role::Server);
    send_fragment(&mut core, DataOpcode::Binary, b"ab", false).expect("start");
    send_fragment(&mut core, DataOpcode::Binary, b"cd", false).expect("middle");
    send_fragment(&mut core, DataOpcode::Binary, b"ef", true).expect("fin");
    send_fragment(&mut core, DataOpcode::Text, b"x", true).expect("fresh single-frame");
    let writes: Vec<_> = std::iter::from_fn(|| core.next_write()).collect();
    assert_eq!(
        writes.iter().map(|w| w.bytes.clone()).collect::<Vec<_>>(),
        vec![
            vec![0x02, 0x02, b'a', b'b'], // binary, non-fin
            vec![0x00, 0x02, b'c', b'd'], // continuation, non-fin
            vec![0x80, 0x02, b'e', b'f'], // continuation, fin
            vec![0x81, 0x01, b'x'],       // fresh fin text keeps its opcode
        ]
    );
    let opcodes: Vec<_> = std::iter::from_fn(|| core.next_event())
        .filter_map(|e| match e.kind {
            SemanticEventKind::OutboundCause { cause, opcode } => Some((cause, opcode)),
            _ => None,
        })
        .collect();
    use ws_core::event::OutboundCause::SendFragment as Cause;
    assert_eq!(
        opcodes,
        vec![
            (Cause, Opcode::Binary),
            (Cause, Opcode::Continuous),
            (Cause, Opcode::Continuous),
            (Cause, Opcode::Text),
        ],
        "the cause events carry the WIRE opcode (derive.go emitOutbound)"
    );
    assert_eq!(core.counts().frames, 4);
    assert_eq!(core.counts().actions, 4);
}

#[test]
fn first_text_fragment_runs_the_send_dfa_and_truncated_tails_pass() {
    // derive.go:938-943: Draft.continuousFrame builds a TextFrame whose
    // isValid applies the DFA — definitely invalid content is
    // JAVA_NOT_SENDABLE; a truncated tail PASSES and is sent.
    let mut core = open_core(Role::Server);
    let err = send_fragment(&mut core, DataOpcode::Text, b"\x80", false)
        .expect_err("0x80 alone is definitely invalid");
    assert_eq!(err.code, FailureCode::JavaNotSendable);
    assert_eq!(err.close_code, None);

    let mut core = open_core(Role::Server);
    send_fragment(&mut core, DataOpcode::Text, b"\xf0\x9f", false)
        .expect("a dangling tail passes the DFA and is sent");
    assert_eq!(core.counts().frames, 1);

    // Continuation fragments are NOT DFA-checked (only the first frame).
    send_fragment(&mut core, DataOpcode::Text, b"\x80\x80", false)
        .expect("continuations skip the DFA");
    assert_eq!(core.counts().frames, 2);
}

#[test]
fn send_fragment_payload_gate_precedes_the_dfa() {
    // derive.go sendFragment: requirePayloadLimit runs before the DFA, so
    // an oversized invalid payload reports BUFFER_LIMIT_EXCEEDED.
    let mut core = ConnectionCore::new_in_state(tight_config(2), Role::Server, InitialState::Open);
    let err = send_fragment(&mut core, DataOpcode::Text, b"\x80\x80\x80", false)
        .expect_err("3 > 2 payload limit");
    assert_eq!(err.code, FailureCode::BufferLimitExceeded);
}

#[test]
fn inbound_fragments_and_outbound_sends_do_not_share_sequence_state() {
    // Java tracks inbound continuation (Draft_6455 current frame) and
    // outbound continuous type independently.
    let mut core = open_core(Role::Client);
    core.handle(Input::TransportBytes(&[0x01, 0x01, b'a']))
        .expect("inbound fragment start");
    send_fragment(&mut core, DataOpcode::Binary, b"z", false)
        .expect("outbound sequence opens independently");
    core.handle(Input::TransportBytes(&[0x80, 0x01, b'b']))
        .expect("inbound fin still assembles");
    let events: Vec<_> = std::iter::from_fn(|| core.next_event()).collect();
    assert!(
        events
            .iter()
            .any(|e| matches!(&e.kind, SemanticEventKind::Text { text } if text == "ab")),
        "inbound reassembly unaffected by the open outbound sequence"
    );
}
