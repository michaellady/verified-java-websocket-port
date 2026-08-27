//! US-013 message tests: the two-stage UTF-8 gates (quirk Q15), text and
//! binary delivery, and the borrowed deterministic seed corpus replayed
//! with Java-faithful expectations.
//!
//! Seed provenance: `fuzz-seeds/us013/*.hex` adopted with attribution from
//! the Codex plane (codex-import 0be0766..dca0fdb); every expectation below
//! is re-derived from `internal/corpora/derive.go`. The load-bearing
//! distinction this file pins: a DEFINITELY invalid text payload rejects at
//! TRANSLATE time (frame never recorded, close 1007), while a payload
//! ending in a valid-but-incomplete multi-byte tail passes the translate
//! DFA (frame RECORDED) and rejects at PROCESS time (still 1007) — the
//! two-stage truncated-tail semantics the quirk registry pins and the
//! borrowed chain's single-stage validator did not reproduce.

use ws_core::config::ConnectionConfig;
use ws_core::connection::{ConnectionCore, InitialState, Input, ReadyState, Role};
use ws_core::error::{FailureCode, TypedProtocolFailure};
use ws_core::event::{Counts, SemanticEvent, SemanticEventKind};
use ws_core::message::Charsetfunctions;

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

fn replay_seed(name: &str) -> Replay {
    let mut core = ConnectionCore::new_in_state(
        ConnectionConfig::default(),
        Role::Client,
        InitialState::Open,
    );
    let bytes = seed(name);
    let result = core.handle(Input::TransportBytes(&bytes));
    let events = std::iter::from_fn(|| core.next_event()).collect();
    Replay {
        result,
        events,
        counts: core.counts(),
        state: core.state(),
    }
}

fn texts(replay: &Replay) -> Vec<String> {
    replay
        .events
        .iter()
        .filter_map(|e| match &e.kind {
            SemanticEventKind::Text { text } => Some(text.clone()),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Stage one: translate-time DFA rejections (frame never recorded)
// ---------------------------------------------------------------------------

#[test]
fn definitely_invalid_text_rejects_at_translate_with_no_frame_record() {
    // derive.go decodeFrame:471-474 -> fail(full, 1007): the frame is
    // consumed whole but never recorded.
    for (name, wire_len) in [
        ("us013/invalid-continuation.hex", 4),
        ("us013/invalid-leading.hex", 3),
        ("us013/out-of-range.hex", 6),
        ("us013/overlong-four.hex", 6),
        ("us013/overlong-three.hex", 5),
        ("us013/overlong-two-c0.hex", 4),
        ("us013/overlong-two-c1.hex", 4),
        ("us013/surrogate.hex", 5),
        ("us013/unexpected-continuation.hex", 3),
    ] {
        let obs = replay_seed(name);
        let err = obs.result.as_ref().expect_err(name);
        assert_eq!(err.code, FailureCode::JavaInvalidData, "{name}");
        assert_eq!(err.close_code, Some(1007), "{name}");
        assert_eq!(obs.counts.frames, 0, "{name}: translate-stage rejection");
        assert_eq!(obs.counts.consumed_bytes, wire_len, "{name}: full frame");
    }
}

#[test]
fn prior_valid_frame_is_discarded_when_a_later_frame_fails_translate() {
    // derive.go builds the decoded list before recording anything: text
    // "ok" followed by an invalid text frame in one chunk records neither.
    let obs = replay_seed("us013/prior-valid-then-invalid.hex");
    let err = obs.result.as_ref().expect_err("second frame is invalid");
    assert_eq!(err.code, FailureCode::JavaInvalidData);
    assert_eq!(err.close_code, Some(1007));
    assert_eq!(obs.counts.frames, 0, "the valid 'ok' frame is NOT recorded");
    assert!(texts(&obs).is_empty(), "no text delivery");
    assert_eq!(obs.counts.consumed_bytes, 4 + 3, "span start + full frame");
}

// ---------------------------------------------------------------------------
// Stage two: truncated tails pass translate (frame recorded), reject at
// process time
// ---------------------------------------------------------------------------

#[test]
fn truncated_tails_record_the_frame_then_reject_1007_at_process_time() {
    for (name, wire_len) in [
        ("us013/truncated-two.hex", 3),
        ("us013/truncated-three.hex", 4),
        ("us013/truncated-four.hex", 5),
    ] {
        let obs = replay_seed(name);
        let err = obs.result.as_ref().expect_err(name);
        assert_eq!(err.code, FailureCode::JavaInvalidData, "{name}");
        assert_eq!(err.close_code, Some(1007), "{name}");
        assert_eq!(
            obs.counts.frames, 1,
            "{name}: the translate DFA accepted the tail, so the frame IS recorded"
        );
        assert_eq!(obs.counts.consumed_bytes, wire_len, "{name}");
        assert!(
            obs.events
                .iter()
                .any(|e| matches!(e.kind, SemanticEventKind::FrameObserved(_))),
            "{name}: frame record exists"
        );
        assert!(
            obs.events
                .iter()
                .any(|e| matches!(e.kind, SemanticEventKind::InputChunk { .. })),
            "{name}: process-stage failures happen after input_chunk"
        );
    }
}

#[test]
fn nonfinal_truncated_prefix_buffers_as_a_fragment_start() {
    // A NON-fin text frame ending in an incomplete tail passes translate
    // and simply opens a fragment sequence (strict validation waits for
    // the fin — US-014 semantics).
    let obs = replay_seed("us013/nonfinal-prefix.hex");
    assert!(obs.result.is_ok());
    assert_eq!(obs.counts.frames, 1);
    assert_eq!(obs.counts.message_buffered_bytes, 2);
    assert_eq!(obs.state, ReadyState::Open);
}

// ---------------------------------------------------------------------------
// Valid deliveries
// ---------------------------------------------------------------------------

#[test]
fn valid_text_seeds_deliver_their_decoded_scalars() {
    for (name, expected) in [
        ("us013/valid-ascii.hex", "A"),
        ("us013/valid-empty-text.hex", ""),
        ("us013/valid-two-byte.hex", "\u{0080}"),
        ("us013/valid-three-byte.hex", "\u{0800}"),
        ("us013/valid-four-byte.hex", "\u{10000}"),
    ] {
        let obs = replay_seed(name);
        assert!(obs.result.is_ok(), "{name}");
        assert_eq!(texts(&obs), vec![expected.to_owned()], "{name}");
        assert_eq!(obs.counts.frames, 1, "{name}");
        assert_eq!(obs.counts.message_buffered_bytes, 0, "{name}");
    }
}

#[test]
fn valid_binary_seed_delivers_uninterpreted_bytes() {
    let obs = replay_seed("us013/valid-binary.hex");
    assert!(obs.result.is_ok());
    let binaries: Vec<_> = obs
        .events
        .iter()
        .filter_map(|e| match &e.kind {
            SemanticEventKind::Binary { data } => Some(data.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(binaries, vec![vec![0x00, 0xff, 0x7f]]);
}

// ---------------------------------------------------------------------------
// Charsetfunctions unit properties (the proof-target symbols)
// ---------------------------------------------------------------------------

#[test]
fn the_two_gates_diverge_exactly_on_dangling_incomplete_tails() {
    // Quirk Q15: is_valid_utf8 (translate DFA) accepts an incomplete tail;
    // string_utf8 (strict) rejects it. On everything else they agree.
    let tails: [&[u8]; 5] = [
        b"\xc2",
        b"\xe1\x80",
        b"\xf0\x90\x80",
        b"ok\xc2",
        b"\xf4\x8f",
    ];
    for tail in tails {
        assert!(
            Charsetfunctions::is_valid_utf8(tail),
            "translate DFA accepts dangling tail {tail:?}"
        );
        assert!(
            Charsetfunctions::string_utf8(tail.to_vec()).is_err(),
            "strict decoder rejects dangling tail {tail:?}"
        );
    }
}

/// The reference translate-DFA predicate (derive.go
/// `dfaAcceptsAtTranslate` :481-491): strict validity OR a dangling
/// incomplete tail at the very end of the input. `Utf8Error::error_len()`
/// answering `None` is exactly the "unexpected end of input inside a valid
/// prefix" condition derive.go's `isIncompleteUTF8Tail` encodes.
fn reference_dfa_accepts(bytes: &[u8]) -> bool {
    match std::str::from_utf8(bytes) {
        Ok(_) => true,
        Err(error) => error.error_len().is_none(),
    }
}

#[test]
fn both_gates_agree_with_the_standard_library_on_complete_inputs() {
    // Exhaustive sweeps against the reference predicate: every 1- and
    // 2-byte input, every 3-byte input over the interesting lead bytes,
    // plus targeted 4-byte vectors. The borrowed incremental DFA must match
    // derive.go's translate acceptance EXACTLY.
    for a in 0..=255u8 {
        assert_eq!(
            Charsetfunctions::is_valid_utf8(&[a]),
            reference_dfa_accepts(&[a]),
            "single byte {a:#04x}"
        );
        for b in 0..=255u8 {
            let bytes = [a, b];
            assert_eq!(
                Charsetfunctions::is_valid_utf8(&bytes),
                reference_dfa_accepts(&bytes),
                "pair {bytes:x?}"
            );
        }
    }
    // Every 3-byte combination over the window-restricted leads and their
    // neighbors, all second/third bytes.
    for lead in [
        0xdfu8, 0xe0, 0xe1, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf3, 0xf4, 0xf5,
    ] {
        for b in (0x00..=0xff).step_by(0x10) {
            for c in (0x00..=0xff).step_by(0x10) {
                let bytes = [lead, b, c];
                assert_eq!(
                    Charsetfunctions::is_valid_utf8(&bytes),
                    reference_dfa_accepts(&bytes),
                    "triple {bytes:x?}"
                );
            }
        }
    }
    // Known scalars round-trip the strict decoder losslessly.
    for text in ["", "A", "héllo", "\u{0800}", "\u{10FFFF}", "🦀🦀"] {
        assert!(Charsetfunctions::is_valid_utf8(text.as_bytes()));
        assert_eq!(
            Charsetfunctions::string_utf8(text.as_bytes().to_vec()).expect("valid text decodes"),
            text
        );
    }
    // Surrogate range boundaries and overlong minima reject in both gates.
    for bad in [
        &b"\xed\xa0\x80"[..],     // U+D800 surrogate
        &b"\xf4\x90\x80\x80"[..], // above U+10FFFF
        &b"\xc0\x80"[..],         // overlong NUL
        &b"\xe0\x80\x80"[..],     // overlong 3-byte
        &b"\xf0\x80\x80\x80"[..], // overlong 4-byte
    ] {
        assert!(!Charsetfunctions::is_valid_utf8(bad), "{bad:x?}");
        assert!(
            Charsetfunctions::string_utf8(bad.to_vec()).is_err(),
            "{bad:x?}"
        );
    }
}
