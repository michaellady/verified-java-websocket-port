//! Harnesses over the ACTUAL shipped `ws_core` functions.
//!
//! Every symbolic input is stated with an explicit bound in the harness name
//! and in the doc comment. Bounded model checking proves a property UP TO its
//! bound and never universally; the only harnesses here that are exhaustive
//! over their whole input domain are the `u16` close-code harnesses, where a
//! symbolic `u16` covers all 65 536 values.

use ws_core::close::{close_code_rejection, normalize_send_close_code};
use ws_core::framing::{Draft6455, FrameHeader, HeaderDecode, Opcode};
use ws_core::message::Charsetfunctions;

use crate::spec;

/// The frame-header symbolic buffer bound: 14 bytes is the largest possible
/// WebSocket frame header (2 base + 8 extended length + 4 mask key).
pub const HEADER_BUF_BOUND: usize = 14;

/// The symbolic payload bound for the UTF-8 harnesses that use the
/// independent reference decoder as their oracle.
pub const UTF8_BOUND: usize = 4;

/// The symbolic payload bound for the UTF-8 harnesses that must symbolically
/// execute the standard library's own validator.
pub const STRICT_BOUND: usize = 3;

/// The symbolic payload bound for the masking harnesses.
pub const MASK_BOUND: usize = 12;

/// The symbolic close-reason bound.
pub const REASON_BOUND: usize = 3;

// ---------------------------------------------------------------------------
// close.rs — EXHAUSTIVE over the full u16 close-code domain
// ---------------------------------------------------------------------------

/// BOUND: exhaustive — a symbolic `u16` covers all 65 536 close codes.
#[kani::proof]
fn real_normalize_send_close_code_all_65536() {
    let code: u16 = kani::any();
    let out = normalize_send_close_code(code);
    assert!(spec::normalize_fact(code, out));
}

/// BOUND: exhaustive over all 65 536 close codes.
#[kani::proof]
fn real_normalize_send_close_code_idempotent_all_65536() {
    let code: u16 = kani::any();
    let once = normalize_send_close_code(code);
    assert_eq!(normalize_send_close_code(once), once);
}

/// BOUND: exhaustive over all 65 536 close codes, with the close reason
/// represented by the two canonical witnesses `""` and `"x"`. The reason
/// dimension is discharged separately and symbolically by
/// [`real_close_code_rejection_reason_insensitive_len_le_3`].
#[kani::proof]
fn real_close_code_rejection_all_65536_witness_reasons() {
    let code: u16 = kani::any();
    let empty: bool = kani::any();
    let reason: &str = if empty { "" } else { "x" };
    let result = close_code_rejection(code, reason);
    assert!(spec::close_rejection_fact(code, empty, result));
}

/// BOUND: all 65 536 close codes x every valid UTF-8 close reason of length
/// <= 3 bytes. Proves the answer depends on the reason ONLY through
/// `is_empty()`, which is what makes the two-witness table harness above a
/// complete account of the reason dimension within this bound.
#[kani::proof]
#[kani::unwind(16)]
fn real_close_code_rejection_reason_insensitive_len_le_3() {
    let code: u16 = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= REASON_BOUND);
    let raw: [u8; REASON_BOUND] = kani::any();
    let Ok(reason) = core::str::from_utf8(&raw[..len]) else {
        return;
    };
    let witness: &str = if reason.is_empty() { "" } else { "x" };
    assert_eq!(
        close_code_rejection(code, reason),
        close_code_rejection(code, witness)
    );
}

// ---------------------------------------------------------------------------
// message.rs — the UTF-8 validator, differential against core::str
// ---------------------------------------------------------------------------

/// BOUND: all byte strings of length <= 3, every byte symbolic.
///
/// ORACLE VALIDATION. Ties the independent reference decoder in
/// [`crate::spec`] to `core::str::from_utf8` itself, whose `error_len()` is
/// documented to be `None` exactly when the input ended mid-sequence. This is
/// what earns the reference decoder the right to be used as an oracle in the
/// harnesses below.
///
/// The bound is 3 rather than 4 because `core::str::from_utf8`'s word-at-a-time
/// ASCII fast path is expensive to symbolically execute; see the receipt's
/// nonclaims.
#[kani::proof]
#[kani::unwind(16)]
fn real_reference_decoder_agrees_with_core_str_len_le_3() {
    let len: usize = kani::any();
    kani::assume(len <= 3);
    let raw: [u8; 3] = kani::any();
    let bytes = &raw[..len];
    let core_translate = match core::str::from_utf8(bytes) {
        Ok(_) => true,
        Err(e) => e.error_len().is_none(),
    };
    let core_strict = core::str::from_utf8(bytes).is_ok();
    assert_eq!(spec::utf8_translate_oracle(bytes), core_translate);
    assert_eq!(spec::utf8_strict_oracle(bytes), core_strict);
}

/// BOUND: all byte strings of length <= [`UTF8_BOUND`], every byte symbolic
/// (2^32 + 2^24 + 2^16 + 2^8 + 1 concrete inputs at bound 4, covered
/// symbolically).
///
/// Proves the translate-stage DFA is EXACTLY "is a prefix of some valid UTF-8
/// string", against the independent value-based reference decoder.
#[kani::proof]
#[kani::unwind(10)]
fn real_is_valid_utf8_exact_vs_reference_len_le_4() {
    let len: usize = kani::any();
    kani::assume(len <= UTF8_BOUND);
    let raw: [u8; UTF8_BOUND] = kani::any();
    let bytes = &raw[..len];
    assert_eq!(
        Charsetfunctions::is_valid_utf8(bytes),
        spec::utf8_translate_oracle(bytes)
    );
}

/// The strict process-stage property, applied to one concrete-length slice.
///
/// Quirk Q15 layering: the strict decode is strictly stronger than the
/// translate-stage gate — anything the strict stage accepts, the translate
/// stage accepts too — it accepts exactly the complete well-formed strings,
/// and it is byte-faithful (zero-copy: the decoded string's bytes ARE the
/// input bytes).
///
/// The SLICE LENGTH IS CONCRETE at every call site, deliberately.
/// `string_utf8` wraps `String::from_utf8`, so this property pays the cost of
/// symbolically executing the standard library's own validator; with a
/// SYMBOLIC length CBMC cannot bound `core::str::validations::
/// run_utf8_validation`'s loop and reports an unwinding assertion failure
/// (measured: still failing at `--unwind 16` after 924s). Fixing the length
/// per harness bounds that loop while leaving every BYTE symbolic, so the
/// union of the four harnesses below covers exactly the same input set as a
/// single `len <= 3` harness would have.
fn check_strict_stage(bytes: &[u8]) {
    let strict_ok = Charsetfunctions::string_utf8(bytes.to_vec()).is_ok();
    assert_eq!(strict_ok, spec::utf8_strict_oracle(bytes));
    if strict_ok {
        assert!(Charsetfunctions::is_valid_utf8(bytes));
        let decoded = Charsetfunctions::string_utf8(bytes.to_vec()).expect("just checked");
        assert_eq!(decoded.as_bytes(), bytes);
    }
}

/// BOUND: the empty payload.
#[kani::proof]
#[kani::unwind(16)]
fn real_string_utf8_strict_stage_len_eq_0() {
    check_strict_stage(&[]);
}

/// BOUND: all 2^8 one-byte payloads, symbolically.
#[kani::proof]
#[kani::unwind(16)]
fn real_string_utf8_strict_stage_len_eq_1() {
    let raw: [u8; 1] = kani::any();
    check_strict_stage(&raw);
}

/// BOUND: all 2^16 two-byte payloads, symbolically.
#[kani::proof]
#[kani::unwind(16)]
fn real_string_utf8_strict_stage_len_eq_2() {
    let raw: [u8; 2] = kani::any();
    check_strict_stage(&raw);
}

/// BOUND: all 2^24 three-byte payloads, symbolically. Together with the
/// `len_eq_0/1/2` harnesses this covers every payload of length <=
/// [`STRICT_BOUND`].
#[kani::proof]
#[kani::unwind(16)]
fn real_string_utf8_strict_stage_len_eq_3() {
    let raw: [u8; 3] = kani::any();
    check_strict_stage(&raw);
}

/// BOUND: exhaustive over all 65 536 close codes, with the two canonical
/// reason witnesses.
///
/// CROSS-CHECK against the merged E1 property suite, which records
/// `m016-send-close-normalize-skip` as a PROVEN output-identical (equivalent)
/// mutant on the grounds that
/// `close_code_rejection(normalize(c), r) == close_code_rejection(c, r)` for
/// all `c`. This harness re-derives that equivalence with a different vehicle.
/// A disagreement here would be a finding about the E1 equivalence ruling.
#[kani::proof]
fn real_normalize_then_reject_equals_reject_all_65536() {
    let code: u16 = kani::any();
    let empty: bool = kani::any();
    let reason: &str = if empty { "" } else { "x" };
    assert_eq!(
        close_code_rejection(normalize_send_close_code(code), reason),
        close_code_rejection(code, reason)
    );
}

// ---------------------------------------------------------------------------
// framing.rs — masking
// ---------------------------------------------------------------------------

/// BOUND: all payloads of length <= [`MASK_BOUND`] with every payload byte and
/// every one of the 4 key bytes symbolic.
///
/// The EXACT mask equation. This is the property that actually pins the
/// key-to-byte alignment; see
/// [`crate::negative_control`] for the demonstration that the involution
/// property alone does not.
#[kani::proof]
#[kani::unwind(16)]
fn real_apply_mask_exact_equation_len_le_12() {
    let len: usize = kani::any();
    kani::assume(len <= MASK_BOUND);
    let original: [u8; MASK_BOUND] = kani::any();
    let key: [u8; 4] = kani::any();
    let mut buf = original;
    Draft6455::apply_mask(&mut buf[..len], key);
    let mut i = 0usize;
    while i < len {
        assert_eq!(buf[i], original[i] ^ key[i % 4]);
        i += 1;
    }
    // Bytes past the masked slice must be untouched.
    let mut j = len;
    while j < MASK_BOUND {
        assert_eq!(buf[j], original[j]);
        j += 1;
    }
}

/// BOUND: all payloads of length <= [`MASK_BOUND`], all keys.
///
/// Involution (proof family mask-equation-involution): masking twice with the
/// same key restores the input.
#[kani::proof]
#[kani::unwind(16)]
fn real_apply_mask_involution_len_le_12() {
    let len: usize = kani::any();
    kani::assume(len <= MASK_BOUND);
    let original: [u8; MASK_BOUND] = kani::any();
    let key: [u8; 4] = kani::any();
    let mut buf = original;
    Draft6455::apply_mask(&mut buf[..len], key);
    Draft6455::apply_mask(&mut buf[..len], key);
    assert_eq!(buf, original);
}

// ---------------------------------------------------------------------------
// framing.rs — frame-header decode
// ---------------------------------------------------------------------------

fn opcode_nibble_of(opcode: Opcode) -> u8 {
    match opcode {
        Opcode::Continuous => 0,
        Opcode::Text => 1,
        Opcode::Binary => 2,
        Opcode::Closing => 8,
        Opcode::Ping => 9,
        Opcode::Pong => 10,
    }
}

/// Every structural fact a successfully decoded header must satisfy.
fn assert_header_shape(buf: &[u8], max: u64, h: &FrameHeader) {
    let nibble = opcode_nibble_of(h.opcode);
    // D13: the opcode nibble round-trips through the parsed enum.
    assert_eq!(nibble, buf[0] & 0x0f);
    assert!(spec::opcode_known(nibble));
    // D12: fin and the reserved bits are exactly byte 0's high nibble.
    assert_eq!(h.fin, buf[0] & 0x80 != 0);
    assert_eq!(h.rsv1, buf[0] & 0x40 != 0);
    assert_eq!(h.rsv2, buf[0] & 0x20 != 0);
    assert_eq!(h.rsv3, buf[0] & 0x10 != 0);
    // D5: the mask bit, the key presence and the key bytes agree.
    assert_eq!(h.masked, buf[1] & 0x80 != 0);
    assert_eq!(h.masked, h.mask_key.is_some());
    // D4: the declared length is exactly what the RFC 6455 length grammar says.
    let (grammar_len, base) = spec::length_grammar(buf).expect("header is complete");
    assert_eq!(h.payload_len, grammar_len);
    // D5: header_len is the base header plus the mask key, and it fits.
    assert_eq!(h.header_len, base + if h.masked { 4 } else { 0 });
    assert!(h.header_len <= buf.len());
    if let Some(key) = h.mask_key {
        assert_eq!(key, [buf[base], buf[base + 1], buf[base + 2], buf[base + 3]]);
    }
    // D6: a control frame that decoded successfully is within the 125 ceiling.
    if spec::opcode_is_control(nibble) {
        assert!(h.payload_len <= spec::CONTROL_LIMIT);
        // D3: and it never used an extended-length marker.
        assert!(u64::from(buf[1] & 0x7f) < 126);
    }
    // D7: and within the configured frame cap.
    assert!(h.payload_len <= max);
}

/// BOUND: all buffers of length <= [`HEADER_BUF_BOUND`] (14 bytes — the
/// largest possible frame header) with every byte symbolic, and a fully
/// symbolic `max_frame_payload_bytes: u64`.
///
/// Proves the length grammar, the header shape, the opcode mapping, the
/// control ceiling, the frame cap, and the rejection vocabulary/offsets — and,
/// because Kani checks them by default, the absence of panics, arithmetic
/// overflow and out-of-bounds indexing over that whole input space.
#[kani::proof]
#[kani::unwind(16)]
fn real_decode_frame_header_len_le_14() {
    let len: usize = kani::any();
    kani::assume(len <= HEADER_BUF_BOUND);
    let raw: [u8; HEADER_BUF_BOUND] = kani::any();
    let max: u64 = kani::any();
    let buf = &raw[..len];

    match Draft6455::decode_frame_header(buf, max) {
        Ok(HeaderDecode::Insufficient) => {
            // D1: an Insufficient answer means a genuinely incomplete header:
            // either fewer than 2 bytes, or the declared length/mask needs
            // more bytes than are present.
            if buf.len() >= 2 {
                match spec::length_grammar(buf) {
                    None => {}
                    Some((_, base)) => {
                        let masked = buf[1] & 0x80 != 0;
                        assert!(buf.len() < base + if masked { 4 } else { 0 });
                    }
                }
            }
        }
        Ok(HeaderDecode::Header(h)) => assert_header_shape(buf, max, &h),
        Err(reject) => {
            // D10: rejections land on a length-grammar site.
            assert!(reject.consumed == 2 || reject.consumed == 4 || reject.consumed == 10);
            // The header-time vocabulary is exactly 1002 and 1009.
            let close = reject.failure.close_code;
            assert!(close == Some(1002) || close == Some(1009));
            assert!(buf.len() >= 2);
            let nibble = buf[0] & 0x0f;
            let marker = u64::from(buf[1] & 0x7f);
            if !spec::opcode_known(nibble) {
                // D2: unknown opcode rejects as 1002 after exactly 2 bytes.
                assert_eq!(reject.consumed, 2);
                assert_eq!(close, Some(1002));
            } else if spec::opcode_is_control(nibble) && marker >= 126 {
                // D3: an extended-length control frame is rejected BEFORE the
                // extended length bytes are read — 2 bytes consumed, not 4/10.
                assert_eq!(reject.consumed, 2);
                assert_eq!(close, Some(1002));
            } else {
                // Every other rejection is a length-site rejection, so the
                // length must have been readable.
                let (payload_len, base) =
                    spec::length_grammar(buf).expect("length site was reached");
                assert_eq!(reject.consumed, base);
                if spec::opcode_is_control(nibble) && payload_len > spec::CONTROL_LIMIT {
                    assert_eq!(close, Some(1002));
                } else {
                    // D9: the only remaining reason to reject is the frame cap.
                    assert!(payload_len > max);
                    assert_eq!(close, Some(1009));
                }
            }
        }
    }
}

/// BOUND: all buffers of length <= [`HEADER_BUF_BOUND`], all `u64` caps.
///
/// COMPLETENESS (no false rejection): a complete header that violates none of
/// the four header-time checks must decode, not reject. This is the direction
/// that catches an over-strict gate, which the soundness harness above cannot.
#[kani::proof]
#[kani::unwind(16)]
fn real_decode_frame_header_no_false_reject_len_le_14() {
    let len: usize = kani::any();
    kani::assume(len <= HEADER_BUF_BOUND);
    let raw: [u8; HEADER_BUF_BOUND] = kani::any();
    let max: u64 = kani::any();
    let buf = &raw[..len];
    if buf.len() < 2 {
        return;
    }
    let nibble = buf[0] & 0x0f;
    let marker = u64::from(buf[1] & 0x7f);
    kani::assume(spec::opcode_known(nibble));
    kani::assume(!(spec::opcode_is_control(nibble) && marker >= 126));
    let Some((payload_len, base)) = spec::length_grammar(buf) else {
        return;
    };
    kani::assume(!(spec::opcode_is_control(nibble) && payload_len > spec::CONTROL_LIMIT));
    kani::assume(payload_len <= max);
    let masked = buf[1] & 0x80 != 0;
    kani::assume(buf.len() >= base + if masked { 4 } else { 0 });

    match Draft6455::decode_frame_header(buf, max) {
        Ok(HeaderDecode::Header(h)) => {
            assert_eq!(h.payload_len, payload_len);
            assert_eq!(h.header_len, base + if masked { 4 } else { 0 });
        }
        Ok(HeaderDecode::Insufficient) => panic!("complete legal header answered Insufficient"),
        Err(_) => panic!("legal header was rejected"),
    }
}

/// BOUND: all buffers of length <= [`HEADER_BUF_BOUND`], all `u64` caps.
///
/// PREFIX STABILITY: a header that decodes from `buf` decodes identically from
/// exactly its own `header_len` bytes — the decoder never depends on payload
/// bytes it has not claimed.
#[kani::proof]
#[kani::unwind(16)]
fn real_decode_frame_header_prefix_stable_len_le_14() {
    let len: usize = kani::any();
    kani::assume(len <= HEADER_BUF_BOUND);
    let raw: [u8; HEADER_BUF_BOUND] = kani::any();
    let max: u64 = kani::any();
    let buf = &raw[..len];
    if let Ok(HeaderDecode::Header(h)) = Draft6455::decode_frame_header(buf, max) {
        let hl = h.header_len;
        match Draft6455::decode_frame_header(&buf[..hl], max) {
            Ok(HeaderDecode::Header(again)) => {
                assert_eq!(again.payload_len, h.payload_len);
                assert_eq!(again.header_len, h.header_len);
                assert_eq!(again.masked, h.masked);
                assert_eq!(again.mask_key, h.mask_key);
                assert_eq!(again.fin, h.fin);
                assert_eq!(opcode_nibble_of(again.opcode), opcode_nibble_of(h.opcode));
            }
            _ => panic!("header did not re-decode from its own header_len prefix"),
        }
    }
}
