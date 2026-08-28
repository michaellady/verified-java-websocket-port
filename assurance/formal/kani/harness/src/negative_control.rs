//! NEGATIVE CONTROL harnesses.
//!
//! Each harness applies a spec from [`crate::spec`] — the same spec the
//! corresponding [`crate::real`] harness applies to the shipped function — to a
//! defect-planted copy from [`crate::mutants`].
//!
//! EVERY harness in this module whose name starts with `nc_` and does not end
//! in `_expected_success` is REQUIRED TO FAIL. A run in which any of them
//! reports SUCCESS invalidates the corresponding positive claim, because it
//! shows the spec or the verifier cannot see the defect.
//!
//! Two harnesses here are deliberately expected to SUCCEED, and are the point
//! of the exercise rather than an accident: `nc_m9`/`nc_m10` under the
//! INVOLUTION property. XOR with any fixed per-index key is an involution, so
//! the involution property is blind to key misalignment. They are the control
//! that shows which of the two masking properties is load-bearing.

use crate::mutants;
use crate::spec;

const UTF8_BOUND: usize = 4;
const MASK_BOUND: usize = 12;
const HEADER_BUF_BOUND: usize = 14;

// ---------------------------------------------------------------------------
// close-code mutants — must FAIL
// ---------------------------------------------------------------------------

/// MUST FAIL. M1 lets 1015 survive normalization.
#[kani::proof]
fn nc_m1_normalize_off_by_one_must_fail() {
    let code: u16 = kani::any();
    assert!(spec::normalize_fact(code, mutants::m1_normalize_off_by_one(code)));
}

/// MUST FAIL. M2 normalizes 1015 to the wrong code.
#[kani::proof]
fn nc_m2_normalize_wrong_target_must_fail() {
    let code: u16 = kani::any();
    assert!(spec::normalize_fact(code, mutants::m2_normalize_wrong_target(code)));
}

/// MUST FAIL. M3 wrongly rejects application close code 3000.
#[kani::proof]
fn nc_m3_rejection_span_off_by_one_must_fail() {
    let code: u16 = kani::any();
    let empty: bool = kani::any();
    let reason: &str = if empty { "" } else { "x" };
    assert!(spec::close_rejection_fact(
        code,
        empty,
        mutants::m3_rejection_span_off_by_one(code, reason)
    ));
}

/// MUST FAIL. M4 drops the only rule that reports close code 1007.
#[kani::proof]
fn nc_m4_rejection_drop_1007_rule_must_fail() {
    let code: u16 = kani::any();
    let empty: bool = kani::any();
    let reason: &str = if empty { "" } else { "x" };
    assert!(spec::close_rejection_fact(
        code,
        empty,
        mutants::m4_rejection_drop_1007_rule(code, reason)
    ));
}

/// MUST FAIL. M5 wrongly accepts reserved close code 1004.
#[kani::proof]
fn nc_m5_rejection_drop_1004_must_fail() {
    let code: u16 = kani::any();
    let empty: bool = kani::any();
    let reason: &str = if empty { "" } else { "x" };
    assert!(spec::close_rejection_fact(
        code,
        empty,
        mutants::m5_rejection_drop_1004(code, reason)
    ));
}

// ---------------------------------------------------------------------------
// UTF-8 mutants — must FAIL
// ---------------------------------------------------------------------------

/// MUST FAIL. M6 accepts overlong 0xc0/0xc1 leads.
#[kani::proof]
#[kani::unwind(10)]
fn nc_m6_utf8_allow_overlong_must_fail() {
    let len: usize = kani::any();
    kani::assume(len <= UTF8_BOUND);
    let raw: [u8; UTF8_BOUND] = kani::any();
    let bytes = &raw[..len];
    assert_eq!(
        mutants::m6_utf8_allow_overlong(bytes),
        spec::utf8_translate_oracle(bytes)
    );
}

/// MUST FAIL. M7 accepts UTF-16 surrogates.
#[kani::proof]
#[kani::unwind(10)]
fn nc_m7_utf8_allow_surrogates_must_fail() {
    let len: usize = kani::any();
    kani::assume(len <= UTF8_BOUND);
    let raw: [u8; UTF8_BOUND] = kani::any();
    let bytes = &raw[..len];
    assert_eq!(
        mutants::m7_utf8_allow_surrogates(bytes),
        spec::utf8_translate_oracle(bytes)
    );
}

/// MUST FAIL. M8 accepts the out-of-range leads 0xf5..=0xff.
#[kani::proof]
#[kani::unwind(10)]
fn nc_m8_utf8_allow_over_max_must_fail() {
    let len: usize = kani::any();
    kani::assume(len <= UTF8_BOUND);
    let raw: [u8; UTF8_BOUND] = kani::any();
    let bytes = &raw[..len];
    assert_eq!(
        mutants::m8_utf8_allow_over_max(bytes),
        spec::utf8_translate_oracle(bytes)
    );
}

// ---------------------------------------------------------------------------
// masking mutants — the discriminating pair
// ---------------------------------------------------------------------------

/// MUST FAIL. M9 rotates the key; the EXACT mask equation sees it.
#[kani::proof]
#[kani::unwind(16)]
fn nc_m9_mask_rotated_key_exact_equation_must_fail() {
    let len: usize = kani::any();
    kani::assume(len <= MASK_BOUND);
    let original: [u8; MASK_BOUND] = kani::any();
    let key: [u8; 4] = kani::any();
    let mut buf = original;
    mutants::m9_mask_rotated_key(&mut buf[..len], key);
    let mut i = 0usize;
    while i < len {
        assert_eq!(buf[i], original[i] ^ key[i % 4]);
        i += 1;
    }
}

/// MUST FAIL. M10 skips the first byte; the EXACT mask equation sees it.
#[kani::proof]
#[kani::unwind(16)]
fn nc_m10_mask_skips_first_byte_exact_equation_must_fail() {
    let len: usize = kani::any();
    kani::assume(len <= MASK_BOUND);
    let original: [u8; MASK_BOUND] = kani::any();
    let key: [u8; 4] = kani::any();
    let mut buf = original;
    mutants::m10_mask_skips_first_byte(&mut buf[..len], key);
    let mut i = 0usize;
    while i < len {
        assert_eq!(buf[i], original[i] ^ key[i % 4]);
        i += 1;
    }
}

/// EXPECTED SUCCESS — and that is the finding. M9 is a real defect that the
/// INVOLUTION property cannot see, because XOR with any fixed per-index key is
/// an involution. Documents that involution alone is not a sufficient masking
/// property.
#[kani::proof]
#[kani::unwind(16)]
fn nc_m9_mask_rotated_key_involution_expected_success() {
    let len: usize = kani::any();
    kani::assume(len <= MASK_BOUND);
    let original: [u8; MASK_BOUND] = kani::any();
    let key: [u8; 4] = kani::any();
    let mut buf = original;
    mutants::m9_mask_rotated_key(&mut buf[..len], key);
    mutants::m9_mask_rotated_key(&mut buf[..len], key);
    assert_eq!(buf, original);
}

/// EXPECTED SUCCESS — same finding for the skipped-byte defect.
#[kani::proof]
#[kani::unwind(16)]
fn nc_m10_mask_skips_first_byte_involution_expected_success() {
    let len: usize = kani::any();
    kani::assume(len <= MASK_BOUND);
    let original: [u8; MASK_BOUND] = kani::any();
    let key: [u8; 4] = kani::any();
    let mut buf = original;
    mutants::m10_mask_skips_first_byte(&mut buf[..len], key);
    mutants::m10_mask_skips_first_byte(&mut buf[..len], key);
    assert_eq!(buf, original);
}

// ---------------------------------------------------------------------------
// frame-header mutants — must FAIL
// ---------------------------------------------------------------------------

/// Soundness spec over a mutant decode result (mirrors
/// [`crate::real::real_decode_frame_header_len_le_14`]).
fn assert_mutant_header_sound(buf: &[u8], max: u64, out: mutants::MutantDecode) {
    match out {
        mutants::MutantDecode::Insufficient => {}
        mutants::MutantDecode::Header {
            masked,
            payload_len,
            header_len,
            opcode_nibble,
        } => {
            let (grammar_len, base) = spec::length_grammar(buf).expect("header is complete");
            assert_eq!(payload_len, grammar_len);
            assert_eq!(header_len, base + if masked { 4 } else { 0 });
            assert!(header_len <= buf.len());
            if spec::opcode_is_control(opcode_nibble) {
                assert!(payload_len <= spec::CONTROL_LIMIT);
                assert!(u64::from(buf[1] & 0x7f) < 126);
            }
            assert!(payload_len <= max);
        }
        mutants::MutantDecode::Reject {
            consumed,
            close_code,
        } => {
            assert!(consumed == 2 || consumed == 4 || consumed == 10);
            assert!(close_code == 1002 || close_code == 1009);
            let nibble = buf[0] & 0x0f;
            let marker = u64::from(buf[1] & 0x7f);
            if !spec::opcode_known(nibble) {
                assert_eq!(consumed, 2);
            } else if spec::opcode_is_control(nibble) && marker >= 126 {
                assert_eq!(consumed, 2);
                assert_eq!(close_code, 1002);
            } else {
                let (payload_len, base) =
                    spec::length_grammar(buf).expect("length site was reached");
                assert_eq!(consumed, base);
                if !(spec::opcode_is_control(nibble) && payload_len > spec::CONTROL_LIMIT) {
                    assert!(payload_len > max);
                    assert_eq!(close_code, 1009);
                }
            }
        }
    }
}

/// Completeness spec over a mutant decode result (mirrors
/// [`crate::real::real_decode_frame_header_no_false_reject_len_le_14`]).
fn assert_mutant_header_complete(buf: &[u8], _max: u64, out: mutants::MutantDecode) {
    match out {
        mutants::MutantDecode::Header {
            masked,
            payload_len,
            header_len,
            ..
        } => {
            let (grammar_len, base) = spec::length_grammar(buf).expect("header is complete");
            assert_eq!(payload_len, grammar_len);
            assert_eq!(header_len, base + if masked { 4 } else { 0 });
        }
        mutants::MutantDecode::Insufficient => panic!("complete legal header answered Insufficient"),
        mutants::MutantDecode::Reject { .. } => panic!("legal header was rejected"),
    }
}

/// Constrains the symbolic buffer to a complete, legal header.
fn legal_header_setup(buf: &[u8], max: u64) -> bool {
    if buf.len() < 2 {
        return false;
    }
    let nibble = buf[0] & 0x0f;
    let marker = u64::from(buf[1] & 0x7f);
    kani::assume(spec::opcode_known(nibble));
    kani::assume(!(spec::opcode_is_control(nibble) && marker >= 126));
    let Some((payload_len, base)) = spec::length_grammar(buf) else {
        return false;
    };
    kani::assume(!(spec::opcode_is_control(nibble) && payload_len > spec::CONTROL_LIMIT));
    kani::assume(payload_len <= max);
    let masked = buf[1] & 0x80 != 0;
    kani::assume(buf.len() >= base + if masked { 4 } else { 0 });
    true
}

/// EXPECTED SUCCESS — a FINDING, recorded after the fact.
///
/// M11 widens the control payload ceiling from 125 to 126, and was planted
/// expecting detection. Kani reported SUCCESS instead, and the reason is
/// sound: `decode_frame_header` rejects a control frame with
/// `marker >= 126` BEFORE the ceiling is reached, so the ceiling only ever
/// sees `payload_len == marker <= 125`. Both `> 125` and `> 126` are therefore
/// dead comparisons for control frames, and M11 is an EQUIVALENT mutant.
///
/// [`nc_m11_control_limit_proven_equivalent_to_clean_clone`] states that
/// directly, and [`nc_m15_control_limit_too_tight_must_fail`] is the
/// reachable control-ceiling mutant that replaces it as a live negative
/// control.
#[kani::proof]
#[kani::unwind(16)]
fn nc_m11_control_limit_expected_success_equivalent_mutant() {
    let len: usize = kani::any();
    kani::assume(len <= HEADER_BUF_BOUND);
    let raw: [u8; HEADER_BUF_BOUND] = kani::any();
    let max: u64 = kani::any();
    let buf = &raw[..len];
    if buf.len() < 2 {
        return;
    }
    assert_mutant_header_sound(buf, max, mutants::m11_control_limit(buf, max));
}

/// EXPECTED SUCCESS. The rigorous form of the M11 equivalence finding: the
/// widened-ceiling mutant is OUTPUT-IDENTICAL to the clean clone over the whole
/// bounded input space, not merely unnoticed by the spec.
///
/// BOUND: all buffers of length <= [`HEADER_BUF_BOUND`], all `u64` caps.
#[kani::proof]
#[kani::unwind(16)]
fn nc_m11_control_limit_proven_equivalent_to_clean_clone() {
    let len: usize = kani::any();
    kani::assume(len <= HEADER_BUF_BOUND);
    let raw: [u8; HEADER_BUF_BOUND] = kani::any();
    let max: u64 = kani::any();
    let buf = &raw[..len];
    assert_eq!(
        mutants::m11_control_limit(buf, max),
        mutants::m0_clean_clone(buf, max)
    );
}

/// MUST FAIL. M15 tightens the control payload ceiling to 124, over-rejecting
/// a legal 125-byte control payload. This is the REACHABLE control-ceiling
/// mutant that replaces the proven-equivalent M11.
#[kani::proof]
#[kani::unwind(16)]
fn nc_m15_control_limit_too_tight_must_fail() {
    let len: usize = kani::any();
    kani::assume(len <= HEADER_BUF_BOUND);
    let raw: [u8; HEADER_BUF_BOUND] = kani::any();
    let max: u64 = kani::any();
    let buf = &raw[..len];
    if !legal_header_setup(buf, max) {
        return;
    }
    assert_mutant_header_complete(buf, max, mutants::m15_control_limit_too_tight(buf, max));
}

/// MUST FAIL. M12 rejects a frame whose declared length is exactly the cap.
#[kani::proof]
#[kani::unwind(16)]
fn nc_m12_size_gate_ge_must_fail() {
    let len: usize = kani::any();
    kani::assume(len <= HEADER_BUF_BOUND);
    let raw: [u8; HEADER_BUF_BOUND] = kani::any();
    let max: u64 = kani::any();
    let buf = &raw[..len];
    if !legal_header_setup(buf, max) {
        return;
    }
    assert_mutant_header_complete(buf, max, mutants::m12_size_gate_ge(buf, max));
}

/// MUST FAIL. M13 reports the extended-length control rejection at offset
/// 4/10 instead of Java's 2.
#[kani::proof]
#[kani::unwind(16)]
fn nc_m13_control_check_late_must_fail() {
    let len: usize = kani::any();
    kani::assume(len <= HEADER_BUF_BOUND);
    let raw: [u8; HEADER_BUF_BOUND] = kani::any();
    let max: u64 = kani::any();
    let buf = &raw[..len];
    if buf.len() < 2 {
        return;
    }
    assert_mutant_header_sound(buf, max, mutants::m13_control_check_late(buf, max));
}

/// MUST FAIL. M14 decodes the 16-bit extended length little-endian.
#[kani::proof]
#[kani::unwind(16)]
fn nc_m14_len16_little_endian_must_fail() {
    let len: usize = kani::any();
    kani::assume(len <= HEADER_BUF_BOUND);
    let raw: [u8; HEADER_BUF_BOUND] = kani::any();
    let max: u64 = kani::any();
    let buf = &raw[..len];
    if buf.len() < 2 {
        return;
    }
    assert_mutant_header_sound(buf, max, mutants::m14_len16_little_endian(buf, max));
}

/// EXPECTED SUCCESS. The control-on-the-control: the same clone with every
/// defect switch off satisfies the soundness spec, so the `must_fail`
/// harnesses above fail because of their planted defect and not because the
/// clone or the spec is broken.
#[kani::proof]
#[kani::unwind(16)]
fn nc_m0_clean_clone_expected_success() {
    let len: usize = kani::any();
    kani::assume(len <= HEADER_BUF_BOUND);
    let raw: [u8; HEADER_BUF_BOUND] = kani::any();
    let max: u64 = kani::any();
    let buf = &raw[..len];
    if buf.len() < 2 {
        return;
    }
    assert_mutant_header_sound(buf, max, mutants::m0_clean_clone(buf, max));
}
