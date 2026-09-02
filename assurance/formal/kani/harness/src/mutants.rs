//! NEGATIVE CONTROL: defect-planted copies of the verification targets.
//!
//! Every function here is a copy of a real `ws_core` function with exactly one
//! deliberate defect. The harnesses in [`crate::negative_control`] apply the
//! SAME [`crate::spec`] predicates to these copies that
//! [`crate::real`] applies to the shipped functions. A verifier that reports
//! SUCCESS on any of these is not proving anything about the real code, so
//! every one of these harnesses is REQUIRED to fail.
//!
//! Nothing in this module is ever linked into a shipped artifact: this crate is
//! not a workspace member and no shipped crate depends on it.

// ---------------------------------------------------------------------------
// close.rs targets
// ---------------------------------------------------------------------------

/// MUTANT M1 of `normalize_send_close_code`: off-by-one on the normalized code
/// (1014 instead of 1015), so 1015 survives normalization.
pub fn m1_normalize_off_by_one(code: u16) -> u16 {
    if code == 1014 { 1005 } else { code }
}

/// MUTANT M2 of `normalize_send_close_code`: right trigger, wrong target
/// (1015 -> 1006 instead of 1015 -> 1005).
pub fn m2_normalize_wrong_target(code: u16) -> u16 {
    if code == 1015 { 1006 } else { code }
}

/// MUTANT M3 of `close_code_rejection`: reserved-span boundary widened from
/// `code < 3000` to `code <= 3000`, so the legal application code 3000 is
/// wrongly rejected.
pub fn m3_rejection_span_off_by_one(code: u16, reason: &str) -> Option<u16> {
    if code == 1007 && reason.is_empty() {
        return Some(1007);
    }
    if code == 1005 && !reason.is_empty() {
        return Some(1002);
    }
    if code > 1015 && code <= 3000 {
        return Some(1002);
    }
    if code == 1006
        || code == 1015
        || code == 1005
        || code == 1004
        || !(1000..=4999).contains(&code)
    {
        return Some(1002);
    }
    None
}

/// MUTANT M4 of `close_code_rejection`: the 1007-with-empty-reason rule is
/// dropped, so the one code that reports 1007 no longer does.
pub fn m4_rejection_drop_1007_rule(code: u16, reason: &str) -> Option<u16> {
    if code == 1005 && !reason.is_empty() {
        return Some(1002);
    }
    if code > 1015 && code < 3000 {
        return Some(1002);
    }
    if code == 1006
        || code == 1015
        || code == 1005
        || code == 1004
        || !(1000..=4999).contains(&code)
    {
        return Some(1002);
    }
    None
}

/// MUTANT M5 of `close_code_rejection`: 1004 dropped from the
/// never-on-the-wire disjunction, so a reserved code is wrongly accepted.
pub fn m5_rejection_drop_1004(code: u16, reason: &str) -> Option<u16> {
    if code == 1007 && reason.is_empty() {
        return Some(1007);
    }
    if code == 1005 && !reason.is_empty() {
        return Some(1002);
    }
    if code > 1015 && code < 3000 {
        return Some(1002);
    }
    if code == 1006 || code == 1015 || code == 1005 || !(1000..=4999).contains(&code) {
        return Some(1002);
    }
    None
}

// ---------------------------------------------------------------------------
// message.rs target: the UTF-8 DFA
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Pending {
    remaining: u8,
    next_min: u8,
    next_max: u8,
}

/// A parameterised copy of the real `Utf8Validator` DFA. The three `defect_*`
/// switches each plant one classic UTF-8 validator shortcut.
struct MutantValidator {
    pending: Option<Pending>,
    errored: bool,
    /// M6: accept the overlong lead bytes 0xc0/0xc1.
    defect_allow_overlong: bool,
    /// M7: accept UTF-16 surrogates by widening the 0xed window to 0xbf.
    defect_allow_surrogates: bool,
    /// M8: accept the out-of-range lead bytes 0xf5..=0xff.
    defect_allow_over_max: bool,
}

impl MutantValidator {
    fn new(overlong: bool, surrogates: bool, over_max: bool) -> MutantValidator {
        MutantValidator {
            pending: None,
            errored: false,
            defect_allow_overlong: overlong,
            defect_allow_surrogates: surrogates,
            defect_allow_over_max: over_max,
        }
    }

    fn feed(&mut self, bytes: &[u8]) -> bool {
        for &byte in bytes {
            if self.errored {
                return false;
            }
            match self.pending {
                None => self.start(byte),
                Some(window) => self.continue_sequence(window, byte),
            }
        }
        !self.errored
    }

    fn start(&mut self, byte: u8) {
        let ed_max: u8 = if self.defect_allow_surrogates { 0xbf } else { 0x9f };
        let window = match byte {
            0x00..=0x7f => return,
            0x80..=0xbf => {
                self.errored = true;
                return;
            }
            0xc0..=0xc1 => {
                // The overlong lead bytes: the real validator errors here.
                if self.defect_allow_overlong {
                    Pending {
                        remaining: 1,
                        next_min: 0x80,
                        next_max: 0xbf,
                    }
                } else {
                    self.errored = true;
                    return;
                }
            }
            0xc2..=0xdf => Pending {
                remaining: 1,
                next_min: 0x80,
                next_max: 0xbf,
            },
            0xe0 => Pending {
                remaining: 2,
                next_min: 0xa0,
                next_max: 0xbf,
            },
            0xe1..=0xec | 0xee..=0xef => Pending {
                remaining: 2,
                next_min: 0x80,
                next_max: 0xbf,
            },
            0xed => Pending {
                remaining: 2,
                next_min: 0x80,
                next_max: ed_max,
            },
            0xf0 => Pending {
                remaining: 3,
                next_min: 0x90,
                next_max: 0xbf,
            },
            0xf1..=0xf3 => Pending {
                remaining: 3,
                next_min: 0x80,
                next_max: 0xbf,
            },
            0xf4 => Pending {
                remaining: 3,
                next_min: 0x80,
                next_max: 0x8f,
            },
            0xf5..=0xff => {
                if self.defect_allow_over_max {
                    Pending {
                        remaining: 3,
                        next_min: 0x80,
                        next_max: 0xbf,
                    }
                } else {
                    self.errored = true;
                    return;
                }
            }
        };
        self.pending = Some(window);
    }

    fn continue_sequence(&mut self, window: Pending, byte: u8) {
        if byte < window.next_min || byte > window.next_max {
            self.errored = true;
            return;
        }
        self.pending = if window.remaining == 1 {
            None
        } else {
            Some(Pending {
                remaining: window.remaining - 1,
                next_min: 0x80,
                next_max: 0xbf,
            })
        };
    }
}

/// MUTANT M6: overlong-encoding shortcut (accepts 0xc0/0xc1 leads).
pub fn m6_utf8_allow_overlong(bytes: &[u8]) -> bool {
    MutantValidator::new(true, false, false).feed(bytes)
}

/// MUTANT M7: surrogate shortcut (accepts 0xed 0xa0.. sequences).
pub fn m7_utf8_allow_surrogates(bytes: &[u8]) -> bool {
    MutantValidator::new(false, true, false).feed(bytes)
}

/// MUTANT M8: out-of-range lead shortcut (accepts 0xf5..=0xff).
pub fn m8_utf8_allow_over_max(bytes: &[u8]) -> bool {
    MutantValidator::new(false, false, true).feed(bytes)
}

// ---------------------------------------------------------------------------
// framing.rs target: masking
// ---------------------------------------------------------------------------

/// MUTANT M9 of `apply_mask`: key rotated by one (`key[(i + 1) % 4]`).
///
/// This mutant is deliberately chosen to be INVISIBLE to the involution
/// property — XOR with any fixed per-index key is an involution — and visible
/// only to the exact per-byte mask equation.
pub fn m9_mask_rotated_key(payload: &mut [u8], key: [u8; 4]) {
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= key[(index + 1) % 4];
    }
}

/// MUTANT M10 of `apply_mask`: byte 0 skipped. Also invisible to involution.
pub fn m10_mask_skips_first_byte(payload: &mut [u8], key: [u8; 4]) {
    for (index, byte) in payload.iter_mut().enumerate() {
        if index > 0 {
            *byte ^= key[index % 4];
        }
    }
}

// ---------------------------------------------------------------------------
// framing.rs target: frame-header decode
// ---------------------------------------------------------------------------

/// The mutant decoder's result, mirroring `HeaderDecode` / `FrameReject`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MutantDecode {
    Insufficient,
    Header {
        masked: bool,
        payload_len: u64,
        header_len: usize,
        opcode_nibble: u8,
    },
    Reject {
        consumed: usize,
        close_code: u16,
    },
}

/// A parameterised copy of `decode_frame_header`. Each `defect_*` switch plants
/// exactly one defect.
fn mutant_decode(
    buf: &[u8],
    max_frame_payload_bytes: u64,
    // M11: control payload ceiling widened from 125 to 126. Kani PROVED this
    // mutant output-identical to the clean clone: a control frame with
    // `marker >= 126` is rejected before the ceiling is reached, so the
    // ceiling only ever sees `payload_len == marker <= 125` and both `> 125`
    // and `> 126` are dead. M15 is the reachable control-ceiling mutant.
    defect_control_limit_off_by_one: bool,
    // M12: frame-size gate `>` weakened to `>=` (rejects a legal max-size frame).
    defect_size_gate_ge: bool,
    // M13: extended-length control check moved AFTER the length read, so the
    // reported `consumed` offset is 4/10 instead of Java's 2.
    defect_control_check_late: bool,
    // M14: 16-bit extended length read little-endian.
    defect_len16_little_endian: bool,
    // M15: control payload ceiling TIGHTENED from 125 to 124, which
    // over-rejects a legal 125-byte control payload. Unlike M11 this defect is
    // reachable, because 124 < 125 = the largest marker a control frame can
    // carry past the extended-length check.
    defect_control_limit_too_tight: bool,
) -> MutantDecode {
    if buf.len() < 2 {
        return MutantDecode::Insufficient;
    }
    let b1 = buf[0];
    let b2 = buf[1];
    let nibble = b1 & 0x0f;
    if !crate::spec::opcode_known(nibble) {
        return MutantDecode::Reject {
            consumed: 2,
            close_code: 1002,
        };
    }
    let is_control = crate::spec::opcode_is_control(nibble);
    let masked = b2 & 0x80 != 0;
    let marker = u64::from(b2 & 0x7f);
    if !defect_control_check_late && is_control && marker >= 126 {
        return MutantDecode::Reject {
            consumed: 2,
            close_code: 1002,
        };
    }
    let (payload_len, length_site) = if marker == 126 {
        if buf.len() < 4 {
            return MutantDecode::Insufficient;
        }
        let value = if defect_len16_little_endian {
            u64::from(u16::from_le_bytes([buf[2], buf[3]]))
        } else {
            u64::from(u16::from_be_bytes([buf[2], buf[3]]))
        };
        (value, 4usize)
    } else if marker == 127 {
        if buf.len() < 10 {
            return MutantDecode::Insufficient;
        }
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&buf[2..10]);
        (u64::from_be_bytes(raw), 10usize)
    } else {
        (marker, 2usize)
    };
    if defect_control_check_late && is_control && marker >= 126 {
        return MutantDecode::Reject {
            consumed: length_site,
            close_code: 1002,
        };
    }
    let control_ceiling: u64 = if defect_control_limit_off_by_one {
        126
    } else if defect_control_limit_too_tight {
        124
    } else {
        125
    };
    if is_control && payload_len > control_ceiling {
        return MutantDecode::Reject {
            consumed: length_site,
            close_code: 1002,
        };
    }
    let over_size = if defect_size_gate_ge {
        payload_len >= max_frame_payload_bytes
    } else {
        payload_len > max_frame_payload_bytes
    };
    if over_size {
        return MutantDecode::Reject {
            consumed: length_site,
            close_code: 1009,
        };
    }
    let header_len = length_site + if masked { 4 } else { 0 };
    if buf.len() < header_len {
        return MutantDecode::Insufficient;
    }
    MutantDecode::Header {
        masked,
        payload_len,
        header_len,
        opcode_nibble: nibble,
    }
}

/// MUTANT M11: control payload ceiling widened to 126. PROVEN EQUIVALENT.
pub fn m11_control_limit(buf: &[u8], max: u64) -> MutantDecode {
    mutant_decode(buf, max, true, false, false, false, false)
}

/// MUTANT M12: frame-size gate over-rejects at exactly the limit.
pub fn m12_size_gate_ge(buf: &[u8], max: u64) -> MutantDecode {
    mutant_decode(buf, max, false, true, false, false, false)
}

/// MUTANT M13: extended-length control rejection reported at the wrong offset.
pub fn m13_control_check_late(buf: &[u8], max: u64) -> MutantDecode {
    mutant_decode(buf, max, false, false, true, false, false)
}

/// MUTANT M14: 16-bit extended length decoded little-endian.
pub fn m14_len16_little_endian(buf: &[u8], max: u64) -> MutantDecode {
    mutant_decode(buf, max, false, false, false, true, false)
}

/// MUTANT M15: control payload ceiling tightened to 124, over-rejecting a
/// legal 125-byte control payload. The REACHABLE control-ceiling mutant.
pub fn m15_control_limit_too_tight(buf: &[u8], max: u64) -> MutantDecode {
    mutant_decode(buf, max, false, false, false, false, true)
}

/// The UNMUTATED copy, as a control-on-the-control: the same clone with every
/// defect switch off must satisfy the same specs the real function satisfies.
pub fn m0_clean_clone(buf: &[u8], max: u64) -> MutantDecode {
    mutant_decode(buf, max, false, false, false, false, false)
}
