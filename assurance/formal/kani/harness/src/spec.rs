//! Specification predicates, stated ONCE and applied identically to the real
//! `ws_core` functions and to the defect-planted copies in [`crate::mutants`].
//!
//! These are deliberately written as *derived facts* about the protocol
//! (close-code ranges, RFC 6455 length grammar, UTF-8 prefix semantics), not
//! as a restatement of the implementation's control flow. A spec that mirrors
//! the implementation's `if` chain proves only that the code equals itself;
//! the negative controls exist to demonstrate these specs are not that.

/// The close-code rejection codomain: the shipped runtime reports only
/// `None`, `Some(1002)` or `Some(1007)`.
pub fn close_rejection_codomain_ok(result: Option<u16>) -> bool {
    matches!(result, None | Some(1002) | Some(1007))
}

/// Derived facts about `close_code_rejection(code, reason)`.
///
/// Each clause is an independent statement about which close codes the pinned
/// Java runtime accepts on the wire, taken from the RFC 6455 registry ranges
/// and the `CloseFrame.isValid` rejection vocabulary — not from the port's
/// branch order.
pub fn close_rejection_fact(code: u16, reason_empty: bool, result: Option<u16>) -> bool {
    // C9: codomain.
    if !close_rejection_codomain_ok(result) {
        return false;
    }
    // C6/C7: 1007 is the ONLY code that can ever be reported as 1007, and it
    // does so exactly when the reason is empty.
    if code == 1007 {
        return if reason_empty {
            result == Some(1007)
        } else {
            result.is_none()
        };
    }
    if result == Some(1007) {
        return false;
    }
    // C4/C5: the never-on-the-wire codes always reject as 1002, for every reason.
    if code == 1004 || code == 1005 || code == 1006 || code == 1015 {
        return result == Some(1002);
    }
    // C3: outside the whole legal 1000..=4999 span, always 1002.
    if code < 1000 || code > 4999 {
        return result == Some(1002);
    }
    // C2: the unassigned/reserved 1016..=2999 span always rejects as 1002.
    if code >= 1016 && code <= 2999 {
        return result == Some(1002);
    }
    // C1: the registered 3000..=4999 application/private span is always legal.
    if code >= 3000 && code <= 4999 {
        return result.is_none();
    }
    // C8: everything left in 1000..=1015 that is not a never-on-the-wire code
    // is legal (1000..=1003 and 1008..=1014).
    result.is_none()
}

/// Derived facts about `normalize_send_close_code(code)` (quirk Q14).
pub fn normalize_fact(code: u16, out: u16) -> bool {
    // N1: 1015 never survives normalization, for any input.
    if out == 1015 {
        return false;
    }
    // N3: 1015 normalizes to 1005 specifically.
    if code == 1015 {
        return out == 1005;
    }
    // N2: every other code passes through untouched.
    out == code
}

/// The verdict of the independent reference decoder.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RefUtf8 {
    /// A complete, well-formed UTF-8 string.
    Complete,
    /// A well-formed PREFIX of some UTF-8 string: the input ended mid-sequence
    /// but every constraint so far is still satisfiable.
    Incomplete,
    /// Not a prefix of any UTF-8 string.
    Invalid,
}

/// The valid scalar range for a sequence with `need` continuation bytes,
/// as `(low, high)`.
fn scalar_range(need: usize) -> (u32, u32) {
    match need {
        0 => (0x0000, 0x007f),
        1 => (0x0080, 0x07ff),
        2 => (0x0800, 0xffff),
        _ => (0x0001_0000, 0x0010_ffff),
    }
}

/// Whether `[lo, hi]` contains any scalar admissible for a `need`-continuation
/// sequence: inside the length's range, and not a UTF-16 surrogate.
fn range_admits(lo: u32, hi: u32, need: usize) -> bool {
    let (vlo, vhi) = scalar_range(need);
    let ilo = if lo > vlo { lo } else { vlo };
    let ihi = if hi < vhi { hi } else { vhi };
    if ilo > ihi {
        return false;
    }
    // Surrogates D800..=DFFF are never scalars. The intersection admits
    // something only if it is not entirely inside the surrogate block.
    !(ilo >= 0xd800 && ihi <= 0xdfff)
}

/// An INDEPENDENT UTF-8 reference decoder.
///
/// It is deliberately structured differently from the shipped
/// `ws_core::message::Utf8Validator`: this decoder RECONSTRUCTS each scalar
/// value and validates it by CODE POINT RANGE (rejecting overlongs and
/// surrogates by their decoded value), whereas the shipped DFA validates by
/// precomputed per-byte continuation windows and never computes a code point
/// at all. A shared blind spot between the two would have to be a coincidence
/// of two different algorithms, not a copied line.
///
/// For a truncated trailing sequence it decides `Incomplete` vs `Invalid` by
/// asking whether the scalar bits accumulated so far can still be extended
/// into an admissible scalar — which is exactly the "prefix of a valid string"
/// semantics the translate stage is specified to have (quirk Q15 stage 1).
pub fn reference_utf8(bytes: &[u8]) -> RefUtf8 {
    let mut i = 0usize;
    while i < bytes.len() {
        let b0 = bytes[i];
        let (need, start_bits) = if b0 < 0x80 {
            (0usize, u32::from(b0))
        } else if b0 & 0xe0 == 0xc0 {
            (1usize, u32::from(b0 & 0x1f))
        } else if b0 & 0xf0 == 0xe0 {
            (2usize, u32::from(b0 & 0x0f))
        } else if b0 & 0xf8 == 0xf0 {
            (3usize, u32::from(b0 & 0x07))
        } else {
            // A bare continuation byte (0x80..=0xbf) or a 5+ byte lead
            // (0xf8..=0xff): no UTF-8 string starts a scalar here.
            return RefUtf8::Invalid;
        };
        let mut cp = start_bits;
        let mut have = 0usize;
        while have < need && i + have + 1 < bytes.len() {
            let c = bytes[i + have + 1];
            if c & 0xc0 != 0x80 {
                return RefUtf8::Invalid;
            }
            cp = (cp << 6) | u32::from(c & 0x3f);
            have += 1;
        }
        if have < need {
            // Truncated tail: admissible only if the missing 6-bit groups can
            // still land the scalar in an admissible range.
            let shift = 6u32 * ((need - have) as u32);
            let lo = cp << shift;
            let hi = lo | ((1u32 << shift) - 1);
            return if range_admits(lo, hi, need) {
                RefUtf8::Incomplete
            } else {
                RefUtf8::Invalid
            };
        }
        if !range_admits(cp, cp, need) {
            return RefUtf8::Invalid;
        }
        i += need + 1;
    }
    RefUtf8::Complete
}

/// The translate-stage oracle: accept anything that is a prefix of a valid
/// UTF-8 string (quirk Q15 stage 1).
pub fn utf8_translate_oracle(bytes: &[u8]) -> bool {
    reference_utf8(bytes) != RefUtf8::Invalid
}

/// The strict process-stage oracle: a complete, valid UTF-8 string.
pub fn utf8_strict_oracle(bytes: &[u8]) -> bool {
    reference_utf8(bytes) == RefUtf8::Complete
}

/// The 4-bit wire opcodes the pinned runtime knows.
pub fn opcode_known(nibble: u8) -> bool {
    matches!(nibble, 0 | 1 | 2 | 8 | 9 | 10)
}

/// Control opcodes per RFC 6455 (high bit of the opcode nibble set).
pub fn opcode_is_control(nibble: u8) -> bool {
    matches!(nibble, 8 | 9 | 10)
}

/// The RFC 6455 control-frame payload ceiling.
pub const CONTROL_LIMIT: u64 = 125;

/// The RFC 6455 length grammar: given the marker and the header bytes, the
/// declared payload length and the base (pre-mask) header size.
///
/// Returns `None` when `buf` is too short to contain the declared length.
pub fn length_grammar(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.len() < 2 {
        return None;
    }
    let marker = u64::from(buf[1] & 0x7f);
    if marker == 126 {
        if buf.len() < 4 {
            return None;
        }
        Some((u64::from(u16::from_be_bytes([buf[2], buf[3]])), 4))
    } else if marker == 127 {
        if buf.len() < 10 {
            return None;
        }
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&buf[2..10]);
        Some((u64::from_be_bytes(raw), 10))
    } else {
        Some((marker, 2))
    }
}
