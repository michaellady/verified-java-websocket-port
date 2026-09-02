//! E1 adversarial-evidence lane: deterministic property campaigns for the
//! pure behavioral functions (gap G5 of the US-010..016 AC-closure dossier;
//! owner amendment 2026-08-27 amends BEHAVIOR clauses to Java-faithful but
//! does NOT waive this evidence machinery).
//!
//! Zero new dependencies (the audit gate asserts the crate stays
//! dependency-free): the generator is a hand-rolled SplitMix64 PRNG from
//! fixed committed seeds, so every campaign is deterministic and
//! re-runnable byte-for-byte.
//!
//! Families and case counts (each family documents its own count):
//!
//! - UTF-8 differential: `Charsetfunctions::{is_valid_utf8, string_utf8}`
//!   vs an INDEPENDENT interval-arithmetic reference decoder (structurally
//!   different from the shipped first-continuation-window DFA), over random
//!   byte soup, independently-encoded random scalar strings, single-byte
//!   corruptions, and every truncation of multi-byte tails.
//! - Mask involution/equation: `Draft6455::apply_mask` vs a naive
//!   independent XOR model; involution; chunked-application equivalence.
//! - Length-encoding round trip: `encode_frame` -> `decode_frame_header` /
//!   `translate_single_frame` across the pinned length sites
//!   (0/1/125/126/127/65535/65536) plus random lengths, masked and
//!   unmasked, plus Java-faithful noncanonical 16/64-bit acceptance.
//! - Close-code tables: `normalize_send_close_code` and
//!   `close_code_rejection` EXHAUSTIVE over all 65536 codes (x empty and
//!   non-empty reasons) against an independently re-derived
//!   `CloseFrame.isValid` model, plus `parse_close_payload` round trips.

#![forbid(unsafe_code)]

use ws_core::close::{close_code_rejection, normalize_send_close_code};
use ws_core::error::FailureCode;
use ws_core::framing::{Draft6455, HeaderDecode, Opcode};
use ws_core::message::Charsetfunctions;

// ---------------------------------------------------------------------------
// Deterministic PRNG (SplitMix64, Steele et al.) — fixed seeds only.
// ---------------------------------------------------------------------------

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> SplitMix64 {
        SplitMix64 { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform-enough draw below `n` (modulo bias is irrelevant for fuzzing).
    fn below(&mut self, n: u64) -> u64 {
        assert!(n > 0);
        self.next_u64() % n
    }

    fn byte(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }

    fn chance(&mut self, one_in: u64) -> bool {
        self.below(one_in) == 0
    }
}

// ---------------------------------------------------------------------------
// Independent UTF-8 reference: interval arithmetic over achievable
// codepoints. Structurally different from the shipped window-table DFA: a
// byte is a hard error exactly when the achievable codepoint interval no
// longer intersects the valid scalar set for the sequence length
// (shortest-form minimum, surrogate exclusion, U+10FFFF ceiling).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefScan {
    /// Hard error at some byte (the DFA error state).
    Error,
    /// Every byte consumed, no sequence pending.
    Complete,
    /// Ended mid-sequence with every prefix byte still plausible.
    PendingTail,
}

/// Valid scalar-value interval for a UTF-8 sequence of `len` bytes
/// (shortest-form minimum, absolute ceiling).
fn scalar_bounds(len: u32) -> (u32, u32) {
    match len {
        2 => (0x80, 0x7ff),
        3 => (0x800, 0xffff),
        4 => (0x1_0000, 0x10_ffff),
        _ => unreachable!("only multi-byte lengths have bounds"),
    }
}

/// Whether `[lo, hi]` contains at least one valid scalar for a `len`-byte
/// sequence: inside the length bounds and not entirely surrogate.
fn interval_viable(lo: u32, hi: u32, len: u32) -> bool {
    let (min, max) = scalar_bounds(len);
    let lo = lo.max(min);
    let hi = hi.min(max);
    if lo > hi {
        return false;
    }
    // The only excluded interior region is the surrogate block.
    !(lo >= 0xd800 && hi <= 0xdfff)
}

fn reference_scan(bytes: &[u8]) -> RefScan {
    let mut i = 0usize;
    while i < bytes.len() {
        let lead = bytes[i];
        let (len, initial_bits) = if lead < 0x80 {
            i += 1;
            continue;
        } else if lead & 0xe0 == 0xc0 {
            (2u32, u32::from(lead & 0x1f))
        } else if lead & 0xf0 == 0xe0 {
            (3u32, u32::from(lead & 0x0f))
        } else if lead & 0xf8 == 0xf0 {
            (4u32, u32::from(lead & 0x07))
        } else {
            // Continuation byte or 0xf8..0xff lead outside any sequence.
            return RefScan::Error;
        };
        // After the lead, `remaining` continuation bytes each add 6 bits.
        let mut value = initial_bits;
        let mut remaining = len - 1;
        // Lead-byte viability (kills C0/C1 and F5..F7 with no lookahead).
        let shift = 6 * remaining;
        if !interval_viable(value << shift, (value << shift) | ((1 << shift) - 1), len) {
            return RefScan::Error;
        }
        i += 1;
        while remaining > 0 {
            if i >= bytes.len() {
                return RefScan::PendingTail;
            }
            let b = bytes[i];
            if b & 0xc0 != 0x80 {
                return RefScan::Error;
            }
            value = (value << 6) | u32::from(b & 0x3f);
            remaining -= 1;
            let shift = 6 * remaining;
            if !interval_viable(value << shift, (value << shift) | ((1 << shift) - 1), len) {
                return RefScan::Error;
            }
            i += 1;
        }
        // A completed sequence with a viable exact value is by construction
        // a valid scalar (interval width zero).
    }
    RefScan::Complete
}

/// Independent scalar-value UTF-8 encoder (never uses `char` / std encode).
fn reference_encode(scalar: u32, out: &mut Vec<u8>) {
    match scalar {
        0..=0x7f => out.push(scalar as u8),
        0x80..=0x7ff => {
            out.push(0xc0 | (scalar >> 6) as u8);
            out.push(0x80 | (scalar & 0x3f) as u8);
        }
        0x800..=0xffff => {
            assert!(!(0xd800..=0xdfff).contains(&scalar));
            out.push(0xe0 | (scalar >> 12) as u8);
            out.push(0x80 | ((scalar >> 6) & 0x3f) as u8);
            out.push(0x80 | (scalar & 0x3f) as u8);
        }
        0x1_0000..=0x10_ffff => {
            out.push(0xf0 | (scalar >> 18) as u8);
            out.push(0x80 | ((scalar >> 12) & 0x3f) as u8);
            out.push(0x80 | ((scalar >> 6) & 0x3f) as u8);
            out.push(0x80 | (scalar & 0x3f) as u8);
        }
        _ => unreachable!("caller draws valid scalars only"),
    }
}

/// Draw a valid Unicode scalar, biased toward encoding-length boundaries.
fn draw_scalar(rng: &mut SplitMix64) -> u32 {
    const BOUNDARIES: [u32; 12] = [
        0x00, 0x7f, 0x80, 0x7ff, 0x800, 0xd7ff, 0xe000, 0xfffd, 0xffff, 0x1_0000, 0x10_fffe,
        0x10_ffff,
    ];
    if rng.chance(3) {
        return BOUNDARIES[rng.below(BOUNDARIES.len() as u64) as usize];
    }
    loop {
        let v = (rng.next_u64() % 0x11_0000) as u32;
        if !(0xd800..=0xdfff).contains(&v) {
            return v;
        }
    }
}

/// The single differential oracle: shipped gates vs the reference intervals
/// vs the standard library, on one byte stream.
fn check_utf8_case(bytes: &[u8], label: &str) {
    let scan = reference_scan(bytes);
    let ref_dfa_accepts = scan != RefScan::Error;
    let ref_complete = scan == RefScan::Complete;

    let shipped_translate = Charsetfunctions::is_valid_utf8(bytes);
    let shipped_strict = Charsetfunctions::string_utf8(bytes.to_vec()).is_ok();
    let std_strict = std::str::from_utf8(bytes).is_ok();

    assert_eq!(
        shipped_translate, ref_dfa_accepts,
        "{label}: translate-time DFA vs interval reference on {bytes:02x?}"
    );
    assert_eq!(
        shipped_strict, ref_complete,
        "{label}: strict decode vs interval reference on {bytes:02x?}"
    );
    assert_eq!(
        std_strict, ref_complete,
        "{label}: std::str::from_utf8 vs interval reference on {bytes:02x?}"
    );
    // Q15 stage relation: the strict gate is strictly stronger.
    assert!(
        !shipped_strict || shipped_translate,
        "{label}: strict acceptance implies DFA acceptance on {bytes:02x?}"
    );
}

/// 20_000 random byte soups (length 0..64, biased toward non-ASCII).
#[test]
fn utf8_differential_random_byte_soup() {
    let mut rng = SplitMix64::new(0xe1a1_0001);
    for case in 0..20_000u32 {
        let len = rng.below(64) as usize;
        let mut bytes = Vec::with_capacity(len);
        for _ in 0..len {
            // Bias into the interesting lead/continuation ranges.
            let b = match rng.below(4) {
                0 => rng.byte(),
                1 => 0x80 | (rng.byte() & 0x3f),
                2 => 0xc0 | (rng.byte() & 0x3f),
                _ => 0xe0 | (rng.byte() & 0x1f),
            };
            bytes.push(b);
        }
        check_utf8_case(&bytes, &format!("soup case {case}"));
    }
}

/// 5_000 independently-encoded random scalar strings; each is verified
/// valid, then corrupted at one random byte and re-verified, then truncated
/// at EVERY byte offset (the truncated-tail acceptance split, quirk Q15).
#[test]
fn utf8_differential_encoded_strings_corruptions_and_truncations() {
    let mut rng = SplitMix64::new(0xe1a1_0002);
    for case in 0..5_000u32 {
        let mut bytes = Vec::new();
        for _ in 0..rng.below(12) {
            reference_encode(draw_scalar(&mut rng), &mut bytes);
        }
        check_utf8_case(&bytes, &format!("encoded case {case}"));
        assert!(
            Charsetfunctions::string_utf8(bytes.clone()).is_ok(),
            "independently encoded scalars must decode: {bytes:02x?}"
        );
        if !bytes.is_empty() {
            // Single-byte corruption.
            let mut corrupted = bytes.clone();
            let at = rng.below(corrupted.len() as u64) as usize;
            corrupted[at] ^= 1 << rng.below(8);
            check_utf8_case(&corrupted, &format!("corrupted case {case}"));
            // Every truncation point, including mid-sequence tails.
            for cut in 0..bytes.len() {
                check_utf8_case(&bytes[..cut], &format!("truncated case {case} cut {cut}"));
            }
        }
    }
}

/// The curated malformed corpus every UTF-8 validator must classify: one
/// case per overlong/surrogate/range/truncation family.
#[test]
fn utf8_curated_malformed_corpus() {
    // (bytes, dfa_accepts, complete_valid)
    let table: &[(&[u8], bool, bool)] = &[
        (b"", true, true),
        (b"hello", true, true),
        (&[0xc3, 0xa9], true, true),               // U+00E9
        (&[0xe2, 0x82, 0xac], true, true),         // U+20AC
        (&[0xf0, 0x9f, 0x92, 0xa9], true, true),   // U+1F4A9
        (&[0xed, 0x9f, 0xbf], true, true),         // U+D7FF
        (&[0xee, 0x80, 0x80], true, true),         // U+E000
        (&[0xf4, 0x8f, 0xbf, 0xbf], true, true),   // U+10FFFF
        (&[0xc0, 0xaf], false, false),             // overlong '/'
        (&[0xc1, 0xbf], false, false),             // overlong
        (&[0xe0, 0x80, 0x80], false, false),       // overlong NUL
        (&[0xe0, 0x9f, 0xbf], false, false),       // overlong < U+0800
        (&[0xf0, 0x80, 0x80, 0x80], false, false), // overlong
        (&[0xf0, 0x8f, 0xbf, 0xbf], false, false), // overlong < U+10000
        (&[0xed, 0xa0, 0x80], false, false),       // U+D800 surrogate
        (&[0xed, 0xbf, 0xbf], false, false),       // U+DFFF surrogate
        (&[0xf4, 0x90, 0x80, 0x80], false, false), // > U+10FFFF
        (&[0xf5, 0x80, 0x80, 0x80], false, false), // invalid lead
        (&[0xf8, 0x80], false, false),             // 5-byte-form lead
        (&[0xff], false, false),
        (&[0x80], false, false), // orphan continuation
        (&[0xbf], false, false),
        (&[0xc3], true, false),                         // dangling 2-byte lead
        (&[0xe2, 0x82], true, false),                   // dangling 3-byte tail
        (&[0xf0, 0x9f, 0x92], true, false),             // dangling 4-byte tail
        (&[0xe1, 0x41], false, false),                  // non-continuation
        (&[0x61, 0xc3, 0xa9, 0xe2, 0x82], true, false), // valid + tail
    ];
    for (bytes, dfa, complete) in table {
        assert_eq!(
            Charsetfunctions::is_valid_utf8(bytes),
            *dfa,
            "translate gate on {bytes:02x?}"
        );
        assert_eq!(
            Charsetfunctions::string_utf8(bytes.to_vec()).is_ok(),
            *complete,
            "strict gate on {bytes:02x?}"
        );
        check_utf8_case(bytes, "curated");
    }
}

// ---------------------------------------------------------------------------
// Masking properties.
// ---------------------------------------------------------------------------

/// 2_000 cases: the repeating four-byte XOR equation against a naive
/// independent model, the involution (mask twice = identity), and
/// chunk-split application with rotated keys matching whole-buffer
/// application at every split point offset.
#[test]
fn masking_equation_involution_and_chunked_equivalence() {
    let mut rng = SplitMix64::new(0xe1a1_0003);
    for case in 0..2_000u32 {
        let len = rng.below(300) as usize;
        let payload: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        let key = [rng.byte(), rng.byte(), rng.byte(), rng.byte()];

        // Equation: out[i] = in[i] ^ key[i % 4] (independent naive model).
        let mut masked = payload.clone();
        Draft6455::apply_mask(&mut masked, key);
        let expected: Vec<u8> = payload
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % 4])
            .collect();
        assert_eq!(masked, expected, "case {case}: XOR equation");

        // Involution.
        let mut round = masked.clone();
        Draft6455::apply_mask(&mut round, key);
        assert_eq!(round, payload, "case {case}: involution");

        // Chunked application at an arbitrary split, with the key rotated by
        // the split offset, equals whole-buffer application.
        if len > 0 {
            let split = rng.below(len as u64 + 1) as usize;
            let mut chunked = payload.clone();
            let (head, tail) = chunked.split_at_mut(split);
            Draft6455::apply_mask(head, key);
            let rotated = [
                key[split % 4],
                key[(split + 1) % 4],
                key[(split + 2) % 4],
                key[(split + 3) % 4],
            ];
            Draft6455::apply_mask(tail, rotated);
            assert_eq!(chunked, masked, "case {case}: chunked equivalence");
        }
    }
}

// ---------------------------------------------------------------------------
// Length-encoding round trip.
// ---------------------------------------------------------------------------

fn data_opcodes() -> [Opcode; 3] {
    [Opcode::Text, Opcode::Binary, Opcode::Continuous]
}

/// Round-trip the pinned length sites 0/1/125/126/127/65535/65536 plus 500
/// random lengths through encode -> header decode -> full translate, masked
/// and unmasked, checking the canonical marker choice on the wire.
#[test]
fn length_encoding_round_trip_at_the_pinned_sites() {
    let pinned: [usize; 7] = [0, 1, 125, 126, 127, 65_535, 65_536];
    let mut rng = SplitMix64::new(0xe1a1_0004);
    let mut lengths: Vec<usize> = pinned.to_vec();
    for _ in 0..500 {
        lengths.push(rng.below(2_000) as usize);
    }
    let cap = 70_000u64; // decode cap above the largest tested length
    for (case, &len) in lengths.iter().enumerate() {
        let opcode = data_opcodes()[case % 3];
        // Text frames pass the translate-time DFA, so their payloads must be
        // valid UTF-8: use ASCII there, arbitrary bytes elsewhere.
        let payload: Vec<u8> = if opcode == Opcode::Text {
            (0..len).map(|_| rng.byte() & 0x7f).collect()
        } else {
            (0..len).map(|_| rng.byte()).collect()
        };
        for mask in [None, Some([rng.byte(), rng.byte(), rng.byte(), rng.byte()])] {
            let fin = case % 2 == 0;
            let wire = Draft6455::encode_frame(fin, opcode, &payload, mask);

            // Canonical marker choice on the wire.
            let marker = wire[1] & 0x7f;
            let expected_marker_class = match len {
                0..=125 => len as u8,
                126..=65_535 => 126,
                _ => 127,
            };
            assert_eq!(
                marker, expected_marker_class,
                "case {case}: marker for {len}"
            );
            let mask_len = if mask.is_some() { 4 } else { 0 };
            let header_len = match len {
                0..=125 => 2,
                126..=65_535 => 4,
                _ => 10,
            } + mask_len;
            assert_eq!(wire.len(), header_len + len, "case {case}: wire size");

            // Header decode round trip.
            match Draft6455::decode_frame_header(&wire, cap) {
                Ok(HeaderDecode::Header(header)) => {
                    assert_eq!(header.fin, fin, "case {case}");
                    assert_eq!(header.opcode, opcode, "case {case}");
                    assert_eq!(header.masked, mask.is_some(), "case {case}");
                    assert_eq!(header.payload_len, len as u64, "case {case}");
                    assert_eq!(header.header_len, header_len, "case {case}");
                    assert_eq!(header.mask_key, mask, "case {case}");
                    assert!(!header.rsv1 && !header.rsv2 && !header.rsv3, "case {case}");
                }
                other => panic!("case {case}: header must decode, got {other:?}"),
            }

            // Full translate round trip: the unmask restores the payload.
            let frame = Draft6455::translate_single_frame(&wire, cap)
                .unwrap_or_else(|e| panic!("case {case}: translate must accept: {e:?}"));
            assert_eq!(frame.payload, payload, "case {case}: payload round trip");
            assert_eq!(frame.wire_bytes, wire.len(), "case {case}");
        }
    }
}

/// Java-faithful noncanonical acceptance (amended AC stance): a small
/// length spelled with the 16- or 64-bit escape decodes to the same value,
/// and every incomplete header prefix answers Insufficient.
#[test]
fn noncanonical_length_escapes_and_incomplete_prefixes() {
    let cap = 70_000u64;
    // Length 5 spelled three ways.
    let canonical = [0x82u8, 0x05, 1, 2, 3, 4, 5];
    let escape16 = [0x82u8, 126, 0x00, 0x05, 1, 2, 3, 4, 5];
    let escape64 = [0x82u8, 127, 0, 0, 0, 0, 0, 0, 0x00, 0x05, 1, 2, 3, 4, 5];
    for (wire, header_len) in [
        (&canonical[..], 2usize),
        (&escape16[..], 4),
        (&escape64[..], 10),
    ] {
        match Draft6455::decode_frame_header(wire, cap) {
            Ok(HeaderDecode::Header(header)) => {
                assert_eq!(header.payload_len, 5, "noncanonical value");
                assert_eq!(header.header_len, header_len);
            }
            other => panic!("noncanonical encoding must decode, got {other:?}"),
        }
        let frame = Draft6455::translate_single_frame(wire, cap)
            .expect("noncanonical escape translates like shipped Java");
        assert_eq!(frame.payload, [1, 2, 3, 4, 5]);
        // Every strict prefix of the header is Insufficient, never a panic
        // or a reject (the prefix passes all visible checks).
        for cut in 0..header_len {
            match Draft6455::decode_frame_header(&wire[..cut], cap) {
                Ok(HeaderDecode::Insufficient) => {}
                other => panic!("prefix {cut} must be Insufficient, got {other:?}"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Close-code tables (exhaustive).
// ---------------------------------------------------------------------------

/// Independent re-derivation of Java `CloseFrame.isValid`
/// (framing/CloseFrame.java:226-243), written from the Java control flow
/// rather than the Rust port's phrasing — the literal Java disjunction is
/// the point, so the range-contains restatement lint is suppressed.
#[allow(clippy::manual_range_contains)]
fn model_close_rejection(code: u16, reason: &str) -> Option<u16> {
    if code == 1007 && reason.is_empty() {
        return Some(1007);
    }
    if code == 1005 && !reason.is_empty() {
        return Some(1002);
    }
    if (1016..3000).contains(&code) {
        return Some(1002);
    }
    if code == 1006 || code == 1015 || code == 1005 || code > 4999 || code < 1000 || code == 1004 {
        return Some(1002);
    }
    None
}

/// Exhaustive over all 65536 codes x {empty, non-empty} reasons: the
/// shipped rejection chain equals the independent Java model, and 1015
/// normalization is the only normalization.
#[test]
fn close_code_tables_exhaustive_against_the_java_model() {
    for code in 0..=u16::MAX {
        // Q14 normalization: exactly 1015 -> 1005, identity elsewhere.
        let normalized = normalize_send_close_code(code);
        if code == 1015 {
            assert_eq!(normalized, 1005, "1015 must normalize to 1005");
        } else {
            assert_eq!(normalized, code, "only 1015 normalizes");
        }
        // Q13 rejection chain, both reason classes.
        for reason in ["", "going away"] {
            assert_eq!(
                close_code_rejection(code, reason),
                model_close_rejection(code, reason),
                "rejection chain at code {code}, reason {reason:?}"
            );
        }
    }
}

/// `parse_close_payload` round trips: the empty/one-byte constructor
/// defaults, the exhaustive code table on two-byte payloads, valid reasons,
/// the strict (Q12 runtime-rejection) reason decode, and 1_000 random
/// payloads for panic-freedom.
#[test]
fn close_payload_parse_round_trips() {
    // Empty payload: constructor defaults (1000, "").
    assert_eq!(
        Draft6455::parse_close_payload(&[]),
        Ok((1000, String::new()))
    );
    // One-byte payload: Java's protocol-error default (1002, "") — which the
    // rejection chain then accepts as a parsed value.
    assert_eq!(
        Draft6455::parse_close_payload(&[0x42]),
        Ok((1002, String::new()))
    );
    // Exhaustive two-byte payloads against the model.
    for code in 0..=u16::MAX {
        let payload = code.to_be_bytes();
        let parsed = Draft6455::parse_close_payload(&payload);
        match model_close_rejection(code, "") {
            Some(reported) => {
                let failure = parsed.expect_err("model rejects");
                assert_eq!(failure.code, FailureCode::JavaInvalidData, "code {code}");
                assert_eq!(failure.close_code, Some(reported), "code {code}");
            }
            None => assert_eq!(parsed, Ok((code, String::new())), "code {code}"),
        }
    }
    // Valid reason round trip.
    let mut payload = 1000u16.to_be_bytes().to_vec();
    payload.extend_from_slice("bye now".as_bytes());
    assert_eq!(
        Draft6455::parse_close_payload(&payload),
        Ok((1000, "bye now".to_owned()))
    );
    // Q12: an invalid-UTF-8 reason is the runtime-rejection path (no close
    // code), even for an otherwise legal code.
    let mut bad = 1000u16.to_be_bytes().to_vec();
    bad.extend_from_slice(&[0xed, 0xa0, 0x80]);
    let failure = Draft6455::parse_close_payload(&bad).expect_err("invalid reason");
    assert_eq!(failure.code, FailureCode::JavaRuntimeRejection);
    assert_eq!(failure.close_code, None);
    // Random payloads: no panic, and every outcome is one of the typed
    // vocabulary entries.
    let mut rng = SplitMix64::new(0xe1a1_0005);
    for _ in 0..1_000 {
        let len = rng.below(140) as usize;
        let payload: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        match Draft6455::parse_close_payload(&payload) {
            Ok((_, _)) => {}
            Err(failure) => assert!(
                matches!(
                    failure.code,
                    FailureCode::JavaInvalidData | FailureCode::JavaRuntimeRejection
                ),
                "unexpected failure vocabulary: {failure:?}"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Equivalent-mutant witnesses (mutation campaign, gap G6): three campaign-1
// survivors mutate the close-chain wiring in ways that are OBSERVABLY
// EQUIVALENT because the `CloseFrame.isValid` chain is redundant at those
// sites. Rather than assert that informally, each witness reimplements the
// mutated chain inline and proves output-identity EXHAUSTIVELY over all
// 65536 codes x {empty, non-empty} reasons. A mutant proven
// output-identical cannot be killed by any behavioral test — these are
// documented equivalents, not coverage gaps.
// ---------------------------------------------------------------------------

/// m016-1005-reason-flip: flipping rule 2's reason predicate reroutes
/// 1005-with-any-reason through rule 4 (`code == 1005`), which reports the
/// identical 1002.
#[allow(clippy::manual_range_contains)]
fn mutant_chain_1005_reason_flipped(code: u16, reason: &str) -> Option<u16> {
    if code == 1007 && reason.is_empty() {
        return Some(1007);
    }
    if code == 1005 && reason.is_empty() {
        // mutated predicate
        return Some(1002);
    }
    if code > 1015 && code < 3000 {
        return Some(1002);
    }
    if code == 1006 || code == 1015 || code == 1005 || code > 4999 || code < 1000 || code == 1004 {
        return Some(1002);
    }
    None
}

/// m016-range-lower-off-by-one: admitting 1015 into the 1016..2999 band
/// changes which rule rejects 1015 (rule 3 instead of rule 4) but not the
/// reported 1002.
#[allow(clippy::manual_range_contains)]
fn mutant_chain_range_lower_ge(code: u16, reason: &str) -> Option<u16> {
    if code == 1007 && reason.is_empty() {
        return Some(1007);
    }
    if code == 1005 && !reason.is_empty() {
        return Some(1002);
    }
    if code >= 1015 && code < 3000 {
        // mutated bound
        return Some(1002);
    }
    if code == 1006 || code == 1015 || code == 1005 || code > 4999 || code < 1000 || code == 1004 {
        return Some(1002);
    }
    None
}

#[test]
fn equivalent_mutant_witnesses_close_chain_redundancy() {
    for code in 0..=u16::MAX {
        for reason in ["", "going away"] {
            let shipped = close_code_rejection(code, reason);
            assert_eq!(
                mutant_chain_1005_reason_flipped(code, reason),
                shipped,
                "m016-1005-reason-flip is output-identical at code {code} reason {reason:?}"
            );
            assert_eq!(
                mutant_chain_range_lower_ge(code, reason),
                shipped,
                "m016-range-lower-off-by-one is output-identical at code {code} reason {reason:?}"
            );
            // m016-send-close-normalize-skip: the send path calls
            // normalize (1015 -> 1005) before the chain; skipping it is
            // inert because the chain rejects 1005 and 1015 with the same
            // 1002 for every reason, so no send_close observable changes.
            assert_eq!(
                close_code_rejection(normalize_send_close_code(code), reason),
                shipped,
                "m016-send-close-normalize-skip is output-identical at code {code} reason {reason:?}"
            );
        }
    }
}
