//! Framing seam: opcode vocabulary and the two US-006-named proof-target
//! symbols (US-009 fixes names and signatures; US-012 supplies behavior).
//!
//! `assurance/formal/proof-targets.json` plans
//! `ws_core::framing::Draft6455::apply_mask` (sym.framing.apply-mask) and
//! `ws_core::framing::Draft6455::decode_frame_header`
//! (sym.framing.decode-frame-header) as the shipped mask function and
//! frame-header decoder. Per the design draft (section 6, "Inputs to wait
//! for"), US-009 finalizes exactly these two signatures once US-006 fixes the
//! names — which it has. [`Draft6455::apply_mask`] is implemented (a pure,
//! fixed-spec involution); [`Draft6455::decode_frame_header`] is an honest
//! skeleton that always answers [`HeaderDecode::Insufficient`], so the US-009
//! core buffers bytes without ever claiming frame decoding (the
//! protocol-stub gate). Canonical 7/16/64-bit length decoding, the
//! header-time length gate, checked packet-size arithmetic
//! (note.framing.checked-packet-size-arithmetic), and encode_frame are
//! US-012.

use crate::error::TypedProtocolFailure;

/// Frame opcode, mirroring `org.java_websocket.framing.Framedata.Opcode`.
/// The corpus wire name of the close opcode is `closing` — Java's own
/// `Opcode.CLOSING` spelling, mirrored deliberately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Opcode {
    /// Continuation frame (`continuous`).
    Continuous,
    /// Text frame.
    Text,
    /// Binary frame.
    Binary,
    /// Close frame (`closing`, Java's Opcode.CLOSING).
    Closing,
    /// Ping control frame.
    Ping,
    /// Pong control frame.
    Pong,
}

impl Opcode {
    /// The corpus wire string (`frames[].opcode` enum).
    #[must_use]
    pub fn wire_name(&self) -> &'static str {
        match self {
            Opcode::Continuous => "continuous",
            Opcode::Text => "text",
            Opcode::Binary => "binary",
            Opcode::Closing => "closing",
            Opcode::Ping => "ping",
            Opcode::Pong => "pong",
        }
    }
}

/// A decoded frame header (filled by US-012's decoder). Field layout mirrors
/// the wire header plus the parsed mask key; the semantic payload never
/// appears here (headers are decoded before any payload allocation — the
/// header-time length gate of the bounds strategy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// FIN bit.
    pub fin: bool,
    /// RSV1 bit.
    pub rsv1: bool,
    /// RSV2 bit.
    pub rsv2: bool,
    /// RSV3 bit.
    pub rsv3: bool,
    /// Parsed opcode.
    pub opcode: Opcode,
    /// Whether the payload is masked.
    pub masked: bool,
    /// The 4-byte mask key when `masked` (never observable in transcripts —
    /// quirk Q28).
    pub mask_key: Option<[u8; 4]>,
    /// Declared payload length (validated against the frame cap *before*
    /// any payload allocation).
    pub payload_len: u64,
    /// Total header length in bytes (base header + length escape + mask).
    pub header_len: usize,
}

/// Outcome of a frame-header decode attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderDecode {
    /// Not enough bytes for a complete, validated header; the caller keeps
    /// buffering (bounded by `max_buffered_bytes + 14`, quirk Q24).
    Insufficient,
    /// A complete header (US-012).
    Header(FrameHeader),
}

/// The RFC 6455 draft implementation seam, mirroring
/// `org.java_websocket.drafts.Draft_6455` (migration map namespace
/// `ws_core::framing::Draft6455`). US-009 ships it stateless; US-012 adds
/// the per-connection decode state (incomplete frame, continuation
/// tracking).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Draft6455;

impl Draft6455 {
    /// XOR-mask `payload` in place with the 4-byte `key`: byte `i` XORs with
    /// `key[i % 4]`. Applied on encode for the client role and removed on
    /// decode (Draft_6455.java:511-517 encode loop, 558-563 decode unmask
    /// loop). Masking is an involution: applying the same key twice restores
    /// the input (proof family mask-equation-involution,
    /// property.framing.mask-involution).
    pub fn apply_mask(payload: &mut [u8], key: [u8; 4]) {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= key[index % 4];
        }
    }

    /// Decode one frame header from the start of `buf`, gating the declared
    /// payload length against `max_frame_payload_bytes` *before* any payload
    /// allocation (Draft_6455.java translateSingleFrame :528-566,
    /// translateSingleFramePayloadLength :612-641,
    /// translateSingleFrameCheckLengthLimit :648-663).
    ///
    /// US-009 skeleton: always answers [`HeaderDecode::Insufficient`] — this
    /// story claims no frame decoding, so every byte stays buffered and a
    /// corpus evaluation of this core must fail (protocol-stub gate). US-012
    /// replaces the body with the real decoder, including the checked
    /// packet-size arithmetic strengthening
    /// (note.framing.checked-packet-size-arithmetic) and the error-site
    /// consumption quirk Q25.
    ///
    /// # Errors
    ///
    /// The skeleton never fails; US-012's decoder reports translate-stage
    /// rejections (unknown opcode, oversized control, length-limit and
    /// reserved-bit violations) as [`TypedProtocolFailure`] values.
    pub fn decode_frame_header(
        buf: &[u8],
        max_frame_payload_bytes: u64,
    ) -> Result<HeaderDecode, TypedProtocolFailure> {
        let _ = (buf, max_frame_payload_bytes);
        Ok(HeaderDecode::Insufficient)
    }
}
