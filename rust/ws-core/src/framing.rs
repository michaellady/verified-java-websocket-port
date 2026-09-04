//! Framing: the RFC 6455 wire codec of the pinned Java runtime (US-012),
//! plus the fragment-reassembly processing arms (US-014).
//!
//! Behavior authority is the reference model `internal/corpora/derive.go`
//! (derived line-by-line from quarantined Java-WebSocket 1.6.0); every
//! rejection site, close code, and consumed-byte offset below cites it.
//! Structure mirrors the model's three stages exactly:
//!
//! 1. **Span scan** ([`Draft6455::scan_spans`], `WireTracker.frameLength` /
//!    derive.go `scanSpans`): complete frame extents by length grammar only;
//!    the incomplete tail stays buffered.
//! 2. **Translate** ([`Draft6455::translate_single_frame`] over each span,
//!    built on the proof-target header decoder
//!    [`Draft6455::decode_frame_header`]): Java's validity order with
//!    per-site consumption (quirk Q25) — unknown opcode and extended-length
//!    control markers reject after the 2 base header bytes, control/frame
//!    length limits at the length site (2/4/10), and reserved bits, control
//!    fin, close semantics (Q11/Q12/Q13), and the translate-time text UTF-8
//!    DFA (Q15 first stage) only after the full frame.
//! 3. **Process** ([`Draft6455::process_frame`] /
//!    [`Draft6455::process_frame_continuous`] /
//!    [`Draft6455::check_buffer_limit`], derive.go `processInbound` /
//!    `processDataFrame`): fragment starts, continuations, fin assembly
//!    (Q23 start/fin-only cumulative checks), and the strict process-time
//!    UTF-8 gate (Q15 second stage).
//!
//! ## Borrow attribution (owner strategy: borrow with attribution)
//!
//! Adapted from the Codex-plane US-012/US-014 implementation
//! (`codex-import` commits 8e5b19b `frame/decode.rs`+`frame/encode.rs`,
//! dca0fdb `fragment.rs`): the header-time length gate before any payload
//! allocation, the reserve-exactly-then-move payload backing, and the
//! incremental header-completeness discipline are theirs. **Java-fidelity
//! corrections applied here** (their codec is RFC-strict where shipped Java
//! is not — each divergence reconciled against derive.go):
//!
//! - their non-canonical 16/64-bit length rejection is STRIPPED (Java
//!   accepts non-minimal extended lengths; derive.go:400-420 reads whatever
//!   the wire says);
//! - their mask-by-role rejection is STRIPPED (the pinned runtime accepts
//!   either masking toward either role, derive.go:439-447; the corpus scopes
//!   itself to spec-conformant masking, so this is invisible there);
//! - their 64-bit high-bit rejection is STRIPPED (the length parses as an
//!   unsigned value and fails the ordinary frame-size gate instead);
//! - their header-time RSV / control-fin / fragment-sequence rejections are
//!   MOVED to Java's post-payload and process-time sites with Java's close
//!   codes and consumed offsets;
//! - failure vocabulary remapped onto the oracle
//!   [`crate::error::FailureCode`] wire codes.

use crate::close::close_code_rejection;
use crate::error::{FailureCode, TypedProtocolFailure};
use crate::fragment::ContinuousFrame;
use crate::message::Charsetfunctions;

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

    /// Parse the 4-bit wire opcode (`None` = Java `InvalidFrameException`
    /// "unknown opcode", rejected at header byte 2 — derive.go:393-394).
    #[must_use]
    pub(crate) fn from_wire(value: u8) -> Option<Opcode> {
        match value {
            0x0 => Some(Opcode::Continuous),
            0x1 => Some(Opcode::Text),
            0x2 => Some(Opcode::Binary),
            0x8 => Some(Opcode::Closing),
            0x9 => Some(Opcode::Ping),
            0xA => Some(Opcode::Pong),
            _ => None,
        }
    }

    /// The wire nibble for encoding.
    #[must_use]
    pub(crate) fn wire_nibble(self) -> u8 {
        match self {
            Opcode::Continuous => 0x0,
            Opcode::Text => 0x1,
            Opcode::Binary => 0x2,
            Opcode::Closing => 0x8,
            Opcode::Ping => 0x9,
            Opcode::Pong => 0xA,
        }
    }

    /// Whether this is a control opcode (close/ping/pong).
    #[must_use]
    pub(crate) fn is_control(self) -> bool {
        matches!(self, Opcode::Closing | Opcode::Ping | Opcode::Pong)
    }
}

/// A decoded frame header. Field layout mirrors the wire header plus the
/// parsed mask key; the semantic payload never appears here (headers are
/// decoded before any payload allocation — the header-time length gate of
/// the bounds strategy, a design element adopted with attribution from the
/// Codex US-012 decoder).
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
    /// Not enough bytes for a complete header AND the visible prefix passed
    /// every check the runtime performs before noticing incompleteness
    /// (derive.go `screenIncompleteHeader`); the caller keeps buffering
    /// (bounded by `max_buffered_bytes + 14`, quirk Q24).
    Insufficient,
    /// A complete header that passed the header-time checks.
    Header(FrameHeader),
}

/// A translate-stage rejection: the typed failure plus the exact byte
/// offset the pinned runtime consumed before throwing (quirk Q25;
/// derive.go `decodeFrame` fail sites — 2 after the base header, 4/10 after
/// an extended length, the full frame for post-payload checks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameReject {
    /// Bytes of the frame consumed before the rejection.
    pub consumed: usize,
    /// The typed failure.
    pub failure: TypedProtocolFailure,
}

impl FrameReject {
    fn at(consumed: usize, failure: TypedProtocolFailure) -> FrameReject {
        FrameReject { consumed, failure }
    }
}

/// A fully decoded, unmasked inbound frame awaiting processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedFrame {
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
    /// Whether the wire frame was masked.
    pub masked: bool,
    /// Semantic (unmasked) payload bytes.
    pub payload: Vec<u8>,
    /// Total wire size of the frame (header + mask + payload); filled by
    /// the caller from the frame's span.
    pub wire_bytes: usize,
}

/// One complete wire frame's extent within a combined buffer
/// (`WireTracker.frameLength` / derive.go `frameSpan`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FrameSpan {
    /// Absolute start offset.
    pub(crate) start: usize,
    /// Total frame size (header + mask + payload).
    pub(crate) size: usize,
}

/// What processing one data frame produced (derive.go `processDataFrame` /
/// `emitMessage` outcomes). Extended by US-015/US-016 with the control and
/// close outcomes when those arms land.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessOutcome {
    /// A non-fin fragment was absorbed; nothing is delivered.
    Buffered,
    /// A complete text message (already strictly validated — Q15 second
    /// stage) is delivered.
    Text(String),
    /// A complete binary message is delivered.
    Binary(Vec<u8>),
}

/// The close constructor payload (quirk Q10): `CloseFrame`'s constructor
/// stores `setReason("")` + `setCode(1000)` as `[0x03, 0xe8]` via
/// `updatePayload`, and the wire-parsing `setPayload` override never
/// replaces it — every parsed inbound close frame records and echoes
/// exactly these two bytes (derive.go `closeFrameConstructorPayload`).
pub const CLOSE_CONSTRUCTOR_PAYLOAD: [u8; 2] = [0x03, 0xe8];

/// Java's fixed control-payload limit (`translateSingleFramePayloadLength`;
/// derive.go `ControlPayloadLimit: 125`).
const CONTROL_PAYLOAD_LIMIT: u64 = 125;

/// The RFC 6455 draft implementation seam, mirroring
/// `org.java_websocket.drafts.Draft_6455` (migration map namespace
/// `ws_core::framing::Draft6455`). US-012/US-014 make it stateful: it owns
/// the inbound continuation accumulator (Java's `currentContinuousFrame`
/// plane, planned identity [`crate::fragment::ContinuousFrame`]) and the
/// outbound `send_fragment` sequence opcode (Java `Draft.continuousFrame`
/// tracking).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Draft6455 {
    /// Inbound fragment reassembly (US-014).
    continuous: ContinuousFrame,
    /// The declared opcode of an open outbound `send_fragment` sequence
    /// (derive.go `sendFragmentOpen`; `None` = no sequence open).
    send_continuous: Option<Opcode>,
}

impl Draft6455 {
    /// A fresh draft with no continuation state.
    #[must_use]
    pub fn new() -> Draft6455 {
        Draft6455::default()
    }

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

    /// Extract complete frame spans by length grammar only, mirroring
    /// `WireTracker.frameLength` (derive.go `scanSpans`): no opcode or
    /// validity checks here — those belong to the translate stage. Returns
    /// the spans and the offset where the incomplete tail begins.
    ///
    /// 64-bit lengths are read as unsigned values with saturating span
    /// arithmetic: a frame whose declared length cannot fit the buffered
    /// input simply never completes, and its header-time limit checks fire
    /// through [`Draft6455::decode_frame_header`] on the leftover instead
    /// (the reference model marks such lengths outside the generated space,
    /// derive.go:266-268; the port keeps the checked-arithmetic behavior as
    /// note.framing.checked-packet-size-arithmetic).
    pub(crate) fn scan_spans(data: &[u8]) -> (Vec<FrameSpan>, usize) {
        let mut spans = Vec::new();
        let mut at = 0usize;
        loop {
            if data.len() - at < 2 {
                break;
            }
            let marker = u64::from(data[at + 1] & 0x7f);
            let mut header = 2usize;
            let length: u64;
            if marker == 126 {
                if data.len() - at < 4 {
                    break;
                }
                header = 4;
                length = u64::from(u16::from_be_bytes([data[at + 2], data[at + 3]]));
            } else if marker == 127 {
                if data.len() - at < 10 {
                    break;
                }
                header = 10;
                let mut raw = [0u8; 8];
                raw.copy_from_slice(&data[at + 2..at + 10]);
                length = u64::from_be_bytes(raw);
            } else {
                length = marker;
            }
            if data[at + 1] & 0x80 != 0 {
                header += 4;
            }
            let total = (header as u64).saturating_add(length);
            if ((data.len() - at) as u64) < total {
                break;
            }
            // total fits within data, so the usize conversion is exact.
            let size = usize::try_from(total).unwrap_or(usize::MAX);
            spans.push(FrameSpan { start: at, size });
            at += size;
        }
        (spans, at)
    }

    /// Decode one frame header from the start of `buf`, applying exactly the
    /// checks the pinned runtime performs before the payload arrives, in
    /// Java's order with Java's consumed offsets
    /// (`translateSingleFrame` :528-566, `translateSingleFramePayloadLength`
    /// :612-641, `translateSingleFrameCheckLengthLimit` :648-663; derive.go
    /// `decodeFrame` header phase + `screenIncompleteHeader`):
    ///
    /// 1. unknown opcode — [`FailureCode::JavaInvalidData`] close code 1002,
    ///    2 bytes consumed;
    /// 2. a control frame with an extended-length marker (>= 126) — 1002, 2
    ///    bytes consumed, BEFORE the extended length bytes are read;
    /// 3. control payload over 125 — 1002 at the length site (2/4/10);
    /// 4. declared length over `max_frame_payload_bytes` — 1009 at the
    ///    length site (the header-time length gate: no payload allocation
    ///    has happened yet).
    ///
    /// Reserved bits are parsed but deliberately NOT validated here — Java
    /// checks them only after the payload is read
    /// (`DefaultExtension.isFrameValid`, derive.go:452-453); see
    /// [`Draft6455::translate_single_frame`]. An incomplete prefix that
    /// passes every visible check answers [`HeaderDecode::Insufficient`]
    /// (the caller keeps buffering), which makes this function double as
    /// the incomplete-header screen the runtime applies during the same
    /// read (derive.go `screenIncompleteHeader`).
    ///
    /// # Errors
    ///
    /// [`FrameReject`] with the failure and the exact consumed offset.
    pub fn decode_frame_header(
        buf: &[u8],
        max_frame_payload_bytes: u64,
    ) -> Result<HeaderDecode, FrameReject> {
        if buf.len() < 2 {
            return Ok(HeaderDecode::Insufficient);
        }
        let b1 = buf[0];
        let b2 = buf[1];
        let fin = b1 & 0x80 != 0;
        let rsv1 = b1 & 0x40 != 0;
        let rsv2 = b1 & 0x20 != 0;
        let rsv3 = b1 & 0x10 != 0;
        let Some(opcode) = Opcode::from_wire(b1 & 0x0f) else {
            // derive.go:393-394: unknown opcode, 2 bytes consumed.
            return Err(FrameReject::at(
                2,
                TypedProtocolFailure::java_invalid_data(1002),
            ));
        };
        let masked = b2 & 0x80 != 0;
        let marker = u64::from(b2 & 0x7f);
        // derive.go:403-407: an extended-length control frame is rejected
        // BEFORE the extended length bytes are read.
        if opcode.is_control() && marker >= 126 {
            return Err(FrameReject::at(
                2,
                TypedProtocolFailure::java_invalid_data(1002),
            ));
        }
        let (payload_len, length_site, length_end) = if marker == 126 {
            if buf.len() < 4 {
                return Ok(HeaderDecode::Insufficient);
            }
            (
                u64::from(u16::from_be_bytes([buf[2], buf[3]])),
                4usize,
                4usize,
            )
        } else if marker == 127 {
            if buf.len() < 10 {
                return Ok(HeaderDecode::Insufficient);
            }
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&buf[2..10]);
            (u64::from_be_bytes(raw), 10usize, 10usize)
        } else {
            (marker, 2usize, 2usize)
        };
        // derive.go:421-422: control payload limit at the length site.
        if opcode.is_control() && payload_len > CONTROL_PAYLOAD_LIMIT {
            return Err(FrameReject::at(
                length_site,
                TypedProtocolFailure::java_invalid_data(1002),
            ));
        }
        // derive.go:424-425: the frame-size gate (1009) at the length site —
        // before any payload allocation (header-time length gate).
        if payload_len > max_frame_payload_bytes {
            return Err(FrameReject::at(
                length_site,
                TypedProtocolFailure::java_invalid_data(1009),
            ));
        }
        let header_len = length_end + if masked { 4 } else { 0 };
        if buf.len() < header_len {
            return Ok(HeaderDecode::Insufficient);
        }
        let mask_key = if masked {
            let mut key = [0u8; 4];
            key.copy_from_slice(&buf[length_end..length_end + 4]);
            Some(key)
        } else {
            None
        };
        Ok(HeaderDecode::Header(FrameHeader {
            fin,
            rsv1,
            rsv2,
            rsv3,
            opcode,
            masked,
            mask_key,
            payload_len,
            header_len,
        }))
    }

    /// Translate one COMPLETE wire frame (`data` is exactly one span from
    /// [`Draft6455::scan_spans`]), mirroring derive.go `decodeFrame`: the
    /// header phase ([`Draft6455::decode_frame_header`]), then the payload
    /// copy with in-place unmasking (masking accepted in either direction —
    /// the pinned runtime accepts either masking toward either role,
    /// derive.go:439-447), then the post-payload validity order with the
    /// full frame consumed on rejection:
    ///
    /// 1. reserved bits — 1002 (`DefaultExtension.isFrameValid`);
    /// 2. non-fin control frame — 1002 (`ControlFrame.isValid`);
    /// 3. close semantics (Q11/Q12/Q13) via
    ///    [`Draft6455::parse_close_payload`];
    /// 4. translate-time text UTF-8 (Q15 first stage): the Hoehrmann DFA
    ///    rejects invalid content with 1007 but ACCEPTS a dangling
    ///    incomplete tail — the strict rejection happens later at process
    ///    time ([`Charsetfunctions::string_utf8`]).
    ///
    /// # Errors
    ///
    /// [`FrameReject`] with the failure and the exact consumed offset.
    pub fn translate_single_frame(
        data: &[u8],
        max_frame_payload_bytes: u64,
    ) -> Result<DecodedFrame, FrameReject> {
        let header = match Draft6455::decode_frame_header(data, max_frame_payload_bytes)? {
            HeaderDecode::Header(header) => header,
            HeaderDecode::Insufficient => {
                // The caller hands complete spans only; an insufficient
                // answer here is a span-arithmetic bug, failed loudly.
                unreachable!("translate_single_frame requires one complete frame span")
            }
        };
        // payload_len passed the frame-size gate, so it fits usize on every
        // supported platform (config ceilings are far below u32::MAX).
        let payload_len = usize::try_from(header.payload_len).unwrap_or(usize::MAX);
        // Reserve exactly, then copy and unmask in place (borrowed design:
        // codex 8e5b19b payload reservation + in-place range unmask).
        let mut payload = Vec::with_capacity(payload_len);
        payload.extend_from_slice(&data[header.header_len..header.header_len + payload_len]);
        if let Some(key) = header.mask_key {
            Draft6455::apply_mask(&mut payload, key);
        }
        let full = data.len();
        // derive.go:452-453: reserved bits, after the payload read.
        if header.rsv1 || header.rsv2 || header.rsv3 {
            return Err(FrameReject::at(
                full,
                TypedProtocolFailure::java_invalid_data(1002),
            ));
        }
        // derive.go:456-457: ControlFrame fin check.
        if header.opcode.is_control() && !header.fin {
            return Err(FrameReject::at(
                full,
                TypedProtocolFailure::java_invalid_data(1002),
            ));
        }
        // derive.go:459-465: close semantics apply at translate time.
        if header.opcode == Opcode::Closing
            && let Err(failure) = Draft6455::parse_close_payload(&payload)
        {
            return Err(FrameReject::at(full, failure));
        }
        // derive.go:471-474 (quirk Q15 first stage): translate-time DFA.
        if header.opcode == Opcode::Text && !Charsetfunctions::is_valid_utf8(&payload) {
            return Err(FrameReject::at(
                full,
                TypedProtocolFailure::java_invalid_data(1007),
            ));
        }
        Ok(DecodedFrame {
            fin: header.fin,
            rsv1: header.rsv1,
            rsv2: header.rsv2,
            rsv3: header.rsv3,
            opcode: header.opcode,
            masked: header.masked,
            payload,
            wire_bytes: full,
        })
    }

    /// Parse a close frame payload exactly as `CloseFrame.setPayload`
    /// followed by `isValid` does (quirks Q11/Q12/Q13; derive.go
    /// `parseCloseSemantics`):
    ///
    /// - empty payload -> code 1000, reason "";
    /// - one byte -> code 1002, reason "" (valid);
    /// - two or more bytes -> big-endian code + UTF-8 reason, where an
    ///   invalid reason becomes a null reason whose `isValid` dereference
    ///   raises Java's `NullPointerException`
    ///   ([`FailureCode::JavaRuntimeRejection`], Q12);
    /// - then the `CloseFrame.isValid` rejection chain
    ///   ([`close_code_rejection`], Q13).
    ///
    /// # Errors
    ///
    /// The typed failure the pinned runtime reports for the payload.
    pub fn parse_close_payload(payload: &[u8]) -> Result<(u16, String), TypedProtocolFailure> {
        let (code, reason) = match payload.len() {
            0 => (1000u16, String::new()),
            1 => (1002u16, String::new()),
            _ => {
                let code = u16::from_be_bytes([payload[0], payload[1]]);
                // Q12: the reason decode is STRICT (Go utf8.Valid); failure
                // is the NullPointerException path, not a 1007.
                let Ok(reason) = std::str::from_utf8(&payload[2..]) else {
                    return Err(TypedProtocolFailure::protocol(
                        FailureCode::JavaRuntimeRejection,
                    ));
                };
                (code, reason.to_owned())
            }
        };
        if let Some(reported) = close_code_rejection(code, &reason) {
            return Err(TypedProtocolFailure::java_invalid_data(reported));
        }
        Ok((code, reason))
    }

    /// Encode one wire frame, masking the payload when a key is supplied
    /// (RFC 6455 sections 5.2/5.3; mirrors the reference model's
    /// `EncodeFrame`, `internal/corpora/frames.go`, and Java
    /// `Draft_6455.createBinaryFrame`). The port never sets reserved bits
    /// on outbound frames, exactly as the pinned runtime never does.
    #[must_use]
    pub fn encode_frame(
        fin: bool,
        opcode: Opcode,
        payload: &[u8],
        mask: Option<[u8; 4]>,
    ) -> Vec<u8> {
        let mut first = opcode.wire_nibble();
        if fin {
            first |= 0x80;
        }
        let mask_bit = if mask.is_some() { 0x80u8 } else { 0 };
        let mut out = Vec::with_capacity(
            Draft6455::header_size(payload.len())
                + payload.len()
                + if mask.is_some() { 4 } else { 0 },
        );
        out.push(first);
        let length = payload.len();
        if length <= 125 {
            // The length fits in the 7-bit marker.
            #[allow(clippy::cast_possible_truncation)]
            out.push(mask_bit | length as u8);
        } else if length <= 0xffff {
            out.push(mask_bit | 126);
            #[allow(clippy::cast_possible_truncation)]
            out.extend_from_slice(&(length as u16).to_be_bytes());
        } else {
            out.push(mask_bit | 127);
            out.extend_from_slice(&(length as u64).to_be_bytes());
        }
        if let Some(key) = mask {
            out.extend_from_slice(&key);
            let start = out.len();
            out.extend_from_slice(payload);
            Draft6455::apply_mask(&mut out[start..], key);
        } else {
            out.extend_from_slice(payload);
        }
        out
    }

    /// RFC 6455 header size for a payload length, excluding any masking key
    /// (`headerSize`, internal/corpora/frames.go:91-100).
    #[must_use]
    pub(crate) fn header_size(payload_len: usize) -> usize {
        match payload_len {
            0..=125 => 2,
            126..=0xffff => 4,
            _ => 10,
        }
    }

    /// Process one translated inbound frame (`Draft_6455.processFrame`;
    /// derive.go `processInbound` dispatch + `processDataFrame` data arms).
    /// The caller (the connection) has already applied the closing/closed
    /// state gates and recorded the frame.
    ///
    /// `message_buffered` is the adapter's fragment accounting counter
    /// (corpus `counts.message_buffered_bytes`), updated at exactly the
    /// reference model's sites: assigned at fragment starts, add-bounded on
    /// non-fin continuations (never updated past the bound), and reset to
    /// zero only after a successful fin delivery.
    ///
    /// Control frames (close/ping/pong) never reach this seam: the
    /// connection dispatches them first (US-015/US-016 — the close
    /// lifecycle and ping/pong delivery own state, so they live beside the
    /// state gates in `ConnectionCore::process_inbound`). The control arm
    /// here is a defensive refusal for direct misuse of the seam, not a
    /// behavior claim.
    ///
    /// # Errors
    ///
    /// The typed process-stage failure (1002 fragment-sequence violations,
    /// 1009 fin-assembly overflow, adapter `BUFFER_LIMIT_EXCEEDED`, strict
    /// 1007 text validation, or the defensive control refusal).
    pub fn process_frame(
        &mut self,
        frame: &DecodedFrame,
        max_buffered_bytes: usize,
        max_message_bytes: usize,
        message_buffered: &mut u64,
    ) -> Result<ProcessOutcome, TypedProtocolFailure> {
        if frame.opcode.is_control() {
            // Unreachable via ConnectionCore (its process_inbound dispatches
            // control frames before this seam); defensive refusal only.
            return Err(TypedProtocolFailure::protocol(FailureCode::Unimplemented));
        }
        if frame.opcode == Opcode::Continuous {
            return self.process_frame_continuous(
                frame,
                max_buffered_bytes,
                max_message_bytes,
                message_buffered,
            );
        }
        if !frame.fin {
            // Fragment start (derive.go processDataFrame "fragment start"):
            // a start during an open sequence is 1002.
            if self.continuous.active_opcode().is_some() {
                return Err(TypedProtocolFailure::java_invalid_data(1002));
            }
            // Java checkBufferLimit runs at starts (Q23); the header-time
            // frame-size gate (1009 at decode) already bounds a start
            // payload to the same limit, so this cannot fire — kept to
            // mirror Java's call sites.
            Draft6455::check_buffer_limit(frame.payload.len(), max_message_bytes)?;
            *message_buffered = frame.payload.len() as u64;
            self.continuous.start(frame.opcode, frame.payload.clone());
            return Ok(ProcessOutcome::Buffered);
        }
        // Unfragmented data frame: 1002 when a fragment sequence is open
        // (derive.go processDataFrame default arm).
        if self.continuous.active_opcode().is_some() {
            return Err(TypedProtocolFailure::java_invalid_data(1002));
        }
        Draft6455::emit_message(frame.opcode, frame.payload.clone())
    }

    /// Process one continuation frame (`Draft_6455.processFrame` continuous
    /// arms; derive.go `processDataFrame` continuation cases; US-014):
    ///
    /// - orphan continuation (no open sequence) — 1002;
    /// - non-fin continuation: the adapter's add-bounded accounting
    ///   (`BUFFER_LIMIT_EXCEEDED`, no close code) BEFORE the counter or the
    ///   buffer grows (port-side strengthening
    ///   note.fragmentation.per-append-buffer-cap: the reference retains
    ///   the bytes then leaves the counter stale — observables identical);
    /// - fin continuation: cumulative [`Draft6455::check_buffer_limit`]
    ///   (Q23, close code 1009), assembly, then delivery through the strict
    ///   process-time gate; `message_buffered` resets ONLY after a
    ///   successful delivery (a strict-UTF-8 1007 leaves it at the pre-fin
    ///   value, exactly as the reference model does).
    ///
    /// # Errors
    ///
    /// The typed process-stage failure (see above).
    pub fn process_frame_continuous(
        &mut self,
        frame: &DecodedFrame,
        max_buffered_bytes: usize,
        max_message_bytes: usize,
        message_buffered: &mut u64,
    ) -> Result<ProcessOutcome, TypedProtocolFailure> {
        if self.continuous.active_opcode().is_none() {
            // derive.go: EnforceContinuationStart -> 1002.
            return Err(TypedProtocolFailure::java_invalid_data(1002));
        }
        if !frame.fin {
            let next = message_buffered.saturating_add(frame.payload.len() as u64);
            if next > max_buffered_bytes as u64 {
                return Err(TypedProtocolFailure::protocol(
                    FailureCode::BufferLimitExceeded,
                ));
            }
            self.continuous.append(&frame.payload);
            *message_buffered = next;
            return Ok(ProcessOutcome::Buffered);
        }
        // Fin: checkBufferLimit on the assembled size BEFORE assembly and
        // emission (derive.go:722-726, close code 1009).
        let assembled_size = self
            .continuous
            .buffered_len()
            .saturating_add(frame.payload.len());
        Draft6455::check_buffer_limit(assembled_size, max_message_bytes)?;
        let (message_opcode, assembled) = self.continuous.finish(&frame.payload);
        let outcome = Draft6455::emit_message(message_opcode, assembled)?;
        *message_buffered = 0;
        Ok(outcome)
    }

    /// The cumulative fragment-total gate Java applies at starts and fins
    /// (`checkBufferLimit`, quirk Q23; derive.go:722-726): an assembled
    /// size over the reassembly cap rejects with close code 1009.
    ///
    /// # Errors
    ///
    /// [`FailureCode::JavaInvalidData`] with close code 1009.
    pub fn check_buffer_limit(
        size: usize,
        max_message_bytes: usize,
    ) -> Result<(), TypedProtocolFailure> {
        if size > max_message_bytes {
            return Err(TypedProtocolFailure::java_invalid_data(1009));
        }
        Ok(())
    }

    /// Deliver one complete data message (derive.go `emitMessage`): text
    /// runs the strict process-time UTF-8 gate (Q15 second stage, close
    /// code 1007); binary passes through.
    fn emit_message(
        opcode: Opcode,
        payload: Vec<u8>,
    ) -> Result<ProcessOutcome, TypedProtocolFailure> {
        if opcode == Opcode::Text {
            let text = Charsetfunctions::string_utf8(payload)
                .map_err(|_| TypedProtocolFailure::java_invalid_data(1007))?;
            return Ok(ProcessOutcome::Text(text));
        }
        Ok(ProcessOutcome::Binary(payload))
    }

    /// The wire opcode for one `send_fragment` step, mirroring
    /// `Draft.continuousFrame` (derive.go `sendFragment`): the first call
    /// keeps the declared opcode (including a fin=true single-frame
    /// message) and opens the sequence when non-fin; later calls emit
    /// continuation frames until a fin closes the sequence. A mid-sequence
    /// opcode change is Java's `IllegalArgumentException` path, reported as
    /// [`FailureCode::JavaNotSendable`] (outside the verified corpus space —
    /// the reference model marks it unsupported; the mapping is recorded in
    /// the batch borrow receipt).
    ///
    /// The first-frame text DFA gate (JAVA_NOT_SENDABLE on definitely
    /// invalid UTF-8) is the CALLER's, ordered after the payload-limit gate
    /// as in derive.go.
    ///
    /// # Errors
    ///
    /// [`FailureCode::JavaNotSendable`] on a mid-sequence opcode change.
    pub fn continuous_send_opcode(
        &mut self,
        declared: Opcode,
        fin: bool,
    ) -> Result<Opcode, TypedProtocolFailure> {
        match self.send_continuous {
            None => {
                if !fin {
                    self.send_continuous = Some(declared);
                }
                Ok(declared)
            }
            Some(open) => {
                if open != declared {
                    return Err(TypedProtocolFailure::protocol(FailureCode::JavaNotSendable));
                }
                if fin {
                    self.send_continuous = None;
                }
                Ok(Opcode::Continuous)
            }
        }
    }

    /// Whether an outbound `send_fragment` sequence is currently open
    /// (derive.go `sendFragmentOpen != 0`).
    #[must_use]
    pub fn send_sequence_open(&self) -> bool {
        self.send_continuous.is_some()
    }
}
