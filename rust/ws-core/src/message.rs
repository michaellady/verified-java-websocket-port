//! Message plane (US-013): the two-stage UTF-8 machinery mirroring
//! `org.java_websocket.util.Charsetfunctions` (migration map row
//! `migration.org-java-websocket-util-charsetfunctions`; proof-target
//! symbols `ws_core::message::Charsetfunctions::is_valid_utf8` and
//! `ws_core::message::Charsetfunctions::string_utf8`,
//! target.formal.messages.utf8-validation-total).
//!
//! The two-stage truncated-tail semantics are contract-pinned (quirk Q15)
//! and the two gates stay distinct — US-013 may NOT collapse them into one
//! RFC-style check:
//!
//! - [`Charsetfunctions::is_valid_utf8`] is the translate-time Hoehrmann
//!   DFA (`Charsetfunctions.isValidUTF8`): it reports failure only from the
//!   DFA error state, so a payload ending in a valid-but-incomplete
//!   multi-byte prefix is ACCEPTED at translate time and the frame is
//!   recorded (derive.go `dfaAcceptsAtTranslate` :481-535);
//! - [`Charsetfunctions::string_utf8`] is the strict process-time decoder
//!   (`Charsetfunctions.stringUtf8` with the REPORT error action): it
//!   rejects the same dangling tail, which the caller surfaces as close
//!   code 1007 after the frame record exists (derive.go `emitMessage`).
//!
//! ## Borrow attribution
//!
//! The allocation-free incremental [`Utf8Validator`] state machine below is
//! adapted from the Codex-plane US-013 implementation (`codex-import`
//! commit 0be0766, `rust/connection-core/src/utf8.rs`): the
//! first-continuation window encoding of the overlong/surrogate/range
//! rules (0xE0->A0..BF, 0xED->80..9F, 0xF0->90..BF, 0xF4->80..8F) is
//! theirs. Adaptations: their per-failure taxonomy collapses to the DFA
//! error state (Java reports only the state, and the oracle only close
//! code 1007), and the validator serves ONLY the translate-time gate — the
//! strict gate decodes with the standard library (exactly Go `utf8.Valid`
//! semantics, the reference model's strict stage) so the two stages cannot
//! accidentally share the lenient tail rule.

/// The first-continuation admission window for a multi-byte sequence
/// (borrowed encoding — see the module attribution note).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Pending {
    /// Continuation bytes still required.
    remaining: u8,
    /// Lowest admissible next byte.
    next_min: u8,
    /// Highest admissible next byte.
    next_max: u8,
}

/// Allocation-free incremental UTF-8 DFA. Feeding bytes either stays in a
/// live state or trips the error state permanently; a live-but-pending end
/// state is the "dangling incomplete tail" the translate gate accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Utf8Validator {
    pending: Option<Pending>,
    errored: bool,
}

impl Utf8Validator {
    /// A fresh validator in the accept state.
    pub(crate) const fn new() -> Utf8Validator {
        Utf8Validator {
            pending: None,
            errored: false,
        }
    }

    /// Feed bytes; returns `false` once the DFA has reached the error state
    /// (further feeding stays errored).
    pub(crate) fn feed(&mut self, bytes: &[u8]) -> bool {
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
        let window = match byte {
            0x00..=0x7f => return,
            // A continuation or overlong lead byte outside any sequence is
            // the DFA error state.
            0x80..=0xc1 => {
                self.errored = true;
                return;
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
                next_max: 0x9f,
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
                self.errored = true;
                return;
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

/// A strict-stage decode rejection (the process-time REPORT decoder said
/// no). Carries no detail: Java reports only the failure, and the oracle
/// only close code 1007 (or the runtime-rejection path for close reasons) —
/// the caller supplies the site-correct failure vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Utf8DecodeError;

/// The `org.java_websocket.util.Charsetfunctions` seam: the exact pair of
/// UTF-8 gates the pinned runtime applies to text payloads, published as
/// the pinned proof-target symbols (US-006 `assurance/formal/proof-targets
/// .json`: sym.utf8.is-valid, sym.utf8.string-decode).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Charsetfunctions;

impl Charsetfunctions {
    /// Translate-time DFA acceptance (`Charsetfunctions.isValidUTF8`;
    /// derive.go `dfaAcceptsAtTranslate`): `false` only when the DFA
    /// reaches its error state, so a payload ending in a
    /// valid-but-incomplete multi-byte prefix is accepted here (quirk Q15
    /// first stage).
    #[must_use]
    pub fn is_valid_utf8(bytes: &[u8]) -> bool {
        let mut validator = Utf8Validator::new();
        validator.feed(bytes)
    }

    /// Strict process-time decode (`Charsetfunctions.stringUtf8` with the
    /// REPORT action; derive.go `emitMessage` strict stage): rejects
    /// everything invalid INCLUDING the dangling incomplete tail the
    /// translate gate accepted. Zero-copy: a valid payload becomes the
    /// delivered `String` without reallocation.
    ///
    /// # Errors
    ///
    /// [`Utf8DecodeError`] when the bytes are not one complete valid UTF-8
    /// sequence; the caller maps it to the site's failure vocabulary
    /// (close code 1007 for text delivery).
    pub fn string_utf8(bytes: Vec<u8>) -> Result<String, Utf8DecodeError> {
        String::from_utf8(bytes).map_err(|_| Utf8DecodeError)
    }
}
