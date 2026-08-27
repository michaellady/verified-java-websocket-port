//! Close vocabulary and the pure close-code model (US-009 contract slice).
//!
//! [`CloseDetail`] is the corpus `close` object. The two pure functions
//! mirror `CloseFrame`'s shipped quirks exactly (quarantined Java-WebSocket
//! 1.6.0; reference model `internal/corpora/derive.go`):
//!
//! - [`normalize_send_close_code`] — quirk Q14: `CloseFrame.setCode` maps
//!   TLS_ERROR 1015 to NOCODE 1005 *before* validation
//!   (framing/CloseFrame.java:179-184; derive.go:888-893).
//! - [`close_code_rejection`] — quirk Q13: the `CloseFrame.isValid` rejection
//!   chain (framing/CloseFrame.java:226-243; derive.go `closeIsValidRejection`
//!   :618-635).
//!
//! US-016 wires these into the state machine's close paths; publishing them
//! here fixes the tested vocabulary without claiming any close *behavior*
//! (no frame is parsed or emitted by this module). The full close sequence —
//! echo-while-open (Q19), constructor-payload recording (Q10), payload parse
//! (Q11/Q12) — is US-016's, per the design draft's transition table.

/// Origin of the governing close outcome (`close.origin`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CloseOrigin {
    /// The remote endpoint's close frame governs.
    Remote,
    /// A local `send_close` governs.
    Local,
    /// Transport EOF governs (quirk Q20).
    Transport,
}

impl CloseOrigin {
    /// The corpus wire string.
    #[must_use]
    pub fn wire_name(&self) -> &'static str {
        match self {
            CloseOrigin::Remote => "remote",
            CloseOrigin::Local => "local",
            CloseOrigin::Transport => "transport",
        }
    }
}

/// The corpus `close` object: `{code, reason, origin, remote,
/// handshake_complete}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseDetail {
    /// The governing close code.
    pub code: u16,
    /// The governing close reason.
    pub reason: String,
    /// Who caused the close.
    pub origin: CloseOrigin,
    /// The oracle's `remote` flag (derive.go closeMap call sites; e.g. EOF
    /// sets it to whether the state was `closing`).
    pub remote: bool,
    /// The oracle's `handshake_complete` flag.
    pub handshake_complete: bool,
}

/// Quirk Q14: `CloseFrame.setCode` silently normalizes a requested send
/// close code of 1015 (TLS_ERROR) to 1005 (NOCODE) before any validation
/// runs (framing/CloseFrame.java:179-184; derive.go:888-893). Every other
/// code passes through unchanged.
#[must_use]
pub fn normalize_send_close_code(code: u16) -> u16 {
    if code == 1015 { 1005 } else { code }
}

/// Quirk Q13: the `CloseFrame.isValid` rejection chain
/// (framing/CloseFrame.java:226-243; derive.go closeIsValidRejection). Returns
/// `Some(reported_close_code)` when the shipped runtime rejects the
/// code/reason pair with an `InvalidDataException`, in Java's exact check
/// order:
///
/// 1. 1007 with an empty reason rejects as 1007;
/// 2. 1005 with a non-empty reason rejects as 1002;
/// 3. 1016..=2999 rejects as 1002;
/// 4. 1006, 1015, 1005, 1004, codes below 1000, and codes above 4999 reject
///    as 1002.
///
/// `None` means the pair is wire-legal for the shipped runtime.
#[must_use]
pub fn close_code_rejection(code: u16, reason: &str) -> Option<u16> {
    if code == 1007 && reason.is_empty() {
        return Some(1007);
    }
    if code == 1005 && !reason.is_empty() {
        return Some(1002);
    }
    if code > 1015 && code < 3000 {
        return Some(1002);
    }
    // Java's literal disjunction is: 1006 || 1015 || 1005 || >4999 || <1000
    // || 1004 (CloseFrame.java:239-242); `!(1000..=4999).contains(&code)`
    // is the same out-of-range predicate, restated for the range lint.
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
