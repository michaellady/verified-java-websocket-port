//! Server opening handshake (US-011): shipped Java-WebSocket 1.6.0's
//! acceptance behavior, live-verified.
//!
//! Provenance: incremental machine shape borrowed from the Codex plane
//! (`connection-core/src/handshake/server.rs`, tree `b6d4b99`), with the
//! Codex RFC validation REPLACED by the Java predicate transcribed in
//! `internal/corpora/handshake_live.go` (`javaServerObservable`; validated
//! 49/49 against the real pinned jar). The stripped Codex checks — bare-LF
//! and obs-fold byte policing, header-name tokens, duplicate headers,
//! Host/Upgrade/Connection requirements, key base64/length validation,
//! Content-Length/Transfer-Encoding/extension/subprotocol rejections, and
//! the strict request-line grammar — are exactly the 16 live-recorded
//! RFC-reject-but-Java-accept divergences this slice must NOT reject.
//!
//! The Java server path (WebSocketImpl.java:269-315):
//! 1. `translateHandshakeHttp` parses the head (Draft.java:70-132); parse
//!    failures throw `InvalidHandshakeException`.
//! 2. `translateHandshakeHttpServer` (Draft.java:141-155) checks the method
//!    and HTTP version, both `equalsIgnoreCase`.
//! 3. `acceptHandshakeAsServer` (Draft_6455.java:262-286) checks ONLY that
//!    `Sec-WebSocket-Version` parses (after trim) to 13 — `NOT_MATCHED`
//!    otherwise ([`Draft6455::accept_handshake_as_server`]).
//! 4. `postProcessHandshakeResponseAsServer` (Draft_6455.java:432-441)
//!    requires a non-empty `Sec-WebSocket-Key` and derives the accept value
//!    ([`Draft6455::generate_accept_key`]).

use super::http::{HeadAccumulator, JavaHeadParse, JavaHeaders, parse_java_head};
use super::{HandshakeLimitExceeded, HandshakeLimits, RejectChannel};
use crate::framing::Draft6455;

/// `HandshakeState` (org.java_websocket.enums.HandshakeState): the outcome
/// of a draft-level handshake match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HandshakeState {
    /// The handshake matches this draft.
    Matched,
    /// The handshake does not match (`NOT_MATCHED`).
    NotMatched,
}

impl Draft6455 {
    /// `acceptHandshakeAsServer` (Draft_6455.java:262-286): the ONLY check
    /// is that `Sec-WebSocket-Version` parses to 13 after `String.trim`
    /// (`readVersion`, Draft.java:329-341: `Integer.parseInt`, so `"+13"`,
    /// `"0013"`, and `" 13 "` all match — a live-verified Java quirk). The
    /// default extension and empty protocol accept anything
    /// (DefaultExtension.java:52-58, Protocol.java:58-61), and Host /
    /// Upgrade / Connection are never examined.
    #[must_use]
    pub fn accept_handshake_as_server(headers: &JavaHeaders) -> HandshakeState {
        if java_read_version(headers) == 13 {
            HandshakeState::Matched
        } else {
            HandshakeState::NotMatched
        }
    }
}

/// `Draft.readVersion` (Draft.java:329-341): `Integer.parseInt` over the
/// trimmed `Sec-WebSocket-Version` value; -1 on absence or any parse
/// failure (including int overflow, mirroring `NumberFormatException`).
fn java_read_version(headers: &JavaHeaders) -> i32 {
    let value = headers.get("Sec-WebSocket-Version");
    if value.is_empty() {
        return -1;
    }
    super::http::java_trim(value).parse::<i32>().unwrap_or(-1)
}

/// One step of the incremental server handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerHandshakeOutcome {
    /// The head's terminator has not arrived; keep buffering.
    Incomplete,
    /// The handshake was accepted.
    Accept {
        /// The derived `Sec-WebSocket-Accept` value (the live-scored
        /// observable).
        accept_key: String,
        /// The deterministic 101 response head to write. Byte-exact fidelity
        /// of this head to Java's (which appends non-deterministic `Date`
        /// and `Server` fields at the I/O shell) is NOT claimed; the scored
        /// observables are the 101 status and the accept value.
        response: Vec<u8>,
        /// Post-head remainder bytes from the final chunk (wire bytes for
        /// the frame layer).
        remainder: Vec<u8>,
    },
    /// The handshake was rejected. On the wire Java collapses every
    /// rejection to one observable: an HTTP error head plus a close with
    /// code 1002 ([`super::HANDSHAKE_REJECT_CLOSE_CODE`]).
    Reject {
        /// The draft-API channel (the finest honest distinction).
        channel: RejectChannel,
        /// The deterministic error head to write (byte-exact fidelity to
        /// Java's 404 flow is NOT claimed; the scored observable is the
        /// rejection itself).
        response: Vec<u8>,
    },
    /// A PLUS_SAFE budget refused further buffering (port strengthening —
    /// never a Java observable; see the module-level limits note).
    LimitExceeded(HandshakeLimitExceeded),
    /// The machine already reached a terminal outcome; no further bytes
    /// belong to the handshake.
    NotAwaiting,
}

/// Incremental server-handshake machine: bounded accumulation, Java-exact
/// parse and predicate. Deterministic under arbitrary re-chunking (each
/// chunk re-runs the pure parse over the accumulated head, exactly as
/// Java's `translateHandshake` re-runs per read).
#[derive(Debug)]
pub struct ServerHandshake {
    accumulator: HeadAccumulator,
    done: bool,
}

impl ServerHandshake {
    /// A fresh machine with the given budgets (configured on the connection
    /// path; hard ceilings in the Java-fidelity exam posture).
    #[must_use]
    pub fn new(limits: HandshakeLimits) -> Self {
        ServerHandshake {
            accumulator: HeadAccumulator::new(limits),
            done: false,
        }
    }

    /// Feed one transport chunk.
    pub fn consume(&mut self, chunk: &[u8]) -> ServerHandshakeOutcome {
        if self.done {
            return ServerHandshakeOutcome::NotAwaiting;
        }
        if let Err(refusal) = self.accumulator.push(chunk) {
            self.done = true;
            return ServerHandshakeOutcome::LimitExceeded(refusal);
        }
        match parse_java_head(self.accumulator.bytes()) {
            JavaHeadParse::Incomplete => ServerHandshakeOutcome::Incomplete,
            JavaHeadParse::Reject => self.reject(RejectChannel::InvalidHandshake),
            JavaHeadParse::Complete(head) => {
                // Draft.java:141-155: method and HTTP version, equalsIgnoreCase.
                if !head.first_line[0].eq_ignore_ascii_case("GET")
                    || !head.first_line[2].eq_ignore_ascii_case("HTTP/1.1")
                {
                    return self.reject(RejectChannel::InvalidHandshake);
                }
                // Draft_6455.java:262-286: version-only draft match.
                if Draft6455::accept_handshake_as_server(&head.headers)
                    == HandshakeState::NotMatched
                {
                    return self.reject(RejectChannel::NotMatched);
                }
                // Draft_6455.java:432-441: a missing or empty key throws while
                // building the response; any non-empty key (base64 or not, any
                // length) is hashed as-is.
                let key = head.headers.get("Sec-WebSocket-Key").to_string();
                if key.is_empty() {
                    return self.reject(RejectChannel::InvalidHandshake);
                }
                let accept_key = Draft6455::generate_accept_key(&key);
                let remainder = self.accumulator.bytes()[head.head_len..].to_vec();
                self.done = true;
                ServerHandshakeOutcome::Accept {
                    response: accept_response(&accept_key),
                    accept_key,
                    remainder,
                }
            }
        }
    }

    fn reject(&mut self, channel: RejectChannel) -> ServerHandshakeOutcome {
        self.done = true;
        ServerHandshakeOutcome::Reject {
            channel,
            response: REJECT_RESPONSE.to_vec(),
        }
    }
}

/// The deterministic 101 head (status line per HandshakeImpl1Server's
/// default `Web Socket Protocol Handshake` message; Upgrade/Connection/
/// Sec-WebSocket-Accept per `postProcessHandshakeResponseAsServer`).
fn accept_response(accept_key: &str) -> Vec<u8> {
    let mut response = Vec::with_capacity(160);
    response.extend_from_slice(b"HTTP/1.1 101 Web Socket Protocol Handshake\r\n");
    response.extend_from_slice(b"Upgrade: websocket\r\n");
    response.extend_from_slice(b"Connection: Upgrade\r\n");
    response.extend_from_slice(b"Sec-WebSocket-Accept: ");
    response.extend_from_slice(accept_key.as_bytes());
    response.extend_from_slice(b"\r\n\r\n");
    response
}

/// The deterministic error head for the collapsed rejection observable
/// (Java answers wrong handshakes with an HTTP 404 error body before the
/// 1002 close; byte-exact fidelity is not claimed).
const REJECT_RESPONSE: &[u8] = b"HTTP/1.1 404 Not Found\r\n\r\n";
