//! Client opening handshake (US-010): deterministic upgrade-request
//! generation plus shipped Java-WebSocket 1.6.0's response acceptance,
//! live-verified.
//!
//! Provenance: the request descriptor, canonical request rendering, and
//! nonce/key encoding are borrowed from the Codex plane
//! (`connection-core/src/handshake/client.rs`, trees `19f7067`/`b6d4b99`)
//! and adapted; the response validation REPLACES the Codex RFC parser
//! (`validate_response`) with the Java predicate transcribed in
//! `internal/corpora/handshake_live.go` (`javaClientObservable`):
//!
//! 1. parse per Draft.java:70-132 (CRLF-only lines, `"; "` duplicate
//!    joining; parse failures are the `invalid_handshake` channel);
//! 2. `translateHandshakeHttpClient` (Draft.java:164-180): the status token
//!    is compared LITERALLY against `"101"` before the HTTP version check
//!    (`equalsIgnoreCase`) — so `"0101"` and two-token status lines reject;
//! 3. `basicAccept` (Draft.java:188-191): `Upgrade` equalsIgnoreCase
//!    `websocket` AND `Connection` containing `upgrade` case-insensitively
//!    (`NOT_MATCHED` otherwise — quirk Q9);
//! 4. both the request key and a `Sec-WebSocket-Accept` field must exist,
//!    and `generateFinalKey(trim(key))` must LITERALLY equal the response
//!    value (Draft_6455.java:306-343) — `NOT_MATCHED` otherwise.
//!
//! The stripped Codex client checks (bare-LF/obs-fold byte policing,
//! header-name tokens, duplicate-header rejection, header-value and
//! reason-phrase octet policing, extension/subprotocol rejection,
//! trailing-data rejection, strict status-line grammar) do not exist in
//! shipped Java and are live-recorded divergences on the response side.
//!
//! **Determinism seam (adaptation)**: the Codex API took a caller-supplied
//! nonce; here [`nonce_from_seed`] derives the 16-byte nonce from the
//! configured `mask_key_seed` (quirk Q28: key material is never observable,
//! so any deterministic source scores identically against the oracle).

use super::http::{HeadAccumulator, JavaHeadParse, java_trim, parse_java_head};
use super::{HandshakeLimitExceeded, HandshakeLimits, RejectChannel, RejectStage, crypto};
use crate::framing::Draft6455;

/// Hard ceiling on the caller-selected descriptor fields (borrowed Codex
/// bound; keeps the rendered request within every handshake budget).
const DESCRIPTOR_FIELD_MAX: usize = 1024;

/// Caller-owned origin-form target and Host value for a client handshake
/// (borrowed from the Codex `ClientRequestDescriptor`). Outbound-request
/// validation is a port-side construction guard (it shapes only what WE
/// send, never how inbound bytes are judged), so it is kept.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientRequestDescriptor {
    request_target: Box<str>,
    host: Box<str>,
}

/// Why a descriptor could not be represented canonically.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientRequestDescriptorError {
    /// The target did not begin with `/` as an origin-form target must.
    RequestTargetNotOriginForm,
    /// The target contained a non-visible-ASCII byte (whitespace, control,
    /// or high byte — header-injection guard).
    InvalidRequestTargetByte,
    /// The target exceeded the descriptor hard ceiling.
    RequestTargetTooLong,
    /// The Host value was empty.
    EmptyHost,
    /// The Host value contained a non-visible-ASCII byte.
    InvalidHostByte,
    /// The Host value exceeded the descriptor hard ceiling.
    HostTooLong,
}

impl ClientRequestDescriptor {
    /// Validates and owns the two caller-selected HTTP wire fields.
    ///
    /// # Errors
    ///
    /// [`ClientRequestDescriptorError`] naming the first offending field.
    pub fn try_new(request_target: &str, host: &str) -> Result<Self, ClientRequestDescriptorError> {
        if !request_target.starts_with('/') {
            return Err(ClientRequestDescriptorError::RequestTargetNotOriginForm);
        }
        if request_target.len() > DESCRIPTOR_FIELD_MAX {
            return Err(ClientRequestDescriptorError::RequestTargetTooLong);
        }
        if !request_target.bytes().all(is_visible_ascii) {
            return Err(ClientRequestDescriptorError::InvalidRequestTargetByte);
        }
        if host.is_empty() {
            return Err(ClientRequestDescriptorError::EmptyHost);
        }
        if host.len() > DESCRIPTOR_FIELD_MAX {
            return Err(ClientRequestDescriptorError::HostTooLong);
        }
        if !host.bytes().all(is_visible_ascii) {
            return Err(ClientRequestDescriptorError::InvalidHostByte);
        }
        Ok(Self {
            request_target: request_target.into(),
            host: host.into(),
        })
    }

    /// The validated origin-form request target.
    #[must_use]
    pub fn request_target(&self) -> &str {
        &self.request_target
    }

    /// The validated Host field value.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }
}

const fn is_visible_ascii(byte: u8) -> bool {
    byte >= 0x21 && byte <= 0x7e
}

/// Deterministic 16-byte handshake nonce from the configured
/// `mask_key_seed` (SplitMix64 stream — any deterministic source scores
/// identically; quirk Q28).
#[must_use]
pub fn nonce_from_seed(seed: u64) -> [u8; 16] {
    let mut nonce = [0u8; 16];
    let mut state = seed;
    for chunk in nonce.chunks_exact_mut(8) {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        chunk.copy_from_slice(&z.to_be_bytes());
    }
    nonce
}

/// One step of the client handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientHandshakeOutcome {
    /// The response head's terminator has not arrived; keep buffering.
    Incomplete,
    /// The server's response was accepted; the connection opens.
    Accept {
        /// Post-head remainder bytes from the final chunk.
        remainder: Vec<u8>,
        /// The `Sec-WebSocket-Accept` value this client MATCHED. It is the
        /// value the client's own challenge derivation produced
        /// (`generateFinalKey(trim(key))`, Draft_6455.java:318-325): the
        /// acceptance predicate below succeeds only when the derived value
        /// equals the field the server sent, so on this arm the two are the
        /// same string. Shipped Java computes it on every client-side
        /// acceptance; nothing in the handshake protocol used to report it,
        /// which left the client-side accept derivation unscored.
        sec_websocket_accept: String,
    },
    /// The response was rejected (Java closes 1002).
    Reject {
        /// The draft-API channel.
        channel: RejectChannel,
        /// WHICH draft-API call decided (see [`RejectStage`]).
        stage: RejectStage,
    },
    /// A PLUS_SAFE budget refused further buffering (port strengthening).
    LimitExceeded(HandshakeLimitExceeded),
    /// The machine already reached a terminal outcome.
    NotAwaiting,
}

/// Incremental client-handshake machine: request generation plus bounded,
/// Java-exact response acceptance.
#[derive(Debug)]
pub struct ClientHandshake {
    accumulator: HeadAccumulator,
    /// The raw `Sec-WebSocket-Key` this client sent (trimmed at compare
    /// time, mirroring `generateFinalKey(trim(key))`).
    client_key: String,
    done: bool,
}

impl ClientHandshake {
    /// Start a client handshake: render the canonical upgrade request for
    /// `descriptor` with the deterministic `nonce`, and return the machine
    /// awaiting the server's response plus the request bytes to write.
    #[must_use]
    pub fn start(
        descriptor: &ClientRequestDescriptor,
        nonce: [u8; 16],
        limits: HandshakeLimits,
    ) -> (Self, Vec<u8>) {
        let key = crypto::encode_nonce(nonce);
        let key_string =
            String::from_utf8(key.to_vec()).expect("base64-encoded nonce keys are ASCII");
        let request = canonical_request(descriptor, &key);
        (Self::for_recorded_key(&key_string, limits), request)
    }

    /// A machine awaiting the server's response for an already-recorded
    /// client key (the java-oracle handshake exam seam: `server_response`
    /// cases carry the recorded key in `context.client_key`; an absent key
    /// is the empty string and rejects `not_matched` exactly as Java's
    /// missing-key path does).
    #[must_use]
    pub fn for_recorded_key(client_key: &str, limits: HandshakeLimits) -> Self {
        ClientHandshake {
            accumulator: HeadAccumulator::new(limits),
            client_key: client_key.to_string(),
            done: false,
        }
    }

    /// Feed one transport chunk of the server's response.
    pub fn consume(&mut self, chunk: &[u8]) -> ClientHandshakeOutcome {
        if self.done {
            return ClientHandshakeOutcome::NotAwaiting;
        }
        if let Err(refusal) = self.accumulator.push(chunk) {
            self.done = true;
            return ClientHandshakeOutcome::LimitExceeded(refusal);
        }
        match parse_java_head(self.accumulator.bytes()) {
            JavaHeadParse::Incomplete => ClientHandshakeOutcome::Incomplete,
            JavaHeadParse::Reject => {
                self.reject(RejectChannel::InvalidHandshake, RejectStage::Translate)
            }
            JavaHeadParse::Complete(head) => {
                // Draft.java:164-180: the status code is compared literally
                // against "101" BEFORE the HTTP version check.
                if head.first_line[1] != "101"
                    || !head.first_line[0].eq_ignore_ascii_case("HTTP/1.1")
                {
                    return self.reject(RejectChannel::InvalidHandshake, RejectStage::Translate);
                }
                // Draft.java:188-191 (basicAccept, quirk Q9).
                let upgrade_ok = head
                    .headers
                    .get("Upgrade")
                    .eq_ignore_ascii_case("websocket");
                let connection_ok = head
                    .headers
                    .get("Connection")
                    .to_ascii_lowercase()
                    .contains("upgrade");
                if !upgrade_ok || !connection_ok {
                    return self.reject(RejectChannel::NotMatched, RejectStage::AcceptPredicate);
                }
                // Draft_6455.java:312-325: key and accept must both exist and
                // the derived value must literally equal the response value.
                if self.client_key.is_empty() || !head.headers.has("Sec-WebSocket-Accept") {
                    return self.reject(RejectChannel::NotMatched, RejectStage::AcceptPredicate);
                }
                let expected = Draft6455::generate_accept_key(java_trim(&self.client_key));
                if expected != head.headers.get("Sec-WebSocket-Accept") {
                    return self.reject(RejectChannel::NotMatched, RejectStage::AcceptPredicate);
                }
                let remainder = self.accumulator.bytes()[head.head_len..].to_vec();
                self.done = true;
                ClientHandshakeOutcome::Accept {
                    remainder,
                    sec_websocket_accept: expected,
                }
            }
        }
    }

    fn reject(&mut self, channel: RejectChannel, stage: RejectStage) -> ClientHandshakeOutcome {
        self.done = true;
        ClientHandshakeOutcome::Reject { channel, stage }
    }
}

/// Render the canonical upgrade request (borrowed Codex layout — the exact
/// field set shipped Java's `ClientHandshakeBuilder` sends: request line,
/// Host, Upgrade, Connection, Sec-WebSocket-Key, Sec-WebSocket-Version).
fn canonical_request(descriptor: &ClientRequestDescriptor, key: &[u8; 24]) -> Vec<u8> {
    const GET: &[u8] = b"GET ";
    const HTTP_HOST: &[u8] = b" HTTP/1.1\r\nHost: ";
    const FIXED_AFTER_HOST: &[u8] =
        b"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ";
    const VERSION: &[u8] = b"\r\nSec-WebSocket-Version: 13\r\n\r\n";

    let mut request = Vec::with_capacity(
        GET.len()
            + descriptor.request_target.len()
            + HTTP_HOST.len()
            + descriptor.host.len()
            + FIXED_AFTER_HOST.len()
            + key.len()
            + VERSION.len(),
    );
    request.extend_from_slice(GET);
    request.extend_from_slice(descriptor.request_target.as_bytes());
    request.extend_from_slice(HTTP_HOST);
    request.extend_from_slice(descriptor.host.as_bytes());
    request.extend_from_slice(FIXED_AFTER_HOST);
    request.extend_from_slice(key);
    request.extend_from_slice(VERSION);
    request
}
