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
//! 4. `postProcessHandshakeResponseAsServer` (Draft_6455.java:431-452)
//!    requires a non-empty `Sec-WebSocket-Key` (:437-440) and builds the
//!    WHOLE 101 response ([`accept_response`]). See that function for the
//!    field-by-field citation; the method writes FIVE fields, not three.

use super::http::{HeadAccumulator, JavaHeadParse, JavaHeaders, parse_java_head};
use super::{HandshakeLimitExceeded, HandshakeLimits, RejectChannel, RejectStage};
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
        /// The 101 response head to write: byte-identical to what shipped
        /// Java's `postProcessHandshakeResponseAsServer` +
        /// `Draft.createHandshake` produce for the same request at the
        /// instant this machine was given ([`accept_response`]). The `Date`
        /// value is a clock reading and so is NOT reproducible from the
        /// request alone; the instant is supplied by the owner at
        /// [`ServerHandshake::new`], which keeps this core clockless and
        /// every byte here a pure function of its inputs.
        response: Vec<u8>,
        /// Post-head remainder bytes from the final chunk (wire bytes for
        /// the frame layer).
        remainder: Vec<u8>,
    },
    /// The handshake was rejected. On the wire Java collapses every
    /// rejection to one observable: an HTTP error head plus a close with
    /// code 1002 ([`super::HANDSHAKE_REJECT_CLOSE_CODE`]).
    Reject {
        /// The draft-API channel.
        channel: RejectChannel,
        /// WHICH draft-API call decided (see [`RejectStage`]). `channel`
        /// alone conflates a `translateHandshake` refusal with a
        /// `postProcessHandshakeResponseAsServer` refusal; those differ in
        /// whether the application listener was ever reached.
        stage: RejectStage,
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
    server_date_epoch_seconds: i64,
}

impl ServerHandshake {
    /// A fresh machine with the given budgets (configured on the connection
    /// path; hard ceilings in the Java-fidelity exam posture) and the
    /// instant this server will stamp into the response's `Date` field.
    ///
    /// The instant is a PARAMETER, not a clock read, because this core is
    /// dependency-free and clockless by design (see `ws-core/Cargo.toml`):
    /// Java reads the wall clock inside `getServerTime`
    /// (Draft_6455.java:818-824), and the port confines that one read to its
    /// owner. The owner passes a Unix epoch second — the adapter reads the
    /// real clock per connection, exactly as Java does per handshake; a test
    /// passes a fixed instant and gets a byte-reproducible head.
    ///
    /// There is deliberately no clockless constructor: a default instant
    /// would emit a plausible-looking `Date` that no clock produced.
    #[must_use]
    pub fn new(limits: HandshakeLimits, server_date_epoch_seconds: i64) -> Self {
        ServerHandshake {
            accumulator: HeadAccumulator::new(limits),
            done: false,
            server_date_epoch_seconds,
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
            JavaHeadParse::Reject => {
                self.reject(RejectChannel::InvalidHandshake, RejectStage::Translate)
            }
            JavaHeadParse::Complete(head) => {
                // Draft.java:141-155: method and HTTP version, equalsIgnoreCase.
                if !head.first_line[0].eq_ignore_ascii_case("GET")
                    || !head.first_line[2].eq_ignore_ascii_case("HTTP/1.1")
                {
                    return self.reject(RejectChannel::InvalidHandshake, RejectStage::Translate);
                }
                // Draft_6455.java:262-286: version-only draft match.
                if Draft6455::accept_handshake_as_server(&head.headers)
                    == HandshakeState::NotMatched
                {
                    return self.reject(RejectChannel::NotMatched, RejectStage::AcceptPredicate);
                }
                // Draft_6455.java:432-441: a missing or empty key throws while
                // building the response; any non-empty key (base64 or not, any
                // length) is hashed as-is.
                let key = head.headers.get("Sec-WebSocket-Key").to_string();
                if key.is_empty() {
                    // The predicate MATCHED and shipped Java has already
                    // called onWebsocketHandshakeReceivedAsServer by here
                    // (WebSocketImpl.java:287-301); only response
                    // construction failed.
                    return self
                        .reject(RejectChannel::InvalidHandshake, RejectStage::ResponseBuild);
                }
                let accept_key = Draft6455::generate_accept_key(&key);
                // Draft_6455.java:435-436 echoes the REQUEST's Connection
                // value into the response; HandshakedataImpl1.getFieldValue
                // (HandshakedataImpl1.java:59-65) yields "" when the request
                // has no such field, which `JavaHeaders::get` matches.
                let connection = head.headers.get("Connection").to_string();
                let remainder = self.accumulator.bytes()[head.head_len..].to_vec();
                self.done = true;
                ServerHandshakeOutcome::Accept {
                    response: accept_response(
                        &accept_key,
                        &connection,
                        self.server_date_epoch_seconds,
                    ),
                    accept_key,
                    remainder,
                }
            }
        }
    }

    fn reject(&mut self, channel: RejectChannel, stage: RejectStage) -> ServerHandshakeOutcome {
        self.done = true;
        ServerHandshakeOutcome::Reject {
            channel,
            stage,
            response: REJECT_RESPONSE.to_vec(),
        }
    }
}

/// The 101 head, byte for byte as shipped Java writes it.
///
/// ## What `postProcessHandshakeResponseAsServer` actually does
///
/// `Draft_6455.java:431-452`. On the default configuration it writes FIVE
/// fields into a `HandshakeImpl1Server` that starts EMPTY
/// (`WebSocketAdapter.java:53-56` returns `new HandshakeImpl1Server()`):
///
/// | Java line | field | value |
/// |---|---|---|
/// | :434 | `Upgrade` | the literal `websocket` |
/// | :435-436 | `Connection` | **the REQUEST's `Connection` value, echoed** (`// to respond to a Connection keep alives`) |
/// | :441 | `Sec-WebSocket-Accept` | `generateFinalKey(seckey)` |
/// | :449 | `Server` | the literal `TooTallNate Java-WebSocket` |
/// | :450 | `Date` | `getServerTime()` — a clock read |
///
/// `:448` sets the status MESSAGE `Web Socket Protocol Handshake`, which
/// `Draft.java:270` renders into the status line, not into a field.
/// `:442-444` and `:445-447` add `Sec-WebSocket-Extensions` and
/// `Sec-WebSocket-Protocol` only when non-empty; under `DefaultExtension`
/// (`DefaultExtension.java:76-78` returns `""`) and the default protocol
/// both are empty, so neither reaches the wire. This port configures
/// neither, so this function reproduces the five-field case.
///
/// ## Why the order is not the order they are written in
///
/// `HandshakedataImpl1` stores fields in
/// `new TreeMap<>(String.CASE_INSENSITIVE_ORDER)`
/// (`HandshakedataImpl1.java:50`); `iterateHttpFields` (`:55-57`) walks that
/// key set and `Draft.createHandshake` (`Draft.java:275-283`) writes them in
/// exactly that order. So the wire order is case-insensitive alphabetical —
/// `Connection, Date, Sec-WebSocket-Accept, Server, Upgrade` — regardless of
/// insertion order. The field NAMES are Java's own constants
/// (`Draft_6455.java:96-106`), so the request's casing never reaches the
/// response.
///
/// ## The two arguments that are not constants
///
/// `connection` is the request's `Connection` value as `JavaHeaders::get`
/// returns it (leading spaces stripped, duplicates joined with `"; "`,
/// `""` when absent) — the same string `getFieldValue` would return. An
/// absent request `Connection` yields an EMPTY field, not a missing one:
/// `put("Connection", "")` still inserts the key.
///
/// `server_date_epoch_seconds` is the instant the owner supplies; see
/// [`java_server_time`].
fn accept_response(accept_key: &str, connection: &str, server_date_epoch_seconds: i64) -> Vec<u8> {
    let mut response = Vec::with_capacity(200);
    // Draft.java:270 -- "HTTP/1.1 101 " + getHttpStatusMessage(), the
    // message Draft_6455.java:448 set.
    response.extend_from_slice(b"HTTP/1.1 101 Web Socket Protocol Handshake\r\n");
    // The five fields, in String.CASE_INSENSITIVE_ORDER.
    response.extend_from_slice(b"Connection: ");
    response.extend_from_slice(connection.as_bytes());
    response.extend_from_slice(b"\r\nDate: ");
    response.extend_from_slice(java_server_time(server_date_epoch_seconds).as_bytes());
    response.extend_from_slice(b"\r\nSec-WebSocket-Accept: ");
    response.extend_from_slice(accept_key.as_bytes());
    response.extend_from_slice(b"\r\nServer: TooTallNate Java-WebSocket\r\n");
    response.extend_from_slice(b"Upgrade: websocket\r\n\r\n");
    response
}

/// `Draft_6455.getServerTime` (Draft_6455.java:818-824), as a pure function
/// of the instant:
///
/// ```java
/// Calendar calendar = Calendar.getInstance();
/// SimpleDateFormat dateFormat = new SimpleDateFormat(
///     "EEE, dd MMM yyyy HH:mm:ss z", Locale.US);
/// dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
/// return dateFormat.format(calendar.getTime());
/// ```
///
/// Java's one non-determinism here is `Calendar.getInstance()`, the wall
/// clock. Everything else is fixed: `Locale.US` pins the English `EEE` and
/// `MMM` abbreviations, and the explicit GMT zone makes `z` render the
/// literal `GMT` and the field independent of the host's default timezone
/// (verified: the pinned JDK printed an identical table under
/// `-Duser.timezone=UTC` and `-Duser.timezone=Asia/Kolkata`).
///
/// So this function takes the instant as a Unix epoch second and returns
/// exactly what the pinned JDK's `SimpleDateFormat` prints for it. The
/// expectations are pinned in `ws-core/tests/handshake_server_response.rs`
/// from that formatter's own output, not derived by hand.
///
/// ## Claimed domain
///
/// Byte-identical to the pinned JDK for every instant at or after the
/// Gregorian cutover, `1582-10-15T00:00:00Z` (epoch `-12_219_292_800`).
/// This is proleptic Gregorian; Java's `GregorianCalendar` switches to the
/// JULIAN calendar strictly before that instant, where the two disagree by
/// the historical 10-day gap (measured: the pinned JDK renders epoch
/// `-12_219_292_801` as `Thu, 04 Oct 1582 23:59:59 GMT`). No server clock
/// reaches that region, and reproducing a Julian branch nothing exercises
/// would be speculative code, so the gap is DISCLOSED rather than closed.
/// Outside the claimed domain the function is still total: every `i64`
/// returns a string and none panics.
#[must_use]
pub fn java_server_time(epoch_seconds: i64) -> String {
    // Floor division, so pre-epoch instants land on the right civil day.
    let days = epoch_seconds.div_euclid(SECONDS_PER_DAY);
    let second_of_day = epoch_seconds.rem_euclid(SECONDS_PER_DAY);
    let (year, month, day) = civil_from_days(days);

    // 1970-01-01 was a Thursday, index 4 in a Sunday-first week.
    const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    // Both indexes are in range by construction: rem_euclid(7) is 0..=6 and
    // civil_from_days returns month 1..=12.
    let weekday = WEEKDAYS[(days + 4).rem_euclid(7) as usize];
    let month_name = MONTHS[(month - 1) as usize];

    let hour = second_of_day / 3600;
    let minute = (second_of_day % 3600) / 60;
    let second = second_of_day % 60;

    // `yyyy` pads to at least four digits and never truncates (measured:
    // the pinned JDK prints `0001` and `10000`).
    format!("{weekday}, {day:02} {month_name} {year:04} {hour:02}:{minute:02}:{second:02} GMT")
}

const SECONDS_PER_DAY: i64 = 86_400;

/// Days since 1970-01-01 to a proleptic-Gregorian `(year, month, day)`.
/// Howard Hinnant's `civil_from_days`; total over `i64` (every intermediate
/// stays far inside the type: `|days|` is at most `i64::MAX / 86_400`).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    // Shift the era origin to 0000-03-01 so leap days land at the end.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097; // 0..=146_096
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365; // 0..=399
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100); // 0..=365
    let month_position = (5 * day_of_year + 2) / 153; // 0..=11, March-based
    let day = day_of_year - (153 * month_position + 2) / 5 + 1; // 1..=31
    let month = month_position + if month_position < 10 { 3 } else { -9 }; // 1..=12
    (year + i64::from(month <= 2), month, day)
}

/// The deterministic error head for the collapsed rejection observable
/// (Java answers wrong handshakes with an HTTP 404 error body before the
/// 1002 close; byte-exact fidelity is not claimed).
const REJECT_RESPONSE: &[u8] = b"HTTP/1.1 404 Not Found\r\n\r\n";
