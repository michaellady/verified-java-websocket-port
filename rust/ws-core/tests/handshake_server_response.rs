//! DIV-06: the SERVER's 101 response head, field by field, against shipped
//! Java-WebSocket 1.6.0.
//!
//! ## What authority these expectations carry
//!
//! Every expectation in this file is a **source citation into the pinned
//! Java tree**, corroborated by an **offline computation over the pinned
//! `Java-WebSocket-1.6.0.jar`**. Neither is a live socket observation: no
//! Java server was started, and this repository's `java-oracle` is a JSONL
//! request/response oracle that never opens a server socket.
//!
//! The citation
//! (`.quarantine/Java-WebSocket-da3cf2a777aed862f2f5b5cf060cae7969958667/`,
//! archive `sha256:f44e7647b4aee40819b51947cf0bb5f35a48293a202b77704c3c79e98ed13cb4`):
//!
//! - `src/main/java/org/java_websocket/drafts/Draft_6455.java:431-452`
//!   (`postProcessHandshakeResponseAsServer`) writes FIVE fields on the
//!   default configuration, not three:
//!   `Upgrade: websocket` (:434), `Connection: <the REQUEST's Connection
//!   value>` (:435-436), `Sec-WebSocket-Accept: generateFinalKey(seckey)`
//!   (:441), `Server: TooTallNate Java-WebSocket` (:449) and
//!   `Date: getServerTime()` (:450). It also sets the status message
//!   `Web Socket Protocol Handshake` (:448), which is the status LINE, not
//!   a field. `Sec-WebSocket-Extensions` (:442-444) and
//!   `Sec-WebSocket-Protocol` (:445-447) are conditional and both empty
//!   under `DefaultExtension` (`extensions/DefaultExtension.java:76-78`
//!   returns `""`) and the default protocol, so neither reaches the wire.
//! - `src/main/java/org/java_websocket/handshake/HandshakedataImpl1.java:50`
//!   stores fields in `new TreeMap<>(String.CASE_INSENSITIVE_ORDER)`;
//!   `:55-57` iterates that key set, and
//!   `src/main/java/org/java_websocket/drafts/Draft.java:275-283` writes the
//!   fields in exactly that iteration order. So the WIRE ORDER is
//!   case-insensitive alphabetical, NOT insertion order:
//!   `Connection, Date, Sec-WebSocket-Accept, Server, Upgrade`.
//! - The response's field NAMES are Java's own constants
//!   (`Draft_6455.java:96-106`), so a lowercase `connection:` in the request
//!   still produces `Connection:` in the response.
//!
//! The offline computation drives the same three library calls
//! `WebSocketImpl.java:300-301` makes — `Draft.translateHandshakeHttp`,
//! `postProcessHandshakeResponseAsServer`, `createHandshake` — on the pinned
//! jar under the pinned JDK 17.0.19+10 and prints the resulting bytes. Its
//! source and full transcript are in
//! `drafts/self-review/div06-handshake-response-round-1.md`. For the exact
//! request the Autobahn suite sent in the recorded native run it reproduces
//! `Sec-WebSocket-Accept: Hq135RN2s62Ig7vP5+0RjcM2Ies=`, the same value the
//! recorded run's `httpResponse` carries
//! (`evidence/autobahn/native-x86_64-provenance/java/fuzzingclient-run1/cases/verified_java_websocket_port_1_6_0_case_10_1_1.json`),
//! which is what binds this offline computation to the one socket
//! observation that exists.

use ws_core::handshake::HandshakeLimits;
use ws_core::handshake::server::{ServerHandshake, ServerHandshakeOutcome, java_server_time};

/// A fixed instant for every byte-exact expectation. `Date` is a clock read
/// in Java (`Draft_6455.java:818-824` calls `Calendar.getInstance()`), so it
/// is NOT byte-reproducible from a fixed input; the port formats an instant
/// its owner supplies, and these tests supply one. The liveness of the real
/// clock is a separate check, in `ws-testee`.
///
/// This particular instant is the one that produces
/// `Fri, 28 Aug 2026 18:51:39 GMT` — a `Date` value the recorded native
/// Autobahn run actually observed on the wire from the pinned Java server.
const PINNED_INSTANT: i64 = 1_787_943_099;
const PINNED_DATE: &str = "Fri, 28 Aug 2026 18:51:39 GMT";

fn machine() -> ServerHandshake {
    ServerHandshake::new(HandshakeLimits::hard_ceilings(), PINNED_INSTANT)
}

fn response_head(raw: &[u8]) -> String {
    match machine().consume(raw) {
        ServerHandshakeOutcome::Accept { response, .. } => {
            String::from_utf8(response).expect("the 101 head is ASCII")
        }
        other => panic!("expected accept, got {other:?}"),
    }
}

/// The field names the port put on the wire, in wire order.
fn field_names(head: &str) -> Vec<String> {
    head.split("\r\n")
        .skip(1) // the status line
        .filter(|line| !line.is_empty())
        .map(|line| {
            line.split_once(':')
                .map_or_else(|| line.to_string(), |(name, _)| name.to_string())
        })
        .collect()
}

/// The request the Autobahn suite sent in the recorded native run, byte for
/// byte (`…/java/fuzzingclient-run1/cases/…case_10_1_1.json`, `httpRequest`).
const AUTOBAHN_REQUEST: &[u8] = b"GET / HTTP/1.1\r\nUser-Agent: AutobahnTestSuite/25.10.1-0.10.9\r\nHost: 127.0.0.1:9011\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\nPragma: no-cache\r\nCache-Control: no-cache\r\nSec-WebSocket-Key: wNqPo2hgNAiH5vgtqN4dtg==\r\nSec-WebSocket-Version: 13\r\n\r\n";

/// The RFC 6455 sample key with a plain `Connection: Upgrade`.
const RFC_SAMPLE_REQUEST: &[u8] = b"GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";

// ---------------------------------------------------------------------------
// The five fields, and the order they go out in
// ---------------------------------------------------------------------------

/// DIV-06's core claim. `postProcessHandshakeResponseAsServer` writes five
/// fields (Draft_6455.java:434, :435-436, :441, :449, :450) and the
/// `HandshakedataImpl1` TreeMap (HandshakedataImpl1.java:50) sorts them
/// case-insensitively before `Draft.createHandshake` (Draft.java:275-283)
/// writes them out.
#[test]
fn the_101_response_carries_javas_five_field_names_in_javas_order() {
    let expected = [
        "Connection",
        "Date",
        "Sec-WebSocket-Accept",
        "Server",
        "Upgrade",
    ];
    for (label, request) in [
        ("the recorded Autobahn request", AUTOBAHN_REQUEST),
        ("the RFC 6455 sample request", RFC_SAMPLE_REQUEST),
    ] {
        let head = response_head(request);
        let names = field_names(&head);
        assert_eq!(
            names, expected,
            "DIV-06 ({label}): shipped Java's 101 response carries {expected:?} \
             — five fields sorted by String.CASE_INSENSITIVE_ORDER \
             (Draft_6455.java:431-452 writes them, HandshakedataImpl1.java:50 \
             sorts them, Draft.java:275-283 writes them out). The port \
             produced {names:?}. Missing/extra/misordered fields are the \
             divergence."
        );
    }
}

/// The whole head, byte for byte, against what the pinned jar produced
/// offline for the same request at the same instant.
#[test]
fn the_101_response_is_byte_exact_against_the_pinned_jars_own_output() {
    assert_eq!(
        response_head(AUTOBAHN_REQUEST),
        format!(
            "HTTP/1.1 101 Web Socket Protocol Handshake\r\n\
             Connection: Upgrade\r\n\
             Date: {PINNED_DATE}\r\n\
             Sec-WebSocket-Accept: Hq135RN2s62Ig7vP5+0RjcM2Ies=\r\n\
             Server: TooTallNate Java-WebSocket\r\n\
             Upgrade: websocket\r\n\r\n"
        ),
        "DIV-06: the port's 101 head must equal, byte for byte, what the \
         pinned Java-WebSocket 1.6.0 jar produced offline for this exact \
         request at this exact instant."
    );
    assert_eq!(
        response_head(RFC_SAMPLE_REQUEST),
        format!(
            "HTTP/1.1 101 Web Socket Protocol Handshake\r\n\
             Connection: Upgrade\r\n\
             Date: {PINNED_DATE}\r\n\
             Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
             Server: TooTallNate Java-WebSocket\r\n\
             Upgrade: websocket\r\n\r\n"
        )
    );
}

/// The two literal values Java hard-codes.
#[test]
fn the_server_field_carries_javas_literal_and_upgrade_is_lowercase() {
    let head = response_head(RFC_SAMPLE_REQUEST);
    assert!(
        head.contains("Server: TooTallNate Java-WebSocket\r\n"),
        "DIV-06: Draft_6455.java:449 writes the literal \
         `Server: TooTallNate Java-WebSocket`; the port wrote: {head:?}"
    );
    // Draft_6455.java:434 writes lowercase "websocket" regardless of how the
    // request spelled its own Upgrade value ("WebSocket" above).
    assert!(
        head.contains("Upgrade: websocket\r\n"),
        "Draft_6455.java:434 writes the literal lowercase `websocket`; \
         the port wrote: {head:?}"
    );
}

// ---------------------------------------------------------------------------
// The Connection ECHO -- the part of the method the recorded run could not see
// ---------------------------------------------------------------------------

/// `Draft_6455.java:435-436` is `response.put(CONNECTION,
/// request.getFieldValue(CONNECTION))` — the response's `Connection` value
/// is the REQUEST's, echoed, not a literal. The recorded Autobahn run cannot
/// distinguish an echo from a hard-coded `Upgrade`, because the suite always
/// sends exactly `Connection: Upgrade`. These are the inputs that separate
/// them, and each expectation is the pinned jar's own offline output.
#[test]
fn the_connection_field_echoes_the_requests_value_rather_than_a_literal() {
    // A value that is not "Upgrade" is echoed verbatim.
    let keep_alive = b"GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    let head = response_head(keep_alive);
    assert!(
        head.contains("Connection: keep-alive, Upgrade\r\n"),
        "Draft_6455.java:435-436 echoes the request's Connection value \
         (`// to respond to a Connection keep alives`); the pinned jar \
         answers this request with `Connection: keep-alive, Upgrade`. \
         The port wrote: {head:?}"
    );

    // Duplicated request headers join with "; " (Draft.java:120-125) BEFORE
    // the echo, so the joined string is what goes out.
    let duplicated = b"GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nConnection: close\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    let head = response_head(duplicated);
    assert!(
        head.contains("Connection: Upgrade; close\r\n"),
        "Draft.java:120-125 joins duplicate request fields with \"; \" and \
         Draft_6455.java:435-436 echoes the joined value; the pinned jar \
         answers with `Connection: Upgrade; close`. The port wrote: {head:?}"
    );

    // An ABSENT Connection header still produces the field, with an empty
    // value: HandshakedataImpl1.getFieldValue returns "" rather than null
    // (HandshakedataImpl1.java:59-65), and put("Connection", "") still
    // inserts the key.
    let absent = b"GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    let head = response_head(absent);
    assert!(
        head.contains("Connection: \r\n"),
        "HandshakedataImpl1.java:59-65 returns \"\" for an absent field, so \
         Java emits an EMPTY `Connection: ` rather than omitting it; the \
         pinned jar answers this request with `Connection: `. \
         The port wrote: {head:?}"
    );
    assert_eq!(
        field_names(&head).len(),
        5,
        "the field is present-but-empty, so the count stays 5: {head:?}"
    );
}

/// The response's field NAMES are Java's constants (Draft_6455.java:96-106),
/// so request casing never reaches the response head.
#[test]
fn response_field_names_are_javas_constants_not_the_requests_casing() {
    let lowercased = b"GET /chat HTTP/1.1\r\nHost: example.com\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    assert_eq!(
        response_head(lowercased),
        format!(
            "HTTP/1.1 101 Web Socket Protocol Handshake\r\n\
             Connection: Upgrade\r\n\
             Date: {PINNED_DATE}\r\n\
             Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
             Server: TooTallNate Java-WebSocket\r\n\
             Upgrade: websocket\r\n\r\n"
        ),
        "a lowercase request field name must not change the response's \
         field names: Draft_6455 puts its own constants"
    );
}

// ---------------------------------------------------------------------------
// The Date FORMAT -- deterministic given an instant, pinned against the jar
// ---------------------------------------------------------------------------

/// `getServerTime` (Draft_6455.java:818-824) is
/// `new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss z", Locale.US)` with
/// `TimeZone.getTimeZone("GMT")`. Every right-hand side below was PRINTED by
/// that expression running on the pinned JDK 17.0.19+10, not derived by
/// hand. The same table was produced under two different host default
/// timezones (`-Duser.timezone=UTC` and `-Duser.timezone=Asia/Kolkata`) and
/// came out identical, so the format depends on the instant alone.
#[test]
fn the_date_field_format_matches_the_pinned_jdks_simpledateformat() {
    let table: &[(i64, &str)] = &[
        (0, "Thu, 01 Jan 1970 00:00:00 GMT"),
        (1, "Thu, 01 Jan 1970 00:00:01 GMT"),
        (-1, "Wed, 31 Dec 1969 23:59:59 GMT"),
        (-86_400, "Wed, 31 Dec 1969 00:00:00 GMT"),
        (946_684_800, "Sat, 01 Jan 2000 00:00:00 GMT"),
        // 2000 and 2004 are leap years, 2100 is not.
        (951_782_400, "Tue, 29 Feb 2000 00:00:00 GMT"),
        (1_078_012_800, "Sun, 29 Feb 2004 00:00:00 GMT"),
        (1_000_000_000, "Sun, 09 Sep 2001 01:46:40 GMT"),
        (1_234_567_890, "Fri, 13 Feb 2009 23:31:30 GMT"),
        (1_583_020_799, "Sat, 29 Feb 2020 23:59:59 GMT"),
        (1_583_020_800, "Sun, 01 Mar 2020 00:00:00 GMT"),
        (1_583_107_200, "Mon, 02 Mar 2020 00:00:00 GMT"),
        (1_600_000_000, "Sun, 13 Sep 2020 12:26:40 GMT"),
        (1_735_689_600, "Wed, 01 Jan 2025 00:00:00 GMT"),
        (1_756_407_099, "Thu, 28 Aug 2025 18:51:39 GMT"),
        (1_767_225_599, "Wed, 31 Dec 2025 23:59:59 GMT"),
        // The two Date values the recorded native Autobahn run observed on
        // the wire from the pinned Java server.
        (1_787_943_099, "Fri, 28 Aug 2026 18:51:39 GMT"),
        (1_787_943_111, "Fri, 28 Aug 2026 18:51:51 GMT"),
        (2_147_483_647, "Tue, 19 Jan 2038 03:14:07 GMT"),
        (4_102_444_800, "Fri, 01 Jan 2100 00:00:00 GMT"),
        (4_294_967_295, "Sun, 07 Feb 2106 06:28:15 GMT"),
        (253_402_300_799, "Fri, 31 Dec 9999 23:59:59 GMT"),
    ];
    for &(epoch, expected) in table {
        assert_eq!(
            java_server_time(epoch),
            expected,
            "getServerTime (Draft_6455.java:818-824) on the pinned JDK \
             prints {expected:?} at epoch second {epoch}"
        );
    }
}

/// The formatter is total: no input panics, and every output has the shape
/// the pattern fixes. This is the guard on the domain the pinned table does
/// not enumerate.
#[test]
fn the_date_formatter_is_total_over_every_instant_it_can_be_handed() {
    for epoch in [
        i64::MIN,
        i64::MAX,
        i64::MIN + 1,
        i64::MAX - 1,
        -62_167_219_200,
    ] {
        let rendered = java_server_time(epoch);
        assert!(
            rendered.ends_with(" GMT"),
            "epoch {epoch} rendered {rendered:?}"
        );
    }
    // The shape SimpleDateFormat's pattern fixes, on an ordinary instant.
    let rendered = java_server_time(PINNED_INSTANT);
    assert_eq!(rendered.len(), 29, "{rendered:?}");
    assert_eq!(&rendered[3..5], ", ", "{rendered:?}");
}

// ---------------------------------------------------------------------------
// The response is still only written on ACCEPT
// ---------------------------------------------------------------------------

/// Java builds the response inside `postProcessHandshakeResponseAsServer`,
/// which throws before writing anything when the key is missing
/// (Draft_6455.java:437-440). A rejection must therefore carry neither
/// `Server` nor `Date`.
#[test]
fn a_rejected_handshake_still_writes_no_server_or_date_field() {
    let no_key = b"GET / HTTP/1.1\r\nSec-WebSocket-Version: 13\r\n\r\n";
    let ServerHandshakeOutcome::Reject { response, .. } = machine().consume(no_key) else {
        panic!("expected reject");
    };
    let head = String::from_utf8(response).expect("ASCII");
    assert!(!head.contains("Server:"), "{head:?}");
    assert!(!head.contains("Date:"), "{head:?}");
}
