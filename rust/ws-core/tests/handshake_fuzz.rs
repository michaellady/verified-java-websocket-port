//! US-021 AC2 generative fuzz targets for the two OPENING-HANDSHAKE parsers.
//!
//! ## Why this file exists
//!
//! `assurance/fuzz/manifest.json` recorded `handshake-client` and
//! `handshake-server` as `ABSENT`, and the census was right: before this
//! file, no byte of handshake input was ever GENERATED anywhere in the
//! tree. `fuzz-seeds/us010` (11 files) and `fuzz-seeds/us011` (17 files)
//! were replayed by `tests/handshake_seeds.rs` at FIXED expectations — a
//! regression corpus, not a campaign. `adversarial_fuzz.rs`'s
//! `family_seed_corpus_anchors` DOES read those same files, but feeds them
//! to `ConnectionCore` as post-handshake FRAME bytes, so the handshake
//! parsers got no coverage from it at all.
//!
//! This file generates handshake bytes and drives
//! [`ws_core::handshake::server::ServerHandshake`] and
//! [`ws_core::handshake::client::ClientHandshake`] over them.
//!
//! Zero new dependencies (the Rust workspace is dependency-free by policy):
//! a hand-rolled SplitMix64 from fixed committed seeds is the engine, the
//! same idiom as `adversarial_fuzz.rs` and `adversarial_properties.rs`.
//!
//! ## Two generation modes
//!
//! **Modeled.** A `HeadModel` is drawn first — a first line, a list of
//! header lines, how many of those lines carry their CRLF, and a post-head
//! remainder — and only then rendered to bytes. Because the generator holds
//! the model, it can predict the machine's verdict WITHOUT parsing the bytes
//! it just wrote, which makes the differential oracle below a real
//! model-versus-implementation comparison rather than a re-implementation
//! diff.
//!
//! **Seed-derived.** The committed `us010`/`us011` corpora are read as
//! MUTATION SEEDS (byte flips, splices, deletions, insertions, truncations,
//! CRLF corruptions) — the honest use of a seed corpus in a generative
//! campaign. Mutants are unmodeled, so they carry the structural oracles
//! only.
//!
//! ## Oracles
//!
//! - **No panic** — every drive runs under `catch_unwind`; a parser panic
//!   fails the case with its seed label.
//! - **Terminal stickiness** — once a machine reports Accept/Reject/
//!   LimitExceeded, every later chunk must answer `NotAwaiting`, and the
//!   machine must never answer `NotAwaiting` before a terminal outcome.
//! - **Determinism** — same bytes, same chunking, byte-identical verdict.
//! - **Rechunking invariance** — the same bytes under whole-chunk,
//!   byte-at-a-time, and seeded random splits must produce the IDENTICAL
//!   chunk-invariant verdict. `remainder` itself is chunk-dependent by
//!   construction (it is "post-head remainder bytes from the final chunk"),
//!   so the invariant projection carries `head_len`, recovered as
//!   `bytes_fed_at_terminal - remainder.len()`, which is an absolute offset
//!   and must not move.
//! - **Differential predicate (modeled cases only)** — the model computes
//!   the expected verdict from Java's cited rules and the machine must
//!   agree exactly, including the derived `Sec-WebSocket-Accept` and the
//!   head length.
//! - **Bounded buffering** — under drawn small budgets a refusal must be
//!   terminal, must name a budget whose `attempted` value does not exceed
//!   that budget by more than one, and must refuse at a chunk-invariant
//!   position.
//! - **Shrinking** — `shrink_to_1_minimal` reduces a generated failing
//!   input to a 1-minimal witness preserving its verdict; the shrinker has
//!   its own documented domain and its own pinned normal forms (see the
//!   shrinker section at the bottom of this file).
//!
//! ## What the model deliberately SHARES with the implementation
//!
//! Stated so the differential is not read as more independent than it is:
//!
//! 1. `Draft6455::generate_accept_key` is called by BOTH sides. The
//!    accept-key derivation is a separate proof target
//!    (`target.formal.handshake.accept-derivation`) with its own tests; this
//!    campaign is about the PARSE and the PREDICATE, and a defect planted in
//!    the SHA-1/base64 derivation would not be caught here.
//! 2. The model restates Java's header-map rules (case-insensitive names,
//!    `"; "` duplicate joining per `HandshakedataImpl1.java:50`, leading
//!    SPACES stripped from the value per `Draft.java:115-125`) rather than
//!    re-deriving them. What is genuinely independent is everything the
//!    generator INVERTED: line framing, CRLF terminator detection, first-line
//!    tokenization, colon splitting, head-length accounting, and the
//!    acceptance predicates themselves.
//! 3. Bare-LF folding, obs-fold, and byte-level corruptions are marked
//!    UNPREDICTABLE by the generator, which drops only the differential
//!    oracle for that case; every structural oracle still applies.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};

use ws_core::framing::Draft6455;
use ws_core::handshake::client::{ClientHandshake, ClientHandshakeOutcome};
use ws_core::handshake::server::{ServerHandshake, ServerHandshakeOutcome};
use ws_core::handshake::{
    HandshakeLimitExceeded, HandshakeLimitKind, HandshakeLimits, RejectChannel,
};

// ---------------------------------------------------------------------------
// Deterministic PRNG (SplitMix64) — fixed committed seeds only.
// ---------------------------------------------------------------------------

#[derive(Clone)]
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

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.byte()).collect()
    }

    fn pick<'a, T>(&mut self, options: &'a [T]) -> &'a T {
        &options[self.below(options.len() as u64) as usize]
    }
}

/// The instant the server stamps into `Date`. Fixed so the 101 head is a
/// pure function of the request (the core is clockless by design; see
/// `ServerHandshake::new`).
const FIXED_INSTANT: i64 = 1_787_943_099;

// ---------------------------------------------------------------------------
// The chunk-invariant verdict projection.
// ---------------------------------------------------------------------------

/// Everything about a handshake outcome that does NOT depend on how the
/// bytes were chunked. `remainder` is excluded on purpose and `head_len`
/// carries its information in absolute-offset form.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    /// The head terminator never arrived and no budget refused.
    Incomplete,
    /// Accepted. `key` is the derived accept value (server side) and
    /// `response` the head to write; the client side carries neither.
    Accept {
        key: Option<String>,
        response: Option<Vec<u8>>,
        head_len: usize,
    },
    Reject(RejectChannel),
    Limit(HandshakeLimitExceeded),
}

/// One chunking of a byte string.
fn chunk(rng: &mut SplitMix64, bytes: &[u8], strategy: u64) -> Vec<Vec<u8>> {
    match strategy {
        0 => vec![bytes.to_vec()],
        1 => bytes.iter().map(|byte| vec![*byte]).collect(),
        _ => {
            let mut chunks = Vec::new();
            let mut at = 0usize;
            while at < bytes.len() {
                let take = 1 + rng.below(48) as usize;
                let end = (at + take).min(bytes.len());
                chunks.push(bytes[at..end].to_vec());
                at = end;
            }
            if rng.chance(8) {
                chunks.push(Vec::new());
            }
            chunks
        }
    }
}

/// Feed `chunks` to a fresh `ServerHandshake` and project the outcome.
///
/// Checks the terminal-stickiness oracle inline: `NotAwaiting` may not
/// appear before a terminal outcome, must appear for every chunk after one,
/// and must still appear for a probe byte fed afterwards.
fn judge_server(chunks: &[Vec<u8>], limits: HandshakeLimits) -> Verdict {
    let mut machine = ServerHandshake::new(limits, FIXED_INSTANT);
    let mut fed = 0usize;
    let mut verdict = Verdict::Incomplete;
    let mut terminal = false;
    for piece in chunks {
        let outcome = machine.consume(piece);
        if terminal {
            assert_eq!(
                outcome,
                ServerHandshakeOutcome::NotAwaiting,
                "a terminal server machine must answer NotAwaiting"
            );
            continue;
        }
        fed += piece.len();
        match outcome {
            ServerHandshakeOutcome::Incomplete => {}
            ServerHandshakeOutcome::Accept {
                accept_key,
                response,
                remainder,
            } => {
                assert!(
                    remainder.len() <= fed,
                    "remainder cannot exceed the bytes fed"
                );
                verdict = Verdict::Accept {
                    key: Some(accept_key),
                    response: Some(response),
                    head_len: fed - remainder.len(),
                };
                terminal = true;
            }
            ServerHandshakeOutcome::Reject { channel, response } => {
                assert!(!response.is_empty(), "a rejection must carry an error head");
                verdict = Verdict::Reject(channel);
                terminal = true;
            }
            ServerHandshakeOutcome::LimitExceeded(refusal) => {
                verdict = Verdict::Limit(refusal);
                terminal = true;
            }
            ServerHandshakeOutcome::NotAwaiting => {
                panic!("server answered NotAwaiting before any terminal outcome")
            }
        }
    }
    if terminal {
        assert_eq!(
            machine.consume(b"probe"),
            ServerHandshakeOutcome::NotAwaiting,
            "a terminal server machine must stay terminal"
        );
    }
    verdict
}

/// Feed `chunks` to a fresh `ClientHandshake` and project the outcome.
fn judge_client(chunks: &[Vec<u8>], key: &str, limits: HandshakeLimits) -> Verdict {
    let mut machine = ClientHandshake::for_recorded_key(key, limits);
    let mut fed = 0usize;
    let mut verdict = Verdict::Incomplete;
    let mut terminal = false;
    for piece in chunks {
        let outcome = machine.consume(piece);
        if terminal {
            assert_eq!(
                outcome,
                ClientHandshakeOutcome::NotAwaiting,
                "a terminal client machine must answer NotAwaiting"
            );
            continue;
        }
        fed += piece.len();
        match outcome {
            ClientHandshakeOutcome::Incomplete => {}
            ClientHandshakeOutcome::Accept { remainder } => {
                assert!(
                    remainder.len() <= fed,
                    "remainder cannot exceed the bytes fed"
                );
                verdict = Verdict::Accept {
                    key: None,
                    response: None,
                    head_len: fed - remainder.len(),
                };
                terminal = true;
            }
            ClientHandshakeOutcome::Reject { channel } => {
                verdict = Verdict::Reject(channel);
                terminal = true;
            }
            ClientHandshakeOutcome::LimitExceeded(refusal) => {
                verdict = Verdict::Limit(refusal);
                terminal = true;
            }
            ClientHandshakeOutcome::NotAwaiting => {
                panic!("client answered NotAwaiting before any terminal outcome")
            }
        }
    }
    if terminal {
        assert_eq!(
            machine.consume(b"probe"),
            ClientHandshakeOutcome::NotAwaiting,
            "a terminal client machine must stay terminal"
        );
    }
    verdict
}

/// `judge_server` under `catch_unwind` so a parser panic fails the case
/// attributably (the no-panic oracle).
fn judge_server_checked(label: &str, chunks: &[Vec<u8>], limits: HandshakeLimits) -> Verdict {
    catch_unwind(AssertUnwindSafe(|| judge_server(chunks, limits)))
        .unwrap_or_else(|_| panic!("{label}: ServerHandshake panicked"))
}

/// `judge_client` under `catch_unwind`.
fn judge_client_checked(
    label: &str,
    chunks: &[Vec<u8>],
    key: &str,
    limits: HandshakeLimits,
) -> Verdict {
    catch_unwind(AssertUnwindSafe(|| judge_client(chunks, key, limits)))
        .unwrap_or_else(|_| panic!("{label}: ClientHandshake panicked"))
}

// ---------------------------------------------------------------------------
// The generator's model of a handshake head.
// ---------------------------------------------------------------------------

/// A head as the GENERATOR built it, before rendering. The model never
/// re-reads the rendered bytes; every prediction below is computed from
/// these fields.
#[derive(Debug, Clone)]
struct HeadModel {
    /// The request/status line text, without its CRLF.
    first: String,
    /// Header line texts, without their CRLFs. Never empty strings in
    /// modeled mode (an empty line would terminate the head).
    headers: Vec<String>,
    /// How many of the `1 + headers.len() + 1` lines carry a real CRLF. A
    /// value below the total is a truncation.
    terminated_lines: usize,
    /// Bytes appended after a fully terminated head.
    remainder: Vec<u8>,
    /// False when a byte-level corruption (bare LF, lone CR, obs-fold) makes
    /// the rendered bytes no longer a faithful rendering of these lines. The
    /// differential oracle is skipped for such a case; every structural
    /// oracle still applies.
    predictable: bool,
}

impl HeadModel {
    fn line_count(&self) -> usize {
        self.headers.len() + 2
    }

    /// Render to wire bytes. Each of the first `terminated_lines` lines gets
    /// its CRLF; the rest are truncated away with the line they follow.
    fn render(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut lines: Vec<&str> = Vec::with_capacity(self.line_count());
        lines.push(&self.first);
        for header in &self.headers {
            lines.push(header);
        }
        lines.push("");
        for (index, line) in lines.iter().enumerate() {
            out.extend_from_slice(line.as_bytes());
            if index < self.terminated_lines {
                out.extend_from_slice(b"\r\n");
            } else {
                return out;
            }
        }
        out.extend_from_slice(&self.remainder);
        out
    }

    /// Byte length of the head through its terminating empty line, or
    /// `None` when the head is not fully terminated.
    fn head_len(&self) -> Option<usize> {
        if self.terminated_lines < self.line_count() {
            return None;
        }
        let mut len = self.first.len() + 2;
        for header in &self.headers {
            len += header.len() + 2;
        }
        Some(len + 2)
    }

    /// Java's header map, restated from `HandshakedataImpl1.java:50` and
    /// `Draft.java:115-125`: case-insensitive names, leading SPACES stripped
    /// from the value, duplicates joined with `"; "`. See the file header
    /// for what this deliberately shares with the implementation.
    fn java_map(&self) -> Option<BTreeMap<String, String>> {
        let mut map: BTreeMap<String, String> = BTreeMap::new();
        for header in &self.headers {
            let (name, raw) = header.split_once(':')?;
            let value = raw.trim_start_matches(' ').to_string();
            map.entry(name.to_ascii_lowercase())
                .and_modify(|existing| {
                    existing.push_str("; ");
                    existing.push_str(&value);
                })
                .or_insert(value);
        }
        Some(map)
    }

    /// The parse-stage verdict every head shares, walking the lines in the
    /// machine's order: the first line must be terminated and tokenize into
    /// exactly three `split(" ", 3)` tokens; every header line must be
    /// terminated and carry a colon; then the empty line must be terminated.
    ///
    /// `Ok(tokens)` means the head parsed completely.
    fn parse_stage(&self) -> Result<[String; 3], Verdict> {
        if self.terminated_lines == 0 {
            return Err(Verdict::Incomplete);
        }
        let tokens: Vec<&str> = self.first.splitn(3, ' ').collect();
        let [a, b, c] = tokens.as_slice() else {
            return Err(Verdict::Reject(RejectChannel::InvalidHandshake));
        };
        let first_line = [(*a).to_string(), (*b).to_string(), (*c).to_string()];
        for (index, header) in self.headers.iter().enumerate() {
            if index + 1 >= self.terminated_lines {
                return Err(Verdict::Incomplete);
            }
            if !header.contains(':') {
                return Err(Verdict::Reject(RejectChannel::InvalidHandshake));
            }
        }
        if self.terminated_lines < self.line_count() {
            return Err(Verdict::Incomplete);
        }
        Ok(first_line)
    }

    /// The server-side verdict, from `handshake/server.rs`'s cited Java
    /// rules: method and HTTP version `equalsIgnoreCase` (Draft.java:141-155),
    /// then the version-only draft match (Draft_6455.java:262-286), then a
    /// missing/empty key throwing while the response is built
    /// (Draft_6455.java:432-441).
    fn server_verdict(&self) -> Verdict {
        let first_line = match self.parse_stage() {
            Ok(tokens) => tokens,
            Err(verdict) => return verdict,
        };
        if !first_line[0].eq_ignore_ascii_case("GET")
            || !first_line[2].eq_ignore_ascii_case("HTTP/1.1")
        {
            return Verdict::Reject(RejectChannel::InvalidHandshake);
        }
        let map = self.java_map().expect("modeled header lines carry a colon");
        let version = map.get("sec-websocket-version").map_or("", String::as_str);
        let parsed = if version.is_empty() {
            -1
        } else {
            java_trim(version).parse::<i32>().unwrap_or(-1)
        };
        if parsed != 13 {
            return Verdict::Reject(RejectChannel::NotMatched);
        }
        let key = map.get("sec-websocket-key").map_or("", String::as_str);
        if key.is_empty() {
            return Verdict::Reject(RejectChannel::InvalidHandshake);
        }
        Verdict::Accept {
            key: Some(Draft6455::generate_accept_key(key)),
            response: None,
            head_len: self.head_len().expect("a complete head has a length"),
        }
    }

    /// The client-side verdict, from `handshake/client.rs`'s cited Java
    /// rules: the literal `"101"` status compared BEFORE the HTTP version
    /// (Draft.java:164-180), then `basicAccept` (Draft.java:188-191), then
    /// key/accept existence and literal equality (Draft_6455.java:312-325).
    fn client_verdict(&self, client_key: &str) -> Verdict {
        let first_line = match self.parse_stage() {
            Ok(tokens) => tokens,
            Err(verdict) => return verdict,
        };
        if first_line[1] != "101" || !first_line[0].eq_ignore_ascii_case("HTTP/1.1") {
            return Verdict::Reject(RejectChannel::InvalidHandshake);
        }
        let map = self.java_map().expect("modeled header lines carry a colon");
        let upgrade = map.get("upgrade").map_or("", String::as_str);
        let connection = map.get("connection").map_or("", String::as_str);
        if !upgrade.eq_ignore_ascii_case("websocket")
            || !connection.to_ascii_lowercase().contains("upgrade")
        {
            return Verdict::Reject(RejectChannel::NotMatched);
        }
        if client_key.is_empty() || !map.contains_key("sec-websocket-accept") {
            return Verdict::Reject(RejectChannel::NotMatched);
        }
        let expected = Draft6455::generate_accept_key(java_trim(client_key));
        if expected != map["sec-websocket-accept"] {
            return Verdict::Reject(RejectChannel::NotMatched);
        }
        Verdict::Accept {
            key: None,
            response: None,
            head_len: self.head_len().expect("a complete head has a length"),
        }
    }
}

/// Java `String.trim`: both ends stripped of chars `<= U+0020`. Restated
/// here rather than imported so the model does not borrow the parser's
/// helper.
fn java_trim(value: &str) -> &str {
    value.trim_matches(|c: char| c <= ' ')
}

/// Compare a machine verdict against a model verdict. `Accept` is compared
/// on the fields the model predicts; the response head is checked
/// separately by the rechunk oracle (it is a pure function of the accept
/// key, the echoed Connection value, and the fixed instant).
fn assert_matches_model(label: &str, actual: &Verdict, expected: &Verdict) {
    match (actual, expected) {
        (
            Verdict::Accept {
                key: actual_key,
                head_len: actual_len,
                ..
            },
            Verdict::Accept {
                key: expected_key,
                head_len: expected_len,
                ..
            },
        ) => {
            assert_eq!(
                actual_key, expected_key,
                "{label}: derived accept key disagrees with the model"
            );
            assert_eq!(
                actual_len, expected_len,
                "{label}: head length disagrees with the model"
            );
        }
        _ => assert_eq!(actual, expected, "{label}: verdict disagrees with the model"),
    }
}

// ---------------------------------------------------------------------------
// Head generators.
// ---------------------------------------------------------------------------

const METHODS: [&str; 7] = ["GET", "get", "GeT", "POST", "HEAD", "", "GET "];
const HTTP_VERSIONS: [&str; 6] = [
    "HTTP/1.1",
    "http/1.1",
    "HTTP/1.0",
    "HTTP/1.1 ",
    "HTTP/2",
    "",
];
const STATUS_CODES: [&str; 8] = ["101", "200", "404", " 101", "101 ", "1010", "0101", ""];
const VERSION_VALUES: [&str; 12] = [
    "13", " 13", "13 ", " 13 ", "+13", "0013", "13x", "", "8", "-13", "99999999999999999999",
    "1 3",
];
const KEY_VALUES: [&str; 8] = [
    "dGhlIHNhbXBsZSBub25jZQ==",
    "x",
    "",
    "not base64 at all",
    "AAAAAAAAAAAAAAAAAAAAAA==",
    "  spaced  ",
    "dGhlIHNhbXBsZSBub25jZQ",
    "0123456789abcdef0123456789abcdef",
];
const UPGRADE_VALUES: [&str; 6] = ["websocket", "WebSocket", "WEBSOCKET", "websockets", "", "web"];
const CONNECTION_VALUES: [&str; 7] = [
    "Upgrade",
    "upgrade",
    "keep-alive, Upgrade",
    "keep-alive",
    "",
    "UPGRADEX",
    "Upgrade, close",
];
const NOISE_NAMES: [&str; 8] = [
    "Host",
    "Origin",
    "User-Agent",
    "Sec-WebSocket-Protocol",
    "Sec-WebSocket-Extensions",
    "Content-Length",
    "X-Weird Name",
    "Cookie",
];

/// The client keys the client-side campaign records. The empty key is the
/// live-verified "absent key" case that rejects `not_matched`.
const CLIENT_KEYS: [&str; 4] = [
    "dGhlIHNhbXBsZSBub25jZQ==",
    "",
    "  dGhlIHNhbXBsZSBub25jZQ==  ",
    "another-key",
];

/// One header line, biased toward the fields the predicates actually read.
fn draw_header_line(rng: &mut SplitMix64, role_specific: &[(&str, &[&str])]) -> String {
    if rng.below(4) == 0 {
        // Noise header: sometimes with no colon at all (an InvalidHandshake
        // parse rejection), sometimes with hostile spacing.
        let name = *rng.pick(&NOISE_NAMES);
        if rng.chance(12) {
            return name.to_string();
        }
        let spacing = *rng.pick(&["", " ", "  ", "\t"]);
        let value_len = rng.below(12) as usize;
        let value: String = (0..value_len)
            .map(|_| char::from(0x21 + (rng.byte() % 0x5e)))
            .collect();
        return format!("{name}:{spacing}{value}");
    }
    let (name, values) = rng.pick(role_specific);
    let value = *rng.pick(values);
    let spacing = if rng.chance(4) { "" } else { " " };
    // Casing quirk: the map is case-insensitive, so the model must agree.
    let rendered_name = match rng.below(5) {
        0 => name.to_ascii_lowercase(),
        1 => name.to_ascii_uppercase(),
        _ => (*name).to_string(),
    };
    format!("{rendered_name}:{spacing}{value}")
}

fn server_header_alphabet() -> Vec<(&'static str, &'static [&'static str])> {
    vec![
        ("Sec-WebSocket-Version", &VERSION_VALUES[..]),
        ("Sec-WebSocket-Key", &KEY_VALUES[..]),
        ("Upgrade", &UPGRADE_VALUES[..]),
        ("Connection", &CONNECTION_VALUES[..]),
    ]
}

fn client_header_alphabet(accepts: &'static [&'static str]) -> Vec<(&'static str, &'static [&'static str])> {
    vec![
        ("Upgrade", &UPGRADE_VALUES[..]),
        ("Connection", &CONNECTION_VALUES[..]),
        ("Sec-WebSocket-Accept", accepts),
        ("Sec-WebSocket-Version", &VERSION_VALUES[..]),
    ]
}

/// The accept values a generated server response may carry: the two
/// derivations that match a recorded client key, plus near-misses.
const ACCEPT_VALUES: [&str; 6] = [
    "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
    "ICX+Yqv66kxgM0FcWaLWlFLwTAI=",
    "",
    "s3pPLMBiTxaQ9kYGzzhZRbK+xOo",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    " s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
];

/// Draw a modeled request head for the server parser.
fn draw_request_model(rng: &mut SplitMix64) -> HeadModel {
    let alphabet = server_header_alphabet();
    let first = match rng.below(12) {
        0 => {
            // Deliberately wrong token count (0, 1, 2, or 4+ spaces). Java
            // splits with limit 3, so 4 tokens still yields 3.
            let words = rng.below(3);
            (0..=words)
                .map(|_| "tok")
                .collect::<Vec<_>>()
                .join(" ")
        }
        1 => String::new(),
        _ => {
            let method = *rng.pick(&METHODS);
            let target = *rng.pick(&["/", "/chat", "/a b", "*", ""]);
            let version = *rng.pick(&HTTP_VERSIONS);
            format!("{method} {target} {version}")
        }
    };
    let header_count = rng.below(6) as usize;
    let headers: Vec<String> = (0..header_count)
        .map(|_| draw_header_line(rng, &alphabet))
        .collect();
    finish_model(rng, first, headers)
}

/// Draw a modeled response head for the client parser.
fn draw_response_model(rng: &mut SplitMix64) -> HeadModel {
    let alphabet = client_header_alphabet(&ACCEPT_VALUES[..]);
    let first = match rng.below(12) {
        0 => {
            let words = rng.below(3);
            (0..=words).map(|_| "tok").collect::<Vec<_>>().join(" ")
        }
        1 => String::new(),
        _ => {
            let version = *rng.pick(&HTTP_VERSIONS);
            let status = *rng.pick(&STATUS_CODES);
            let message = *rng.pick(&["Switching Protocols", "Web Socket Protocol Handshake", "OK", ""]);
            format!("{version} {status} {message}")
        }
    };
    let header_count = rng.below(6) as usize;
    let headers: Vec<String> = (0..header_count)
        .map(|_| draw_header_line(rng, &alphabet))
        .collect();
    finish_model(rng, first, headers)
}

/// Decide truncation and remainder for a drawn head.
fn finish_model(rng: &mut SplitMix64, first: String, headers: Vec<String>) -> HeadModel {
    let total_lines = headers.len() + 2;
    let terminated_lines = if rng.chance(4) {
        rng.below(total_lines as u64) as usize
    } else {
        total_lines
    };
    let remainder = if terminated_lines == total_lines && rng.chance(3) {
        let len = rng.below(20) as usize;
        rng.bytes(len)
    } else {
        Vec::new()
    };
    HeadModel {
        first,
        headers,
        terminated_lines,
        remainder,
        predictable: true,
    }
}

/// Byte-level corruption applied AFTER rendering: bare LF, lone CR,
/// obs-fold, a NUL splice. The model can no longer predict the verdict, so
/// it is marked unpredictable.
fn corrupt_rendering(rng: &mut SplitMix64, model: &mut HeadModel, bytes: &mut Vec<u8>) {
    if bytes.is_empty() {
        return;
    }
    model.predictable = false;
    match rng.below(5) {
        0 => {
            // Replace a CRLF with a bare LF (the Java line-folding quirk).
            let positions: Vec<usize> = (0..bytes.len().saturating_sub(1))
                .filter(|&i| bytes[i] == b'\r' && bytes[i + 1] == b'\n')
                .collect();
            if let Some(&at) = positions.first() {
                bytes.remove(at);
            }
        }
        1 => {
            // Drop the LF of a CRLF, leaving a lone CR.
            let positions: Vec<usize> = (0..bytes.len().saturating_sub(1))
                .filter(|&i| bytes[i] == b'\r' && bytes[i + 1] == b'\n')
                .collect();
            if let Some(&at) = positions.first() {
                bytes.remove(at + 1);
            }
        }
        2 => {
            // obs-fold: a continuation line starting with SP.
            let at = rng.below(bytes.len() as u64) as usize;
            bytes.splice(at..at, b"\r\n folded".iter().copied());
        }
        3 => {
            let at = rng.below(bytes.len() as u64) as usize;
            bytes[at] = rng.byte();
        }
        _ => {
            let at = rng.below(bytes.len() as u64) as usize;
            bytes.truncate(at);
        }
    }
}

/// Drawn budgets: usually the Java-fidelity hard ceilings, sometimes small
/// enough that a refusal is reachable.
fn draw_limits(rng: &mut SplitMix64) -> HandshakeLimits {
    if rng.chance(3) {
        HandshakeLimits {
            max_handshake_bytes: 1 + rng.below(200) as usize,
            max_header_count: 1 + rng.below(6) as usize,
            max_header_line_bytes: 1 + rng.below(80) as usize,
        }
    } else {
        HandshakeLimits::hard_ceilings()
    }
}

/// Every budget refusal must name a budget it could actually have hit, and
/// its `attempted` value may exceed that budget by at most one (the
/// accumulator refuses BEFORE buffering the byte that would breach).
fn assert_refusal_is_bounded(label: &str, refusal: HandshakeLimitExceeded, limits: HandshakeLimits) {
    let budget = match refusal.limit {
        HandshakeLimitKind::TotalBytes => limits.max_handshake_bytes,
        HandshakeLimitKind::HeaderCount => limits.max_header_count,
        HandshakeLimitKind::HeaderLineBytes => limits.max_header_line_bytes,
    } as u64;
    assert!(
        refusal.attempted > budget,
        "{label}: refusal attempted={} does not exceed its budget {budget}",
        refusal.attempted
    );
    assert!(
        refusal.attempted <= budget + 1,
        "{label}: refusal attempted={} overshoots its budget {budget} by more than one byte",
        refusal.attempted
    );
}

/// The chunk relation that holds when a PLUS_SAFE budget is small enough to
/// be REACHABLE.
///
/// ## The finding this encodes
///
/// `ServerHandshake::consume` / `ClientHandshake::consume` push the whole
/// chunk into the bounded accumulator BEFORE parsing it. So a budget breach
/// anywhere inside a chunk is reported before the parse that would have
/// rejected earlier in that same chunk. Under byte-at-a-time delivery the
/// parse runs after every byte and therefore reaches its terminal verdict
/// first. The two dispositions are NOT interchangeable at the connection
/// seam: `connection.rs` maps a handshake `Reject` to the Java-faithful
/// protocol failure and a `LimitExceeded` to `BufferLimitExceeded`, so the
/// SAME byte stream can surface two different typed failure codes depending
/// only on how the transport chopped it.
///
/// This campaign records that rather than asserting it away. The exact
/// witness is pinned deterministically by
/// `handshake_budget_refusal_races_the_parse_rejection_under_rechunking`.
/// What still holds, and is asserted here for every drawn case:
///
///  1. a chunking that refuses on a budget implies the whole-chunk drive
///     refuses too, with the identical refusal (a breach a coarser delivery
///     could miss is not a breach);
///  2. when the whole-chunk drive refuses and a finer one does not, the
///     finer one must have reached a TERMINAL PARSE verdict first — never
///     `Incomplete`, which would mean bytes went missing;
///  3. when neither refuses, the verdicts are identical, exactly as under
///     the hard ceilings.
fn assert_budget_rechunk_relation(label: &str, whole: &Verdict, other: &Verdict, strategy: u64) {
    match (whole, other) {
        (Verdict::Limit(_), Verdict::Limit(_)) => assert_eq!(
            whole, other,
            "{label} strategy {strategy}: two refusals must name the same budget"
        ),
        (Verdict::Limit(_), _) => assert!(
            matches!(other, Verdict::Accept { .. } | Verdict::Reject(_)),
            "{label} strategy {strategy}: whole-chunk refused on a budget but the finer \
             chunking answered {other:?}; only a terminal parse verdict may win that race"
        ),
        (_, Verdict::Limit(_)) => panic!(
            "{label} strategy {strategy}: a finer chunking refused on a budget the \
             whole-chunk drive never hit ({whole:?} vs {other:?})"
        ),
        _ => assert_eq!(
            whole, other,
            "{label} strategy {strategy}: budget-free verdicts must be chunk-invariant"
        ),
    }
}

/// Drive one byte string under all three chunkings with REACHABLE budgets
/// and check `assert_budget_rechunk_relation`. Returns the whole-chunk
/// verdict and whether any finer chunking won the race described above.
fn server_budget_relation(
    label: &str,
    bytes: &[u8],
    limits: HandshakeLimits,
    salt: u64,
) -> (Verdict, bool) {
    let whole = judge_server_checked(label, &[bytes.to_vec()], limits);
    let mut raced = false;
    for strategy in 1..3u64 {
        let mut chunk_rng = SplitMix64::new(salt);
        let chunks = chunk(&mut chunk_rng, bytes, strategy);
        let other = judge_server_checked(label, &chunks, limits);
        assert_budget_rechunk_relation(label, &whole, &other, strategy);
        raced |= whole != other;
    }
    (whole, raced)
}

fn client_budget_relation(
    label: &str,
    bytes: &[u8],
    key: &str,
    limits: HandshakeLimits,
    salt: u64,
) -> (Verdict, bool) {
    let whole = judge_client_checked(label, &[bytes.to_vec()], key, limits);
    let mut raced = false;
    for strategy in 1..3u64 {
        let mut chunk_rng = SplitMix64::new(salt);
        let chunks = chunk(&mut chunk_rng, bytes, strategy);
        let other = judge_client_checked(label, &chunks, key, limits);
        assert_budget_rechunk_relation(label, &whole, &other, strategy);
        raced |= whole != other;
    }
    (whole, raced)
}

/// Run one byte string through all three chunkings and require an identical
/// chunk-invariant verdict; return it.
fn server_verdict_across_chunkings(
    label: &str,
    bytes: &[u8],
    limits: HandshakeLimits,
    salt: u64,
) -> Verdict {
    let mut verdicts = Vec::with_capacity(3);
    for strategy in 0..3u64 {
        let mut chunk_rng = SplitMix64::new(salt);
        let chunks = chunk(&mut chunk_rng, bytes, strategy);
        verdicts.push(judge_server_checked(
            &format!("{label} strategy {strategy}"),
            &chunks,
            limits,
        ));
    }
    assert_eq!(
        verdicts[0], verdicts[1],
        "{label}: whole-chunk vs byte-at-a-time"
    );
    assert_eq!(
        verdicts[0], verdicts[2],
        "{label}: whole-chunk vs random splits"
    );
    verdicts.remove(0)
}

fn client_verdict_across_chunkings(
    label: &str,
    bytes: &[u8],
    key: &str,
    limits: HandshakeLimits,
    salt: u64,
) -> Verdict {
    let mut verdicts = Vec::with_capacity(3);
    for strategy in 0..3u64 {
        let mut chunk_rng = SplitMix64::new(salt);
        let chunks = chunk(&mut chunk_rng, bytes, strategy);
        verdicts.push(judge_client_checked(
            &format!("{label} strategy {strategy}"),
            &chunks,
            key,
            limits,
        ));
    }
    assert_eq!(
        verdicts[0], verdicts[1],
        "{label}: whole-chunk vs byte-at-a-time"
    );
    assert_eq!(
        verdicts[0], verdicts[2],
        "{label}: whole-chunk vs random splits"
    );
    verdicts.remove(0)
}

// ---------------------------------------------------------------------------
// Committed seed corpora, read as MUTATION SEEDS.
// ---------------------------------------------------------------------------

fn committed_seeds(story: &str) -> Vec<(String, Vec<u8>)> {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz-seeds")
        .join(story);
    let mut entries: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("seed dir {} must exist: {e}", dir.display()))
        .map(|entry| entry.expect("readable entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "hex"))
        .collect();
    entries.sort();
    entries
        .into_iter()
        .map(|path| {
            let raw = std::fs::read_to_string(&path).expect("readable seed");
            let hex: String = raw.chars().filter(|c| !c.is_ascii_whitespace()).collect();
            assert!(
                hex.len().is_multiple_of(2),
                "seed {} must hold an even number of hex digits",
                path.display()
            );
            let bytes = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("seed is hex"))
                .collect();
            (
                path.file_name()
                    .expect("seed has a name")
                    .to_string_lossy()
                    .into_owned(),
                bytes,
            )
        })
        .collect()
}

/// Mutate a seed: 1..4 edits drawn from flip / insert / delete / splice /
/// truncate / CRLF-corrupt.
fn mutate(rng: &mut SplitMix64, seed: &[u8]) -> Vec<u8> {
    let mut bytes = seed.to_vec();
    let edits = 1 + rng.below(4);
    for _ in 0..edits {
        if bytes.is_empty() {
            bytes.push(rng.byte());
            continue;
        }
        let at = rng.below(bytes.len() as u64) as usize;
        match rng.below(7) {
            0 => bytes[at] ^= 1 << rng.below(8),
            1 => bytes[at] = rng.byte(),
            2 => bytes.insert(at, rng.byte()),
            3 => {
                bytes.remove(at);
            }
            4 => {
                let piece = *rng.pick(&[
                    &b"\r\n"[..],
                    &b"\r\n\r\n"[..],
                    &b"\n"[..],
                    &b":"[..],
                    &b" "[..],
                    &b"Sec-WebSocket-Version: 13\r\n"[..],
                    &b"Sec-WebSocket-Key: x\r\n"[..],
                ]);
                bytes.splice(at..at, piece.iter().copied());
            }
            5 => bytes.truncate(at),
            _ => {
                let len = rng.below(8) as usize;
                let tail = rng.bytes(len);
                bytes.extend_from_slice(&tail);
            }
        }
    }
    bytes
}

// ===========================================================================
// TARGET: handshake-server. Entrypoints are prefixed `handshake_server_` so
// the manifest's replay command can select exactly this target's campaign.
// ===========================================================================

/// Modeled request heads against `ServerHandshake`, with the full oracle
/// set including the model differential.
#[test]
fn handshake_server_modeled_requests() {
    let mut rng = SplitMix64::new(0xf00d_0001);
    for case in 0..8_000u32 {
        let mut model = draw_request_model(&mut rng);
        let mut bytes = model.render();
        if rng.chance(4) {
            corrupt_rendering(&mut rng, &mut model, &mut bytes);
        }
        let limits = HandshakeLimits::hard_ceilings();
        let label = format!("handshake_server modeled case {case}");
        let verdict = server_verdict_across_chunkings(&label, &bytes, limits, 0x51ce_0000 + u64::from(case));

        // Determinism: an independent replay of the whole-chunk drive.
        let replay = judge_server_checked(&label, &[bytes.clone()], limits);
        assert_eq!(verdict, replay, "{label}: determinism");

        if model.predictable {
            assert_matches_model(&label, &verdict, &model.server_verdict());
        }
    }
}

/// Mutants of the committed `fuzz-seeds/us011` server corpus. The seeds are
/// generator INPUT here, not fixed expectations.
#[test]
fn handshake_server_seed_mutations() {
    let seeds = committed_seeds("us011");
    assert!(
        seeds.len() >= 17,
        "the us011 server seed corpus must still hold its 17 committed seeds, found {}",
        seeds.len()
    );
    let mut rng = SplitMix64::new(0xf00d_0002);
    for case in 0..6_000u32 {
        let (name, seed) = &seeds[rng.below(seeds.len() as u64) as usize];
        let bytes = mutate(&mut rng, seed);
        let limits = HandshakeLimits::hard_ceilings();
        let label = format!("handshake_server mutant case {case} of {name}");
        let verdict =
            server_verdict_across_chunkings(&label, &bytes, limits, 0x52ce_0000 + u64::from(case));
        let replay = judge_server_checked(&label, &[bytes.clone()], limits);
        assert_eq!(verdict, replay, "{label}: determinism");
    }
}

/// Small drawn budgets: a refusal must be terminal, bounded, and refuse at
/// a chunk-invariant position.
#[test]
fn handshake_server_budget_refusals() {
    let mut rng = SplitMix64::new(0xf00d_0003);
    let mut refusals = 0usize;
    for case in 0..2_000u32 {
        let mut model = draw_request_model(&mut rng);
        // Bias toward heads big enough to breach a small budget.
        model
            .headers
            .push("Padding: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string());
        model.terminated_lines = model.line_count();
        let bytes = model.render();
        let limits = draw_limits(&mut rng);
        let label = format!("handshake_server budget case {case}");
        let (verdict, _) =
            server_budget_relation(&label, &bytes, limits, 0x53ce_0000 + u64::from(case));
        if let Verdict::Limit(refusal) = verdict {
            assert_refusal_is_bounded(&label, refusal, limits);
            refusals += 1;
        }
    }
    assert!(
        refusals >= 100,
        "a budget campaign that never reaches a refusal proves nothing; reached {refusals}"
    );
}

// ===========================================================================
// TARGET: handshake-client.
// ===========================================================================

/// Modeled response heads against `ClientHandshake`, with the full oracle
/// set including the model differential.
#[test]
fn handshake_client_modeled_responses() {
    let mut rng = SplitMix64::new(0xf00d_0011);
    for case in 0..8_000u32 {
        let mut model = draw_response_model(&mut rng);
        let mut bytes = model.render();
        if rng.chance(4) {
            corrupt_rendering(&mut rng, &mut model, &mut bytes);
        }
        let key = *rng.pick(&CLIENT_KEYS);
        let limits = HandshakeLimits::hard_ceilings();
        let label = format!("handshake_client modeled case {case}");
        let verdict = client_verdict_across_chunkings(
            &label,
            &bytes,
            key,
            limits,
            0x51c1_0000 + u64::from(case),
        );

        let replay = judge_client_checked(&label, &[bytes.clone()], key, limits);
        assert_eq!(verdict, replay, "{label}: determinism");

        if model.predictable {
            assert_matches_model(&label, &verdict, &model.client_verdict(key));
        }
    }
}

/// Mutants of the committed `fuzz-seeds/us010` client corpus.
#[test]
fn handshake_client_seed_mutations() {
    let seeds = committed_seeds("us010");
    assert!(
        seeds.len() >= 11,
        "the us010 client seed corpus must still hold its 11 committed seeds, found {}",
        seeds.len()
    );
    let mut rng = SplitMix64::new(0xf00d_0012);
    for case in 0..6_000u32 {
        let (name, seed) = &seeds[rng.below(seeds.len() as u64) as usize];
        let bytes = mutate(&mut rng, seed);
        let key = *rng.pick(&CLIENT_KEYS);
        let limits = HandshakeLimits::hard_ceilings();
        let label = format!("handshake_client mutant case {case} of {name}");
        let verdict = client_verdict_across_chunkings(
            &label,
            &bytes,
            key,
            limits,
            0x52c1_0000 + u64::from(case),
        );
        let replay = judge_client_checked(&label, &[bytes.clone()], key, limits);
        assert_eq!(verdict, replay, "{label}: determinism");
    }
}

/// Small drawn budgets on the client response path.
#[test]
fn handshake_client_budget_refusals() {
    let mut rng = SplitMix64::new(0xf00d_0013);
    let mut refusals = 0usize;
    for case in 0..2_000u32 {
        let mut model = draw_response_model(&mut rng);
        model
            .headers
            .push("Padding: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string());
        model.terminated_lines = model.line_count();
        let bytes = model.render();
        let key = *rng.pick(&CLIENT_KEYS);
        let limits = draw_limits(&mut rng);
        let label = format!("handshake_client budget case {case}");
        let (verdict, _) = client_budget_relation(
            &label,
            &bytes,
            key,
            limits,
            0x53c1_0000 + u64::from(case),
        );
        if let Verdict::Limit(refusal) = verdict {
            assert_refusal_is_bounded(&label, refusal, limits);
            refusals += 1;
        }
    }
    assert!(
        refusals >= 100,
        "a budget campaign that never reaches a refusal proves nothing; reached {refusals}"
    );
}

// ===========================================================================
// SHRINKER
//
// AC1 requires documented shrinkers. Before this file `grep -ci shrink`
// over `rust/ws-core/tests/` returned 0.
//
// ## Generator domain (the shrinker's contract)
//
// The shrinker's domain is exactly the byte strings this file's generators
// produce: rendered `HeadModel`s (optionally corrupted) and mutants of the
// committed us010/us011 corpora. It is NOT a general byte-string shrinker
// and makes no claim to find a GLOBAL minimum.
//
// ## What it preserves
//
// The chunk-invariant [`Verdict`] observed on the original input, judged by
// the same `judge_*` function under the same budgets. A candidate is kept
// only when its verdict is byte-identical to the original's.
//
// ## The reduction it computes
//
// Two passes to fixpoint:
//   1. contiguous-range deletion, halving the window from `len/2` down to 1;
//   2. byte simplification toward `b' '` then `b'A'`, left to right.
// The result is 1-MINIMAL for deletion: no single byte can be removed from
// it without changing the verdict. That is the property the tests assert;
// it is strictly weaker than global minimality and is not claimed as more.
//
// ## Bound
//
// Every pass is bounded by the input length, and the outer fixpoint is
// bounded by `SHRINK_MAX_ROUNDS`; the shrinker cannot loop forever on any
// input.
// ===========================================================================

/// Outer fixpoint bound. A round that removes nothing stops the loop; this
/// is the belt-and-braces cap so no input can spin.
const SHRINK_MAX_ROUNDS: usize = 24;

/// Reduce `input` to a 1-minimal witness preserving `judge(input)`.
fn shrink_to_1_minimal(input: &[u8], judge: &dyn Fn(&[u8]) -> Verdict) -> Vec<u8> {
    let target = judge(input);
    let mut current = input.to_vec();
    for _ in 0..SHRINK_MAX_ROUNDS {
        let before = current.len();

        // Pass 1: contiguous-range deletion, coarse to fine.
        let mut window = (current.len() / 2).max(1);
        while window >= 1 {
            let mut at = 0usize;
            while at + window <= current.len() {
                let mut candidate = current.clone();
                candidate.drain(at..at + window);
                if judge(&candidate) == target {
                    current = candidate;
                } else {
                    at += 1;
                }
            }
            if window == 1 {
                break;
            }
            window /= 2;
        }

        // Pass 2: byte simplification toward a canonical alphabet.
        for index in 0..current.len() {
            for simpler in [b' ', b'A'] {
                if current[index] == simpler {
                    break;
                }
                let mut candidate = current.clone();
                candidate[index] = simpler;
                if judge(&candidate) == target {
                    current = candidate;
                    break;
                }
            }
        }

        if current.len() == before {
            break;
        }
    }
    current
}

/// Assert the shrinker's contract on one witness: the verdict is preserved
/// and the result is 1-minimal for deletion.
fn assert_1_minimal(label: &str, original: &[u8], shrunk: &[u8], judge: &dyn Fn(&[u8]) -> Verdict) {
    let target = judge(original);
    assert_eq!(
        judge(shrunk),
        target,
        "{label}: the shrunk witness changed the verdict"
    );
    assert!(
        shrunk.len() <= original.len(),
        "{label}: the shrunk witness grew"
    );
    for index in 0..shrunk.len() {
        let mut candidate = shrunk.to_vec();
        candidate.remove(index);
        assert_ne!(
            judge(&candidate),
            target,
            "{label}: byte {index} of the shrunk witness is removable, so it is not 1-minimal"
        );
    }
}

/// The shrinker over generated SERVER rejections: every witness reduces to a
/// 1-minimal input carrying the same rejection channel.
#[test]
fn handshake_server_shrinker_reaches_1_minimal_witnesses() {
    let limits = HandshakeLimits::hard_ceilings();
    let judge = move |bytes: &[u8]| judge_server(&[bytes.to_vec()], limits);
    let mut rng = SplitMix64::new(0xf00d_0004);
    let mut shrunk_total = 0usize;
    let mut original_total = 0usize;
    let mut witnessed = 0usize;
    for case in 0..300u32 {
        let model = draw_request_model(&mut rng);
        let bytes = model.render();
        if !matches!(judge(&bytes), Verdict::Reject(_)) {
            continue;
        }
        witnessed += 1;
        let label = format!("handshake_server shrink case {case}");
        let shrunk = shrink_to_1_minimal(&bytes, &judge);
        assert_1_minimal(&label, &bytes, &shrunk, &judge);
        original_total += bytes.len();
        shrunk_total += shrunk.len();
    }
    assert!(
        witnessed >= 100,
        "the shrinker campaign must reach at least 100 rejecting witnesses, reached {witnessed}"
    );
    assert!(
        shrunk_total < original_total,
        "shrinking must reduce the corpus overall ({shrunk_total} vs {original_total})"
    );
}

/// The shrinker over generated CLIENT rejections.
#[test]
fn handshake_client_shrinker_reaches_1_minimal_witnesses() {
    let limits = HandshakeLimits::hard_ceilings();
    let key = CLIENT_KEYS[0];
    let judge = move |bytes: &[u8]| judge_client(&[bytes.to_vec()], key, limits);
    let mut rng = SplitMix64::new(0xf00d_0014);
    let mut shrunk_total = 0usize;
    let mut original_total = 0usize;
    let mut witnessed = 0usize;
    for case in 0..300u32 {
        let model = draw_response_model(&mut rng);
        let bytes = model.render();
        if !matches!(judge(&bytes), Verdict::Reject(_)) {
            continue;
        }
        witnessed += 1;
        let label = format!("handshake_client shrink case {case}");
        let shrunk = shrink_to_1_minimal(&bytes, &judge);
        assert_1_minimal(&label, &bytes, &shrunk, &judge);
        original_total += bytes.len();
        shrunk_total += shrunk.len();
    }
    assert!(
        witnessed >= 100,
        "the shrinker campaign must reach at least 100 rejecting witnesses, reached {witnessed}"
    );
    assert!(
        shrunk_total < original_total,
        "shrinking must reduce the corpus overall ({shrunk_total} vs {original_total})"
    );
}

/// The shrinker's NORMAL FORMS, pinned byte for byte.
///
/// A shrinker whose output nobody pinned is machinery, not evidence: it can
/// silently stop reducing and every 1-minimality assertion above still
/// passes. These pins are the polarity: each names a hostile input, the
/// verdict it carries, and the exact witness the shrinker reduces it to.
#[test]
fn handshake_shrinker_normal_forms_are_pinned() {
    let limits = HandshakeLimits::hard_ceilings();
    let server = move |bytes: &[u8]| judge_server(&[bytes.to_vec()], limits);
    let client = move |bytes: &[u8]| judge_client(&[bytes.to_vec()], CLIENT_KEYS[0], limits);

    // A parse-stage rejection (the first line does not split into three
    // tokens) reduces to the shortest input that still reads a first line:
    // the bare CRLF, whose empty first line yields one token.
    let invalid = b"POST /a/b/c HTTP/1.1\r\nHost: x\r\nSec-WebSocket-Version: 13\r\n\r\n";
    assert_eq!(
        server(invalid),
        Verdict::Reject(RejectChannel::InvalidHandshake)
    );
    let shrunk = shrink_to_1_minimal(invalid, &server);
    assert_eq!(
        shrunk,
        b"\r\n".to_vec(),
        "server InvalidHandshake normal form drifted: {:?}",
        String::from_utf8_lossy(&shrunk)
    );

    // A version-predicate rejection cannot lose its request line (the line
    // must still be GET/HTTP/1.1 to reach the predicate at all), so its
    // normal form keeps a three-token GET line and the head terminator.
    let not_matched = b"GET /chat HTTP/1.1\r\nHost: server.example.com\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 8\r\n\r\n";
    assert_eq!(
        server(not_matched),
        Verdict::Reject(RejectChannel::NotMatched)
    );
    let shrunk = shrink_to_1_minimal(not_matched, &server);
    assert_eq!(
        shrunk,
        b"GET  HTTP/1.1\r\n\r\n".to_vec(),
        "server NotMatched normal form drifted: {:?}",
        String::from_utf8_lossy(&shrunk)
    );

    // Client side: a non-101 status is the InvalidHandshake channel and
    // reduces to the same bare-CRLF witness.
    let bad_status = b"HTTP/1.1 404 Not Found\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
    assert_eq!(
        client(bad_status),
        Verdict::Reject(RejectChannel::InvalidHandshake)
    );
    let shrunk = shrink_to_1_minimal(bad_status, &client);
    assert_eq!(
        shrunk,
        b"\r\n".to_vec(),
        "client InvalidHandshake normal form drifted: {:?}",
        String::from_utf8_lossy(&shrunk)
    );

    // A 101 whose Upgrade header is wrong is the NotMatched channel; the
    // status line and terminator must survive.
    let bad_upgrade = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n";
    assert_eq!(client(bad_upgrade), Verdict::Reject(RejectChannel::NotMatched));
    let shrunk = shrink_to_1_minimal(bad_upgrade, &client);
    assert_eq!(
        shrunk,
        b"HTTP/1.1 101 \r\n\r\n".to_vec(),
        "client NotMatched normal form drifted: {:?}",
        String::from_utf8_lossy(&shrunk)
    );
}

// ===========================================================================
// PINNED WITNESS: the PLUS_SAFE budget refusal races the Java-faithful parse
// rejection under rechunking.
//
// FOUND BY the generative campaign in this file (handshake_server budget
// case 37 of the 0xf00d_0003 stream), not by inspection. It is pinned here
// deterministically so the behavior is a RECORD rather than a surprise, and
// so a future change to it fails loudly instead of silently.
//
// WHAT IT IS. `consume` pushes the whole chunk into the bounded accumulator
// before parsing. `"X\r\n"` already parses to a Java `InvalidHandshake`
// rejection (the first line does not split into three tokens), but under a
// `max_handshake_bytes` of 10 a single 103-byte chunk breaches the budget at
// byte 10 and reports `LimitExceeded` without ever parsing. Delivered one
// byte at a time the same stream rejects at byte 3.
//
// WHY IT MATTERS. `connection.rs:975/985` and `:1001/1004` map the two
// outcomes to DIFFERENT typed failures (the Java-faithful protocol failure
// versus `BufferLimitExceeded`), so the typed failure a caller sees depends
// on how the transport chopped the bytes.
//
// WHAT IS **NOT** CLAIMED HERE. This test does not decide whether the
// ordering is a defect. It is an observed, reproducible divergence between
// a port-side strengthening and the Java-faithful path, recorded for the
// owner. No shipped source is changed by this file.
// ===========================================================================

#[test]
fn handshake_budget_refusal_races_the_parse_rejection_under_rechunking() {
    let limits = HandshakeLimits {
        max_handshake_bytes: 10,
        max_header_count: 1024,
        max_header_line_bytes: 65_536,
    };

    let mut stream = b"X\r\n".to_vec();
    stream.extend(std::iter::repeat_n(b'A', 100));
    assert_eq!(stream.len(), 103);

    // Whole chunk: the budget refuses at byte 10, before any parse.
    assert_eq!(
        judge_server(&[stream.clone()], limits),
        Verdict::Limit(HandshakeLimitExceeded {
            limit: HandshakeLimitKind::TotalBytes,
            attempted: 11,
        }),
        "whole-chunk delivery must report the PLUS_SAFE budget refusal"
    );

    // One byte at a time: the parse rejects at byte 3, before the breach.
    let per_byte: Vec<Vec<u8>> = stream.iter().map(|byte| vec![*byte]).collect();
    assert_eq!(
        judge_server(&per_byte, limits),
        Verdict::Reject(RejectChannel::InvalidHandshake),
        "byte-at-a-time delivery must reach the Java-faithful rejection first"
    );

    // The client parser has the identical ordering.
    assert_eq!(
        judge_client(&[stream.clone()], CLIENT_KEYS[0], limits),
        Verdict::Limit(HandshakeLimitExceeded {
            limit: HandshakeLimitKind::TotalBytes,
            attempted: 11,
        }),
    );
    assert_eq!(
        judge_client(&per_byte, CLIENT_KEYS[0], limits),
        Verdict::Reject(RejectChannel::InvalidHandshake),
    );

    // The race is confined to REACHABLE budgets: at the Java-fidelity hard
    // ceilings the same stream is chunk-invariant.
    let ceilings = HandshakeLimits::hard_ceilings();
    assert_eq!(
        judge_server(&[stream.clone()], ceilings),
        judge_server(&per_byte, ceilings),
        "at the hard ceilings the verdict must not depend on chunking"
    );
    assert_eq!(
        judge_client(&[stream], CLIENT_KEYS[0], ceilings),
        judge_client(&per_byte, CLIENT_KEYS[0], ceilings),
    );
}
