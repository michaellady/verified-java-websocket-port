//! Budgeted incremental HTTP-head accumulation plus the Java-faithful head
//! parse shared by the client (US-010) and server (US-011) slices.
//!
//! Provenance: the incremental, budget-before-buffer accumulator design is
//! borrowed from the Codex plane (`connection-core/src/handshake/http.rs`,
//! `HeadAccumulator`, story trees `19f7067`/`b6d4b99`) and adapted; the
//! parse itself is a transcription of shipped Java-WebSocket 1.6.0 exactly
//! as pinned by the live-verified Go model
//! (`internal/corpora/handshake_live.go`, `javaReadLine` /
//! `javaParseHandshake`; Draft.java:70-132):
//!
//! - a line terminates ONLY on the exact CRLF pair — a bare LF or bare CR
//!   stays inside the line (Codex's byte-level `BareLineEnding` rejection is
//!   stripped: quirk basis, the HS_BARE_LF live divergence);
//! - the first line splits `split(" ", 3)` and must yield exactly 3 tokens;
//! - header lines split `split(":", 2)`; a line with no colon rejects
//!   (Java's only parse-level header rejection — this is also how obs-fold
//!   continuation lines reject); the value has LEADING SPACES ONLY stripped;
//!   the name is lower-cased un-trimmed (`HandshakedataImpl1`'s
//!   case-insensitive map); duplicates join with `"; "`;
//! - the head completes at the first empty line; anything after it is
//!   remainder (post-handshake wire bytes), untouched by the parse;
//! - a head whose terminating empty line (or first-line CRLF) has not
//!   arrived is `Incomplete` (IncompleteHandshakeException,
//!   Draft.java:100-102/128-130).
//!
//! Non-ASCII bytes are outside the calibrated live mapping (the Go model
//! fails closed on them); this parser treats each byte as one char
//! (Latin-1 projection) and claims fidelity only for ASCII input.
//!
//! Reject timing note (documented nonclaim): like the live-verified Go
//! model, predicate-level rejections (method, HTTP version, version != 13)
//! are evaluated only once the head is complete; real Java evaluates the
//! first-line checks as soon as the first line arrives. The 49-case live
//! corpus contains no input distinguishing the two (its partial inputs are
//! prefixes of valid requests), so the model's timing is the calibrated
//! authority.

use super::{HandshakeLimitExceeded, HandshakeLimitKind, HandshakeLimits};
use std::collections::BTreeMap;

/// Case-insensitive header map with Java's `"; "` duplicate joining
/// (HandshakedataImpl1.java:50, Draft.java:119-125). Keys are stored
/// lower-cased and un-trimmed, exactly as Java's case-insensitive `TreeMap`
/// resolves them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JavaHeaders {
    fields: BTreeMap<String, String>,
}

impl JavaHeaders {
    /// Java `put` semantics: join duplicates with `"; "`.
    fn put(&mut self, name_lower: String, value: String) {
        self.fields
            .entry(name_lower)
            .and_modify(|existing| {
                existing.push_str("; ");
                existing.push_str(&value);
            })
            .or_insert(value);
    }

    /// Case-insensitive field lookup (empty string when absent, mirroring
    /// Java's `getFieldValue` returning `""` for missing fields).
    #[must_use]
    pub fn get(&self, name: &str) -> &str {
        self.fields
            .get(&name.to_ascii_lowercase())
            .map_or("", String::as_str)
    }

    /// Case-insensitive presence check (`hasFieldValue`).
    #[must_use]
    pub fn has(&self, name: &str) -> bool {
        self.fields.contains_key(&name.to_ascii_lowercase())
    }
}

/// A completely parsed handshake head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaHead {
    /// The exactly-three first-line tokens (`split(" ", 3)`).
    pub first_line: [String; 3],
    /// The parsed header fields.
    pub headers: JavaHeaders,
    /// Byte length of the head including its terminating empty line; bytes
    /// past this offset are post-handshake remainder.
    pub head_len: usize,
}

/// Outcome of parsing the accumulated buffer with Java's semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JavaHeadParse {
    /// The head's terminator has not arrived; keep buffering
    /// (IncompleteHandshakeException path).
    Incomplete,
    /// A parse-level rejection (first line not exactly 3 tokens, or a
    /// header line with no colon) — Java's `InvalidHandshakeException`
    /// channel.
    Reject,
    /// The head parsed completely.
    Complete(JavaHead),
}

/// Java `String.trim` over the Latin-1 projection: both ends stripped of
/// chars `<= U+0020` (mirrors `javaTrim` in the Go model).
#[must_use]
pub fn java_trim(value: &str) -> &str {
    value.trim_matches(|c: char| c <= ' ')
}

/// `Draft.readLine` (Draft.java:70-88): the next line terminated by the
/// exact CRLF pair, starting at `at`. Returns the line's byte range end
/// (exclusive of CRLF) and the offset after the CRLF, or `None` when no
/// terminator has arrived.
fn java_read_line(buffer: &[u8], at: usize) -> Option<(usize, usize)> {
    let mut index = at + 1;
    while index < buffer.len() {
        if buffer[index - 1] == b'\r' && buffer[index] == b'\n' {
            return Some((index - 1, index + 1));
        }
        index += 1;
    }
    None
}

/// Latin-1 projection of a byte slice (byte == char; ASCII-faithful).
fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| char::from(b)).collect()
}

/// Parse the accumulated buffer with shipped Java's exact semantics
/// (`javaParseHandshake`, Go model; Draft.java:95-132).
#[must_use]
pub fn parse_java_head(buffer: &[u8]) -> JavaHeadParse {
    let Some((first_end, mut at)) = java_read_line(buffer, 0) else {
        return JavaHeadParse::Incomplete;
    };
    let first = latin1(&buffer[..first_end]);
    // Draft.java:104-107: line.split(" ", 3) must yield exactly 3 tokens.
    let tokens: Vec<&str> = first.splitn(3, ' ').collect();
    let [method, second, third] = tokens.as_slice() else {
        return JavaHeadParse::Reject;
    };
    let first_line = [
        (*method).to_string(),
        (*second).to_string(),
        (*third).to_string(),
    ];
    let mut headers = JavaHeaders::default();
    loop {
        let Some((line_end, next)) = java_read_line(buffer, at) else {
            // Draft.java:128-130: headers not terminated by an empty line.
            return JavaHeadParse::Incomplete;
        };
        let line = latin1(&buffer[at..line_end]);
        at = next;
        if line.is_empty() {
            return JavaHeadParse::Complete(JavaHead {
                first_line,
                headers,
                head_len: at,
            });
        }
        // Draft.java:115-125: split(":", 2); no colon rejects; the value has
        // leading SPACES (only spaces) stripped; duplicates join with "; ".
        let Some((name, raw_value)) = line.split_once(':') else {
            return JavaHeadParse::Reject;
        };
        let value = raw_value.trim_start_matches(' ').to_string();
        headers.put(name.to_ascii_lowercase(), value);
    }
}

/// Bounded, incremental head accumulator (borrowed Codex design, Java line
/// semantics). Budgets are enforced BEFORE the byte is buffered, so memory
/// never exceeds the configured bounds; the budget walk is per byte, making
/// the refusing budget deterministic under arbitrary re-chunking.
#[derive(Debug)]
pub struct HeadAccumulator {
    buffer: Vec<u8>,
    limits: HandshakeLimits,
    /// Bytes of the current (unterminated) Java line, CRLF included.
    current_line_bytes: usize,
    /// Completed non-empty lines after the first line.
    header_count: usize,
    /// Whether the first line's CRLF has been consumed.
    start_line_complete: bool,
}

impl HeadAccumulator {
    /// An empty accumulator with the given budgets.
    #[must_use]
    pub fn new(limits: HandshakeLimits) -> Self {
        HeadAccumulator {
            buffer: Vec::new(),
            limits,
            current_line_bytes: 0,
            header_count: 0,
            start_line_complete: false,
        }
    }

    /// The accumulated bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.buffer
    }

    /// Append a chunk within the budgets.
    ///
    /// # Errors
    ///
    /// [`HandshakeLimitExceeded`] naming the first refused budget; the
    /// buffer retains everything accepted before the refusal.
    pub fn push(&mut self, chunk: &[u8]) -> Result<(), HandshakeLimitExceeded> {
        for &byte in chunk {
            if self.buffer.len() >= self.limits.max_handshake_bytes {
                return Err(HandshakeLimitExceeded {
                    limit: HandshakeLimitKind::TotalBytes,
                    attempted: (self.buffer.len() as u64).saturating_add(1),
                });
            }
            let attempted_line = self.current_line_bytes.saturating_add(1);
            if attempted_line > self.limits.max_header_line_bytes {
                return Err(HandshakeLimitExceeded {
                    limit: HandshakeLimitKind::HeaderLineBytes,
                    attempted: attempted_line as u64,
                });
            }
            // A Java line completes ONLY on the CRLF pair (bare LF folds).
            let completes_line = byte == b'\n' && self.buffer.last() == Some(&b'\r');
            // The completing line is a header when the start line is done and
            // the line holds more than its own CRLF.
            let completes_header =
                completes_line && self.start_line_complete && attempted_line != 2;
            if completes_header && self.header_count >= self.limits.max_header_count {
                return Err(HandshakeLimitExceeded {
                    limit: HandshakeLimitKind::HeaderCount,
                    attempted: (self.header_count as u64).saturating_add(1),
                });
            }
            self.buffer.push(byte);
            if completes_line {
                if self.start_line_complete {
                    if completes_header {
                        self.header_count += 1;
                    }
                } else {
                    self.start_line_complete = true;
                }
                self.current_line_bytes = 0;
            } else {
                self.current_line_bytes = attempted_line;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(bytes: &[u8]) -> JavaHeadParse {
        parse_java_head(bytes)
    }

    #[test]
    fn incomplete_until_empty_line() {
        assert_eq!(parse(b""), JavaHeadParse::Incomplete);
        assert_eq!(parse(b"GET / HTTP/1.1"), JavaHeadParse::Incomplete);
        assert_eq!(parse(b"GET / HTTP/1.1\r\n"), JavaHeadParse::Incomplete);
        assert_eq!(
            parse(b"GET / HTTP/1.1\r\nHost: h\r\n"),
            JavaHeadParse::Incomplete
        );
    }

    #[test]
    fn first_line_must_have_exactly_three_tokens() {
        // Rejects as soon as the malformed first line is CRLF-complete, even
        // without the head terminator (Go model loop order).
        assert_eq!(parse(b"GETALL\r\n"), JavaHeadParse::Reject);
        assert_eq!(parse(b"GET /\r\n"), JavaHeadParse::Reject);
        // Extra tokens FOLD into the third token (split limit 3) — parse-level
        // accept; the predicate rejects later on the version comparison.
        let JavaHeadParse::Complete(head) = parse(b"GET / HTTP/1.1 EXTRA\r\n\r\n") else {
            panic!("three-plus tokens parse with folding");
        };
        assert_eq!(head.first_line[2], "HTTP/1.1 EXTRA");
    }

    #[test]
    fn header_without_colon_rejects_midstream() {
        assert_eq!(
            parse(b"GET / HTTP/1.1\r\nno-colon-line\r\n"),
            JavaHeadParse::Reject
        );
        // Obs-fold continuation: leading-space line has no colon -> same
        // rejection (live mapping HS_OBS_FOLD note).
        assert_eq!(
            parse(b"GET / HTTP/1.1\r\nUpgrade: websocket\r\n folded\r\n"),
            JavaHeadParse::Reject
        );
    }

    #[test]
    fn bare_lf_folds_into_the_next_crlf_line() {
        let JavaHeadParse::Complete(head) =
            parse(b"GET / HTTP/1.1\r\nUpgrade: websocket\nConnection: Upgrade\r\n\r\n")
        else {
            panic!("bare-LF head parses with folding");
        };
        // One folded header: name "upgrade", value carrying the bare-LF tail.
        assert_eq!(
            head.headers.get("Upgrade"),
            "websocket\nConnection: Upgrade"
        );
        assert!(!head.headers.has("Connection"));
    }

    #[test]
    fn duplicates_join_with_semicolon_space_case_insensitively() {
        let JavaHeadParse::Complete(head) = parse(b"GET / HTTP/1.1\r\nA: one\r\na: two\r\n\r\n")
        else {
            panic!("duplicate head parses");
        };
        assert_eq!(head.headers.get("A"), "one; two");
    }

    #[test]
    fn value_strips_leading_spaces_only() {
        let JavaHeadParse::Complete(head) = parse(b"GET / HTTP/1.1\r\nK:   \tv \r\n\r\n") else {
            panic!("head parses");
        };
        assert_eq!(head.headers.get("K"), "\tv ");
    }

    #[test]
    fn head_len_marks_the_remainder_boundary() {
        let raw = b"GET / HTTP/1.1\r\n\r\nREMAINDER";
        let JavaHeadParse::Complete(head) = parse(raw) else {
            panic!("head parses");
        };
        assert_eq!(&raw[head.head_len..], b"REMAINDER");
    }

    #[test]
    fn accumulator_budgets_refuse_before_buffering() {
        let limits = HandshakeLimits {
            max_handshake_bytes: 8,
            max_header_count: 1024,
            max_header_line_bytes: 65536,
        };
        let mut acc = HeadAccumulator::new(limits);
        let err = acc.push(b"123456789").unwrap_err();
        assert_eq!(err.limit, HandshakeLimitKind::TotalBytes);
        assert_eq!(err.attempted, 9);
        assert_eq!(acc.bytes().len(), 8);
    }

    #[test]
    fn accumulator_is_chunking_invariant() {
        let limits = HandshakeLimits {
            max_handshake_bytes: 64,
            max_header_count: 2,
            max_header_line_bytes: 16,
        };
        let input: &[u8] = b"GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n";
        let mut one_shot = HeadAccumulator::new(limits);
        let whole = one_shot.push(input);
        for split in 1..input.len() {
            let mut chunked = HeadAccumulator::new(limits);
            let first = chunked.push(&input[..split]);
            let outcome = match first {
                Err(e) => Err(e),
                Ok(()) => chunked.push(&input[split..]),
            };
            assert_eq!(outcome, whole, "split at {split}");
        }
    }
}
