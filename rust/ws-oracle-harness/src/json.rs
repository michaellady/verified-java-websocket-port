//! Strict JSON value, parser, and canonical writer.
//!
//! The writer reproduces, byte for byte, the canonical form shared by the Go
//! reference tooling (`internal/corpora/canonical.go` `CanonicalJSON`) and the
//! java-oracle adapter (`StrictJson.write`): lexicographically sorted object
//! keys, no insignificant whitespace, plain integers, and the StrictJson
//! escape set. Digests computed over this form bind the identical bytes the
//! oracle and `corporactl` recompute.
//!
//! The parser mirrors `StrictJson.parse` fail-closed behavior: duplicate
//! object fields, unescaped control characters, leading zeros, invalid
//! escapes, trailing content, surrogate-pairing violations in `\uXXXX`
//! escapes (`INVALID_UNICODE`, StrictJson's exact per-case details; Java's
//! RAW-surrogate `INVALID_UNICODE` branch is unreachable through both
//! adapters because strict UTF-8 decoding rejects surrogate encodings as
//! `INVALID_UTF8` first, and a Rust `&str` cannot carry one at all), the
//! [`MAX_DEPTH`] nesting limit
//! (`JSON_DEPTH_LIMIT`), and the [`MAX_CONTAINER_ENTRIES`] entry limit
//! (`JSON_CONTAINER_LIMIT`) are all typed rejections with StrictJson's exact
//! code vocabulary. The depth limit is enforced by depth-counted recursion
//! (checked on every `value` entry, exactly like `StrictJson.Parser.value`),
//! so pathologically deep input rejects long before recursion depth becomes
//! dangerous. One deliberate narrowing (documented in the crate honesty
//! notes, `crate` docs § Narrowings): only integer numbers are accepted,
//! because the oracle protocol's canonical vocabulary contains nothing else;
//! fraction/exponent forms fail closed as `INVALID_JSON`.

use std::collections::BTreeMap;

use crate::request::ProtocolError;

/// StrictJson's `MAX_DEPTH`: the deepest permitted container nesting.
pub const MAX_DEPTH: u32 = 32;
/// StrictJson's `MAX_CONTAINER_ENTRIES`: the most entries one object or
/// array may hold.
pub const MAX_CONTAINER_ENTRIES: usize = 16_384;

/// One strict JSON value. Object keys iterate in byte-lexicographic order
/// (`BTreeMap`), which is exactly the canonical key order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// JSON `null`.
    Null,
    /// JSON boolean.
    Bool(bool),
    /// JSON integer (the only number form in the oracle vocabulary).
    Int(i64),
    /// JSON string.
    Str(String),
    /// JSON array.
    Arr(Vec<Value>),
    /// JSON object with byte-lexicographic key order.
    Obj(BTreeMap<String, Value>),
}

impl Value {
    /// Renders the canonical form (sorted keys, no whitespace, StrictJson
    /// escapes) into a `String`.
    pub fn canonical(&self) -> String {
        let mut out = String::new();
        self.write_canonical(&mut out);
        out
    }

    fn write_canonical(&self, out: &mut String) {
        match self {
            Value::Null => out.push_str("null"),
            Value::Bool(true) => out.push_str("true"),
            Value::Bool(false) => out.push_str("false"),
            Value::Int(number) => out.push_str(&number.to_string()),
            Value::Str(text) => write_canonical_string(out, text),
            Value::Arr(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    item.write_canonical(out);
                }
                out.push(']');
            }
            Value::Obj(members) => {
                out.push('{');
                for (index, (key, value)) in members.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    write_canonical_string(out, key);
                    out.push(':');
                    value.write_canonical(out);
                }
                out.push('}');
            }
        }
    }
}

/// Writes one canonical JSON string token using the exact StrictJson /
/// `canonical.go` escape set: `\" \\ \b \f \n \r \t`, `\u00xx` for other
/// control characters, and raw UTF-8 for everything else.
fn write_canonical_string(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Parses exactly one strict JSON value from `input`, rejecting trailing
/// content, mirroring `StrictJson.parse`.
///
/// # Errors
///
/// Returns a typed [`ProtocolError`] (`INVALID_JSON` or `DUPLICATE_FIELD`)
/// for any deviation from the strict grammar.
pub fn parse(input: &str) -> Result<Value, ProtocolError> {
    let mut parser = Parser {
        bytes: input.as_bytes(),
        input,
        at: 0,
    };
    parser.skip_whitespace();
    let value = parser.value(0)?;
    parser.skip_whitespace();
    if parser.at != parser.bytes.len() {
        return Err(invalid("trailing content"));
    }
    Ok(value)
}

fn invalid(detail: &str) -> ProtocolError {
    ProtocolError::new("INVALID_JSON", detail)
}

struct Parser<'a> {
    bytes: &'a [u8],
    input: &'a str,
    at: usize,
}

impl Parser<'_> {
    fn skip_whitespace(&mut self) {
        while let Some(&b) = self.bytes.get(self.at) {
            if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                self.at += 1;
            } else {
                break;
            }
        }
    }

    /// One value at `depth` container-nesting levels, mirroring
    /// `StrictJson.Parser.value(int depth)`: the depth guard fires on entry,
    /// before any further recursion, so the recursion depth is bounded by
    /// `MAX_DEPTH + 1` frames regardless of input size.
    fn value(&mut self, depth: u32) -> Result<Value, ProtocolError> {
        if depth > MAX_DEPTH {
            return Err(ProtocolError::new(
                "JSON_DEPTH_LIMIT",
                format!("JSON nesting exceeds {MAX_DEPTH}"),
            ));
        }
        match self.bytes.get(self.at) {
            None => Err(invalid("expected value")),
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => Ok(Value::Str(self.string()?)),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'n') => self.literal("null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => Err(invalid("expected value")),
        }
    }

    fn literal(&mut self, expected: &str, value: Value) -> Result<Value, ProtocolError> {
        if self.input[self.at..].starts_with(expected) {
            self.at += expected.len();
            Ok(value)
        } else {
            Err(invalid("invalid literal"))
        }
    }

    fn object(&mut self, depth: u32) -> Result<Value, ProtocolError> {
        self.at += 1; // consume '{'
        let mut members = BTreeMap::new();
        self.skip_whitespace();
        if self.bytes.get(self.at) == Some(&b'}') {
            self.at += 1;
            return Ok(Value::Obj(members));
        }
        loop {
            self.skip_whitespace();
            if self.bytes.get(self.at) != Some(&b'"') {
                return Err(invalid("object key must be a string"));
            }
            let key = self.string()?;
            if members.contains_key(&key) {
                return Err(ProtocolError::new(
                    "DUPLICATE_FIELD",
                    format!("duplicate object field: {}", clipped(&key)),
                ));
            }
            self.skip_whitespace();
            if self.bytes.get(self.at) != Some(&b':') {
                return Err(invalid("expected ':' after object key"));
            }
            self.at += 1;
            self.skip_whitespace();
            let value = self.value(depth)?;
            members.insert(key, value);
            // StrictJson checks the entry count after the insert, so the
            // 16385th member (not its value's own errors) trips the limit.
            if members.len() > MAX_CONTAINER_ENTRIES {
                return Err(ProtocolError::new(
                    "JSON_CONTAINER_LIMIT",
                    "object has too many fields",
                ));
            }
            self.skip_whitespace();
            match self.bytes.get(self.at) {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Value::Obj(members));
                }
                _ => return Err(invalid("expected ',' or '}'")),
            }
        }
    }

    fn array(&mut self, depth: u32) -> Result<Value, ProtocolError> {
        self.at += 1; // consume '['
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.bytes.get(self.at) == Some(&b']') {
            self.at += 1;
            return Ok(Value::Arr(items));
        }
        loop {
            self.skip_whitespace();
            items.push(self.value(depth)?);
            // StrictJson checks the element count after the append.
            if items.len() > MAX_CONTAINER_ENTRIES {
                return Err(ProtocolError::new(
                    "JSON_CONTAINER_LIMIT",
                    "array has too many elements",
                ));
            }
            self.skip_whitespace();
            match self.bytes.get(self.at) {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return Ok(Value::Arr(items));
                }
                _ => return Err(invalid("expected ',' or ']'")),
            }
        }
    }

    fn string(&mut self) -> Result<String, ProtocolError> {
        self.at += 1; // consume '"'
        let mut out = String::new();
        loop {
            let Some(&b) = self.bytes.get(self.at) else {
                return Err(invalid("unterminated string"));
            };
            match b {
                b'"' => {
                    self.at += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.at += 1;
                    out.push(self.escape()?);
                }
                0x00..=0x1f => {
                    return Err(invalid("unescaped control character in string"));
                }
                _ => {
                    // Consume one full UTF-8 scalar from the (already valid)
                    // input string.
                    let rest = &self.input[self.at..];
                    let c = rest
                        .chars()
                        .next()
                        .ok_or_else(|| invalid("unterminated string"))?;
                    out.push(c);
                    self.at += c.len_utf8();
                }
            }
        }
    }

    fn escape(&mut self) -> Result<char, ProtocolError> {
        let Some(&b) = self.bytes.get(self.at) else {
            return Err(invalid("unterminated string escape"));
        };
        self.at += 1;
        Ok(match b {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{0008}',
            b'f' => '\u{000c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => return self.unicode_escape(),
            _ => return Err(invalid("invalid string escape")),
        })
    }

    /// Mirrors `StrictJson.Parser.appendUnicode`: surrogate-pairing
    /// violations are `INVALID_UNICODE` (each with StrictJson's exact
    /// detail), while hex-level problems inside either `\uXXXX` unit stay
    /// `INVALID_JSON` (from [`Self::hex4`], mirroring `unicodeUnit`).
    fn unicode_escape(&mut self) -> Result<char, ProtocolError> {
        let first = self.hex4()?;
        if (0xdc00..=0xdfff).contains(&first) {
            return Err(ProtocolError::new(
                "INVALID_UNICODE",
                "unpaired low surrogate",
            ));
        }
        if (0xd800..=0xdbff).contains(&first) {
            // High surrogate: require a following \uXXXX low surrogate.
            if self.bytes.get(self.at) != Some(&b'\\') || self.bytes.get(self.at + 1) != Some(&b'u')
            {
                return Err(ProtocolError::new(
                    "INVALID_UNICODE",
                    "unpaired high surrogate",
                ));
            }
            self.at += 2;
            let second = self.hex4()?;
            if !(0xdc00..=0xdfff).contains(&second) {
                return Err(ProtocolError::new(
                    "INVALID_UNICODE",
                    "invalid surrogate pair",
                ));
            }
            let combined = 0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00);
            return char::from_u32(combined).ok_or_else(|| invalid("invalid unicode escape"));
        }
        char::from_u32(first).ok_or_else(|| invalid("invalid unicode escape"))
    }

    fn hex4(&mut self) -> Result<u32, ProtocolError> {
        if self.at + 4 > self.bytes.len() {
            return Err(invalid("short unicode escape"));
        }
        let mut value = 0u32;
        for offset in 0..4 {
            let digit = match self.bytes[self.at + offset] {
                b @ b'0'..=b'9' => u32::from(b - b'0'),
                b @ b'a'..=b'f' => u32::from(b - b'a') + 10,
                b @ b'A'..=b'F' => u32::from(b - b'A') + 10,
                _ => return Err(invalid("invalid unicode escape")),
            };
            value = value << 4 | digit;
        }
        self.at += 4;
        Ok(value)
    }

    fn number(&mut self) -> Result<Value, ProtocolError> {
        let start = self.at;
        if self.bytes.get(self.at) == Some(&b'-') {
            self.at += 1;
        }
        let digits_start = self.at;
        while matches!(self.bytes.get(self.at), Some(b'0'..=b'9')) {
            self.at += 1;
        }
        if self.at == digits_start {
            return Err(invalid("incomplete number"));
        }
        if self.bytes[digits_start] == b'0' && self.at - digits_start > 1 {
            return Err(invalid("leading zero in number"));
        }
        // The oracle vocabulary is integer-only; fraction/exponent forms fail
        // closed rather than being silently normalized.
        if matches!(self.bytes.get(self.at), Some(b'.' | b'e' | b'E')) {
            return Err(invalid(
                "non-integer numbers are outside the oracle vocabulary",
            ));
        }
        self.input[start..self.at]
            .parse::<i64>()
            .map(Value::Int)
            .map_err(|_| invalid("integer out of range"))
    }
}

fn clipped(value: &str) -> &str {
    if value.len() <= 80 {
        value
    } else {
        let mut end = 80;
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        &value[..end]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(pairs: &[(&str, Value)]) -> Value {
        Value::Obj(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), v.clone()))
                .collect(),
        )
    }

    #[test]
    fn canonical_sorts_keys_and_omits_whitespace() {
        let value = obj(&[
            ("b", Value::Int(2)),
            ("a", Value::Arr(vec![Value::Bool(true), Value::Null])),
        ]);
        assert_eq!(value.canonical(), "{\"a\":[true,null],\"b\":2}");
    }

    #[test]
    fn canonical_string_escapes_match_strictjson() {
        let value = Value::Str("q\"\\\u{0008}\u{000c}\n\r\t\u{0001}é".to_string());
        assert_eq!(value.canonical(), "\"q\\\"\\\\\\b\\f\\n\\r\\t\\u0001é\"",);
    }

    #[test]
    fn parse_round_trips_canonical_lines() {
        let line = "{\"a\":[1,-2,\"x\"],\"b\":{\"c\":null,\"d\":false}}";
        let value = parse(line).expect("canonical line parses");
        assert_eq!(value.canonical(), line);
    }

    #[test]
    fn parse_rejects_duplicates_trailing_and_floats() {
        assert_eq!(
            parse("{\"a\":1,\"a\":2}").unwrap_err().code,
            "DUPLICATE_FIELD"
        );
        assert_eq!(parse("{} {}").unwrap_err().code, "INVALID_JSON");
        assert_eq!(parse("1.5").unwrap_err().code, "INVALID_JSON");
        assert_eq!(parse("1e3").unwrap_err().code, "INVALID_JSON");
        assert_eq!(parse("01").unwrap_err().code, "INVALID_JSON");
        assert_eq!(parse("\"\u{0001}\"").unwrap_err().code, "INVALID_JSON");
        assert_eq!(parse("{\"a\":}").unwrap_err().code, "INVALID_JSON");
        assert_eq!(parse("").unwrap_err().code, "INVALID_JSON");
    }

    #[test]
    fn parse_handles_escapes_and_surrogate_pairs() {
        let value = parse("\"\\u0041\\ud83d\\ude00\\/\"").expect("escapes parse");
        assert_eq!(value, Value::Str("A😀/".to_string()));
        assert_eq!(parse("\"\\q\"").unwrap_err().code, "INVALID_JSON");
    }

    /// StrictJson rejects surrogate-pairing violations as `INVALID_UNICODE`
    /// (not `INVALID_JSON`), with a distinct detail per case
    /// (`StrictJson.appendUnicode`).
    #[test]
    fn unpaired_surrogate_escapes_reject_invalid_unicode() {
        let lone_low = parse("\"\\udc00\"").unwrap_err();
        assert_eq!(lone_low.code, "INVALID_UNICODE");
        assert_eq!(lone_low.detail, "unpaired low surrogate");

        let high_at_end = parse("\"\\ud83d\"").unwrap_err();
        assert_eq!(high_at_end.code, "INVALID_UNICODE");
        assert_eq!(high_at_end.detail, "unpaired high surrogate");

        let high_then_char = parse("\"\\ud83dx\"").unwrap_err();
        assert_eq!(high_then_char.code, "INVALID_UNICODE");
        assert_eq!(high_then_char.detail, "unpaired high surrogate");

        let high_then_escape = parse("\"\\ud83d\\n\"").unwrap_err();
        assert_eq!(high_then_escape.code, "INVALID_UNICODE");
        assert_eq!(high_then_escape.detail, "unpaired high surrogate");

        let bad_pair = parse("\"\\ud83d\\u0041\"").unwrap_err();
        assert_eq!(bad_pair.code, "INVALID_UNICODE");
        assert_eq!(bad_pair.detail, "invalid surrogate pair");

        // Hex-level problems inside the second escape stay INVALID_JSON,
        // exactly like Java's unicodeUnit.
        assert_eq!(parse("\"\\ud83d\\u00\"").unwrap_err().code, "INVALID_JSON");
        assert_eq!(
            parse("\"\\ud83d\\uzzzz\"").unwrap_err().code,
            "INVALID_JSON"
        );
    }

    /// StrictJson's `MAX_DEPTH = 32`: a value nested 32 containers deep
    /// parses; the 33rd nesting level rejects with `JSON_DEPTH_LIMIT`.
    #[test]
    fn depth_limit_mirrors_strictjson() {
        let ok = format!("{}0{}", "[".repeat(32), "]".repeat(32));
        parse(&ok).expect("32 nesting levels parse");
        let deep = format!("{}0{}", "[".repeat(33), "]".repeat(33));
        let err = parse(&deep).unwrap_err();
        assert_eq!(err.code, "JSON_DEPTH_LIMIT");
        assert_eq!(err.detail, "JSON nesting exceeds 32");
    }

    /// The depth limit must fire before recursion depth becomes dangerous:
    /// pathologically deep input rejects instead of overflowing the stack.
    #[test]
    fn deep_input_rejects_without_stack_overflow() {
        let deep_arrays = "[".repeat(100_000);
        assert_eq!(parse(&deep_arrays).unwrap_err().code, "JSON_DEPTH_LIMIT");
        let deep_objects = "{\"k\":".repeat(100_000);
        assert_eq!(parse(&deep_objects).unwrap_err().code, "JSON_DEPTH_LIMIT");
    }

    /// StrictJson's `MAX_CONTAINER_ENTRIES = 16_384`: the 16385th entry of
    /// an object or array rejects with `JSON_CONTAINER_LIMIT`.
    #[test]
    fn container_entry_limits_mirror_strictjson() {
        let ok_array = format!("[{}]", vec!["0"; 16_384].join(","));
        parse(&ok_array).expect("16384 array elements parse");
        let over_array = format!("[{}]", vec!["0"; 16_385].join(","));
        let err = parse(&over_array).unwrap_err();
        assert_eq!(err.code, "JSON_CONTAINER_LIMIT");
        assert_eq!(err.detail, "array has too many elements");

        let members: Vec<String> = (0..16_385).map(|i| format!("\"k{i}\":0")).collect();
        let over_object = format!("{{{}}}", members.join(","));
        let err = parse(&over_object).unwrap_err();
        assert_eq!(err.code, "JSON_CONTAINER_LIMIT");
        assert_eq!(err.detail, "object has too many fields");

        let ok_members: Vec<String> = (0..16_384).map(|i| format!("\"k{i}\":0")).collect();
        let ok_object = format!("{{{}}}", ok_members.join(","));
        parse(&ok_object).expect("16384 object fields parse");
    }
}
