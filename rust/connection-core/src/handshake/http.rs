use crate::{HandshakeFailure, LimitKind};

#[derive(Debug)]
pub(crate) struct ResponseParser {
    head: HeadAccumulator,
}

#[derive(Debug)]
pub(super) struct HeadAccumulator {
    buffer: Vec<u8>,
    maximum_bytes: usize,
    maximum_line_bytes: usize,
    maximum_header_count: usize,
    current_line_bytes: usize,
    header_count: usize,
    start_line_complete: bool,
}

pub(crate) enum ParseProgress {
    Incomplete,
    Complete(Result<(), HandshakeFailure>),
    LimitExceeded { limit: LimitKind, attempted: u64 },
}

pub(super) enum HeadProgress {
    Incomplete,
    Complete,
    Rejected(HandshakeFailure),
    LimitExceeded { limit: LimitKind, attempted: u64 },
}

impl ResponseParser {
    pub(crate) fn new(
        maximum_bytes: usize,
        maximum_line_bytes: usize,
        maximum_header_count: usize,
    ) -> Self {
        Self {
            head: HeadAccumulator::new(maximum_bytes, maximum_line_bytes, maximum_header_count),
        }
    }

    pub(crate) fn consume(&mut self, bytes: &[u8], expected_accept: &[u8; 28]) -> ParseProgress {
        match self.head.consume(bytes) {
            HeadProgress::Incomplete => ParseProgress::Incomplete,
            HeadProgress::Complete => {
                ParseProgress::Complete(validate_response(self.head.bytes(), expected_accept))
            }
            HeadProgress::Rejected(failure) => ParseProgress::Complete(Err(failure)),
            HeadProgress::LimitExceeded { limit, attempted } => {
                ParseProgress::LimitExceeded { limit, attempted }
            }
        }
    }
}

impl HeadAccumulator {
    pub(super) const fn new(
        maximum_bytes: usize,
        maximum_line_bytes: usize,
        maximum_header_count: usize,
    ) -> Self {
        Self {
            buffer: Vec::new(),
            maximum_bytes,
            maximum_line_bytes,
            maximum_header_count,
            current_line_bytes: 0,
            header_count: 0,
            start_line_complete: false,
        }
    }

    pub(super) fn consume(&mut self, bytes: &[u8]) -> HeadProgress {
        for (index, &byte) in bytes.iter().enumerate() {
            if self.buffer.len() == self.maximum_bytes {
                return HeadProgress::LimitExceeded {
                    limit: LimitKind::HandshakeBytes,
                    attempted: u64::try_from(self.buffer.len())
                        .unwrap_or(u64::MAX)
                        .saturating_add(1),
                };
            }
            let attempted_line = self.current_line_bytes.saturating_add(1);
            if attempted_line > self.maximum_line_bytes {
                return HeadProgress::LimitExceeded {
                    limit: LimitKind::HandshakeHeaderLineBytes,
                    attempted: u64::try_from(attempted_line).unwrap_or(u64::MAX),
                };
            }
            let completes_line = byte == b'\n';
            let completes_header =
                completes_line && self.start_line_complete && attempted_line != 2;
            if completes_header && self.header_count == self.maximum_header_count {
                return HeadProgress::LimitExceeded {
                    limit: LimitKind::HandshakeHeaderCount,
                    attempted: u64::try_from(self.header_count)
                        .unwrap_or(u64::MAX)
                        .saturating_add(1),
                };
            }
            if byte == b'\n' && self.buffer.last() != Some(&b'\r')
                || self.buffer.last() == Some(&b'\r') && byte != b'\n'
            {
                return HeadProgress::Rejected(HandshakeFailure::BareLineEnding);
            }
            self.buffer.push(byte);
            debug_assert!(self.buffer.len() <= self.maximum_bytes);
            if completes_line {
                if self.start_line_complete {
                    if completes_header {
                        self.header_count += 1;
                    } else {
                        let trailing = bytes.len() - index - 1;
                        return if trailing == 0 {
                            HeadProgress::Complete
                        } else {
                            HeadProgress::Rejected(HandshakeFailure::TrailingData {
                                bytes: u64::try_from(trailing).unwrap_or(u64::MAX),
                            })
                        };
                    }
                } else {
                    self.start_line_complete = true;
                }
                self.current_line_bytes = 0;
            } else {
                self.current_line_bytes = attempted_line;
            }
        }
        HeadProgress::Incomplete
    }

    pub(super) fn bytes(&self) -> &[u8] {
        &self.buffer
    }

    pub(super) fn clear(&mut self) {
        self.buffer.clear();
        self.current_line_bytes = 0;
        self.header_count = 0;
        self.start_line_complete = false;
        debug_assert!(self.buffer.is_empty());
    }
}

fn validate_response(bytes: &[u8], expected_accept: &[u8; 28]) -> Result<(), HandshakeFailure> {
    let status_end = find_crlf(bytes, 0).ok_or(HandshakeFailure::MalformedStatusLine)?;
    validate_status_line(&bytes[..status_end])?;

    let headers_end = bytes.len() - 2;
    let mut cursor = status_end + 2;
    let first_header = cursor;
    let mut upgrade = None;
    let mut connection = None;
    let mut accept = None;
    while cursor < headers_end {
        let line_end = find_crlf(bytes, cursor).ok_or(HandshakeFailure::MalformedHeader)?;
        if line_end == cursor {
            break;
        }
        let line = &bytes[cursor..line_end];
        if line
            .first()
            .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
        {
            return Err(HandshakeFailure::ObsoleteLineFolding);
        }
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or(HandshakeFailure::MalformedHeader)?;
        if colon == 0 {
            return Err(HandshakeFailure::MalformedHeader);
        }
        let name = &line[..colon];
        if !name.iter().copied().all(is_token_byte) {
            return Err(HandshakeFailure::InvalidHeaderName);
        }
        let raw_value = &line[colon + 1..];
        if !raw_value.iter().copied().all(is_field_value_byte) {
            return Err(HandshakeFailure::InvalidHeaderValueOctet);
        }
        if duplicate_before(bytes, first_header, cursor, name)? {
            return Err(HandshakeFailure::DuplicateHeader);
        }
        let value = trim_ows(raw_value);
        if ascii_eq(name, b"upgrade") {
            upgrade = Some(value);
        } else if ascii_eq(name, b"connection") {
            connection = Some(value);
        } else if ascii_eq(name, b"sec-websocket-accept") {
            accept = Some(value);
        } else if ascii_eq(name, b"sec-websocket-extensions") {
            return Err(HandshakeFailure::UnexpectedExtension);
        } else if ascii_eq(name, b"sec-websocket-protocol") {
            return Err(HandshakeFailure::UnexpectedSubprotocol);
        }
        cursor = line_end + 2;
    }

    let upgrade = upgrade.ok_or(HandshakeFailure::MissingUpgrade)?;
    if !contains_comma_token(upgrade, b"websocket") {
        return Err(HandshakeFailure::InvalidUpgrade);
    }
    let connection = connection.ok_or(HandshakeFailure::MissingConnection)?;
    if !contains_comma_token(connection, b"upgrade") {
        return Err(HandshakeFailure::InvalidConnection);
    }
    let accept = accept.ok_or(HandshakeFailure::MissingAccept)?;
    if accept != expected_accept {
        return Err(HandshakeFailure::AcceptMismatch);
    }
    Ok(())
}

fn validate_status_line(line: &[u8]) -> Result<(), HandshakeFailure> {
    if line.len() < 13 || line[8] != b' ' || line[12] != b' ' {
        return Err(HandshakeFailure::MalformedStatusLine);
    }
    let version = &line[..8];
    if !version.starts_with(b"HTTP/") {
        return Err(HandshakeFailure::MalformedStatusLine);
    }
    if version != b"HTTP/1.1" {
        return Err(HandshakeFailure::HttpVersionNot11);
    }
    let digits = &line[9..12];
    if !digits.iter().all(u8::is_ascii_digit) {
        return Err(HandshakeFailure::MalformedStatusLine);
    }
    if !line[13..].iter().copied().all(is_field_value_byte) {
        return Err(HandshakeFailure::InvalidReasonPhraseOctet);
    }
    let status = u16::from(digits[0] - b'0') * 100
        + u16::from(digits[1] - b'0') * 10
        + u16::from(digits[2] - b'0');
    if status != 101 {
        return Err(HandshakeFailure::StatusNotSwitchingProtocols { received: status });
    }
    Ok(())
}

pub(super) fn duplicate_before(
    bytes: &[u8],
    mut cursor: usize,
    stop: usize,
    name: &[u8],
) -> Result<bool, HandshakeFailure> {
    while cursor < stop {
        let line_end = find_crlf(bytes, cursor).ok_or(HandshakeFailure::MalformedHeader)?;
        let line = &bytes[cursor..line_end];
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or(HandshakeFailure::MalformedHeader)?;
        if ascii_eq(&line[..colon], name) {
            return Ok(true);
        }
        cursor = line_end + 2;
    }
    Ok(false)
}

pub(super) fn find_crlf(bytes: &[u8], start: usize) -> Option<usize> {
    bytes[start..]
        .windows(2)
        .position(|window| window == b"\r\n")
        .and_then(|offset| start.checked_add(offset))
}

pub(super) fn contains_comma_token(value: &[u8], required: &[u8]) -> bool {
    let mut found = false;
    for member in value.split(|byte| *byte == b',') {
        let token = trim_ows(member);
        if token.is_empty() || !token.iter().copied().all(is_token_byte) {
            return false;
        }
        found |= ascii_eq(token, required);
    }
    found
}

pub(super) fn trim_ows(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|byte| !matches!(byte, b' ' | b'\t'))
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| !matches!(byte, b' ' | b'\t'))
        .map_or(start, |index| index + 1);
    &value[start..end]
}

pub(super) fn ascii_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

pub(super) const fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

pub(super) const fn is_field_value_byte(byte: u8) -> bool {
    byte == b'\t' || (byte >= b' ' && byte <= b'~') || byte >= 0x80
}

#[cfg(test)]
mod tests {
    use super::{HeadAccumulator, HeadProgress, trim_ows, validate_status_line};
    use crate::HandshakeFailure;

    #[test]
    fn trim_ows_preserves_only_the_interior_octets() {
        assert_eq!(trim_ows(b""), b"");
        assert_eq!(trim_ows(b" \t  "), b"");
        assert_eq!(trim_ows(b"\t value with spaces \t"), b"value with spaces");
        assert_eq!(trim_ows(b"value"), b"value");
    }

    #[test]
    fn status_line_arithmetic_and_minimum_shape_are_exact() {
        assert_eq!(validate_status_line(b"HTTP/1.1 101 "), Ok(()));
        for malformed in [b"HTTP/1.1x101 ".as_slice(), b"HTTP/1.1 101x"] {
            assert_eq!(
                validate_status_line(malformed),
                Err(HandshakeFailure::MalformedStatusLine)
            );
        }
        assert_eq!(
            validate_status_line(b"HTTP/1.1 201 nope"),
            Err(HandshakeFailure::StatusNotSwitchingProtocols { received: 201 })
        );
        assert_eq!(
            validate_status_line(b"HTTP/1.1 111 nope"),
            Err(HandshakeFailure::StatusNotSwitchingProtocols { received: 111 })
        );
        assert_eq!(
            validate_status_line(b"HTTP/1.1 10x nope"),
            Err(HandshakeFailure::MalformedStatusLine)
        );
        assert_eq!(
            validate_status_line(b"HTTP/1.1 101"),
            Err(HandshakeFailure::MalformedStatusLine)
        );
    }

    #[test]
    fn clearing_a_partial_head_resets_all_parser_counters() {
        let mut head = HeadAccumulator::new(64, 32, 2);
        assert!(matches!(
            head.consume(b"HTTP/1.1 101 Switching\r\nX-Test: "),
            HeadProgress::Incomplete
        ));
        assert!(!head.bytes().is_empty());
        head.clear();
        assert!(head.bytes().is_empty());
        assert!(matches!(
            head.consume(b"HTTP/1.1 101 Ok\r\n\r\n"),
            HeadProgress::Complete
        ));
    }
}
