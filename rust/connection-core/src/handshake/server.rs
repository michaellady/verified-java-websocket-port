use crate::handshake::crypto;
use crate::handshake::http::{
    ascii_eq, contains_comma_token, duplicate_before, find_crlf, has_bare_line_ending, header_end,
    is_field_value_byte, is_token_byte, trim_ows,
};
use crate::{HandshakeFailure, LimitKind};

/// An immutable request descriptor produced by a successful server handshake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerRequestDescriptor {
    request_target: Box<str>,
    host: Box<str>,
}

impl ServerRequestDescriptor {
    /// Returns the validated origin-form request target.
    #[must_use]
    pub fn request_target(&self) -> &str {
        &self.request_target
    }

    /// Returns the validated Host field value.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }
}

#[derive(Debug)]
pub(crate) struct ServerHandshake {
    phase: ServerPhase,
    maximum_bytes: usize,
    maximum_line_bytes: usize,
    maximum_header_count: usize,
}

#[derive(Debug)]
enum ServerPhase {
    AwaitingRequest { parser: RequestParser },
    Opened,
    Failed,
}

impl ServerHandshake {
    pub(crate) const fn new(
        maximum_bytes: usize,
        maximum_line_bytes: usize,
        maximum_header_count: usize,
    ) -> Self {
        Self {
            phase: ServerPhase::AwaitingRequest {
                parser: RequestParser::new(maximum_bytes, maximum_line_bytes, maximum_header_count),
            },
            maximum_bytes,
            maximum_line_bytes,
            maximum_header_count,
        }
    }

    pub(crate) fn awaiting_request(&self) -> bool {
        matches!(self.phase, ServerPhase::AwaitingRequest { .. })
    }

    pub(crate) fn mark_failed(&mut self) {
        self.phase = ServerPhase::Failed;
    }

    pub(crate) fn consume_request(&mut self, request: &[u8]) -> ServerRequest {
        let ServerPhase::AwaitingRequest { parser } = &mut self.phase else {
            return ServerRequest::NotAwaiting;
        };
        let progress = parser.consume(request);
        match progress {
            RequestProgress::Incomplete => ServerRequest::Incomplete,
            RequestProgress::LimitExceeded { limit, attempted } => {
                ServerRequest::LimitExceeded { limit, attempted }
            }
            RequestProgress::Complete(Err(failure)) => ServerRequest::Rejected(failure),
            RequestProgress::Complete(Ok(parsed)) => {
                let response = match canonical_response(
                    &parsed.key,
                    self.maximum_bytes,
                    self.maximum_line_bytes,
                    self.maximum_header_count,
                ) {
                    Ok(response) => response,
                    Err(failure) => {
                        return ServerRequest::LimitExceeded {
                            limit: failure.limit,
                            attempted: failure.attempted,
                        };
                    }
                };
                self.phase = ServerPhase::Opened;
                ServerRequest::Opened {
                    descriptor: parsed.descriptor,
                    response,
                }
            }
        }
    }
}

pub(crate) enum ServerRequest {
    NotAwaiting,
    Incomplete,
    Opened {
        descriptor: ServerRequestDescriptor,
        response: Box<[u8]>,
    },
    Rejected(HandshakeFailure),
    LimitExceeded {
        limit: LimitKind,
        attempted: u64,
    },
}

pub(crate) struct ServerLimitExceeded {
    pub(crate) limit: LimitKind,
    pub(crate) attempted: u64,
}

#[derive(Debug)]
struct RequestParser {
    buffer: Vec<u8>,
    maximum_bytes: usize,
    maximum_line_bytes: usize,
    maximum_header_count: usize,
    current_line_bytes: usize,
    header_count: usize,
    request_line_complete: bool,
}

enum RequestProgress {
    Incomplete,
    Complete(Result<ParsedRequest, HandshakeFailure>),
    LimitExceeded { limit: LimitKind, attempted: u64 },
}

struct ParsedRequest {
    descriptor: ServerRequestDescriptor,
    key: [u8; 24],
}

impl RequestParser {
    const fn new(
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
            request_line_complete: false,
        }
    }

    fn consume(&mut self, bytes: &[u8]) -> RequestProgress {
        for &byte in bytes {
            if self.buffer.len() == self.maximum_bytes {
                return RequestProgress::LimitExceeded {
                    limit: LimitKind::HandshakeBytes,
                    attempted: u64::try_from(self.buffer.len())
                        .unwrap_or(u64::MAX)
                        .saturating_add(1),
                };
            }
            if byte == b'\n' && self.buffer.last() != Some(&b'\r')
                || self.buffer.last() == Some(&b'\r') && byte != b'\n'
            {
                return RequestProgress::Complete(Err(HandshakeFailure::BareLineEnding));
            }
            let attempted_line = self.current_line_bytes.saturating_add(1);
            if attempted_line > self.maximum_line_bytes {
                return RequestProgress::LimitExceeded {
                    limit: LimitKind::HandshakeHeaderLineBytes,
                    attempted: u64::try_from(attempted_line).unwrap_or(u64::MAX),
                };
            }
            let completes_line = byte == b'\n';
            let completes_header =
                completes_line && self.request_line_complete && attempted_line != 2;
            if completes_header && self.header_count == self.maximum_header_count {
                return RequestProgress::LimitExceeded {
                    limit: LimitKind::HandshakeHeaderCount,
                    attempted: u64::try_from(self.header_count)
                        .unwrap_or(u64::MAX)
                        .saturating_add(1),
                };
            }
            self.buffer.push(byte);
            debug_assert!(self.buffer.len() <= self.maximum_bytes);
            if completes_line {
                if self.request_line_complete {
                    if completes_header {
                        self.header_count += 1;
                    }
                } else {
                    self.request_line_complete = true;
                }
                self.current_line_bytes = 0;
            } else {
                self.current_line_bytes = attempted_line;
            }
        }
        let Some(end) = header_end(&self.buffer) else {
            return RequestProgress::Incomplete;
        };
        if end != self.buffer.len() {
            return RequestProgress::Complete(Err(HandshakeFailure::TrailingData {
                bytes: u64::try_from(self.buffer.len() - end).unwrap_or(u64::MAX),
            }));
        }
        RequestProgress::Complete(validate_request(&self.buffer))
    }
}

fn validate_request(bytes: &[u8]) -> Result<ParsedRequest, HandshakeFailure> {
    if has_bare_line_ending(bytes) {
        return Err(HandshakeFailure::BareLineEnding);
    }
    let request_line_end = find_crlf(bytes, 0).ok_or(HandshakeFailure::MalformedRequestLine)?;
    let request_target = validate_request_line(&bytes[..request_line_end])?;

    let headers_end = bytes.len() - 2;
    let mut cursor = request_line_end + 2;
    let first_header = cursor;
    let mut host = None;
    let mut upgrade = None;
    let mut connection = None;
    let mut key = None;
    let mut version = None;
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
        if ascii_eq(name, b"host") {
            host = Some(value);
        } else if ascii_eq(name, b"upgrade") {
            upgrade = Some(value);
        } else if ascii_eq(name, b"connection") {
            connection = Some(value);
        } else if ascii_eq(name, b"sec-websocket-key") {
            key = Some(value);
        } else if ascii_eq(name, b"sec-websocket-version") {
            version = Some(value);
        } else if ascii_eq(name, b"content-length") {
            return Err(HandshakeFailure::UnexpectedContentLength);
        } else if ascii_eq(name, b"transfer-encoding") {
            return Err(HandshakeFailure::UnexpectedTransferEncoding);
        } else if ascii_eq(name, b"sec-websocket-extensions") {
            return Err(HandshakeFailure::UnexpectedExtension);
        } else if ascii_eq(name, b"sec-websocket-protocol") {
            return Err(HandshakeFailure::UnexpectedSubprotocol);
        }
        cursor = line_end + 2;
    }

    let host = host.ok_or(HandshakeFailure::MissingHost)?;
    if host.is_empty()
        || !host
            .iter()
            .copied()
            .all(|byte| (0x21..=0x7e).contains(&byte) && byte != b',')
    {
        return Err(HandshakeFailure::InvalidHost);
    }
    let upgrade = upgrade.ok_or(HandshakeFailure::MissingUpgrade)?;
    if !contains_comma_token(upgrade, b"websocket") {
        return Err(HandshakeFailure::InvalidUpgrade);
    }
    let connection = connection.ok_or(HandshakeFailure::MissingConnection)?;
    if !contains_comma_token(connection, b"upgrade") {
        return Err(HandshakeFailure::InvalidConnection);
    }
    let version = version.ok_or(HandshakeFailure::MissingVersion)?;
    if version != b"13" {
        return Err(HandshakeFailure::UnsupportedVersion);
    }
    let key = key.ok_or(HandshakeFailure::MissingKey)?;
    let key = crypto::canonical_nonce_key(key).ok_or(HandshakeFailure::InvalidKeyEncoding)?;

    let request_target =
        core::str::from_utf8(request_target).map_err(|_| HandshakeFailure::InvalidRequestTarget)?;
    let host = core::str::from_utf8(host).map_err(|_| HandshakeFailure::InvalidHost)?;
    Ok(ParsedRequest {
        descriptor: ServerRequestDescriptor {
            request_target: request_target.into(),
            host: host.into(),
        },
        key,
    })
}

fn validate_request_line(line: &[u8]) -> Result<&[u8], HandshakeFailure> {
    let Some(remainder) = line.strip_prefix(b"GET ") else {
        return Err(if line.starts_with(b"GET") {
            HandshakeFailure::MalformedRequestLine
        } else {
            HandshakeFailure::MethodNotGet
        });
    };
    let target = remainder
        .strip_suffix(b" HTTP/1.1")
        .ok_or(HandshakeFailure::MalformedRequestLine)?;
    if target.is_empty()
        || target.first() != Some(&b'/')
        || target
            .iter()
            .copied()
            .any(|byte| !(0x21..=0x7e).contains(&byte) || byte == b'#')
    {
        return Err(HandshakeFailure::InvalidRequestTarget);
    }
    Ok(target)
}

fn canonical_response(
    key: &[u8; 24],
    maximum_bytes: usize,
    maximum_line_bytes: usize,
    maximum_header_count: usize,
) -> Result<Box<[u8]>, ServerLimitExceeded> {
    const STATUS: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\n";
    const UPGRADE: &[u8] = b"Upgrade: websocket\r\n";
    const CONNECTION: &[u8] = b"Connection: Upgrade\r\n";
    const ACCEPT_PREFIX: &[u8] = b"Sec-WebSocket-Accept: ";
    const END: &[u8] = b"\r\n\r\n";
    let accept = crypto::derive_accept(key);
    let accept_line = ACCEPT_PREFIX
        .len()
        .checked_add(accept.len())
        .and_then(|length| length.checked_add(2))
        .ok_or(ServerLimitExceeded {
            limit: LimitKind::HandshakeHeaderLineBytes,
            attempted: u64::MAX,
        })?;
    let line_lengths = [STATUS.len(), UPGRADE.len(), CONNECTION.len(), accept_line];
    if let Some(attempted) = line_lengths
        .into_iter()
        .find(|length| *length > maximum_line_bytes)
    {
        return Err(ServerLimitExceeded {
            limit: LimitKind::HandshakeHeaderLineBytes,
            attempted: u64::try_from(attempted).unwrap_or(u64::MAX),
        });
    }
    const RESPONSE_HEADER_COUNT: usize = 3;
    if RESPONSE_HEADER_COUNT > maximum_header_count {
        return Err(ServerLimitExceeded {
            limit: LimitKind::HandshakeHeaderCount,
            attempted: u64::try_from(RESPONSE_HEADER_COUNT).unwrap_or(u64::MAX),
        });
    }
    let total = line_lengths
        .into_iter()
        .try_fold(2usize, usize::checked_add)
        .ok_or(ServerLimitExceeded {
            limit: LimitKind::HandshakeBytes,
            attempted: u64::MAX,
        })?;
    if total > maximum_bytes {
        return Err(ServerLimitExceeded {
            limit: LimitKind::HandshakeBytes,
            attempted: u64::try_from(total).unwrap_or(u64::MAX),
        });
    }

    let mut response = Vec::with_capacity(total);
    response.extend_from_slice(STATUS);
    response.extend_from_slice(UPGRADE);
    response.extend_from_slice(CONNECTION);
    response.extend_from_slice(ACCEPT_PREFIX);
    response.extend_from_slice(&accept);
    response.extend_from_slice(END);
    debug_assert_eq!(response.len(), total);
    Ok(response.into_boxed_slice())
}
