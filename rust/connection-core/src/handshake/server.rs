use crate::handshake::crypto;
use crate::handshake::http::{
    HeadAccumulator, HeadProgress, ascii_eq, contains_comma_token, duplicate_before, find_crlf,
    has_bare_line_ending, is_field_value_byte, is_token_byte, trim_ows,
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
    AwaitingRequest { parser: HeadAccumulator },
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
                parser: HeadAccumulator::new(
                    maximum_bytes,
                    maximum_line_bytes,
                    maximum_header_count,
                ),
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
        if let ServerPhase::AwaitingRequest { parser } = &mut self.phase {
            parser.clear();
        }
        self.phase = ServerPhase::Failed;
    }

    pub(crate) fn consume_request(&mut self, request: &[u8]) -> ServerRequest {
        let ServerPhase::AwaitingRequest { parser } = &mut self.phase else {
            return ServerRequest::NotAwaiting;
        };
        let progress = parser.consume(request);
        let parsed = match progress {
            HeadProgress::Incomplete => return ServerRequest::Incomplete,
            HeadProgress::Rejected(failure) => return ServerRequest::Rejected(failure),
            HeadProgress::LimitExceeded { limit, attempted } => {
                return ServerRequest::LimitExceeded { limit, attempted };
            }
            HeadProgress::Complete => match validate_request(parser.bytes()) {
                Ok(parsed) => parsed,
                Err(failure) => return ServerRequest::Rejected(failure),
            },
        };
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

struct ParsedRequest {
    descriptor: ServerRequestDescriptor,
    key: [u8; 24],
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
    let mut content_length = false;
    let mut transfer_encoding = false;
    let mut extension = false;
    let mut subprotocol = false;
    while cursor < headers_end {
        let line_end = find_crlf(bytes, cursor).ok_or(HandshakeFailure::MalformedHeader)?;
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
            content_length = true;
        } else if ascii_eq(name, b"transfer-encoding") {
            transfer_encoding = true;
        } else if ascii_eq(name, b"sec-websocket-extensions") {
            extension = true;
        } else if ascii_eq(name, b"sec-websocket-protocol") {
            subprotocol = true;
        }
        cursor = line_end + 2;
    }

    if content_length {
        return Err(HandshakeFailure::UnexpectedContentLength);
    }
    if transfer_encoding {
        return Err(HandshakeFailure::UnexpectedTransferEncoding);
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
    let key = crypto::canonical_nonce_key(key).map_err(|failure| match failure {
        crypto::NonceKeyError::InvalidEncoding => HandshakeFailure::InvalidKeyEncoding,
        crypto::NonceKeyError::InvalidLength { decoded } => {
            HandshakeFailure::InvalidKeyLength { decoded }
        }
    })?;
    if extension {
        return Err(HandshakeFailure::UnexpectedExtension);
    }
    if subprotocol {
        return Err(HandshakeFailure::UnexpectedSubprotocol);
    }

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
    let first_space = line
        .iter()
        .position(|byte| *byte == b' ')
        .ok_or(HandshakeFailure::MalformedRequestLine)?;
    let second_space = line[first_space + 1..]
        .iter()
        .position(|byte| *byte == b' ')
        .and_then(|offset| first_space.checked_add(offset)?.checked_add(1))
        .ok_or(HandshakeFailure::MalformedRequestLine)?;
    if first_space == 0
        || second_space == first_space + 1
        || second_space + 1 == line.len()
        || line[second_space + 1..].contains(&b' ')
    {
        return Err(HandshakeFailure::MalformedRequestLine);
    }
    if &line[..first_space] != b"GET" {
        return Err(HandshakeFailure::MethodNotGet);
    }
    let target = &line[first_space + 1..second_space];
    if target.is_empty()
        || target.first() != Some(&b'/')
        || target
            .iter()
            .copied()
            .any(|byte| !(0x21..=0x7e).contains(&byte) || byte == b'#')
    {
        return Err(HandshakeFailure::InvalidRequestTarget);
    }
    if &line[second_space + 1..] != b"HTTP/1.1" {
        return Err(HandshakeFailure::HttpVersionNot11);
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
