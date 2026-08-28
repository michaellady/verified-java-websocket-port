use crate::handshake::crypto;
use crate::handshake::http::{ParseProgress, ResponseParser};
use crate::{HandshakeFailure, LimitKind};

const DESCRIPTOR_FIELD_MAX: usize = 1_048_576;

/// Caller-owned origin-form target and Host value for a client handshake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientRequestDescriptor {
    request_target: Box<str>,
    host: Box<str>,
}

/// Why client request wire fields could not be represented canonically.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientRequestDescriptorError {
    /// The target did not begin with `/` as an origin-form target must.
    RequestTargetNotOriginForm,
    /// The target contained a non-ASCII, whitespace, control, or injection byte.
    InvalidRequestTargetByte,
    /// The target exceeded the immutable descriptor hard ceiling.
    RequestTargetTooLong,
    /// The Host value was empty.
    EmptyHost,
    /// The Host value contained a non-ASCII, whitespace, control, or injection byte.
    InvalidHostByte,
    /// The Host value exceeded the immutable descriptor hard ceiling.
    HostTooLong,
}

impl ClientRequestDescriptor {
    /// Validates and owns the two caller-selected HTTP wire fields.
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

const fn is_visible_ascii(byte: u8) -> bool {
    byte >= 0x21 && byte <= 0x7e
}

#[derive(Debug)]
pub(crate) struct ClientHandshake {
    phase: ClientPhase,
}

#[derive(Debug)]
enum ClientPhase {
    AwaitingStart,
    AwaitingResponse {
        descriptor: ClientRequestDescriptor,
        expected_accept: [u8; 28],
        parser: ResponseParser,
    },
    Opened,
    Failed,
}

impl ClientHandshake {
    pub(crate) const fn new() -> Self {
        Self {
            phase: ClientPhase::AwaitingStart,
        }
    }

    pub(crate) fn start(
        &mut self,
        descriptor: ClientRequestDescriptor,
        nonce: [u8; 16],
        maximum_bytes: usize,
        maximum_line_bytes: usize,
        maximum_header_count: usize,
    ) -> Result<Box<[u8]>, ClientLimitExceeded> {
        let key = crypto::encode_nonce(nonce);
        let expected_accept = crypto::derive_accept(&key);
        let (line_lengths, total) =
            canonical_request_lengths(&descriptor).ok_or(ClientLimitExceeded {
                limit: LimitKind::HandshakeBytes,
                attempted: u64::MAX,
            })?;
        if total > maximum_bytes {
            return Err(ClientLimitExceeded {
                limit: LimitKind::HandshakeBytes,
                attempted: u64::try_from(total).unwrap_or(u64::MAX),
            });
        }
        if let Some(attempted) = line_lengths
            .into_iter()
            .find(|length| *length > maximum_line_bytes)
        {
            return Err(ClientLimitExceeded {
                limit: LimitKind::HandshakeHeaderLineBytes,
                attempted: u64::try_from(attempted).unwrap_or(u64::MAX),
            });
        }
        const REQUEST_HEADER_COUNT: usize = 5;
        if REQUEST_HEADER_COUNT > maximum_header_count {
            return Err(ClientLimitExceeded {
                limit: LimitKind::HandshakeHeaderCount,
                attempted: u64::try_from(REQUEST_HEADER_COUNT).unwrap_or(u64::MAX),
            });
        }
        let request = canonical_request(&descriptor, &key, total);
        self.phase = ClientPhase::AwaitingResponse {
            descriptor,
            expected_accept,
            parser: ResponseParser::new(maximum_bytes, maximum_line_bytes, maximum_header_count),
        };
        debug_assert!(matches!(self.phase, ClientPhase::AwaitingResponse { .. }));
        Ok(request)
    }

    pub(crate) fn has_started(&self) -> bool {
        !matches!(self.phase, ClientPhase::AwaitingStart)
    }

    pub(crate) fn mark_failed(&mut self) {
        self.phase = ClientPhase::Failed;
    }

    pub(crate) fn consume_response(&mut self, response: &[u8]) -> ClientResponse {
        let ClientPhase::AwaitingResponse {
            descriptor,
            expected_accept,
            parser,
        } = &mut self.phase
        else {
            return ClientResponse::NotAwaiting;
        };
        match parser.consume(response, expected_accept) {
            ParseProgress::Incomplete => ClientResponse::Incomplete,
            ParseProgress::LimitExceeded { limit, attempted } => {
                ClientResponse::LimitExceeded { limit, attempted }
            }
            ParseProgress::Complete(Err(failure)) => ClientResponse::Rejected(failure),
            ParseProgress::Complete(Ok(())) => {
                let descriptor = descriptor.clone();
                self.phase = ClientPhase::Opened;
                ClientResponse::Opened(descriptor)
            }
        }
    }
}

pub(crate) enum ClientResponse {
    NotAwaiting,
    Incomplete,
    Opened(ClientRequestDescriptor),
    Rejected(HandshakeFailure),
    LimitExceeded { limit: LimitKind, attempted: u64 },
}

#[derive(Debug)]
pub(crate) struct ClientLimitExceeded {
    pub(crate) limit: LimitKind,
    pub(crate) attempted: u64,
}

fn canonical_request_lengths(descriptor: &ClientRequestDescriptor) -> Option<([usize; 6], usize)> {
    let lines = [
        4usize
            .checked_add(descriptor.request_target.len())?
            .checked_add(11)?,
        6usize.checked_add(descriptor.host.len())?.checked_add(2)?,
        b"Upgrade: websocket\r\n".len(),
        b"Connection: Upgrade\r\n".len(),
        b"Sec-WebSocket-Key: "
            .len()
            .checked_add(24)?
            .checked_add(2)?,
        b"Sec-WebSocket-Version: 13\r\n".len(),
    ];
    let total = lines.into_iter().try_fold(2usize, usize::checked_add)?;
    Some((lines, total))
}

fn canonical_request(
    descriptor: &ClientRequestDescriptor,
    key: &[u8; 24],
    length: usize,
) -> Box<[u8]> {
    const GET: &[u8] = b"GET ";
    const HTTP_HOST: &[u8] = b" HTTP/1.1\r\nHost: ";
    const FIXED_AFTER_HOST: &[u8] =
        b"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ";
    const VERSION: &[u8] = b"\r\nSec-WebSocket-Version: 13\r\n\r\n";

    let mut request = Vec::with_capacity(length);
    request.extend_from_slice(GET);
    request.extend_from_slice(descriptor.request_target.as_bytes());
    request.extend_from_slice(HTTP_HOST);
    request.extend_from_slice(descriptor.host.as_bytes());
    request.extend_from_slice(FIXED_AFTER_HOST);
    request.extend_from_slice(key);
    request.extend_from_slice(VERSION);
    debug_assert_eq!(request.len(), length);
    request.into_boxed_slice()
}

#[cfg(test)]
mod tests {
    use super::{ClientHandshake, ClientRequestDescriptor, ClientResponse};
    use crate::LimitKind;

    #[test]
    fn canonical_request_admits_each_exact_limit_and_rejects_one_less() {
        let descriptor = ClientRequestDescriptor::try_new("/chat", "server.example.com").unwrap();
        let nonce = *b"the sample nonce";
        let mut unconstrained = ClientHandshake::new();
        let request = unconstrained
            .start(
                descriptor.clone(),
                nonce,
                usize::MAX,
                usize::MAX,
                usize::MAX,
            )
            .unwrap();
        let total = request.len();
        let longest_line = request
            .split_inclusive(|byte| *byte == b'\n')
            .map(<[u8]>::len)
            .max()
            .unwrap();

        assert!(
            ClientHandshake::new()
                .start(descriptor.clone(), nonce, total, longest_line, 5)
                .is_ok()
        );
        let total_failure = ClientHandshake::new()
            .start(descriptor.clone(), nonce, total - 1, longest_line, 5)
            .unwrap_err();
        assert_eq!(total_failure.limit, LimitKind::HandshakeBytes);
        assert_eq!(total_failure.attempted, u64::try_from(total).unwrap());
        let line_failure = ClientHandshake::new()
            .start(descriptor.clone(), nonce, total, longest_line - 1, 5)
            .unwrap_err();
        assert_eq!(line_failure.limit, LimitKind::HandshakeHeaderLineBytes);
        assert_eq!(line_failure.attempted, u64::try_from(longest_line).unwrap());
        let count_failure = ClientHandshake::new()
            .start(descriptor, nonce, total, longest_line, 4)
            .unwrap_err();
        assert_eq!(count_failure.limit, LimitKind::HandshakeHeaderCount);
        assert_eq!(count_failure.attempted, 5);
    }

    #[test]
    fn marking_failed_releases_the_partial_response_parser() {
        let descriptor = ClientRequestDescriptor::try_new("/", "example.com").unwrap();
        let mut handshake = ClientHandshake::new();
        handshake.start(descriptor, [0; 16], 4096, 512, 32).unwrap();
        assert!(matches!(
            handshake.consume_response(b"HTTP/1.1 101 Switching"),
            ClientResponse::Incomplete
        ));
        handshake.mark_failed();
        assert!(matches!(
            handshake.consume_response(b"ignored"),
            ClientResponse::NotAwaiting
        ));
    }
}
