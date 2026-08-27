use crate::handshake::crypto;

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
    },
    Opened,
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
        maximum: usize,
    ) -> Result<Box<[u8]>, u64> {
        let key = crypto::encode_nonce(nonce);
        let expected_accept = crypto::derive_accept(&key);
        let request = canonical_request(&descriptor, &key).ok_or(u64::MAX)?;
        if request.len() > maximum {
            return Err(u64::try_from(request.len()).unwrap_or(u64::MAX));
        }
        self.phase = ClientPhase::AwaitingResponse {
            descriptor,
            expected_accept,
        };
        Ok(request)
    }

    pub(crate) fn has_started(&self) -> bool {
        !matches!(self.phase, ClientPhase::AwaitingStart)
    }

    pub(crate) fn accept_canonical_response(
        &mut self,
        response: &[u8],
    ) -> Option<ClientRequestDescriptor> {
        let ClientPhase::AwaitingResponse {
            descriptor,
            expected_accept,
        } = &self.phase
        else {
            return None;
        };
        if !crate::handshake::http::is_canonical_response(response, expected_accept) {
            return None;
        }
        let descriptor = descriptor.clone();
        self.phase = ClientPhase::Opened;
        Some(descriptor)
    }
}

fn canonical_request(descriptor: &ClientRequestDescriptor, key: &[u8; 24]) -> Option<Box<[u8]>> {
    const GET: &[u8] = b"GET ";
    const HTTP_HOST: &[u8] = b" HTTP/1.1\r\nHost: ";
    const FIXED_AFTER_HOST: &[u8] =
        b"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ";
    const VERSION: &[u8] = b"\r\nSec-WebSocket-Version: 13\r\n\r\n";

    let length = GET
        .len()
        .checked_add(descriptor.request_target.len())?
        .checked_add(HTTP_HOST.len())?
        .checked_add(descriptor.host.len())?
        .checked_add(FIXED_AFTER_HOST.len())?
        .checked_add(key.len())?
        .checked_add(VERSION.len())?;
    let mut request = Vec::with_capacity(length);
    request.extend_from_slice(GET);
    request.extend_from_slice(descriptor.request_target.as_bytes());
    request.extend_from_slice(HTTP_HOST);
    request.extend_from_slice(descriptor.host.as_bytes());
    request.extend_from_slice(FIXED_AFTER_HOST);
    request.extend_from_slice(key);
    request.extend_from_slice(VERSION);
    debug_assert_eq!(request.len(), length);
    Some(request.into_boxed_slice())
}
