//! Private HTTP/1.1 opening-handshake parser mechanics.

pub(crate) fn is_canonical_response(response: &[u8], expected_accept: &[u8; 28]) -> bool {
    const PREFIX: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ";
    const SUFFIX: &[u8] = b"\r\n\r\n";
    let Some(expected_length) = PREFIX
        .len()
        .checked_add(expected_accept.len())
        .and_then(|length| length.checked_add(SUFFIX.len()))
    else {
        return false;
    };
    response.len() == expected_length
        && response.starts_with(PREFIX)
        && response[PREFIX.len()..PREFIX.len() + expected_accept.len()] == expected_accept[..]
        && response.ends_with(SUFFIX)
}
