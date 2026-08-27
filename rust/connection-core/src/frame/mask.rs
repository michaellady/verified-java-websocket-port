//! RFC 6455 masking over arbitrary payload ranges.

/// Applies the RFC 6455 repeating four-byte XOR mask in place.
///
/// `payload_offset` is the range's offset within the complete frame payload,
/// allowing callers to mask or unmask independently arrived chunks without
/// restarting the key index.
pub fn apply_mask_in_place(bytes: &mut [u8], key: [u8; 4], payload_offset: usize) {
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte ^= key[(payload_offset + index) % key.len()];
    }
}
