//! RFC 6455 masking over arbitrary payload ranges.

/// Applies the RFC 6455 repeating four-byte XOR mask in place.
///
/// `payload_offset` is the range's offset within the complete frame payload,
/// allowing callers to mask or unmask independently arrived chunks without
/// restarting the key index.
pub fn apply_mask_in_place(bytes: &mut [u8], key: [u8; 4], payload_offset: usize) {
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte ^= key[payload_offset.wrapping_add(index) % key.len()];
    }
}

#[cfg(kani)]
mod proofs {
    use super::apply_mask_in_place;

    const PROOF_BYTES: usize = 4;

    #[kani::proof]
    #[kani::unwind(5)]
    fn prove_mask_equation() {
        let input: [u8; PROOF_BYTES] = kani::any();
        let key: [u8; 4] = kani::any();
        let offset: usize = kani::any();
        let mut output = input;

        apply_mask_in_place(&mut output, key, offset);

        for index in 0..PROOF_BYTES {
            assert_eq!(
                output[index],
                input[index] ^ key[offset.wrapping_add(index) % key.len()]
            );
        }
    }

    #[kani::proof]
    #[kani::unwind(9)]
    fn prove_mask_involution() {
        let input: [u8; PROOF_BYTES] = kani::any();
        let key: [u8; 4] = kani::any();
        let offset: usize = kani::any();
        let mut output = input;

        apply_mask_in_place(&mut output, key, offset);
        apply_mask_in_place(&mut output, key, offset);

        assert_eq!(output, input);
    }
}
