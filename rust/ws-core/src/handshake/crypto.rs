//! Accept-key derivation: SHA-1 + base64, dependency-free safe Rust.
//!
//! Provenance: the SHA-1 compression function and base64 encoding tables are
//! borrowed from the Codex plane (`connection-core/src/handshake/crypto.rs`,
//! trees `19f7067`/`b6d4b99`) and adapted: the Codex `derive_accept` was
//! hard-wired to a validated 24-byte key (their RFC posture); shipped Java's
//! `generateFinalKey` (Draft_6455.java:832-841) hashes ANY trimmed non-empty
//! string, so the derivation here is generalized to arbitrary-length input
//! (multi-block SHA-1 with standard padding). The Codex RFC key validator
//! (`canonical_nonce_key`) is deliberately NOT borrowed: Java never
//! validates the key's encoding or decoded length (live divergences
//! HS_KEY_NOT_BASE64 / HS_KEY_LENGTH), so no such check may exist on the
//! server path.
//!
//! The proof-target symbol `ws_core::framing::Draft6455::generate_accept_key`
//! (target.formal.handshake.accept-derivation) is implemented here as an
//! inherent method on [`Draft6455`].

use super::http::java_trim;
use crate::framing::Draft6455;

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The RFC 6455 / Draft_6455.java accept GUID.
const GUID: &[u8; 36] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

impl Draft6455 {
    /// `generateFinalKey` (Draft_6455.java:832-841): SHA-1 over
    /// `String.trim(key)` + the accept GUID, base64-encoded. Java hashes any
    /// trimmed string — including empty, non-base64, and wrong-length keys
    /// (the caller gates the empty case, mirroring
    /// `postProcessHandshakeResponseAsServer`).
    #[must_use]
    pub fn generate_accept_key(key: &str) -> String {
        let trimmed = java_trim(key);
        let mut message = Vec::with_capacity(trimmed.len() + GUID.len());
        // Latin-1 projection: the parse layer produced this string from
        // bytes one-to-one, so this re-projection is lossless for every
        // calibrated (ASCII) input.
        message.extend(trimmed.chars().map(|c| c as u32 as u8));
        message.extend_from_slice(GUID);
        let digest = sha1(&message);
        encode_base64(&digest)
    }
}

/// Deterministic client nonce key: base64 of a 16-byte nonce
/// (borrowed Codex `encode_nonce`, byte-identical output).
pub(crate) fn encode_nonce(nonce: [u8; 16]) -> [u8; 24] {
    let mut output = [b'='; 24];
    let mut input_index = 0usize;
    let mut output_index = 0usize;
    while input_index + 3 <= nonce.len() {
        encode_triplet(
            nonce[input_index],
            nonce[input_index + 1],
            nonce[input_index + 2],
            &mut output[output_index..output_index + 4],
        );
        input_index += 3;
        output_index += 4;
    }
    let first = nonce[input_index];
    output[output_index] = BASE64[usize::from(first >> 2)];
    output[output_index + 1] = BASE64[usize::from((first & 0x03) << 4)];
    output
}

/// Standard base64 (with padding) over arbitrary bytes.
fn encode_base64(data: &[u8]) -> String {
    let mut output = Vec::with_capacity(data.len().div_ceil(3) * 4);
    let mut chunks = data.chunks_exact(3);
    for chunk in &mut chunks {
        let mut quad = [0u8; 4];
        encode_triplet(chunk[0], chunk[1], chunk[2], &mut quad);
        output.extend_from_slice(&quad);
    }
    match chunks.remainder() {
        [] => {}
        [first] => {
            output.push(BASE64[usize::from(first >> 2)]);
            output.push(BASE64[usize::from((first & 0x03) << 4)]);
            output.push(b'=');
            output.push(b'=');
        }
        [first, second] => {
            output.push(BASE64[usize::from(first >> 2)]);
            output.push(BASE64[usize::from(((first & 0x03) << 4) | (second >> 4))]);
            output.push(BASE64[usize::from((second & 0x0f) << 2)]);
            output.push(b'=');
        }
        _ => unreachable!("chunks_exact(3) remainder is at most 2 bytes"),
    }
    String::from_utf8(output).expect("base64 alphabet is ASCII")
}

/// SHA-1 over arbitrary-length input (standard padding; multi-block).
fn sha1(message: &[u8]) -> [u8; 20] {
    let mut state = [
        0x6745_2301u32,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    let mut blocks = message.chunks_exact(64);
    for block in &mut blocks {
        sha1_compress(&mut state, block);
    }
    let remainder = blocks.remainder();
    let mut tail = [0u8; 128];
    tail[..remainder.len()].copy_from_slice(remainder);
    tail[remainder.len()] = 0x80;
    let bit_length = (message.len() as u64).wrapping_mul(8);
    let tail_len = if remainder.len() + 1 + 8 <= 64 {
        64
    } else {
        128
    };
    tail[tail_len - 8..tail_len].copy_from_slice(&bit_length.to_be_bytes());
    sha1_compress(&mut state, &tail[..64]);
    if tail_len == 128 {
        sha1_compress(&mut state, &tail[64..]);
    }
    let mut digest = [0u8; 20];
    for (index, word) in state.into_iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// Borrowed Codex SHA-1 compression function (verbatim).
fn sha1_compress(state: &mut [u32; 5], block: &[u8]) {
    let mut words = [0u32; 80];
    for (index, bytes) in block.chunks_exact(4).enumerate() {
        words[index] = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }
    for index in 16..80 {
        words[index] =
            (words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16])
                .rotate_left(1);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    for (index, word) in words.into_iter().enumerate() {
        let (function, constant) = match index {
            0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999),
            20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
            _ => (b ^ c ^ d, 0xca62_c1d6),
        };
        let temporary = a
            .rotate_left(5)
            .wrapping_add(function)
            .wrapping_add(e)
            .wrapping_add(constant)
            .wrapping_add(word);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temporary;
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

fn encode_triplet(first: u8, second: u8, third: u8, output: &mut [u8]) {
    output[0] = BASE64[usize::from(first >> 2)];
    output[1] = BASE64[usize::from(((first & 0x03) << 4) | (second >> 4))];
    output[2] = BASE64[usize::from(((second & 0x0f) << 2) | (third >> 6))];
    output[3] = BASE64[usize::from(third & 0x3f)];
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6455 section 1.3 sample derivation.
    #[test]
    fn rfc_sample_accept() {
        assert_eq!(
            Draft6455::generate_accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    /// Live-recorded pinned-jar derivation (us005.hs.0000, protected live
    /// transcript): the real Java produced this exact accept value.
    #[test]
    fn live_recorded_accept() {
        assert_eq!(
            Draft6455::generate_accept_key("7Qg8Jw3qQL4ERr/n83YN7w=="),
            "FJGDqEtc/7v2gIxV23nYHrpYQtU="
        );
    }

    /// Java trims (chars <= U+0020) before hashing, so padded spellings of
    /// the same key derive identically.
    #[test]
    fn accept_trims_like_java() {
        assert_eq!(
            Draft6455::generate_accept_key("  dGhlIHNhbXBsZSBub25jZQ==\t "),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    /// Java hashes non-base64 and wrong-length keys without complaint
    /// (HS_KEY_NOT_BASE64 / HS_KEY_LENGTH live divergences): the derivation
    /// must be total over trimmed strings.
    #[test]
    fn accept_is_total_over_arbitrary_keys() {
        // SHA-1("!!definitely-not-base64!!258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
        // is well-defined; only stability matters here (exact value is pinned
        // by the live handshake exam).
        let value = Draft6455::generate_accept_key("!!definitely-not-base64!!");
        assert_eq!(value.len(), 28);
        assert_ne!(
            value,
            Draft6455::generate_accept_key("other"),
            "distinct keys derive distinct accepts"
        );
    }

    /// Multi-block coverage: input longer than one SHA-1 block.
    #[test]
    fn accept_handles_multi_block_keys() {
        let long_key = "A".repeat(200);
        let value = Draft6455::generate_accept_key(&long_key);
        assert_eq!(value.len(), 28);
    }

    #[test]
    fn nonce_encoding_matches_standard_base64() {
        let nonce = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        assert_eq!(&encode_nonce(nonce), b"AAECAwQFBgcICQoLDA0ODw==");
    }
}
