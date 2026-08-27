//! Canonical RFC 4648 base64 (standard alphabet, padding), dependency-free.
//!
//! Decode is strict exactly the way the java-oracle adapter and the Go
//! reference model are strict: the input must round-trip
//! (`decode` then `encode` must reproduce the input byte-for-byte), so
//! non-canonical trailing bits, missing padding, whitespace, and URL-safe
//! characters all fail closed (`OracleEngine.base64`, `Step.payload`).

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encodes `data` as standard padded base64.
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let word = b0 << 16 | b1 << 8 | b2;
        out.push(ALPHABET[(word >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(word >> 12) as usize & 0x3f] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(word >> 6) as usize & 0x3f] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[word as usize & 0x3f] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn sextet(byte: u8) -> Option<u32> {
    match byte {
        b'A'..=b'Z' => Some(u32::from(byte - b'A')),
        b'a'..=b'z' => Some(u32::from(byte - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(byte - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decodes canonical standard base64, failing closed on anything that does
/// not round-trip byte-identically through [`encode`].
pub fn decode_canonical(encoded: &str) -> Option<Vec<u8>> {
    let bytes = encoded.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for (index, chunk) in bytes.chunks_exact(4).enumerate() {
        let last_chunk = (index + 1) * 4 == bytes.len();
        let padding = chunk.iter().filter(|&&b| b == b'=').count();
        if padding > 0 && (!last_chunk || padding > 2 || chunk[..4 - padding].contains(&b'=')) {
            return None;
        }
        let mut word = 0u32;
        for &b in &chunk[..4 - padding] {
            word = word << 6 | sextet(b)?;
        }
        word <<= 6 * padding as u32;
        out.push((word >> 16) as u8);
        if padding < 2 {
            out.push((word >> 8) as u8);
        }
        if padding < 1 {
            out.push(word as u8);
        }
    }
    // Canonicality: re-encoding must reproduce the input exactly.
    if encode(&out) != encoded {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_matches_rfc4648_vectors() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg==");
        assert_eq!(encode(b"fo"), "Zm8=");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"foob"), "Zm9vYg==");
        assert_eq!(encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn decode_round_trips_canonical_inputs() {
        for data in [
            &b""[..],
            b"f",
            b"fo",
            b"foo",
            b"\x00\xff\x80",
            b"hello world",
        ] {
            let encoded = encode(data);
            assert_eq!(decode_canonical(&encoded).as_deref(), Some(data));
        }
    }

    #[test]
    fn decode_rejects_non_canonical_forms() {
        assert!(decode_canonical("Zg").is_none(), "missing padding");
        assert!(decode_canonical("Zg= =").is_none(), "interior space");
        assert!(decode_canonical("Zh==").is_none(), "non-zero trailing bits");
        assert!(
            decode_canonical("Zm8=Zm8=").is_none(),
            "interior padding chunk"
        );
        assert!(decode_canonical("Z-8=").is_none(), "url-safe alphabet");
        assert!(decode_canonical("====").is_none(), "all padding");
        assert!(decode_canonical("Zm9v\n").is_none(), "trailing newline");
    }
}
