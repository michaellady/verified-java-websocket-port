const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

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

pub(crate) enum NonceKeyError {
    InvalidEncoding,
    InvalidLength { decoded: u64 },
}

pub(crate) fn canonical_nonce_key(key: &[u8]) -> Result<[u8; 24], NonceKeyError> {
    if !key.len().is_multiple_of(4) {
        return Err(NonceKeyError::InvalidEncoding);
    }
    let padding = key.iter().rev().take_while(|byte| **byte == b'=').count();
    if padding > 2 {
        return Err(NonceKeyError::InvalidEncoding);
    }
    let data_end = key.len() - padding;
    if key[..data_end].contains(&b'=')
        || key[..data_end]
            .iter()
            .copied()
            .any(|byte| decode_base64(byte).is_none())
    {
        return Err(NonceKeyError::InvalidEncoding);
    }
    if padding == 2
        && (data_end == 0 || decode_base64(key[data_end - 1]).is_none_or(|value| value & 0x0f != 0))
        || padding == 1
            && (data_end == 0
                || decode_base64(key[data_end - 1]).is_none_or(|value| value & 0x03 != 0))
    {
        return Err(NonceKeyError::InvalidEncoding);
    }
    let decoded = key
        .len()
        .checked_div(4)
        .and_then(|groups| groups.checked_mul(3))
        .and_then(|bytes| bytes.checked_sub(padding))
        .ok_or(NonceKeyError::InvalidEncoding)?;
    if decoded != 16 {
        return Err(NonceKeyError::InvalidLength {
            decoded: u64::try_from(decoded).unwrap_or(u64::MAX),
        });
    }
    if key.len() != 24 || padding != 2 {
        return Err(NonceKeyError::InvalidEncoding);
    }
    let mut nonce = [0u8; 16];
    let mut input_index = 0usize;
    let mut output_index = 0usize;
    while input_index < 20 {
        let first = decode_base64(key[input_index]).ok_or(NonceKeyError::InvalidEncoding)?;
        let second = decode_base64(key[input_index + 1]).ok_or(NonceKeyError::InvalidEncoding)?;
        let third = decode_base64(key[input_index + 2]).ok_or(NonceKeyError::InvalidEncoding)?;
        let fourth = decode_base64(key[input_index + 3]).ok_or(NonceKeyError::InvalidEncoding)?;
        nonce[output_index] = (first << 2) | (second >> 4);
        nonce[output_index + 1] = (second << 4) | (third >> 2);
        nonce[output_index + 2] = (third << 6) | fourth;
        input_index += 4;
        output_index += 3;
    }
    let first = decode_base64(key[20]).ok_or(NonceKeyError::InvalidEncoding)?;
    let second = decode_base64(key[21]).ok_or(NonceKeyError::InvalidEncoding)?;
    if second & 0x0f != 0 {
        return Err(NonceKeyError::InvalidEncoding);
    }
    nonce[15] = (first << 2) | (second >> 4);
    if encode_nonce(nonce).as_slice() != key {
        return Err(NonceKeyError::InvalidEncoding);
    }
    let mut canonical = [0u8; 24];
    canonical.copy_from_slice(key);
    Ok(canonical)
}

pub(crate) fn derive_accept(key: &[u8; 24]) -> [u8; 28] {
    const GUID: &[u8; 36] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut padded = [0u8; 128];
    padded[..key.len()].copy_from_slice(key);
    padded[key.len()..key.len() + GUID.len()].copy_from_slice(GUID);
    let message_len = key.len() + GUID.len();
    padded[message_len] = 0x80;
    padded[120..].copy_from_slice(&480u64.to_be_bytes());

    let mut state = [
        0x6745_2301u32,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    sha1_compress(&mut state, &padded[..64]);
    sha1_compress(&mut state, &padded[64..]);

    let mut digest = [0u8; 20];
    for (index, word) in state.into_iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    encode_digest(digest)
}

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

fn encode_digest(digest: [u8; 20]) -> [u8; 28] {
    let mut output = [b'='; 28];
    let mut input_index = 0usize;
    let mut output_index = 0usize;
    while input_index + 3 <= 18 {
        encode_triplet(
            digest[input_index],
            digest[input_index + 1],
            digest[input_index + 2],
            &mut output[output_index..output_index + 4],
        );
        input_index += 3;
        output_index += 4;
    }
    let first = digest[18];
    let second = digest[19];
    output[24] = BASE64[usize::from(first >> 2)];
    output[25] = BASE64[usize::from(((first & 0x03) << 4) | (second >> 4))];
    output[26] = BASE64[usize::from((second & 0x0f) << 2)];
    output
}

fn decode_base64(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn encode_triplet(first: u8, second: u8, third: u8, output: &mut [u8]) {
    output[0] = BASE64[usize::from(first >> 2)];
    output[1] = BASE64[usize::from(((first & 0x03) << 4) | (second >> 4))];
    output[2] = BASE64[usize::from(((second & 0x0f) << 2) | (third >> 6))];
    output[3] = BASE64[usize::from(third & 0x3f)];
}
