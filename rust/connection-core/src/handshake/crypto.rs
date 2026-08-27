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

fn encode_triplet(first: u8, second: u8, third: u8, output: &mut [u8]) {
    output[0] = BASE64[usize::from(first >> 2)];
    output[1] = BASE64[usize::from(((first & 0x03) << 4) | (second >> 4))];
    output[2] = BASE64[usize::from(((second & 0x0f) << 2) | (third >> 6))];
    output[3] = BASE64[usize::from(third & 0x3f)];
}
