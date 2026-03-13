//! Minimal SCALE encoding helpers and Substrate hashing utilities.
//! No Substrate dependencies — pure Rust implementations.

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;

/// Compute twox128 hash (used for Substrate storage key prefixes).
pub fn twox128(data: &[u8]) -> [u8; 16] {
    use std::hash::Hasher;

    let mut h0 = twox_hash::XxHash64::with_seed(0);
    h0.write(data);
    let r0 = h0.finish();

    let mut h1 = twox_hash::XxHash64::with_seed(1);
    h1.write(data);
    let r1 = h1.finish();

    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&r0.to_le_bytes());
    out[8..].copy_from_slice(&r1.to_le_bytes());
    out
}

/// Compute blake2b-128 hash (used for Blake2_128Concat storage key hasher).
pub fn blake2_128(data: &[u8]) -> [u8; 16] {
    let mut hasher = Blake2bVar::new(16).expect("valid output size");
    hasher.update(data);
    let mut out = [0u8; 16];
    hasher.finalize_variable(&mut out).expect("valid");
    out
}

/// Decode a SCALE compact-encoded u32. Returns (value, bytes_consumed).
pub fn decode_compact_u32(data: &[u8]) -> Option<(u32, usize)> {
    if data.is_empty() {
        return None;
    }
    let mode = data[0] & 0b11;
    match mode {
        0b00 => Some(((data[0] >> 2) as u32, 1)),
        0b01 => {
            if data.len() < 2 {
                return None;
            }
            let val = ((data[0] as u16 | ((data[1] as u16) << 8)) >> 2) as u32;
            Some((val, 2))
        }
        0b10 => {
            if data.len() < 4 {
                return None;
            }
            let val = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) >> 2;
            Some((val, 4))
        }
        _ => None, // Big integer mode — not expected for our use cases
    }
}

/// Decode an SS58-encoded address to raw 32-byte public key.
pub fn ss58_decode(address: &str) -> Option<[u8; 32]> {
    let decoded = bs58_decode(address)?;

    // Simple SS58: 1 byte prefix + 32 bytes pubkey + 2 bytes checksum = 35 bytes
    if decoded.len() != 35 {
        return None;
    }

    // Verify checksum
    let payload = &decoded[..33]; // prefix + pubkey
    let expected_checksum = &decoded[33..35];

    let mut hasher = Blake2bVar::new(64).expect("valid size");
    hasher.update(b"SS58PRE");
    hasher.update(payload);
    let mut hash = [0u8; 64];
    hasher.finalize_variable(&mut hash).expect("valid");

    if hash[0] != expected_checksum[0] || hash[1] != expected_checksum[1] {
        return None;
    }

    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&decoded[1..33]);
    Some(pubkey)
}

/// Minimal base58 decoder.
fn bs58_decode(input: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    if input.is_empty() {
        return Some(Vec::new());
    }

    // Build reverse lookup
    let mut table = [255u8; 128];
    for (i, &c) in ALPHABET.iter().enumerate() {
        table[c as usize] = i as u8;
    }

    // Count leading '1's (zeros in base58)
    let leading_zeros = input.chars().take_while(|&c| c == '1').count();

    // Convert from base58
    let mut bytes: Vec<u8> = Vec::new();
    for c in input.chars() {
        if c as usize >= 128 {
            return None;
        }
        let val = table[c as usize];
        if val == 255 {
            return None;
        }

        let mut carry = val as u32;
        for byte in bytes.iter_mut() {
            carry += (*byte as u32) * 58;
            *byte = (carry & 0xFF) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xFF) as u8);
            carry >>= 8;
        }
    }

    // Construct result: leading zeros + decoded bytes (reversed)
    let mut result = vec![0u8; leading_zeros];
    result.extend(bytes.iter().rev());
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ss58_decode_alice() {
        // Alice's SS58 address (substrate generic prefix 42)
        let alice = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
        let pubkey = ss58_decode(alice).expect("should decode");
        // Alice's public key is well-known
        assert_eq!(
            hex::encode(pubkey),
            "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"
        );
    }

    #[test]
    fn test_twox128() {
        // Known twox128 of "System"
        let hash = twox128(b"System");
        assert_eq!(
            hex::encode(hash),
            "26aa394eea5630e07c48ae0c9558cef7"
        );
    }

    #[test]
    fn test_compact_decode() {
        assert_eq!(decode_compact_u32(&[0x00]), Some((0, 1)));
        assert_eq!(decode_compact_u32(&[0x04]), Some((1, 1)));
        assert_eq!(decode_compact_u32(&[0xfc]), Some((63, 1)));
        assert_eq!(decode_compact_u32(&[0x01, 0x01]), Some((64, 2)));
    }
}
