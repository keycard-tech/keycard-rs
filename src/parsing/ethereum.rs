//! Ethereum address derivation utilities.

use sha3::{Digest, Keccak256};

/// Computes an Ethereum address from a public key.
///
/// Takes Keccak-256 of the public key bytes starting from index 1
/// (skipping the 0x04 prefix for uncompressed keys) and returns
/// the last 20 bytes of the hash.
///
/// # Arguments
/// * `public_key` - Uncompressed secp256k1 public key (65 bytes, starting with 0x04)
///
/// # Returns
/// 20-byte Ethereum address
pub fn to_ethereum_address(public_key: &[u8]) -> [u8; 20] {
    let mut hasher = Keccak256::new();
    // Skip the 0x04 prefix byte
    hasher.update(&public_key[1..]);
    let hash: [u8; 32] = hasher.finalize().into();
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethereum_address_length() {
        // Use a dummy 65-byte public key
        let mut pub_key = vec![0x04];
        pub_key.extend(std::iter::repeat(0x42).take(64));
        let addr = to_ethereum_address(&pub_key);
        assert_eq!(addr.len(), 20);
    }

    #[test]
    fn test_known_vector() {
        // Public key from Ethereum yellow paper test vector
        // Keccak-256 of pubkey[1:] = 8c9564d6883a96096c8469d63e9003153d9a39d3f57b126b0c38513d5e289c3e
        // Address = last 20 bytes
        let pub_key_hex = "0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b23522cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6";
        let pub_key = hex_decode(pub_key_hex);
        let addr = to_ethereum_address(&pub_key);
        // Expected: 3e9003153d9a39d3f57b126b0c38513d5e289c3e
        let expected = hex_decode("3e9003153d9a39d3f57b126b0c38513d5e289c3e");
        assert_eq!(addr, <[u8; 20]>::try_from(expected).unwrap());
    }

    fn hex_decode(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
}
