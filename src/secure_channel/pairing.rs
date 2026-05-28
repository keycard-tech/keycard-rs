//! Pairing data for Secure Channel V1.

use crate::error::Error;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

/// Pairing data stored on the client side for Secure Channel V1.
#[derive(Debug, Clone)]
pub struct Pairing {
    pairing_key: [u8; 32],
    pairing_index: u8,
}

impl Pairing {
    /// Creates a new pairing from a derived key and slot index.
    pub fn new(pairing_key: [u8; 32], pairing_index: u8) -> Self {
        Self {
            pairing_key,
            pairing_index,
        }
    }

    /// Deserializes from bytes: byte 0 is index, bytes 1..=32 are the key.
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        if data.len() < 33 {
            return Err(Error::Tlv(format!(
                "Pairing data too short: expected 33 bytes, got {}",
                data.len()
            )));
        }
        let pairing_index = data[0];
        let mut pairing_key = [0u8; 32];
        pairing_key.copy_from_slice(&data[1..33]);
        Ok(Self {
            pairing_key,
            pairing_index,
        })
    }

    /// Serializes to bytes: index byte followed by key bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(33);
        buf.push(self.pairing_index);
        buf.extend_from_slice(&self.pairing_key);
        buf
    }

    /// Base64-decodes then calls `from_bytes`.
    pub fn from_base64(b64: &str) -> Result<Self, Error> {
        let data = BASE64
            .decode(b64)
            .map_err(|e| Error::Tlv(format!("Failed to base64-decode pairing data: {}", e)))?;
        Self::from_bytes(&data)
    }

    /// Serializes then base64-encodes.
    pub fn to_base64(&self) -> String {
        BASE64.encode(self.to_bytes())
    }

    /// Returns the pairing key.
    pub fn pairing_key(&self) -> &[u8; 32] {
        &self.pairing_key
    }

    /// Returns the pairing slot index.
    pub fn pairing_index(&self) -> u8 {
        self.pairing_index
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pairing_roundtrip() {
        let key = [0xABu8; 32];
        let pairing = Pairing::new(key, 3);
        assert_eq!(pairing.pairing_index(), 3);
        assert_eq!(pairing.pairing_key(), &key);

        let bytes = pairing.to_bytes();
        assert_eq!(bytes.len(), 33);
        assert_eq!(bytes[0], 3);

        let parsed = Pairing::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.pairing_index(), 3);
        assert_eq!(parsed.pairing_key(), &key);
    }

    #[test]
    fn test_pairing_from_bytes_too_short() {
        assert!(Pairing::from_bytes(&[0u8; 32]).is_err());
    }

    #[test]
    fn test_pairing_base64_roundtrip() {
        let key = [0xCDu8; 32];
        let pairing = Pairing::new(key, 1);
        let b64 = pairing.to_base64();
        let parsed = Pairing::from_base64(&b64).unwrap();
        assert_eq!(parsed.pairing_index(), 1);
        assert_eq!(parsed.pairing_key(), &key);
    }

    #[test]
    fn test_pairing_base64_invalid() {
        assert!(Pairing::from_base64("not-valid-base64!!").is_err());
    }
}
