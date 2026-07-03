//! BIP32 keypair with TLV serialization.

use hmac::{Hmac, KeyInit, Mac};
use k256::{Sec1Point, SecretKey};
use sha2::Sha512;
use zeroize::Zeroize;

use crate::constants::BIP32_HMAC_KEY;
use crate::error::Error;
use crate::parsing::ethereum::to_ethereum_address;
use crate::tlv::{
    BerTlvReader, BerTlvWriter, TLV_CHAIN_CODE, TLV_KEY_TEMPLATE, TLV_PUB_KEY, TLV_PRIV_KEY,
};

type HmacSha512 = Hmac<Sha512>;

/// Strips a leading zero byte from a private key, if present.
///
/// A 32-byte secp256k1 private key is sometimes prefixed with a sign/padding
/// zero byte (e.g. from a BER INTEGER encoding); this normalizes it back to
/// the raw 32-byte form expected by `SecretKey::from_slice` and the card.
fn strip_leading_zero(pk: &[u8]) -> &[u8] {
    if pk.first() == Some(&0) && pk.len() > 32 {
        &pk[1..]
    } else {
        pk
    }
}

/// Represents a BIP32 keypair.
///
/// Can be a master key or any other key in the derivation path.
#[derive(Debug, Clone)]
pub struct Bip32KeyPair {
    private_key: Option<Vec<u8>>,
    chain_code: Option<Vec<u8>>,
    public_key: Vec<u8>,
}

impl Bip32KeyPair {
    /// Derives a master key from a BIP32 binary seed.
    ///
    /// Uses `HMAC-SHA512(key="Bitcoin seed", msg=seed)`.
    /// Left 32 bytes = private key, right 32 bytes = chain code.
    pub fn from_binary_seed(seed: &[u8]) -> Self {
        let mut mac = HmacSha512::new_from_slice(BIP32_HMAC_KEY)
            .expect("HMAC can take key of any size");
        mac.update(seed);
        let mut bytes = mac.finalize().into_bytes();

        let private_key = bytes[0..32].to_vec();
        let chain_code = bytes[32..64].to_vec();
        // bytes holds the private key and chain code concatenated; scrub it
        // now that they've been copied into their own (zeroize-on-drop) fields.
        bytes.as_mut_slice().zeroize();

        Self::new(Some(private_key), Some(chain_code), None)
    }

    /// Parses a BIP32 keypair from TLV data (e.g., EXPORT KEY response).
    pub fn from_tlv(tlv_data: &[u8]) -> Result<Self, Error> {
        let mut reader = BerTlvReader::new(tlv_data);
        reader
            .enter_constructed(TLV_KEY_TEMPLATE)
            .map_err(|e| Error::Tlv(format!("Failed to enter key template: {}", e)))?;

        let mut pub_key: Option<Vec<u8>> = None;
        let mut priv_key: Option<Vec<u8>> = None;
        let mut chain_code: Option<Vec<u8>> = None;

        // Tags appear in order: PUB_KEY (optional), PRIV_KEY, CHAIN_CODE (optional)
        if reader.next_tag_is(TLV_PUB_KEY) {
            pub_key = Some(
                reader
                    .read_primitive(TLV_PUB_KEY)
                    .map_err(|e| Error::Tlv(format!("Failed to read public key: {}", e)))?,
            );
        }

        if reader.next_tag_is(TLV_PRIV_KEY) {
            priv_key = Some(
                reader
                    .read_primitive(TLV_PRIV_KEY)
                    .map_err(|e| Error::Tlv(format!("Failed to read private key: {}", e)))?,
            );
        }

        if reader.next_tag_is(TLV_CHAIN_CODE) {
            chain_code = Some(
                reader
                    .read_primitive(TLV_CHAIN_CODE)
                    .map_err(|e| Error::Tlv(format!("Failed to read chain code: {}", e)))?,
            );
        }

        Ok(Self::new(priv_key, chain_code, pub_key))
    }

    /// Constructs a BIP32 keypair.
    ///
    /// If `private_key` is `Some` and `public_key` is `None`, the public key
    /// is computed from the private key.
    pub fn new(
        private_key: Option<Vec<u8>>,
        chain_code: Option<Vec<u8>>,
        public_key: Option<Vec<u8>>,
    ) -> Self {
        let public_key = match (private_key.as_ref(), public_key) {
            (Some(pk), None) => {
                // Compute public key from private key
                let stripped = strip_leading_zero(pk);
                match SecretKey::from_slice(stripped) {
                    Ok(sk) => Sec1Point::from(&sk.public_key()).to_bytes().to_vec(),
                    Err(_) => Vec::new(),
                }
            }
            (_, Some(pk)) => pk,
            (None, None) => Vec::new(),
        };

        Self {
            private_key,
            chain_code,
            public_key,
        }
    }

    /// Serializes to TLV format.
    ///
    /// # Arguments
    /// * `include_public` - Whether to include the public key in the output
    pub fn to_tlv(&self, include_public: bool) -> Vec<u8> {
        let mut writer = BerTlvWriter::new();
        writer.write_constructed(TLV_KEY_TEMPLATE, |w| {
            if include_public {
                w.write_primitive(TLV_PUB_KEY, &self.public_key);
            }

            if let Some(ref pk) = self.private_key {
                w.write_primitive(TLV_PRIV_KEY, strip_leading_zero(pk));
            }

            if let Some(ref cc) = self.chain_code {
                w.write_primitive(TLV_CHAIN_CODE, cc);
            }
        });
        writer.to_vec()
    }

    /// Returns the Ethereum address of the public key.
    pub fn to_ethereum_address(&self) -> [u8; 20] {
        to_ethereum_address(&self.public_key)
    }

    pub fn private_key(&self) -> Option<&[u8]> {
        self.private_key.as_deref()
    }

    pub fn chain_code(&self) -> Option<&[u8]> {
        self.chain_code.as_deref()
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Returns `true` if only the public key is present (no private key).
    pub fn is_public_only(&self) -> bool {
        self.private_key.is_none()
    }

    /// Returns `true` if the key has a chain code (extended key).
    pub fn is_extended(&self) -> bool {
        self.chain_code.is_some()
    }
}

impl Drop for Bip32KeyPair {
    /// Scrubs the private key and chain code from memory. This only covers
    /// bytes owned by this struct: `private_key()`/`chain_code()` give
    /// borrowed access, but `to_tlv()` serializes the private key into a new
    /// owned `Vec<u8>` handed to the caller, which this `Drop` impl can't
    /// reach — the caller is responsible for that copy.
    fn drop(&mut self) {
        self.private_key.zeroize();
        self.chain_code.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_binary_seed() {
        // BIP32 test vector: seed = "Satoshi"
        let seed = b"Satoshi";
        let keypair = Bip32KeyPair::from_binary_seed(seed);

        assert!(keypair.private_key.is_some());
        assert!(keypair.chain_code.is_some());
        assert!(!keypair.public_key.is_empty());
        assert!(!keypair.is_public_only());
        assert!(keypair.is_extended());
    }

    #[test]
    fn test_from_binary_seed_known_vector() {
        // BIP32 test vector from the spec
        // seed: 000102030405060708090a0b0c0d0e0f
        let seed = hex_decode("000102030405060708090a0b0c0d0e0f");
        let keypair = Bip32KeyPair::from_binary_seed(&seed);

        // Expected master key (from BIP32 spec)
        let expected_pk = hex_decode("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35");
        assert_eq!(keypair.private_key().unwrap(), &expected_pk);

        let expected_cc = hex_decode("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508");
        assert_eq!(keypair.chain_code().unwrap(), &expected_cc);
    }

    #[test]
    fn test_to_tlv_roundtrip() {
        let seed = b"test seed for roundtrip";
        let original = Bip32KeyPair::from_binary_seed(seed);

        let tlv = original.to_tlv(true);
        let parsed = Bip32KeyPair::from_tlv(&tlv).unwrap();

        assert_eq!(original.private_key(), parsed.private_key());
        assert_eq!(original.chain_code(), parsed.chain_code());
        assert_eq!(original.public_key(), parsed.public_key());
    }

    #[test]
    fn test_to_tlv_without_public() {
        let seed = b"test seed";
        let keypair = Bip32KeyPair::from_binary_seed(seed);
        let tlv = keypair.to_tlv(false);

        let parsed = Bip32KeyPair::from_tlv(&tlv).unwrap();
        assert_eq!(keypair.private_key(), parsed.private_key());
        assert_eq!(keypair.chain_code(), parsed.chain_code());
    }

    #[test]
    fn test_ethereum_address() {
        let seed = b"ethereum address test";
        let keypair = Bip32KeyPair::from_binary_seed(seed);
        let addr = keypair.to_ethereum_address();
        assert_eq!(addr.len(), 20);
    }

    #[test]
    fn test_is_public_only() {
        let mut pub_key = vec![0x04u8];
        pub_key.extend(vec![0x42u8; 64]);
        let keypair = Bip32KeyPair::new(
            None,
            None,
            Some(pub_key),
        );
        assert!(keypair.is_public_only());
        assert!(!keypair.is_extended());
    }

    fn hex_decode(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
}
