//! ECDSA signature with secp256k1 public key recovery.

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use k256::{AffinePoint, PublicKey};
use k256::elliptic_curve::sec1::ToSec1Point;

use crate::error::Error;
use crate::parsing::ethereum::to_ethereum_address;
use crate::tlv::{
    BerTlvReader, TLV_ECDSA_TEMPLATE, TLV_INT, TLV_PUB_KEY, TLV_SIGNATURE_TEMPLATE,
};

/// Tag for raw signature format (r || s || rec_id, 65 bytes)
pub const TLV_RAW_SIGNATURE: u8 = 0x80;

/// ECDSA signature with recoverable public key.
#[derive(Debug, Clone)]
pub struct RecoverableSignature {
    public_key: Vec<u8>,
    rec_id: i32,
    r: Vec<u8>,
    s: Vec<u8>,
}

impl RecoverableSignature {
    /// Parses a signature from the card's response.
    ///
    /// Supports two formats:
    /// - **Raw signature** (`TLV_RAW_SIGNATURE`): 65 bytes = `r(32) || s(32) || rec_id(1)`
    /// - **Legacy** (`TLV_SIGNATURE_TEMPLATE`): Contains `TLV_PUB_KEY` and `TLV_ECDSA_TEMPLATE` with r and s
    ///
    /// # Arguments
    /// * `hash` - The 32-byte message hash that was signed
    /// * `tlv_data` - The TLV-encoded signature response from the card
    pub fn from_card_response(hash: &[u8], tlv_data: &[u8]) -> Result<Self, Error> {
        let mut reader = BerTlvReader::new(tlv_data);

        if reader.next_tag_is(TLV_RAW_SIGNATURE) {
            let value = reader.read_primitive(TLV_RAW_SIGNATURE).map_err(|e| {
                Error::Tlv(format!("Failed to read raw signature: {}", e))
            })?;
            Self::init_from_raw_signature(hash, &value)
        } else if reader.next_tag_is(TLV_SIGNATURE_TEMPLATE) {
            Self::init_from_legacy(hash, &mut reader)
        } else {
            let tag = reader.read_tag().map_err(|e| {
                Error::Tlv(format!("Failed to read signature tag: {}", e))
            })?;
            Err(Error::Tlv(format!(
                "Invalid signature TLV tag: 0x{:02X}",
                tag
            )))
        }
    }

    fn init_from_raw_signature(hash: &[u8], signature: &[u8]) -> Result<Self, Error> {
        if signature.len() != 65 {
            return Err(Error::Tlv(format!(
                "Raw signature must be 65 bytes, got {}",
                signature.len()
            )));
        }

        let r = signature[0..32].to_vec();
        let s = signature[32..64].to_vec();
        let rec_id = signature[64] as i32;

        let public_key =
            Self::recover_public_key(rec_id, hash, &r, &s, false).ok_or_else(|| {
                Error::Crypto("Failed to recover public key from signature".to_string())
            })?;

        Ok(Self {
            public_key,
            rec_id,
            r,
            s,
        })
    }

    fn init_from_legacy(hash: &[u8], reader: &mut BerTlvReader) -> Result<Self, Error> {
        reader
            .enter_constructed(TLV_SIGNATURE_TEMPLATE)
            .map_err(|e| Error::Tlv(format!("Failed to enter signature template: {}", e)))?;

        let public_key = reader.read_primitive(TLV_PUB_KEY).map_err(|e| {
            Error::Tlv(format!("Failed to read public key from signature: {}", e))
        })?;

        reader
            .enter_constructed(TLV_ECDSA_TEMPLATE)
            .map_err(|e| Error::Tlv(format!("Failed to enter ECDSA template: {}", e)))?;

        let r_raw = reader.read_primitive(TLV_INT).map_err(|e| {
            Error::Tlv(format!("Failed to read R component: {}", e))
        })?;
        let s_raw = reader.read_primitive(TLV_INT).map_err(|e| {
            Error::Tlv(format!("Failed to read S component: {}", e))
        })?;

        let r = to_uint(&r_raw);
        let s = to_uint(&s_raw);

        // Calculate rec_id by brute force (try 0..=3)
        let mut rec_id: i32 = -1;
        for i in 0..4i32 {
            if let Some(candidate) = Self::recover_public_key(i, hash, &r, &s, false) {
                if candidate == public_key {
                    rec_id = i;
                    break;
                }
            }
        }

        if rec_id == -1 {
            return Err(Error::Crypto(
                "Unrecoverable signature, cannot find recId".to_string(),
            ));
        }

        Ok(Self {
            public_key,
            rec_id,
            r,
            s,
        })
    }

    /// Direct construction from components.
    ///
    /// `public_key` is stored as given — the caller is responsible for
    /// providing it in whichever encoding (compressed or uncompressed) they
    /// want it in.
    pub fn from_components(
        public_key: Vec<u8>,
        r: Vec<u8>,
        s: Vec<u8>,
        rec_id: i32,
    ) -> Self {
        Self {
            public_key,
            rec_id,
            r,
            s,
        }
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn rec_id(&self) -> i32 {
        self.rec_id
    }

    pub fn r(&self) -> &[u8] {
        &self.r
    }

    pub fn s(&self) -> &[u8] {
        &self.s
    }

    /// Returns the Ethereum address of the signing key.
    pub fn ethereum_address(&self) -> [u8; 20] {
        to_ethereum_address(&self.public_key)
    }

    /// Standard secp256k1 pubkey recovery from ECDSA signature components.
    ///
    /// # Arguments
    /// * `rec_id` - Recovery ID (0..=3)
    /// * `hash` - 32-byte message hash
    /// * `r` - R component (32 bytes)
    /// * `s` - S component (32 bytes)
    /// * `compressed` - Whether to return compressed public key (33 bytes). If false, returns uncompressed (65 bytes).
    ///
    /// # Returns
    /// Recovered public key (uncompressed 65 bytes or compressed 33 bytes), or `None` on failure.
    pub fn recover_public_key(
        rec_id: i32,
        hash: &[u8],
        r: &[u8],
        s: &[u8],
        compressed: bool,
    ) -> Option<Vec<u8>> {
        if !(0..=3).contains(&rec_id) {
            return None;
        }

        let r_bytes: [u8; 32] = r.try_into().ok()?;
        let s_bytes: [u8; 32] = s.try_into().ok()?;
        let hash_bytes: [u8; 32] = hash.try_into().ok()?;

        let sig = Signature::from_scalars(r_bytes, s_bytes).ok()?;
        let recovery_id = RecoveryId::from_byte(rec_id as u8)?;

        let recovered = VerifyingKey::recover_from_prehash(&hash_bytes, &sig, recovery_id).ok()?;

        let public_key = PublicKey::from(&recovered);
        let affine: AffinePoint = public_key.into();
        let point = affine.to_sec1_point(compressed);
        Some(point.to_bytes().to_vec())
    }
}

/// Strips a leading zero byte from signed big-endian integers (BER encoding convention).
pub fn to_uint(signed_int: &[u8]) -> Vec<u8> {
    if signed_int.first() == Some(&0) && signed_int.len() > 1 {
        signed_int[1..].to_vec()
    } else {
        signed_int.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::BerTlvWriter;
    use k256::{AffinePoint, PublicKey, elliptic_curve::Generate, ecdsa::SigningKey};
    use k256::elliptic_curve::sec1::ToSec1Point;

    #[test]
    fn test_to_uint_strips_leading_zero() {
        assert_eq!(to_uint(&[0x00, 0x01, 0x02]), vec![0x01, 0x02]);
    }

    #[test]
    fn test_to_uint_no_leading_zero() {
        assert_eq!(to_uint(&[0x01, 0x02]), vec![0x01, 0x02]);
    }

    #[test]
    fn test_to_uint_single_zero() {
        assert_eq!(to_uint(&[0x00]), vec![0x00]);
    }

    #[test]
    fn test_recover_public_key_valid() {
        // Use a known test vector
        let hash = [
            0x79, 0x00, 0x47, 0x7c, 0x49, 0x7e, 0x1d, 0x0a, 0x95, 0xae, 0xd5, 0x96, 0xe3, 0xe2,
            0x74, 0x6e, 0x2b, 0x3e, 0x99, 0x25, 0x78, 0x6e, 0x8a, 0x79, 0x34, 0x41, 0xe5, 0xe3,
            0x26, 0xb7, 0x91, 0x82,
        ];

        // Generate a key pair and sign
        let mut rng = getrandom_04::SysRng;
        let signing_key = SigningKey::try_generate_from_rng(&mut rng).unwrap();
        let pk = signing_key.verifying_key();
        // Card returns uncompressed keys
        let public_key = PublicKey::from(pk);
        let affine: AffinePoint = public_key.into();
        let pk_bytes = affine.to_sec1_point(false).to_bytes().to_vec();

        // Sign the hash
        let (sig, recovery_id) = signing_key.sign_prehash_recoverable(&hash);
        let sig_bytes = sig.to_bytes();
        let r: Vec<u8> = sig_bytes[..32].to_vec();
        let s: Vec<u8> = sig_bytes[32..].to_vec();
        let rec_id = recovery_id.to_byte() as i32;

        let recovered =
            RecoverableSignature::recover_public_key(rec_id, &hash, &r, &s, false).unwrap();
        assert_eq!(recovered, pk_bytes);
    }

    #[test]
    fn test_recover_public_key_invalid_rec_id() {
        let result = RecoverableSignature::recover_public_key(
            4,
            &[0u8; 32],
            &[0u8; 32],
            &[0u8; 32],
            false,
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_recoverable_signature_from_raw() {
        let hash = [
            0x79, 0x00, 0x47, 0x7c, 0x49, 0x7e, 0x1d, 0x0a, 0x95, 0xae, 0xd5, 0x96, 0xe3, 0xe2,
            0x74, 0x6e, 0x2b, 0x3e, 0x99, 0x25, 0x78, 0x6e, 0x8a, 0x79, 0x34, 0x41, 0xe5, 0xe3,
            0x26, 0xb7, 0x91, 0x82,
        ];

        // Generate a key pair and sign
        let mut rng = getrandom_04::SysRng;
        let signing_key = SigningKey::try_generate_from_rng(&mut rng).unwrap();
        let (sig, recovery_id) = signing_key.sign_prehash_recoverable(&hash);
        let sig_bytes = sig.to_bytes();

        // Build raw signature TLV: tag 0x80, length 65, r || s || rec_id
        let mut raw_sig = sig_bytes.to_vec();
        raw_sig.push(recovery_id.to_byte());

        let mut writer = BerTlvWriter::new();
        writer.write_primitive(TLV_RAW_SIGNATURE, &raw_sig);
        let tlv_data = writer.to_vec();

        let sig_parsed = RecoverableSignature::from_card_response(&hash, &tlv_data).unwrap();
        assert_eq!(sig_parsed.rec_id(), recovery_id.to_byte() as i32);
        assert_eq!(sig_parsed.r().len(), 32);
        assert_eq!(sig_parsed.s().len(), 32);
        assert_eq!(sig_parsed.public_key().len(), 65); // uncompressed (card format)
    }

    #[test]
    fn test_recoverable_signature_from_legacy() {
        let hash = [
            0x79, 0x00, 0x47, 0x7c, 0x49, 0x7e, 0x1d, 0x0a, 0x95, 0xae, 0xd5, 0x96, 0xe3, 0xe2,
            0x74, 0x6e, 0x2b, 0x3e, 0x99, 0x25, 0x78, 0x6e, 0x8a, 0x79, 0x34, 0x41, 0xe5, 0xe3,
            0x26, 0xb7, 0x91, 0x82,
        ];

        // Generate a key pair and sign
        let mut rng = getrandom_04::SysRng;
        let signing_key = SigningKey::try_generate_from_rng(&mut rng).unwrap();
        let pk = signing_key.verifying_key();
        // Card returns uncompressed public keys (65 bytes: 0x04 || x || y)
        let public_key = PublicKey::from(pk);
        let affine: AffinePoint = public_key.into();
        let pk_bytes = affine.to_sec1_point(false).to_bytes().to_vec();
        let (sig, _recovery_id) = signing_key.sign_prehash_recoverable(&hash);
        let sig_bytes = sig.to_bytes();
        let r_bytes: [u8; 32] = sig_bytes[..32].try_into().unwrap();
        let s_bytes: [u8; 32] = sig_bytes[32..].try_into().unwrap();

        // Build legacy signature TLV:
        // A0 (constructed) {
        //   80 (pub key) <pk_bytes>
        //   30 (ECDSA sequence) {
        //     02 (INTEGER) <r>
        //     02 (INTEGER) <s>
        //   }
        // }
        let mut writer = BerTlvWriter::new();
        writer.write_constructed(TLV_SIGNATURE_TEMPLATE, |w| {
            w.write_primitive(TLV_PUB_KEY, &pk_bytes);
            w.write_constructed(TLV_ECDSA_TEMPLATE, |w2| {
                // BER INTEGER encoding: prepend 0x00 if high bit is set
                let r_tlv = if r_bytes[0] & 0x80 != 0 {
                    let mut buf = vec![0x00];
                    buf.extend_from_slice(&r_bytes);
                    buf
                } else {
                    r_bytes.to_vec()
                };
                let s_tlv = if s_bytes[0] & 0x80 != 0 {
                    let mut buf = vec![0x00];
                    buf.extend_from_slice(&s_bytes);
                    buf
                } else {
                    s_bytes.to_vec()
                };
                w2.write_primitive(TLV_INT, &r_tlv);
                w2.write_primitive(TLV_INT, &s_tlv);
            });
        });
        let tlv_data = writer.to_vec();

        let sig_parsed = RecoverableSignature::from_card_response(&hash, &tlv_data).unwrap();
        assert_eq!(sig_parsed.public_key(), pk_bytes);
        assert_eq!(sig_parsed.r(), &r_bytes[..]);
        assert_eq!(sig_parsed.s(), &s_bytes[..]);
        assert!(sig_parsed.rec_id() >= 0 && sig_parsed.rec_id() <= 3);
    }

    #[test]
    fn test_recoverable_signature_from_legacy_high_bit() {
        let hash = [
            0x79, 0x00, 0x47, 0x7c, 0x49, 0x7e, 0x1d, 0x0a, 0x95, 0xae, 0xd5, 0x96, 0xe3, 0xe2,
            0x74, 0x6e, 0x2b, 0x3e, 0x99, 0x25, 0x78, 0x6e, 0x8a, 0x79, 0x34, 0x41, 0xe5, 0xe3,
            0x26, 0xb7, 0x91, 0x82,
        ];

        // Generate keys until we get a signature with high bit set (common enough)
        let mut rng = getrandom_04::SysRng;
        let signing_key = SigningKey::try_generate_from_rng(&mut rng).unwrap();
        let pk = signing_key.verifying_key();
        // Card returns uncompressed public keys (65 bytes: 0x04 || x || y)
        let public_key = PublicKey::from(pk);
        let affine: AffinePoint = public_key.into();
        let pk_bytes = affine.to_sec1_point(false).to_bytes().to_vec();
        let (sig, _recovery_id) = signing_key.sign_prehash_recoverable(&hash);
        let sig_bytes = sig.to_bytes();
        let r_bytes: [u8; 32] = sig_bytes[..32].try_into().unwrap();
        let s_bytes: [u8; 32] = sig_bytes[32..].try_into().unwrap();

        // Build legacy TLV with BER INTEGER encoding (0x00 prefix if high bit set)
        let mut writer = BerTlvWriter::new();
        writer.write_constructed(TLV_SIGNATURE_TEMPLATE, |w| {
            w.write_primitive(TLV_PUB_KEY, &pk_bytes);
            w.write_constructed(TLV_ECDSA_TEMPLATE, |w2| {
                let r_tlv = if r_bytes[0] & 0x80 != 0 {
                    let mut buf = vec![0x00];
                    buf.extend_from_slice(&r_bytes);
                    buf
                } else {
                    r_bytes.to_vec()
                };
                let s_tlv = if s_bytes[0] & 0x80 != 0 {
                    let mut buf = vec![0x00];
                    buf.extend_from_slice(&s_bytes);
                    buf
                } else {
                    s_bytes.to_vec()
                };
                w2.write_primitive(TLV_INT, &r_tlv);
                w2.write_primitive(TLV_INT, &s_tlv);
            });
        });
        let tlv_data = writer.to_vec();

        let sig_parsed = RecoverableSignature::from_card_response(&hash, &tlv_data).unwrap();
        assert_eq!(sig_parsed.public_key(), pk_bytes);
        // to_uint strips the leading zero, so r/s should be 32 bytes
        assert_eq!(sig_parsed.r().len(), 32);
        assert_eq!(sig_parsed.s().len(), 32);
        assert!(sig_parsed.rec_id() >= 0 && sig_parsed.rec_id() <= 3);
    }
}
