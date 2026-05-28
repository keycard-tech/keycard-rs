//! Card identity certificate handling.

use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use k256::Sec1Point;
use sha2::{Digest, Sha256};

use crate::error::Error;
use crate::parsing::signature::RecoverableSignature;
use crate::tlv::{BerTlvReader, TLV_CERT, TLV_SIGNATURE_TEMPLATE};

/// Card identity certificate.
///
/// Extends `RecoverableSignature` with card identity public key.
#[derive(Debug, Clone)]
pub struct Certificate {
    ident_pub: [u8; 33],
    // RecoverableSignature fields (embedded)
    public_key: Vec<u8>,
    rec_id: i32,
    r: Vec<u8>,
    s: Vec<u8>,
}

impl Certificate {
    /// Parses a 98-byte certificate from card data.
    ///
    /// Format: `compressed_pubkey(33) || r(32) || s(32) || v(1)`
    ///
    /// The hash is `SHA-256(compressed_pubkey)`. The CA public key is recovered
    /// from the signature.
    pub fn from_tlv(cert_data: &[u8]) -> Result<Self, Error> {
        if cert_data.len() < 98 {
            return Err(Error::Tlv(format!(
                "Certificate data too short: expected 98 bytes, got {}",
                cert_data.len()
            )));
        }

        let ident_pub: [u8; 33] = cert_data[0..33].try_into().unwrap();
        let r = cert_data[33..65].to_vec();
        let s = cert_data[65..97].to_vec();
        let rec_id = cert_data[97] as i32;

        // Hash the compressed public key
        let hash = Sha256::digest(&ident_pub);

        // Recover CA public key from signature
        let ca_pub = RecoverableSignature::recover_public_key(rec_id, &hash, &r, &s, true)
            .ok_or_else(|| Error::Crypto("Failed to recover CA public key from certificate".to_string()))?;

        Ok(Self {
            ident_pub,
            public_key: ca_pub,
            rec_id,
            r,
            s,
        })
    }

    /// Returns the card's identity public key (compressed, 33 bytes).
    pub fn ident_pub(&self) -> &[u8; 33] {
        &self.ident_pub
    }

    /// Returns the recovered CA public key.
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

    /// Verifies a signed identity proof.
    ///
    /// Parses the TLV to extract the certificate and the signature over `hash`.
    /// Verifies the signature using the card's identity public key.
    /// Returns the CA public key on success.
    pub fn verify_identity(hash: &[u8], tlv_data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut reader = BerTlvReader::new(tlv_data);
        reader
            .enter_constructed(TLV_SIGNATURE_TEMPLATE)
            .map_err(|e| Error::Tlv(format!("Failed to enter signature template: {}", e)))?;

        let cert_data = reader.read_primitive(TLV_CERT).map_err(|e| {
            Error::Tlv(format!("Failed to read certificate: {}", e))
        })?;

        let cert = Self::from_tlv(&cert_data)?;

        // The remaining data is the signature over hash
        let signature_bytes = reader.peek_unread();
        if signature_bytes.len() < 2 {
            return Err(Error::Tlv("Signature data too short".to_string()));
        }

        // Parse the signature - it could be raw (65 bytes: r || s || v) or DER-encoded
        let sig = if signature_bytes.len() == 65 {
            // Raw signature format
            let r_bytes: [u8; 32] = signature_bytes[0..32].try_into().map_err(|_| {
                Error::Crypto("Invalid R component length".to_string())
            })?;
            let s_bytes: [u8; 32] = signature_bytes[32..64].try_into().map_err(|_| {
                Error::Crypto("Invalid S component length".to_string())
            })?;
            Signature::from_scalars(r_bytes, s_bytes).map_err(|_| {
                Error::Crypto("Invalid signature scalars".to_string())
            })?
        } else {
            // DER-encoded signature
            Signature::from_der(signature_bytes).map_err(|_| {
                Error::Crypto("Failed to parse DER signature".to_string())
            })?
        };

        // Verify using the card's identity public key
        let ident_point = Sec1Point::from_bytes(&cert.ident_pub).map_err(|_| {
            Error::Crypto("Invalid identity public key encoding".to_string())
        })?;
        let verifying_key = VerifyingKey::from_sec1_point(&ident_point).map_err(|_| {
            Error::Crypto("Invalid identity public key".to_string())
        })?;

        verifying_key.verify_prehash(hash, &sig).map_err(|_| {
            Error::Crypto("Identity signature verification failed".to_string())
        })?;

        Ok(cert.public_key.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_from_tlv_too_short() {
        let short_data = vec![0u8; 50];
        assert!(Certificate::from_tlv(&short_data).is_err());
    }
}
