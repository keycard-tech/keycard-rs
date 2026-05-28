//! Secure Channel V2 implementation.
//!
//! Uses ECDHE on secp256k1 with HKDF-SHA256 key derivation
//! and AES-128-CCM (T=8, L=13) for encrypted commands.

use aes::Aes128;
use ccm::{
    Ccm,
    aead::{Aead, KeyInit},
};
use hkdf::Hkdf;
use k256::{
    AffinePoint, Sec1Point, PublicKey,
    ecdh::EphemeralSecret,
    ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier},
    elliptic_curve::sec1::ToSec1Point,
};
use sha2::{Digest, Sha256};


use crate::apdu::{ApduCommand, ApduResponse};
use crate::channel::CardChannel;
use crate::constants::ins;
use crate::error::Error;
use crate::parsing::certificate::Certificate;
use crate::secure_channel::{SecureChannel, SecureChannelVersion, Pairing};

type Aes128Ccm = Ccm<Aes128, typenum::consts::U8, typenum::consts::U13>;

/// Protocol label for HKDF: "sc_v2_ccm"
const PROTOCOL_LABEL: &[u8] = b"sc_v2_ccm";
/// HKDF salt size in bytes.
const HKDF_SALT_SIZE: usize = 32;
/// Uncompressed secp256k1 public key size.
const PUBKEY_SIZE: usize = 65;
/// HKDF output key material size.
const OKM_SIZE: usize = 32;
/// AES key size in bytes.
const AES_KEY_SIZE: usize = 16;
/// CCM nonce size in bytes.
const CCM_NONCE_SIZE: usize = 13;

/// Secure Channel V2 session.
pub struct SecureChannelV2 {
    /// Trusted CA public keys (compressed secp256k1, 33 bytes each).
    ca_public_keys: Vec<[u8; 33]>,
    /// Whitelisted card identity public keys (compressed secp256k1, 33 bytes each).
    whitelisted_card_public_keys: Vec<[u8; 33]>,
    /// Client-to-card AES-128-CCM key.
    key_h2c: Option<[u8; AES_KEY_SIZE]>,
    /// Card-to-client AES-128-CCM key.
    key_c2h: Option<[u8; AES_KEY_SIZE]>,
    /// Per-session nonce counter (big-endian, starts at 0).
    nonce_counter: [u8; CCM_NONCE_SIZE],
    /// Whether the session is active.
    open: bool,
    /// Card's identity public key (set during certificate validation).
    card_ident_pub: Option<[u8; 33]>,
    /// Client's ephemeral public key (for debugging).
    client_eph_pub: Option<Vec<u8>>,
}

impl SecureChannelV2 {
    /// Creates a new V2 secure channel with the given trusted CA keys
    /// and optionally whitelisted card identity keys.
    pub fn new(
        ca_public_keys: Vec<[u8; 33]>,
        whitelisted_card_public_keys: Vec<[u8; 33]>,
    ) -> Self {
        Self {
            ca_public_keys,
            whitelisted_card_public_keys,
            key_h2c: None,
            key_c2h: None,
            nonce_counter: [0u8; CCM_NONCE_SIZE],
            open: false,
            card_ident_pub: None,
            client_eph_pub: None,
        }
    }

    /// Parses the card's identity certificate from the SELECT response
    /// and validates the CA public key against the known anchors.
    pub fn set_card_certificate(&mut self, cert_data: &[u8]) -> Result<(), Error> {
        let cert = Certificate::from_tlv(cert_data)?;
        let ident_pub = cert.ident_pub().clone();
        self.card_ident_pub = Some(ident_pub);

        // Check if the card's identity public key is whitelisted
        let whitelisted = self.is_card_whitelisted(&ident_pub);

        // Check if the CA public key is trusted
        let ca_pub_bytes = cert.public_key();
        // The recovered CA key from k256 is compressed (33 bytes)
        let ca_trusted = if ca_pub_bytes.len() == 33 {
            let mut ca_pub = [0u8; 33];
            ca_pub.copy_from_slice(ca_pub_bytes);
            self.is_ca_trusted(&ca_pub)
        } else {
            false
        };

        if !ca_trusted && !whitelisted {
            return Err(Error::Protocol(
                "Card certificate verification failed: unknown CA public key and card not whitelisted"
                    .to_string(),
            ));
        }

        Ok(())
    }

    /// Returns the card's identity public key (set during handshake).
    pub fn get_card_ident_pub(&self) -> Option<&[u8; 33]> {
        self.card_ident_pub.as_ref()
    }

    /// Checks if the given card identity public key is in the whitelist.
    pub fn is_card_whitelisted(&self, ident_pub: &[u8; 33]) -> bool {
        self.whitelisted_card_public_keys
            .iter()
            .any(|key| key == ident_pub)
    }

    /// Checks if the given CA public key is trusted.
    pub fn is_ca_trusted(&self, ca_pub: &[u8; 33]) -> bool {
        self.ca_public_keys.iter().any(|key| key == ca_pub)
    }
}

impl SecureChannel for SecureChannelV2 {
    fn auto_open(&mut self, channel: &mut dyn CardChannel) -> Result<(), Error> {
        // Generate random salt
        let mut salt = [0u8; HKDF_SALT_SIZE];
        getrandom::getrandom(&mut salt)
            .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;

        // Generate client ephemeral key pair
        use k256::elliptic_curve::Generate;
        let mut rng = getrandom_04::SysRng;
        let client_eph_priv = EphemeralSecret::try_generate_from_rng(&mut rng)
            .map_err(|_| Error::Crypto("Failed to generate ephemeral secret".to_string()))?;
        let client_eph_pub = client_eph_priv.public_key();
        let affine: AffinePoint = client_eph_pub.into();
        let client_eph_pub_bytes = affine.to_sec1_point(false).to_bytes().to_vec(); // uncompressed
        self.client_eph_pub = Some(client_eph_pub_bytes.clone());

        // Build request: salt || client_eph_pub (uncompressed)
        let mut request_data = Vec::with_capacity(HKDF_SALT_SIZE + PUBKEY_SIZE);
        request_data.extend_from_slice(&salt);
        request_data.extend_from_slice(&client_eph_pub_bytes);

        // Send OPEN_SECURE_CHANNEL
        let resp = self.open_secure_channel(channel, 0, &request_data)?;
        resp.check_ok()?;

        // Process handshake response
        self.process_handshake_response(&salt, &client_eph_priv, resp.data())
    }

    fn auto_pair(
        &mut self,
        _channel: &mut dyn CardChannel,
        _mode: u8,
        _shared_secret: &[u8],
    ) -> Result<(), Error> {
        Err(Error::Protocol("Pairing is not supported in Secure Channel V2".to_string()))
    }

    fn auto_unpair(&mut self, _channel: &mut dyn CardChannel) -> Result<(), Error> {
        Err(Error::Protocol("Unpairing is not supported in Secure Channel V2".to_string()))
    }

    fn unpair_others(&mut self, _channel: &mut dyn CardChannel) -> Result<(), Error> {
        Err(Error::Protocol("Unpairing is not supported in Secure Channel V2".to_string()))
    }

    fn open_secure_channel(
        &mut self,
        channel: &mut dyn CardChannel,
        _index: u8,
        data: &[u8],
    ) -> Result<ApduResponse, Error> {
        self.open = false;
        let cmd = ApduCommand::new(0x80, ins::OPEN_SECURE_CHANNEL, 0, 0, data.to_vec());
        channel.send(&cmd)
    }

    fn mutually_authenticate(
        &mut self,
        _channel: &mut dyn CardChannel,
    ) -> Result<ApduResponse, Error> {
        Err(Error::Protocol(
            "Mutual authentication is not a separate step in Secure Channel V2".to_string(),
        ))
    }

    fn mutually_authenticate_with_data(
        &mut self,
        _channel: &mut dyn CardChannel,
        _data: &[u8],
    ) -> Result<ApduResponse, Error> {
        Err(Error::Protocol(
            "Mutual authentication is not a separate step in Secure Channel V2".to_string(),
        ))
    }

    fn pair(
        &mut self,
        _channel: &mut dyn CardChannel,
        _p1: u8,
        _p2: u8,
        _data: &[u8],
    ) -> Result<ApduResponse, Error> {
        Err(Error::Protocol("Pairing is not supported in Secure Channel V2".to_string()))
    }

    fn unpair(
        &mut self,
        _channel: &mut dyn CardChannel,
        _p1: u8,
    ) -> Result<ApduResponse, Error> {
        Err(Error::Protocol("Unpairing is not supported in Secure Channel V2".to_string()))
    }

    fn protected_command(
        &mut self,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> ApduCommand {
        if !self.open {
            return ApduCommand::new(cla, ins, p1, p2, data.to_vec());
        }

        // Build inner APDU: CLA | INS | P1 | P2 | LC | data
        let mut inner = Vec::with_capacity(5 + data.len());
        inner.push(cla);
        inner.push(ins);
        inner.push(p1);
        inner.push(p2);
        inner.push(data.len() as u8);
        inner.extend_from_slice(data);

        // Encrypt with AES-128-CCM
        let ciphertext = self.encrypt_ccm(&inner)
            .expect("AES-CCM encryption failed");

        ApduCommand::new(0x80, ins::SECURED_APDU, 0, 0, ciphertext)
    }

    fn transmit(
        &mut self,
        channel: &mut dyn CardChannel,
        cmd: &ApduCommand,
    ) -> Result<ApduResponse, Error> {
        let resp = channel.send(cmd)?;

        if resp.sw() != ApduResponse::SW_OK {
            self.open = false;
            return Ok(resp);
        }

        if !self.open {
            return Ok(resp);
        }

        // Decrypt with AES-128-CCM
        let plaintext = self.decrypt_ccm(resp.data())
            .map_err(|_| Error::Protocol("AES-CCM decryption failed".to_string()))?;

        // Increment nonce counter
        self.increment_nonce();

        Ok(ApduResponse::new(&plaintext)?)
    }

    fn pairing(&self) -> Option<&Pairing> {
        None // V2 does not use pairing
    }

    fn set_pairing(&mut self, _pairing: Pairing) {
        // No-op: V2 does not use pairing
    }

    fn reset(&mut self) {
        self.open = false;
        self.key_h2c = None;
        self.key_c2h = None;
        self.nonce_counter = [0u8; CCM_NONCE_SIZE];
        self.card_ident_pub = None;
        self.client_eph_pub = None;
    }

    fn version(&self) -> SecureChannelVersion {
        SecureChannelVersion::V2
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

impl SecureChannelV2 {
    /// Processes the card's handshake response.
    fn process_handshake_response(
        &mut self,
        salt: &[u8],
        client_eph_priv: &EphemeralSecret,
        card_response: &[u8],
    ) -> Result<(), Error> {
        // Parse: card_eph_pub (65B) || signature (DER, variable)
        if card_response.len() < PUBKEY_SIZE + 2 {
            return Err(Error::Protocol("Invalid handshake response: too short".to_string()));
        }

        let card_eph_pub_bytes = &card_response[0..PUBKEY_SIZE];
        let signature_bytes = &card_response[PUBKEY_SIZE..];

        // Decode card ephemeral public key
        let card_eph_pub = k256::PublicKey::from_sec1_bytes(card_eph_pub_bytes)
            .map_err(|_| Error::Protocol("Invalid card ephemeral public key".to_string()))?;

        // ECDH key agreement
        let shared = client_eph_priv.diffie_hellman(&card_eph_pub);
        let shared_secret = shared.raw_secret_bytes();

        // HKDF-SHA256 key derivation
        let okm = hkdf_derive(salt, shared_secret, PROTOCOL_LABEL, OKM_SIZE)
            .map_err(|_| Error::Crypto("HKDF derivation failed".to_string()))?;

        // Set session keys
        let mut key_h2c = [0u8; AES_KEY_SIZE];
        let mut key_c2h = [0u8; AES_KEY_SIZE];
        key_h2c.copy_from_slice(&okm[0..AES_KEY_SIZE]);
        key_c2h.copy_from_slice(&okm[AES_KEY_SIZE..OKM_SIZE]);
        self.key_h2c = Some(key_h2c);
        self.key_c2h = Some(key_c2h);

        // Verify card's ECDSA signature over transcript
        self.verify_card_signature(salt, &client_eph_priv.public_key(), &card_eph_pub, signature_bytes)?;

        // Initialize nonce counter to zero
        self.nonce_counter = [0u8; CCM_NONCE_SIZE];
        self.open = true;

        Ok(())
    }

    /// Verifies the card's ECDSA signature over the handshake transcript.
    fn verify_card_signature(
        &self,
        salt: &[u8],
        client_pub: &PublicKey,
        card_pub: &PublicKey,
        signature_bytes: &[u8],
    ) -> Result<(), Error> {
        let card_ident_pub = self.card_ident_pub.as_ref()
            .ok_or_else(|| Error::Protocol("Card identity public key not available".to_string()))?;

        // Hash the transcript: SHA-256(PROTOCOL_LABEL || salt || client_pub || card_pub)
        // Public keys are in uncompressed form (65 bytes) to match wire format.
        let client_uncompressed = AffinePoint::from(*client_pub)
            .to_sec1_point(false).to_bytes();
        let card_uncompressed = AffinePoint::from(*card_pub)
            .to_sec1_point(false).to_bytes();
        let mut hasher = Sha256::new();
        hasher.update(PROTOCOL_LABEL);
        hasher.update(salt);
        hasher.update(&client_uncompressed);
        hasher.update(&card_uncompressed);
        let transcript_hash = hasher.finalize();

        // Parse the signature
        let sig = Signature::from_der(signature_bytes)
            .map_err(|_| Error::Crypto("Failed to parse card signature DER".to_string()))?;

        // Verify using the card's identity public key
        let ident_point = Sec1Point::from_bytes(card_ident_pub)
            .map_err(|_| Error::Crypto("Invalid identity public key encoding".to_string()))?;
        let verifying_key = VerifyingKey::from_sec1_point(&ident_point)
            .map_err(|_| Error::Crypto("Invalid identity public key".to_string()))?;

        verifying_key
            .verify_prehash(&transcript_hash, &sig)
            .map_err(|_| Error::Protocol("Card authentication failed: invalid signature".to_string()))?;

        Ok(())
    }

    /// Encrypts plaintext with AES-128-CCM using the client-to-card key.
    fn encrypt_ccm(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let key = self.key_h2c.as_ref()
            .ok_or_else(|| Error::Protocol("No client-to-card key available".to_string()))?;
        let cipher = Aes128Ccm::new_from_slice(key)
            .map_err(|_| Error::Crypto("Failed to create AES-CCM cipher".to_string()))?;

        let nonce = ccm::aead::Nonce::<Aes128Ccm>::try_from(&self.nonce_counter[..])
            .map_err(|_| Error::Crypto("Invalid nonce".to_string()))?;
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| Error::Crypto("AES-CCM encryption failed".to_string()))?;

        Ok(ciphertext)
    }

    /// Decrypts ciphertext with AES-128-CCM using the card-to-client key.
    fn decrypt_ccm(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let key = self.key_c2h.as_ref()
            .ok_or_else(|| Error::Protocol("No card-to-client key available".to_string()))?;
        let cipher = Aes128Ccm::new_from_slice(key)
            .map_err(|_| Error::Crypto("Failed to create AES-CCM cipher".to_string()))?;

        let nonce = ccm::aead::Nonce::<Aes128Ccm>::try_from(&self.nonce_counter[..])
            .map_err(|_| Error::Crypto("Invalid nonce".to_string()))?;
        let plaintext = cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| Error::Crypto("AES-CCM decryption failed".to_string()))?;

        Ok(plaintext)
    }

    /// Increments the 13-byte nonce counter as a big-endian integer.
    fn increment_nonce(&mut self) {
        for i in (0..CCM_NONCE_SIZE).rev() {
            self.nonce_counter[i] = self.nonce_counter[i].wrapping_add(1);
            if self.nonce_counter[i] != 0 {
                return;
            }
        }
        // Overflow — session must be reset
        self.open = false;
    }
}

/// HKDF-SHA256 (Extract-then-Expand) as defined in RFC 5869.
fn hkdf_derive(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, Error> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; length];
    hkdf.expand(info, &mut okm)
        .map_err(|_| Error::Crypto("HKDF expansion failed".to_string()))?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v2_new_state() {
        let ca_key: [u8; 33] = [0x02u8; 33];
        let sc = SecureChannelV2::new(vec![ca_key], vec![]);
        assert!(!sc.open);
        assert!(sc.pairing().is_none());
    }

    #[test]
    fn test_v2_pairing_not_supported() {
        let ca_key: [u8; 33] = [0x02u8; 33];
        let _sc = SecureChannelV2::new(vec![ca_key], vec![]);
        // Can't test without a channel, but the method should return error
    }

    #[test]
    fn test_hkdf_derive() {
        // RFC 5869 Test Case 1
        let ikm = &[
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        ];
        let salt = &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = &[
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
        ];
        let expected = &[
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];

        let okm = hkdf_derive(salt, ikm, info, expected.len()).unwrap();
        assert_eq!(&okm, expected);
    }

    #[test]
    fn test_increment_nonce() {
        let mut sc = SecureChannelV2::new(vec![], vec![]);
        sc.nonce_counter = [0u8; CCM_NONCE_SIZE];
        sc.nonce_counter[12] = 0xFF; // Last byte
        sc.increment_nonce();
        assert_eq!(sc.nonce_counter[12], 0);
        assert_eq!(sc.nonce_counter[11], 1);
    }

    #[test]
    fn test_is_ca_trusted() {
        let ca_key: [u8; 33] = [0x02u8; 33];
        let sc = SecureChannelV2::new(vec![ca_key], vec![]);
        assert!(sc.is_ca_trusted(&ca_key));
        let other: [u8; 33] = [0x03u8; 33];
        assert!(!sc.is_ca_trusted(&other));
    }

    #[test]
    fn test_is_card_whitelisted() {
        let card_key: [u8; 33] = [0x03u8; 33];
        let sc = SecureChannelV2::new(vec![], vec![card_key]);
        assert!(sc.is_card_whitelisted(&card_key));
        let other: [u8; 33] = [0x04u8; 33];
        assert!(!sc.is_card_whitelisted(&other));
    }
}
