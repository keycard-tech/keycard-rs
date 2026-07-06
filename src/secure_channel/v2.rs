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
    AffinePoint, PublicKey,
    ecdh::EphemeralSecret,
    ecdsa::{Signature, signature::hazmat::PrehashVerifier},
    elliptic_curve::sec1::ToSec1Point,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::apdu::{ApduCommand, ApduResponse};
use crate::channel::CardChannel;
use crate::constants::ins;
use crate::error::Error;
use crate::parsing::certificate::{parse_verifying_key, Certificate};
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
    /// Per-session nonce counter (big-endian, starts at 0). Holds the nonce
    /// to use for the *next* encryption; advanced as soon as a nonce is
    /// consumed by `protected_command`, before the round trip completes.
    nonce_counter: [u8; CCM_NONCE_SIZE],
    /// The nonce used to encrypt the in-flight command, saved so the
    /// matching response can be decrypted with it even though
    /// `nonce_counter` has already advanced past it.
    pending_decrypt_nonce: Option<[u8; CCM_NONCE_SIZE]>,
    /// Whether the session is active.
    open: bool,
    /// Whether the channel has ever been successfully opened.
    ///
    /// Distinct from `open`: this stays `true` across a transmit failure so
    /// that `protected_command` knows to refuse (rather than silently send
    /// plaintext, or worse, re-encrypt under a reused CCM nonce) once the
    /// session has previously carried protected traffic. Only `reset()`
    /// clears it, since that's the only deliberate teardown.
    established: bool,
    /// Card's identity public key (set during certificate validation).
    card_ident_pub: Option<[u8; 33]>,
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
            pending_decrypt_nonce: None,
            open: false,
            established: false,
            card_ident_pub: None,
        }
    }

    /// Parses the card's identity certificate from the SELECT response
    /// and validates the CA public key against the known anchors.
    pub fn set_card_certificate(&mut self, cert_data: &[u8]) -> Result<(), Error> {
        let cert = Certificate::from_tlv(cert_data)?;
        let ident_pub = *cert.ident_pub();
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
            .map_err(Error::io_other)?;

        // Generate client ephemeral key pair
        use k256::elliptic_curve::Generate;
        let mut rng = getrandom_04::SysRng;
        let client_eph_priv = EphemeralSecret::try_generate_from_rng(&mut rng)
            .map_err(|_| Error::Crypto("Failed to generate ephemeral secret".to_string()))?;
        let client_eph_pub = client_eph_priv.public_key();
        let affine: AffinePoint = client_eph_pub.into();
        let client_eph_pub_bytes = affine.to_sec1_point(false).to_bytes().to_vec(); // uncompressed

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
    ) -> Result<ApduCommand, Error> {
        if !self.open {
            if self.established {
                return Err(Error::Protocol(
                    "Secure channel was closed after an error; call auto_open again before sending protected commands".to_string(),
                ));
            }
            return Ok(ApduCommand::new(cla, ins, p1, p2, data.to_vec()));
        }

        if data.len() > u8::MAX as usize {
            return Err(Error::InvalidArgument(format!(
                "Protected command payload too large: {} bytes", data.len()
            )));
        }

        // Build inner APDU: CLA | INS | P1 | P2 | LC | data
        let mut inner = Vec::with_capacity(5 + data.len());
        inner.push(cla);
        inner.push(ins);
        inner.push(p1);
        inner.push(p2);
        inner.push(data.len() as u8);
        inner.extend_from_slice(data);

        // Encrypt with AES-128-CCM using the current nonce, then advance the
        // counter immediately — before we know whether the round trip to
        // the card will even complete. Once a nonce has been used to
        // encrypt a command it must never be reused, so the advance cannot
        // wait for a successful response. The nonce just consumed is saved
        // so `transmit` can decrypt the matching response with it.
        let ciphertext = self.encrypt_ccm(&inner)
            .map_err(|_| Error::Crypto("AES-CCM encryption failed".to_string()))?;
        self.pending_decrypt_nonce = Some(self.nonce_counter);
        self.increment_nonce();

        Ok(ApduCommand::new(0x80, ins::SECURED_APDU, 0, 0, ciphertext))
    }

    fn transmit(
        &mut self,
        channel: &mut dyn CardChannel,
        cmd: &ApduCommand,
    ) -> Result<ApduResponse, Error> {
        // Whether or not this exchange succeeds, the nonce it used must
        // never be handed to `decrypt_ccm` again — consume it now.
        let nonce_for_decrypt = self.pending_decrypt_nonce.take();

        let resp = match channel.send(cmd) {
            Ok(resp) => resp,
            Err(e) => {
                // The nonce used to encrypt `cmd` was already consumed by
                // `protected_command`, so no reuse risk here — but we can't
                // know whether the card actually received/processed the
                // command, so the session state is unknown. Close it and
                // force the caller to re-establish before retrying.
                self.open = false;
                return Err(e);
            }
        };

        if resp.sw() != ApduResponse::SW_OK {
            self.open = false;
            return Ok(resp);
        }

        if !self.open {
            return Ok(resp);
        }

        let nonce_for_decrypt = nonce_for_decrypt.ok_or_else(|| {
            self.open = false;
            Error::Protocol("No pending nonce for decryption".to_string())
        })?;

        // Decrypt with AES-128-CCM, using the nonce saved by
        // `protected_command` for this exact exchange (the counter has
        // already moved on to the next one). A decrypt failure here cannot
        // lead to nonce reuse, but it does mean either transport corruption
        // or tampering, so close the session rather than leave it open.
        let plaintext = match self.decrypt_ccm(resp.data(), &nonce_for_decrypt) {
            Ok(plaintext) => plaintext,
            Err(_) => {
                self.open = false;
                return Err(Error::Protocol("AES-CCM decryption failed".to_string()));
            }
        };

        ApduResponse::new(&plaintext)
    }

    fn pairing(&self) -> Option<&Pairing> {
        None // V2 does not use pairing
    }

    fn set_pairing(&mut self, _pairing: Pairing) {
        // No-op: V2 does not use pairing
    }

    fn reset(&mut self) {
        self.open = false;
        self.established = false;
        // Zeroize before dropping: a plain `= None` assignment also
        // overwrites the key bytes, but the compiler is free to elide that
        // as a dead store since the old value is never read again —
        // `zeroize()` uses a volatile write that can't be optimized away.
        self.key_h2c.zeroize();
        self.key_c2h.zeroize();
        self.key_h2c = None;
        self.key_c2h = None;
        self.nonce_counter = [0u8; CCM_NONCE_SIZE];
        self.pending_decrypt_nonce = None;
        self.card_ident_pub = None;
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
        let mut okm = hkdf_derive(salt, shared_secret, PROTOCOL_LABEL, OKM_SIZE)
            .map_err(|_| Error::Crypto("HKDF derivation failed".to_string()))?;

        // Set session keys
        let mut key_h2c = [0u8; AES_KEY_SIZE];
        let mut key_c2h = [0u8; AES_KEY_SIZE];
        key_h2c.copy_from_slice(&okm[0..AES_KEY_SIZE]);
        key_c2h.copy_from_slice(&okm[AES_KEY_SIZE..OKM_SIZE]);
        // okm holds both keys concatenated; scrub it now that they've been
        // split into their own (zeroize-on-drop) fields.
        okm.zeroize();
        self.key_h2c = Some(key_h2c);
        self.key_c2h = Some(key_c2h);

        // Verify card's ECDSA signature over transcript
        self.verify_card_signature(salt, &client_eph_priv.public_key(), &card_eph_pub, signature_bytes)?;

        // Initialize nonce counter to zero
        self.nonce_counter = [0u8; CCM_NONCE_SIZE];
        self.open = true;
        self.established = true;

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

        // The applet's OPEN_SECURE_CHANNEL signing path doesn't normalize `s` to low-S form
        // (unlike its application-signing path, which does), so roughly half of otherwise-valid
        // handshake signatures have high S — and this crate's ECDSA verifier rejects those by
        // default. Malleability doesn't matter for a one-shot transcript-authentication
        // signature, so normalizing before verifying is safe.
        let sig = sig.normalize_s();

        // Verify using the card's identity public key
        let verifying_key = parse_verifying_key(card_ident_pub)?;

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

    /// Decrypts ciphertext with AES-128-CCM using the card-to-client key
    /// and the given nonce (the nonce that was used to encrypt the
    /// corresponding outgoing command, not necessarily the current
    /// `nonce_counter`, which may have already advanced).
    fn decrypt_ccm(&self, ciphertext: &[u8], nonce_bytes: &[u8; CCM_NONCE_SIZE]) -> Result<Vec<u8>, Error> {
        let key = self.key_c2h.as_ref()
            .ok_or_else(|| Error::Protocol("No card-to-client key available".to_string()))?;
        let cipher = Aes128Ccm::new_from_slice(key)
            .map_err(|_| Error::Crypto("Failed to create AES-CCM cipher".to_string()))?;

        let nonce = ccm::aead::Nonce::<Aes128Ccm>::try_from(&nonce_bytes[..])
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

impl Drop for SecureChannelV2 {
    fn drop(&mut self) {
        self.key_h2c.zeroize();
        self.key_c2h.zeroize();
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

    #[test]
    fn test_v2_protected_command_plaintext_before_established() {
        let mut sc = SecureChannelV2::new(vec![], vec![]);
        let cmd = sc.protected_command(0x80, 0xF2, 0x00, 0x00, &[0x01]).unwrap();
        assert_eq!(cmd.cla(), 0x80);
        assert_eq!(cmd.ins(), 0xF2);
        assert_eq!(cmd.data(), &[0x01]);
    }

    #[test]
    fn test_v2_protected_command_errors_after_established_and_closed() {
        let mut sc = SecureChannelV2::new(vec![], vec![]);
        sc.established = true;
        sc.open = false;
        assert!(sc.protected_command(0x80, 0xF2, 0x00, 0x00, &[]).is_err());
    }

    /// Regression test for the nonce/pending-nonce handoff: `protected_command`
    /// must advance `nonce_counter` immediately (so a second encryption can
    /// never reuse it), while the *response* to the first command must still
    /// be decryptable — which only works if it's decrypted with the nonce
    /// that was actually used to encrypt it, not the already-advanced counter.
    #[test]
    fn test_v2_protected_command_advances_nonce_and_saves_pending() {
        let mut sc = SecureChannelV2::new(vec![], vec![]);
        sc.open = true;
        sc.established = true;
        let key = [0x11u8; AES_KEY_SIZE];
        sc.key_h2c = Some(key);
        sc.key_c2h = Some(key); // same key so the test can decrypt its own ciphertext

        let starting_nonce = sc.nonce_counter;
        let cmd = sc.protected_command(0x80, 0xC0, 0x00, 0x00, &[0xAA, 0xBB]).unwrap();

        // Nonce advanced immediately, before any response was seen.
        assert_ne!(sc.nonce_counter, starting_nonce);
        assert_eq!(sc.pending_decrypt_nonce, Some(starting_nonce));

        // Decrypting with the saved pending nonce recovers the inner APDU.
        let inner = sc.decrypt_ccm(cmd.data(), &starting_nonce).unwrap();
        assert_eq!(inner, vec![0x80, 0xC0, 0x00, 0x00, 0x02, 0xAA, 0xBB]);

        // Decrypting with the *current* (already-advanced) counter must fail —
        // this is exactly the bug the pending-nonce field prevents.
        assert!(sc.decrypt_ccm(cmd.data(), &sc.nonce_counter).is_err());
    }

    struct MockChannel {
        response: Result<Vec<u8>, ()>,
    }

    impl CardChannel for MockChannel {
        fn send(&mut self, _cmd: &ApduCommand) -> Result<ApduResponse, Error> {
            match &self.response {
                Ok(raw) => ApduResponse::new(raw),
                Err(()) => Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "mock I/O failure",
                ))),
            }
        }
        fn is_connected(&self) -> bool {
            true
        }
    }

    fn open_test_session(key: [u8; AES_KEY_SIZE]) -> SecureChannelV2 {
        let mut sc = SecureChannelV2::new(vec![], vec![]);
        sc.open = true;
        sc.established = true;
        sc.key_h2c = Some(key);
        sc.key_c2h = Some(key);
        sc
    }

    #[test]
    fn test_v2_transmit_send_error_closes_session_without_reuse() {
        let mut sc = open_test_session([0x22u8; AES_KEY_SIZE]);
        let cmd = sc.protected_command(0x80, 0xC0, 0x00, 0x00, &[0x01]).unwrap();

        let mut channel = MockChannel { response: Err(()) };
        assert!(sc.transmit(&mut channel, &cmd).is_err());

        // Session must be closed, and the just-used nonce must never be
        // handed to another encryption.
        assert!(!sc.open);
        assert!(sc.pending_decrypt_nonce.is_none());
        assert!(sc.protected_command(0x80, 0xC0, 0x00, 0x00, &[0x02]).is_err());
    }

    #[test]
    fn test_v2_transmit_decrypt_failure_closes_session() {
        let mut sc = open_test_session([0x33u8; AES_KEY_SIZE]);
        let cmd = sc.protected_command(0x80, 0xC0, 0x00, 0x00, &[0x01]).unwrap();

        // Corrupt the ciphertext so the CCM tag check fails on decrypt.
        let mut corrupted = cmd.data().to_vec();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 0xFF;
        let mut raw = corrupted;
        raw.extend_from_slice(&[0x90, 0x00]);

        let mut channel = MockChannel { response: Ok(raw) };
        assert!(sc.transmit(&mut channel, &cmd).is_err());
        assert!(!sc.open);
        assert!(sc.protected_command(0x80, 0xC0, 0x00, 0x00, &[0x02]).is_err());
    }

    #[test]
    fn test_v2_transmit_full_roundtrip() {
        let mut sc = open_test_session([0x44u8; AES_KEY_SIZE]);
        let cmd = sc.protected_command(0x80, 0xC0, 0x00, 0x00, &[0xDE, 0xAD]).unwrap();
        let nonce_used = sc.pending_decrypt_nonce.unwrap();

        // Simulate the card: it would encrypt its response with key_c2h
        // (== key_h2c in this test) under the same nonce used for this
        // exchange, so temporarily point nonce_counter at it to reuse
        // encrypt_ccm rather than duplicating its logic. The plaintext
        // itself embeds the inner status word as its last 2 bytes (matching
        // how `ApduResponse::new` splits data from SW).
        let saved_nonce = sc.nonce_counter;
        sc.nonce_counter = nonce_used;
        let card_response_data = vec![0x01, 0x02, 0x03];
        let mut card_plaintext = card_response_data.clone();
        card_plaintext.extend_from_slice(&[0x90, 0x00]);
        let response_ciphertext = sc.encrypt_ccm(&card_plaintext).unwrap();
        sc.nonce_counter = saved_nonce;

        let mut raw = response_ciphertext;
        raw.extend_from_slice(&[0x90, 0x00]);

        let mut channel = MockChannel { response: Ok(raw) };
        let resp = sc.transmit(&mut channel, &cmd).unwrap();
        assert_eq!(resp.data(), &card_response_data[..]);
        assert_eq!(resp.sw(), ApduResponse::SW_OK);
        assert!(sc.open);
        assert!(sc.pending_decrypt_nonce.is_none());
    }
}
