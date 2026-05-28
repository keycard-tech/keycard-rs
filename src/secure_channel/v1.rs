//! Secure Channel V1 implementation.
//!
//! Uses AES-256-CBC with AES-CBC-MAC for encryption and authentication,
//! with pairing-based key derivation via ECDH on secp256k1.

use aes::{Aes256, cipher::{BlockCipherEncrypt, BlockModeEncrypt, BlockModeDecrypt, KeyInit, KeyIvInit}};
use cbc::{Encryptor, Decryptor};
use k256::{AffinePoint, ecdh::EphemeralSecret};
use k256::elliptic_curve::sec1::ToSec1Point;
use sha2::{Digest, Sha512, Sha256};

use crate::apdu::{ApduCommand, ApduResponse};
use crate::channel::CardChannel;
use crate::constants::ins;
use crate::error::Error;
use crate::secure_channel::{SecureChannel, SecureChannelVersion, Pairing};

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

/// AES block size in bytes.
const SC_BLOCK_SIZE: usize = 16;
/// ECDH shared secret length in bytes.
const SC_SECRET_LENGTH: usize = 32;
/// Maximum number of pairing slots on the card.
const PAIRING_MAX_CLIENT_COUNT: usize = 5;

/// Secure Channel V1 session.
pub struct SecureChannelV1 {
    /// ECDH shared secret with the card's static key.
    secret: Option<[u8; SC_SECRET_LENGTH]>,
    /// Client's uncompressed ephemeral public key (65 bytes).
    public_key: Option<Vec<u8>>,
    /// Current IV (doubles as MAC in V1 protocol).
    iv: [u8; SC_BLOCK_SIZE],
    /// Current pairing data.
    pairing: Option<Pairing>,
    /// AES encryption key (derived).
    enc_key: Option<[u8; 32]>,
    /// AES-CBC-MAC key (derived).
    mac_key: Option<[u8; 32]>,
    /// Whether the secure channel session is active.
    open: bool,
}

impl SecureChannelV1 {
    pub fn new() -> Self {
        Self {
            secret: None,
            public_key: None,
            iv: [0u8; SC_BLOCK_SIZE],
            pairing: None,
            enc_key: None,
            mac_key: None,
            open: false,
        }
    }

    /// Generates an ephemeral ECDH key pair and computes the shared secret
    /// with the card's static public key.
    pub fn generate_secret(&mut self, card_pub_key: &[u8]) {
        use k256::elliptic_curve::Generate;

        // Decode the card's public key
        let card_public = k256::PublicKey::from_sec1_bytes(card_pub_key)
            .expect("Invalid card public key");

        // Generate ephemeral key pair
        let mut rng = getrandom_04::SysRng;
        let sk = EphemeralSecret::try_generate_from_rng(&mut rng)
            .expect("Failed to generate ephemeral secret");
        let client_public = sk.public_key();

        // Store uncompressed public key (65 bytes: 0x04 || x || y)
        let affine: AffinePoint = client_public.into();
        let uncompressed = affine.to_sec1_point(false); // false = uncompressed
        self.public_key = Some(uncompressed.to_bytes().to_vec());

        // Compute ECDH shared secret
        let shared = sk.diffie_hellman(&card_public);
        let mut secret = [0u8; SC_SECRET_LENGTH];
        secret.copy_from_slice(shared.raw_secret_bytes());
        self.secret = Some(secret);
    }

    /// Returns the client's public key.
    pub fn get_public_key(&self) -> Option<&[u8]> {
        self.public_key.as_deref()
    }

    /// Encrypts the payload for the INIT command (one-shot encryption).
    ///
    /// Uses the ECDH shared secret as the AES key with a random IV.
    /// Output format: `[pub_key_len] || public_key || iv || encrypted_data`
    pub fn one_shot_encrypt(&mut self, init_data: &[u8]) -> Result<Vec<u8>, Error> {
        let secret = self.secret.as_ref()
            .ok_or_else(|| Error::Protocol("No ECDH secret available for one-shot encrypt".to_string()))?;
        let public_key = self.public_key.as_ref()
            .ok_or_else(|| Error::Protocol("No public key available for one-shot encrypt".to_string()))?;

        // Generate random IV
        let mut iv = [0u8; SC_BLOCK_SIZE];
        getrandom::getrandom(&mut iv).map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;

        // Encrypt with AES-CBC using ISO 7816-4 padding
        let enc = Aes256CbcEnc::new_from_slices(secret, &iv)
            .map_err(|_| Error::Crypto("Failed to create AES-CBC encryptor".to_string()))?;
        let mut buf = vec![0u8; init_data.len() + SC_BLOCK_SIZE];
        buf[..init_data.len()].copy_from_slice(init_data);
        let encrypted = enc.encrypt_padded::<aes::cipher::block_padding::Iso7816>(&mut buf, init_data.len())
            .map_err(|_| Error::Crypto("AES-CBC encryption failed".to_string()))?;
        let encrypted = encrypted.to_vec();

        // Build output: [pub_key_len] || public_key || iv || encrypted_data
        let mut output = Vec::with_capacity(1 + public_key.len() + iv.len() + encrypted.len());
        output.push(public_key.len() as u8);
        output.extend_from_slice(public_key);
        output.extend_from_slice(&iv);
        output.extend_from_slice(&encrypted);
        Ok(output)
    }
}

impl Default for SecureChannelV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureChannel for SecureChannelV1 {
    fn auto_open(&mut self, channel: &mut dyn CardChannel) -> Result<(), Error> {
        let public_key = self.public_key.clone()
            .ok_or_else(|| Error::Protocol("No public key available. Call generate_secret first.".to_string()))?;
        let pairing_index = self.pairing.as_ref()
            .ok_or_else(|| Error::Protocol("No pairing data available. Call set_pairing or auto_pair first.".to_string()))?
            .pairing_index();

        // Open secure channel
        let response = self.open_secure_channel(channel, pairing_index, &public_key)?;
        response.check_ok()?;
        self.process_open_response(&response)?;

        // Mutual authentication
        let response = self.mutually_authenticate(channel)?;
        response.check_ok()?;
        self.verify_mutual_auth_response(&response)?;

        Ok(())
    }

    fn auto_pair(
        &mut self,
        channel: &mut dyn CardChannel,
        mode: u8,
        shared_secret: &[u8],
    ) -> Result<(), Error> {
        // Generate random client challenge
        let mut client_challenge = [0u8; 32];
        getrandom::getrandom(&mut client_challenge)
            .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;

        // Step 1: Send client challenge
        let resp = self.pair(channel, 0x00, mode, &client_challenge)?;
        resp.check_ok()?;

        let resp_data = resp.data();
        if resp_data.len() < 64 {
            return Err(Error::Protocol("Pairing response too short".to_string()));
        }

        let card_cryptogram = &resp_data[0..32];
        let card_challenge = &resp_data[32..];

        // Verify card cryptogram: SHA-256(shared_secret || client_challenge)
        let mut hasher = Sha256::new();
        hasher.update(shared_secret);
        hasher.update(&client_challenge);
        let expected = hasher.finalize();

        if card_cryptogram != expected.as_slice() {
            return Err(Error::Protocol("Invalid card cryptogram".to_string()));
        }

        // Compute client cryptogram: SHA-256(shared_secret || card_challenge)
        let mut hasher = Sha256::new();
        hasher.update(shared_secret);
        hasher.update(card_challenge);
        let client_cryptogram = hasher.finalize();

        // Step 2: Send client cryptogram
        let resp = self.pair(channel, 0x01, 0x00, &client_cryptogram)?;
        resp.check_ok()?;

        let resp_data = resp.data();
        if resp_data.len() < 2 {
            return Err(Error::Protocol("Pairing step 2 response too short".to_string()));
        }

        let pairing_index = resp_data[0];

        // Derive pairing key: SHA-256(shared_secret || resp_data[1..])
        let mut hasher = Sha256::new();
        hasher.update(shared_secret);
        hasher.update(&resp_data[1..]);
        let derived = hasher.finalize();
        let mut pairing_key = [0u8; 32];
        pairing_key.copy_from_slice(&derived);

        self.pairing = Some(Pairing::new(pairing_key, pairing_index));
        Ok(())
    }

    fn auto_unpair(&mut self, channel: &mut dyn CardChannel) -> Result<(), Error> {
        let pairing = self.pairing.as_ref()
            .ok_or_else(|| Error::Protocol("No pairing data available".to_string()))?;
        self.unpair(channel, pairing.pairing_index())?;
        Ok(())
    }

    fn unpair_others(&mut self, channel: &mut dyn CardChannel) -> Result<(), Error> {
        let current_index = self.pairing.as_ref()
            .map(|p| p.pairing_index())
            .unwrap_or(0xFF);

        for i in 0..PAIRING_MAX_CLIENT_COUNT {
            if (i as u8) != current_index {
                let cmd = self.protected_command(0x80, ins::UNPAIR, i as u8, 0, &[]);
                self.transmit(channel, &cmd)?.check_ok()?;
            }
        }
        Ok(())
    }

    fn open_secure_channel(
        &mut self,
        channel: &mut dyn CardChannel,
        index: u8,
        data: &[u8],
    ) -> Result<ApduResponse, Error> {
        self.open = false;
        let cmd = ApduCommand::new(0x80, ins::OPEN_SECURE_CHANNEL, index, 0, data.to_vec());
        channel.send(&cmd)
    }

    fn mutually_authenticate(
        &mut self,
        channel: &mut dyn CardChannel,
    ) -> Result<ApduResponse, Error> {
        let mut data = [0u8; SC_SECRET_LENGTH];
        getrandom::getrandom(&mut data)
            .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;
        self.mutually_authenticate_with_data(channel, &data)
    }

    fn mutually_authenticate_with_data(
        &mut self,
        channel: &mut dyn CardChannel,
        data: &[u8],
    ) -> Result<ApduResponse, Error> {
        let cmd = self.protected_command(0x80, ins::MUTUALLY_AUTHENTICATE, 0, 0, data);
        self.transmit(channel, &cmd)
    }

    fn pair(
        &mut self,
        channel: &mut dyn CardChannel,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> Result<ApduResponse, Error> {
        let cmd = ApduCommand::new(0x80, ins::PAIR, p1, p2, data.to_vec());
        self.transmit(channel, &cmd)
    }

    fn unpair(
        &mut self,
        channel: &mut dyn CardChannel,
        p1: u8,
    ) -> Result<ApduResponse, Error> {
        let cmd = self.protected_command(0x80, ins::UNPAIR, p1, 0, &[]);
        self.transmit(channel, &cmd)
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

        let enc_key = self.enc_key.as_ref()
            .expect("Session encryption key not set");

        // Encrypt data with AES-CBC using ISO 7816-4 padding
        let enc = Aes256CbcEnc::new_from_slices(enc_key, &self.iv)
            .expect("Invalid AES key/IV");
        let mut buf = vec![0u8; data.len() + SC_BLOCK_SIZE];
        buf[..data.len()].copy_from_slice(data);
        let encrypted = enc.encrypt_padded::<aes::cipher::block_padding::Iso7816>(&mut buf, data.len())
            .expect("AES-CBC encryption failed");
        let encrypted = encrypted.to_vec();

        // Build metadata for MAC
        let mut meta = [0u8; SC_BLOCK_SIZE];
        meta[0] = cla;
        meta[1] = ins;
        meta[2] = p1;
        meta[3] = p2;
        meta[4] = (encrypted.len() + SC_BLOCK_SIZE) as u8;

        // Update IV with MAC
        self.update_iv(&meta, &encrypted);

        // Final data: iv || encrypted_data
        let mut final_data = Vec::with_capacity(SC_BLOCK_SIZE + encrypted.len());
        final_data.extend_from_slice(&self.iv);
        final_data.extend_from_slice(&encrypted);

        ApduCommand::new(cla, ins, p1, p2, final_data)
    }

    fn transmit(
        &mut self,
        channel: &mut dyn CardChannel,
        cmd: &ApduCommand,
    ) -> Result<ApduResponse, Error> {
        let resp = channel.send(cmd)?;

        // If security condition not satisfied, invalidate session
        if resp.sw() == ApduResponse::SW_SECURITY_CONDITION_NOT_SATISFIED {
            self.open = false;
        }

        if self.open {
            let data = resp.data();
            if data.len() < SC_BLOCK_SIZE {
                return Err(Error::Protocol("Encrypted response too short".to_string()));
            }

            let mac = &data[0..SC_BLOCK_SIZE];
            let encrypted = &data[SC_BLOCK_SIZE..];

            // Build metadata for MAC verification
            let mut meta = [0u8; SC_BLOCK_SIZE];
            meta[0] = data.len() as u8;

            // Decrypt
            let enc_key = self.enc_key.as_ref().expect("Session encryption key not set");
            let dec = Aes256CbcDec::new_from_slices(enc_key, &self.iv)
                .expect("Invalid AES key/IV");
            let mut encrypted_buf = encrypted.to_vec();
            let plain_data = dec.decrypt_padded::<aes::cipher::block_padding::Iso7816>(&mut encrypted_buf)
                .map_err(|_| Error::Protocol("AES-CBC decryption failed".to_string()))?;
            let plain_data = plain_data.to_vec();

            // Update IV with MAC
            self.update_iv(&meta, encrypted);

            // Verify MAC
            if &self.iv != mac {
                return Err(Error::Protocol("Invalid MAC".to_string()));
            }

            // Return decrypted response (the inner SW is embedded in the plaintext)
            Ok(ApduResponse::new(&plain_data)?)
        } else {
            Ok(resp)
        }
    }

    fn pairing(&self) -> Option<&Pairing> {
        self.pairing.as_ref()
    }

    fn set_pairing(&mut self, pairing: Pairing) {
        self.pairing = Some(pairing);
    }

    fn reset(&mut self) {
        self.open = false;
        self.enc_key = None;
        self.mac_key = None;
        self.iv = [0u8; SC_BLOCK_SIZE];
    }

    fn version(&self) -> SecureChannelVersion {
        SecureChannelVersion::V1
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

impl SecureChannelV1 {
    /// Processes the OPEN SECURE CHANNEL response to derive session keys.
    fn process_open_response(&mut self, response: &ApduResponse) -> Result<(), Error> {
        let secret = self.secret.as_ref()
            .ok_or_else(|| Error::Protocol("No ECDH secret available".to_string()))?;
        let pairing = self.pairing.as_ref()
            .ok_or_else(|| Error::Protocol("No pairing data available".to_string()))?;

        let data = response.data();
        if data.len() < SC_SECRET_LENGTH + SC_BLOCK_SIZE {
            return Err(Error::Protocol("OPEN SECURE CHANNEL response too short".to_string()));
        }

        // key_data = SHA-512(secret || pairing_key || data[0..32])
        // (Java: md.update(secret); md.update(pairing.getPairingKey());
        //  md.digest(Arrays.copyOf(data, SC_SECRET_LENGTH)))
        let mut hasher = Sha512::new();
        hasher.update(secret);
        hasher.update(pairing.pairing_key());
        hasher.update(&data[0..SC_SECRET_LENGTH]);
        let key_data = hasher.finalize();

        // enc_key = key_data[0..32], mac_key = key_data[32..64]
        let mut enc_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        enc_key.copy_from_slice(&key_data[0..32]);
        mac_key.copy_from_slice(&key_data[32..64]);

        // IV = data[32..] (the salt/seed-IV from the card)
        let iv_data = &data[SC_SECRET_LENGTH..];
        self.iv.copy_from_slice(&iv_data[0..SC_BLOCK_SIZE]);

        self.enc_key = Some(enc_key);
        self.mac_key = Some(mac_key);
        self.open = true;

        Ok(())
    }

    /// Verifies the MUTUALLY AUTHENTICATE response.
    fn verify_mutual_auth_response(&self, response: &ApduResponse) -> Result<(), Error> {
        if response.data().len() != SC_SECRET_LENGTH {
            return Err(Error::Protocol("Invalid authentication data from the card".to_string()));
        }
        Ok(())
    }

    /// Computes AES-CBC-MAC and stores result as new IV.
    fn update_iv(&mut self, meta: &[u8], data: &[u8]) {
        let mac_key = self.mac_key.as_ref().expect("MAC key not set");

        // CBC-MAC: encrypt meta || data block by block, last block is the MAC
        let cipher = Aes256::new_from_slice(mac_key).expect("Invalid AES key");
        let mut block = [0u8; SC_BLOCK_SIZE];

        // Process all blocks of meta + data
        let mut combined = Vec::with_capacity(meta.len() + data.len());
        combined.extend_from_slice(meta);
        combined.extend_from_slice(data);

        // CBC-MAC (no padding, just process full blocks)
        let num_blocks = combined.len() / SC_BLOCK_SIZE;
        for i in 0..num_blocks {
            let start = i * SC_BLOCK_SIZE;
            let chunk = &combined[start..start + SC_BLOCK_SIZE];
            // XOR with previous block (IV for first block)
            for j in 0..SC_BLOCK_SIZE {
                block[j] ^= chunk[j];
            }
            // Encrypt block in place
            let mut block_array: aes::cipher::Array<u8, typenum::consts::U16> =
                (&block[..]).try_into().expect("block size mismatch");
            cipher.encrypt_block(&mut block_array);
            block.copy_from_slice(&block_array);
        }

        self.iv.copy_from_slice(&block);
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v1_new_state() {
        let sc = SecureChannelV1::new();
        assert!(!sc.open);
        assert!(sc.pairing().is_none());
    }

    #[test]
    fn test_v1_protected_command_not_open() {
        let mut sc = SecureChannelV1::new();
        let cmd = sc.protected_command(0x80, 0xF2, 0x00, 0x00, &[0x01, 0x02]);
        assert_eq!(cmd.cla(), 0x80);
        assert_eq!(cmd.ins(), 0xF2);
        assert_eq!(cmd.data(), &[0x01, 0x02]);
    }

    #[test]
    fn test_v1_unpair_others_no_pairing() {
        let _sc = SecureChannelV1::new();
        // Without pairing, unpair_others should error
        // We can't test the full flow without a mock channel
    }
}
