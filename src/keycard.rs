//! KeycardCommandSet — the main API for interacting with a Status Keycard.
//!
//! This module provides the `KeycardCommandSet` struct which wraps a `CardChannel`
//! transport and a `SecureChannel` implementation to send APDU commands to the
//! Keycard applet.

use std::str::FromStr;

use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

use crate::apdu::{ApduCommand, ApduResponse};
use crate::channel::CardChannel;
use crate::constants::{
    self, keycard_instance_aid,
    ins,
    change_pin_p1,
    derive_p1,
    export_key_p1,
    export_key_p2,
    factory_reset,
    load_key_p1,
    pair_p2,
    sign_p1,
    sign_p2,
    store_data_p1,
};
use crate::error::Error;
use crate::parsing::{ApplicationInfo, Bip32KeyPair, KeyPath};
use crate::secure_channel::{
    SecureChannel, SecureChannelV1, SecureChannelV2, SecureChannelVersion, Pairing,
};

/// The main API for sending APDU commands to a Status Keycard.
///
/// The secure channel version (V1 or V2) is auto-detected based on the applet
/// version after the first SELECT command.
pub struct KeycardCommandSet {
    /// The APDU transport channel.
    channel: Box<dyn CardChannel>,
    /// Current secure channel implementation.
    secure_channel: Box<dyn SecureChannel>,
    /// Cached application info from the last SELECT.
    info: Option<ApplicationInfo>,
    /// Trusted CA public keys for V2 certificate verification.
    ca_public_keys: Vec<[u8; 33]>,
    /// Whitelisted card identity public keys for V2.
    whitelisted_card_public_keys: Vec<[u8; 33]>,
}

impl KeycardCommandSet {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Creates a `KeycardCommandSet` using the given APDU channel.
    ///
    /// Uses the default Status CA public key for V2 certificate verification.
    pub fn new(channel: impl CardChannel + 'static) -> Self {
        Self::new_with_ca(channel, constants::DEFAULT_CA_PUBLIC_KEY)
    }

    /// Creates a `KeycardCommandSet` with a single trusted CA public key.
    ///
    /// # Arguments
    /// * `channel` — The APDU transport.
    /// * `ca_public_key` — Compressed secp256k1 CA public key (33 bytes).
    pub fn new_with_ca(channel: impl CardChannel + 'static, ca_public_key: [u8; 33]) -> Self {
        Self::new_with_cas(channel, vec![ca_public_key], vec![])
    }

    /// Creates a `KeycardCommandSet` with custom trusted CA keys and
    /// optionally whitelisted card identity keys.
    ///
    /// # Arguments
    /// * `channel` — The APDU transport.
    /// * `ca_public_keys` — Compressed secp256k1 CA public keys (33 bytes each).
    /// * `whitelisted_card_public_keys` — Compressed card identity public keys (33 bytes each).
    pub fn new_with_cas(
        channel: impl CardChannel + 'static,
        ca_public_keys: Vec<[u8; 33]>,
        whitelisted_card_public_keys: Vec<[u8; 33]>,
    ) -> Self {
        Self {
            channel: Box::new(channel),
            secure_channel: Box::new(SecureChannelV2::new(
                ca_public_keys.clone(),
                whitelisted_card_public_keys.clone(),
            )),
            info: None,
            ca_public_keys,
            whitelisted_card_public_keys,
        }
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// Returns the application info from the last SELECT command.
    pub fn app_info(&self) -> Option<&ApplicationInfo> {
        self.info.as_ref()
    }

    /// Returns the secure channel version in use (if secure channel is supported).
    ///
    /// Returns `None` if the applet has not been selected yet, or if the card
    /// does not support secure channels.
    pub fn secure_channel_version(&self) -> Option<SecureChannelVersion> {
        self.info
            .as_ref()
            .filter(|i| i.has_secure_channel())
            .map(|_| self.secure_channel.version())
    }

    /// Returns a reference to the current secure channel.
    pub fn secure_channel(&self) -> &dyn SecureChannel {
        &*self.secure_channel
    }

    /// Returns the current pairing data (V1 only, `None` for V2).
    pub fn pairing(&self) -> Option<&Pairing> {
        self.secure_channel.pairing()
    }

    /// Sets the pairing data (V1 only, no-op for V2).
    pub fn set_pairing(&mut self, pairing: Pairing) {
        self.secure_channel.set_pairing(pairing);
    }

    // -----------------------------------------------------------------------
    // SELECT
    // -----------------------------------------------------------------------

    /// Selects the default instance (index 1) of the Keycard applet.
    ///
    /// Parses the response as `ApplicationInfo` and auto-selects the correct
    /// secure channel version (V1 or V2) based on applet version.
    pub fn select(&mut self) -> Result<ApduResponse, Error> {
        self.select_with_index(constants::KEYCARD_DEFAULT_INSTANCE_IDX)
    }

    /// Selects a specific Keycard instance by index.
    ///
    /// # Arguments
    /// * `instance_idx` — The instance index (1..=255).
    pub fn select_with_index(&mut self, instance_idx: u8) -> Result<ApduResponse, Error> {
        let aid = keycard_instance_aid(instance_idx);
        let cmd = ApduCommand::new(0x00, 0xA4, 4, 0, aid);
        let resp = self.channel.send(&cmd)?;

        if resp.sw() == ApduResponse::SW_OK {
            self.info = Some(ApplicationInfo::from_tlv(resp.data())?);

            if self.info.as_ref().is_some_and(|i| i.has_secure_channel()) {
                if Self::is_secure_channel_v2(self.info.as_ref().unwrap()) {
                    let mut sc_v2 = SecureChannelV2::new(
                        self.ca_public_keys.clone(),
                        self.whitelisted_card_public_keys.clone(),
                    );
                    if let Some(cert_data) = self.info.as_ref().unwrap().cert_data() {
                        sc_v2.set_card_certificate(cert_data)?;
                    }
                    self.secure_channel = Box::new(sc_v2);
                } else {
                    let mut sc_v1 = SecureChannelV1::new();
                    if let Some(pub_key) = self.info.as_ref().unwrap().secure_channel_pub_key() {
                        sc_v1.generate_secret(pub_key);
                    }
                    self.secure_channel = Box::new(sc_v1);
                }
            }
        }

        Ok(resp)
    }

    /// Returns `true` if the applet uses Secure Channel V2 (app version >= 4.0).
    fn is_secure_channel_v2(app_info: &ApplicationInfo) -> bool {
        app_info.app_version() >= 0x0400
    }

    // -----------------------------------------------------------------------
    // Secure Channel lifecycle
    // -----------------------------------------------------------------------

    /// Opens the secure channel.
    pub fn auto_open_secure_channel(&mut self) -> Result<(), Error> {
        self.secure_channel.auto_open(&mut *self.channel)
    }

    /// Automatically pairs using a password (derived via PBKDF2).
    pub fn auto_pair(&mut self, pairing_password: &str) -> Result<(), Error> {
        self.auto_pair_with_mode(pairing_password, pair_p2::ANY)
    }

    /// Automatically pairs using a password with explicit mode.
    pub fn auto_pair_with_mode(
        &mut self,
        pairing_password: &str,
        mode: u8,
    ) -> Result<(), Error> {
        let secret = self.pairing_password_to_secret(pairing_password);
        self.auto_pair_with_secret_and_mode(&secret, mode)
    }

    /// Converts a pairing password to a binary pairing secret via PBKDF2-HMAC-SHA256.
    pub fn pairing_password_to_secret(&self, pairing_password: &str) -> Vec<u8> {
        let iterations = self.channel.pairing_password_pbkdf2_iterations();
        let mut output = vec![0u8; 32];
        pbkdf2_hmac::<Sha256>(
            pairing_password.as_bytes(),
            constants::PAIRING_PASSWORD_SALT,
            iterations,
            &mut output,
        );
        output
    }

    /// Automatically pairs using a raw binary shared secret.
    pub fn auto_pair_with_secret(&mut self, shared_secret: &[u8]) -> Result<(), Error> {
        self.auto_pair_with_secret_and_mode(shared_secret, pair_p2::ANY)
    }

    /// Automatically pairs using a raw binary shared secret with explicit mode.
    pub fn auto_pair_with_secret_and_mode(
        &mut self,
        shared_secret: &[u8],
        mode: u8,
    ) -> Result<(), Error> {
        self.secure_channel
            .auto_pair(&mut *self.channel, mode, shared_secret)
    }

    /// Automatically unpairs the current pairing.
    pub fn auto_unpair(&mut self) -> Result<(), Error> {
        self.secure_channel.auto_unpair(&mut *self.channel)
    }

    /// Unpair all other clients (V1 only).
    pub fn unpair_others(&mut self) -> Result<(), Error> {
        self.secure_channel.unpair_others(&mut *self.channel)
    }

    // -----------------------------------------------------------------------
    // Low-level Secure Channel commands (V1)
    // -----------------------------------------------------------------------

    /// Sends an OPEN SECURE CHANNEL APDU.
    pub fn open_secure_channel(
        &mut self,
        index: u8,
        data: &[u8],
    ) -> Result<ApduResponse, Error> {
        self.secure_channel
            .open_secure_channel(&mut *self.channel, index, data)
    }

    /// Sends a MUTUALLY AUTHENTICATE APDU (V1 only).
    pub fn mutually_authenticate(&mut self) -> Result<ApduResponse, Error> {
        self.secure_channel
            .mutually_authenticate(&mut *self.channel)
    }

    /// Sends a MUTUALLY AUTHENTICATE APDU with explicit data (V1 only).
    pub fn mutually_authenticate_with_data(
        &mut self,
        data: &[u8],
    ) -> Result<ApduResponse, Error> {
        self.secure_channel
            .mutually_authenticate_with_data(&mut *self.channel, data)
    }

    /// Sends a PAIR APDU (V1 only).
    pub fn pair(&mut self, p1: u8, p2: u8, data: &[u8]) -> Result<ApduResponse, Error> {
        self.secure_channel
            .pair(&mut *self.channel, p1, p2, data)
    }

    /// Sends an UNPAIR APDU (V1 only).
    pub fn unpair(&mut self, p1: u8) -> Result<ApduResponse, Error> {
        self.secure_channel.unpair(&mut *self.channel, p1)
    }

    // -----------------------------------------------------------------------
    // APDU commands — Card identification
    // -----------------------------------------------------------------------

    /// Wraps `data` in the secure channel (CLA 0x80) and transmits it.
    ///
    /// Every protected command shares this shape; this just avoids repeating
    /// the `protected_command` + `transmit` pair at every call site below.
    fn send_protected(&mut self, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Result<ApduResponse, Error> {
        let cmd = self.secure_channel.protected_command(0x80, ins, p1, p2, data)?;
        self.secure_channel.transmit(&mut *self.channel, &cmd)
    }

    /// Sends an IDENTIFY CARD APDU.
    ///
    /// The challenge must be 32 bytes long.
    pub fn identify_card(&mut self, challenge: &[u8]) -> Result<ApduResponse, Error> {
        self.send_protected(ins::IDENTIFY_CARD, 0, 0, challenge)
    }

    // -----------------------------------------------------------------------
    // APDU commands — Status
    // -----------------------------------------------------------------------

    /// Sends a GET STATUS APDU.
    ///
    /// # Arguments
    /// * `info` — The P1 parameter (use `get_status_p1::APPLICATION` or `KEY_PATH`).
    pub fn get_status(&mut self, info: u8) -> Result<ApduResponse, Error> {
        self.send_protected(ins::GET_STATUS, info, 0, &[])
    }

    // -----------------------------------------------------------------------
    // APDU commands — PIN management
    // -----------------------------------------------------------------------

    /// Sends a VERIFY PIN APDU.
    pub fn verify_pin(&mut self, pin: &str) -> Result<ApduResponse, Error> {
        self.send_protected(ins::VERIFY_PIN, 0, 0, pin.as_bytes())
    }

    /// Sends a CHANGE PIN APDU to change the user PIN.
    pub fn change_pin(&mut self, pin: &str) -> Result<ApduResponse, Error> {
        self.change_pin_with_type(change_pin_p1::USER_PIN, pin.as_bytes())
    }

    /// Sends a CHANGE PIN APDU to change the PUK.
    pub fn change_puk(&mut self, puk: &str) -> Result<ApduResponse, Error> {
        self.change_pin_with_type(change_pin_p1::PUK, puk.as_bytes())
    }

    /// Sends a CHANGE PIN APDU to change the pairing password.
    ///
    /// This does not break existing pairings, but new pairings will use the new password.
    pub fn change_pairing_password(&mut self, pairing_password: &str) -> Result<ApduResponse, Error> {
        let secret = self.pairing_password_to_secret(pairing_password);
        self.change_pin_with_type(change_pin_p1::PAIRING_SECRET, &secret)
    }

    /// Sends a CHANGE PIN APDU with explicit pin type.
    pub fn change_pin_with_type(&mut self, pin_type: u8, pin: &[u8]) -> Result<ApduResponse, Error> {
        self.send_protected(ins::CHANGE_PIN, pin_type, 0, pin)
    }

    /// Sends an UNBLOCK PIN APDU.
    ///
    /// The PUK and new PIN are concatenated.
    pub fn unblock_pin(&mut self, puk: &str, new_pin: &str) -> Result<ApduResponse, Error> {
        let mut data = puk.as_bytes().to_vec();
        data.extend_from_slice(new_pin.as_bytes());
        self.send_protected(ins::UNBLOCK_PIN, 0, 0, &data)
    }

    // -----------------------------------------------------------------------
    // APDU commands — Key management
    // -----------------------------------------------------------------------

    /// Sends a LOAD KEY APDU with a BIP32 seed (P1 = SEED).
    pub fn load_key(&mut self, seed: &[u8]) -> Result<ApduResponse, Error> {
        self.load_key_raw(seed, load_key_p1::SEED)
    }

    /// Sends a LOAD KEY APDU for LEE mode (P1 = LEE).
    pub fn load_lee_key(&mut self, seed: &[u8]) -> Result<ApduResponse, Error> {
        self.load_key_raw(seed, load_key_p1::LEE)
    }

    /// Sends a LOAD KEY APDU with a BIP32 keypair (includes public key).
    pub fn load_key_bip32(&mut self, key_pair: &Bip32KeyPair) -> Result<ApduResponse, Error> {
        self.load_key_bip32_inner(key_pair, false)
    }

    /// Sends a LOAD KEY APDU with a BIP32 keypair (omits public key).
    pub fn load_key_bip32_omit_public(
        &mut self,
        key_pair: &Bip32KeyPair,
    ) -> Result<ApduResponse, Error> {
        self.load_key_bip32_inner(key_pair, true)
    }

    fn load_key_bip32_inner(
        &mut self,
        key_pair: &Bip32KeyPair,
        omit_public: bool,
    ) -> Result<ApduResponse, Error> {
        let p1 = if key_pair.is_extended() {
            load_key_p1::EXT_EC
        } else {
            load_key_p1::EC
        };
        self.load_key_raw(&key_pair.to_tlv(!omit_public), p1)
    }

    /// Sends a LOAD KEY APDU with raw data and explicit key type (P1).
    pub fn load_key_raw(&mut self, data: &[u8], key_type: u8) -> Result<ApduResponse, Error> {
        self.send_protected(ins::LOAD_KEY, key_type, 0, data)
    }

    /// Sends a GENERATE MNEMONIC APDU.
    ///
    /// # Arguments
    /// * `cs` — The P1 parameter (use `generate_mnemonic::WORDS_12`, etc.).
    pub fn generate_mnemonic(&mut self, cs: u8) -> Result<ApduResponse, Error> {
        self.send_protected(ins::GENERATE_MNEMONIC, cs, 0, &[])
    }

    /// Sends a REMOVE KEY APDU.
    pub fn remove_key(&mut self) -> Result<ApduResponse, Error> {
        self.send_protected(ins::REMOVE_KEY, 0, 0, &[])
    }

    /// Sends a GENERATE KEY APDU.
    pub fn generate_key(&mut self) -> Result<ApduResponse, Error> {
        self.send_protected(ins::GENERATE_KEY, 0, 0, &[])
    }

    // -----------------------------------------------------------------------
    // APDU commands — Signing
    // -----------------------------------------------------------------------

    /// Signs a precomputed 32-byte hash with the current key (ECDSA).
    pub fn sign(&mut self, hash: &[u8]) -> Result<ApduResponse, Error> {
        self.sign_raw(hash, sign_p1::CURRENT_KEY, sign_p2::ECDSA)
    }

    /// Signs a hash with a derived key path (ECDSA).
    ///
    /// # Arguments
    /// * `hash` — The 32-byte hash to sign.
    /// * `path` — BIP32 path string (e.g. `"m/44'/60'/0'/0/0"`).
    /// * `make_current` — Whether to make the derived key the current key.
    pub fn sign_with_path(
        &mut self,
        hash: &[u8],
        path: &str,
        make_current: bool,
    ) -> Result<ApduResponse, Error> {
        self.sign_with_path_and_algo(hash, path, sign_p2::ECDSA, make_current)
    }

    /// Signs a hash with a derived key path and explicit algorithm.
    ///
    /// # Arguments
    /// * `hash` — The 32-byte hash to sign.
    /// * `path` — BIP32 path string.
    /// * `algo` — Signing algorithm (`sign_p2::ECDSA`, `EDDSA_ED25519`, etc.).
    /// * `make_current` — Whether to make the derived key the current key.
    pub fn sign_with_path_and_algo(
        &mut self,
        hash: &[u8],
        path: &str,
        algo: u8,
        make_current: bool,
    ) -> Result<ApduResponse, Error> {
        let key_path = KeyPath::from_str(path)?;
        let mut data = hash.to_vec();
        data.extend_from_slice(key_path.data());
        let p1 = key_path.source()
            | if make_current {
                sign_p1::DERIVE_AND_MAKE_CURRENT
            } else {
                sign_p1::DERIVE
            };
        self.sign_raw(&data, p1, algo)
    }

    /// Signs a hash using the pinless path.
    ///
    /// This is the only sign variant that works without a secure channel.
    pub fn sign_pinless(&mut self, hash: &[u8]) -> Result<ApduResponse, Error> {
        self.sign_raw(hash, sign_p1::PINLESS, sign_p2::ECDSA)
    }

    /// Sends a SIGN APDU with raw data and explicit P1/P2.
    pub fn sign_raw(&mut self, data: &[u8], p1: u8, p2: u8) -> Result<ApduResponse, Error> {
        self.send_protected(ins::SIGN, p1, p2, data)
    }

    // -----------------------------------------------------------------------
    // APDU commands — Key derivation
    // -----------------------------------------------------------------------

    /// Derives a key at the given BIP32 path.
    pub fn derive_key(&mut self, keypath: &str) -> Result<ApduResponse, Error> {
        let path = KeyPath::from_str(keypath)?;
        self.derive_key_raw_with_source(path.data(), path.source())
    }

    /// Derives a key from raw path data (source = MASTER).
    pub fn derive_key_raw(&mut self, data: &[u8]) -> Result<ApduResponse, Error> {
        self.derive_key_raw_with_source(data, derive_p1::SOURCE_MASTER)
    }

    /// Derives a key from raw path data with explicit source.
    pub fn derive_key_raw_with_source(
        &mut self,
        data: &[u8],
        source: u8,
    ) -> Result<ApduResponse, Error> {
        self.send_protected(ins::DERIVE_KEY, source, 0, data)
    }

    // -----------------------------------------------------------------------
    // APDU commands — Pinless path
    // -----------------------------------------------------------------------

    /// Sets the pinless signing path. Must be an absolute path (from master key).
    pub fn set_pinless_path(&mut self, path: &str) -> Result<ApduResponse, Error> {
        let key_path = KeyPath::from_str(path)?;
        if key_path.source() != derive_p1::SOURCE_MASTER {
            return Err(Error::InvalidArgument(
                "Only absolute paths can be set as PINLESS path".to_string(),
            ));
        }
        self.set_pinless_path_raw(key_path.data())
    }

    /// Resets the pinless path (clears it).
    pub fn reset_pinless_path(&mut self) -> Result<ApduResponse, Error> {
        self.set_pinless_path_raw(&[])
    }

    /// Sets the pinless path from raw data.
    pub fn set_pinless_path_raw(&mut self, data: &[u8]) -> Result<ApduResponse, Error> {
        self.send_protected(ins::SET_PINLESS_PATH, 0, 0, data)
    }

    // -----------------------------------------------------------------------
    // APDU commands — Key export
    // -----------------------------------------------------------------------

    /// Exports the current key.
    ///
    /// # Arguments
    /// * `public_only` — If true, exports only the public key.
    pub fn export_current_key(&mut self, public_only: bool) -> Result<ApduResponse, Error> {
        self.export_current_key_with_p2(if public_only {
            export_key_p2::PUBLIC_ONLY
        } else {
            export_key_p2::PRIVATE_AND_PUBLIC
        })
    }

    /// Exports the current key with explicit P2.
    pub fn export_current_key_with_p2(&mut self, p2: u8) -> Result<ApduResponse, Error> {
        self.export_key_raw(&[], export_key_p1::CURRENT, false, p2)
    }

    /// Exports a key at the given BIP32 path.
    ///
    /// # Arguments
    /// * `keypath` — BIP32 path string.
    /// * `make_current` — Whether to make the derived key the current key.
    /// * `public_only` — If true, exports only the public key.
    pub fn export_key(
        &mut self,
        keypath: &str,
        make_current: bool,
        public_only: bool,
    ) -> Result<ApduResponse, Error> {
        let path = KeyPath::from_str(keypath)?;
        let p2 = if public_only {
            export_key_p2::PUBLIC_ONLY
        } else {
            export_key_p2::PRIVATE_AND_PUBLIC
        };
        self.export_key_raw(path.data(), path.source(), make_current, p2)
    }

    /// Exports a key with raw path data and explicit parameters.
    pub fn export_key_raw(
        &mut self,
        keypath: &[u8],
        source: u8,
        make_current: bool,
        p2: u8,
    ) -> Result<ApduResponse, Error> {
        let p1 = source
            | if make_current {
                export_key_p1::DERIVE_AND_MAKE_CURRENT
            } else {
                export_key_p1::DERIVE
            };
        self.send_protected(ins::EXPORT_KEY, p1, p2, keypath)
    }

    /// Exports an LEE key at the given BIP32 path.
    pub fn export_lee_key(&mut self, keypath: &str) -> Result<ApduResponse, Error> {
        let path = KeyPath::from_str(keypath)?;
        self.export_lee_key_raw(path.data(), path.source())
    }

    /// Exports an LEE key with raw path data.
    pub fn export_lee_key_raw(
        &mut self,
        path: &[u8],
        source: u8,
    ) -> Result<ApduResponse, Error> {
        self.send_protected(ins::EXPORT_LEE, source, 0, path)
    }

    // -----------------------------------------------------------------------
    // APDU commands — Data storage
    // -----------------------------------------------------------------------

    /// Sends a GET DATA APDU.
    pub fn get_data(&mut self, data_type: u8) -> Result<ApduResponse, Error> {
        self.send_protected(ins::GET_DATA, data_type, 0, &[])
    }

    /// Sends a GET CHALLENGE APDU.
    ///
    /// # Arguments
    /// * `len` — Requested challenge length.
    pub fn get_challenge(&mut self, len: u8) -> Result<ApduResponse, Error> {
        self.send_protected(ins::GET_CHALLENGE, len, 0, &[])
    }

    /// Sends a STORE DATA APDU (offset 0).
    pub fn store_data(
        &mut self,
        data: &[u8],
        data_type: u8,
    ) -> Result<ApduResponse, Error> {
        self.store_data_with_offset(data, data_type, 0)
    }

    /// Sends a STORE DATA APDU with explicit offset.
    ///
    /// Offset must be a multiple of 4.
    pub fn store_data_with_offset(
        &mut self,
        data: &[u8],
        data_type: u8,
        offset: u16,
    ) -> Result<ApduResponse, Error> {
        self.send_protected(ins::STORE_DATA, data_type, (offset / 4) as u8, data)
    }

    /// Sends a SET NDEF APDU.
    ///
    /// For app version > 2.x, data is chunked and stored via STORE_DATA.
    /// For app version <= 2.x, data is sent directly via SET_NDEF.
    pub fn set_ndef(&mut self, ndef: &[u8]) -> Result<ApduResponse, Error> {
        let app_major = self
            .info
            .as_ref()
            .map(|i| i.app_version() >> 8)
            .unwrap_or(0);

        if app_major > 2 {
            // Ensure 2-byte length prefix
            let mut data = ndef.to_vec();
            if data.len() < 2 || (data.len() - 2) != ((data[0] as usize) << 8 | data[1] as usize) {
                let mut prefixed = Vec::with_capacity(2 + ndef.len());
                prefixed.push((ndef.len() >> 8) as u8);
                prefixed.push((ndef.len() & 0xFF) as u8);
                prefixed.extend_from_slice(ndef);
                data = prefixed;
            }

            let mut to_send = data.len();
            let mut off: usize = 0;
            let mut last_resp: Option<ApduResponse> = None;

            while to_send > 0 {
                let chunk_size = std::cmp::min(constants::NDEF_MAX_CHUNK_SIZE, to_send);
                let chunk = &data[off..off + chunk_size];
                let resp = self.store_data_with_offset(
                    chunk,
                    store_data_p1::NDEF,
                    off as u16,
                )?;
                last_resp = Some(resp.clone());
                if resp.sw() != ApduResponse::SW_OK {
                    break;
                }
                off += chunk_size;
                to_send -= chunk_size;
            }

            last_resp.ok_or_else(|| {
                Error::Protocol("NDEF write completed with no responses".to_string())
            })
        } else {
            self.send_protected(ins::SET_NDEF, 0, 0, ndef)
        }
    }

    // -----------------------------------------------------------------------
    // INIT and FACTORY RESET
    // -----------------------------------------------------------------------

    /// Initializes the card with PIN, PUK, and pairing password.
    pub fn init(
        &mut self,
        pin: &str,
        puk: &str,
        pairing_password: &str,
    ) -> Result<ApduResponse, Error> {
        self.init_with_options(pin, None, puk, pairing_password, 0, 0)
    }

    /// Initializes the card with PIN, optional alt PIN, PUK, pairing password,
    /// and retry counts.
    pub fn init_with_options(
        &mut self,
        pin: &str,
        alt_pin: Option<&str>,
        puk: &str,
        pairing_password: &str,
        pin_retries: u8,
        puk_retries: u8,
    ) -> Result<ApduResponse, Error> {
        let shared_secret = self.pairing_password_to_secret(pairing_password);
        self.init_with_secret(pin, alt_pin, puk, &shared_secret, pin_retries, puk_retries)
    }

    /// Initializes the card with a raw shared secret.
    pub fn init_with_secret(
        &mut self,
        pin: &str,
        alt_pin: Option<&str>,
        puk: &str,
        shared_secret: &[u8],
        pin_retries: u8,
        puk_retries: u8,
    ) -> Result<ApduResponse, Error> {
        // Build init data: PIN || PUK || shared_secret || [pin_retries, puk_retries] || alt_pin
        let base_len = pin.len() + puk.len() + shared_secret.len();
        let ext_len = if let Some(ap) = alt_pin {
            2 + ap.len()
        } else if pin_retries != 0 || puk_retries != 0 {
            2
        } else {
            0
        };

        let mut init_data = Vec::with_capacity(base_len + ext_len);
        init_data.extend_from_slice(pin.as_bytes());
        init_data.extend_from_slice(puk.as_bytes());
        init_data.extend_from_slice(shared_secret);

        if ext_len > 0 {
            init_data.push(pin_retries);
            init_data.push(puk_retries);
            if let Some(ap) = alt_pin {
                init_data.extend_from_slice(ap.as_bytes());
            }
        }

        // V2: open secure channel first, then send INIT as encrypted command
        if self.secure_channel.as_any().is::<SecureChannelV2>() {
            self.auto_open_secure_channel()?;
            self.send_protected(ins::INIT, 0, 0, &init_data)
        } else {
            // V1: use one-shot encryption
            let encrypted = self
                .secure_channel
                .as_mut()
                .as_any_mut()
                .downcast_mut::<SecureChannelV1>()
                .ok_or_else(|| {
                    Error::Protocol("Expected SecureChannelV1 for init".to_string())
                })?
                .one_shot_encrypt(&init_data)?;
            let cmd = ApduCommand::new(0x80, ins::INIT, 0, 0, encrypted);
            self.channel.send(&cmd)
        }
    }

    /// Initializes the card without a pairing password (V2 only).
    ///
    /// Secure Channel V2 does not use a shared secret for pairing, so this
    /// convenience method initializes the card with an empty shared secret.
    ///
    /// For V1 cards, use [`Self::init`] or [`Self::init_with_secret`] instead.
    pub fn init_v2(
        &mut self,
        pin: &str,
        puk: &str,
    ) -> Result<ApduResponse, Error> {
        self.init_v2_with_options(pin, None, puk, 0, 0)
    }

    /// Initializes the card without a pairing password (V2 only), with
    /// optional alt PIN and retry counts.
    ///
    /// Secure Channel V2 does not use a shared secret for pairing, so this
    /// convenience method initializes the card with an empty shared secret.
    ///
    /// For V1 cards, use [`Self::init_with_options`] or [`Self::init_with_secret`] instead.
    pub fn init_v2_with_options(
        &mut self,
        pin: &str,
        alt_pin: Option<&str>,
        puk: &str,
        pin_retries: u8,
        puk_retries: u8,
    ) -> Result<ApduResponse, Error> {
        self.init_with_secret(pin, alt_pin, puk, &[], pin_retries, puk_retries)
    }

    /// Sends the FACTORY RESET command.
    ///
    /// This is sent as a raw (unencrypted) command.
    pub fn factory_reset(&mut self) -> Result<ApduResponse, Error> {
        let cmd = ApduCommand::new(
            0x80,
            ins::FACTORY_RESET,
            factory_reset::P1_MAGIC,
            factory_reset::P2_MAGIC,
            vec![],
        );
        self.channel.send(&cmd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::CardChannel;

    /// Mock channel for testing constructor and accessor logic.
    struct MockChannel;

    impl CardChannel for MockChannel {
        fn send(&mut self, _cmd: &ApduCommand) -> Result<ApduResponse, Error> {
            Err(Error::Protocol("mock".to_string()))
        }
        fn is_connected(&self) -> bool {
            false
        }
        fn pairing_password_pbkdf2_iterations(&self) -> u32 {
            50_000
        }
    }

    #[test]
    fn test_new_uses_default_ca() {
        let kcs = KeycardCommandSet::new(MockChannel);
        assert!(kcs.app_info().is_none());
    }

    #[test]
    fn test_new_with_ca() {
        let ca: [u8; 33] = [0x02u8; 33];
        let kcs = KeycardCommandSet::new_with_ca(MockChannel, ca);
        assert!(kcs.app_info().is_none());
    }

    #[test]
    fn test_pairing_password_to_secret_deterministic() {
        let kcs = KeycardCommandSet::new(MockChannel);
        let secret1 = kcs.pairing_password_to_secret("test");
        let secret2 = kcs.pairing_password_to_secret("test");
        assert_eq!(secret1, secret2);
        assert_eq!(secret1.len(), 32);
    }
}
