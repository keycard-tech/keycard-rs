/// AID for the Keycard package
pub const PACKAGE_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01];

/// AID for the Keycard applet
pub const KEYCARD_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x01];

/// Default instance index for Keycard
pub const KEYCARD_DEFAULT_INSTANCE_IDX: u8 = 1;

/// AID for NDEF
pub const NDEF_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x02];

/// NDEF instance AID
pub const NDEF_INSTANCE_AID: &[u8] = &[0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01];

/// Get the instance AID for a specific Keycard instance.
///
/// # Arguments
/// * `instance_idx` - Instance index (0x01..=0xFF)
///
/// # Panics
/// Panics if `instance_idx` is not in range 0x01..=0xFF.
pub fn keycard_instance_aid(instance_idx: u8) -> Vec<u8> {
    if instance_idx == 0 {
        panic!("Instance index must be between 1 and 255");
    }
    let mut aid = KEYCARD_AID.to_vec();
    aid.push(instance_idx);
    aid
}

// ============================================================================
// INS codes
// ============================================================================

/// Keycard applet INS codes
pub mod ins {
    /// Initialize the applet
    pub const INIT: u8 = 0xFE;
    /// Factory reset
    pub const FACTORY_RESET: u8 = 0xFD;
    /// Get status
    pub const GET_STATUS: u8 = 0xF2;
    /// Set NDEF data (legacy, app version <= 2.x)
    pub const SET_NDEF: u8 = 0xF3;
    /// Identify card
    pub const IDENTIFY_CARD: u8 = 0x14;
    /// Verify PIN
    pub const VERIFY_PIN: u8 = 0x20;
    /// Change PIN/PUK/pairing password
    pub const CHANGE_PIN: u8 = 0x21;
    /// Unblock PIN
    pub const UNBLOCK_PIN: u8 = 0x22;
    /// Load key
    pub const LOAD_KEY: u8 = 0xD0;
    /// Derive key
    pub const DERIVE_KEY: u8 = 0xD1;
    /// Generate mnemonic
    pub const GENERATE_MNEMONIC: u8 = 0xD2;
    /// Remove key
    pub const REMOVE_KEY: u8 = 0xD3;
    /// Generate key on card
    pub const GENERATE_KEY: u8 = 0xD4;
    /// Sign
    pub const SIGN: u8 = 0xC0;
    /// Set pinless path
    pub const SET_PINLESS_PATH: u8 = 0xC1;
    /// Export key
    pub const EXPORT_KEY: u8 = 0xC2;
    /// Export LEE key
    pub const EXPORT_LEE: u8 = 0xC3;
    /// Export BIP85 derived key
    pub const EXPORT_BIP85: u8 = 0xC4;
    /// Get data
    pub const GET_DATA: u8 = 0xCA;
    /// Store data
    pub const STORE_DATA: u8 = 0xE2;
    /// Get challenge
    pub const GET_CHALLENGE: u8 = 0x84;

    // Secure Channel V1 INS codes
    /// Open secure channel
    pub const OPEN_SECURE_CHANNEL: u8 = 0x10;
    /// Mutually authenticate
    pub const MUTUALLY_AUTHENTICATE: u8 = 0x11;
    /// Pair
    pub const PAIR: u8 = 0x12;
    /// Unpair
    pub const UNPAIR: u8 = 0x13;

    // Secure Channel V2 INS codes
    /// Secured APDU (V2 encrypted command)
    pub const SECURED_APDU: u8 = 0x18;
}

// ============================================================================
// P1/P2 parameter constants
// ============================================================================

/// CHANGE_PIN P1 values
pub mod change_pin_p1 {
    /// User PIN
    pub const USER_PIN: u8 = 0x00;
    /// PUK
    pub const PUK: u8 = 0x01;
    /// Pairing secret
    pub const PAIRING_SECRET: u8 = 0x02;
}

/// GET_STATUS P1 values
pub mod get_status_p1 {
    /// Application status
    pub const APPLICATION: u8 = 0x00;
    /// Key path status
    pub const KEY_PATH: u8 = 0x01;
}

/// LOAD_KEY P1 values
pub mod load_key_p1 {
    /// EC key pair
    pub const EC: u8 = 0x01;
    /// Extended EC key pair (with chain code)
    pub const EXT_EC: u8 = 0x02;
    /// Seed (BIP32 master derivation)
    pub const SEED: u8 = 0x03;
    /// LEE key
    pub const LEE: u8 = 0x04;
}

/// DERIVE_KEY P1 source values
pub mod derive_p1 {
    /// Derive from master
    pub const SOURCE_MASTER: u8 = 0x00;
    /// Derive from parent
    pub const SOURCE_PARENT: u8 = 0x40;
    /// Derive from current
    pub const SOURCE_CURRENT: u8 = 0x80;
}

/// SIGN P1 values
pub mod sign_p1 {
    /// Sign with current key
    pub const CURRENT_KEY: u8 = 0x00;
    /// Derive then sign
    pub const DERIVE: u8 = 0x01;
    /// Derive, make current, then sign
    pub const DERIVE_AND_MAKE_CURRENT: u8 = 0x02;
    /// Sign with pinless path
    pub const PINLESS: u8 = 0x03;
}

/// SIGN P2 algorithm values
pub mod sign_p2 {
    /// ECDSA (secp256k1)
    pub const ECDSA: u8 = 0x00;
    /// EdDSA (Ed25519)
    pub const EDDSA_ED25519: u8 = 0x01;
    /// BLS12-381 (passthrough, card supports it)
    pub const BLS12_381: u8 = 0x02;
    /// BIP340 Schnorr
    pub const BIP340_SCHNORR: u8 = 0x03;
}

/// STORE_DATA P1 data type values
pub mod store_data_p1 {
    /// Public data
    pub const PUBLIC: u8 = 0x00;
    /// NDEF data
    pub const NDEF: u8 = 0x01;
    /// Cash data
    pub const CASH: u8 = 0x02;
}

/// EXPORT_KEY P1 values
pub mod export_key_p1 {
    /// Export current key
    pub const CURRENT: u8 = 0x00;
    /// Derive then export
    pub const DERIVE: u8 = 0x01;
    /// Derive, make current, then export
    pub const DERIVE_AND_MAKE_CURRENT: u8 = 0x02;
}

/// EXPORT_KEY P2 values
pub mod export_key_p2 {
    /// Export private and public
    pub const PRIVATE_AND_PUBLIC: u8 = 0x00;
    /// Export public only
    pub const PUBLIC_ONLY: u8 = 0x01;
    /// Export extended public (with chain code)
    pub const EXTENDED_PUBLIC: u8 = 0x02;
}

/// PAIR P1 values
pub mod pair_p1 {
    /// First step of pairing
    pub const FIRST_STEP: u8 = 0x00;
    /// Last step of pairing
    pub const LAST_STEP: u8 = 0x01;
}

/// PAIR P2 mode values
pub mod pair_p2 {
    /// Any pairing mode
    pub const ANY: u8 = 0x00;
    /// Ephemeral pairing (not persisted on card)
    pub const EPHEMERAL: u8 = 0x01;
    /// Persistent pairing (persisted on card)
    pub const PERSISTENT: u8 = 0x02;
}

/// FACTORY_RESET magic values
pub mod factory_reset {
    pub const P1_MAGIC: u8 = 0xAA;
    pub const P2_MAGIC: u8 = 0x55;
}

/// GENERATE_MNEMONIC P1 word count values
pub mod generate_mnemonic {
    /// 12 words (128 bits entropy)
    pub const WORDS_12: u8 = 0x04;
    /// 15 words (160 bits entropy)
    pub const WORDS_15: u8 = 0x05;
    /// 18 words (192 bits entropy)
    pub const WORDS_18: u8 = 0x06;
    /// 21 words (224 bits entropy)
    pub const WORDS_21: u8 = 0x07;
    /// 24 words (256 bits entropy)
    pub const WORDS_24: u8 = 0x08;
}

// ============================================================================
// Capability flags
// ============================================================================

pub mod capability {
    /// Secure channel support
    pub const SECURE_CHANNEL: u8 = 0x01;
    /// Key management support
    pub const KEY_MANAGEMENT: u8 = 0x02;
    /// Credentials management support
    pub const CREDENTIALS_MANAGEMENT: u8 = 0x04;
    /// NDEF support
    pub const NDEF: u8 = 0x08;
    /// Factory reset support
    pub const FACTORY_RESET: u8 = 0x10;
    /// All capabilities
    pub const ALL: u8 = 0x1F;
}

// ============================================================================
// App status flags
// ============================================================================

pub mod app_status {
    /// App is initialized
    pub const INITIALIZED: u8 = 0x10;
    /// App is in LEE mode
    pub const LEE_MODE: u8 = 0x20;
}

// ============================================================================
// Other constants
// ============================================================================

/// Maximum NDEF chunk size for storage (220 bytes)
pub const NDEF_MAX_CHUNK_SIZE: usize = 220;

/// Maximum number of pairing slots on the card
pub const PAIRING_MAX_CLIENT_COUNT: usize = 5;

/// Default Status CA public key (compressed secp256k1, 33 bytes).
pub const DEFAULT_CA_PUBLIC_KEY: [u8; 33] = [
    0x02,
    0x9a, 0xb9, 0x9e, 0xe1, 0xe7, 0xa7, 0x1b,
    0xdf, 0x45, 0xb3, 0xf9, 0xc5, 0x8c, 0x99,
    0x86, 0x6f, 0xf1, 0x29, 0x4d, 0x2c, 0x1e,
    0x30, 0x4e, 0x22, 0x8a, 0x86, 0xe1, 0x0c,
    0x33, 0x43, 0x50, 0x1c,
];

/// Pairing password salt
pub const PAIRING_PASSWORD_SALT: &[u8] = b"Keycard Pairing Password Salt";

/// BIP39 mnemonic seed derivation prefix
pub const MNEMONIC_SEED_PREFIX: &str = "mnemonic";

/// PBKDF2 iterations for pairing password
pub const PAIRING_PBKDF2_ITERATIONS: u32 = 50_000;

/// BIP39 PBKDF2 iterations for mnemonic seed derivation
pub const MNEMONIC_PBKDF2_ITERATIONS: u32 = 2048;

/// BIP32 HMAC key
pub const BIP32_HMAC_KEY: &[u8] = b"Bitcoin seed";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keycard_instance_aid_default() {
        let aid = keycard_instance_aid(1);
        assert_eq!(aid, vec![0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x01, 0x01]);
    }

    #[test]
    fn test_keycard_instance_aid_custom() {
        let aid = keycard_instance_aid(0xFF);
        assert_eq!(aid[aid.len() - 1], 0xFF);
    }

    #[test]
    #[should_panic(expected = "Instance index must be between 1 and 255")]
    fn test_keycard_instance_aid_invalid_zero() {
        keycard_instance_aid(0);
    }

    #[test]
    fn test_default_ca_public_key_length() {
        assert_eq!(DEFAULT_CA_PUBLIC_KEY.len(), 33);
    }

    #[test]
    fn test_capability_flags() {
        assert_eq!(capability::SECURE_CHANNEL, 0x01);
        assert_eq!(capability::KEY_MANAGEMENT, 0x02);
        assert_eq!(capability::ALL, 0x1F);
    }
}
