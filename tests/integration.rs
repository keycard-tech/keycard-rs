//! Integration tests that communicate with a real Keycard via PC/SC.
//!
//! These tests require a physically connected Keycard and a smart card reader.
//! They are marked with `#[ignore]` and will **not** run during regular `cargo test`.
//!
//! To run them:
//! ```text
//! cargo test --test integration -- --ignored
//! ```
//!
//! To run a specific test:
//! ```text
//! cargo test --test integration full_sign_flow -- --ignored --nocapture
//! ```

#![cfg(feature = "pcsc")]

use keycard_rs::{ApduCommand, ApduResponse, CardChannel, Error, KeycardCommandSet, PcscChannel, SecureChannelVersion};
use keycard_rs::parsing::{Bip32KeyPair, Mnemonic};

/// Test CA public key — only to be used in tests.
const TEST_CA_PUBLIC_KEY: [u8; 33] = [
    0x02, 0x58, 0x77, 0x22, 0x0a, 0xaa, 0xe6, 0xe5,
    0x4a, 0x6f, 0x97, 0x46, 0x02, 0xd5, 0x99, 0x5c,
    0x0f, 0xe2, 0x4a, 0x3e, 0xa7, 0xdd, 0xab, 0xd8,
    0x64, 0x4b, 0xec, 0x79, 0x5b, 0x9d, 0xa0, 0x07,
    0x43,
];

/// Wrapper that logs every APDU sent/received (for diagnostics).
struct LoggingChannel {
    inner: PcscChannel,
}

impl LoggingChannel {
    fn new(inner: PcscChannel) -> Self {
        Self { inner }
    }
}

impl CardChannel for LoggingChannel {
    fn send(&mut self, cmd: &ApduCommand) -> Result<ApduResponse, Error> {
        let serialized = cmd.serialize();
        let resp = self.inner.send(cmd)?;
        eprintln!(
            "APDU >> {:02X?}\nAPDU << SW={:04X} data={:02X?}",
            serialized,
            resp.sw(),
            resp.data()
        );
        Ok(resp)
    }

    fn is_connected(&self) -> bool {
        self.inner.is_connected()
    }
}

/// Connect to the card and select the Keycard applet.
#[test]
#[ignore]
fn select_applet() {
    let channel = PcscChannel::connect().expect("failed to connect to card via PC/SC");
    let mut keycard = KeycardCommandSet::new_with_ca(channel, TEST_CA_PUBLIC_KEY);

    let response = keycard.select().expect("SELECT failed");
    assert!(
        response.is_ok(),
        "SELECT returned error: {:02X} {:02X}",
        response.sw1(),
        response.sw2()
    );

    let info = keycard
        .app_info()
        .expect("app_info should be set after SELECT");
    assert!(
        info.app_version() > 0,
        "expected non-zero app version, got {}",
        info.app_version()
    );
}

/// Full integration test: connect → select → pair (V1 only) → open secure channel
/// → verify PIN → export key at derivation path → sign at same path → verify signature.
///
/// Uses the Ethereum main wallet path `m/44'/60'/0'/0/0`.
///
/// Requires a card that is initialized with the default PIN ("123456") and
/// default pairing password ("KeycardDefaultPairing").
#[test]
#[ignore]
fn full_sign_flow() {
    // 1. Connect and select
    let channel = PcscChannel::connect().expect("failed to connect to card via PC/SC");
    let channel = LoggingChannel::new(channel);
    let mut keycard = KeycardCommandSet::new_with_ca(channel, TEST_CA_PUBLIC_KEY);
    let resp = keycard.select().expect("SELECT failed");
    assert!(resp.is_ok(), "SELECT failed: {:02X} {:02X}", resp.sw1(), resp.sw2());

    let info = keycard.app_info().expect("app_info should be set");
    let has_secure_channel = info.has_secure_channel();
    let has_master_key = info.has_master_key();

    // 2. Pair with default password (V1 only)
    if has_secure_channel && keycard.secure_channel_version() == Some(SecureChannelVersion::V1) {
        keycard
            .auto_pair("KeycardDefaultPairing")
            .expect("pairing failed");
    }

    // 3. Open secure channel
    if has_secure_channel {
        keycard
            .auto_open_secure_channel()
            .expect("failed to open secure channel");
    }

    // 4. Verify PIN
    let pin_resp = keycard
        .verify_pin("000000")
        .expect("verify_pin failed");
    assert!(
        pin_resp.is_ok(),
        "PIN verification failed: {:02X} {:02X}",
        pin_resp.sw1(),
        pin_resp.sw2()
    );

    // 5. Load a test master key if none is present
    if !has_master_key {
        // BIP39 test vector mnemonic (12 words)
        const TEST_MNEMONIC: &str =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = Mnemonic::binary_seed_from_phrase(TEST_MNEMONIC, "");
        let load_resp = keycard
            .load_key(&seed)
            .expect("load_key failed");
        assert!(
            load_resp.is_ok(),
            "load_key failed: {:02X} {:02X}",
            load_resp.sw1(),
            load_resp.sw2()
        );
        eprintln!("loaded test master key from mnemonic");
    }

    // 6. Export the public key at the Ethereum wallet path
    let path = "m/44'/60'/0'/0/0";
    let export_resp = keycard
        .export_key(path, false, true) // don't make current, public only
        .expect("export_key failed");
    assert!(
        export_resp.is_ok(),
        "export failed: {:02X} {:02X}",
        export_resp.sw1(),
        export_resp.sw2()
    );
    let key_pair = Bip32KeyPair::from_tlv(export_resp.data())
        .expect("failed to parse exported key");
    let public_key = key_pair.public_key();

    // 7. Sign a fixed 32-byte hash at the same derivation path
    let hash: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    ];
    let sign_resp = keycard.sign_with_path(&hash, path, false).expect("sign failed");
    assert!(
        sign_resp.is_ok(),
        "sign failed: {:02X} {:02X}",
        sign_resp.sw1(),
        sign_resp.sw2()
    );

    // 8. Parse and verify the signature
    let sig = keycard_rs::parsing::RecoverableSignature::from_card_response(&hash, sign_resp.data())
        .expect("failed to parse signature");

    // 9. Recovered public key must match the exported key
    assert_eq!(
        sig.public_key(),
        public_key,
        "signature public key mismatch: recovered {:02X?} vs exported {:02X?}",
        sig.public_key(),
        public_key
    );

    // 10. Unpair (V1 only)
    if has_secure_channel && keycard.secure_channel_version() == Some(SecureChannelVersion::V1) {
        keycard
            .auto_unpair()
            .expect("unpairing failed");
    }
}
