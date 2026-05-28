# keycard-rs

Rust port of the Status Keycard Java library. Provides a complete API for
interacting with Status Keycard hardware security modules via APDU commands
over PC/SC transport.

## Features

- Full APDU command set for Keycard operations (signing, key management, PIN, etc.)
- Secure Channel V1 and V2 with automatic version detection
- PC/SC smart card transport (via the `pcsc` crate)
- BIP32 key derivation and export
- BIP39 mnemonic support
- ECDSA signature recovery
- NDEF data storage
- Pinless signing path

## Installation

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
keycard-rs = { git = "https://github.com/keycard-tech/keycard-rs" }
```

The `pcsc` feature is enabled by default. Disable it if you provide your own
`CardChannel` implementation:

```toml
keycard-rs = { git = "https://github.com/keycard-tech/keycard-rs", default-features = false }
```

## Usage

### Connecting and selecting the applet

```rust
use keycard_rs::{KeycardCommandSet, PcscChannel};

let channel = PcscChannel::connect()?;
let mut keycard = KeycardCommandSet::new(channel);

let response = keycard.select()?;
assert!(response.is_ok());

let info = keycard.app_info().expect("app_info should be set after SELECT");
```

### Pairing and opening a secure channel

```rust
// Pair with a password (V1 only)
if keycard.secure_channel_version() == Some(SecureChannelVersion::V1) {
    keycard.auto_pair("KeycardDefaultPairing")?;
}

// Open the secure channel (V1 and V2)
if info.has_secure_channel() {
    keycard.auto_open_secure_channel()?;
}
```

### Verifying PIN and signing

```rust
keycard.verify_pin("000000")?;

let hash: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
];

let sign_resp = keycard.sign_with_path(&hash, "m/44'/60'/0'/0/0", false)?;
```

### Loading a key and exporting a public key

```rust
use keycard_rs::parsing::{Bip32KeyPair, Mnemonic};

let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
let seed = Mnemonic::binary_seed_from_phrase(mnemonic, "");
keycard.load_key(&seed)?;

let export_resp = keycard.export_key("m/44'/60'/0'/0/0", false, true)?;
let key_pair = Bip32KeyPair::from_tlv(export_resp.data())?;
let public_key = key_pair.public_key();
```

### Verifying a signature

```rust
use keycard_rs::parsing::RecoverableSignature;

let sig = RecoverableSignature::from_card_response(&hash, sign_resp.data())?;
assert_eq!(sig.public_key(), public_key);
```

### Custom transport

Implement the `CardChannel` trait to use a different transport layer:

```rust
use keycard_rs::{ApduCommand, ApduResponse, CardChannel, Error};

struct MyChannel { /* ... */ }

impl CardChannel for MyChannel {
    fn send(&mut self, cmd: &ApduCommand) -> Result<ApduResponse, Error> {
        // transmit APDU and return response
        todo!()
    }

    fn is_connected(&self) -> bool {
        todo!()
    }
}
```

## Integration tests

The repository includes integration tests that communicate with a real Keycard.
They require a physically connected card and smart card reader, and are marked
with `#[ignore]`.

Run all integration tests:

```text
cargo test --test integration -- --ignored
```

Run a specific test with output:

```text
cargo test --test integration full_sign_flow -- --ignored --nocapture
```

## License

MIT
