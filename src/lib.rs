//! # keycard-rs
//!
//! Rust port of the Status Keycard Java library.
//!
//! This crate provides a complete API for interacting with Status Keycard hardware
//! security modules via APDU commands over PC/SC transport.
//!
//! ## Features
//!
//! - **`pcsc`** (default) — PC/SC smart card transport via the `pcsc` crate.
//!

pub mod apdu;
pub mod channel;
pub mod constants;
pub mod error;
pub mod keycard;
pub mod metadata;
pub mod parsing;
pub mod secure_channel;
pub mod tlv;

#[cfg(feature = "pcsc")]
pub mod pcsc;

// Re-export main types for convenience
pub use apdu::{ApduCommand, ApduResponse};
pub use channel::CardChannel;
pub use error::{ApduError, Error, WrongPinError};
pub use keycard::KeycardCommandSet;
pub use metadata::Metadata;
pub use secure_channel::{
    Pairing, SecureChannel, SecureChannelV1, SecureChannelV2, SecureChannelVersion,
};

#[cfg(feature = "pcsc")]
pub use pcsc::PcscChannel;
