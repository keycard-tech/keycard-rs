//! Secure Channel protocol implementations.
//!
//! Two versions are supported:
//! - **V1**: AES-256-CBC with AES-CBC-MAC, pairing-based key derivation via ECDH.
//! - **V2**: ECDHE on secp256k1, HKDF-SHA256 key derivation, AES-128-CCM (T=8, L=13).

pub mod pairing;
pub mod v1;
pub mod v2;

pub use pairing::Pairing;
pub use v1::SecureChannelV1;
pub use v2::SecureChannelV2;

use crate::apdu::{ApduCommand, ApduResponse};
use crate::channel::CardChannel;
use crate::error::Error;

/// The version of the Secure Channel protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureChannelVersion {
    /// Secure Channel V1: pairing-based, AES-CBC + AES-CBC-MAC
    V1,
    /// Secure Channel V2: ECDHE + HKDF + AES-128-CCM
    V2,
}

/// Common interface for Secure Channel implementations.
///
/// Both V1 and V2 implement this trait. Methods that are only valid for one
/// version return `Err(Error::Protocol(...))` on the other.
pub trait SecureChannel {
    /// Establishes a Secure Channel with the card, performing the full handshake.
    fn auto_open(&mut self, channel: &mut dyn CardChannel) -> Result<(), Error>;

    /// Performs the pairing procedure (V1 only).
    fn auto_pair(
        &mut self,
        channel: &mut dyn CardChannel,
        mode: u8,
        shared_secret: &[u8],
    ) -> Result<(), Error>;

    /// Unpairs the current paired key (V1 only).
    fn auto_unpair(&mut self, channel: &mut dyn CardChannel) -> Result<(), Error>;

    /// Unpair all other clients (V1 only).
    fn unpair_others(&mut self, channel: &mut dyn CardChannel) -> Result<(), Error>;

    /// Sends an OPEN SECURE CHANNEL APDU.
    fn open_secure_channel(
        &mut self,
        channel: &mut dyn CardChannel,
        index: u8,
        data: &[u8],
    ) -> Result<ApduResponse, Error>;

    /// Sends a MUTUALLY AUTHENTICATE APDU (V1 only).
    fn mutually_authenticate(
        &mut self,
        channel: &mut dyn CardChannel,
    ) -> Result<ApduResponse, Error>;

    /// Sends a MUTUALLY AUTHENTICATE APDU with explicit data (V1 only).
    fn mutually_authenticate_with_data(
        &mut self,
        channel: &mut dyn CardChannel,
        data: &[u8],
    ) -> Result<ApduResponse, Error>;

    /// Sends a PAIR APDU (V1 only).
    fn pair(
        &mut self,
        channel: &mut dyn CardChannel,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> Result<ApduResponse, Error>;

    /// Sends an UNPAIR APDU (V1 only).
    fn unpair(
        &mut self,
        channel: &mut dyn CardChannel,
        p1: u8,
    ) -> Result<ApduResponse, Error>;

    /// Returns a command APDU with the secure channel wrapper applied.
    ///
    /// Returns `Err` if the channel was previously established but is not
    /// currently open (e.g. after a transmit failure) — the caller must call
    /// `auto_open` again rather than silently falling back to plaintext.
    fn protected_command(&mut self, cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8])
        -> Result<ApduCommand, Error>;

    /// Transmits a protected command APDU and unwraps the response.
    fn transmit(
        &mut self,
        channel: &mut dyn CardChannel,
        cmd: &ApduCommand,
    ) -> Result<ApduResponse, Error>;

    /// Returns the current pairing data (V1 only, `None` for V2).
    fn pairing(&self) -> Option<&Pairing>;

    /// Sets the pairing data (V1 only, no-op for V2).
    fn set_pairing(&mut self, pairing: Pairing);

    /// Resets the secure channel, invalidating the current session.
    fn reset(&mut self);

    /// Returns the protocol version of this secure channel.
    fn version(&self) -> SecureChannelVersion;

    /// Downcast to `&dyn Any` for runtime type inspection.
    fn as_any(&self) -> &dyn std::any::Any;

    /// Downcast to `&mut dyn Any` for runtime type inspection.
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;
}
