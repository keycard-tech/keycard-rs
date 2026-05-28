use crate::apdu::{ApduCommand, ApduResponse};
use crate::constants::DEFAULT_PAIRING_PBKDF2_ITERATIONS;
use crate::error::Error;

/// Trait for APDU transport channels.
///
/// Implementations handle the physical transport layer (PC/SC, NFC, USB HID, etc.)
/// and provide a uniform interface for sending APDU commands and receiving responses.
pub trait CardChannel {
    /// Transmits a command APDU and returns the response.
    ///
    /// # Arguments
    /// * `cmd` - The APDU command to send
    ///
    /// # Returns
    /// The APDU response, or an error if the transmission fails.
    fn send(&mut self, cmd: &ApduCommand) -> Result<ApduResponse, Error>;

    /// Returns `true` if the channel has an active connection.
    fn is_connected(&self) -> bool;

    /// Returns the PBKDF2 iteration count for deriving the pairing secret.
    ///
    /// Default is 50,000. May be overridden by implementations
    /// for resource-constrained devices.
    fn pairing_password_pbkdf2_iterations(&self) -> u32 {
        DEFAULT_PAIRING_PBKDF2_ITERATIONS
    }
}
