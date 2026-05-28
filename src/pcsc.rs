//! PCSC smart card transport implementation.
//!
//! This module provides `PcscChannel`, which implements [`CardChannel`]
//! using the PC/SC API via the `pcsc` crate.

use crate::apdu::{ApduCommand, ApduResponse};
use crate::channel::CardChannel;
use crate::error::Error;

/// A PCSC-based card channel implementing [`CardChannel`].
///
/// Connects to a smart card reader via PC/SC and transmits APDU commands.
pub struct PcscChannel {
    card: Option<pcsc::Card>,
}

impl PcscChannel {
    /// Connect to a reader by name.
    ///
    /// # Arguments
    /// * `reader_name` - The name of the reader to connect to. If `None` or empty string,
    ///   auto-selects the first available reader.
    pub fn new(reader_name: Option<&str>) -> Result<Self, Error> {
        let context = pcsc::Context::establish(pcsc::Scope::User)
            .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;

        let readers = context
            .list_readers_owned()
            .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;

        if readers.is_empty() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "No smart card readers found",
            )));
        }

        let reader = if let Some(name) = reader_name {
            readers
                .iter()
                .find(|r| r.to_string_lossy().starts_with(name))
                .ok_or_else(|| {
                    Error::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("Reader not found: {}", name),
                    ))
                })?
                .clone()
        } else {
            readers[0].clone()
        };

        let card = context
            .connect(
                &reader,
                pcsc::ShareMode::Shared,
                pcsc::Protocols::T0 | pcsc::Protocols::T1,
            )
            .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;

        Ok(Self { card: Some(card) })
    }

    /// Discover and connect to the first available reader.
    pub fn connect() -> Result<Self, Error> {
        Self::new(None)
    }

    /// Close the PC/SC connection.
    pub fn disconnect(&mut self) {
        if let Some(card) = self.card.take() {
            let _ = card.disconnect(pcsc::Disposition::LeaveCard);
        }
    }
}

impl CardChannel for PcscChannel {
    fn send(&mut self, cmd: &ApduCommand) -> Result<ApduResponse, Error> {
        let card = self
            .card
            .as_ref()
            .ok_or_else(|| Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Not connected to any card",
            )))?;

        let data = cmd.serialize();
        let mut response_buf = [0u8; pcsc::MAX_BUFFER_SIZE_EXTENDED];

        let response = card
            .transmit(&data, &mut response_buf)
            .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;

        ApduResponse::new(response)
    }

    fn is_connected(&self) -> bool {
        self.card.is_some()
    }
}

impl Drop for PcscChannel {
    fn drop(&mut self) {
        self.disconnect();
    }
}
