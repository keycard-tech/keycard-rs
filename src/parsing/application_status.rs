//! Application status parsing from GET STATUS response.

use crate::error::Error;
use crate::tlv::{BerTlvReader, TLV_APPLICATION_STATUS_TEMPLATE};

/// Parsed status from a GET STATUS command response.
#[derive(Debug, Clone)]
pub struct ApplicationStatus {
    pin_retry_count: u8,
    puk_retry_count: u8,
    has_master_key: bool,
}

impl ApplicationStatus {
    /// Parses the TLV response from a GET STATUS command.
    pub fn from_tlv(data: &[u8]) -> Result<Self, Error> {
        let mut reader = BerTlvReader::new(data);

        reader
            .enter_constructed(TLV_APPLICATION_STATUS_TEMPLATE)
            .map_err(|e| {
                Error::Tlv(format!("Failed to enter application status template: {}", e))
            })?;

        let pin_retry_count = reader.read_integer().map_err(|e| {
            Error::Tlv(format!("Failed to read PIN retry count: {}", e))
        })? as u8;

        let puk_retry_count = reader.read_integer().map_err(|e| {
            Error::Tlv(format!("Failed to read PUK retry count: {}", e))
        })? as u8;

        let has_master_key = reader.read_boolean().map_err(|e| {
            Error::Tlv(format!("Failed to read has master key: {}", e))
        })?;

        Ok(Self {
            pin_retry_count,
            puk_retry_count,
            has_master_key,
        })
    }

    /// Returns the remaining PIN retry count.
    pub fn pin_retry_count(&self) -> u8 {
        self.pin_retry_count
    }

    /// Returns the remaining PUK retry count.
    pub fn puk_retry_count(&self) -> u8 {
        self.puk_retry_count
    }

    /// Returns `true` if the card has a master key loaded.
    pub fn has_master_key(&self) -> bool {
        self.has_master_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::BerTlvWriter;

    #[test]
    fn test_parse_application_status() {
        let mut writer = BerTlvWriter::new();
        writer.write_constructed(TLV_APPLICATION_STATUS_TEMPLATE, |w| {
            w.write_integer(TLV_INT, 3); // PIN retries
            w.write_integer(TLV_INT, 5); // PUK retries
            w.write_boolean(TLV_BOOL, true); // has master key
        });
        let data = writer.to_vec();

        let status = ApplicationStatus::from_tlv(&data).unwrap();
        assert_eq!(status.pin_retry_count(), 3);
        assert_eq!(status.puk_retry_count(), 5);
        assert!(status.has_master_key());
    }

    #[test]
    fn test_parse_application_status_no_master_key() {
        let mut writer = BerTlvWriter::new();
        writer.write_constructed(TLV_APPLICATION_STATUS_TEMPLATE, |w| {
            w.write_integer(TLV_INT, 10);
            w.write_integer(TLV_INT, 10);
            w.write_boolean(TLV_BOOL, false);
        });
        let data = writer.to_vec();

        let status = ApplicationStatus::from_tlv(&data).unwrap();
        assert!(!status.has_master_key());
    }

    use crate::tlv::{TLV_BOOL, TLV_INT};
}
