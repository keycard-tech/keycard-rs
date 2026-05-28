//! Application info parsing from SELECT response.

use crate::constants::capability;
use crate::error::Error;
use crate::tlv::{
    BerTlvReader, TLV_APPLICATION_INFO_TEMPLATE, TLV_CAPABILITIES, TLV_INT, TLV_KEY_UID,
    TLV_PUB_KEY, TLV_STATUS, TLV_UID,
};

/// Tag for certificate data
const TLV_CERT: u8 = 0x8A;

/// App status flags
const APP_STATUS_INITIALIZED: u8 = 0x10;
const APP_STATUS_LEE_MODE: u8 = 0x20;

/// Parsed information from a SELECT command response.
#[derive(Debug, Clone)]
pub struct ApplicationInfo {
    initialized: bool,
    instance_uid: Option<Vec<u8>>,
    secure_channel_pub_key: Option<Vec<u8>>,
    app_version: u16,
    free_pairing_slots: u8,
    key_uid: Vec<u8>,
    capabilities: u8,
    cert_data: Option<Vec<u8>>,
    app_status: u8,
}

impl ApplicationInfo {
    /// Parses the TLV response from a SELECT command.
    ///
    /// Handles both uninitialized cards (only `TLV_PUB_KEY` present)
    /// and initialized cards (constructed `TLV_APPLICATION_INFO_TEMPLATE`).
    #[allow(unused_assignments)]
    pub fn from_tlv(data: &[u8]) -> Result<Self, Error> {
        let mut reader = BerTlvReader::new(data);

        // Uninitialized card: only TLV_PUB_KEY present
        if reader.next_tag_is(TLV_PUB_KEY) {
            let secure_channel_pub_key = reader.read_primitive(TLV_PUB_KEY).map_err(|e| {
                Error::Tlv(format!("Failed to read public key from SELECT response: {}", e))
            })?;

            let mut caps = capability::CREDENTIALS_MANAGEMENT;
            if !secure_channel_pub_key.is_empty() {
                caps |= capability::SECURE_CHANNEL;
            }

            return Ok(Self {
                initialized: false,
                instance_uid: None,
                secure_channel_pub_key: Some(secure_channel_pub_key),
                app_version: 0,
                free_pairing_slots: 0,
                key_uid: Vec::new(),
                capabilities: caps,
                cert_data: None,
                app_status: 0,
            });
        }

        // Initialized card: constructed TLV_APPLICATION_INFO_TEMPLATE
        reader
            .enter_constructed(TLV_APPLICATION_INFO_TEMPLATE)
            .map_err(|e| {
                Error::Tlv(format!("Failed to enter application info template: {}", e))
            })?;

        let mut instance_uid: Option<Vec<u8>> = None;
        let mut secure_channel_pub_key: Option<Vec<u8>> = None;
        let mut app_version: u16 = 0;
        let mut app_status: u8 = APP_STATUS_INITIALIZED;
        let mut free_pairing_slots: u8 = 0;
        let mut key_uid: Vec<u8> = Vec::new();
        let mut capabilities: u8 = capability::ALL;
        let mut cert_data: Option<Vec<u8>> = None;

        // instanceUID (0x8F) - present in V1-V3, absent in V4+
        if reader.next_tag_is(TLV_UID) {
            instance_uid = Some(reader.read_primitive(TLV_UID).map_err(|e| {
                Error::Tlv(format!("Failed to read instance UID: {}", e))
            })?);
        }

        // secureChannelPubKey (0x80) - present in V1-V3, absent in V4+
        if reader.next_tag_is(TLV_PUB_KEY) {
            secure_channel_pub_key = Some(reader.read_primitive(TLV_PUB_KEY).map_err(|e| {
                Error::Tlv(format!("Failed to read secure channel public key: {}", e))
            })?);
        }

        // appVersion (INTEGER 0x02) - present in all versions
        app_version = reader.read_integer().map_err(|e| {
            Error::Tlv(format!("Failed to read app version: {}", e))
        })? as u16;

        // appStatus (0x8C) - initialized, lee mode, pin retries
        if reader.next_tag_is(TLV_STATUS) {
            let status_bytes = reader.read_primitive(TLV_STATUS).map_err(|e| {
                Error::Tlv(format!("Failed to read app status: {}", e))
            })?;
            app_status = status_bytes[0];
        }

        let initialized = (app_status & APP_STATUS_INITIALIZED) == APP_STATUS_INITIALIZED;

        // freePairingSlots (INTEGER 0x02) - present in V1-V3, absent in V4+
        if reader.next_tag_is(TLV_INT) {
            free_pairing_slots = reader.read_integer().map_err(|e| {
                Error::Tlv(format!("Failed to read free pairing slots: {}", e))
            })? as u8;
        }

        // keyUID (0x8E) - present in all versions
        key_uid = reader.read_primitive(TLV_KEY_UID).map_err(|e| {
            Error::Tlv(format!("Failed to read key UID: {}", e))
        })?;

        // capabilities (0x8D) - present in V2+
        if reader.next_tag_is(TLV_CAPABILITIES) {
            let caps_bytes = reader.read_primitive(TLV_CAPABILITIES).map_err(|e| {
                Error::Tlv(format!("Failed to read capabilities: {}", e))
            })?;
            capabilities = caps_bytes[0];
        }

        // certData (0x8A) - present in V4+
        if reader.next_tag_is(TLV_CERT) {
            cert_data = Some(reader.read_primitive(TLV_CERT).map_err(|e| {
                Error::Tlv(format!("Failed to read certificate data: {}", e))
            })?);
        }

        Ok(Self {
            initialized,
            instance_uid,
            secure_channel_pub_key,
            app_version,
            free_pairing_slots,
            key_uid,
            capabilities,
            cert_data,
            app_status,
        })
    }

    /// Returns `true` if the card is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns `true` if the card has a master key loaded.
    pub fn has_master_key(&self) -> bool {
        !self.key_uid.is_empty()
    }

    /// Returns the instance UID (present in V1-V3, absent in V4+).
    pub fn instance_uid(&self) -> Option<&[u8]> {
        self.instance_uid.as_deref()
    }

    /// Returns the secure channel public key (present in V1-V3, absent in V4+).
    pub fn secure_channel_pub_key(&self) -> Option<&[u8]> {
        self.secure_channel_pub_key.as_deref()
    }

    /// Returns the app version (major in MSB, minor in LSB).
    pub fn app_version(&self) -> u16 {
        self.app_version
    }

    /// Returns the app version as a formatted string (e.g., "4.2").
    pub fn app_version_string(&self) -> String {
        format!("{}.{}", (self.app_version >> 8) & 0xFF, self.app_version & 0xFF)
    }

    /// Returns the number of free pairing slots (V1-V3 only).
    pub fn free_pairing_slots(&self) -> u8 {
        self.free_pairing_slots
    }

    /// Returns the key UID.
    pub fn key_uid(&self) -> &[u8] {
        &self.key_uid
    }

    /// Returns the capability flags.
    pub fn capabilities(&self) -> u8 {
        self.capabilities
    }

    /// Returns `true` if the device supports Secure Channel.
    pub fn has_secure_channel(&self) -> bool {
        (self.capabilities & capability::SECURE_CHANNEL) != 0
    }

    /// Returns `true` if the device supports Key Management.
    pub fn has_key_management(&self) -> bool {
        (self.capabilities & capability::KEY_MANAGEMENT) != 0
    }

    /// Returns `true` if the device supports Credentials Management.
    pub fn has_credentials_management(&self) -> bool {
        (self.capabilities & capability::CREDENTIALS_MANAGEMENT) != 0
    }

    /// Returns `true` if the device supports NDEF.
    pub fn has_ndef(&self) -> bool {
        (self.capabilities & capability::NDEF) != 0
    }

    /// Returns `true` if the device supports Factory Reset.
    pub fn has_factory_reset(&self) -> bool {
        (self.capabilities & capability::FACTORY_RESET) != 0
    }

    /// Returns `true` if the device is in LEE mode.
    pub fn is_lee_mode(&self) -> bool {
        (self.app_status & APP_STATUS_LEE_MODE) != 0
    }

    /// Returns the remaining PIN retry count (V4+ only).
    /// Returns `None` for older applet versions.
    pub fn pin_retries(&self) -> Option<u8> {
        if self.app_version < 0x0400 {
            None
        } else {
            Some(self.app_status & 0x0F)
        }
    }

    /// Returns the raw certificate data (V4+ only).
    pub fn cert_data(&self) -> Option<&[u8]> {
        self.cert_data.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::BerTlvWriter;

    #[test]
    fn test_uninitialized_card() {
        // Uninitialized card: just TLV_PUB_KEY with some data
        let mut writer = BerTlvWriter::new();
        writer.write_primitive(TLV_PUB_KEY, &[0x04; 65]);
        let data = writer.to_vec();

        let info = ApplicationInfo::from_tlv(&data).unwrap();
        assert!(!info.is_initialized());
        assert!(info.secure_channel_pub_key().is_some());
        assert!(info.has_secure_channel());
    }

    #[test]
    fn test_uninitialized_no_secure_channel() {
        // Empty public key = no secure channel
        let mut writer = BerTlvWriter::new();
        writer.write_primitive(TLV_PUB_KEY, &[]);
        let data = writer.to_vec();

        let info = ApplicationInfo::from_tlv(&data).unwrap();
        assert!(!info.is_initialized());
        assert!(!info.has_secure_channel());
    }

    #[test]
    fn test_initialized_card_v4() {
        // V4+ card: no instance UID, no secure channel pub key, has cert
        let mut writer = BerTlvWriter::new();
        writer.write_constructed(TLV_APPLICATION_INFO_TEMPLATE, |w| {
            // Skip instance_uid and secure_channel_pub_key (V4+)
            w.write_integer(TLV_INT, 0x0402); // version 4.2
            w.write_primitive(TLV_STATUS, &[APP_STATUS_INITIALIZED | 0x06]); // initialized, 6 retries
            // Skip free_pairing_slots (V4+)
            w.write_primitive(TLV_KEY_UID, &[0x01, 0x02, 0x03]);
            w.write_primitive(TLV_CAPABILITIES, &[capability::ALL]);
            w.write_primitive(TLV_CERT, &[0xAA; 98]);
        });
        let data = writer.to_vec();

        let info = ApplicationInfo::from_tlv(&data).unwrap();
        assert!(info.is_initialized());
        assert_eq!(info.app_version(), 0x0402);
        assert_eq!(info.app_version_string(), "4.2");
        assert_eq!(info.pin_retries(), Some(6));
        assert!(info.cert_data().is_some());
        assert_eq!(info.key_uid(), &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_initialized_card_v3() {
        // V3 card: has instance UID, secure channel pub key, free pairing slots
        let mut writer = BerTlvWriter::new();
        writer.write_constructed(TLV_APPLICATION_INFO_TEMPLATE, |w| {
            w.write_primitive(TLV_UID, &[0x01, 0x02]);
            w.write_primitive(TLV_PUB_KEY, &[0x04; 65]);
            w.write_integer(TLV_INT, 0x0301); // version 3.1
            w.write_primitive(TLV_STATUS, &[APP_STATUS_INITIALIZED]);
            w.write_integer(TLV_INT, 3); // 3 free pairing slots
            w.write_primitive(TLV_KEY_UID, &[0x01, 0x02, 0x03]);
            w.write_primitive(TLV_CAPABILITIES, &[capability::ALL]);
        });
        let data = writer.to_vec();

        let info = ApplicationInfo::from_tlv(&data).unwrap();
        assert!(info.is_initialized());
        assert_eq!(info.app_version(), 0x0301);
        assert!(info.instance_uid().is_some());
        assert!(info.secure_channel_pub_key().is_some());
        assert_eq!(info.free_pairing_slots(), 3);
        assert!(info.pin_retries().is_none()); // V3 doesn't have pin retries
    }
}
