//! Parsing of the LEE key export response.
//!
//! The applet's `EXPORT LEE` command returns a constructed
//! `TLV_KEY_TEMPLATE` containing four 32-byte primitive values, per the
//! LEE-Keys v1 derivation scheme:
//!
//! - `TLV_LEE_ASK` (0x84) — authorization secret key
//! - `TLV_LEE_NSK` (0x83) — nullifier secret key
//! - `TLV_LEE_VSK_D` (0x85) — viewing seed (diversifier)
//! - `TLV_LEE_VSK_Z` (0x86) — viewing seed (nullifier)

use crate::error::Error;
use crate::tlv::{
    BerTlvReader, TLV_KEY_TEMPLATE, TLV_LEE_ASK, TLV_LEE_NSK, TLV_LEE_VSK_D, TLV_LEE_VSK_Z,
};

/// Size of a LEE secret in bytes (each ASK/NSK/VSK component is 32 bytes).
pub const LEE_SECRET_SIZE: usize = 32;

/// Parsed LEE key material from an EXPORT LEE response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeeKey {
    ask: [u8; LEE_SECRET_SIZE],
    nsk: [u8; LEE_SECRET_SIZE],
    vsk_d: [u8; LEE_SECRET_SIZE],
    vsk_z: [u8; LEE_SECRET_SIZE],
}

impl LeeKey {
    /// Parses the TLV response from an EXPORT LEE command.
    ///
    /// The response is a constructed `TLV_KEY_TEMPLATE` containing, in order:
    /// ASK (0x84), NSK (0x83), VSK_D (0x85) and VSK_Z (0x86), each 32 bytes.
    ///
    /// # Errors
    /// Returns [`Error::Tlv`] if the response is malformed or any component is
    /// not exactly 32 bytes long.
    pub fn from_tlv(data: &[u8]) -> Result<Self, Error> {
        let mut reader = BerTlvReader::new(data);
        reader.enter_constructed(TLV_KEY_TEMPLATE).map_err(|e| {
            Error::Tlv(format!("Failed to enter LEE key template: {}", e))
        })?;

        let ask = read_secret(&mut reader, TLV_LEE_ASK, "ASK")?;
        let nsk = read_secret(&mut reader, TLV_LEE_NSK, "NSK")?;
        let vsk_d = read_secret(&mut reader, TLV_LEE_VSK_D, "VSK_D")?;
        let vsk_z = read_secret(&mut reader, TLV_LEE_VSK_Z, "VSK_Z")?;

        Ok(Self { ask, nsk, vsk_d, vsk_z })
    }

    /// Returns the authorization secret key (ASK).
    pub fn ask(&self) -> &[u8; LEE_SECRET_SIZE] {
        &self.ask
    }

    /// Returns the nullifier secret key (NSK).
    pub fn nsk(&self) -> &[u8; LEE_SECRET_SIZE] {
        &self.nsk
    }

    /// Returns the viewing seed diversifier (VSK_D).
    pub fn vsk_d(&self) -> &[u8; LEE_SECRET_SIZE] {
        &self.vsk_d
    }

    /// Returns the viewing seed nullifier (VSK_Z).
    pub fn vsk_z(&self) -> &[u8; LEE_SECRET_SIZE] {
        &self.vsk_z
    }
}

/// Reads a 32-byte primitive secret with the given tag.
fn read_secret(
    reader: &mut BerTlvReader,
    tag: u8,
    name: &str,
) -> Result<[u8; LEE_SECRET_SIZE], Error> {
    let value = reader.read_primitive(tag).map_err(|e| {
        Error::Tlv(format!("Failed to read LEE {} (0x{:02X}): {}", name, tag, e))
    })?;

    let bytes: [u8; LEE_SECRET_SIZE] = value.as_slice().try_into().map_err(|_| {
        Error::Tlv(format!(
            "LEE {} must be exactly {} bytes, got {}",
            name,
            LEE_SECRET_SIZE,
            value.len()
        ))
    })?;

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::BerTlvWriter;

    #[test]
    fn test_parse_lee_key() {
        let ask = [0x7Bu8; 32];
        let nsk = [0xEFu8; 32];
        let vsk_d = [0x9Bu8; 32];
        let vsk_z = [0xBFu8; 32];

        let mut writer = BerTlvWriter::new();
        writer.write_constructed(TLV_KEY_TEMPLATE, |w| {
            w.write_primitive(TLV_LEE_ASK, &ask);
            w.write_primitive(TLV_LEE_NSK, &nsk);
            w.write_primitive(TLV_LEE_VSK_D, &vsk_d);
            w.write_primitive(TLV_LEE_VSK_Z, &vsk_z);
        });

        let key = LeeKey::from_tlv(&writer.to_vec()).unwrap();
        assert_eq!(key.ask(), &ask);
        assert_eq!(key.nsk(), &nsk);
        assert_eq!(key.vsk_d(), &vsk_d);
        assert_eq!(key.vsk_z(), &vsk_z);
    }

    #[test]
    fn test_parse_lee_key_missing_component() {
        let mut writer = BerTlvWriter::new();
        writer.write_constructed(TLV_KEY_TEMPLATE, |w| {
            w.write_primitive(TLV_LEE_ASK, &[0x11u8; 32]);
            // NSK missing
            w.write_primitive(TLV_LEE_VSK_D, &[0x22u8; 32]);
            w.write_primitive(TLV_LEE_VSK_Z, &[0x33u8; 32]);
        });

        let err = LeeKey::from_tlv(&writer.to_vec()).unwrap_err();
        assert!(matches!(err, Error::Tlv(_)));
    }

    #[test]
    fn test_parse_lee_key_wrong_size() {
        let mut writer = BerTlvWriter::new();
        writer.write_constructed(TLV_KEY_TEMPLATE, |w| {
            w.write_primitive(TLV_LEE_ASK, &[0x11u8; 16]); // too short
            w.write_primitive(TLV_LEE_NSK, &[0x22u8; 32]);
            w.write_primitive(TLV_LEE_VSK_D, &[0x33u8; 32]);
            w.write_primitive(TLV_LEE_VSK_Z, &[0x44u8; 32]);
        });

        let err = LeeKey::from_tlv(&writer.to_vec()).unwrap_err();
        match err {
            Error::Tlv(msg) => assert!(msg.contains("ASK")),
            _ => panic!("Expected Tlv error"),
        }
    }

    #[test]
    fn test_parse_lee_key_not_constructed() {
        // Not wrapped in a key template
        let mut writer = BerTlvWriter::new();
        writer.write_primitive(TLV_LEE_ASK, &[0x11u8; 32]);

        let err = LeeKey::from_tlv(&writer.to_vec()).unwrap_err();
        assert!(matches!(err, Error::Tlv(_)));
    }

    #[test]
    fn test_lee_key_known_vector() {
        // Test vector from the applet's LEE Keys test (LEE-Keys v1).
        fn hex(s: &str) -> [u8; LEE_SECRET_SIZE] {
            let bytes: Vec<u8> = (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect();
            bytes.try_into().unwrap()
        }

        let ask = hex("7b9530590b74199ec623fd74bedc5b981c8eb36205f9981980f80c7cefc99d7d");
        let nsk = hex("ef2b7994d905e72109f60de69ee212f82ed3b99d261916671337a8b744f7a515");
        let vsk_d = hex("9bbdfc6def553c24cd50755f8c45e120a2210e66f8a3d2d2487d591158fe7439");
        let vsk_z = hex("bfabaa3ab7f9537b11035f6f1d31a3e9d2e85249f7e42e3053386c0b14b1384e");

        let mut writer = BerTlvWriter::new();
        writer.write_constructed(TLV_KEY_TEMPLATE, |w| {
            w.write_primitive(TLV_LEE_ASK, &ask);
            w.write_primitive(TLV_LEE_NSK, &nsk);
            w.write_primitive(TLV_LEE_VSK_D, &vsk_d);
            w.write_primitive(TLV_LEE_VSK_Z, &vsk_z);
        });

        let key = LeeKey::from_tlv(&writer.to_vec()).unwrap();
        assert_eq!(key.ask(), &ask);
        assert_eq!(key.nsk(), &nsk);
        assert_eq!(key.vsk_d(), &vsk_d);
        assert_eq!(key.vsk_z(), &vsk_z);
    }
}
