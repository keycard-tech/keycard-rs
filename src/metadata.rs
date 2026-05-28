//! Card metadata handling (name + wallet set).

use std::collections::BTreeSet;

use crate::error::Error;

/// Card metadata containing a name and a set of wallet IDs.
#[derive(Debug, Clone)]
pub struct Metadata {
    card_name: String,
    wallets: BTreeSet<u64>,
}

impl Metadata {
    /// Parses metadata from the card's binary format.
    ///
    /// Format:
    /// - Byte 0: `(version << 5) | name_length` (version must be 1)
    /// - Next `name_length` bytes: ASCII card name
    /// - Remaining: variable-length encoded wallet ranges
    pub fn from_data(data: &[u8]) -> Result<Self, Error> {
        if data.is_empty() {
            return Err(Error::Tlv("Empty metadata data".to_string()));
        }

        let version = (data[0] & 0xE0) >> 5;
        if version != 1 {
            return Err(Error::Tlv(format!("Invalid metadata version: {}", version)));
        }

        let name_len = (data[0] & 0x1F) as usize;
        let mut off = 1;

        if off + name_len > data.len() {
            return Err(Error::Tlv("Metadata data too short for card name".to_string()));
        }

        let card_name = String::from_utf8(data[off..off + name_len].to_vec())
            .map_err(|e| Error::Tlv(format!("Invalid UTF-8 in card name: {}", e)))?;
        off += name_len;

        let mut wallets = BTreeSet::new();

        while off < data.len() {
            let (start, next_off) = read_num(data, off)?;
            off = next_off;
            let (count, next_off) = read_num(data, off)?;
            off = next_off;

            for i in 0..=count {
                wallets.insert((start + i) as u64);
            }
        }

        Ok(Self { card_name, wallets })
    }

    /// Creates new metadata with an empty wallet set.
    pub fn new(card_name: String) -> Self {
        Self {
            card_name,
            wallets: BTreeSet::new(),
        }
    }

    /// Returns the card name.
    pub fn card_name(&self) -> &str {
        &self.card_name
    }

    /// Sets the card name (max 20 characters).
    pub fn set_card_name(&mut self, name: String) -> Result<(), Error> {
        if name.len() > 20 {
            return Err(Error::InvalidArgument("Card name too long (max 20 characters)".to_string()));
        }
        self.card_name = name;
        Ok(())
    }

    /// Returns the set of wallet IDs.
    pub fn wallets(&self) -> &BTreeSet<u64> {
        &self.wallets
    }

    /// Adds a wallet ID.
    pub fn add_wallet(&mut self, wallet_id: u64) {
        self.wallets.insert(wallet_id);
    }

    /// Removes a wallet ID.
    pub fn remove_wallet(&mut self, wallet_id: u64) {
        self.wallets.remove(&wallet_id);
    }

    /// Serializes to the binary format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let name_bytes = self.card_name.as_bytes();
        let mut buf = Vec::with_capacity(1 + name_bytes.len());

        // Header: version 1 << 5 | name_length
        buf.push(0x20 | (name_bytes.len() as u8));
        buf.extend_from_slice(name_bytes);

        if self.wallets.is_empty() {
            return buf;
        }

        // Compress wallets into contiguous ranges
        let mut ranges: Vec<(u64, u64)> = Vec::new(); // (start, count)
        let mut start = *self.wallets.first().unwrap();
        let mut len: u64 = 0;

        for &w in self.wallets.iter().skip(1) {
            if w == start + len + 1 {
                len += 1;
            } else {
                ranges.push((start, len));
                len = 0;
                start = w;
            }
        }
        ranges.push((start, len));

        // Encode ranges
        for &(start, count) in &ranges {
            write_num(&mut buf, start as u32);
            write_num(&mut buf, count as u32);
        }

        buf
    }
}

/// Reads a variable-length encoded integer from `data` at offset `off`.
/// Returns `(value, next_offset)`.
fn read_num(data: &[u8], off: usize) -> Result<(u32, usize), Error> {
    if off >= data.len() {
        return Err(Error::Tlv("End of data while reading number".to_string()));
    }

    let first = data[off] as u32;
    let mut off = off + 1;

    if first < 0x80 {
        // Short form
        Ok((first, off))
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if off + num_bytes > data.len() {
            return Err(Error::Tlv("End of data while reading number length".to_string()));
        }

        let mut val: u32 = 0;
        for i in 0..num_bytes {
            val = (val << 8) | data[off + i] as u32;
        }
        off += num_bytes;
        Ok((val, off))
    }
}

/// Writes a variable-length encoded integer to `buf`.
fn write_num(buf: &mut Vec<u8>, val: u32) {
    if val > 0xFFFFFF {
        buf.push(0x84);
        buf.push(((val >> 24) & 0xFF) as u8);
        buf.push(((val >> 16) & 0xFF) as u8);
        buf.push(((val >> 8) & 0xFF) as u8);
        buf.push((val & 0xFF) as u8);
    } else if val > 0xFFFF {
        buf.push(0x83);
        buf.push(((val >> 16) & 0xFF) as u8);
        buf.push(((val >> 8) & 0xFF) as u8);
        buf.push((val & 0xFF) as u8);
    } else if val > 0xFF {
        buf.push(0x82);
        buf.push(((val >> 8) & 0xFF) as u8);
        buf.push((val & 0xFF) as u8);
    } else if val > 0x7F {
        buf.push(0x81);
        buf.push((val & 0xFF) as u8);
    } else {
        buf.push(val as u8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_roundtrip() {
        let mut meta = Metadata::new("TestCard".to_string());
        meta.add_wallet(1);
        meta.add_wallet(2);
        meta.add_wallet(3);
        meta.add_wallet(100);

        let bytes = meta.to_bytes();
        let parsed = Metadata::from_data(&bytes).unwrap();

        assert_eq!(parsed.card_name(), "TestCard");
        assert_eq!(parsed.wallets(), meta.wallets());
    }

    #[test]
    fn test_metadata_empty_wallets() {
        let meta = Metadata::new("EmptyCard".to_string());
        let bytes = meta.to_bytes();
        let parsed = Metadata::from_data(&bytes).unwrap();
        assert_eq!(parsed.card_name(), "EmptyCard");
        assert!(parsed.wallets().is_empty());
    }

    #[test]
    fn test_metadata_invalid_version() {
        let data = vec![0x00, b'T', b'e', b's', b't'];
        assert!(Metadata::from_data(&data).is_err());
    }

    #[test]
    fn test_metadata_name_too_long() {
        let mut meta = Metadata::new("Short".to_string());
        meta.set_card_name("ThisNameIsWayTooLongForACard".to_string())
            .unwrap_err();
    }

    #[test]
    fn test_write_num_short() {
        let mut buf = Vec::new();
        write_num(&mut buf, 42);
        assert_eq!(buf, vec![42]);
    }

    #[test]
    fn test_write_num_long_1() {
        let mut buf = Vec::new();
        write_num(&mut buf, 200);
        assert_eq!(buf, vec![0x81, 200]);
    }

    #[test]
    fn test_write_num_long_2() {
        let mut buf = Vec::new();
        write_num(&mut buf, 300);
        assert_eq!(buf, vec![0x82, 1, 44]);
    }

    #[test]
    fn test_read_num_roundtrip() {
        let values = [0u32, 1, 127, 128, 255, 256, 300, 0xFFFF, 0x10000, 0xFFFFFF, 0x1000000];
        for &val in &values {
            let mut buf = Vec::new();
            write_num(&mut buf, val);
            let (read_val, _) = read_num(&buf, 0).unwrap();
            assert_eq!(read_val, val, "Failed for value {}", val);
        }
    }

    #[test]
    fn test_metadata_wallet_range_compression() {
        let mut meta = Metadata::new("RangeCard".to_string());
        for i in 1..=5 {
            meta.add_wallet(i);
        }
        meta.add_wallet(20);
        meta.add_wallet(21);

        let bytes = meta.to_bytes();
        let parsed = Metadata::from_data(&bytes).unwrap();
        assert_eq!(parsed.wallets(), meta.wallets());
    }
}
