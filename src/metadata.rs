//! Card metadata handling (name + wallet set).

use std::collections::BTreeSet;

use crate::error::Error;
use crate::tlv::{decode_ber_length, encode_ber_length};

/// Upper bound on a single encoded wallet range's count.
///
/// Guards against a malformed or hostile metadata blob whose `count` field
/// (attacker/card-controlled, up to `0xFFFFFFFF` via the 5-byte length form)
/// would otherwise drive an unbounded loop and an OOM/CPU-exhaustion DoS.
/// Real Keycard wallet sets are on the order of tens of entries.
const MAX_WALLET_RANGE_COUNT: u32 = 100_000;

/// Upper bound on the *total* number of wallet IDs across all ranges in one
/// blob. `MAX_WALLET_RANGE_COUNT` alone only bounds a single range — nothing
/// stops a hostile blob from repeating many near-max-count ranges back to
/// back, so the aggregate needs its own bound to actually cap the total
/// work done per `from_data` call.
const MAX_TOTAL_WALLETS: u64 = 100_000;

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
        let mut total_inserted: u64 = 0;

        while off < data.len() {
            let (start, next_off) = read_num(data, off)?;
            off = next_off;
            let (count, next_off) = read_num(data, off)?;
            off = next_off;

            if count > MAX_WALLET_RANGE_COUNT {
                return Err(Error::Tlv(format!(
                    "Wallet range count too large: {} (max {})",
                    count, MAX_WALLET_RANGE_COUNT
                )));
            }

            total_inserted += count as u64 + 1;
            if total_inserted > MAX_TOTAL_WALLETS {
                return Err(Error::Tlv(format!(
                    "Total wallet count too large: {} (max {})",
                    total_inserted, MAX_TOTAL_WALLETS
                )));
            }

            for i in 0..=count as u64 {
                wallets.insert(start as u64 + i);
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
///
/// Uses the same BER length encoding as `tlv.rs` (just without an
/// accompanying tag byte, since this isn't a full TLV value).
fn read_num(data: &[u8], off: usize) -> Result<(u32, usize), Error> {
    let (val, next_off) = decode_ber_length(data, off)?;
    let val: u32 = val
        .try_into()
        .map_err(|_| Error::Tlv("Number too large to fit in u32".to_string()))?;
    Ok((val, next_off))
}

/// Writes a variable-length encoded integer to `buf`.
fn write_num(buf: &mut Vec<u8>, val: u32) {
    buf.extend_from_slice(&encode_ber_length(val as usize));
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

    #[test]
    fn test_metadata_huge_range_count_rejected() {
        // Header: version 1, empty name.
        let mut data = vec![0x20];
        // start = 0
        data.push(0x00);
        // count = 0xFFFFFFFF (5-byte long form), which would otherwise
        // drive a ~4 billion iteration loop.
        data.push(0x84);
        data.extend_from_slice(&0xFFFFFFFFu32.to_be_bytes());

        let err = Metadata::from_data(&data).unwrap_err();
        match err {
            Error::Tlv(msg) => assert!(msg.contains("too large")),
            _ => panic!("Expected Tlv error"),
        }
    }

    #[test]
    fn test_metadata_range_count_at_limit_still_bounded() {
        // A count just above the limit must still be rejected quickly
        // rather than looping.
        let mut data = vec![0x20, 0x00];
        data.push(0x83);
        let over_limit = MAX_WALLET_RANGE_COUNT + 1;
        data.extend_from_slice(&over_limit.to_be_bytes()[1..]);

        assert!(Metadata::from_data(&data).is_err());
    }

    #[test]
    fn test_metadata_start_near_max_does_not_overflow() {
        // start near u32::MAX plus a small count must not panic on overflow.
        let mut data = vec![0x20];
        data.push(0x84);
        data.extend_from_slice(&(u32::MAX - 2).to_be_bytes());
        data.push(0x02); // count = 2

        let parsed = Metadata::from_data(&data).unwrap();
        assert_eq!(parsed.wallets().len(), 3);
        assert!(parsed.wallets().contains(&(u32::MAX as u64)));
    }

    #[test]
    fn test_metadata_rejects_indefinite_length_prefix() {
        // A length-prefix byte of exactly 0x80 (indefinite length) must be
        // rejected, matching tlv.rs's BerTlvReader — not silently read as 0.
        let data = vec![0x20, 0x80, 0x00];
        assert!(Metadata::from_data(&data).is_err());
    }

    #[test]
    fn test_metadata_rejects_length_prefix_over_4_bytes() {
        // A long-form prefix claiming more than 4 length bytes (0x85 = 5)
        // must be rejected outright, matching tlv.rs's BerTlvReader.
        let mut data = vec![0x20, 0x85];
        data.extend_from_slice(&[0x00; 5]);
        let err = Metadata::from_data(&data).unwrap_err();
        match err {
            Error::Tlv(msg) => assert!(msg.contains("too long")),
            _ => panic!("Expected Tlv error"),
        }
    }

    #[test]
    fn test_metadata_rejects_aggregate_count_over_multiple_ranges() {
        // Two ranges, each individually under MAX_WALLET_RANGE_COUNT, but
        // together over MAX_TOTAL_WALLETS. The per-range cap alone would
        // let this through; only the aggregate cap catches it.
        let mut data = vec![0x20]; // header, empty name
        for _ in 0..2 {
            data.push(0x00); // start = 0
            data.push(0x82); // long form, 2 length bytes
            data.extend_from_slice(&50_000u16.to_be_bytes()); // count = 50,000
        }

        let err = Metadata::from_data(&data).unwrap_err();
        match err {
            Error::Tlv(msg) => assert!(msg.contains("Total wallet count too large")),
            _ => panic!("Expected Tlv error"),
        }
    }

    #[test]
    fn test_metadata_allows_multiple_ranges_within_aggregate_cap() {
        // Two small ranges that stay well within the aggregate cap must
        // still parse successfully.
        let mut data = vec![0x20];
        data.push(0x00); // start = 0
        data.push(0x02); // count = 2 -> wallets 0,1,2
        data.push(0x0A); // start = 10
        data.push(0x01); // count = 1 -> wallets 10,11

        let parsed = Metadata::from_data(&data).unwrap();
        assert_eq!(parsed.wallets().len(), 5);
    }
}
