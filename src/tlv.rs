use crate::error::Error;

// ============================================================================
// TLV tag constants
// ============================================================================

/// BOOLEAN tag
pub const TLV_BOOL: u8 = 0x01;
/// INTEGER tag
pub const TLV_INT: u8 = 0x02;
/// SEQUENCE tag (used in ECDSA signatures)
pub const TLV_ECDSA_TEMPLATE: u8 = 0x30;
/// Signature template
pub const TLV_SIGNATURE_TEMPLATE: u8 = 0xA0;
/// Key template
pub const TLV_KEY_TEMPLATE: u8 = 0xA1;
/// Application status template
pub const TLV_APPLICATION_STATUS_TEMPLATE: u8 = 0xA3;
/// Application info template
pub const TLV_APPLICATION_INFO_TEMPLATE: u8 = 0xA4;
/// Public key
pub const TLV_PUB_KEY: u8 = 0x80;
/// Private key
pub const TLV_PRIV_KEY: u8 = 0x81;
/// Chain code
pub const TLV_CHAIN_CODE: u8 = 0x82;
/// Certificate
pub const TLV_CERT: u8 = 0x8A;
/// Capabilities
pub const TLV_CAPABILITIES: u8 = 0x8D;
/// Key UID
pub const TLV_KEY_UID: u8 = 0x8E;
/// UID (instance UID)
pub const TLV_UID: u8 = 0x8F;
/// Status
pub const TLV_STATUS: u8 = 0x8C;

// ============================================================================
// BerTlvReader
// ============================================================================

/// A cursor-based BER-TLV reader over a byte slice.
pub struct BerTlvReader<'a> {
    buffer: &'a [u8],
    pos: usize,
}

impl<'a> BerTlvReader<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { buffer, pos: 0 }
    }

    /// Reads a single-byte tag.
    pub fn read_tag(&mut self) -> Result<u8, Error> {
        if self.pos >= self.buffer.len() {
            return Err(Error::Tlv("End of buffer, no tag to read".to_string()));
        }
        let tag = self.buffer[self.pos];
        self.pos += 1;
        Ok(tag)
    }

    /// Peeks at the next tag without consuming it.
    /// Returns `true` if the next byte matches the expected tag.
    pub fn next_tag_is(&mut self, expected: u8) -> bool {
        if self.pos < self.buffer.len() {
            self.buffer[self.pos] == expected
        } else {
            false
        }
    }

    /// Reads the TLV length field.
    /// Supports short form (1 byte, 0..=127) and long form (1..=4 bytes).
    pub fn read_length(&mut self) -> Result<usize, Error> {
        if self.pos >= self.buffer.len() {
            return Err(Error::Tlv("End of buffer, no length to read".to_string()));
        }

        let first = self.buffer[self.pos] as usize;
        self.pos += 1;

        if first < 0x80 {
            // Short form: length is the byte value directly
            Ok(first)
        } else if first == 0x80 {
            // Indefinite length - not supported
            Err(Error::Tlv("Indefinite length encoding not supported".to_string()))
        } else {
            // Long form: high nibble is number of length bytes
            let num_bytes = first & 0x7F;
            if num_bytes > 4 {
                return Err(Error::Tlv(format!("Length encoding too long: {} bytes", num_bytes)));
            }
            if self.pos + num_bytes > self.buffer.len() {
                return Err(Error::Tlv("End of buffer while reading length".to_string()));
            }

            let mut len: usize = 0;
            for i in 0..num_bytes {
                len = (len << 8) | self.buffer[self.pos + i] as usize;
            }
            self.pos += num_bytes;
            Ok(len)
        }
    }

    /// Asserts next tag matches, reads and returns the length.
    pub fn enter_constructed(&mut self, tag: u8) -> Result<usize, Error> {
        let actual_tag = self.read_tag()?;
        if actual_tag != tag {
            return Err(Error::Tlv(format!(
                "Expected tag 0x{:02X} but got 0x{:02X}",
                tag, actual_tag
            )));
        }
        self.read_length()
    }

    /// Asserts next tag matches, reads length, returns the value bytes.
    pub fn read_primitive(&mut self, tag: u8) -> Result<Vec<u8>, Error> {
        let actual_tag = self.read_tag()?;
        if actual_tag != tag {
            return Err(Error::Tlv(format!(
                "Expected tag 0x{:02X} but got 0x{:02X}",
                tag, actual_tag
            )));
        }
        let len = self.read_length()?;
        if self.pos + len > self.buffer.len() {
            return Err(Error::Tlv(format!(
                "Not enough data for value: need {} bytes, have {}",
                len,
                self.buffer.len() - self.pos
            )));
        }
        let value = self.buffer[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(value)
    }

    /// Reads a BOOLEAN tag (0x01), returns `true` if value byte is `0xFF`.
    pub fn read_boolean(&mut self) -> Result<bool, Error> {
        let value = self.read_primitive(TLV_BOOL)?;
        if value.len() != 1 {
            return Err(Error::Tlv(format!(
                "BOOLEAN value must be 1 byte, got {}",
                value.len()
            )));
        }
        Ok(value[0] == 0xFF)
    }

    /// Reads an INTEGER tag (0x02), decodes as big-endian.
    pub fn read_integer(&mut self) -> Result<i32, Error> {
        let value = self.read_primitive(TLV_INT)?;
        if value.is_empty() || value.len() > 4 {
            return Err(Error::Tlv(format!(
                "INTEGER value must be 1-4 bytes, got {}",
                value.len()
            )));
        }
        let mut result: i32 = 0;
        for &byte in &value {
            result = (result << 8) | byte as i32;
        }
        Ok(result)
    }

    /// Returns remaining unconsumed bytes.
    pub fn peek_unread(&self) -> &'a [u8] {
        if self.pos < self.buffer.len() {
            &self.buffer[self.pos..]
        } else {
            &[]
        }
    }

    /// Returns the current position in the buffer.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Returns the total buffer length.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Returns `true` if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Returns a reference to the underlying buffer.
    pub fn buffer(&self) -> &'a [u8] {
        self.buffer
    }

    /// Advances the read position by `count` bytes.
    pub fn advance(&mut self, count: usize) {
        self.pos = std::cmp::min(self.pos + count, self.buffer.len());
    }
}

// ============================================================================
// BerTlvWriter
// ============================================================================

/// A builder for constructing BER-TLV byte sequences.
pub struct BerTlvWriter {
    buffer: Vec<u8>,
}

impl BerTlvWriter {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
        }
    }

    /// Writes a length field in BER-TLV encoding (short or long form).
    pub fn write_num_length(&mut self, len: usize) {
        if len < 0x80 {
            // Short form
            self.buffer.push(len as u8);
        } else if len < 0x100 {
            self.buffer.push(0x81);
            self.buffer.push(len as u8);
        } else if len < 0x10000 {
            self.buffer.push(0x82);
            self.buffer.push((len >> 8) as u8);
            self.buffer.push(len as u8);
        } else if len < 0x1000000 {
            self.buffer.push(0x83);
            self.buffer.push((len >> 16) as u8);
            self.buffer.push((len >> 8) as u8);
            self.buffer.push(len as u8);
        } else {
            self.buffer.push(0x84);
            self.buffer.push((len >> 24) as u8);
            self.buffer.push((len >> 16) as u8);
            self.buffer.push((len >> 8) as u8);
            self.buffer.push(len as u8);
        }
    }

    /// Writes a single tag byte.
    pub fn write_tag(&mut self, tag: u8) {
        self.buffer.push(tag);
    }

    /// Writes tag + length + value.
    pub fn write_primitive(&mut self, tag: u8, value: &[u8]) {
        self.buffer.push(tag);
        self.write_num_length(value.len());
        self.buffer.extend_from_slice(value);
    }

    /// Writes a constructed TLV: tag + total length, then invokes `content_fn` to write inner TLVs.
    pub fn write_constructed<F>(&mut self, tag: u8, content_fn: F)
    where
        F: FnOnce(&mut Self),
    {
        // First, write content to a temporary buffer
        let mut temp_writer = BerTlvWriter::new();
        content_fn(&mut temp_writer);
        let content = temp_writer.to_vec();

        // Write tag + length + content
        self.buffer.push(tag);
        self.write_num_length(content.len());
        self.buffer.extend_from_slice(&content);
    }

    /// Writes a BOOLEAN TLV.
    pub fn write_boolean(&mut self, tag: u8, value: bool) {
        self.write_primitive(tag, &[if value { 0xFF } else { 0x00 }]);
    }

    /// Writes an INTEGER TLV.
    pub fn write_integer(&mut self, tag: u8, value: i32) {
        let bytes = value.to_be_bytes();
        // Strip leading zero bytes (but keep at least one byte)
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(3);
        // For negative values, keep the sign byte
        let start = if value < 0 { 0 } else { start };
        self.write_primitive(tag, &bytes[start..]);
    }

    /// Returns the accumulated bytes.
    pub fn to_vec(&self) -> Vec<u8> {
        self.buffer.clone()
    }

    /// Returns a reference to the accumulated bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.buffer
    }
}

impl Default for BerTlvWriter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_tag() {
        let mut reader = BerTlvReader::new(&[0x80, 0x01, 0xAB]);
        assert_eq!(reader.read_tag().unwrap(), 0x80);
    }

    #[test]
    fn test_read_tag_end_of_buffer() {
        let mut reader = BerTlvReader::new(&[]);
        assert!(reader.read_tag().is_err());
    }

    #[test]
    fn test_read_length_short() {
        let mut reader = BerTlvReader::new(&[0x0A]);
        assert_eq!(reader.read_length().unwrap(), 10);
    }

    #[test]
    fn test_read_length_long_1_byte() {
        let mut reader = BerTlvReader::new(&[0x81, 0xFF]);
        assert_eq!(reader.read_length().unwrap(), 255);
    }

    #[test]
    fn test_read_length_long_2_bytes() {
        let mut reader = BerTlvReader::new(&[0x82, 0x01, 0x00]);
        assert_eq!(reader.read_length().unwrap(), 256);
    }

    #[test]
    fn test_next_tag_is() {
        let mut reader = BerTlvReader::new(&[0x80, 0x01, 0xAB]);
        assert!(reader.next_tag_is(0x80));
        assert!(!reader.next_tag_is(0x81));
    }

    #[test]
    fn test_read_primitive() {
        let data = [0x80, 0x03, 0x01, 0x02, 0x03, 0x81, 0x02, 0xAA, 0xBB];
        let mut reader = BerTlvReader::new(&data);
        let val = reader.read_primitive(0x80).unwrap();
        assert_eq!(val, vec![0x01, 0x02, 0x03]);
        let val2 = reader.read_primitive(0x81).unwrap();
        assert_eq!(val2, vec![0xAA, 0xBB]);
    }

    #[test]
    fn test_read_boolean() {
        let data = [0x01, 0x01, 0xFF];
        let mut reader = BerTlvReader::new(&data);
        assert!(reader.read_boolean().unwrap());

        let data = [0x01, 0x01, 0x00];
        let mut reader = BerTlvReader::new(&data);
        assert!(!reader.read_boolean().unwrap());
    }

    #[test]
    fn test_read_integer() {
        // Single byte
        let data = [0x02, 0x01, 0x05];
        let mut reader = BerTlvReader::new(&data);
        assert_eq!(reader.read_integer().unwrap(), 5);

        // Two bytes
        let data = [0x02, 0x02, 0x00, 0x64];
        let mut reader = BerTlvReader::new(&data);
        assert_eq!(reader.read_integer().unwrap(), 100);

        // Four bytes
        let data = [0x02, 0x03, 0x00, 0x01, 0x00];
        let mut reader = BerTlvReader::new(&data);
        assert_eq!(reader.read_integer().unwrap(), 256);
    }

    #[test]
    fn test_peek_unread() {
        let data = [0x01, 0x02, 0x03, 0x04];
        let mut reader = BerTlvReader::new(&data);
        assert_eq!(reader.peek_unread(), &[0x01, 0x02, 0x03, 0x04]);
        reader.read_tag().unwrap();
        assert_eq!(reader.peek_unread(), &[0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_write_primitive() {
        let mut writer = BerTlvWriter::new();
        writer.write_primitive(0x80, &[0x01, 0x02, 0x03]);
        assert_eq!(writer.to_vec(), vec![0x80, 0x03, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_write_boolean() {
        let mut writer = BerTlvWriter::new();
        writer.write_boolean(0x01, true);
        assert_eq!(writer.to_vec(), vec![0x01, 0x01, 0xFF]);

        let mut writer = BerTlvWriter::new();
        writer.write_boolean(0x01, false);
        assert_eq!(writer.to_vec(), vec![0x01, 0x01, 0x00]);
    }

    #[test]
    fn test_write_integer() {
        let mut writer = BerTlvWriter::new();
        writer.write_integer(0x02, 5);
        assert_eq!(writer.to_vec(), vec![0x02, 0x01, 0x05]);

        let mut writer = BerTlvWriter::new();
        writer.write_integer(0x02, 256);
        assert_eq!(writer.to_vec(), vec![0x02, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn test_write_constructed() {
        let mut writer = BerTlvWriter::new();
        writer.write_constructed(0xA0, |w| {
            w.write_primitive(0x80, &[0x01, 0x02]);
            w.write_primitive(0x81, &[0x03, 0x04, 0x05]);
        });
        // Tag 0xA0, length 9 (4 + 5), then inner TLVs
        assert_eq!(
            writer.to_vec(),
            vec![0xA0, 0x09, 0x80, 0x02, 0x01, 0x02, 0x81, 0x03, 0x03, 0x04, 0x05]
        );
    }

    #[test]
    fn test_write_num_length_short() {
        let mut writer = BerTlvWriter::new();
        writer.write_num_length(10);
        assert_eq!(writer.to_vec(), vec![0x0A]);
    }

    #[test]
    fn test_write_num_length_long() {
        let mut writer = BerTlvWriter::new();
        writer.write_num_length(256);
        assert_eq!(writer.to_vec(), vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn test_reader_enter_constructed() {
        let data = [0xA0, 0x05, 0x80, 0x03, 0x01, 0x02, 0x03];
        let mut reader = BerTlvReader::new(&data);
        let len = reader.enter_constructed(0xA0).unwrap();
        assert_eq!(len, 5);
    }

    #[test]
    fn test_reader_enter_constructed_wrong_tag() {
        let data = [0xA0, 0x01, 0x01];
        let mut reader = BerTlvReader::new(&data);
        let err = reader.enter_constructed(0xA1).unwrap_err();
        match err {
            Error::Tlv(msg) => assert!(msg.contains("0xA1")),
            _ => panic!("Expected Tlv error"),
        }
    }

    #[test]
    fn test_roundtrip_constructed() {
        let mut writer = BerTlvWriter::new();
        writer.write_constructed(0xA1, |w| {
            w.write_primitive(0x80, &[0x04; 65]); // public key
            w.write_primitive(0x81, &[0x00; 32]); // private key
            w.write_primitive(0x82, &[0xCC; 32]); // chain code
        });

        let bytes = writer.to_vec();
        let mut reader = BerTlvReader::new(&bytes);
        let len = reader.enter_constructed(0xA1).unwrap();
        assert_eq!(len, 1 + 1 + 65 + 1 + 1 + 32 + 1 + 1 + 32);

        let pub_key = reader.read_primitive(0x80).unwrap();
        assert_eq!(pub_key.len(), 65);
        let priv_key = reader.read_primitive(0x81).unwrap();
        assert_eq!(priv_key.len(), 32);
        let chain_code = reader.read_primitive(0x82).unwrap();
        assert_eq!(chain_code.len(), 32);
        assert_eq!(reader.peek_unread(), &[]);
    }
}
