use crate::error::{ApduError, Error, WrongPinError};

/// An ISO 7816-4 command APDU.
#[derive(Debug, Clone)]
pub struct ApduCommand {
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: Vec<u8>,
    needs_le: bool,
}

impl ApduCommand {
    pub fn new(cla: u8, ins: u8, p1: u8, p2: u8, data: Vec<u8>) -> Self {
        Self {
            cla,
            ins,
            p1,
            p2,
            data,
            needs_le: false,
        }
    }

    pub fn with_le(mut self, needs_le: bool) -> Self {
        self.needs_le = needs_le;
        self
    }

    /// Serializes the command APDU to bytes.
    /// Format: CLA | INS | P1 | P2 | LC | data [| LE]
    /// LC is always 1 byte (short APDU body, max 255 bytes).
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + if self.data.is_empty() && !self.needs_le { 0 } else { 1 + self.data.len() } + if self.needs_le && !self.data.is_empty() { 1 } else { 0 });
        buf.push(self.cla);
        buf.push(self.ins);
        buf.push(self.p1);
        buf.push(self.p2);

        if !self.data.is_empty() {
            // Short APDU body: LC is always 1 byte
            buf.push(self.data.len() as u8);
            buf.extend_from_slice(&self.data);
            if self.needs_le {
                buf.push(0x00);
            }
        } else if self.needs_le {
            // No data but we need LE: write LE directly (no LC)
            buf.push(0x00);
        }

        buf
    }

    pub fn cla(&self) -> u8 {
        self.cla
    }

    pub fn ins(&self) -> u8 {
        self.ins
    }

    pub fn p1(&self) -> u8 {
        self.p1
    }

    pub fn p2(&self) -> u8 {
        self.p2
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn needs_le(&self) -> bool {
        self.needs_le
    }
}

/// An ISO 7816-4 response APDU.
#[derive(Debug, Clone)]
pub struct ApduResponse {
    data: Vec<u8>,
    sw: u16,
    raw: Vec<u8>,
}

impl ApduResponse {
    /// SW_OK: Normal processing
    pub const SW_OK: u16 = 0x9000;
    /// SW_SECURITY_CONDITION_NOT_SATISFIED
    pub const SW_SECURITY_CONDITION_NOT_SATISFIED: u16 = 0x6982;
    /// SW_AUTHENTICATION_METHOD_BLOCKED
    pub const SW_AUTHENTICATION_METHOD_BLOCKED: u16 = 0x6983;
    /// SW_CARD_LOCKED
    pub const SW_CARD_LOCKED: u16 = 0x6283;
    /// SW_REFERENCED_DATA_NOT_FOUND
    pub const SW_REFERENCED_DATA_NOT_FOUND: u16 = 0x6A88;
    /// SW_CONDITIONS_OF_USE_NOT_SATISFIED
    pub const SW_CONDITIONS_OF_USE_NOT_SATISFIED: u16 = 0x6985;
    /// SW_WRONG_PIN_MASK
    pub const SW_WRONG_PIN_MASK: u16 = 0x63C0;

    /// Parse raw response bytes into an ApduResponse.
    /// Requires at least 2 bytes for the status word.
    pub fn new(raw: &[u8]) -> Result<Self, Error> {
        if raw.len() < 2 {
            return Err(Error::Tlv("Response must contain at least 2 bytes (status word)".to_string()));
        }
        let sw = ((raw[raw.len() - 2] as u16) << 8) | (raw[raw.len() - 1] as u16);
        let data = raw[..raw.len() - 2].to_vec();
        Ok(Self {
            data,
            sw,
            raw: raw.to_vec(),
        })
    }

    /// Returns true if the status word is SW_OK (0x9000).
    pub fn is_ok(&self) -> bool {
        self.sw == Self::SW_OK
    }

    /// Asserts the status word is SW_OK, returns a reference to self or an APDUError.
    pub fn check_ok(&self) -> Result<&Self, Error> {
        if self.is_ok() {
            Ok(self)
        } else {
            Err(ApduError::unexpected_sw(self.sw, "Expected SW_OK (0x9000)").into())
        }
    }

    /// Asserts the status word is one of the given codes.
    pub fn check_sw(&self, codes: &[u16]) -> Result<&Self, Error> {
        if codes.contains(&self.sw) {
            Ok(self)
        } else {
            Err(ApduError::unexpected_sw(
                self.sw,
                format!("Expected one of {:?}", codes),
            )
            .into())
        }
    }

    /// Checks authentication response.
    /// If (sw & SW_WRONG_PIN_MASK) == SW_WRONG_PIN_MASK, returns WrongPinError.
    /// Otherwise delegates to check_ok.
    pub fn check_auth_ok(&self) -> Result<&Self, Error> {
        if (self.sw & Self::SW_WRONG_PIN_MASK) == Self::SW_WRONG_PIN_MASK {
            let retry_count = self.sw2() & 0x0F;
            Err(WrongPinError::new(
                retry_count,
                ApduError::unexpected_sw(self.sw, "Wrong PIN/PUK"),
            )
            .into())
        } else {
            self.check_ok()
        }
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn sw(&self) -> u16 {
        self.sw
    }

    pub fn sw1(&self) -> u8 {
        (self.sw >> 8) as u8
    }

    pub fn sw2(&self) -> u8 {
        self.sw as u8
    }

    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apdu_command_serialize_no_data() {
        let cmd = ApduCommand::new(0x00, 0xA4, 0x04, 0x00, Vec::new());
        let serialized = cmd.serialize();
        assert_eq!(serialized, vec![0x00, 0xA4, 0x04, 0x00]);
    }

    #[test]
    fn test_apdu_command_serialize_with_data() {
        let cmd = ApduCommand::new(0x00, 0xA4, 0x04, 0x00, vec![0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x01]);
        let serialized = cmd.serialize();
        assert_eq!(serialized, vec![0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x01]);
    }

    #[test]
    fn test_apdu_command_serialize_with_le() {
        let cmd = ApduCommand::new(0x80, 0xCA, 0x00, 0x00, Vec::new()).with_le(true);
        let serialized = cmd.serialize();
        assert_eq!(serialized, vec![0x80, 0xCA, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_apdu_command_serialize_with_data_and_le() {
        let cmd = ApduCommand::new(0x80, 0xC0, 0x00, 0x00, vec![0x01, 0x02, 0x03]).with_le(true);
        let serialized = cmd.serialize();
        assert_eq!(serialized, vec![0x80, 0xC0, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00]);
    }

    #[test]
    fn test_apdu_command_accessors() {
        let cmd = ApduCommand::new(0x80, 0xFE, 0x00, 0x00, vec![0x01]);
        assert_eq!(cmd.cla(), 0x80);
        assert_eq!(cmd.ins(), 0xFE);
        assert_eq!(cmd.p1(), 0x00);
        assert_eq!(cmd.p2(), 0x00);
        assert_eq!(cmd.data(), &[0x01]);
        assert!(!cmd.needs_le());
    }

    #[test]
    fn test_apdu_response_parse_ok() {
        let raw = vec![0x01, 0x02, 0x03, 0x90, 0x00];
        let resp = ApduResponse::new(&raw).unwrap();
        assert_eq!(resp.data(), &[0x01, 0x02, 0x03]);
        assert_eq!(resp.sw(), 0x9000);
        assert!(resp.is_ok());
    }

    #[test]
    fn test_apdu_response_parse_no_data() {
        let raw = vec![0x90, 0x00];
        let resp = ApduResponse::new(&raw).unwrap();
        assert_eq!(resp.data(), &[]);
        assert_eq!(resp.sw(), 0x9000);
        assert!(resp.is_ok());
    }

    #[test]
    fn test_apdu_response_parse_error_sw() {
        let raw = vec![0x69, 0x82];
        let resp = ApduResponse::new(&raw).unwrap();
        assert_eq!(resp.sw(), 0x6982);
        assert!(!resp.is_ok());
    }

    #[test]
    fn test_apdu_response_check_ok_success() {
        let raw = vec![0x90, 0x00];
        let resp = ApduResponse::new(&raw).unwrap();
        resp.check_ok().unwrap();
    }

    #[test]
    fn test_apdu_response_check_ok_failure() {
        let raw = vec![0x69, 0x82];
        let resp = ApduResponse::new(&raw).unwrap();
        let err = resp.check_ok().unwrap_err();
        match err {
            Error::Apdu(ApduError::UnexpectedSw { sw, .. }) => assert_eq!(sw, 0x6982),
            _ => panic!("Expected UnexpectedSw"),
        }
    }

    #[test]
    fn test_apdu_response_check_sw() {
        let raw = vec![0x69, 0x82];
        let resp = ApduResponse::new(&raw).unwrap();
        resp.check_sw(&[0x6982, 0x6983]).unwrap();
        resp.check_sw(&[0x9000]).unwrap_err();
    }

    #[test]
    fn test_apdu_response_check_auth_ok_wrong_pin() {
        let raw = vec![0x63, 0xC5];
        let resp = ApduResponse::new(&raw).unwrap();
        let err = resp.check_auth_ok().unwrap_err();
        match err {
            Error::WrongPin(wpe) => {
                assert_eq!(wpe.retry_attempts, 5);
            },
            _ => panic!("Expected WrongPinError"),
        }
    }

    #[test]
    fn test_apdu_response_check_auth_ok_ok() {
        let raw = vec![0x90, 0x00];
        let resp = ApduResponse::new(&raw).unwrap();
        resp.check_auth_ok().unwrap();
    }

    #[test]
    fn test_apdu_response_sw1_sw2() {
        let raw = vec![0x63, 0xC5];
        let resp = ApduResponse::new(&raw).unwrap();
        assert_eq!(resp.sw1(), 0x63);
        assert_eq!(resp.sw2(), 0xC5);
    }

    #[test]
    fn test_apdu_response_too_short() {
        let raw = vec![0x90];
        assert!(ApduResponse::new(&raw).is_err());
    }

    #[test]
    fn test_apdu_response_empty() {
        let raw: Vec<u8> = vec![];
        assert!(ApduResponse::new(&raw).is_err());
    }
}
