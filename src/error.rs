use std::io;
use thiserror::Error;

/// Represents an APDU-level error with a status word.
#[derive(Debug, Error)]
pub enum ApduError {
    #[error("Security condition not satisfied (SW: 0x{:04X})", .sw)]
    SecurityConditionNotSatisfied { sw: u16 },

    #[error("Authentication method blocked (SW: 0x{:04X})", .sw)]
    AuthenticationMethodBlocked { sw: u16 },

    #[error("Unexpected status word 0x{:04X}: {}", .sw, .message)]
    UnexpectedSw { sw: u16, message: String },
}

impl ApduError {
    pub fn security_condition_not_satisfied(sw: u16) -> Self {
        Self::SecurityConditionNotSatisfied { sw }
    }

    pub fn authentication_method_blocked(sw: u16) -> Self {
        Self::AuthenticationMethodBlocked { sw }
    }

    pub fn unexpected_sw(sw: u16, message: impl Into<String>) -> Self {
        Self::UnexpectedSw {
            sw,
            message: message.into(),
        }
    }

    pub fn sw(&self) -> u16 {
        match self {
            Self::SecurityConditionNotSatisfied { sw } => *sw,
            Self::AuthenticationMethodBlocked { sw } => *sw,
            Self::UnexpectedSw { sw, .. } => *sw,
        }
    }
}

/// Error for wrong PIN/PUK with remaining retry count.
#[derive(Debug, Error)]
#[error("Wrong PIN/PUK. Remaining retry attempts: {}", .retry_attempts)]
pub struct WrongPinError {
    pub retry_attempts: u8,
    source: ApduError,
}

impl WrongPinError {
    pub fn new(retry_attempts: u8, source: ApduError) -> Self {
        Self {
            retry_attempts,
            source,
        }
    }

    pub fn source(&self) -> &ApduError {
        &self.source
    }
}

/// Crate-level error enum unifying all error sources.
#[derive(Debug, Error)]
pub enum Error {
    #[error("APDU error: {0}")]
    Apdu(#[from] ApduError),

    #[error("Wrong PIN: {0}")]
    WrongPin(#[from] WrongPinError),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("BER-TLV parsing error: {0}")]
    Tlv(String),

    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apdu_error_display() {
        let err = ApduError::security_condition_not_satisfied(0x6982);
        assert_eq!(err.sw(), 0x6982);
        let msg = format!("{}", err);
        assert!(msg.contains("0x6982"));

        let err = ApduError::authentication_method_blocked(0x6983);
        assert_eq!(err.sw(), 0x6983);

        let err = ApduError::unexpected_sw(0x6F00, "something went wrong");
        assert_eq!(err.sw(), 0x6F00);
    }

    #[test]
    fn test_wrong_pin_error() {
        let source = ApduError::unexpected_sw(0x63C3, "wrong pin");
        let err = WrongPinError::new(3, source);
        assert_eq!(err.retry_attempts, 3);
        let msg = format!("{}", err);
        assert!(msg.contains("3"));
    }

    #[test]
    fn test_error_from_apdu() {
        let apdu_err = ApduError::security_condition_not_satisfied(0x6982);
        let err: Error = apdu_err.into();
        match err {
            Error::Apdu(_) => {},
            _ => panic!("Expected Apdu variant"),
        }
    }

    #[test]
    fn test_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "device not found");
        let err: Error = io_err.into();
        match err {
            Error::Io(_) => {},
            _ => panic!("Expected Io variant"),
        }
    }
}
