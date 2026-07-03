//! BIP32 derivation path parsing and encoding.

use std::fmt;
use std::str::FromStr;

use crate::constants::derive_p1;
use crate::error::Error;

/// A BIP32 derivation path with source indicator.
///
/// Parses paths like `"m/44'/0'/0'/0/0"` into encoded bytes for card commands.
#[derive(Debug, Clone)]
pub struct KeyPath {
    source: u8,
    data: Vec<u8>,
}

impl FromStr for KeyPath {
    type Err = Error;

    /// Parses a BIP32 path string.
    ///
    /// # Format
    /// - First component: `"m"` (master), `".."` (parent), `"."` (current), or omitted (= current)
    /// - Remaining components: 31-bit integers, optionally suffixed with `'` for hardened
    /// - Maximum 10 components after the source
    ///
    /// # Examples
    /// ```
    /// use std::str::FromStr;
    /// use keycard_rs::parsing::key_path::KeyPath;
    ///
    /// let path = KeyPath::from_str("m/44'/0'/0'/0/0").unwrap();
    /// assert_eq!(path.source(), 0x00); // SOURCE_MASTER
    /// ```
    fn from_str(path: &str) -> Result<Self, Error> {
        let mut components: Vec<&str> = path.split('/').collect();

        let first = components.remove(0).trim();
        if first.is_empty() {
            return Err(Error::InvalidArgument(
                "Path must start with m, .., ., or a number".to_string(),
            ));
        }

        let source = match first {
            "m" => derive_p1::SOURCE_MASTER,
            ".." => derive_p1::SOURCE_PARENT,
            "." => derive_p1::SOURCE_CURRENT,
            _ => {
                // Not a source indicator, treat as first component with SOURCE_CURRENT
                components.insert(0, first);
                derive_p1::SOURCE_CURRENT
            }
        };

        if components.len() > 10 {
            return Err(Error::InvalidArgument("Too many path components (max 10)".to_string()));
        }

        let data = components
            .iter()
            .map(|c| parse_component(c))
            .collect::<Result<Vec<u32>, Error>>()?
            .into_iter()
            .flat_map(|n| n.to_be_bytes())
            .collect();

        Ok(Self { source, data })
    }
}

impl KeyPath {
    /// Direct construction from raw bytes with a source.
    pub fn from_raw(data: Vec<u8>, source: u8) -> Self {
        Self { source, data }
    }

    /// Direct construction from raw bytes with SOURCE_MASTER.
    pub fn from_raw_master(data: Vec<u8>) -> Self {
        Self {
            source: derive_p1::SOURCE_MASTER,
            data,
        }
    }

    pub fn source(&self) -> u8 {
        self.source
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

}

impl fmt::Display for KeyPath {
    /// Reverse-encodes to a BIP32 path string.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.source {
            derive_p1::SOURCE_MASTER => f.write_str("m")?,
            derive_p1::SOURCE_PARENT => f.write_str("..")?,
            derive_p1::SOURCE_CURRENT => f.write_str(".")?,
            _ => f.write_str(".")?,
        }

        for chunk in self.data.chunks_exact(4) {
            let num = ((chunk[0] as u32 & 0x7F) << 24)
                | ((chunk[1] as u32) << 16)
                | ((chunk[2] as u32) << 8)
                | (chunk[3] as u32);
            write!(f, "/{}", num)?;
            if chunk[0] & 0x80 != 0 {
                f.write_str("'")?;
            }
        }

        Ok(())
    }
}

fn parse_component(s: &str) -> Result<u32, Error> {
    let (is_hardened, num_str) = if let Some(stripped) = s.strip_suffix('\'') {
        (true, stripped)
    } else {
        (false, s)
    };

    if num_str.starts_with('+') || num_str.starts_with('-') {
        return Err(Error::InvalidArgument(format!(
            "No sign allowed in path component: {}",
            s
        )));
    }

    let num: u32 = num_str
        .parse()
        .map_err(|_| Error::InvalidArgument(format!("Invalid path component: {}", s)))?;

    if num > 0x7FFFFFFF {
        return Err(Error::InvalidArgument(format!(
            "Path component too large: {}",
            num
        )));
    }

    Ok(if is_hardened { num | 0x80000000 } else { num })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_str_master() {
        let path = KeyPath::from_str("m/44'/0'/0'/0/0").unwrap();
        assert_eq!(path.source(), derive_p1::SOURCE_MASTER);
        assert_eq!(path.data().len(), 20); // 5 components * 4 bytes

        // Check first component: 44' = 0x8000002C
        assert_eq!(path.data()[0], 0x80);
        assert_eq!(path.data()[1], 0x00);
        assert_eq!(path.data()[2], 0x00);
        assert_eq!(path.data()[3], 0x2C);
    }

    #[test]
    fn test_from_str_parent() {
        let path = KeyPath::from_str("../0/1").unwrap();
        assert_eq!(path.source(), derive_p1::SOURCE_PARENT);
    }

    #[test]
    fn test_from_str_current() {
        let path = KeyPath::from_str("./0/1").unwrap();
        assert_eq!(path.source(), derive_p1::SOURCE_CURRENT);
    }

    #[test]
    fn test_from_str_implicit_current() {
        let path = KeyPath::from_str("0/1/2").unwrap();
        assert_eq!(path.source(), derive_p1::SOURCE_CURRENT);
    }

    #[test]
    fn test_from_str_single_component() {
        let path = KeyPath::from_str("m/0").unwrap();
        assert_eq!(path.data().len(), 4);
    }

    #[test]
    fn test_to_string_roundtrip() {
        let original = "m/44'/0'/0'/0/0";
        let path = KeyPath::from_str(original).unwrap();
        assert_eq!(path.to_string(), original);

        let original = "./1/2/3'";
        let path = KeyPath::from_str(original).unwrap();
        assert_eq!(path.to_string(), original);
    }

    #[test]
    fn test_from_str_too_many_components() {
        assert!(KeyPath::from_str("m/0/1/2/3/4/5/6/7/8/9/10").is_err());
    }

    #[test]
    fn test_from_str_signed_component() {
        assert!(KeyPath::from_str("m/+44").is_err());
        assert!(KeyPath::from_str("m/-44").is_err());
    }

    #[test]
    fn test_from_str_invalid_number() {
        assert!(KeyPath::from_str("m/abc").is_err());
    }

    #[test]
    fn test_from_raw() {
        let path = KeyPath::from_raw(vec![0x80, 0x00, 0x00, 0x2C], derive_p1::SOURCE_MASTER);
        assert_eq!(path.source(), derive_p1::SOURCE_MASTER);
        assert_eq!(path.data(), &[0x80, 0x00, 0x00, 0x2C]);
    }

    #[test]
    fn test_from_raw_master() {
        let path = KeyPath::from_raw_master(vec![0x00, 0x00, 0x00, 0x00]);
        assert_eq!(path.source(), derive_p1::SOURCE_MASTER);
    }
}
