//! BLAKE3 content identifiers.
//!
//! A [`ContentHash`] is the 32-byte BLAKE3 digest of a complete file.  Files
//! are additionally split into fixed-size pieces, each with its own
//! `ContentHash`, so a receiver can verify data incrementally (and resume a
//! partial download) before the whole file has arrived.

use std::fmt;

use anyhow::{Context, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A 32-byte BLAKE3 digest, rendered as lowercase hex.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContentHash(pub [u8; 32]);

impl ContentHash {
    pub const LEN: usize = 32;

    /// Hash a byte slice.
    pub fn of(data: &[u8]) -> Self {
        Self(*blake3::hash(data).as_bytes())
    }

    /// Hash an already-finalised BLAKE3 hasher.
    pub fn from_hasher(hasher: blake3::Hasher) -> Self {
        Self(*hasher.finalize().as_bytes())
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .context("content hash must be exactly 32 bytes")?;
        Ok(Self(bytes))
    }

    pub fn from_hex(value: &str) -> Result<Self> {
        let value = value.trim();
        let bytes = hex::decode(value).context("invalid hex content hash")?;
        Self::from_slice(&bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    /// Short form used in status output and log lines.
    pub fn short(self) -> String {
        self.to_hex()[..12].to_string()
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ContentHash({})", self.short())
    }
}

impl std::str::FromStr for ContentHash {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_hex(s)
    }
}

impl Serialize for ContentHash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for ContentHash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::from_hex(&value).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let hash = ContentHash::of(b"meshvault");
        assert_eq!(ContentHash::from_hex(&hash.to_hex()).unwrap(), hash);
        assert_eq!(hash.to_string().len(), 64);
    }

    #[test]
    fn knows_empty_hash() {
        assert_eq!(
            ContentHash::of(b"").to_hex(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }
}
