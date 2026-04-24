use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A string that is zeroized from memory when dropped.
///
/// # Warning
///
/// The `Serialize` implementation for this type emits the **plaintext** string.
/// This is intended for encrypted storage (e.g. MessagePack vaults) but means
/// this type must **never** be used as a field in a struct that is serialized
/// to JSON for an HTTP response (e.g. in a server handler).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretString(pub String);

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString(***REDACTED***)")
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(pub Vec<u8>);

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes(***REDACTED***)")
    }
}

impl Serialize for SecretString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str("***REDACTED***")
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(SecretString)
    }
}

impl Serialize for SecretBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(b"***REDACTED***")
    }
}

impl<'de> Deserialize<'de> for SecretBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<u8>::deserialize(deserializer).map(SecretBytes)
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VaultEncryptionKey(pub [u8; 32]);

impl fmt::Debug for VaultEncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VaultEncryptionKey(***REDACTED***)")
    }
}

impl AsRef<[u8; 32]> for VaultEncryptionKey {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct VaultNonce(pub [u8; 24]);

impl AsRef<[u8; 24]> for VaultNonce {
    fn as_ref(&self) -> &[u8; 24] {
        &self.0
    }
}

pub mod secret_string_wire {
    use super::SecretString;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &SecretString, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.0)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SecretString, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(SecretString)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_string_zeroize() {
        let mut s = SecretString("password123".to_string());
        let len = s.0.len();

        // We do this BEFORE zeroize to make sure we see the data.
        {
            let ptr = s.0.as_ptr();
            let slice_before = unsafe { std::slice::from_raw_parts(ptr, len) };
            assert_eq!(slice_before, b"password123");
        }

        s.zeroize();

        // After zeroize, the buffer should be all zeros.
        // We must re-derive the pointer and length because s.zeroize() for String
        // may change the internal buffer or its length.
        {
            let ptr = s.0.as_ptr();
            let len = s.0.len();
            let slice_after = unsafe { std::slice::from_raw_parts(ptr, len) };
            for &byte in slice_after {
                assert_eq!(byte, 0);
            }
        }
    }

    #[test]
    fn test_vault_key_zeroize() {
        let mut key = VaultEncryptionKey([0xAA; 32]);

        // Before zeroize
        {
            let slice = key.as_ref();
            for &byte in slice {
                assert_eq!(byte, 0xAA);
            }
        }

        key.zeroize();

        // After zeroize
        {
            let slice = key.as_ref();
            for &byte in slice {
                assert_eq!(byte, 0);
            }
        }
    }
}
