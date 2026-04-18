use crate::crypto;
use crate::error::VaultError;
use crate::types::{VaultEncryptionKey, VaultNonce};

pub struct VaultCipher;

impl VaultCipher {
    pub fn encrypt(
        key: &VaultEncryptionKey,
        plaintext: &[u8],
    ) -> Result<(VaultNonce, Vec<u8>), VaultError> {
        crypto::encrypt(key, plaintext)
    }

    pub fn decrypt(
        key: &VaultEncryptionKey,
        nonce: &VaultNonce,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, VaultError> {
        crypto::decrypt(key, nonce, ciphertext)
    }
}
