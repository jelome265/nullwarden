use crate::error::VaultError;
use crate::types::{VaultEncryptionKey, VaultNonce};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    Key, XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};

pub const NONCE_LEN: usize = 24;

pub fn generate_nonce() -> VaultNonce {
    let mut nonce = [0_u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    VaultNonce(nonce)
}

pub fn encrypt(
    key: &VaultEncryptionKey,
    plaintext: &[u8],
) -> Result<(VaultNonce, Vec<u8>), VaultError> {
    let nonce = generate_nonce();
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(nonce.as_ref()), plaintext)
        .map_err(|_| VaultError::DecryptionFailed)?;
    Ok((nonce, ciphertext))
}

pub fn decrypt(
    key: &VaultEncryptionKey,
    nonce: &VaultNonce,
    ciphertext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    cipher
        .decrypt(XNonce::from_slice(nonce.as_ref()), ciphertext)
        .map_err(|_| VaultError::DecryptionFailed)
}
