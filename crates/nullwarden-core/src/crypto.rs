use crate::error::VaultError;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    Key, XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};

pub const NONCE_LEN: usize = 24;

pub fn generate_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0_u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<([u8; NONCE_LEN], Vec<u8>), VaultError> {
    let nonce = generate_nonce();
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| VaultError::DecryptionFailed)?;
    Ok((nonce, ciphertext))
}

pub fn decrypt(key: &[u8; 32], nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> Result<Vec<u8>, VaultError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| VaultError::DecryptionFailed)
}
