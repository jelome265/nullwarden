#![no_main]
use libfuzzer_sys::fuzz_target;
use nullwarden_core::crypto::decrypt;
use nullwarden_core::types::{VaultEncryptionKey, VaultNonce};

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 + 24 {
        return;
    }
    let key: [u8; 32] = data[..32].try_into().unwrap();
    let enc_key = VaultEncryptionKey(key);
    let rest = &data[32..];
    let nonce: [u8; 24] = rest[..24].try_into().unwrap();
    let vnonce = VaultNonce(nonce);
    let ct = &rest[24..];
    // Must never panic — only return Err
    let _ = decrypt(&enc_key, &vnonce, ct);
});
