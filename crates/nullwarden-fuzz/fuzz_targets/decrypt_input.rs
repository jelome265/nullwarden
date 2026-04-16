#![no_main]
use libfuzzer_sys::fuzz_target;
use nullwarden_core::crypto::decrypt;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 + 24 {
        return;
    }
    let key: [u8; 32] = data[..32].try_into().unwrap();
    let rest = &data[32..];
    let nonce: [u8; 24] = rest[..24].try_into().unwrap();
    let ct = &rest[24..];
    // Must never panic — only return Err
    let _ = decrypt(&key, &nonce, ct);
});
