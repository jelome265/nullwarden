use nullwarden_core::kdf::{derive_key, KdfParams, SALT_LEN};

#[test]
fn kdf_uses_32_byte_key() {
    let salt = [0_u8; SALT_LEN];
    let params = KdfParams::default();
    let key = derive_key(b"password", &salt, params).unwrap();
    assert_eq!(key.as_ref().len(), 32);
}

#[test]
fn kdf_meets_minimum_latency() {
    let salt = [9_u8; SALT_LEN];
    let params = KdfParams::default();
    let start = std::time::Instant::now();
    derive_key(b"testpassword", &salt, params).unwrap();
    let elapsed = start.elapsed();
    assert!(
        elapsed >= std::time::Duration::from_millis(300),
        "KDF latency {elapsed:?} is below the 300ms minimum — Argon2 params have been weakened"
    );
}
