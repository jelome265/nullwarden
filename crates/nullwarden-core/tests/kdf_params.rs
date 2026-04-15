use nullwarden_core::kdf::{derive_key, KdfParams};

#[test]
fn kdf_uses_32_byte_key() {
    let salt = [9_u8; 32];
    let params = KdfParams::default();
    let key = derive_key(b"testpassword", &salt, params).expect("key");
    assert_eq!(key.len(), 32);
}
