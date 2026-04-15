use nullwarden_core::vault::VaultKey;

#[test]
fn vault_key_wraps_32_bytes() {
    let key = VaultKey([0_u8; 32]);
    assert_eq!(key.as_ref().len(), 32);
}
