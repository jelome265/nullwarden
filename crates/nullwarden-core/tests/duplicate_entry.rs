use nullwarden_core::error::VaultError;
use nullwarden_core::vault::VaultData;

#[test]
fn test_duplicate_entry_error() {
    let mut vault = VaultData::default();
    vault
        .add_entry(
            "github".to_string(),
            "alice".to_string(),
            "secret".to_string(),
            None,
        )
        .expect("first add should succeed");

    let res = vault.add_entry(
        "github".to_string(),
        "bob".to_string(),
        "secret2".to_string(),
        None,
    );

    match res {
        Err(VaultError::DuplicateEntry) => (),
        _ => panic!("Expected DuplicateEntry error, got {:?}", res),
    }
}
